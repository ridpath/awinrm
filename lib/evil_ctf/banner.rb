# lib/evil_ctf/banner.rb

require 'colorize'

module EvilCTF::Banner
  # Color helper module
  module Color
    def self.header(text, color = :cyan)
      text = "  #{text}".ljust(70, '-')
      case color
      when :red; text.red
      when :green; text.green
      when :yellow; text.yellow
      when :blue; text.blue
      when :magenta; text.magenta
      when :white; text.white
      when :cyan; text.cyan
      else; text
      end
    end

    def self.success(text)
      "  [+] #{text}".green
    end

    def self.warning(text)
      "  [!] #{text}".yellow
    end

    def self.error(text)
      "  [-] #{text}".red
    end

    def self.info(text)
      "  [i] #{text}".blue
    end

    def self.critical(text)
      "  [CRITICAL] #{text}".magenta
    end

    def self.flag(text)
      "  [!] FLAG: #{text}".red
    end

    def self.risk(score)
      case score
      when 0..30; :red
      when 31..60; :yellow
      when 61..100; :green
      end
    end

    def self.risk_text(score)
      case score
      when 0..30; "LOW"
      when 31..60; "MEDIUM"
      when 61..100; "HIGH"
      end
    end
  end

  # Show banner with optional color
  def self.show_banner(shell, options, mode: :minimal, no_color: false)
    # Disable color if requested
    if no_color
      # Use plain text
      puts "\n" + "=" * 70
      puts "AWINRM CTF SESSION - #{mode.to_s.upcase} MODE".center(70)
      puts "=" * 70
      case mode
      when :minimal
        show_minimal_banner(shell, options, no_color: true)
      when :expanded
        show_expanded_banner(shell, options, no_color: true)
      end
      return
    end

    # Colorized version
    case mode
    when :minimal
      show_minimal_banner(shell, options)
    when :expanded
      show_expanded_banner(shell, options)
    else
      show_minimal_banner(shell, options)
    end
  end

  # Backward compatibility
  def self.show_banner_with_flagscan(shell, options)
    show_banner(shell, options, mode: :expanded, no_color: false)
  end

  # Minimal Mode with Color
  def self.show_minimal_banner(shell, options, no_color: false)
    # ASCII Art
    puts <<~BANNER.green
     █████╗ ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
    ██╔══██╗██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
    ███████║██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
    ██╔══██║██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
    ██║  ██║╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
    BANNER

    puts "                    AWINRM OPERATOR SHELL".cyan
    puts "        CTF Edition v2025 — For Red Teamers & Flag Hunters".white
    puts "        🔹 Quick enum: `enum basic` | Full recon: `enum deep`".white
    puts "        🔹 Credentials: `dump_creds` | Memory: `lsass_dump`".white
    puts "        🔹 Bypass: `bypass-4msi` | Shell: `!bash`".white
    puts "        🔹 Tools: `tool all` | Help: `menu`".white
    puts

    # Separator
    puts '=' * 70
    puts 'AWINRM CTF SESSION - MINIMAL MODE'.center(70).yellow
    puts '=' * 70

    # System Info
    begin
      hostname = shell.run('hostname').output.strip
      current_user = shell.run('[Security.Principal.WindowsIdentity]::GetCurrent().Name').output.strip
      integrity = shell.run('whoami /groups | findstr "Mandatory Label" | findstr /v "Level"').output.strip.split.first || "Unknown"
      domain = shell.run('(Get-WmiObject Win32_ComputerSystem).Domain').output.strip
    rescue => e
      hostname = "Unknown"
      current_user = "Unknown"
      integrity = "Unknown"
      domain = "Unknown"
    end

    puts "\n".cyan + "ESSENTIAL SYSTEM INFO:".cyan
    puts "  Hostname     : #{hostname}".white
    puts "  Domain       : #{domain}".white
    puts "  Current User : #{current_user}".white
    puts "  Integrity    : #{integrity}".white

    # Privilege Check
    puts "\n".cyan + "PRIVILEGE CHECK:".cyan
    begin
      priv_check = shell.run('whoami /priv').output
      if priv_check.include?('SeDebugPrivilege')
        puts "  [!] SeDebugPrivilege - LSASS access possible".red
      end
      if priv_check.include?('SeImpersonatePrivilege')
        puts "  [!] SeImpersonatePrivilege - Potato attacks possible".red
      end
    rescue => e
      puts "  [!] Privilege check failed: #{e.message}".yellow
    end

    # Defender Status
    begin
      defender = shell.run('(Get-MpComputerStatus).RealTimeProtectionEnabled').output.strip
      status = defender == 'True' ? 'ENABLED' : 'DISABLED'
      puts "  Defender     : #{status == 'ENABLED' ? status.green : status.red}".white
    rescue => e
      puts "  [!] Defender check failed: #{e.message}".yellow
    end

    # Connection Info
    puts "\n".cyan + "CONNECTION:".cyan
    transport = options[:ssl] ? 'HTTPS'.green : 'HTTP'.red
    auth = options[:hash] ? 'NTLM Hash'.green : 'Password'.red
    puts "  Transport    : #{transport}".white
    puts "  Port         : #{options[:port]}".white
    puts "  Auth         : #{auth}".white

    # Quick Flag Scan
    puts "\n".cyan + "QUICK FLAG SCAN".cyan
    begin
      ps = <<~POWERSHELL
        $flag_locations = @(
          "C:\\flag.txt", "C:\\user.txt", "C:\\root.txt",
          "C:\\Users\\*\\Desktop\\flag.txt",
          "C:\\Users\\*\\Documents\\flag.txt", 
          "C:\\Users\\*\\Downloads\\flag.txt",
          "C:\\Users\\*\\user.txt",
          "C:\\Users\\*\\root.txt"
        )
        
        foreach ($pattern in $flag_locations) {
          if ($pattern -like "*\\*\\*") {
            Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
              $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim()) {
                Write-Output "FLAGFOUND|||$($_.FullName)|||$content"
              }
            }
          } else {
            if (Test-Path $pattern) {
              $content = Get-Content $pattern -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim()) {
                Write-Output "FLAGFOUND|||$pattern|||$content"
              }
            }
          }
        }
      POWERSHELL

      result = shell.run(ps)
      flags_found = false
      result.output.each_line do |line|
        next unless line.include?("FLAGFOUND|||")
        flags_found = true
        path, value = line.strip.split("|||", 3)[1..2]
        puts "  [!] FLAG: #{path}".red
        puts "      #{value.strip}".yellow
      end
      puts "  [+] No flags found in common locations".white unless flags_found
    rescue => e
      puts "  [ ] Flag scan error: #{e.message}".red
    end

    puts "\n" + '=' * 70
    puts "SESSION READY - Type 'help' for commands".green
    puts '=' * 70
  end

  # Expanded Mode with Color
  def self.show_expanded_banner(shell, options, no_color: false)
    # ASCII Art
    puts <<~BANNER.green
     █████╗ ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
    ██╔══██╗██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
    ███████║██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
    ██╔══██║██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
    ██║  ██║╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
    BANNER

    puts "                    AWINRM OPERATOR SHELL".cyan
    puts "        CTF Edition v2025 — For Red Teamers, Pentesters & Flag Hunters".white
    puts "        🔹 Try `enum deep` for full recon, `dump_creds` for live creds".white
    puts "        🔹 Use `lsass_dump` for memory, `tool all` to stage everything".white
    puts "        🔹 AMSI & Defender? Use `bypass-4msi` to go stealth".white
    puts "        🔹 Need a shell on target? `!bash` or `invoke-binary` is your friend".white
    puts "        🔹 Domain intel quick? Run `dom_enum` or `powerview all`".white
    puts "        🔹 Kerberoast tickets: `kerberoast` for SPN attacks".white
    puts "        🔹 AD mapping: `tool sharphound` then `sharphound -c all`".white
    puts "        🔹 Harvest creds: `cred_harvest` or `tool mimikatz`".white
    puts "        🔹 Relay attacks: `tool inveigh` and `inveigh start`".white
    puts "        🔹 Rev shells: `tool nishang` for PowerShell payloads".white
    puts "        🔹 Sys internals: `tool seatbelt` with `seatbelt -group=all`".white
    puts "        🔹 Priv esc scans: `tool winpeas` for vuln checks".white
    puts "        🔹 Ticket ops: `tool rubeus` like `rubeus klist`".white
    puts "        🔹 ETW evade: `bypass-etw` for advanced logging bypass".white
    puts "        🔹 File upload stealth: `upload -x /local/path remote/path`".white
    puts "        🔹 Download artifacts: `download C:\\path loot/`".white
    puts "        🔹 SOCKS pivot: `socks_init` for proxy chaining".white
    puts "        🔹 Loot overview: `loot show` for extracted items".white
    puts "        🔹 Menu help: `menu` for module list, `help` for commands".white
    puts

    # Separator
    puts '=' * 70
    puts 'AWINRM CTF SESSION - EXPANDED MODE'.center(70).yellow
    puts '=' * 70

    # Basic System Info
    begin
      hostname = shell.run('hostname').output.strip
      os_version = shell.run('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"').output.strip
      arch = shell.run('$env:PROCESSOR_ARCHITECTURE').output.strip
    rescue => e
      hostname = "Unknown"
      os_version = "Unknown"
      arch = "Unknown"
    end

    puts "\n".cyan + "System Information:".cyan
    puts "  Hostname        : #{hostname}".white
    puts "  OS Version      : #{os_version}".white
    puts "  Architecture    : #{arch}".white

    # Core System Info
    puts "\n".cyan + "CORE SYSTEM INFORMATION".center(70, '-').cyan
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
        puts "  #{label.ljust(30)} : #{output}".white
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}".yellow
      end
    end

    # Privilege & Token
    puts "\n".cyan + "PRIVILEGE & TOKEN INFORMATION".center(70, '-').cyan
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
        puts "  #{label.ljust(30)} : #{output}".white
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}".yellow
      end
    end

    # Performance & Health
    puts "\n".cyan + "PERFORMANCE & HEALTH".center(70, '-').cyan
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
        puts "  #{label.ljust(25)} : #{output.empty? ? 'N/A' : output}".white
      rescue => e
        puts "  #{label.ljust(25)} : Error: #{e.message}".yellow
      end
    end

    # MSSQL Detection
    puts "\n".cyan + "MSSQL DETECTION".center(70, '-').cyan
    begin
      sql_ver_check = shell.run("sqlcmd -Q \"SELECT @@version\"").output.strip
      if sql_ver_check.include?("Microsoft SQL Server")
        puts "  [*] MSSQL Instance Detected".green
        sql_queries = {
          "SQL Version"       => "sqlcmd -Q \"SELECT @@version\"",
          "SQL Current User"  => "sqlcmd -Q \"SELECT SYSTEM_USER, USER_NAME()\"",
          "SQL Available DBs" => "sqlcmd -Q \"SELECT name FROM sys.databases\"",
          "SQL Linked Servers"=> "sqlcmd -Q \"EXEC sp_linkedservers\""
        }

        sql_queries.each do |label, cmd|
          output = shell.run(cmd).output.strip
          output = output.lines.take(2).join(" | ").strip
          puts "  #{label.ljust(25)} : #{output.empty? ? 'N/A' : output}".white
        end

        # Check enabled features
        sql_checks = {
          "SQL xp_cmdshell" => "sqlcmd -Q \"EXEC sp_configure 'xp_cmdshell';\"",
          "SQL CLR Enabled" => "sqlcmd -Q \"EXEC sp_configure 'clr enabled';\""
        }

        sql_checks.each do |check, cmd|
          output = shell.run(cmd).output.strip
          if output.include?("1")
            puts "  [!] #{check} : ENABLED".red
          else
            puts "  [ ] #{check} : disabled".green
          end
        end
      else
        puts "  [ ] No MSSQL Instance Detected".white
      end
    rescue => e
      puts "  [ ] MSSQL Detection Error: #{e.message}".yellow
    end

    # Patch Info
    puts "\n".cyan + "PATCH & VULNERABILITY STATUS".center(70, '-').cyan
    begin
      all_hotfixes = shell.run("Get-HotFix | Select-Object HotFixID").output

      critical_patches = {
        "MS17-010 (EternalBlue)" => ["KB4012212", "KB4012215", "KB4012216", "KB4012217", "KB4012218", "KB4012219", "KB4012220", "KB4012598", "KB4012606", "KB4013198", "KB4013389", "KB4013429"],
        "MS08-067 (Conficker)" => ["KB958644"],
        "MS14-068 (Kerberos)" => ["KB3011780"]
      }

      critical_patches.each do |desc, kb_list|
        patched = kb_list.any? { |kb| all_hotfixes.include?(kb) }
        status = patched ? "PATCHED" : "MISSING"
        symbol = patched ? "[+]".green : "[!]".red
        puts "  #{symbol} #{desc} - #{status}".white
      end

      last_patch = shell.run('Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-Table HotFixID,InstalledOn -AutoSize').output.strip
      patch_count = shell.run('(Get-HotFix | Measure-Object).Count').output.strip

      puts "\n  Patch Summary:".white
      puts "    Total Hotfixes: #{patch_count}".white
      if last_patch && !last_patch.empty?
        puts "    Last Patch: #{last_patch.lines.last.strip}" if last_patch.lines.count > 1
      end
    rescue => e
      puts "  [ ] Patch info error: #{e.message}".yellow
    end

    # Security Hardening Checks
    puts "\n".cyan + "SECURITY HARDENING CHECKS".center(70, '-').cyan
    security_cmds = {
      'LSA Protection'          => '(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL',
      'Credential Guard'        => '(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning',
      'BitLocker Status'        => 'if (Get-Command Manage-BDE -ErrorAction SilentlyContinue) { (Manage-BDE -Status C: 2>$null | findstr "Conversion Status") -split ": " | Select-Object -Last 1 } else { "Not Available" }',
      'SMB Signing'             => '(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature',
      'Wdigest Enabled'         => 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue',
      'LSASS Protection'        => '(Get-Process -Name lsass -ErrorAction SilentlyContinue).Protection'
    }

    security_cmds.each do |label, cmd|
      begin
        output = shell.run(cmd).output.strip
        output = "Not Enabled" if output.empty? || output == "N/A"
        if label == 'BitLocker Status' && (output.include?("not recognized") || output.empty?)
          output = "Not Available"
        end
        puts "  #{label.ljust(30)} : #{output}".white
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}".yellow
      end
    end

    # Application Detection
    puts "\n".cyan + "APPLICATION & SERVICE DETECTION".center(70, '-').cyan
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
        puts "  #{label.ljust(30)} : #{output}".white
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}".yellow
      end
    end

    # Network Info
    puts "\n".cyan + "NETWORK & CONNECTIVITY".center(70, '-').cyan
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
        puts "  #{label.ljust(30)} : #{output.empty? ? 'N/A' : output}".white
      rescue => e
        puts "  #{label.ljust(30)} : Error: #{e.message}".yellow
      end
    end

    # Risk Assessment
    risk_data = assess_risk(shell)
    display_risk_assessment(risk_data)
    display_auto_suggestions(risk_data)
    display_attack_paths(risk_data)
    display_lateral_movement_opportunities(shell)

    # Shadow Copies
    puts "\n".cyan + "BACKUP & SHADOW COPIES".center(70, '-').cyan
    begin
      shadow_copies = shell.run('vssadmin list shadows 2>$null').output.strip
      if shadow_copies.include?('Shadow Copy Volume')
        count = shadow_copies.scan('Shadow Copy Volume').count
        puts "  [+] Shadow Copies Available: #{count} found".green
        puts "  [!] Use: `vssadmin create shadow /For=C:` to create new".yellow
        puts "  [!] Use: `copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit .` for NTDS".yellow
      else
        puts "  [ ] No Shadow Copies Detected".white
      end
    rescue => e
      puts "  [ ] Shadow Copy Check Failed: #{e.message}".yellow
    end

    # Group Policy
    puts "\n".cyan + "GROUP POLICY SETTINGS".center(70, '-').cyan
    begin
      gpo = shell.run('gpresult /Z | findstr /C:"Group Policy was applied" 2>$null').output.strip
      if gpo.include?('applied')
        puts "  [+] Group Policy Applied: Yes".green
        puts "  [i] Run: `gpresult /H gpo.html` to export detailed report".yellow
      else
        puts "  [ ] Group Policy: Not applied or limited".white
      end
    rescue => e
      puts "  [ ] GPO Check Failed: #{e.message}".yellow
    end

    # Trust Relationships
    domain_check = shell.run('(Get-WmiObject Win32_ComputerSystem).PartOfDomain').output.strip
    if domain_check == "True"
      puts "\n".cyan + "TRUST RELATIONSHIPS".center(70, '-').cyan
      begin
        trusts = shell.run('nltest /domain_trusts /all_trusts 2>$null').output.strip
        if trusts.include?('Domain Trusts')
          puts "  [+] Domain Trusts Found".green
          trusts.split("\n").each do |line|
            puts "      #{line}" if line.include?('Trusted domain:') || line.include?('Trust attributes:')
          end
        else
          puts "  [ ] No Domain Trusts Detected".white
        end
      rescue => e
        puts "  [ ] Trust Relationship Check Failed: #{e.message}".yellow
      end
    end

    # Default Accounts
    puts "\n".cyan + "DEFAULT ACCOUNT CHECKS".center(70, '-').cyan
    begin
      default_accounts = {
        'Administrator' => 'Built-in admin',
        'Guest' => 'Built-in guest',
        'DefaultAccount' => 'Windows 10 default'
      }

      default_accounts.each do |acc, desc|
        status = shell.run("net user #{acc} 2>$null").output.strip
        if status.include?('Account active') && status.include?('Yes')
          puts "  [!] #{acc} (#{desc}): ENABLED".red
        else
          puts "  [+] #{acc} (#{desc}): Disabled".green
        end
      end
    rescue => e
      puts "  [ ] Default Account Check Failed: #{e.message}".yellow
    end

    # Unquoted Service Paths
    puts "\n".cyan + "UNQUOTED SERVICE PATHS".center(70, '-').cyan
    begin
      services_ps = <<~POWERSHELL
        Get-CimInstance -Class Win32_Service | Where-Object { 
          $_.PathName -notlike '`"*' -and $_.PathName -like '*.exe*' -and $_.PathName -like '* *'
        } | Select-Object Name, DisplayName, PathName, State | Format-Table -AutoSize
      POWERSHELL

      services_output = shell.run(services_ps).output.strip
      if services_output.lines.count > 3
        puts "  [!] Unquoted Service Paths Found:".red
        services_output.lines[3..6].each do |line|
          cleaned_line = line.strip
          puts "      #{cleaned_line}" if cleaned_line.length > 0
        end
        puts "      ... (run 'get-unquotedservices' for full list)".yellow
      else
        puts "  [+] No Unquoted Service Paths Detected".green
      end
    rescue => e
      puts "  [ ] Unquoted Service Path Check Failed: #{e.message}".yellow
    end

    # Connection Info
    puts "\n".cyan + "CONNECTION INFORMATION".center(70, '-').cyan
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
      puts "  #{label.ljust(30)} : #{eval(value)}".white
    end

    # Optimized Flag Scan
    puts "\n".cyan + "OPTIMIZED FLAG SCAN".center(70, '-').cyan
    begin
      ps = <<~POWERSHELL
        $found_flags = @{}
        $search_locations = @(
          "C:\\flag.txt", "C:\\user.txt", "C:\\root.txt",
          "C:\\Users\\*\\Desktop\\flag.txt",
          "C:\\Users\\*\\Desktop\\user.txt", 
          "C:\\Users\\*\\Desktop\\root.txt",
          "C:\\Users\\*\\Documents\\flag.txt",
          "C:\\Users\\*\\Downloads\\flag.txt"
        )
        
        foreach ($location in $search_locations) {
          try {
            Get-ChildItem -Path $location -ErrorAction SilentlyContinue | ForEach-Object {
              $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim() -and $content.Trim().Length -lt 500) {
                if (-not $found_flags.ContainsKey($_.FullName)) {
                  $found_flags[$_.FullName] = $content.Trim()
                }
              }
            }
          } catch { }
        }
        
        # Quick recursive search in user directories
        $user_dirs = @("Desktop", "Documents", "Downloads")
        foreach ($user_dir in $user_dirs) {
          try {
            Get-ChildItem "C:\\Users\\*\\$user_dir\\*" -Include "flag*", "user.txt", "root.txt" -Recurse -Depth 1 -ErrorAction SilentlyContinue | ForEach-Object {
              $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim() -and $content.Trim().Length -lt 500) {
                if (-not $found_flags.ContainsKey($_.FullName)) {
                  $found_flags[$_.FullName] = $content.Trim()
                }
              }
            }
          } catch { }
        }
        
        $found_flags.GetEnumerator() | ForEach-Object {
        $found_flags.GetEnumerator() | ForEach-Object {
          Write-Output "FLAGFOUND|||$($_.Key)|||$($_.Value)"
        }
      POWERSHELL

      result = shell.run(ps)
      flags_found = false
      unique_paths = Set.new

      result.output.each_line do |line|
        next unless line.include?("FLAGFOUND|||")
        flags_found = true
        path, value = line.strip.split("|||", 3)[1..2]

        unless unique_paths.include?(path)
          unique_paths.add(path)
          puts "  [!] Found: #{path}".red
          puts "      #{value.strip}" if value && value.strip.length > 0
        end
      end

      puts "  [+] No flags found in optimized search".white unless flags_found
    rescue => e
      puts "  [ ] Flag scan failed: #{e.message}".red
    end

    puts "\n" + '=' * 70
    puts "SESSION READY - Type 'help' for commands or 'menu' for modules".green
    puts '=' * 70
  end

  # Risk Assessment (unchanged, just colorized)
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

    # Check Defender
    defender_check = shell.run('(Get-MpComputerStatus).RealTimeProtectionEnabled').output.strip
    if defender_check == "False"
      risk_score += 15
      findings << "Windows Defender real-time protection disabled"
      suggestions << "Easier to run tools and payloads"
    end

    # Check UAC
    uac_check = shell.run('Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin').output.strip
    if uac_check == "0"
      risk_score += 10
      findings << "UAC disabled - no elevation prompts"
      suggestions << "Direct privilege escalation possible"
    end

    # Check domain
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

  # Display methods (colorized)
  def self.display_risk_assessment(risk_data)
    puts "\n".cyan + "RISK ASSESSMENT".center(70, '-').cyan
    if risk_data[:score] >= 70
      puts "  [CRITICAL] RISK: #{risk_data[:score]}/100".magenta
      puts "      High privilege environment with multiple attack vectors".white
    elsif risk_data[:score] >= 40
      puts "  [MEDIUM] RISK: #{risk_data[:score]}/100".yellow
      puts "      Moderate privileges with some attack vectors".white
    else
      puts "  [LOW] RISK: #{risk_data[:score]}/100".green
      puts "      Limited privileges - focus on enumeration and discovery".white
    end

    puts "\n  KEY FINDINGS:".white
    risk_data[:findings].each do |finding|
      puts "    • #{finding}".white
    end
  end

  def self.display_auto_suggestions(risk_data)
    puts "\n".cyan + "AUTO-SUGGESTIONS".center(70, '-').cyan
    if risk_data[:score] >= 50
      puts "  [HIGH] PRIVILEGE ENVIRONMENT DETECTED".red
      puts "      → Run: 'dump_creds' for immediate credential harvesting".white
      puts "      → Run: 'lsass_dump' for memory credential extraction".white
      puts "      → Run: 'dom_enum' for domain enumeration".white
    elsif risk_data[:score] >= 25
      puts "  [MEDIUM] PRIVILEGE ENVIRONMENT".yellow
      puts "      → Run: 'enum basic' for system enumeration".white
      puts "      → Run: 'priv_esc_check' for privilege escalation vectors".white
      puts "      → Run: 'kerberoast' for service account attacks".white
    else
      puts "  [LOW] PRIVILEGE ENVIRONMENT".green
      puts "      → Run: 'enum deep' for comprehensive recon".white
      puts "      → Run: 'file_search' for sensitive files".white
      puts "      → Run: 'cred_harvest' for credential hunting".white
    end

    risk_data[:suggestions].each_with_index do |suggestion, index|
      puts "      → #{suggestion}".white if index < 3
    end
  end

  def self.display_attack_paths(risk_data)
    puts "\n".cyan + "COMMON ATTACK PATHS".center(70, '-').cyan
    if risk_data[:findings].any? { |f| f.include?('SeImpersonatePrivilege') }
      puts "  [→] Potato Family Attacks:".green
      puts "      JuicyPotato, RoguePotato, PrintSpoofer".white
    end
    if risk_data[:findings].any? { |f| f.include?('Local Administrator') }
      puts "  [→] Credential Attacks:".green
      puts "      Dump SAM/LSA secrets, check unattend.xml".white
    end
    if risk_data[:findings].any? { |f| f.include?('Domain joined') }
      puts "  [→] Active Directory Attacks:".green
      puts "      Kerberoasting, AS-REP Roasting, DCSync".white
    end
    puts "  [→] Always: Check for unquoted service paths".white
    puts "  [→] Always: Check for writable service binaries".white
    puts "  [→] Always: Check for stored credentials".white
  end

  def self.display_lateral_movement_opportunities(shell)
    puts "\n".cyan + "LATERAL MOVEMENT OPPORTUNITIES".center(70, '-').cyan
    shares = shell.run('net share 2>$null').output
    if shares.include?('ADMIN$') || shares.include?('C$')
      puts "  [→] Admin Shares: Available (ADMIN$, C$)".green
    end
    smb_signing = shell.run('(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature) 2>$null').output.strip
    if smb_signing == "False"
      puts "  [→] SMB Signing: Disabled (SMB relay possible)".red
    end
    ps_remoting = shell.run('Get-PSSessionConfiguration 2>$null').output
    if ps_remoting.include?('Microsoft.PowerShell')
      puts "  [→] PS Remoting: Enabled".green
    end
    winrm = shell.run('Get-Service WinRM 2>$null').output
    if winrm.include?('Running')
      puts "  [→] WinRM: Running (lateral movement possible)".green
    end
    puts "  [→] Always: Check for reused passwords".white
    puts "  [→] Always: Check for token impersonation".white
  end
end
