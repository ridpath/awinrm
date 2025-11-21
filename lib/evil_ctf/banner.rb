# lib/evil_ctf/banner.rb

module EvilCTF::Banner
  def self.show_banner_with_flagscan(shell, options)
    puts <<~BANNER

      ███████╗██╗   ██╗██╗██╗     ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
      ██╔════╝██║   ██║██║██║     ██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
      █████╗  ██║   ██║██║██║     ██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
      ██╔══╝  ╚██╗ ██╔╝██║██║     ██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
      ███████╗ ╚████╔╝ ██║███████╗╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
      ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝

    CTF Edition v2025 - For CTF Warriors, Red Team Operators, and Pentest Pros
    Quick Tips: Run 'dump_creds' for creds | 'lsass_dump' for memory | 'enum deep' for loot hunt
    Pro Tip: Stage tools with 'tool all' and bypass AMSI/ETW automatically!

  BANNER

    puts "\n" + '=' * 70
    puts 'EVIL-WINRM CTF SESSION'.center(70)
    puts '=' * 70

    # ---------- Basic system info ----------
    hostname = shell.run('hostname').output.strip
    os_version_cmd = 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'
    os_version = shell.run(os_version_cmd).output.strip
    arch = shell.run('$env:PROCESSOR_ARCHITECTURE').output.strip

    puts "\nSystem Information:"
    puts "  Hostname      : #{hostname}"
    puts "  OS Version     : #{os_version}"
    puts "  Architecture   : #{arch}"

    # ---------- Additional info commands ----------
    info_cmds = {
      'Hostname'            => 'hostname',
      'Domain'              => '(Get-WmiObject Win32_ComputerSystem).Domain',
      'Domain Joined'       => '(Get-WmiObject Win32_ComputerSystem).PartOfDomain',
      'OS Version'          => 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
      'Architecture'        => '$env:PROCESSOR_ARCHITECTURE',
      'Current User'        => '[Security.Principal.WindowsIdentity]::GetCurrent().Name',
      'Integrity Level'     => 'whoami /groups | findstr "Mandatory Label"',
      'Token Type'          => '[Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel',
      'PS Language Mode'    => '$ExecutionContext.SessionState.LanguageMode',
      'Defender Enabled'    => '(Get-MpComputerStatus).RealTimeProtectionEnabled',
      'AV Exclusions'       => '(Get-MpPreference).ExclusionPath -join ";"',
      'UAC Level'           => 'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin',
      'Is Local Admin'      => 'net localgroup Administrators | findstr /i "$env:USERNAME"',
      'Sessions'            => 'query user',
      'Remote Time (UTC)'   => '[datetime]::UtcNow',
      'Transport'           => "'#{options[:ssl] ? 'HTTPS' : 'HTTP'}'",
      'Port'                => "'#{options[:port]}'",
      'SSL'                 => "'#{options[:ssl] ? 'Yes' : 'No'}'",
      'Auth Type'           => "'#{options[:hash] ? 'NTLM Hash' : 'Password'}'",
      'Endpoint'            => "'#{options[:endpoint] || 'N/A'}'",
      'Stealth Mode'        => "'#{options[:stealth] ? 'Yes' : 'No'}'",
      'Random Names'        => "'#{options[:random_names] ? 'Yes' : 'No'}'",
      'Auto Evasion'        => "'#{options[:auto_evasion] ? 'Yes' : 'No'}'",
      'Webhook'             => "'#{options[:webhook] || 'No'}'",
      'Loot Items'          => "'#{Dir.glob('loot/**/*').select { |f| File.file?(f) }.count} text / #{Dir.glob('loot/**/*.json').count} JSON'"
    }

    puts "\nAdditional Information:"
    info_cmds.each do |label, cmd|
      output = shell.run(cmd).output.strip
      puts "  #{label.ljust(25)} : #{output}"
    end

    # ---------- Flag scan ----------
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

      $paths += "C:\\flag.txt", "C:\\user.txt", "C:\\root.txt"

      foreach ($f in $paths) {
        if (Test-Path $f) {
          $c = Get-Content $f -Raw
          Write-Output "FLAGFOUND|||$f|||$c"
        }
      }
    POWERSHELL

    begin
      result = shell.run(ps)

      result.output.each_line do |line|
        next unless line.include?("FLAGFOUND|||")
        parts = line.strip.split("|||", 3)
        next unless parts.length == 3
        path, value = parts[1].strip, parts[2].strip

        puts "[+] Found flag: #{path}"
        puts value
        puts
      end
    rescue => e
      puts "[!] Flag scan failed: #{e.message}"
    end
  end
end
