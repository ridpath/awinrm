# lib/evil_ctf/enums.rb
require_relative 'sql_enum'
module EvilCTF::Enums
  def self.presets
    {
      'basic' => ->(shell, _) { run_enumeration(shell, type: 'basic') },
      'network' => ->(shell, _) { run_enumeration(shell, type: 'network') },
      'privilege' => ->(shell, _) { run_enumeration(shell, type: 'privilege') },
      'av_check' => ->(shell, _) { run_enumeration(shell, type: 'av_check') },
      'persistence' => ->(shell, _) { run_enumeration(shell, type: 'persistence') },
      'deep' => ->(shell, _) { run_enumeration(shell, type: 'deep') },
      'sql' => ->(shell, _) { EvilCTF::SQLEnum.run_sql_enum(shell) }
    }
  end

  def self.run_enum(shell, type, options = {})
    preset = presets[type.to_s]
    if preset
      preset.call(shell, options)
    else
      puts "[!] Unknown enum type: #{type}"
    end
  end

  def self.run_enumeration(shell, type: 'basic', cache: {}, fresh: false)
    if !fresh && cache[type]
      puts "[*] Using cached enumeration for #{type}"
      puts cache[type]
      return
    end
    
    puts "[*] Running #{type} enumeration..."
    
    # Use a more compact approach similar to winPEAS.bat's structure
    cmds = case type
           when 'basic'
             ['whoami /all', 'net user', 'systeminfo']
           when 'network'
             ['ipconfig /all',
              'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,State,OwningProcess',
              'netstat -ano']
           when 'privilege'
             ['whoami /priv',
              'net localgroup Administrators',
              'Get-WmiObject Win32_Service | Where-Object {$_.StartName -notmatch "LocalSystem"}']
           when 'av_check'
             ['Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled',
              'Get-Service WinDefend']
           when 'persistence'
             ['schtasks /query /fo LIST /v',
              'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
              'Get-WmiObject -Namespace root\\subscription -Class __EventFilter']
           when 'deep'
             [
               # Simplified deep enumeration focused on key areas
               'whoami /all',
               'systeminfo',
               'net user',
               'net localgroup Administrators',
               'Get-Process | Select-Object Name,Id,Path',
               'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name,DisplayName,StartMode,Status',
               'Get-WmiObject Win32_Product | Select-Object Name,Version,InstallDate'
             ]
           when 'dom'
             [
               'Get-Domain',
               'Get-DomainController',
               'Get-DomainUser',
               'Get-DomainGroup',
               'Get-DomainComputer'
             ]
           else
             ['systeminfo']
           end

    output = ''
    
    # Process commands with better error handling and progress tracking (similar to winPEAS.bat approach)
    cmds.each_with_index do |cmd, index|
      begin
        result = shell.run(cmd)
        header = cmd.is_a?(String) ? cmd[0..80] : cmd.to_s[0..80]
        output += "=== #{header} ===\n#{result.output}\n\n"
      rescue => e
        output += "=== Error in #{cmd[0..80]} ===\n[!] Enumeration command failed: #{e.message}\n\n"
      end
    end
    
    cache[type] = output
    puts output
  end
end
