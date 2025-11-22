# lib/evil_ctf/enums.rb

module EvilCTF::Enums
  def self.run_enumeration(shell, type: 'basic', cache: {}, fresh: false)
    if !fresh && cache[type]
      puts "[*] Using cached enumeration for #{type}"
      puts cache[type]
      return
    end

    puts "[*] Running #{type} enumeration..."
    cmds = case type
           when 'basic'
             ['whoami /all', 'net user', 'net group', 'systeminfo', 'ipconfig /all']
           when 'network'
             ['ipconfig /all', 'netstat -ano', 'route print', 'arp -a']
           when 'privilege'
             ['whoami /priv', 'whoami /groups', 'net localgroup Administrators']
           when 'av_check'
             ['Get-MpComputerStatus', 'Get-MpPreference']
           when 'persistence'
             ['schtasks /query /fo LIST /v', 'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"']
           when 'deep'
             ['Get-Process | Select-Object Name,Id,Path',
              'Get-Service | Where-Object {$_.Status -eq "Running"}',
              'Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length']
           else
             ['systeminfo']
           end

    output = ''
    cmds.each do |cmd|
      result = shell.run(cmd)
      output += "=== #{cmd} ===\n#{result.output}\n\n"
    end

    cache[type] = output
    puts output
  end
end
