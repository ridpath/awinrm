module EvilCTF::Enums
  def self.run_enumeration(shell, type: 'basic', cache: {}, fresh: false)
    if !fresh && cache[type]
      puts "[*] Using cached enumeration for #{type}"
      puts cache[type]
      return
    end

    puts "[*] Running #{type} enumeration..."
    
    cmds = case type.downcase
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
              'Get-ChildItem C:\\Users -Recurse -ErrorAction SilentlyContinue -Include *.txt,*.doc*,*.pdf*']
           else
             ['systeminfo']
           end

    output = ''
    cmds.each do |cmd|
      begin
        result = shell.run(cmd)
        output += "=== #{cmd} ===\n#{result.output}\n\n"
        
        # Save interesting outputs to loot directory for deeper enumeration
        if cmd =~ /password|secret|key|token/i || result.output =~ /password|secret|key|token|count: [0-9]+$/i
          save_enumeration_loot(cmd, result.output)
        end
      rescue => e
        puts "[!] Command failed (#{cmd}): #{e.message}"
        output += "=== #{cmd} ===\nERROR: #{e.message}\n\n"
      end
    end

    cache[type] = output if !fresh
    puts output
    
    # Summary for deep enumeration
    if type.downcase == 'deep'
      print_summary(output)
    end
  rescue => e
    puts "[!] Enumeration failed: #{e.message}"
  end

  private

  def self.save_enumeration_loot(cmd, output)
    return unless output && !output.strip.empty?
    
    FileUtils.mkdir_p('loot')
    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    
    # Clean filename
    clean_cmd = cmd.gsub(/[^a-zA-Z0-9]/, '_').downcase[0..30]
    loot_file = "loot/enum_#{clean_cmd}_#{timestamp}.txt"
    
    begin
      File.write(loot_file, "#{cmd}\n#{'='*50}\n\n#{output}")
      puts "[+] Saved enumeration results: #{loot_file}"
    rescue => e
      puts "[!] Failed to save loot: #{e.message}"
    end
  end

  def self.print_summary(output)
    lines = output.split("\n")
    
    # Count interesting findings
    users = lines.count { |l| l =~ /admin/i || l =~ /administrator/i }
    processes = lines.count { |l| l =~ /System\s+\s*\d+/i }
    services = lines.count { |l| l =~ /Running.*\d+/i }
    
    puts "\n" + "="*60
    puts "ENUMERATION SUMMARY".center(60)
    puts "="*60
    puts "Potential admin users found: #{users}"
    puts "System processes running: #{processes}"  
    puts "Services active: #{services}"
    puts "Loot files created: Check ./loot/ directory"
    puts "="*60
  end
end

