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
             ['ipconfig /all', 
              'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,State,OwningProcess',
              'Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Protocol,LocalPort,Action',
              'netstat -ano',
              'route print',
              'arp -a']
           when 'privilege'
             ['whoami /priv', 
              'whoami /groups',
              'net localgroup Administrators',
              'Get-NetUser | Where-Object {$_.Privilege -match "Se.*"}',
              'Get-WmiObject Win32_Service | Where-Object {$_.StartName -notmatch "LocalSystem"}']
           when 'av_check'
             ['Get-MpComputerStatus', 
              'Get-MpPreference',
              'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled',
              'Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionIpAddress',
              'Get-Service WinDefend']
           when 'persistence'
             ['schtasks /query /fo LIST /v', 
              'Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
              'Get-WmiObject -Namespace root\subscription -Class __EventFilter',
              'Get-ChildItem C:\\Users\\Public\\Start Menu\\Programs\\Startup',
              'Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.State -eq "Running"}']
           when 'deep'
             ['Get-Process | Select-Object Name,Id,Path,WorkingSet',
              'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name,DisplayName,StartMode,Status',
              'Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime',
              'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,State,OwningProcess',
              'Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Protocol,LocalPort,Action',
              'Get-WmiObject Win32_Product | Select-Object Name,Version,InstallDate',
              # Add winpeas execution to deep enumeration
              <<~PS]
                try {
                  $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                  $outputFile = "C:\\Users\\Public\\winpeas_output_$timestamp.txt"
                  
                  Write-Output "[*] Starting WinPeas enumeration at $(Get-Date)" | Out-File -FilePath $outputFile -Append
                  Write-Output "[*] Target: $env:COMPUTERNAME" | Out-File -FilePath $outputFile -Append
                  
                  # Run winpeas64 if available, otherwise winpeas
                  if (Test-Path "C:\\Users\\Public\\winPEAS.exe") {
                    & "C:\\Users\\Public\\winPEAS.exe" --no-color 2>&1 | Tee-Object -FilePath $outputFile -Append
                  } else {
                    Write-Output "[!] WinPeas not found on target"
                  }
                  
                  Write-Output "[*] WinPeas completed at $(Get-Date)" | Out-File -FilePath $outputFile -Append
                  Write-Output "[*] Results saved to: $outputFile" | Out-File -FilePath $outputFile -Append
                  
                  # Read and output the results for immediate viewing
                  if (Test-Path $outputFile) {
                    Get-Content $outputFile
                  } else {
                    Write-Output "Error: Could not find output file"
                  }
                } catch {
                  Write-Output "[!] Error running WinPeas: $($_.Exception.Message)"
                }
              PS
           else
             ['systeminfo']
           end

    output = ''
    cmds.each do |cmd|
      if cmd.is_a?(String) && cmd.include?('WinPeas')
        # Special handling for winpeas command
        result = shell.run(cmd)
        output += "=== WinPeas Execution ===\n#{result.output}\n\n"
      else
        result = shell.run(cmd)
        output += "=== #{cmd} ===\n#{result.output}\n\n"
      end
    end

    cache[type] = output
    puts output
  end
end
