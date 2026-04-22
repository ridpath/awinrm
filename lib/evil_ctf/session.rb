
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
require_relative 'session_heartbeat'
require_relative 'session/log_channels'
require_relative 'session/interactive_loop'
require_relative 'session/bootstrap'
require_relative 'session/runtime_setup'
require_relative 'session/session_logger'
require_relative 'session/command_history'
require_relative 'engine_audit'
require 'readline'
require 'timeout'
require 'evil_ctf/uploader'
require 'ipaddr'
require 'yaml'
require 'fileutils'

module EvilCTF::Session
  # Alias for the uploader helper
  Uploader = EvilCTF::Uploader

  def self.test_connection(endpoint:, user:, password:, hash: nil, ssl: false,
                           kerberos: false, realm: nil, keytab: nil,
                           debug: false, transport: nil, user_agent: nil,
                           timeout: 10)
    conn = nil
    begin
      conn = EvilCTF::Connection.build_full(
        endpoint: endpoint,
        user: user,
        password: password,
        hash: hash,
        kerberos: kerberos,
        realm: realm,
        keytab: keytab,
        ssl: ssl,
        debug: debug,
        transport: transport,
        user_agent: user_agent
      )
      return { ok: false, error: "Could not create connection for #{endpoint}" } unless conn

      validation = EvilCTF::ConnectionValidator.validate(conn, timeout: timeout)
      return validation if validation[:ok]

      report = nil
      if validation[:error].to_s.match?(/wrong number of arguments|unknown keyword|no keywords accepted|given \d+, expected \d+/i)
        report = ruby40_compatibility_report(
          endpoint: endpoint,
          operation: 'ConnectionValidator.validate',
          detail: validation[:error]
        )
      end
      validation.merge(report: report)
    rescue ArgumentError => e
      report = ruby40_compatibility_report(
        endpoint: endpoint,
        operation: 'Session.test_connection',
        detail: e.message
      )
      { ok: false, error: e.message, report: report }
    rescue => e
      if defined?(WinRM::WinRMHTTPTransportError) && e.is_a?(WinRM::WinRMHTTPTransportError)
        return {
          ok: false,
          error: "HTTP transport error: #{e.message}",
          report: ruby40_compatibility_report(
            endpoint: endpoint,
            operation: 'WinRM HTTP transport',
            detail: e.message
          )
        }
      end

      { ok: false, error: "#{e.class}: #{e.message}" }
    ensure
      # test_connection creates a throwaway connection used only for validation.
      begin
        conn.close if conn && conn.respond_to?(:close)
      rescue
        nil
      end
      begin
        conn.reset if conn && conn.respond_to?(:reset)
      rescue
        nil
      end
    end
  end

  def self.ruby40_compatibility_report(endpoint:, operation:, detail:)
    <<~REPORT
      Ruby 4.0 Compatibility Report
      - Endpoint: #{endpoint}
      - Operation: #{operation}
      - Ruby: #{RUBY_VERSION}
      - Detail: #{detail}
      - Suggestion: verify all call sites use keyword arguments only and ensure winrm/winrm-fs are loaded from bundle exec context.
    REPORT
  end

  # ------------------------------------------------------------------
  # Main session loop & command handling
  # ------------------------------------------------------------------
  def self.run_session(session_options)
    context = Bootstrap.prepare_session_context(session_options)
    orig_ip = context[:orig_ip]
    host = context[:host]
    puts "[*] Testing connection to #{orig_ip} (using #{host} in endpoint...)"

    # --- Session Logging Setup ---
    session_logs = LogChannels.setup(session_options)

    # Centralized connection creation
    conn = Bootstrap.build_connection(session_options)
    unless conn
      puts "[!] ERROR - Could not create WinRM connection. Check your options and try again."
      return [false, { ok: false, error: 'Could not create connection' }]
    end

    # Validate connection and capture validation info
    validation_info = Bootstrap.resolve_validation(conn, session_options)

    shell = nil
    heartbeat = nil
    begin
      shell = conn.shell(:powershell)
      logger = SessionLogger.new(session_options[:logfile])
      history = CommandHistory.new
      command_manager = EvilCTF::Tools::CommandManager.new

      runtime_state = RuntimeSetup.prepare(
        shell: shell,
        session_options: session_options,
        history: history,
        logger: logger,
        orig_ip: orig_ip
      )
      heartbeat = runtime_state[:heartbeat]
      prompt_cache = runtime_state[:prompt_cache]

      return [true, validation_info] if runtime_state[:tui_exited]

      puts "Type 'help' for commands, '__exit__' or 'exit' to quit, or !bash for local shell.\n\n"

      InteractiveLoop.run(
        shell: shell,
        prompt_cache: prompt_cache,
        history: history,
        command_manager: command_manager,
        session_options: session_options,
        logger: logger,
        session_logs: session_logs
      )

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
      begin
        heartbeat&.stop
      rescue StandardError => e
        EvilCTF::EngineAudit.error(message: 'failed to stop heartbeat', error: e, source: 'session')
      end
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

  # Normalize remote prompt output so Readline renders correctly.
  # - Converts literal "\\n" sequences into real newlines.
  # - Collapses CRLF/CR variations to LF.
  # - Trims trailing newlines and ensures a trailing space for cursor alignment.
  def self.normalize_readline_prompt(raw_prompt)
    prompt = raw_prompt.to_s
    prompt = prompt.gsub('\\r\\n', "\n").gsub('\\n', "\n")
    prompt = prompt.gsub("\r\n", "\n").gsub("\r", "\n")
    prompt = prompt.rstrip
    if prompt.empty? || prompt.include?('TIMED_OUT') || prompt.start_with?('ERROR:')
      prompt = '> '
    end
    prompt.end_with?(' ') ? prompt : "#{prompt} "
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

end
