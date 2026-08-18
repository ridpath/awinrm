# frozen_string_literal: true

# lib/evil_ctf/session.rb
require_relative 'shell_wrapper'
require_relative 'banner'
require_relative 'tools'
require_relative 'uploader' # loads EvilCTF::Uploader
require_relative 'enums'
require_relative 'sql_enum'
require_relative 'connection'
require_relative 'connection_pool'
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
require 'ipaddr'
require 'yaml'
require 'fileutils'

module EvilCTF
  module Session
    # Alias for the uploader helper
    Uploader = EvilCTF::Uploader

    def self.test_connection(endpoint:, user:, password:, hash: nil, ssl: false,
                             kerberos: false, realm: nil, keytab: nil,
                             debug: false, transport: nil, user_agent: nil,
                             timeout: 10)
      conn = nil
      handed_to_pool = false
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
        if validation[:ok]
          # Hand the validated connection to the pool: run_session's
          # Bootstrap.build_connection acquires with the same parameters
          # and reuses it, so the session pays for one handshake instead
          # of two. A failed validation's connection is still closed in
          # the ensure block below.
          EvilCTF::ConnectionPool.register(conn, endpoint: endpoint, user: user, password: password,
                                                 hash: hash, kerberos: kerberos, realm: realm, keytab: keytab,
                                                 ssl: ssl, debug: debug, transport: transport,
                                                 user_agent: user_agent)
          handed_to_pool = true
          return validation
        end

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
      rescue StandardError => e
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
        # test_connection's connection is throwaway UNLESS validation
        # succeeded, in which case it was handed to the pool for the
        # session to reuse (closing it here would kill the session's
        # connection).
        unless handed_to_pool
          begin
            conn.close if conn.respond_to?(:close)
          rescue StandardError
            nil
          end
          begin
            conn.reset if conn.respond_to?(:reset)
          rescue StandardError
            nil
          end
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

      shell = nil
      heartbeat = nil
      conn = nil
      validation_info = nil
      begin
        # Centralized connection creation — inside the begin block so the
        # reconnect retry (below) re-acquires from the pool: the rescue
        # path evicts the dead connection first, so each attempt gets a
        # fresh one instead of retrying against a closed object.
        conn = Bootstrap.build_connection(session_options)
        unless conn
          puts '[!] ERROR - Could not create WinRM connection. Check your options and try again.'
          return [false, { ok: false, error: 'Could not create connection' }]
        end

        # Validate connection and capture validation info
        validation_info = Bootstrap.resolve_validation(conn, session_options)

        shell = conn.shell(:powershell)
        logger = SessionLogger.new(session_options[:logfile])
        session_options[:logger] = logger
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
        shell&.close
      rescue StandardError => e
        # Enhanced error handling for connection creation failures
        puts "[!] WARNING - Failed to create PowerShell session: #{e.class}: #{e.message}"
        puts '  This may indicate: network issues, firewall blocking, WinRM misconfig, or auth problems'

        # Attempt to reconnect if possible. The failed connection is dead
        # (that is why we are here): evict it from the pool so the retry
        # builds a fresh one, and tear down the half-broken shell and
        # heartbeat from this attempt — retry re-runs the begin block but
        # the ensure block only runs on final exit, so without this the
        # old shell/heartbeat would leak on every retry.
        if session_options[:reconnect_attempts].to_i.positive?
          puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
          begin
            heartbeat&.stop
          rescue StandardError
            nil
          end
          begin
            shell&.close
          rescue StandardError
            nil
          end
          EvilCTF::ConnectionPool.evict(conn) if defined?(conn) && conn
          sleep(5)
          session_options[:reconnect_attempts] -= 1
          retry
        else
          puts '[!] Maximum reconnection attempts reached. Exiting.'
          EvilCTF::ConnectionPool.evict(conn) if defined?(conn) && conn
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
        shell&.close
        # The session owns its connection for its lifetime; return it to
        # the pool's discard so multi-host loops and TUI flows do not
        # accumulate client connections (this also closes connections
        # that were never handed to the pool).
        EvilCTF::ConnectionPool.evict(conn) if defined?(conn) && conn
      end

      puts '[+] Session closed.'
      [true, validation_info]
    end

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------
    def self.normalize_host(host)
      ip_addr = IPAddr.new(host.split('%').first)
      ip_addr.ipv6? ? "[#{host.split('%')[0]}]" : host
    rescue IPAddr::InvalidAddressError
      host
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
        backup = "#{hosts_file}.evilctf.bak"
        FileUtils.cp(hosts_file, backup) unless File.exist?(backup)
        # Append entry
        File.open(hosts_file, 'a') { |f| f.puts entry }
        puts "[+] /etc/hosts updated: #{entry}"
      rescue Errno::EACCES, Errno::EPERM => e
        puts "[!] WARNING: Unable to modify /etc/hosts (permissions required): #{e.message}"
        puts '[!] Try running with sudo: sudo -E ./evil-ctf [args]'
        puts '[!] Continuing session anyway...'
      rescue StandardError => e
        puts "[!] WARNING: Failed to update /etc/hosts: #{e.message}"
        puts '[!] Continuing session anyway...'
      end
    end

    def self.setup_autocomplete(history)
      Readline.completion_append_character = ' '
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
      prompt = '> ' if prompt.empty? || prompt.include?('TIMED_OUT') || prompt.start_with?('ERROR:')
      prompt.end_with?(' ') ? prompt : "#{prompt} "
    end

    # Parse a hosts file of the form `ip:user:password[:hash]` (one per line).
    # The host field may be an IPv6 literal (which itself contains colons), so
    # candidate splits are validated before being accepted: the last three
    # fields are preferred as user/password/hash, falling back to treating the
    # last two fields as user/password.
    def self.parse_hosts_file(hosts_file)
      hosts = []
      return hosts unless File.exist?(hosts_file)

      File.readlines(hosts_file).each do |line|
        line.strip!
        next if line.empty? || line.start_with?('#')

        parsed = parse_host_line(line)
        if parsed
          hosts << parsed
        else
          puts "[!] Invalid host line: #{line}"
        end
      end
      hosts
    end

    def self.parse_host_line(line)
      parts = line.split(':')
      return nil if parts.size < 3

      # Prefer <host>|<user>|<password>|<hash>; fall back to <host>|<user>|<password>.
      [3, 2].each do |tail|
        next if parts.size < tail + 1

        host_candidate = parts[0, parts.size - tail].join(':')
        next unless valid_host_field?(host_candidate)

        user = parts[-tail]
        password = parts[-tail + 1]
        hash = tail == 3 ? parts[-1] : nil
        return { ip: host_candidate, user: user, password: password || '', hash: hash }
      end
      nil
    end

    def self.valid_host_field?(host)
      return false if host.nil? || host.empty?

      # Plain IPv4 / hostname never contains a colon; anything with a colon must
      # be a well-formed IPv6 literal (zone indices such as fd00::1%eth0 allowed).
      return true unless host.include?(':')

      IPAddr.new(host.split('%').first)
      true
    rescue IPAddr::InvalidAddressError
      false
    end
  end
end
