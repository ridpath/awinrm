#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'session'
require_relative 'connection'
require_relative 'staging'
require_relative '../config/profiles'

module EvilCTF
  module CLI
    def self.run(argv)
      require 'yaml'
      options = {
        ip: nil, user: nil, password: nil, hash: nil,
        port: nil, ssl: false, auto_exec: false, stealth: false,
        random_names: false, auto_evasion: false, beacon: false,
        webhook: nil, logfile: nil, proxy: nil, profile: nil,
        list_tools: false, enum: nil, fresh: false, hosts: nil,
        no_resume: false,
        kerberos: false, realm: nil, keytab: nil,
        banner_mode: :minimal, debug: false,
        ipv6: nil, ipv6_hostname: nil,
        staging_path: nil,
        verify: true
      }
      parser = OptionParser.new do |opts|
        opts.banner = 'Usage: evil-ctf.rb [options]'
        opts.on('-i', '--ip IP', 'Target IP / hostname') { |v| options[:ip] = v }
        opts.on('--ipv6 IP,HOSTNAME', Array, 'Add IPv6 address and hostname to /etc/hosts') do |v|
          options[:ipv6] = v[0] if v
          options[:ipv6_hostname] = v[1] if v
        end
        opts.on('-u', '--username USERNAME', 'Username')                 { |v| options[:username] = v }
        opts.on('-p', '--password PASSWORD', 'Password')                 { |v| options[:password] = v }
        opts.on('-H', '--hash HASH', 'NTLM hash')                        { |v| options[:hash] = v }
        opts.on('--hosts FILE', 'Multiple hosts file')                   { |v| options[:hosts] = v }
        opts.on('--port PORT', Integer, 'Port (default: 5985, or 5986 with --ssl)') { |v| options[:port] = v }
        opts.on('--ssl', 'Use HTTPS (5986 typical)')                     { options[:ssl] = true }
        opts.on('--auto-exec', 'Auto execute staged tools')              { options[:auto_exec] = true }
        opts.on('--stealth', 'Use ADS staging and random filenames') do
          options[:stealth] = true
          options[:random_names] = true
        end
        opts.on('--xor-key KEY', 'XOR encryption key (hex or decimal)') do |v|
          options[:xor_key] = v.start_with?('0x') ? v.to_i(16) : v.to_i
        end
        opts.on('--random-names', 'Randomize filenames') { options[:random_names] = true }
        opts.on('--staging-path DIR', 'Remote tool staging directory (default: C:\\Users\\Public)') { |v| options[:staging_path] = v }
        opts.on('--auto-evasion', 'Auto-disable Defender')               { options[:auto_evasion] = true }
        opts.on('--beacon', 'Add sleep delay between commands')          { options[:beacon] = true }
        opts.on('--webhook URL', 'Loot webhook URL')                     { |v| options[:webhook] = v }
        opts.on('--log FILE', 'Log command output')                      { |v| options[:logfile] = v }
        opts.on('--socks HOST:PORT', 'SOCKS proxy')                      { |v| options[:proxy] = v }
        opts.on('--profile NAME', 'Load profile from profiles/*.yaml')   { |v| options[:profile] = v }
        opts.on('--list-tools', 'List available tools and exit')         { options[:list_tools] = true }
        opts.on('--enum TYPE', 'Run enumeration (basic, deep, etc.)')    { |v| options[:enum] = v }
        opts.on('--fresh', 'Bypass enum cache and force re-staging of tools') { options[:fresh] = true }
        opts.on('--no-resume', 'Do not resume interrupted uploads (force re-upload from zero)') { options[:no_resume] = true }
        opts.on('-k', '--kerberos', 'Use Kerberos')                      { options[:kerberos] = true }
        opts.on('--realm REALM', 'Kerberos realm')                       { |v| options[:realm] = v }
        opts.on('--keytab FILE', 'Kerberos keytab')                      { |v| options[:keytab] = v }
        opts.on('--banner MODE', 'Banner mode (minimal|expanded)')       { |v| options[:banner_mode] = v&.to_sym }
        opts.on('--tui', 'Launch interactive TTY-based UI (uses tty gems)') { options[:tui] = true }
        opts.on('--user-agent AGENT', 'Custom User-Agent for WinRM HTTP requests') { |v| options[:user_agent] = v }
        opts.on('--log-session', 'Enable session logging to disk (log/ directory)') { options[:log_session] = true }
        opts.on('--debug', 'Enable WinRM debug output (passes debug:true to WinRM client)') { options[:debug] = true }
        opts.on('--no-verify', 'Skip connection validation') { options[:verify] = false }
        opts.on('-h', '--help', 'Show help') do
          puts opts
          exit 0
        end
      end

      parser.parse!(argv)

      # If --ipv6 is provided, add mapping to /etc/hosts and exit. Note that
      # OptionParser's Array type consumes a single comma-separated argument,
      # so the documented form is `--ipv6 IP,HOSTNAME`.
      if options[:ipv6]
        if options[:ipv6_hostname] && !options[:ipv6_hostname].to_s.empty?
          EvilCTF::Session.add_ipv6_to_hosts(options[:ipv6], options[:ipv6_hostname])
        else
          warn '[*] --ipv6 requires a hostname (comma-separated: --ipv6 IP,HOSTNAME)'
          return 1
        end
        exit 0
      end

      # Profile loading: merge profile if --profile is given

      if options[:profile]
        prof = EvilCTF::Config::Profiles.load_profile(
          name: options[:profile],
          root_path: File.expand_path('../..', __dir__)
        )
        if prof
          # Accept all keys from profile, including username, user, password, hash, port, ssl, etc.
          options.merge!(prof.transform_keys(&:to_sym))
        else
          warn "[!] Profile '#{options[:profile]}' not found in profiles/ or config/profiles.yaml."
        end
      end

      # Normalize username/user after merging profile and CLI
      options[:user] = options[:username] if options[:username]
      options[:username] = options[:user] if options[:user] && !options[:username]

      # Apply an optional custom staging directory (CLI --staging-path or a
      # staging_path: profile key). Everything remote derives from this.
      if options[:staging_path]
        begin
          EvilCTF::Staging.dir = options[:staging_path]
        rescue ArgumentError => e
          warn "[!] #{e.message}"
          return 1
        end
      end

      # Tool listing mode: print the catalog and exit without a session.
      if options[:list_tools]
        EvilCTF::Tools.list_available_tools
        return 0
      end

      # Multi-host mode: run a session per host from the hosts file.
      if options[:hosts]
        hosts = EvilCTF::Session.parse_hosts_file(options[:hosts])
        if hosts.empty?
          warn "[-] No valid hosts found in #{options[:hosts]}"
          return 1
        end
        warn "[*] Found #{hosts.size} host(s) in #{options[:hosts]}"
        hosts.each_with_index do |host, idx|
          warn "\n#{'=' * 60}"
          warn "[*] Host #{idx + 1}/#{hosts.size}: #{host[:ip]}"
          host_opts = options.dup
          host_opts[:ip] = host[:ip]
          host_opts[:user] = host[:user]
          host_opts[:username] = host[:user]
          host_opts[:password] = host[:password]
          host_opts[:hash] = host[:hash]
          host_opts.delete(:hosts)
          begin
            Session.run_session(host_opts)
          rescue StandardError => e
            warn "[!] Error with #{host[:ip]}: #{e.message}"
          end
          sleep(2) unless idx == hosts.size - 1
        end
        # Each run_session already evicts its connection at session end;
        # close_all catches anything left over (e.g. a failed host).
        EvilCTF::ConnectionPool.close_all
        warn "\n[+] All sessions complete. Check ./loot/"
        return 0
      end

      if options[:ip].nil? || options[:user].nil?
        puts parser
        return 1
      end

      # Connection validation before session
      if options[:verify]
        validation_port = options[:port] || (options[:ssl] ? 5986 : 5985)
        endpoint = options[:endpoint] || "#{options[:ssl] ? 'https' : 'http'}://#{options[:ip]}:#{validation_port}/wsman"
        validation = EvilCTF::Session.test_connection(
          endpoint: endpoint,
          user: options[:user],
          password: options[:password],
          hash: options[:hash],
          kerberos: options[:kerberos],
          realm: options[:realm],
          keytab: options[:keytab],
          ssl: options[:ssl],
          debug: options[:debug],
          transport: options[:transport],
          user_agent: options[:user_agent],
          timeout: 10
        )
        unless validation[:ok]
          puts "[!] Connection validation failed: #{validation[:error]}"
          puts validation[:report] if validation[:report]
          exit 1
        end
        options[:prevalidated] = true
        options[:validation_info] = validation
        puts "[+] Connection validated: #{validation[:hostname]}"
      end

      result = Session.run_session(options)

      # The session evicted its own connection at exit; close_all sweeps
      # anything else still pooled.
      EvilCTF::ConnectionPool.close_all

      # Check for validation failure from session
      if result.is_a?(Array) && !result[0]
        puts "[!] Session validation failed: #{result[1]}" if result[1]
        exit 1
      elsif !result
        puts '[!] Session failed'
        exit 1
      end
      0
    end
  end
end
