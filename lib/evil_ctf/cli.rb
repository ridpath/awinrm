#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'session'

module EvilCTF
  module CLI
    def self.run(argv)
      require 'yaml'
      options = {
        ip: nil, user: nil, password: nil, hash: nil,
        port: 5985, ssl: false, auto_exec: false, stealth: false,
        random_names: false, auto_evasion: false, beacon: false,
        webhook: nil, logfile: nil, proxy: nil, profile: nil,
        list_tools: false, enum: nil, fresh: false, hosts: nil,
        kerberos: false, realm: nil, keytab: nil,
        banner_mode: :minimal, debug: false
      }
      parser = OptionParser.new do |opts|
        opts.banner = 'Usage: evil-ctf.rb [options]'
        opts.on('-i', '--ip IP', 'Target IP / hostname')                  { |v| options[:ip] = v }
        opts.on('-u', '--username USERNAME', 'Username')                 { |v| options[:username] = v }
        opts.on('-p', '--password PASSWORD', 'Password')                 { |v| options[:password] = v }
        opts.on('-H', '--hash HASH', 'NTLM hash')                        { |v| options[:hash] = v }
        opts.on('--hosts FILE', 'Multiple hosts file')                   { |v| options[:hosts] = v }
        opts.on('--port PORT', Integer, 'Port (default: 5985)')          { |v| options[:port] = v }
        opts.on('--ssl', 'Use HTTPS (5986 typical)')                     { options[:ssl] = true }
        opts.on('--auto-exec', 'Auto execute staged tools')              { options[:auto_exec] = true }
        opts.on('--stealth', 'Use ADS staging and random filenames') do
          options[:stealth] = true
          options[:random_names] = true
        end
        opts.on('--xor-key KEY', 'XOR encryption key (hex or decimal)') do |v|
          options[:xor_key] = v.start_with?('0x') ? v.to_i(16) : v.to_i
        end
        opts.on('--random-names', 'Randomize filenames')                 { options[:random_names] = true }
        opts.on('--auto-evasion', 'Auto-disable Defender')               { options[:auto_evasion] = true }
        opts.on('--beacon', 'Add sleep delay between commands')          { options[:beacon] = true }
        opts.on('--webhook URL', 'Loot webhook URL')                     { |v| options[:webhook] = v }
        opts.on('--log FILE', 'Log command output')                      { |v| options[:logfile] = v }
        opts.on('--socks HOST:PORT', 'SOCKS proxy')                      { |v| options[:proxy] = v }
        opts.on('--profile NAME', 'Load profile from profiles/*.yaml')   { |v| options[:profile] = v }
        opts.on('--list-tools', 'List available tools and exit')         { options[:list_tools] = true }
        opts.on('--enum TYPE', 'Run enumeration (basic, deep, etc.)')    { |v| options[:enum] = v }
        opts.on('--fresh', 'Bypass enum cache')                          { options[:fresh] = true }
        opts.on('-k', '--kerberos', 'Use Kerberos')                      { options[:kerberos] = true }
        opts.on('--realm REALM', 'Kerberos realm')                       { |v| options[:realm] = v }
        opts.on('--keytab FILE', 'Kerberos keytab')                      { |v| options[:keytab] = v }
        opts.on('--banner MODE', 'Banner mode (minimal|expanded)')       { |v| options[:banner_mode] = v&.to_sym }
        opts.on('--user-agent AGENT', 'Custom User-Agent for WinRM HTTP requests') { |v| options[:user_agent] = v }
        opts.on('--log-session', 'Enable session logging to disk (log/ directory)') { options[:log_session] = true }
        opts.on('--debug', 'Enable WinRM debug output (passes debug:true to WinRM client)') { options[:debug] = true }
        opts.on('-h', '--help', 'Show help')                             { puts opts; exit 0 }
      end

      parser.parse!(argv)

      # Profile loading: merge profile if --profile is given

      if options[:profile]
        prof = nil
        # Try profiles/NAME.yaml first, then config/profiles.yaml
        prof_path1 = File.expand_path("../../profiles/#{options[:profile]}.yaml", __dir__)
        prof_path2 = File.expand_path("../../config/profiles.yaml", __dir__)
        if File.exist?(prof_path1)
          prof = YAML.load_file(prof_path1)
        elsif File.exist?(prof_path2)
          all_profiles = YAML.load_file(prof_path2)
          prof = all_profiles[options[:profile].to_s] if all_profiles
        end
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

      if options[:ip].nil? || options[:user].nil?
        puts parser
        return 1
      end

      Session.run_session(options)
      0
    end
  end
end
