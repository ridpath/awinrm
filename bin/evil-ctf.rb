#!/usr/bin/env ruby
# frozen_string_literal: true

# AWINRM CTF Edition

require 'optparse'
require 'winrm'
require 'ipaddr'
require 'socket'
require 'socksify'
require 'fileutils'
require 'timeout'
require 'base64'
require 'zip'
require 'yaml'
require 'open-uri'
require 'thread'
require 'net/http'
require 'json'
require 'uri'
require 'digest/sha1'
require 'readline'
require 'shellwords'
require 'tmpdir'
require 'concurrent'
require 'set'

Signal.trap('INT') do
  LOGGER&.warn("\nCtrl-C detected, exiting cleanly...") rescue nil
  $evil_ctf_should_exit = true
  # Force exit if we're in a blocking operation
  Thread.new { sleep(5); exit! } if defined?($evil_ctf_should_exit)
end


# Root namespace
module EvilCTF; end

# Set up lib path
base_path = File.expand_path(File.dirname(__FILE__) + '/..')
lib_path  = File.join(base_path, 'lib')
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

# Load modular components
require 'evil_ctf/session'
require 'evil_ctf/tools'
require 'evil_ctf/shell_wrapper'
require 'evil_ctf/banner'
require 'evil_ctf/enums'
require 'evil_ctf/uploader'
require 'evil_ctf/sql_enum'
require 'evil_ctf/logger'

# ---------------- Preflight Check ----------------
def run_preflight_check
  LOGGER&.info('[*] Running preflight check...')

  begin
    %w[loot profiles].each do |dir|
      unless Dir.exist?(dir)
        FileUtils.mkdir_p(dir)
        LOGGER&.info("[+] Created missing directory: #{dir}/")
      end
    end
  rescue => e
    LOGGER&.error("[!] Failed preflight check: #{e.message}")
    exit 1
  end
end

# ---------------- IPv6 Workaround ----------------
def add_ipv6_to_hosts(ip, hostname = 'ipv6addr')
  hosts_file = '/etc/hosts'
  entry = "#{ip} #{hostname}"
  return if File.exist?(hosts_file) && File.read(hosts_file).include?(entry)

  LOGGER&.info("[*] Adding IPv6 entry to #{hosts_file}: #{entry}")
  cmd = "echo '#{entry}' >> #{hosts_file}"

  if Process.uid == 0
    system(cmd)
  else
    system("sudo sh -c \"#{cmd}\"")
  end

  unless $?.success?
    LOGGER&.error("[!] Failed to add entry. Manually add: sudo echo '#{entry}' >> #{hosts_file}")
    exit 1
  end

  LOGGER&.info('[+] IPv6 entry added successfully')
end

# ---------------- Options ----------------
options = {
  ip: nil, user: nil, password: nil, hash: nil,
  port: 5985, ssl: false, auto_exec: false, stealth: false,
  random_names: false, auto_evasion: false, beacon: false,
  webhook: nil, logfile: nil, proxy: nil, profile: nil,
  list_tools: false, enum: nil, fresh: false, hosts: nil,
  kerberos: false, realm: nil, keytab: nil,
  banner_mode: :minimal  # NEW: Default to minimal banner for CTF
}

options[:debug] = false

OptionParser.new do |opts|
    opts.on('--user-agent AGENT', 'Custom User-Agent for WinRM HTTP requests') { |v| options[:user_agent] = v }
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
    options[:xor_key] = v.to_i(16) if v.start_with?('0x')                                                                                                                                                                
    options[:xor_key] = v.to_i unless v.start_with?('0x')                                                                                                                                                                
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
  opts.on('--banner MODE', 'Banner mode (minimal|expanded)')       { |v| options[:banner_mode] = v&.to_sym }  # NEW: Banner mode option
  opts.on('--debug', 'Enable WinRM debug output (passes debug:true to WinRM client)') { options[:debug] = true }
  opts.on('-h', '--help', 'Show help')                             { puts opts; exit }
end.parse!

# ---------------- Run Preflight ----------------
# Temporary logger until options/profile are merged
LOGGER = EvilCTF::Logger.new(nil)
run_preflight_check

# ---------------- Profile Load ----------------
if options[:profile]
  prof = EvilCTF::Session.load_config_profile(options[:profile])
  options = prof.merge(options)
end

# Initialize global logger instance
LOGGER = EvilCTF::Logger.new(options[:logfile])

# ---------------- Tool Listing ----------------
if options[:list_tools]
  EvilCTF::Tools.list_available_tools
  exit
end

# ---------------- Multi-host ----------------
if options[:hosts]
  LOGGER&.info("[*] Reading hosts file: #{options[:hosts]}")
  hosts = EvilCTF::Session.parse_hosts_file(options[:hosts])
  if hosts.empty?
    LOGGER&.error('[-] No valid hosts found')
    exit 1
  end
  LOGGER&.info("[*] Found #{hosts.size} host(s)")

  hosts.each_with_index do |host, idx|
    LOGGER&.info("\n#{'='*60}")
    LOGGER&.info("[*] Host #{idx+1}/#{hosts.size}: #{host[:ip]}")
    LOGGER&.info("#{'='*60}")

    add_ipv6_to_hosts(host[:ip].split('%').first, 'ipv6addr') if host[:ip].include?(':')

    session_options = options.dup.merge({
      ip: host[:ip], user: host[:user], password: host[:password], hash: host[:hash]
    })

    begin
      EvilCTF::Session.run_session(session_options)
    rescue => e
      LOGGER&.error("[!] Error with #{host[:ip]}: #{e.message}")
    end

    sleep(2) unless idx == hosts.size - 1
  end

  LOGGER&.info("\n[+] All sessions complete. Check ./loot/")
  exit
end

# ---------------- Validate Single-Host ----------------
%i[ip username].each do |k|
  abort "[-] Missing required --#{k}" unless options[k]
end

options[:user] = options[:username] if options[:username]

add_ipv6_to_hosts(options[:ip].split('%').first, 'ipv6addr') if options[:ip].include?(':')
# ---------------- Session Start ----------------
ok = EvilCTF::Session.run_session(options)
LOGGER&.info('[+] Session closed. Loot saved under ./loot/') if ok
