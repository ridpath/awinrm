#!/usr/bin/env ruby
# frozen_string_literal: true

# AWINRM CTF Edition VERSION

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

Signal.trap('INT') { puts "\n[!] Ctrl-C detected, exiting cleanly..."; exit }

# Compatibility shim – define Fixnum for Ruby 3.x
class Fixnum < Integer; end unless defined?(Fixnum)

# Root namespace for all sub‑modules
module EvilCTF; end

# Determine base path
base_path = File.expand_path(File.dirname(__FILE__) + '/..')
lib_path = File.join(base_path, 'lib')
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

# Required modules
require 'evil_ctf/session'
require 'evil_ctf/tools'
require 'evil_ctf/shell_wrapper'
require 'evil_ctf/banner'
require 'evil_ctf/enums'
require 'evil_ctf/uploader'

# ---------------- Helper ----------------
def add_ipv6_to_hosts(ip, hostname = 'ipv6addr')
  hosts_file = '/etc/hosts'
  entry = "#{ip} #{hostname}"

  return if File.exist?(hosts_file) && File.read(hosts_file).include?(entry)

  puts "[*] Adding IPv6 entry to #{hosts_file}: #{entry}"
  cmd = "echo '#{entry}' >> #{hosts_file}"

  if Process.uid == 0
    system(cmd)
  else
    system("sudo sh -c \"#{cmd}\"")
  end

  unless $?.success?
    puts "[!] Failed to add entry to #{hosts_file}. Please add manually:\n  sudo echo '#{entry}' >> #{hosts_file}"
    exit 1
  end

  puts "[+] Entry added successfully"
end

# ---------------- Options ----------------
options = {
  ip: nil,
  user: nil,
  password: nil,
  hash: nil,
  port: 5985,
  ssl: false,
  auto_exec: false,
  stealth: false,
  random_names: false,
  auto_evasion: false,
  beacon: false,
  webhook: nil,
  logfile: nil,
  proxy: nil,
  profile: nil,
  list_tools: false,
  enum: nil,
  fresh: false,
  hosts: nil,
  kerberos: false,
  realm: nil,
  keytab: nil
}

OptionParser.new do |opts|
  opts.banner = 'Usage: evil-ctf.rb [options]'
  opts.on('-i', '--ip IP', 'Target IP / hostname') { |v| options[:ip] = v }
  opts.on('-u', '--user USER', 'Username') { |v| options[:user] = v }
  opts.on('-p', '--password PASS', 'Password') { |v| options[:password] = v }
  opts.on('-H', '--hash HASH', 'NTLM hash for pass-the-hash') { |v| options[:hash] = v }
  opts.on('--hosts FILE', 'File with multiple hosts') { |v| options[:hosts] = v }
  opts.on('--port PORT', Integer, 'Port (default 5985)') { |v| options[:port] = v }
  opts.on('--ssl', 'Use HTTPS (5986 typical)') { options[:ssl] = true }
  opts.on('--auto-exec', 'Auto-execute staged tools') { options[:auto_exec] = true }
  opts.on('--stealth', 'Use ADS staging + random names') do
    options[:stealth] = true
    options[:random_names] = true
  end
  opts.on('--random-names', 'Randomize tool filenames') { options[:random_names] = true }
  opts.on('--auto-evasion', 'Auto-disable Defender') { options[:auto_evasion] = true }
  opts.on('--beacon', 'Random sleep between commands') { options[:beacon] = true }
  opts.on('--webhook URL', 'Webhook for loot beacons') { |v| options[:webhook] = v }
  opts.on('--log FILE', 'Log commands/output to FILE') { |v| options[:logfile] = v }
  opts.on('--socks HOST:PORT', 'Use SOCKS proxy') { |v| options[:proxy] = v }
  opts.on('--profile NAME', 'Load YAML profile') { |v| options[:profile] = v }
  opts.on('--list-tools', 'List tools and exit') { options[:list_tools] = true }
  opts.on('--enum TYPE', 'Enumeration preset') { |v| options[:enum] = v }
  opts.on('--fresh', 'Bypass enum cache') { options[:fresh] = true }
  opts.on('-k', '--kerberos', 'Use Kerberos authentication') { options[:kerberos] = true }
  opts.on('--realm REALM', 'Kerberos realm') { |v| options[:realm] = v }
  opts.on('--keytab FILE', 'Keytab file') { |v| options[:keytab] = v }
  opts.on('-h', '--help', 'Show help') { puts opts; exit }
end.parse!

# ---------------- Load profile ----------------
if options[:profile]
  prof = EvilCTF::Session.load_config_profile(options[:profile])
  options = prof.merge(options)
end

# ---------------- Tool listing ----------------
if options[:list_tools]
  EvilCTF::Tools.list_available_tools
  exit
end

# ---------------- Multi-host support ----------------
if options[:hosts]
  puts "[*] Processing multiple hosts from: #{options[:hosts]}"
  hosts = EvilCTF::Session.parse_hosts_file(options[:hosts])
  if hosts.empty?
    puts "[-] No valid hosts found"
    exit 1
  end

  puts "[*] Found #{hosts.size} hosts"

  hosts.each_with_index do |host, idx|
    puts "\n#{'=' * 60}"
    puts "[*] Processing host #{idx + 1}/#{hosts.size}: #{host[:ip]}"
    puts "#{'=' * 60}"

    add_ipv6_to_hosts(host[:ip].split('%').first, 'ipv6addr') if host[:ip].match?(/:/)

    session_options = options.dup.merge({
      ip: host[:ip],
      user: host[:user],
      password: host[:password],
      hash: host[:hash]
    })

    begin
      EvilCTF::Session.run_session(session_options)
    rescue => e
      puts "[!] Session failed for #{host[:ip]}: #{e.message}"
    end

    sleep(2) unless idx == hosts.size - 1
  end

  puts "\n[+] All hosts processed. Loot saved under ./loot/"
  exit
end

# ---------------- Single-host validation ----------------
%i[ip user].each do |k|
  abort "[-] Missing required --#{k}" unless options[k]
end

unless options[:password] || options[:hash] || options[:kerberos]
  abort "[-] Must provide --password, --hash, or --kerberos"
end

add_ipv6_to_hosts(options[:ip].split('%').first, 'ipv6addr') if options[:ip].match?(/:/)

# ---------------- Run session ----------------
EvilCTF::Session.run_session(options)
puts '[+] Session closed. Loot saved under ./loot/'
