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


# Delegate all CLI parsing and execution to EvilCTF::CLI
exit EvilCTF::CLI.run(ARGV)

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
