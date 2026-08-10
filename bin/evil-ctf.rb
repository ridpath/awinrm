#!/usr/bin/env ruby
# frozen_string_literal: true

# AWINRM CTF Edition — launcher.
# All CLI parsing and execution lives in EvilCTF::CLI so behaviour stays
# in one place (see lib/evil_ctf/cli.rb). This file only sets up the load
# path and delegates.

require 'English'
require 'optparse'
require_relative '../lib/compat/silence_warnings'
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
require 'net/http'
require 'json'
require 'uri'
require 'digest/sha1'
require 'readline'
require 'shellwords'
require 'tmpdir'
require 'concurrent'

# Root namespace
module EvilCTF; end

# Set up lib path
base_path = File.expand_path("#{File.dirname(__FILE__)}/..")
lib_path  = File.join(base_path, 'lib')
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

# Auto-setup Bundler when the user requested the TUI so gems from
# `vendor/bundle` are available even when running with plain `ruby`.
if ARGV.any? { |a| a.to_s.start_with?('--tui') }
  begin
    require 'bundler/setup'
  rescue LoadError
    # bundler not available system-wide; user can run with `bundle exec` instead
  end
end

# Graceful Ctrl-C: ask the session to exit, force-kill if it is stuck.
Signal.trap('INT') do
  warn "\nCtrl-C detected, exiting cleanly..."
  $evil_ctf_should_exit = true
  Thread.new do
    sleep(5)
    exit!
  end
end

require 'evil_ctf/cli'

exit EvilCTF::CLI.run(ARGV)
