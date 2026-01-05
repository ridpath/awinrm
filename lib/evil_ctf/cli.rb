#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'session'

module EvilCTF
  module CLI
    def self.run(argv)
      options = {}
      parser = OptionParser.new do |opts|
        opts.banner = 'Usage: evil-ctf.rb [options]'
        opts.on('-i', '--ip IP', 'Target IP / hostname') { |v| options[:ip] = v }
        opts.on('-u', '--username USER', 'Username') { |v| options[:user] = v }
        opts.on('-p', '--password PASS', 'Password') { |v| options[:password] = v }
        opts.on('--user-agent AGENT', 'Custom User-Agent for WinRM HTTP requests') { |v| options[:user_agent] = v }
        opts.on('-h', '--help', 'Show help') { puts opts; exit 0 }
      end

      parser.parse!(argv)

      if options[:ip].nil? || options[:user].nil?
        puts parser
        return 1
      end

      Session.run_session(options)
      0
    end
  end
end
