# frozen_string_literal: true
require 'fileutils'

module EvilCTF
  class Logger
    def initialize(path = nil)
      @path = path
      @file = nil
      setup if @path
    end

    def setup
      FileUtils.mkdir_p(File.dirname(@path)) if @path && File.dirname(@path) != '.'
      @file = File.open(@path, 'a')
      @file.sync = true
      @file.puts "=== Session started: #{Time.now} ==="
    end

    def close
      return unless @file
      @file.close rescue nil
      @file = nil
    end

    def info(msg); puts "[+] #{msg}"; write(msg) end
    def warn(msg); puts "[!] #{msg}"; write(msg) end
    def error(msg); puts "[-] #{msg}"; write(msg) end

    def log_command(cmd, result, elapsed = nil, meta = {})
      write("[CMD] #{cmd} => exit=#{result&.exitcode} time=#{elapsed}")
    end

    private
    def write(msg)
      return unless @file
      @file.puts("[#{Time.now}] #{msg}")
    rescue
      nil
    end
  end
end
