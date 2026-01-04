# frozen_string_literal: true
require 'fileutils'

module EvilCTF
  class Logger
    def initialize(path = nil)
      @path = path
      setup if @path
    end

    def setup
      FileUtils.mkdir_p(File.dirname(@path)) if @path && File.dirname(@path) != '.'
      File.open(@path, 'a') { |f| f.puts "=== Session started: #{Time.now} ===" }
    end

    def info(msg); puts "[+] #{msg}"; write(msg) end
    def warn(msg); puts "[!] #{msg}"; write(msg) end
    def error(msg); puts "[-] #{msg}"; write(msg) end

    def log_command(cmd, result, elapsed = nil, meta = {})
      write("[CMD] #{cmd} => exit=#{result&.exitcode} time=#{elapsed}")
    end

    private
    def write(msg)
      return unless @path
      File.open(@path, 'a') { |f| f.puts("[#{Time.now}] #{msg}") }
    rescue
      nil
    end
  end
end
