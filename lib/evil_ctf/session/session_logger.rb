# frozen_string_literal: true

require 'fileutils'

module EvilCTF
  module Session
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
  end
end
