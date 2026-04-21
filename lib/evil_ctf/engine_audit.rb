# frozen_string_literal: true

require 'fileutils'
require 'time'

module EvilCTF
  module EngineAudit
    LOG_PATH = File.expand_path('../../log/engine_audit.log', __dir__)

    module_function

    def info(message:, source: 'engine')
      write(level: 'INFO', source: source, message: message)
    end

    def error(message:, error: nil, source: 'engine')
      lines = [message.to_s]
      if error
        lines << "#{error.class}: #{error.message}"
        lines.concat(Array(error.backtrace))
      end
      write(level: 'ERROR', source: source, message: lines.join("\n"))
    end

    def write(level:, source:, message:)
      FileUtils.mkdir_p(File.dirname(LOG_PATH))
      File.open(LOG_PATH, 'a') do |f|
        f.puts("[#{Time.now.utc.iso8601}] [#{level}] [#{source}] #{message}")
      end
    rescue StandardError
      nil
    end
  end
end
