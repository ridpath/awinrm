# frozen_string_literal: true

require 'fileutils'

module EvilCTF
  module Session
    module LogChannels
      module_function

      def setup(session_options)
        return {} unless session_options[:log_session]

        log_dir = File.expand_path('../../../log', __dir__)
        FileUtils.mkdir_p(log_dir)
        ts = Time.now.strftime('%Y%m%d-%H%M%S')
        ip_or_host = (session_options[:ip] || 'unknown').gsub(/[^\w\.-]/, '_')
        session_logs = {
          operator: File.join(log_dir, "operator-#{ip_or_host}-#{ts}.log"),
          telemetry: File.join(log_dir, "telemetry-#{ip_or_host}-#{ts}.log"),
          loot: File.join(log_dir, "loot-events-#{ip_or_host}-#{ts}.log")
        }
        session_options[:session_logs] = session_logs

        session_logs.each do |channel, path|
          File.open(path, 'a') do |f|
            f.puts "=== EvilCTF #{channel.to_s.capitalize} Log ==="
            f.puts "Host: #{session_options[:ip]}"
            f.puts "User: #{session_options[:user]}"
            f.puts "Started: #{Time.now}"
            f.puts '================================'
          end
        end

        session_logs
      end

      def append(path, tag, payload)
        return if path.nil?

        File.open(path, 'a') do |f|
          f.puts "\n[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] #{tag}"
          f.puts payload.to_s
        end
      rescue StandardError => e
        EvilCTF::EngineAudit.error(message: "failed to append #{tag} log", error: e, source: 'session')
      end
    end
  end
end
