# frozen_string_literal: true
require 'winrm' rescue nil

module EvilCTF
  module Connection
    # Build a WinRM::Connection (if available). Returns nil if WinRM not installed.
    def self.build(opts = {})
      return nil unless defined?(WinRM::Connection)
      endpoint = opts[:endpoint] || opts[:url]
      WinRM::Connection.new(endpoint: endpoint,
                            user: opts[:user],
                            password: opts[:password],
                            transport: opts[:transport] || :negotiate,
                            no_ssl_peer_verification: true)
    rescue => e
      nil
    end

    # Simple adapter to normalize shell.run results
    class WinRMShellAdapter
      ShellResult = Struct.new(:output, :exitcode)

      def initialize(shell)
        @shell = shell
      end

      def run(cmd)
        res = @shell.run(cmd)
        ShellResult.new(res.output.to_s, res.exitcode || 0)
      rescue => e
        ShellResult.new("ERROR: #{e.message}", 255)
      end

      def close
        @shell.close if @shell.respond_to?(:close)
      rescue
        nil
      end
    end
  end
end
