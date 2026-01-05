# frozen_string_literal: true
require 'winrm' rescue nil


module EvilCTF
  module Connection
    # Centralized WinRM connection builder supporting all options and robust error handling
    # opts: endpoint, user, password, hash, kerberos, realm, keytab, ssl, debug, transport
    def self.build_full(opts = {})
      return nil unless defined?(WinRM::Connection)
      endpoint = opts[:endpoint] || opts[:url]
      user = opts[:user]
      pass = opts[:password]
      hash = opts[:hash]
      kerberos = opts[:kerberos]
      realm = opts[:realm]
      keytab = opts[:keytab]
      ssl = opts[:ssl]
      debug = opts[:debug]
      transport = opts[:transport]

      # Default port logic
      if endpoint.nil? && opts[:ip]
        port = opts[:port] || (ssl ? 5986 : 5985)
        scheme = ssl ? 'https' : 'http'
        endpoint = "#{scheme}://#{opts[:ip]}:#{port}/wsman"
      end

      options = {
        no_ssl_peer_verification: true,
        debug: !!debug
      }

      begin
        conn = if kerberos
          WinRM::Connection.new(
            endpoint: endpoint,
            user: user,
            password: '',
            transport: :kerberos,
            realm: realm,
            keytab: keytab,
            **options
          )
        elsif hash
          WinRM::Connection.new(
            endpoint: endpoint,
            user: user,
            password: '',
            transport: :negotiate,
            **options
          )
        else
          WinRM::Connection.new(
            endpoint: endpoint,
            user: user,
            password: pass,
            transport: transport || :negotiate,
            **options
          )
        end
        return conn
      rescue WinRM::WinRMEndpointError => e
        warn "[!] WARNING - Connection failed for #{endpoint} (endpoint error): #{e.message}"
      rescue WinRM::WinRMAuthenticationError => e
        warn "[!] WARNING - Authentication failed for #{user}@#{endpoint}: #{e.message}"
      rescue WinRM::WinRMTransportError => e
        warn "[!] WARNING - Transport error for #{endpoint}: #{e.message}"
      rescue WinRM::WinRMEndpointUnavailableError => e
        warn "[!] WARNING - Endpoint unavailable for #{endpoint}: #{e.message}"
      rescue WinRM::WinRMSessionError => e
        warn "[!] WARNING - Session creation failed for #{endpoint}: #{e.message}"
      rescue => e
        warn "[!] WARNING - Connection error for #{endpoint}: #{e.class}: #{e.message}"
      end
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
