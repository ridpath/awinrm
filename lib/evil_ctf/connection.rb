# frozen_string_literal: true
unless defined?(Fixnum)
  Fixnum = Integer
end

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
        no_ssl_peer_verification: !!opts[:ssl_no_verify],
        debug: !!debug
      }
      # Inject custom User-Agent if provided
      if opts[:user_agent]
        options[:http_client] = WinRM::HTTP::HttpTransport.new(endpoint, {})
        options[:http_client].instance_variable_get(:@httpcli).default_header['User-Agent'] = opts[:user_agent]
      end

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
      rescue => e
        # The WinRM gem defines several specific exception classes across
        # versions; to avoid uninitialized constant errors on older/newer
        # versions and Ruby 3 compatibility issues, catch all errors here
        # and give a concise warning message.
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

  # Validator class for testing WinRM connection validity
  class ConnectionValidator
    def self.validate(conn, timeout: 5)
      shell = nil
      result = nil
      validation_result = nil

      begin
        shell = conn.shell(:powershell)
        result = shell.run("hostname", timeout: timeout)
        hostname = result.output.to_s.strip

        validation_result = { ok: true, hostname: hostname }
      rescue WinRM::WinRMAuthenticationError => e
        validation_result = { ok: false, hostname: nil, error: "AuthenticationError: #{e.message}" }
      rescue WinRM::WinRMEndpointError => e
        validation_result = { ok: false, hostname: nil, error: "EndpointError: #{e.message}" }
      rescue WinRM::WinRMAuthorizationError => e
        validation_result = { ok: false, hostname: nil, error: "AuthorizationError: #{e.message}" }
      rescue => e
        validation_result = { ok: false, hostname: nil, error: "#{e.class}: #{e.message}" }
      ensure
        shell&.close
        begin
          conn.close if conn.respond_to?(:close)
        rescue
          nil
        end
        begin
          conn.reset if conn.respond_to?(:reset)
        rescue
          nil
        end
      end

      validation_result
    end
  end
end
