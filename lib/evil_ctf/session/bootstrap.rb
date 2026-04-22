# frozen_string_literal: true

module EvilCTF
  module Session
    module Bootstrap
      module_function

      def prepare_session_context(session_options)
        # Ensure reconnect_attempts is always an integer
        session_options[:reconnect_attempts] = session_options[:reconnect_attempts].to_i

        orig_ip = session_options[:ip]
        if orig_ip.match?(/:/)
          # Remove zone index if present (e.g., fd00::1%eth0)
          ipv6_addr = orig_ip.split('%')[0]
          host = "[#{ipv6_addr}]"
          EvilCTF::Session.add_ipv6_to_hosts(ipv6_addr)
        else
          host = EvilCTF::Session.normalize_host(orig_ip)
        end

        # Ensure port is set to WinRM default if missing or invalid
        if !session_options[:port] || session_options[:port].to_s.strip == '' || session_options[:port].to_i == 0
          session_options[:port] = session_options[:ssl] ? 5986 : 5985
        end

        scheme = session_options[:ssl] ? 'https' : 'http'
        endpoint = "#{scheme}://#{host}:#{session_options[:port]}/wsman"
        session_options[:endpoint] = endpoint
        EvilCTF::ShellWrapper.socksify!(session_options[:proxy]) if session_options[:proxy]

        { orig_ip: orig_ip, host: host, endpoint: endpoint }
      end

      def build_connection(session_options)
        EvilCTF::Connection.build_full(
          endpoint: session_options[:endpoint],
          user: session_options[:user],
          password: session_options[:password],
          hash: session_options[:hash],
          kerberos: session_options[:kerberos],
          realm: session_options[:realm],
          keytab: session_options[:keytab],
          ssl: session_options[:ssl],
          debug: session_options[:debug],
          transport: session_options[:transport],
          user_agent: session_options[:user_agent]
        )
      end

      def resolve_validation(conn, session_options)
        if session_options[:prevalidated] && session_options[:validation_info].is_a?(Hash)
          return session_options[:validation_info]
        end

        begin
          validation_info = EvilCTF::ConnectionValidator.validate(conn, timeout: 10)
          if validation_info[:ok]
            puts "[+] Connection validated: #{validation_info[:hostname]}"
          else
            puts "[!] Connection validation failed: #{validation_info[:error]}"
          end
          validation_info
        rescue StandardError => e
          { ok: false, hostname: nil, error: "Validation error: #{e.message}" }
        end
      end
    end
  end
end
