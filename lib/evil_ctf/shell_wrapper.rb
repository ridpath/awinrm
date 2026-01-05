# lib/evil_ctf/shell_wrapper.rb
require 'winrm'
require 'ipaddr'

module EvilCTF
  require 'colorize'
  module ShellWrapper
    # ---------- SOCKS support ----------
    def self.socksify!(proxy)
      return unless proxy

      begin
        host, port = proxy.split(':')
        TCPSocket.socks_server = host
        TCPSocket.socks_port = port.to_i if port && Integer(port) rescue false

        puts "[*] SOCKS proxy configured: #{host}:#{port}".colorize(:cyan)
      rescue => e
        puts "[!] WARNING - Failed to configure SOCKS proxy: #{e.message}".colorize(:yellow)
        puts " This may affect all subsequent connection attempts".colorize(:light_black)
      end
    end

    # ---------- Connection test ----------
    def self.test_connection(endpoint, user, pass, hash: nil, ssl: false)
      conn = EvilCTF::Connection.build_full(
        endpoint: endpoint,
        user: user,
        password: pass,
        hash: hash,
        ssl: ssl
      )
      unless conn
        puts "[!] WARNING - Could not create WinRM connection for test.".colorize(:yellow)
        return false
      end

      begin
        shell = conn.shell(:powershell)
        result = shell.run('hostname')
        success = !result.output.strip.empty?
        shell.close

        if success
          puts "[+] Connection test successful - #{endpoint} is accessible".colorize(:green)
        else
          puts "[!] WARNING - Connection test failed for #{endpoint}".colorize(:yellow)
          puts " Empty response received. This could indicate:".colorize(:light_black)
          puts " - Firewall blocking access".colorize(:light_black)
          puts " - WinRM service not properly configured".colorize(:light_black)
          puts " - Network connectivity issues".colorize(:light_black)
        end

        success
      rescue WinRM::WinRMEndpointError => e
        if e.message.include?('5985') || e.message.include?('5986')
          puts "[!] WARNING - Connection failed for #{endpoint}".colorize(:yellow)
          puts " Port #{e.message.split(':').last} (WinRM default) is not open".colorize(:light_black)
          puts " Check if WinRM service is running and ports are accessible".colorize(:light_black)
        else
          puts "[!] WARNING - Connection test failed: #{e.message}".colorize(:yellow)
          puts " This may indicate network connectivity issues or incorrect endpoint configuration".colorize(:light_black)
        end
        false
      rescue WinRM::WinRMAuthenticationError => e
        if user && pass
          puts "[!] WARNING - Authentication failed for #{user}@#{endpoint}".colorize(:yellow)
          puts " Invalid credentials provided. Try different username/password combinations".colorize(:light_black)
        else
          puts "[!] WARNING - Connection test failed with hash-based auth".colorize(:yellow)
          puts " Possible issues with the hash or Kerberos configuration".colorize(:light_black)
        end
        false
      rescue WinRM::WinRMTransportError => e
        if ssl && e.message.include?('SSL')
          puts "[!] WARNING - SSL connection failed for #{endpoint}".colorize(:yellow)
          puts " Check certificate validity and network connectivity".colorize(:light_black)
          puts " Try without SSL or with different certificate settings".colorize(:light_black)
        else
          puts "[!] WARNING - Connection test failed (transport error): #{e.message}".colorize(:yellow)
          puts " This may indicate network issues or incorrect transport configuration".colorize(:light_black)
        end
        false
      rescue WinRM::WinRMEndpointUnavailableError => e
        puts "[!] WARNING - Connection failed for #{endpoint}".colorize(:yellow)
        puts " WinRM service may not be running (check if HTTP/HTTPS listener is enabled)".colorize(:light_black)
      rescue WinRM::WinRMSessionError => e
        puts "[!] WARNING - Session creation failed for #{endpoint}".colorize(:yellow)
        puts " This may indicate issues with the PowerShell session setup".colorize(:light_black)
      rescue => e
        puts "[!] WARNING - Connection test failed: #{e.message}".colorize(:yellow)
        puts " This is a generic connection error. Check network connectivity and target system status".colorize(:light_black)
      end

      begin; conn.reset; rescue; end if defined?(conn) && conn.respond_to?(:reset)
    end

    # ---------- Create connection ----------
    def self.create_connection(endpoint, user, pass, hash: nil, ssl: false)
      EvilCTF::Connection.build_full(
        endpoint: endpoint,
        user: user,
        password: pass,
        hash: hash,
        ssl: ssl
      )
    end

    # ---------- Exit handling ----------
    def self.exit_session(shell)
      begin
        shell.close if shell
      rescue => e
        puts "[!] WARNING - shell.close failed: #{e.message}".colorize(:yellow)
      end
      :exit
    end
  end
end
