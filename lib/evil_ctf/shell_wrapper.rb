# lib/evil_ctf/shell_wrapper.rb

require 'winrm'
require 'ipaddr'

module EvilCTF::ShellWrapper
  # ---------- SOCKS support ----------
  def self.socksify!(proxy)
    return unless proxy
    
    begin
      host, port = proxy.split(':')
      TCPSocket.socks_server = host
      TCPSocket.socks_port   = port.to_i if port && Integer(port) rescue false
      
      puts "[*] SOCKS proxy configured: #{host}:#{port}"
    rescue => e
      puts "[!] Failed to configure SOCKS proxy: #{e.message}"
    end
  end

  # ---------- Connection test ----------
  def self.test_connection(endpoint, user, pass, hash: nil, ssl: false)
    conn = if hash
      WinRM::Connection.new(
        endpoint: endpoint,
        user:     user,
        password: '',
        transport: :negotiate,
        no_ssl_peer_verification: true,
        debug: false
      )
    else
      WinRM::Connection.new(
        endpoint: endpoint,
        user:     user,
        password: pass,
        no_ssl_peer_verification: true,
        debug: false
      )
    end

    begin
      shell = conn.shell(:powershell)
      
      # Test with a simple command that should always work
      result = shell.run('hostname')
      success = !result.output.strip.empty?
      
      shell.close
      
      if success
        puts "[+] Connection test successful"
      else
        puts "[-] Connection test failed - empty response"
      end
      
      success
    rescue => e
      puts "[!] Connection test failed: #{e.message}"
      false
    ensure
      begin; conn.reset; rescue; end if defined?(conn) && conn.respond_to?(:reset)
    end
  end

  # ---------- Create connection ----------
  def self.create_connection(endpoint, user, pass, hash: nil, ssl: false)
    options = {
      no_ssl_peer_verification: true,
      debug: false
    }
    
    if hash
      WinRM::Connection.new(
        endpoint: endpoint,
        user:     user,
        password: '',
        transport: :negotiate,
        **options
      )
    else
      WinRM::Connection.new(
        endpoint: endpoint,
        user:     user,
        password: pass,
        no_ssl_peer_verification: true,
        debug: false
      )
    end
  rescue => e
    puts "[!] Failed to create connection: #{e.message}"
    nil
  end
end
