#!/usr/bin/env ruby
require 'bundler/setup'
require 'winrm'

endpoint = 'http://192.168.0.143:5985/wsman'
user = 'jabbatheduck'
pass = '3litehax0r'

puts "[DEBUG] Creating WinRM connection to #{endpoint} (user=#{user})"
conn = WinRM::Connection.new(endpoint: endpoint,
                             user: user,
                             password: pass,
                             no_ssl_peer_verification: true,
                             debug: true)

begin
  shell = conn.shell(:powershell)
  puts '[DEBUG] Running hostname on remote...'
  res = shell.run('hostname')
  puts "[RESULT] exit=#{res.exitcode} output=#{res.output.strip}"
  shell.close
rescue => e
  puts "[ERROR] #{e.class}: #{e.message}"
  puts e.backtrace.join("\n")
ensure
  begin; conn.reset; rescue; end
end
