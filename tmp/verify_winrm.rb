#!/usr/bin/env ruby
require 'bundler/setup'
require 'winrm'
require_relative '../lib/evil_ctf/shell_adapter'
require_relative '../lib/evil_ctf/uploader'

HOST = '192.168.0.143'
USER = 'jabbatheduck'
PASS = '3litehax0r'

endpoint = "http://#{HOST}:5985/wsman"

conn = WinRM::Connection.new(endpoint: endpoint, user: USER, password: PASS, no_ssl_peer_verification: true)
begin
  shell = conn.shell(:powershell)
  puts "Connected. Running hostname..."
  res = shell.run('hostname')
  puts "hostname => exit=#{res.exitcode} output=#{res.output.strip}"

  # small upload test
  local = 'tmp/verify_upload.txt'
  File.write(local, "verify #{Time.now}\n")
  remote = 'C:\Users\Public\verify_upload.txt'
  puts "Uploading #{local} -> #{remote}"
  ok = EvilCTF::Uploader.upload_file(local, remote, shell, verify: true)
  puts "upload result: #{ok.inspect}"
ensure
  shell.close if shell
  begin; conn.reset; rescue; end
end
