#!/usr/bin/env ruby
# Test the dashboard render with a mock shell
$LOAD_PATH.unshift(File.expand_path('../', __dir__))
require 'ostruct'
module EvilCTF; end unless defined?(EvilCTF)
require 'lib/evil_ctf/tui'

class MockShell
  def run(cmd)
    case cmd
    when 'hostname'
      OpenStruct.new(output: "WIN-CTF-01\n")
    when /whoami/
      OpenStruct.new(output: "WIN-CTF-01\\Administrator\n")
    when /systeminfo /
      OpenStruct.new(output: "OS Name:                   Microsoft Windows Server 2019 Standard\nOS Version:                10.0.17763 N/A Build 17763\n")
    else
      OpenStruct.new(output: "")
    end
  end
end

EvilCTF::TUI.render_dashboard(MockShell.new, {ip: '10.0.0.5', ssl: true})
