#!/usr/bin/env ruby
# Test the TUI's flag-scan helper without launching interactive TTY.
$LOAD_PATH.unshift(File.expand_path('../', __dir__))
require 'ostruct'
module EvilCTF; end unless defined?(EvilCTF)
require 'lib/evil_ctf/tui'

class MockShell
  def run(cmd)
    # Simulate optimized flag-scan output
    if cmd.include?('Write-Output "FLAGFOUND') || cmd.include?('Get-ChildItem')
      OpenStruct.new(output: "FLAGFOUND|||C:\\Users\\Alice\\Desktop\\flag.txt|||flag{demo}\nFLAGFOUND|||C:\\Users\\Bob\\Documents\\user.txt|||flag{bob}\n")
    else
      OpenStruct.new(output: "")
    end
  end
end

rows = EvilCTF::TUI.run_flag_scan(MockShell.new)
puts "Found rows:"
puts rows.inspect
