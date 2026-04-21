#!/usr/bin/env ruby
# Test non-interactive TUI rendering paths without launching interactive TTY.
$LOAD_PATH.unshift(File.expand_path('../', __dir__))
require 'ostruct'
module EvilCTF; end unless defined?(EvilCTF)
require 'lib/evil_ctf/tui'

class MockShell
  def run(cmd)
    normalized = cmd.to_s.downcase
    case normalized
    when /hostname/
      OpenStruct.new(output: "demo-host\n")
    when /windowsidentity/
      OpenStruct.new(output: "DEMO\\operator\n")
    when /systeminfo/
      OpenStruct.new(output: "OS Name: Microsoft Windows 11 Pro\nOS Version: 10.0.22631\n")
    else
      OpenStruct.new(output: "")
    end
  end
end

shell = MockShell.new

puts '[*] Rendering dashboard with mock shell state...'
EvilCTF::TUI.render_dashboard(shell, {
  host: 'demo-host',
  user: 'DEMO\\operator',
  os_info: 'OS Name: Microsoft Windows 11 Pro',
  connected: true,
  shell: 'PowerShell',
  ssl: false
})

puts '[*] Building fixed layout frame with mock flag lines...'
frame = EvilCTF::TUI.build_fixed_layout_lines(
  shell,
  { host: 'demo-host', connected: true, shell: 'PowerShell', ssl: false, remote_prompt: 'PS C:\\Users\\operator> ' },
  [],
  [
    'FLAGFOUND|||C:\\Users\\Alice\\Desktop\\flag.txt|||flag{demo}',
    'FLAGFOUND|||C:\\Users\\Bob\\Documents\\user.txt|||flag{bob}'
  ]
)

puts "[+] Built frame with #{frame[:lines].length} lines"
