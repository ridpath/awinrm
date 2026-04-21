#!/usr/bin/env ruby
# Demo script to run the TUI demo mode without a live session
begin
  require 'bundler/setup'
rescue LoadError
  # ignore if bundler/setup not available
end
require_relative '../lib/evil_ctf/tui'

# Minimal mock shell for interactive TUI demos without WinRM.
class DemoMockShell
  Result = Struct.new(:exitcode, :output)

  def run(cmd)
    normalized = cmd.to_s.strip

    case normalized
    when /^hostname$/i
      Result.new(0, "demo-host\n")
    when /WindowsIdentity\]::GetCurrent\(\)\.Name/i
      Result.new(0, "DEMO\\operator\n")
    when /systeminfo/i
      Result.new(0, "OS Name: Microsoft Windows 11 Pro\nOS Version: 10.0.22631\n")
    when /^prompt$/i
      Result.new(0, 'PS C:\\Users\\operator> ')
    else
      Result.new(0, "Executed (demo): #{normalized}\n")
    end
  end

  def close
    nil
  end
end

# Launch the existing TUI entrypoint with a mock shell.
EvilCTF::TUI.start_rainfrog(DemoMockShell.new, shell: 'PowerShell', ssl: false)
