#!/usr/bin/env ruby
# Demo script to run the TUI demo mode without a live session
begin
  require 'bundler/setup'
rescue LoadError
  # ignore if bundler/setup not available
end
require_relative '../lib/evil_ctf/tui'

# Run demo mode
EvilCTF::TUI.demo(nil, {})
