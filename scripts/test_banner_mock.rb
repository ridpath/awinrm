#!/usr/bin/env ruby
# Quick safe test of EvilCTF::Banner.show_banner using a mock shell
 $LOAD_PATH.unshift(File.expand_path('../', __dir__))
require 'ostruct'
# Ensure base module exists for nested module definition in banner
module EvilCTF; end unless defined?(EvilCTF)
require 'lib/evil_ctf/banner'

class MockShell
  def run(cmd)
    case cmd
    when 'hostname'
      OpenStruct.new(output: "TEST-HOST\n")
    when /Get-WmiObject Win32_ComputerSystem/
      OpenStruct.new(output: "TestDomain\n")
    when /whoami .*priv/, /whoami \/priv/
      OpenStruct.new(output: "SeDebugPrivilege Enabled\n")
    when /\(Get-MpComputerStatus\).RealTimeProtectionEnabled/
      OpenStruct.new(output: "False\n")
    else
      OpenStruct.new(output: "")
    end
  end
end

puts "Running mock banner test (minimal mode)..."
EvilCTF::Banner.show_banner(MockShell.new, {ssl: false, port: 5985, hash: false}, mode: :minimal)

puts "\nRunning mock banner test (expanded mode)..."
EvilCTF::Banner.show_banner(MockShell.new, {ssl: false, port: 5985, hash: false}, mode: :expanded)
