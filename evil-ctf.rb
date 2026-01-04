#!/usr/bin/env ruby
# frozen_string_literal: true

BASE = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(BASE, 'lib'))

require 'evil_ctf/cli'

exit EvilCTF::CLI.run(ARGV)
