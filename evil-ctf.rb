#!/usr/bin/env ruby
# frozen_string_literal: true

BASE = __dir__
$LOAD_PATH.unshift(File.join(BASE, 'lib'))

require 'evil_ctf/cli'

exit EvilCTF::CLI.run(ARGV)
