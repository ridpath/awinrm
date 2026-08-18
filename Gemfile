# frozen_string_literal: true

source 'https://rubygems.org'

gem 'colorize', '>= 0.8'
gem 'concurrent-ruby', '>= 1.2'
gem 'ffi', '>= 1.17.4'
gem 'gssapi', '>= 1.3.1'
gem 'logging', '>= 2.4'
gem 'nori', '>= 2.7'
gem 'ostruct', '>= 0.6.0'
gem 'readline', '>= 0.0.4'
gem 'rubyzip', '>= 2.0', '< 3' # winrm-fs pins ~> 2.0; our Zip::File usage is 2.x-compatible
gem 'socksify', '>= 1.8'
gem 'syslog', '>= 0.1.2'
gem 'winrm', '>= 2.3.9'
gem 'winrm-fs', '>= 1.3.5'

# Test/dev
group :test do
  gem 'mocha', '>= 1.15'
  gem 'rspec', '>= 3.12'
end

group :development do
  gem 'rubocop', '~> 1.89' # needs >= 1.89 for TargetRubyVersion 4.0 support
  # Transitive dep of rubocop. Pin to 1.28.x: parallel 2.0+ requires Ruby >= 3.3,
  # which makes the lockfile unusable on the Ruby 3.2 CI matrix job (frozen mode
  # refuses to re-resolve). rubocop only requires >= 1.10.
  gem 'parallel', '~> 1.28'
  gem 'tty-prompt'
  gem 'tty-screen'
  gem 'tty-table'
end
