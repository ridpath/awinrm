require 'bundler/setup'
require 'rspec'
require 'ostruct'

RSpec.configure do |c|
  c.mock_with :rspec
  c.order = :random
end
