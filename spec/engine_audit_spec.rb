# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/engine_audit'

RSpec.describe EvilCTF::EngineAudit do
  describe '.error' do
    it 'omits frame 16 when capped at 15' do
      captured = {}
      allow(described_class).to receive(:write) do |**kw|
        captured[:message] = kw[:message]
      end
      err = StandardError.new('boom')
      err.set_backtrace((1..40).map { |i| "file_#{i}.rb:#{i}:in `method_#{i}'" })

      described_class.error(message: 'test', error: err)

      expect(captured[:message]).to include("file_#{described_class::MAX_BACKTRACE_FRAMES}.rb")
      expect(captured[:message]).not_to include('file_16.rb')
      expect(captured[:message]).to include('25 more frames')
    end

    it 'records short backtraces in full without a cap notice' do
      captured = {}
      allow(described_class).to receive(:write) { |**kw| captured[:message] = kw[:message] }
      err = StandardError.new('boom')
      err.set_backtrace(["a.rb:1:in `x'", "b.rb:2:in `y'"])

      described_class.error(message: 'test', error: err)

      expect(captured[:message]).to include('b.rb:2:in `y\'')
      expect(captured[:message]).not_to include('more frames')
    end

    it 'writes message and class only when no error is given' do
      captured = {}
      allow(described_class).to receive(:write) { |**kw| captured[:message] = kw[:message] }

      described_class.error(message: 'plain failure')

      expect(captured[:message]).to eq('plain failure')
    end
  end
end
