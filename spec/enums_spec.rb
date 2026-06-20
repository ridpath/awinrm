# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/enums'

RSpec.describe EvilCTF::Enums do
  let(:shell) do
    instance_double('Shell', run: OpenStruct.new(output: 'test output', exitcode: 0))
  end

  describe '.presets' do
    it 'returns a hash with expected preset keys' do
      expect(described_class.presets).to include('basic', 'network', 'privilege', 'deep', 'sql')
    end

    it 'returns 7 presets total' do
      expect(described_class.presets.keys.size).to eq(7)
    end
  end

  describe '.run_enum' do
    it 'calls the preset lambda for known types' do
      expect(described_class).to receive(:run_enumeration).with(shell, type: 'basic')
      described_class.run_enum(shell, 'basic')
    end

    it 'outputs warning for unknown types' do
      expect do
        described_class.run_enum(shell, 'unknown_type_xyz')
      end.to output(/Unknown enum type/).to_stdout
    end

    it 'passes options hash to the preset' do
      expect(described_class).to receive(:run_enumeration).with(shell, type: 'network')
      described_class.run_enum(shell, 'network', { some: 'option' })
    end
  end

  describe '.run_enumeration' do
    let(:cache) { {} }

    it 'returns cached result if available' do
      cache['basic'] = 'CACHED OUTPUT'
      expect do
        described_class.run_enumeration(shell, type: 'basic', cache: cache)
      end.to output(/CACHED OUTPUT/).to_stdout
    end

    it 'does not use cache when fresh: true' do
      cache['basic'] = 'CACHED OUTPUT'
      expect(shell).to receive(:run).at_least(:once)
      described_class.run_enumeration(shell, type: 'basic', cache: cache, fresh: true)
    end

    it 'runs commands for basic type' do
      expect(shell).to receive(:run).with('cmd /c whoami /all')
      expect(shell).to receive(:run).with('net user')
      expect(shell).to receive(:run).with('systeminfo')
      described_class.run_enumeration(shell, type: 'basic', cache: cache)
    end

    it 'runs network enumeration commands' do
      expect(shell).to receive(:run).with(/ipconfig/)
      expect(shell).to receive(:run).with(/Get-NetTCPConnection/)
      expect(shell).to receive(:run).with(/netstat/)
      described_class.run_enumeration(shell, type: 'network', cache: cache)
    end

    it 'runs privilege enumeration commands' do
      expect(shell).to receive(:run).with(%r{whoami /priv})
      expect(shell).to receive(:run).with(/net localgroup Administrators/)
      described_class.run_enumeration(shell, type: 'privilege', cache: cache)
    end

    it 'caches output after running' do
      described_class.run_enumeration(shell, type: 'basic', cache: cache)
      expect(cache['basic']).to include('test output')
    end

    it 'handles command errors gracefully' do
      allow(shell).to receive(:run).and_raise(StandardError.new('access denied'))
      expect do
        described_class.run_enumeration(shell, type: 'basic', cache: cache)
      end.to output(/access denied/).to_stdout
      expect(cache['basic']).to include('access denied')
    end
  end
end
