# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/tools'

RSpec.describe EvilCTF::Staging do
  after { described_class.reset! }

  describe '.dir' do
    it 'defaults to C:\\Users\\Public' do
      expect(described_class.dir).to eq('C:\\Users\\Public')
    end

    it 'normalizes slashes and trailing separators' do
      described_class.dir = 'd:/staging/'
      expect(described_class.dir).to eq('D:\\staging')
    end

    it 'accepts drive-root paths' do
      described_class.dir = 'D:/'
      expect(described_class.dir).to eq('D:')
    end

    it 'accepts UNC paths' do
      described_class.dir = '\\\\corp\\ops'
      expect(described_class.dir).to eq('\\\\corp\\ops')
    end

    it 'rejects non-absolute paths and keeps the previous value' do
      described_class.dir = 'D:\\staging'
      expect { described_class.dir = 'relative/path' }.to raise_error(ArgumentError)
      expect(described_class.dir).to eq('D:\\staging')
    end

    it 'rejects empty input' do
      expect { described_class.dir = '  ' }.to raise_error(ArgumentError)
    end
  end

  describe '.tool_path' do
    it 'joins onto the staging dir' do
      described_class.dir = 'C:\\Temp'
      expect(described_class.tool_path('Rubeus.exe')).to eq('C:\\Temp\\Rubeus.exe')
    end
  end

  describe 'tool_registry' do
    it 'derives recommended_remote from the staging dir' do
      expect(EvilCTF::Tools.tool_registry['sharphound'][:recommended_remote])
        .to eq('C:\\Users\\Public\\SharpHound.exe')

      described_class.dir = 'D:\\staging'
      expect(EvilCTF::Tools.tool_registry['sharphound'][:recommended_remote])
        .to eq('D:\\staging\\SharpHound.exe')
    end
  end

  describe 'macro steps' do
    it 'interpolate the staging dir' do
      step = EvilCTF::Tools::CommandManager.new.instance_variable_get(:@macros)['kerberoast'].last
      expect(step).to include('C:\\Users\\Public\\Rubeus.exe')

      described_class.dir = 'D:\\staging'
      step2 = EvilCTF::Tools::CommandManager.new.instance_variable_get(:@macros)['kerberoast'].last
      expect(step2).to include('D:\\staging\\Rubeus.exe')
    end
  end
end
