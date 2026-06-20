# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/banner'

RSpec.describe EvilCTF::Banner do
  describe EvilCTF::Banner::Color do
    describe '.header' do
      it 'formats text with cyan by default' do
        result = described_class.header('TEST')
        expect(result).to include('TEST')
      end

      it 'accepts color parameter' do
        result = described_class.header('WARN', :yellow)
        expect(result).to include('WARN')
      end
    end

    describe '.success' do
      it 'returns green text with [+] prefix' do
        result = described_class.success('done')
        expect(result).to include('[+]', 'done')
      end
    end

    describe '.warning' do
      it 'returns yellow text with [!] prefix' do
        result = described_class.warning('caution')
        expect(result).to include('[!]', 'caution')
      end
    end

    describe '.error' do
      it 'returns red text with [-] prefix' do
        result = described_class.error('fail')
        expect(result).to include('[-]', 'fail')
      end
    end

    describe '.info' do
      it 'returns blue text with [i] prefix' do
        result = described_class.info('notice')
        expect(result).to include('[i]', 'notice')
      end
    end

    describe '.critical' do
      it 'returns magenta text with [CRITICAL] prefix' do
        result = described_class.critical('severe')
        expect(result).to include('[CRITICAL]', 'severe')
      end
    end

    describe '.flag' do
      it 'returns red text with FLAG prefix' do
        result = described_class.flag('CTF{test}')
        expect(result).to include('FLAG:', 'CTF{test}')
      end
    end

    describe '.risk' do
      it 'returns :red for scores 0-30' do
        expect(described_class.risk(15)).to eq(:red)
        expect(described_class.risk(0)).to eq(:red)
        expect(described_class.risk(30)).to eq(:red)
      end

      it 'returns :yellow for scores 31-60' do
        expect(described_class.risk(45)).to eq(:yellow)
        expect(described_class.risk(31)).to eq(:yellow)
      end

      it 'returns :green for scores 61-100' do
        expect(described_class.risk(80)).to eq(:green)
        expect(described_class.risk(61)).to eq(:green)
        expect(described_class.risk(100)).to eq(:green)
      end
    end

    describe '.risk_text' do
      it 'returns LOW for low scores' do
        expect(described_class.risk_text(15)).to eq('LOW')
      end

      it 'returns MEDIUM for medium scores' do
        expect(described_class.risk_text(45)).to eq('MEDIUM')
      end

      it 'returns HIGH for high scores' do
        expect(described_class.risk_text(80)).to eq('HIGH')
      end
    end
  end

  describe '.show_banner' do
    let(:shell) { instance_double('Shell', run: OpenStruct.new(output: '', exitcode: 0)) }
    let(:options) { { ip: '10.0.0.1', port: 5985, ssl: false } }

    before do
      allow(EvilCTF::Execution).to receive(:run).and_return(OpenStruct.new(output: '', ok: true, exitcode: 0))
    end

    it 'renders minimal banner by default' do
      expect(described_class).to receive(:show_minimal_banner).and_call_original
      expect do
        described_class.show_banner(shell, options, mode: :minimal)
      end.to output(/AWINRM/).to_stdout
    end

    it 'renders expanded banner in expanded mode' do
      expect(described_class).to receive(:show_expanded_banner).and_call_original
      expect do
        described_class.show_banner(shell, options, mode: :expanded)
      end.to output(/AWINRM/).to_stdout
    end

    it 'defaults to minimal when mode is unrecognized' do
      expect(described_class).to receive(:show_minimal_banner)
      described_class.show_banner(shell, options, mode: :bogus)
    end

    it 'shows plain text when no_color is true' do
      expect do
        described_class.show_banner(shell, options, mode: :minimal, no_color: true)
      end.to output(/AWINRM CTF SESSION/).to_stdout
    end

    it 'does not attempt TUI when options[:tui] is not set' do
      expect(EvilCTF::TUI).not_to receive(:start)
      described_class.show_banner(shell, options, mode: :minimal)
    end
  end

  describe '.show_banner_with_flagscan' do
    it 'delegates to show_banner with expanded mode' do
      shell = instance_double('Shell', run: OpenStruct.new(output: '', exitcode: 0))
      allow(EvilCTF::Execution).to receive(:run).and_return(OpenStruct.new(output: '', ok: true, exitcode: 0))
      expect(described_class).to receive(:show_banner).with(shell, anything, mode: :expanded, no_color: false)
      described_class.show_banner_with_flagscan(shell, {})
    end
  end
end
