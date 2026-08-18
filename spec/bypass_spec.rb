# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/bypass'

RSpec.describe EvilCTF::Bypass do
  describe 'BYPASS_4MSI_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Bypass::BYPASS_4MSI_PS).to be_a(String)
      expect(EvilCTF::Bypass::BYPASS_4MSI_PS.length).to be > 100
    end

    it 'contains key PowerShell bypass elements' do
      ps = EvilCTF::Bypass::BYPASS_4MSI_PS
      expect(ps).to include('AmsiScanBuffer')
      expect(ps).to include('VirtualProtect')
      expect(ps).to include('kernel32')
      expect(ps).to include('LoadLibrary')
    end

    it 'has error handling' do
      expect(EvilCTF::Bypass::BYPASS_4MSI_PS).to include('catch')
      expect(EvilCTF::Bypass::BYPASS_4MSI_PS).to include('try')
    end
  end

  describe 'ETW_BYPASS_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Bypass::ETW_BYPASS_PS).to be_a(String)
      expect(EvilCTF::Bypass::ETW_BYPASS_PS.length).to be > 50
    end

    it 'contains ETW patching elements' do
      ps = EvilCTF::Bypass::ETW_BYPASS_PS
      expect(ps).to include('EtwEventWrite')
      expect(ps).to include('ntdll')
      expect(ps).to include('xor')
    end
  end

  describe 'BYPASS_DETECTION_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Bypass::BYPASS_DETECTION_PS).to be_a(String)
      expect(EvilCTF::Bypass::BYPASS_DETECTION_PS.length).to be > 50
    end

    it 'contains Windows version detection' do
      expect(EvilCTF::Bypass::BYPASS_DETECTION_PS).to include('Windows')
      expect(EvilCTF::Bypass::BYPASS_DETECTION_PS).to include('Build')
    end
  end

  describe 'BYPASS_VERIFICATION_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Bypass::BYPASS_VERIFICATION_PS).to be_a(String)
      expect(EvilCTF::Bypass::BYPASS_VERIFICATION_PS.length).to be > 50
    end

    it 'contains AMSI verification logic' do
      expect(EvilCTF::Bypass::BYPASS_VERIFICATION_PS).to include('AmsiUtils')
      expect(EvilCTF::Bypass::BYPASS_VERIFICATION_PS).to include('ScanString')
    end
  end
  describe '.apply' do
    let(:shell) { instance_double('Shell') }
    let(:good_result) { OpenStruct.new(ok: true, output: '[+] Patched') }

    it 'runs the AMSI and ETW scripts on the shell' do
      executed = []
      allow(EvilCTF::Execution).to receive(:run) do |_sh, cmd, **_opts|
        executed << cmd
        good_result
      end

      results = described_class.apply(shell, verbose: false)

      expect(executed).to eq([described_class::BYPASS_4MSI_PS, described_class::ETW_BYPASS_PS])
      expect(results[:amsi]).to eq(true)
      expect(results[:etw]).to eq(true)
    end

    it 'skips the AMSI script when amsi: false' do
      executed = []
      allow(EvilCTF::Execution).to receive(:run) { |_, cmd, **_opts|
        executed << cmd
        good_result
      }

      results = described_class.apply(shell, amsi: false, verbose: false)

      expect(executed).to eq([described_class::ETW_BYPASS_PS])
      expect(results).not_to have_key(:amsi)
      expect(results[:etw]).to eq(true)
    end

    it 'runs verification when verify: true' do
      executed = []
      allow(EvilCTF::Execution).to receive(:run) { |_, cmd, **_opts|
        executed << cmd
        good_result
      }

      described_class.apply(shell, verify: true, verbose: false)

      expect(executed.last).to eq(described_class::BYPASS_VERIFICATION_PS)
    end

    it 'reports failed script results instead of raising' do
      allow(EvilCTF::Execution).to receive(:run)
        .and_return(OpenStruct.new(ok: false, output: 'ERROR'))

      results = described_class.apply(shell, verbose: false)

      expect(results[:amsi]).to eq(false)
      expect(results[:etw]).to eq(false)
    end

    it 'rescues execution errors and returns a failure hash' do
      allow(EvilCTF::Execution).to receive(:run).and_raise('connection lost')

      results = described_class.apply(shell, verbose: false)

      expect(results[:amsi]).to eq(false)
      expect(results[:error]).to eq('connection lost')
    end

    it 'prints a status line when verbose' do
      allow(EvilCTF::Execution).to receive(:run).and_return(good_result)

      expect { described_class.apply(shell, verbose: true) }
        .to output(/Per-shell bypass applied: AMSI=true ETW=true/).to_stdout
    end
  end
end
