# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/session'

RSpec.describe EvilCTF::Session::RuntimeSetup do
  let(:shell) { instance_double('Shell') }
  let(:session_options) { {} }

  describe '.run_auto_evasion' do
    it 'disables Defender and applies the per-shell AMSI/ETW bypass' do
      expect(EvilCTF::Tools).to receive(:disable_defender).with(shell)
      expect(EvilCTF::Bypass).to receive(:apply).with(shell)

      described_class.run_auto_evasion(shell, session_options)

      expect(session_options[:bypass_applied]).to eq(true)
    end

    it 'still applies the per-shell bypass when Defender disable fails' do
      allow(EvilCTF::Tools).to receive(:disable_defender).and_raise('Get-MpComputerStatus not available')
      expect(EvilCTF::Bypass).to receive(:apply).with(shell)

      described_class.run_auto_evasion(shell, session_options)

      expect(session_options[:bypass_applied]).to eq(true)
    end

    it 'rescues bypass failures without raising (session must not die on evasion errors)' do
      allow(EvilCTF::Tools).to receive(:disable_defender)
      allow(EvilCTF::Bypass).to receive(:apply).and_raise('shell lost')

      expect { described_class.run_auto_evasion(shell, session_options) }.not_to raise_error
    end
  end
end
