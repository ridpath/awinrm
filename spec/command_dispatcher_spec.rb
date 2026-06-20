# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/command_dispatcher'

RSpec.describe EvilCTF::CommandDispatcher do
  let(:shell) do
    instance_double('Shell', run: OpenStruct.new(output: '', exitcode: 0), close: nil,
                             adapter_info: { type: :mock })
  end
  let(:session_opts) { { ip: '10.0.0.1', port: 5985 } }
  let(:cmd_manager) { instance_double('CommandManager') }
  let(:history) { instance_double('History') }
  subject(:dispatcher) { described_class.instance }

  before do
    # Reset singleton between tests
    allow(EvilCTF::EngineAudit).to receive(:error)
    allow(cmd_manager).to receive(:list_macros).and_return(%w[kerberoast dump_creds])
    allow(cmd_manager).to receive(:list_aliases).and_return(%w[kerb dc])
  end

  # Use a fresh dispatcher for handler registration tests
  describe '#initialize' do
    it 'registers core commands on init' do
      d = described_class.new
      expect(d.handlers).to include('help', 'menu', 'clear', 'tools', 'enum', 'history')
    end
  end

  describe '#register / #unregister' do
    it 'registers a handler lambda' do
      d = described_class.new
      d.register('ping') { |_, _, _| 'pong' }
      expect(d.handlers).to have_key('ping')
    end

    it 'unregisters a handler' do
      d = described_class.new
      d.register('temp') { |_, _, _| 'temp' }
      expect { d.unregister('temp') }.to change { d.handlers.key?('temp') }.from(true).to(false)
    end

    it 'is thread-safe' do
      d = described_class.new
      threads = 5.times.map do |i|
        Thread.new { d.register("t#{i}") { |_, _, _| i.to_s } }
      end
      threads.each(&:join)
      expect(d.handlers).to include('t0', 't1', 't2', 't3', 't4')
    end
  end

  describe '#dispatch' do
    it 'returns handled: false for unknown commands' do
      result = dispatcher.dispatch(
        name: 'nonexistent_cmd_xyz', args: nil,
        shell: shell, session_options: session_opts
      )
      expect(result[:handled]).to eq(false)
      expect(result[:ok]).to eq(false)
    end

    it 'aliases menu to help' do
      result = dispatcher.dispatch(
        name: 'menu', args: nil,
        shell: shell, session_options: session_opts.merge(command_manager: cmd_manager)
      )
      expect(result[:handled]).to eq(true)
      expect(result[:output]).to include('help', 'Builtin commands')
    end

    it 'dispatches help command' do
      result = dispatcher.dispatch(
        name: 'help', args: nil,
        shell: shell, session_options: session_opts.merge(command_manager: cmd_manager)
      )
      expect(result[:handled]).to eq(true)
      expect(result[:output]).to include('help', 'enum', 'dump_creds', 'bypass-4msi')
    end

    it 'handles validate without command_manager' do
      result = dispatcher.dispatch(
        name: 'validate', args: 'macros',
        shell: shell, session_options: session_opts
      )
      expect(result[:handled]).to eq(true)
      expect(result[:output]).to include('Command manager unavailable')
    end

    it 'handles dispatch errors and logs them' do
      d = described_class.new
      d.register('crash') { |_, _, _| raise 'kaboom' }
      expect(EvilCTF::EngineAudit).to receive(:error).with(hash_including(message: /dispatcher handler failed/))
      result = d.dispatch(
        name: 'crash', args: nil,
        shell: shell, session_options: session_opts
      )
      expect(result[:handled]).to eq(true)
      expect(result[:ok]).to eq(false)
      expect(result[:error]).to include('kaboom')
    end

    it 'supports tolerant key resolution (multi-word -> two-word -> one-word)' do
      d = described_class.new
      d.register('history clear') { |_, _, _| 'cleared!' }
      result = d.dispatch(
        name: 'history clear', args: nil,
        shell: shell, session_options: session_opts
      )
      expect(result[:output]).to eq('cleared!')
    end

    it 'normalizes history with args to history <arg>' do
      result = dispatcher.dispatch(
        name: 'history', args: 'clear',
        shell: shell, session_options: session_opts
      )
      expect(result[:handled]).to eq(true)
    end
  end

  describe 'built-in commands' do
    it 'clear runs system clear' do
      expect(dispatcher).to receive(:system).with('clear || cls')
      result = dispatcher.dispatch(
        name: 'clear', args: nil,
        shell: shell, session_options: session_opts
      )
      expect(result[:ok]).to eq(true)
    end

    it 'tools returns tool registry output' do
      expect(EvilCTF::Tools).to receive(:list_available_tools)
      result = dispatcher.dispatch(
        name: 'tools', args: nil,
        shell: shell, session_options: session_opts
      )
      expect(result[:ok]).to eq(true)
    end

    it 'enum dispatches to Enums module' do
      expect(EvilCTF::Enums).to receive(:run_enumeration).with(shell, hash_including(type: 'basic'))
      dispatcher.dispatch(
        name: 'enum', args: nil,
        shell: shell, session_options: session_opts
      )
    end

    it 'enum deep stages winpeas' do
      expect(EvilCTF::Tools).to receive(:safe_autostage).with('winpeas', shell, anything, anything)
      expect(EvilCTF::Enums).to receive(:run_enumeration).with(shell, hash_including(type: 'deep'))
      dispatcher.dispatch(
        name: 'enum', args: 'deep',
        shell: shell, session_options: session_opts
      )
    end

    it 'enum sql runs SQLEnum' do
      expect(EvilCTF::SQLEnum).to receive(:run_sql_enum).with(shell)
      dispatcher.dispatch(
        name: 'enum', args: 'sql',
        shell: shell, session_options: session_opts
      )
    end

    it 'bypass-4msi runs detection PS first' do
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::BYPASS_DETECTION_PS, anything
      ).and_return(OpenStruct.new(output: 'Windows 10', exitcode: 0))
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::BYPASS_4MSI_PS, anything
      ).and_return(OpenStruct.new(output: 'Bypass OK', exitcode: 0))
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::BYPASS_VERIFICATION_PS, anything
      ).and_return(OpenStruct.new(output: 'Verified', exitcode: 0))
      dispatcher.dispatch(
        name: 'bypass-4msi', args: nil,
        shell: shell, session_options: session_opts
      )
    end

    it 'bypass-etw runs ETW bypass' do
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::BYPASS_DETECTION_PS, anything
      ).and_return(OpenStruct.new(output: 'Windows 10', exitcode: 0))
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::ETW_BYPASS_PS, anything
      ).and_return(OpenStruct.new(output: 'ETW patched', exitcode: 0))
      expect(EvilCTF::Execution).to receive(:run).with(
        shell, EvilCTF::Tools::BYPASS_VERIFICATION_PS, anything
      ).and_return(OpenStruct.new(output: 'Verified', exitcode: 0))
      dispatcher.dispatch(
        name: 'bypass-etw', args: nil,
        shell: shell, session_options: session_opts
      )
    end

    it 'download_missing calls Tools.download_missing_tools' do
      expect(EvilCTF::Tools).to receive(:download_missing_tools)
      dispatcher.dispatch(
        name: 'download_missing', args: nil,
        shell: shell, session_options: session_opts
      )
    end

    it 'fileops calls file_operations_menu' do
      expect(EvilCTF::Uploader).to receive(:file_operations_menu).with(shell)
      dispatcher.dispatch(
        name: 'fileops', args: nil,
        shell: shell, session_options: session_opts
      )
    end

    it 'disable_defender calls Tools.disable_defender' do
      expect(EvilCTF::Tools).to receive(:disable_defender).with(shell)
      dispatcher.dispatch(
        name: 'disable_defender', args: nil,
        shell: shell, session_options: session_opts
      )
    end
  end
end
