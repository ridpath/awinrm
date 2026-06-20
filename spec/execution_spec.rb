# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/execution'

RSpec.describe EvilCTF::Execution do
  let(:fake_shell) do
    Class.new do
      def run(_cmd)
        OpenStruct.new(output: "OK\n", exitcode: 0)
      end
    end.new
  end

  it 'returns ok for simple success' do
    res = EvilCTF::Execution.run(fake_shell, 'echo hi', timeout: 2)
    expect(res.ok).to eq(true)
    expect(res.exitcode).to eq(0)
    expect(res.output).to include('OK')
  end

  it 'times out for long-running threads' do
    slow_shell = Class.new do
      def run(_cmd)
        sleep 3
        OpenStruct.new(output: 'done', exitcode: 0)
      end
    end.new

    res = EvilCTF::Execution.run(slow_shell, 'sleep 3', timeout: 1)
    expect(res.ok).to eq(false)
    expect(res.exitcode).to be_nil
    expect(res.output).to match(/TIMED_OUT/)
  end

  it 'surfaces command errors instead of misclassifying them as timeouts' do
    failing_shell = Class.new do
      def run(_cmd)
        raise 'not authorized'
      end
    end.new

    res = EvilCTF::Execution.run(failing_shell, 'whoami', timeout: 2)
    expect(res.ok).to eq(false)
    expect(res.exitcode).to eq(255)
    expect(res.output).to include('RuntimeError')
    expect(res.output).not_to include('TIMED_OUT')
  end

  describe '#stream' do
    let(:fake_shell) do
      Class.new do
        def run(cmd)
          @last_cmd = cmd
          case cmd
          when /Start-Job/
            OpenStruct.new(exitcode: 0, output: '42') # Simulates job ID
          when /Get-Job -Id 42/
            OpenStruct.new(exitcode: 0, output: 'Running')
          when /Test-Path/
            OpenStruct.new(exitcode: 0, output: 'OK')
          else
            OpenStruct.new(exitcode: 0, output: 'done')
          end
        end

        def adapter_info
          { type: :fake }
        end
      end.new
    end

    it 'tracks the specific job ID created by Start-Job' do
      job_ids = []
      allow(fake_shell).to receive(:run) do |cmd|
        job_ids << 'Start-Job' if cmd.to_s.include?('Start-Job')
        job_ids << 'Get-Job -Id' if cmd.to_s.include?('Get-Job -Id')
        OpenStruct.new(exitcode: 0, output: '42')
      end

      EvilCTF::Execution.stream(fake_shell, 'echo test', timeout: 1, poll_interval: 0.1)

      # Verify that both Start-Job and Get-Job -Id reference the same job
      expect(job_ids).to include('Start-Job', 'Get-Job -Id')
    end
  end
end
