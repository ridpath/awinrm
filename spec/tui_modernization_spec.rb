# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/tui'

RSpec.describe EvilCTF::TUI do
  describe '.fit_line' do
    it 'returns unchanged text when width is sufficient' do
      expect(described_class.fit_line('operator', 20)).to eq('operator')
    end

    it 'clips long text with ellipsis when width is constrained' do
      expect(described_class.fit_line('abcdefghij', 5)).to eq('abcd…')
    end

    it 'normalizes newlines before clipping' do
      expect(described_class.fit_line("a\n\rb", 10)).to eq('a b')
    end
  end

  describe '.prompt_value' do
    it 'falls back cleanly when ask does not support quiet/filter keywords' do
      prompt = instance_double('TTY::Prompt')
      allow(prompt).to receive(:ask)
        .with('User:', default: 'Administrator', quiet: true, filter: kind_of(Proc))
        .and_raise(ArgumentError)
      allow(prompt).to receive(:ask)
        .with('User:', default: 'Administrator')
        .and_return('operator')

      value = described_class.prompt_value(prompt: prompt, label: 'User:', default: 'Administrator')
      expect(value).to eq('operator')
    end

    it 'falls back cleanly when mask does not support quiet/filter keywords' do
      prompt = instance_double('TTY::Prompt')
      allow(prompt).to receive(:mask)
        .with('Password:', quiet: true, filter: kind_of(Proc))
        .and_raise(ArgumentError)
      allow(prompt).to receive(:mask)
        .with('Password:')
        .and_return('secret')

      value = described_class.prompt_value(prompt: prompt, label: 'Password:', default: nil, secret: true)
      expect(value).to eq('secret')
    end
  end

  describe '.render_modernization_report' do
    it 'renders a bounded table for narrow screens without long-line bleed' do
      app = described_class.app_state
      app.mutex.synchronize { app.instance_variable_set(:@stream_buffer, []) }

      allow(described_class).to receive(:screen_size).and_return([60, 24])

      described_class.render_modernization_report(
        target: '10.0.0.7',
        validation: {
          ok: false,
          error: 'A' * 200,
          report: "Ruby 4.0 Compatibility Report #{'B' * 200}"
        }
      )

      stream = described_class.stream_snapshot
      table_lines = stream.select { |line| line.start_with?('┌', '│', '└', '├') }

      expect(table_lines).not_to be_empty
      expect(table_lines.map(&:length).max).to be <= 60
      expect(stream.any? { |line| line.include?('Ruby 4 Compatibility') }).to be true
    end
  end
end
