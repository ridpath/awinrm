# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/tui'

RSpec.describe EvilCTF::TUI do
  describe 'thread-safe helpers' do
    it 'appends and snapshots stream buffer safely' do
      EvilCTF::TUI.append_stream('line1')
      EvilCTF::TUI.append_stream('line2')
      buf = EvilCTF::TUI.stream_snapshot
      expect(buf).to include('line1')
      expect(buf).to include('line2')
    end

    it 'adds and snapshots sessions safely' do
      s = { ip: '127.0.0.1', user: 'test', thread: Thread.new { sleep 0.01 } }
      EvilCTF::TUI.add_session(s)
      snap = EvilCTF::TUI.sessions_snapshot
      expect(snap.any? { |ss| ss[:ip] == '127.0.0.1' }).to be true
      # ensure background thread can finish
      s[:thread].join
    end
  end

  describe 'renderers' do
    it 'can render fixed layout without a shell (no exceptions)' do
      expect do
        EvilCTF::TUI.render_fixed_layout(nil, { host: 'x', connected: false }, [], %w[a b])
      end.not_to raise_error
    end

    it 'can render dashboard without a shell (no exceptions)' do
      expect do
        EvilCTF::TUI.render_dashboard(nil, { host: 'x', user: 'y', os_info: 'z', connected: false })
      end.not_to raise_error
    end
  end
end
