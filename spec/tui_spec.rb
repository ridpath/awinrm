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

  describe '.render_frame_diff (regression: frozen string buffers)' do
    let(:cursor) { double('cursor', move_to: 'MOVE', show: 'SHOW', hide: 'HIDE') }

    before do
      allow(EvilCTF::TUI).to receive(:screen_size).and_return([80, 24])
    end

    it 'emits only changed lines without raising on the mutable buffer' do
      out = EvilCTF::TUI.render_frame_diff(cursor: cursor, previous_frame: %w[same old],
                                           frame: %w[same new], cursor_anchor: nil, show_cursor: false)
      # one diff-line move plus the final cursor park (move_to 0, frame.length)
      expect(out.scan('MOVE').size).to eq(2)
      expect(out).to include('new')
      expect(out).not_to include('old')
      expect(out).to include('HIDE')
    end

    it 'clears trailing lines when the frame shrinks' do
      out = EvilCTF::TUI.render_frame_diff(cursor: cursor, previous_frame: %w[same gone also-gone],
                                           frame: %w[same], cursor_anchor: nil, show_cursor: true)
      expect(out).not_to include('gone')
      expect(out).to include('SHOW')
      # two stale lines each get a clear (\e[0K) from the shrink branch
      expect(out.scan("\e[0K").size).to be >= 2
    end
  end
end
