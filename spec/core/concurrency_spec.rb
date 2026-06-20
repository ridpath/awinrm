# frozen_string_literal: true

require_relative '../spec_helper'
require_relative '../../lib/evil_ctf/app_state'

RSpec.describe EvilCTF::AppState do
  it 'remains consistent under concurrent session/task/stream writes' do
    app_state = described_class.new
    thread_count = 12
    iterations = 75

    threads = Array.new(thread_count) do |tidx|
      Thread.new do
        iterations.times do |idx|
          app_state.add_session(id: "s-#{tidx}-#{idx}")
          app_state.enqueue_task(id: "q-#{tidx}-#{idx}")
          app_state.append_stream("stream-#{tidx}-#{idx}")
          app_state.set_active_session("active-#{tidx}-#{idx}")
          app_state.set_session_status(connected: true, hostname: "host-#{tidx}")
        end
      end
    end

    threads.each(&:join)

    expect(app_state.sessions.length).to eq(thread_count * iterations)
    expect(app_state.task_queue_snapshot.length).to eq(thread_count * iterations)
    expect(app_state.stream_snapshot.length).to be >= 50

    status = app_state.session_status
    expect(status[:connected]).to eq(true)
    expect(status[:hostname]).to match(/host-/)
    expect(app_state.active_session).to match(/active-/)
  end
end
