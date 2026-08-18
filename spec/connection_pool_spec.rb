# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/connection_pool'

# Stand-in for a WinRM connection: records close/reset calls.
class ConnectionPoolFakeConn
  attr_reader :closed, :resets

  def initialize
    @closed = false
    @resets = 0
  end

  def close
    @closed = true
  end

  def reset
    @resets += 1
  end
end

RSpec.describe EvilCTF::ConnectionPool do
  before do
    described_class.reset!
    # Default: build fake connections (specs may re-stub per example).
    allow(EvilCTF::Connection).to receive(:build_full) { |_opts = nil, **_kwargs| ConnectionPoolFakeConn.new }
  end

  after { described_class.reset! }

  describe '.acquire' do
    it 'builds once and returns the same connection on repeat acquire' do
      built = []
      allow(EvilCTF::Connection).to receive(:build_full) { |**| built << ConnectionPoolFakeConn.new }
      a = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      b = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      expect(a).to be(b)
      expect(built.size).to eq(1)
      expect(described_class.size).to eq(1)
    end

    it 'keys connections by endpoint and user separately' do
      a = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      b = described_class.acquire(endpoint: 'http://b:5985/wsman', user: 'u')
      c = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'v')
      expect([a, b, c].uniq.size).to eq(3)
      expect(described_class.size).to eq(3)
    end

    it 'distinguishes password, hash, and kerberos auth' do
      a = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u', password: 'p')
      b = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u', hash: 'aa' * 16)
      c = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u', kerberos: true)
      expect([a, b, c].uniq.size).to eq(3)
    end

    it 'keys ip:+port: callers identically to explicit-endpoint callers' do
      a = described_class.acquire(ip: '10.0.0.5', user: 'u', port: 5985, ssl: false)
      b = described_class.acquire(endpoint: 'http://10.0.0.5:5985/wsman', user: 'u')
      expect(a).to be(b)
    end

    it 'evicts the least-recently-used entry at MAX_SIZE' do
      conns = {}
      allow(EvilCTF::Connection).to receive(:build_full) do |**p|
        conns[p[:endpoint]] ||= ConnectionPoolFakeConn.new
      end
      described_class::MAX_SIZE.times do |i|
        described_class.acquire(endpoint: "http://h#{i}:5985/wsman", user: 'u')
      end
      # Touch h0 so h1 becomes LRU, then add one more
      described_class.acquire(endpoint: 'http://h0:5985/wsman', user: 'u')
      described_class.acquire(endpoint: 'http://new:5985/wsman', user: 'u')

      expect(described_class.size).to eq(described_class::MAX_SIZE)
      expect(conns['http://h1:5985/wsman'].closed).to eq(true)
      expect(conns['http://h0:5985/wsman'].closed).to eq(false)
    end

    it 'returns nil when the builder fails' do
      allow(EvilCTF::Connection).to receive(:build_full).and_return(nil)
      expect(described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')).to be_nil
      expect(described_class.size).to eq(0)
    end

    it 'builds exactly once under concurrent acquire' do
      count = 0
      mutex = Mutex.new
      built_conn = ConnectionPoolFakeConn.new
      allow(EvilCTF::Connection).to receive(:build_full) do
        mutex.synchronize do
          count += 1
          sleep 0.01 if count == 1
        end
        built_conn
      end

      results = 16.times.map do
        Thread.new { described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u') }
      end.map(&:value)

      expect(count).to eq(1)
      expect(results.uniq.size).to eq(1)
    end
  end

  describe '.register' do
    it 'lets a later acquire reuse a pre-built connection' do
      conn = ConnectionPoolFakeConn.new
      built = 0
      allow(EvilCTF::Connection).to receive(:build_full) {
        built += 1
        ConnectionPoolFakeConn.new
      }

      described_class.register(conn, endpoint: 'http://a:5985/wsman', user: 'u', password: 'p')
      acquired = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u', password: 'p')

      expect(acquired).to be(conn)
      expect(built).to eq(0)
    end
  end

  describe '.evict' do
    it 'removes the connection and closes it' do
      conn = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      described_class.evict(conn)
      expect(described_class.size).to eq(0)
      expect(conn.closed).to eq(true)

      # A subsequent acquire builds fresh
      fresh = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      expect(fresh).not_to be(conn)
    end

    it 'ignores connections that were never pooled' do
      outsider = ConnectionPoolFakeConn.new
      expect { described_class.evict(outsider) }.not_to raise_error
      expect(outsider.closed).to eq(false)
    end
  end

  describe '.detach' do
    it 'removes without closing' do
      conn = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      described_class.detach(conn)
      expect(described_class.size).to eq(0)
      expect(conn.closed).to eq(false)
    end
  end

  describe '.close_all' do
    it 'closes every pooled connection' do
      a = described_class.acquire(endpoint: 'http://a:5985/wsman', user: 'u')
      b = described_class.acquire(endpoint: 'http://b:5985/wsman', user: 'u')
      described_class.close_all
      expect(a.closed).to eq(true)
      expect(b.closed).to eq(true)
      expect(described_class.size).to eq(0)
    end
  end

  describe 'test_connection → run_session handoff' do
    it 'reuses the validated connection through Bootstrap.build_connection' do
      require_relative '../lib/evil_ctf/session'
      require_relative '../lib/evil_ctf/session/bootstrap'

      conn = ConnectionPoolFakeConn.new
      allow(EvilCTF::Connection).to receive(:build_full).and_return(conn)
      allow(EvilCTF::ConnectionValidator).to receive(:validate).and_return({ ok: true, hostname: 'WIN' })

      validation = EvilCTF::Session.test_connection(endpoint: 'http://a:5985/wsman', user: 'u', password: 'p')
      expect(validation[:ok]).to eq(true)
      expect(conn.closed).to eq(false) # handed to the pool, not closed
      expect(described_class.size).to eq(1)

      session_options = { endpoint: 'http://a:5985/wsman', user: 'u', password: 'p', prevalidated: true,
                          validation_info: validation }
      reused = EvilCTF::Session::Bootstrap.build_connection(session_options)
      expect(reused).to be(conn)
    end

    it 'closes the connection when validation fails' do
      require_relative '../lib/evil_ctf/session'
      conn = ConnectionPoolFakeConn.new
      allow(EvilCTF::Connection).to receive(:build_full).and_return(conn)
      allow(EvilCTF::ConnectionValidator).to receive(:validate).and_return({ ok: false, error: 'auth failed' })

      validation = EvilCTF::Session.test_connection(endpoint: 'http://a:5985/wsman', user: 'u', password: 'p')
      expect(validation[:ok]).to eq(false)
      expect(conn.closed).to eq(true)
      expect(described_class.size).to eq(0)
    end
  end
end
