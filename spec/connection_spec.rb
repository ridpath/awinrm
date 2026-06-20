# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/connection'

RSpec.describe EvilCTF::Connection do
  describe '.build_full' do
    before do
      # Stub WinRM::Connection.new to avoid real network calls
      stub_const('WinRM::Connection', Class.new do
        def self.new(**opts)
          instance = allocate
          instance.instance_variable_set(:@opts, opts)
          instance
        end
      end)
    end

    it 'returns nil when WinRM is not defined' do
      hide_const('WinRM::Connection')
      expect(described_class.build_full(endpoint: 'http://host:5985/wsman', user: 'u', password: 'p')).to be_nil
    end

    it 'raises ArgumentError for non-Hash first arg' do
      expect { described_class.build_full('not-a-hash') }.to raise_error(ArgumentError, /keyword args/)
    end

    it 'builds endpoint from ip and default port (5985)' do
      conn = described_class.build_full(ip: '10.0.0.1', user: 'admin', password: 'pass')
      expect(conn).not_to be_nil
    end

    it 'uses SSL port 5986 when ssl: true and no port given' do
      stub_const('WinRM::HTTP::HttpTransport', Class.new do
        define_method(:initialize) { |ep, _| @ep = ep }
      end)
      opts = described_class.build_full(ip: '10.0.0.1', user: 'admin', password: 'pass', ssl: true)
      expect(opts).not_to be_nil
    end

    it 'passes keyword args through to WinRM::Connection' do
      expect(WinRM::Connection).to receive(:new).with(hash_including(
                                                        endpoint: 'http://10.0.0.1:5985/wsman', user: 'admin', password: 'pass', transport: :negotiate
                                                      ))
      described_class.build_full(ip: '10.0.0.1', user: 'admin', password: 'pass')
    end

    it 'supports Kerberos transport' do
      expect(WinRM::Connection).to receive(:new).with(hash_including(
                                                        transport: :kerberos, realm: 'EXAMPLE.COM', keytab: '/path/to/keytab'
                                                      ))
      described_class.build_full(
        ip: '10.0.0.1', user: 'admin', password: 'pass',
        kerberos: true, realm: 'EXAMPLE.COM', keytab: '/path/to/keytab'
      )
    end

    it 'supports pass-the-hash with empty password' do
      expect(WinRM::Connection).to receive(:new).with(hash_including(
                                                        transport: :negotiate, password: ''
                                                      ))
      described_class.build_full(ip: '10.0.0.1', user: 'admin', password: '', hash: 'aad3b435b51404eeaad3b435b51404ee')
    end

    it 'warns on deprecated positional Hash argument' do
      expect do
        described_class.build_full({ ip: '10.0.0.1', user: 'u', password: 'p' })
      end.to output(/DEPRECATION/).to_stderr
    end

    it 'merges opts hash with kwargs (kwargs win)' do
      conn = described_class.build_full({ user: 'from_hash' }, user: 'from_kwarg', password: 'p', ip: '10.0.0.1')
      expect(conn).not_to be_nil
    end

    it 'does not crash on WinRM::Connection construction error' do
      allow(WinRM::Connection).to receive(:new).and_raise(StandardError, 'boom')
      expect do
        conn = described_class.build_full(ip: '10.0.0.1', user: 'u', password: 'p')
        expect(conn).to be_nil
      end.not_to raise_error
    end

    it 'sets no_ssl_peer_verification to false by default' do
      expect(WinRM::Connection).to receive(:new).with(hash_including(
                                                        no_ssl_peer_verification: false
                                                      ))
      described_class.build_full(ip: '10.0.0.1', user: 'u', password: 'p', debug: false)
    end

    it 'passes debug flag through' do
      expect(WinRM::Connection).to receive(:new).with(hash_including(debug: true))
      described_class.build_full(ip: '10.0.0.1', user: 'u', password: 'p', debug: true)
    end
  end

  describe EvilCTF::Connection::WinRMShellAdapter do
    let(:mock_shell) do
      instance_double('Shell', run: OpenStruct.new(output: 'Hello', exitcode: 0), close: nil)
    end
    subject(:adapter) { described_class.new(mock_shell) }

    it 'wraps a shell and normalizes output' do
      result = adapter.run('hostname')
      expect(result.output).to eq('Hello')
      expect(result.exitcode).to eq(0)
    end

    it 'returns exitcode 255 on shell error' do
      allow(mock_shell).to receive(:run).and_raise(RuntimeError, 'connection lost')
      result = adapter.run('whoami')
      expect(result.exitcode).to eq(255)
      expect(result.output).to include('connection lost')
    end

    it 'handles nil exitcode gracefully' do
      allow(mock_shell).to receive(:run).and_return(OpenStruct.new(output: 'ok', exitcode: nil))
      result = adapter.run('echo hi')
      expect(result.exitcode).to eq(0)
    end

    it 'calls close on the underlying shell' do
      expect(mock_shell).to receive(:close)
      adapter.close
    end

    it 'does not raise if underlying shell lacks close' do
      stub = instance_double('Shell', run: OpenStruct.new(output: '', exitcode: 0))
      a = described_class.new(stub)
      expect { a.close }.not_to raise_error
    end
  end
end

RSpec.describe EvilCTF::ConnectionValidator do
  let(:mock_conn) do
    instance_double('WinRM::Connection')
  end

  before do
    allow(mock_conn).to receive(:shell).and_return(mock_shell)
  end

  let(:mock_shell) do
    s = instance_double('WinRM::Shell')
    allow(s).to receive(:run).and_return(OpenStruct.new(output: 'DESKTOP-ABC123', exitcode: 0))
    allow(s).to receive(:close)
    s
  end

  describe '.validate' do
    it 'returns ok: true with hostname on success' do
      result = described_class.validate(mock_conn, timeout: 5)
      expect(result[:ok]).to eq(true)
      expect(result[:hostname]).to eq('DESKTOP-ABC123')
    end

    it 'strips whitespace from hostname' do
      allow(mock_shell).to receive(:run).and_return(OpenStruct.new(output: "  DESKTOP-ABC\n", exitcode: 0))
      result = described_class.validate(mock_conn)
      expect(result[:hostname]).to eq('DESKTOP-ABC')
    end

    it 'closes the validation shell even on success' do
      expect(mock_shell).to receive(:close)
      described_class.validate(mock_conn)
    end

    it 'closes the validation shell even on error' do
      allow(mock_conn).to receive(:shell).and_raise(WinRM::WinRMAuthorizationError.new('bad creds'))
      expect(mock_shell).not_to receive(:close) # shell was never created
      result = described_class.validate(mock_conn)
      expect(result[:ok]).to eq(false)
      expect(result[:error]).to include('WinRMAuthorizationError')
    end

    it 'handles WinRM errors with class name in prefix' do
      allow(mock_conn).to receive(:shell).and_raise(WinRM::WinRMAuthorizationError.new('denied'))
      result = described_class.validate(mock_conn)
      expect(result[:ok]).to eq(false)
      expect(result[:error]).to include('WinRMAuthorizationError')
    end

    it 'handles generic errors gracefully' do
      allow(mock_conn).to receive(:shell).and_raise(StandardError, 'timeout')
      result = described_class.validate(mock_conn)
      expect(result[:ok]).to eq(false)
      expect(result[:error]).to include('StandardError')
    end

    it 'passes timeout option to shell.run' do
      expect(mock_shell).to receive(:run).with('hostname', timeout: 30)
      described_class.validate(mock_conn, timeout: 30)
    end

    it 'returns hostname nil on authentication failure' do
      allow(mock_conn).to receive(:shell).and_raise(WinRM::WinRMAuthorizationError.new('auth failed'))
      result = described_class.validate(mock_conn)
      expect(result[:hostname]).to be_nil
    end
  end
end
