# frozen_string_literal: true

require 'tmpdir'
require 'spec_helper'
require_relative '../lib/evil_ctf/uploader/smb'

RSpec.describe EvilCTF::Uploader::SmbUpload do
  describe '.upload' do
    before do
      # Stub smbclient availability check — assume it's installed
      allow(described_class).to receive(:smbclient_available?).and_return(true)
    end

    it 'returns nil when smbclient is not available' do
      allow(described_class).to receive(:smbclient_available?).and_return(false)
      result = described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\Users\\Public\\test.exe',
        ip: '10.0.0.1', user: 'admin', password: 'pass'
      )
      expect(result).to be_nil
    end

    it 'returns nil when port 445 is closed' do
      allow(described_class).to receive(:port_open?).and_return(false)
      result = described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\Users\\Public\\test.exe',
        ip: '10.0.0.1', user: 'admin', password: 'pass'
      )
      expect(result).to be_nil
    end

    it 'returns nil when smbclient command fails' do
      allow(described_class).to receive(:port_open?).and_return(true)
      # Stub the share attempt to return nil (failure)
      allow(described_class).to receive(:try_share).and_return(nil)
      result = described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\Users\\Public\\test.exe',
        ip: '10.0.0.1', user: 'admin', password: 'pass'
      )
      expect(result).to be_nil
    end

    it 'returns success hash when smbclient succeeds' do
      allow(described_class).to receive(:port_open?).and_return(true)
      allow(described_class).to receive(:try_share).and_return(
        { ok: true, method: 'smb', share: 'C$', path: 'Users\\Public\\test.exe' }
      )
      result = described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\Users\\Public\\test.exe',
        ip: '10.0.0.1', user: 'admin', password: 'pass'
      )
      expect(result).to include(ok: true, share: 'C$')
    end

    it 'builds auth with NTLM hash format' do
      allow(described_class).to receive(:port_open?).and_return(true)
      expect(described_class).to receive(:try_share).with(
        anything, anything, anything, '10.0.0.1',
        a_string_including('--pw-nt-hash')
      ).and_return(nil).at_least(:once)

      described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\test.exe',
        ip: '10.0.0.1', user: 'admin', hash: 'aad3b435b51404eeaad3b435b51404ee:deadbeef'
      )
    end

    it 'tries ADMIN$ first then C$' do
      allow(described_class).to receive(:port_open?).and_return(true)
      tried_shares = []
      allow(described_class).to receive(:try_share) do |share, *|
        tried_shares << share
        nil
      end

      described_class.upload(
        local_path: '/tmp/test.exe', remote_path: 'C:\\test.exe',
        ip: '10.0.0.1', user: 'admin', password: 'pass'
      )
      expect(tried_shares).to eq(%w[ADMIN$ C$])
    end
  end

  describe '.port_open?' do
    it 'returns true when TCP connect succeeds' do
      socket = instance_double(TCPSocket, close: nil)
      allow(TCPSocket).to receive(:new).with('10.0.0.1', 445).and_return(socket)
      result = described_class.send(:port_open?, '10.0.0.1', 445)
      expect(result).to be(true)
    end

    it 'returns false on connection refused' do
      allow(TCPSocket).to receive(:new).and_raise(Errno::ECONNREFUSED)
      result = described_class.send(:port_open?, '10.0.0.1', 445)
      expect(result).to be(false)
    end

    it 'returns false on timeout' do
      allow(TCPSocket).to receive(:new).and_raise(Timeout::Error)
      result = described_class.send(:port_open?, '10.0.0.1', 445)
      expect(result).to be(false)
    end
  end

  describe '.smb_relative_path' do
    it 'strips drive letter for C$' do
      result = described_class.send(:smb_relative_path, 'C:\\Users\\Public\\tool.exe', 'C$')
      expect(result).to eq('Users\\Public\\tool.exe')
    end

    it 'strips Windows prefix for ADMIN$' do
      result = described_class.send(:smb_relative_path, 'C:\\Windows\\System32\\evil.dll', 'ADMIN$')
      expect(result).to eq('System32\\evil.dll')
    end

    it 'returns nil for C$ path without drive letter' do
      result = described_class.send(:smb_relative_path, 'Users\\tool.exe', 'C$')
      expect(result).to be_nil
    end

    it 'normalizes forward slashes' do
      result = described_class.send(:smb_relative_path, 'C:/Users/Public/tool.exe', 'C$')
      expect(result).to eq('Users\\Public\\tool.exe')
    end
  end
end
