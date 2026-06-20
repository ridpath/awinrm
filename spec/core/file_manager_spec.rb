# frozen_string_literal: true

require 'base64'
require 'fileutils'
require 'tmpdir'
require_relative '../spec_helper'
require_relative '../../lib/evil_ctf/shell_adapter'
require_relative '../../lib/evil_ctf/errors'

RSpec.describe EvilCTF::ShellAdapter::WinRMShellAdapter::InternalFileManager do
  let(:shell_adapter) { instance_double('ShellAdapter') }
  let(:manager) { described_class.new(shell_adapter: shell_adapter) }

  describe '#upload' do
    it 'verifies SHA256 successfully after chunked upload' do
      Dir.mktmpdir do |dir|
        local_path = File.join(dir, 'payload.bin')
        File.binwrite(local_path, 'hello-world')

        allow(shell_adapter).to receive(:run) do |cmd|
          case cmd
          when /WriteAllBytes/
            OpenStruct.new(output: 'OK')
          when /FromBase64String/
            OpenStruct.new(output: 'OK')
          when /Get-FileHash/
            OpenStruct.new(output: Digest::SHA256.file(local_path).hexdigest)
          else
            OpenStruct.new(output: 'OK')
          end
        end

        expect(manager.upload(local_path: local_path, remote_path: 'C:\\Users\\Public\\payload.bin',
                              verify: true)).to eq(true)
      end
    end

    it 'raises when SHA256 does not match' do
      Dir.mktmpdir do |dir|
        local_path = File.join(dir, 'payload.bin')
        File.binwrite(local_path, 'hello-world')

        allow(shell_adapter).to receive(:run) do |cmd|
          case cmd
          when /WriteAllBytes/
            OpenStruct.new(output: 'OK')
          when /FromBase64String/
            OpenStruct.new(output: 'OK')
          when /Get-FileHash/
            OpenStruct.new(output: 'deadbeef' * 8)
          else
            OpenStruct.new(output: 'OK')
          end
        end

        expect do
          manager.upload(local_path: local_path, remote_path: 'C:\\Users\\Public\\payload.bin', verify: true)
        end.to raise_error(EvilCTF::Errors::UploadError, /hash mismatch/i)
      end
    end
  end

  describe '#download' do
    it 'raises when downloaded file hash does not match remote hash' do
      Dir.mktmpdir do |dir|
        local_path = File.join(dir, 'download.bin')
        encoded = Base64.strict_encode64('content')
        calls = 0

        allow(shell_adapter).to receive(:run) do |cmd|
          case cmd
          when /OpenRead/
            calls += 1
            OpenStruct.new(output: calls == 1 ? encoded : '')
          when /Get-FileHash/
            OpenStruct.new(output: 'cafebabe' * 8)
          else
            OpenStruct.new(output: 'OK')
          end
        end

        expect do
          manager.download(remote_path: 'C:\\Users\\Public\\download.bin', local_path: local_path, verify: true)
        end.to raise_error(EvilCTF::Errors::DownloadError, /hash mismatch/i)
      end
    end
  end
end
