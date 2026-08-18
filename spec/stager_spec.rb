# frozen_string_literal: true

require 'spec_helper'
require 'digest'
require 'tmpdir'
require_relative '../lib/evil_ctf/tools'
require_relative '../lib/evil_ctf/uploader'

RSpec.describe EvilCTF::Tools::Stager do
  let(:registry) do
    {
      'sharphound' => {
        name: 'SharpHound (BloodHound Collector)',
        filename: 'SharpHound.exe',
        search_patterns: ['SharpHound.exe'],
        description: 'BloodHound AD collector',
        download_url: 'https://example.com/SharpHound.exe',
        recommended_remote: 'C:\\Users\\Public\\SharpHound.exe',
        category: 'recon',
        zip: false,
        backup_urls: [],
        auto_execute: false
      }
    }
  end
  let(:shell) { instance_double('Shell') }

  def make_local_tool(content: 'FAKE-BINARY')
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'SharpHound.exe')
      File.write(path, content)
      yield path
    end
  end

  def stub_hash_check(_path, output)
    allow(EvilCTF::Execution).to receive(:run)
      .with(shell, /Test-Path -LiteralPath 'C:\\Users\\Public\\SharpHound\.exe'/, timeout: 60)
      .and_return(OpenStruct.new(ok: true, output: output))
  end

  describe '.remote_file_current?' do
    it 'returns true when the remote SHA-256 matches the local file' do
      make_local_tool do |path|
        stub_hash_check(path, "HASH::#{Digest::SHA256.file(path).hexdigest}")

        expect(described_class.remote_file_current?(shell, 'C:\\Users\\Public\\SharpHound.exe', path))
          .to eq(true)
      end
    end

    it 'is case-insensitive on the remote hash' do
      make_local_tool do |path|
        stub_hash_check(path, "HASH::#{Digest::SHA256.file(path).hexdigest.upcase}")

        expect(described_class.remote_file_current?(shell, 'C:\\Users\\Public\\SharpHound.exe', path))
          .to eq(true)
      end
    end

    it 'returns false when the remote hash differs (different build)' do
      make_local_tool do |path|
        stub_hash_check(path, "HASH::#{'0' * 64}")

        expect(described_class.remote_file_current?(shell, 'C:\\Users\\Public\\SharpHound.exe', path))
          .to eq(false)
      end
    end

    it 'returns false when the remote file is missing' do
      make_local_tool do |path|
        stub_hash_check(path, 'MISSING')

        expect(described_class.remote_file_current?(shell, 'C:\\Users\\Public\\SharpHound.exe', path))
          .to eq(false)
      end
    end

    it 'returns false without raising when the check command errors' do
      allow(EvilCTF::Execution).to receive(:run).and_raise('connection lost')

      make_local_tool do |path|
        expect(described_class.remote_file_current?(shell, 'C:\\Users\\Public\\SharpHound.exe', path))
          .to eq(false)
      end
    end
  end

  describe '.safe_autostage' do
    before do
      allow(described_class).to receive(:get_system_architecture).and_return('x64')
    end

    it 'skips the upload when the remote file already matches (hash hit)' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        stub_hash_check(path, "HASH::#{Digest::SHA256.file(path).hexdigest}")
        expect(EvilCTF::Uploader).not_to receive(:upload_file)

        result = described_class.safe_autostage('sharphound', shell, {}, nil,
                                                registry: registry, download_tool_proc: ->(_k) { path })

        expect(result).to eq('C:\\Users\\Public\\SharpHound.exe')
      end
    end

    it 'uploads when the remote file is a different build' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        stub_hash_check(path, "HASH::#{'0' * 64}")
        expect(EvilCTF::Uploader).to receive(:upload_file)
          .and_return(true)

        result = described_class.safe_autostage('sharphound', shell, {}, nil,
                                                registry: registry, download_tool_proc: ->(_k) { path })

        expect(result).to eq('C:\\Users\\Public\\SharpHound.exe')
      end
    end

    it 'uploads when the remote file is missing' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        stub_hash_check(path, 'MISSING')
        expect(EvilCTF::Uploader).to receive(:upload_file).and_return(true)

        described_class.safe_autostage('sharphound', shell, {}, nil,
                                       registry: registry, download_tool_proc: ->(_k) { path })
      end
    end

    it 'skips the hash check with --fresh (force re-stage)' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        expect(EvilCTF::Execution).not_to receive(:run)
        expect(EvilCTF::Uploader).to receive(:upload_file).and_return(true)

        described_class.safe_autostage('sharphound', shell, { fresh: true }, nil,
                                       registry: registry, download_tool_proc: ->(_k) { path })
      end
    end

    it 'skips the hash check with --random-names (destination is fresh by definition)' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        expect(EvilCTF::Execution).not_to receive(:run)
        expect(EvilCTF::Uploader).to receive(:upload_file).and_return(true)

        result = described_class.safe_autostage('sharphound', shell, { random_names: true }, nil,
                                                registry: registry, download_tool_proc: ->(_k) { path })

        # randomized destination is returned, not the registry default
        expect(result).to match(/C:\\Users\\Public\\svc_[0-9a-f]{8}\.exe/)
      end
    end

    it 'skips the hash check with --stealth (ADS stream is fresh by definition)' do
      make_local_tool do |path|
        allow(described_class).to receive(:find_tool_on_disk).and_return(path)
        expect(EvilCTF::Execution).not_to receive(:run)
        expect(EvilCTF::Uploader).to receive(:upload_file).and_return(true)

        result = described_class.safe_autostage('sharphound', shell, { stealth: true }, nil,
                                                registry: registry, download_tool_proc: ->(_k) { path })

        expect(result).to include(':')
      end
    end
  end
end
