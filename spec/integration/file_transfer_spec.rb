# frozen_string_literal: true

require 'securerandom'
require 'tmpdir'

require_relative 'integration_helper'
require_relative '../../lib/evil_ctf/execution'
require_relative '../../lib/evil_ctf/uploader'
require_relative '../../lib/evil_ctf/uploader/client'
require_relative '../../lib/evil_ctf/errors'

# Shells are created inside each example (never in before(:all)) so a
# disabled/skipped suite performs zero network work.
RSpec.describe 'Live file transfer (upload + download round trip)', integration: true do
  let(:shell) { EvilCTF::Connection.build_full(**AwinrmIntegration.build_opts).shell(:powershell) }

  it 'uploads a file, downloads it back, and verifies byte-for-byte equality' do
    remote_path = "C:/Users/Public/awinrm_it_#{SecureRandom.hex(4)}.txt"
    content = "awinrm integration round-trip #{SecureRandom.uuid}\n"
    Dir.mktmpdir('awinrm-it') do |dir|
      local_path = File.join(dir, 'roundtrip.txt')
      File.write(local_path, content)

      client = EvilCTF::Uploader::Client.new(shell, nil)

      # Chunked WinRM upload (no SMB in the test VM setup).
      expect(client.upload_file(local_path, remote_path, try_smb: false, verify: true)).to eq(true)

      # Independent existence check via the product execution path.
      check = EvilCTF::Execution.run(shell, "Test-Path -LiteralPath '#{remote_path}'",
                                     timeout: AwinrmIntegration::RUN_TIMEOUT)
      expect(check.exitcode).to eq(0)
      expect(check.output.strip).to eq('True')

      # Round trip back down.
      downloaded = File.join(dir, 'roundtrip.downloaded.txt')
      expect(client.download_file(remote_path, downloaded)).to eq(true)
      expect(File.read(downloaded)).to eq(content)
    end
  ensure
    AwinrmIntegration.safe_close(shell)
  end

  it 'raises DownloadError for a missing remote file' do
    missing = "C:/Users/Public/awinrm_it_missing_#{SecureRandom.hex(4)}.txt"
    Dir.mktmpdir('awinrm-it') do |dir|
      client = EvilCTF::Uploader::Client.new(shell, nil)
      expect do
        client.download_file(missing, File.join(dir, 'nope.txt'))
      end.to raise_error(EvilCTF::Errors::DownloadError)
    end
  ensure
    AwinrmIntegration.safe_close(shell)
  end
end
