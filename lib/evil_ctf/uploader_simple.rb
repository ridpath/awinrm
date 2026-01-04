# frozen_string_literal: true
require 'base64'
require 'fileutils'
require_relative 'tools/crypto'
require 'digest'

module EvilCTF
  module Uploader
    DEFAULT_CHUNK_SIZE = 64 * 1024

    def self.upload_file(local_path, remote_path, shell, encrypt: false, chunk_size: DEFAULT_CHUNK_SIZE, xor_key: nil, verify: false)
      return false unless File.file?(local_path)

      # Compute local SHA256 for verification when requested
      local_hash = Digest::SHA256.file(local_path).hexdigest

      File.open(local_path, 'rb') do |f|
        idx = 0
        while (buf = f.read(chunk_size))
          # Prefer explicit xor_key when provided, otherwise honor encrypt boolean with default key
          if xor_key
            payload = EvilCTF::Tools::Crypto.xor_crypt(buf, xor_key)
          elsif encrypt
            payload = EvilCTF::Tools::Crypto.xor_crypt(buf, 0x42)
          else
            payload = buf
          end

          b64 = Base64.strict_encode64(payload)
          ps = <<~PS
            # Upload chunk #{idx}
            $bytes = [Convert]::FromBase64String('#{b64}')
            $fs = [IO.File]::Open('#{remote_path}', [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Close()
          PS
          res = shell.run(ps)
          return false unless res && res.respond_to?(:output)
          idx += 1
        end
      end

      # Optionally verify remote SHA256
      if verify
        ps = "(Get-FileHash -Path '#{remote_path}' -Algorithm SHA256).Hash"
        res = shell.run(ps)
        remote_raw = res && res.respond_to?(:output) ? res.output.to_s : ''
        # Extract 64-hex chars or fallback to stripping non-hex and taking first 64
        remote_hash = remote_raw.scan(/[0-9A-Fa-f]{64}/).first
        if remote_hash.nil? || remote_hash.empty?
          cleaned = remote_raw.gsub(/[^0-9A-Fa-f]/, '')
          remote_hash = cleaned[0, 64] if cleaned && cleaned.length >= 64
        end
        return { ok: true, local_hash: local_hash, remote_hash: remote_hash }
      end

      true
    rescue => e
      puts "[!] Upload failed: #{e.message}"
      false
    end

    def self.download_file(remote_path, local_path, shell, xor_key: nil)
        # Request Base64 output from remote
        ps = "$b = [Convert]::ToBase64String([IO.File]::ReadAllBytes('#{remote_path}')); Write-Output $b"
        res = shell.run(ps)
        return false unless res && res.respond_to?(:output)

        raw = res.output.to_s

        # Extract candidate Base64 blocks (allow whitespace/newlines between blocks)
        candidates = raw.scan(/[A-Za-z0-9+\/=\s]{80,}/m).map { |s| s.gsub(/\s+/, '') }
        # Fallback to stripping all non-base64 chars from the entire output
        candidates << raw.gsub(/[^A-Za-z0-9+\/=]/, '')

        # Choose the longest candidate and attempt to decode
        b64 = candidates.max_by(&:length).to_s
        if b64.empty?
          puts "[!] No base64 data found in remote output"
          return false
        end

        data = nil
        begin
          data = Base64.strict_decode64(b64)
        rescue => _e_strict
          begin
            # Try a more lenient decode
            data = Base64.decode64(b64)
          rescue => e
            puts "[!] Invalid base64 from remote: #{e.message}"
            return false
          end
        end

        data = EvilCTF::Tools::Crypto.xor_crypt(data, xor_key) if xor_key
        FileUtils.mkdir_p(File.dirname(local_path))
        File.open(local_path, 'wb') { |f| f.write(data) }
        true
    end
  end
end
