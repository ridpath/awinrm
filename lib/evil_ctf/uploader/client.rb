# frozen_string_literal: true
require 'base64'
require 'fileutils'
require 'digest'
require_relative '../tools/crypto'
require_relative '../shell_adapter'
require_relative '../logger'

module EvilCTF
  module Uploader
    class Client
      DEFAULT_CHUNK_SIZE = 64 * 1024

      def initialize(shell_or_adapter, logger = nil)
        # Accept either a raw shell/connection or an adapter; wrap to a consistent interface
        @shell_adapter = EvilCTF::ShellAdapter.wrap(shell_or_adapter)
        @logger = logger || EvilCTF::Logger.new(nil) rescue nil
      end

      def upload_file(local_path, remote_path, encrypt: false, chunk_size: DEFAULT_CHUNK_SIZE, verify: false, xor_key: nil)
        return false unless File.exist?(local_path)

        local_sha256 = Digest::SHA256.file(local_path).hexdigest

        # Ensure remote directory exists
        remote_dir = File.dirname(remote_path).gsub('\\', '\\\\')
        ps_mkdir = <<~PS
          try {
            $d = '#{remote_dir}'
            if (!(Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
            "OK"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS
        @shell_adapter.run(ps_mkdir)

        # Use a temporary remote file and move into place atomically after upload
        tmp_token = Time.now.to_i.to_s + rand(9999).to_s
        tmp_remote = remote_path + ".part_#{tmp_token}"
        escaped_tmp = tmp_remote.gsub("'", "''")

        # Prefer WinRM::FS upload if available for performance and reliability
        fm = @shell_adapter.respond_to?(:file_manager) ? @shell_adapter.file_manager : nil
        if fm && fm.respond_to?(:upload)
          begin
            @logger&.info("[Uploader] Using WinRM::FS upload via adapter for #{local_path} -> #{tmp_remote}")
            fm.upload(local_path, tmp_remote)
            # move into place
            escaped_final = remote_path.gsub("'", "''")
            ps_rm_final = <<~PS
              try { Remove-Item -Path '#{escaped_final}' -Force -ErrorAction SilentlyContinue; "OK" } catch { "ERROR: $($_.Exception.Message)" }
            PS
            @shell_adapter.run(ps_rm_final)
            ps_move = <<~PS
              try {
                Move-Item -Path '#{escaped_tmp}' -Destination '#{escaped_final}' -Force
                "MOVED"
              } catch {
                "ERROR: $($_.Exception.Message)"
              }
            PS
            @shell_adapter.run(ps_move)
            if verify
              ps = "(Get-FileHash -Path '#{remote_path}' -Algorithm SHA256).Hash"
              res = @shell_adapter.run(ps)
              remote_raw = res && res.output ? res.output.to_s : ''
              remote_hash = remote_raw.scan(/[0-9A-Fa-f]{64}/).first
              return { ok: true, local_hash: local_sha256, remote_hash: remote_hash, tmp_hash: remote_hash }
            end
            return true
          rescue => e
            @logger&.warn("[Uploader] WinRM::FS upload failed, falling back to chunked upload: #{e.message}")
            # fallthrough to legacy chunked upload
          end
        end

        # Initialize tmp remote file
        ps_init = <<~PS
          try {
            $path = '#{escaped_tmp}'
            if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
            $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
            $fs.Close()
            "INIT"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS
        init = @shell_adapter.run(ps_init)
        return false unless init && init.output.to_s.include?('INIT')

        # Chunked upload with resume and per-chunk sanity checks
        File.open(local_path, 'rb') do |f|
          escaped_tmp_q = tmp_remote.gsub("'", "''")
          # Check for existing tmp file to resume
          ps_exists = "Test-Path '#{escaped_tmp_q}'"
          exist_res = @shell_adapter.run(ps_exists)
          offset = 0
          if exist_res && exist_res.output.to_s.strip == 'True'
            ps_len = "(Get-Item -Path '#{escaped_tmp_q}' -ErrorAction SilentlyContinue).Length"
            len_res = @shell_adapter.run(ps_len)
            offset = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
            @logger&.info("[Uploader] Resuming upload at offset #{offset}") if offset && offset > 0
            f.seek(offset)
          else
            # create empty tmp file
            ps_init = <<~PS
              try {
                $path = '#{escaped_tmp_q}'
                if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
                $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
                $fs.Close()
                "INIT"
              } catch {
                "ERROR: $($_.Exception.Message)"
              }
            PS
            init = @shell_adapter.run(ps_init)
            return false unless init && init.output.to_s.include?('INIT')
          end

          idx = (offset / chunk_size)
          bytes_sent = offset
          while (buf = f.read(chunk_size))
            payload = if xor_key
                        EvilCTF::Tools::Crypto.xor_crypt(buf, xor_key)
                      elsif encrypt
                        EvilCTF::Tools::Crypto.xor_crypt(buf, 0x42)
                      else
                        buf
                      end
            b64 = Base64.strict_encode64(payload)
            escaped_remote = tmp_remote.gsub("'", "''")
            ps = <<~PS
              try {
                $b64 = @'
#{b64}
'@
                $bytes = [Convert]::FromBase64String($b64)
                $path = '#{escaped_remote}'
                $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
                $fs.Write($bytes, 0, $bytes.Length)
                $fs.Close()
                "CHUNK #{idx}"
              } catch {
                "ERROR: $($_.Exception.Message)"
              }
            PS
            res = @shell_adapter.run(ps)
            unless res && res.output.to_s.include?("CHUNK #{idx}")
              @logger&.error("[Uploader] Chunk #{idx} failed to write")
              return false
            end

            # Sanity check: verify remote tmp length increased appropriately
            bytes_sent += buf.bytesize
            ps_len_check = "(Get-Item -Path '#{escaped_remote}' -ErrorAction SilentlyContinue).Length"
            len_res = @shell_adapter.run(ps_len_check)
            remote_len = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
            if remote_len < bytes_sent
              @logger&.warn("[Uploader] Remote tmp length (#{remote_len}) less than expected (#{bytes_sent}), retrying chunk #{idx}")
              # Simple retry once
              res_retry = @shell_adapter.run(ps)
              len_res = @shell_adapter.run(ps_len_check)
              remote_len = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
              if remote_len < bytes_sent
                @logger&.error("[Uploader] Chunk #{idx} still missing after retry; aborting")
                return false
              end
            end

            idx += 1
          end
        end

        # Compute hash of tmp remote file
        tmp_hash = nil
        if verify
          ps_tmp_hash = "(Get-FileHash -Path '#{tmp_remote}' -Algorithm SHA256).Hash"
          res_tmp = @shell_adapter.run(ps_tmp_hash)
          tmp_raw = res_tmp && res_tmp.output ? res_tmp.output.to_s : ''
          tmp_hash = tmp_raw.scan(/[0-9A-Fa-f]{64}/).first
          if tmp_hash.nil? || tmp_hash.empty?
            cleaned = tmp_raw.gsub(/[^0-9A-Fa-f]/, '')
            tmp_hash = cleaned[0,64] if cleaned && cleaned.length >= 64
          end
        end

        # Ensure final does not exist, then move temp file into place atomically (or try copy as fallback)
        escaped_final = remote_path.gsub("'", "''")
        ps_rm_final = <<~PS
          try { Remove-Item -Path '#{escaped_final}' -Force -ErrorAction SilentlyContinue; "OK" } catch { "ERROR: $($_.Exception.Message)" }
        PS
        @shell_adapter.run(ps_rm_final)
        
        # Move temp file into place
        ps_move = <<~PS
          try {
            Move-Item -Path '#{escaped_tmp}' -Destination '#{escaped_final}' -Force
            "MOVED"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS
        move_res = @shell_adapter.run(ps_move)
        # If move failed, try Copy-Item fallback
        if move_res && move_res.output.to_s.start_with?('ERROR')
          ps_copy = <<~PS
            try {
              Copy-Item -Path '#{escaped_tmp}' -Destination '#{escaped_final}' -Force
              Remove-Item -Path '#{escaped_tmp}' -Force
              "COPIED"
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS
          copy_res = @shell_adapter.run(ps_copy)
        end

        if verify
          ps = "(Get-FileHash -Path '#{remote_path}' -Algorithm SHA256).Hash"
          res = @shell_adapter.run(ps)
          remote_raw = res && res.output ? res.output.to_s : ''
          remote_hash = remote_raw.scan(/[0-9A-Fa-f]{64}/).first
          if remote_hash.nil? || remote_hash.empty?
            cleaned = remote_raw.gsub(/[^0-9A-Fa-f]/, '')
            remote_hash = cleaned[0,64] if cleaned && cleaned.length >= 64
          end
          return { ok: true, local_hash: local_sha256, remote_hash: remote_hash, tmp_hash: tmp_hash }
        end

        true
      rescue => e
        warn "[!] Upload failed: #{e.class}: #{e.message}"
        false
      end

      def download_file(remote_path, local_path, xor_key: nil, allow_empty: true)
        # Verify remote exists
        exist = @shell_adapter.run("Test-Path '#{remote_path.gsub("'", "''")}'")
        return false unless exist && exist.output.to_s.strip == 'True'

        ps_read = <<~PS
          try {
            $path = '#{remote_path.gsub("'", "''")}'
            $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
            $b64 | Out-String -Width 9999999
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        # Prefer WinRM::FS file manager if available for efficient binary transfer
        fm = @shell_adapter.respond_to?(:file_manager) ? @shell_adapter.file_manager : nil
        if fm
          # Use WinRM::FS to download directly
          begin
            tmp_local = local_path + ".winrmfs.tmp"
            fm.read(remote_path, tmp_local)
            FileUtils.mv(tmp_local, local_path)
            return true
          rescue => e
            # fallback to legacy method
            warn "[!] WinRM::FS download failed, falling back: #{e.message}"
          end
        end

        result = @shell_adapter.run(ps_read)
        return false if result.nil? || result.output.nil?
        raw = result.output.to_s

        # Extract candidate base64 blocks
        candidates = raw.scan(/[A-Za-z0-9+\/=\s]{32,}/m).map { |s| s.gsub(/\s+/, '') }
        candidates << raw.gsub(/[^A-Za-z0-9+\/=]/, '')
        b64 = candidates.max_by(&:length).to_s
        return false if b64.empty?

        data = nil
        begin
          data = Base64.strict_decode64(b64)
        rescue
          begin
            data = Base64.decode64(b64)
          rescue
            # Try sanitizing non-base64 chars and decode again
            cleaned = b64.gsub(/[^A-Za-z0-9+\/=]/, '')
            begin
              data = Base64.decode64(cleaned)
            rescue => e
              warn "[!] Invalid base64 from remote after sanitize: #{e.message}"
              return false
            end
          end
        end

        data = EvilCTF::Tools::Crypto.xor_crypt(data, xor_key) if xor_key
        FileUtils.mkdir_p(File.dirname(local_path))
        File.open(local_path, 'wb') { |f| f.write(data) }
        true
      rescue => e
        warn "[!] Download failed: #{e.class}: #{e.message}"
        false
      end
    end
  end
end
