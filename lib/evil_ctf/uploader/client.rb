# frozen_string_literal: true
require 'base64'
require 'fileutils'
require 'digest'
require_relative '../tools/crypto'
require_relative '../shell_adapter'
require_relative '../logger'
require_relative '../errors'
require_relative '../utils'
require_relative '../app_state'

module EvilCTF
  require 'colorize'
  module Uploader
    class Client
      DEFAULT_CHUNK_SIZE = 64 * 1024

      def initialize(shell_or_adapter, logger = nil)
        @shell_adapter = EvilCTF::ShellAdapter.wrap(shell_or_adapter)
        @logger = logger || EvilCTF::Logger.new(nil) rescue nil
      end


      def upload_file(local_path, remote_path, encrypt: false, chunk_size: DEFAULT_CHUNK_SIZE, verify: true, xor_key: nil)
        unless File.exist?(local_path)
          puts '[!] Local file missing'.colorize(:red)
          raise ::EvilCTF::Errors::UploadError, 'local file missing'
        end

        local_sha256 = Digest::SHA256.file(local_path).hexdigest

        # Check PowerShell availability before upload
        ps_check = "try { $PSVersionTable.PSVersion.ToString() } catch { 'NO_POWERSHELL' }"
        check_res = @shell_adapter.run(ps_check)
        unless check_res && check_res.output && check_res.output.to_s.strip != 'NO_POWERSHELL'
          puts '[!] PowerShell not available on target. Cannot upload file.'.colorize(:red)
          @logger&.error('[Uploader] PowerShell not available on target. Cannot upload file.')
          raise ::EvilCTF::Errors::UploadError, 'PowerShell not available on target.'
        end

        # If remote_path is a directory, append the local filename
        is_dir = remote_path.end_with?('\\') || remote_path.end_with?('/')
        final_remote_path = if is_dir
          File.join(remote_path, File.basename(local_path)).gsub('/', '\\')
        else
          remote_path
        end

        # Detect if this is an ADS upload (C:\path\file.txt:adsname)
        is_ads = !!(final_remote_path =~ /:[^\\\/]+$/)

        if is_ads
          # --- ADS upload logic using Add-Content -Encoding Byte ---
          ads_path = EvilCTF::Utils.escape_ps_string(final_remote_path)
          begin
            File.open(local_path, 'rb') do |f|
              idx = 0
              while (buf = f.read(chunk_size))
                payload = if xor_key
                            EvilCTF::Tools::Crypto.xor_crypt(buf, xor_key)
                          elsif encrypt
                            EvilCTF::Tools::Crypto.xor_crypt(buf, 0x42)
                          else
                            buf
                          end
                b64 = Base64.strict_encode64(payload)
                ps = <<~PS
                  try {
                    $b64 = @'
#{b64}
'@
                    $bytes = [Convert]::FromBase64String($b64)
                    Add-Content -Path '#{ads_path}' -Value $bytes -Encoding Byte
                    "ADS_CHUNK #{idx}"
                  } catch {
                    "ERROR: $($_.Exception.Message)"
                  }
                PS
                res = @shell_adapter.run(ps)
                unless res && res.output.to_s.include?("ADS_CHUNK #{idx}")
                  @logger&.error("[Uploader] ADS chunk #{idx} failed to write. Script: #{ps.strip}\nOutput: #{res&.output}")
                  raise ::EvilCTF::Errors::UploadError, "ADS chunk #{idx} failed to write. Output: #{res&.output}"
                end
                idx += 1
              end
            end
            # Optionally verify by reading back the ADS length
            if verify
              ps_len = <<~PS
                try {
                  $ads = '#{ads_path}'
                  (Get-Item -Path $ads -ErrorAction SilentlyContinue).Length
                } catch { "ERROR: $($_.Exception.Message)" }
              PS
              len_res = @shell_adapter.run(ps_len)
              remote_len = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : nil
              local_len = File.size(local_path)
              return { ok: remote_len == local_len, local_len: local_len, remote_len: remote_len }
            end
            return true
          rescue => e
            @logger&.error("[Uploader] ADS upload failed: #{e.class}: #{e.message}")
            raise ::EvilCTF::Errors::UploadError, e.message
          end
        end

        # --- Standard file upload logic (unchanged) ---
        # Ensure remote directory exists
        remote_dir = File.dirname(final_remote_path).gsub('\\', '\\\\')
        ps_mkdir = <<~PS
          try {
            $d = '#{remote_dir}'
            if (!(Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
            "OK"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS
        mkdir_res = @shell_adapter.run(ps_mkdir)
        unless mkdir_res && mkdir_res.output.to_s.include?('OK')
          puts '[!] Failed to create remote directory on target.'.colorize(:red)
          @logger&.error("[Uploader] Failed to create remote directory. Script: #{ps_mkdir.strip}\nOutput: #{mkdir_res&.output}")
        end

        tmp_token = Time.now.to_i.to_s + rand(9999).to_s
        tmp_remote = final_remote_path + ".part_#{tmp_token}"
        escaped_tmp = EvilCTF::Utils.escape_ps_string(tmp_remote)

        # Register upload in AppState so UI can show real progress
        upload_id = "upload_#{tmp_token}_#{Thread.current.object_id}"
        begin
          EvilCTF::AppState.instance.set_upload(upload_id, { name: File.basename(local_path), total: File.size(local_path), sent: 0 })
        rescue => _e
        end

        # Use adapter file manager if available
        fm = @shell_adapter.respond_to?(:file_manager) ? @shell_adapter.file_manager : nil
        if fm && fm.respond_to?(:upload)
          begin
            @logger&.info("[Uploader] Using file manager upload via adapter for #{local_path} -> #{tmp_remote}")
            fm.upload(local_path: local_path, remote_path: tmp_remote)
            # mark as completed
            begin
              EvilCTF::AppState.instance.set_upload(upload_id, { name: File.basename(local_path), total: File.size(local_path), sent: File.size(local_path) })
            rescue
            end
            # move into place
            escaped_final = EvilCTF::Utils.escape_ps_string(final_remote_path)
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
              ps = "(Get-FileHash -Path '#{final_remote_path}' -Algorithm SHA256).Hash"
              res = @shell_adapter.run(ps)
              remote_raw = res && res.output ? res.output.to_s : ''
              remote_hash = remote_raw.scan(/[0-9A-Fa-f]{64}/).first
              if local_sha256 != remote_hash
                return { ok: false, local_hash: local_sha256, remote_hash: remote_hash, error: "Hash mismatch: local=#{local_sha256}, remote=#{remote_hash}" }
              end
              return { ok: true, local_hash: local_sha256, remote_hash: remote_hash, tmp_hash: remote_hash }
            end
            return true
          rescue => e
            @logger&.warn("[Uploader] File manager upload failed, falling back: #{e.message}")
            begin
              EvilCTF::AppState.instance.clear_upload(upload_id)
            rescue
            end
          end
        end

        # Fallback: chunked upload
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
        unless init && init.output.to_s.include?('INIT')
          puts '[!] Failed to initialize remote tmp file.'.colorize(:red)
          @logger&.error("[Uploader] Failed to initialize remote tmp file: #{tmp_remote}. Script: #{ps_init.strip}\nOutput: #{init&.output}")
          raise ::EvilCTF::Errors::UploadError, "Failed to initialize remote tmp file. Output: #{init&.output}"
        end

        begin
          File.open(local_path, 'rb') do |f|
            escaped_tmp_q = EvilCTF::Utils.escape_ps_string(tmp_remote)
            ps_exists = "Test-Path '#{escaped_tmp_q}'"
            exist_res = @shell_adapter.run(ps_exists)
            offset = 0
            if exist_res && exist_res.output.to_s.strip == 'True'
              ps_len = "(Get-Item -Path '#{escaped_tmp_q}' -ErrorAction SilentlyContinue).Length"
              len_res = @shell_adapter.run(ps_len)
              offset = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
              @logger&.info("[Uploader] Resuming upload at offset #{offset}") if offset && offset > 0
              f.seek(offset)
            end

            idx = (offset / chunk_size)
            bytes_sent = offset
            local_size = File.size(local_path)
            # ensure app_state knows total
            begin
              EvilCTF::AppState.instance.set_upload(upload_id, { name: File.basename(local_path), total: local_size, sent: bytes_sent })
            rescue
            end
            while (buf = f.read(chunk_size))
              payload = if xor_key
                          EvilCTF::Tools::Crypto.xor_crypt(buf, xor_key)
                        elsif encrypt
                          EvilCTF::Tools::Crypto.xor_crypt(buf, 0x42)
                        else
                          buf
                        end
              b64 = Base64.strict_encode64(payload)
              escaped_remote = EvilCTF::Utils.escape_ps_string(tmp_remote)
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
                @logger&.error("[Uploader] Chunk #{idx} failed to write. Script: #{ps.strip}\nOutput: #{res&.output}")
                raise ::EvilCTF::Errors::UploadError, "Chunk #{idx} failed to write. Output: #{res&.output}"
              end

              bytes_sent += buf.bytesize
              # update progress in AppState
              begin
                EvilCTF::AppState.instance.set_upload(upload_id, { name: File.basename(local_path), total: local_size, sent: bytes_sent })
              rescue
              end
              ps_len_check = "(Get-Item -Path '#{escaped_remote}' -ErrorAction SilentlyContinue).Length"
              len_res = @shell_adapter.run(ps_len_check)
              remote_len = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
              if remote_len < bytes_sent
                @logger&.warn("[Uploader] Remote tmp length (#{remote_len}) less than expected (#{bytes_sent}), retrying chunk #{idx}")
                res_retry = @shell_adapter.run(ps)
                len_res = @shell_adapter.run(ps_len_check)
                remote_len = len_res && len_res.output ? len_res.output.to_s.scan(/\d+/).first.to_i : 0
                if remote_len < bytes_sent
                  @logger&.error("[Uploader] Chunk #{idx} still missing after retry; aborting. Script: #{ps.strip}\nOutput: #{res_retry&.output}")
                  raise ::EvilCTF::Errors::UploadError, "Chunk #{idx} failed after retry. Output: #{res_retry&.output}"
                end
              end

              idx += 1
            end
          end
        rescue => e
          @logger&.error("[Uploader] Upload failed during chunked transfer: #{e.class}: #{e.message}")
          begin
            EvilCTF::AppState.instance.clear_upload(upload_id) rescue nil
          rescue
          end
          raise ::EvilCTF::Errors::UploadError, e.message
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
        escaped_final = EvilCTF::Utils.escape_ps_string(final_remote_path)
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
          ps = "(Get-FileHash -Path '#{final_remote_path}' -Algorithm SHA256).Hash"
          res = @shell_adapter.run(ps)
          remote_raw = res && res.output ? res.output.to_s : ''
          remote_hash = remote_raw.scan(/[0-9A-Fa-f]{64}/).first
          if remote_hash.nil? || remote_hash.empty?
            cleaned = remote_raw.gsub(/[^0-9A-Fa-f]/, '')
            remote_hash = cleaned[0,64] if cleaned && cleaned.length >= 64
          end
          if local_sha256 != remote_hash
            begin
              EvilCTF::AppState.instance.clear_upload(upload_id) rescue nil
            rescue
            end
            return { ok: false, local_hash: local_sha256, remote_hash: remote_hash, error: "Hash mismatch: local=#{local_sha256}, remote=#{remote_hash}" }
          end
          begin
            EvilCTF::AppState.instance.clear_upload(upload_id) rescue nil
          rescue
          end
          return { ok: true, local_hash: local_sha256, remote_hash: remote_hash, tmp_hash: tmp_hash }
        end

        begin
          EvilCTF::AppState.instance.clear_upload(upload_id) rescue nil
        rescue
        end
        true
      ensure
        # best-effort cleanup of temporary part files if any error occurred
        begin
          if defined?(tmp_remote) && tmp_remote && @shell_adapter
            ::EvilCTF::Uploader.cleanup_tmp(tmp_remote, @shell_adapter) rescue nil
          end
        rescue
        end
        begin
          EvilCTF::AppState.instance.clear_upload(upload_id) rescue nil
        rescue
        end
      end

      def download_file(remote_path, local_path, xor_key: nil, allow_empty: true)
        requested_remote_path = remote_path.to_s
        resolved_remote_path = resolve_remote_path(remote_path: requested_remote_path, retries: 10, delay: 1)
        if resolved_remote_path && resolved_remote_path != requested_remote_path
          @logger&.info("[Downloader] Resolved remote path '#{requested_remote_path}' to '#{resolved_remote_path}'")
        end
        remote_path = resolved_remote_path || requested_remote_path

        # Prefer adapter file manager
        fm = @shell_adapter.respond_to?(:file_manager) ? @shell_adapter.file_manager : nil
        if fm
          begin
            @logger&.info("[Downloader] Using file manager to download #{remote_path} -> #{local_path}")
            tmp_local = local_path + ".winrmfs.tmp"
            if fm.respond_to?(:download)
              fm.download(remote_path: remote_path, local_path: tmp_local)
            elsif fm.respond_to?(:read)
              fm.read(remote_path: remote_path, local_path: tmp_local)
            else
              raise 'File manager does not implement download/read'
            end
            FileUtils.mkdir_p(File.dirname(local_path))
            FileUtils.mv(tmp_local, local_path)
            @logger&.info("[Downloader] Download complete: #{local_path}")
            return true
          rescue => e
            if remote_not_found_error?(e)
              retry_remote = resolve_remote_path(remote_path: requested_remote_path, retries: 4, delay: 1)
              if retry_remote && retry_remote != remote_path
                @logger&.info("[Downloader] Retrying with resolved path #{retry_remote}")
                begin
                  tmp_local = local_path + ".winrmfs.tmp"
                  if fm.respond_to?(:download)
                    fm.download(remote_path: retry_remote, local_path: tmp_local)
                  elsif fm.respond_to?(:read)
                    fm.read(remote_path: retry_remote, local_path: tmp_local)
                  end
                  FileUtils.mkdir_p(File.dirname(local_path))
                  FileUtils.mv(tmp_local, local_path)
                  @logger&.info("[Downloader] Download complete after path retry: #{local_path}")
                  return true
                rescue => retry_error
                  @logger&.warn("[Downloader] Retry with resolved path failed: #{retry_error.message}")
                end
              end
            end
            @logger&.warn("[Downloader] File manager download failed, falling back: #{e.message}")
          end
        end

        begin
          return download_via_chunks(remote_path: remote_path, local_path: local_path, xor_key: xor_key, allow_empty: allow_empty)
        rescue ::EvilCTF::Errors::DownloadError => e
          if remote_not_found_error?(e)
            retry_remote = resolve_remote_path(remote_path: requested_remote_path, retries: 6, delay: 1)
            if retry_remote && retry_remote != remote_path
              @logger&.info("[Downloader] Retrying chunked download with resolved path #{retry_remote}")
              return download_via_chunks(remote_path: retry_remote, local_path: local_path, xor_key: xor_key, allow_empty: allow_empty)
            end
            @logger&.warn("[Downloader] No remote candidates found for #{requested_remote_path}")
            log_nearby_remote_candidates(remote_path: requested_remote_path)
            puts '[!] Remote path not found'.colorize(:red)
            @logger&.error("[Downloader] Remote path not found: #{requested_remote_path}")
          end
          raise
        end
      rescue ::EvilCTF::Errors::DownloadError
        raise
      rescue => e
        @logger&.error("[Downloader] Download failed: #{e.class}: #{e.message}")
        raise ::EvilCTF::Errors::DownloadError, e.message
      end

      private

      def resolve_remote_path(remote_path:, retries:, delay:)
        requested = remote_path.to_s.gsub('/', '\\')
        attempts = [retries.to_i, 1].max

        attempts.times do |idx|
          return requested if remote_path_exists?(remote_path: requested, retries: 1, delay: 0)

          matched = find_matching_remote_path(remote_path: requested)
          return matched if matched

          break if idx == attempts - 1
          sleep(delay)
        end

        nil
      rescue => e
        @logger&.warn("[Downloader] Remote path resolution failed: #{e.class}: #{e.message}")
        nil
      end

      def find_matching_remote_path(remote_path:)
        escaped = EvilCTF::Utils.escape_ps_string(remote_path)
        ps = <<~PS
          try {
            $target = '#{escaped}'
            $dir = Split-Path -Parent $target
            $leaf = Split-Path -Leaf $target
            if (!(Test-Path -LiteralPath $dir)) { 'MISSING'; return }

            $base = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
            $ext = [System.IO.Path]::GetExtension($leaf)
            if ([string]::IsNullOrWhiteSpace($base)) { 'MISSING'; return }

            $pattern = if ([string]::IsNullOrWhiteSpace($ext)) { "$base*" } else { "$base*$ext*" }

            $m = Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like $pattern } |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1

            if ($m) { "MATCH::$($m.FullName)" } else { 'MISSING' }
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        res = @shell_adapter.run(ps)
        out = res&.output.to_s
        marker = out.lines.map(&:strip).find { |ln| ln.start_with?('MATCH::') }
        return nil unless marker

        marker.sub('MATCH::', '').strip
      rescue => e
        @logger&.warn("[Downloader] Match probe failed: #{e.class}: #{e.message}")
        nil
      end

      def remote_not_found_error?(error)
        msg = error.to_s.downcase
        msg.include?('path not found') || msg.include?('remote path not found') || msg.include?('could not find file')
      end

      def download_via_chunks(remote_path:, local_path:, xor_key:, allow_empty:)
        chunk_size = DEFAULT_CHUNK_SIZE
        tmp_local = local_path + '.part'
        FileUtils.mkdir_p(File.dirname(local_path))

        offset = File.exist?(tmp_local) ? File.size(tmp_local) : 0
        @logger&.info("[Downloader] Starting chunked download from #{remote_path}: offset=#{offset} chunk_size=#{chunk_size}")

        loop do
          ps_chunk = <<~PS
            try {
              $path = '#{EvilCTF::Utils.escape_ps_string(remote_path)}'
              $fs = [System.IO.File]::OpenRead($path)
              $fs.Seek(#{offset}, 'Begin') | Out-Null
              $buf = New-Object byte[] #{chunk_size}
              $read = $fs.Read($buf, 0, $buf.Length)
              if ($read -gt 0) {
                if ($read -lt $buf.Length) {
                  $b = $buf[0..($read - 1)]
                  [Convert]::ToBase64String($b)
                } else {
                  [Convert]::ToBase64String($buf)
                }
              } else { "" }
              $fs.Close()
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS

          res = @shell_adapter.run(ps_chunk)
          if res.nil? || res.output.nil?
            puts '[!] Empty response during chunk read'.colorize(:red)
            @logger&.error('[Downloader] Empty response during chunk read')
            raise ::EvilCTF::Errors::DownloadError, 'Empty response during chunk read'
          end

          raw = res.output.to_s
          if raw.include?('ERROR:')
            msg = raw.lines.map(&:strip).find { |ln| ln.start_with?('ERROR:') } || raw.strip
            raise ::EvilCTF::Errors::DownloadError, msg
          end

          b64 = raw.scan(/[A-Za-z0-9+\/=\s]{4,}/m).map { |s| s.gsub(/\s+/, '') }.max_by(&:length).to_s

          if b64.empty?
            @logger&.info('[Downloader] No more data from remote; finishing')
            break
          end

          begin
            chunk = Base64.strict_decode64(b64)
          rescue
            chunk = Base64.decode64(b64) rescue nil
          end

          if chunk.nil? || chunk.empty?
            puts '[!] Failed to decode chunk from remote'.colorize(:red)
            @logger&.error('[Downloader] Failed to decode chunk from remote')
            raise ::EvilCTF::Errors::DownloadError, 'Failed to decode chunk'
          end

          chunk = EvilCTF::Tools::Crypto.xor_crypt(chunk, xor_key) if xor_key

          File.open(tmp_local, 'ab') { |f| f.write(chunk) }
          offset += chunk.bytesize
          @logger&.info("[Downloader] Wrote chunk, new offset=#{offset}")

          break if chunk.bytesize < chunk_size
        end

        if File.exist?(tmp_local) && File.size(tmp_local) == 0 && !allow_empty
          puts '[!] Remote file empty and empty files not allowed'.colorize(:red)
          @logger&.error('[Downloader] Remote file empty and empty files not allowed')
          raise ::EvilCTF::Errors::DownloadError, 'Remote file empty'
        end

        FileUtils.mv(tmp_local, local_path)
        @logger&.info("[Downloader] Download complete: #{local_path}")
        true
      end

      def log_nearby_remote_candidates(remote_path:)
        escaped = EvilCTF::Utils.escape_ps_string(remote_path)
        ps = <<~PS
          try {
            $target = '#{escaped}'
            $dir = Split-Path -Parent $target
            if (!(Test-Path -LiteralPath $dir)) { 'CANDIDATES::DIR_MISSING'; return }
            $items = Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 10 -ExpandProperty FullName
            if ($items) {
              "CANDIDATES::" + ($items -join '|')
            } else {
              'CANDIDATES::NONE'
            }
          } catch {
            "CANDIDATES::ERROR::$($_.Exception.Message)"
          }
        PS
        out = @shell_adapter.run(ps)&.output.to_s
        line = out.lines.map(&:strip).find { |ln| ln.start_with?('CANDIDATES::') }
        @logger&.warn("[Downloader] #{line}") if line && !line.empty?
      rescue => e
        @logger&.warn("[Downloader] Candidate listing failed: #{e.class}: #{e.message}")
      end

      def remote_path_exists?(remote_path:, retries:, delay:)
        escaped = EvilCTF::Utils.escape_ps_string(remote_path)
        ps = <<~PS
          try {
            if (Test-Path -LiteralPath '#{escaped}') { 'EXISTS' } else { 'MISSING' }
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        attempts = [retries.to_i, 1].max
        attempts.times do |idx|
          res = @shell_adapter.run(ps)
          out = res&.output.to_s
          return true if out.include?('EXISTS')

          break if idx == attempts - 1
          sleep(delay)
        end

        false
      rescue => e
        @logger&.warn("[Downloader] Existence probe failed: #{e.class}: #{e.message}")
        false
      end
    end
  end
end

