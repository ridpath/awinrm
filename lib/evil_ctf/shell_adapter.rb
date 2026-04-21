# frozen_string_literal: true
require 'base64'
require 'concurrent'
require 'digest'
require 'fileutils'
require 'ostruct'
require_relative 'logger'
require_relative 'utils'
require_relative 'engine_audit'
module EvilCTF
  # Adapter abstraction for remote shells. Provides a stable `run(cmd)` and `close` API
  # and exposes the underlying WinRM connection when available for advanced operations
  # (e.g., WinRM::FS file manager).
  module ShellAdapter
    # Try to wrap given object into an adapter that responds to `run(cmd)` and `close`.
    def self.wrap(obj)
      return obj if obj.respond_to?(:run) && obj.respond_to?(:close) && obj.respond_to?(:adapter_info) rescue false
      if defined?(WinRM) && obj.is_a?(WinRM::Connection)
        WinRMShellAdapter.new_from_connection(obj)
      elsif defined?(WinRM) && obj.class.to_s =~ /WinRM::Shell/ || (obj.respond_to?(:run) && obj.respond_to?(:close))
        WinRMShellAdapter.new_from_shell(obj)
      else
        GenericAdapter.new(obj)
      end
    end

    class GenericAdapter
      def initialize(obj)
        @obj = obj
      end

      def run(cmd)
        if @obj.respond_to?(:run)
          @obj.run(cmd)
        else
          raise EvilCTF::Errors::ConnectionError, 'Wrapped object does not support run(cmd)'
        end
      end

      def close
        @obj.close if @obj.respond_to?(:close)
      end

      def adapter_info
        { type: :generic }
      end
    end

    # WinRM-specific adapter: can be constructed from a WinRM::Connection or a WinRM shell
    class WinRMShellAdapter < GenericAdapter
      class InternalFileManager
        DEFAULT_CHUNK_SIZE = 64 * 1024

        def initialize(shell_adapter:)
          @shell_adapter = shell_adapter
        end

        def run_remote(command:, timeout: 60)
          done = false
          result = nil
          mutex = Mutex.new
          cv = ConditionVariable.new

          worker = Thread.new do
            begin
              response = @shell_adapter.run(command)
              mutex.synchronize do
                next if done
                done = true
                result = response
                cv.broadcast
              end
            rescue StandardError => e
              mutex.synchronize do
                next if done
                done = true
                result = OpenStruct.new(output: "ERROR: #{e.class}: #{e.message}")
                cv.broadcast
              end
            end
          end

          timer = Concurrent::TimerTask.new(execution_interval: timeout.to_f, run_now: false) do
            mutex.synchronize do
              next if done
              done = true
              worker.kill if worker.alive?
              result = OpenStruct.new(output: "ERROR: TIMED_OUT after #{timeout}s")
              cv.broadcast
            end
          end

          timer.execute
          mutex.synchronize { cv.wait(mutex) until done }
          result
        rescue StandardError => e
          EvilCTF::EngineAudit.error(message: 'internal file manager remote run failed', error: e, source: 'internal_file_manager')
          OpenStruct.new(output: "ERROR: #{e.class}: #{e.message}")
        ensure
          timer&.shutdown
          worker&.kill if worker&.alive?
        end

        def upload(local_path:, remote_path:, chunk_size: DEFAULT_CHUNK_SIZE, verify: true)
          raise ArgumentError, 'local_path is required' if local_path.to_s.empty?
          raise ArgumentError, 'remote_path is required' if remote_path.to_s.empty?
          raise Errno::ENOENT, local_path unless File.exist?(local_path)

          escaped_remote = EvilCTF::Utils.escape_ps_string(remote_path)
          remote_dir = EvilCTF::Utils.escape_ps_string(File.dirname(remote_path).gsub('/', '\\'))
          init_ps = <<~PS
            try {
              if (!(Test-Path '#{remote_dir}')) { New-Item -Path '#{remote_dir}' -ItemType Directory -Force | Out-Null }
              if (Test-Path '#{escaped_remote}') { Remove-Item '#{escaped_remote}' -Force -ErrorAction SilentlyContinue }
              [System.IO.File]::WriteAllBytes('#{escaped_remote}', @())
              'OK'
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS
          init_res = run_remote(command: init_ps, timeout: 30)
          unless init_res && init_res.output.to_s.include?('OK')
            raise EvilCTF::Errors::UploadError, "InternalFileManager init failed: #{init_res&.output}"
          end

          File.open(local_path, 'rb') do |file|
            while (chunk = file.read(chunk_size))
              b64 = Base64.strict_encode64(chunk)
              append_ps = <<~PS
                try {
                  $b64 = @'
#{b64}
'@
                  $bytes = [Convert]::FromBase64String($b64)
                  $fs = [System.IO.File]::Open('#{escaped_remote}', [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
                  $fs.Write($bytes, 0, $bytes.Length)
                  $fs.Close()
                  'OK'
                } catch {
                  "ERROR: $($_.Exception.Message)"
                }
              PS
              append_res = run_remote(command: append_ps, timeout: 60)
              unless append_res && append_res.output.to_s.include?('OK')
                raise EvilCTF::Errors::UploadError, "InternalFileManager upload failed: #{append_res&.output}"
              end
            end
          end

          return true unless verify

          local_hash = Digest::SHA256.file(local_path).hexdigest
          verify_ps = <<~PS
            try {
              (Get-FileHash -Path '#{escaped_remote}' -Algorithm SHA256).Hash
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS
          verify_res = run_remote(command: verify_ps, timeout: 45)
          remote_hash = verify_res&.output.to_s.scan(/[0-9A-Fa-f]{64}/).first
          if remote_hash.to_s.downcase != local_hash.downcase
            raise EvilCTF::Errors::UploadError, "InternalFileManager hash mismatch local=#{local_hash} remote=#{remote_hash}"
          end
          true
        end

        def download(remote_path:, local_path:, chunk_size: DEFAULT_CHUNK_SIZE, verify: true)
          raise ArgumentError, 'remote_path is required' if remote_path.to_s.empty?
          raise ArgumentError, 'local_path is required' if local_path.to_s.empty?

          FileUtils.mkdir_p(File.dirname(local_path))
          File.open(local_path, 'wb') {}

          offset = 0
          loop do
            read_ps = <<~PS
              try {
                $path = '#{EvilCTF::Utils.escape_ps_string(remote_path)}'
                if (!(Test-Path $path)) { throw "Path not found: $path" }
                $fs = [System.IO.File]::OpenRead($path)
                $fs.Seek(#{offset}, 'Begin') | Out-Null
                $buf = New-Object byte[] #{chunk_size}
                $read = $fs.Read($buf, 0, $buf.Length)
                if ($read -gt 0) {
                  $slice = if ($read -lt $buf.Length) { $buf[0..($read - 1)] } else { $buf }
                  [Convert]::ToBase64String($slice)
                } else { '' }
                $fs.Close()
              } catch {
                "ERROR: $($_.Exception.Message)"
              }
            PS
            read_res = run_remote(command: read_ps, timeout: 60)
            output = read_res&.output.to_s.strip
            raise EvilCTF::Errors::DownloadError, output if output.start_with?('ERROR:')
            break if output.empty?

            bytes = Base64.strict_decode64(output)
            File.open(local_path, 'ab') { |f| f.write(bytes) }
            offset += bytes.bytesize
            break if bytes.bytesize < chunk_size
          end
          return true unless verify

          local_hash = Digest::SHA256.file(local_path).hexdigest
          verify_ps = <<~PS
            try {
              (Get-FileHash -Path '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -Algorithm SHA256).Hash
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS
          verify_res = run_remote(command: verify_ps, timeout: 45)
          remote_hash = verify_res&.output.to_s.scan(/[0-9A-Fa-f]{64}/).first
          raise EvilCTF::Errors::DownloadError, "InternalFileManager hash mismatch local=#{local_hash} remote=#{remote_hash}" if remote_hash.to_s.downcase != local_hash.downcase

          true
        end

        def read(remote_path:, local_path:)
          download(remote_path: remote_path, local_path: local_path)
        end
      end

      def self.new_from_connection(conn)
        adapter = allocate
        adapter.send(:initialize_from_connection, conn)
        adapter
      end

      def self.new_from_shell(shell)
        adapter = allocate
        adapter.send(:initialize_from_shell, shell)
        adapter
      end

      def initialize_from_connection(conn)
        @conn = conn
        @shell = conn.shell(:powershell)
        @run_mutex = shared_run_mutex(@shell)
      end

      def initialize_from_shell(shell)
        @shell = shell
        # try to find connection if available
        @conn = shell.instance_variable_get(:@connection) || shell.instance_variable_get(:@conn) rescue nil
        @run_mutex = shared_run_mutex(@shell)
      end

      def run(cmd)
        @run_mutex.synchronize do
          @shell.run(cmd)
        end
      rescue => e
        raise EvilCTF::Errors::ConnectionError, e.message
      end

      def close
        @shell.close if @shell
        begin; @conn.reset if @conn && @conn.respond_to?(:reset); rescue; end
      end

      def adapter_info
        { type: :winrm, connection: @conn }
      end

      # Return an internal file manager implementation (WinRM::FS optional).
      def file_manager
        return nil unless @shell
        InternalFileManager.new(shell_adapter: self)
      rescue
        nil
      end

      private

      def shared_run_mutex(shell)
        existing = shell.instance_variable_get(:@evilctf_run_mutex)
        return existing if existing

        shell.instance_variable_set(:@evilctf_run_mutex, Mutex.new)
      rescue StandardError
        Mutex.new
      end
    end
  end
end
