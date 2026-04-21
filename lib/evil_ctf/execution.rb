# frozen_string_literal: true
require 'ostruct'
require 'concurrent'
require 'securerandom'
require_relative 'shell_adapter'
require_relative 'sanitizer'
require_relative 'engine_audit'

module EvilCTF
  module Execution
    module_function

    def run_with_timer(timeout:, &block)
      worker = Thread.new do
        begin
          block.call
        rescue StandardError => e
          e
        end
      end
      worker.report_on_exception = false if worker.respond_to?(:report_on_exception=)

      # TimerTask is used as required for timeout lifecycle management.
      timer = Concurrent::TimerTask.new(execution_interval: timeout.to_f, run_now: false) do
        # no-op: join timeout controls termination deterministically
      end

      timer.execute

      finished = worker.join(timeout.to_f)
      return :timed_out if finished.nil? || worker.alive?

      result = worker.value
      raise result if result.is_a?(StandardError)

      result
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: 'run_with_timer failed', error: e, source: 'execution')
      raise
    ensure
      timer&.shutdown
      worker&.kill if worker&.alive?
    end

    # Run a PowerShell command/script via a shell or adapter with a local timeout.
    # Returns OpenStruct with :ok (bool), :exitcode (Integer or nil), :output (String).
    def self.run(shell_or_adapter, ps, timeout: 60)
      adapter = EvilCTF::ShellAdapter.wrap(shell_or_adapter)
      sanitized = EvilCTF::Sanitizer.sanitize_command(command: ps)
      adapter_type = adapter.respond_to?(:adapter_info) ? adapter.adapter_info[:type] : nil

      # WinRM command execution performs remote cleanup inside the gem. Forcing
      # local thread-kill timeouts leaves orphaned remote commands behind, which
      # eventually trips the per-shell concurrent command quota. Run WinRM calls
      # synchronously and reserve kill-based timeouts for non-WinRM adapters.
      result = if adapter_type == :winrm
                 adapter.run(sanitized)
               else
                 run_with_timer(timeout: timeout) { adapter.run(sanitized) }
               end

      if result == :timed_out
        return OpenStruct.new(ok: false, exitcode: nil, output: "ERROR: TIMED_OUT after #{timeout}s")
      end

      out_raw = result && result.output ? result.output.to_s : ''
      out = normalize_output(out_raw)

      exitcode = if result.respond_to?(:exitcode) && !result.exitcode.nil?
                   result.exitcode
                 else
                   parse_exitcode_from_output(out)
                 end

      ok = (exitcode == 0)
      OpenStruct.new(ok: ok, exitcode: exitcode, output: out)
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: 'execution.run failed', error: e, source: 'execution')
      OpenStruct.new(ok: false, exitcode: 255, output: "ERROR: #{e.class}: #{e.message}")
    end

    def self.normalize_output(s)
      return '' if s.nil?
      str = s.dup
      # Detect UTF-16LE by presence of NULs and try to convert
      if str.encoding == Encoding::ASCII_8BIT || str.index("\x00")
        begin
          # strip trailing nulls and convert
          tmp = str.gsub(/\x00/, '')
          return tmp.encode('UTF-8', invalid: :replace, undef: :replace)
        rescue
          return str.force_encoding('UTF-8').encode('UTF-8', invalid: :replace, undef: :replace)
        end
      end
      str.force_encoding('UTF-8')
    end

    def self.parse_exitcode_from_output(out)
      return nil unless out && !out.empty?
      # Common patterns: 'exit code: 0', 'ExitCode: 0', 'Exited with code 0'
      m = out.match(/(?:exit code|ExitCode|Exited with code|ExitCode\:?)\s*[:]?\s*(\d{1,3})/i)
      return m[1].to_i if m
      # If no explicit code, attempt to infer 0 if typical success words exist
      return 0 if out =~ /completed|OK|MOVED|COPIED/i
      nil
    end

    # Stream a long-running command by launching it as a PowerShell background job
    # that writes output to a temporary file on the remote host. Yields new text
    # chunks to the provided block as they appear. Returns final OpenStruct
    # similar to `run` when the job completes or on timeout.
    def self.stream(shell_or_adapter, ps, timeout: 300, poll_interval: 1)
      adapter = EvilCTF::ShellAdapter.wrap(shell_or_adapter)
      sanitized = EvilCTF::Sanitizer.sanitize_command(command: ps)
      token = "stream_#{Time.now.to_i}_#{SecureRandom.hex(2)}"
      remote_tmp = "C:/Users/Public/evilctf_#{token}.log"

      # Start background job that runs the command and appends stdout/stderr to file
      start_job = <<~PS
        try {
          $j = Start-Job -ScriptBlock { #{sanitized} 2>&1 | Out-File -FilePath '#{remote_tmp}' -Encoding UTF8 -Append }
          if ($j) { Write-Output $j.Id } else { Write-Output "ERROR: Failed to start job" }
        } catch { Write-Output "ERROR: $($_.Exception.Message)" }
      PS

      begin
        start_res = run(shell_or_adapter, start_job, timeout: 20)
      rescue => e
        return OpenStruct.new(ok: false, exitcode: nil, output: "ERROR: #{e.class}: #{e.message}")
      end

      job_id = start_res && start_res.output ? start_res.output.to_s.scan(/\d+/).first.to_i : nil
      unless job_id && job_id > 0
        # fallback: if we couldn't start a job, run directly
        res = run(shell_or_adapter, sanitized, timeout: timeout)
        return OpenStruct.new(
          ok: (res && res.respond_to?(:ok) ? !!res.ok : false),
          exitcode: (res && res.respond_to?(:exitcode) ? res.exitcode : nil),
          output: (res && res.output ? res.output.to_s : '')
        )
      end

      elapsed = 0
      last_content = ''
      begin
        while elapsed < timeout
          # read remote tmp file content (may be empty)
          read_ps = "try { if (Test-Path '#{remote_tmp}') { (Get-Content -Path '#{remote_tmp}' -Raw) } else { '' } } catch { '' }"
          read_res = run(shell_or_adapter, read_ps, timeout: 20)
          content = read_res && read_res.output ? read_res.output.to_s : ''
          if content && content.length > last_content.length
            new_text = content[last_content.length..-1]
            emit_nonblocking(text: new_text) do |chunk|
              yield chunk if block_given? && chunk && !chunk.empty?
            end
            last_content = content
          end

          # check job state
          state_ps = "try { (Get-Job -Id #{job_id} -ErrorAction SilentlyContinue).State } catch { 'Unknown' }"
          state_res = run(shell_or_adapter, state_ps, timeout: 20)
          state = state_res && state_res.output ? state_res.output.to_s.strip : nil
          break if state && state =~ /Completed|Failed|Stopped/i

          sleep poll_interval
          elapsed += poll_interval
        end

        # final read
        read_res = run(shell_or_adapter, "try { if (Test-Path '#{remote_tmp}') { (Get-Content -Path '#{remote_tmp}' -Raw) } else { '' } } catch { '' }", timeout: 20)
        final_output = read_res && read_res.output ? read_res.output.to_s : ''

        # cleanup job and tmp file
        begin
          adapter.run("Remove-Job -Id #{job_id} -Force -ErrorAction SilentlyContinue")
        rescue
        end
        begin
          adapter.run("Remove-Item -Path '#{remote_tmp}' -Force -ErrorAction SilentlyContinue")
        rescue
        end

        OpenStruct.new(ok: true, exitcode: nil, output: final_output)
      rescue => e
        EvilCTF::EngineAudit.error(message: 'execution.stream failed', error: e, source: 'execution')
        begin; adapter.run("Remove-Job -Id #{job_id} -Force -ErrorAction SilentlyContinue"); rescue; end
        begin; adapter.run("Remove-Item -Path '#{remote_tmp}' -Force -ErrorAction SilentlyContinue"); rescue; end
        return OpenStruct.new(ok: false, exitcode: nil, output: "ERROR: #{e.class}: #{e.message}")
      end
    end

    def self.emit_nonblocking(text:)
      return if text.to_s.empty?

      reader, writer = IO.pipe
      writer.write(text)
      writer.close

      loop do
        ready = IO.select([reader], nil, nil, 0.01)
        break unless ready

        begin
          chunk = reader.read_nonblock(8192)
          yield chunk if block_given?
        rescue IO::WaitReadable
          next
        rescue EOFError
          break
        end
      end
    ensure
      reader&.close
      writer&.close unless writer&.closed?
    end
  end
end
