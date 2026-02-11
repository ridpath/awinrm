# frozen_string_literal: true
require 'ostruct'
require_relative 'shell_adapter'

module EvilCTF
  module Execution
    # Run a PowerShell command/script via a shell or adapter with a local timeout.
    # Returns OpenStruct with :ok (bool), :exitcode (Integer or nil), :output (String).
    def self.run(shell_or_adapter, ps, timeout: 60)
      adapter = EvilCTF::ShellAdapter.wrap(shell_or_adapter)
      result = nil

      runner = Thread.new do
        begin
          result = adapter.run(ps)
        rescue => e
          result = OpenStruct.new(output: "ERROR: #{e.class}: #{e.message}", exitcode: 255)
        end
      end

      finished = runner.join(timeout)
      if finished.nil? || runner.alive?
        # Timeout: return explicit failure and do not try to guess remote state
        begin; runner.kill; rescue; end
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
      token = "stream_#{Time.now.to_i}_#{rand(9999)}"
      remote_tmp = "C:/Users/Public/evilctf_#{token}.log"

      # Start background job that runs the command and appends stdout/stderr to file
      start_job = <<~PS
        try {
          Start-Job -ScriptBlock { #{ps} 2>&1 | Out-File -FilePath '#{remote_tmp}' -Encoding UTF8 -Append } | Out-Null
          $j = (Get-Job | Where-Object { $_.State -eq 'Running' } | Select-Object -First 1).Id
          Write-Output $j
        } catch { Write-Output "ERROR: $($_.Exception.Message)" }
      PS

      begin
        start_res = adapter.run(start_job)
      rescue => e
        return OpenStruct.new(ok: false, exitcode: nil, output: "ERROR: #{e.class}: #{e.message}")
      end

      job_id = start_res && start_res.output ? start_res.output.to_s.scan(/\d+/).first.to_i : nil
      unless job_id && job_id > 0
        # fallback: if we couldn't start a job, run directly
        res = adapter.run(ps)
        return OpenStruct.new(ok: true, exitcode: (res.respond_to?(:exitcode) ? res.exitcode : nil), output: res && res.output ? res.output.to_s : '')
      end

      elapsed = 0
      last_content = ''
      begin
        while elapsed < timeout
          # read remote tmp file content (may be empty)
          read_ps = "try { if (Test-Path '#{remote_tmp}') { (Get-Content -Path '#{remote_tmp}' -Raw) } else { '' } } catch { '' }"
          read_res = adapter.run(read_ps)
          content = read_res && read_res.output ? read_res.output.to_s : ''
          if content && content.length > last_content.length
            new_text = content[last_content.length..-1]
            yield new_text if block_given? && new_text && !new_text.empty?
            last_content = content
          end

          # check job state
          state_ps = "try { (Get-Job -Id #{job_id} -ErrorAction SilentlyContinue).State } catch { 'Unknown' }"
          state_res = adapter.run(state_ps)
          state = state_res && state_res.output ? state_res.output.to_s.strip : nil
          break if state && state =~ /Completed|Failed|Stopped/i

          sleep poll_interval
          elapsed += poll_interval
        end

        # final read
        read_res = adapter.run("try { if (Test-Path '#{remote_tmp}') { (Get-Content -Path '#{remote_tmp}' -Raw) } else { '' } } catch { '' }")
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
        begin; adapter.run("Remove-Job -Id #{job_id} -Force -ErrorAction SilentlyContinue"); rescue; end
        begin; adapter.run("Remove-Item -Path '#{remote_tmp}' -Force -ErrorAction SilentlyContinue"); rescue; end
        return OpenStruct.new(ok: false, exitcode: nil, output: "ERROR: #{e.class}: #{e.message}")
      end
    end
  end
end
