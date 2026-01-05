require_relative 'uploader/client'

module EvilCTF
  module Uploader
    # Backwards-compatible module-level wrappers
    def self.upload_file(local_path, remote_path, shell, **opts)
      client = Client.new(shell)
      client.upload_file(local_path, remote_path, **opts)
    end

    def self.download_file(remote_path, local_path, shell, **opts)
      client = Client.new(shell)
      client.download_file(remote_path, local_path, **opts)
    end

    # Interactive file operations menu (upload/download/ZIP)
    def self.file_operations_menu(shell)
      require 'readline'
      client = Client.new(shell)
      puts "\nFile Operations Menu:\n---------------------"
      puts "[!] To upload into a directory, end the remote destination path with a backslash (e.g., C:\\Users\\jabbatheduck\\)"
      # Tab completion for local files/dirs
      file_completion = proc do |input|
        Dir["#{input}*"]
      end
      # Tab completion for remote paths (PowerShell Get-ChildItem)
      remote_completion = proc do |input|
        begin
          base = input.strip.gsub('/', '\\')
          # Expand ~ to user profile
          if base.start_with?("~")
            ps_base = "$env:USERPROFILE" + base[1..-1]
          elsif base =~ /^%([^%]+)%/i
            env_var = base[/^%([^%]+)%/i, 1]
            ps_base = "$env:#{env_var}" + base[env_var.length+2..-1].to_s
          elsif base =~ /^[A-Za-z]:$/
            ps_base = base + '\\'
          elsif base =~ /^[A-Za-z]$/
            ps_base = base + ':\\'
          elsif base.empty?
            ps_base = 'C:\\'
          else
            ps_base = base
          end

          # For tab completion, split into dir and partial
          if ps_base.end_with?('\\')
            dir = ps_base
            partial = ''
          else
            dir = File.dirname(ps_base + 'x') + '\\'
            partial = File.basename(ps_base)
          end

          # Always show completions for drive roots and partials
          ps = <<~PS
            try {
              $d = '#{dir.gsub("'", "''")}'
              $p = '#{partial.gsub("'", "''")}'
              $results = Get-ChildItem -Path $d -Directory -Name | Where-Object { $_ -like "$p*" } | ForEach-Object { Join-Path $d $_ }
              if ($results.Count -eq 0 -and $p -eq '') {
                # Show drive letters
                Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name + ':' }
              } else {
                $results
              }
            } catch { '' }
          PS
          out = shell.run(ps).output.to_s.split("\n").map(&:strip).reject(&:empty?)
          out.uniq
        rescue
          []
        end
      end
      loop do
        puts "\nChoose an option:"
        puts "  1. Upload file"
        puts "  2. Download file"
        puts "  3. ZIP and upload directory"
        puts "  4. Exit fileops menu"
        print "> "
        choice = $stdin.gets.strip rescue '4'
        case choice
        when '1'
          Readline.completion_append_character = nil
          Readline.completion_proc = file_completion
          local = Readline.readline("Local file to upload: ", true).strip
          Readline.completion_proc = nil
          # Remote path completion
          Readline.completion_append_character = nil
          Readline.completion_proc = remote_completion
          remote_dir = Readline.readline("Remote destination directory: ", true).strip
          Readline.completion_proc = nil
          # If user gives a directory, use the same filename as local
          if remote_dir.end_with?('\\') || remote_dir =~ /^[A-Za-z]:$/
            remote = File.join(remote_dir, File.basename(local)).gsub('/', '\\')
          else
            remote = remote_dir
          end
          begin
            ok = client.upload_file(local, remote)
            puts ok ? "[+] Upload successful" : "[!] Upload failed"
          rescue => e
            puts "[!] Upload error: #{e.message}"
          end
        when '2'
          # Remote path completion
          Readline.completion_append_character = nil
          Readline.completion_proc = remote_completion
          remote = Readline.readline("Remote file to download: ", true).strip
          Readline.completion_proc = nil
          Readline.completion_append_character = nil
          Readline.completion_proc = file_completion
          local = Readline.readline("Local destination path: ", true).strip
          Readline.completion_proc = nil
          begin
            ok = client.download_file(remote, local)
            puts ok ? "[+] Download successful" : "[!] Download failed"
          rescue => e
            puts "[!] Download error: #{e.message}"
          end
        when '3'
          Readline.completion_append_character = nil
          Readline.completion_proc = file_completion
          dir = Readline.readline("Local directory to ZIP and upload: ", true).strip
          Readline.completion_proc = nil
          # Remote path completion
          Readline.completion_append_character = nil
          Readline.completion_proc = remote_completion
          remote_dir = Readline.readline("Remote ZIP destination directory: ", true).strip
          Readline.completion_proc = nil
          zip_path = "#{dir}.zip"
          # If user gives a directory, use the same filename as local
          if remote_dir.end_with?('\\') || remote_dir =~ /^[A-Za-z]:$/
            remote = File.join(remote_dir, File.basename(zip_path)).gsub('/', '\\')
          else
            remote = remote_dir
          end
          begin
            require 'zip'
            Zip::File.open(zip_path, Zip::File::CREATE) do |zipfile|
              Dir[File.join(dir, '**', '**')].each do |file|
                zipfile.add(file.sub(dir + '/', ''), file)
              end
            end
            puts "[*] Created ZIP: #{zip_path}"
            ok = client.upload_file(zip_path, remote)
            puts ok ? "[+] ZIP upload successful" : "[!] ZIP upload failed"
          rescue => e
            puts "[!] ZIP/upload error: #{e.message}"
          ensure
            File.delete(zip_path) if File.exist?(zip_path)
          end
        when '4', '', nil
          puts "Exiting file operations menu."
          break
        else
          puts "Invalid option."
        end
      end
    end
  end
end
