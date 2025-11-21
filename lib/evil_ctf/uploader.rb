require 'base64'
require 'fileutils'

module EvilCTF::Uploader
  # ---------------------------------------------
  # Upload a local file to the remote target (chunked)
  # ---------------------------------------------
  def self.upload_file(local_path, remote_path, shell, encrypt: false, chunk_size: 40000)
    return false unless File.exist?(local_path)

    content = File.binread(local_path)
    content = xor_crypt(content) if encrypt
    base64_content = Base64.strict_encode64(content)

    # Small file – single shot
    if base64_content.length <= chunk_size
      ps_single = <<~PS
        try {
          $bytes = [Convert]::FromBase64String('#{base64_content}')
          New-Item -Path '#{remote_path}' -ItemType File -Force | Out-Null
          [System.IO.File]::WriteAllBytes('#{remote_path}', $bytes)
          "SUCCESS"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      result = shell.run(ps_single)
      return false unless result.output.include?('SUCCESS')
    else
      # Chunked upload
      ps_init = <<~PS
        try {
          New-Item -Path '#{remote_path}' -ItemType File -Force | Out-Null
          "INIT"
        } catch {
          "ERROR: $($_.Exception.Message)"
        }
      PS

      init = shell.run(ps_init)
      return false unless init.output.include?('INIT')

      chunks = base64_content.scan(/.{1,#{chunk_size}}/)
      chunks.each_with_index do |chunk, idx|
        ps_chunk = <<~PS
          try {
            $b = [Convert]::FromBase64String('#{chunk}')
            Add-Content -Path '#{remote_path}' -Value $b -Encoding Byte
            "CHUNK #{idx}"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        result = shell.run(ps_chunk)
        return false unless result.output.include?("CHUNK #{idx}")
      end
    end

    # Final verification
    verify = shell.run("if (Test-Path '#{remote_path}') { 'EXISTS' } else { 'MISSING' }")
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
    return false unless exist.output.strip == 'True'

    result = shell.run("[Convert]::ToBase64String([IO.File]::ReadAllBytes('#{remote_path}'))")
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
        local = Readline.readline.strip rescue nil
        remote = Readline.readline.strip rescue nil
        upload_file(local, remote, shell) if local && remote
      when '2'
        remote = Readline.readline.strip rescue nil
        local = Readline.readline.strip rescue nil
        download_file(remote, local, shell) if remote && local
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


