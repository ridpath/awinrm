module EvilCTF
  class TUI
    # Simple in-memory trackers for sessions started via the TUI and a small
    # streaming output buffer used by the CLI pane.
    def self.sessions
      @sessions ||= []
    end

    def self.stream_buffer
      @stream_buffer ||= []
    end

    # Render a fixed 3-column layout (left menu, center CLI, right meta)
    # Accepts optional `sessions` (array) and `stream_lines` to display
    # live data in the panels.
    def self.render_fixed_layout(shell, state = {}, sessions = [], stream_lines = [])
      cols = (TTY::Screen.width rescue 100)
      total = [cols, 120].min

      left_w   = 28
      right_w  = 24
      center_w = total - left_w - right_w - 6   # borders + spacing

      # Top bar
      puts "┌" + "─" * (total - 2) + "┐"
      puts "│ AWINRM OPERATOR CONSOLE".ljust(total - 1) + "│"
      meta = "Host: #{state[:host] || 'N/A'}   Status: #{state[:connected] ? 'Connected' : 'Disconnected'}   Shell: #{state[:shell] || 'PowerShell'}   SSL: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}"
      puts "│ #{meta.ljust(total - 4)} │"
      puts "└" + "─" * (total - 2) + "┘"

      # Pane headers
      puts "┌" + "─" * (left_w) + "┬" + "─" * (center_w) + "┬" + "─" * (right_w) + "┐"
      puts "│ MENU (Alt+1)".ljust(left_w + 1) +
           "│ INTERACTIVE CLI (Alt+2)".ljust(center_w + 1) +
           "│ META ".ljust(right_w + 1) + "│"
      puts "├" + "─" * (left_w) + "┼" + "─" * (center_w) + "┼" + "─" * (right_w) + "┤"

      # Left menu content
      left = [
        "Sessions",
        "  Active Sessions",
        "  New Session",
        "  Close Session",
        "",
        "Tools",
        "  Recon",
        "  Credential Access",
        "  Lateral Movement",
        "  Enumeration",
        "  Upload / Download",
        "",
        "Macros",
        "  recon_basic",
        "  recon_full",
        "  dump_creds",
        "  disable_defender",
        "",
        "Profiles",
        "  default.yml",
        "  ctf.yml",
        "  prod.yml",
        "",
        "Settings",
        "  SSL Verification",
        "  Logging",
        "  Shell Adapter",
        "  Paths"
      ]

      # Center CLI content (inject streaming output at the bottom)
      center = [
        "PS> whoami",
        (shell && (shell.run('whoami').output.strip rescue 'demo\\user')) || 'demo\\user',
        "",
        "PS> systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
        "OS Name: Microsoft Windows Server 2019 Standard",
        "OS Version: 10.0.17763",
        "",
        "PS> upload_file C:\\Tools\\SharpHound.exe",
        "[██████████░░░░░░░░░░░░░░░] 48%   Chunk 12/25",
        "",
        "[history] recon_basic"
      ]

      # Append latest stream lines (keep center area informative)
      if stream_lines && !stream_lines.empty?
        center << ""
        stream_lines.last(6).each do |ln|
          center << ln.to_s
        end
      else
        center << "[streaming output continues]"
      end

      # Right meta panel (show active sessions)
      right = ["Active Sessions:"]
      if sessions && !sessions.empty?
        sessions.each do |s|
          status = s[:thread] && s[:thread].alive? ? 'running' : 'stopped'
          right << "  - #{s[:ip]} (#{s[:user]}) [#{status}]"
        end
      else
        right << "  (none)"
      end
      right << ""
      right << "Last Scan: 00:12"
      right << ""
      right << "Alerts:"
      right << "  [!] 2 pending"
      right << ""
      right << "Mode:"
      right << "  NORMAL"
      right << "  (i = insert, v = visual)"

      # Render rows
      max_rows = [left.size, center.size, right.size].max
      max_rows.times do |i|
        l = left[i]   || ""
        c = center[i] || ""
        r = right[i]  || ""

        print "│ #{l.ljust(left_w - 1)}"
        print "│ #{c.ljust(center_w - 1)}"
        print "│ #{r.ljust(right_w - 1)}│\n"
      end

      puts "└" + "─" * (left_w) + "┴" + "─" * (center_w) + "┴" + "─" * (right_w) + "┘"

      # Results pane
      puts
      puts "┌" + "─" * (total - 2) + "┐"
      puts "│ RESULTS (Alt+3)".ljust(total - 1) + "│"
      puts "├" + "─" * (total - 2) + "┤"
      puts "│ Command: recon_basic".ljust(total - 1) + "│"
      puts "│ ------------------------------------------------------------".ljust(total - 1) + "│"
      puts "│ [+] Hostname: WIN-CTF-01".ljust(total - 1) + "│"
      puts "│ [+] Domain: CONTOSO".ljust(total - 1) + "│"
      puts "│ [+] Logged-on users: Administrator".ljust(total - 1) + "│"
      puts "│ [+] High-value targets: DC01, SQL01".ljust(total - 1) + "│"
      puts "│ [+] Defender status: Enabled".ljust(total - 1) + "│"
      puts "└" + "─" * (total - 2) + "┘"

      # Footer
      footer = "[R] refresh  [j] down  [k] up  [/] search  [g] top  [G] bottom  [F1] Sessions  [F2] CLI  [F3] Results"
      puts footer.center(total)
    end

    def self.render_dashboard(shell, state = {})
      cols = (TTY::Screen.width rescue 100)
      total = [cols, 100].min

      puts "┌" + "─" * (total - 2) + "┐"
      puts "│ EvilCTF Dashboard".ljust(total - 1) + "│"
      puts "├" + "─" * (total - 2) + "┤"

      host = state[:host] || 'N/A'
      user = (shell.run('whoami').output.strip rescue 'N/A')
      os_info = (shell.run('systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"').output.strip rescue 'N/A')

      puts "│ Host: #{host.ljust(total - 10)}│"
      puts "│ User: #{user.ljust(total - 10)}│"
      puts "│ #{os_info.ljust(total - 4)} │"

      puts "├" + "─" * (total - 2) + "┤"
      puts "│ Connection Status: #{state[:connected] ? 'Connected' : 'Disconnected'}".ljust(total - 1) + "│"
      puts "│ Shell Type: #{state[:shell] || 'PowerShell'}".ljust(total - 1) + "│"
      puts "│ SSL Verification: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}".ljust(total - 1) + "│"
      puts "└" + "─" * (total - 2) + "┘"
    end

    def self.run_enumeration(shell, type, cache = {})
      if cache[type]
        puts "[*] Using cached enumeration for #{type}".colorize(:cyan)
        puts cache[type]
        return
      end

      puts "[*] Running #{type} enumeration...".colorize(:cyan)

      cmds = case type
             when 'basic'
               ['whoami /all', 'net user', 'systeminfo']
             when 'network'
               ['ipconfig /all', 'netstat -ano']
             when 'privilege'
               ['whoami /priv', 'net localgroup Administrators', 'net share', 'tasklist /v']
             when 'av_check'
               ['powershell "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled"', 'sc query WinDefend']
             when 'persistence'
               ['schtasks /query /fo LIST /v', 'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"']
             when 'deep'
               [
                 'whoami /all',
                 'systeminfo',
                 'net user',
                 'net localgroup Administrators',
                 'tasklist /v',
                 'sc query state= all',
                 'wmic product get Name,Version,InstallDate'
               ]
             else
               ['systeminfo']
             end

      output = ''
      cmds.each do |cmd|
        result = shell.run(cmd)
        output += "\n> #{cmd}\n"
        output += result.output.to_s
        output += "\n"
      end

      cache[type] = output
      puts output
    end

    # Lightweight interactive dashboard loop. Shows live info from `shell` and
    # supports manual refresh ('r') and quit ('q'). Resilient if TTY gems are
    # missing — will still render once and exit.
    def self.start_rainfrog(shell = nil, options = {})
      begin
        require 'tty-screen'
        require 'tty-reader'
      rescue LoadError
        # Render once and return if tty gems aren't available
        render_fixed_layout(shell, host: (shell && (shell.run('hostname').output.strip rescue nil)), connected: !!shell, shell: (options[:shell] || 'PowerShell'), ssl: options[:ssl])
        return
      end

      reader = TTY::Reader.new
      should_exit = false

      while !should_exit
        # Build state safely from shell
        state = {}
        begin
          state[:host] = shell && (shell.run('hostname').output.strip rescue nil)
        rescue
          state[:host] = nil
        end
        begin
          state[:user] = shell && (shell.run('[Security.Principal.WindowsIdentity]::GetCurrent().Name').output.strip rescue nil)
        rescue
          state[:user] = nil
        end
        state[:connected] = !!shell
        state[:shell] = options[:shell] || 'PowerShell'
        state[:ssl] = !!options[:ssl]

        system('clear') rescue nil
        render_fixed_layout(shell, state, self.sessions, self.stream_buffer)

        # Read a single key and react
        key = nil
        begin
          if reader.respond_to?(:read_key)
            key = reader.read_key
          elsif reader.respond_to?(:read_char)
            key = reader.read_char
          else
            key = STDIN.getch rescue nil
          end
        rescue Interrupt
          should_exit = true
          break
        rescue => _e
          # Non-fatal — allow refresh or quit via Enter
          key = nil
        end

        case key
        when 'q', 'Q', :ctrl_c
          should_exit = true
        when 'r', 'R'
          next
        when 'n', 'N'
          # Start a new background session via prompt
          begin
            prompt = (defined?(TTY::Prompt) ? TTY::Prompt.new : nil)
            ip = prompt ? prompt.ask('Target IP:') : (print('Target IP: '); STDIN.gets&.strip)
            user = prompt ? prompt.ask('User:', default: 'Administrator') : (print('User [Administrator]: '); (STDIN.gets&.strip || 'Administrator'))
            pass = nil
            if prompt
              pass = prompt.mask('Password:')
            else
              print 'Password: '
              pass = STDIN.noecho(&:gets).to_s.strip rescue STDIN.gets.to_s.strip
              puts
            end
            t = Thread.new do
              begin
                Session.run_session({ ip: ip, user: user, password: pass, ssl: false, banner_mode: :minimal })
              rescue => e
                puts "[!] Failed to start session: #{e.message}"
              end
            end
            self.sessions << { ip: ip, user: user, thread: t, started_at: Time.now }
          rescue => e
            # ignore prompt failures
          end
          next
        when 'c', 'C'
          # Run a command on the provided shell (if present) and append output to stream buffer
          if shell
            begin
              cmd = (defined?(TTY::Prompt) ? TTY::Prompt.new.ask('PS>') : (print 'PS> '; STDIN.gets&.strip))
              if cmd && !cmd.strip.empty?
                res = shell.run(cmd)
                out = res.output.to_s
                out.lines.each { |ln| self.stream_buffer << "#{cmd} -> #{ln.chomp}" }
                # keep buffer bounded
                self.stream_buffer.shift while self.stream_buffer.size > 300
              end
            rescue => e
              self.stream_buffer << "[!] Command error: #{e.message}"
            end
          else
            self.stream_buffer << "[!] No active shell to run commands"
          end
          next
        else
          # any other key refreshes
          next
        end
      end
    end
  end
end
