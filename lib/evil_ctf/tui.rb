module EvilCTF
  class TUI
    # Simple in-memory trackers for sessions started via the TUI and a small
    # streaming output buffer used by the CLI pane.
    require_relative 'app_state'

    def self.app_state
      EvilCTF::AppState.instance
    end

    # Thread-safe helpers
    def self.sessions_mutex; app_state.mutex; end
    def self.stream_mutex; app_state.mutex; end
    def self.ui_state_mutex; app_state.mutex; end


    def self.add_session(s)
      app_state.add_session(s)
    end

    def self.sessions_snapshot
      app_state.sessions
    end

    def self.append_stream(line)
      app_state.append_stream(line)
    end

    def self.stream_snapshot
      app_state.stream_snapshot
    end

    # Render a fixed 3-column layout (left menu, center CLI, right meta)
    # Accepts optional `sessions` (array) and `stream_lines` to display
    # live data in the panels.
    def self.render_fixed_layout(shell, state = {}, sessions = [], stream_lines = [])
      width, height = screen_size
      total = [[width, 72].max, 180].min

      left_w = [[(total * 0.26).to_i, 22].max, 36].min
      center_w = [total - left_w - 6, 24].max # borders + spacing (no meta column)

      # Top bar
      puts "┌" + "─" * (total - 2) + "┐"
      puts "│ " + fit_line("AWINRM OPERATOR CONSOLE", total - 4).ljust(total - 4) + " │"
      meta = "Host: #{state[:host] || 'N/A'}   Status: #{state[:connected] ? 'Connected' : 'Disconnected'}   Shell: #{state[:shell] || 'PowerShell'}   SSL: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}"
      puts "│ " + fit_line(meta, total - 4).ljust(total - 4) + " │"
      puts "└" + "─" * (total - 2) + "┘"

       # Pane headers (two-column layout)
       puts "┌" + "─" * (left_w) + "┬" + "─" * (center_w) + "┐"
       puts "│ MENU (Alt+1)".ljust(left_w + 1) +
         "│ INTERACTIVE CLI (Alt+2)".ljust(center_w + 1) + "│"
       puts "├" + "─" * (left_w) + "┼" + "─" * (center_w) + "┤"

      # Left menu content
      # Top-level menu definitions (for rendering and interaction)
      menus = {
        sessions: ["Active Sessions", "New Session", "Close Session"],
        tools:    ["Recon", "Credential Access", "Lateral Movement", "Enumeration", "Upload / Download"],
        macros:   ["recon_basic", "recon_full", "dump_creds", "disable_defender"],
        profiles: ["default.yml", "ctf.yml", "prod.yml"],
        settings: ["SSL Verification", "Logging", "Shell Adapter", "Paths"]
      }

      # Build left menu from `menus` with collapsible behavior
      left = []
      open = app_state.menu_open
      menus.each do |k, children|
        label = k.to_s.capitalize
        indicator = (open == k) ? '[-]' : '[+]'
        left << "#{label} #{indicator}"
        if open == k
          children.each do |ch|
            left << "  #{ch}"
          end
          left << ""
        end
      end

      # Center CLI content (history + interactive prompt)
      center = []
      # Show last CLI history lines (real commands/results)
      cli_hist = app_state.cli_history_snapshot || []
      if cli_hist && !cli_hist.empty?
        cli_hist.last(6).each do |ln|
          center << ln.to_s
        end
      else
        # Fallback to showing recent stream lines or example placeholders
        if stream_lines && !stream_lines.empty?
          stream_lines.last(6).each do |ln|
            center << ln.to_s
          end
        else
          center << "(no CLI history yet)"
        end
      end

      # Always show the latest stream lines after history for realtime feedback
      if stream_lines && !stream_lines.empty?
        center << ""
        stream_lines.last(6).each do |ln|
          center << ln.to_s
        end
      end

      # Show active uploads as additional info
      uploads = app_state.uploads
      if uploads && !uploads.empty?
        center << ""
        uploads.each do |id, info|
          pct = if info[:total] && info[:sent] && info[:total] > 0
                  ((info[:sent].to_f / info[:total]) * 100).round
                else
                  0
                end
          center << "Upload #{info[:name]}: #{pct}% (#{info[:sent]}/#{info[:total]})"
        end
      end

      # Provide the interactive prompt line (PS> ...) reflecting current CLI input
      center << ""
      cli_input = app_state.cli_input || ''
      center << "PS> #{cli_input}"

        # Render rows (two-column layout), constrained to terminal height.
        reserved_lines = 10
        visible_rows = [[height - reserved_lines, 8].max, [left.size, center.size].max].min
        left_tail = left.last(visible_rows)
        center_tail = center.last(visible_rows)
        max_rows = [left_tail.size, center_tail.size].max
        max_rows.times do |i|
          l = fit_line(left_tail[i] || "", left_w - 1)
          c = fit_line(center_tail[i] || "", center_w - 1)

          print "│ #{l.ljust(left_w - 1)}"
          print "│ #{c.ljust(center_w - 1)}│\n"
        end

        puts "└" + "─" * (left_w) + "┴" + "─" * (center_w) + "┘"

      # Footer: include menu toggle hints and insert-mode indicator
      mode_label = app_state.mode == :insert ? '[INSERT]' : '[NORMAL]'
      footer = "[S] Sessions [T] Tools [M] Macros [P] Profiles [E] Settings [U] Upload [D] Download #{mode_label} [i] insert [q] quit"
      puts fit_line(footer, total).center(total)
    end

    def self.render_dashboard(shell, state = {})
      width, _height = screen_size
      total = [[width, 72].max, 120].min

      puts "┌" + "─" * (total - 2) + "┐"
      puts "│ EvilCTF Dashboard".ljust(total - 1) + "│"
      puts "├" + "─" * (total - 2) + "┤"

      host = state[:host] || 'N/A'
      user = state[:user] || 'N/A'
      os_info = state[:os_info] || 'N/A'

      puts "│ " + fit_line("Host: #{host}", total - 4).ljust(total - 4) + " │"
      puts "│ " + fit_line("User: #{user}", total - 4).ljust(total - 4) + " │"
      puts "│ " + fit_line(os_info, total - 4).ljust(total - 4) + " │"

      puts "├" + "─" * (total - 2) + "┤"
      puts "│ " + fit_line("Connection Status: #{state[:connected] ? 'Connected' : 'Disconnected'}", total - 4).ljust(total - 4) + " │"
      puts "│ " + fit_line("Shell Type: #{state[:shell] || 'PowerShell'}", total - 4).ljust(total - 4) + " │"
      puts "│ " + fit_line("SSL Verification: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}", total - 4).ljust(total - 4) + " │"
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
        begin
          res = EvilCTF::Execution.run(shell, cmd, timeout: 30)
          output += "\n> #{cmd}\n"
          output += res.output.to_s
          output += "\n"
          unless res.ok
            output += "[!] Command may have timed out or failed\n"
          end
        rescue => e
          output += "\n> #{cmd}\n"
          output += "[!] Enumeration command error: #{e.class}: #{e.message}\n"
        end
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
      shutdown = false

      # If TUI was launched with an active shell, register it as the active session
      begin
        if shell
          app_state.set_active_session(EvilCTF::ShellAdapter.wrap(shell)) rescue nil
        end
      rescue
      end

      # Drain any pending stdin bytes (avoid accidentally processing keys
      # that were typed before the TUI fully initialized) and set a short
      # grace period during which keypresses are ignored.
      begin
        while IO.select([STDIN], nil, nil, 0)
          begin
            STDIN.read_nonblock(1024)
          rescue IO::WaitReadable, Errno::EAGAIN, EOFError
            break
          rescue => _e
            break
          end
        end
      rescue
      end
      ignore_until = Time.now + 0.35

      # UI state populated by a background poller (avoids blocking UI on WinRM)
      ui_state = {}
      poller = Thread.new do
        loop do
          break if shutdown
          begin
            current_shell = app_state.active_session || shell
            if current_shell
              h = EvilCTF::Execution.run(current_shell, 'hostname', timeout: 5)
              u = EvilCTF::Execution.run(current_shell, '[Security.Principal.WindowsIdentity]::GetCurrent().Name', timeout: 5)
              o = EvilCTF::Execution.run(current_shell, 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"', timeout: 8)
              host = h && h.output ? h.output.strip : nil
              user = u && u.output ? u.output.strip : nil
              os   = o && o.output ? o.output.strip : nil
              connected = h && h.ok
              ui_state_mutex.synchronize { ui_state[:host] = host; ui_state[:user] = user; ui_state[:os_info] = os; ui_state[:connected] = connected }
            else
              ui_state_mutex.synchronize { ui_state[:connected] = false }
            end
          rescue => _e
            ui_state_mutex.synchronize { ui_state[:connected] = false }
          end
          sleep 2
        end
      end

      while !should_exit
        # Build state from poller snapshot
        state = ui_state_mutex.synchronize { ui_state.dup }
        state[:connected] = !!state[:connected]
        state[:shell] = options[:shell] || 'PowerShell'
        state[:ssl] = !!options[:ssl]

        # Ensure we use the currently active session (if any) for commands
        current_shell = app_state.active_session || shell

        # Use authoritative AppState for sessions/streams/results
        system('clear') rescue nil
        render_fixed_layout(current_shell, state, app_state.sessions, app_state.stream_snapshot)

        # Read a single key and react. Use IO.select with short timeout so
        # the UI refreshes regularly and shows background output without
        # requiring a key press.
        key = nil
        begin
          if IO.select([STDIN], nil, nil, 0.2)
            if reader.respond_to?(:read_key)
              key = reader.read_key
            elsif reader.respond_to?(:read_char)
              key = reader.read_char
            else
              key = STDIN.getch rescue nil
            end
          else
            key = nil
          end
        rescue Interrupt
          should_exit = true
          break
        rescue => _e
          key = nil
        end

        # Ignore any accidental keypresses during the short grace period
        if key && Time.now < ignore_until
          key = nil
        end

        # Menu toggle keys (uppercase): toggle top-level menus
        if key == 'S' || key == 'T' || key == 'M' || key == 'P' || key == 'E'
          map = { 'S' => :sessions, 'T' => :tools, 'M' => :macros, 'P' => :profiles, 'E' => :settings }
          sel = map[key]
          if app_state.menu_open == sel
            app_state.set_menu_open(nil)
          else
            app_state.set_menu_open(sel)
          end
          next
        end

        # If user entered insert mode, capture typed characters directly into AppState.cli_input
        if app_state.mode == :insert
          # handle insert-mode keys: printable strings append, backspace removes, Enter submits
          begin
            if key == :return || key == :enter || key == "\r" || key == "\n"
              cmd = app_state.cli_input.to_s.strip
              app_state.append_cli_history("PS> #{cmd}") if cmd && !cmd.empty?
              app_state.set_cli_input('')
              app_state.set_mode(:NORMAL)
              if current_shell && cmd && !cmd.empty?
                Thread.new do
                  begin
                    res = EvilCTF::Execution.run(current_shell, cmd, timeout: 120)
                    out = res.output.to_s
                    # Append both to stream and CLI history so output shows in the interactive pane
                    out.lines.each do |ln|
                      app_state.append_stream("#{cmd} -> #{ln.chomp}")
                      app_state.append_cli_history(ln.chomp)
                    end
                    app_state.append_result("#{cmd}\n#{out}")
                    unless res.ok
                      app_state.push_alert("Command finished with non-zero exit or timeout: #{cmd}")
                    end
                  rescue => e
                    app_state.append_stream("[!] Command error: #{e.class}: #{e.message}")
                  end
                end
              else
                app_state.append_stream('[!] No active shell to run command') unless current_shell
              end
            elsif key == :backspace || key == :delete || key == 127 || key == "\u007F"
              cur = app_state.cli_input.to_s
              app_state.set_cli_input(cur[0..-2] || '')
            elsif key.is_a?(String)
              # printable character(s)
              cur = app_state.cli_input.to_s
              app_state.set_cli_input(cur + key)
            end
          rescue => e
            app_state.append_stream("[!] Insert-mode input error: #{e.class}: #{e.message}")
            app_state.set_mode(:NORMAL)
          end
          next
        end

        case key
        when 'q', 'Q', :ctrl_c
          should_exit = true
        when 'r', 'R'
          next
        when 'i', 'I'
          # Enter insert mode to type directly into the CLI prompt
          app_state.set_mode(:insert)
          next
        when '1'
          # Map menu item '1' to recon_basic
          if current_shell
            Thread.new { run_recon_basic(current_shell) }
          else
            TUI.append_stream('[!] No active shell to run recon_basic')
          end
          next
        when 'n', 'N'
          # Start a new background session via prompt
          begin
            prompt = (defined?(TTY::Prompt) ? TTY::Prompt.new : nil)
            ip = prompt_value(prompt: prompt, label: 'Target IP:', default: nil)
            user = prompt_value(prompt: prompt, label: 'User:', default: 'Administrator')
            pass = prompt_value(prompt: prompt, label: 'Password:', default: nil, secret: true)
            if ip.to_s.strip.empty? || user.to_s.strip.empty?
              TUI.append_stream('[!] Target IP and User are required')
              next
            end
            # Create a connection and shell adapter in background and set it as active
            t = Thread.new do
              begin
                opts = { ip: ip, user: user, password: pass, ssl: false }
                endpoint = "http://#{ip}:5985/wsman"
                validation = EvilCTF::Session.test_connection(
                  endpoint: endpoint,
                  user: user,
                  password: pass,
                  ssl: false,
                  timeout: 10
                )
                unless validation[:ok]
                  render_modernization_report(target: ip, validation: validation)
                  next
                end
                conn = EvilCTF::Connection.build_full(**opts)
                unless conn
                  TUI.append_stream("[!] Failed to create connection for #{ip}")
                  next
                end
                sh = conn.shell(:powershell)
                adapter = EvilCTF::ShellAdapter.wrap(sh)
                app_state.set_active_session(adapter)
                TUI.add_session({ ip: ip, user: user, adapter: adapter, thread: Thread.current, started_at: Time.now })
                TUI.append_stream("[+] Connected and set active session: #{ip}")
              rescue => e
                TUI.append_stream("[!] Failed to start session #{ip}: #{e.class}: #{e.message}")
              end
            end
            TUI.add_session({ ip: ip, user: user, thread: t, started_at: Time.now })
          rescue => e
            # ignore prompt failures
          end
          next
        when 'c', 'C', :f2
          # Run a command on the provided shell (if present) in background and append output to stream buffer
          if current_shell
            begin
              handle_cli_submit(current_shell)
            rescue => e
              TUI.append_stream("[!] Command error (submit): #{e.class}: #{e.message}")
            end
          else
            TUI.append_stream("[!] No active shell to run commands")
          end
          next
        when 's', 'S', :f3
          # session enumeration / refresh results
          if current_shell
            Thread.new do
              begin
                res = EvilCTF::Execution.run(current_shell, 'Get-Process | Select-Object -First 10 Name,Id', timeout: 10)
                TUI.append_stream(res.output.to_s)
                unless res.ok
                  TUI.append_stream('[!] Enumeration may have timed out or failed')
                end
              rescue => e
                TUI.append_stream("[!] Session enumerate error: #{e.class}: #{e.message}")
              end
            end
          else
            TUI.append_stream('[!] No active shell to enumerate')
          end
          next
        when :f1
          # Map F1 to 'new session' flow
          begin
            prompt = (defined?(TTY::Prompt) ? TTY::Prompt.new : nil)
            ip = prompt_value(prompt: prompt, label: 'Target IP:', default: nil)
            user = prompt_value(prompt: prompt, label: 'User:', default: 'Administrator')
            pass = prompt_value(prompt: prompt, label: 'Password:', default: nil, secret: true)
            if ip.to_s.strip.empty? || user.to_s.strip.empty?
              TUI.append_stream('[!] Target IP and User are required')
              next
            end
            t = Thread.new do
              begin
                opts = { ip: ip, user: user, password: pass, ssl: false }
                endpoint = "http://#{ip}:5985/wsman"
                validation = EvilCTF::Session.test_connection(
                  endpoint: endpoint,
                  user: user,
                  password: pass,
                  ssl: false,
                  timeout: 10
                )
                unless validation[:ok]
                  render_modernization_report(target: ip, validation: validation)
                  next
                end
                conn = EvilCTF::Connection.build_full(**opts)
                unless conn
                  TUI.append_stream("[!] Failed to create connection for #{ip}")
                  next
                end
                sh = conn.shell(:powershell)
                adapter = EvilCTF::ShellAdapter.wrap(sh)
                app_state.set_active_session(adapter)
                TUI.add_session({ ip: ip, user: user, adapter: adapter, thread: Thread.current, started_at: Time.now })
                TUI.append_stream("[+] Connected and set active session: #{ip}")
              rescue => e
                TUI.append_stream("[!] Failed to start session #{ip}: #{e.class}: #{e.message}")
              end
            end
            TUI.add_session({ ip: ip, user: user, thread: t, started_at: Time.now })
          rescue => _e
            # ignore prompt failures
          end
          next
        when 'u', 'U', :f5
          if current_shell
            transfer_file(shell: current_shell, direction: :upload)
          else
            TUI.append_stream('[!] No active shell for upload')
          end
          next
        when 'd', 'D', :f6
          if current_shell
            transfer_file(shell: current_shell, direction: :download)
          else
            TUI.append_stream('[!] No active shell for download')
          end
          next
        else
          # any other key refreshes
          next
        end
      end
    ensure
      # Clean shutdown: stop poller and restore terminal mode
      begin
        shutdown = true
        poller.join(1) if poller && poller.alive?
      rescue
      end
      begin
        system('stty sane') rescue nil
      rescue
      end
    end

    # Helper: prompt for a command and execute it in background using Execution.run
    def self.handle_cli_submit(shell)
      prompt = (defined?(TTY::Prompt) ? TTY::Prompt.new : nil)
      cmd = prompt_value(prompt: prompt, label: 'PS>', default: nil)
      return unless cmd && !cmd.strip.empty?
      Thread.new do
        begin
          res = EvilCTF::Execution.run(shell, cmd, timeout: 120)
          out = res.output.to_s
          out.lines.each { |ln| TUI.append_stream("#{cmd} -> #{ln.chomp}") }
          unless res.ok
            TUI.append_stream("[!] Command finished with non-zero exit or timeout: #{res.output}")
          end
        rescue => e
          TUI.append_stream("[!] Command error: #{e.class}: #{e.message}")
        end
      end
    end

    # Run a recon_basic enumeration using real commands and stream results
    def self.run_recon_basic(shell)
      id = "recon_basic_#{Time.now.to_i}_#{rand(9999)}"
      app_state.add_task(id, { name: 'recon_basic', started_at: Time.now })
      app_state.set_last_scan_time(Time.now)
      commands = ['whoami /all', 'net user', 'systeminfo']
      commands.each do |cmd|
        begin
          append_stream("[recon_basic] Running: #{cmd}")
          # Use streaming API to get incremental updates as the remote job runs
          full = ''
          res = EvilCTF::Execution.stream(shell, cmd, timeout: 120, poll_interval: 1) do |chunk|
            # chunk may contain multiple lines; append to AppState incrementally
            app_state.append_result(chunk)
            chunk.lines.each { |ln| append_stream("#{cmd} -> #{ln.chomp}") }
            full << chunk
          end
          # If stream returned final output object with output, ensure final append
          if res && res.output && !res.output.empty?
            app_state.append_result(res.output)
          end
          unless res && res.ok
            append_stream("[!] #{cmd} finished with non-zero exit or timeout")
            app_state.push_alert("recon_basic: #{cmd} failed or timed out")
          end
        rescue => e
          append_stream("[!] recon_basic command error: #{e.class}: #{e.message}")
          app_state.push_alert("recon_basic exception: #{e.class}")
        end
      end
      app_state.remove_task(id)
    end

    def self.screen_size
      width = (TTY::Screen.width rescue 100)
      height = (TTY::Screen.height rescue 30)
      [width, height]
    end

    def self.fit_line(text, width)
      t = text.to_s.gsub(/[\r\n]+/, ' ')
      return '' if width <= 0
      return t if t.length <= width
      return '…' if width == 1
      t[0, width - 1] + '…'
    end

    def self.prompt_value(prompt:, label:, default:, secret: false)
      return fallback_prompt(label: label, default: default, secret: secret) unless prompt

      if secret
        begin
          prompt.mask(label, quiet: true, filter: ->(value) { value.to_s.strip })
        rescue ArgumentError
          prompt.mask(label)
        end
      else
        begin
          prompt.ask(label, default: default, quiet: true, filter: ->(value) { value.to_s.strip })
        rescue ArgumentError
          prompt.ask(label, default: default)
        end
      end
    end

    def self.fallback_prompt(label:, default:, secret: false)
      if secret
        print "#{label} "
        value = (STDIN.noecho(&:gets).to_s.strip rescue STDIN.gets.to_s.strip)
        puts
        return value
      end

      if default
        print "#{label} [#{default}] "
      else
        print "#{label} "
      end
      value = STDIN.gets&.strip
      value = default if (value.nil? || value.empty?) && !default.nil?
      value
    end

    def self.transfer_file(shell:, direction:)
      prompt = (defined?(TTY::Prompt) ? TTY::Prompt.new : nil)
      adapter = EvilCTF::ShellAdapter.wrap(shell)
      fm = adapter.respond_to?(:file_manager) ? adapter.file_manager : nil
      unless fm
        append_stream('[!] File manager unavailable for current session')
        return
      end

      case direction
      when :upload
        local_path = prompt_value(prompt: prompt, label: 'Local file path:', default: nil)
        remote_path = prompt_value(prompt: prompt, label: 'Remote destination path:', default: nil)
        return if local_path.to_s.empty? || remote_path.to_s.empty?

        Thread.new do
          begin
            fm.upload(local_path: local_path, remote_path: remote_path)
            append_stream("[+] Upload complete: #{local_path} -> #{remote_path}")
          rescue => e
            append_stream("[!] Upload failed: #{e.class}: #{e.message}")
          end
        end
      when :download
        remote_path = prompt_value(prompt: prompt, label: 'Remote file path:', default: nil)
        local_path = prompt_value(prompt: prompt, label: 'Local destination path:', default: nil)
        return if local_path.to_s.empty? || remote_path.to_s.empty?

        Thread.new do
          begin
            fm.download(remote_path: remote_path, local_path: local_path)
            append_stream("[+] Download complete: #{remote_path} -> #{local_path}")
          rescue => e
            append_stream("[!] Download failed: #{e.class}: #{e.message}")
          end
        end
      end
    end

    def self.render_modernization_report(target:, validation:)
      status = validation[:ok] ? 'PASS' : 'FAIL'
      error = validation[:error].to_s
      report_text = validation[:report].to_s

      begin
        require 'tty-table'
        width, _height = screen_size
        value_width = [[width - 28, 20].max, 120].min
        rows = [
          ['Target', fit_line(target.to_s, value_width)],
          ['Ruby 4 Compatibility', fit_line(status, value_width)],
          ['Connection Error', fit_line(error.empty? ? 'N/A' : error, value_width)],
          ['Report', fit_line(report_text.empty? ? 'No additional report' : report_text.gsub(/\s+/, ' ').strip, value_width)]
        ]
        table = TTY::Table.new(['Field', 'Value'], rows)
        append_stream('')
        append_stream('[!] Connection validation failed')
        table.render(:unicode, multiline: true).lines.each { |ln| append_stream(ln.chomp) }
      rescue LoadError
        append_stream("[!] Connection validation failed for #{target}: #{error}")
        append_stream(report_text) unless report_text.empty?
      end
    end
  end
end
