module EvilCTF
  class TUI
    # Simple in-memory trackers for sessions started via the TUI and a small
    # streaming output buffer used by the CLI pane.
    require_relative 'app_state'
    require_relative 'tui_controller'

    def self.app_state
      EvilCTF::AppState.instance
    end

    # Thread-safe helpers
    def self.sessions_mutex = app_state.mutex
    def self.stream_mutex = app_state.mutex
    def self.ui_state_mutex = app_state.mutex

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

    # Build a dynamic 2-column frame (left menu, center CLI).
    # Returns frame lines plus cursor anchor metadata for diff-based rendering.
    def self.build_fixed_layout_lines(_shell, state = {}, _sessions = [], stream_lines = [])
      width, height = screen_size
      total = [width, 40].max

      left_w = [[(total * 0.20).to_i, 18].max, total - 15].min
      center_w = [total - left_w - 3, 10].max

      lines = []

      # Top bar
      lines << "┌#{'─' * (total - 2)}┐"
      lines << "│ #{fit_line('AWINRM OPERATOR CONSOLE', total - 4).ljust(total - 4)} │"
      meta = "Host: #{state[:host] || 'N/A'}   Status: #{state[:connected] ? 'Connected' : 'Disconnected'}   Shell: #{state[:shell] || 'PowerShell'}   SSL: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}"
      lines << "│ #{fit_line(meta, total - 4).ljust(total - 4)} │"
      lines << "└#{'─' * (total - 2)}┘"

      # Pane headers (two-column layout)
      lines << "┌#{'─' * left_w}┬#{'─' * center_w}┐"
      lines << "│#{fit_line('MENU (Alt+1)', left_w).ljust(left_w)}" \
               "│#{fit_line('INTERACTIVE CLI (Alt+2)', center_w).ljust(center_w)}│"
      lines << "├#{'─' * left_w}┼#{'─' * center_w}┤"

      # Left menu content
      # Top-level menu definitions (for rendering and interaction)
      menus = {
        sessions: ['Active Sessions', 'New Session', 'Close Session'],
        tools: ['Recon', 'Credential Access', 'Lateral Movement', 'Enumeration', 'Upload / Download'],
        macros: %w[recon_basic recon_full dump_creds disable_defender],
        profiles: ['default.yml', 'ctf.yml', 'prod.yml'],
        settings: ['SSL Verification', 'Logging', 'Shell Adapter', 'Paths']
      }

      # Build left menu from `menus` with collapsible behavior
      left = []
      open = app_state.menu_open
      menus.each do |k, children|
        label = k.to_s.capitalize
        indicator = open == k ? '[-]' : '[+]'
        left << "#{label} #{indicator}"
        next unless open == k

        children.each do |ch|
          left << "  #{ch}"
        end
        left << ''
      end

      # Center CLI content (history + interactive prompt)
      center = []
      center_inner_w = [center_w, 1].max
      # Show last CLI history lines (real commands/results)
      cli_hist = app_state.cli_history_snapshot || []
      wrapped_hist = wrap_lines(cli_hist, center_inner_w)
      if wrapped_hist && !wrapped_hist.empty?
        wrapped_hist.last(12).each do |ln|
          center << ln.to_s
        end
      else
        # Fallback to showing recent stream lines or example placeholders
        if stream_lines && !stream_lines.empty?
          wrap_lines(stream_lines, center_inner_w).last(12).each do |ln|
            center << ln.to_s
          end
        else
          center << '(no CLI history yet)'
        end
      end

      # Always show the latest stream lines after history for realtime feedback
      if stream_lines && !stream_lines.empty?
        center << ''
        wrap_lines(stream_lines, center_inner_w).last(16).each do |ln|
          center << ln.to_s
        end
      end

      # Show active uploads as additional info
      uploads = app_state.uploads
      if uploads && !uploads.empty?
        center << ''
        uploads.each_value do |info|
          pct = if info[:total] && info[:sent] && info[:total].positive?
                  ((info[:sent].to_f / info[:total]) * 100).round
                else
                  0
                end
          center << "Upload #{info[:name]}: #{pct}% (#{info[:sent]}/#{info[:total]})"
        end
      end

      # Raw-input CLI line with prompt sourced from remote shell state.
      center << ''
      cli_input = app_state.cli_input || ''
      prompt_text = state[:remote_prompt].to_s
      prompt_text = 'PS> ' if prompt_text.strip.empty?
      visible_prompt_line = build_prompt_display_line(
        prompt_text: prompt_text,
        cli_input: cli_input,
        width: center_w
      )
      center << visible_prompt_line

      # Render rows (two-column layout), constrained to terminal height.
      fixed_rows = 4 + 3 + 1 + 1 # top bar + pane header + pane bottom + footer
      visible_rows = [height - fixed_rows, 4].max
      left_tail = left.last(visible_rows)
      center_tail = center.last(visible_rows)
      prompt_index = center.length - 1
      center_start = [center.length - visible_rows, 0].max
      prompt_visible_row = prompt_index - center_start

      visible_rows.times do |i|
        l = fit_line(left_tail[i] || '', left_w)
        c = fit_line(center_tail[i] || '', center_w)

        lines << "│#{l.ljust(left_w)}│#{c.ljust(center_w)}│"
      end

      lines << "└#{'─' * left_w}┴#{'─' * center_w}┘"

      # Footer: include menu toggle hints and insert-mode indicator
      mode_label = app_state.mode == :insert ? '[INSERT]' : '[NORMAL]'
      footer = "[S] Sessions [T] Tools [M] Macros [P] Profiles [E] Settings [U] Upload [D] Download #{mode_label} [i] insert [q] quit"
      lines << fit_line(footer, total).center(total)

      prompt_row = if prompt_visible_row >= 0 && prompt_visible_row < visible_rows
                     7 + prompt_visible_row
                   else
                     7 + visible_rows - 1
                   end
      center_text_col = left_w + 2
      prompt_col = center_text_col + [visible_prompt_line.length, center_w].min

      {
        lines: lines,
        cursor_anchor: { row: prompt_row, col: prompt_col },
        show_cursor: app_state.pane_focus == :cli,
        width: total
      }
    end

    # Render fixed layout for compatibility with existing specs.
    def self.render_fixed_layout(shell, state = {}, sessions = [], stream_lines = [])
      frame = build_fixed_layout_lines(shell, state, sessions, stream_lines)
      frame[:lines].each { |ln| puts ln }
    end

    def self.render_dashboard(_shell, state = {})
      width, _height = screen_size
      total = [[width, 72].max, 120].min

      puts "┌#{'─' * (total - 2)}┐"
      puts "#{'│ EvilCTF Dashboard'.ljust(total - 1)}│"
      puts "├#{'─' * (total - 2)}┤"

      host = state[:host] || 'N/A'
      user = state[:user] || 'N/A'
      os_info = state[:os_info] || 'N/A'

      puts "│ #{fit_line("Host: #{host}", total - 4).ljust(total - 4)} │"
      puts "│ #{fit_line("User: #{user}", total - 4).ljust(total - 4)} │"
      puts "│ #{fit_line(os_info, total - 4).ljust(total - 4)} │"

      puts "├#{'─' * (total - 2)}┤"
      puts '│ ' + fit_line("Connection Status: #{state[:connected] ? 'Connected' : 'Disconnected'}",
                           total - 4).ljust(total - 4) + ' │'
      puts "│ #{fit_line("Shell Type: #{state[:shell] || 'PowerShell'}", total - 4).ljust(total - 4)} │"
      puts "│ #{fit_line("SSL Verification: #{state[:ssl] ? 'OK' : 'UNVERIFIED'}", total - 4).ljust(total - 4)} │"
      puts "└#{'─' * (total - 2)}┘"
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
               [
                 'powershell "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled"', 'sc query WinDefend'
               ]
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
        res = EvilCTF::Execution.run(shell, cmd, timeout: 30)
        output += "\n> #{cmd}\n"
        output += res.output.to_s
        output += "\n"
        output += "[!] Command may have timed out or failed\n" unless res.ok
      rescue StandardError => e
        output += "\n> #{cmd}\n"
        output += "[!] Enumeration command error: #{e.class}: #{e.message}\n"
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
        require 'tty-prompt'
        require 'tty-cursor'
        require 'concurrent'
      rescue LoadError
        # Render once and return if tty gems aren't available
        render_fixed_layout(shell, host: shell && begin
          shell.run('hostname').output.strip
        rescue StandardError
          nil
        end,
                                   connected: !!shell, shell: options[:shell] || 'PowerShell', ssl: options[:ssl])
        return
      end

      reader = TTY::Reader.new
      should_exit = false
      shutdown = false
      cursor = TTY::Cursor
      previous_frame = []
      last_layout_version = app_state.layout_version
      previous_winch = nil

      refresh_screen_size!(bump: false)
      app_state.set_pane_focus(:sidebar)

      # Queue-driven async command execution keeps UI loop non-blocking.
      command_queue = Queue.new
      prompt_factory = lambda do
        defined?(TTY::Prompt) ? TTY::Prompt.new : nil
      end
      controller = EvilCTF::TUI::Controller.new(
        app_state: app_state,
        command_queue: command_queue,
        transfer_callback: ->(direction:, shell:) { transfer_file(shell: shell, direction: direction) },
        root_path: File.expand_path('../..', __dir__),
        prompt_factory: prompt_factory
      )

      begin
        previous_winch = Signal.trap('WINCH') do
          refresh_screen_size!(bump: true)
        end
      rescue ArgumentError
        previous_winch = nil
      end

      # If TUI was launched with an active shell, register it as the active session
      begin
        if shell
          begin
            app_state.set_active_session(EvilCTF::ShellAdapter.wrap(shell))
          rescue StandardError
            nil
          end
        end
      rescue StandardError
      end

      # Drain any pending stdin bytes (avoid accidentally processing keys
      # that were typed before the TUI fully initialized) and set a short
      # grace period during which keypresses are ignored.
      begin
        while $stdin.wait_readable(0)
          begin
            $stdin.read_nonblock(1024)
          rescue StandardError => _e
            break
          end
        end
      rescue StandardError
      end
      ignore_until = Time.now + 0.35

      # UI state populated by a background poller (avoids blocking UI on WinRM).
      # All probes are batched into a single PowerShell round-trip; the slow
      # systeminfo probe only runs every 6th poll (~30s) to avoid hammering the
      # target with a slow command while idle.
      ui_state = {}
      poller = Thread.new do
        poll_count = 0
        loop do
          break if shutdown

          begin
            current_shell = app_state.active_session || shell
            if current_shell
              include_os = (poll_count % 6).zero?
              probe_ps = <<~PS
                try {
                  $h = hostname
                  $u = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                  $p = (prompt)
                  "HOST|||$h"
                  "USER|||$u"
                  "PROMPT|||$p"
                } catch {}
              PS
              if include_os
                probe_ps += <<~PS
                  try {
                    $o = systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
                    "OS|||$o"
                  } catch {}
                PS
              end
              r = EvilCTF::Execution.run(current_shell, probe_ps, timeout: include_os ? 12 : 6)
              out = r&.output ? r.output.to_s : ''
              host = out.lines.find { |ln| ln.start_with?('HOST|||') }.to_s.sub('HOST|||', '').strip
              user = out.lines.find { |ln| ln.start_with?('USER|||') }.to_s.sub('USER|||', '').strip
              os   = out.lines.find { |ln| ln.start_with?('OS|||') }.to_s.sub('OS|||', '').strip
              remote_prompt = out.lines.find { |ln| ln.start_with?('PROMPT|||') }.to_s.sub('PROMPT|||', '').strip
              remote_prompt = 'PS> ' if remote_prompt.nil? || remote_prompt.empty?
              remote_prompt = "#{remote_prompt} " unless remote_prompt.end_with?(' ')
              connected = r&.ok
              ui_state_mutex.synchronize do
                ui_state[:host] = host.empty? ? nil : host
                ui_state[:user] = user.empty? ? nil : user
                # systeminfo is only fetched every 6th poll; keep the last known
                # value on intermediate polls so the OS line doesn't flicker.
                ui_state[:os_info] = os.empty? ? ui_state[:os_info] : os
                ui_state[:connected] = !!connected
                ui_state[:remote_prompt] = remote_prompt
              end
            else
              ui_state_mutex.synchronize { ui_state[:connected] = false }
            end
          rescue StandardError => _e
            ui_state_mutex.synchronize { ui_state[:connected] = false }
          end
          poll_count += 1
          sleep 5
        end
      end

      worker = Thread.new do
        loop do
          break if shutdown

          begin
            item = command_queue.pop
            break if item == :shutdown

            shell_obj = item[:shell]
            cmd = item[:cmd].to_s
            next if shell_obj.nil? || cmd.empty?

            app_state.append_cli_history("PS> #{cmd}")

            res = EvilCTF::Execution.stream(shell_obj, cmd, timeout: 180, poll_interval: 1) do |chunk|
              chunk.to_s.lines.each do |ln|
                stripped = ln.chomp
                app_state.append_stream(stripped)
                app_state.append_cli_history(stripped)
              end
            end

            final_output = res&.output.to_s
            unless final_output.empty?
              final_output.lines.each do |ln|
                stripped = ln.chomp
                app_state.append_stream(stripped)
                app_state.append_cli_history(stripped)
              end
            end

            app_state.push_alert("Command failed or timed out: #{cmd}") unless res&.ok

            begin
              prompt_res = EvilCTF::Execution.run(shell_obj, 'prompt', timeout: 3)
              prompt_line = prompt_res&.output.to_s.strip
              prompt_line = 'PS> ' if prompt_line.empty?
              prompt_line = "#{prompt_line} " unless prompt_line.end_with?(' ')
              app_state.append_stream(prompt_line)
            rescue StandardError
            end
          rescue StandardError => e
            app_state.append_stream("[!] Worker error: #{e.class}: #{e.message}")
          end
        end
      end

      until should_exit
        # Build state from poller snapshot
        state = ui_state_mutex.synchronize { ui_state.dup }
        state[:connected] = !!state[:connected]
        state[:shell] = options[:shell] || 'PowerShell'
        state[:ssl] = !!options[:ssl]

        # Ensure we use the currently active session (if any) for commands
        current_shell = app_state.active_session || shell

        current_layout_version = app_state.layout_version
        if current_layout_version != last_layout_version
          previous_frame = []
          last_layout_version = current_layout_version
        end

        # Use authoritative AppState for sessions/streams/results and render via frame diff.
        frame_data = build_fixed_layout_lines(current_shell, state, app_state.sessions, app_state.stream_snapshot)
        render_frame_diff(
          cursor: cursor,
          previous_frame: previous_frame,
          frame: frame_data[:lines],
          cursor_anchor: frame_data[:cursor_anchor],
          show_cursor: frame_data[:show_cursor]
        )
        previous_frame = frame_data[:lines]

        # Read a single key and react. Use IO.select with short timeout so
        # the UI refreshes regularly and shows background output without
        # requiring a key press.
        key = nil
        begin
          key = if $stdin.wait_readable(0.2)
                  if reader.respond_to?(:read_key)
                    reader.read_key
                  elsif reader.respond_to?(:read_char)
                    reader.read_char
                  else
                    begin
                      $stdin.getch
                    rescue StandardError
                      nil
                    end
                  end
                end
        rescue Interrupt
          should_exit = true
          break
        rescue StandardError => _e
          key = nil
        end

        # Ignore any accidental keypresses during the short grace period
        key = nil if key && Time.now < ignore_until

        # If user entered insert mode, capture typed characters directly into AppState.cli_input
        if app_state.mode == :insert
          # handle insert-mode keys: printable strings append, backspace removes, Enter submits
          begin
            if [:return, :enter, "\r", "\n"].include?(key)
              cmd = app_state.cli_input.to_s.strip
              app_state.set_cli_input('')
              app_state.set_mode(:NORMAL)
              if current_shell && cmd && !cmd.empty?
                command_queue << { shell: current_shell, cmd: cmd }
              else
                app_state.append_stream('[!] No active shell to run command') unless current_shell
              end
            elsif [:alt_1, "\e1"].include?(key)
              app_state.set_pane_focus(:sidebar)
              app_state.set_mode(:NORMAL)
            elsif [:alt_2, "\e2"].include?(key)
              app_state.set_pane_focus(:cli)
              app_state.set_mode(:insert)
            elsif [:backspace, :delete, 127, "\u007F"].include?(key)
              cur = app_state.cli_input.to_s
              app_state.set_cli_input(cur[0..-2] || '')
            elsif key.is_a?(String) && key.match?(/\A[[:print:]]+\z/)
              # printable character(s)
              cur = app_state.cli_input.to_s
              app_state.set_cli_input(cur + key)
            end
          rescue StandardError => e
            app_state.append_stream("[!] Insert-mode input error: #{e.class}: #{e.message}")
            app_state.set_mode(:NORMAL)
          end
          next
        end

        # Global hotkeys are routed through the controller in NORMAL mode.
        next if controller.handle_key(key: key, current_shell: current_shell)

        case key
        when 'q', 'Q', :ctrl_c
          should_exit = true
        when 'r', 'R'
          next
        when 'i', 'I', 'c', 'C', :alt_2, "\e2", :f2
          # Focus CLI pane for raw input (insert mode).
          app_state.set_pane_focus(:cli)
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
            prompt = prompt_factory.call
            profile = app_state.pending_connection
            ip = prompt_value(prompt: prompt, label: 'Target IP:', default: profile[:ip])
            user = prompt_value(prompt: prompt, label: 'User:',
                                default: profile[:user] || profile[:username] || 'Administrator')
            pass = prompt_value(prompt: prompt, label: 'Password:', default: profile[:password], secret: true)
            if ip.to_s.strip.empty? || user.to_s.strip.empty?
              TUI.append_stream('[!] Target IP and User are required')
              next
            end
            # Create a connection and shell adapter in background and set it as active
            t = Thread.new do
              opts = {
                ip: ip,
                user: user,
                password: pass,
                hash: profile[:hash],
                port: profile[:port],
                ssl: !!profile[:ssl],
                kerberos: profile[:kerberos],
                realm: profile[:realm],
                keytab: profile[:keytab],
                proxy: profile[:proxy],
                user_agent: profile[:user_agent],
                debug: profile[:debug]
              }
              port = opts[:port] || (opts[:ssl] ? 5986 : 5985)
              scheme = opts[:ssl] ? 'https' : 'http'
              endpoint = "#{scheme}://#{ip}:#{port}/wsman"
              validation = EvilCTF::Session.test_connection(
                endpoint: endpoint,
                user: user,
                password: pass,
                hash: profile[:hash],
                kerberos: profile[:kerberos],
                realm: profile[:realm],
                keytab: profile[:keytab],
                transport: profile[:transport],
                user_agent: profile[:user_agent],
                ssl: opts[:ssl],
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
            rescue StandardError => e
              TUI.append_stream("[!] Failed to start session #{ip}: #{e.class}: #{e.message}")
            end
            TUI.add_session({ ip: ip, user: user, thread: t, started_at: Time.now })
          rescue StandardError => e
            # ignore prompt failures
          end
          next
        when :f3
          # session enumeration / refresh results
          if current_shell
            Thread.new do
              res = EvilCTF::Execution.run(current_shell, 'Get-Process | Select-Object -First 10 Name,Id',
                                           timeout: 10)
              TUI.append_stream(res.output.to_s)
              TUI.append_stream('[!] Enumeration may have timed out or failed') unless res.ok
            rescue StandardError => e
              TUI.append_stream("[!] Session enumerate error: #{e.class}: #{e.message}")
            end
          else
            TUI.append_stream('[!] No active shell to enumerate')
          end
          next
        when :f1
          # Map F1 to 'new session' flow
          begin
            prompt = prompt_factory.call
            profile = app_state.pending_connection
            ip = prompt_value(prompt: prompt, label: 'Target IP:', default: profile[:ip])
            user = prompt_value(prompt: prompt, label: 'User:',
                                default: profile[:user] || profile[:username] || 'Administrator')
            pass = prompt_value(prompt: prompt, label: 'Password:', default: profile[:password], secret: true)
            if ip.to_s.strip.empty? || user.to_s.strip.empty?
              TUI.append_stream('[!] Target IP and User are required')
              next
            end
            t = Thread.new do
              opts = {
                ip: ip,
                user: user,
                password: pass,
                hash: profile[:hash],
                port: profile[:port],
                ssl: !!profile[:ssl],
                kerberos: profile[:kerberos],
                realm: profile[:realm],
                keytab: profile[:keytab],
                proxy: profile[:proxy],
                user_agent: profile[:user_agent],
                debug: profile[:debug]
              }
              port = opts[:port] || (opts[:ssl] ? 5986 : 5985)
              scheme = opts[:ssl] ? 'https' : 'http'
              endpoint = "#{scheme}://#{ip}:#{port}/wsman"
              validation = EvilCTF::Session.test_connection(
                endpoint: endpoint,
                user: user,
                password: pass,
                hash: profile[:hash],
                kerberos: profile[:kerberos],
                realm: profile[:realm],
                keytab: profile[:keytab],
                transport: profile[:transport],
                user_agent: profile[:user_agent],
                ssl: opts[:ssl],
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
            rescue StandardError => e
              TUI.append_stream("[!] Failed to start session #{ip}: #{e.class}: #{e.message}")
            end
            TUI.add_session({ ip: ip, user: user, thread: t, started_at: Time.now })
          rescue StandardError => _e
            # ignore prompt failures
          end
          next
        else
          # any other key just refreshes the frame on the next loop iteration
        end
      end
    ensure
      # Clean shutdown: stop poller and restore terminal mode
      begin
        shutdown = true
        begin
          command_queue << :shutdown
        rescue StandardError
          nil
        end
        poller.join(1) if poller&.alive?
        worker.join(1) if worker&.alive?
      rescue StandardError
      end
      begin
        Signal.trap('WINCH', previous_winch) if previous_winch
      rescue StandardError
      end
      begin
        begin
          print cursor.show
        rescue StandardError
          nil
        end
        begin
          system('stty sane')
        rescue StandardError
          nil
        end
      rescue StandardError
      end
    end

    def self.render_frame_diff(cursor:, previous_frame:, frame:, cursor_anchor:, show_cursor:)
      width, _height = screen_size
      max = [previous_frame.length, frame.length].max
      output = ''

      max.times do |idx|
        current = frame[idx] || ''
        prior = previous_frame[idx] || ''
        next if current == prior

        line = fit_line(current, width)
        output << cursor.move_to(0, idx)
        output << line
        output << "\e[0K"
      end

      if previous_frame.length > frame.length
        (frame.length...previous_frame.length).each do |idx|
          output << cursor.move_to(0, idx)
          output << "\e[0K"
        end
      end

      output << if show_cursor
                  cursor.show
                else
                  cursor.hide
                end
      output << if cursor_anchor && cursor_anchor[:row] && cursor_anchor[:col]
                  cursor.move_to(cursor_anchor[:col], cursor_anchor[:row])
                else
                  cursor.move_to(0, frame.length)
                end

      print output unless output.empty?
    end

    def self.toggle_menu(sel)
      if app_state.menu_open == sel
        app_state.set_menu_open(nil)
      else
        app_state.set_menu_open(sel)
      end
    end

    # Run a recon_basic enumeration using real commands and stream results
    def self.run_recon_basic(shell)
      id = "recon_basic_#{Time.now.to_i}_#{rand(9999)}"
      app_state.add_task(id, { name: 'recon_basic', started_at: Time.now })
      app_state.set_last_scan_time(Time.now)
      commands = ['whoami /all', 'net user', 'systeminfo']
      commands.each do |cmd|
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
        app_state.append_result(res.output) if res&.output && !res.output.empty?
        unless res&.ok
          append_stream("[!] #{cmd} finished with non-zero exit or timeout")
          app_state.push_alert("recon_basic: #{cmd} failed or timed out")
        end
      rescue StandardError => e
        append_stream("[!] recon_basic command error: #{e.class}: #{e.message}")
        app_state.push_alert("recon_basic exception: #{e.class}")
      end
      app_state.remove_task(id)
    end

    def self.screen_size
      width, height = app_state.screen_size
      return [width, height] if width.to_i.positive? && height.to_i.positive?

      fallback_w = begin
        TTY::Screen.width
      rescue StandardError
        100
      end
      fallback_h = begin
        TTY::Screen.height
      rescue StandardError
        30
      end
      [fallback_w, fallback_h]
    end

    def self.refresh_screen_size!(bump: false)
      width = begin
        TTY::Screen.width
      rescue StandardError
        100
      end
      height = begin
        TTY::Screen.height
      rescue StandardError
        30
      end
      app_state.set_screen_size(width, height)
      app_state.bump_layout_version if bump
    end

    def self.fit_line(text, width)
      t = text.to_s.gsub(/[\r\n]+/, ' ')
      return '' if width <= 0
      return t if t.length <= width
      return '…' if width == 1

      "#{t[0, width - 1]}…"
    end

    def self.wrap_lines(lines, width)
      return [] if lines.nil? || lines.empty?

      wrapped = []
      lines.each do |line|
        text = line.to_s.gsub("\r", '')
        segments = text.split("\n", -1)
        segments.each do |segment|
          if width <= 0 || segment.empty?
            wrapped << ''
          else
            segment.scan(/.{1,#{width}}/).each { |chunk| wrapped << chunk }
          end
        end
      end
      wrapped
    end

    # Keep typed input visible even when prompt text is long.
    # We prioritize input visibility and compress prompt prefix first.
    def self.build_prompt_display_line(prompt_text:, cli_input:, width:)
      prompt = prompt_text.to_s
      input = cli_input.to_s
      return '' if width <= 0

      plain = "#{prompt}#{input}"
      return plain if plain.length <= width

      return '…' if width == 1

      min_input_width = [[(width * 0.5).to_i, 8].max, width].min

      visible_input = if input.length <= min_input_width
                        input
                      elsif min_input_width <= 1
                        '…'
                      else
                        tail = input[-(min_input_width - 1), min_input_width - 1]
                        "…#{tail}"
                      end

      remaining_for_prompt = width - visible_input.length
      return visible_input[-width, width] if remaining_for_prompt <= 0

      visible_prompt = if prompt.length <= remaining_for_prompt
                         prompt
                       elsif remaining_for_prompt <= 1
                         ''
                       else
                         tail = prompt[-(remaining_for_prompt - 1), remaining_for_prompt - 1]
                         "…#{tail}"
                       end

      result = "#{visible_prompt}#{visible_input}"
      result.length > width ? result[-width, width] : result
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
        value = begin
          $stdin.noecho(&:gets).to_s.strip
        rescue StandardError
          $stdin.gets.to_s.strip
        end
        puts
        return value
      end

      if default
        print "#{label} [#{default}] "
      else
        print "#{label} "
      end
      value = $stdin.gets&.strip
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
          fm.upload(local_path: local_path, remote_path: remote_path)
          append_stream("[+] Upload complete: #{local_path} -> #{remote_path}")
        rescue StandardError => e
          append_stream("[!] Upload failed: #{e.class}: #{e.message}")
        end
      when :download
        remote_path = prompt_value(prompt: prompt, label: 'Remote file path:', default: nil)
        local_path = prompt_value(prompt: prompt, label: 'Local destination path:', default: nil)
        return if local_path.to_s.empty? || remote_path.to_s.empty?

        Thread.new do
          fm.download(remote_path: remote_path, local_path: local_path)
          append_stream("[+] Download complete: #{remote_path} -> #{local_path}")
        rescue StandardError => e
          append_stream("[!] Download failed: #{e.class}: #{e.message}")
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
          ['Report',
           fit_line(report_text.empty? ? 'No additional report' : report_text.gsub(/\s+/, ' ').strip, value_width)]
        ]
        table = TTY::Table.new(%w[Field Value], rows)
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
