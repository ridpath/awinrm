# Minimal TTY Toolkit-safe TUI prototype for EvilCTF
# This file is intentionally resilient if TTY gems are not installed.

module EvilCTF
  class TUI
    def self.start(shell = nil, options = {})
      begin
        require 'tty-prompt'
        require 'tty-table'
        require 'tty-screen'
      rescue LoadError
        puts "TTY gems not installed. Install tty-prompt, tty-table, tty-screen to enable the TUI.".yellow
        return
      end

      prompt = TTY::Prompt.new

      loop do
        # Render only the header (title, menus, actions) so prompt appears at top
        render_dashboard_header(shell, options)

        choice = prompt.select('Main Menu', ['Actions Menu', 'Flag Scan', 'Exit'])

        case choice
        when 'Actions Menu'
          sub = prompt.select('Actions Menu', [
            'Run Command', 'Upload File', 'Download File', 'Stage Tool', 'Execute Tool',
            'AMSI/ETW Bypass', 'System Recon', 'Open Interactive Shell', 'Back'
          ])
          case sub
          when 'Run Command'
            prompt.keypress('Run Command selected - press any key to continue')
          when 'Upload File'
            prompt.keypress('Upload File selected - press any key to continue')
          when 'Download File'
            prompt.keypress('Download File selected - press any key to continue')
          when 'Stage Tool'
            prompt.keypress('Stage Tool selected - press any key to continue')
          when 'Execute Tool'
            prompt.keypress('Execute Tool selected - press any key to continue')
          when 'AMSI/ETW Bypass'
            prompt.keypress('AMSI/ETW Bypass selected - press any key to continue')
          when 'System Recon'
            prompt.keypress('System Recon selected - press any key to continue')
          when 'Open Interactive Shell'
            prompt.keypress('Open Interactive Shell selected - press any key to continue')
          when 'Back'
            # return to main menu
          end
        when 'Flag Scan'
          rows = run_flag_scan(shell)
          if rows.empty?
            puts "\nNo flags found.".white
            prompt.keypress('Press any key to continue')
          else
            table = TTY::Table.new(['Path', 'Value'], rows)
            puts table.render(:unicode)
            prompt.keypress('Press any key to continue')
          end
        when 'Exit'
          break
        end

        # After selection, render the main dashboard body below
        render_dashboard_body(shell, options)
      end
    end

    # Public helper to run the same optimized flag scan as the banner and
    # return an array of [path, value] rows.
    def self.run_flag_scan(shell)
      ps = <<~POWERSHELL
        $found_flags = @{}
        $search_locations = @(
          "C:\\flag.txt", "C:\\user.txt", "C:\\root.txt",
          "C:\\Users\\*\\Desktop\\flag.txt",
          "C:\\Users\\*\\Desktop\\user.txt",
          "C:\\Users\\*\\Desktop\\root.txt",
          "C:\\Users\\*\\Documents\\flag.txt",
          "C:\\Users\\*\\Downloads\\flag.txt"
        )

        foreach ($location in $search_locations) {
          try {
            Get-ChildItem -Path $location -ErrorAction SilentlyContinue | ForEach-Object {
              $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim() -and $content.Trim().Length -lt 500) {
                if (-not $found_flags.ContainsKey($_.FullName)) {
                  $found_flags[$_.FullName] = $content.Trim()
                }
              }
            }
          } catch { }
        }

        $user_dirs = @("Desktop", "Documents", "Downloads")
        foreach ($user_dir in $user_dirs) {
          try {
            Get-ChildItem "C:\\Users\\*\\$user_dir\\*" -Include "flag*", "user.txt", "root.txt" -Recurse -Depth 1 -ErrorAction SilentlyContinue | ForEach-Object {
              $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -and $content.Trim() -and $content.Trim().Length -lt 500) {
                if (-not $found_flags.ContainsKey($_.FullName)) {
                  $found_flags[$_.FullName] = $content.Trim()
                }
              }
            }
          } catch { }
        }

        $found_flags.GetEnumerator() | ForEach-Object {
          Write-Output "FLAGFOUND|||$($_.Key)|||$($_.Value)"
        }
      POWERSHELL

      begin
        result = shell.run(ps)
      rescue => e
        return []
      end

      rows = []
      require 'set'
      seen = Set.new
      result.output.each_line do |line|
        next unless line.include?("FLAGFOUND|||")
        path, value = line.strip.split('|||', 3)[1..2]
        next unless path
        key = path.strip
        next if seen.include?(key)
        seen << key
        rows << [path.strip, (value || '').strip]
      end

      rows
    end

    # Keep old combined renderer for compatibility: header + body
    def self.render_dashboard(shell, options)
      render_dashboard_header(shell, options)
      render_dashboard_body(shell, options)
    end

    def self.render_dashboard_header(shell, options)
      cols = (TTY::Screen.width rescue 80)
      header = ' AWINRM OPERATOR CONSOLE '
      hn = (shell.run('hostname').output.strip rescue 'Unknown')
      ip = options[:ip] || 'N/A'
      host = "Host: #{hn} (#{ip})"

      box_width = [cols, 100].min
      left_w = [24, (box_width * 0.20).floor].max
      center_w = box_width - left_w - 3

      # Title box
      puts "┌" + "─" * (box_width - 2) + "┐"
      puts "│" + header.center(box_width - 2) + "│"
      puts "│" + host.center(box_width - 2) + "│"
      puts "└" + "─" * (box_width - 2) + "┘"
      puts

      # Two-column header: left = MENU, center = TERMINAL
      puts "─" * box_width
      left_title = ' MENU '
      center_title = ' TERMINAL '
      puts left_title.ljust(left_w) + ' ' * 3 + center_title.rjust(center_w)
      puts "─" * box_width
    end

    def self.render_dashboard_body(shell, options)
      cols = (TTY::Screen.width rescue 80)
      box_width = [cols, 100].min
      left_w = [24, (box_width * 0.20).floor].max
      center_w = box_width - left_w - 3

      # Left: vertical menu / commands
      menu_lines = []
      menu_lines << 'Actions:'
      menu_lines << '  1) Open Actions Menu'
      menu_lines << '  2) Sessions'
      menu_lines << '  3) Tools'
      menu_lines << '  4) Loot'
      menu_lines << '  5) Macros'
      menu_lines << '  6) Profiles'
      menu_lines << '  7) Logs'
      menu_lines << ''
      menu_lines << 'Commands:'
      menu_lines << '  r) Run Command'
      menu_lines << '  u) Upload Tool'
      menu_lines << ''

      # Center: terminal-like output
      center_lines = []
      center_lines << 'PS> whoami'
      center_lines << (shell.run('whoami').output.strip rescue '')
      center_lines << ''
      center_lines << 'PS> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'
      center_lines += (shell.run('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"').output.strip rescue '').lines.map(&:chomp)
      center_lines << ''
      center_lines << 'STATUS: ✔ Connected   ✔ Shell Ready'

      max_lines = [menu_lines.size, center_lines.size].max
      (0...max_lines).each do |i|
        l = menu_lines[i] || ''
        c = center_lines[i] || ''
        print l.ljust(left_w)
        print ' ' * 3
        puts c.ljust(center_w)
      end

      puts "─" * box_width
    end

    # Demo mode: replay a scripted, live-updating dashboard for visual testing
    def self.demo(_shell = nil, options = {})
      demo_shell = Object.new
      def demo_shell.run(cmd)
        case cmd
        when 'hostname'
          Struct.new(:output).new("demo-host\n")
        when '[Security.Principal.WindowsIdentity]::GetCurrent().Name'
          Struct.new(:output).new("Demo\\User\n")
        when 'whoami /groups'
          Struct.new(:output).new("Users\n")
        when 'whoami'
          Struct.new(:output).new("demo\\user\n")
        when /systeminfo/
          Struct.new(:output).new("OS Name: DemoOS\nOS Version: 1.0\n")
        else
          Struct.new(:output).new("\n")
        end
      end

      cols = (TTY::Screen.width rescue 80)
      box_width = [cols, 100].min
      left_w = [24, (box_width * 0.20).floor].max
      center_w = box_width - left_w - 3

      # scripted right-panel events
      events = [
        "Initializing quick scan...",
        "FLAGFOUND: C:\\Users\\Alice\\Desktop\\flag.txt flag{demo}",
        "Scanning Profiles...",
        "Found suspicious file: C:\\Users\\Bob\\Documents\\user.txt",
        "FLAGFOUND: C:\\Users\\Bob\\Documents\\user.txt flag{bob}",
        "Upload complete: tool.exe (12KB)",
        "Integrity check passed"
      ]

      # progressively render frames
      right_buffer = []
      events.each_with_index do |ev, idx|
        right_buffer << ev
        system('clear') rescue nil
        render_dashboard_header(demo_shell, options)


        menu_lines = [
          "Actions:",
          "  1) Open Actions Menu",
          "  2) Sessions",
          "  3) Tools",
          "  4) Loot",
          "  5) Macros",
          "  6) Profiles",
          "  7) Logs",
          "",
        ]

        max_lines = [menu_lines.size, right_buffer.size].max
        (0...max_lines).each do |i|
          l = menu_lines[i] || ''
          r = right_buffer[i] || ''
          print l.ljust(left_w)
          print ' ' * 3
          puts r.ljust(center_w)
        end

        puts "─" * box_width
        sleep 0.55
      end

      puts "\nDemo complete. Press Enter to exit."
      STDIN.gets rescue nil
    end

    # Render a full Rainfrog-inspired layout once (non-interactive preview)
    def self.render_full_layout_once(shell, state = {})
      cols = (TTY::Screen.width rescue 80)
      box_width = [cols, 120].min
      left_w = [24, (box_width * 0.20).floor].max
      center_w = box_width - left_w - 3

      # Top bar
      top = " AWINRM OPERATOR CONSOLE "
      host = state[:host] || (shell && (shell.run('hostname').output.strip rescue 'Unknown')) || 'N/A'
      status = state[:connected] ? 'Connected' : 'Disconnected'
      shell_type = state[:shell] || 'PowerShell'
      ssl = state[:ssl] ? 'OK' : 'UNVERIFIED'

      puts "┌" + "─" * (box_width - 2) + "┐"
      puts "│ " + top.ljust(box_width - 4) + " │"
      meta = "Host: #{host}   Status: #{status}   Shell: #{shell_type}   SSL: #{ssl}"
      puts "│ " + meta.ljust(box_width - 4) + " │"
      puts "└" + "─" * (box_width - 2) + "┘"

      # Main panes header
      puts
      puts "┌" + "─" * (box_width - 2) + "┐"
      left_title = ' MENU (Alt+1) '
      center_title = ' INTERACTIVE CLI (Alt+2) '
      right_title = ' META '
      puts "│" + left_title.ljust(left_w) + ' ' * 3 + center_title.center(center_w) + " │"
      puts "├" + "─" * (box_width - 2) + "┤"

      # Sample left menu + center content
      menu_lines = [
        'Sessions',
        '  Active Sessions',
        '  New Session',
        '  Close Session',
        '',
        'Tools',
        '  Recon',
        '  Credential Access',
        '  Lateral Movement',
        '  Enumeration',
        '  Upload / Download',
        '',
        'Macros',
        '  recon_basic',
        '  recon_full',
        '  dump_creds',
        '  disable_defender',
        '',
        'Profiles',
        '  default.yml',
        '  ctf.yml',
        '  prod.yml',
        '',
        'Settings',
        '  SSL Verification',
        '  Logging',
        '  Shell Adapter',
        '  Paths'
      ]

      center_lines = [
        'PS> whoami',
        (shell && (shell.run('whoami').output.strip rescue '')) || 'WIN-CTF-01\\Administrator',
        '',
        'PS> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
        'OS Name: Microsoft Windows Server 2019 Standard',
        'OS Version: 10.0.17763',
        '',
        'PS> upload_file C:\\Tools\\SharpHound.exe',
        '[██████████░░░░░░░░░░░░░░░] 48%   Chunk 12/25',
        '',
        '[command history]  recon_basic',
        '[streaming output continues below]'
      ]

      max_lines = [menu_lines.size, center_lines.size].max
      (0...max_lines).each do |i|
        l = menu_lines[i] || ''
        c = center_lines[i] || ''
        print '│ '
        print l.ljust(left_w - 2)
        print ' ' * 3
        print c.ljust(center_w)
        puts ' │'
      end

      puts "└" + "─" * (box_width - 2) + "┘"

      # Bottom results pane
      puts
      puts "┌" + "─" * (box_width - 2) + "┐"
      puts "│ RESULTS (Alt+3)".ljust(box_width - 1) + "│"
      puts "├" + "─" * (box_width - 2) + "┤"
      puts "│ Command: recon_basic".ljust(box_width - 1) + "│"
      puts "│ ------------------------------------------------------------".ljust(box_width - 1) + "│"
      puts "│ [+] Hostname: WIN-CTF-01".ljust(box_width - 1) + "│"
      puts "│ [+] Domain: CONTOSO".ljust(box_width - 1) + "│"
      puts "│ [+] Logged-on users: Administrator".ljust(box_width - 1) + "│"
      puts "│ [+] High-value targets: DC01, SQL01".ljust(box_width - 1) + "│"
      puts "│ [+] Defender status: Enabled".ljust(box_width - 1) + "│"
      puts "└" + "─" * (box_width - 2) + "┘"

      # Footer
      footer = "[R] refresh  [j] down  [k] up  [/] search  [g] top  [G] bottom  [F1] Sessions  [F2] CLI  [F3] Results"
      puts footer.center(box_width)
    end

    # Starter interactive Rainfrog-like loop (minimal): left menu navigation + CLI input
    def self.start_rainfrog(shell = nil, options = {})
      begin
        require 'tty-prompt'
        require 'tty-screen'
      rescue LoadError
        puts "TTY gems not installed. Install tty-prompt and tty-screen to enable the TUI.".yellow
        return
      end

      prompt = TTY::Prompt.new
      state = { host: (shell && (shell.run('hostname').output.strip rescue nil)), connected: !!shell, shell: 'PowerShell', ssl: true }
      history = []
      results = []

      loop do
        system('clear') rescue nil
        render_full_layout_once(shell, state)

        # Focus: ask for a command in the CLI pane
        cmd = prompt.ask('PS> ', default: '')
        break if cmd.nil? || cmd.strip.downcase == 'exit'
        next if cmd.strip.empty?

        # Record history and simulate output
        history << cmd
        if cmd.start_with?('upload')
          results << "Uploading: #{cmd.split.last}"
          puts "Uploading... (simulated)"
        else
          # In real use: send to shell.run(cmd) and stream output
          out = (shell && (shell.run(cmd).output rescue '')) || "[simulated output for: #{cmd}]"
          results << "#{cmd} -> #{out.to_s.lines.first.to_s.strip}"
        end

        prompt.keypress('Press any key to continue', keys: [:any])
      end
    end
  end
end
