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
        choice = prompt.select('EvilCTF TUI Prototype', ['Show Banner', 'Run Flag Scan', 'Exit'])
        case choice
        when 'Show Banner'
          begin
            EvilCTF::Banner.show_minimal_banner(shell, options)
          rescue => e
            puts "(TUI) Unable to render banner: #{e.message}"
          end
        when 'Run Flag Scan'
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
  end
end
