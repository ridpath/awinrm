# frozen_string_literal: true

module EvilCTF
  module Session
    module RuntimeSetup
      module_function

      def prepare(shell:, session_options:, history:, logger:, orig_ip:)
        configure_shell(shell)

        heartbeat = start_heartbeat(shell, session_options)

        puts "[+] Connected to #{orig_ip}"
        show_banner(shell, session_options)

        EvilCTF::Session.setup_autocomplete(history)
        prompt_cache = detect_prompt(shell)

        if session_options[:tui]
          launch_tui(shell, session_options)
          return { heartbeat: heartbeat, prompt_cache: prompt_cache, tui_exited: true }
        end

        run_enum_preset(shell, session_options, logger)

        { heartbeat: heartbeat, prompt_cache: prompt_cache, tui_exited: false }
      end

      def configure_shell(shell)
        shell.run(%q{
          function prompt { "PS $pwd> " }
          Set-Alias __exit__ Exit-PSSession
        })
      end

      def start_heartbeat(shell, session_options)
        return nil unless session_options[:tui] || session_options[:enable_heartbeat]

        heartbeat = EvilCTF::SessionHeartbeat.new(
          shell: shell,
          interval_seconds: 30,
          on_update: lambda { |status|
            session_options[:session_status] = status
          }
        )
        heartbeat.start
        heartbeat
      end

      def show_banner(shell, session_options)
        banner_mode = session_options[:banner_mode] || :minimal
        if EvilCTF::Banner.respond_to?(:show_banner)
          EvilCTF::Banner.show_banner(shell, session_options, mode: banner_mode, no_color: false)
        else
          EvilCTF::Banner.show_banner_with_flagscan(shell, session_options)
        end
      end

      def detect_prompt(shell)
        prompt_cache = '> '
        begin
          prompt_probe = EvilCTF::Execution.run(shell, 'prompt', timeout: 2)
          if prompt_probe.ok && prompt_probe.output && !prompt_probe.output.to_s.empty?
            prompt_cache = EvilCTF::Session.normalize_readline_prompt(prompt_probe.output)
          end
        rescue StandardError
          nil
        end
        prompt_cache
      end

      def launch_tui(shell, session_options)
        begin
          puts '[*] Launching TUI...'
          EvilCTF::TUI.start_rainfrog(shell, session_options)
        rescue StandardError => e
          puts "[!] Failed to start TUI: #{e.class}: #{e.message}"
        ensure
          EvilCTF::ShellWrapper.exit_session(shell) if defined?(EvilCTF::ShellWrapper.exit_session)
          shell.close if shell
        end
      end

      def run_enum_preset(shell, session_options, logger)
        return unless session_options[:enum]

        enum_cache = {}
        puts "[*] Running enumeration preset: #{session_options[:enum]}"
        case session_options[:enum]
        when 'deep'
          EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
        when 'dom'
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          EvilCTF::Execution.run(shell, "IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)", timeout: 60)
        when 'sql'
          EvilCTF::SQLEnum.run_sql_enum(shell)
        else
          EvilCTF::Enums.run_enumeration(shell, type: session_options[:enum], cache: enum_cache,
                                         fresh: session_options[:fresh])
        end
      end
    end
  end
end
