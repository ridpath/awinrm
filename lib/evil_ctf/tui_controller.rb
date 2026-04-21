# frozen_string_literal: true

require_relative 'app_state'
require_relative '../config/profiles'

module EvilCTF
  class TUI
    class InputHandler
      def hotkey_for(key:, mode:)
        return nil if key.nil?

        return :focus_sidebar if key == :alt_1 || key == "\e1"
        return :focus_cli if key == :alt_2 || key == "\e2"
        return nil if mode == :insert

        return :sessions if key == 'S' || key == 's'
        return :tools if key == 'T' || key == 't'
        return :macros if key == 'M' || key == 'm'
        return :profiles if key == 'P' || key == 'p'
        return :settings if key == 'E' || key == 'e'
        return :upload if key == 'U' || key == 'u' || key == :f5
        return :download if key == 'D' || key == 'd' || key == :f6

        nil
      end
    end

    class SessionManager
      def initialize(app_state:, prompt_factory:)
        @app_state = app_state
        @prompt_factory = prompt_factory
      end

      def select_current_session
        sessions = @app_state.sessions
        return nil if sessions.empty?

        prompt = @prompt_factory.call
        return nil unless prompt

        labels = sessions.map.with_index do |s, idx|
          host = s[:ip] || s[:host] || 'unknown'
          user = s[:user] || 'unknown'
          "#{idx + 1}) #{host} (#{user})"
        end

        selected_label = prompt.select('Active sessions', labels)
        selected_idx = labels.index(selected_label)
        selected = selected_idx ? sessions[selected_idx] : nil
        return nil unless selected

        adapter = selected[:adapter] || selected[:shell] || selected[:session]
        return nil unless adapter

        @app_state.set_current_session(adapter)
        @app_state.set_pane_focus(:cli)
        @app_state.set_mode(:insert)
        selected
      end
    end

    class ToolRegistry
      ALLOWED_EXTENSIONS = %w[.ps1 .psm1 .bat .cmd .exe .rb .sh].freeze

      def initialize(root_path:)
        @root_path = root_path
      end

      def scan
        entries = []
        %w[tools scripts].each do |dir_name|
          dir = File.join(@root_path, dir_name)
          next unless Dir.exist?(dir)

          Dir.glob(File.join(dir, '**', '*')).sort.each do |path|
            next unless File.file?(path)
            ext = File.extname(path).downcase
            next unless ALLOWED_EXTENSIONS.include?(ext)

            rel = path.sub(/^#{Regexp.escape(@root_path)}\//, '')
            entries << {
              name: File.basename(path),
              path: rel,
              source: dir_name.to_sym
            }
          end
        end

        entries.uniq { |entry| entry[:path] }
      end

      def build_command(entry:, args: '')
        path = entry[:path].to_s
        ext = File.extname(path).downcase
        escaped_path = path.gsub('/', '\\\\')
        suffix = args.to_s.strip

        command = case ext
                  when '.ps1', '.psm1'
                    "powershell -ExecutionPolicy Bypass -File \"#{escaped_path}\""
                  when '.bat', '.cmd', '.exe'
                    "\"#{escaped_path}\""
                  when '.rb'
                    "ruby \"#{path}\""
                  when '.sh'
                    "bash \"#{path}\""
                  else
                    path
                  end

        suffix.empty? ? command : "#{command} #{suffix}"
      end
    end

    class SettingsManager
      THEMES = %w[default matrix stealth].freeze

      def initialize(app_state:, prompt_factory:)
        @app_state = app_state
        @prompt_factory = prompt_factory
      end

      def open
        prompt = @prompt_factory.call
        return nil unless prompt

        selection = prompt.select('Settings', [
          'Toggle Logging',
          'Change Theme',
          'Adjust Scrollback Limit'
        ])

        case selection
        when 'Toggle Logging'
          @app_state.toggle_setting(:logging_enabled)
          { type: :toggle_logging, value: @app_state.settings[:logging_enabled] }
        when 'Change Theme'
          theme = prompt.select('Theme', THEMES)
          @app_state.set_setting(:theme, theme)
          { type: :theme, value: theme }
        when 'Adjust Scrollback Limit'
          current = @app_state.settings[:scrollback_limit].to_i
          value = prompt.ask('Scrollback limit', default: current.to_s)
          limit = [value.to_i, 50].max
          @app_state.set_setting(:scrollback_limit, limit)
          { type: :scrollback_limit, value: limit }
        else
          nil
        end
      end
    end

    class Controller
      attr_reader :tool_registry

      def initialize(app_state:, command_queue:, transfer_callback:, root_path:, prompt_factory:)
        @app_state = app_state
        @command_queue = command_queue
        @transfer_callback = transfer_callback
        @prompt_factory = prompt_factory
        @root_path = root_path

        @input_handler = InputHandler.new
        @session_manager = SessionManager.new(app_state: app_state, prompt_factory: prompt_factory)
        @tool_registry = ToolRegistry.new(root_path: root_path)
        @settings_manager = SettingsManager.new(app_state: app_state, prompt_factory: prompt_factory)
      end

      def handle_key(key:, current_shell:)
        action = @input_handler.hotkey_for(key: key, mode: @app_state.mode)
        return false unless action

        case action
        when :focus_sidebar
          @app_state.set_pane_focus(:sidebar)
          @app_state.set_mode(:NORMAL)
        when :focus_cli
          @app_state.set_pane_focus(:cli)
          @app_state.set_mode(:insert)
        when :sessions
          selected = @session_manager.select_current_session
          if selected
            label = selected[:ip] || selected[:host] || 'unknown'
            @app_state.append_stream("[+] Switched session to #{label}")
          else
            @app_state.append_stream('[!] No selectable sessions')
          end
        when :tools
          launch_tool(current_shell: current_shell)
        when :macros
          launch_macro(current_shell: current_shell)
        when :profiles
          select_profile
        when :settings
          apply_settings
        when :upload
          enqueue_transfer(direction: :upload, shell: current_shell)
        when :download
          enqueue_transfer(direction: :download, shell: current_shell)
        end

        true
      end

      private

      def launch_tool(current_shell:)
        return @app_state.append_stream('[!] No active shell for tool execution') unless current_shell

        entries = @tool_registry.scan
        return @app_state.append_stream('[!] No tools found in tools/ or scripts/') if entries.empty?

        prompt = @prompt_factory.call
        return unless prompt

        labels = entries.map { |entry| "#{entry[:name]} (#{entry[:source]})" }
        selected_label = prompt.select('Tool registry', labels)
        selected_idx = labels.index(selected_label)
        selected = selected_idx ? entries[selected_idx] : nil
        return unless selected

        args = prompt.ask('Arguments (optional)', default: '')
        command = @tool_registry.build_command(entry: selected, args: args)
        @command_queue << { shell: current_shell, cmd: command }
        @app_state.append_stream("[+] Queued tool: #{selected[:name]}")
      end

      def launch_macro(current_shell:)
        return @app_state.append_stream('[!] No active shell for macro execution') unless current_shell

        macros = {
          'recon_basic' => 'whoami /all; hostname; systeminfo',
          'quick_process_check' => 'Get-Process | Select-Object -First 20 Name,Id',
          'network_snapshot' => 'ipconfig /all; netstat -ano'
        }

        prompt = @prompt_factory.call
        return unless prompt

        selected = prompt.select('Macros', macros.keys)
        command = macros[selected]
        return unless command

        @command_queue << { shell: current_shell, cmd: command }
        @app_state.append_stream("[+] Queued macro: #{selected}")
      end

      def select_profile
        names = EvilCTF::Config::Profiles.profile_names(root_path: @root_path)
        return @app_state.append_stream('[!] No profiles found') if names.empty?

        prompt = @prompt_factory.call
        return unless prompt

        selected = prompt.select('Profiles', names)
        profile = EvilCTF::Config::Profiles.load_profile(name: selected, root_path: @root_path)
        if profile
          @app_state.set_pending_connection(profile)
          @app_state.append_stream("[+] Loaded profile '#{selected}' for next session")
        else
          @app_state.append_stream("[!] Failed to load profile '#{selected}'")
        end
      end

      def apply_settings
        result = @settings_manager.open
        return unless result

        case result[:type]
        when :toggle_logging
          state = result[:value] ? 'enabled' : 'disabled'
          @app_state.append_stream("[+] Logging #{state}")
        when :theme
          @app_state.append_stream("[+] Theme set to #{result[:value]}")
        when :scrollback_limit
          @app_state.append_stream("[+] Scrollback limit set to #{result[:value]}")
        end
      end

      def enqueue_transfer(direction:, shell:)
        unless shell
          @app_state.append_stream("[!] No active shell for #{direction}")
          return
        end

        Thread.new do
          begin
            @transfer_callback.call(direction: direction, shell: shell)
          rescue StandardError => e
            @app_state.append_stream("[!] #{direction} failed: #{e.class}: #{e.message}")
          end
        end
      end
    end
  end
end
