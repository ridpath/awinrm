# frozen_string_literal: true

module EvilCTF
  module Tools
    module AliasEngine
      def build_aliases
        {
          'ls' => 'Get-ChildItem',
          'dir' => 'Get-ChildItem',
          'whoami' => '$env:USERNAME',
          'pwd' => 'Get-Location',
          'cd' => 'Set-Location',
          'ps' => 'Get-Process',
          'processes' => 'Get-Process',
          'sysinfo' => 'systeminfo',
          'services' => 'Get-Service',
          'rm' => 'Remove-Item',
          'cat' => 'Get-Content',
          'mkdir' => 'New-Item -ItemType Directory',
          'cp' => 'Copy-Item',
          'mv' => 'Move-Item'
        }
      end

      def expand_alias(cmd)
        stripped = cmd.to_s.lstrip
        return cmd if stripped.empty?

        token, remainder = stripped.split(/\s+/, 2)
        alias_expansion = @aliases[token]
        return cmd unless alias_expansion

        expanded = remainder && !remainder.empty? ? "#{alias_expansion} #{remainder}" : alias_expansion

        leading_ws_len = cmd.length - stripped.length
        (' ' * leading_ws_len) + expanded
      end

      def validate_alias_name(name)
        alias_name = name.to_s.strip
        expansion = @aliases[alias_name]
        if expansion
          {
            name: alias_name,
            ok: true,
            expansion: expansion,
            error: nil
          }
        else
          {
            name: alias_name,
            ok: false,
            expansion: nil,
            error: "Unknown alias: #{alias_name}"
          }
        end
      end

      def validate_alias_command(cmd)
        raw = cmd.to_s
        expanded = expand_alias(raw)
        stripped = raw.lstrip
        token = stripped.split(/\s+/, 2).first.to_s
        known = @aliases.key?(token)

        {
          input: raw,
          ok: known,
          alias: token,
          expanded: expanded,
          error: known ? nil : "Unknown alias: #{token}"
        }
      end

      def validate_aliases(names: nil)
        selected = if names.nil? || names.empty?
                     list_aliases
                   else
                     names.map(&:to_s)
                   end

        results = selected.map { |alias_name| validate_alias_name(alias_name) }
        {
          ok: results.all? { |result| result[:ok] },
          total: results.length,
          passed: results.count { |result| result[:ok] },
          failed: results.count { |result| !result[:ok] },
          results: results
        }
      end

      def list_aliases
        @aliases.keys.sort
      end
    end
  end
end
