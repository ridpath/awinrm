# frozen_string_literal: true
module EvilCTF
  class CommandManager
    def initialize(macros: nil, aliases: nil)
      @aliases = aliases || default_aliases
      @macros = macros || default_macros
    end

    def expand_alias(cmd)
      @aliases.each do |k, v|
        return cmd.sub(/^#{Regexp.escape(k)}(\b|$)/, v) if cmd.start_with?(k)
      end
      cmd
    end

    def expand_macro(name, shell, context: {})
      macro = @macros[name.downcase]
      return false unless macro
      macro.each do |step|
        begin
          res = shell.run(step)
          puts res.output if res && res.respond_to?(:output)
        rescue => e
          puts "[!] Macro step failed: #{e.message}"
        end
      end
      true
    end

    def list_macros; @macros.keys.sort end
    def list_aliases; @aliases.keys.sort end

    private
    def default_aliases
      {
        'ls' => 'Get-ChildItem',
        'pwd' => 'Get-Location',
        'whoami' => '$env:USERNAME'
      }
    end

    def default_macros
      {
        'dump_creds' => [ 'echo DUMP_CREDS_PLACEHOLDER' ]
      }
    end
  end
end
