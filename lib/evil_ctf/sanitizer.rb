# frozen_string_literal: true

module EvilCTF
  module Sanitizer
    module_function

    def sanitize_command(command:)
      normalized = command.to_s.encode('UTF-8', invalid: :replace, undef: :replace).tr("\r", '')
      normalized = normalized.gsub("\u0000", '')
      raise ArgumentError, 'command cannot be empty' if normalized.strip.empty?

      # Permit multi-line PowerShell scripts while rejecting control characters
      # that can corrupt local/remote command transport.
      if normalized.match?(/[\u0001-\u0008\u000B\u000C\u000E-\u001F]/)
        raise ArgumentError, 'command contains unsupported control characters'
      end

      normalized
    end

    def escape_argument(argument:)
      value = argument.to_s
      "'#{value.gsub("'", "''")}'"
    end
  end
end
