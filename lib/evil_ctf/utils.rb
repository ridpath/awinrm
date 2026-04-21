# frozen_string_literal: true
module EvilCTF
  module Utils
    # Escape a string for safe inclusion inside a PowerShell single-quoted string
    # e.g. 'O''Reilly' style escaping
    def self.escape_ps_string(str)
      return '' if str.nil?
      str.to_s.gsub("'", "''")
    end
  end
end
