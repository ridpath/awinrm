# frozen_string_literal: true

module EvilCTF
  module Tools
    module LootScanner
      PATTERNS = [
        /flag\{[^\}]+\}/i,
        /htb\{[^\}]+\}/i,
        /picoctf\{[^\}]+\}/i,
        /ctf\{[^\}]+\}/i,
        /password\s*[:=]\s*["']?([^"'\s]+)["']?/i,
        /Password\s*[:=]\s*["']?([^"'\s]+)["']?/i,
        /pwd\s*[:=]\s*["']?([^"'\s]+)["']?/i,
        /token\s*[:=]\s*["']?([^"'\s]+)["']?/i,
        /Token\s*[:=]\s*["']?([^"'\s]+)["']?/i,
        /[A-Fa-f0-9]{32}/,
        /[A-Fa-f0-9]{40}/,
        /[A-Fa-f0-9]{64}/,
        /[A-Fa-f0-9]{128}/,
        /[A-Za-z0-9+\/]{20,}={0,2}/,
        /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/,
        /-----BEGIN [A-Z ]+-----/,
        /-----END [A-Z ]+-----/,
        /jwt\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/i,
        /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/i,
        /(\w+@\w+\.\w+):([^@\s]+)/,
        /Username\s*:\s*(\S+)\s+Password\s*:\s*(\S+)/i,
        /User\s*:\s*(\S+)\s+Pass\s*:\s*(\S+)/i,
        /NTLM\s*:\s*([A-F0-9]{32})/i,
        /LM\s*:\s*([A-F0-9]{32})/i,
        /Hash\s*:\s*([A-F0-9]{32})/i,
        /AKIA[0-9A-Z]{16}/,
        /aws_secret_access_key\s*=\s*["']?([^"'\s]+)["']?/i,
        /ssh-rsa AAAA[0-9A-Za-z+\/]+[=]{0,3}/,
        /-----BEGIN PRIVATE KEY-----/,
        /sk-[a-zA-Z0-9]{48}/,
        /ghp_[0-9A-Za-z]{36}/,
        /AIza[0-9A-Za-z\-_]{35}/,
        /ya29\.[0-9A-Za-z\-_]+/,
        /xoxp-[0-9A-Za-z\-]+/,
        /Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/,
        /azure_client_secret\s*=\s*["']?([^"'\s]+)["']?/i,
        /DB_PASSWORD\s*=\s*["']?([^"'\s]+)["']?/i,
        /PRIVATE-TOKEN:\s*[0-9a-zA-Z\-_]{20,}/,
        /npm_token\s*=\s*[0-9a-f-]{36}/i
      ].freeze

      ERROR_INDICATORS = [
        'ObjectNotFound',
        'CommandNotFoundException',
        'FileNotFoundException',
        'ResourceUnavailable',
        'Modules_ModuleNotFound',
        'CategoryInfo',
        'FullyQualifiedErrorId',
        'is not recognized'
      ].freeze

      module_function

      def grep_output(output)
        return [] if output.nil? || output.empty?

        if output.include?('execution policy') || output.include?('SecurityError')
          puts '[!] PowerShell execution policy issue detected'
          return []
        end

        matches = []
        error_count = ERROR_INDICATORS.count { |error| output.include?(error) }
        total_lines = output.lines.count
        error_ratio = error_count.to_f / total_lines
        if error_ratio > 0.3
          puts '[*] Skipping loot scan - output appears to be mostly errors'
          return matches
        end

        output.each_line do |line|
          next if line.include?('CategoryInfo') || line.include?('FullyQualifiedErrorId') || line.include?('is not recognized')

          PATTERNS.each do |regex|
            line.scan(regex).each do |match|
              if match.is_a?(Array)
                cleaned_match = match.compact.join(':')
                matches << cleaned_match unless cleaned_match.empty?
              else
                matches << match.strip
              end
            end
          end
        end

        matches.uniq
      end
    end
  end
end
