# frozen_string_literal: true
module EvilCTF
  module Tools
    module Crypto
      DEFAULT_KEY = 0x42

      # Binary-safe XOR obfuscation. Returns binary string.
      def self.xor_crypt(data, key = DEFAULT_KEY)
        raise ::EvilCTF::Errors::CryptoError, 'data must be a String or bytes' if data.nil?
        bytes = data.is_a?(String) ? data.bytes : Array(data)
        out = bytes.map { |b| b ^ (key & 0xFF) }
        s = out.pack('C*')
        # preserve encoding for String inputs
        s.force_encoding(data.encoding) if data.is_a?(String)
        s
      rescue => e
        raise ::EvilCTF::Errors::CryptoError, e.message
      end
    end
  end
end
