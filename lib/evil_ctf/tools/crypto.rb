# frozen_string_literal: true
module EvilCTF
  module Tools
    module Crypto
      DEFAULT_KEY = 0x42

      # Binary-safe XOR obfuscation. Returns binary string.
      def self.xor_crypt(data, key = DEFAULT_KEY)
        bytes = data.is_a?(String) ? data.bytes : Array(data)
        out = bytes.map { |b| b ^ (key & 0xFF) }
        out.pack('C*')
      rescue => e
        raise ::EvilCTF::Errors::CryptoError, e.message
      end
    end
  end
end
