# Compatibility shim: redirect legacy EvilCTF::Crypto calls to EvilCTF::Tools::Crypto
require_relative 'tools/crypto'
module EvilCTF
  module Crypto
    DEFAULT_KEY = EvilCTF::Tools::Crypto::DEFAULT_KEY

    def self.xor_crypt(data, key = DEFAULT_KEY)
      warn '[!] Deprecated: EvilCTF::Crypto is deprecated; use EvilCTF::Tools::Crypto' if ENV['EVC_DEBUG']
      EvilCTF::Tools::Crypto.xor_crypt(data, key)
    end
  end
end
