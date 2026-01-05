require_relative 'spec_helper'
require_relative '../lib/evil_ctf/tools/crypto'
require_relative '../lib/evil_ctf/errors'

RSpec.describe EvilCTF::Tools::Crypto do
  describe '.xor_crypt' do
    it 'xors and returns binary string and is reversible' do
      data = "hello\x00\xFF"
      key = 0x42
      enc = described_class.xor_crypt(data, key)
      expect(enc).to be_a(String)
      dec = described_class.xor_crypt(enc, key)
      expect(dec).to eq(data)
    end

    it 'raises CryptoError on invalid input' do
      expect { described_class.xor_crypt(nil, 0x42) }.to raise_error(EvilCTF::Errors::CryptoError)
    end
  end
end
