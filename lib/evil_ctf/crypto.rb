# lib/evil_ctf/crypto.rb
module EvilCTF::Crypto
  def self.xor_crypt(data, key = 0x42)
    data.bytes.map { |b| (b ^ key).chr }.join
  rescue => e
    puts "[!] XOR crypt failed: #{e.message}"
    data
  end
end
