# lib/evil_ctf/crypto.rb
require 'base64'
require 'digest/sha1'

module EvilCTF::Crypto
  def self.xor_crypt(data, key = 0x42)
    data.bytes.map { |b| (b ^ key).chr }.join
  rescue => e
    puts "[!] XOR crypt failed: #{e.message}" if ENV['EVC_DEBUG']
    data
  end
end
