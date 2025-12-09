# lib/evil_ctf/crypto.rb
require 'base64'
require 'digest/sha1'

module EvilCTF::Crypto                                                                                                                                                                                                 
  # Default key (can be overridden via options)                                                                                                                                                                        
  DEFAULT_KEY = 0x42                                                                                                                                                                                                   
                                                                                                                                                                                                                       
  def self.xor_crypt(data, key = DEFAULT_KEY)                                                                                                                                                                          
    data.bytes.map { |b| (b ^ key).chr }.join                                                                                                                                                                          
  rescue => e                                                                                                                                                                                                          
    puts "[!] XOR crypt failed: #{e.message}" if ENV['EVC_DEBUG']                                                                                                                                                      
    data                                                                                                                                                                                                               
  end                                                                                                                                                                                                                  
end 
