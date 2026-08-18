# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'
require_relative '../lib/evil_ctf/tools/loot_store'

RSpec.describe EvilCTF::Tools::LootStore do
  # save_loot writes to ./loot relative to the working directory;
  # run every example inside a throwaway tmpdir.
  around do |example|
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) { example.run }
    end
  end

  describe '.save_loot' do
    it 'appends plain-text matches to loot.txt' do
      described_class.save_loot(['flag {test123}', 'user:pass:dom'])
      content = File.read('loot/loot.txt')
      expect(content).to include('flag {test123}')
      expect(content).to include('user:pass:dom')
    end

    it 'stores JSON matches in creds.json and dedupes them' do
      entry = '{"user": "admin", "hash": "AAD3B435B51404EE"}'
      described_class.save_loot([entry, 'note line'])
      described_class.save_loot([entry]) # duplicate
      stored = JSON.parse(File.read('loot/creds.json'))
      expect(stored).to eq([entry])
    end

    it 'ignores empty input' do
      described_class.save_loot([])
      expect(Dir.exist?('loot')).to be false
    end

    it 'does not lose JSON updates under concurrent callers' do
      threads = 8
      per_thread = 25
      workers = Array.new(threads) do |t|
        Thread.new do
          per_thread.times do |i|
            described_class.save_loot(["{\"user\": \"user#{t}-#{i}\", \"hash\": \"AB#{t}#{i}\"}"])
          end
        end
      end
      workers.each(&:join)

      stored = JSON.parse(File.read('loot/creds.json'))
      expect(stored.size).to eq(threads * per_thread)
      expect(stored.uniq.size).to eq(stored.size)
    end
  end
end
