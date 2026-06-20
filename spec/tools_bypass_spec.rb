# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/evil_ctf/tools'

RSpec.describe EvilCTF::Tools do
  describe 'TOOL_REGISTRY' do
    let(:registry) { EvilCTF::Tools::TOOL_REGISTRY }

    it 'is frozen' do
      expect(registry).to be_frozen
    end

    it 'contains expected tools' do
      %w[sharphound mimikatz powerview rubeus seatbelt inveigh procdump winpeas
         invoke_mimikatz nishang socksproxy plink edr_redir].each do |key|
        expect(registry).to have_key(key), "Missing tool: #{key}"
      end
    end

    it 'each tool has required fields' do
      registry.each do |key, entry|
        expect(entry[:name]).to be_a(String), "#{key}: missing name"
        expect(entry[:filename]).to be_a(String), "#{key}: missing filename"
        expect(entry[:description]).to be_a(String), "#{key}: missing description"
        expect(entry[:download_url]).to be_a(String), "#{key}: missing download_url"
        expect(entry[:recommended_remote]).to be_a(String), "#{key}: missing recommended_remote"
        expect(%w[recon privilege pivot]).to include(entry[:category]),
                                             "#{key}: invalid category '#{entry[:category]}'"
      end
    end

    it 'zip tools have zip_pick fields' do
      %w[mimikatz edr_redir].each do |key|
        expect(registry[key][:zip]).to eq(true), "#{key} should be a zip tool"
        expect(registry[key]).to have_key(:zip_pick_x64),
                                 "#{key}: missing zip_pick_x64"
      end
    end

    it 'nishang zip tool uses zip_pick (not zip_pick_x64)' do
      entry = registry['nishang']
      expect(entry[:zip]).to eq(true)
      expect(entry).to have_key(:zip_pick)
      expect(entry[:zip_pick]).to eq('nishang-master')
    end

    it 'non-zip tools have zip: false' do
      %w[sharphound powerview rubeus seatbelt inveigh procdump winpeas
         invoke_mimikatz socksproxy plink].each do |key|
        expect(registry[key][:zip]).to eq(false), "#{key} should have zip: false"
      end
    end

    it 'all tools have backup_urls as an array' do
      registry.each do |key, entry|
        expect(entry[:backup_urls]).to be_an(Array), "#{key}: missing backup_urls"
      end
    end

    it 'all tools have search_patterns array' do
      registry.each do |key, entry|
        expect(entry[:search_patterns]).to be_an(Array), "#{key}: missing search_patterns"
        expect(entry[:search_patterns]).not_to be_empty, "#{key}: empty search_patterns"
      end
    end

    it 'each tool has auto_execute: false' do
      registry.each do |key, entry|
        expect(entry[:auto_execute]).to eq(false), "#{key}: auto_execute should be false"
      end
    end
  end

  describe 'BYPASS_4MSI_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Tools::BYPASS_4MSI_PS).to be_a(String)
      expect(EvilCTF::Tools::BYPASS_4MSI_PS.length).to be > 100
    end

    it 'contains key PowerShell bypass elements' do
      ps = EvilCTF::Tools::BYPASS_4MSI_PS
      expect(ps).to include('AmsiScanBuffer')
      expect(ps).to include('VirtualProtect')
      expect(ps).to include('kernel32')
      expect(ps).to include('LoadLibrary')
    end

    it 'has error handling' do
      expect(EvilCTF::Tools::BYPASS_4MSI_PS).to include('catch')
      expect(EvilCTF::Tools::BYPASS_4MSI_PS).to include('try')
    end
  end

  describe 'ETW_BYPASS_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Tools::ETW_BYPASS_PS).to be_a(String)
      expect(EvilCTF::Tools::ETW_BYPASS_PS.length).to be > 50
    end

    it 'contains ETW patching elements' do
      ps = EvilCTF::Tools::ETW_BYPASS_PS
      expect(ps).to include('EtwEventWrite')
      expect(ps).to include('ntdll')
      expect(ps).to include('xor')
    end
  end

  describe 'BYPASS_DETECTION_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Tools::BYPASS_DETECTION_PS).to be_a(String)
      expect(EvilCTF::Tools::BYPASS_DETECTION_PS.length).to be > 50
    end

    it 'contains Windows version detection' do
      expect(EvilCTF::Tools::BYPASS_DETECTION_PS).to include('Windows')
      expect(EvilCTF::Tools::BYPASS_DETECTION_PS).to include('Build')
    end
  end

  describe 'BYPASS_VERIFICATION_PS' do
    it 'is a non-empty string' do
      expect(EvilCTF::Tools::BYPASS_VERIFICATION_PS).to be_a(String)
      expect(EvilCTF::Tools::BYPASS_VERIFICATION_PS.length).to be > 50
    end

    it 'contains AMSI verification logic' do
      expect(EvilCTF::Tools::BYPASS_VERIFICATION_PS).to include('AmsiUtils')
      expect(EvilCTF::Tools::BYPASS_VERIFICATION_PS).to include('ScanString')
    end
  end

  describe 'macro/alias constants' do
    it 'NISHANG_REV_REMOTE points to expected path' do
      expect(EvilCTF::Tools::NISHANG_REV_REMOTE).to include('Invoke-PowerShellTcp.ps1')
    end

    it 'DOM_ENUM_PS is a non-empty PowerShell script' do
      expect(EvilCTF::Tools::DOM_ENUM_PS).to be_a(String)
      expect(EvilCTF::Tools::DOM_ENUM_PS.length).to be > 50
      expect(EvilCTF::Tools::DOM_ENUM_PS).to include('Get-Domain')
    end
  end

  describe 'CommandManager' do
    subject(:manager) { EvilCTF::Tools::CommandManager.new }

    it 'lists macros' do
      macros = manager.list_macros
      expect(macros).to be_an(Array)
      expect(macros).not_to be_empty
      expect(macros).to include('kerberoast', 'dump_creds', 'sharphound_all')
    end

    it 'lists aliases' do
      aliases = manager.list_aliases
      expect(aliases).to be_an(Array)
      expect(aliases).not_to be_empty
    end
  end

  describe '.list_available_tools' do
    it 'outputs tool names and descriptions' do
      expect(EvilCTF::Tools::CatalogRenderer).to receive(:list_available_tools)
      EvilCTF::Tools.list_available_tools
    end
  end

  describe '.download_missing_tools' do
    it 'delegates to Downloader' do
      expect(EvilCTF::Tools::Downloader).to receive(:download_missing_tools)
      EvilCTF::Tools.download_missing_tools
    end
  end

  describe '.load_config_profile' do
    it 'returns empty hash for missing profile' do
      result = EvilCTF::Tools.load_config_profile('nonexistent_profile_xyz')
      expect(result).to eq({})
    end
  end
end
