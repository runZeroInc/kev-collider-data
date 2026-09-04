# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Kevology::Configuration do
  subject(:config) { described_class.new }

  describe 'default values' do
    it 'initialises epss_snapshots_dir to nil' do
      expect(config.epss_snapshots_dir).to be_nil
    end

    it 'initialises attck_mappings_dir to nil' do
      expect(config.attck_mappings_dir).to be_nil
    end

    it 'initialises metasploit_modules_dir to nil' do
      expect(config.metasploit_modules_dir).to be_nil
    end

    it 'initialises metasploit_cache_file to nil' do
      expect(config.metasploit_cache_file).to be_nil
    end

    it 'initialises nuclei_templates_dir to nil' do
      expect(config.nuclei_templates_dir).to be_nil
    end

    it 'initialises nuclei_cache_file to nil' do
      expect(config.nuclei_cache_file).to be_nil
    end

    it 'initialises nuclei_refactor_map_file to nil' do
      expect(config.nuclei_refactor_map_file).to be_nil
    end
  end

  describe 'attribute writers' do
    it 'allows setting epss_snapshots_dir' do
      config.epss_snapshots_dir = '/data/epss'
      expect(config.epss_snapshots_dir).to eq('/data/epss')
    end

    it 'allows setting attck_mappings_dir' do
      config.attck_mappings_dir = '/data/ctid'
      expect(config.attck_mappings_dir).to eq('/data/ctid')
    end

    it 'allows setting metasploit_modules_dir' do
      config.metasploit_modules_dir = '/data/msf/modules'
      expect(config.metasploit_modules_dir).to eq('/data/msf/modules')
    end

    it 'allows setting metasploit_cache_file' do
      config.metasploit_cache_file = '/data/msf-cache.json'
      expect(config.metasploit_cache_file).to eq('/data/msf-cache.json')
    end

    it 'allows setting nuclei_templates_dir' do
      config.nuclei_templates_dir = '/data/nuclei'
      expect(config.nuclei_templates_dir).to eq('/data/nuclei')
    end

    it 'allows setting nuclei_cache_file' do
      config.nuclei_cache_file = '/data/nuclei-cache.json'
      expect(config.nuclei_cache_file).to eq('/data/nuclei-cache.json')
    end

    it 'allows setting nuclei_refactor_map_file' do
      config.nuclei_refactor_map_file = '/data/refactor-map.json'
      expect(config.nuclei_refactor_map_file).to eq('/data/refactor-map.json')
    end
  end
end

RSpec.describe Kevology do
  describe '.configure' do
    it 'yields the configuration object' do
      Kevology.configure do |c|
        c.epss_snapshots_dir = '/tmp/epss'
      end
      expect(Kevology.configuration.epss_snapshots_dir).to eq('/tmp/epss')
    end

    it 'returns the configuration for chained calls' do
      Kevology.configure { |c| c.nuclei_templates_dir = '/tmp/nuclei' }
      expect(Kevology.configuration.nuclei_templates_dir).to eq('/tmp/nuclei')
    end
  end

  describe '.configuration' do
    it 'returns a Configuration instance' do
      expect(Kevology.configuration).to be_a(Kevology::Configuration)
    end

    it 'returns the same instance on repeated calls' do
      first  = Kevology.configuration
      second = Kevology.configuration
      expect(first).to equal(second)
    end
  end

  describe '.reset_configuration!' do
    it 'creates a fresh Configuration with nil values' do
      Kevology.configuration.epss_snapshots_dir = '/data/epss'
      Kevology.reset_configuration!
      expect(Kevology.configuration.epss_snapshots_dir).to be_nil
    end

    it 'returns a new object on subsequent .configuration calls' do
      original = Kevology.configuration
      Kevology.reset_configuration!
      expect(Kevology.configuration).not_to equal(original)
    end
  end
end
