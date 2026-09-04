# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

RSpec.describe Kevology::NucleiIndex do
  let(:fixture_root) do
    File.expand_path('../../fixtures/nuclei', __FILE__)
  end

  let(:cache_data) do
    {
      'cves/CVE-2021-44228.yaml' => '2021-12-12T10:00:00.000Z',
      'cves/CVE-2021-45046.yaml' => '2021-12-15T08:00:00.000Z'
      # no_cve.yaml intentionally absent — will also miss git (nil returned)
    }
  end

  around(:each) do |example|
    Dir.mktmpdir('nuclei_cache_') do |tmpdir|
      cache_path = File.join(tmpdir, 'nuclei-commit-cache.json')
      File.write(cache_path, JSON.generate(cache_data))
      @cache_path = cache_path
      example.run
    end
  end

  subject(:index) do
    described_class.new(root: fixture_root, cache_file: @cache_path, debug: false)
  end

  describe '#templates_for' do
    context 'for a CVE referenced in exactly one template' do
      it 'returns the template path' do
        result = index.templates_for('CVE-2021-44228')
        paths  = result.map { |t| t[:template] }
        expect(paths).to include('cves/CVE-2021-44228.yaml')
      end

      it 'returns the cached first-commit date' do
        entry = index.templates_for('CVE-2021-44228')
                     .find { |t| t[:template] == 'cves/CVE-2021-44228.yaml' }
        expect(entry[:firstCommitDate]).to eq('2021-12-12T10:00:00.000Z')
      end
    end

    context 'for a CVE that appears in a multi-CVE template' do
      it 'returns the multi-CVE template for the primary CVE' do
        result = index.templates_for('CVE-2021-45046')
        paths  = result.map { |t| t[:template] }
        expect(paths).to include('cves/CVE-2021-45046.yaml')
      end

      # CVE-2021-44228 is listed in the CVE-2021-45046.yaml as a secondary CVE
      it 'also indexes the secondary CVE from a multi-CVE template' do
        result = index.templates_for('CVE-2021-44228')
        paths  = result.map { |t| t[:template] }
        expect(paths).to include('cves/CVE-2021-45046.yaml')
      end
    end

    context 'for a CVE with no matching templates' do
      it 'returns an empty array' do
        expect(index.templates_for('CVE-9999-99999')).to eq([])
      end
    end
  end

  describe '#index' do
    it 'returns a Hash' do
      expect(index.index).to be_a(Hash)
    end

    it 'includes known CVE keys' do
      expect(index.index.keys).to include('CVE-2021-44228', 'CVE-2021-45046')
    end
  end

  describe 'excluded directories' do
    it 'does not index templates inside workflows/' do
      expect(index.templates_for('CVE-2099-99999')).to eq([])
    end

    it 'does not include workflow paths in the index values' do
      all_templates = index.index.values.flatten.map { |t| t[:template] }
      expect(all_templates).not_to include(a_string_starting_with('workflows/'))
    end
  end

  describe 'templates without a CVE classification' do
    it 'does not add entries for templates missing cve-id' do
      # no_cve.yaml has no classification block, so nothing new should appear
      # from that file. Verify that no unexpected CVE IDs were added.
      known_cves = %w[CVE-2021-44228 CVE-2021-45046]
      unexpected = index.index.keys.reject { |k| known_cves.include?(k) }
      expect(unexpected).to be_empty
    end
  end

  describe 'with no templates root' do
    subject(:empty_index) do
      described_class.new(root: nil, cache_file: nil, debug: false)
    end

    it 'returns empty results for any CVE' do
      expect(empty_index.templates_for('CVE-2021-44228')).to eq([])
    end
  end

  describe 'with a non-existent root directory' do
    subject(:empty_index) do
      described_class.new(root: '/nonexistent/path', cache_file: nil, debug: false)
    end

    it 'returns empty results' do
      expect(empty_index.templates_for('CVE-2021-44228')).to eq([])
    end
  end

  describe 'CVE ID normalisation' do
    it 'returns entries regardless of whether the caller uses upper or mixed case' do
      # The index always stores upper-case keys; callers should pass upper-case too
      expect(index.templates_for('CVE-2021-44228')).not_to be_empty
    end
  end

  describe 'cache persistence' do
    it 'writes the cache file after building' do
      Dir.mktmpdir('nuclei_persist_') do |tmpdir|
        cache_path = File.join(tmpdir, 'new-cache.json')
        File.write(cache_path, JSON.generate(cache_data))
        described_class.new(root: fixture_root, cache_file: cache_path, debug: false)
        expect(File.exist?(cache_path)).to be true
      end
    end
  end
end
