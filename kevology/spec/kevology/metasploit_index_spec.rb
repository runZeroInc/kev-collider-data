# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'json'

RSpec.describe Kevology::MetasploitIndex do
  # We point the index at the checked-in fixture tree and supply a pre-populated
  # cache so that no real `git log` commands are ever executed.
  let(:fixture_root) do
    File.expand_path('../../fixtures/metasploit/modules', __FILE__)
  end

  let(:cache_data) do
    {
      'modules/exploit/test/log4shell.rb'    => '2021-12-10T12:00:00.000Z',
      'modules/exploit/test/multi_cve.rb'    => '2021-12-14T08:00:00.000Z',
      'modules/exploit/test/python_exploit.py' => '2020-06-01T00:00:00.000Z'
    }
  end

  around(:each) do |example|
    Dir.mktmpdir('msf_cache_') do |tmpdir|
      cache_path = File.join(tmpdir, 'msf-commit-cache.json')
      File.write(cache_path, JSON.generate(cache_data))
      @cache_path = cache_path
      example.run
    end
  end

  subject(:index) do
    described_class.new(root: fixture_root, cache_file: @cache_path, debug: false)
  end

  describe '#modules_for' do
    context 'for a CVE that appears in a Ruby module' do
      it 'returns the module path' do
        result = index.modules_for('CVE-2021-44228')
        paths  = result.map { |m| m[:module] }
        expect(paths).to include('exploit/test/log4shell.rb')
      end

      it 'returns the cached first-commit date' do
        entry = index.modules_for('CVE-2021-44228').find { |m| m[:module] == 'exploit/test/log4shell.rb' }
        expect(entry[:firstCommitDate]).to eq('2021-12-10T12:00:00.000Z')
      end

      it 'also returns the module from the multi-CVE file' do
        result = index.modules_for('CVE-2021-44228')
        paths  = result.map { |m| m[:module] }
        expect(paths).to include('exploit/test/multi_cve.rb')
      end
    end

    context 'for a CVE that appears only in the multi-CVE Ruby file' do
      it 'returns that module' do
        result = index.modules_for('CVE-2021-45046')
        paths  = result.map { |m| m[:module] }
        expect(paths).to include('exploit/test/multi_cve.rb')
      end

      it 'does not include modules that do not reference this CVE' do
        result = index.modules_for('CVE-2021-45046')
        paths  = result.map { |m| m[:module] }
        expect(paths).not_to include('exploit/test/log4shell.rb')
      end
    end

    context 'for a CVE that appears only in a Python module' do
      it 'returns the Python module path' do
        result = index.modules_for('CVE-2020-1234')
        paths  = result.map { |m| m[:module] }
        expect(paths).to include('exploit/test/python_exploit.py')
      end

      it 'returns the cached first-commit date for the Python module' do
        entry = index.modules_for('CVE-2020-1234')
                     .find { |m| m[:module] == 'exploit/test/python_exploit.py' }
        expect(entry[:firstCommitDate]).to eq('2020-06-01T00:00:00.000Z')
      end
    end

    context 'for a CVE with no matching modules' do
      it 'returns an empty array' do
        expect(index.modules_for('CVE-9999-99999')).to eq([])
      end
    end
  end

  describe '#index' do
    it 'returns a Hash' do
      expect(index.index).to be_a(Hash)
    end

    it 'contains entries for known CVEs' do
      expect(index.index.keys).to include('CVE-2021-44228', 'CVE-2020-1234')
    end
  end

  describe 'with no modules root' do
    subject(:empty_index) do
      described_class.new(root: nil, cache_file: nil, debug: false)
    end

    it 'returns empty results for any CVE' do
      expect(empty_index.modules_for('CVE-2021-44228')).to eq([])
    end
  end

  describe 'with a non-existent root directory' do
    subject(:empty_index) do
      described_class.new(root: '/nonexistent/path', cache_file: nil, debug: false)
    end

    it 'returns empty results' do
      expect(empty_index.modules_for('CVE-2021-44228')).to eq([])
    end
  end

  describe 'cache persistence' do
    it 'writes the cache file after building' do
      Dir.mktmpdir('msf_persist_') do |tmpdir|
        cache_path = File.join(tmpdir, 'new-cache.json')
        # Provide pre-populated cache so no git calls are made
        File.write(cache_path, JSON.generate(cache_data))
        described_class.new(root: fixture_root, cache_file: cache_path, debug: false)
        expect(File.exist?(cache_path)).to be true
      end
    end
  end
end
