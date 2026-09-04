# frozen_string_literal: true

# lib/kevology/metasploit_index.rb

require 'json'
require 'open3'

module Kevology
  class MetasploitIndex
    # Matches arrays like ['CVE', '2025-12345']
    CVE_REF_REGEX = /
      \[\s*
        ['"]CVE['"]
        \s*,\s*
        ['"](\d{4}-\d{4,19})['"]
      \s*\]
    /x.freeze

    # Matches {'type': 'cve', 'ref': '2020-16139'}
    PY_CVE_REF_REGEX = /
      ['"]type['"]\s*:\s*['"]cve['"]\s*,\s*
      ['"]ref['"]\s*:\s*
      ['"](\d{4}-\d{4,19})['"]
    /ix.freeze

    # @param root [String, nil] Root of the Metasploit modules/ tree.
    #   Defaults to {Kevology.configuration#metasploit_modules_dir}.
    # @param cache_file [String, nil] Path to the JSON commit-date cache.
    #   Defaults to {Kevology.configuration#metasploit_cache_file}.
    # @param debug [Boolean] Print per-file discovery lines to stdout.
    def initialize(root: nil, cache_file: nil, debug: true)
      @new_cache_entries = 0
      @root       = root       || Kevology.configuration.metasploit_modules_dir
      @cache_file = cache_file || Kevology.configuration.metasploit_cache_file
      @debug      = debug
      @index      = Hash.new { |h, k| h[k] = [] }
      @commit_cache = load_commit_cache
      build_index
      persist_commit_cache
    end

    def modules_for(cve_id)
      @index[cve_id] || []
    end

    def index
      @index
    end

    private

    #
    # Index build
    #
    def build_index
      return unless @root && Dir.exist?(@root)

      Dir.glob(File.join(@root, '**', '*.py')).each do |path|
        scan_python_file(path)
      end

      Dir.glob(File.join(@root, '**', '*.rb')).each do |path|
        scan_ruby_file(path)
      end

      @index.each_value do |mods|
        mods.uniq!
        mods.sort_by! { |m| m[:module] }
      end
    end

    def scan_file_with_regex(path:, cve_regex:, precheck:, error_label:)
      content = File.read(path)
      return unless precheck.call(content)

      module_relative = path.sub(@root + '/', '')
      git_relative    = File.join('modules', module_relative)

      commit_date, fresh = first_commit_date(git_relative)

      content.scan(cve_regex) do |match|
        cve = "CVE-#{match.first}"
        debug_print(module_relative, cve, commit_date) if fresh

        @index[cve] << {
          module: module_relative,
          firstCommitDate: commit_date
        }
      end
    rescue => e
      warn "Metasploit #{error_label} scan error in #{path}: #{e.message}"
    end

    def scan_ruby_file(path)
      scan_file_with_regex(
        path:        path,
        cve_regex:   CVE_REF_REGEX,
        precheck:    ->(c) { c.include?("'CVE'") || c.include?('"CVE"') },
        error_label: 'Ruby'
      )
    end

    def scan_python_file(path)
      scan_file_with_regex(
        path:        path,
        cve_regex:   PY_CVE_REF_REGEX,
        precheck:    ->(c) { c.match?(/['"]type['"]\s*:\s*['"]cve['"]/i) },
        error_label: 'Python'
      )
    end

    #
    # Git commit date cache
    #
    def load_commit_cache
      return {} unless @cache_file && File.exist?(@cache_file)
      JSON.parse(File.read(@cache_file))
    rescue
      {}
    end

    def persist_commit_cache
      return unless @cache_file
      File.write(
        @cache_file,
        JSON.pretty_generate(@commit_cache.sort.to_h)
      )
    rescue => e
      warn "Failed to write Metasploit commit cache: #{e.message}"
    end

    def first_commit_date(git_relative_path)
      return @commit_cache[git_relative_path], false if @commit_cache.key?(git_relative_path)

      out, = Open3.capture3(
        'git', 'log', '--follow', '--reverse', '--format=%aI', '--', git_relative_path,
        chdir: metasploit_repo_root
      )
      @commit_cache[git_relative_path] =
        out.lines.first ? Time.parse(out.lines.first.strip).utc.iso8601(3) : nil

      @new_cache_entries += 1
      persist_commit_cache if (@commit_cache.size % 5).zero?

      return @commit_cache[git_relative_path], true
    rescue => e
      warn "Git history error for #{git_relative_path}: #{e.message}"
      @commit_cache[git_relative_path] = nil
      return nil, true
    end

    def metasploit_repo_root
      @metasploit_repo_root ||= File.expand_path('..', @root)
    end

    #
    # Debug
    #
    def debug_print(path, cve, date)
      return unless @debug
      puts "[msf] [#{cve}] #{path} : #{date || 'no git history'}"
    end
  end
end
