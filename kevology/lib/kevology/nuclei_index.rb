# frozen_string_literal: true

# lib/kevology/nuclei_index.rb

require 'yaml'
require 'json'
require 'time'
require 'open3'

module Kevology
  class NucleiIndex
    CVE_ID_REGEX = /^CVE-\d{4}-\d{4,19}$/i.freeze
    MAX_TEMPLATE_BYTES = 1_000_000

    EXCLUDED_DIRS = %w[
      workflows
    ].freeze

    # This comes from commit e0af666e1c54c621695317076d6af2ff81d83c24
    # See: https://github.com/projectdiscovery/nuclei-templates/commit/e0af666e1c54c621695317076d6af2ff81d83c24
    REFACTOR_COMMIT_TIMESTAMP = Time.utc(2023, 4, 27, 4, 28, 59).iso8601(3)

    # @param root [String, nil] Root of the Nuclei templates repository.
    #   Defaults to {Kevology.configuration#nuclei_templates_dir}.
    # @param cache_file [String, nil] Path to the JSON commit-date cache.
    #   Defaults to {Kevology.configuration#nuclei_cache_file}.
    # @param refactor_map_file [String, nil] Path to the JSON refactor-map file.
    #   Defaults to {Kevology.configuration#nuclei_refactor_map_file}.
    # @param debug [Boolean] Print per-template discovery lines to stdout.
    def initialize(root: nil, cache_file: nil, refactor_map_file: nil, debug: true)
      @root             = root             || Kevology.configuration.nuclei_templates_dir
      @cache_file       = cache_file       || Kevology.configuration.nuclei_cache_file
      @refactor_map_file = refactor_map_file || Kevology.configuration.nuclei_refactor_map_file
      @debug            = debug
      @index            = Hash.new { |h, k| h[k] = [] }
      @commit_cache     = load_commit_cache
      @new_cache_entries = 0
      @seen_yaml_files  = {}
      @refactor_map     = load_refactor_map
      build_index
      persist_commit_cache
    end

    def templates_for(cve_id)
      @index[cve_id] || []
    end

    def index
      @index
    end

    private

    def build_index
      return unless @root && Dir.exist?(@root)

      Dir.glob(File.join(@root, '**', '*.yaml')).each do |path|
        next if excluded_path?(path)
        scan_template(path)
      end

      @index.each_value do |templates|
        templates.uniq!
        templates.sort_by! { |t| t[:template] }
      end
    end

    def excluded_path?(path)
      relative = path.sub(@root + '/', '')
      EXCLUDED_DIRS.any? { |dir| relative.start_with?(dir + '/') }
    end

    def scan_template(path)
      doc = safe_yaml_load(path)
      return unless doc.is_a?(Hash)

      cve_ids = extract_cve_ids(doc)
      return if cve_ids.empty?

      template_relative = path.sub(@root + '/', '')
      git_relative      = template_relative

      commit_date, fresh = first_commit_date(git_relative)

      cve_ids.each do |cve|
        debug_print(template_relative, cve, commit_date) if fresh

        @index[cve] << {
          template: template_relative,
          firstCommitDate: commit_date
        }
      end
    rescue => e
      warn "Nuclei template scan error in #{path}: #{e.message}"
    end

    def extract_cve_ids(doc)
      raw = doc.dig('info', 'classification', 'cve-id')

      Array(raw)
        .map(&:to_s)
        .map(&:upcase)
        .select { |v| v.match?(CVE_ID_REGEX) }
        .uniq
    end

    #
    # YAML parsing
    #
    def safe_yaml_load(path)
      @yaml_count ||= 0
      @yaml_count += 1
      return if @seen_yaml_files[path]
      @seen_yaml_files[path] = true

      return unless acceptable_template_file?(path)

      content = File.read(path)

      # Guard against files that don't mention a CVE ID
      return unless content.include?('cve-id')

      YAML.safe_load(
        content,
        permitted_classes: [],
        permitted_symbols: [],
        aliases: false
      )
    rescue Psych::Exception => e
      warn "[nuclei] YAML error in #{path}: #{e.message}"
      nil
    end

    def acceptable_template_file?(path)
      stat = File.lstat(path)
      return false unless stat.file?

      if stat.size > MAX_TEMPLATE_BYTES
        warn "[nuclei] Template file too large, skipping: #{path}"
        return false
      end

      true
    rescue SystemCallError => e
      warn "[nuclei] Template stat error in #{path}: #{e.message}"
      false
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

    def load_refactor_map
      return {} unless @refactor_map_file && File.exist?(@refactor_map_file)
      JSON.parse(File.read(@refactor_map_file))
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
      warn "Failed to write Nuclei commit cache: #{e.message}"
    end

    def refactored_timestamp(git_relative_path, ts)
      return ts unless ts == REFACTOR_COMMIT_TIMESTAMP
      return ts unless @refactor_map

      old_path = @refactor_map[git_relative_path]
      return ts unless old_path

      out, = Open3.capture3(
        'git', 'log', '--follow', '--reverse', '--format=%aI', '--', old_path,
        chdir: nuclei_repo_root
      )
      raw = out.lines.first
      return ts unless raw

      Time.parse(raw.strip).utc.iso8601(3)
    rescue
      ts
    end

    def first_commit_date(git_relative_path)
      return @commit_cache[git_relative_path], false if @commit_cache.key?(git_relative_path)

      out, = Open3.capture3(
        'git', 'log', '--follow', '--reverse', '--format=%aI', '--', git_relative_path,
        chdir: nuclei_repo_root
      )
      raw = out.lines.first
      ts  = raw ? Time.parse(raw.strip).utc.iso8601(3) : nil
      @commit_cache[git_relative_path] = ts ? refactored_timestamp(git_relative_path, ts) : nil

      @new_cache_entries += 1
      persist_commit_cache if (@commit_cache.size % 5).zero?

      return @commit_cache[git_relative_path], true
    rescue => e
      warn "Git history error for #{git_relative_path}: #{e.message}"
      @commit_cache[git_relative_path] = nil
      return nil, true
    end

    def nuclei_repo_root
      @nuclei_repo_root ||= @root
    end

    #
    # Debug
    #
    def debug_print(path, cve, date)
      return unless @debug
      puts "[nuclei] [#{cve}] #{path} : #{date || 'no git history'}"
    end
  end
end
