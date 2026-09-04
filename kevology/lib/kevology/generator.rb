# frozen_string_literal: true

require 'time'
require 'json'
require 'holidays'
require 'cvss_suite'
require 'cvss_to_31'
require 'zlib'
require 'csv'

module Kevology
  class Generator
    SCHEMA_VERSION = "1.1.0-dev"
    SCHEMA_PATH    = File.join(__dir__, "schema-v#{SCHEMA_VERSION}.json")

    # Returns the bundled JSON schema (lazy-loaded).
    def self.schema
      @schema ||= JSON.parse(File.read(SCHEMA_PATH))
    end

    # Resets all memoized class-level indexes. Call after reconfiguring.
    def self.reset_indexes!
      @attck_index       = nil
      @metasploit_index  = nil
      @nuclei_index      = nil
      @epss_index        = nil
    end

    # CTID / ATT&CK preload
    def self.attck_index
      @attck_index ||= load_attck_index
    end

    def self.metasploit_index
      @metasploit_index ||= MetasploitIndex.new(
        root:       Kevology.configuration.metasploit_modules_dir,
        cache_file: Kevology.configuration.metasploit_cache_file
      )
    end

    def self.nuclei_index
      @nuclei_index ||= NucleiIndex.new(
        root:              Kevology.configuration.nuclei_templates_dir,
        cache_file:        Kevology.configuration.nuclei_cache_file,
        refactor_map_file: Kevology.configuration.nuclei_refactor_map_file
      )
    end

    def self.epss_index
      @epss_index ||= load_epss_index
    end

    def self.parse_epss_snapshot(path)
      data = {}

      Zlib::GzipReader.open(path) do |gz|
        lines = gz.each_line.reject { |l| l.start_with?('#') }.join
        csv   = CSV.new(StringIO.new(lines), headers: true)

        csv.each do |row|
          cve  = row['cve']
          next unless cve

          epss = row['epss']&.to_f
          pct  = row['percentile']&.to_f
          next if epss.nil? || pct.nil?

          data[cve] = {
            score:      epss,
            percentile: pct
          }
        end
      end

      data
    end

    def self.build_epss_variant_index(snapshots)
      return {} if snapshots.empty?

      today_file     = snapshots[-1]
      yesterday_file = snapshots[-2]

      today_scores     = parse_epss_snapshot(today_file)
      yesterday_scores = yesterday_file ? parse_epss_snapshot(yesterday_file) : {}

      index = {}

      today_scores.each do |cve, today|
        entry = {
          'todayScore'      => today[:score],
          'todayPercentile' => today[:percentile]
        }

        if yesterday_scores[cve]
          y = yesterday_scores[cve]
          entry.merge!(
            'yesterdayScore'      => y[:score],
            'yesterdayPercentile' => y[:percentile],
            'deltaScore'          => (today[:score] - y[:score]).round(5),
            'deltaPercentile'     => (today[:percentile] - y[:percentile]).round(5)
          )
        end

        index[cve] = entry
      end

      index
    end

    def self.load_epss_index
      base = Kevology.configuration.epss_snapshots_dir
      return {} unless base

      snapshots = Dir.glob(File.join(base, '*', 'epss_scores-*.csv.gz')).sort
      index     = build_epss_variant_index(snapshots)

      beta_snapshots = Dir.glob(File.join(base, 'beta_scores', 'epssv5_beta-*.csv.gz')).sort
      beta_index     = build_epss_variant_index(beta_snapshots)

      beta_index.each do |cve, beta_scores|
        next unless index[cve]
        index[cve]['beta'] = beta_scores
      end

      index
    end

    def self.load_attck_index
      base = Kevology.configuration.attck_mappings_dir
      return {} unless base

      files = {
        'enterprise' => File.join(base, 'enterprise'),
        'mobile'     => File.join(base, 'mobile')
      }

      index = Hash.new { |h, k| h[k] = {} }

      files.each do |domain, dir|
        next unless Dir.exist?(dir)

        Dir.glob(File.join(dir, '*.json')).each do |path|
          data     = JSON.parse(File.read(path))
          mappings = data['mapping_objects'] || []

          mappings.each do |m|
            cve = m['capability_id']
            next unless cve

            entry = {
              'mappingType'     => m['mapping_type'],
              'id'              => m['attack_object_id'],
              'name'            => m['attack_object_name'],
              'capabilityGroup' => m['capability_group'],
              'source'          => "CTID-#{m['mapping_framework_version']}"
            }

            index[cve][domain] ||= []
            index[cve][domain] << entry
          end
        end
      end

      index.each_value do |domains|
        domains.each_value(&:uniq!)
      end

      index
    end

    #
    # Initialization
    #
    def initialize(kev_entry:, cve_filename:, cve_data:)
      raise "Schema file not found: #{SCHEMA_PATH}" unless File.exist?(SCHEMA_PATH)

      @kev_entry    = kev_entry
      @cve_filename = cve_filename
      @cve_data     = cve_data
      @cve_id       = cve_filename[/CVE-\d+-\d+/]
      @json         = {}
    end

    #
    # Generation
    #
    def generate
      create_cve_container
      create_cve_assertions_container
      create_cve_metadata_container
      create_kev_container
      self.class.private_instance_methods(false).grep(/^set_/).each { |m| send(m) }
      @json.sort.to_h
    end

    def cve_data?
      @cve_data.is_a?(Hash) && !@cve_data.empty?
    end

    private

    #
    # Top-level fields
    #
    def set_schema_version
      @json['schemaVersion'] = SCHEMA_VERSION
    end

    def set_date_generated
      @json['dateGenerated'] = Time.now.utc.iso8601(3)
    end

    def set_cve_id
      @json['cveID'] = @cve_id
    end

    def set_cve_data_present
      @json['cveDataPresent'] = cve_data?
    end

    #
    # KEV container
    #
    def create_kev_container
      @json['kev'] ||= {}
    end

    #
    # KEV-derived fields
    #
    def kev_cwes
      @kev_entry['cwes'].compact.uniq
    end

    def set_kev_cwes
      @json['kev']['cwes'] = kev_cwes unless kev_cwes.empty?
    end

    def set_vendor_project
      @json['kev']['vendorProject'] = (@kev_entry['vendorProject'] || 'unknown').strip
    end

    def set_product
      @json['kev']['product'] = (@kev_entry['product'] || 'unknown').strip
    end

    def set_vulnerability_name
      vuln_name = (@kev_entry['vulnerabilityName'] || 'unknown').strip
      vuln_name = vuln_name.sub(/\s+Vulnerability\z/, '')
      @json['kev']['vulnerabilityName'] = vuln_name
    end

    def set_date_added
      @json['kev']['dateAdded'] = @kev_entry['dateAdded']
    end

    def set_date_due
      @json['kev']['dateDue'] = @kev_entry['dueDate']
    end

    def set_days_allotted
      added = Date.parse(@kev_entry['dateAdded'])
      due   = Date.parse(@kev_entry['dueDate'])
      @json['kev']['daysAllotted'] = (due - added).to_i
    end

    def set_day_added
      @json['kev']['dayAdded'] = Time.parse(@kev_entry['dateAdded']).strftime("%A")
    end

    def set_holiday_added
      added   = Date.parse(@kev_entry['dateAdded'])
      holiday = Holidays.on(added, :us, :observed)
      @json['kev']['holidayAdded'] = holiday.first[:name] unless holiday.empty?
    end

    def set_ransomware
      ransom = @kev_entry['knownRansomwareCampaignUse']
      @json['kev']['ransomware'] = ransom.to_s.downcase.strip == 'known'
    end

    #
    # CVE containers
    #
    def create_cve_container
      return unless cve_data?
      @json['cve'] ||= {}
    end

    def create_cve_metadata_container
      return unless cve_data?
      @json['cve']['metadata'] ||= {}
    end

    def create_cve_assertions_container
      return unless cve_data?
      @json['cve']['assertions'] ||= {}
    end

    #
    # CVE metadata
    #
    def set_cve_assigning_cna
      return unless cve_data?
      @json['cve']['metadata']['assigningCNA'] =
        @cve_data.dig('containers', 'cna', 'providerMetadata', 'shortName')
    end

    def set_cve_date_published
      return unless cve_data?
      @json['cve']['metadata']['datePublished'] =
        @cve_data.dig('cveMetadata', 'datePublished')
    end

    def set_cve_date_updated
      return unless cve_data?
      @json['cve']['metadata']['dateUpdated'] =
        @cve_data.dig('cveMetadata', 'dateUpdated')
    end

    #
    # CWE logic
    #
    def cve_cna_cwes
      problem_types = @cve_data.dig('containers', 'cna', 'problemTypes') || []
      problem_types.flat_map { |pt|
        Array(pt['descriptions']).map { |d| d['cweId'] }
      }.compact.uniq
    end

    def cve_adp_cwes
      adps = Array(@cve_data.dig('containers', 'adp'))
      adps.select { |c| c.dig('providerMetadata', 'shortName') == 'CISA-ADP' }
          .flat_map { |c|
            Array(c['problemTypes']).flat_map { |pt|
              Array(pt['descriptions']).map { |d| d['cweId'] }
            }
          }.compact.uniq
    end

    def set_cve_cwes
      return unless cve_data?
      cwes = cve_cna_cwes
      cwes = cve_adp_cwes if cwes.empty?
      @json['cve']['assertions']['cwes'] = cwes unless cwes.empty?
    end

    #
    # CVSS
    #
    def find_cvss_vectors(obj, path = [], results = {})
      case obj
      when Hash
        obj.each { |k, v| find_cvss_vectors(v, path + [k], results) }
      when Array
        obj.each_with_index { |v, i| find_cvss_vectors(v, path + ["[#{i}]"], results) }
      when String
        results[path.join('.').gsub('.[', '[')] = obj if obj.match?(/^CVSS:[34]/)
      end
      results
    end

    def validate_cvss_vectors(vectors = {})
      vectors.transform_values { |v| CvssSuite.new(v) }.select { |_, v| v.valid? }
    end

    def select_cvss(validated_cvss = {})
      return {} if validated_cvss.empty?

      cna_cvss, adp_cvss = validated_cvss.partition { |path, _| path.include?('containers.cna') }

      candidates =
        if cna_cvss.any?
          cna_cvss
        else
          adp_cvss.select do |path, _|
            if path =~ /containers\.adp\[(\d+)\]/
              adp_idx       = Regexp.last_match(1).to_i
              adp_container = @cve_data.dig('containers', 'adp', adp_idx)
              adp_container&.dig('providerMetadata', 'shortName') == 'CISA-ADP'
            else
              false
            end
          end
        end

      return {} if candidates.empty?

      preferred_versions = %w[3.1 3.0 4.0]
      selected_version   = preferred_versions.find { |ver|
        candidates.any? { |_, cvss| cvss.version.to_s == ver }
      }
      candidates = candidates.select { |_, cvss| cvss.version.to_s == selected_version }

      candidates.sort_by! { |_, cvss| -(cvss.respond_to?(:base_score) ? cvss.base_score : cvss.score) }

      path, cvss = candidates.first
      { path => cvss }
    end

    def recast_cvss_to_3_1(entry)
      return {} if entry.empty?
      path, cvss = entry.first
      version = cvss.version.to_s
      recasted = case version
        when "3.1", "3.0", "4.0"
          @json['cve']['assertions']['cvssOriginalVersion'] = version
          CvssTo31.convert(cvss)
        else
          cvss
        end
      { path => recasted }
    end

    def insert_cvss_json(recasted_cvss = {})
      return if recasted_cvss.empty?
      key, cvss_obj = recasted_cvss.first
      @json['cve']['assertions']['cvssSource'] = case key
        when /^containers\.cna/ then "CNA"
        when /^containers\.adp/ then "CISA"
        else "unknown"
      end
      base = cvss_obj.base
      @json['cve']['assertions']['cvss'] = {
        version:               "3.1",
        attackVector:          base.attack_vector.selected_value[:name].upcase,
        attackComplexity:      base.attack_complexity.selected_value[:name].upcase,
        privilegesRequired:    base.privileges_required.selected_value[:name].upcase,
        scope:                 base.scope.selected_value[:name].upcase,
        userInteraction:       base.user_interaction.selected_value[:name].upcase,
        confidentialityImpact: base.confidentiality.selected_value[:name].upcase,
        integrityImpact:       base.integrity.selected_value[:name].upcase,
        availabilityImpact:    base.availability.selected_value[:name].upcase,
        vectorString:          cvss_obj.vector,
        baseScore:             cvss_obj.base_score,
        baseSeverity:          cvss_obj.severity.upcase
      }
    end

    def set_cve_cvss
      return unless cve_data?
      cvss_vectors    = find_cvss_vectors(@cve_data)
      validated_cvss  = validate_cvss_vectors(cvss_vectors)
      selected_cvss   = select_cvss(validated_cvss)
      recasted_cvss   = recast_cvss_to_3_1(selected_cvss)
      insert_cvss_json(recasted_cvss)
    end

    #
    # EPSS
    #
    def set_epss
      return unless cve_data?
      epss_scores = self.class.epss_index[@cve_id]
      return unless epss_scores
      @json['epss'] = epss_scores
    end

    #
    # SSVC
    #
    def cisa_adp_ssvc_content
      adp_containers = Array(@cve_data.dig('containers', 'adp'))
      cisa_adp       = adp_containers.find { |c| c.dig('providerMetadata', 'shortName') == "CISA-ADP" }
      return unless cisa_adp

      ssvc_metric = cisa_adp['metrics']&.find { |m| m.dig('other', 'type') == 'ssvc' }
      return unless ssvc_metric

      content = ssvc_metric['other']['content']
      return unless content['version'] == '2.0.3'

      content
    end

    def normalize_ssvc_options(options_array)
      return {} unless options_array.is_a?(Array)
      options_array.each_with_object({}) do |entry, h|
        entry.each do |k, v|
          camel_key  = k.gsub(/\s+/, '').sub(/\A./) { |c| c.downcase }
          h[camel_key] = v.to_s.downcase
        end
      end
    end

    def set_ssvc
      return unless cve_data?
      content = cisa_adp_ssvc_content
      return unless content
      @json['cve']['assertions']['ssvc'] = {
        'timestamp' => content['timestamp'][0, 10],
        'version'   => content['version'],
        'role'      => content['role'],
        'options'   => normalize_ssvc_options(content['options'])
      }
    end

    #
    # ATT&CK data from CTID
    #
    def attck_for_cve
      self.class.attck_index[@cve_id]
    end

    def set_attck
      attck = attck_for_cve
      return unless attck && !attck.empty?
      @json['attck'] = attck
    end

    #
    # Metasploit modules
    #
    def build_metasploit_modules
      modules = self.class.metasploit_index.modules_for(@cve_id)
      return if modules.empty?

      @json['metasploit'] ||= {}
      @json['metasploit']['modules'] =
        modules.sort_by { |m| [m[:firstCommitDate] || "", m[:module]] }
    end

    def add_metasploit_delta_from_kev
      return unless @json.dig('metasploit', 'modules')

      kev_date = Date.parse(@kev_entry['dateAdded'])

      @json['metasploit']['modules'].each do |m|
        next unless m[:firstCommitDate]
        commit_date = Date.parse(m[:firstCommitDate]) rescue nil
        next unless commit_date

        m[:deltaFromKev] = (commit_date - kev_date).to_i
      end
    end

    def add_metasploit_delta_from_cve
      return unless cve_data?
      return unless @json.dig('metasploit', 'modules')

      published = @cve_data.dig('cveMetadata', 'datePublished')
      return unless published

      cve_date = Date.parse(published) rescue nil
      return unless cve_date

      @json['metasploit']['modules'].each do |m|
        next unless m[:firstCommitDate]
        commit_date = Date.parse(m[:firstCommitDate]) rescue nil
        next unless commit_date

        m[:deltaFromCve] = (commit_date - cve_date).to_i
      end
    end

    def set_metasploit_modules
      build_metasploit_modules
      add_metasploit_delta_from_cve
      add_metasploit_delta_from_kev
    end

    #
    # Nuclei templates
    #
    def build_nuclei_templates
      templates = self.class.nuclei_index.templates_for(@cve_id)
      return if templates.empty?

      @json['nuclei'] ||= {}
      @json['nuclei']['templates'] =
        templates.sort_by { |t| [t[:firstCommitDate] || "", t[:template]] }
    end

    def add_nuclei_delta_from_kev
      return unless @json.dig('nuclei', 'templates')

      kev_date = Date.parse(@kev_entry['dateAdded'])

      @json['nuclei']['templates'].each do |t|
        next unless t[:firstCommitDate]
        commit_date = Date.parse(t[:firstCommitDate]) rescue nil
        next unless commit_date

        t[:deltaFromKev] = (commit_date - kev_date).to_i
      end
    end

    def add_nuclei_delta_from_cve
      return unless cve_data?
      return unless @json.dig('nuclei', 'templates')

      published = @cve_data.dig('cveMetadata', 'datePublished')
      return unless published

      cve_date = Date.parse(published) rescue nil
      return unless cve_date

      @json['nuclei']['templates'].each do |t|
        next unless t[:firstCommitDate]
        commit_date = Date.parse(t[:firstCommitDate]) rescue nil
        next unless commit_date

        t[:deltaFromCve] = (commit_date - cve_date).to_i
      end
    end

    def set_nuclei_templates
      build_nuclei_templates
      add_nuclei_delta_from_cve
      add_nuclei_delta_from_kev
    end
  end
end
