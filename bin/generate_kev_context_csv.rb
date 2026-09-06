#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require 'json'
require 'csv'
require 'date'

KEV_CONTEXT_DIR = File.expand_path('../json', __dir__)

# Output CSV path
output_csv = File.join(KEV_CONTEXT_DIR, 'kev_flat.csv')

# CSV headers
headers = [
  'cve_id',
  'schema_version',
  'date_generated',

  'kev_vulnerability_name',
  'kev_date_added',
  'kev_day_added',
  'kev_date_due',
  'kev_days_allotted',
  'kev_short_deadline',
  'kev_ransomware',

  'cvss_version',
  'cvss_attack_vector',
  'cvss_attack_complexity',
  'cvss_privileges_required',
  'cvss_scope',
  'cvss_user_interaction',
  'cvss_confidentiality_impact',
  'cvss_integrity_impact',
  'cvss_availability_impact',
  'cvss_vector_string',
  'cvss_base_score',
  'cvss_base_severity',

  'ssvc_exploitation',
  'ssvc_automatable',
  'ssvc_technical_impact',

  'epss_today',
  'epss_percentile',
  'epss_delta',

  'attck_technique_count',
  'attck_capability_groups',

  'has_metasploit',
  'metasploit_module_count',
  'min_metasploit_delta',

  'has_nuclei',
  'nuclei_template_count',
  'min_nuclei_delta'
]

CSV.open(output_csv, 'w', write_headers: true, headers: headers) do |csv|
  Dir.glob("#{KEV_CONTEXT_DIR}/*.json").each do |file|
    begin
      data = JSON.parse(File.read(file))
    rescue JSON::ParserError => e
      warn "[!] Skipping #{file}: #{e.message}"
      next
    end

    kev = data['kev']
    cve = data['cve'] || {}
    assertions = cve.dig('assertions') || {}
    cvss = assertions['cvss'] || {}
    ssvc = assertions.dig('ssvc', 'options') || {}
    epss = data['epss'] || {}

    metasploit = data.dig('metasploit', 'modules') || []
    nuclei = data.dig('nuclei', 'templates') || []

    attck = data.dig('attck', 'enterprise') || []

    csv << [
      data['cveID'],
      data['schemaVersion'],
      data['dateGenerated'],

      kev['vulnerabilityName'],
      kev['dateAdded'],
      kev['dayAdded'],
      kev['dateDue'],
      kev['daysAllotted'],
      kev['daysAllotted'] && kev['daysAllotted'] < 21,
      kev['ransomware'],

      cvss['version'],
      cvss['attackVector'],
      cvss['attackComplexity'],
      cvss['privilegesRequired'],
      cvss['scope'],
      cvss['userInteraction'],
      cvss['confidentialityImpact'],
      cvss['integrityImpact'],
      cvss['availabilityImpact'],
      cvss['vectorString'],
      cvss['baseScore'],
      cvss['baseSeverity'],

      ssvc['exploitation'],
      ssvc['automatable'],
      ssvc['technicalImpact'],

      epss['todayScore'],
      epss['todayPercentile'],
      epss['deltaScore'],

      attck.size,
      attck.map { |t| t['capabilityGroup'] }.uniq.join('|'),

      # Metasploit
      !metasploit.empty?,
      metasploit.size,
      metasploit.map { |m| m['deltaFromKev'] }.min,

      # Nuclei
      !nuclei.empty?,
      nuclei.size,
      nuclei.map { |t| t['deltaFromKev'] }.min
    ]
  end
end

puts "[*] CSV generation complete: #{output_csv}"
