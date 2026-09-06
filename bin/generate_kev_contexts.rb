#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require 'fileutils'
require 'json'
require 'kevology'

SOURCES_DIR = File.expand_path('../sources', __dir__)
KEV_JSON    = File.join(SOURCES_DIR, 'kev-data/known_exploited_vulnerabilities.json')
CVELIST_DIR = File.join(SOURCES_DIR, 'cvelistV5/cves')
OUTPUT_DIR  = File.expand_path('../json', __dir__)

Kevology.configure do |c|
  c.epss_snapshots_dir     = File.join(SOURCES_DIR, 'epss_scores')
  c.attck_mappings_dir     = Dir.glob(
    File.join(SOURCES_DIR, 'ctid/mappings/kev/attack-*/kev-*')
  ).select { |d| File.directory?(d) }.sort.last
  c.metasploit_modules_dir = File.join(SOURCES_DIR, 'metasploit-framework/modules')
  c.metasploit_cache_file  = File.join(SOURCES_DIR, 'metasploit-commit-dates.json')
  c.nuclei_templates_dir   = File.join(SOURCES_DIR, 'nuclei-templates')
  c.nuclei_cache_file      = File.join(SOURCES_DIR, 'nuclei-commit-dates.json')
  c.nuclei_refactor_map_file = File.join(SOURCES_DIR, 'nuclei-refactor-map.json')
end

FileUtils.mkdir_p(OUTPUT_DIR)

def cve_file_for(cve_id)
  match = cve_id.match(/\ACVE-(\d{4})-\d{4,19}\z/)
  return unless match

  matches = Dir.glob(File.join(CVELIST_DIR, match[1], '*xxx', "#{cve_id}.json"))
  matches.first
end

kev_data  = JSON.parse(File.read(KEV_JSON))
kev_vulns = kev_data['vulnerabilities']

puts "[*] Found #{kev_vulns.size} vulnerabilities in KEV list"

found_count   = 0
missing_count = 0

kev_vulns.each do |vuln|
  cve_data = nil
  cve_id   = vuln['cveID']
  cve_file = cve_file_for(cve_id)

  if cve_file && File.exist?(cve_file)
    cve_data = JSON.parse(File.read(cve_file))
  else
    warn "[!] Missing CVE file for #{cve_id}, most useful data will be missing!"
    missing_count += 1
    cve_file = File.join(CVELIST_DIR, "#{cve_id}.json")
  end

  generator   = Kevology::Generator.new(kev_entry: vuln, cve_filename: cve_file, cve_data: cve_data)
  output_json = generator.generate
  output_path = File.join(OUTPUT_DIR, "#{cve_id}.json")
  File.write(output_path, JSON.pretty_generate(output_json))
  found_count += 1
end

puts "[*] Processed KEV vulnerabilities: #{found_count} found, #{missing_count} missing"
puts "[*] Contextualized KEV JSON files written to #{OUTPUT_DIR}"
