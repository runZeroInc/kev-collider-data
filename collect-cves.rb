#!/usr/bin/env ruby

require 'json'
require 'pathname'
require 'fileutils'
require 'date'
require 'stringio'

# Config
KEV_JSON      = File.expand_path("sources/kev-data/known_exploited_vulnerabilities.json", __dir__)
CVELIST_DIR   = File.expand_path("sources/cvelistV5/cves", __dir__)
OUTPUT_DIR    = File.expand_path("cves-original", __dir__)

FileUtils.mkdir_p(OUTPUT_DIR)

# --- Load KEV CVEs ---
kev_data = JSON.parse(File.read(KEV_JSON))
kev_cves = kev_data["vulnerabilities"].map { |v| v["cveID"] }

puts "[*] Loaded #{kev_cves.size} CVEs from KEV"

found_count   = 0
missing_count = 0
found_cves = []

kev_cves.each do |cve|
  year, _id = cve.match(/CVE-(\d+)-(\d+)/).captures
  pattern = File.join(CVELIST_DIR, year, "*xxx", "#{cve}.json")
  matches = Dir.glob(pattern)

  if matches.empty?
    puts "[!] Missing: #{cve}"
    missing_count += 1
    next
  end

  src = matches.first
  dst = File.join(OUTPUT_DIR, "#{cve}.json")
  FileUtils.cp(src, dst)
  found_count += 1
  found_cves << cve
end

puts "[*] CVEs sought: #{kev_cves.size}"
puts "[*] CVEs found:  #{found_count}"
puts "[*] Missing:     #{missing_count}"
