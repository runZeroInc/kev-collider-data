#!/usr/bin/env ruby
require 'net/http'
require 'uri'
require 'openssl'
require 'csv'
require 'daru'

# Step 0: Build Daru data frame.
require 'json'
require 'csv'
require 'date'
require 'daru'

json_files = Dir.glob("./kev-context/*.json")

records = json_files.map do |file|
  data = JSON.parse(File.read(file)) rescue next
  kev = data['kev'] || {}
  cve = data['cve'] || {}
  assertions = cve.dig('assertions') || {}
  cvss = assertions['cvss'] || {}
  ssvc = assertions.dig('ssvc','options') || {}
  epss = data['epss'] || {}
  metasploit = data.dig('metasploit','modules') || []
  nuclei = data.dig('nuclei','templates') || []
  attck = data.dig('attck','enterprise') || []

  date_generated = begin
    DateTime.parse(data['dateGenerated']) if data['dateGenerated']
  rescue
    nil
  end

  kev_date_added = begin
    Date.parse(kev['dateAdded']) if kev['dateAdded']
  rescue
    nil
  end

  kev_date_due = begin
    Date.parse(kev['dateDue']) if kev['dateDue']
  rescue
    nil
  end

  {
    # Top-level metadata
    cve_id: data['cveID'],
    schema_version: data['schemaVersion'],
    date_generated: date_generated,
    cve_data_present: data['cveDataPresent'],

    # KEV fields
    kev_vulnerability_name: kev['vulnerabilityName'],
    kev_vendor_project: kev['vendorProject'],
    kev_date_added: kev_date_added,
    kev_day_added: kev['dayAdded'],
    kev_date_due: kev_date_due,
    kev_days_allotted: kev['daysAllotted'],
    kev_short_deadline: kev['daysAllotted'] && kev['daysAllotted'] < 21,
    kev_ransomware: kev['ransomware'],
    kev_holiday: kev['holidayAdded'],

    # CVSS fields
    cvss_version: cvss['version'],
    cvss_attack_vector: cvss['attackVector'],
    cvss_attack_complexity: cvss['attackComplexity'],
    cvss_privileges_required: cvss['privilegesRequired'],
    cvss_scope: cvss['scope'],
    cvss_user_interaction: cvss['userInteraction'],
    cvss_confidentiality_impact: cvss['confidentialityImpact'],
    cvss_integrity_impact: cvss['integrityImpact'],
    cvss_availability_impact: cvss['availabilityImpact'],
    cvss_vector_string: cvss['vectorString'],
    cvss_base_score: cvss['baseScore'],
    cvss_base_severity: cvss['baseSeverity'],

    # CWE fields
    kev_cwes: (kev['cwes'] || []).join('|'),
    cve_cwes: (cve['cwes'] || []).join('|'),

    # SSVC fields
    ssvc_exploitation: ssvc['exploitation'],
    ssvc_automatable: ssvc['automatable'],
    ssvc_technical_impact: ssvc['technicalImpact'],

    # EPSS fields
    epss_today: epss['todayScore'],
    epss_percentile: epss['todayPercentile'],
    epss_delta: epss['deltaScore'],

    # ATT&CK
    attck_technique_count: attck.size,
    attck_capability_groups: attck.map { |t| t['capabilityGroup'] }.uniq.join('|'),

    # Metasploit
    has_metasploit: !metasploit.empty?,
    metasploit_module_count: metasploit.size,
    min_metasploit_delta: metasploit.map { |m| m['deltaFromKev'] }.compact.min,

    # Nuclei
    has_nuclei: !nuclei.empty?,
    nuclei_template_count: nuclei.size,
    min_nuclei_delta: nuclei.map { |t| t['deltaFromKev'] }.compact.min
  }
end.compact

df = Daru::DataFrame.new(records)

vectors = df.vectors.to_a

# Step 1: Extract all CWEs
all_cwes = df.map_rows do |row|
  cwes = row[:cve_cwes].to_s.strip
  cwes = row[:kev_cwes].to_s.strip if cwes.empty?
  cwes.split('|')
end.flatten.compact

unique_cwes = all_cwes.uniq

puts "Total CWEs observed: #{all_cwes.size}"
puts "Unique CWEs: #{unique_cwes.size}"

# Step 2: Optional counts (how many times each CWE appears)
counts = Hash.new(0)
all_cwes.each { |cwe| counts[cwe] += 1 }

# Step 3: Fetch CWE descriptions
results = []

unique_cwes.each do |cwe|
  number = cwe.split('-').last
  url = URI("https://cwe.mitre.org/data/definitions/#{number}.html")
  puts "Fetching #{cwe} from #{url}..."

  begin
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE # skip SSL verification
    http.open_timeout = 5
    http.read_timeout = 5

    req = Net::HTTP::Get.new(url)
    res = http.request(req)

    if res.is_a?(Net::HTTPSuccess)
      # Grab everything after <title> up to the first parenthesis
      title_match = res.body.match(/<title>\s*([^\(]*)/im)
      desc = title_match ? title_match[1].strip.sub(/^CWE\s*-\s*/, '') : "N/A"
    else
      desc = "Error: #{res.code} #{res.message}"
    end

  rescue => e
    desc = "Error: #{e.class} #{e.message}"
  end

  results << { cwe_id: cwe, count: counts[cwe], desc: desc }
end

# Step 4: Build a Daru::DataFrame
cwe_df = Daru::DataFrame.new(results)

# Step 5: Write to CSV for later use
CSV.open("./sources/cwe_descriptions.csv", "w") do |csv|
  csv << ["cwe_id", "count", "desc"]
  cwe_df.each_row do |row|
    csv << [row[:cwe_id], row[:count], row[:desc]]
  end
end

puts "Done! CWE descriptions written to cwe_descriptions.csv"
