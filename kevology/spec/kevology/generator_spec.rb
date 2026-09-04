# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Kevology::Generator do
  # ---------------------------------------------------------------------------
  # Shared fixture data
  # ---------------------------------------------------------------------------

  let(:base_kev_entry) do
    {
      'cveID'                      => 'CVE-2021-44228',
      'vendorProject'              => 'Apache',
      'product'                    => 'Log4j',
      'vulnerabilityName'          => 'Apache Log4j2 Remote Code Execution Vulnerability',
      'dateAdded'                  => '2021-12-10',
      'dueDate'                    => '2021-12-24',
      'knownRansomwareCampaignUse' => 'Known',
      'cwes'                       => ['CWE-917', nil, 'CWE-917'] # duplicates + nil on purpose
    }
  end

  let(:base_cve_data) do
    {
      'cveMetadata' => {
        'cveId'         => 'CVE-2021-44228',
        'datePublished' => '2021-12-10T10:00:00Z',
        'dateUpdated'   => '2021-12-12T10:00:00Z'
      },
      'containers' => {
        'cna' => {
          'providerMetadata' => { 'shortName' => 'apache' },
          'problemTypes'     => [
            { 'descriptions' => [{ 'cweId' => 'CWE-917', 'type' => 'CWE' }] }
          ],
          'metrics' => [
            { 'cvssV3_1' => {
              'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              'baseScore'    => 10.0
            } }
          ]
        }
      }
    }
  end

  def make_generator(kev_entry: base_kev_entry, cve_data: base_cve_data, cve_filename: 'CVE-2021-44228.json')
    described_class.new(kev_entry: kev_entry, cve_filename: cve_filename, cve_data: cve_data)
  end

  # Stub out all class-level data-source indexes so tests don't hit the filesystem.
  before do
    allow(described_class).to receive(:metasploit_index).and_return(
      instance_double(Kevology::MetasploitIndex, modules_for: [])
    )
    allow(described_class).to receive(:nuclei_index).and_return(
      instance_double(Kevology::NucleiIndex, templates_for: [])
    )
    allow(described_class).to receive(:epss_index).and_return({})
    allow(described_class).to receive(:attck_index).and_return(Hash.new { |h, k| h[k] = {} })
  end

  # ---------------------------------------------------------------------------
  # Schema constants and validation
  # ---------------------------------------------------------------------------

  describe 'schema' do
    it 'SCHEMA_PATH is derived from SCHEMA_VERSION' do
      expect(described_class::SCHEMA_PATH).to include(described_class::SCHEMA_VERSION)
    end

    it 'SCHEMA_PATH exists on disk' do
      expect(File.exist?(described_class::SCHEMA_PATH)).to be true
    end

    it 'raises RuntimeError on instantiation when schema file is missing' do
      allow(File).to receive(:exist?).with(described_class::SCHEMA_PATH).and_return(false)
      expect { make_generator }.to raise_error(RuntimeError, /Schema file not found/)
    end

    describe '.schema' do
      it 'returns a Hash' do
        expect(described_class.schema).to be_a(Hash)
      end

      it 'is memoized' do
        expect(described_class.schema).to equal(described_class.schema)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # .reset_indexes!
  # ---------------------------------------------------------------------------

  describe '.reset_indexes!' do
    it 'clears memoized class-level indexes without raising' do
      # Simply confirm that calling reset_indexes! does not error.
      expect { described_class.reset_indexes! }.not_to raise_error
    end
  end

  describe '.load_epss_index' do
    let(:base) { '/tmp/epss' }
    let(:v4_yesterday) { File.join(base, '2026', 'epss_scores-2026-05-21.csv.gz') }
    let(:v4_today) { File.join(base, '2026', 'epss_scores-2026-05-22.csv.gz') }
    let(:v5_yesterday) { File.join(base, 'beta_scores', 'epssv5_beta-2026-05-21.csv.gz') }
    let(:v5_today) { File.join(base, 'beta_scores', 'epssv5_beta-2026-05-22.csv.gz') }

    before do
      described_class.reset_indexes!
      allow(Kevology.configuration).to receive(:epss_snapshots_dir).and_return(base)
      allow(Dir).to receive(:glob).with(File.join(base, '*', 'epss_scores-*.csv.gz')).and_return([v4_yesterday, v4_today])
      allow(Dir).to receive(:glob).with(File.join(base, 'beta_scores', 'epssv5_beta-*.csv.gz')).and_return([v5_yesterday, v5_today])

      allow(described_class).to receive(:parse_epss_snapshot).with(v4_today).and_return(
        'CVE-2021-44228' => { score: 0.97, percentile: 0.999 }
      )
      allow(described_class).to receive(:parse_epss_snapshot).with(v4_yesterday).and_return(
        'CVE-2021-44228' => { score: 0.96, percentile: 0.998 }
      )
      allow(described_class).to receive(:parse_epss_snapshot).with(v5_today).and_return(
        'CVE-2021-44228' => { score: 0.95, percentile: 0.997 }
      )
      allow(described_class).to receive(:parse_epss_snapshot).with(v5_yesterday).and_return(
        'CVE-2021-44228' => { score: 0.94, percentile: 0.996 }
      )
    end

    it 'merges beta fields into each CVE epss payload' do
      result = described_class.load_epss_index
      expect(result.dig('CVE-2021-44228', 'todayScore')).to eq(0.97)
      expect(result.dig('CVE-2021-44228', 'beta', 'todayScore')).to eq(0.95)
      expect(result.dig('CVE-2021-44228', 'beta', 'deltaScore')).to eq(0.01)
    end

    context 'when beta exists for a CVE that is missing from main v4' do
      before do
        allow(described_class).to receive(:parse_epss_snapshot).with(v5_today).and_return(
          'CVE-2021-44228' => { score: 0.95, percentile: 0.997 },
          'CVE-2099-9999' => { score: 0.55, percentile: 0.955 }
        )
      end

      it 'does not create a beta-only epss record' do
        result = described_class.load_epss_index
        expect(result).not_to have_key('CVE-2099-9999')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # #cve_data?
  # ---------------------------------------------------------------------------

  describe '#cve_data?' do
    it 'returns true when cve_data is a non-empty Hash' do
      expect(make_generator.cve_data?).to be true
    end

    it 'returns false when cve_data is nil' do
      expect(make_generator(cve_data: nil).cve_data?).to be false
    end

    it 'returns false when cve_data is an empty Hash' do
      expect(make_generator(cve_data: {}).cve_data?).to be false
    end

    it 'returns false when cve_data is not a Hash' do
      expect(make_generator(cve_data: "not a hash").cve_data?).to be false
    end
  end

  # ---------------------------------------------------------------------------
  # #generate — top-level structure
  # ---------------------------------------------------------------------------

  describe '#generate' do
    subject(:result) { make_generator.generate }

    it 'returns a Hash' do
      expect(result).to be_a(Hash)
    end

    it 'returns keys in sorted order' do
      expect(result.keys).to eq(result.keys.sort)
    end

    it 'sets schemaVersion' do
      expect(result['schemaVersion']).to eq(described_class::SCHEMA_VERSION)
    end

    it 'sets cveID extracted from the filename' do
      expect(result['cveID']).to eq('CVE-2021-44228')
    end

    it 'sets dateGenerated to an ISO-8601 timestamp' do
      expect(result['dateGenerated']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    end

    it 'sets cveDataPresent to true when CVE data is supplied' do
      expect(result['cveDataPresent']).to be true
    end

    it 'sets cveDataPresent to false when no CVE data is supplied' do
      result = make_generator(cve_data: nil).generate
      expect(result['cveDataPresent']).to be false
    end

    it 'includes a kev section' do
      expect(result['kev']).to be_a(Hash)
    end
  end

  # ---------------------------------------------------------------------------
  # KEV section
  # ---------------------------------------------------------------------------

  describe '#generate — kev section' do
    subject(:kev) { make_generator.generate['kev'] }

    it 'strips trailing " Vulnerability" from vulnerabilityName' do
      expect(kev['vulnerabilityName']).to eq('Apache Log4j2 Remote Code Execution')
    end

    it 'does not strip "Vulnerability" from names that are not suffixed with it' do
      entry  = base_kev_entry.merge('vulnerabilityName' => 'ProxyShell Exchange Server')
      result = make_generator(kev_entry: entry).generate['kev']
      expect(result['vulnerabilityName']).to eq('ProxyShell Exchange Server')
    end

    it 'strips leading/trailing whitespace from vendorProject' do
      entry = base_kev_entry.merge('vendorProject' => '  Apache  ')
      kev   = make_generator(kev_entry: entry).generate['kev']
      expect(kev['vendorProject']).to eq('Apache')
    end

    it 'sets vendorProject to "unknown" when missing' do
      entry = base_kev_entry.reject { |k| k == 'vendorProject' }
      kev   = make_generator(kev_entry: entry).generate['kev']
      expect(kev['vendorProject']).to eq('unknown')
    end

    it 'sets product' do
      expect(kev['product']).to eq('Log4j')
    end

    it 'sets dateAdded' do
      expect(kev['dateAdded']).to eq('2021-12-10')
    end

    it 'sets dateDue' do
      expect(kev['dateDue']).to eq('2021-12-24')
    end

    it 'calculates daysAllotted' do
      expect(kev['daysAllotted']).to eq(14)
    end

    it 'sets dayAdded to the correct weekday' do
      # 2021-12-10 was a Friday
      expect(kev['dayAdded']).to eq('Friday')
    end

    it 'sets ransomware to true when knownRansomwareCampaignUse is "Known"' do
      expect(kev['ransomware']).to be true
    end

    it 'sets ransomware to false when knownRansomwareCampaignUse is not "Known"' do
      entry = base_kev_entry.merge('knownRansomwareCampaignUse' => 'Unknown')
      kev   = make_generator(kev_entry: entry).generate['kev']
      expect(kev['ransomware']).to be false
    end

    it 'sets ransomware to false when knownRansomwareCampaignUse is blank' do
      entry = base_kev_entry.merge('knownRansomwareCampaignUse' => '')
      kev   = make_generator(kev_entry: entry).generate['kev']
      expect(kev['ransomware']).to be false
    end

    it 'sets cwes from the KEV entry, filtering nils and deduplicating' do
      expect(kev['cwes']).to eq(['CWE-917'])
    end

    it 'omits the cwes key when the KEV entry has no cwes' do
      entry = base_kev_entry.merge('cwes' => [nil])
      kev   = make_generator(kev_entry: entry).generate['kev']
      expect(kev).not_to have_key('cwes')
    end

    context 'holiday detection' do
      it 'sets holidayAdded when the date falls on a US holiday' do
        # 2021-12-24 is Christmas Eve (observed in some states) but let's use a
        # well-known holiday: 2021-12-25 Christmas — skip weekends, try
        # 2024-01-01 (New Year's Day)
        entry = base_kev_entry.merge('dateAdded' => '2024-01-01', 'dueDate' => '2024-01-15')
        kev   = make_generator(kev_entry: entry).generate['kev']
        expect(kev['holidayAdded']).not_to be_nil
      end

      it 'omits holidayAdded for a regular weekday' do
        # 2021-12-10 is a normal Friday
        expect(kev).not_to have_key('holidayAdded')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CVE section — metadata
  # ---------------------------------------------------------------------------

  describe '#generate — cve metadata' do
    subject(:cve_meta) { make_generator.generate.dig('cve', 'metadata') }

    it 'sets assigningCNA' do
      expect(cve_meta['assigningCNA']).to eq('apache')
    end

    it 'sets datePublished' do
      expect(cve_meta['datePublished']).to eq('2021-12-10T10:00:00Z')
    end

    it 'sets dateUpdated' do
      expect(cve_meta['dateUpdated']).to eq('2021-12-12T10:00:00Z')
    end

    context 'with no CVE data' do
      it 'does not include a cve section at all' do
        result = make_generator(cve_data: nil).generate
        expect(result).not_to have_key('cve')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CVE assertions — CWE extraction
  # ---------------------------------------------------------------------------

  describe '#generate — CWE extraction' do
    context 'when CNA provides CWEs' do
      it 'extracts CWEs from the CNA problemTypes' do
        cwes = make_generator.generate.dig('cve', 'assertions', 'cwes')
        expect(cwes).to eq(['CWE-917'])
      end
    end

    context 'when CNA has no CWEs but CISA-ADP does' do
      let(:cve_with_adp_cwes) do
        base_cve_data.merge(
          'containers' => {
            'cna' => {
              'providerMetadata' => { 'shortName' => 'test' },
              'problemTypes'     => [],
              'metrics'          => []
            },
            'adp' => [
              {
                'providerMetadata' => { 'shortName' => 'CISA-ADP' },
                'problemTypes'     => [
                  { 'descriptions' => [{ 'cweId' => 'CWE-502' }] }
                ]
              }
            ]
          }
        )
      end

      it 'falls back to CISA-ADP CWEs' do
        cwes = make_generator(cve_data: cve_with_adp_cwes).generate.dig('cve', 'assertions', 'cwes')
        expect(cwes).to eq(['CWE-502'])
      end
    end

    context 'when neither CNA nor ADP has CWEs' do
      let(:cve_without_cwes) do
        base_cve_data.merge(
          'containers' => {
            'cna' => {
              'providerMetadata' => { 'shortName' => 'test' },
              'problemTypes'     => [],
              'metrics'          => []
            }
          }
        )
      end

      it 'omits cwes from assertions' do
        assertions = make_generator(cve_data: cve_without_cwes).generate.dig('cve', 'assertions')
        expect(assertions).not_to have_key('cwes')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CVE assertions — CVSS
  # ---------------------------------------------------------------------------

  describe '#generate — CVSS selection and recasting' do
    def cvss_assertions_for(cve_data)
      make_generator(cve_data: cve_data).generate.dig('cve', 'assertions')
    end

    context 'with a CNA CVSS 3.1 vector' do
      let(:cve_data_cvss31) do
        build_cve_with_cna_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
      end

      subject(:assertions) { cvss_assertions_for(cve_data_cvss31) }

      it 'records cvssOriginalVersion as 3.1' do
        expect(assertions['cvssOriginalVersion']).to eq('3.1')
      end

      it 'sets cvssSource to CNA' do
        expect(assertions['cvssSource']).to eq('CNA')
      end

      it 'sets cvss.version to "3.1"' do
        expect(assertions.dig('cvss', :version)).to eq('3.1')
      end

      it 'sets cvss.baseScore' do
        expect(assertions.dig('cvss', :baseScore)).to be_a(Numeric)
      end

      it 'sets cvss.baseSeverity' do
        expect(assertions.dig('cvss', :baseSeverity)).to eq('CRITICAL')
      end

      it 'sets cvss.vectorString matching the input' do
        expect(assertions.dig('cvss', :vectorString)).to start_with('CVSS:3.1/')
      end
    end

    context 'with a CNA CVSS 3.0 vector (recast to 3.1)' do
      let(:cve_data_cvss30) do
        build_cve_with_cna_vector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
      end

      subject(:assertions) { cvss_assertions_for(cve_data_cvss30) }

      it 'records cvssOriginalVersion as 3.0' do
        expect(assertions['cvssOriginalVersion']).to eq('3.0')
      end

      it 'outputs a 3.1 vector string after recasting' do
        expect(assertions.dig('cvss', :vectorString)).to start_with('CVSS:3.1/')
      end
    end

    context 'with a CNA CVSS 4.0 vector (recast to 3.1)' do
      let(:cve_data_cvss40) do
        build_cve_with_cna_vector(
          'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
        )
      end

      subject(:assertions) { cvss_assertions_for(cve_data_cvss40) }

      it 'records cvssOriginalVersion as 4.0' do
        expect(assertions['cvssOriginalVersion']).to eq('4.0')
      end

      it 'outputs a 3.1 vector string after recasting' do
        expect(assertions.dig('cvss', :vectorString)).to start_with('CVSS:3.1/')
      end
    end

    context 'when CNA has no valid CVSS and CISA-ADP has one' do
      let(:cve_with_adp_cvss) do
        {
          'cveMetadata' => base_cve_data['cveMetadata'],
          'containers'  => {
            'cna' => {
              'providerMetadata' => { 'shortName' => 'test' },
              'problemTypes'     => [],
              'metrics'          => []
            },
            'adp' => [
              {
                'providerMetadata' => { 'shortName' => 'CISA-ADP' },
                'metrics'          => [
                  { 'cvssV3_1' => {
                    'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                  } }
                ]
              }
            ]
          }
        }
      end

      subject(:assertions) { cvss_assertions_for(cve_with_adp_cvss) }

      it 'sets cvssSource to CISA' do
        expect(assertions['cvssSource']).to eq('CISA')
      end

      it 'sets a CVSS score' do
        expect(assertions.dig('cvss', :baseScore)).to be_a(Numeric)
      end
    end

    context 'with multiple CNA CVSS vectors (highest score wins)' do
      let(:cve_with_two_cvss) do
        # The second vector (CVSS 8.8) should lose to the first (CVSS 10.0)
        {
          'cveMetadata' => base_cve_data['cveMetadata'],
          'containers'  => {
            'cna' => {
              'providerMetadata' => { 'shortName' => 'test' },
              'problemTypes'     => [],
              'metrics'          => [
                { 'cvssV3_1' => { 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' } },
                { 'cvssV3_1' => { 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' } }
              ]
            }
          }
        }
      end

      it 'selects the vector with the higher base score' do
        assertions = cvss_assertions_for(cve_with_two_cvss)
        # The first vector is 10.0, the second is 8.8; 10.0 should win.
        expect(assertions.dig('cvss', :baseScore)).to eq(10.0)
      end
    end

    context 'with no valid CVSS vectors at all' do
      let(:cve_without_cvss) do
        {
          'cveMetadata' => base_cve_data['cveMetadata'],
          'containers'  => {
            'cna' => {
              'providerMetadata' => { 'shortName' => 'test' },
              'problemTypes'     => [],
              'metrics'          => []
            }
          }
        }
      end

      it 'omits the cvss key from assertions' do
        assertions = cvss_assertions_for(cve_without_cvss)
        expect(assertions).not_to have_key('cvss')
      end

      it 'omits cvssSource from assertions' do
        assertions = cvss_assertions_for(cve_without_cvss)
        expect(assertions).not_to have_key('cvssSource')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CVE assertions — SSVC
  # ---------------------------------------------------------------------------

  describe '#generate — SSVC' do
    let(:cve_with_ssvc) do
      base_cve_data.merge(
        'containers' => base_cve_data['containers'].merge(
          'adp' => [
            {
              'providerMetadata' => { 'shortName' => 'CISA-ADP' },
              'metrics'          => [
                {
                  'other' => {
                    'type'    => 'ssvc',
                    'content' => {
                      'version'   => '2.0.3',
                      'timestamp' => '2024-03-15T12:00:00Z',
                      'role'      => 'CISA Coordinator',
                      'options'   => [
                        { 'Exploitation'     => 'Active' },
                        { 'Automatable'      => 'Yes' },
                        { 'Technical Impact' => 'Total' }
                      ]
                    }
                  }
                }
              ]
            }
          ]
        )
      )
    end

    subject(:ssvc) { make_generator(cve_data: cve_with_ssvc).generate.dig('cve', 'assertions', 'ssvc') }

    it 'sets ssvc.timestamp to a date-only string' do
      expect(ssvc['timestamp']).to eq('2024-03-15')
    end

    it 'sets ssvc.version' do
      expect(ssvc['version']).to eq('2.0.3')
    end

    it 'sets ssvc.role' do
      expect(ssvc['role']).to eq('CISA Coordinator')
    end

    it 'normalises option keys to lowerCamelCase' do
      expect(ssvc['options'].keys).to include('exploitation', 'automatable', 'technicalImpact')
    end

    it 'lowercases option values' do
      expect(ssvc['options']['exploitation']).to eq('active')
      expect(ssvc['options']['automatable']).to eq('yes')
    end

    context 'when SSVC version is not 2.0.3' do
      let(:cve_wrong_ssvc_version) do
        wrong = Marshal.load(Marshal.dump(cve_with_ssvc))
        wrong['containers']['adp'][0]['metrics'][0]['other']['content']['version'] = '1.0.0'
        wrong
      end

      it 'omits the ssvc key' do
        assertions = make_generator(cve_data: cve_wrong_ssvc_version).generate.dig('cve', 'assertions')
        expect(assertions).not_to have_key('ssvc')
      end
    end

    context 'when there is no CISA-ADP container' do
      it 'omits the ssvc key' do
        assertions = make_generator.generate.dig('cve', 'assertions')
        expect(assertions).not_to have_key('ssvc')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Metasploit modules
  # ---------------------------------------------------------------------------

  describe '#generate — metasploit modules' do
    let(:msf_modules) do
      [
        { module: 'exploit/test/log4shell.rb', firstCommitDate: '2021-12-14T00:00:00.000Z' }
      ]
    end

    before do
      allow(described_class).to receive(:metasploit_index).and_return(
        instance_double(Kevology::MetasploitIndex, modules_for: msf_modules)
      )
    end

    subject(:result) { make_generator.generate }

    it 'includes a metasploit.modules array' do
      expect(result.dig('metasploit', 'modules')).to be_an(Array)
    end

    it 'calculates deltaFromKev (days from KEV date to first commit)' do
      mod = result.dig('metasploit', 'modules').first
      # KEV dateAdded: 2021-12-10, module commit: 2021-12-14 → delta = 4
      expect(mod[:deltaFromKev]).to eq(4)
    end

    it 'calculates deltaFromCve (days from CVE publish date to first commit)' do
      mod = result.dig('metasploit', 'modules').first
      # CVE datePublished: 2021-12-10, module commit: 2021-12-14 → delta = 4
      expect(mod[:deltaFromCve]).to eq(4)
    end

    context 'when no modules exist for the CVE' do
      before do
        allow(described_class).to receive(:metasploit_index).and_return(
          instance_double(Kevology::MetasploitIndex, modules_for: [])
        )
      end

      it 'omits the metasploit key' do
        expect(result).not_to have_key('metasploit')
      end
    end

    context 'when a module has no firstCommitDate' do
      let(:msf_modules) do
        [{ module: 'exploit/test/log4shell.rb', firstCommitDate: nil }]
      end

      it 'does not set deltaFromKev' do
        mod = result.dig('metasploit', 'modules').first
        expect(mod).not_to have_key(:deltaFromKev)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Nuclei templates
  # ---------------------------------------------------------------------------

  describe '#generate — nuclei templates' do
    let(:nuclei_templates) do
      [
        { template: 'cves/CVE-2021-44228.yaml', firstCommitDate: '2021-12-15T00:00:00.000Z' }
      ]
    end

    before do
      allow(described_class).to receive(:nuclei_index).and_return(
        instance_double(Kevology::NucleiIndex, templates_for: nuclei_templates)
      )
    end

    subject(:result) { make_generator.generate }

    it 'includes a nuclei.templates array' do
      expect(result.dig('nuclei', 'templates')).to be_an(Array)
    end

    it 'calculates deltaFromKev' do
      tmpl = result.dig('nuclei', 'templates').first
      # KEV dateAdded: 2021-12-10, template commit: 2021-12-15 → delta = 5
      expect(tmpl[:deltaFromKev]).to eq(5)
    end

    it 'calculates deltaFromCve' do
      tmpl = result.dig('nuclei', 'templates').first
      expect(tmpl[:deltaFromCve]).to eq(5)
    end

    context 'when no templates exist for the CVE' do
      before do
        allow(described_class).to receive(:nuclei_index).and_return(
          instance_double(Kevology::NucleiIndex, templates_for: [])
        )
      end

      it 'omits the nuclei key' do
        expect(result).not_to have_key('nuclei')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # ATT&CK data
  # ---------------------------------------------------------------------------

  describe '#generate — ATT&CK' do
    let(:attck_entries) do
      {
        'CVE-2021-44228' => {
          'enterprise' => [
            { 'mappingType' => 'primary', 'id' => 'T1190', 'name' => 'Exploit Public-Facing Application',
              'capabilityGroup' => 'initial_access', 'source' => 'CTID-16.1' }
          ]
        }
      }
    end

    before do
      allow(described_class).to receive(:attck_index).and_return(attck_entries)
    end

    it 'includes attck data when available' do
      result = make_generator.generate
      expect(result['attck']).to be_a(Hash)
    end

    context 'when no ATT&CK entries exist' do
      before do
        allow(described_class).to receive(:attck_index).and_return(Hash.new { |h, k| h[k] = {} })
      end

      it 'omits the attck key' do
        result = make_generator.generate
        expect(result).not_to have_key('attck')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # EPSS
  # ---------------------------------------------------------------------------

  describe '#generate — EPSS' do
    let(:epss_data) do
      {
        'CVE-2021-44228' => {
          'todayScore'          => 0.97,
          'todayPercentile'     => 0.999,
          'yesterdayScore'      => 0.96,
          'yesterdayPercentile' => 0.998,
          'deltaScore'          => 0.01,
          'deltaPercentile'     => 0.001,
          'beta'             => {
            'todayScore'          => 0.87,
            'todayPercentile'     => 0.991,
            'yesterdayScore'      => 0.85,
            'yesterdayPercentile' => 0.989,
            'deltaScore'          => 0.02,
            'deltaPercentile'     => 0.002
          }
        }
      }
    end

    before do
      allow(described_class).to receive(:epss_index).and_return(epss_data)
    end

    it 'includes epss data when available' do
      result = make_generator.generate
      expect(result['epss']).to include('todayScore' => 0.97)
      expect(result['epss'].dig('beta', 'todayScore')).to eq(0.87)
    end

    context 'when no EPSS data is available' do
      before do
        allow(described_class).to receive(:epss_index).and_return({})
      end

      it 'omits the epss key' do
        expect(make_generator.generate).not_to have_key('epss')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helper
  # ---------------------------------------------------------------------------

  def build_cve_with_cna_vector(vector_string)
    {
      'cveMetadata' => base_cve_data['cveMetadata'],
      'containers'  => {
        'cna' => {
          'providerMetadata' => { 'shortName' => 'test' },
          'problemTypes'     => [],
          'metrics'          => [
            { 'cvssV3_1' => { 'vectorString' => vector_string } }
          ]
        }
      }
    }
  end
end
