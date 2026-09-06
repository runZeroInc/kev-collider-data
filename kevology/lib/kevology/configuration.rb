# frozen_string_literal: true

module Kevology
  class Configuration
    # Directory containing EPSS snapshot subdirectories, each with *.csv.gz files.
    attr_accessor :epss_snapshots_dir

    # Base directory for CTID ATT&CK KEV mapping files (the versioned subdirectory
    # containing enterprise/ and mobile/ subfolders with JSON mapping files).
    attr_accessor :attck_mappings_dir

    # Root directory of the Metasploit Framework modules/ tree.
    attr_accessor :metasploit_modules_dir

    # Path to the JSON file used to cache per-file first-commit dates for Metasploit.
    attr_accessor :metasploit_cache_file

    # Root directory of the Nuclei templates repository.
    attr_accessor :nuclei_templates_dir

    # Path to the JSON file used to cache per-file first-commit dates for Nuclei.
    attr_accessor :nuclei_cache_file

    # Path to the JSON file mapping post-refactor Nuclei paths back to their
    # original paths (used to look up accurate first-commit dates).
    attr_accessor :nuclei_refactor_map_file

    def initialize
      @epss_snapshots_dir       = nil
      @attck_mappings_dir       = nil
      @metasploit_modules_dir   = nil
      @metasploit_cache_file    = nil
      @nuclei_templates_dir     = nil
      @nuclei_cache_file        = nil
      @nuclei_refactor_map_file = nil
    end
  end
end
