# frozen_string_literal: true

require_relative 'kevology/version'
require_relative 'kevology/configuration'
require_relative 'kevology/metasploit_index'
require_relative 'kevology/nuclei_index'
require_relative 'kevology/generator'

module Kevology
  # Yields the current {Configuration} for mutation.
  #
  # @example
  #   Kevology.configure do |c|
  #     c.epss_snapshots_dir     = '/data/sources/epss_scores'
  #     c.attck_mappings_dir     = '/data/sources/ctid/mappings/kev/attack-16.1/kev-07.28.2025'
  #     c.metasploit_modules_dir = '/data/sources/metasploit-framework/modules'
  #     c.metasploit_cache_file  = '/data/sources/metasploit-commit-dates.json'
  #     c.nuclei_templates_dir   = '/data/sources/nuclei-templates'
  #     c.nuclei_cache_file      = '/data/sources/nuclei-commit-dates.json'
  #     c.nuclei_refactor_map_file = '/data/sources/nuclei-refactor-map.json'
  #   end
  def self.configure
    yield configuration
  end

  # Returns the current {Configuration} instance, creating it if necessary.
  def self.configuration
    @configuration ||= Configuration.new
  end

  # Resets configuration to defaults. Primarily useful in tests.
  def self.reset_configuration!
    @configuration = Configuration.new
    Generator.reset_indexes!
  end
end
