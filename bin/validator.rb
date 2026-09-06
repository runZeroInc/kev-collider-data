#!/usr/bin/env ruby
# frozen_string_literal: true

# filename: bin/validator.rb
# usage: bin/validator.rb
#   No arguments: all of json
#   quoted single argument: a dirname, or a glob "json/CVE-2025-*" or a single file.

require 'bundler/setup'
require 'json'
require 'json-schema'
require 'pathname'

JSON::Validator.use_multi_json = false

SCRIPT_ROOT  = Pathname.new(__dir__).realpath
PROJECT_ROOT = SCRIPT_ROOT.parent

SCHEMA_PATH       = PROJECT_ROOT.join('schema/schema-v1.1.0-dev.json')
DEFAULT_DATA_PATH = PROJECT_ROOT.join('json')

MAX_BYTES = 25_000                                      # Largest KEV json is about 5k now.
CONTROL_CHAR_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/ # Guard against unsophisticated shellcode

EXIT_CODES = {
  schema_not_found: 10,
  schema_read_error: 11,
  schema_invalid_json: 12,
  no_json_files_matched: 13,
  file_too_large: 21,
  file_read_error: 22,
  contains_control_char: 23,
  file_invalid_json: 24,
  schema_validation_failed: 25,
  unexpected_error: 99
}.freeze

unless SCHEMA_PATH.exist?
  warn "[ERROR] Schema not found at #{SCHEMA_PATH}"
  exit EXIT_CODES[:schema_not_found]
end

begin
  schema = JSON.parse(SCHEMA_PATH.read)
rescue SystemCallError => e
  warn "[ERROR] Could not read schema: #{SCHEMA_PATH}"
  warn "        #{e.class}: #{e.message}"
  exit EXIT_CODES[:schema_read_error]
rescue JSON::ParserError => e
  warn "[ERROR] Schema is not valid JSON: #{SCHEMA_PATH}"
  warn "        #{e.message}"
  exit EXIT_CODES[:schema_invalid_json]
end

input = ARGV.first || DEFAULT_DATA_PATH.to_s

paths =
  if File.directory?(input)
    Dir.glob(File.join(input, '*.json'))
  else
    Dir.glob(input)
  end

if paths.empty?
  warn "[ERROR] No JSON files matched: #{input}"
  exit EXIT_CODES[:no_json_files_matched]
end

paths.each do |path|
  begin
    size = File.size(path)
    if size > MAX_BYTES
      warn "[FAIL] #{path}"
      warn "       File too large: #{size} bytes (max #{MAX_BYTES})"
      exit EXIT_CODES[:file_too_large]
    end

    raw = File.binread(path)

    if raw.match?(CONTROL_CHAR_REGEX)
      bad = raw.match(CONTROL_CHAR_REGEX)[0].ord
      warn "[FAIL] #{path}"
      warn format("       Contains control character byte: 0x%02X", bad)
      exit EXIT_CODES[:contains_control_char]
    end

    data = JSON.parse(raw, max_nesting: 50) # Guard against JSON nesting bombs

    JSON::Validator.validate!(
      schema,
      data,
      validate_schema: false
    )

  rescue JSON::Schema::ValidationError => e
    warn "[FAIL] #{path}"
    warn "       #{e.message}"
    exit EXIT_CODES[:schema_validation_failed]

  rescue JSON::ParserError => e
    warn "[ERROR] #{path}"
    warn "        Invalid JSON: #{e.message}"
    exit EXIT_CODES[:file_invalid_json]

  rescue SystemCallError => e
    warn "[ERROR] #{path}"
    warn "        File read error: #{e.class}: #{e.message}"
    exit EXIT_CODES[:file_read_error]

  rescue StandardError => e
    warn "[ERROR] #{path}"
    warn "        Unexpected error: #{e.class}: #{e.message}"
    exit EXIT_CODES[:unexpected_error]
  end
end

puts "[*] Validated #{paths.size} file(s) successfully"
