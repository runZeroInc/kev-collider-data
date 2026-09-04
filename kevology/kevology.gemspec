# frozen_string_literal: true

require_relative 'lib/kevology/version'

Gem::Specification.new do |spec|
  spec.name    = 'kevology'
  spec.version = Kevology::VERSION
  spec.authors = ['runZero']
  spec.summary = 'Reusable library for parsing KEV/CVE data and generating enriched context'

  spec.files         = Dir['lib/**/*']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.1'

  spec.add_dependency 'cvss-to-3.1', '~> 1.0'
  spec.add_dependency 'holidays',    '~> 8.8'
  spec.add_dependency 'cvss-suite',  '~> 4.1'
  spec.add_dependency 'csv',         '~> 3.3'

  spec.add_development_dependency 'rspec', '~> 3.13'
end
