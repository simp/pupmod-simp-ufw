# frozen_string_literal: true

# Temporary: simp-rspec-puppet-facts 4.0.x ships only EL factsets, so
# `on_supported_os` returns nothing for Ubuntu. This fills in the
# rspec-puppet-facts (FacterDB) factsets for the supported releases the SIMP
# gem lacks, with their keys deep-symbolized to match the SIMP factsets.
#
# Remove this file, and use `on_supported_os` directly, once a
# simp-rspec-puppet-facts release with the FacterDB fallback
# (simp/rubygem-simp-rspec-puppet-facts#95) is out.
module FacterDBFallback
  def self.deep_symbolize(value)
    case value
    when Hash then value.each_with_object({}) { |(k, v), h| h[k.is_a?(String) ? k.to_sym : k] = deep_symbolize(v) }
    when Array then value.map { |v| deep_symbolize(v) }
    else value
    end
  end

  def on_supported_os_with_fallback(opts = {})
    found = on_supported_os(opts)

    supported = opts.fetch(:supported_os) { RspecPuppetFacts.meta_supported_os }
    supported.each do |os|
      os['operatingsystemrelease'].each do |release|
        key = "#{os['operatingsystem'].downcase}-#{release}-x86_64"
        next if found.key?(key)

        upstream = Simp::RspecPuppetFacts::Shim.on_supported_os(
          opts.merge(supported_os: [os.merge('operatingsystemrelease' => [release])]),
        )
        upstream.each { |name, facts| found[name] = FacterDBFallback.deep_symbolize(facts) }
      end
    end

    found
  end
end

include FacterDBFallback
