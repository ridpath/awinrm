# -*- encoding: utf-8 -*-
# stub: socksify 1.8.1 ruby lib

Gem::Specification.new do |s|
  s.name = "socksify".freeze
  s.version = "1.8.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "funding_uri" => "https://github.com/sponsors/astro" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Stephan Maka".freeze, "Andrey Kouznetsov".freeze, "Christopher Thorpe".freeze, "Musy Bite".freeze, "Yuichi Tateno".freeze, "David Dollar".freeze]
  s.date = "2025-07-20"
  s.email = "stephan@spaceboyz.net".freeze
  s.executables = ["socksify_ruby".freeze]
  s.extra_rdoc_files = ["doc/index.css".freeze, "doc/index.html".freeze, "COPYING".freeze]
  s.files = ["COPYING".freeze, "bin/socksify_ruby".freeze, "doc/index.css".freeze, "doc/index.html".freeze]
  s.homepage = "https://github.com/astro/socksify-ruby".freeze
  s.licenses = ["Ruby".freeze, "GPL-3.0-only".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7".freeze)
  s.rubygems_version = "3.4.20".freeze
  s.summary = "Redirect all TCPSockets through a SOCKS5 proxy".freeze

  s.installed_by_version = "3.4.20" if s.respond_to? :installed_by_version
end
