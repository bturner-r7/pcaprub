# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pcaprub/version'

Gem::Specification.new do |spec|
  spec.name          = "pcaprub"
  spec.version       = PCAPRUB::VERSION::STRING
  spec.authors       = ["shadowbq"]
  spec.email         = ["shadowbq@gmail.com"]
  spec.summary       = %q{libpcap bindings for ruby}
  spec.description   = %q{libpcap bindings for ruby compat with JRUBY Ruby1.8 Ruby1.9}
  spec.homepage      = "http://github.com/shadowbq/pcaprub"
  spec.license       = "LGPL"

  spec.files         = `git ls-files`.split($/)
  spec.extensions    = ['ext/pcaprub/extconf.rb']
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rake-compiler", ">= 0"
  spec.add_development_dependency "shoulda"
end
