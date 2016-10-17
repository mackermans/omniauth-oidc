# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/oidc/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-oidc"
  spec.version       = OmniAuth::OIDC::VERSION
  spec.authors       = ["Maarten Ackermans"]
  spec.email         = ["maarten.ackermans@gmail.com"]

  spec.summary       = "OpenID Connect adapter for OmniAuth"
  spec.homepage      = "https://github.com/mackermans/omniauth-oidc"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"

  spec.add_dependency "omniauth", "~> 1.3"
  spec.add_dependency "openid_connect", "~> 0.12"
end
