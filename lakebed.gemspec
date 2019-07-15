lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "lakebed/version"

Gem::Specification.new do |spec|
  spec.name          = "lakebed"
  spec.version       = Lakebed::VERSION
  spec.authors       = ["misson20000"]
  spec.email         = ["xenotoad@xenotoad.net"]

  spec.summary       = "Emulation-based testing library for Nintendo Switch reimplementations"
  spec.homepage      = "https://github.com/misson20000/lakebed"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "unicorn-engine"
  spec.add_dependency "lz4-ruby"
  spec.add_dependency "rspec", "~> 3.0"
  spec.add_dependency "hexdump", "~> 0.2.3"
  spec.add_dependency "paint"
  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "pry"
end
