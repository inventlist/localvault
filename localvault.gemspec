require_relative "lib/localvault/version"

Gem::Specification.new do |spec|
  spec.name          = "localvault"
  spec.version       = LocalVault::VERSION
  spec.authors       = ["Nauman Tariq"]
  spec.email         = ["nauman@intellecta.co"]

  spec.summary       = "Zero-infrastructure secrets manager"
  spec.description   = "Encrypted local vault for secrets with MCP server for AI agents. No cloud required. Powers credentials management at inventlist.com."
  spec.homepage      = "https://github.com/inventlist/localvault"
  spec.license       = "MIT"

  spec.metadata = {
    "homepage_uri" => "https://github.com/inventlist/localvault",
    "source_code_uri" => "https://github.com/inventlist/localvault",
    "funding_uri" => "https://inventlist.com"
  }

  spec.required_ruby_version = ">= 3.2.0"

  spec.files         = Dir["lib/**/*", "bin/*", "LICENSE", "README.md"]
  spec.bindir        = "bin"
  spec.executables   = ["localvault"]

  spec.add_dependency "thor", "~> 1.3"
  spec.add_dependency "rbnacl", "~> 7.1"
  spec.add_dependency "base64"
  spec.add_dependency "lipgloss", "~> 0.2"

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
