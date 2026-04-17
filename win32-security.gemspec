Gem::Specification.new do |spec|
  spec.name       = 'win32-security'
  spec.version    = '0.5.0'
  spec.authors    = ['Daniel J. Berger', 'Park Heesob']
  spec.license    = 'Apache-2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'https://github.com/djberg96/win32-security'
  spec.summary    = 'A library for dealing with aspects of Windows security.'
  spec.test_files = Dir['test/*.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.extra_rdoc_files  = ['README.md', 'CHANGELOG.md']

  spec.required_ruby_version = '>= 3.1.6'

  spec.add_dependency('ffi', '>= 1.15.5', '< 1.17.0')
  spec.add_dependency('ffi-win32-extensions')

  spec.add_development_dependency('rake')
  spec.add_development_dependency('test-unit', '>= 3.6.7')
  spec.add_development_dependency('sys-admin', '>= 1.8.4')

  spec.description = <<-EOF
    The win32-security library provides an interface for dealing with
    security related aspects of MS Windows, such as SID's, ACL's and
    ACE's.
  EOF
end
