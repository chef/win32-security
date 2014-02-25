require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-security'
  spec.version    = '0.2.5'
  spec.authors    = ['Daniel J. Berger', 'Park Heesob']
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'https://github.com/djberg96/win32-security'
  spec.summary    = 'A library for dealing with aspects of Windows security.'
  spec.test_files = Dir['test/*.rb']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']
  spec.rubyforge_project = 'win32utils'
   
  spec.add_dependency('ffi')

  spec.add_development_dependency('rake')
  spec.add_development_dependency('test-unit', '>= 2.5.0')
  spec.add_development_dependency('sys-admin', '>= 1.6.0')
   
  spec.description = <<-EOF
    The win32-security library provides an interface for dealing with
    security related aspects of MS Windows. At the moment it provides an
    interface for inspecting or creating SID's.
  EOF
end
