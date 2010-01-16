require 'rubygems'

spec = Gem::Specification.new do |gem|
   gem.name       = 'win32-security'
   gem.version    = '0.1.3'
   gem.authors    = ['Daniel J. Berger', 'Park Heesob']
   gem.license    = 'Artistic 2.0'
   gem.email      = 'djberg96@gmail.com'
   gem.homepage   = 'http://www.rubyforge.org/projects/win32utils'
   gem.platform   = Gem::Platform::RUBY
   gem.summary    = 'A library for dealing with aspects of Windows security.'
   gem.test_files = Dir['test/*.rb']
   gem.has_rdoc   = true
   gem.files      = Dir['**/*'].reject{ |f| f.include?('CVS') }

   gem.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']
   gem.rubyforge_project = 'win32utils'
   
   gem.add_dependency('windows-pr', '>= 1.0.8')

   gem.add_development_dependency('test-unit', '>= 2.0.1')
   gem.add_development_dependency('sys-admin', '>= 1.4.4')
   
   gem.description = <<-EOF
      The win32-security library provides an interface for dealing with
      security related aspects of MS Windows. At the moment it provides an
      interface for inspecting or creating SID's.
   EOF
end

Gem::Builder.new(spec).build
