require 'rake'
require 'rake/testtask'
require 'rbconfig'
include Config

desc 'Cleanup any temp files left over by Test::Unit'
task :clean do
   Dir['*'].each{ |file|
      file = File.expand_path(file)
      next unless File.directory?(file)
      next if file =~ /CVS/
      Dir.chdir(file) do
         rm_rf '.test-result' if File.exists?('.test-result')
      end
   }end

desc 'Install the win32-security package (non-gem)'
task :install do
   install_dir = File.join(CONFIG["sitelibdir"], 'win32', 'security')
   mkdir_p(install_dir) unless File.exists?(install_dir)
   cp 'lib/win32/security.rb', File.dirname(install_dir), :verbose => true
   cp 'lib/win32/security/acl.rb', install_dir, :verbose => true
   cp 'lib/win32/security/sid.rb', install_dir, :verbose => true
end

task :install_gem do
   ruby 'win32-security.gemspec'
   file = Dir["*.gem"].first
   sh "gem install #{file}"
end

# TODO: Add more test files as more classes are added.
Rake::TestTask.new do |t|
   t.verbose = true
   t.warning = true
   t.test_files = Dir['test/test_sid.rb', 'test/test_security.rb']
end
