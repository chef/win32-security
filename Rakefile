require 'rake'
require 'rake/clean'
require 'rake/testtask'
require 'rbconfig'

CLEAN.include('**/*.gem', '**/*.rbc')

namespace :gem do
  desc "Create the win32-security gem"
  task :create => [:clean] do
    require 'rubygems/package'
    spec = eval(IO.read('win32-security.gemspec'))
    spec.signing_key = File.join(Dir.home, '.ssh', 'gem-private_key.pem')
    Gem::Package.build(spec, true)
  end

  desc "Install the win32-security gem"
  task :install => [:create] do
    ruby 'win32-security.gemspec'
    file = Dir["*.gem"].first
    sh "gem install -l #{file}"
  end
end

namespace :test do
  Rake::TestTask.new(:security) do |t|
    t.verbose = true
    t.warning = true
    t.test_files = Dir['test/test_security.rb']
  end

  Rake::TestTask.new(:acl) do |t|
    t.verbose = true
    t.warning = true
    t.test_files = Dir['test/test_acl.rb']
  end

  Rake::TestTask.new(:ace) do |t|
    t.verbose = true
    t.warning = true
    t.test_files = Dir['test/test_ace.rb']
  end

  Rake::TestTask.new(:sid) do |t|
    t.verbose = true
    t.warning = true
    t.test_files = Dir['test/test_sid.rb']
  end

  # ACL class isn't ready yet
  Rake::TestTask.new(:all) do |t|
    t.verbose = true
    t.warning = true
    t.test_files = Dir['test/test_sid.rb', 'test/test_security.rb']
  end
end

task :default => 'test:all'
