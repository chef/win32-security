########################################################################
# test_security.rb
#
# Test suite for the Win32::Security base class. You should run these
# tests via the 'rake test' task.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'win32/security'
require 'windows/system_info'

class TC_Win32_Security < Test::Unit::TestCase
   extend Windows::SystemInfo

   def self.startup
      @@version = windows_version
   end

   def test_version
      assert_equal('0.1.4', Win32::Security::VERSION)
   end

   def test_elevated_security
      omit_if(@@version < 6.0, 'Skipped on Windows 2000 and Windows XP')
      assert_respond_to(Win32::Security, :elevated_security?)
      assert_boolean(Win32::Security.elevated_security?)
   end

   def self.shutdown
      @@version= nil
   end
end
