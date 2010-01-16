########################################################################
# test_acl.rb
#
# Test suite for the Win32::Security::ACL class. You should run these
# tests via the 'rake test' task.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/security'
require 'test/unit'

class TC_Win32_Security_Acl < Test::Unit::TestCase
   def setup
      @acl = Security::ACL.new
   end

   def test_version
      assert_equal('0.1.0', Security::ACL::VERSION)
   end

   def test_ace_count
      assert_respond_to(@acl, :ace_count)
      assert_kind_of(Fixnum, @acl.ace_count)
      assert_equal(0, @acl.ace_count)
   end

   def test_acl
      assert_respond_to(@acl, :acl)
      assert_kind_of(String, @acl.acl)
   end

   def test_add_access_allowed_ace
      assert_respond_to(@acl, :add_access_allowed_ace)
   end

   def test_add_access_denied_ace
      assert_respond_to(@acl, :add_access_denied_ace)
   end

   def test_add_ace
      assert_respond_to(@acl, :add_ace)
   end

   def test_delete_ace
      assert_respond_to(@acl, :delete_ace)
   end

   def test_find_ace
      assert_respond_to(@acl, :find_ace)
      assert_kind_of(Fixnum, @acl.find_ace)
   end

   def test_revision
      assert_respond_to(@acl, :revision)
      assert_kind_of(Fixnum, @acl.revision)
   end

   def test_is_valid
      assert_respond_to(@acl, :valid?)
      assert_equal(true, @acl.valid?)
   end

   def teardown
      @acl = nil
   end
end
