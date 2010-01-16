########################################################################
# test_sid.rb
#
# Test suite for the Win32::Security::SID class. You should run these
# tests via the 'rake test' task.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'win32/security'
require 'sys/admin'
include Win32

class TC_Win32_Security_Sid < Test::Unit::TestCase
   def self.startup
      @@host = Socket.gethostname
      @@name = Sys::Admin.users[0].name
   end

   def setup
      @sid = Security::SID.new(@@name)
   end

   def test_version
      assert_equal('0.1.2', Security::SID::VERSION)
   end

   def test_sid
      assert_respond_to(@sid, :sid)
      assert_kind_of(String, @sid.sid)
   end

   def test_account
      assert_respond_to(@sid, :account)
      assert_kind_of(String, @sid.account)
   end

   def test_account_type
      assert_respond_to(@sid, :account_type)
      assert_kind_of(String, @sid.account_type)
   end

   def test_domain
      assert_respond_to(@sid, :domain)
      assert_kind_of(String, @sid.domain)
   end

   def test_host
      assert_respond_to(@sid, :host)
      assert_kind_of(String, @sid.host)
   end

   def test_sid_to_string
      assert_respond_to(Security::SID, :sid_to_string)
      assert_kind_of(String, Security::SID.sid_to_string(@sid.sid))
      assert_not_nil(Security::SID.sid_to_string(@sid.sid) =~ /\w+\-\w+/)
   end

   def test_string_to_sid
      assert_respond_to(Security::SID, :string_to_sid)
      assert_kind_of(String, Security::SID.string_to_sid(@sid.to_s))
   end

   def test_to_s
      assert_respond_to(@sid, :to_s)
      assert_kind_of(String, @sid.to_s)
      assert_equal(true, @sid.to_s.include?('-'))
   end

   def test_to_str_alias
      assert_respond_to(@sid, :to_str)
      assert_equal(true, @sid.method(:to_s) == @sid.method(:to_str))
   end

   def test_equal
      assert_respond_to(@sid, :==)
      assert_equal(true, @sid == @sid)
   end

   def test_valid
      assert_respond_to(@sid, :valid?)
      assert_equal(true, @sid.valid?)
   end

   def test_length
      assert_respond_to(@sid, :length)
      assert_equal(true, @sid.length > 0)
   end

   def test_create
      assert_respond_to(Security::SID, :create)
      assert_nothing_raised{
         Security::SID.create(
            Security::SID::SECURITY_WORLD_SID_AUTHORITY,
            Security::SID::SECURITY_WORLD_RID
         )
      }
   end

   def test_new_with_host
      assert_nothing_raised{ Security::SID.new(@@name, @@host) }
   end

   def test_new_expected_errors
      assert_raise(ArgumentError){ Security::SID.new }
      assert_raise(ArgumentError){ Security::SID.new(@@name, @@host, @@host) }
      assert_raise(Security::SID::Error){ Security::SID.new('bogus') }
   end

   def test_well_known_sid_constants
      assert_equal('S-1-0', Security::SID::Null)
      assert_equal('S-1-0-0', Security::SID::Nobody)
      assert_equal('S-1-1', Security::SID::World)
      assert_equal('S-1-1-0', Security::SID::Everyone)
      assert_equal('S-1-5-32-544', Security::SID::BuiltinAdministrators)
      assert_equal('S-1-5-32-545', Security::SID::BuiltinUsers)
      assert_equal('S-1-5-32-546', Security::SID::Guests)
   end

   def teardown
      @sid = nil
   end

   def self.shutdown
      @@host = nil
      @@name = nil
   end
end
