########################################################################
# test_sid.rb
#
# Test suite for the Win32::Security::SID class. You should run these
# tests via the 'rake test' task.
########################################################################
require 'etc'
require 'test-unit'
require 'win32/security'
include Win32

class TC_Win32_Security_Sid < Test::Unit::TestCase
  def self.startup
    @@host = Socket.gethostname
    @@name = Etc.getlogin
  end

  def setup
    @sid = Security::SID.new(@@name)
  end

  test "version is set to expected value" do
    assert_equal('0.2.1', Security::SID::VERSION)
  end

  test "sid method basic functionality" do
    assert_respond_to(@sid, :sid)
    assert_kind_of(String, @sid.sid)
  end

  test "account method basic functionality" do
    assert_respond_to(@sid, :account)
    assert_kind_of(String, @sid.account)
  end

  test "account_type method basic functionality" do
    assert_respond_to(@sid, :account_type)
    assert_kind_of(String, @sid.account_type)
  end

  test "domain method basic functionality" do
    assert_respond_to(@sid, :domain)
    assert_kind_of(String, @sid.domain)
  end

  test "host method basic functionality" do
    assert_respond_to(@sid, :host)
    assert_kind_of(String, @sid.host)
  end

  test "sid_to_string works as expected" do
    assert_respond_to(Security::SID, :sid_to_string)
    assert_kind_of(String, Security::SID.sid_to_string(@sid.sid))
    assert_not_nil(Security::SID.sid_to_string(@sid.sid) =~ /\w+\-\w+/)
  end

  test "string_to_sid works as expected" do
    assert_respond_to(Security::SID, :string_to_sid)
    assert_kind_of(String, Security::SID.string_to_sid(@sid.to_s))
  end

  test "we can convert back and forth between a sid and a string" do
    str = Security::SID.sid_to_string(@sid.sid)
    assert_equal(@sid.sid, Security::SID.string_to_sid(str))
  end

  test "to_s works as expected" do
    assert_respond_to(@sid, :to_s)
    assert_kind_of(String, @sid.to_s)
    assert_true(@sid.to_s.include?('-'))
  end

  test "to_str is an alias for to_s" do
    assert_respond_to(@sid, :to_str)
    assert_alias_method(@sid, :to_str, :to_s)
  end

  test "equality works as expected" do
    assert_respond_to(@sid, :==)
    assert_true(@sid == @sid)
  end

  test "valid? method works as expected" do
    assert_respond_to(@sid, :valid?)
    assert_true(@sid.valid?)
  end

  test "length method works as expected" do
    assert_respond_to(@sid, :length)
    assert_true(@sid.length > 0)
  end

  test "create method works as expected" do
    assert_respond_to(Security::SID, :create)
    assert_nothing_raised{
      Security::SID.create(
        Security::SID::SECURITY_WORLD_SID_AUTHORITY,
        Security::SID::SECURITY_WORLD_RID
      )
    }
  end

  test "constructor defaults to current account" do
    assert_nothing_raised{ @sid = Security::SID.new }
    assert_equal(Etc.getlogin, @sid.account)
  end

  test "constructor accepts an account argument" do
    assert_nothing_raised{ Security::SID.new(@@name) }
  end

  test "constructor accepts a host argument" do
    assert_nothing_raised{ Security::SID.new(@@name, @@host) }
  end

  test "constructor accepts a maximum of two arguments" do
    assert_raise(ArgumentError){ Security::SID.new(@@name, @@host, @@host) }
  end

  test "constructor raises an error if an invalid account is passed" do
    assert_raise(SystemCallError){ Security::SID.new('bogus') }
  end

  test "well known sid constants are defined" do
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
