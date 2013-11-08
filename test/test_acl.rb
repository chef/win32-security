########################################################################
# test_acl.rb
#
# Test suite for the Win32::Security::ACL class. You should run these
# tests via the 'rake test' task.
########################################################################
require 'test-unit'
require 'win32/security'
require 'win32/security/sid'
require 'win32/security/acl'

class TC_Win32_Security_Acl < Test::Unit::TestCase
  def setup
    @acl = Win32::Security::ACL.new
  end

  test "ACL version is set to the expected value" do
    assert_equal('0.2.0', Win32::Security::ACL::VERSION)
  end

  test "ace_count basic functionality" do
    assert_respond_to(@acl, :ace_count)
    assert_kind_of(Fixnum, @acl.ace_count)
  end

  test "ace_count returns the expected value" do
    assert_equal(0, @acl.ace_count)
  end

  test "ace_count does not accept any arguments" do
    assert_raise(ArgumentError){ @acl.ace_count(0) }
  end

  test "acl method basic functionality" do
    assert_respond_to(@acl, :acl)
    assert_nothing_raised{ @acl.acl }
  end

  test "add_access_allowed_ace basic functionality" do
    assert_respond_to(@acl, :add_access_allowed_ace)
  end

  test "add_access_denied_ace basic functionality" do
    assert_respond_to(@acl, :add_access_denied_ace)
  end

  test "add_ace basic functionality" do
    assert_respond_to(@acl, :add_ace)
  end

  test "delete_ace basic functionality" do
    assert_respond_to(@acl, :delete_ace)
  end

  test "find_ace basic functionality" do
    assert_respond_to(@acl, :find_ace)
    assert_kind_of(Fixnum, @acl.find_ace)
  end

  test "find_ace returns a sane value" do
    assert_true(@acl.find_ace > 1000)
  end

  test "revision getter basic functionality" do
    assert_respond_to(@acl, :revision)
    assert_kind_of(Fixnum, @acl.revision)
  end

  test "revision setter basic functionality" do
    assert_respond_to(@acl, :revision=)
    assert_nothing_raised{ @acl.revision = 3 }
    assert_kind_of(Fixnum, @acl.revision = 3)
  end

  test "revision setter sets and returns the new value" do
    assert_equal(3, @acl.revision = 3)
    assert_equal(3, @acl.revision)
  end

  test "valid? basic functionality" do
    assert_respond_to(@acl, :valid?)
    assert_boolean(@acl.valid?)
  end

  test "valid? returns the expected value" do
    assert_true(@acl.valid?)
  end

  test "ffi functions are private" do
    assert_not_respond_to(@acl, :CloseHandle)
  end

  def teardown
    @acl = nil
  end
end
