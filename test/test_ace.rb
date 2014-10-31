########################################################################
# test_ace.rb
#
# Test suite for the Win32::Security::ACE class.
########################################################################
require 'test-unit'
require 'win32/security'
require 'win32/security/sid'
require 'win32/security/acl'
require 'win32/security/ace'

class TC_Win32_Security_Ace < Test::Unit::TestCase
  def setup
    @ace = Win32::Security::ACE.new(1, 1, 1)
  end

  test "ACE version is set to the expected value" do
    assert_equal('0.1.0', Win32::Security::ACE::VERSION)
  end

  test "ace_type basic functionality" do
    assert_respond_to(@ace, :ace_type)
    assert_equal(1, @ace.ace_type)
  end

  test "access_mask basic functionality" do
    assert_respond_to(@ace, :access_mask)
    assert_equal(1, @ace.access_mask)
  end

  test "flags basic functionality" do
    assert_respond_to(@ace, :flags)
    assert_equal(1, @ace.flags)
  end

  test "ace_type_string basic functionality" do
    assert_respond_to(@ace, :ace_type_string)
    assert_kind_of(String, @ace.ace_type_string)
  end

  test "ace_type_string returns the expected value" do
    assert_equal('ACCESS_DENIED_ACE_TYPE', @ace.ace_type_string)
  end

  def teardown
    @ace = nil
  end
end
