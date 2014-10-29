########################################################################
# test_security.rb
#
# Test suite for the Win32::Security base class. You should run these
# tests via the rake test tasks.
########################################################################
require 'test-unit'
require 'win32/security'

class TC_Win32_Security < Test::Unit::TestCase
  test "version constant is set to expected value" do
    assert_equal('0.2.5', Win32::Security::VERSION)
  end

  test "elevated security basic functionality" do
    assert_respond_to(Win32::Security, :elevated_security?)
    assert_boolean(Win32::Security.elevated_security?)
  end

  test "ffi functions are private" do
    assert_not_respond_to(Win32::Security, :CloseHandle)
  end
end
