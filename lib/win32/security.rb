# This file allows users to require all security related classes from
# a single file, instead of having to require individual files.

require File.join(File.dirname(__FILE__), 'security', 'windows', 'functions')

# The Win32 module serves as a namespace only.
module Win32

  # The Security class encapsulates security aspects of MS Windows.
  class Security

    # Base error class for all Win32::Security errors.
    class Error < StandardError; end

    include Windows::Security::Functions
    extend Windows::Security::Functions

    # The version of the win32-security library
    VERSION = '0.2.0'

    # Used by OpenProcessToken
    TOKEN_QUERY = 8

    # Returns whether or not the owner of the current process is running
    # with elevated security privileges.
    #
    # Only supported on Windows Vista or later.
    #
    def self.elevated_security?
      token = FFI::MemoryPointer.new(:ulong)

      unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
        raise SystemCallError.new("OpenProcessToken", FFI.errno)
      end

      begin
        token = token.read_ulong

        # Since the TokenElevation struct only has 1 member, we use a pointer.
        te = FFI::MemoryPointer.new(:ulong)
        rl = FFI::MemoryPointer.new(:ulong)

        bool = GetTokenInformation(
          token,
          :TokenElevation,
          te,
          te.size,
          rl
        )

        raise SystemCallError.new("GetTokenInformation", FFI.errno) unless bool
      ensure
        CloseHandle(token)
      end

      te.read_ulong != 0
    end
  end
end

require 'win32/security/sid'
#require 'win32/security/acl'
#require 'win32/security/ace'
