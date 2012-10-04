# This file allows users to require all security related classes from
# a single file, instead of having to require individual files.

require 'windows/process'
require 'windows/security'
require 'windows/handle'
require 'windows/error'

# The Win32 module serves as a namespace only.
module Win32

  # The Security class encapsulates security aspects of MS Windows.
  class Security

    # Base error class for all Win32::Security errors.
    class Error < StandardError; end

    include Windows::Security

    extend Windows::Process
    extend Windows::Security
    extend Windows::Handle
    extend Windows::Error

    # The version of the win32-security library
    VERSION = '0.1.4'

    # Returns whether or not the owner of the current process is running
    # with elevated security privileges.
    #
    # Only supported on Windows Vista or later.
    #
    def self.elevated_security?
      token = 0.chr * 4

      unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
        raise Error, get_last_error
      end

      begin
        token = token.unpack('V')[0]

        te = 0.chr * 4 # TOKEN_ELEVATION
        rl = 0.chr * 4 # Return length

        bool = GetTokenInformation(
          token,
          TokenElevation,
          te,
          te.size,
          rl
        )

        raise Error, get_last_error unless bool
      ensure
        CloseHandle(token)
      end

      # TokenIsElevated member of the TOKEN_ELEVATION struct
      te.unpack('L')[0] != 0
    end
  end
end

require 'win32/security/sid'
#require 'win32/security/acl'
#require 'win32/security/ace'
