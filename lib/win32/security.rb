# This file allows users to require all security related classes from
# a single file, instead of having to require individual files.

require_relative 'security/windows/constants'
require_relative 'security/windows/structs'
require_relative 'security/windows/functions'

# The Win32 module serves as a namespace only.
module Win32

  # The Security class encapsulates security aspects of MS Windows.
  class Security

    # Base error class for all Win32::Security errors.
    class Error < StandardError; end

    include Windows::Security::Functions
    include Windows::Security::Constants
    include Windows::Security::Structs
    extend Windows::Security::Functions

    # The version of the win32-security library
    VERSION = '0.3.0'

    # Used by OpenProcessToken
    TOKEN_QUERY = 8

    # Returns whether or not the owner of the current process is running
    # with elevated security privileges.
    #
    # On Windows XP an earlier this method is actually just checking to
    # see if the caller's process is a member of the local Administrator's
    # group.
    #
    def self.elevated_security?
      result = false

      FFI::MemoryPointer.new(:uintptr_t) do |token|
        unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
          raise SystemCallError.new("OpenProcessToken", FFI.errno)
        end

        begin
          token = token.read_pointer.to_i

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

          result = te.read_ulong != 0
        ensure
          CloseHandle(token)
          te.free
          rl.free
        end
      end

      result
    end

    private

    def self.windows_version
      ver = OSVERSIONINFO.new
      ver[:dwOSVersionInfoSize] = ver.size

      unless GetVersionExA(ver)
        raise SystemCallError.new("GetVersionEx", FFI.errno)
      end

      ver[:dwMajorVersion]
    end
  end
end

require 'win32/security/sid'
require 'win32/security/acl'
require 'win32/security/ace'
