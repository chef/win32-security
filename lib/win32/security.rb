# This file allows users to require all security related classes from
# a single file, instead of having to require individual files.

require File.join(File.dirname(__FILE__), 'security', 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'security', 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'security', 'windows', 'functions')

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
    VERSION = '0.2.5'

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
      if windows_version < 6
        sid_ptr     = FFI::MemoryPointer.new(:pointer)
        nt_auth_ptr = FFI::MemoryPointer.new(SID_IDENTIFIER_AUTHORITY,1)

        nt_auth = SID_IDENTIFIER_AUTHORITY.new(nt_auth_ptr)
        nt_auth[:Value].to_ptr.put_bytes(0, 0.chr*5 + 5.chr)

        bool = AllocateAndInitializeSid(
          nt_auth_ptr,
          2,
          SECURITY_BUILTIN_DOMAIN_RID,
          DOMAIN_ALIAS_RID_ADMINS,
          0, 0, 0, 0, 0, 0,
          sid_ptr
        )
        unless bool
          raise SystemCallError.new("AllocateAndInitializeSid", FFI.errno)
        end

        pbool = FFI::MemoryPointer.new(:long)

        unless CheckTokenMembership(0, sid_ptr.read_pointer, pbool)
          raise SystemCallError.new("CheckTokenMembership", FFI.errno)
        end

        pbool.read_long != 0
      else
        token = FFI::MemoryPointer.new(:uintptr_t)

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
        ensure
          CloseHandle(token)
        end

        te.read_ulong != 0
      end
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
#require 'win32/security/ace'
