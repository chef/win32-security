require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'functions')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require 'socket'

# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The SID class encapsulates a Security Identifier.
    class SID
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      # The version of the Win32::Security::SID class.
      VERSION = '0.2.1'

      # Some constant SID's for your convenience, in string format.
      # See http://support.microsoft.com/kb/243330 for details.

      Null                        = 'S-1-0'
      Nobody                      = 'S-1-0-0'
      World                       = 'S-1-1'
      Everyone                    = 'S-1-1-0'
      Local                       = 'S-1-2'
      Creator                     = 'S-1-3'
      CreatorOwner                = 'S-1-3-0'
      CreatorGroup                = 'S-1-3-1'
      CreatorOwnerServer          = 'S-1-3-2'
      CreatorGroupServer          = 'S-1-3-3'
      NonUnique                   = 'S-1-4'
      Nt                          = 'S-1-5'
      Dialup                      = 'S-1-5-1'
      Network                     = 'S-1-5-2'
      Batch                       = 'S-1-5-3'
      Interactive                 = 'S-1-5-4'
      Service                     = 'S-1-5-6'
      Anonymous                   = 'S-1-5-7'
      Proxy                       = 'S-1-5-8'
      EnterpriseDomainControllers = 'S-1-5-9'
      PrincipalSelf               = 'S-1-5-10'
      AuthenticatedUsers          = 'S-1-5-11'
      RestrictedCode              = 'S-1-5-12'
      TerminalServerUsers         = 'S-1-5-13'
      LocalSystem                 = 'S-1-5-18'
      NtLocal                     = 'S-1-5-19'
      NtNetwork                   = 'S-1-5-20'
      BuiltinAdministrators       = 'S-1-5-32-544'
      BuiltinUsers                = 'S-1-5-32-545'
      Guests                      = 'S-1-5-32-546'
      PowerUsers                  = 'S-1-5-32-547'
      AccountOperators            = 'S-1-5-32-548'
      ServerOperators             = 'S-1-5-32-549'
      PrintOperators              = 'S-1-5-32-550'
      BackupOperators             = 'S-1-5-32-551'
      Replicators                 = 'S-1-5-32-552'

      # The binary SID object itself.
      attr_reader :sid

      # The account name passed to the constructor.
      attr_reader :account

      # The SID account type, e.g. 'user, 'group', etc.
      attr_reader :account_type

      # The domain the SID is on.
      attr_reader :domain

      # The host passed to the constructor, or the localhost if none
      # was specified.
      attr_reader :host

      # Converts a binary SID to a string in S-R-I-S-S... format.
      #
      def self.sid_to_string(sid)
        string_sid = FFI::MemoryPointer.new(:pointer)

        unless ConvertSidToStringSid(sid, string_sid)
          raise SystemCallError.new("ConvertSidToStringSid", FFI.errno)
        end

        string_sid.read_pointer.read_string
      end

      # Converts a string in S-R-I-S-S... format back to a binary SID.
      #
      def self.string_to_sid(string)
        sid = FFI::MemoryPointer.new(:pointer)

        unless ConvertStringSidToSid(string, sid)
          raise SystemCallError.new("ConvertStringSidToSid", FFI.errno)
        end

        ptr = sid.read_pointer

        ptr.read_bytes(GetLengthSid(ptr))
      end

      # Creates a new SID with +authority+ and up to 8 +subauthorities+,
      # and returns new Win32::Security::SID object.
      #
      # Example:
      #
      #    sec = Security::SID.create(
      #       Security::SID::SECURITY_WORLD_SID_AUTHORITY,
      #       Security::SID::SECURITY_WORLD_RID
      #    )
      #
      #    p sec
      #
      #    #<Win32::Security::SID:0x2c5a95c
      #       @host="your_host",
      #       @account="Everyone",
      #       @account_type="well known group",
      #       @sid="\001\001\000\000\000\000\000\001\000\000\000\000",
      #       @domain=""
      #    >
      #
      def self.create(authority, *sub_authorities)
        if sub_authorities.length > 8
          raise ArgumentError, "maximum of 8 subauthorities allowed"
        end

        size = GetSidLengthRequired(sub_authorities.length)
        sid  = FFI::MemoryPointer.new(:uchar, size)

        auth = SID_IDENTIFIER_AUTHORITY.new
        auth[:Value][5] = authority

        unless InitializeSid(sid, auth, sub_authorities.length)
          raise SystemCallError.new("InitializeSid", FFI.errno)
        end

        sub_authorities.each_index do |i|
          ptr = GetSidSubAuthority(sid, i)
          ptr.write_ulong(sub_authorities[i])
        end

        new(sid.read_string(size)) # Pass a binary string
      end

      # Creates and returns a new Win32::Security::SID object, based on
      # the account name, which may also be a binary SID. If a host is
      # provided, then the information is retrieved from that host.
      # Otherwise, the local host is used.
      #
      # If no account is provided then it retrieves information for the
      # user account associated with the calling thread and the host argument
      # is ignored.
      #
      # Note that this does NOT create a new SID, but merely retrieves
      # information for an existing SID. To create a new SID, use the
      # SID.create method.
      #
      # Examples:
      #
      #  # Current user
      #  Win32::Security::SID.new
      #
      #  # User 'john' on the localhost
      #  Win32::Security::SID.new('john')
      #
      #  # User 'jane' on a remote machine
      #  Win32::Security::SID.new('jane', 'some_host')
      #
      #  # Binary SID
      #  Win32::Security::SID.new("\001\000\000\000\000\000\001\000\000\000\000")
      #
      def initialize(account=nil, host=Socket.gethostname)
        if account.nil?
          begin
            ptoken = FFI::MemoryPointer.new(:uintptr_t)

            # Try the thread token first, default to the process token.
            bool = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, ptoken)

            if !bool && FFI.errno != ERROR_NO_TOKEN
              raise SystemCallError.new("OpenThreadToken", FFI.errno)
            else
              ptoken = FFI::MemoryPointer.new(:uintptr_t)
              unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ptoken)
                raise SystemCallError.new("OpenProcessToken", FFI.errno)
              end
            end

            token = ptoken.read_pointer.to_i
            pinfo = FFI::MemoryPointer.new(:pointer)
            plength = FFI::MemoryPointer.new(:ulong)

            # First pass, just get the size needed (1 is TokenOwner)
            GetTokenInformation(token, 1, pinfo, pinfo.size, plength)

            pinfo = FFI::MemoryPointer.new(plength.read_ulong)
            plength = FFI::MemoryPointer.new(:ulong)

            # Second pass, actual call (1 is TokenOwner)
            unless GetTokenInformation(token, 1, pinfo, pinfo.size, plength)
              raise SystemCallError.new("GetTokenInformation", FFI.errno)
            end

            token_info = pinfo.read_pointer
          ensure
            CloseHandle(token) if token
          end
        end

        if account
          ordinal_val = account[0]
          ordinal_val = ordinal_val.ord if RUBY_VERSION.to_f >= 1.9
        else
          ordinal_val = nil
        end

        sid = FFI::MemoryPointer.new(:uchar, 260)
        sid_size = FFI::MemoryPointer.new(:ulong)
        sid_size.write_ulong(sid.size)

        domain = FFI::MemoryPointer.new(:uchar, 260)
        domain_size = FFI::MemoryPointer.new(:ulong)
        domain_size.write_ulong(domain.size)

        use_ptr = FFI::MemoryPointer.new(:ulong)

        if ordinal_val.nil?
          bool = LookupAccountSid(
            nil,
            token_info,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )
          unless bool
            raise SystemCallError.new("LookupAccountSid", FFI.errno)
          end
        elsif ordinal_val < 10 # Assume it's a binary SID.
          account_ptr = FFI::MemoryPointer.from_string(account)
          bool = LookupAccountSid(
            host,
            account_ptr,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )
          unless bool
            raise SystemCallError.new("LookupAccountSid", FFI.errno)
          end
        else
          bool = LookupAccountName(
            host,
            account,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )
          unless bool
            raise SystemCallError.new("LookupAccountName", FFI.errno)
          end
        end

        # The arguments are flipped depending on which path we took
        if ordinal_val.nil?
          @sid = token_info.read_string
          @account = sid.read_string(sid.size).strip
        elsif ordinal_val < 10
          @sid     = account
          @account = sid.read_string(sid.size).strip
        else
          length = GetLengthSid(sid)
          @sid     = sid.read_string(length)
          @account = account
        end

        @host   = host
        @domain = domain.read_string

        @account_type = get_account_type(use_ptr.read_ulong)
      end

      # Synonym for SID.new.
      #
      def self.open(account=nil, host=Socket.gethostname)
        new(account, host)
      end

      # Returns the binary SID in string format suitable for display,
      # storage or transmission.
      #
      def to_s
        ptr = FFI::MemoryPointer.new(:pointer)

        unless ConvertSidToStringSid(@sid, ptr)
          raise SystemCallError.new("ConvertSidToStringSid", FFI.errno)
        end

        ptr.read_pointer.read_string
      end

      alias to_str to_s

      # Returns whether or not the SID object is equal to +other+.
      #
      def ==(other)
        EqualSid(@sid, other.sid)
      end

      # Returns whether or not the SID is a valid sid.
      #
      def valid?
        IsValidSid(@sid)
      end

      # Returns whether or not the SID is a well known SID.
      #
      # Requires Windows XP or later. Earlier versions will raise a
      # NoMethodError.
      #
      def well_known?
        if defined? IsWellKnownSid
          IsWellKnownSid(@sid)
        else
          raise NoMethodError, 'requires Windows XP or later'
        end
      end

      # Returns the length of the SID object, in bytes.
      #
      def length
        GetLengthSid(@sid)
      end

      private

      # Converts a numeric account type into a human readable string.
      #
      def get_account_type(value)
        case value
          when SidTypeUser
            'user'
          when SidTypeGroup
            'group'
          when SidTypeDomain
            'domain'
          when SidTypeAlias
            'alias'
          when SidTypeWellKnownGroup
            'well known group'
          when SidTypeDeletedAccount
            'deleted account'
          when SidTypeInvalid
            'invalid'
          when SidTypeUnknown
            'unknown'
          when SidComputer
            'computer'
        end
      end
    end
  end
end
