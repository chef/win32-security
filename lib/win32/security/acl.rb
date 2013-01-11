require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The ACL class encapsulates an Access Control List.
    class ACL
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      # The version of the Win32::Security::ACL class.
      VERSION = '0.2.0'

      # The underlying ACL structure.
      attr_reader :acl

      # The revision level.
      attr_reader :revision

      # Creates and returns a new Win32::Security::ACL object. This object
      # encapsulates an ACL structure, including a binary representation of
      # the ACL itself, and the revision information.
      #
      def initialize(revision = ACL_REVISION)
        acl = ACL_STRUCT.new

        unless InitializeAcl(acl, acl.size, revision)
          raise SystemCallError.new("InitializeAcl", FFI.errno)
        end

        @acl = acl
        @revision = revision
      end

      # Returns the number of ACE's in the ACL object.
      #
      def ace_count
        info = ACL_SIZE_INFORMATION.new

        unless GetAclInformation(@acl, info, info.size, AclSizeInformation)
          raise SystemCallError.new("GetAclInformation", FFI.errno)
        end

        info[:AceCount]
      end

      # Adds an access allowed ACE to the given +sid+. The +mask+ is a
      # bitwise OR'd value of access rights.
      #
      # TODO: Move this into the SID class?
      def add_access_allowed_ace(sid, mask=0)
        unless AddAccessAllowedAce(@acl, @revision, mask, sid)
          raise SystemCallError.new("AddAccessAllowedAce", FFI.errno)
        end
      end

      # Adds an access denied ACE to the given +sid+.
      #
      def add_access_denied_ace(sid, mask=0)
        unless AddAccessDeniedAce(@acl, @revision, mask, sid)
          raise SystemCallError.new("AddAccessDeniedAce", FFI.errno)
        end
      end

      # Adds an ACE to the ACL object with the given +revision+ at +index+
      # or the end of the chain if no index is specified.
      #
      # Returns the index if successful.
      #--
      # This is untested and will require an actual implementation of
      # Win32::Security::Ace before it can work properly.
      #
      def add_ace(ace, index=MAXDWORD)
        unless AddAce(@acl, @revision, index, ace, ace.length)
          raise SystemCallError.new("AddAce", FFI.errno)
        end

        index
      end

      # Deletes an ACE from the ACL object at +index+, or from the end of
      # the chain if no index is specified.
      #
      # Returns the index if successful.
      #--
      # This is untested and will require an actual implementation of
      # Win32::Security::Ace before it can work properly.
      #
      def delete_ace(index=MAXDWORD)
        unless DeleteAce(@ace, index)
          raise SystemCallError.new("DeleteAce", FFI.errno)
        end

        index
      end

      # Finds and returns a pointer (address) to an ACE in the ACL at the
      # given +index+. If no index is provided, then an address to the
      # first free byte of the ACL is returned.
      #
      def find_ace(index = nil)
        pptr = FFI::MemoryPointer.new(:pointer)

        if index.nil?
          unless FindFirstFreeAce(@acl, pptr)
            raise SystemCallError.new("DeleteAce", FFI.errno)
          end
        else
          unless GetAce(@acl, index, pptr)
            raise SystemCallError.new("GetAce", FFI.errno)
          end
        end

        pptr.read_pointer.address
      end

      # Sets the revision information level, where the +revision_level+
      # can be ACL_REVISION1, ACL_REVISION2, ACL_REVISION3 or ACL_REVISION4.
      #
      # Returns the revision level if successful.
      #
      def revision=(revision_level)
        buf = FFI::MemoryPointer.new(:ulong)
        buf.write_ulong(revision_level)

        unless SetAclInformation(@acl, buf, buf.size, AclRevisionInformation)
          raise SystemCallError.new("SetAclInformation", FFI.errno)
        end

        @revision = revision_level

        revision_level
      end

      # Returns whether or not the ACL is a valid ACL.
      #
      def valid?
        IsValidAcl(@acl)
      end
    end
  end
end
