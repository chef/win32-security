require 'windows/security'
require 'windows/error'
require 'windows/limits'
require 'windows/msvcrt/buffer'

# The Win32 module serves as a namespace only.
module Win32
   
  # The Security class serves as a toplevel class namespace.
  class Security
      
    # The ACL class encapsulates an Access Control List.
    class ACL
      include Windows::Error
      include Windows::Security
      include Windows::Limits
      include Windows::MSVCRT::Buffer
         
      # The version of the Win32::Security::ACL class.
      VERSION = '0.1.0'

      # The binary representation of the ACL structure
      attr_reader :acl

      # The revision level.
      attr_reader :revision

      # Creates and returns a new Win32::Security::ACL object. This object
      # encapsulates an ACL structure, including a binary representation of
      # the ACL itself, and the revision information.
      #
      def initialize(revision = ACL_REVISION)
        acl = 0.chr * 8 # This can be increased later as needed

        unless InitializeAcl(acl, acl.size, revision)
          raise Error, get_last_error
        end

        @acl = acl
        @revision = revision
      end

      # Returns the number of ACE's in the ACL object.
      #
      def ace_count
        buf = 0.chr * 12 # sizeof(ACL_SIZE_INFORMATION)

        unless GetAclInformation(@acl, buf, buf.size, AclSizeInformation)
          raise Error, get_last_error
        end

        buf[0, 4].unpack('L')[0]
      end

      # Adds an access allowed ACE to the given +sid+. The +mask+ is a
      # bitwise OR'd value of access rights.
      #
      def add_access_allowed_ace(sid, mask=0)
        unless AddAccessAllowedAce(@acl, @revision, mask, sid)
          raise Error, get_last_error
        end
      end

      # Adds an access denied ACE to the given +sid+.
      #
      def add_access_denied_ace(sid, mask=0)
        unless AddAccessDeniedAce(@acl, @revision, mask, sid)
          raise Error, get_last_error
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
          raise Error, get_last_error
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
          raise Error, get_last_error
        end

        index
      end

      # Finds and returns a pointer (address) to an ACE in the ACL at the
      # given +index+. If no index is provided, then an address to the
      # first free byte of the ACL is returned.
      #
      def find_ace(index = nil)
        ptr = [0].pack('L')

        if index.nil?
          unless FindFirstFreeAce(@acl, ptr)
            raise Error, get_last_error
          end
        else
          unless GetAce(@acl, index, ptr)
            raise Error, get_last_error
          end
        end

        [ptr].pack('p*').unpack('L')[0]
      end

      # Sets the revision information level, where the +revision_level+
      # can be ACL_REVISION1, ACL_REVISION2, ACL_REVISION3 or ACL_REVISION4.
      #
      # Returns the revision level if successful.
      #
      def revision=(revision_level)
        buf = [revision_level].pack('L')

        unless SetAclInformation(@acl, buf, buf.size, AclRevisionInformation)
          raise Error, get_last_error
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
