# The Win32 module serves as a namespace only.
module Win32
   
  # The Security class serves as a toplevel class namespace.
  class Security
      
    # The ACE class encapsulates an Access Control Entry, an element within
    # an Access Control List.
    class ACE
      # The version of the Win32::Security::ACE class.
      VERSION = '0.1.0'

      # The ACE type, e.g. ACCESS_ALLOWED, ACCESS_DENIED, etc.
      attr_accessor :ace_type

      # The ACE mask, e.g. INHERITED_ACE
      attr_accessor :ace_mask

      # Standard access rights, e.g. GENERIC_READ, GENERIC_WRITE, etc 
      attr_accessor :access_mask

      # Bit flags that indicate whether the ObjectType and
      # InheritedObjectType members are present. This value is set
      # internally based on the values passed to the ACE#object_type or
      # ACE#inherited_object_type methods, if any.
      attr_reader :flags

      # A Win32::Security::GUID object that identifies the type of child
      # object that can inherit the ACE. 
      attr_accessor :object_type

      attr_accessor :inherited_object_type

      def initialize
        yield self if block_given?
      end
    end
  end
end
