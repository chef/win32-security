require 'ffi'

module Windows
  module Security
    module Functions
      extend FFI::Library

      module FFI::Library
        # Wrapper method for attach_function + private
        def attach_pfunc(*args)
          attach_function(*args)
          private args[0]
        end
      end

      ffi_lib :kernel32

      enum :token_information_class, [
        :TokenUser, 1,
        :TokenGroups,
        :TokenPrivileges,
        :TokenOwner,
        :TokenPrimaryGroup,
        :TokenDefaultDacl,
        :TokenSource,
        :TokenType,
        :TokenImpersonationLevel,
        :TokenStatistics,
        :TokenRestrictedSids,
        :TokenSessionId,
        :TokenGroupsAndPrivileges,
        :TokenSessionReference,
        :TokenSandBoxInert,
        :TokenAuditPolicy,
        :TokenOrigin,
        :TokenElevationType,
        :TokenLinkedToken,
        :TokenElevation,
        :TokenHasRestrictions,
        :TokenAccessInformation,
        :TokenVirtualizationAllowed,
        :TokenVirtualizationEnabled,
        :TokenIntegrityLevel,
        :TokenUIAccess,
        :TokenMandatoryPolicy,
        :TokenLogonSid,
        :TokenIsAppContainer,
        :TokenCapabilities,
        :TokenAppContainerSid,
        :TokenAppContainerNumber,
        :TokenUserClaimAttributes,
        :TokenDeviceClaimAttributes,
        :TokenRestrictedUserClaimAttributes,
        :TokenRestrictedDeviceClaimAttributes,
        :TokenDeviceGroups,
        :TokenRestrictedDeviceGroups,
        :TokenSecurityAttributes,
        :TokenIsRestricted,
        :MaxTokenInfoClass
      ]

      attach_pfunc :GetCurrentProcess, [], :ulong
      attach_pfunc :CloseHandle, [:ulong], :bool

      ffi_lib :advapi32

      attach_pfunc :GetTokenInformation, [:ulong, :token_information_class, :pointer, :ulong, :pointer], :bool
      attach_pfunc :OpenProcessToken, [:ulong, :ulong, :pointer], :bool
    end
  end
end
