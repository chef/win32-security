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

      class SID_IDENTIFIER_AUTHORITY < FFI::Struct
        layout(:Value, [:char, 6])
      end

      class OSVERSIONINFO < FFI::Struct
        layout(
          :dwOSVersionInfoSize, :ulong,
          :dwMajorVersion, :ulong,
          :dwMinorVersion, :ulong,
          :dwBuildNumber, :ulong,
          :dwPlatformId, :ulong,
          :szCSDVersion, [:char, 128]
        )
      end

      enum :token_info_class, [
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
      attach_pfunc :GetVersionExA, [:pointer], :bool
      attach_pfunc :GetLastError, [], :ulong
      attach_pfunc :CloseHandle, [:ulong], :bool

      ffi_lib :advapi32

      attach_pfunc :AllocateAndInitializeSid, [:pointer, :int, :ulong, :ulong, :ulong, :ulong, :ulong, :ulong, :ulong, :ulong, :pointer], :bool
      attach_pfunc :CheckTokenMembership, [:ulong, :pointer, :pointer], :bool
      attach_pfunc :ConvertSidToStringSid, :ConvertSidToStringSidA, [:pointer, :pointer], :bool
      attach_pfunc :ConvertStringSidToSid, :ConvertStringSidToSidA, [:string, :pointer], :bool
      attach_pfunc :EqualSid, [:pointer, :pointer], :bool
      attach_pfunc :GetLengthSid, [:pointer], :ulong
      attach_pfunc :GetSidLengthRequired, [:uint], :ulong
      attach_pfunc :GetSidSubAuthority, [:pointer, :ulong], :pointer
      attach_pfunc :GetTokenInformation, [:ulong, :token_info_class, :pointer, :ulong, :pointer], :bool
      attach_pfunc :InitializeSid, [:pointer, :pointer, :uint], :bool
      attach_pfunc :IsValidSid, [:pointer], :bool
      attach_pfunc :IsWellKnownSid, [:pointer, :int], :bool
      attach_pfunc :LookupAccountName, :LookupAccountNameA, [:string, :string, :pointer, :pointer, :pointer, :pointer, :pointer], :bool
      attach_pfunc :LookupAccountSid, :LookupAccountSidA, [:string, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :bool
      attach_pfunc :OpenProcessToken, [:ulong, :ulong, :pointer], :bool
      attach_pfunc :OpenThreadToken, [:ulong, :ulong, :bool, :pointer], :bool
    end
  end
end
