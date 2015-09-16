require 'ffi'

module Windows
  module Security
    module Functions
      extend FFI::Library

      private

      # Wrapper method for attach_function + private
      def self.attach_pfunc(*args)
        attach_function(*args)
        private args[0]
      end

      typedef :ulong, :dword
      typedef :pointer, :ptr

      # Work around a bug in 64-bit JRuby
      if RUBY_PLATFORM == 'java' && ENV_JAVA['sun.arch.data.model'] == '64'
        typedef :ulong_long, :handle
      else
        typedef :uintptr_t, :handle
      end

      ffi_lib :kernel32
      ffi_convention :stdcall

      enum :well_known_sid_type, [
        :WinNullSid, 0,
        :WinWorldSid,
        :WinLocalSid,
        :WinCreatorOwnerSid,
        :WinCreatorGroupSid,
        :WinCreatorOwnerServerSid,
        :WinCreatorGroupServerSid,
        :WinNtAuthoritySid,
        :WinDialupSid,
        :WinNetworkSid,
        :WinBatchSid,
        :WinInteractiveSid,
        :WinServiceSid,
        :WinAnonymousSid,
        :WinProxySid,
        :WinEnterpriseControllersSid,
        :WinSelfSid,
        :WinAuthenticatedUserSid,
        :WinRestrictedCodeSid,
        :WinTerminalServerSid,
        :WinRemoteLogonIdSid,
        :WinLogonIdsSid,
        :WinLocalSystemSid,
        :WinLocalServiceSid,
        :WinNetworkServiceSid,
        :WinBuiltinDomainSid,
        :WinBuiltinAdministratorsSid,
        :WinBuiltinUsersSid,
        :WinBuiltinGuestsSid,
        :WinBuiltinPowerUsersSid,
        :WinBuiltinAccountOperatorsSid,
        :WinBuiltinSystemOperatorsSid,
        :WinBuiltinPrintOperatorsSid,
        :WinBuiltinBackupOperatorsSid,
        :WinBuiltinReplicatorSid,
        :WinBuiltinPreWindows2000CompatibleAccessSid,
        :WinBuiltinRemoteDesktopUsersSid,
        :WinBuiltinNetworkConfigurationOperatorsSid,
        :WinAccountAdministratorSid,
        :WinAccountGuestSid,
        :WinAccountKrbtgtSid,
        :WinAccountDomainAdminsSid,
        :WinAccountDomainUsersSid,
        :WinAccountDomainGuestsSid,
        :WinAccountComputersSid,
        :WinAccountControllersSid,
        :WinAccountCertAdminsSid,
        :WinAccountSchemaAdminsSid,
        :WinAccountEnterpriseAdminsSid,
        :WinAccountPolicyAdminsSid,
        :WinAccountRasAndIasServersSid,
        :WinNTLMAuthenticationSid,
        :WinDigestAuthenticationSid,
        :WinSChannelAuthenticationSid,
        :WinThisOrganizationSid,
        :WinOtherOrganizationSid,
        :WinBuiltinIncomingForestTrustBuildersSid,
        :WinBuiltinPerfMonitoringUsersSid,
        :WinBuiltinPerfLoggingUsersSid,
        :WinBuiltinAuthorizationAccessSid,
        :WinBuiltinTerminalServerLicenseServersSid,
        :WinBuiltinDCOMUsersSid,
        :WinBuiltinIUsersSid,
        :WinIUserSid,
        :WinBuiltinCryptoOperatorsSid,
        :WinUntrustedLabelSid,
        :WinLowLabelSid,
        :WinMediumLabelSid,
        :WinHighLabelSid,
        :WinSystemLabelSid,
        :WinWriteRestrictedCodeSid,
        :WinCreatorOwnerRightsSid,
        :WinCacheablePrincipalsGroupSid,
        :WinNonCacheablePrincipalsGroupSid,
        :WinEnterpriseReadonlyControllersSid,
        :WinAccountReadonlyControllersSid,
        :WinBuiltinEventLogReadersGroup,
        :WinNewEnterpriseReadonlyControllersSid,
        :WinBuiltinCertSvcDComAccessGroup,
        :WinMediumPlusLabelSid,
        :WinLocalLogonSid,
        :WinConsoleLogonSid,
        :WinThisOrganizationCertificateSid,
        :WinApplicationPackageAuthoritySid,
        :WinBuiltinAnyPackageSid,
        :WinCapabilityInternetClientSid,
        :WinCapabilityInternetClientServerSid,
        :WinCapabilityPrivateNetworkClientServerSid,
        :WinCapabilityPicturesLibrarySid,
        :WinCapabilityVideosLibrarySid,
        :WinCapabilityMusicLibrarySid,
        :WinCapabilityDocumentsLibrarySid,
        :WinCapabilitySharedUserCertificatesSid,
        :WinCapabilityEnterpriseAuthenticationSid,
        :WinCapabilityRemovableStorageSid
      ]

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

      attach_pfunc :GetCurrentProcess, [], :handle
      attach_pfunc :GetCurrentThread, [], :handle
      attach_pfunc :GetVersionExA, [:ptr], :bool
      attach_pfunc :GetLastError, [], :dword
      attach_pfunc :CloseHandle, [:dword], :bool

      ffi_lib :advapi32

      attach_pfunc :AddAce, [:ptr, :dword, :dword, :ptr, :dword], :bool
      attach_pfunc :AddAccessAllowedAce, [:ptr, :dword, :dword, :ptr], :bool
      attach_pfunc :AddAccessAllowedAceEx, [:ptr, :dword, :dword, :dword, :ptr], :bool
      attach_pfunc :AddAccessDeniedAce, [:ptr, :dword, :dword, :ptr], :bool
      attach_pfunc :AddAccessDeniedAceEx, [:ptr, :dword, :dword, :dword, :ptr], :bool
      attach_pfunc :AllocateAndInitializeSid, [:ptr, :int, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :ptr], :bool
      attach_pfunc :CheckTokenMembership, [:handle, :ptr, :ptr], :bool
      attach_pfunc :ConvertSidToStringSid, :ConvertSidToStringSidA, [:ptr, :ptr], :bool
      attach_pfunc :ConvertStringSidToSid, :ConvertStringSidToSidA, [:string, :ptr], :bool
      attach_pfunc :CreateWellKnownSid, [:well_known_sid_type, :ptr, :ptr, :ptr], :bool
      attach_pfunc :DeleteAce, [:ptr, :dword], :bool
      attach_pfunc :EqualSid, [:ptr, :ptr], :bool
      attach_pfunc :FindFirstFreeAce, [:ptr, :ptr], :bool
      attach_pfunc :GetAce, [:ptr, :dword, :ptr], :bool
      attach_pfunc :GetAclInformation, [:ptr, :ptr, :dword, :int], :bool
      attach_pfunc :GetLengthSid, [:ptr], :dword
      attach_pfunc :GetSidLengthRequired, [:uint], :dword
      attach_pfunc :GetSidSubAuthority, [:ptr, :dword], :ptr
      attach_pfunc :GetTokenInformation, [:handle, :token_info_class, :ptr, :dword, :ptr], :bool
      attach_pfunc :InitializeAcl, [:ptr, :dword, :dword], :bool
      attach_pfunc :InitializeSid, [:ptr, :ptr, :uint], :bool
      attach_pfunc :IsValidAcl, [:ptr], :bool
      attach_pfunc :IsValidSid, [:ptr], :bool
      attach_pfunc :IsWellKnownSid, [:ptr, :int], :bool
      attach_pfunc :LookupAccountName, :LookupAccountNameA, [:string, :string, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupAccountSid, :LookupAccountSidA, [:string, :ptr, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :OpenProcessToken, [:handle, :dword, :ptr], :bool
      attach_pfunc :OpenThreadToken, [:handle, :dword, :bool, :ptr], :bool
      attach_pfunc :SetAclInformation, [:ptr, :ptr, :dword, :int], :bool

      attach_pfunc :ConvertSecurityDescriptorToStringSecurityDescriptor,
        :ConvertSecurityDescriptorToStringSecurityDescriptorA, [:ptr, :dword, :dword, :ptr, :ptr], :bool
      attach_pfunc :ConvertStringSecurityDescriptorToSecurityDescriptor,
        :ConvertStringSecurityDescriptorToSecurityDescriptorA, [:string, :dword, :ptr, :ptr], :bool
    end
  end
end
