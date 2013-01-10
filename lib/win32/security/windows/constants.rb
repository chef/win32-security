module Windows
  module Security
    module Constants
      TOKEN_QUERY = 8
      ERROR_NO_TOKEN = 1008

      ACL_REVISION = 2
      AclSizeInformation = 2

      SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
      DOMAIN_ALIAS_RID_ADMINS = 0x00000220

      # Identifier Authorities

      SECURITY_NULL_SID_AUTHORITY         = 0
      SECURITY_WORLD_SID_AUTHORITY        = 1
      SECURITY_LOCAL_SID_AUTHORITY        = 2
      SECURITY_CREATOR_SID_AUTHORITY      = 3
      SECURITY_NON_UNIQUE_AUTHORITY       = 4
      SECURITY_NT_AUTHORITY               = 5
      SECURITY_RESOURCE_MANAGER_AUTHORITY = 9

      # SID types

      SidTypeUser           = 1
      SidTypeGroup          = 2
      SidTypeDomain         = 3
      SidTypeAlias          = 4
      SidTypeWellKnownGroup = 5
      SidTypeDeletedAccount = 6
      SidTypeInvalid        = 7
      SidTypeUnknown        = 8
      SidTypeComputer       = 9
    end
  end
end
