module Windows
  module Security
    module Constants
      TOKEN_QUERY = 8
      ERROR_NO_TOKEN = 1008

      SECURITY_NT_AUTHORITY = 5
      SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
      DOMAIN_ALIAS_RID_ADMINS = 0x00000220

      ACL_REVISION = 2
      AclSizeInformation = 2

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
