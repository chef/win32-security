module Windows
  module Security
    module Constants
      TOKEN_QUERY = 8
      ERROR_NO_TOKEN = 1008

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
