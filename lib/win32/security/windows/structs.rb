require 'ffi'

module Windows
  module Security
    module Structs
      extend FFI::Library

      private

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

      class ACE_HEADER < FFI::Struct
        layout(
          :AceType, :uchar,
          :AceFlags, :uchar,
          :AceSize, :ushort
        )
      end

      class ACCESS_ALLOWED_ACE < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong
        )
      end

      class ACCESS_ALLOWED_ACE2 < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong,
          :dummy, [:uchar, 40]
        )
      end

      class ACL_STRUCT < FFI::Struct
        layout(
          :AclRevision, :uchar,
          :Sbz1, :uchar,
          :AclSize, :ushort,
          :AceCount, :ushort,
          :Sbz2, :ushort
        )
      end

      class ACL_SIZE_INFORMATION < FFI::Struct
        layout(
          :AceCount, :ulong,
          :AclBytesInUse, :ulong,
          :AceBytesFree, :ulong
        )
      end
    end
  end
end
