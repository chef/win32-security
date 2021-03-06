# win32-security gem

[![Gem Version](https://badge.fury.io/rb/win32-security.svg)](https://badge.fury.io/rb/win32-security)

A security library for MS Windows that allows you to open existing or
create new security identifiers (SID's), as well as create access
control lists (ACL's) and access control entries (ACE's).

## Usage

```ruby
require 'win32/security'
include Win32

sid = Security::SID.open('some_user')

sid.valid? # => true
sid.to_s   # => "S-1-5-21-3733855671-1102023144-2002619019-1000"
sid.length # => 28
sid.sid    # => "\001\005\000\000\000\000\000\005\025\000\000\000..."

acl = Security::ACL.new
mask = Security::ACL::GENERIC_READ | Security::ACL::GENERIC_WRITE

acl.add_access_allowed_ace('some_user', mask)
acl.add_access_denied_ace('some_user', Security::ACL::GENERIC_EXECUTE)

acl.acl_count # => 2
acl.valid?    # => true
```

## Known Issues

There appears to be an issue with 64-bit versions of JRuby. I believe it
is related to this issue: https://github.com/jruby/jruby/issues/1315. There
is nothing I can do about it here.

Please file any other bug reports on the project page at:

https://github.com/djberg96/win32-security

## License

Apache 2.0

## Copyright

(C) 2003-2016 Daniel J. Berger
All Rights Reserved

## Authors

- Daniel J. Berger
- Park Heesob
