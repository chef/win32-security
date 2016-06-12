== 0.5.0 - 12-Jun-2016
* Changed license to Apache 2.0.
* Fixed a bug in the SID class where arguments weren't encoded properly
  in Ruby 1.9.x and 2.0.x.

== 0.4.1 - 9-May-2016
* Added the ffi-win32-extensions dependency, and removed the helper file.
* The SID.new method is now a bit more flexible with regards to failures of
  the OpenThreadToken function. It now just defaults to OpenProcessToken no
  matter what, if it can.
* The Security.elevated_security? method is now more robust, using a double
  pass approach.
* The above fixes were mainly to resolve issues on cygwin64. Thanks go to
  Tobias Hochgürtel and Wouter Scheele for raising the issues and providing
  providing patches (for both this library and cygwin64 + ffi).

== 0.4.0 - 7-Mar-2016
* Added wide character support. Thanks go to Ethan J. Brown for finally forcing
  me to get around to this.
* Removed some unused FFI functions.
* Added the String#wstrip helper method if not already defined.

== 0.3.3 - 1-Mar-2016
* Fixed a potential bug in the Win32::Security::SID constructor. Thanks go
  to nmeilick for the spot and patch.
* This gem now requires Ruby 1.9.3 or later.
* Added some SID tests.

== 0.3.2 - 4-Dec-2015
* This gem is now signed.
* Added a win32-security.rb file for convenience.
* The gem related tasks in the Rakefile now assume Rubygems 2.x.
* Fixed a function and struct prototype.

== 0.3.1 - 8-Dec-2014
* Work around a bug in 64-bit JRuby, which doesn't handle uintptr_t properly.

== 0.3.0 - 31-Oct-2014
* Implemented an ACL class that lets you create and inspect acccess
  control lists.
* Implemented a basic ACE class that encapsulates an ACE object.
* Removed Windows XP support.
* Some minor updates to the Rakefile and gemspec.

== 0.2.5 - 24-Feb-2014
* Fixed a bug in the SID#string_to_sid method. Thanks go to Rob Reynolds
  for the spot.

== 0.2.4 - 8-Nov-2013
* Added rake as a development dependency.
* Attempted to make FFI related constants and structs more private.
* Updated the gem:create task for Rubygems 2.

== 0.2.3 - 27-Jun-2013
* Fixed a bug where a sid could be inappropriately stripped. Thanks
  go to Josh Cooper for the spot.

== 0.2.2 - 8-Apr-2013
* Fixed HANDLE prototypes in the underlying FFI code. This affected
  64 bit versions of Ruby.

== 0.2.1 - 19-Feb-2013
* Removed a trailing comma that was causing problems.

== 0.2.0 - 11-Jan-2013
* Converted the code to FFI.
* Refactored some of the tests.

= 0.1.4 - 4-Oct-2012
* Updated the SID.string_to_sid method so that it completes a string/sid
  round trip successfully now. Thanks go to Josh Cooper for the patch.

= 0.1.3 - 12-Jul-2012
* The SID.new method now defaults to the owner of the current thread if
  no account name is provided.
* Updates to the gemspec, Rakefile, and SID tests, including updates to
  some of the gemspec dependencies.

= 0.1.2 - 2-Aug-2009
* Now compatible with Ruby 1.9.x.
* Switched test-unit and sys-admin from standard dependencies to development
  dependencies.

= 0.1.1 - 14-Jul-2009
* Added some well known SID's as constants to the Win32::Security::SID class
  for convenience, e.g. SID::World, SID::Everyone.
* Fixes for the gemspec.
* Changed license to Artistic 2.0.

= 0.1.0 - 17-Dec-2008
* Initial release
