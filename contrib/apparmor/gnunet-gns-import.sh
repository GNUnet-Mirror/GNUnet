# Last Modified: Tue Aug 11 10:19:01 2015
#include <tunables/global>
#include <tunables/gnunet>

profile @{GNUNET_PREFIX}/bin/gnunet-gns-import.sh {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/gnunet-common>

  /dev/tty rw,
  /usr/bin/bash ix,
  /usr/bin/gawk rix,
  /usr/bin/grep rix,
  /usr/bin/which rix,
  @{GNUNET_PREFIX}/bin/gnunet-arm Px,
  @{GNUNET_PREFIX}/bin/gnunet-config rPx,
  @{GNUNET_PREFIX}/bin/gnunet-gns-import.sh r,
  @{GNUNET_PREFIX}/bin/gnunet-identity Px,

  # Site-specific additions and overrides. See local/README for details.
  #include <local/gnunet>
}
