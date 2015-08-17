# vim:syntax=apparmor
# Last Modified: Tue Aug 11 11:17:17 2015
#include <tunables/global>
#include <tunables/gnunet>

profile @{GNUNET_PREFIX}/bin/gnunet-download-manager.scm {
  #include <abstractions/base>
  #include <abstractions/bash>

  /dev/tty rw,

  @{HOME}/.cache/guile/ccache/*-LE-*@{GNUNET_PREFIX}/bin/gnunet-download-manager.scm.go.* rw,

  @{PROC}/@{pid}/statm r,

  /usr/bin/bash ix,
  /usr/bin/guile rix,

  @{GNUNET_PREFIX}/bin/gnunet-download-manager.scm r,

  /usr/share/guile/**/*.scm r,

  # Site-specific additions and overrides. See local/README for details.
  #include <local/gnunet>
}
