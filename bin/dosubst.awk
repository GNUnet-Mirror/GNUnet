# Dedicated to the public domain.
# SPDX-License-Identifier: 0BSD
#
# awk script to substitute variables in scripts and applications.
#
# You can pass these variables to it in Makefiles or on the
# commandline:
#  bdir="$(bindir)"
#  py="$(PYTHON)"
#  awkay="$(AWK_BINARY)"
#  pfx="$(prefix)"
#  prl="$(PERL)"
#  sysconfdirectory="$(sysconfdir)"
#  pkgdatadirectory="$(pkgdatadir)"

{

  if (/@bindirectory@/) {
    gsub("@bindirectory@",bdir) ;
  }

  if (/@PYTHONEXE@/) {
    gsub("@PYTHONEXE@",py) ;
  }

  if (/@AWKEXE@/) {
    gsub("@AWKEXE@",awkay) ;
  }

  if (/@SUBSTPREFIX@/) {
    gsub("@SUBSTPREFIX@",pfx) ;
  }

  if (/@PERLEXE@/) {
    gsub("@PERLEXE@",prl) ;
  }

  if (/@SYSCONFDIR@/) {
    gsub("@SYSCONFDIR@",sysconfdirectory) ;
  }

  if (/@PKGDATADIRECTORY@/) {
    gsub("@PKGDATADIRECTORY@",pkgdatadirectory) ;
  }

  print $0 ;
}
