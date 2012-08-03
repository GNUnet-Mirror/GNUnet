#!/bin/bash
# $1 - sudo binary (empty if root)
# $2 - shell
# $3 - top_builddir
# $4 - nssdir
if [ "`whoami`" = "root" ]; then
  $1 $2/libtool --finish $3
  rm -f $3/libnss_gns.la $3/libnss_gns4.la $3/libnss_gns6.la
else
  $1 $2 $3/libtool --finish $4
  $1 rm -f $4/libnss_gns.la $4/libnss_gns4.la $4/libnss_gns6.la
fi

