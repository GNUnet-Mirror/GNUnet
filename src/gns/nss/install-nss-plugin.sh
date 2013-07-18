#!/bin/sh
# $1 - shell
# $2 - top_builddir
# $3 - nssdir
# $4 - sudo binary (empty if root)
$4 $1 $2/libtool --mode=finish $3
echo LTINST: $4 $1 $2/libtool --mode=finish $3
$4 rm -f $3/libnss_gns.la $3/libnss_gns4.la $3/libnss_gns6.la
