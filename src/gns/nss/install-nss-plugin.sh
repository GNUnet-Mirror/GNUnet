#!/bin/bash
# $1 - sudo binary
# $2 - shell
# $3 - top_builddir
# $4 - nssdir
$1 $2 $3/libtool --finish $4
$1 rm -f $4/libnss_gns.la $4/libnss_gns4.la $4/libnss_gns6.la 
