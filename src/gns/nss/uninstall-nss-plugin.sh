#!/bin/bash
# $1 - shell
# $2 - top_builddir
# $3 - nssdir+path of library to remove
# $4 - sudo binary (empty if root)
$4 $1 $2/libtool --mode=uninstall $3


