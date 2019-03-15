#!/bin/sh
# This file is in the public domain.
# test -z being correct was a false assumption here.
# I have no executable 'fooble', but this will
# return 1:
# if test -z "`which fooble`"; then echo 1; fi
# The command builtin might not work with busybox's ash
# but this works for now.
existence()
{
    command -v "$1" >/dev/null 2>&1
}

LOCATION=`existence gnunet-config`
if test -z $LOCATION; then
    LOCATION="gnunet-config"
fi
$LOCATION --version
if test $? != 0
then
    echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX" 
    exit 77
fi

trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
ME=`whoami`
if [ "$ME" != "root" ]
then
  echo "This test only works if run as root.  Skipping."
  exit 77
fi
export PATH=".:$PATH"
gnunet-service-gns -c gns.conf &
sleep 1
LO=`nslookup alice.gnu | grep Address | tail -n1`
if [ "$LO" != "Address: 1.2.3.4" ]
then
 echo "Fail: $LO"
fi
LO=`nslookup www.bob.gnu | grep Address | tail -n1`
if [ "$LO" != "Address: 4.5.6.7" ]
then
  echo "Fail: $LO"
fi
# XXX: jobs. a builtin by bash, netbsd sh, maybe leave it be for now.
kill `jobs -p`
