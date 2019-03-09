#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
TEST_IP="127.0.0.1"
MY_EGO="myego"
LABEL="www"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t A -V $TEST_IP -e never -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u $LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $LABEL -t A -V $TEST_IP -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" = "$TEST_IP" ]
then
  exit 0
else
  echo "FAIL: Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
