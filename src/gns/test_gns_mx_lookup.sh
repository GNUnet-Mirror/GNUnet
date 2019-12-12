#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" INT

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

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"

MY_EGO="myego"
TEST_MX="5,mail.+"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
PKEY=`gnunet-identity -d | grep "$MY_EGO - " | awk '{print $3'}`
WANT_MX="5,mail.$PKEY"
gnunet-namestore -p -z $MY_EGO -a -n www -t MX -V "$TEST_MX" -e never -c test_gns_lookup.conf

RES_MX=`$DO_TIMEOUT gnunet-gns --raw -u www.$MY_EGO -t MX -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n www -t MX -V "$TEST_MX" -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

# make cmp case-insensitive by converting to lower case first
RES_MX=`echo $RES_MX | tr [A-Z] [a-z]`
WANT_MX=`echo $WANT_MX | tr [A-Z] [a-z]`

if [ "$RES_MX" = "$WANT_MX" ]
then
  exit 0
else
  echo "FAIL: did not get proper IP, got $RES_MX, expected $WANT_MX."
  exit 1
fi
