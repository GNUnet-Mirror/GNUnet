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

MY_EGO="myego"
OTHER_EGO="delegatedego"


rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"
TEST_IP="127.0.0.1"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-identity -C $OTHER_EGO -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep $OTHER_EGO | awk '{print $3}')
gnunet-arm -i gns -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
# Give GNS/namestore time to fully start and finish initial iteration
sleep 2
# Performing namestore update
gnunet-namestore -p -z $OTHER_EGO -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
# Give GNS chance to observe store event via monitor
sleep 1
gnunet-namestore -z $OTHER_EGO -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
# give GNS chance to process monitor event
sleep 1
# stop everything and restart to check that DHT PUT did happen
gnunet-arm -k gns -c test_gns_lookup.conf
gnunet-arm -k namestore -c test_gns_lookup.conf
gnunet-arm -k namecache -c test_gns_lookup.conf
gnunet-arm -k zonemaster -c test_gns_lookup.conf
# Purge nameacache, as we might otherwise fetch from there
# FIXME: testcase started failing after the line below was fixed by adding '-f',
# might have never worked (!)
rm -r `gnunet-config -f -c test_gns_lookup.conf -s namecache-sqlite -o FILENAME`
gnunet-arm -i namestore -c test_gns_lookup.conf
gnunet-arm -i namecache -c test_gns_lookup.conf
gnunet-arm -i zonemaster -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u www.b.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-identity -D $OTHER_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_IP" = "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to properly resolve IP, expected $TEST_IP, got $RES_IP."
  exit 1
fi
