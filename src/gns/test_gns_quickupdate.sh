#!/bin/bash
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

rm -rf /tmp/test-gnunet-gns-peer-1/
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
TEST_IP="127.0.0.1"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-identity -C delegatedego -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
gnunet-arm -i gns -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
# Give GNS/namestore time to fully start and finish initial iteration
sleep 2
# Performing namestore update
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
# Give GNS chance to observe store event via monitor
sleep 1
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
# give GNS chance to process monitor event
sleep 1
# stop everything and restart to check that DHT PUT did happen
gnunet-arm -k gns -c test_gns_lookup.conf
gnunet-arm -k namestore -c test_gns_lookup.conf
gnunet-arm -k namecache -c test_gns_lookup.conf
# Purge nameacache, as we might otherwise fetch from there
rm -r `gnunet-config -c test_gns_lookup.conf -s namecache-sqlite -o FILENAME`
gnunet-arm -i namestore -c test_gns_lookup.conf
gnunet-arm -i namecache -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.b.gnu -t A -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-identity -D delegatedego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to properly resolve IP, got $RES_IP."
  exit 1
fi
