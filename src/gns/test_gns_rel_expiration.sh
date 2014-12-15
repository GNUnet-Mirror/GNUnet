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
gnunet-namestore -p -z testego -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e '5 s' -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
# confirm that lookup currently works
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.b.gnu -t A -c test_gns_lookup.conf`
# remove entry
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e '5 s' -c test_gns_lookup.conf
# wait for old entry with 5s 'expiration' to definitively expire
sleep 6
# try again, should no longer work
RES_IP_EXP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.b.gnu -t A -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-identity -D delegatedego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "$RES_IP_EXP" == "$TEST_IP" ]
then
  echo "Failed to properly expire IP, got $RES_IP_EXP."
  exit 1
fi

if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to properly resolve IP, got $RES_IP."
  exit 1
fi
