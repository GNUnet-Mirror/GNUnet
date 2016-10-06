#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"

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

TEST_NAME="dave.bob.alice.gnu"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C bobego -c test_gns_lookup.conf
BOB_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep bob | awk '{print $3}')
gnunet-identity -C daveego -c test_gns_lookup.conf
DAVE_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep dave | awk '{print $3}')
gnunet-identity -C aliceego -c test_gns_lookup.conf
ALICE_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep alice | awk '{print $3}')
gnunet-identity -C testego -c test_gns_lookup.conf
ROOT_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep testego | awk '{print $3}')
gnunet-namestore -p -z testego -a -n alice -t PKEY -V $ALICE_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z aliceego -a -n bob -t PKEY -V $BOB_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z aliceego -a -n + -t REVERSE -V "alice $ROOT_PKEY 0" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z bobego -a -n dave -t PKEY -V $DAVE_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z bobego -a -n + -t REVERSE -V "bob $ALICE_PKEY 0" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z daveego -a -n + -t REVERSE -V "dave $BOB_PKEY 0" -e never -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
sleep 0.5
RES_NAME=`$DO_TIMEOUT gnunet-gns --raw -z testego -R $DAVE_PKEY -c test_gns_lookup.conf`
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "$RES_NAME" == "$TEST_NAME" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
