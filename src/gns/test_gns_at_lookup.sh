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

which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

TEST_IP="127.0.0.1"
MY_EGO="myego"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C delegatedego -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n '@' -t A -V $TEST_IP -e never -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u b.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-namestore -z delegatedego -d -n '@' -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
