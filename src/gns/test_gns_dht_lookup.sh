#!/bin/bash
# This file is in the public domain.
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

TEST_IP="127.0.0.1"
MY_EGO="myego"
OTHER_EGO="delegatedego"

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
gnunet-arm -s -c test_gns_lookup.conf
gnunet-arm -i zonemaster -c test_gns_lookup.conf
gnunet-arm -i datastore -c test_gns_lookup.conf
gnunet-identity -C $OTHER_EGO -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep $OTHER_EGO | awk '{print $3}')
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
#This works
gnunet-namestore -p -z $OTHER_EGO -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
#This doesn't
gnunet-namestore -p -z $OTHER_EGO -a -n www2 -t A -V $TEST_IP -e '5 s' -c test_gns_lookup.conf
sleep 6
#gnunet-namestore -p -z $OTHER_EGO -d -n www2 -t A -V $TEST_IP -e '5 s' -c test_gns_lookup.conf
#gnunet-namestore -p -z $OTHER_EGO -a -n www2 -t A -V $TEST_IP -e '5 s' -c test_gns_lookup.conf
gnunet-arm -k zonemaster -c test_gns_lookup.conf
gnunet-arm -i zonemaster -c test_gns_lookup.conf
#gnunet-arm -r -c test_gns_lookup.conf
#gnunet-arm -i zonemaster
#gnunet-arm -i gns -c test_gns_lookup.conf
gnunet-arm -I -c test_gns_lookup.conf
#gnunet-identity -D $OTHER_EGO -c test_gns_lookup.conf
#gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
#gnunet-namestore -z $OTHER_EGO -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u www.b.$MY_EGO -t A -c test_gns_lookup.conf`
RES_IP_REL=`$DO_TIMEOUT gnunet-gns --raw -u www2.b.$MY_EGO -t A -c test_gns_lookup.conf`
#gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-arm -I -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_IP_REL" != "$TEST_IP" ]
then
  echo "Failed to resolve to proper IP, got $RES_IP_REL. (relative expiration)"
  #exit 1
fi
if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
