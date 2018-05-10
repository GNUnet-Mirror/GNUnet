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

MY_EGO="myego"
OTHER_EGO="delegatedego"

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
TEST_IP="127.0.0.1"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-identity -C $OTHER_EGO -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep $OTHER_EGO | awk '{print $3}')
gnunet-namestore -p -z $MY_EGO -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $OTHER_EGO -a -n www -t A -V $TEST_IP -e '5 s' -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
# confirm that lookup currently works
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u www.b.$MY_EGO -t A -c test_gns_lookup.conf`
# remove entry
gnunet-namestore -z $OTHER_EGO -d -n www -t A -V $TEST_IP  -e '5 s' -c test_gns_lookup.conf
# wait for old entry with 5s 'expiration' to definitively expire
sleep 6
# try again, should no longer work
RES_IP_EXP=`$DO_TIMEOUT gnunet-gns --raw -u www.b.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-identity -D $OTHER_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

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
