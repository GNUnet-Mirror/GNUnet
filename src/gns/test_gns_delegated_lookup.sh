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

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
MY_EGO="myego"
OTHER_EGO="delegatedego"
FINAL_LABEL="www"
DELEGATION_LABEL="b"

TEST_IP="127.0.0.1"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $OTHER_EGO -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep $OTHER_EGO | awk '{print $3}')
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $DELEGATION_LABEL -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $OTHER_EGO -a -n $FINAL_LABEL -t A -V $TEST_IP -e never -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u $FINAL_LABEL.$DELEGATION_LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-namestore -z $OTHER_EGO -d -n $FINAL_LABEL -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_IP" == "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
