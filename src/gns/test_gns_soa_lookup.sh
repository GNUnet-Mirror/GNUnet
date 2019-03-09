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

which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
MY_EGO="myego"
TEST_DOMAIN="homepage.$MY_EGO"
# some public DNS resolver we can use
TEST_IP_GNS2DNS="184.172.157.218"
TEST_RECORD_NAME="homepage"
TEST_RECORD_GNS2DNS="gnunet.org"

if ! nslookup $TEST_RECORD_GNS2DNS $TEST_IP_GNS2DNS > /dev/null 2>&1
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME -t GNS2DNS -V ${TEST_RECORD_GNS2DNS}@${TEST_IP_GNS2DNS} -e never -c test_gns_lookup.conf
RES_SOA=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN -t SOA -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $TEST_RECORD_NAME -t GNS2DNS -V ${TEST_RECORD_GNS2DNS}@${TEST_IP_GNS2DNS} -e never -c test_gns_lookup.conf > /dev/null 2>&1
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "x$RES_SOA" != "x" ]
then
  echo "PASS: Resolved SOA for $TEST_DOMAIN to $RES_SOA."
  exit 0
else
  echo "Failed to resolve to proper SOA for $TEST_DOMAIN, got no result."
  exit 1
fi
