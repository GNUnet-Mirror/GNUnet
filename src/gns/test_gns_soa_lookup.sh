#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version &> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf /tmp/test-gnunet-gns-peer-1/
TEST_DOMAIN="homepage.gnu"
# some public DNS resolver we can use
TEST_IP_GNS2DNS="184.172.157.218"
TEST_RECORD_NAME="homepage"
TEST_RECORD_GNS2DNS="gnunet.org"

if ! nslookup $TEST_RECORD_GNS2DNS $TEST_IP_GNS2DNS &> /dev/null
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t GNS2DNS -V ${TEST_RECORD_GNS2DNS}@${TEST_IP_GNS2DNS} -e never -c test_gns_lookup.conf
RES_SOA=$(timeout 5 gnunet-gns --raw -z testego -u $TEST_DOMAIN -t SOA -c test_gns_lookup.conf)
gnunet-namestore -z testego -d -n $TEST_RECORD_NAME -t GNS2DNS -V ${TEST_RECORD_GNS2DNS}@${TEST_IP_GNS2DNS} -e never -c test_gns_lookup.conf &> /dev/null
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "x$RES_SOA" != "x" ]
then
  echo "PASS: Resolved SOA for $TEST_DOMAIN to $RES_SOA."
  exit 0
else
  echo "Failed to resolve to proper SOA for $TEST_DOMAIN, got no result."
  exit 1
fi
