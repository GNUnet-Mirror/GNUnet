#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
rm -r `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
TEST_DOMAIN="homepage.gnu"
TEST_IP_GNS2DNS="184.172.157.218"
TEST_RECORD_NAME="homepage"
TEST_RECORD_GNS2DNS="gnunet.org"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf
RES_SOA=$(timeout 5 gnunet-gns --raw -z testego -u $TEST_DOMAIN -t SOA -c test_gns_lookup.conf)
gnunet-namestore -z testego -d -n $TEST_RECORD_NAME -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-namestore -z testego -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf &> /dev/null
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "x$RES_SOA" != "x" ]
then
  echo "PASS: Resolved SOA for $TEST_DOMAIN to $RES_SOA."
  exit 0
else
  echo "Failed to resolve to proper SOA for $TEST_DOMAIN, got no result."
  exit 1
fi
