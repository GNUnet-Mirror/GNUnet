#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
rm -r `gnunet-config -c test_gns_lookup.conf -s PATHS -o SERVICEHOME`
TEST_DOMAIN="www.homepage.gnu"
TEST_DOMAIN_ALT="homepage.gnu"
TEST_DOMAIN_ALT2="uk.homepage.gnu"
TEST_IP_ALT2="81.187.252.184"
TEST_IP="131.159.74.67"
TEST_IP_GNS2DNS="184.172.157.218"
TEST_RECORD_NAME="homepage"
TEST_RECORD_GNS2DNS="gnunet.org"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf
RES_IP=$(timeout 5 gnunet-gns --raw -z testego -u $TEST_DOMAIN -t A -c test_gns_lookup.conf)
RES_IP_ALT=$(timeout 5 gnunet-gns --raw -z testego -u $TEST_DOMAIN_ALT -t A -c test_gns_lookup.conf)
RES_IP_ALT2=$(timeout 5 gnunet-gns --raw -z testego -u $TEST_DOMAIN_ALT2 -t A -c test_gns_lookup.conf)
gnunet-namestore -z testego -d -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
gnunet-namestore -z testego -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_DOMAIN to $RES_IP."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN, got $RES_IP, wanted $TEST_IP."
  exit 1
fi

if [ "$RES_IP_ALT" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT to $RES_IP_ALT."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT, got $RES_IP_ALT, wanted $TEST_IP."
  exit 1
fi

if [ "$RES_IP_ALT2" == "$TEST_IP_ALT2" ]
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT2 to $RES_IP_ALT2."
  exit 0
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT2, got $RES_IP_ALT2, wanted $TEST_IP_ALT2."
  exit 1
fi
