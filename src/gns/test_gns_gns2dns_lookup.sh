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

rm -r rm -rf /tmp/test-gnunet-gns-peer-1/
# IP address of 'uk.gnunet.org'
TEST_IP_ALT2="81.187.252.184"
# IP address of 'www.gnunet.org'
TEST_IP="131.159.74.67"
# IPv6 address of 'gnunet.org'
TEST_IP6="2001:4ca0:2001:42:225:90ff:fe6b:d60"
# permissive DNS resolver we will use for the test
TEST_IP_GNS2DNS="8.8.8.8"

# main label used during resolution
TEST_RECORD_NAME="homepage"
# various names we will use for resolution
TEST_DOMAIN="www.${TEST_RECORD_NAME}.gnu"
TEST_DOMAIN_ALT="${TEST_RECORD_NAME}.gnu"
TEST_DOMAIN_ALT2="uk.${TEST_RECORD_NAME}.gnu"

if ! nslookup gnunet.org $TEST_IP_GNS2DNS &> /dev/null
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi

# helper record for pointing to the DNS resolver
TEST_RESOLVER_LABEL="resolver"
# GNS2DNS record value: delegate to DNS domain 'gnunet.org'
# using the TEST_RESOLVER_LABEL DNS server for resolution
TEST_RECORD_GNS2DNS="gnunet.org@${TEST_RESOLVER_LABEL}.+"

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf

# set IP address for DNS resolver for resolving in gnunet.org domain
gnunet-namestore -p -z testego -a -n $TEST_RESOLVER_LABEL -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
# map 'homepage.gnu' to 'gnunet.org' in DNS
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf

which timeout &> /dev/null && DO_TIMEOUT="timeout 15"

# lookup 'www.gnunet.org', IPv4
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN -t A -c test_gns_lookup.conf`
# lookup 'www.gnunet.org', IPv6
RES_IP6=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN -t AAAA -c test_gns_lookup.conf`
# lookup 'gnunet.org', IPv4
RES_IP_ALT=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN_ALT -t A -c test_gns_lookup.conf`
# lookup 'uk.gnunet.org', IPv4
RES_IP_ALT2=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN_ALT2 -t A -c test_gns_lookup.conf`

# clean up
gnunet-namestore -z testego -d -n $TEST_RESOLVER_LABEL -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-namestore -z testego -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

ret=0
if [ "$RES_IP" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_DOMAIN to $RES_IP."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN, got $RES_IP, wanted $TEST_IP."
  ret=1
fi

if [ "$RES_IP6" == "$TEST_IP6" ]
then
  echo "PASS: Resolved $TEST_DOMAIN to $RES_IP6."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN, got $RES_IP6, wanted $TEST_IP6."
  ret=1
fi

if [ "$RES_IP_ALT" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT to $RES_IP_ALT."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT, got $RES_IP_ALT, wanted $TEST_IP."
  ret=1
fi

if [ "$RES_IP_ALT2" == "$TEST_IP_ALT2" ]
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT2 to $RES_IP_ALT2."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT2, got $RES_IP_ALT2, wanted $TEST_IP_ALT2."
  ret=1
fi
exit $ret
