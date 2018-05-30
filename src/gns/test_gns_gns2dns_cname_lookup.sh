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

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
# IP address of 'www.gnunet.org'
TEST_IP="131.159.74.67"
# IPv6 address of 'gnunet.org'
TEST_IP6="2001:4ca0:2001:42:225:90ff:fe6b:d60"

# main label used during resolution
TEST_RECORD_NAME="homepage"

XNS=ns.joker.com

if ! nslookup gnunet.org a.$XNS &> /dev/null
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi

# helper record for pointing to the DNS resolver
TEST_RESOLVER_LABEL="resolver"
# GNS2DNS record value: delegate to DNS domain 'gnunet.org'
# using the TEST_RESOLVER_LABEL DNS server for resolution
TEST_RECORD_GNS2DNS1="gnunet.org@a.$XNS"
TEST_RECORD_GNS2DNS2="gnunet.org@b.$XNS"
TEST_RECORD_GNS2DNS3="gnunet.org@c.$XNS"

MY_EGO="myego"
# various names we will use for resolution
TEST_DOMAIN="www.${TEST_RECORD_NAME}.$MY_EGO"

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf

# set IP address for DNS resolver for resolving in gnunet.org domain
# map '$TEST_RECORD_NAME.$MY_EGO' to 'gnunet.org' in DNS
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS1 -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS2 -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS3 -e never -c test_gns_lookup.conf

which timeout &> /dev/null && DO_TIMEOUT="timeout 15"

echo "EGOs:"
gnunet-identity -d

# lookup 'www.gnunet.org', IPv4
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN -t A -c test_gns_lookup.conf`
# lookup 'www.gnunet.org', IPv6
RES_IP6=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN -t AAAA -c test_gns_lookup.conf`

# clean up
gnunet-namestore -z $MY_EGO -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS1 -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS2 -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS3 -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

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

exit $ret
