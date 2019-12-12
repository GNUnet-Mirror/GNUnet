#!/bin/sh
trap "gnunet-arm -e -c test_gns_lookup.conf" INT

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
# IP address of 'docs.gnunet.org'
TEST_IP_ALT2="147.87.255.218"
# IP address of 'www.gnunet.org'
TEST_IP="131.159.74.67"
# IPv6 address of 'gnunet.org'
TEST_IP6="2001:4ca0:2001:42:225:90ff:fe6b:d60"
# permissive DNS resolver we will use for the test
TEST_IP_GNS2DNS="8.8.8.8"

# main label used during resolution
TEST_RECORD_NAME="homepage"

if ! nslookup gnunet.org $TEST_IP_GNS2DNS > /dev/null 2>&1
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi

# helper record for pointing to the DNS resolver
TEST_RESOLVER_LABEL="resolver"

MY_EGO="myego"
# various names we will use for resolution
TEST_DOMAIN="www.${TEST_RECORD_NAME}.$MY_EGO"
TEST_DOMAIN_ALT="${TEST_RECORD_NAME}.$MY_EGO"
TEST_DOMAIN_ALT2="docs.${TEST_RECORD_NAME}.$MY_EGO"

which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 15"


gnunet-arm -s -c test_gns_lookup.conf

OUT=`$DO_TIMEOUT gnunet-resolver -c test_gns_lookup.conf gnunet.org`
echo $OUT | grep $TEST_IP - > /dev/null || { gnunet-arm -e -c test_gns_lookup.conf ; echo "IPv4 for gnunet.org not found ($OUT), skipping test"; exit 77; }
echo $OUT | grep $TEST_IP6 - > /dev/null || { gnunet-arm -e -c test_gns_lookup.conf ; echo "IPv6 for gnunet.org not found ($OUT), skipping test"; exit 77; }



gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
MY_EGO_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep ${MY_EGO} | awk '{print $3}')
# GNS2DNS record value: delegate to DNS domain 'gnunet.org'
# using the TEST_RESOLVER_LABEL DNS server for resolution
TEST_RECORD_GNS2DNS="gnunet.org@${TEST_RESOLVER_LABEL}.${MY_EGO_PKEY}"

# set IP address for DNS resolver for resolving in gnunet.org domain
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RESOLVER_LABEL -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
# map '$TEST_RECORD_NAME.$MY_EGO' to 'gnunet.org' in DNS
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf

# lookup 'www.gnunet.org', IPv4
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN -t A -c test_gns_lookup.conf`
# lookup 'www.gnunet.org', IPv6
RES_IP6=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN -t AAAA -c test_gns_lookup.conf`
# lookup 'gnunet.org', IPv4
RES_IP_ALT=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_ALT -t A -c test_gns_lookup.conf`
# lookup 'docs.gnunet.org', IPv4
RES_IP_ALT2=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_ALT2 -t A -c test_gns_lookup.conf`

# clean up
gnunet-namestore -z $MY_EGO -d -n $TEST_RESOLVER_LABEL -t A -V $TEST_IP_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $TEST_RECORD_NAME -t GNS2DNS -V $TEST_RECORD_GNS2DNS -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

ret=0
if echo "$RES_IP" | grep "$TEST_IP" > /dev/null
then
  echo "PASS: Resolved $TEST_DOMAIN to $RES_IP."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN, got $RES_IP, wanted $TEST_IP."
  ret=1
fi

if [ "$RES_IP6" = "$TEST_IP6" ]
then
  echo "PASS: Resolved $TEST_DOMAIN to $RES_IP6."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN, got $RES_IP6, wanted $TEST_IP6."
  ret=1
fi

if echo "$RES_IP_ALT" | grep "$TEST_IP" > /dev/null
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT to $RES_IP_ALT."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT, got $RES_IP_ALT, wanted $TEST_IP."
  ret=1
fi

if echo "$RES_IP_ALT2" | grep "$TEST_IP_ALT2" > /dev/null
then
  echo "PASS: Resolved $TEST_DOMAIN_ALT2 to $RES_IP_ALT2."
else
  echo "Failed to resolve to proper IP for $TEST_DOMAIN_ALT2, got $RES_IP_ALT2, wanted $TEST_IP_ALT2."
  ret=1
fi
exit $ret
