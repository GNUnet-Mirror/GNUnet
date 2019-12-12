#!/bin/sh
# This file is in the public domain.
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

# permissive DNS resolver we will use for the test
DNS_RESOLVER="8.8.8.8"
if ! nslookup gnunet.org $DNS_RESOLVER > /dev/null 2>&1
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi


rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

TEST_IP_PLUS="127.0.0.1"
TEST_IP_DNS="131.159.74.67"
TEST_RECORD_CNAME_SERVER="server"
TEST_RECORD_CNAME_PLUS="server.+"
TEST_RECORD_CNAME_DNS="gnunet.org"
TEST_RECORD_NAME_SERVER="server"
TEST_RECORD_NAME_PLUS="www"
TEST_RECORD_NAME_ZKEY="www2"
TEST_RECORD_NAME_DNS="www3"
MY_EGO="myego"
TEST_DOMAIN_PLUS="www.$MY_EGO"
TEST_DOMAIN_ZKEY="www2.$MY_EGO"
TEST_DOMAIN_DNS="www3.$MY_EGO"
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 15"

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
MY_EGO_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep ${MY_EGO} | awk '{print $3}')
TEST_RECORD_CNAME_ZKEY="server.${MY_EGO_PKEY}"
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME_DNS -t CNAME -V $TEST_RECORD_CNAME_DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME_PLUS -t CNAME -V $TEST_RECORD_CNAME_PLUS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_NAME_ZKEY -t CNAME -V $TEST_RECORD_CNAME_ZKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $TEST_RECORD_CNAME_SERVER -t A -V $TEST_IP_PLUS -e never -c test_gns_lookup.conf
RES_CNAME=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_PLUS -t A -c test_gns_lookup.conf`
RES_CNAME_RAW=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_PLUS -t CNAME -c test_gns_lookup.conf`
RES_CNAME_ZKEY=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_ZKEY -t A -c test_gns_lookup.conf`
RES_CNAME_DNS=`$DO_TIMEOUT gnunet-gns --raw -u $TEST_DOMAIN_DNS -t A -c test_gns_lookup.conf | grep $TEST_IP_DNS`

TESTEGOZONE=`gnunet-identity -c test_gns_lookup.conf -d | awk '{print $3}'`
gnunet-namestore -p -z $MY_EGO -d -n $TEST_RECORD_NAME_DNS -t CNAME -V $TEST_RECORD_CNAME_DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -d -n $TEST_RECORD_NAME_PLUS -t CNAME -V $TEST_RECORD_CNAME_PLUS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -d -n $TEST_RECORD_NAME_ZKEY -t CNAME -V $TEST_RECORD_CNAME_ZKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -d -n $TEST_RECORD_CNAME_SERVER -t A -V $TEST_IP_PLUS -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

# make cmp case-insensitive by converting to lower case first
RES_CNAME_RAW=`echo $RES_CNAME_RAW | tr [A-Z] [a-z]`
TESTEGOZONE=`echo $TESTEGOZONE | tr [A-Z] [a-z]`
if [ "$RES_CNAME_RAW" = "server.$TESTEGOZONE" ]
then
  echo "PASS: CNAME resolution from GNS"
else
  echo "FAIL: CNAME resolution from GNS, got $RES_CNAME_RAW, expected server.$TESTEGOZONE."
  exit 1
fi

if [ "$RES_CNAME" = "$TEST_IP_PLUS" ]
then
  echo "PASS: IP resolution from GNS (.+)"
else
  echo "FAIL: IP resolution from GNS (.+), got $RES_CNAME, expected $TEST_IP_PLUS."
  exit 1
fi

if [ "$RES_CNAME_ZKEY" = "$TEST_IP_PLUS" ]
then
  echo "PASS: IP resolution from GNS (.zkey)"
else
  echo "FAIL: IP resolution from GNS (.zkey), got $RES_CNAME, expected $TEST_IP_PLUS."
  exit 1
fi

if echo "$RES_CNAME_DNS" | grep "$TEST_IP_DNS" > /dev/null
then
  echo "PASS: IP resolution from DNS"
  exit 0
else
  echo "FAIL: IP resolution from DNS, got $RES_CNAME_DNS, expected $TEST_IP_DNS."
  exit 1
fi
