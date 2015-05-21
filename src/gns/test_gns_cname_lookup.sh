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

# permissive DNS resolver we will use for the test
DNS_RESOLVER="8.8.8.8"
if ! nslookup gnunet.org $DNS_RESOLVER &> /dev/null
then
  echo "Cannot reach DNS, skipping test"
  exit 77
fi


rm -rf /tmp/test-gnunet-gns-peer-1/

TEST_DOMAIN_PLUS="www.gnu"
TEST_DOMAIN_DNS="www3.gnu"
TEST_IP_PLUS="127.0.0.1"
TEST_IP_DNS="131.159.74.67"
TEST_RECORD_CNAME_SERVER="server"
TEST_RECORD_CNAME_PLUS="server.+"
TEST_RECORD_CNAME_DNS="gnunet.org"
TEST_RECORD_NAME_SERVER="server"
TEST_RECORD_NAME_PLUS="www"
TEST_RECORD_NAME_DNS="www3"
which timeout &> /dev/null && DO_TIMEOUT="timeout 15"

gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME_DNS -t CNAME -V $TEST_RECORD_CNAME_DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME_PLUS -t CNAME -V $TEST_RECORD_CNAME_PLUS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n $TEST_RECORD_CNAME_SERVER -t A -V $TEST_IP_PLUS -e never -c test_gns_lookup.conf
RES_CNAME=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN_PLUS -t A -c test_gns_lookup.conf`
RES_CNAME_RAW=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN_PLUS -t CNAME -c test_gns_lookup.conf`
RES_CNAME_DNS=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_DOMAIN_DNS -t A -c test_gns_lookup.conf`
TESTEGOZONE=`gnunet-identity -c test_gns_lookup.conf -d | awk '{print $3}'`
gnunet-namestore -p -z testego -d -n $TEST_RECORD_NAME_DNS -t CNAME -V $TEST_RECORD_CNAME_DNS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -d -n $TEST_RECORD_NAME_PLUS -t CNAME -V $TEST_RECORD_CNAME_PLUS -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -d -n $TEST_RECORD_CNAME_SERVER -t A -V $TEST_IP_PLUS -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "$RES_CNAME_RAW" == "server.$TESTEGOZONE.zkey" ]
then
  echo "PASS: CNAME resulution from GNS"
else
  echo "FAIL: CNAME resolution from GNS, got $RES_CNAME_RAW, expected server.$TESTEGOZONE.zkey."
  exit 1
fi

if [ "$RES_CNAME" == "$TEST_IP_PLUS" ]
then
  echo "PASS: IP resulution from GNS"
else
  echo "FAIL: IP resolution from GNS, got $RES_CNAME, expected $TEST_IP_PLUS."
  exit 1
fi

if [ "$RES_CNAME_DNS" == "$TEST_IP_DNS" ]
then
  echo "PASS: IP resulution from DNS"
  exit 0
else
  echo "FAIL: IP resulution from DNS, got $RES_IP, expected $TEST_IP_DNS."
  exit 1
fi
