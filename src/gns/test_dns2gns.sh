#!/bin/bash
# This file is in the public domain.
trap "gnunet-arm -e -c test_dns2gns.conf" INT
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"

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

rm -rf `gnunet-config -c test_dns2gns.conf -f -s paths -o GNUNET_TEST_HOME`
MY_EGO="localego"
TEST_IP="127.0.0.1"
TEST_IPV6="dead::beef"
LABEL="fnord"
TEST_DOMAIN="gnunet.org"

gnunet-arm -s -c test_dns2gns.conf
PKEY=`gnunet-identity -V -C $MY_EGO -c test_dns2gns.conf`
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t A -V $TEST_IP -e 3600s -c test_dns2gns.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t AAAA -V $TEST_IPV6 -e 3600s -c test_dns2gns.conf

# FIXME resolution works but always returns all available records
# also, the records seem to be returned twice if using GNS

if nslookup -port=12000 $LABEL.$PKEY localhost && nslookup -port=12000 $LABEL.$MY_EGO localhost; then
  echo "PASS: GNS records can be resolved using dns2gns bridge"
else
  echo "FAIL: GNS records can't be resolved using dns2gns bridge"
  rm -rf `gnunet-config -c test_dns2gns.conf -f -s paths -o GNUNET_TEST_HOME`
  exit 1
fi

if nslookup -port=12000 gnunet.org localhost; then
  echo "PASS: DNS records can be resolved using dns2gns bridge"
else
  echo "FAIL: DNS records can't be resolved using dns2gns bridge"
  rm -rf `gnunet-config -c test_dns2gns.conf -f -s paths -o GNUNET_TEST_HOME`
  exit 1
fi
gnunet-arm -e -c test_dns2gns.conf

rm -rf `gnunet-config -c test_dns2gns.conf -f -s paths -o GNUNET_TEST_HOME`
