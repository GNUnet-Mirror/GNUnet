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
MY_EGO="myego"

rm -rf `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
CFG=`mktemp  --tmpdir=$PWD`
cp test_gns_lookup.conf $CFG || exit 77
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"
TEST_IP="dead::beef"
gnunet-arm -s -c $CFG || exit 77
gnunet-identity -C $MY_EGO -c $CFG 
EPUB=`gnunet-identity -d -c $CFG | grep $MY_EGO | awk '{print $3}'`
gnunet-arm -e -c $CFG
gnunet-config -c $CFG -s "gns" -o ".google.com" -V $EPUB
gnunet-arm -s -c $CFG
sleep 1
gnunet-namestore -p -z $MY_EGO -a -n www -t AAAA -V $TEST_IP -e never -c $CFG
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -u www.google.com -t AAAA -c $CFG`
gnunet-namestore -z $MY_EGO -d -n www -t AAAA -V $TEST_IP -e never -c $CFG
gnunet-identity -D $MY_EGO -c $CFG
gnunet-arm -e -c $CFG
rm -rf `gnunet-config -c $CFG -f -s paths -o GNUNET_TEST_HOME`
rm $CFG

if [ "$RES_IP" = "$TEST_IP" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_IP."
  exit 1
fi
