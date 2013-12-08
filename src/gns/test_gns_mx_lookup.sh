#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX" 
	exit 77
fi

rm -fr `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

TEST_MX="5,mail.gnu"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n www -t MX -V "$TEST_MX" -e never -c test_gns_lookup.conf

RES_MX=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.gnu -t MX -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n www -t MX -V "$TEST_MX" -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_MX" == "$TEST_MX" ]
then
  exit 0
else
  echo "FAIL: did not get proper IP, got $RES_MX."
  exit 1
fi
