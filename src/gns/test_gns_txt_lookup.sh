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

rm -rf /tmp/test-gnunet-gns-peer-1/
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
TEST_TXT="GNS powered txt record data"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n testtxt -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
RES_TXT=`$DO_TIMEOUT gnunet-gns --raw -z testego -u testtxt.gnu -t TXT -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n testtxt -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

if [ "$RES_TXT" == "$TEST_TXT" ]
then
  exit 0
else
  echo "Failed to resolve to proper TXT, got '$RES_TXT'."
  exit 1
fi
