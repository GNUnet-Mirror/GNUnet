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
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
TEST_TXT="GNS powered txt record data"
MY_EGO="myego"
LABEL="testtxt"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
RES_TXT=`$DO_TIMEOUT gnunet-gns --raw -u $LABEL.$MY_EGO -t TXT -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $LABEL -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_TXT" == "$TEST_TXT" ]
then
  exit 0
else
  echo "Failed to resolve to proper TXT, got '$RES_TXT'."
  exit 1
fi
