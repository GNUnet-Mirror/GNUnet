#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
rm -r `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"
TEST_TXT="GNS powered txt record data"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n testtxt -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
RES_TXT=`$DO_TIMEOUT gnunet-gns --raw -z testego -u testtxt.gnu -t TXT -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n testtxt -t TXT -V "$TEST_TXT" -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_TXT" == "$TEST_TXT" ]
then
  exit 0
else
  echo "Failed to resolve to proper TXT, got '$RES_TXT'."
  exit 1
fi
