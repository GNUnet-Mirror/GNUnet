#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
rm -r `gnunet-config -c test_gns_lookup.conf -s PATHS -o SERVICEHOME`
TEST_MX="mail.gnunet"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n gnunet -t MX -V $TEST_MX -e never -c test_gns_lookup.conf
RES_MX=$(timeout 5 gnunet-gns --raw -z testego -u www.gnu -t MX -c test_gns_lookup.conf)
gnunet-namestore -z testego -d -n www -t MX -V $TEST_MX -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_MX" == "$TEST_MX" ]
then
  exit 0
else
  echo "Failed to resolve to proper IP, got $RES_MX."
  exit 1
fi
