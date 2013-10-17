#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
rm -r `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
TEST_IP="127.0.0.1"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf
gnunet-identity -C delegatedego -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
gnunet-namestore -p -z testego -a -n b -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e '2 s' -c test_gns_lookup.conf
gnunet-arm -i gns -c test_gns_lookup.conf
sleep 1
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e '2 s' -c test_gns_lookup.conf
sleep 8
RES_IP_EXP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.b.gnu -t A -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-identity -D testego -c test_gns_lookup.conf
gnunet-identity -D delegatedego -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP_EXP" == "$TEST_IP" ]
then
  echo "Failed to properly expire IP, got $RES_IP_EXP."
  exit 1
fi
