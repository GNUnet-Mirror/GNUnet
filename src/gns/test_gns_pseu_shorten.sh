#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

rm -rf `gnunet-config -c test_gns_lookup.conf -s PATHS -o SERVICEHOME`
TEST_IP="127.0.0.1"
TEST_PSEU="alice"
TEST_NAME="www.mybestfriendalice.gnu"
TEST_NAME_SHORT="www.alice.short.gnu"
gnunet-arm -s -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
gnunet-identity -c test_gns_lookup.conf -d 
gnunet-identity -C short-zone -c test_gns_lookup.conf
gnunet-identity -C delegatedego -c test_gns_lookup.conf
gnunet-identity -e short-zone -s gns-short -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf -c test_gns_lookup.conf
DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
SHORT=$(gnunet-identity -c test_gns_lookup.conf -d | grep short-zone | awk '{print $3}')
gnunet-namestore -p -z testego -a -n mybestfriendalice -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf
gnunet-namestore -p -z testego -a -n short -t PKEY -V $SHORT -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf
gnunet-namestore -p -z delegatedego -a -n "+" -t PSEU -V $TEST_PSEU -e never -c test_gns_lookup.conf
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_NAME -t A -c test_gns_lookup.conf`
RES_IP_PSEU=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.alice.short.gnu -t A -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n b -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" == "$TEST_IP" ]
then
  echo "$TEST_NAME resolved , got $RES_IP."
else
  echo "Failed to resolve $TEST_NAME to proper IP, got $RES_IP."
  exit 1
fi

if [ "$RES_IP_PSEU" == "$TEST_IP" ]
then
  echo "$TEST_NAME_SHORT resolved , got $RES_IP."
  exit 0
else
  echo "Failed to resolve $TEST_NAME_SHORT to proper IP, got $RES_IP_PSEU."
  exit 1
fi
