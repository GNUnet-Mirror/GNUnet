#!/bin/bash
trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
which timeout &> /dev/null && DO_TIMEOUT="timeout 30"

# This test tests shortening functionality based on NICK records:
# 
# zone "delegatedego": Alice's zone
# zone "testego": Local zone with delegation to alice

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX" 
	exit 1
fi

# Deleting home directory from previous runs
rm -rf `gnunet-config -c test_gns_lookup.conf -s PATHS -o GNUNET_HOME -f`
TEST_IP="127.0.0.1"
TEST_IP="127.0.0.2"
TEST_NICK_EGO="ego"
TEST_NICK_DELEGATED="alice"
TEST_NAME="www.mybestfriendalice.gnu"
TEST_NAME_SHORT="www.alice.short.gnu"

# Start gnunet
gnunet-arm -s -c test_gns_lookup.conf

DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')

# Create initial identities: short-zone, delegated-zone, testego
gnunet-identity -c test_gns_lookup.conf -d
gnunet-identity -C short-zone -c test_gns_lookup.conf
gnunet-identity -C delegatedego -c test_gns_lookup.conf
gnunet-identity -e short-zone -s gns-short -c test_gns_lookup.conf
gnunet-identity -C testego -c test_gns_lookup.conf

# We should set NICKs here
gnunet-namestore -z testego -i $TEST_NICK_EGO -c test_gns_lookup.conf
gnunet-namestore -z delegatedego -i $TEST_NICK_DELEGATED -c test_gns_lookup.conf

DELEGATED_PKEY=$(gnunet-identity -d -c test_gns_lookup.conf | grep delegatedego | awk '{print $3}')
SHORT=$(gnunet-identity -c test_gns_lookup.conf -d | grep short-zone | awk '{print $3}')

# Delegate the name "mybestfriendalice" to alice
gnunet-namestore -p -z testego -a -n mybestfriendalice -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_lookup.conf

# Delegate the name "short" to shortenzone
gnunet-namestore -p -z testego -a -n short -t PKEY -V $SHORT -e never -c test_gns_lookup.conf
# Adding label mail in ego's zone zone 
gnunet-namestore -p -z testego  -a -n mail -t A -V $TEST_IP -e never -c test_gns_lookup.conf

# Adding label www in Alice's delegatedego zone 
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e never -c test_gns_lookup.conf

# Delete namecache content
gnunet-arm -c test_gns_lookup.conf -k namecache
rm -rf `gnunet-config -c test_gns_lookup.conf -s namecache-sqlite -o FILENAME`

# Force start of GNS
gnunet-arm -c test_gns_lookup.conf -i gns

# need to sleep here, to give PSEU record chance to be copied to DHT
sleep 1
RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_NAME -t A -c test_gns_lookup.conf`

# need to sleep here, as shortening happens asynchronously...
sleep 1
RES_IP_PSEU=`$DO_TIMEOUT gnunet-gns --raw -z testego -u www.alice.short.gnu -t A -c test_gns_lookup.conf`
gnunet-namestore -z testego -d -n mybestfriendalice -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_lookup.conf

gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e never -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf

if [ "$RES_IP" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_NAME properly to $RES_IP."
else
  echo "FAIL: Could not resolve $TEST_NAME to proper IP, got $RES_IP."
  exit 1
fi

if [ "$RES_IP_PSEU" == "$TEST_IP" ]
then
  echo "PASS: Resolved $TEST_NAME_SHORT properly to $RES_IP."
  exit 0
else
  echo "FAIL: Could not resolve $TEST_NAME_SHORT to proper IP, got $RES_IP_PSEU."
  exit 1
fi  