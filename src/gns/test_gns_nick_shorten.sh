#!/bin/bash
trap "gnunet-arm -e -c test_gns_nick_shorten.conf" SIGINT
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

# This test tests shortening functionality based on NICK records:
#
# zone "delegatedego": Alice's zone
# zone "testego": Local zone with delegation to alice

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version &> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

# Deleting home directory from previous runs
TEST_CONFIG="test_gns_nick_shorten.conf "
rm -rf /tmp/test-gnunet-gns-peer-1/
TEST_IP="127.0.0.1"
TEST_IP="127.0.0.2"
TEST_NICK_EGO="ego"
TEST_NICK_DELEGATED="alice"
TEST_NAME="www.mybestfriendalice.gnu"
TEST_NAME_SHORT="www.alice.short.gnu"

# export GNUNET_FORCE_LOG="namestore;;;;DEBUG/gns;;;;DEBUG/;;;;WARNING"

# Start gnunet
echo "Starting arm with configuration $TEST_CONFIG"
gnunet-arm -s -c $TEST_CONFIG

# Create initial identities: short-zone, delegated-zone, testego
echo "Creating identities"
gnunet-identity -d -c $TEST_CONFIG
gnunet-identity -C short-zone -c $TEST_CONFIG
gnunet-identity -C delegatedego -c $TEST_CONFIG
gnunet-identity -e short-zone -s gns-short -c $TEST_CONFIG
gnunet-identity -C testego -c $TEST_CONFIG

echo "Adding nick names for identities"
gnunet-namestore -z testego -i $TEST_NICK_EGO -c $TEST_CONFIG
gnunet-namestore -z delegatedego -i $TEST_NICK_DELEGATED -c $TEST_CONFIG

# Adding label www in Alice's delegatedego zone
echo "Adding www record with IP $TEST_IP"
gnunet-namestore -p -z delegatedego -a -n www -t A -V $TEST_IP -e never -c test_gns_nick_shorten.conf

# Retrieve PKEYs for delegation
DELEGATED_PKEY=$(gnunet-identity -d -c $TEST_CONFIG| grep delegatedego | awk '{print $3}')
echo "Alice's PKEY is $DELEGATED_PKEY"

SHORTEN_PKEY=$(gnunet-identity -c test_gns_nick_shorten.conf -d | grep short-zone | awk '{print $3}')
echo "Shorten PKEY is $SHORTEN_PKEY"

# Delegate the name "short" to shortenzone
gnunet-namestore -p -z testego -a -n short -t PKEY -V $SHORTEN_PKEY -e never -c test_gns_nick_shorten.conf

# Delegate the name "mybestfriendalice" to alice
gnunet-namestore -p -z testego -a -n mybestfriendalice -t PKEY -V $DELEGATED_PKEY -e never -c test_gns_nick_shorten.conf

# Perform lookup to shorten
echo "Start gns..."
gnunet-arm -c test_gns_nick_shorten.conf -i gns


RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_NAME -t A -c test_gns_nick_shorten.conf`

sleep 1

echo "Lookup shortened names"
PKEY_SHORT_RES=$($DO_TIMEOUT gnunet-gns --raw -c test_gns_nick_shorten.conf -z short-zone -u alice.gnu -t PKEY)
echo "Resolving alice's PKEY in shorten zone: $PKEY_SHORT_RES"
PKEY_RES=$($DO_TIMEOUT gnunet-gns --raw -c test_gns_nick_shorten.conf -z testego -u alice.short.gnu -t PKEY)
echo "Resolving alice's PKEY in master zone: $PKEY_RES"

RES=0
if [ "$DELEGATED_PKEY" == "$PKEY_SHORT_RES" ]
then
  echo "PASS: Resolved delegation for shorten name in shortened zone"
else
  echo "FAIL: Expected PKEY in $DELEGATED_PKEY, received PKEY '$PKEY_SHORT_RES' in shorten zone."
  RES=1
fi

if [ "$DELEGATED_PKEY" == "$PKEY_RES" ]
then
  echo "PASS: Resolved delegation for shorten name in master zone"
else
  echo "FAIL: Expected PKEY in $DELEGATED_PKEY, received PKEY $PKEY_SHORT_RES in master zone."
  RES=1
fi

if [ $RES -eq 0 ]
then
	RES_IP=`$DO_TIMEOUT gnunet-gns --raw -z testego -u $TEST_NAME_SHORT -t A -c test_gns_nick_shorten.conf`
	if [ "$RES_IP" == "$TEST_IP" ]
	then
		echo "PASS: Received $TEST_IP for $TEST_NAME_SHORT"
	else
		echo "FAIL: Expected IP in $TEST_IP, received IP '$RES_IP' for $TEST_SHORT_NAME."
		RES=1
	fi
fi


# Clean up
echo "Clean up..."
gnunet-namestore -z testego -d -n mybestfriendalice -t PKEY -V $DELEGATED_PKEY  -e never -c test_gns_nick_shorten.conf
gnunet-namestore -z delegatedego -d -n www -t A -V $TEST_IP  -e never -c test_gns_nick_shorten.conf
gnunet-identity -D -z testego -c $TEST_CONFIG
gnunet-identity -D -z delegatedego -c $TEST_CONFIG
gnunet-identity -D -z short-zone -c $TEST_CONFIG

gnunet-arm -e -c test_gns_nick_shorten.conf
rm -rf /tmp/test-gnunet-gns-peer-1/

exit $RES

