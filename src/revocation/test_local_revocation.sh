#!/bin/bash
TEST_CONFIGURATION="test_revocation.conf"
TEST_REVOCATION_EGO="revoc_test"

which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
trap "gnunet-arm -e -c test_revocation.conf" SIGINT

# clean up
rm -rf `gnunet-config -c test_revocation.conf -s PATHS -o GNUNET_HOME -f`

# Start 
gnunet-arm -s -c $TEST_CONFIGURATION
gnunet-identity -C $TEST_REVOCATION_EGO -c $TEST_CONFIGURATION
TEST_REVOCATION_KEY=$(gnunet-identity -d | awk '{split($0,a," "); print a[3]}')

echo Testing key $TEST_REVOCATION_KEY
OUTPUT_NOT_REVOKED=$(gnunet-revocation -t $TEST_REVOCATION_KEY -c $TEST_CONFIGURATION )

echo Revoking key $TEST_REVOCATION_KEY
gnunet-revocation -R $TEST_REVOCATION_EGO -p -c $TEST_CONFIGURATION 1> /dev/null 2> /dev/null

echo Testing revoked key $TEST_REVOCATION_KEY
OUTPUT_REVOKED=$(gnunet-revocation -t $TEST_REVOCATION_KEY -c $TEST_CONFIGURATION)

#clean up
gnunet-arm -e -c test_revocation.conf
rm -rf `gnunet-config -c test_revocation.conf -s PATHS -o GNUNET_HOME -f`
