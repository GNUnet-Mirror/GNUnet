#!/bin/bash
TEST_CONFIGURATION="test_revocation.conf"
TEST_REVOCATION_EGO="revoc_test"

which timeout &> /dev/null && DO_TIMEOUT="timeout 5"
trap "gnunet-arm -e -c test_revocation.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX" 
	exit 1
fi

# clean up
rm -rf `gnunet-config -c test_revocation.conf -s PATHS -o GNUNET_HOME -f`

# Start 
RES=0
gnunet-arm -s -c $TEST_CONFIGURATION
gnunet-identity -C $TEST_REVOCATION_EGO -c $TEST_CONFIGURATION
TEST_REVOCATION_KEY=$(gnunet-identity -d | awk '{split($0,a," "); print a[3]}')

echo Testing key $TEST_REVOCATION_KEY
OUTPUT_NOT_REVOKED=$(gnunet-revocation -t $TEST_REVOCATION_KEY -c $TEST_CONFIGURATION)
if grep -q valid <<<$OUTPUT_NOT_REVOKED; 
then
		echo "Key was valid" 
else
    RES=1
fi

echo Revoking key $TEST_REVOCATION_KEY
gnunet-revocation -R $TEST_REVOCATION_EGO -p -c $TEST_CONFIGURATION 1> /dev/null 2> /dev/null

echo Testing revoked key $TEST_REVOCATION_KEY
OUTPUT_REVOKED=$(gnunet-revocation -t $TEST_REVOCATION_KEY -c $TEST_CONFIGURATION)
if grep -q revoked <<<$OUTPUT_REVOKED; 
then
    echo "Key was revoked"
else
    RES=1
fi


#clean up
gnunet-arm -e -c $TEST_CONFIGURATION
rm -rf `gnunet-config -c test_revocation.conf -s PATHS -o GNUNET_HOME -f`

exit $RES