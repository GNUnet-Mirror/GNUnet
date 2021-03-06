#!/bin/bash
CONFIGURATION="test_namestore_api.conf"
trap "gnunet-arm -e -c $CONFIGURATION" SIGINT

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

rm -rf `$LOCATION -c $CONFIGURATION -s PATHS -o GNUNET_HOME`
TEST_IP_PLUS="127.0.0.1"
TEST_RECORD_NAME_DNS="www3"
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

# start peer
gnunet-arm -s -c $CONFIGURATION
gnunet-identity -C testego -c $CONFIGURATION

# Create a public record
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME_DNS -t A -V $TEST_IP_PLUS -e never -c $CONFIGURATION
NAMESTORE_RES=$?
# Lookup specific name
OUTPUT=`gnunet-namestore -p -z testego -n $TEST_RECORD_NAME_DNS -D`


FOUND_IP=false
FOUND_NAME=false
for LINE in $OUTPUT ;
 do
	if echo "$LINE" | grep -q "$TEST_RECORD_NAME_DNS"; then
		FOUND_NAME=true;
		#echo $FOUND_NAME
	fi
	if echo "$LINE" | grep -q "$TEST_IP_PLUS"; then
		FOUND_IP=true;
		#echo $FOUND_IP
	fi
done
# stop peer
gnunet-identity -D testego -c $CONFIGURATION
gnunet-arm -e -c $CONFIGURATION


if [ $FOUND_NAME = true -a $FOUND_IP = true ]
then
  echo "PASS: Lookup name in namestore"
  exit 0
elif [ $FOUND_NAME = false ]
then
  echo "FAIL: Lookup name in namestore: name not returned"
  exit 1
elif [ $FOUND_IP = false ]
then
  echo "FAIL: Lookup name in namestore: IP not returned"
  exit 1
fi
