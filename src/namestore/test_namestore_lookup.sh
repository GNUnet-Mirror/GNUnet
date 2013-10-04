#!/bin/bash
CONFIGURATION="test_namestore_api.conf"
trap "gnunet-arm -e -c $CONFIGURATION" SIGINT
rm -rf `gnunet-config -c $CONFIGURATION -s PATHS -o SERVICEHOME`
TEST_IP_PLUS="127.0.0.1"
TEST_RECORD_NAME_PLUS="www"
TEST_RECORD_NAME_DNS="www3"
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

function start_peer
{
	gnunet-arm -s -c $CONFIGURATION
	gnunet-identity -C testego -c $CONFIGURATION	
}

function stop_peer
{
	gnunet-identity -D testego -c $CONFIGURATION
	gnunet-arm -e -c $CONFIGURATION
}


start_peer
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
stop_peer


if [ $FOUND_NAME == true -a $FOUND_IP == true ]
then
  echo "PASS: Lookup name in namestore"
  exit 0
elif [ $FOUND_NAME == false ]
then
  echo "FAIL: Lookup name in namestore: name not returned"
  exit 1
elif [ $FOUND_IP == false ]
then
  echo "FAIL: Lookup name in namestore: IP not returned"
  exit 1
fi
