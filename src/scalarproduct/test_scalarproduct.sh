#!/bin/bash

#necessary to make the testing prefix deterministic, so we can access the config files
GNUNET_TESTING_PREFIX=/tmp/test-scalarproduct1337
CFGA="-c ./test_scalarproduct_alice.conf"
CFGB="-c ./test_scalarproduct_bob.conf"
					#can't use ` directly
SESSIONDATA="-k AAAA -e 10,10,10"
EXPECTED="2C0"

gnunet-arm -s $CFGA
sleep 2
gnunet-arm -s $CFGB
sleep 2

IDB=`gnunet-peerinfo -s $CFGB | awk -F "\x60" '{print $2}' | awk -F "'" '{print $1}'`

gnunet-scalarproduct $CFGB $SESSIONDATA

RESULT=`gnunet-scalarproduct $CFGA $SESSIONDATA -p $IDB`

gnunet-arm -e $CFGA &
gnunet-arm -e $CFGB &

if [ "$RESULT" == "$EXPECTED" ]
then
  echo "OK"
  exit 0
else
  echo "Result $RESULT NOTOK"
  exit 1
fi

