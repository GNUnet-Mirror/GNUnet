#!/bin/bash

#necessary to make the testing prefix deterministic, so we can access the config files
GNUNET_TESTING_PREFIX=/tmp/test-scalarproduct`date +%H%M%S`
CFGALICE="-c $GNUNET_TESTING_PREFIX/0/config"
CFGBOB="-c $GNUNET_TESTING_PREFIX/1/config"

../testbed/gnunet-testbed-profiler -c test_scalarproduct.conf -p 2 2>gnunet_error.log &
sleep 5

PEERIDBOB=`gnunet-peerinfo -qs $CFGB`
INPUTALICE="-k AAAA -e 10,10,10"
INPUTBOB="-k AAAA -e 10,10,10"
EXPECTED="2C0"

gnunet-scalarproduct $CFGBOB $INPUTBOB
RESULT=`gnunet-scalarproduct $CFGALICE $INPUTALICE -p $PEERIDBOB 2>client_error.log`

if [ "$RESULT" == "$EXPECTED" ]
then
  echo "OK"
  exit 0
else
  echo "Result $RESULT NOTOK"
  exit 1
fi

