#!/bin/bash
# compute a simple scalar product

#necessary to make the testing prefix deterministic, so we can access the config files
PREFIX=/tmp/test-scalarproduct`date +%H%M%S`

#where can we find the peers config files?
CFGALICE="-c $PREFIX/0/config"
CFGBOB="-c $PREFIX/1/config"

#log at which loglevel?
LOG="-L ERROR"

#launch two peers in line topology
GNUNET_TESTING_PREFIX=$PREFIX ../testbed/gnunet-testbed-profiler $LOG -c test_scalarproduct.conf -p 2 2>gnunet_error.log &
sleep 5

#get bob's peer ID, necessary for alice
PEERIDBOB=`gnunet-peerinfo -qs $CFGB`

#payload for this test on both sides
INPUTALICE="-k AAAA -e 10,10,10"
INPUTBOB="-k AAAA -e 10,10,10"

echo "gnunet-scalarproduct $LOG $CFGBOB $INPUTBOB &"
echo "gnunet-scalarproduct $LOG $CFGALICE $INPUTALICE -p $PEERIDBOB -L ERROR"
gnunet-scalarproduct $LOG $CFGBOB $INPUTBOB 2>bob_error.log &
RESULT=`gnunet-scalarproduct $LOG $CFGALICE $INPUTALICE -p $PEERIDBOB 2>alice_error.log`

EXPECTED="12C"
if [ "$RESULT" == "$EXPECTED" ]
then
  echo "OK"
  exit 0
else
  echo "Result $RESULT NOTOK"
  exit 1
fi

