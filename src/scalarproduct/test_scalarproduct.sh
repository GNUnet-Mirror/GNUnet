#!/bin/bash
# compute a simple scalar product
# payload for this test:
INPUTALICE="-k AAAA -e 10,10,10"
INPUTBOB="-k AAAA -e 10,10,10"

# necessary to make the testing prefix deterministic, so we can access the config files
PREFIX=/tmp/test-scalarproduct`date +%H%M%S`

# where can we find the peers config files?
CFGALICE="-c $PREFIX/0/config"
CFGBOB="-c $PREFIX/1/config"
# log at which loglevel?
LOGLEVEL=DEBUG

echo start
# launch two peers in line topology non-interactively
#
# interactive mode would terminate the test immediately 
# because the rest of the script is already in stdin, 
# thus redirecting stdin does not suffice)
GNUNET_LOG="scalarproduct;;;;$LOGLEVEL" GNUNET_TESTING_PREFIX=$PREFIX ../testbed/gnunet-testbed-profiler -n -c test_scalarproduct.conf -p 2 2>service.log &
sleep 2
echo tesbed up

# get bob's peer ID, necessary for alice
PEERIDBOB=`gnunet-peerinfo -qs $CFGB`
echo peerinfo receivd

GNUNET_LOG="scalarproduct;;;;$LOGLEVEL" gnunet-scalarproduct $CFGBOB $INPUTBOB 2>bob.log &
echo bob started
GNUNET_LOG="scalarproduct;;;;$LOGLEVEL" gnunet-scalarproduct $CFGALICE $INPUTALICE -p $PEERIDBOB 2>alice.log
echo alice returned

# termiante the testbed
kill $( pgrep -P $$ | tr '\n' ' ' )
echo killed testbed

EXPECTED="12C"
if [ "$RESULT" == "$EXPECTED" ]
then
  echo "OK"
  exit 0
else
  echo "Result $RESULT NOTOK"
  exit 1
fi

