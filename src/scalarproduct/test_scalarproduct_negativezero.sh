#!/bin/bash
# compute a simple scalar product
# payload for this test:
INPUTALICE="-k CCC -e -1,1,-1"
INPUTBOB="-k CCC -e 1,1,0"

# necessary to make the testing prefix deterministic, so we can access the config files
PREFIX=/tmp/test-scalarproduct`date +%H%M%S`

# where can we find the peers config files?
CFGALICE="-c $PREFIX/0/config"
CFGBOB="-c $PREFIX/1/config"

# launch two peers in line topology non-interactively
#
# interactive mode would terminate the test immediately 
# because the rest of the script is already in stdin, 
# thus redirecting stdin does not suffice)
GNUNET_LOG='scalarproduct;;;;DEBUG' GNUNET_TESTING_PREFIX=$PREFIX ../testbed/gnunet-testbed-profiler -n -c test_scalarproduct.conf -p 2 2>service.log &
PID=$!
sleep 5

# get bob's peer ID, necessary for alice
PEERIDBOB=`gnunet-peerinfo -qs $CFGBOB`

GNUNET_LOG='scalarproduct;;;;DEBUG' gnunet-scalarproduct $CFGBOB $INPUTBOB 2>bob.log &
RESULT=`GNUNET_LOG='scalarproduct;;;;DEBUG' gnunet-scalarproduct $CFGALICE $INPUTALICE -p $PEERIDBOB 2>alice.log`

cat alice.log bob.log service.log >> test_scalarproduct.log
rm -f alice.log bob.log service.log
ISSUES=$((`grep scalarproduct test_scalarproduct.log | grep -c ERROR` + `grep scalarproduct test_scalarproduct.log | grep -c WARNING`))

# terminate the testbed
kill $PID 

EXPECTED="00"
if [ "$ISSUES" -eq "0" ]
then
	if [ "$RESULT" == "$EXPECTED" ]
	then
	  echo "OK"
          rm -f test_scalarproduct.log
	  exit 0
	fi
else
  echo "Result $RESULT NOTOK, see $PWD/test_scalarproduct.log for details"
  exit 1
fi

