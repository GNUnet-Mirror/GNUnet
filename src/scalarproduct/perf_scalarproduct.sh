#!/bin/bash
# Computes a simple scalar product, with configurable vector size.
#
# Some results:
# SIZE   TIME-H(s)  TIME-O(s)
#  25     10
#  50     17
# 100     32          39
# 200                 77
#
#
# Configure benchmark size:
SIZE=400
#
# Construct input vectors:
INPUTALICE="-k CCC -e '"
INPUTBOB="-k CCC -e '"
for X in `seq 1 $SIZE`
do
  INPUTALICE="${INPUTALICE}A${X},$X;"
  INPUTBOB="${INPUTBOB}A${X},$X;"
done
INPUTALICE="${INPUTALICE}BC,-20000;RO,1000;FL,100;LOL,24;'"
INPUTBOB="${INPUTBOB}AB,10;RO,3;FL,3;LOL,-1;'"

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
GNUNET_FORCE_LOG=';;;;ERROR'
GNUNET_TESTING_PREFIX=$PREFIX ../testbed/gnunet-testbed-profiler -n -c test_scalarproduct.conf -p 2 &
PID=$!
# sleep 1 is too short on most systems, 2 works on most, 5 seems to be safe
echo "Waiting for peers to start..."
sleep 5
# get Bob's peer ID, necessary for Alice
PEERIDBOB=`gnunet-peerinfo -qs $CFGBOB`

echo "Running problem of size $SIZE"
gnunet-scalarproduct $CFGBOB $INPUTBOB &
time RESULT=`gnunet-scalarproduct $CFGALICE $INPUTALICE -p $PEERIDBOB`
gnunet-statistics $CFGALICE -s core | grep "bytes encrypted"
gnunet-statistics $CFGBOB -s core | grep "bytes encrypted"

echo "Terminating testbed..."
# terminate the testbed
kill $PID

