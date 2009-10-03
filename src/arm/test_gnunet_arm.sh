#!/bin/sh

rm -rf /tmp/test-gnunetd-arm/
exe="./gnunet-arm -c test_arm_api_data.conf"
base=/tmp/gnunet-test-arm
out=/tmp/test-gnunetd-arm.log
#DEBUG="-L DEBUG"

# -------------------------------------------
echo -n "TEST: can this script work?... "
LINES=`ps -C gnunet-service-arm -o pid= | wc -l`
if test $LINES -ne 0; then
  echo "No (arm exists). Exiting early."
  exit 0
fi
LINES=`ps -C gnunet-service-resolver -o pid= | wc -l`
if test $LINES -ne 0; then
  echo "No (resolver exists). Exiting early."
  exit 0
fi
echo "Yes."


# ----------------------------------------------------------------------------------
echo -n "TEST: Bad argument checking... "

if $exe -x 2> /dev/null; then
  echo "FAIL: error running $exe"
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Start ARM... "

if ! $exe $DEBUG -s > $out ; then
  echo "FAIL: error running $exe"
  echo "Command output was:"
  cat $out
  exit 1
fi
LINES=`ps -u $USER -C gnunet-service-arm -o pid= | wc -l`
if test $LINES -eq 0; then
  echo "FAIL: found $LINES gnunet-service-arm processes"
  echo "Command output was:"
  cat $out
  exit 1
fi
echo "PASS"
sleep 1

# ----------------------------------------------------------------------------------
echo -n "TEST: Start another service... "

if ! $exe $DEBUG -i resolver > $out ; then
  echo "FAIL: error running $exe"
  echo "Command output was:"
  cat $out
  kill %%
  exit 1
fi
sleep 1
LINES=`ps -C gnunet-service-resolver -o pid= | wc -l`
if test $LINES -ne 1; then
  echo "FAIL: unexpected output (got $LINES lines, wanted 1)"
  echo "Command output was:"
  cat $out
  $exe -e > /dev/null
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Test -t on running service... "

if ! $exe $DEBUG -t resolver > $base.out; then
    echo "FAIL: error running $exe"
    exit 1
fi
LINES=`cat $base.out | grep resolver | grep not | wc -l`
if test $LINES -ne 0; then
  echo "FAIL: unexpected output:"
  cat $base.out
  $exe -e
  exit 1
fi
LINES=`cat $base.out | grep resolver | grep -v not | wc -l`
if test $LINES -ne 1; then
  echo "FAIL: unexpected output"
  cat $base.out
  $exe -e
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Stop a service... "

if ! $exe $DEBUG -k resolver > $out; then
  echo "FAIL: error running $exe"
  $exe -e
  exit 1
fi
sleep 1
LINES=`ps -C gnunet-service-resolver -o pid= | wc -l`
if test $LINES -ne 0; then
  sleep 5
  LINES=`ps -C gnunet-service-resolver -o pid= | wc -l`
fi
if test $LINES -ne 0; then
  sleep 2

  echo "FAIL: unexpected output"
  echo "Command output was:"
  cat $out
  $exe -e > /dev/null
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Test -t on stopped service... "

if ! $exe $DEBUG -t resolver > $base.out; then
  echo "FAIL: error running $exe"
  cat $base.out
  $exe -e > /dev/null
  exit 1
fi
LINES=`cat $base.out | grep resolver | grep not | wc -l`
if test $LINES -ne 1; then
  echo "FAIL: unexpected output"
  cat $base.out 
  $exe -e > /dev/null
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Stop ARM... "

if ! $exe $DEBUG -e > $out; then
  echo "FAIL: error running $exe"
  exit 1
fi
sleep 1
LINES=`ps -C gnunet-service-arm -o pid= | wc -l`
if test $LINES -ne 0; then
  sleep 5
  LINES=`ps -C gnunet-service-arm -o pid= | wc -l`
fi
if test $LINES -ne 0; then
  echo "FAIL: unexpected output, still have $LINES gnunet-service-arm processes"
  echo "Command output was:"
  cat $out  
  exit 1
fi
echo "PASS"

rm -rf /tmp/test-gnunetd-arm/
rm -f $base.out $out

