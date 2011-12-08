#!/bin/sh

exe="./gnunet-arm -c test_arm_api_data.conf"
out=`mktemp /tmp/test-gnunet-arm-logXXXXXXXX`
#DEBUG="-L DEBUG"


# ----------------------------------------------------------------------------------
echo -n "TEST: Bad argument checking... "

if $exe -x 2> /dev/null; then
  echo "FAIL: error running $exe"
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Start ARM..."

if ! $exe $DEBUG -s > $out ; then
  echo "FAIL: error running $exe"
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
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Stop a service... "

if ! $exe $DEBUG -k resolver > $out; then
  echo "FAIL: error running $exe"
  $exe -e
  exit 1
fi
sleep 1
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Stop ARM... "

if ! $exe $DEBUG -e > $out; then
  echo "FAIL: error running $exe"
  exit 1
fi
sleep 1
echo "PASS"

rm -rf /tmp/test-gnunetd-arm/
rm -f $out

