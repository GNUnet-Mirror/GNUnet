#!/bin/sh

armexe="gnunet-arm -c test_dht_api_peer1.conf "
putexe="gnunet-dht-put -c test_dht_api_peer1.conf "
getexe="gnunet-dht-get -c test_dht_api_peer1.conf "
out=`mktemp /tmp/test-gnunet-arm-logXXXXXXXX`
checkout="check.out"

stop_arm()
{
  if ! $armexe $DEBUG -e > $out ; then
    echo "FAIL: error running $armexe"
    echo "Command output was:"
    cat $out
    stop_arm
    exit 1
  fi
}

echo -n "TEST: Starting ARM..."
if ! $armexe $DEBUG -s > $out ; then
  echo "FAIL: error running $armexe"
  echo "Command output was:"
  cat $out
  stop_arm
  exit 1
fi
echo "PASS"
sleep 1

echo -n "TEST: Testing put..."
if ! $putexe -k testkey -d testdata > $out ; then
  echo "FAIL: error running $putexe"
  echo "Command output was:"
  cat $out
  stop_arm
  exit 1
fi
echo "PASS"
sleep 1

echo -n "TEST: Testing get..."
echo "Result 0, type 0:" > $checkout
echo "testdata" >> $checkout

if ! $getexe -k testkey -T 1 > $out ; then
  echo "FAIL: error running $putexe"
  echo "Command output was:"
  cat $out
  stop_arm
  exit 1
fi
if ! diff -q $out $checkout ; then
  echo "FAIL: $out and $checkout differ"
  stop_arm
  exit 1
fi
echo "PASS"

stop_arm
