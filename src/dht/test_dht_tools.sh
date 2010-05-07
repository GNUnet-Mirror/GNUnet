#!/bin/sh

out=`mktemp /tmp/test-gnunet-arm-logXXXXXXXX`
tempcfg=`mktemp /tmp/test_dht_api_peer1.XXXXXXXX`
checkout="check.out"
armexe="gnunet-arm -c $tempcfg "
putexe="gnunet-dht-put -c $tempcfg "
getexe="gnunet-dht-get -c $tempcfg "
peerinfo="gnunet-peerinfo -c $tempcfg -sq"
stop_arm()
{
  if ! $armexe $DEBUG -e -d > $out ; then
    echo "FAIL: error running $armexe"
    echo "Command output was:"
    cat $out
    exit 1
  fi
}

cp test_dht_api_peer1.conf $tempcfg

echo -n "TEST: Generating hostkey..."
if ! $peerinfo > $out ; then
  echo "FAIL: error running $peerinfo"
  echo "Command output was:"
  cat $out 
  exit 1
fi
echo "PASS"

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
