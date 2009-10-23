#!/bin/sh

rm -rf /tmp/test-gnunetd-statistics/
exe="./gnunet-statistics -c test_statistics_api_data.conf"
out=`mktemp /tmp/test-gnunet-statistics-logXXXXXXXX`
arm="gnunet-arm -c test_statistics_api_data.conf $DEBUG"
#DEBUG="-L DEBUG"
# -----------------------------------
echo -n "Preparing: Starting service..."

$arm -s > /dev/null
sleep 1
$arm -i statistics > /dev/null
sleep 1 
echo "DONE"

# ----------------------------------------------------------------------------------
echo -n "TEST: Bad argument checking..."

if $exe -x 2> /dev/null; then
  echo "FAIL: error running $exe"
  $arm -e
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Set value..."

if ! $exe $DEBUG -n test -s subsystem 42 ; then
  echo "FAIL: error running $exe"
  $arm -e
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: Set another value..."

if ! $exe $DEBUG -n other -s osystem 43 ; then
  echo "FAIL: error running $exe"
  $arm -e
  exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: viewing all stats..."

if ! $exe $DEBUG > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | wc -l`
if test $LINES -ne 2; then
    echo "FAIL: unexpected output"
    $arm -e
    exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: viewing stats by name..."

if ! $exe $DEBUG -n other > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep 43 | wc -l`
if test $LINES -ne 1; then
    echo "FAIL: unexpected output"
    $arm -e
    exit 1
fi
echo "PASS"

# ----------------------------------------------------------------------------------
echo -n "TEST: viewing stats by subsystem..."

if ! $exe $DEBUG -s subsystem > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep 42 | wc -l`
if test $LINES -ne 1; then
    echo "FAIL: unexpected output"
    $arm -e
    exit 1
fi
echo "PASS"


# ----------------------------------------------------------------------------------
echo -n "TEST: Set persistent value..."

if ! $exe $DEBUG -n lasting -s subsystem 40 -p; then
  echo "FAIL: error running $exe"
  $arm -e
  exit 1
fi
if ! $exe $DEBUG > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep 40 | wc -l`
if test $LINES -ne 1; then
    echo "FAIL: unexpected output"
    cat $out
    $arm -e
    exit 1
fi
echo "PASS"

# -----------------------------------
echo -n "Restarting service..."
$arm -k statistics > /dev/null
sleep 1
$arm -i statistics > /dev/null
sleep 1
echo "DONE"

# ----------------------------------------------------------------------------------
echo -n "TEST: checking persistence..."

if ! $exe $DEBUG > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep 40 | wc -l`
if test $LINES -ne 1; then
    echo "FAIL: unexpected output"
    cat $out
    $arm -e
    exit 1
fi
echo "PASS"



# ----------------------------------------------------------------------------------
echo -n "TEST: Removing persistence..."

if ! $exe  $DEBUG -n lasting -s subsystem 40; then
  echo "FAIL: error running $exe"
  $arm -e
  exit 1
fi
if ! $exe $DEBUG > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep \! | wc -l`
if test $LINES -ne 0; then
    echo "FAIL: unexpected output"
    cat $out
    $arm -e
    exit 1
fi
echo "PASS"


# -----------------------------------
echo -n "Restarting service..."
$arm -k statistics > /dev/null
sleep 1
$arm -i statistics > /dev/null
sleep 1
echo "DONE"

# ----------------------------------------------------------------------------------
echo -n "TEST: checking removed persistence..."

if ! $exe $DEBUG > $out; then
    echo "FAIL: error running $exe"
    $arm -e
    exit 1
fi
LINES=`cat $out | grep 40 | wc -l`
if test $LINES -ne 0; then
    echo "FAIL: unexpected output"
    cat $out
    $arm -e
    exit 1
fi
echo "PASS"

# -----------------------------------
echo -n "Stopping service..."
$arm -e > /dev/null
sleep 1
echo "DONE"
rm -f $out
rm -rf /tmp/test-gnunetd-statistics/
