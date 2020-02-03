#!/bin/bash
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup_peer1.conf" INT
trap "gnunet-arm -e -c test_gns_lookup_peer2.conf" INT
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_gns_lookup_peer1.conf -f -s paths -o GNUNET_TEST_HOME`
rm -rf `gnunet-config -c test_gns_lookup_peer2.conf -f -s paths -o GNUNET_TEST_HOME`
MY_EGO="localego"
OTHER_EGO="remoteego"

TEST_IP="127.0.0.1"
TEST_IPV6="dead::beef"
LABEL="fnord"

gnunet-arm -s -c test_gns_lookup_peer2.conf
PKEY=`$DO_TIMEOUT gnunet-identity -V -C $OTHER_EGO -c test_gns_lookup_peer2.conf`
gnunet-namestore -p -z $OTHER_EGO -a -n $LABEL -t A -V $TEST_IP -e 3600s -c test_gns_lookup_peer2.conf
gnunet-namestore -p -z $OTHER_EGO -a -n $LABEL -t AAAA -V $TEST_IPV6 -e 3600s -c test_gns_lookup_peer2.conf
gnunet-namestore -D -z $OTHER_EGO -n $LABEL
gnunet-arm -e -c test_gns_lookup_peer2.conf

echo "Second peer"
gnunet-arm -s -c test_gns_lookup_peer1.conf
echo "Second peer started"
RESP=`$DO_TIMEOUT gnunet-gns --raw -u $LABEL.$PKEY -t ANY -c test_gns_lookup_peer1.conf`
RESP1=`$DO_TIMEOUT gnunet-gns --raw -u $LABEL.$PKEY -t A -c test_gns_lookup_peer1.conf`
RESP2=`$DO_TIMEOUT gnunet-gns --raw -u $LABEL.$PKEY -t AAAA -c test_gns_lookup_peer1.conf`
gnunet-arm -e -c test_gns_lookup_peer1.conf

rm -rf `gnunet-config -c test_gns_lookup_peer1.conf -f -s paths -o GNUNET_TEST_HOME`
rm -rf `gnunet-config -c test_gns_lookup_peer2.conf -f -s paths -o GNUNET_TEST_HOME`

RESPONSES=($(echo $RESP | tr "\n" " " ))

if [ "$RESP1" == "$TEST_IP" ]
then
  echo "PASS: A record resolution from DHT via separate peer"
else
  echo "FAIL: A record resolution from DHT via separate peer, got $RESP1, expected $TEST_IP"
  exit 1
fi
if [ "$RESP2" == "$TEST_IPV6" ]
then
  echo "PASS: AAAA record resolution from DHT via separate peer"
else
  echo "FAIL: AAAA record resolution from DHT via separate peer, got $RESP2, expected $TEST_IPV6"
  exit 1
fi
if [[ "${RESPONSES[0]} ${RESPONSES[1]}" == "$TEST_IPV6 $TEST_IP" ]] || [[ "${RESPONSES[0]} ${RESPONSES[1]}" == "$TEST_IP $TEST_IPV6" ]]
then
  echo "PASS: ANY record resolution from DHT via separate peer"
else
  echo "FAIL: ANY record resolution from DHT via separate peer, got $RESP, expected $TEST_IPV6 $TEST_IP or $TEST_IP $TEST_IPV6"
  exit 1
fi
