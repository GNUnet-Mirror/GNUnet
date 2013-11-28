#!/bin/bash

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX" 
	exit 1
fi

trap "gnunet-arm -e -c test_gns_lookup.conf" SIGINT
ME=`whoami`
if [ "$ME" != "root" ]
then
  echo "This test only works if run as root.  Skipping."
  exit 0
fi
export PATH=".:$PATH"
gnunet-service-gns -c gns.conf &
sleep 1
LO=`nslookup alice.gnu | grep Address | tail -n1`
if [ "$LO" != "Address: 1.2.3.4" ]
then
 echo "Fail: $LO"
fi
LO=`nslookup www.bob.gnu | grep Address | tail -n1`
if [ "$LO" != "Address: 4.5.6.7" ]
then
  echo "Fail: $LO"
fi
kill `jobs -p`
