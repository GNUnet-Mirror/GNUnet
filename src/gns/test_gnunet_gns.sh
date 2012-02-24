#!/bin/bash

ME=`whoami`
if [ "$ME" != "root" ]
then
  echo "This test only works if run as root.  Skipping."
  exit 0
fi
export PATH=".:$PATH"
gnunet-service-gns -c gns.conf &
sleep 1
LO=`nslookup alice.gnunet | grep Address | tail -n1`
if [ "$LO" != "Address: 1.2.3.4" ]
then
 echo "Fail: $LO"
fi
LO=`nslookup www.bob.gnunet | grep Address | tail -n1`
if [ "$LO" != "Address: 4.5.6.7" ]
then
  echo "Fail: $LO"
fi
kill `jobs -p`
