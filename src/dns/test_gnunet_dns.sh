#!/bin/bash

ME=`whoami`
if [ "$ME" != "root" ]
then
  echo "This test only works if run as root.  Skipping."
  exit 0
fi
export PATH=".:$PATH"
gnunet-service-dns -c dns.conf &
gnunet-dns-redirector -c dns.conf -4 127.0.0.1 &
sleep 1
LO=`nslookup gnunet.org | grep Address | tail -n1`
if [ "$LO" != "Address: 127.0.0.1" ]
then
 echo "Fail: $LO"
fi
kill `jobs -p`
