#!/bin/bash

ME=`whoami`
if [ "$ME" != "root" ]
then
  echo "This test only works if run as root.  Skipping."
  exit 77
fi
if ! which sudo > /dev/null 
then
  echo "This test requires sudo.  Skipping."
  exit 77
fi
if [ ! -x `which sudo` ]
then
  echo "This test requires sudo.  Skipping."
  exit 77
fi
if ! which nslookup > /dev/null
then 
  echo "This test requires nslookup.  Skipping."
  exit 77
fi
if [ ! -x `which nslookup` ]
then
  echo "This test requires nslookup.  Skipping."
  exit 77
fi
if ! iptables -t mangle --list &> /dev/null
then
  echo "This test requires iptables with 'mangle' support. Skipping."
  exit 77
fi

export PATH=".:$PATH"
gnunet-service-dns -c dns.conf &
gnunet-dns-redirector -c dns.conf -4 127.0.0.1 &
sleep 1
# need to run 'nslookup' as 'nobody', as gnunet-service-dns runs as root
# and thus 'root' is excepted from DNS interception!
LO=`sudo -u nobody nslookup gnunet.org | grep Address | tail -n1`
if [ "$LO" != "Address: 127.0.0.1" ]
then
 echo "Fail: got address $LO, wanted 127.0.0.1"
 ret=1
else
 echo "Test run, with success."
 ret=0
fi
kill `jobs -p`
exit $ret
