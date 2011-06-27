#!/bin/sh
IP=`ifconfig | grep inet | head -n1 | awk '{print $2}' | sed -e "s/addr://"`
echo "Using IP $IP, trying to connect to $1"
./gnunet-nat-client-udp $IP $1
