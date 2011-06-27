#!/bin/sh
IP=`ifconfig | grep inet | head -n1 | awk '{print $2}' | sed -e "s/addr://"`
echo "Using IP $IP"
./gnunet-nat-server $IP | sed -u -e "s/.*/.\/gnunet-nat-server-udp $IP &\&/" | sh
