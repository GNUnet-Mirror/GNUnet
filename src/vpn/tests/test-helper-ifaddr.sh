#!/bin/bash

FIFO=$(mktemp)

rm $FIFO

mkfifo $FIFO

/opt/gnunet/bin/gnunet-helper-vpn > $FIFO 2>&1 &

PID=$!

sleep 1

IF=""
while read line < $FIFO; do
	IF=$(echo $line | grep interface | sed -e 's/.*interface \([^ ]*\).*/\1/')
	if [ "$IF" != "" ]; then
		break
	fi
done

r=0
if /sbin/ifconfig $IF | grep inet6 | grep -q '1234::1/16'; then
	echo OK
else
	echo FAILED: Interface-Address not set for IPv6!
	r=1
fi

if /sbin/ifconfig $IF | grep "inet " | grep -q '10.10.10.1'; then
	echo OK
else
	echo FAILED: Interface-Address not set for IPv4!
	r=1
fi

rm $FIFO
kill $PID

exit $r
