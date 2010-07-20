#!/bin/bash

FIFO=$(mktemp)

rm $FIFO

mkfifo $FIFO

/opt/gnunet/bin/gnunet-vpn-helper > $FIFO 2>&1 &

PID=$!

sleep 1

IF=""
while read line < $FIFO; do
	IF=$(echo $line | grep interface | sed -e 's/.*interface \([^ ]*\).*/\1/')
	if [ "$IF" != "" ]; then
		break
	fi
done

if /sbin/ifconfig $IF | grep inet6 | grep -q '1234::1/16'; then
	echo OK
	exit 0
else
	echo FAILED: Interface-Address not set!
	exit 1
fi

rm $FIFO
kill $PID
