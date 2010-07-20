#!/bin/bash

/opt/gnunet/bin/gnunet-vpn-helper < ping > result 2>/dev/null &

PID=$!

sleep 1

kill $PID

if cmp result expected; then
	echo OK
	exit 0
else
	echo FAILED: ICMP-Reply
	exit 1
fi
