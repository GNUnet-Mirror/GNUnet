#!/bin/sh
while true; do
    if [ "$1" == "" ]; then
	taskset 1 make check || break;
    else
	taskset 1 $1 |& tee log | grep -v DEBUG;
	if [ "${PIPESTATUS[0]}" != "0" ]; then
	    echo "Failed";
	    date;
	    break;
	fi
    fi
    grep -B 10 Assert *log && break
    ls core* &> /dev/null && break
done
