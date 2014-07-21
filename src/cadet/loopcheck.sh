#!/bin/sh
if ["$1" == ""]; then
    while true; do
	date;
	taskset 1 make check || break;
	grep -B 10 Assert *log && break
	ls core* &> /dev/null && break
    done
else
    while true; do
	date;
	taskset 1 $1 |& tee log | grep -v DEBUG;
	if [ "${PIPESTATUS[0]}" != "0" ]; then
	    echo "Failed";
	    date;
	    break;
	fi
    done
fi
