#!/bin/sh
while true; do
    if [ "$1" = "" ]; then
	echo All
	taskset 1 make check || break;
    else
	echo One
	LOGFILE="test_`date "+%m.%d-%H:%M:%S"`.log"
	taskset 01 $1 2>&1 | tee $LOGFILE | grep -v DEBUG;
	if [ "${PIPESTATUS[0]}" != "0" ]; then
	    echo "Failed";
	    date;
	    break;
	fi
    fi
    grep cadet test_*.log | grep -B 10 ERROR && break
    grep cadet test_*.log | grep -B 10 Assert && break
    ls core* &> /dev/null && break
done
