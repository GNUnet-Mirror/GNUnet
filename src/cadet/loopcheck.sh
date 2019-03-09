#!/usr/bin/env bash
# This script is in the public domain
# POSIX shell solution for named pipes and pipestatus,
# http://shell.cfajohnson.com/cus-faq-2.html#Q11
# run() {
#     j=1
#     while eval "\${pipestatus_$j+:} false"; do
#         unset pipestatus_$j
#         j=$(($j+1))
#     done
#     j=1 com= k=1 l=
#     for a; do
#         if [ "x$a" = 'x|' ]; then
#             com="$com { $l "'3>&-
#                          echo "pipestatus_'$j'=$?" >&3
#                        } 4>&- |'
#             j=$(($j+1)) l=
#         else
#             l="$l \"\$$k\""
#         fi
#         k=$(($k+1))
#     done
#     com="$com $l"' 3>&- >&4 4>&-
#                     echo "pipestatus_'$j'=$?"'
#     exec 4>&1
#     eval "$(exec 3>&1; eval "$com")"
#     exec 4>&-
#     j=1
#     while eval "\${pipestatus_$j+:} false"; do
#         eval "[ \$pipestatus_$j -eq 0 ]" || return 1
#         j=$(($j+1))
#     done
#     return 0
# }

# # https://mywiki.wooledge.org/Bashism has another solution:
# # mkfifo fifo; command2 <fifo & command1 >fifo; echo "$?"

while true; do
    if [ "$1" = "" ]; then
	echo All
	taskset 1 make check || break;
    else
	echo One
	LOGFILE="test_`date "+%m.%d-%H:%M:%S"`.log"
	taskset 01 $1 2>&1 | tee $LOGFILE | grep -v DEBUG;
        # TODO: Replace $PIPESTATUS with more portable code
	if [ "${PIPESTATUS[0]}" != "0" ]; then
	    echo "Failed";
	    date;
	    break;
	fi
    fi
    grep cadet test_*.log | grep -B 10 ERROR && break
    grep cadet test_*.log | grep -B 10 Assert && break
    ls core* > /dev/null 2>&1 && break
done
