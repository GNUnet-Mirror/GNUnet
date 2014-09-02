#!/bin/bash

C_ITERATIONS=5
C_MESSAGE_DELTA=10
C_MESSAGE_START=10
C_MESSAGE_END=2000

#for i in {$C_MESSAGE_START..$C_MESSAGE_END..$C_MESSAGE_DELTA}
#  do
#     echo "Welcome $i times"
# done


for ((cur=$C_MESSAGE_START; cur<=$C_MESSAGE_END; cur = cur + $C_MESSAGE_DELTA))
{
	./gnunet-transport-profiler -p  NSGWRTMHG2YJK9KZSTEWKJ5TK20AGRDBWHFA1ZNKKZ7T360MZ8S0 -s -c perf_https_peer1.conf -n 20240 -m $cur -i 4
	sleep 1
}
