#!/bin/bash

C_ITERATIONS=5
C_MESSAGE_DELTA=1000
C_MESSAGE_START=23000
C_MESSAGE_END=65500

#for i in {$C_MESSAGE_START..$C_MESSAGE_END..$C_MESSAGE_DELTA}
#  do
#     echo "Welcome $i times"
# done


for ((cur=$C_MESSAGE_START; cur<=$C_MESSAGE_END; cur = cur + $C_MESSAGE_DELTA))
{
	./gnunet-transport-profiler -p  NSGWRTMHG2YJK9KZSTEWKJ5TK20AGRDBWHFA1ZNKKZ7T360MZ8S0 -s -c perf_https_peer1.conf -n 10240 -m $cur -i 4
	sleep 1
}
