#!/bin/sh

if [ "$#" -lt "1" ]; then
    echo "usage: $0 PEERS";
    exit 1;
fi

PEERS=$1

if [ $PEERS -eq 1 ]; then
    echo "cannot run 1 peer";
    exit 1;
fi

LINKS=`echo "l($PEERS) * $PEERS" | bc -l`
LINKS=`printf "%.0f" $LINKS`
echo "using $PEERS peers, $LINKS links";
    
sed -e "s/%LINKS%/$LINKS/g" .profiler.template > profiler.conf

./gnunet-mesh-profiler $PEERS
