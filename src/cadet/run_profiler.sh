#!/bin/sh

if [ "$#" -lt "3" ]; then
    echo "usage: $0 ROUND_TIME PEERS PINGING_PEERS";
    echo "example: $0 30s 16 1";
    exit 1;
fi

ROUNDTIME=$1
PEERS=$2
PINGS=$3

if [ $PEERS -eq 1 ]; then
    echo "cannot run 1 peer";
    exit 1;
fi

LINKS=`echo "l($PEERS) * l($PEERS) * $PEERS / 2" | bc -l`
LINKS=`printf "%.0f" $LINKS`
NSE=`echo "l($PEERS)/l(2)" | bc -l`
echo "using $PEERS peers, $LINKS links";
    
sed -e "s/%LINKS%/$LINKS/;s/%NSE%/$NSE/" profiler.conf > .profiler.conf

./gnunet-cadet-profiler $ROUNDTIME $PEERS $PINGS $4 |& tee log | grep -v DEBUG
