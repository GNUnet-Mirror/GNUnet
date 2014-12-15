#!/bin/sh
grep "STARTING SERVICE " log > __tmp_peers
SED_EXPR=""
while read -r line; do
    PEER=`echo $line | sed -e 's/.*\[\(....\)\].*/\1/'`
    PID=`echo $line | sed -e 's/.*cadet-\([0-9]*\).*/\1/'`
    echo "$PID => $PEER"
    SED_EXPR="${SED_EXPR}s/cadet-\([a-z2]*\)-$PID/CADET \1 $PEER/;"
    SED_EXPR="${SED_EXPR}s/cadet-$PID/CADET XXX $PEER/;"
done < __tmp_peers
rm __tmp_peers

SED_EXPR="${SED_EXPR}s/cadet-api-/cadet-api-                                            /g"
sed -e "$SED_EXPR" log > .log

if [[ "`ps aux | grep "kwrite .lo[g]"`" = "" ]]; then
    kwrite .log --geometry 960x1140-960 &
fi
