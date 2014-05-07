#!/bin/sh
grep "STARTING SERVICE " log > __tmp_peers
SED_EXPR=""
while read -r line; do
    PEER=`echo $line | sed -e 's/.*\[\(....\)\].*/\1/'`
    PID=`echo $line | sed -e 's/.*mesh-\([0-9]*\).*/\1/'`
    echo "$PID => $PEER"
    SED_EXPR="${SED_EXPR}s/mesh-\([a-z2]*\)-$PID/MESH \1 $PEER/;"
    SED_EXPR="${SED_EXPR}s/mesh-$PID/MESH XXX $PEER/;"
done < __tmp_peers
rm __tmp_peers

SED_EXPR="${SED_EXPR}s/mesh-api-/mesh-api-                                            /g"
sed -e "$SED_EXPR" log > .log

if [[ "`ps aux | grep "kwrite .lo[g]"`" = "" ]]; then
    kwrite .log --geometry 960x1140-960 &
fi
