#!/bin/sh
cp log .log
cat .log | grep "STARTING SERVICE " > __tmp_peers
SED_EXPR="a"
while read -r line; do
    PEER=`echo $line | sed -e 's/.*\[\(....\)\].*/\1/'`
    PID=`echo $line | sed -e 's/.*mesh-\([0-9]*\).*/\1/'`
    echo "$PID => $PEER"
    export SED_EXPR="${SED_EXPR}s/mesh-\([a-z2]*\)-$PID/MESH \1 $PEER/;"
    export SED_EXPR="${SED_EXPR}s/mesh-$PID/MESH XXX $PEER/"
done < __tmp_peers
rm __tmp_peers

SED_EXPR="${SED_EXPR}s/mesh-api-/mesh-api-                                            /g"
cat .log | sed -e "$SED_EXPR" > .log2
mv .log2 .log

if [[ "`ps aux | grep "kwrite .lo[g]"`" = "" ]]; then
    kwrite .log --geometry 960x1140-960 &
fi
