#!/bin/bash

# Usage: service should print "STARTING SERVICE (srvc) for peer [PEER]" where:
# - "srvc" is the service name (in lowercase, as in the log output).
#   It cannot contain parenthesis in its name.
# - "PEER" is the peer ID. Should be 4 alfanumeric characters

grep "STARTING SERVICE " log > __tmp_peers

SED_EXPR=""
while read -r line; do
    SRVC=`echo $line | sed -e 's/.*(\([^)]*\)).*/\1/'`
    PEER=`echo $line | sed -e 's/.*\[\(....\)\].*/\1/'`
    PID=`echo $line | sed -e "s/.*$SRVC-\([0-9]*\).*/\1/"`
    echo "$SRVC $PID => $PEER"
    
    SED_EXPR="${SED_EXPR}s/$SRVC-\([a-z2]*\)-$PID/$SRVC \1 $PEER/;"
    SED_EXPR="${SED_EXPR}s/$SRVC-$PID/$SRVC XXX $PEER/;"
    SED_EXPR="${SED_EXPR}s/$SRVC-api-[0-9]/$SRVC-api-                                            /;"
done < __tmp_peers
rm __tmp_peers

sed -e "$SED_EXPR" log > .log
echo "$0 sed regex: $SED_EXPR" >> .log

SIZE=`stat -c%s .log`

if [[ "`ps aux | grep "kwrite .lo[g]"`" = "" && "$SIZE" < 10000000 ]]; then
    kwrite .log --geometry 960x1140-960 &
fi
