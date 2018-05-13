#!/bin/sh
# This script is in the public domain.
# Converts the output of gnunet-zonewalk (DNS resolutions)
# into a proper input for gnunet-gns-benchmark.

NUM_CLIENTS=3
# How many different groups of names should we
# create?  1/N will be in the 'shared' group.

# FILE ($1) contains results from DNS lookup; strip
# everything but the hostnames, remove duplicates
# and then randomize the order.
cat $1 | awk '{print $1}' | sort | uniq | shuf > $1.tmp
TOTAL=`cat $1.tmp | wc -l`
GROUP_SIZE=`expr $TOTAL / \( $NUM_TYPES + 1 \)`

# First group (0) is to be shared among all clients
for i in `seq 1 $NUM_CLIENTS`
do
  cat $1.tmp | head -n $GROUP_SIZE | awk "{print 0 \" \" \$1}" > $1.$i.tmp
done

# Second group (1) is unique per client
OFF=0
for i in `seq 0 $NUM_CLIENTS`
do
  END=`expr $OFF + $GROUP_SIZE`
  cat $1.tmp | head -n $END | tail -n $GROUP_SIZE | awk "{print 1 \" \" \$1}" >> $1.$i.tmp
# Shuffle again, so we mix the different request categories in terms of
# when we issue the queries.
  cat $1.$i.tmp | shuf > $1.$i
  OFF="$END"
  rm $1.$i.tmp
done
rm $1.tmp
