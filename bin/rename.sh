#!/bin/sh
# This script is in the public domain.
for n in `find * -name "*.c"` `find * -name "*.h"` `find * -name "*.am"` `find * -name "*.conf"`  `find * -name "*.conf.in"` 
do
 cat $n | sed -e "s/$1/$2/g" > $n.new
 mv $n.new $n || echo "Move failed: $n.new to $n"
done
