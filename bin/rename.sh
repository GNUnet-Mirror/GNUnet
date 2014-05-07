#!/bin/sh
for n in `find * -name "*.c"` `find * -name "*.h"` `find * -name "*.am"` `find * -name "*.conf"`
do
 cat $n | sed -e "s/$1/$2/g" > $n.new
 mv $n.new $n || echo "Move failed: $n.new to $n"
done
