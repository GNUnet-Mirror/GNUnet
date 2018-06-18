#!/bin/sh
# This scipt is in the public domain.
# grepsrc.sh string  --- greps for string over all java files
find . -name "*.h" -print | grep -v "#" | xargs grep "$@" 
