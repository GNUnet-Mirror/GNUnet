#!/bin/sh
# This script is in the public domain.
# grepsrc.sh string  --- greps for string over all header files
find . -name "*.h" -print | grep -v "#" | xargs grep "$@" 
