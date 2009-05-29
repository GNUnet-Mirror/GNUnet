#!/bin/sh
# grepsrc.sh string  --- greps for string over all C files
find . -name "*.c" -print | grep -v "#" | xargs grep -n "$*" 
