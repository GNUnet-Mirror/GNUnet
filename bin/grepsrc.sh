#!/bin/sh
# This script is in the public domain.
# grepsrc.sh string  --- greps for string over all C files
find . -name "*.c" -print | grep -v "#" | xargs grep -n "$*" 
