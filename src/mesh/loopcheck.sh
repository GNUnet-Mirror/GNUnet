#!/bin/sh

while true; do
    date;
    make check || break;
    grep Assert *log && break
    ls core* &> /dev/null && break
done
