#!/bin/sh

while true; do
    date;
    taskset 1 make check || break;
    grep -B 10 Assert *log && break
    ls core* &> /dev/null && break
done
