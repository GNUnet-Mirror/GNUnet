#!/bin/sh

while true; do
    date;
    taskset 1 make check || break;
    grep Assert *log && break
    ls core* &> /dev/null && break
done
