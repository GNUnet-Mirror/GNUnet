#!/bin/sh
echo -n "Test Monkey with Bug - Null Pointer Exception -"
gnunet-monkey --mode text --binary bug_null_pointer_exception --output npe.out && exit 0
grep "Bug detected in file:bug_null_pointer_exception.c" npe.out > /dev/null || exit 1
grep "function:crashFunction" npe.out > /dev/null || exit 1
grep "line:8" npe.out > /dev/null || exit 1
grep "reason:Signal received" npe.out > /dev/null || exit 1
grep "received signal:EXC_BAD_ACCESS" npe.out > /dev/null || exit 1
grep "Could not access memory" npe.out > /dev/null || exit 1
rm -f npe.out
echo "PASS"