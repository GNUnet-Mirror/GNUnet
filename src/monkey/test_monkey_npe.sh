#!/bin/sh
./gnunet-monkey --output=npe.out ./bug_null_pointer_exception && exit 1
grep "null pointer exception on line bug_null_pointer_exception.c:12" npe.out  > /dev/null || exit 2
grep "expression \`nullString\' is NULL" npe.out  > /dev/null || exit 2
rm -f npe.out
