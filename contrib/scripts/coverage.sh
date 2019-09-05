#!/bin/sh
# make sure configure was run with coverage enabled...
lcov --directory . --zerocounters
make check
rm `find * -name "test_*.gc??"` `find * -name "perf_*.gc??"`
for n in `find * -name "*.gc??" | grep libs`
do
  cd `dirname $n`
  mv `basename $n` ..
  cd -
done
lcov --directory . --capture --output-file app.info
lcov --remove app.info /usr/include/* -o app.clean.info
mkdir -p doc/coverage
genhtml -o doc/coverage app.clean.info
