#!/bin/sh
# check python style (and 2 to 3 migration)

rm python-lint.log

if [ -e "python" ]
then
    python --version >> python-lint.log
fi

if [ -e "python2" ]
then
    python2 --version >> python-lint.log
fi

if [ -e "python3" ]
then
    python3 --version >> python-lint.log
fi

flake8 >> python-lint.log

2to3 -v -d . >> python-lint.log
2to3 -v -p . >> python-lint.log
