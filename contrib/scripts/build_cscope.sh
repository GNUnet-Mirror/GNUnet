#!/bin/sh

find . -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.py" -o -name "*.sh" > cscope.files
cscope -q -R -b -i cscope.files
