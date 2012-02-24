#!/bin/sh
find src -name "*.c" | grep -v \# | grep -v /test_ | grep -v /perf_  | sort  > po/POTFILES.in
grep -l _\( `find src -name "*.h"` | grep -v "platform.h" | sort >> po/POTFILES.in
