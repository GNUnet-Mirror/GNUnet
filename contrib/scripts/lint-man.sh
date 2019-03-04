#!/bin/sh
#
# SPDX-License-Identifier: 0BSD
# spit out ONLY error messages using groff.

existence()
{
    command -v "$1" >/dev/null 2>&1
}

if existence groff;
then
    echo "groff check"
    for f in `find . -name \*\.[1-9]`;
    do
        LC_ALL=en_US.UTF-8 \
              MANROFFSEQ='' \
              MANWIDTH=80 \
              groff -m mandoc -b -z -w w $f;
    done
fi

echo "mandoc check"
# spit out ONLY error messages with mandoc:
if existence mandoc;
then
    mandoc -T lint `find . -name \*\.[1-9]`
fi

#LC_ALL=en_US.UTF-8 MANROFFSEQ='' MANWIDTH=80 /run/current-system/profile/bin/man --warnings -E UTF-8 -l -Tutf8 -Z <*.5> >report5.log
#LC_ALL=en_US.UTF-8 MANROFFSEQ='' MANWIDTH=80 /run/current-system/profile/bin/man --warnings -E UTF-8 -l -Tutf8 -Z <*.1> >report1.log
