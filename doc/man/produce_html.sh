#!/bin/sh

existence()
{
    command -v "$1" >/dev/null 2>&1
}

if existence mandoc;
then
    for f in `find . -name \*\.[1-9]`;
    do
        mandoc -T html $f > $f.html;
    done
fi
