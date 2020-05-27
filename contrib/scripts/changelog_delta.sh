#!/bin/bash
LASTHASH=$(head -n1 ChangeLog | cut -d " " -f 7 | tr -d \( | tr -d \))
git log --no-merges --no-color --format="%aD (%h)%n%s - %cN%n" $LASTHASH..HEAD
