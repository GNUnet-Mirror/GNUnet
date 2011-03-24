#!/bin/sh

COMMAND='svn up; cp -v gauger-cli.py `which gauger-cli.py`'

#debian-amd64-grothoff.gnunet.org
echo debian-amd64-grothoff
BASEPATH='/home/buildslave/gauger'
ssh root@buildslave "cd $BASEPATH; $COMMAND"
echo

#ubuntu-armv71-evans
echo ubuntu-armv71-evans
BASEPATH='/home/oem/gauger'
ssh root@efikamx "cd $BASEPATH; $COMMAND"
echo

#freebsd7-amd64-wachs
echo freebsd7-amd64-wachs
BASEPATH='/home/gnunet/gauger'
ssh root@gnunet.org -p 2220 "cd $BASEPATH; $COMMAND"
echo

#wachs-lenny-powerpc
echo wachs-lenny-powerpc
BASEPATH='/home/gnunet/gauger'
ssh root@powerbot "cd $BASEPATH; $COMMAND"
echo
