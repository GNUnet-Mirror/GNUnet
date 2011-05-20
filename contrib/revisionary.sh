#!/usr/local/bin/bash

STARTREVISION=14033
ENDREVISION=15268
CURRENTREVISION=$STARTREVISION 
HOME_DIR='/home/gnunet/FreeBSD7-AMD64-wachs/freebsd7-amd64-wachs/build'


CMD_UPDATE="svn up --force --accept theirs-full -r"
CMD_CLEANUP="killall -s 31 -r gnunet-*; make distclean;"
CMD_PREPARATION="./bootstrap; ./configure --prefix=/tmp/gnb --with-extractor=/usr/local"
CMD_BUILD="make all"
CMD_TEST="cd src/transport ; make test_transport_api_tcp; ./test_transport_api_tcp"

#LOGGING=""
LOGGING=" 1> /dev/null 2> errors.txt"
LOGFILE="log.txt"

function output ()
{
  eval echo $1
  eval echo $1 >> $LOGFILE
}


while [ $CURRENTREVISION -le $ENDREVISION ]; do
  output 'Testing revision $CURRENTREVISION'
# updating
  output ' -> updating '
  eval cd $HOME_DIR
  CMD="$CMD_UPDATE $CURRENTREVISION $LOGGING"
  eval $CMD
  result=$?
  if [ $result -eq 0 ]; then
    output "    updating OK"
  else
    output "    updating FAILED"
    (( CURRENTREVISION++ )) 
    continue
  fi

# clean up
  output " -> cleanup "
  CMD="$CMD_CLEANUP $LOGGING"
  eval $CMD
  result=$?
  if [ $result -eq 0 ]; then
    output "    cleanup OK"
  else
    output "    cleanup FAILED"
    (( CURRENTREVISION++ ))     
    continue
  fi
# preparing 
  output " -> preparation "
  CMD="$CMD_PREPARATION $LOGGING"
  #echo $CMD
  eval $CMD
  result=$?
  if [ $result -eq 0 ]; then
    output "    preparation OK"
  else
    output "    preparation FAILED"
    (( CURRENTREVISION++ )) 
    continue
  fi
# building
  output  " -> building "
  CMD="$CMD_BUILD $LOGGING"
  #echo $CMD
  eval $CMD
  result=$?
  if [ $result -eq 0 ]; then
    output "    building OK"
  else
    output "    building FAILED"
    (( CURRENTREVISION++ )) 
    continue
  fi
# testing
  output " -> testing "
  CMD="$CMD_TEST $LOGGING"
  #echo $CMD
  eval $CMD
  result=$?
  testresult=result
  if [ $result -eq 0 ]; then
    output "    testing OK"
  else
    output "    testing FAILED"
    output 'Revision $CURRENTREVISION FAILED'
  fi
  (( CURRENTREVISION++ ))
done

exit


