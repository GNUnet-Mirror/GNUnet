#!/bin/sh
cd
cd gnunet
svn up > /dev/null
H=`hostname`
echo "================START===================" >> regression.$H
RUN=`date +%0y%0m%0d%0k%0M`
uname -a >> regression.$H
date >> regression.$H
echo "Run $RUN" >> regression.$H
svn up >> regression.$H
export GNUNET_PREFIX=$HOME
export PATH=$HOME/bin:$PATH
./bootstrap >> regression.$H.$RUN  2>&1
./configure --prefix=$HOME --with-extractor=$HOME --with-microhttpd=$HOME  >> regression.$H.$RUN  2>&1
if [ $? != 0 ]
then
  echo configure failed >> regression.$H
  exit
fi
KEEP=0
make clean >> regression.$H.$RUN 2>&1
make install >> regression.$H.$RUN 2>&1
cd src
for n in `ls --hide "Makefile*"`
do
  cd $n
  if [ -f Makefile ]
  then
    make check >> ../regression.$H.$RUN.$n  2>&1
    if [ $? != 0 ]
    then
      echo Tests for $n failed >> ../regression.$H
      echo "--------- Details for $n -----------" >> ../regression.$H
      cat regression.$H.$RUN.$n >> ../regression.$H
      echo "----- End of Details for $n --------" >> ../regression.$H
      KEEP=1
    else
      echo Tests for $n succeeded >> ../regression.$H
    fi
  fi
  cd ..
done
echo "================END====================" >> regression.$H

if [ $KEEP == 0]
then
  rm regression.$H.$RUN*
  rm regression.$H
else
  svn add regression.$H > /dev/null
  svn commit -m "Regression in tests on $H" regression.$H
fi

