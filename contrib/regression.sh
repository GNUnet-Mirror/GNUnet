#!/bin/sh
cd
cd gnunet
echo "================START===================" >> regression.txt
uname -a >> regression.txt
svn up >> regression.txt
export GNUNET_PREFIX=$HOME
export PATH=$HOME/bin:$PATH
./bootstrap
./configure --prefix=$HOME --with-extractor=$HOME --with-microhttpd=$HOME
make clean
make install
make check || echo Failed >> regression.txt
make check && echo Success >> regression.txt
echo "================END====================" >> regression.txt
svn commit -m reg regression.txt
