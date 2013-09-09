#!/bin/sh

BASEPATH="$(dirname $0)"
OLDDIR="${pwd}"
GN_HOME="/usr/local/bin"

export CC="cparser"
export CFLAGS="-m32 --seaspider"

cd $BASEPATH/.. && ./configure --prefix=$GN_HOME --with-extractor=$GN_HOME --with-microhttpd=$GN_HOME --with-libgcrypt=$GN_HOME && make && seaspider
if test "$?" -ne 0
then
	echo "FAIL: building GNUnet"
	exit 1
fi

cd $OLDDIR
