#!/bin/sh

TEST=`type type|grep not`
if test -n "$TEST"; then
  WHICH=which
else
  WHICH=type
fi

echo "Please submit the following information with your bug report: "
echo "--------------------------------------------------------------"
OS=`uname -s 2>/dev/null`
echo "OS             : $OS" 
REL=`uname -r 2>/dev/null`
echo "OS RELEASE     : $REL"
HW=`uname -m 2>/dev/null`
echo "HARDWARE       : $HW"

TEST=`$WHICH gcc 2>/dev/null`
if test -n "$TEST"; then
  VERS=`gcc --version 2>/dev/null | head -n 1`
  echo "gcc            : $VERS"
else
  echo "gcc            : Not Found";
fi

TEST=`$WHICH gmake 2>/dev/null`
if test -n "$TEST" ; then
	gmake --version 2>/dev/null |\
		awk -F, '{print $1}' |\
		awk '/GNU Make/{print "GNU gmake      :",$NF}'
else
  TEST=`make --version 2>/dev/null`
  if test -n "$TEST"; then
		make --version 2>/dev/null |\
			awk -F, '{print $1}' |\
			awk '/GNU Make/{print "make           :",$NF}'
  else
		echo "make           : Not Found"
  fi
fi

TEST=`$WHICH autoconf 2>/dev/null`
if test -n "$TEST"; then
  autoconf --version |\
    head -n 1 |\
    awk '{\
	if (length($4) == 0) {\
		print "autoconf       : "$3\
	} else {\
		print "autoconf       : "$4\
	}}'
else
  echo "autoconf       : Not Found"
fi

TEST=`$WHICH automake 2>/dev/null`
if test -n "$TEST"; then
  automake --version 2>/dev/null |\
    head -n 1 |\
    awk '{print "automake       : "$4}'
else
  echo "automake       : Not Found"
fi

TEST=`$WHICH libtool 2>/dev/null`
if test -n "$TEST"; then
  libtool --version 2>/dev/null |\
    head -n 1 |\
    awk '{print "libtool        : "$4}'
else
  echo "libtool        : Not Found"
fi

TEST=`$WHICH extract 2>/dev/null`
if test -n "$TEST"; then
  extract -v 2>/dev/null |\
    head -n 1 |\
    awk '{print "libextractor   : "$2}'
else
  echo "libextractor   : Not Found"
fi

if test -x gnunetd; then
  gnunetd -v | sed -e "s/v//" 2>/dev/null |\
    awk '{print "GNUnet 0.8     : "$2 (may conflict!)}'
else
  echo "GNUnet 0.8     : Not Found (good)"
fi

TEST=`$WHICH gnunet-arm 2>/dev/null`
if test -n "$TEST"; then
  gnunet-arm -v | sed -e "s/v//" 2>/dev/null |\
    awk '{print "GNUnet 0.9     : "$2}'
else
  echo "GNUnet 0.9     : Not Found"
fi

TEST=`$WHICH libgcrypt-config 2> /dev/null`
if test -n "$TEST"; then
  libgcrypt-config --version 2> /dev/null | \
    awk '{print "libgcrypt      : "$1}'
else
  echo "libgcrypt      : Not Found"
fi

TEST=`$WHICH mysql_config 2> /dev/null`
if test -n "$TEST"; then
  mysql_config --version 2> /dev/null | \
    awk '{print "mysql          : "$1}'
else
  echo "mysql          : Not Found"
fi

TEST=`$WHICH pkg-config 2> /dev/null`
if test -n "$TEST"; then
  pkg-config --version 2> /dev/null | \
    awk '{print "pkg-config     : "$1}'
else
  echo "pkg-config     : Not Found"
fi

TEST=`$WHICH pkg-config 2> /dev/null`
if test -n "$TEST"; then
  pkg-config --modversion glib-2.0 2> /dev/null | \
    awk '{print "glib2          : "$1}'
else
  echo "glib2          : Not Found"
fi

TEST=`$WHICH pkg-config 2> /dev/null`
if test -n "$TEST"; then
  pkg-config --modversion gtk+-2.0 2> /dev/null | \
    awk '{print "gtk2+          : "$1}'
else
  echo "gtk2+          : Not Found"
fi

TEST=`$WHICH dpkg 2> /dev/null`
if test -n "$TEST"; then
  LINES=`dpkg -s libgmp3-dev | grep Version | wc -l`
  if test "$LINES" = "1"
  then
    VERSION=`dpkg -s libgmp3-dev | grep Version | awk '{print $2}'`
    echo "GMP            : libgmp3-dev-$VERSION.deb"
  else
    echo "GMP            : dpkg: libgmp3-dev not installed"
  fi
else
  TEST=`$WHICH rpm 2> /dev/null`
  if test -n "$TEST"; then
    rpm -q gmp | sed -e "s/gmp-//" 2> /dev/null | \
      awk '{print "GMP            : "$1.rpm}'
  else
    echo "GMP            : Test not available"
  fi
fi

TEST=`$WHICH gettext 2> /dev/null`
if test -n "$TEST"; then
  gettext --version | head -n1 2> /dev/null | \
    awk '{print "GNU gettext    : "$4}'
else
  echo "GNU gettext    : Not found"
fi


TEST=`$WHICH curl-config 2> /dev/null`
if test -n "$TEST"; then
  curl-config --version | head -n1 2> /dev/null | \
    awk '{print "libcurl        : "$2}'
else
  echo "libcurl        : Not found"
fi


TEST=`which qmake 2> /dev/null`
if test -x "$TEST"; then
  qmake --version | tail -n 1 | awk '{print "Qt             : "$4}'
else
  echo "Qt             : Not found"
fi

echo -n "MHD            : "
TMPFILE=`mktemp /tmp/mhd-version-testXXXXXX`
cat - >$TMPFILE.c <<EOF
#include <microhttpd.h>
#include <stdio.h>
int main()
{
  fprintf (stdout, "%X\n", MHD_VERSION);
  return 0;
}
EOF

gcc -o $TMPFILE $TMPFILE.c 2> /dev/null && $TMPFILE || echo "Not found"
rm -f $TMPFILE $TMPFILE.bin


echo "--------------------------------------------------------------"
