# This file is part of GNUnet.
# (C) 2001--2012 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ(2.61)
# Checks for programs.
AC_INIT([gnunet], [0.9.2],[bug-gnunet@gnu.org])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([gnunet], [0.9.2])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([gnunet_config.h])
AH_TOP([#define _GNU_SOURCE  1])

AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_OBJC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
LT_INIT([disable-static dlopen win32-dll])
LTDL_INIT
AC_SUBST(LTDLINCL)
AC_SUBST(LIBLTDL)
AC_SUBST(MKDIR_P)

# large file support
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO


if test "$enable_shared" = "no"
then
 AC_MSG_ERROR([GNUnet only works with shared libraries. Sorry.])
fi

CFLAGS="-Wall $CFLAGS"
# use '-fno-strict-aliasing', but only if the compiler can take it
if gcc -fno-strict-aliasing -S -o /dev/null -xc /dev/null >/dev/null 2>&1;
then
 CFLAGS="-fno-strict-aliasing $CFLAGS"
fi

# Use Linux interface name unless the OS has a different preference
DEFAULT_INTERFACE="\"eth0\""

# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(DARWIN,1,[This is an Apple Darwin system])
     CPPFLAGS="-D_APPLE_C_SOURCE $CPPFLAGS"
     CFLAGS="-no-cpp-precomp -fno-common $CFLAGS"
     AC_MSG_WARN([The VPN application cannot be compiled on your OS])
     build_target="darwin"
     DEFAULT_INTERFACE="\"en0\""
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     build_target="linux"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     AC_PATH_XTRA
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     build_target="freebsd"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     LIBS=`echo $LIBS | sed -e "s/-ldl//"`
     build_target="openbsd"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AC_CHECK_LIB(resolv, res_init)
     AC_CHECK_LIB(rt, nanosleep)
     build_target="solaris"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     build_target="linux"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -no-undefined"
     CFLAGS="-mms-bitfields $CFLAGS"
     build_target="cygwin"
     LIBPREFIX=lib
     DLLDIR=bin
     AC_PROG_CXX
     UNIXONLY=""
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AC_DEFINE_UNQUOTED(_WIN32,1,[This is a Windows system])
     AC_CHECK_LIB(intl, gettext)
     LDFLAGS="$LDFLAGS -Wl,-no-undefined -Wl,--export-all-symbols"
     LIBS="$LIBS -lws2_32 -lplibc -lgnurx -lole32"
     CFLAGS="-mms-bitfields $CFLAGS"
     CPPFLAGS="-D_WIN32_WINNT=0x0501 $CPPFLAGS"
     build_target="mingw"
     AC_PROG_CXX
     LIBPREFIX=lib
     DLLDIR=bin
     UNIXONLY=""
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
     UNIXONLY=""
;;
esac
AC_DEFINE_UNQUOTED([GNUNET_DEFAULT_INTERFACE], $DEFAULT_INTERFACE, [This should be the default choice for the name of the first network interface])
AC_SUBST(DEFAULT_INTERFACE)

# Disable TCP-based IPC on systems that support UNIX domain
# sockets in default configuratin:
AC_SUBST(UNIXONLY)

AC_MSG_CHECKING([for build target])
AM_CONDITIONAL(DARWIN,  test "$build_target" = "darwin")
AM_CONDITIONAL(CYGWIN,  test "$build_target" = "cygwin")
AM_CONDITIONAL(MINGW,   test "$build_target" = "mingw")
AM_CONDITIONAL(SOLARIS, test "$build_target" = "solaris")
AM_CONDITIONAL(XFREEBSD, test "$build_target" = "freebsd")
AM_CONDITIONAL(OPENBSD, test "$build_target" = "openbsd")
AM_CONDITIONAL(LINUX, test "$build_target" = "linux")

AC_MSG_RESULT([$build_target])
AC_SUBST(build_target)
AM_CONDITIONAL([am__fastdepOBJC], false)
AC_UNALIGNED_64_ACCESS

# some other checks for standard libs
AC_SEARCH_LIBS([gethostbyname], [nsl ws2_32])
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))

# 'save' libs; only those libs found so far will be
# linked against _everywhere_.  For the others, we
# will be more selective!
SAVE_LIBS=$LIBS

# libgnurx (regex library for W32)
gnurx=0
AC_CHECK_LIB(gnurx, regexec, gnurx=1)
if test "x$gnurx" = "x0" -a "x$build_target" = "xmingw"
then
  AC_MSG_ERROR([on W32 GNUnet needs libgnurx])
fi

# libgcrypt
gcrypt=0
AM_PATH_LIBGCRYPT(1.2.0, gcrypt=1)
AC_CHECK_DECLS([gcry_mpi_lshift], [], [], [[#include <gcrypt.h>]])

if test $gcrypt = 0
then
  AC_MSG_ERROR([GNUnet needs libgcrypt])
fi

# Adam shostack suggests the following for Windows:
# -D_FORTIFY_SOURCE=2 -fstack-protector-all
AC_ARG_ENABLE(gcc-hardening,
   AS_HELP_STRING(--enable-gcc-hardening, enable compiler security checks),
[if test x$enableval = xyes; then
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector-all"
    CFLAGS="$CFLAGS -fwrapv -fPIE -Wstack-protector"
    CFLAGS="$CFLAGS --param ssp-buffer-size=1"
    LDFLAGS="$LDFLAGS -pie"
fi])


# Linker hardening options
# Currently these options are ELF specific - you can't use this with MacOSX
AC_ARG_ENABLE(linker-hardening,
  AS_HELP_STRING(--enable-linker-hardening, enable linker security fixups),
[if test x$enableval = xyes; then
   LDFLAGS="$LDFLAGS -z relro -z now"
fi])


extra_logging=GNUNET_NO
AC_ARG_ENABLE([logging],
   AS_HELP_STRING([--enable-logging@<:@=value@:>@],[Enable logging calls. Possible values: yes,no,verbose,veryverbose ('yes' is the default)]),
   [AS_IF([test "x$enableval" = "xyes"], [],
          [test "x$enableval" = "xno"], [AC_DEFINE([GNUNET_CULL_LOGGING],[],[Define to cull all logging calls])],
          [test "x$enableval" = "xverbose"], [extra_logging=GNUNET_YES]
          [test "x$enableval" = "xveryverbose"], [extra_logging=\(GNUNET_YES+1\)])
   ], [])
AC_DEFINE_UNQUOTED([GNUNET_EXTRA_LOGGING],[$extra_logging],[1 if extra logging is enabled, 2 for very verbose extra logging, 0 otherwise])

if test $build = $target
then
AC_MSG_CHECKING([for working HMAC])
AC_LANG_PUSH(C)
LIBS="$LIBS $LIBGCRYPT_LIBS"
CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
AC_RUN_IFELSE(
  [AC_LANG_PROGRAM([#include <gcrypt.h> 
  	#include <stdio.h>], [[
        gcry_md_hd_t mac;
      
        unsigned char data[] = { 0xbf, 0x16, 0x6e, 0x46, 0x3a, 0x6c, 0xf3, 0x93, 0xa7, 0x72,
            0x11, 0xa1, 0xdc, 0x0b, 0x07, 0xdb, 0x1a, 0x5e, 0xd9, 0xb9, 0x81, 0xbe,
            0xea, 0xe4, 0x31, 0x5f, 0x24, 0xff, 0xfe, 0x50, 0x8a, 0xde };
        unsigned char key[] = { 0xfc, 0x62, 0x76, 0x35 };
        unsigned char result[] = {0xa2, 0xb, 0x1, 0xd9, 0xc0, 0x8b, 0x5a, 0x12, 0x80,
            0xd5, 0x50, 0x12, 0x8e, 0xd0, 0x5b, 0xb6, 0x5c, 0x87, 0x24, 0xe2, 0xd0,
            0xd2, 0xaf, 0x63, 0xae, 0xd1, 0xd6, 0x64, 0x14, 0xe3, 0x6e, 0x61, 0x5b,
            0xd, 0xba, 0x17, 0x7d, 0xd3, 0x10, 0xb1, 0x37, 0x41, 0x91, 0x7d, 0xeb,
            0x1, 0x4d, 0x71, 0xe8, 0x59, 0x71, 0x42, 0x8e, 0xd6, 0xf3, 0x29, 0x3b,
            0x90, 0xf2, 0xd1, 0xaf, 0x65, 0x1e, 0xb3};
      
        if (!gcry_check_version (GCRYPT_VERSION))
        {
          fprintf (stderr, "Version mismatch %s <-> %s \n", gcry_check_version (NULL), GCRYPT_VERSION);
          return 1;
        }
  
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  
        if (gcry_md_open(&mac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != GPG_ERR_NO_ERROR)
        {
          fprintf (stderr, "gcry_md_open error\n");
          return 2;
        }
  
        gcry_md_setkey (mac, key, sizeof (key));
        gcry_md_write (mac, data, sizeof (data));
  
        if (memcmp(gcry_md_read (mac, 0), result, gcry_md_get_algo_dlen (gcry_md_get_algo (mac))) != 0)
        {
          fprintf (stderr, "memcmp error\n");
          return 3;
        }
  
        gcry_md_close (mac);
  
        return 0;
    ]])],
  [AC_MSG_RESULT([yes])],
  [
   RESULT=$?
   if test $RESULT = 3
   then
     AC_MSG_FAILURE([HMAC test vector does not match. This is a known problem with libgcrypt 1.2.2 on Windows and fixed in 1.4.6.])
   fi
   if test $RESULT = 2
   then
     AC_MSG_FAILURE([HMAC test failed])
   fi
   if test $RESULT = 1
   then
     AC_MSG_FAILURE([libgcrypt header version does not match library version])
   fi
  ])
AC_LANG_POP(C)
fi	# $build = $target

# libcurl
LIBCURL_CHECK_CONFIG(,7.20.1,,AC_MSG_ERROR([GNUnet requires libcurl >= 7.20.1]))
# restore LIBS
LIBS=$SAVE_LIBS


AC_CHECK_HEADERS([glpk.h],[glpk=true],[gplk=false])
AC_CHECK_LIB([glpk],[glp_create_prob],,[gplk=false])
# GLPK must support atm MLP presolving, version >= 4.32
AC_CHECK_MEMBERS(glp_iocp.presolve,,[gplk=false],[[#include <glpk.h>]])
if test x$gplk = xfalse
then
	AM_CONDITIONAL(HAVE_LIBGLPK, false)
	AC_MSG_WARN([GNUnet requires GLPK  >= 4.32])
else
	AM_CONDITIONAL(HAVE_LIBGLPK, true)
	AC_DEFINE([HAVE_LIBGLPK],[1],[Have GLPK])
fi


# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])

# test for libextractor
extractor=0
AC_MSG_CHECKING(for libextractor)
AC_ARG_WITH(extractor,
   [  --with-extractor=PFX    base of libextractor installation],
   [AC_MSG_RESULT([$with_extractor])
    case $with_extractor in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
            extractor=1))
        ;;
      *)
        LDFLAGS="-L$with_extractor/lib $LDFLAGS"
        CPPFLAGS="-I$with_extractor/include $CPPFLAGS"
        AC_CHECK_HEADERS(extractor.h,
          AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
            EXT_LIB_PATH="-L$with_extractor/lib $EXT_LIB_PATH"
            extractor=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-extractor not specified])
    AC_CHECK_HEADERS(extractor.h,
     AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
      extractor=1))])
if test "$extractor" != 1
then
 AC_MSG_ERROR([GNUnet requires libextractor])
fi
# restore LIBS
LIBS=$SAVE_LIBS

# test for libunistring
gl_LIBUNISTRING
if test $HAVE_LIBUNISTRING != yes; then
 AC_MSG_ERROR([GNUnet requires libunistring])
fi
if test $gl_libunistring_hexversion -le 2305; then
 AC_MSG_ERROR([GNUnet requires libunistring >= 0.9.1.1])
fi
# restore LIBS
LIBS=$SAVE_LIBS



# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h ctype.h limits.h stdio.h stdlib.h string.h unistd.h stdarg.h signal.h locale.h sys/stat.h sys/types.h],,AC_MSG_ERROR([Compiling GNUnet requires standard UNIX headers files]))

# Checks for headers that are only required on some systems or opional (and where we do NOT abort if they are not there)
AC_CHECK_HEADERS([langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h netinet/in_systm.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h sys/resource.h ifaddrs.h mach/mach.h stddef.h sys/timeb.h terminos.h argz.h ucred.h endian.h sys/endian.h])

SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS

# test for sqlite
sqlite=false
AC_MSG_CHECKING(for SQLite)
AC_ARG_WITH(sqlite,
  [  --with-sqlite=PFX       base of SQLite installation],
  [AC_MSG_RESULT("$with_sqlite")
   case $with_sqlite in
   no)
     ;;
   yes)
    AC_CHECK_HEADERS(sqlite3.h,
     sqlite=true)
     ;;
   *)
    LDFLAGS="-L$with_sqlite/lib $LDFLAGS"
    CPPFLAGS="-I$with_sqlite/include $CPPFLAGS"
    AC_CHECK_HEADERS(sqlite3.h,
     EXT_LIB_PATH="-L$with_sqlite/lib $EXT_LIB_PATH"
     SQLITE_LDFLAGS="-L$with_sqlite/lib"
     SQLITE_CPPFLAGS="-I$with_sqlite/include"
     sqlite=true)
    LDFLAGS=$SAVE_LDFLAGS
    CPPFLAGS=$SAVE_CPPFLAGS
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-sqlite not specified])
    AC_CHECK_HEADERS(sqlite3.h, sqlite=true)])
AM_CONDITIONAL(HAVE_SQLITE, test x$sqlite = xtrue)
AC_SUBST(SQLITE_CPPFLAGS)
AC_SUBST(SQLITE_LDFLAGS)

# test for postgres
postgres=false
AC_MSG_CHECKING(for postgres)
AC_ARG_WITH(postgres,
  [  --with-postgres=PFX       base of postgres installation],
  [AC_MSG_RESULT("$with_postgres")
   case $with_postgres in
   no)
     ;;
   yes)
    AC_CHECK_HEADERS(postgresql/libpq-fe.h,
     postgres=true)
     ;;
   *)
    LDFLAGS="-L$with_postgres/lib $LDFLAGS"
    CPPFLAGS="-I$with_postgres/include $CPPFLAGS"
    AC_CHECK_HEADERS(postgresql/libpq-fe.h,
     EXT_LIB_PATH="-L$with_postgres/lib $EXT_LIB_PATH"
     POSTGRES_LDFLAGS="-L$with_postgres/lib"
     POSTGRES_CPPFLAGS="-I$with_postgres/include"
     postgres=true)
    LDFLAGS=$SAVE_LDFLAGS
    CPPFLAGS=$SAVE_CPPFLAGS
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with-postgres not specified])
    AC_CHECK_HEADERS(postgresql/libpq-fe.h, postgres=true)])
AM_CONDITIONAL(HAVE_POSTGRES, test x$postgres = xtrue)
AC_SUBST(POSTGRES_CPPFLAGS)
AC_SUBST(POSTGRES_LDFLAGS)

# test for libz (maybe required for linking mysql)
zlib=1
AC_CHECK_LIB(z, compress,,zlib=0)
AM_CONDITIONAL(HAVE_ZLIB, test x$zlib = x1)
if test "$zlib" != 1
then
 AC_MSG_ERROR([GNUnet requires zlib])
fi

# mysql & windows
AC_CHECK_TYPES([sigset_t, off_t], [], [], [#include <sys/types.h>])
AC_CHECK_TYPES([size_t], [], [], [#include <stdio.h>])

if test "$build_target" = "mingw"
then
  CYGWIN_MYSQL_MAGIC="#include <mysql/my_global.h>"
fi

# test for mysql
mysql=false
mysqlfail=false
SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS
AC_MSG_CHECKING(for mysql)
AC_ARG_WITH(mysql,
  [  --with-mysql=PFX        base of MySQL installation],
  [AC_MSG_RESULT("$with_mysql")
   if test "$with_mysql" != "no"
   then
    if test "$with_mysql" != "yes"
    then
      LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS $ZLIBS"
      CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
    fi
    AC_CHECK_HEADERS(mysql/mysql.h,
     AC_CHECK_LIB(mysqlclient, mysql_init,
      MYSQL_LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql"
      MYSQL_CPPFLAGS="-I$with_mysql/include"

      mysql=true), [], [$CYGWIN_MYSQL_MAGIC])
   fi
  ],
  [AC_MSG_RESULT([--with-mysql not specified])
   LDFLAGS="-L/usr/lib/mysql $LDFLAGS $ZLIBS"
   AC_CHECK_LIB(mysqlclient, mysql_init,
    [AC_CHECK_HEADERS(mysql/mysql.h,
      MYSQL_LDFLAGS="-L/usr/lib/mysql"
      mysql=true

     , [], [$CYGWIN_MYSQL_MAGIC])])
  ])

AC_SUBST(MYSQL_LDFLAGS)
AC_SUBST(MYSQL_CPPFLAGS)

# additional version check for mysql
AC_ARG_ENABLE(mysql-version-check, [  --disable-mysql-version-check  do not check MySQL version],, enable_mysql_version_check=yes)
if test "$mysql" = "true" -a "x$enable_mysql_version_check" = "xyes"
then
  AC_MSG_CHECKING(mysql version)
  AC_RUN_IFELSE([AC_LANG_PROGRAM(
    [[$CYGWIN_MYSQL_MAGIC
      #include <mysql/mysql.h>]],
    [[if (MYSQL_VERSION_ID < 40100)
        return(-1);
      else
        return(0);
    ]])
    ],mysql=true,mysql=false)
  if test "$mysql" = "false"
  then
    mysqlfail=true
    AC_MSG_RESULT([fail, >= 4.1 required])
  else
    AC_MSG_RESULT(ok)
  fi
fi
AM_CONDITIONAL(HAVE_MYSQL, test x$mysql = xtrue)
AM_CONDITIONAL(HAVE_MYSQLE, test "0" = "1")
# restore LIBS
LIBS=$SAVE_LIBS
LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

if test "$sqlite" = 0 -a "$mysql" = 0
then
 AC_MSG_ERROR([GNUnet requires SQLite or MySQL])
fi

# libmicrohttpd
lmhd=0
AC_MSG_CHECKING([for libmicrohttpd])
AC_ARG_WITH(microhttpd,
   [  --with-microhttpd=PFX   base of libmicrohttpd installation],
   [AC_MSG_RESULT([$with_microhttpd])
    case $with_microhttpd in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS([microhttpd.h],
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
              lmhd=1),
	    [],[#include "src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "src/include/platform.h"])
        ;;
      *)
        LDFLAGS="-L$with_microhttpd/lib $LDFLAGS"
        CPPFLAGS="-I$with_microhttpd/include $CPPFLAGS"
        AC_CHECK_HEADERS(microhttpd.h,
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
              EXT_LIB_PATH="-L$with_microhttpd/lib $EXT_LIB_PATH"
              lmhd=1),
	    [],[#include "src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "src/include/platform.h"])
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-microhttpd not specified])
    AC_CHECK_HEADERS([microhttpd.h],
      AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
        AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
          lmhd=1),
	[],[#include "src/include/platform.h"
            #include <microhttpd.h>]),,
       [#include "src/include/platform.h"])])
AM_CONDITIONAL(HAVE_MHD, test x$lmhd = x1)
AC_DEFINE_UNQUOTED([HAVE_MHD], $lmhd, [We have libmicrohttpd])


# restore LIBS
LIBS=$SAVE_LIBS

# check for python & pexpect (used for some testcases only)
AM_PATH_PYTHON([2.6],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

if test "$PYTHON" != :
then
  AC_MSG_CHECKING([for pexpect])
  $PYTHON -c "import pexpect" > /dev/null 2> /dev/null
  PYEX=$?
  AM_CONDITIONAL(HAVE_PYTHON_PEXPECT, test $PYEX -eq 0)
  if test $PYEX -eq 0
  then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([not found])
  fi
else
  AM_CONDITIONAL(HAVE_PYTHON_PEXPECT, 0)
fi


# check for gettext
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.16.1])

# check for iconv
AM_ICONV

# Checks for standard typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_HEADER_TIME
AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_STRUCT_TM

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
   [ AC_DEFINE(HAVE_SOCKADDR_IN_SIN_LEN, 1, [Do we have sockaddr_in.sin_len?])
   ],
   [],
   [
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <netinet/in.h>
   ])



# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_CHOWN

AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_FUNCS([floor gethostname memmove rmdir strncasecmp strrchr strtol atoll dup2 fdatasync ftruncate gettimeofday memset mkdir mkfifo select socket strcasecmp strchr strdup strerror strstr clock_gettime getrusage rand uname setlocale getcwd mktime gmtime_r gmtime strlcpy strlcat ftruncate stat64 sbrk mmap mremap setrlimit sysconf gethostbyaddr initgroups getifaddrs freeifaddrs getnameinfo getaddrinfo inet_ntoa localtime_r nl_langinfo putenv realpath strndup gethostbyname2 gethostbyname getpeerucred getpeereid setresuid])

# restore LIBS
LIBS=$SAVE_LIBS

gn_user_home_dir="~/.gnunet"
AC_ARG_WITH(user-home-dir,
        AC_HELP_STRING(
                [--with-user-home-dir=DIR],
                [default user home directory (~/.gnunet)]),
        [gn_user_home_dir=$withval])
AC_SUBST(GN_USER_HOME_DIR, $gn_user_home_dir)
gn_daemon_home_dir="/var/lib/gnunet"
AC_ARG_WITH(daemon-home-dir,
        AC_HELP_STRING(
                [--with-daemon-home-dir=DIR],
                [default daemon home directory (/var/lib/gnunet)]),
        [gn_daemon_home_dir=$withval])
AC_SUBST(GN_DAEMON_HOME_DIR, $gn_daemon_home_dir)
gn_daemon_config_dir="/etc"
AC_ARG_WITH(daemon-config-dir,
        AC_HELP_STRING(
                [--with-daemon-config-dir=DIR],
                [default daemon config directory (/etc)]),
        [gn_daemon_config_dir=$withval])
AC_SUBST(GN_DAEMON_CONFIG_DIR, $gn_daemon_config_dir)

GN_INTLINCL=""
GN_LIBINTL="$LTLIBINTL"
AC_ARG_ENABLE(framework, [  --enable-framework      enable Mac OS X framework build helpers],enable_framework_build=$enableval)
AM_CONDITIONAL(WANT_FRAMEWORK, test x$enable_framework_build = xyes)
if test x$enable_framework_build = xyes
then
  AC_DEFINE([FRAMEWORK_BUILD], 1, [Build a Mac OS X Framework])
  GN_INTLINCL='-I$(top_srcdir)/src/intlemu'
  GN_LIBINTL='$(top_builddir)/src/intlemu/libintlemu.la -framework CoreFoundation'
  AC_LIB_APPENDTOVAR([CPPFLAGS], [$GN_INTLINCL]) 
fi

GN_LIB_LDFLAGS="-export-dynamic -no-undefined"
GN_PLUGIN_LDFLAGS="-export-dynamic -avoid-version -module -no-undefined"

AC_SUBST(GN_LIB_LDFLAGS)
AC_SUBST(GN_PLUGIN_LDFLAGS)
AC_SUBST(GN_INTLINCL)
AC_SUBST(GN_LIBINTL)

AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(EXT_LIB_PATH)
AC_SUBST(EXT_LIBS)

AC_SUBST(LIBPREFIX)
AC_SUBST(DLLDIR)
AC_SUBST(EXT_LIB_PATH)


# test for sudo
AC_MSG_CHECKING(for sudo)
AC_ARG_WITH(sudo,
  [  --with-sudo=PATH       path to sudo binary (or just yes)],
  [AC_MSG_RESULT("$with_sudo")
   case $with_sudo in
   no)
     SUDO_BINARY=
     ;;
   yes)
     SUDO_BINARY=sudo
     ;;
   *)
     SUDO_BINARY=$with_sudo
    ;;
   esac
  ],
  [AC_MSG_RESULT([no])])
AC_SUBST(SUDO_BINARY)


# test for gnunetdns group name
GNUNETDNS_GROUP=gnunetdns
AC_MSG_CHECKING(for gnunetdns group name)
AC_ARG_WITH(gnunetdns,
  [  --with-gnunetdns=GRPNAME       name for gnunetdns group],
  [AC_MSG_RESULT("$with_gnunetdns")
   case $with_gnunetdns in
   no)
     GNUNETDNS_GROUP=gnunet
     ;;
   yes)
     GNUNETDNS_GROUP=gnunetdns
     ;;
   *)
     GNUNETDNS_GROUP=$with_gnunetdns
    ;;
   esac
  ],
  [AC_MSG_RESULT([gnunetdns])])
AC_SUBST(GNUNETDNS_GROUP)


# should 'make check' run tests?
AC_MSG_CHECKING(whether to run tests)
AC_ARG_ENABLE([testruns],
   [AS_HELP_STRING([--disable-testruns], [disable running tests on make check (default is YES)])],
   [enable_tests_run=${enableval}],
   [enable_tests_run=yes])
AC_MSG_RESULT($enable_test_run)
AM_CONDITIONAL([ENABLE_TEST_RUN], [test "x$enable_tests_run" = "xyes"])

# should expensive tests be run?
AC_MSG_CHECKING(whether to run expensive tests)
AC_ARG_ENABLE([expensivetests],
   [AS_HELP_STRING([--enable-expensive-tests], [enable running expensive testcases])],
   [enable_expensive=${enableval}],
   [enable_expensive=no])
AC_MSG_RESULT($enable_expensive)
AM_CONDITIONAL([HAVE_EXPENSIVE_TESTS], [test "x$enable_expensive" = "xyes"])

# should benchmarks be run?
AC_MSG_CHECKING(whether to run benchmarks during make check)
AC_ARG_ENABLE([benchmarks],
   [AS_HELP_STRING([--enable-benchmarks], [enable running benchmarks during make check])],
   [enable_benchmarks=${enableval}],
   [enable_benchmarks=no])
AC_MSG_RESULT($enable_benchmarks)
AM_CONDITIONAL([HAVE_BENCHMARKS], [test "x$enable_benchmarks" = "xyes"])

# should experimental code be compiled (code that may not yet compile)?
AC_MSG_CHECKING(whether to compile experimental code)
AC_ARG_ENABLE([experimental],
   [AS_HELP_STRING([--enable-experimental], [enable compiling experimental code])],
   [enable_experimental=${enableval}],
   [enable_experimental=no])
AC_MSG_RESULT($enable_experimental)
AM_CONDITIONAL([HAVE_EXPERIMENTAL], [test "x$enable_experimental" = "xyes"])

# should code be enabled that works around missing OS functionality on Windows?
# used for test cases
if test $build_target = "mingw"
then
	workarounds=1
else
  AC_MSG_CHECKING(whether to enable windows workarounds)
  AC_ARG_ENABLE([windows_workarounds], 
     [AS_HELP_STRING([--enable-windows_workarounds], [enable workarounds used on Windows (only useful for test cases)])],
     [enable_workarounds=${enableval}],
     [enable_workarounds=no])
  AC_MSG_RESULT($enable_workarounds)
  if test x$enable_windows_workarounds = "xyes"
  then
     workarounds=1
  else
     workarounds=0
   fi
fi
AC_DEFINE_UNQUOTED([ENABLE_WINDOWS_WORKAROUNDS], $workarounds, [enable workarounds used on Windows (only useful for test cases)])

# gcov compilation
AC_MSG_CHECKING(whether to compile with support for code coverage analysis)
AC_ARG_ENABLE([coverage], 
              AS_HELP_STRING([--enable-coverage],
                             [compile the library with code coverage support]),
              [use_gcov=${enableval}], 
              [use_gcov=no])
AC_MSG_RESULT($use_gcov)
AM_CONDITIONAL([USE_COVERAGE], [test "x$use_gcov" = "xyes"])


AC_CONFIG_FILES([ 
Makefile
contrib/Makefile
doc/Makefile
doc/man/Makefile
m4/Makefile
po/Makefile.in 
src/Makefile
src/arm/Makefile
src/arm/arm.conf
src/ats/Makefile
src/ats/ats.conf
src/block/Makefile
src/chat/Makefile
src/chat/chat.conf
src/core/Makefile
src/core/core.conf
src/datacache/Makefile
src/datastore/Makefile
src/datastore/datastore.conf
src/dht/Makefile
src/dht/dht.conf
src/dns/Makefile
src/dns/dns.conf
src/dv/Makefile
src/dv/dv.conf
src/exit/Makefile
src/fragmentation/Makefile
src/fs/Makefile
src/fs/fs.conf
src/gns/Makefile
src/gns/gns.conf
src/hello/Makefile
src/include/Makefile
src/include/gnunet_directories.h
src/hostlist/Makefile
src/mesh/Makefile
src/mesh/mesh.conf
src/namestore/Makefile
src/namestore/namestore.conf
src/nat/Makefile
src/nse/Makefile
src/nse/nse.conf
src/peerinfo/Makefile
src/peerinfo/peerinfo.conf
src/peerinfo-tool/Makefile
src/pt/Makefile
src/statistics/Makefile
src/statistics/statistics.conf
src/stream/Makefile
src/template/Makefile
src/testing/Makefile
src/topology/Makefile
src/transport/Makefile
src/transport/transport.conf
src/tun/Makefile
src/util/Makefile
src/util/resolver.conf
src/vpn/Makefile
src/vpn/vpn.conf
src/integration-tests/Makefile
pkgconfig/Makefile
pkgconfig/gnunetarm.pc
pkgconfig/gnunetblock.pc
pkgconfig/gnunetcore.pc
pkgconfig/gnunetdatacache.pc
pkgconfig/gnunetdatastore.pc
pkgconfig/gnunetdht.pc
pkgconfig/gnunetdhtlog.pc
pkgconfig/gnunetdv.pc
pkgconfig/gnunetfragmentation.pc
pkgconfig/gnunetfs.pc
pkgconfig/gnunethello.pc
pkgconfig/gnunetnat.pc
pkgconfig/gnunetnse.pc
pkgconfig/gnunetpeerinfo.pc
pkgconfig/gnunetstatistics.pc
pkgconfig/gnunettesting.pc
pkgconfig/gnunettransport.pc
pkgconfig/gnunetutil.pc
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version
if test "$mysqlfail" = "true"
then
  AC_MSG_NOTICE([NOTICE: MySQL found, but too old. MySQL support will not be compiled.])
fi

# sqlite
if test "x$sqlite" = "x0"
then
  AC_MSG_NOTICE([NOTICE: sqlite not found.  sqLite support will not be compiled.])
fi

if test "x$lmhd" != "x1"
then
 AC_MSG_NOTICE([NOTICE: libmicrohttpd not found, http transport will not be installed.])
fi

AC_MSG_NOTICE([NOTICE: Database support is set to MySQL: $mysql, SQLite: $sqlite, Postgres: $postgres])

if test "$enable_framework_build" = "yes"
then
  AC_MSG_NOTICE([NOTICE: Mac OS X framework build enabled.])
fi

AC_MSG_NOTICE([********************************************
You can compile GNUnet with
	make
now. After that, run (if necessary as 'root')
        make install
to install everything. You may want to create a new user account
to run the GNUnet service:
	adduser gnunet
You also need to create an configuration file that should
specify the path where GNUnet should store data.  For example,
you could store in "/etc/gnunet.conf" the following lines:

[[PATHS]]
SERVICEHOME = /var/lib/gnunet
DEFAULTCONFIG = /etc/gnunet.conf

Now, in order to start your peer, run as the 'gnunet' user
	gnunet-arm -s

Each GNUnet user should also create an (at least initially) empty
configuration file:
	mkdir $HOME/.gnunet/
	touch $HOME/.gnunet/gnunet.conf
	
Optionally, download and compile:
- gnunet-gtk to get a GUI for file-sharing and configuration.
********************************************])
