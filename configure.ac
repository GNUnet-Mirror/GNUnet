# This file is part of GNUnet.
# (C) 2001--2019 GNUnet e.V.
#
# GNUnet is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL3.0-or-later
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ(2.61)
# Checks for programs.
AC_INIT([gnunet], [0.11.4], [bug-gnunet@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])

# check for legacy option that is no longer supported (#5627) and fail hard
AC_ARG_WITH(nssdir,
   [  --with-nssdir=DIR    legacy switch, no longer supported, do not use],
   [AC_MSG_RESULT([$with_nssdir])
    case $with_nssdir in
      no)
        ;;
      *)
        AC_MSG_ERROR([--with-nssdir is no longer supported])
        ;;
     esac
   ])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([gnunet_config.h])
AH_TOP([#define _GNU_SOURCE  1])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_AWK
AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_OBJC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
LT_INIT([disable-static dlopen win32-dll])
AC_SUBST(MKDIR_P)

# large file support
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO


CFLAGS="-Wall $CFLAGS"
# use '-fno-strict-aliasing', but only if the compiler can take it
if gcc -fno-strict-aliasing -S -o /dev/null -xc /dev/null >/dev/null 2>&1;
then
 CFLAGS="-fno-strict-aliasing $CFLAGS"
fi

# Use Linux interface name unless the OS has a different preference
DEFAULT_INTERFACE="\"eth0\""

funcstocheck="getnameinfo gethostname gethostbyname gethostbyaddr getaddrinfo getaddrinfo_a"

# Srcdir in a form that native compiler understands (i.e. DOS path on W32)
native_srcdir=$srcdir

OLD_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,--unresolved-symbols=report-all"

# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(DARWIN,1,[This is an Apple Darwin system])
     CPPFLAGS="-D_APPLE_C_SOURCE $CPPFLAGS"
     CFLAGS="-fno-common $CFLAGS"
     LDFLAGS="$OLD_LDFLAGS"
     AC_MSG_WARN([WARNING: The VPN application cannot be compiled on your OS])
     AC_CHECK_LIB(intl, gettext)
     build_target="darwin"
     DEFAULT_INTERFACE="\"en0\""
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux kernel])
     build_target="linux"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     AC_PATH_XTRA
     ;;
*freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     build_target="freebsd"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
*openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     LIBS=`echo $LIBS | sed -e "s/-ldl//"`
     build_target="openbsd"
     LIBPREFIX=
     DLLDIR=lib
     UNIXONLY="#"
     ;;
*netbsd*)
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
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux kernel])
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
     LDFLAGS="$LDFLAGS -Wl,--export-all-symbols"
     LIBS="$LIBS -lws2_32 -lplibc -lgnurx -lole32"
     CFLAGS="-mms-bitfields $CFLAGS"
     CPPFLAGS="-D_WIN32_WINNT=0x0501 -DHAVE_STAT64=1 -D__USE_MINGW_ANSI_STDIO=1 $CPPFLAGS"
     build_target="mingw"
     AC_PROG_CXX
     LIBPREFIX=lib
     DLLDIR=bin
     UNIXONLY=""
     funcstocheck=""
     native_srcdir=$(cd $srcdir; pwd -W)
     ;;
gnu*)
     AC_DEFINE_UNQUOTED(GNU,1,[This is a GNU system])
     build_target="gnu"
     UNIXONLY="#"
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
AM_CONDITIONAL(GNU, test "$build_target" = "gnu")

AC_MSG_RESULT([$build_target])
AC_SUBST(build_target)
AM_CONDITIONAL([am__fastdepOBJC], false)
AC_UNALIGNED_64_ACCESS

# some other checks for standard libs
AC_SEARCH_LIBS([gethostbyname], [nsl ws2_32])
AC_SEARCH_LIBS([memrchr], [],
               AC_DEFINE(HAVE_MEMRCHR,1,[memrchr supported]), [])
AC_SEARCH_LIBS([memset_s], [],
               AC_DEFINE(HAVE_MEMSET_S,1,[memset_s supported]), [])
AC_SEARCH_LIBS([memset_s], [],
               AC_DEFINE(HAVE_EXPLICIT_BZERO,1,[explicit_bzero supported]), [])
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))

AC_CHECK_PROG(VAR_GETOPT_BINARY, getopt, true, false)
AM_CONDITIONAL(HAVE_GETOPT_BINARY, $VAR_GETOPT_BINARY)

AC_CHECK_PROG(VAR_SSH_BINARY, ssh, true, false)
AM_CONDITIONAL(HAVE_SSH_BINARY, $VAR_SSH_BINARY)
AM_CONDITIONAL(HAVE_SSH_KEY,  ssh -D 12345 -o "BatchMode yes" -o "UserKnownHostsFile /tmp/gnunet_test_cosks_ssh_garbage" -o "StrictHostKeyChecking no" 127.0.0.1 echo -n)
rm -f /tmp/gnunet_test_cosks_ssh_garbage

# autotools' m4 for python has no maximum version!
# python3.4 - python3.7 for tests
m4_define_default([_AM_PYTHON_INTERPRETER_LIST],[python3 python3.4 python3.5 python3.6 python3.7 python])
AM_PATH_PYTHON([3.4],, [:])
AC_SUBST([PYTHON])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

# perl
AC_PATH_PROG( PERL, perl, ,
              $PATH:/usr/local/bin/perl:/usr/bin/:/usr/local/bin )
AC_SUBST([PERL])

# iptables is a soft requirement to run tests
AC_PATH_TARGET_TOOL(VAR_IPTABLES_BINARY, iptables, false)

if test x"$VAR_IPTABLES_BINARY" = x"false"
then
  if test -x "/sbin/iptables"
  then
    VAR_IPTABLES_BINARY="/sbin/iptables"
  elif test -x "/usr/sbin/iptables"
  then
    VAR_IPTABLES_BINARY="/usr/sbin/iptables"
  fi
fi

if test x"$VAR_IPTABLES_BINARY" != x"false"
then
AC_DEFINE_UNQUOTED([IPTABLES], "$VAR_IPTABLES_BINARY", [Path to iptables])
else
AC_MSG_WARN([warning: 'iptables' not found.])
fi

# ip6tables is a soft requirement for some features
AC_PATH_TARGET_TOOL(VAR_IP6TABLES_BINARY, ip6tables, false)

if test x"$VAR_IP6TABLES_BINARY" = x"false"
then
  if test -x "/sbin/ip6tables"
  then
    VAR_IP6TABLES_BINARY="/sbin/ip6tables"
  elif test -x "/usr/sbin/ip6tables"
  then
    VAR_IP6TABLES_BINARY="/usr/sbin/ip6tables"
  fi
fi

if test x"$VAR_IP6TABLES_BINARY" != x"false"
then
AC_DEFINE_UNQUOTED([IP6TABLES], "$VAR_IP6TABLES_BINARY", [Path to ip6tables])
else
AC_MSG_WARN([warning: 'ip6tables' not found.])
fi

# ip is a soft requirement for some features
AC_PATH_TARGET_TOOL(VAR_IP_BINARY, ip, false)

if test x"$VAR_IP_BINARY" = x"false"
then
  if test -x "/sbin/ip"
  then
    VAR_IP_BINARY="/sbin/ip"
  elif test -x "/usr/sbin/ip"
  then
    VAR_IP_BINARY="/usr/sbin/ip"
  fi
fi

if test x"$VAR_IP_BINARY" != x"false"
then
AC_DEFINE_UNQUOTED([PATH_TO_IP], "$VAR_IP_BINARY", [Path to ip])
else
AC_MSG_WARN([warning: 'ip' not found.])
fi

# locate 'ifconfig'
AC_PATH_TARGET_TOOL(VAR_IFCONFIG_BINARY, ifconfig, false)

AC_CHECK_PROG(VAR_IFCONFIG_BINARY, ifconfig, true, false)
if test x"$VAR_IFCONFIG_BINARY" = x"false"
then
  if test -x "/sbin/ifconfig"
  then
    VAR_IFCONFIG_BINARY="/sbin/ifconfig"
  elif test -x "/usr/sbin/ifconfig"
  then
    VAR_IFCONFIG_BINARY="/usr/sbin/ifconfig"
  fi
fi
if test x"$VAR_IFCONFIG_BINARY" != x"false"
then
AC_DEFINE_UNQUOTED([IFCONFIG], "$VAR_IFCONFIG_BINARY", [Path to ifconfig])
else
AC_MSG_WARN(['ifconfig' not found.])
fi


AC_PATH_TARGET_TOOL(VAR_SYSCTL_BINARY, sysctl, false)

AC_CHECK_PROG(VAR_SYSCTL_BINARY, sysctl, true, false)
AS_IF([test x"$VAR_SYSCTL_BINARY" = x"false"],
      [AS_IF([test -x "/sbin/sysctl"],
             [VAR_SYSCTL_BINARY="/sbin/sysctl"],
             [AS_IF([test -x "/usr/sbin/sysctl"],
                    [VAR_SYSCTL_BINARY="/usr/sbin/sysctl"])])])
AS_IF([test x"$VAR_SYSCTL_BINARY" != x"false"],
      [AC_DEFINE_UNQUOTED([SYSCTL], "$VAR_SYSCTL_BINARY", [Path to sysctl])],
      [AC_MSG_WARN(['sysctl' not found.])])

# miniupnpc / upnpc binary is a soft runtime requirement
AC_PATH_TARGET_TOOL(VAR_UPNPC_BINARY, upnpc, false)

if test x"$VAR_UPNPC_BINARY" != x"false"
then
AC_DEFINE_UNQUOTED([UPNPC], "$VAR_UPNPC_BINARY", [Path to upnpc binary])
else
AC_MSG_WARN([warning: 'upnpc' binary not found.])
fi

AC_CHECK_MEMBER(struct tm.tm_gmtoff,
  [AC_DEFINE(HAVE_TM_GMTOFF, 1,
     [Define if struct tm has the tm_gmtoff member.])],
     ,
     [#include <time.h>])

AC_CHECK_DECLS([_stati64])

# 'save' libs; only those libs found so far will be
# linked against _everywhere_.  For the others, we
# will be more selective!
SAVE_LIBS=$LIBS

have_addrinfo_a=0
AC_CHECK_LIB(anl, getaddrinfo_a, [have_addrinfo_a=1 AC_DEFINE(HAVE_GETADDRINFO_A,1,[getaddrinfo_a supported])])
AM_CONDITIONAL(HAVE_GETADDRINFO_A, [test "$have_addrinfo_a" = 1])


# tests only run on Windows
if test "x$build_target" = "xmingw"
then
  AC_CHECK_LIB(plibc, plibc_init, [], [AC_MSG_ERROR([GNUnet requires PlibC on Windows])])
  AC_CHECK_LIB(gnurx, regexec, [], [AC_MSG_ERROR([GNUnet requires libgnurx on Windows])])
fi

# libgcrypt
gcrypt=0
NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.6.0


AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION", gcrypt=1)
AC_CHECK_DECLS([gcry_mpi_set_opaque_copy], [], [], [[#include <gcrypt.h>]])

if test $gcrypt = 0
then
  AC_MSG_ERROR([[
***
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION (API $NEED_LIBGCRYPT_API)
***  is required.)
***]])
fi
AC_DEFINE_UNQUOTED([NEED_LIBGCRYPT_VERSION], "$NEED_LIBGCRYPT_VERSION", [required libgcrypt version])

AC_CHECK_DECLS([struct in6_ifreq], [], [], [[#include <linux/if_tun.h>]])



# should the build process be building the documentation?
AC_MSG_CHECKING(whether to build documentation)
AC_ARG_ENABLE([documentation],
   [AS_HELP_STRING([--disable-documentation], [do not build the documentation])],
   [documentation=${enableval}],
   [documentation=yes])
AC_MSG_RESULT($documentation)
if test "x$documentation" = "xyes"
then
  AM_CONDITIONAL([DOCUMENTATION],true)
  AC_DEFINE([DOCUMENTATION],[1],[Building the documentation])
else
  AM_CONDITIONAL([DOCUMENTATION],false)
  AC_DEFINE([DOCUMENTATION],[0],[Not building the documentation])
fi

# FIXME: Something is wrong about this in the output of ./configure runs
AC_MSG_CHECKING(wether to include generated texi2mdoc output in installation)
AC_ARG_ENABLE([texi2mdoc-generation],
    [AS_HELP_STRING([--enable-texi2mdoc-generation], [include generated texi2mdoc output in installation])],
    [texi2mdoc_generation=${enableval}],
    [texi2mdoc_generation=no])
AC_MSG_RESULT($texi2mdoc_generation)
if test "x$texi2mdoc_generation" = "xyes"
then
  if test "$texi2mdoc" = 0
  then
  AC_MSG_WARN([ERROR: mdoc output currently requires texi2mdoc.])
  AC_MSG_WARN([ERROR: texi2mdoc can be obtained via your Operating System])
  AC_MSG_WARN([ERROR: package manager or from https://mandoc.bsd.lv/texi2mdoc/])
  else
  AM_CONDITIONAL([TEXI2MDOC_GENERATION],true)
  AC_DEFINE([TEXI2MDOC_GENERATION],[1],[Building section 7 mdoc output])
  fi
else
  AM_CONDITIONAL([TEXI2MDOC_GENERATION],false)
  AC_DEFINE([TEXI2MDOC_GENERATION],[0],[Not building section 7 mdoc output])
fi

# should the build process be building only the documentation?
AC_MSG_CHECKING(whether to build only documentation)
AC_ARG_ENABLE([documentation-only],
   [AS_HELP_STRING([--enable-documentation-only], [build only the documentation])],
   [documentation_only=${enableval}],
   [documentation_only=no])
AC_MSG_RESULT($documentation_only)
if test "x$documentation_only" = "xyes"
then
  AM_CONDITIONAL([DOCUMENTATION_ONLY],true)
  AC_DEFINE([DOCUMENTATION_ONLY],[1],[Building only the documentation])
else
  AM_CONDITIONAL([DOCUMENTATION_ONLY],false)
  AC_DEFINE([DOCUMENTATION_ONLY],[0],[Not building only the documentation])
fi

# should the build process be including the manpages? (default: yes)
AC_MSG_CHECKING(whether to include man pages)
AC_ARG_ENABLE([include-manpages],
   [AS_HELP_STRING([--disable-include-manpages], [Do not include the man pages in build and installation])],
   [include_manpages=${enableval}],
   [include_manpages=yes])
AC_MSG_RESULT($include_manpages)
if test "x$include_manpages" = "xyes"
then
  AM_CONDITIONAL([INCLUDE_MANPAGES],true)
  AC_DEFINE([INCLUDE_MANPAGES],[1],[Including the man pages in the build and installation])
else
  AM_CONDITIONAL([INCLUDE_MANPAGES],false)
  AC_DEFINE([INCLUDE_MANPAGES],[0],[Not including the man pages in the build and installation])
fi

# Adam shostack suggests the following for Windows:
# -D_FORTIFY_SOURCE=2 -fstack-protector-all
AC_ARG_ENABLE(gcc-hardening,
   AS_HELP_STRING(--enable-gcc-hardening, enable compiler security checks),
[if test x$enableval = xyes; then
    CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all"
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


AC_ARG_ENABLE(sanitizer,
  AS_HELP_STRING(--enable-sanitizer, enable Address Sanitizer and Undefined Behavior Sanitizer),
[if test x$enableval = xyes; then
   LDFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
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

# should memory poisoning be enabled?
AC_MSG_CHECKING(whether to poison freed memory)
AC_ARG_ENABLE([poisoning],
   [AS_HELP_STRING([--enable-poisoning], [enable poisoning of freed memory (good for debugging)])],
   [enable_poisoning=${enableval}],
   [
     if test "x$extra_logging" != "xGNUNET_NO"; then
       enable_poisoning="defaults to yes (extra logging is enabled)"
     else
       enable_poisoning=no
     fi
   ])
AC_MSG_RESULT($enable_poisoning)
if test ! "x$enable_poisoning" = "xno"; then
  enable_poisoning=1
else
  enable_poisoning=0
fi
AC_DEFINE_UNQUOTED([ENABLE_POISONING],[$enable_poisoning],[1 if freed memory should be poisoned, 0 otherwise])

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
  ],
  [AC_MSG_RESULT([cross compiling, test skipped])])
AC_LANG_POP(C)
fi	# $build = $target

# check for bluetooth library
bluetooth=0
AC_CHECK_LIB(bluetooth, ba2str,[AC_CHECK_HEADER([bluetooth/bluetooth.h],bluetooth=1)])
if test "$build_target" = "mingw"
then
  bluetooth=1
fi
AM_CONDITIONAL(HAVE_LIBBLUETOOTH, [test "$bluetooth" = 1])
if test "$bluetooth" = 1
then
  AC_DEFINE([HAVE_LIBBLUETOOTH],[1],[Have bluetooth library])
else
  AC_DEFINE([HAVE_LIBBLUETOOTH],[0],[Lacking bluetooth library])
fi

# check for zbar library
zbar=0
AC_MSG_CHECKING(for libzbar)
AC_ARG_WITH(zbar,
   [  --with-zbar=PFX    base of libzbar installation],
   [AC_MSG_RESULT([$with_zbar])
    case $with_zbar in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(zbar.h,
          AC_CHECK_LIB([zbar], [zbar_processor_create],
            zbar=1))
        ;;
      *)
        LDFLAGS="-L$with_zbar/lib $LDFLAGS"
        CPPFLAGS="-I$with_zbar/include $CPPFLAGS"
        AC_CHECK_HEADERS(zbar.h,
          AC_CHECK_LIB([zbar], [zbar_processor_create],
            EXT_LIB_PATH="-L$with_zbar/lib $EXT_LIB_PATH"
            zbar=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-zbar not specified])
    AC_CHECK_HEADERS(zbar.h,
     AC_CHECK_LIB([zbar], [zbar_processor_create],
      zbar=1))])
AM_CONDITIONAL(HAVE_ZBAR, [test "$zbar" = 1])
AS_IF([test "x$zbar" = x1],
      [AC_DEFINE([HAVE_ZBAR],[1],[Have zbar library])],
      [AC_DEFINE([HAVE_ZBAR],[0],[Lacking zbar library])])

# check for jansson library
jansson=0
AC_MSG_CHECKING(for libjansson)
AC_ARG_WITH(jansson,
   [  --with-jansson=PFX    base of libjansson installation],
   [AC_MSG_RESULT([$with_jansson])
    case $with_jansson in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(jansson.h,
          AC_CHECK_LIB([jansson], [json_loads],
            jansson=1))
        ;;
      *)
        LDFLAGS="-L$with_jansson/lib $LDFLAGS"
        CPPFLAGS="-I$with_jansson/include $CPPFLAGS"
        AC_CHECK_HEADERS(jansson.h,
          AC_CHECK_LIB([jansson], [json_loads],
            EXT_LIB_PATH="-L$with_jansson/lib $EXT_LIB_PATH"
            jansson=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-jansson not specified])
    AC_CHECK_HEADERS(jansson.h,
     AC_CHECK_LIB([jansson], [json_loads],
      jansson=1))])
AM_CONDITIONAL(HAVE_JANSSON, [test "$jansson" = 1])
AM_CONDITIONAL(HAVE_JSON, [test x$jansson = x1])
AS_IF([test "x$jansson" = x1],
      [AC_DEFINE([HAVE_JANSSON],[1],[Have jansson library])],
      [AC_DEFINE([HAVE_JANSSON],[0],[Lacking jansson library])])


# check for libpulse(audio) library
pulse=0
AC_CHECK_LIB(pulse,pa_stream_peek,
  [AC_CHECK_HEADER([pulse/simple.h],pulse=1)])
AS_IF([test "$build_target" = "mingw"],
      [pulse=0])
AS_IF([test "$pulse" = 1],
      [AC_DEFINE([HAVE_PULSE],[1],[Have libpulse(audio) library])])

# check for libopus(audio) library
opus=0
AC_CHECK_LIB(opus,opus_decode_float,
  [AC_CHECK_HEADER([opus/opus.h],
    [AC_CHECK_DECL([OPUS_SET_GAIN],[opus=1],[],[[#include <opus/opus.h>]]
    )]
  )]
)
AS_IF([test "x$opus" = x1],
      [AC_DEFINE([HAVE_OPUS],[1],[Have libopus library])])

# libogg
AC_CHECK_LIB(ogg, ogg_stream_flush_fill,
        [AC_CHECK_HEADERS([ogg/ogg.h],
          AM_CONDITIONAL(HAVE_OGG, true)
          ogg=1
          AC_DEFINE(HAVE_OGG,1,[Have ogg]),
          AM_CONDITIONAL(HAVE_OGG, false)
          ogg=0
          AC_DEFINE(HAVE_OGG,0,[lacking ogg]))],
        AM_CONDITIONAL(HAVE_OGG, false)
        ogg=0)


PKG_CHECK_MODULES([GLIB],
                  [glib-2.0],
  [# check for pbc library
  pbc=0
   AC_CHECK_HEADER([pbc/pbc.h],pbc=1)
   AC_CHECK_HEADER([gabe.h],abe=1)
   AM_CONDITIONAL(HAVE_PBC, [test "x$pbc" = x1])
   AM_CONDITIONAL(HAVE_ABE, [test "x$abe" = x1])
   AS_IF([test "x$pbc" = x1],
     [AC_DEFINE([HAVE_PBC],[1],[Have pbc library])],
     [AC_DEFINE([HAVE_PBC],[0],[Lacking pbc library])])
   AS_IF([test "x$abe" = x1],
    [AC_DEFINE([HAVE_ABE],[1],[Have ABE library])],
    [AC_DEFINE([HAVE_ABE],[0],[Lacking ABE library])])],
  [# glib-2 not found
   AM_CONDITIONAL(HAVE_PBC, [false])
   AM_CONDITIONAL(HAVE_ABE, [false])
   AC_DEFINE([HAVE_PBC],[0],[Lacking glib library])])

gst=0
PKG_CHECK_MODULES(
  [GST],
  [glib-2.0 gobject-2.0 gstreamer-1.0 gstreamer-app-1.0 gstreamer-audio-1.0],
  [gst=1],
  [gst=0])

# Pulse Audio
if test "x$pulse" != "x1" -o "x$opus" != "x1" -o "x$ogg" != "x1"
then
 if test "x$gst" != "x1"
 then
  conversation_backend=none
  AM_CONDITIONAL(BUILD_PULSE_HELPERS, false)
  AM_CONDITIONAL(BUILD_GST_HELPERS, false)
  AM_CONDITIONAL(BUILD_EXPERIMENTAL_HELPERS, false)
 else
   conversation_backend=gst
   AM_CONDITIONAL(BUILD_PULSE_HELPERS, false)
   AM_CONDITIONAL(BUILD_GST_HELPERS, true)
   AM_CONDITIONAL(BUILD_EXPERIMENTAL_HELPERS, false)
 fi
else

 conversation_backend=pulse
 AM_CONDITIONAL(BUILD_PULSE_HELPERS, true)
 AM_CONDITIONAL(BUILD_GST_HELPERS, false)
 AM_CONDITIONAL(BUILD_EXPERIMENTAL_HELPERS, false)
fi

# libgnurl
LIBGNURL_CHECK_CONFIG(,7.34.0,gnurl=1,gnurl=0)

SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$LIBGNURL_CPPFLAGS $LIBCURL_CPPFLAGS $CPPFLAGS"
LIBS="$LIBGNURL $LIBCURL $LIBS"

# libcurl-gnutls
LIBCURL_CHECK_CONFIG(,7.34.0,[curl=true],[curl=false])
if test "x$curl" = xtrue
then
 AC_CHECK_HEADER([curl/curl.h],
  AC_CHECK_DECLS(CURLINFO_TLS_SESSION,[curl=true],[curl=false],[[#include <curl/curl.h>]]),
  [curl=false])
 # need libcurl-gnutls.so, everything else is not acceptable
 AC_CHECK_LIB([curl-gnutls],[curl_easy_getinfo],,[curl=false])
 # cURL must support CURLINFO_TLS_SESSION, version >= 7.34
fi

# libcurl and libgnurl should be mutually exclusive
AS_IF([test "$gnurl" = 1],
      [AM_CONDITIONAL(HAVE_LIBGNURL, true)
       AC_DEFINE([HAVE_LIBGNURL],[1],[Have libgnurl])
       AM_CONDITIONAL(HAVE_LIBCURL, false)
       AC_DEFINE([HAVE_LIBCURL],[0],[Lacking libcurl])],
      [AS_IF([test "$curl" = true],
             [AM_CONDITIONAL(HAVE_LIBGNURL, false)
              AC_DEFINE([HAVE_LIBGNURL],[0],[Lacking libgnurl])
              AM_CONDITIONAL(HAVE_LIBCURL, true)
              AC_DEFINE([HAVE_LIBCURL],[1],[Have libcurl])],
             [AC_MSG_WARN([ERROR: GNUnet requires libcurl-gnutls or gnurl >= 7.34])
              AM_CONDITIONAL(HAVE_LIBGNURL, false)
              AC_DEFINE([HAVE_LIBGNURL],[0],[Lacking libgnurl])
              AM_CONDITIONAL(HAVE_LIBCURL, false)
              AC_DEFINE([HAVE_LIBCURL],[0],[Lacking libcurl])])])

AC_SEARCH_LIBS(__atomic_load_8, atomic, [have_libatomic=1 AC_DEFINE(HAVE_LIBATOMIC,1,[external libatomic])])
AM_CONDITIONAL(HAVE_LIBATOMIC, [test "$have_libatomic" = 1])

# restore LIBS & CPPFLAGS
LIBS=$SAVE_LIBS
CPPFLAGS=$SAVE_CPPFLAGS

AC_CHECK_HEADERS([glpk.h],[glpk=true],[glpk=false])
# GLPK must support glpk_init_env, version >= 4.43
AC_CHECK_LIB([glpk],[glp_init_env],,[glpk=false])
# GLPK must support atm MLP presolving, version >= 4.32
AC_CHECK_MEMBERS(glp_iocp.presolve,,[glpk=false],[[#include <glpk.h>]])
if test "x$glpk" = xfalse
then
	AM_CONDITIONAL(HAVE_LIBGLPK, false)
	AC_MSG_WARN([ERROR: GNUnet requires GLPK  >= 4.32])
else
	AM_CONDITIONAL(HAVE_LIBGLPK, true)
	AC_DEFINE([HAVE_LIBGLPK],[1],[Have GLPK])
fi


AC_CHECK_HEADERS([nss.h],[nss=true],[nss=false])
if test x$nss = xfalse
then
	AM_CONDITIONAL(HAVE_GLIBCNSS, false)
	AC_MSG_WARN([No GNU libc nss header, will not build NSS plugin])
else
	NSS_INCLUDES="
	#include <nss.h>
	"
	AC_CHECK_DECL([NSS_STATUS_UNAVAIL],
		[AM_CONDITIONAL(HAVE_GLIBCNSS, true)],
		[AM_CONDITIONAL(HAVE_GLIBCNSS, false)
		 AC_MSG_WARN([No nss header fails to define NSS_STATUS_UNAVAIl, will not build NSS plugin])],
		[$NSS_INCLUDES])
fi



# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm],[kvm_open])
AC_CHECK_LIB([kstat],[kstat_open])


# should the build process be restricted to the code required
# for GNU Taler wallets?
AC_MSG_CHECKING(whether to compile GNU Taler Wallet library ONLY)
AC_ARG_ENABLE([taler-wallet],
   [AS_HELP_STRING([--enable-taler-wallet], [only compile for Taler wallet])],
   [taler_only=${enableval}],
   [taler_only=no])
AC_MSG_RESULT($taler_only)
if test "x$taler_only" = "xyes"
then
  AM_CONDITIONAL([TALER_ONLY],true)
  AC_DEFINE([TALER_WALLET_ONLY],[1],[Compiling for Taler wallet])
else
  AM_CONDITIONAL([TALER_ONLY],false)
  AC_DEFINE([TALER_WALLET_ONLY],[0],[Canonical compilation])
fi

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
        AC_CHECK_HEADERS([extractor.h],
          AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
            extractor=1))
        ;;
      *)
        LDFLAGS="-L$with_extractor/lib $LDFLAGS"
        CPPFLAGS="-I$with_extractor/include $CPPFLAGS"
        AC_CHECK_HEADERS([extractor.h],
          AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
            EXT_LIB_PATH="-L$with_extractor/lib $EXT_LIB_PATH"
            extractor=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-extractor not specified])
    AC_CHECK_HEADERS([extractor.h],
     AC_CHECK_LIB([extractor], [EXTRACTOR_plugin_add_defaults],
      extractor=1))])
# restore LIBS
LIBS=$SAVE_LIBS

if test "$extractor" != 1
then
 AM_CONDITIONAL(HAVE_LIBEXTRACTOR, false)
 AC_DEFINE([HAVE_LIBEXTRACTOR],[0],[Lacking libextractor])
else
 AM_CONDITIONAL(HAVE_LIBEXTRACTOR, true)
 AC_DEFINE([HAVE_LIBEXTRACTOR],[1],[Have libextractor])
fi


if test "$taler_only" != yes
then

# Check for libltdl header (#2999)
ltdl=0
AC_MSG_CHECKING(for libltdl)
AC_ARG_WITH(ltdl,
   [  --with-ltdl=PFX    base of libltdl installation],
   [AC_MSG_RESULT([$with_ltdl])
    case $with_ltdl in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS(ltdl.h,
          AC_CHECK_LIB([ltdl], [lt_dlopenext],
            ltdl=1))
        ;;
      *)
        LDFLAGS="-L$with_ltdl/lib $LDFLAGS"
        CPPFLAGS="-I$with_ltdl/include $CPPFLAGS"
        AC_CHECK_HEADERS(ltdl.h,
          AC_CHECK_LIB([ltdl], [lt_dlopenext],
            EXT_LIB_PATH="-L$with_ltdl/lib $EXT_LIB_PATH"
            ltdl=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-ltdl not specified])
    AC_CHECK_HEADERS(ltdl.h,
     AC_CHECK_LIB([ltdl], [lt_dlopenext],
      ltdl=1))])
if test x$ltdl = x1
then
 AC_MSG_RESULT([libltdl found])
else
 AC_MSG_ERROR([GNUnet requires libltdl (from GNU libtool), try installing libltdl-dev])
fi
# restore LIBS
LIBS=$SAVE_LIBS

# libidn and libidn2. The ideal goal is this:
# check for libidn2, if it doesn't exist check for libidn
# if both exist, prefer libidn2
# if none exist, fail and message that libidn or libidn2
# is required with a preference for libidn2.
# TODO: What we have right here can probably be improved.
my_with_libidn=1
AC_ARG_WITH(libidn,
            AS_HELP_STRING([--with-libidn=pathname],
                           [Support IDN (needs libidn)]),
            [],
            [withval="yes"])
AS_IF([test x_$withval = x_yes],
      [AC_CHECK_HEADERS([idna.h],
          AC_MSG_NOTICE([Found idna.h]),
          AC_CHECK_HEADERS([idn/idna.h],
               AC_MSG_NOTICE([Found idn/idna.h]),
               my_with_libidn=0))],
      [AS_IF([test x_$withval != x_no],
             [CFLAGS="$CFLAGS -I$withval/include"
              LDFLAGS="$LDFLAGS -L$withval/lib"
              AC_CHECK_HEADERS([idna.h],
                AC_MSG_NOTICE([Found idna.h]),
	        [AC_MSG_NOTICE([Failed to find idna.h])
                 my_with_libidn=0])],
             [my_with_libidn=0])])

my_with_libidn2=1
AC_ARG_WITH(libidn2,
            AS_HELP_STRING([--with-libidn2=pathname],
                           [Support IDN (needs libidn2)]),
            [],
            [withval="yes"])
AS_IF([test x_$withval = x_yes],
      [AC_CHECK_HEADERS([idn2.h],
       AC_MSG_NOTICE([Found idn2.h]),
       AC_CHECK_HEADERS([idn2/idn2.h],
          AC_MSG_NOTICE([Found idn2/idn2.h]),
          [AC_MSG_NOTICE([Failed to find idn2.h])
           my_with_libidn2=0]))],
      [AS_IF([test x_$withval != x_no],
             [CFLAGS="$CFLAGS -I$withval/include"
              LDFLAGS="$LDFLAGS -L$withval/lib"],
	     [my_with_libidn2=0])])

AC_MSG_CHECKING([if libidn can be used])
# Check for LIBIDNs
there_can_only_be_one=1

working_libidn1=0
working_libidn2=0
AS_IF([test x$my_with_libidn2 = x1],
      [AC_MSG_NOTICE([Checking for libidn2])
       AC_CHECK_LIB([idn2],
                    [idn2_to_unicode_8z8z],
                    [working_libidn2=1
                    LIBS="-lidn2 $LIBS"
 	            AC_DEFINE_UNQUOTED([HAVE_LIBIDN2],
                                       [1],
                                        [Define to 1 if you have 'libidn2' (-lidn2).])],
                     [MISSING_DEPS="${MISSING_DEPS}${MISSING_SEP}libidn2"
                     MISSING_SEP=", "])])
AM_CONDITIONAL(HAVE_LIBIDN2, test x$working_libidn2 = x1)
AS_IF([test x$working_libidn2 = x0],
      [AS_IF([test x$my_with_libidn = x1],
             [AC_MSG_NOTICE([Checking for libidn])
              AC_CHECK_LIB([idn],
                           [idna_to_ascii_8z],
                           [working_libidn1=1
	                   LIBS="-lidn $LIBS"
                             AC_DEFINE_UNQUOTED([HAVE_LIBIDN],
                                                [1],
                                                [Define to 1 if you have 'libidn' (-lidn).])],
                             [there_can_only_be_one=0])],
             [AS_IF([test x$my_with_libidn2 = x1],
                    [there_can_only_be_one=0
                     AC_MSG_FAILURE([* There can only be one libidn.
                                     * Provide either libidn >= 1.13
                                     * or
                                     * libidn2 to the configure
                                     * script via
                                     * --with-libidn2
                                     * --with-libidn])])])])
AM_CONDITIONAL(HAVE_LIBIDN, test x$working_libidn1 = x1)

AS_IF([test "$working_libidn1" = 0 -a "$working_libidn2" = 0],
      [AC_MSG_ERROR([GNUnet requires libidn (or libidn2)])])

AS_IF([test x$there_can_only_be_one = x0],
      [AC_MSG_FAILURE([Missing dependencies: $MISSING_DEPS])])

# test for zlib
SAVE_LDFLAGS=$LDFLAGS
SAVE_CPPFLAGS=$CPPFLAGS
AC_ARG_WITH(zlib,
	    [  --with-zlib[[=DIR]]       use libz in DIR],
	    [AS_IF([test "$withval" = "no"],
		   [AC_MSG_ERROR([GNUnet requires zlib])],
		   [test "$withval" != "yes"],
		   [
		     Z_DIR=$withval
		     CPPFLAGS="${CPPFLAGS} -I$withval/include"
		     LDFLAGS="${LDFLAGS} -L$withval/lib"
		   ])
	    ])
AC_CHECK_HEADER(zlib.h,
		[],
	       	[AC_MSG_ERROR([GNUnet requires zlib])])
AC_CHECK_LIB(z, compress2,
	     [
	      AC_DEFINE([HAVE_ZLIB], [], [Have compression library])
	      if test "x${Z_DIR}" != "x"; then
		      Z_CFLAGS="-I${Z_DIR}/include"
		      Z_LIBS="-L${Z_DIR}/lib -lz"
	      else
		      Z_LIBS="-lz"
	      fi],
	      [AC_MSG_ERROR([GNUnet requires zlib])])
AC_SUBST(Z_CFLAGS)
AC_SUBST(Z_LIBS)

if test "$enable_shared" = "no"
then
 AC_MSG_ERROR([GNUnet only works with shared libraries. Sorry.])
fi



# restore LIBS
LIBS=$SAVE_LIBS


fi

# check for iconv
AM_ICONV

# test for libunistring
gl_LIBUNISTRING
if test $HAVE_LIBUNISTRING != yes; then
 AC_MSG_ERROR([GNUnet requires libunistring])
fi
# under emscripten, $gl_libunistring_hexversion is undefined
if test "$taler_only" != yes; then
if test "x$gl_libunistring_hexversion" = "x" || test "$gl_libunistring_hexversion" -le 2305; then
 AC_MSG_ERROR([GNUnet requires libunistring >= 0.9.1.1])
fi
fi
AC_CHECK_HEADERS([unistr.h],,AC_MSG_ERROR([Compiling GNUnet requires unistr.h (from libunistring) to be installed]))

# restore LIBS
LIBS=$SAVE_LIBS



# Checks for standard header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h ctype.h limits.h stdio.h stdlib.h string.h unistd.h stdarg.h signal.h locale.h sys/stat.h sys/types.h],,AC_MSG_ERROR([Compiling GNUnet requires standard UNIX headers files: fcntl.h math.h errno.h ctype.h limits.h stdio.h stdlib.h string.h unistd.h stdarg.h signal.h locale.h sys/stat.h sys/types.h]))



# Checks for headers that are only required on some systems or opional (and where we do NOT abort if they are not there)
AC_CHECK_HEADERS([stdatomic.h malloc.h malloc/malloc.h malloc/malloc_np.h langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h sys/resource.h ifaddrs.h mach/mach.h stddef.h sys/timeb.h terminos.h argz.h ucred.h sys/ucred.h endian.h sys/endian.h execinfo.h byteswap.h])

# FreeBSD requires something more funky for netinet/in_systm.h and netinet/ip.h...
AC_CHECK_HEADERS([sys/types.h netinet/in_systm.h netinet/in.h netinet/ip.h],,,
[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

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

LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

# test for postgres
postgres=false
# even running the check for postgres breaks emscripten ...
AS_IF([test "$taler_only" != yes],
      [AX_LIB_POSTGRESQL([9.5],
        [CPPFLAGS="$CPPFLAGS $POSTGRESQL_CPPFLAGS"
         AC_CHECK_HEADERS([libpq-fe.h],
         postgres=true)
        ],
        [AC_MSG_RESULT([no postgres])])])
AM_CONDITIONAL(HAVE_POSTGRESQL, test x$postgres = xtrue)


LDFLAGS=$SAVE_LDFLAGS
CPPFLAGS=$SAVE_CPPFLAGS

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
  [AC_MSG_RESULT([$with_mysql])
   case $with_mysql in
   no)
      ;;
   yes|"")
      AC_CHECK_HEADERS(mysql/mysql.h,
       AC_CHECK_LIB(mysqlclient, mysql_init,

       mysql=true), [], [$CYGWIN_MYSQL_MAGIC])
      ;;
   *)
      LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS $ZLIBS"
      CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
      AC_CHECK_HEADERS(mysql/mysql.h,
       AC_CHECK_LIB(mysqlclient, mysql_init,
        MYSQL_LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql"
        MYSQL_CPPFLAGS="-I$with_mysql/include"

        mysql=true), [], [$CYGWIN_MYSQL_MAGIC])
      ;;
   esac
  ],
  [AC_MSG_RESULT([--with-mysql not specified])
   if test -d "/usr/lib64/mysql"; then
    MYSQL_LIBDIR="/usr/lib64/mysql"
   elif test -d "/usr/lib/mysql"; then
    MYSQL_LIBDIR="/usr/lib/mysql"
   else
    MYSQL_LIBDIR="/usr/lib"
   fi
   LDFLAGS="-L$MYSQL_LIBDIR $LDFLAGS $ZLIBS"
   AC_CHECK_LIB(mysqlclient, mysql_init,
    [AC_CHECK_HEADERS(mysql/mysql.h,
      MYSQL_LDFLAGS="-L$MYSQL_LIBDIR"
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
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[$CYGWIN_MYSQL_MAGIC
      #include <mysql/mysql.h>]],
    [[
      #if (MYSQL_VERSION_ID < 40100)
      #error needs at least version >= 4.1
      #endif
      int main () { return 0; }
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
AM_CONDITIONAL(HAVE_MYSQLE, false)
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
      yes|"")
        AC_CHECK_HEADERS([microhttpd.h],
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_get_fdset2],
              [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.63])
              AC_COMPILE_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>
                #if (MHD_VERSION < 0x0096300)
                #error needs at least version 0.9.63
                #endif
                int main () { return 0; }
               ])],
               [AC_MSG_RESULT(ok)
                lmhd=1],
               [AC_MSG_RESULT(failed)])]),
	    [],[#include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "$native_srcdir/src/include/platform.h"])
        ;;
      *)
        LDFLAGS="-L$with_microhttpd/lib $LDFLAGS"
        CPPFLAGS="-I$with_microhttpd/include $CPPFLAGS"
        AC_CHECK_HEADERS(microhttpd.h,
	  AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
            AC_CHECK_LIB([microhttpd], [MHD_get_fdset2],
              EXT_LIB_PATH="-L$with_microhttpd/lib $EXT_LIB_PATH"
              [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.52])
               AC_COMPILE_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>
                #if (MHD_VERSION < 0x0094200)
                #error needs at least version 0.9.42
                #endif
                int main () { return 0; }
               ])],
               [AC_MSG_RESULT(ok)
                lmhd=1],
               [AC_MSG_RESULT(failed)])]),
	    [],[#include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>]),,
            [#include "$native_srcdir/src/include/platform.h"])
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-microhttpd not specified])
    AC_CHECK_HEADERS([microhttpd.h],
      AC_CHECK_DECL(MHD_OPTION_PER_IP_CONNECTION_LIMIT,
        AC_CHECK_LIB([microhttpd], [MHD_get_fdset2],
          [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.52])
              AC_COMPILE_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
		#include <microhttpd.h>
                #if (MHD_VERSION < 0x0094200)
                #error needs at least version 0.9.52
                #endif
               ])],
               [AC_MSG_RESULT(ok)
                lmhd=1],
               [AC_MSG_RESULT(failed)])]),
	[],[#include "$native_srcdir/src/include/platform.h"
            #include <microhttpd.h>]),,
       [#include "$native_srcdir/src/include/platform.h"])])
AM_CONDITIONAL(HAVE_MHD, test x$lmhd = x1)
AC_DEFINE_UNQUOTED([HAVE_MHD], $lmhd, [We have libmicrohttpd])

AM_CONDITIONAL(HAVE_JSON, [test x$jansson = x1])

# restore LIBS
LIBS=$SAVE_LIBS

# check for gettext
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

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

AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
   [ AC_DEFINE(HAVE_SOCKADDR_UN_SUN_LEN, 1, [Do we have sockaddr_un.sun_len?])
   ],
   [],
   [
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <sys/un.h>
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
AC_CHECK_FUNCS([atoll stat64 strnlen mremap getrlimit setrlimit sysconf initgroups strndup gethostbyname2 getpeerucred getpeereid setresuid $funcstocheck getifaddrs freeifaddrs getresgid mallinfo malloc_size malloc_usable_size getrusage random srandom stat statfs statvfs wait4])

# restore LIBS
LIBS=$SAVE_LIBS

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

DATAROOTDIR=$datarootdir
AC_SUBST(DATAROOTDIR)

# test for sudo
# TODO: do we need to change anything for "doas" on openbsd?
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
AM_CONDITIONAL([HAVE_SUDO], [test "x$SUDO_BINARY" != "x" -o -w /])


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



# gnutls
gnutls=0
gnutls_dane=0
AC_MSG_CHECKING(for gnutls)
AC_ARG_WITH(gnutls,
   [  --with-gnutls=PFX   base of gnutls installation],
   [AC_MSG_RESULT([$with_gnutls])
    case $with_gnutls in
      no)
        ;;
      yes)
        AC_CHECK_HEADERS([gnutls/abstract.h],
            AC_CHECK_LIB([gnutls], [gnutls_priority_set],
	     gnutls=true))
        AC_CHECK_HEADERS([gnutls/dane.h],
            AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
	      gnutls_dane=1))
        ;;
      *)
        LDFLAGS="-L$with_gnutls/lib $LDFLAGS"
        CPPFLAGS="-I$with_gnutls/include $CPPFLAGS"
        AC_CHECK_HEADERS([gnutls/abstract.h],
            AC_CHECK_LIB([gnutls], [gnutls_priority_set],
              EXT_LIB_PATH="-L$with_gnutls/lib $EXT_LIB_PATH"
              gnutls=true))
        AC_CHECK_HEADERS([gnutls/dane.h],
            AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
	      gnutls_dane=1))
        ;;
    esac
   ],
   [AC_MSG_RESULT([--with-gnutls not specified])
    AC_CHECK_HEADERS([gnutls/abstract.h],
        AC_CHECK_LIB([gnutls], [gnutls_priority_set],
          gnutls=true))
    AC_CHECK_HEADERS([gnutls/dane.h],
        AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
    	             gnutls_dane=1))
   ])
AM_CONDITIONAL(HAVE_GNUTLS, test x$gnutls = xtrue)
AC_DEFINE_UNQUOTED([HAVE_GNUTLS], $gnutls, [We have GnuTLS])
AM_CONDITIONAL(HAVE_GNUTLS_DANE, test x$gnutls_dane = x1)
AC_DEFINE_UNQUOTED([HAVE_GNUTLS_DANE], $gnutls_dane, [We have GnuTLS with DANE support])



# Test if we are building for superMUC
AC_MSG_CHECKING(if GNUnet is being configured to run on the SuperMUC)
AC_ARG_ENABLE([supermuc],
    [AS_HELP_STRING([--enable-supermuc],
       [build GNUnet with support to run on the SuperMUC (default is NO)])],
    [if test "x$enable_supermuc" = "xno"
     then
       supermuc=0
     else
       supermuc=1
     fi],
    [supermuc=0
     enable_supermuc=no])
AC_MSG_RESULT($enable_SUPERMUC)
AM_CONDITIONAL([ENABLE_SUPERMUC], [test "x$supermuc" = "x1"])
AC_DEFINE_UNQUOTED([ENABLE_SUPERMUC], [$supermuc], [Build with support for SuperMUC])

# Check if NSE has to send timestamp information to testbed logger for
# generating histogram of messages received
AC_MSG_CHECKING(if NSE has to send timestamp information to testbed logger)
AC_ARG_ENABLE([nse-histogram],
    [AS_HELP_STRING([--enable-nse-histogram],
       [have NSE send timestamp information to testbed logger for generating
       histogram of received messages.  NOT useful for production (default is
       NO)])],
    [if test "x$enableval" = "xno"
     then
       nse_histogram=0
     else
       nse_histogram=1
     fi],
    [nse_histogram=0
     enable_nse_histogram=no])
AC_MSG_RESULT($enable_nse_histogram)
AM_CONDITIONAL([ENABLE_NSE_HISTOGRAM], [test "x$nse_histogram" = "x1"])
AC_DEFINE_UNQUOTED([ENABLE_NSE_HISTOGRAM], [$nse_histogram],
                   [have NSE send timestamp information to testbed logger])

# should 'make check' run tests?
AC_MSG_CHECKING(whether to run tests)
AC_ARG_ENABLE([testruns],
   [AS_HELP_STRING([--disable-testruns], [disable running tests on make check (default is YES)])],
   [enable_tests_run=${enableval}],
   [enable_tests_run=yes])
AC_MSG_RESULT($enable_test_run)
AM_CONDITIONAL([ENABLE_TEST_RUN], [test "x$enable_tests_run" = "xyes"])


AC_MSG_CHECKING([whether to compile in benchmarks (currently for http and crypto)])
AC_ARG_ENABLE([benchmark],
   [AS_HELP_STRING([--enable-benchmark], [enable benchmarking])],
   [enable_benchmark=${enableval}],
   [enable_benchmark=no])
AC_MSG_RESULT($enable_benchmark)
AS_IF([test "x$enable_benchmark" = "xyes"],
      [AC_DEFINE_UNQUOTED(ENABLE_BENCHMARK,1,[Benchmarks are enabled])])
AM_CONDITIONAL([ENABLE_BENCHMARK], [test "x$enable_benchmark" = "xyes"])


# should expensive tests be run?
AC_MSG_CHECKING(whether to run expensive tests)
AC_ARG_ENABLE([expensivetests],
   [AS_HELP_STRING([--enable-expensivetests], [enable running expensive testcases])],
   [enable_expensive=${enableval}],
   [enable_expensive=no])
AC_MSG_RESULT($enable_expensive)
AM_CONDITIONAL([HAVE_EXPENSIVE_TESTS], [test "x$enable_expensive" = "xyes"])

# should ports be open for Java services?
AC_MSG_CHECKING(whether to enable ports for gnunet-java)
AC_ARG_ENABLE([javaports],
   [AS_HELP_STRING([--enable-javaports], [use non-zero ports for services with Java bindings (default is NO)])],
   [enable_java_ports=${enableval}],
   [enable_java_ports=no])
AC_MSG_RESULT($enable_java_ports)
if test "x$enable_java_ports" = "xyes"
then
  JAVAPORT=""
else
  JAVAPORT="$UNIXONLY"
fi
AC_SUBST(JAVAPORT)

# should benchmarks be run?
AC_MSG_CHECKING(whether to run benchmarks during make check)
AC_ARG_ENABLE([benchmarks],
   [AS_HELP_STRING([--enable-benchmarks], [enable running benchmarks during make check])],
   [enable_benchmarks=${enableval}],
   [enable_benchmarks=no])
AC_MSG_RESULT($enable_benchmarks)
AM_CONDITIONAL([HAVE_BENCHMARKS], [test "x$enable_benchmarks" = "xyes"])

# should gnunet-testing be compiled
AC_MSG_CHECKING(wether to compile gnunet-testing)
AC_ARG_ENABLE([testing],
   [AS_HELP_STRING([--disable-testing], [do not build gnunet-testing])],
   [enable_testing=${enableval}],
   [enable_testing=yes])
AC_MSG_RESULT($enable_testing)
AM_CONDITIONAL([HAVE_TESTING], [test "x$enable_testing" = "xyes"])

# should experimental code be compiled (code that may not yet compile)?
AC_MSG_CHECKING(whether to compile experimental code)
AC_ARG_ENABLE([experimental],
   [AS_HELP_STRING([--enable-experimental], [enable compiling experimental code])],
   [enable_experimental=${enableval}],
   [enable_experimental=no])
AC_MSG_RESULT($enable_experimental)
AM_CONDITIONAL([HAVE_EXPERIMENTAL], [test "x$enable_experimental" = "xyes"])

# should malicious code be compiled (should only be used for testing)?
AC_MSG_CHECKING(whether to compile malicious code)
AC_ARG_ENABLE([malicious],
   [AS_HELP_STRING([--enable-malicious], [enable compiling malicious code])],
   [if test "x$enableval" = "xno"
     then
       malicious=0
     else
       malicious=1
     fi],
   [malicious=0
    enable_malicious=no])
AC_MSG_RESULT($enable_malicious)
AM_CONDITIONAL([ENABLE_MALICIOUS], [test 1=$malicious])
AC_DEFINE_UNQUOTED([ENABLE_MALICIOUS], [$malicious],
                   [enable compilation of malicious code])

# should services be started on demand when needed?  Some services may choose to
# never start by default and it is up to the service/module developer to decide
# by having "START_ON_DEMAND = NO" instead of "START_ON_DEMAND = @START_ON_DEMAND@"
# in the service/module's conf.in file.
# See also IMMEDIATE_START for an unconditional immediate start.
START_ON_DEMAND="YES"
AC_MSG_CHECKING(whether to start peer's services on demand by default)
AC_ARG_ENABLE([autostart],
   [AS_HELP_STRING([--disable-autostart], [do not start peer's services by default])],
   [enable_autostart=${enableval}
    if test "x$enable_autostart" = "xno"
    then
        START_ON_DEMAND="NO"
    fi
   ],
   [enable_autostart=yes])
AC_MSG_RESULT($enable_autostart)
#AM_CONDITIONAL([HAVE_START_ON_DEMAND], [test "x$enable_autostart" = "xyes"])
AC_SUBST(START_ON_DEMAND)

# should memory statistics be kept (very expensive CPU-wise!)
AC_MSG_CHECKING(whether to create expensive statistics on memory use)
AC_ARG_ENABLE([heapstats],
   [AS_HELP_STRING([--enable-heapstats], [enable expensive heap statistics])],
   [enable_heapstats=1],
   [enable_heapstats=0])
AC_MSG_RESULT($enable_heapstats)
AC_DEFINE_UNQUOTED([ENABLE_HEAP_STATISTICS],$enable_heapstats,[enable expensive heap statistics])

# should code be enabled that works around missing OS functionality on Windows?
# used for test cases
if test $build_target = "mingw"
then
	workarounds=1

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  int s = socket (0, 0, 0);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_SOCKET],1,[Define this if socket() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_SOCKET],0,[Define this if socket() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  int s = select (0, NULL, NULL, NULL, NULL);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_SELECT],1,[Define this if select() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_SELECT],0,[Define this if select() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  struct in_addr i;
  char *s = inet_ntoa (i);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_INET_NTOA],1,[Define this if inet_ntoa() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_INET_NTOA],0,[Define this if inet_ntoa() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  int s = getnameinfo (NULL, 0, NULL, 0, NULL, 0, 0);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETNAMEINFO],1,[Define this if getnameinfo() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETNAMEINFO],0,[Define this if getnameinfo() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  int s = gethostname (NULL, 0);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTNAME],1,[Define this if gethostname() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTNAME],0,[Define this if gethostname() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  void *s = gethostbyname (NULL);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTBYNAME],1,[Define this if gethostbyname() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTBYNAME],0,[Define this if gethostbyname() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  void *s = gethostbyaddr (NULL, 0, 0);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTBYADDR],1,[Define this if gethostbyaddr() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETHOSTBYADDR],0,[Define this if gethostbyaddr() is available])
 ])

AC_LINK_IFELSE(
 [AC_LANG_PROGRAM(
  [#include <ws2tcpip.h>
  ],[
  int s = getaddrinfo (NULL, NULL, NULL, NULL);])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETADDRINFO],1,[Define this if getaddrinfo() is available])
 ],[
  AC_DEFINE_UNQUOTED([HAVE_GETADDRINFO],0,[Define this if getaddrinfo() is available])
 ])

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


# Check if the __thread storage class for thread-local storage is available.
AC_MSG_CHECKING(whether __thread is supported)
AC_LINK_IFELSE(
 [AC_LANG_PROGRAM([#include <stdlib.h>
                   #undef __thread
                   static __thread int a = 1;],
                  [exit(a-1);])],
 [have_thread_local_gcc=1],[have_thread_local_gcc=0])
AC_DEFINE_UNQUOTED([HAVE_THREAD_LOCAL_GCC],$have_thread_local_gcc,[Define this if __thread is supported])
AS_IF([test "x$have_thread_local_gcc" = "x1"],
      [AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)])

# gcov compilation
AC_MSG_CHECKING(whether to compile with support for code coverage analysis)
AC_ARG_ENABLE([coverage],
              AS_HELP_STRING([--enable-coverage],
                             [compile the library with code coverage support]),
              [use_gcov=${enableval}],
              [use_gcov=no])
AC_MSG_RESULT($use_gcov)
AM_CONDITIONAL([USE_COVERAGE], [test "x$use_gcov" = "xyes"])


# version info
# TODO: git blame says this predates our switch to git. git-svn should be adjusted to simply git, or
# an external script that does the job.
AC_PATH_PROG(svnversioncommand, svnversion)
AC_PATH_PROG(gitcommand, git)
AC_MSG_CHECKING(for source being under a VCS)


# version info
AC_PATH_PROG(gitcommand, git)
AC_MSG_CHECKING(for source being under a VCS)
git_version=
AS_IF([test ! "X$gitcommand" = "X"],
[
  git_version=$(cd $srcdir ; git rev-list --full-history --all --abbrev-commit | head -n 1 2>/dev/null)
])
AS_IF([test "X$git_version" = "X"],
  [
    vcs_name="no"
    vcs_version="\"release\""
  ],
  [
    vcs_name="yes, git-svn"
    vcs_version="\"git-$git_version\""
  ])
AC_MSG_RESULT($vcs_name)

AC_MSG_CHECKING(VCS version)
AC_MSG_RESULT($vcs_version)
AC_DEFINE_UNQUOTED(VCS_VERSION, [$vcs_version], [VCS revision/hash or tarball version])

AC_CONFIG_FILES([
Makefile
contrib/Makefile
contrib/hellos/Makefile
contrib/services/Makefile
contrib/services/openrc/Makefile
contrib/services/systemd/Makefile
contrib/scripts/Makefile
contrib/scripts/gnunet-logread/Makefile
doc/Makefile
doc/man/Makefile
doc/doxygen/Makefile
doc/handbook/Makefile
doc/tutorial/Makefile
lint/Makefile
m4/Makefile
po/Makefile.in
src/Makefile
src/arm/Makefile
src/arm/arm.conf
src/ats/Makefile
src/ats/ats.conf
src/ats-tool/Makefile
src/ats-tests/Makefile
src/auction/Makefile
src/block/Makefile
src/cadet/Makefile
src/cadet/cadet.conf
src/core/Makefile
src/core/core.conf
src/consensus/Makefile
src/consensus/consensus.conf
src/conversation/Makefile
src/conversation/conversation.conf
src/curl/Makefile
src/datacache/Makefile
src/datastore/Makefile
src/datastore/datastore.conf
src/dht/Makefile
src/dht/dht.conf
src/dns/Makefile
src/dns/dns.conf
src/exit/Makefile
src/fragmentation/Makefile
src/fs/Makefile
src/fs/fs.conf
src/gns/Makefile
src/gns/gns.conf
src/gns/nss/Makefile
src/gnsrecord/Makefile
src/hello/Makefile
src/identity/Makefile
src/identity/identity.conf
src/credential/Makefile
src/credential/credential.conf
src/include/Makefile
src/integration-tests/Makefile
src/json/Makefile
src/hostlist/Makefile
src/my/Makefile
src/mysql/Makefile
src/namecache/Makefile
src/namecache/namecache.conf
src/namestore/Makefile
src/namestore/namestore.conf
src/nat/Makefile
src/nat/nat.conf
src/nat-auto/Makefile
src/nat-auto/nat-auto.conf
src/nse/Makefile
src/nse/nse.conf
src/nt/Makefile
src/peerinfo/Makefile
src/peerinfo/peerinfo.conf
src/peerinfo-tool/Makefile
src/peerstore/Makefile
src/peerstore/peerstore.conf
src/pq/Makefile
src/pt/Makefile
src/regex/Makefile
src/regex/regex.conf
src/revocation/Makefile
src/revocation/revocation.conf
src/rps/Makefile
src/rps/rps.conf
src/secretsharing/Makefile
src/secretsharing/secretsharing.conf
src/scalarproduct/Makefile
src/scalarproduct/scalarproduct.conf
src/set/Makefile
src/set/set.conf
src/sq/Makefile
src/statistics/Makefile
src/statistics/statistics.conf
src/template/Makefile
src/testbed/Makefile
src/testbed/testbed.conf
src/testbed-logger/Makefile
src/testbed-logger/testbed-logger.conf
src/testing/Makefile
src/topology/Makefile
src/transport/Makefile
src/transport/transport.conf
src/util/Makefile
src/util/resolver.conf
src/vpn/Makefile
src/vpn/vpn.conf
src/zonemaster/Makefile
src/zonemaster/zonemaster.conf
src/rest/Makefile
src/abe/Makefile
src/reclaim-attribute/Makefile
src/reclaim/Makefile
pkgconfig/Makefile
pkgconfig/gnunetarm.pc
pkgconfig/gnunetats.pc
pkgconfig/gnunetblock.pc
pkgconfig/gnunetcadet.pc
pkgconfig/gnunetconsensus.pc
pkgconfig/gnunetconversation.pc
pkgconfig/gnunetcore.pc
pkgconfig/gnunetdatacache.pc
pkgconfig/gnunetdatastore.pc
pkgconfig/gnunetdht.pc
pkgconfig/gnunetdns.pc
pkgconfig/gnunetenv.pc
pkgconfig/gnunetfragmentation.pc
pkgconfig/gnunetfs.pc
pkgconfig/gnunetgns.pc
pkgconfig/gnunethello.pc
pkgconfig/gnunetidentity.pc
pkgconfig/gnunetmicrophone.pc
pkgconfig/gnunetmysql.pc
pkgconfig/gnunetnamestore.pc
pkgconfig/gnunetnat.pc
pkgconfig/gnunetnse.pc
pkgconfig/gnunetpeerinfo.pc
pkgconfig/gnunetpq.pc
pkgconfig/gnunetregex.pc
pkgconfig/gnunetrevocation.pc
pkgconfig/gnunetrps.pc
pkgconfig/gnunetscalarproduct.pc
pkgconfig/gnunetset.pc
pkgconfig/gnunetspeaker.pc
pkgconfig/gnunetstatistics.pc
pkgconfig/gnunettestbed.pc
pkgconfig/gnunettesting.pc
pkgconfig/gnunettransport.pc
pkgconfig/gnunetutil.pc
pkgconfig/gnunetvpn.pc
])
AC_OUTPUT

# Finally: summary!

# warn user if mysql found but not used due to version
AS_IF([test "$mysqlfail" = "true"]
      [AC_MSG_NOTICE([WARNING: optional MySQL not found (or too old)])])

# sqlite
AS_IF([test "x$sqlite" = "x0"],
      [AC_MSG_ERROR([ERROR: sqlite3 not found, but sqlite3 is required.])])

# libgnurl
AS_IF([test "$gnurl" = "0"],
  [AS_IF([test "x$curl" = "xfalse"],
    [AC_MSG_NOTICE([WARNING: libgnurl not found.  http client support will not be compiled.])
     AC_MSG_WARN([ERROR: libgnurl not found.  hostlist daemon will not be compiled, and you probably WANT the hostlist daemon])],
    [AC_MSG_NOTICE([WARNING: libgnurl not found, trying to use libcurl-gnutls instead.])])])

# bluetooth
AS_IF([test "x$bluetooth" = "x0"],
      [AC_MSG_NOTICE([WARNING: optional bluetooth library not found.])])


# jansson
AS_IF([test "x$jansson" = "x0"],
      [AC_MSG_NOTICE([WARNING: optional jansson library not found.])])

#
# FIXME: `some modules' -> be more specific which exact modules.
#

# warn user if iptables is not found
AS_IF([test "$VAR_IPTABLES_BINARY" = "false"],
 [AC_MSG_NOTICE([WARNING: optional iptables not found])])

# warn user if ifconfig is not found
AS_IF([test "$VAR_IFCONFIG_BINARY" = "false"],
 [AC_MSG_NOTICE([WARNING: optional ifconfig not found])])

# warn user if upnpc binary is not found
AS_IF([test "$VAR_UPNPC_BINARY" = "false"],
  [AC_MSG_NOTICE([WARNING: optional upnpc binary not found])])

#gnutls
AS_IF([test x$gnutls != xtrue],
 [AC_MSG_NOTICE([WARNING: GnuTLS not found, gnunet-gns-proxy will not be built])],
 [AS_IF([test "x$gnutls_dane" != "x1"],
  [AC_MSG_NOTICE([WARNING: GnuTLS has no DANE support, DANE validation will not be possible])])])

# warn user if libzbar is not found
AS_IF([test "$have_zbar" = 0],
      [AC_MSG_NOTICE([WARNING: zbar not found, gnunet-qr will not be built.])])

# java ports
AS_IF([test "x$enable_java_ports" = "xyes"],
      [AC_MSG_NOTICE([NOTICE: Opening ports for gnunet-java bindings by default.])])

# MHD
AS_IF([test "x$lmhd" != "x1"],
      [AC_MSG_NOTICE([WARNING: optional libmicrohttpd not found])])

# conversation
AS_IF([test "x$conversation_backend" = "xnone"],
 [AS_IF([test "x$pulse" != "x1"],
   [AC_MSG_NOTICE([WARNING: libpulse(audio) not found, conversation will not be built.])])
  AS_IF([test "x$opus" != "x1"],
   [AC_MSG_NOTICE([WARNING: libopus not found, conversation will not be built.])])
  AS_IF([test "x$gst" != "x1"],
   [AC_MSG_NOTICE([WARNING: GStreamer not found, conversation will not be built.])])])

AS_IF([test "$extractor" != 1],
      [AC_MSG_WARN([ERROR: libextractor not found, but various file-sharing functions require it])])

AS_IF([test "x$working_libidn2" = x1],
      [AC_MSG_NOTICE([INFO: Using libidn2])])
AS_IF([test "x$working_libidn1" = x1],
      [AC_MSG_NOTICE([INFO: Using libidn1])])

AC_MSG_NOTICE([NOTICE: Database support is set to MySQL: $mysql, SQLite: $sqlite, Postgres: $postgres])

AS_IF([test "$enable_framework_build" = "yes"],
      [AC_MSG_NOTICE([Mac OS X framework build enabled.])])

AC_MSG_NOTICE([********************************************
Please make sure NOW that you have created a user and group 'gnunet'
and additionally a group 'gnunetdns'. On Debian and Ubuntu GNU/Linux, type:
        addgroup gnunetdns
        adduser --system --group --disabled-login --home /var/lib/gnunet gnunet

Make sure that '/var/lib/gnunet' is owned (and writable) by user
'gnunet'.  Then, you can compile GNUnet with
        make

After that, run (if necessary as 'root')
        make install
to install everything.

Each GNUnet user should be added to the 'gnunet' group (may
require fresh login to come into effect):
        adduser USERNAME gnunet
(run the above command as root once for each of your users, replacing
"USERNAME" with the respective login names).  If you have a global IP
address, no further configuration is required.

For more detailed setup instructions, see https://docs.gnunet.org/

Optionally, download and compile gnunet-gtk to get a GUI for
file-sharing and configuration.  This is particularly recommended
if your network setup is non-trivial, as gnunet-setup can be
used to test in the GUI if your network configuration is working.
gnunet-setup should be run as the "gnunet" user under X.  As it
does very little with the network, running it as "root" is likely
also harmless.  You can also run it as a normal user, but then
you have to copy ~/.gnunet/gnunet.conf" over to the "gnunet" user's
home directory in the end.

Once you have configured your peer, run (as the 'gnunet' user)
	gnunet-arm -s
to start the peer.  You can then run the various GNUnet-tools as
your "normal" user (who should only be in the group 'gnunet').
********************************************])
