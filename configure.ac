# This file is part of GNUnet.
# (C) 2001--2014 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
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
AC_INIT([gnunet], [0.10.1], [bug-gnunet@gnu.org])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([gnunet_config.h])
AH_TOP([#define _GNU_SOURCE  1])
AC_CONFIG_MACRO_DIR([m4])
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

funcstocheck="getnameinfo gethostname gethostbyname gethostbyaddr getaddrinfo"

# Srcdir in a form that native compiler understands (i.e. DOS path on W32)
native_srcdir=$srcdir

# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(DARWIN,1,[This is an Apple Darwin system])
     CPPFLAGS="-D_APPLE_C_SOURCE $CPPFLAGS"
     CFLAGS="-fno-common $CFLAGS"
     AC_MSG_WARN([The VPN application cannot be compiled on your OS])
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
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, log)
AC_CHECK_LIB(c, getloadavg, AC_DEFINE(HAVE_GETLOADAVG,1,[getloadavg supported]))


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
  ])
AC_LANG_POP(C)
fi	# $build = $target

# check for bluetooth library
bluetooth=0
AC_CHECK_LIB(bluetooth, ba2str,[AC_CHECK_HEADER([bluetooth/bluetooth.h],bluetooth=1)])
if test "$bluetooth" = 1
then
  AM_CONDITIONAL(HAVE_LIBBLUETOOTH, true)
  AC_DEFINE([HAVE_LIBBLUETOOTH],[1],[Have bluetooth library])
else
  AM_CONDITIONAL(HAVE_LIBBLUETOOTH, false)
fi
if test "$build_target" = "mingw"
then
  bluetooth=1
fi

# check for libpulse(audio) library
pulse=0
AC_CHECK_LIB(pulse,pa_stream_peek,
  [AC_CHECK_HEADER([pulse/simple.h],pulse=1)])
if test "$pulse" = 1
then
  AC_DEFINE([HAVE_PULSE],[1],[Have libpulse(audio) library])
fi
if test "$build_target" = "mingw"
then
  pulse=0
fi

# check for libopus(audio) library
opus=0
AC_CHECK_LIB(opus,opus_decode_float,
  [AC_CHECK_HEADER([opus/opus.h],
    [AC_CHECK_DECL([OPUS_SET_GAIN],[opus=1],[],[[#include <opus/opus.h>]]
    )]
  )]
)
if test "$opus" = 1
then
  AC_DEFINE([HAVE_OPUS],[1],[Have libopus library])
fi

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



gst=0
PKG_CHECK_MODULES(
  [GST],
  [glib-2.0 gobject-2.0 gstreamer-1.0 gstreamer-app-1.0 gstreamer-audio-1.0],
  [
    gst=1
    AC_MSG_RESULT(ok)
  ], [
    gst=0
    AC_MSG_RESULT(not found)
  ])

# Pulse Audio
if test "x$pulse" != "x1" -o "x$opus" != "x1" -o "x$ogg" != "x1"
then
 if test "x$gst" != "x1"
 then
  conversation_backend=none
  AM_CONDITIONAL(BUILD_PULSE_HELPERS, false)
  AM_CONDITIONAL(BUILD_GST_HELPERS, false)
 else
  conversation_backend=gst
  AM_CONDITIONAL(BUILD_PULSE_HELPERS, false)
  AM_CONDITIONAL(BUILD_GST_HELPERS, true)
 fi
else
 conversation_backend=pulse
 AM_CONDITIONAL(BUILD_PULSE_HELPERS, true)
 AM_CONDITIONAL(BUILD_GST_HELPERS, false)
fi

# libgnurl
LIBGNURL_CHECK_CONFIG(,7.34.0,gnurl=1,gnurl=0)
if test "$gnurl" = 1
then
	AM_CONDITIONAL(HAVE_LIBGNURL, true)
	AC_DEFINE([HAVE_LIBGNURL],[1],[Have libgnurl])
else
	AM_CONDITIONAL(HAVE_LIBGNURL, false)
fi

# libcurl-gnutls
LIBCURL_CHECK_CONFIG(,7.34.0,[curl=true],[curl=false])
if test "x$curl" = xtrue
then
 AC_CHECK_HEADERS([curl/curl.h],
   AC_CHECK_DECLS(CURLINFO_TLS_SESSION,[curl=true],[curl=false],[[#include <curl/curl.h>]]),
   [curl=false])
 # need libcurl-gnutls.so, everything else is not acceptable
 AC_CHECK_LIB([curl-gnutls],[curl_easy_getinfo],,[curl=false])
 # cURL must support CURLINFO_TLS_SESSION, version >= 7.34

fi
if test x$curl = xfalse
then
	AM_CONDITIONAL(HAVE_LIBCURL, false)
	AC_MSG_WARN([GNUnet requires libcurl-gnutls  >= 7.34])
else
	AM_CONDITIONAL(HAVE_LIBCURL, true)
	AC_DEFINE([HAVE_LIBCURL],[1],[Have CURL])
fi


# libidn
AC_MSG_CHECKING([if Libidn can be used])
AC_ARG_WITH(libidn, AC_HELP_STRING([--with-libidn=[DIR]],
                                    [Support IDN (needs GNU Libidn)]),
libidn=$withval, libidn=yes)
if test "$libidn" != "no"; then
  if test "$libidn" != "yes"; then
     LDFLAGS="${LDFLAGS} -L$libidn/lib"
     CPPFLAGS="${CPPFLAGS} -I$libidn/include"
  fi
fi
libidn=no
AC_CHECK_HEADER(idna.h,
  AC_CHECK_LIB(idn, stringprep_check_version,
    [libidn=yes LIBS="${LIBS} -lidn"], []), [])
if test "$libidn" != "yes"; then
  AC_MSG_FAILURE([GNUnet requires libidn.
libidn-1.13 should be sufficient, newer versions work too.])
fi
AC_MSG_RESULT($libidn)

# restore LIBS
LIBS=$SAVE_LIBS


AC_CHECK_HEADERS([glpk.h],[glpk=true],[gplk=false])
# GLPK must support glpk_init_env, version >= 4.43
AC_CHECK_LIB([glpk],[glp_init_env],,[gplk=false])
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



AC_CHECK_HEADERS([nss.h],[nss=true],[nss=false])
if test x$nss = xfalse
then
	AM_CONDITIONAL(HAVE_GLIBCNSS, false)
	AC_MSG_WARN([No GNU libc nss header, will not build NSS plugin])
else
	AM_CONDITIONAL(HAVE_GLIBCNSS, true)
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
AC_CHECK_HEADERS([malloc.h malloc/malloc.h malloc/malloc_np.h langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h unistd.h kstat.h sys/sysinfo.h kvm.h sys/file.h sys/resource.h ifaddrs.h mach/mach.h stddef.h sys/timeb.h terminos.h argz.h ucred.h sys/ucred.h endian.h sys/endian.h execinfo.h])

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

# test for postgres
postgres=false
AX_LIB_POSTGRESQL([])
if test "$found_postgresql" = "yes"; then
  postgres=true
fi
AM_CONDITIONAL(HAVE_POSTGRESQL, test x$postgres = xtrue)

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
            AC_CHECK_LIB([microhttpd], [MHD_get_fdset2],
              [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.32])
              AC_RUN_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>
                int main () { return MHD_VERSION >= 0x0093200 ? 0 : 1; }
               ])], [
               AC_MSG_RESULT(ok)
               lmhd=1],[AC_MSG_RESULT(failed)],lmhd=0)]),
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
              [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.32])
               AC_RUN_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
                #include <microhttpd.h>
                int main () { return MHD_VERSION >= 0x0093200 ? 0 : 1; }
               ])], [
               AC_MSG_RESULT(ok)
               lmhd=1],[AC_MSG_RESULT(failed)],lmhd=0)]),
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
          [AC_MSG_CHECKING([for libmicrohttpd >= 0.9.32])
              AC_RUN_IFELSE([AC_LANG_SOURCE([
                #include "$native_srcdir/src/include/platform.h"
		#include <microhttpd.h>
                int main () { return MHD_VERSION >= 0x0093200 ? 0 : 1; }
               ])], [
               AC_MSG_RESULT(ok)
               lmhd=1],[AC_MSG_RESULT(failed)],lmhd=0)]),
	[],[#include "$native_srcdir/src/include/platform.h"
            #include <microhttpd.h>]),,
       [#include "$native_srcdir/src/include/platform.h"])])
AM_CONDITIONAL(HAVE_MHD, test x$lmhd = x1)
AC_DEFINE_UNQUOTED([HAVE_MHD], $lmhd, [We have libmicrohttpd])


# restore LIBS
LIBS=$SAVE_LIBS

# check for python & pexpect (used for some testcases only)
AM_PATH_PYTHON([2.6],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

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
AC_CHECK_FUNCS([atoll stat64 strnlen mremap getrlimit setrlimit sysconf initgroups strndup gethostbyname2 getpeerucred getpeereid setresuid $funcstocheck getifaddrs freeifaddrs getresgid mallinfo malloc_size malloc_usable_size getrusage random srandom stat statfs statvfs])

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
AM_CONDITIONAL([HAVE_SUDO], [test "x$SUDO_BINARY" != "x" -o -w /])


# test for nssdir
AC_MSG_CHECKING(with nssdir)
AC_ARG_WITH(nssdir,
  [  --with-nssdir=PATH       where to install NSS plugins],
  [AC_MSG_RESULT("$with_nssdir")
   case $with_nssdir in
   no)
     NSS_DIR=
     install_nss=0
     ;;
   yes)
     NSS_DIR="/lib"
     install_nss=1
     ;;
   *)
     NSS_DIR=$with_nssdir
     install_nss=1
    ;;
   esac
  ],
  [
   if test "x$SUDO_BINARY" != "x" -o -w /
   then
     NSS_DIR="/lib"
     install_nss=1
     AC_MSG_RESULT([yes, to /lib])
   else
     NSS_DIR=
     install_nss=0
     AC_MSG_RESULT([no])
   fi
  ])
AC_SUBST(NSS_DIR)
AM_CONDITIONAL([INSTALL_NSS], [test "x$install_nss" != "x0"])

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


# should monkey be used when running (certain) services?
AC_MSG_CHECKING(whether to run with monkey)
AC_ARG_ENABLE([monkey],
   [AS_HELP_STRING([--enable-monkey], [enable running with monkey])],
   [enable_monkey=${enableval}],
   [enable_monkey=no])
AC_MSG_RESULT($enable_monkey)
AM_CONDITIONAL([ENABLE_MONKEY], [test "x$enable_monkey" = "xyes"])
if test "x$enable_monkey" = "xyes"
then
  MONKEYPREFIX="pathologist -d $(eval echo ${datarootdir}/gnunet/gnunet.sqlite) -p 30 --"
else
  MONKEYPREFIX=""
fi
AC_SUBST(MONKEYPREFIX)


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
AM_CONDITIONAL([ENABLE_MALICIOUS], [1=$malicious])
AC_DEFINE_UNQUOTED([ENABLE_MALICIOUS], [$malicious],
                   [enable compilation of malicious code])

# should services be started by default when a peer starts?  Some services may
# choose to never start by default and it is upto the service/module developer to
# decide it by having "AUTOSTART = NO" instead of "AUTOSTART = @AUTOSTART" in
# the service/module's conf.in file.
AUTOSTART="YES"
AC_MSG_CHECKING(whether to auto-start peer's services by default)
AC_ARG_ENABLE([autostart],
   [AS_HELP_STRING([--disable-autostart], [do not start peer's services by default])],
   [enable_autostart=${enableval}
    if test "x$enable_autostart" == "xno"
    then
        AUTOSTART="NO"
    fi
   ],
   [enable_autostart=yes])
AC_MSG_RESULT($enable_autostart)
#AM_CONDITIONAL([HAVE_AUTOSTART], [test "x$enable_autostart" = "xyes"])
AC_SUBST(AUTOSTART)

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
  AC_DEFINE_UNQUOTED([HAVE_GETADDRINFO],1,[Define this if getaddrinfo() is available])
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
AC_PATH_PROG(svnversioncommand, svnversion)
AC_PATH_PROG(gitcommand, git)
AC_MSG_CHECKING(for source being under a VCS)
svn_version=
gitsvn_version=
AS_IF([test ! "X$svnversioncommand" = "X"],
[
  svn_version=$(cd $srcdir ; $svnversioncommand -n 2>/dev/null)
])
AS_IF([test ! "X$gitcommand" = "X"],
[
  gitsvn_version=$(cd $srcdir ; git log -1 2>/dev/null | grep "git-svn-id" | sed -e 's/.*@\([[0-9]]\+\) .*/\1/')
])
AS_IF([test "X$svn_version" = "X" -o "X$svn_version" = "Xexported" -o "X$svn_version" = "XUnversioned directory"],
[
  AS_IF([test "X$gitsvn_version" = "X"],
  [
    vcs_name="no"
    vcs_version="\"release\""
  ],
  [
    vcs_name="yes, git-svn"
    vcs_version="\"svn-r$gitsvn_version\""
  ])
],
[
  vcs_name="yes, svn"
  vcs_version="\"svn-r$svn_version\""
])
AC_MSG_RESULT($vcs_name)

AC_MSG_CHECKING(VCS version)
AC_MSG_RESULT($vcs_version)
AC_DEFINE_UNQUOTED(VCS_VERSION, [$vcs_version], [VCS revision/hash or tarball version])

AC_CONFIG_FILES([
Makefile
contrib/Makefile
doc/Makefile
doc/man/Makefile
doc/doxygen/Makefile
m4/Makefile
po/Makefile.in
src/Makefile
src/arm/Makefile
src/arm/arm.conf
src/ats/Makefile
src/ats/ats.conf
src/ats-tool/Makefile
src/ats-tests/Makefile
src/block/Makefile
src/cadet/Makefile
src/cadet/cadet.conf
src/core/Makefile
src/core/core.conf
src/consensus/Makefile
src/consensus/consensus.conf
src/conversation/Makefile
src/conversation/conversation.conf
src/datacache/Makefile
src/datastore/Makefile
src/datastore/datastore.conf
src/dht/Makefile
src/dht/dht.conf
src/dns/Makefile
src/dns/dns.conf
src/dv/Makefile
src/dv/dv.conf
src/env/Makefile
src/exit/Makefile
src/experimentation/Makefile
src/experimentation/experimentation.conf
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
src/include/Makefile
src/integration-tests/Makefile
src/hostlist/Makefile
src/multicast/Makefile
src/multicast/multicast.conf
src/mysql/Makefile
src/namecache/Makefile
src/namecache/namecache.conf
src/namestore/Makefile
src/namestore/namestore.conf
src/nat/Makefile
src/nse/Makefile
src/nse/nse.conf
src/peerinfo/Makefile
src/peerinfo/peerinfo.conf
src/peerinfo-tool/Makefile
src/peerstore/Makefile
src/peerstore/peerstore.conf
src/postgres/Makefile
src/psyc/Makefile
src/psyc/psyc.conf
src/psycstore/Makefile
src/psycstore/psycstore.conf
src/pt/Makefile
src/regex/Makefile
src/regex/regex.conf
src/revocation/Makefile
src/revocation/revocation.conf
src/secretsharing/Makefile
src/secretsharing/secretsharing.conf
src/sensor/Makefile
src/sensor/sensor.conf
src/sensordashboard/Makefile
src/sensordashboard/sensordashboard.conf
src/scalarproduct/Makefile
src/scalarproduct/scalarproduct.conf
src/set/Makefile
src/set/set.conf
src/social/Makefile
src/social/social.conf
src/statistics/Makefile
src/statistics/statistics.conf
src/template/Makefile
src/testbed/Makefile
src/testbed/testbed.conf
src/testing/Makefile
src/topology/Makefile
src/transport/Makefile
src/transport/transport.conf
src/tun/Makefile
src/util/Makefile
src/util/resolver.conf
src/vpn/Makefile
src/vpn/vpn.conf
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
pkgconfig/gnunetdnsparser.pc
pkgconfig/gnunetdnsstub.pc
pkgconfig/gnunetdv.pc
pkgconfig/gnunetenv.pc
pkgconfig/gnunetfragmentation.pc
pkgconfig/gnunetfs.pc
pkgconfig/gnunetgns.pc
pkgconfig/gnunethello.pc
pkgconfig/gnunetidentity.pc
pkgconfig/gnunetmicrophone.pc
pkgconfig/gnunetmulticast.pc
pkgconfig/gnunetmysql.pc
pkgconfig/gnunetnamestore.pc
pkgconfig/gnunetnat.pc
pkgconfig/gnunetnse.pc
pkgconfig/gnunetpeerinfo.pc
pkgconfig/gnunetpostgres.pc
pkgconfig/gnunetpsyc.pc
pkgconfig/gnunetpsycstore.pc
pkgconfig/gnunetregex.pc
pkgconfig/gnunetrevocation.pc
pkgconfig/gnunetscalarproduct.pc
pkgconfig/gnunetset.pc
pkgconfig/gnunetsocial.pc
pkgconfig/gnunetspeaker.pc
pkgconfig/gnunetstatistics.pc
pkgconfig/gnunettestbed.pc
pkgconfig/gnunettesting.pc
pkgconfig/gnunettransport.pc
pkgconfig/gnunettun.pc
pkgconfig/gnunetutil.pc
pkgconfig/gnunetvpn.pc
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
  AC_MSG_ERROR([ERROR: sqlite3 not found, but sqlite3 is required.])
fi

# libgnurl
if test "x$gnurl" = "x0"
then
  if test "x$curl" = "x0"
  then
    AC_MSG_NOTICE([NOTICE: libgnurl not found.  http client support will not be compiled.])
    AC_MSG_WARN([ERROR: libgnurl not found.  hostlist daemon will not be compiled, and you probably WANT the hostlist daemon])
  else
    AC_MSG_NOTICE([WARNING: libgnurl not found, trying to use libcurl-gnutls instead.])
  fi
fi


# bluetooth
if test "x$bluetooth" = "x0"
then
  AC_MSG_NOTICE([NOTICE: bluetooth library not found.  bluetooth support will not be compiled.])
fi

#gnutls
if test x$gnutls != xtrue
then
  AC_MSG_NOTICE([NOTICE: GnuTLS not found, gnunet-gns-proxy will not be built])
else
if test "x$gnutls_dane" != "x1"
then
  AC_MSG_NOTICE([NOTICE: GnuTLS has no DANE support, DANE validation will not be possible])
fi
fi

# java ports
if test "x$enable_java_ports" = "xyes"
then
  AC_MSG_NOTICE([NOTICE: opening ports for gnunet-java bindings by default.])
fi

# MHD
if test "x$lmhd" != "x1"
then
 AC_MSG_NOTICE([NOTICE: libmicrohttpd not found, http transport will not be installed.])
fi

# conversation
if test "x$conversation_backend" == "xnone"
then
  if test "x$pulse" != "x1"
  then
    AC_MSG_NOTICE([NOTICE: libpulse(audio) not found, conversation will not be built.])
  fi
  if test "x$opus" != "x1"
  then
   AC_MSG_NOTICE([NOTICE: libopus not found, conversation will not be built.])
  fi
  if test "x$gst" != "x1"
  then
   AC_MSG_NOTICE([NOTICE: GStreamer not found, conversation will not be built.])
  fi
fi


AC_MSG_NOTICE([NOTICE: Database support is set to MySQL: $mysql, SQLite: $sqlite, Postgres: $postgres])

if test "$enable_framework_build" = "yes"
then
  AC_MSG_NOTICE([NOTICE: Mac OS X framework build enabled.])
fi

if test "x$SUDO_BINARY" = "x" -a ! -w /
then
  AC_MSG_NOTICE([NOTICE: --with-sudo not specified and not running as 'root', will not install GNS NSS library])
fi


AC_MSG_NOTICE([********************************************
Please make sure NOW that you have created a user and group 'gnunet'
and additionally a group 'gnunetdns':
        addgroup gnunetdns
        adduser gnunet

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
