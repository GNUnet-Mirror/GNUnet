# LIBGNURL_CHECK_CONFIG ([DEFAULT-ACTION], [MINIMUM-VERSION],
#                       [ACTION-IF-YES], [ACTION-IF-NO])
# ----------------------------------------------------------
#      David Shaw <dshaw@jabberwocky.com>   May-09-2006
#
# Checks for libgnurl.  DEFAULT-ACTION is the string yes or no to
# specify whether to default to --with-libgnurl or --without-libgnurl.
# If not supplied, DEFAULT-ACTION is yes.  MINIMUM-VERSION is the
# minimum version of libgnurl to accept.  Pass the version as a regular
# version number like 7.10.1. If not supplied, any version is
# accepted.  ACTION-IF-YES is a list of shell commands to run if
# libgnurl was successfully found and passed the various tests.
# ACTION-IF-NO is a list of shell commands that are run otherwise.
# Note that using --without-libgnurl does run ACTION-IF-NO.
#
# This macro #defines HAVE_LIBGNURL if a working libgnurl setup is
# found, and sets @LIBGNURL@ and @LIBGNURL_CPPFLAGS@ to the necessary
# values.  Other useful defines are LIBGNURL_FEATURE_xxx where xxx are
# the various features supported by libgnurl, and LIBGNURL_PROTOCOL_yyy
# where yyy are the various protocols supported by libgnurl.  Both xxx
# and yyy are capitalized.  See the list of AH_TEMPLATEs at the top of
# the macro for the complete list of possible defines.  Shell
# variables $libgnurl_feature_xxx and $libgnurl_protocol_yyy are also
# defined to 'yes' for those features and protocols that were found.
# Note that xxx and yyy keep the same capitalization as in the
# gnurl-config list (e.g. it's "HTTP" and not "http").
#
# Users may override the detected values by doing something like:
# LIBGNURL="-lgnurl" LIBGNURL_CPPFLAGS="-I/usr/myinclude" ./configure
#
# For the sake of sanity, this macro assumes that any libgnurl that is
# found is after version 7.7.2, the first version that included the
# gnurl-config script.  Note that it is very important for people
# packaging binary versions of libgnurl to include this script!
# Without gnurl-config, we can only guess what protocols are available,
# or use gnurl_version_info to figure it out at runtime.

AC_DEFUN([LIBGNURL_CHECK_CONFIG],
[
  AH_TEMPLATE([LIBGNURL_FEATURE_SSL],[Defined if libgnurl supports SSL])
  AH_TEMPLATE([LIBGNURL_FEATURE_KRB4],[Defined if libgnurl supports KRB4])
  AH_TEMPLATE([LIBGNURL_FEATURE_IPV6],[Defined if libgnurl supports IPv6])
  AH_TEMPLATE([LIBGNURL_FEATURE_LIBZ],[Defined if libgnurl supports libz])
  AH_TEMPLATE([LIBGNURL_FEATURE_ASYNCHDNS],[Defined if libgnurl supports AsynchDNS])
  AH_TEMPLATE([LIBGNURL_FEATURE_IDN],[Defined if libgnurl supports IDN])
  AH_TEMPLATE([LIBGNURL_FEATURE_SSPI],[Defined if libgnurl supports SSPI])
  AH_TEMPLATE([LIBGNURL_FEATURE_NTLM],[Defined if libgnurl supports NTLM])

  AH_TEMPLATE([LIBGNURL_PROTOCOL_HTTP],[Defined if libgnurl supports HTTP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_HTTPS],[Defined if libgnurl supports HTTPS])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_FTP],[Defined if libgnurl supports FTP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_FTPS],[Defined if libgnurl supports FTPS])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_FILE],[Defined if libgnurl supports FILE])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_TELNET],[Defined if libgnurl supports TELNET])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_LDAP],[Defined if libgnurl supports LDAP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_DICT],[Defined if libgnurl supports DICT])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_TFTP],[Defined if libgnurl supports TFTP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_RTSP],[Defined if libgnurl supports RTSP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_POP3],[Defined if libgnurl supports POP3])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_IMAP],[Defined if libgnurl supports IMAP])
  AH_TEMPLATE([LIBGNURL_PROTOCOL_SMTP],[Defined if libgnurl supports SMTP])

  AC_ARG_WITH(libgnurl,
     AC_HELP_STRING([--with-libgnurl=PREFIX],[look for the gnurl library in PREFIX/lib and headers in PREFIX/include]),
     [_libgnurl_with=$withval],[_libgnurl_with=ifelse([$1],,[yes],[$1])])

  if test "$_libgnurl_with" != "no" ; then

     AC_PROG_AWK

     _libgnurl_version_parse="eval $AWK '{split(\$NF,A,\".\"); X=256*256*A[[1]]+256*A[[2]]+A[[3]]; print X;}'"

     _libgnurl_try_link=yes

     if test -d "$_libgnurl_with" ; then
        LIBGNURL_CPPFLAGS="-I$withval/include"
        _libgnurl_ldflags="-L$withval/lib"
        AC_PATH_PROG([_libgnurl_config],[gnurl-config],[],
                     ["$withval/bin"])
     else
        AC_PATH_PROG([_libgnurl_config],[gnurl-config],[],[$PATH])
     fi

     if test x$_libgnurl_config != "x" ; then
        AC_CACHE_CHECK([for the version of libgnurl],
           [libgnurl_cv_lib_gnurl_version],
           [libgnurl_cv_lib_gnurl_version=`$_libgnurl_config --version | $AWK '{print $[]2}'`])

        _libgnurl_version=`echo $libgnurl_cv_lib_gnurl_version | $_libgnurl_version_parse`
        _libgnurl_wanted=`echo ifelse([$2],,[0],[$2]) | $_libgnurl_version_parse`

        if test $_libgnurl_wanted -gt 0 ; then
           AC_CACHE_CHECK([for libgnurl >= version $2],
              [libgnurl_cv_lib_version_ok],
              [
              if test $_libgnurl_version -ge $_libgnurl_wanted ; then
                 libgnurl_cv_lib_version_ok=yes
              else
                 libgnurl_cv_lib_version_ok=no
              fi
              ])
        fi

        if test $_libgnurl_wanted -eq 0 || test x$libgnurl_cv_lib_version_ok = xyes ; then
           if test x"$LIBGNURL_CPPFLAGS" = "x" ; then
              LIBGNURL_CPPFLAGS=`$_libgnurl_config --cflags`
           fi
           if test x"$LIBGNURL" = "x" ; then
              LIBGNURL=`$_libgnurl_config --libs`

              # This is so silly, but Apple actually has a bug in their
              # gnurl-config script.  Fixed in Tiger, but there are still
              # lots of Panther installs around.
              case "${host}" in
                 powerpc-apple-darwin7*)
                    LIBGNURL=`echo $LIBGNURL | sed -e 's|-arch i386||g'`
                 ;;
              esac
           fi

           # All gnurl-config scripts support --feature
           _libgnurl_features=`$_libgnurl_config --feature`

           # Is it modern enough to have --protocols? (7.12.4)
           if test $_libgnurl_version -ge 461828 ; then
              _libgnurl_protocols=`$_libgnurl_config --protocols`
           fi
        else
           _libgnurl_try_link=no
        fi

        unset _libgnurl_wanted
     fi

     if test $_libgnurl_try_link = yes ; then

        # we didn't find gnurl-config, so let's see if the user-supplied
        # link line (or failing that, "-lgnurl") is enough.
        LIBGNURL=${LIBGNURL-"$_libgnurl_ldflags -lgnurl"}

        AC_CACHE_CHECK([whether libgnurl is usable],
           [libgnurl_cv_lib_gnurl_usable],
           [
           _libgnurl_save_cppflags=$CPPFLAGS
           CPPFLAGS="$LIBGNURL_CPPFLAGS $CPPFLAGS"
           _libgnurl_save_libs=$LIBS
           LIBS="$LIBGNURL $LIBS"

           AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <curl/curl.h>],[
/* Try and use a few common options to force a failure if we are
   missing symbols or can't link. */
int x;
curl_easy_setopt(NULL,CURLOPT_URL,NULL);
x=CURL_ERROR_SIZE;
x=CURLOPT_WRITEFUNCTION;
x=CURLOPT_FILE;
x=CURLOPT_ERRORBUFFER;
x=CURLOPT_STDERR;
x=CURLOPT_VERBOSE;
])],libgnurl_cv_lib_gnurl_usable=yes,libgnurl_cv_lib_gnurl_usable=no)

# BEGIN Changes from original libcurl.m4:
# Give it a 2nd shot using 'gnurl/curl.h'
           AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <gnurl/curl.h>],[
/* Try and use a few common options to force a failure if we are
   missing symbols or can't link. */
int x;
curl_easy_setopt(NULL,CURLOPT_URL,NULL);
x=CURL_ERROR_SIZE;
x=CURLOPT_WRITEFUNCTION;
x=CURLOPT_FILE;
x=CURLOPT_ERRORBUFFER;
x=CURLOPT_STDERR;
x=CURLOPT_VERBOSE;
])],libgnurl_cv_lib_gnurl_usable=yes)
# END Changes from original libcurl.m4:

           CPPFLAGS=$_libgnurl_save_cppflags
           LIBS=$_libgnurl_save_libs
           unset _libgnurl_save_cppflags
           unset _libgnurl_save_libs
           ])

        if test $libgnurl_cv_lib_gnurl_usable = yes ; then

           # Does gnurl_free() exist in this version of libgnurl?
           # If not, fake it with free()

           _libgnurl_save_cppflags=$CPPFLAGS
           CPPFLAGS="$CPPFLAGS $LIBGNURL_CPPFLAGS"
           _libgnurl_save_libs=$LIBS
           LIBS="$LIBS $LIBGNURL"

           AC_CHECK_FUNC(curl_free,,
              AC_DEFINE(curl_free,free,
                [Define curl_free() as free() if our version of gnurl lacks curl_free.]))

           CPPFLAGS=$_libgnurl_save_cppflags
           LIBS=$_libgnurl_save_libs
           unset _libgnurl_save_cppflags
           unset _libgnurl_save_libs

           AC_DEFINE(HAVE_LIBGNURL,1,
             [Define to 1 if you have a functional gnurl library.])
           AC_SUBST(LIBGNURL_CPPFLAGS)
           AC_SUBST(LIBGNURL)

           for _libgnurl_feature in $_libgnurl_features ; do
              AC_DEFINE_UNQUOTED(AS_TR_CPP(libgnurl_feature_$_libgnurl_feature),[1])
              eval AS_TR_SH(libgnurl_feature_$_libgnurl_feature)=yes
           done

           if test "x$_libgnurl_protocols" = "x" ; then

              # We don't have --protocols, so just assume that all
              # protocols are available
              _libgnurl_protocols="HTTP FTP FILE TELNET LDAP DICT TFTP"

              if test x$libgnurl_feature_SSL = xyes ; then
                 _libgnurl_protocols="$_libgnurl_protocols HTTPS"

                 # FTPS wasn't standards-compliant until version
                 # 7.11.0 (0x070b00 == 461568)
                 if test $_libgnurl_version -ge 461568; then
                    _libgnurl_protocols="$_libgnurl_protocols FTPS"
                 fi
              fi

              # RTSP, IMAP, POP3 and SMTP were added in
              # 7.20.0 (0x071400 == 463872)
              if test $_libgnurl_version -ge 463872; then
                 _libgnurl_protocols="$_libgnurl_protocols RTSP IMAP POP3 SMTP"
              fi
           fi

           for _libgnurl_protocol in $_libgnurl_protocols ; do
              AC_DEFINE_UNQUOTED(AS_TR_CPP(libgnurl_protocol_$_libgnurl_protocol),[1])
              eval AS_TR_SH(libgnurl_protocol_$_libgnurl_protocol)=yes
           done
        else
           unset LIBGNURL
           unset LIBGNURL_CPPFLAGS
        fi
     fi

     unset _libgnurl_try_link
     unset _libgnurl_version_parse
     unset _libgnurl_config
     unset _libgnurl_feature
     unset _libgnurl_features
     unset _libgnurl_protocol
     unset _libgnurl_protocols
     unset _libgnurl_version
     unset _libgnurl_ldflags
  fi

  if test x$_libgnurl_with = xno || test x$libgnurl_cv_lib_gnurl_usable != xyes ; then
     # This is the IF-NO path
     ifelse([$4],,:,[$4])
  else
     # This is the IF-YES path
     ifelse([$3],,:,[$3])
  fi

  unset _libgnurl_with
])dnl
