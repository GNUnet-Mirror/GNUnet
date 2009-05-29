dnl Autoconf macro for an always external libltdl
dnl       Copyright (C) 2009 Heikki Lindholm
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

dnl AM_PATH_LIBLTDL(
dnl  [CHECK-SYMBOLS, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl
AC_DEFUN([AM_PATH_LIBLTDL],
[ AC_ARG_WITH(libltdl-prefix,
            AC_HELP_STRING([--with-libltdl-prefix=PFX],
                           [prefix where libltdl is installed (optional)]),
     libltdl_prefix="$withval", libltdl_prefix="")
  ltdl_save_CPPFLAGS="$CPPFLAGS"
  ltdl_save_LDFLAGS="$LDFLAGS"
  if test x$libltdl_prefix != x ; then
    CPPFLAGS="-I$libltdl_prefix/include $CPPFLAGS"
    LDFLAGS="-L$libltdl_prefix/lib -lltdl $LDFLAGS"
  else
    if test x"$LIBLTDL" = x ; then
      LIBLTDL="-lltdl"
    fi
    CPPFLAGS="$LTDLINCL $CPPFLAGS"
    LDFLAGS="$LIBLTDL $LDFLAGS"
  fi

  symbols_to_check=ifelse([$1], ,"ltdl_dlopen","$1")
  ltdl_found=yes
  AC_CHECK_HEADER([ltdl.h],
    [
    for sym in $symbols_to_check
    do
      AC_CHECK_DECL([$sym],
        [AC_LINK_IFELSE(AC_LANG_CALL([], [$sym]),
          [ltdl_found=yes],
          [ltdl_found=no])],
        [ltdl_found=no],
	[AC_INCLUDES_DEFAULT
	 #include <ltdl.h>])
    done
    ],
    [ltdl_found=no],
    [AC_INCLUDES_DEFAULT]
  )

  if test x$libltdl_prefix != x ; then
    LTDLINCL="-I$libltdl_prefix/include"
    LIBLTDL="-L$libltdl_prefix/lib -lltdl"
  else
    if test x"$LIBLTDL" = x ; then
      LIBLTDL="-lltdl"
    fi
  fi
  CPPFLAGS="$ltdl_save_CPPFLAGS"
  LDFLAGS="$ltdl_save_LDFLAGS"

  AC_MSG_CHECKING(for libltdl with symbols $symbols_to_check)
  if test $ltdl_found = yes; then
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LTDLINCL=""
    LIBLTDL=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LTDLINCL)
  AC_SUBST(LIBLTDL)
])
