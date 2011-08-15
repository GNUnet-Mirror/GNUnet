/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file util/test_getopt.c
 * @brief testcase for util/getopt.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"

#define VERBOSE 0

static int
testMinimal ()
{
  char *const emptyargv[] = {
    "test",
    NULL
  };
  const struct GNUNET_GETOPT_CommandLineOption emptyoptionlist[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (1 != GNUNET_GETOPT_run ("test", emptyoptionlist, 1, emptyargv))
    return 1;

  return 0;
}

static int
testVerbose ()
{
  char *const myargv[] = {
    "test",
    "-V",
    "-V",
    "more",
    NULL
  };
  unsigned int vflags = 0;

  const struct GNUNET_GETOPT_CommandLineOption verboseoptionlist[] = {
    GNUNET_GETOPT_OPTION_VERBOSE (&vflags),
    GNUNET_GETOPT_OPTION_END
  };

  if (3 != GNUNET_GETOPT_run ("test", verboseoptionlist, 4, myargv))
  {
    GNUNET_break (0);
    return 1;
  }
  if (vflags != 2)
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}

static int
testVersion ()
{
  char *const myargv[] = {
    "test_getopt",
    "-v",
    NULL
  };
  const struct GNUNET_GETOPT_CommandLineOption versionoptionlist[] = {
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION),
    GNUNET_GETOPT_OPTION_END
  };

  if (-1 != GNUNET_GETOPT_run ("test_getopt", versionoptionlist, 2, myargv))
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}

static int
testAbout ()
{
  char *const myargv[] = {
    "test_getopt",
    "-h",
    NULL
  };
  const struct GNUNET_GETOPT_CommandLineOption aboutoptionlist[] = {
    GNUNET_GETOPT_OPTION_HELP ("Testing"),
    GNUNET_GETOPT_OPTION_END
  };

  if (-1 != GNUNET_GETOPT_run ("test_getopt", aboutoptionlist, 2, myargv))
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}

static int
testLogOpts ()
{
  char *const myargv[] = {
    "test_getopt",
    "-l", "filename",
    "-L", "WARNING",
    NULL
  };
  char *level = GNUNET_strdup ("stuff");
  char *fn = NULL;

  const struct GNUNET_GETOPT_CommandLineOption logoptionlist[] = {
    GNUNET_GETOPT_OPTION_LOGFILE (&fn),
    GNUNET_GETOPT_OPTION_LOGLEVEL (&level),
    GNUNET_GETOPT_OPTION_END
  };

  if (5 != GNUNET_GETOPT_run ("test_getopt", logoptionlist, 5, myargv))
  {
    GNUNET_break (0);
    return 1;
  }
  GNUNET_assert (fn != NULL);
  if ((0 != strcmp (level, "WARNING")) || (0 != strcmp (fn, "filename")))
  {
    GNUNET_break (0);
    GNUNET_free (level);
    GNUNET_free (fn);
    return 1;
  }
  GNUNET_free (level);
  GNUNET_free (fn);
  return 0;
}

static int
testFlagNum ()
{
  char *const myargv[] = {
    "test_getopt",
    "-f",
    "-n", "42",
    "-N", "42",
    NULL
  };
  int flag = 0;
  unsigned int num = 0;
  unsigned long long lnum = 0;

  const struct GNUNET_GETOPT_CommandLineOption logoptionlist[] = {
    {'f', "--flag", NULL, "helptext", 0, &GNUNET_GETOPT_set_one,
     (void *) &flag},
    {'n', "--num", "ARG", "helptext", 1, &GNUNET_GETOPT_set_uint,
     (void *) &num},
    {'N', "--lnum", "ARG", "helptext", 1, &GNUNET_GETOPT_set_ulong,
     (void *) &lnum},
    GNUNET_GETOPT_OPTION_END
  };

  if (6 != GNUNET_GETOPT_run ("test_getopt", logoptionlist, 6, myargv))
  {
    GNUNET_break (0);
    return 1;
  }
  if ((1 != flag) || (42 != num) || (42 != lnum))
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}

int
main (int argc, char *argv[])
{
  int errCnt = 0;

  GNUNET_log_setup ("test_getopt", "WARNING", NULL);
  /* suppress output from -h, -v options */
#ifndef MINGW
  GNUNET_break (0 == CLOSE (1));
#endif
  if (0 != testMinimal ())
    errCnt++;
  if (0 != testVerbose ())
    errCnt++;
  if (0 != testVersion ())
    errCnt++;
  if (0 != testAbout ())
    errCnt++;
  if (0 != testLogOpts ())
    errCnt++;
  if (0 != testFlagNum ())
    errCnt++;
  return errCnt;
}
