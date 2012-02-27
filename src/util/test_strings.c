/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_strings.c
 * @brief testcase for strings.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_strings_lib.h"

#define VERBOSE GNUNET_NO

#define WANT(a,b) if (0 != strcmp(a,b)) { fprintf(stderr, "Got `%s', wanted `%s'\n", b, a); GNUNET_free(b); GNUNET_break(0); return 1;} else { GNUNET_free (b); }
#define WANTB(a,b,l) if (0 != memcmp(a,b,l)) { GNUNET_break(0); return 1;} else { }

static int
check ()
{
  char buf[128];
  char *r;
  char *b;
  struct GNUNET_TIME_Absolute at;
  const char *hdir;

  sprintf (buf, "4 %s", _( /* size unit */ "b"));
  b = GNUNET_STRINGS_byte_size_fancy (4);
  WANT (buf, b);
  sprintf (buf, "10 %s", _( /* size unit */ "KiB"));
  b = GNUNET_STRINGS_byte_size_fancy (10240);
  WANT (buf, b);
  sprintf (buf, "10 %s", _( /* size unit */ "TiB"));
  b = GNUNET_STRINGS_byte_size_fancy (10240LL * 1024LL * 1024LL * 1024LL);
  WANT (buf, b);
  sprintf (buf, "4 %s", _( /* time unit */ "ms"));
  b = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                              (GNUNET_TIME_UNIT_MILLISECONDS,
                                               4));
  WANT (buf, b);
  sprintf (buf, "7 %s", _( /* time unit */ "s"));
  b = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                              (GNUNET_TIME_UNIT_MILLISECONDS,
                                               7 * 1000));
  WANT (buf, b);
  sprintf (buf, "7 %s", _( /* time unit */ "h"));
  b = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                              (GNUNET_TIME_UNIT_MILLISECONDS,
                                               7 * 60 * 60 * 1000));
  WANT (buf, b);
#ifndef MINGW
  hdir = getenv ("HOME");
#else
  hdir = getenv ("USERPROFILE");
#endif
  GNUNET_snprintf (buf, sizeof (buf), "%s%s", hdir, DIR_SEPARATOR_STR);
  b = GNUNET_STRINGS_filename_expand ("~");
  GNUNET_assert (b != NULL);
  WANT (buf, b);
  GNUNET_STRINGS_buffer_fill (buf, sizeof (buf), 3, "a", "btx", "c");
  WANTB ("a\0btx\0c", buf, 8);
  if (6 != GNUNET_STRINGS_buffer_tokenize (buf, sizeof (buf), 2, &r, &b))
    return 1;
  r = GNUNET_strdup (r);
  WANT ("a", r);
  b = GNUNET_strdup (b);
  WANT ("btx", b);
  if (0 != GNUNET_STRINGS_buffer_tokenize (buf, 2, 2, &r, &b))
    return 1;
  at.abs_value = 5000;
  r = GNUNET_STRINGS_absolute_time_to_string (at);
  /* r should be something like "Wed Dec 31 17:00:05 1969"
   * where the details of the day and hour depend on the timezone;
   * however, the "0:05 19" should always be there; hence: */
  if (NULL == strstr (r, "0:05 19"))
  {
    FPRINTF (stderr, "Got %s\n", r);
    GNUNET_break (0);
    GNUNET_free (r);
    return 1;
  }
  GNUNET_free (r);
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "ASCII");
  WANT ("TEST", b);
  GNUNET_log_skip (2, GNUNET_NO);
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "unknown");
  GNUNET_log_skip (0, GNUNET_YES);
  WANT ("TEST", b);
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test_strings", "ERROR", NULL);
  ret = check ();
  return ret;
}

/* end of test_strings.c */
