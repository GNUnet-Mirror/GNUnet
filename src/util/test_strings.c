/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_lib.h"


#define WANT(a,b) if (0 != strcmp(a,b)) { fprintf(stderr, "Got `%s', wanted `%s'\n", b, a); GNUNET_free(b); GNUNET_break(0); return 1;} else { GNUNET_free (b); }
#define WANTNF(a,b) do { if (0 != strcmp(a,b)) { fprintf(stderr, "Got `%s', wanted `%s'\n", b, a); GNUNET_break(0); return 1;} } while (0)
#define WANTB(a,b,l) if (0 != memcmp(a,b,l)) { GNUNET_break(0); return 1;} else { }

int
main (int argc, char *argv[])
{
  char buf[128];
  char *r;
  char *b;
  const char *bc;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Absolute atx;
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Relative rtx;
  const char *hdir;

  GNUNET_log_setup ("test_strings", "ERROR", NULL);
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
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
					       (GNUNET_TIME_UNIT_MILLISECONDS,
						4), GNUNET_YES);
  WANTNF (buf, bc);
  sprintf (buf, "7 %s", _( /* time unit */ "s"));
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
					       (GNUNET_TIME_UNIT_MILLISECONDS,
						7 * 1000), GNUNET_YES);
  WANTNF (buf, bc);
  sprintf (buf, "7 %s", _( /* time unit */ "h"));
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                              (GNUNET_TIME_UNIT_MILLISECONDS,
                                               7 * 60 * 60 * 1000), GNUNET_YES);
  WANTNF (buf, bc);
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
  at.abs_value_us = 5000000;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);
  /* bc should be something like "Wed Dec 31 17:00:05 1969"
   * where the details of the day and hour depend on the timezone;
   * however, the "0:05 19" should always be there; hence: */
  if (NULL == strstr (bc, "0:05 19"))
  {
    FPRINTF (stderr, "Got %s\n", bc);
    GNUNET_break (0);
    return 1;
  }
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "ASCII");
  WANT ("TEST", b);

  at = GNUNET_TIME_UNIT_FOREVER_ABS;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_STRINGS_fancy_time_to_absolute (bc, &atx));
  GNUNET_assert (atx.abs_value_us == at.abs_value_us);

  at.abs_value_us = 50000000000;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STRINGS_fancy_time_to_absolute (bc, &atx));

  if (atx.abs_value_us != at.abs_value_us)
  {
#ifdef WINDOWS
    DWORD tzv;
    TIME_ZONE_INFORMATION tzi;
    tzv = GetTimeZoneInformation (&tzi);
    if (TIME_ZONE_ID_INVALID != tzv)
    {
      atx.abs_value_us -= 1000LL * 1000LL * tzi.Bias * 60LL;
    }
    if (atx.abs_value_us == at.abs_value_us)
      fprintf (stderr,
               "WARNING:  GNUNET_STRINGS_fancy_time_to_absolute() miscalculates timezone!\n");
#endif
    GNUNET_assert (0);
  }

  GNUNET_log_skip (2, GNUNET_NO);
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "unknown");
  GNUNET_log_skip (0, GNUNET_YES);
  WANT ("TEST", b);

  GNUNET_assert (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_relative ("15m", &rt));
  GNUNET_assert (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_relative ("15 m", &rtx));
  GNUNET_assert (rt.rel_value_us == rtx.rel_value_us);

  return 0;
}


/* end of test_strings.c */
