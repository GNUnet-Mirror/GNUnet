/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_time.c
 * @brief testcase for time.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

static int
check ()
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_AbsoluteNBO nown;
  struct GNUNET_TIME_Absolute future;
  struct GNUNET_TIME_Absolute past;
  struct GNUNET_TIME_Absolute last;
  struct GNUNET_TIME_Absolute forever;
  struct GNUNET_TIME_Absolute zero;
  struct GNUNET_TIME_Relative rel;
  struct GNUNET_TIME_Relative relForever;
  struct GNUNET_TIME_Relative relUnit;
  struct GNUNET_TIME_RelativeNBO reln;
  unsigned int i;
  forever = GNUNET_TIME_absolute_get_forever ();
  relForever = GNUNET_TIME_relative_get_forever ();
  relUnit = GNUNET_TIME_relative_get_unit ();
  zero.value = 0;

  last = now = GNUNET_TIME_absolute_get ();
  while (now.value == last.value)
    now = GNUNET_TIME_absolute_get ();
  GNUNET_assert (now.value > last.value);

  /* test overflow checking in multiply */
  rel = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_log_skip (1, GNUNET_NO);
  for (i = 0; i < 55; i++)
    rel = GNUNET_TIME_relative_multiply (rel, 2);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.value == GNUNET_TIME_UNIT_FOREVER_REL.value);

  /* test infinity-check for relative to absolute */
  last = GNUNET_TIME_relative_to_absolute (rel);
  GNUNET_assert (last.value == GNUNET_TIME_UNIT_FOREVER_ABS.value);

  /* check overflow for r2a */
  rel.value = (UINT64_MAX) - 1024;
  GNUNET_log_skip (1, GNUNET_NO);
  last = GNUNET_TIME_relative_to_absolute (rel);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (last.value == GNUNET_TIME_UNIT_FOREVER_ABS.value);

  /* check overflow for relative add */
  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (rel, rel);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.value == GNUNET_TIME_UNIT_FOREVER_REL.value);

  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (relForever, relForever);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.value == relForever.value);

  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (relUnit, relUnit);
  GNUNET_assert (rel.value == 2 * relUnit.value);

  /* check relation check in get_duration */
  future.value = now.value + 1000000;
  GNUNET_assert (GNUNET_TIME_absolute_get_difference (now, future).value ==
                 1000000);
  GNUNET_assert (GNUNET_TIME_absolute_get_difference (future, now).value ==
                 0);

  GNUNET_assert (GNUNET_TIME_absolute_get_difference (zero, forever).value ==
                 forever.value);

  past.value = now.value - 1000000;
  rel = GNUNET_TIME_absolute_get_duration (future);
  GNUNET_assert (rel.value == 0);
  rel = GNUNET_TIME_absolute_get_duration (past);
  GNUNET_assert (rel.value >= 1000000);

  /* check get remaining */
  rel = GNUNET_TIME_absolute_get_remaining (now);
  GNUNET_assert (rel.value == 0);
  rel = GNUNET_TIME_absolute_get_remaining (past);
  GNUNET_assert (rel.value == 0);
  rel = GNUNET_TIME_absolute_get_remaining (future);
  GNUNET_assert (rel.value > 0);
  GNUNET_assert (rel.value <= 1000000);

  /* check endianess */
  reln = GNUNET_TIME_relative_hton (rel);
  GNUNET_assert (rel.value == GNUNET_TIME_relative_ntoh (reln).value);
  nown = GNUNET_TIME_absolute_hton (now);
  GNUNET_assert (now.value == GNUNET_TIME_absolute_ntoh (nown).value);

  /* check absolute addition */
  future = GNUNET_TIME_absolute_add (now, GNUNET_TIME_UNIT_SECONDS);
  GNUNET_assert (future.value == now.value + 1000);

  future = GNUNET_TIME_absolute_add (forever, GNUNET_TIME_UNIT_ZERO);
  GNUNET_assert (future.value == forever.value);

  rel.value = (UINT64_MAX) - 1024;
  now.value = rel.value;
  future = GNUNET_TIME_absolute_add (now, rel);
  GNUNET_assert (future.value == forever.value);

  /* check zero */
  future = GNUNET_TIME_absolute_add (now, GNUNET_TIME_UNIT_ZERO);
  GNUNET_assert (future.value == now.value);

  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-time", "WARNING", NULL);
  ret = check ();

  return ret;
}

/* end of test_time.c */
