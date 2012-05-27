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

  forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  relForever = GNUNET_TIME_UNIT_FOREVER_REL;
  relUnit = GNUNET_TIME_UNIT_MILLISECONDS;
  zero.abs_value = 0;

  last = now = GNUNET_TIME_absolute_get ();
  while (now.abs_value == last.abs_value)
    now = GNUNET_TIME_absolute_get ();
  GNUNET_assert (now.abs_value > last.abs_value);

  /* test overflow checking in multiply */
  rel = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_log_skip (1, GNUNET_NO);
  for (i = 0; i < 55; i++)
    rel = GNUNET_TIME_relative_multiply (rel, 2);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value);
  /*check zero */
  rel.rel_value = (UINT64_MAX) - 1024;
  GNUNET_assert (GNUNET_TIME_UNIT_ZERO.rel_value ==
                 GNUNET_TIME_relative_multiply (rel, 0).rel_value);

  /* test infinity-check for relative to absolute */
  GNUNET_log_skip (1, GNUNET_NO);
  last = GNUNET_TIME_relative_to_absolute (rel);
  GNUNET_assert (last.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value);
  GNUNET_log_skip (0, GNUNET_YES);

  /*check relative to absolute */
  rel.rel_value = 0;
  GNUNET_assert (GNUNET_TIME_absolute_get ().abs_value ==
                 GNUNET_TIME_relative_to_absolute (rel).abs_value);
  /*check forever */
  rel.rel_value = UINT64_MAX;
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value ==
                 GNUNET_TIME_relative_to_absolute (rel).abs_value);
  /* check overflow for r2a */
  rel.rel_value = (UINT64_MAX) - 1024;
  GNUNET_log_skip (1, GNUNET_NO);
  last = GNUNET_TIME_relative_to_absolute (rel);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (last.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value);

  /* check overflow for relative add */
  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (rel, rel);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value);

  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (relForever, relForever);
  GNUNET_log_skip (0, GNUNET_NO);
  GNUNET_assert (rel.rel_value == relForever.rel_value);

  GNUNET_log_skip (1, GNUNET_NO);
  rel = GNUNET_TIME_relative_add (relUnit, relUnit);
  GNUNET_assert (rel.rel_value == 2 * relUnit.rel_value);

  /* check relation check in get_duration */
  future.abs_value = now.abs_value + 1000000;
  GNUNET_assert (GNUNET_TIME_absolute_get_difference (now, future).rel_value ==
                 1000000);
  GNUNET_assert (GNUNET_TIME_absolute_get_difference (future, now).rel_value ==
                 0);

  GNUNET_assert (GNUNET_TIME_absolute_get_difference (zero, forever).rel_value
                 == forever.abs_value);

  past.abs_value = now.abs_value - 1000000;
  rel = GNUNET_TIME_absolute_get_duration (future);
  GNUNET_assert (rel.rel_value == 0);
  rel = GNUNET_TIME_absolute_get_duration (past);
  GNUNET_assert (rel.rel_value >= 1000000);

  /* check get remaining */
  rel = GNUNET_TIME_absolute_get_remaining (now);
  GNUNET_assert (rel.rel_value == 0);
  rel = GNUNET_TIME_absolute_get_remaining (past);
  GNUNET_assert (rel.rel_value == 0);
  rel = GNUNET_TIME_absolute_get_remaining (future);
  GNUNET_assert (rel.rel_value > 0);
  GNUNET_assert (rel.rel_value <= 1000000);
  forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value ==
                 GNUNET_TIME_absolute_get_remaining (forever).rel_value);

  /* check endianess */
  reln = GNUNET_TIME_relative_hton (rel);
  GNUNET_assert (rel.rel_value == GNUNET_TIME_relative_ntoh (reln).rel_value);
  nown = GNUNET_TIME_absolute_hton (now);
  GNUNET_assert (now.abs_value == GNUNET_TIME_absolute_ntoh (nown).abs_value);

  /* check absolute addition */
  future = GNUNET_TIME_absolute_add (now, GNUNET_TIME_UNIT_SECONDS);
  GNUNET_assert (future.abs_value == now.abs_value + 1000);

  future = GNUNET_TIME_absolute_add (forever, GNUNET_TIME_UNIT_ZERO);
  GNUNET_assert (future.abs_value == forever.abs_value);

  rel.rel_value = (UINT64_MAX) - 1024;
  now.abs_value = rel.rel_value;
  future = GNUNET_TIME_absolute_add (now, rel);
  GNUNET_assert (future.abs_value == forever.abs_value);

  /* check zero */
  future = GNUNET_TIME_absolute_add (now, GNUNET_TIME_UNIT_ZERO);
  GNUNET_assert (future.abs_value == now.abs_value);

  GNUNET_assert (forever.abs_value ==
                 GNUNET_TIME_absolute_subtract (forever,
                                                GNUNET_TIME_UNIT_MINUTES).abs_value);
  /*check absolute subtract */
  now.abs_value = 50000;
  rel.rel_value = 100000;
  GNUNET_assert (GNUNET_TIME_UNIT_ZERO_ABS.abs_value ==
                 (GNUNET_TIME_absolute_subtract (now, rel)).abs_value);
  rel.rel_value = 10000;
  GNUNET_assert (40000 == (GNUNET_TIME_absolute_subtract (now, rel)).abs_value);

  /*check relative divide */
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value ==
                 (GNUNET_TIME_relative_divide (rel, 0)).rel_value);

  rel = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value ==
                 (GNUNET_TIME_relative_divide (rel, 2)).rel_value);

  rel = GNUNET_TIME_relative_divide (relUnit, 2);
  GNUNET_assert (rel.rel_value == relUnit.rel_value / 2);


  /* check Return absolute time of 0ms */
  zero = GNUNET_TIME_UNIT_ZERO_ABS;

  /* check GNUNET_TIME_calculate_eta */
  last.abs_value = GNUNET_TIME_absolute_get ().abs_value - 1024;
  forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  forever.abs_value = forever.abs_value - 1024;
  GNUNET_assert (GNUNET_TIME_UNIT_ZERO_ABS.abs_value ==
                 GNUNET_TIME_calculate_eta (forever, 50000, 100000).rel_value);
  /* check zero */
  GNUNET_log_skip (1, GNUNET_NO);
  GNUNET_assert (GNUNET_TIME_UNIT_ZERO.rel_value ==
                 (GNUNET_TIME_calculate_eta (last, 60000, 50000)).rel_value);
  GNUNET_log_skip (0, GNUNET_YES);
  /*check forever */
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value ==
                 (GNUNET_TIME_calculate_eta (last, 0, 50000)).rel_value);

  /*check relative subtract */
  now = GNUNET_TIME_absolute_get ();
  rel.rel_value = now.abs_value;
  relForever.rel_value = rel.rel_value + 1024;
  GNUNET_assert (1024 ==
                 GNUNET_TIME_relative_subtract (relForever, rel).rel_value);
  /*check zero */
  GNUNET_assert (GNUNET_TIME_UNIT_ZERO.rel_value ==
                 GNUNET_TIME_relative_subtract (rel, relForever).rel_value);
  /*check forever */
  rel.rel_value = UINT64_MAX;
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value ==
                 GNUNET_TIME_relative_subtract (rel, relForever).rel_value);

  /*check GNUNET_TIME_relative_min */
  now = GNUNET_TIME_absolute_get ();
  rel.rel_value = now.abs_value;
  relForever.rel_value = rel.rel_value - 1024;
  GNUNET_assert (relForever.rel_value ==
                 GNUNET_TIME_relative_min (rel, relForever).rel_value);

  /*check GNUNET_TIME_relative_max */
  GNUNET_assert (rel.rel_value ==
                 GNUNET_TIME_relative_max (rel, relForever).rel_value);

  /*check GNUNET_TIME_absolute_min */
  now = GNUNET_TIME_absolute_get ();
  last.abs_value = now.abs_value - 1024;
  GNUNET_assert (last.abs_value ==
                 GNUNET_TIME_absolute_min (now, last).abs_value);

  /*check  GNUNET_TIME_absolute_max */
  GNUNET_assert (now.abs_value ==
                 GNUNET_TIME_absolute_max (now, last).abs_value);

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
