/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file util/test_scheduler_delay.c
 * @brief testcase for delay of scheduler, measures how
 *  precise the timers are.  Expect values between 0.2 and 2 ms on
 *  modern machines.
 */
#include "platform.h"
#include "gnunet_util_lib.h"

static struct GNUNET_TIME_Absolute target;

static int i;

static unsigned long long cumDelta;

#define INCR 47

#define MAXV 5000


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context
 */
static void
test_task (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  if (now.abs_value_us > target.abs_value_us)
    cumDelta += (now.abs_value_us - target.abs_value_us);
  else
    cumDelta += (target.abs_value_us - now.abs_value_us);
  target =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_MICROSECONDS, i));
  FPRINTF (stderr, "%s",  ".");
  if (i > MAXV)
  {
    FPRINTF (stderr, "%s",  "\n");
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_MICROSECONDS, i), &test_task,
                                NULL);
  i += INCR;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-scheduler-delay", "WARNING", NULL);
  target = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_run (&test_task, NULL);
  FPRINTF (stdout,
	   "Sleep precision: %llu microseconds (average delta). ",
           cumDelta / (MAXV / INCR));
  if (cumDelta <= 500 * MAXV / INCR)
    FPRINTF (stdout, "%s",  "Timer precision is excellent.\n");
  else if (cumDelta <= 5000 * MAXV / INCR)        /* 5 ms average deviation */
    FPRINTF (stdout, "%s",  "Timer precision is good.\n");
  else if (cumDelta > 25000 * MAXV / INCR)
    FPRINTF (stdout, "%s",  "Timer precision is awful.\n");
  else
    FPRINTF (stdout, "%s",  "Timer precision is acceptable.\n");
  return 0;
}

/* end of test_scheduler_delay.c */
