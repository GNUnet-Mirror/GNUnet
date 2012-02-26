/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/test_scheduler_delay.c
 * @brief testcase for delay of scheduler, measures how
 *  precise the timers are.  Expect values between 10 and 20 ms on
 *  modern machines.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

static struct GNUNET_TIME_Absolute target;

static int i;

static unsigned long long cumDelta;

#define INCR 47

#define MAXV 1500

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context
 */
static void
test_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  if (now.abs_value > target.abs_value)
    cumDelta += (now.abs_value - target.abs_value);
  else
    cumDelta += (target.abs_value - now.abs_value);
  target =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_MILLISECONDS, i));
  FPRINTF (stderr, "%s",  ".");
  if (i > MAXV)
  {
    FPRINTF (stderr, "%s",  "\n");
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_MILLISECONDS, i), &test_task,
                                NULL);
  i += INCR;
}

static int
check ()
{
  target = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_run (&test_task, NULL);
  FPRINTF (stdout, "Sleep precision: %llu ms. ",
           cumDelta / 1000 / (MAXV / INCR));
  if (cumDelta <= 10 * MAXV / INCR)
    FPRINTF (stdout, "%s",  "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * MAXV / INCR)        /* 50 ms average deviation */
    FPRINTF (stdout, "%s",  "Timer precision is good.\n");
  else if (cumDelta > 250 * MAXV / INCR)
    FPRINTF (stdout, "%s",  "Timer precision is awful.\n");
  else
    FPRINTF (stdout, "%s",  "Timer precision is acceptable.\n");
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-scheduler-delay", "WARNING", NULL);
  ret = check ();

  return ret;
}

/* end of test_scheduler_delay.c */
