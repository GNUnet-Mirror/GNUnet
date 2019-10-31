/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
 */
static void
test_task (void *cls)
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
  fprintf (stderr, "%s", ".");
  if (i > MAXV)
  {
    fprintf (stderr, "%s", "\n");
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MICROSECONDS, i),
                                &test_task,
                                NULL);
  i += INCR;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-scheduler-delay",
                    "WARNING",
                    NULL);
  target = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_run (&test_task, NULL);
  fprintf (stdout,
           "Sleep precision: %llu microseconds (average delta). ",
           cumDelta / (MAXV / INCR));
  if (cumDelta <= 500 * MAXV / INCR)
    fprintf (stdout, "%s", "Timer precision is excellent.\n");
  else if (cumDelta <= 5000 * MAXV / INCR)        /* 5 ms average deviation */
    fprintf (stdout, "%s", "Timer precision is good.\n");
  else if (cumDelta > 25000 * MAXV / INCR)
    fprintf (stdout, "%s", "Timer precision is awful.\n");
  else
    fprintf (stdout, "%s", "Timer precision is acceptable.\n");
  return 0;
}


/* end of test_scheduler_delay.c */
