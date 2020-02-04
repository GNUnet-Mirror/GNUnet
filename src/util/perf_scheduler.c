/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file util/perf_scheduler.c
 * @brief measure performance of scheduler functions
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>

#define RUNS (1024 * 1024)

static struct GNUNET_SCHEDULER_Task *task;


static void
run (void *cls)
{
  uint64_t *count = cls;

  task = NULL;
  (*count)++;
  if (*count >= RUNS)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  task = GNUNET_SCHEDULER_add_now (&run,
                                   count);
}


static void
do_shutdown (void *cls)
{
  if (NULL != task)
    GNUNET_SCHEDULER_cancel (task);
}


static void
first (void *cls)
{
  uint64_t *count = cls;

  (*count)++;
  task = GNUNET_SCHEDULER_add_now (&run,
                                   count);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
}


static uint64_t
perf_scheduler ()
{
  uint64_t count = 0;

  GNUNET_SCHEDULER_run (&first,
                        &count);
  return count;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  uint64_t tasks;

  start = GNUNET_TIME_absolute_get ();
  tasks = perf_scheduler ();
  printf ("Scheduler perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GAUGER ("UTIL", "Scheduler",
          tasks / 1024 / (1
                       + GNUNET_TIME_absolute_get_duration
                         (start).rel_value_us / 1000LL), "tasks/ms");
  return 0;
}


/* end of perf_scheduler.c */
