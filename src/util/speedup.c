/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file util/speedup.c
 * @author Matthias Wachs
 * @brief functions to speedup peer execution by manipulation system time
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "speedup.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-speedup", __VA_ARGS__)


static struct GNUNET_TIME_Relative interval;

static struct GNUNET_TIME_Relative delta;

static struct GNUNET_SCHEDULER_Task *speedup_task;


static void
do_speedup (void *cls)
{
  static long long current_offset;

  (void) cls;
  speedup_task = NULL;
  current_offset += delta.rel_value_us;
  GNUNET_TIME_set_offset (current_offset);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Speeding up execution time by %s\n",
       GNUNET_STRINGS_relative_time_to_string (delta, GNUNET_NO));
  speedup_task = GNUNET_SCHEDULER_add_delayed (interval,
                                               &do_speedup,
                                               NULL);
}


/**
 * Start task that may speed up our system clock artificially
 *
 * @param cfg configuration to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the speedup was not configured
 */
int
GNUNET_SPEEDUP_start_ (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (NULL == speedup_task);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "testing",
                                           "SPEEDUP_INTERVAL",
                                           &interval))
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "testing",
                                           "SPEEDUP_DELTA",
                                           &delta))
    return GNUNET_SYSERR;

  if ((0 == interval.rel_value_us) ||
      (0 == delta.rel_value_us))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Speed up disabled\n");
    return GNUNET_OK;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Speed up execution by %s\n",
       GNUNET_STRINGS_relative_time_to_string (delta, GNUNET_NO));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Speed up executed every %s\n",
       GNUNET_STRINGS_relative_time_to_string (interval, GNUNET_NO));
  speedup_task = GNUNET_SCHEDULER_add_now_with_lifeness (GNUNET_NO,
                                                         &do_speedup,
                                                         NULL);
  return GNUNET_OK;
}


/**
 * Stop tasks that modify clock behavior.
 */
void
GNUNET_SPEEDUP_stop_ ()
{
  if (NULL != speedup_task)
  {
    GNUNET_SCHEDULER_cancel (speedup_task);
    speedup_task = NULL;
  }
  if ((0 != interval.rel_value_us) &&
      (0 != delta.rel_value_us))
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Stopped execution speed up\n");
}


/* end of speedup.c */
