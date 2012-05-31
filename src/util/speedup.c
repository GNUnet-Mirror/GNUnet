/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/speedup.c
 * @author Matthias Wachs
 * @brief functions to speedup peer execution by manipulation system time
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gnunet_scheduler_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)


static struct GNUNET_TIME_Relative interval;

static struct GNUNET_TIME_Relative delta;

static GNUNET_SCHEDULER_TaskIdentifier speedup_task;


static void
do_speedup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static long long current_offset;
 
  speedup_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  current_offset += delta.rel_value;
  GNUNET_TIME_set_offset (current_offset);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Speeding up execution time by %llu ms\n", delta.rel_value);
  speedup_task = GNUNET_SCHEDULER_add_delayed (interval, &do_speedup, NULL);
}


int
GNUNET_SPEEDUP_start_ (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "testing", "SPEEDUP_INTERVAL", &interval))
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "testing", "SPEEDUP_DELTA", &delta))
    return GNUNET_SYSERR;

  if ((0 == interval.rel_value) || (0 == delta.rel_value))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Speed up disabled\n");
    return GNUNET_OK;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Speed up execution time %llu ms every %llu ms\n",
       delta.rel_value, interval.rel_value);
  speedup_task = GNUNET_SCHEDULER_add_now_with_lifeness (GNUNET_NO, &do_speedup, NULL);
  return GNUNET_OK;
}


void
GNUNET_SPEEDUP_stop_ ( )
{
  if (GNUNET_SCHEDULER_NO_TASK != speedup_task)
  {
    GNUNET_SCHEDULER_cancel (speedup_task);
    speedup_task = GNUNET_SCHEDULER_NO_TASK;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopped execution speed up\n");
}



/* end of speedup.c */
