/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats_logging.c
 * @brief ats benchmark: logging for performance tests
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "perf_ats.h"

#define LOGGING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)

static GNUNET_SCHEDULER_TaskIdentifier log_task;

static struct BenchmarkPeer *peers;
static int num_peers;

static void
write_to_file ()
{

}

static void
collect_log_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;
  log_task = GNUNET_SCHEDULER_NO_TASK;

  struct BenchmarkPeer *m;
  struct BenchmarkPartner *p;

  for (c_m = 0; c_m < num_peers; c_m++)
  {
    m = &peers[c_m];
    for (c_s = 0; c_s < m->num_partners; c_s++)
    {
      p = &peers[c_m].partners[c_s];
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Master [%u]: slave [%u]\n",
          m->no, p->dest->no);
    }
  }

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  log_task = GNUNET_SCHEDULER_add_delayed (LOGGING_FREQUENCY,
      &collect_log_task, NULL);
}


void
perf_logging_stop ()
{
  struct GNUNET_SCHEDULER_TaskContext tc;

  if (GNUNET_SCHEDULER_NO_TASK != log_task)
    GNUNET_SCHEDULER_cancel (log_task);
  log_task = GNUNET_SCHEDULER_NO_TASK;
  tc.reason = GNUNET_SCHEDULER_REASON_SHUTDOWN;
  collect_log_task (NULL, &tc);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Stop logging\n"));

  write_to_file ();
}

void
perf_logging_start (struct BenchmarkPeer *masters, int num_masters)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging\n"));

  peers = masters;
  num_peers = num_masters;

  /* Schedule logging task */
  log_task = GNUNET_SCHEDULER_add_now (&collect_log_task, NULL);
}
/* end of file perf_ats_logging.c */

