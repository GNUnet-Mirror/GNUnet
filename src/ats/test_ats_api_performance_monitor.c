/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_api_performance_monitor.c
 * @brief test performance monitoring
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static GNUNET_SCHEDULER_TaskIdentifier die_task;

struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ATS_PerformanceHandle *ph;

static struct GNUNET_ATS_PerformanceMonitorHandle *phm;

static int ret;


static void
end_now (int res)
{
	if (GNUNET_SCHEDULER_NO_TASK != die_task)
	{
			GNUNET_SCHEDULER_cancel (die_task);
			die_task = GNUNET_SCHEDULER_NO_TASK;
	}

	if (NULL != ph)
	{
		GNUNET_ATS_performance_done (ph);
		ph = NULL;
	}
	ret = res;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Timeout\n");
  end_now (1);
}


static void
perf_mon_cb (void *cls,
						struct GNUNET_PeerIdentity *peer,
						struct GNUNET_ATS_Information *ats,
						uint32_t ats_count)
{

}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *mycfg,
     struct GNUNET_TESTING_Peer *peer)
{
  ret = 1;
  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
  GNUNET_assert (NULL != ph);

  phm = GNUNET_ATS_performance_monitor_start (ph, &perf_mon_cb, &ret);
  GNUNET_assert (NULL != phm);

  GNUNET_ATS_performance_monitor_stop (phm);

	GNUNET_ATS_performance_done (ph);
	ph = NULL;
  end_now (0);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_performance_monitor",
				    "test_ats_api.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_performance_monitor.c */
