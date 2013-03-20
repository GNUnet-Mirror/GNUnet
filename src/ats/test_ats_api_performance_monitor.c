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

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)
#define SHUTDOWN_CORRECT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static GNUNET_SCHEDULER_TaskIdentifier die_task;
static GNUNET_SCHEDULER_TaskIdentifier stage_task;

struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ATS_SchedulingHandle *sh;

static struct GNUNET_ATS_PerformanceHandle *ph;

static struct GNUNET_ATS_PerformanceMonitorHandle *phm;

static struct GNUNET_HELLO_Address addr;

static struct GNUNET_ATS_Information atsi[3];

static int ret;

static void cleanup_addresses ()
{
	GNUNET_ATS_address_destroyed (sh, &addr, NULL);
}

static void setup_addresses ()
{
	memset (&addr.peer,'\0', sizeof (addr.peer));
	addr.transport_name = "test";
	addr.address = NULL;
	addr.address_length = 0;
	atsi[0].type = htonl(GNUNET_ATS_NETWORK_TYPE);
	atsi[0].value = htonl(GNUNET_ATS_NET_LAN);

	atsi[1].type = htonl(GNUNET_ATS_QUALITY_NET_DELAY);
	atsi[1].value = htonl(100);

	atsi[2].type = htonl(GNUNET_ATS_QUALITY_NET_DISTANCE);
	atsi[2].value = htonl(5);

	GNUNET_ATS_address_add (sh, &addr, NULL, atsi, 3);
}


static void
end_now (int res)
{
	if (GNUNET_SCHEDULER_NO_TASK != stage_task)
	{
			GNUNET_SCHEDULER_cancel (stage_task);
			stage_task = GNUNET_SCHEDULER_NO_TASK;
	}
	if (GNUNET_SCHEDULER_NO_TASK != die_task)
	{
			GNUNET_SCHEDULER_cancel (die_task);
			die_task = GNUNET_SCHEDULER_NO_TASK;
	}
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");

	cleanup_addresses ();

	if (NULL != phm)
	{
		GNUNET_ATS_performance_monitor_stop (phm);
		phm = NULL;
	}

	if (NULL != ph)
	{
		GNUNET_ATS_performance_done (ph);
		ph = NULL;
	}

	if (NULL != sh)
	{
		GNUNET_ATS_scheduling_done (sh);
		sh = NULL;
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
next_stage (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	static int stage_counter = 0;

	stage_task = GNUNET_SCHEDULER_NO_TASK;
	if (0 == stage_counter)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stop performance monitoring\n");

		GNUNET_ATS_performance_monitor_stop (phm);
		phm = NULL;

		stage_task = GNUNET_SCHEDULER_add_delayed (SHUTDOWN_CORRECT, &next_stage, NULL);
		stage_counter++;
		return;
	}
	else
	{
			end_now (0);
	}
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

  sh = GNUNET_ATS_scheduling_init (cfg, NULL, NULL);
  GNUNET_assert (NULL != sh);

  setup_addresses ();

  ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
  GNUNET_assert (NULL != ph);

  phm = GNUNET_ATS_performance_monitor_start (ph, &perf_mon_cb, &ret);
  GNUNET_assert (NULL != phm);

  stage_task = GNUNET_SCHEDULER_add_delayed (SHUTDOWN_CORRECT, &next_stage, NULL);
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
