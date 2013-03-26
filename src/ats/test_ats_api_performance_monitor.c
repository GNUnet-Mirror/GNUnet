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
 * @brief Test performance API:
 * 				Add an address for a peer and request it. We expect an monitor callback
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)
#define SHUTDOWN_CORRECT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define ATS_COUNT 2

static GNUNET_SCHEDULER_TaskIdentifier die_task;
static GNUNET_SCHEDULER_TaskIdentifier stage_task;

struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ATS_SchedulingHandle *sh;

static struct GNUNET_ATS_PerformanceHandle *ph;

static struct GNUNET_HELLO_Address addr[2];

static struct GNUNET_ATS_Information atsi[ATS_COUNT];

static int ret;

static int res_suggest_cb_p0;
static int res_suggest_cb_p1;

static int res_perf_cb_p0;
static int res_perf_cb_p1;

/**
 * Stage 0: Init, request address and wait for peer0 suggest cb
 * Stage 1: Got peer0 suggest cb, expect monitoring cb
 * Stage 2: Got peer0 monitoring cb, update address and expect monitor cb
 * Stage 3: Got 2nd peer0 monitoring cb, shutdown
 */

static int stage;


static void cleanup_addresses ()
{
	GNUNET_ATS_address_destroyed (sh, &addr[0], NULL);
	GNUNET_ATS_address_destroyed (sh, &addr[1], NULL);
}

static void setup_addresses ()
{
	memset (&addr[0].peer,'\0', sizeof (addr[0].peer));
	addr[0].transport_name = "test0";
	addr[0].address = "test_addr0";
	addr[0].address_length = strlen ("test_addr0") + 1;
	atsi[0].type = htonl(GNUNET_ATS_NETWORK_TYPE);
	atsi[0].value = htonl(GNUNET_ATS_NET_LAN);

	atsi[1].type = htonl(GNUNET_ATS_QUALITY_NET_DELAY);
	atsi[1].value = htonl(100);

	atsi[2].type = htonl(GNUNET_ATS_QUALITY_NET_DISTANCE);
	atsi[2].value = htonl(5);

	GNUNET_ATS_address_add (sh, &addr[0], NULL, atsi, ATS_COUNT);

	memset (&addr[1].peer,'\1', sizeof (addr[1].peer));
	addr[1].transport_name = "test1";
	addr[1].address = "test_addr1";
	addr[1].address_length = strlen ("test_addr1") + 1;

	GNUNET_ATS_address_add (sh, &addr[1], NULL, atsi, ATS_COUNT);
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
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stop performance monitoring\n");

		stage_task = GNUNET_SCHEDULER_add_delayed (SHUTDOWN_CORRECT, &next_stage, NULL);
		stage_counter++;
		return;
	}
	if (1 == stage_counter)
	{

	}
	else
	{
			end_now (1);
	}
}

static void end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Success\n");
  end_now (0);
}


static void
perf_mon_cb (void *cls,
						const struct GNUNET_PeerIdentity *peer,
						const struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
						const struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
						const struct GNUNET_ATS_Information *ats,
						uint32_t ats_count)
{
	int c1;
	int c2;
	int c3;

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			"ATS notifies about perfomance change for peer `%s'\n", GNUNET_i2s (peer));

	if ((1 != stage) || (2 == stage))
	{
		GNUNET_break (0);
		end_now(1);
		return;
	}

	if (1 == stage)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received 1st callback for peer `%s' with %u information\n",
					GNUNET_i2s (&addr[0].peer), ats_count);
			if ((0 != memcmp (peer, &addr[0].peer, sizeof (addr[0].peer))) ||
					(ats_count < ATS_COUNT))
			{
					GNUNET_break (0);
					if (GNUNET_SCHEDULER_NO_TASK != die_task)
						GNUNET_SCHEDULER_cancel (die_task);
					die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
					return;
			}

			c3 = 0;
			for (c1 = 0; c1 < ats_count; c1++)
			{
				GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS information [%u] %u : %u \n",
						c1, ntohl (ats[c1].type), ntohl (ats[c1].value));
				for (c2 = 0; c2 < ATS_COUNT; c2++)
				{
					if (ats[c1].type == atsi[c2].type)
					{
						if (ats[c1].value == atsi[c2].value)
								c3++;
						else
								GNUNET_break (0);
					}
				}
			}
			if (ATS_COUNT != c3)
			{
				GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received only %u correct ATS information \n", c3);
				if (GNUNET_SCHEDULER_NO_TASK != die_task)
					GNUNET_SCHEDULER_cancel (die_task);
				die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
				return;
			}

			/* Everything OK */
			stage ++;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %u correct ATS information \n", c3);

			atsi[1].type = htonl(GNUNET_ATS_QUALITY_NET_DELAY);
			atsi[1].value = htonl(1000);

			atsi[2].type = htonl(GNUNET_ATS_QUALITY_NET_DISTANCE);
			atsi[2].value = htonl(50);

			GNUNET_ATS_address_update (sh, &addr[0], NULL, atsi, ATS_COUNT);
	}
	if (1 == stage)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received 2nd callback for peer `%s' with %u information\n",
					GNUNET_i2s (&addr[0].peer), ats_count);
	}


#if 0
	static int stage_counter = 0;



	if (0 == stage_counter)
	{

		c3 = 0;


		stage_counter ++;

	}
	else if (1 == stage_counter)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received updated callback for peer `%s' with %u information\n",
					GNUNET_i2s (&addr.peer), ats_count);

			if ((0 != memcmp (peer, &addr.peer, sizeof (addr.peer))) ||
					(ats_count < ATS_COUNT))
			{
					GNUNET_break (0);
					GNUNET_SCHEDULER_add_now (&end_badly, NULL);
					return;
			}
			c3 = 0;
			for (c1 = 0; c1 < ats_count; c1++)
			{
					GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS information [%u] %u : %u \n", c1, ntohl (ats[c1].type), ntohl (ats[c1].value));
					for (c2 = 0; c2 < ATS_COUNT; c2++)
					{
						if (ats[c1].type == atsi[c2].type)
						{
							if (ats[c1].value == atsi[c2].value)
							{
									c3++;
							}
							else
							{
									GNUNET_break (0);
							}
						}
					}
			}

			if (ATS_COUNT != c3)
			{
			  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received only %u correct ATS information \n", c3);
				GNUNET_break (0);
				GNUNET_SCHEDULER_add_now (&end_badly, NULL);
				return;
			}
			stage_counter ++;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %u correct ATS information, shutdown... \n", c3);
			GNUNET_SCHEDULER_add_now (&end, NULL);
			return;
	}
#endif
}

void ats_suggest_cb (void *cls,
										const struct GNUNET_HELLO_Address * address,
										struct Session * session,
										struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
										struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
										const struct GNUNET_ATS_Information *ats,
										uint32_t ats_count)
{
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			"ATS is suggesting address for peer `%s'\n", GNUNET_i2s (&address->peer));

	if (0 != stage)
	{
		GNUNET_break (0);
		end_now(1);
		return;
	}

	if (0 == memcmp (&addr[0].peer, &address->peer, sizeof (address->peer)))
	{
		res_suggest_cb_p0 = GNUNET_YES;
		stage = 1;
	}
	if (0 == memcmp (&addr[1].peer, &address->peer, sizeof (address->peer)))
		res_suggest_cb_p1 = GNUNET_YES;
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *mycfg,
     struct GNUNET_TESTING_Peer *peer)
{
  ret = 1;
  stage = 0;
  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  sh = GNUNET_ATS_scheduling_init (cfg, &ats_suggest_cb, NULL);
  GNUNET_assert (NULL != sh);

  ph = GNUNET_ATS_performance_init (cfg, &perf_mon_cb, &ret, NULL, NULL);
  GNUNET_assert (NULL != ph);

  /* Add addresses */
  setup_addresses ();

  /* Get an active address for peer0 and expect callback */
  GNUNET_ATS_suggest_address (sh, &addr[0].peer);
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
