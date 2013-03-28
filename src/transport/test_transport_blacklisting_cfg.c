/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_blacklisting.c
 * @brief test for the blacklisting API
 * 		stage 0: init
 * 		stage 1: connect peers and stop
 * 		stage 2: blacklist whole peer and connect
 * 		stage 3: blacklist tcp and try connect
 *
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

struct PeerContext *p1;

struct PeerContext *p2;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

struct GNUNET_TRANSPORT_TESTING_handle *tth;

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

#define CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static int stage;
static int ok;
static int connected;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier timeout_task;

static GNUNET_SCHEDULER_TaskIdentifier stage_task;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

static void
run_stage (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping\n");

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (stage_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stage_task);
    stage_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (cc != NULL)
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel(tth, cc);
    cc = NULL;
  }

  if (p1 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (p2 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (stage_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (stage_task);
    stage_task = GNUNET_SCHEDULER_NO_TASK;
  }


  if (cc != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Fail! Could not connect peers\n"));
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

  ok = GNUNET_SYSERR;
}

static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %u (%s) <-> %u (%s)\n",
              p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  if (1 == stage)
  {
    stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL);
  }
  else
  {
  	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers connected, but they were blacklisted\n");
  		stage_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
  }

}

static void
connect_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers not connected, next stage\n");
	timeout_task = GNUNET_SCHEDULER_NO_TASK;
  stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL);
}

static int started;

void
start_cb (struct PeerContext *p, void *cls)
{

  started++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
              p1->no, sender_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}

static void
run_stage (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	stage_task = GNUNET_SCHEDULER_NO_TASK;
	if (GNUNET_SCHEDULER_NO_TASK != die_task)
		GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Running stage %u\n", stage);
	if (0 == stage)
	{
			/* Try to connect peers successfully */
			started = 0;
			p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_peer1.conf", 1,
		                                            NULL, NULL, NULL, &start_cb, NULL);

		  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_peer2.conf", 2,
		  																					NULL, NULL, NULL, &start_cb, NULL);
		  stage ++;
		  return;
	}

	if (1 == stage)
	{
			/* Try to connect peers successfully with 2nd peer fully blacklisted*/
		  if (p1 != NULL)
		  {
		    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
		    p1 = NULL;
		  }
		  if (p2 != NULL)
		  {
		    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
		    p2 = NULL;
		  }
		  started = 0;
		  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_peer1.conf", 1,
																								NULL, NULL, NULL, &start_cb, NULL);

		  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_blp_peer2.conf", 2,
																								NULL, NULL, NULL, &start_cb, NULL);

		  timeout_task = GNUNET_SCHEDULER_add_delayed (CONNECT_TIMEOUT, &connect_timeout, NULL);
		  stage ++;
		  return;
	}
	if (2 == stage)
	{
			/* Try to connect peers successfully with 1st peer blacklisted on tcp */
		  if (p1 != NULL)
		  {
		    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
		    p1 = NULL;
		  }
		  if (p2 != NULL)
		  {
		    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
		    p2 = NULL;
		  }
		  started = 0;
		  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_blp_peer1.conf", 1,
																								NULL, NULL, NULL, &start_cb, NULL);

		  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_blacklisting_cfg_peer2.conf", 2,
																								NULL, NULL, NULL, &start_cb, NULL);

		  timeout_task = GNUNET_SCHEDULER_add_delayed (CONNECT_TIMEOUT, &connect_timeout, NULL);
		  stage ++;
		  return;
	}
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Done!\n", stage);


	ok = 0;
	GNUNET_SCHEDULER_add_now (&end, NULL);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  connected = GNUNET_NO;
  stage = 0;
  stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL);
}


static int
check ()
{
  static char *const argv[] = { "test-transport-api-blacklisting",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-transport-api-blacklisting",
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-api-blacklisting",
                    "WARNING",
                    NULL);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  ret = check ();

  GNUNET_TRANSPORT_TESTING_done (tth);

  return ret;
}

/* end of transport_api_blacklisting.c */
