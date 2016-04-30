/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file transport/test_transport_api_timeout.c
 * @brief test case for transport plugin implementations complying timeout
 * settings
 *
 *
 * This test case serves ensures that no peer disconnect events occurs
 * while plugins are idle
 */

#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)

#define MTYPE 12345

static char *test_source;

static char *test_plugin;

static char *test_name;

static int ok;

static struct GNUNET_SCHEDULER_Task * die_task;

static struct GNUNET_SCHEDULER_Task * timer_task;

static struct GNUNET_TRANSPORT_TESTING_handle *tth;

static struct PeerContext *p1;

static struct PeerContext *p2;

static struct GNUNET_TRANSPORT_TESTING_ConnectRequest * cc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static char *cfg_file_p1;

static char *cfg_file_p2;

static struct GNUNET_TIME_Relative time_running;

static int shutdown_flag;

static int disconnects;


#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (timer_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (timer_task);
    timer_task = NULL;
  }

  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;


  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

  if (disconnects == 0)
    ok = 0;
  else
  {
    ok = disconnects;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Fail! Had %u disconnects while waiting %s\n",
                disconnects,
		GNUNET_STRINGS_relative_time_to_string (WAIT,
							GNUNET_YES));
  }

  GNUNET_TRANSPORT_TESTING_done (tth);
}


static void
end_badly (void *cls)
{
  die_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (timer_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (timer_task);
    timer_task = NULL;
  }
  if (cc != NULL)
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;
  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
  ok = GNUNET_SYSERR;

  GNUNET_TRANSPORT_TESTING_done (tth);
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %d from peer %s!\n",
              ntohs (message->type), GNUNET_i2s (peer));
}

static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' connected to us (%p)!\n",
              GNUNET_i2s (peer), cls);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (shutdown_flag != GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "FAIL! Peer `%4s' disconnected during waiting period!\n",
                GNUNET_i2s (peer));
    disconnects++;
  }
  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;
}


static void
timer (void *cls)
{
  static int percentage;

  timer_task = NULL;
  percentage += 10;
  time_running =
      GNUNET_TIME_relative_add (time_running,
                                GNUNET_TIME_relative_divide (WAIT, 10));

  if (time_running.rel_value_us ==
      GNUNET_TIME_relative_max (time_running, WAIT).rel_value_us)
  {
    FPRINTF (stderr, "%s",  "100%%\n");
    shutdown_flag = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
  else
  {
    FPRINTF (stderr, "%u%%..", percentage);
    timer_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (WAIT, 10),
                                      &timer, NULL);
  }
}


static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peers connected: %s <-> %s\n", p1_c,
              GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  shutdown_flag = GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Waiting for %s\n",
	      GNUNET_STRINGS_relative_time_to_string (WAIT,
						      GNUNET_YES));

  if (die_task != NULL)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (WAIT, &end_badly, NULL);

  timer_task = GNUNET_SCHEDULER_add_now (&timer, NULL);
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;

  started++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
              p1->no, sender_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p1, 1,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);
  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);

  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != NULL)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}

static int
check ()
{
  static char *const argv[] = { "test-transport-api-timeout",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  timer_task = NULL;

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-transport-api-timeout", "nohelp", options, &run,
                      &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0], &test_name);

  GNUNET_log_setup (test_name,
                    "WARNING",
                    NULL);

  GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__, &test_source);
  GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0], test_source,
                                                 &test_plugin);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p1, 1);
  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p2, 2);

  ret = check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);

  GNUNET_free (test_source);
  GNUNET_free (test_plugin);
  GNUNET_free (test_name);


  return ret;
}

/* end of test_transport_api_timeout.c*/
