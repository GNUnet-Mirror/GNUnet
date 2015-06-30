/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_blacklisting.c
 * @brief test for the blacklisting with blacklistings defined in cfg
 *
 * this file contains multiple tests:
 *
 * test_transport_blacklisting_no_bl:
 *      no blacklisting entries
 *      peers are expected to connect
 * test_transport_blacklisting_outbound_bl_full:
 *      both peers contain bl entries for full peer
 *      test is expected to not connect
 * test_transport_blacklisting_outbound_bl_plugin:
 *      both peers contain bl entries for plugin
 *      test is expected to not connect
 * test_transport_blacklisting_inbound_bl_plugin:
 *      peer 1 contains no bl entries
 *      peer 2 contain bl entries for full peer
 *      test is expected to not connect
 * test_transport_blacklisting_inbound_bl_full:
 *      peer 1 contains no bl entries
 *      peer 2 contain bl entries for plugin
 *      test is expected to not connect
 * test_transport_blacklisting_multiple_plugins:
 *      both peers contain bl entries for plugin
 *      test is expected to  connect with not bl'ed plugin
 *
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

char *test_name;

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

static struct GNUNET_SCHEDULER_Task * die_task;

static struct GNUNET_SCHEDULER_Task * timeout_task;

static struct GNUNET_SCHEDULER_Task * stage_task;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

static void
run_stage(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
end(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Stopping\n");

  if (die_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  if (timeout_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }

  if (stage_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (stage_task);
    stage_task = NULL;
  }

  if (cc != NULL )
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (p1 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (p2 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }
}

static void
end_badly(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;

  if (timeout_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }

  if (stage_task != NULL )
  {
    GNUNET_SCHEDULER_cancel (stage_task);
    stage_task = NULL;
  }

  if (cc != NULL )
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }
  if (p1 != NULL )
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  if (p2 != NULL )
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

  ok = GNUNET_SYSERR;
}

static void
testing_connect_cb(struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Peers connected: %u (%s) <-> %u (%s)\n",
      p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free(p1_c);
  connected = GNUNET_YES;
  stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL );
}

static void
connect_timeout(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Peers not connected, next stage\n");
  timeout_task = NULL;
  stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL );
}

static int started;

void
start_cb(struct PeerContext *p, void *cls)
{

  started++;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Peer %u (`%s') started\n", p->no,
      GNUNET_i2s_full (&p->id));

  if (started != 2)
    return;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n", p1->no,
      sender_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free(sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
      NULL );

}

static int check_blacklist_config (char *cfg_file,
    struct GNUNET_PeerIdentity *peer, struct GNUNET_PeerIdentity *bl_peer)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *section;
  char *peer_str;
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, cfg_file))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not load configuration `%s'\n", cfg_file);
    GNUNET_CONFIGURATION_destroy (cfg);
    return GNUNET_SYSERR;
  }

  peer_str = GNUNET_strdup (GNUNET_i2s_full(peer));
  GNUNET_asprintf (&section, "transport-blacklist-%s", peer_str);

  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (cfg, section, GNUNET_i2s_full(bl_peer)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Configuration `%s' does not have blacklisting section for peer `%s' blacklisting `%s'\n",
        cfg_file, peer_str, GNUNET_i2s_full(bl_peer));
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free (section);
    GNUNET_free (peer_str);
    return GNUNET_SYSERR;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Configuration `%s' does have blacklisting section for peer `%s' blacklisting `%s'\n",
      cfg_file, peer_str, GNUNET_i2s_full(bl_peer));

  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free (section);
  GNUNET_free (peer_str);
  return GNUNET_OK;
}

static void
run_stage(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stage_task = NULL;
  if (NULL != die_task)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL );
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Running stage %u\n", stage);

  if (0 == stage)
  {
    started = GNUNET_NO;
    connected = GNUNET_NO;
    if (0 == strcmp (test_name, "test_transport_blacklisting_no_bl"))
    {
      /* Try to connect peers successfully */
      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          "test_transport_blacklisting_cfg_peer1.conf", 1, NULL, NULL, NULL,
          &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          "test_transport_blacklisting_cfg_peer2.conf", 2, NULL, NULL, NULL,
          &start_cb, NULL );
    }
    else if (0
        == strcmp (test_name, "test_transport_blacklisting_outbound_bl_full"))
    {
      char * cfg_p1 = "test_transport_blacklisting_cfg_blp_peer1_full.conf";
      char * cfg_p2 = "test_transport_blacklisting_cfg_blp_peer2_full.conf";
      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p1 , 1, NULL, NULL, NULL, &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p2, 2, NULL, NULL, NULL,
          &start_cb, NULL );

      /* check if configuration contain correct blacklist entries */
      if ((GNUNET_SYSERR == check_blacklist_config (cfg_p1, &p1->id, &p2->id)) ||
          (GNUNET_SYSERR == check_blacklist_config (cfg_p2, &p2->id, &p1->id)) )
      {
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p1);
        p1 = NULL;
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p2);
        p2 = NULL;
        ok = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL );
      }

    }
    else if (0
        == strcmp (test_name, "test_transport_blacklisting_outbound_bl_plugin"))
    {
      char * cfg_p1 = "test_transport_blacklisting_cfg_blp_peer1_plugin.conf";
      char * cfg_p2 = "test_transport_blacklisting_cfg_blp_peer2_plugin.conf";

      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p1, 1, NULL,
          NULL, NULL, &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p2, 2, NULL, NULL, NULL,
          &start_cb, NULL );

      /* check if configuration contain correct blacklist entries */
      if ((GNUNET_SYSERR == check_blacklist_config (cfg_p1, &p1->id, &p2->id)) ||
          (GNUNET_SYSERR == check_blacklist_config (cfg_p2, &p2->id, &p1->id)) )
      {
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p1);
        p1 = NULL;
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p2);
        p2 = NULL;
        ok = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL );
      }
    }
    else if (0
        == strcmp (test_name, "test_transport_blacklisting_inbound_bl_full"))
    {
      char * cfg_p1 = "test_transport_blacklisting_cfg_peer1.conf";
      char * cfg_p2 = "test_transport_blacklisting_cfg_blp_peer2_full.conf";

      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p1, 1, NULL, NULL, NULL,
          &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p2, 2, NULL, NULL,
          NULL, &start_cb, NULL );

      /* check if configuration contain correct blacklist entries */
      if ((GNUNET_SYSERR == check_blacklist_config (cfg_p2, &p2->id, &p1->id)) )
      {
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p1);
        p1 = NULL;
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p2);
        p2 = NULL;
        ok = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL );
      }
    }
    else if (0
        == strcmp (test_name, "test_transport_blacklisting_inbound_bl_plugin"))
    {
      char * cfg_p1 = "test_transport_blacklisting_cfg_peer1.conf";
      char * cfg_p2 = "test_transport_blacklisting_cfg_blp_peer2_plugin.conf";

      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p1, 1, NULL, NULL, NULL,
          &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p2, 2, NULL, NULL,
          NULL, &start_cb, NULL );

      /* check if configuration contain correct blacklist entries */
      if ((GNUNET_SYSERR == check_blacklist_config (cfg_p2, &p2->id, &p1->id)) )
      {
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p1);
        p1 = NULL;
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p2);
        p2 = NULL;
        ok = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL );
      }

    }
    else if (0
        == strcmp (test_name, "test_transport_blacklisting_multiple_plugins"))
    {
      char * cfg_p1 = "test_transport_blacklisting_cfg_blp_peer1_multiple_plugins.conf";
      char * cfg_p2 = "test_transport_blacklisting_cfg_blp_peer2_multiple_plugins.conf";

      p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p1, 1,
          NULL, NULL, NULL, &start_cb, NULL );

      p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
          cfg_p2, 2,
          NULL, NULL, NULL, &start_cb, NULL );

      /* check if configuration contain correct blacklist entries */
      if ((GNUNET_SYSERR == check_blacklist_config (cfg_p1, &p1->id, &p2->id)) ||
          (GNUNET_SYSERR == check_blacklist_config (cfg_p2, &p2->id, &p1->id)))
      {
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p1);
        p1 = NULL;
        GNUNET_TRANSPORT_TESTING_stop_peer(tth, p2);
        p2 = NULL;
        ok = 1;
        GNUNET_SCHEDULER_add_now (&end, NULL );
      }
    }
    else
    {
      GNUNET_break (0);
      GNUNET_SCHEDULER_add_now (&end, NULL );
    }

    if ((NULL == p1) || (NULL == p2))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to start peers\n");
      ok = 1;
      GNUNET_SCHEDULER_add_now (&end, NULL );
    }

    timeout_task = GNUNET_SCHEDULER_add_delayed (CONNECT_TIMEOUT,
        &connect_timeout, NULL );
    stage++;
    return;
  }

  if (cc != NULL )
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (p1 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (p2 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Done in stage %u: Peers %s and %s!\n",
      stage, (GNUNET_NO == started) ? "NOT STARTED" : "STARTED",
      (GNUNET_YES == connected) ? "CONNECTED" : "NOT CONNECTED");

  if ((0 == strcmp (test_name, "test_transport_blacklisting_no_bl"))
      || (0 == strcmp (test_name, "test_transport_blacklisting_multiple_plugins")))
  {
    if ((GNUNET_NO != started) && (GNUNET_YES == connected))
      ok = 0;
    else
    {
      GNUNET_break(0);
      ok = 1;
    }
  }
  else
  {
    if ((GNUNET_NO != started) && (GNUNET_YES != connected))
      ok = 0;
    else
    {
      ok = 1;
    }
  }
  GNUNET_SCHEDULER_add_now (&end, NULL );
}

static void
run(void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  connected = GNUNET_NO;
  stage = 0;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Running test `%s'!\n", test_name);
  stage_task = GNUNET_SCHEDULER_add_now (&run_stage, NULL );
}

int
main(int argc, char *argv0[])
{
  ok = 1;

  GNUNET_TRANSPORT_TESTING_get_test_name (argv0[0], &test_name);

  GNUNET_log_setup ("test-transport-api-blacklisting", "WARNING", NULL );

  static char * const argv[] =
  { "date", "-c", "test_transport_api_data.conf", NULL };
  static struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_OPTION_END };

  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_PROGRAM_run ((sizeof(argv) / sizeof(char *)) - 1, argv,
      "test-transport-api-blacklisting", "nohelp", options, &run, NULL );

  GNUNET_TRANSPORT_TESTING_done (tth);

  return ok;
}

/* end of transport_api_blacklisting.c */
