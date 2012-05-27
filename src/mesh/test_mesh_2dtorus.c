/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_2dtorus.c
 *
 * @brief Test for creating a 2dtorus.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_YES
#define REMOVE_DIR GNUNET_YES

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * How many events have happened
 */
static int ok;

/**
 * Be verbose
 */
static int verbose;

/**
 * Total number of peers in the test.
 */
static unsigned long long num_peers;

/**
 * Global configuration file
 */
static struct GNUNET_CONFIGURATION_Handle *testing_cfg;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Total number of successful connections in the whole network.
 */
static unsigned int total_connections;

/**
 * Total number of counted topo connections
 */
static unsigned int topo_connections;

/**
 * Total number of failed connections in the whole network.
 */
static unsigned int failed_connections;

/**
 * The currently running peer group.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * Task called to disconnect peers
 */
static GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

/**
 * Task called to shutdown test.
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_handle;


/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "test: Shutdown of peers failed! (%s)\n", emsg);
    ok--;
  }
#if VERBOSE
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: All peers successfully shut down!\n");
  }
#endif
  GNUNET_CONFIGURATION_destroy (testing_cfg);
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Ending test.\n");
#endif

  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


static void
disconnect_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: disconnecting peers\n");

  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
    shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
  }
}


/**
 * Prototype of a callback function indicating that two peers
 * are currently connected.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param emsg error message (NULL on success)
 */
void
topo_cb (void *cls, const struct GNUNET_PeerIdentity *first,
         const struct GNUNET_PeerIdentity *second, const char *emsg)
{
  topo_connections++;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: Error by topo %u: %s\n",
                topo_connections, emsg);
  }
  else
  {
    if (first == NULL || second == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Connection %u NULL\n",
                  topo_connections);
      if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
      {
        GNUNET_SCHEDULER_cancel (disconnect_task);
        disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
      }
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Connection %u ok\n",
                topo_connections);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   %s\n", GNUNET_i2s (first));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   %s\n", GNUNET_i2s (second));
  }
}


/**
 * peergroup_ready: start test when all peers are connected
 * @param cls closure
 * @param emsg error message
 */
static void
peergroup_ready (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Error from testing: `%s'\n",
                emsg);
    ok--;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "************************************************************\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: Peer Group started successfully!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Have %u connections\n",
              total_connections);
#endif

  peers_running = GNUNET_TESTING_daemons_running (pg);
  if (0 < failed_connections)
  {
    ok = GNUNET_SYSERR;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "test: %u connections have FAILED!\n",
                failed_connections);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);

  }
  else
  {
    GNUNET_TESTING_get_topology (pg, &topo_cb, NULL);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_peers, NULL);
    ok = GNUNET_OK;
  }

}


/**
 * Function that will be called whenever two daemons are connected by
 * the testing library.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *first,
            const struct GNUNET_PeerIdentity *second, uint32_t distance,
            const struct GNUNET_CONFIGURATION_Handle *first_cfg,
            const struct GNUNET_CONFIGURATION_Handle *second_cfg,
            struct GNUNET_TESTING_Daemon *first_daemon,
            struct GNUNET_TESTING_Daemon *second_daemon, const char *emsg)
{
  if (emsg == NULL)
  {
    total_connections++;
  }
  else
  {
    failed_connections++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: Problem with new connection (%s)\n", emsg);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   (%s)\n", GNUNET_i2s (first));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   (%s)\n", GNUNET_i2s (second));
  }

}


/**
 * run: load configuration options and schedule test to run (start peergroup)
 * @param cls closure
 * @param args argv
 * @param cfgfile configuration file name (can be NULL)
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_Host *hosts;

  ok = GNUNET_NO;
  total_connections = 0;
  failed_connections = 0;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);

  GNUNET_log_setup ("test_mesh_2dtorus",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Starting daemons.\n");
  GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing",
                                         "use_progressbars", "YES");
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "testing",
                                             "num_peers", &num_peers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option TESTING:NUM_PEERS is required!\n");
    return;
  }

  hosts = GNUNET_TESTING_hosts_load (testing_cfg);

  pg = GNUNET_TESTING_peergroup_start (testing_cfg, num_peers, TIMEOUT,
                                       &connect_cb, &peergroup_ready, NULL,
                                       hosts);
  GNUNET_assert (pg != NULL);
  shutdown_handle =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
}


/**
 * test_mesh_2dtorus command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  char *const argv2[] = {
    argv[0],
    "-c",
    "test_mesh_2dtorus.conf",
#if VERBOSE
    "-L",
    "DEBUG",
#endif
    NULL
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Start\n");


  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_mesh_2dtorus", gettext_noop ("Test mesh 2d torus."),
                      options, &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/test_mesh_2dtorus");
#endif
  if (GNUNET_OK != ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: FAILED!\n");
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: success\n");
  return 0;
}

/* end of test_mesh_2dtorus.c */
