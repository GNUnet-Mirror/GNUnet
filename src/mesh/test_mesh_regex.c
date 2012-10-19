/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_regex.c
 *
 * @brief Test for regex announce / by_string connect.
 * based on the 2dtorus testcase
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_mesh_service.h"

#define VERBOSE GNUNET_YES
#define REMOVE_DIR GNUNET_YES
#define MESH_REGEX_PEERS 4

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Which strings have been found & connected.
 */
static int ok[MESH_REGEX_PEERS];

/**
 * How many connects have happened.
 */
static int regex_peers;

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
 * Mesh handle for connecting peer.
 */
static struct GNUNET_MESH_Handle *h1;

/**
 * Mesh handle for announcing peers.
 */
static struct GNUNET_MESH_Handle *h2[MESH_REGEX_PEERS];

/**
 * Tunnel handles for announcing peer.
 */
static struct GNUNET_MESH_Tunnel *t[MESH_REGEX_PEERS];

/**
 * Incoming tunnels for announcing peers.
 */
static struct GNUNET_MESH_Tunnel *incoming_t[MESH_REGEX_PEERS];

/**
 * Regular expressions for the announces.
 */
static char *regexes[MESH_REGEX_PEERS] = {"(0|1)"
                                          "(0|1)"
                                          "23456789ABC",

                                          "0123456789A*BC",

                                          "0*123456789ABC*",

                                          "GNUNETVPN0001000IPEX401110011101100100000111(0|1)*"};


/**
 * Service strings to look for.
 */
static char *strings[MESH_REGEX_PEERS] = {"1123456789ABC",

                                          "0123456789AABC",

                                          "00123456789ABCCCC",

                                          "GNUNETVPN0001000IPEX401110011101100100000111"};

/**
 * Check whether peers successfully shut down.
 *
 * @param cls Closure (unused).
 * @param emsg Error message, NULL on success.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  unsigned int i;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "test: Shutdown of peers failed! (%s)\n", emsg);
    for (i = 0; i < MESH_REGEX_PEERS; i++)
      ok[i] = GNUNET_NO;
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


/**
 * Task to run for shutdown: stops peers, ends test.
 *
 * @param cls Closure (not used).
 * @param tc TaskContext.
 *
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Ending test.\n");
#endif
  shutdown_handle = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


/**
 * Ends test: Disconnects peers and calls shutdown.
 * @param cls Closure (not used).
 * @param tc TaskContext.
 */
static void
disconnect_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: disconnecting peers\n");

  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    GNUNET_MESH_tunnel_destroy (t[i]);
    GNUNET_MESH_disconnect (h2[i]);
  }
  GNUNET_MESH_disconnect (h1);
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
  }
  shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}

/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
tunnel_cleaner (void *cls, const struct GNUNET_MESH_Tunnel *tunnel,
                void *tunnel_ctx)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Incoming tunnel disconnected at peer %d\n",
              i);
  return;
}


/**
 * Method called whenever a tunnel falls apart.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
dh (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "peer %s disconnected\n",
              GNUNET_i2s (peer));
  return;
}

/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
data_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *m = buf;

  if (NULL == buf || size < sizeof(struct GNUNET_MessageHeader))
    return 0;
  m->type = htons (1);
  m->size = htons (sizeof(struct GNUNET_MessageHeader));
  return sizeof(struct GNUNET_MessageHeader);
}

/**
 * Method called whenever a peer connects to a tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
static void
ch (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_ATS_Information *atsi)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer connected: %s\n",
              GNUNET_i2s (peer));
  regex_peers++;

  GNUNET_MESH_notify_transmit_ready(t[i], GNUNET_NO,
                                    GNUNET_TIME_UNIT_FOREVER_REL,
                                    peer,
                                    sizeof(struct GNUNET_MessageHeader),
                                    &data_ready, NULL);
}

/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void *
incoming_tunnel (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
                 const struct GNUNET_PeerIdentity *initiator,
                 const struct GNUNET_ATS_Information *atsi)
{
  long i = (long) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming tunnel from %s to peer %d\n",
              GNUNET_i2s (initiator), (long) cls);
  if (i > 1L && i <= 1L + MESH_REGEX_PEERS)
  {
    incoming_t[i - 2] = tunnel;
    ok[i - 2] = GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming tunnel for unknown client %lu\n", (long) cls);
  }
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_peers, NULL);
  }
  return NULL;
}

/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
data_callback (void *cls, struct GNUNET_MESH_Tunnel *tunnel, void **tunnel_ctx,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *message,
               const struct GNUNET_ATS_Information *atsi)
{
  int i;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "test: GOT DATA!\n");
  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    if (GNUNET_OK != ok[i]) {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: %u DATA MISSING!\n", i);
      return GNUNET_OK;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "test: EVERYONE GOT DATA, FINISHING!\n");
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
  }
  return GNUNET_OK;
}

/**
 * Handlers, for diverse services
 */
static struct GNUNET_MESH_MessageHandler handlers[] = {
  {&data_callback, 1, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};


/**
 * peergroup_ready: start test when all peers are connected
 * @param cls closure
 * @param emsg error message
 */
static void
peergroup_ready (void *cls, const char *emsg)
{
  GNUNET_MESH_ApplicationType app;
  struct GNUNET_TESTING_Daemon *d;
  unsigned int i;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "test: Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: Error from testing: `%s'\n",
                emsg);
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "test: Peer Group started successfully!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test: Have %u connections\n",
              total_connections);
#endif

  peers_running = GNUNET_TESTING_daemons_running (pg);
  if (0 < failed_connections)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "test: %u connections have FAILED!\n",
                failed_connections);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
    return;
  }
  disconnect_task =
    GNUNET_SCHEDULER_add_delayed (TIMEOUT, &disconnect_peers, NULL);
  d = GNUNET_TESTING_daemon_get (pg, 1);

  app = (GNUNET_MESH_ApplicationType) 0;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Connect to mesh\n");
  h1 = GNUNET_MESH_connect (d->cfg, (void *) 1L,
                            NULL,
                            NULL,
                            handlers,
                            &app);
  regex_peers = 0;
  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    ok[i] = GNUNET_NO;
    d = GNUNET_TESTING_daemon_get (pg, 10 + i);
    h2[i] = GNUNET_MESH_connect (d->cfg, (void *) (long) (i + 2),
                                 &incoming_tunnel,
                                 &tunnel_cleaner,
                                 handlers,
                                 &app);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Announce REGEX %u: %s\n", i, regexes[i]);
    GNUNET_MESH_announce_regex (h2[i], regexes[i]);
  }

  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Create tunnel\n");
    t[i] = GNUNET_MESH_tunnel_create (h1, NULL, &ch, &dh, (void *) (long) i);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Connect by string %s\n", strings[i]);
    GNUNET_MESH_peer_request_connect_by_string (t[i], strings[i]);
  }
  /* connect handler = success, timeout = error */

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

  total_connections = 0;
  failed_connections = 0;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);

  GNUNET_log_setup ("test_mesh_regex",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Starting daemons.\n");
  GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing_old",
                                         "use_progressbars", "YES");
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "testing_old",
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
 * test_mesh_regex command line options
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
  int result;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Start\n");


  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_mesh_regex",
                      gettext_noop ("Test mesh regex integration."),
                      options, &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/test_mesh_2dtorus");
#endif
  result = GNUNET_OK;
  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    if (GNUNET_OK != ok[i])
    {
      result = GNUNET_SYSERR;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "COULD NOT CONNECT TO %u: %s!\n",
                  i, strings[i]);
    }
  }
  if (GNUNET_OK != result || regex_peers != MESH_REGEX_PEERS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "test: FAILED! %u connected peers\n",
                regex_peers);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test: success\n");
  return 0;
}

/* end of test_mesh_regex.c */
