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
 * @file mesh/test_mesh_small.c
 *
 * @brief Test for the mesh service: retransmission of traffic.
 */
#include <stdio.h>
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_mesh_service.h"
#include <gauger.h>


#define VERBOSE GNUNET_YES
#define REMOVE_DIR GNUNET_YES

struct MeshPeer
{
  struct MeshPeer *prev;

  struct MeshPeer *next;

  struct GNUNET_TESTING_Daemon *daemon;

  struct GNUNET_MESH_Handle *mesh_handle;
};


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * DIFFERENT TESTS TO RUN
 */
#define SETUP 0
#define UNICAST 1
#define MULTICAST 2
#define SPEED 3
#define SPEED_ACK 4

/**
 * Which test are we running?
 */
static int test;

/**
 * How many events have happened
 */
static int ok;

static int peers_in_tunnel;

static int peers_responded;

static int data_sent;

static int data_received;

static int data_ack;

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
 * Total number of connections in the whole network.
 */
static unsigned int total_connections;

/**
 * The currently running peer group.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * File to report results to.
 */
static struct GNUNET_DISK_FileHandle *output_file;

/**
 * File to log connection info, statistics to.
 */
static struct GNUNET_DISK_FileHandle *data_file;

/**
 * How many data points to capture before triggering next round?
 */
static struct GNUNET_TIME_Relative wait_time;

/**
 * Task called to disconnect peers.
 */
static GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

/**
 * Task To perform tests
 */
static GNUNET_SCHEDULER_TaskIdentifier test_task;

/**
 * Task called to shutdown test.
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_handle;

static char *topology_file;

static struct GNUNET_TESTING_Daemon *d1;

static GNUNET_PEER_Id pid1;

static struct GNUNET_TESTING_Daemon *d2;

static struct GNUNET_TESTING_Daemon *d3;

static struct GNUNET_MESH_Handle *h1;

static struct GNUNET_MESH_Handle *h2;

static struct GNUNET_MESH_Handle *h3;

static struct GNUNET_MESH_Tunnel *t;

static struct GNUNET_MESH_Tunnel *incoming_t;

static struct GNUNET_MESH_Tunnel *incoming_t2;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_TIME_Absolute end_time;

static struct GNUNET_TIME_Relative total_time;


/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shutdown of peers failed!\n");
#endif
    ok--;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All peers successfully shut down!\n");
#endif
  }
  GNUNET_CONFIGURATION_destroy (testing_cfg);
}


/**
 * Shut down peergroup, clean up.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ending test.\n");
#endif

  if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != h1)
  {
    GNUNET_MESH_disconnect (h1);
    h1 = NULL;
  }
  if (NULL != h2)
  {
    GNUNET_MESH_disconnect (h2);
    h2 = NULL;
  }
  if (test == MULTICAST && NULL != h3)
  {
    GNUNET_MESH_disconnect (h3);
    h3 = NULL;
  }
  
  if (data_file != NULL)
    GNUNET_DISK_file_close (data_file);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


/**
 * Disconnect from mesh services af all peers, call shutdown.
 */
static void
disconnect_mesh_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting mesh service of peers\n");
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != t)
  {
    GNUNET_MESH_tunnel_destroy(t);
    t = NULL;
  }
  if (NULL != incoming_t)
  {
    GNUNET_MESH_tunnel_destroy(incoming_t);
    incoming_t = NULL;
  }
  if (NULL != incoming_t2)
  {
    GNUNET_MESH_tunnel_destroy(incoming_t2);
    incoming_t2 = NULL;
  }
  GNUNET_MESH_disconnect (h1);
  GNUNET_MESH_disconnect (h2);
  h1 = h2 = NULL;
  if (test == MULTICAST)
  {
    GNUNET_MESH_disconnect (h3);
    h3 = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
    shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
  }
}

size_t
tmt_rdy (void *cls, size_t size, void *buf);

static void
data_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_TransmitHandle *th;
  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;
  th = GNUNET_MESH_notify_transmit_ready (t, GNUNET_NO, 0,
                                    GNUNET_TIME_UNIT_FOREVER_REL, &d2->id,
                                    sizeof (struct GNUNET_MessageHeader),
                                    &tmt_rdy, (void *) 1L);
  if (NULL == th)
  {
    unsigned long i = (unsigned long) cls;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Retransmission\n");
    if (0 == i)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "  in 1 ms\n");
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                    &data_task, (void *)1UL);
    }
    else
    {
      i++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "in %u ms\n", i);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(
                                      GNUNET_TIME_UNIT_MILLISECONDS,
                                      i),
                                    &data_task, (void *)i);
    }
  }
}

/**
 * Transmit ready callback
 *
 * @param cls Closure.
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
size_t
tmt_rdy (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " tmt_rdy called\n");
  if (size < sizeof (struct GNUNET_MessageHeader) || NULL == buf)
    return 0;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  msg->type = htons ((long) cls);
  if (test == SPEED)
  {
    data_sent++;
    if (data_sent < 1000)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Scheduling %d packet\n", data_sent);
      GNUNET_SCHEDULER_add_now(&data_task, NULL);
    }
  }
  return sizeof (struct GNUNET_MessageHeader);
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
  long client = (long) cls;

  switch (client)
  {
  case 1L:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Origin client got a response!\n");
    ok++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
    peers_responded++;
    data_ack++;
    if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    {
      GNUNET_SCHEDULER_cancel (disconnect_task);
      disconnect_task =
          GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                        NULL);
    }
    if (test == MULTICAST && peers_responded < 2)
      return GNUNET_OK;
    if (test == SPEED_ACK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              " received ack %u\n", data_ack);
      GNUNET_MESH_notify_transmit_ready (tunnel, GNUNET_NO, 0,
                                        GNUNET_TIME_UNIT_FOREVER_REL, sender,
                                        sizeof (struct GNUNET_MessageHeader),
                                        &tmt_rdy, (void *) 1L);
      if (data_ack < 1000)
        return GNUNET_OK;
      end_time = GNUNET_TIME_absolute_get();
      total_time = GNUNET_TIME_absolute_get_difference(start_time, end_time);
      FPRINTF (stderr, "\nTest time %llu ms\n",
               (unsigned long long) total_time.rel_value);
      FPRINTF (stderr, "Test bandwidth: %f kb/s\n",
               4000.0 / total_time.rel_value);
      FPRINTF (stderr, "Test throughput: %f packets/s\n",
               1000000.0 / total_time.rel_value);
      GAUGER ("MESH", "Tunnel 5 peers", 1000000.0 / total_time.rel_value,
              "packets/s");
    }
    GNUNET_assert (tunnel == t);
    GNUNET_MESH_tunnel_destroy (t);
    t = NULL;
    break;
  case 2L:
  case 3L:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Destination client %u got a message.\n",
                client);
    ok++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
    if (SPEED != test)
    {
      GNUNET_MESH_notify_transmit_ready (tunnel, GNUNET_NO, 0,
                                        GNUNET_TIME_UNIT_FOREVER_REL, sender,
                                        sizeof (struct GNUNET_MessageHeader),
                                        &tmt_rdy, (void *) 1L);
    }
    else
    {
      data_received++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              " received data %u\n", data_received);
      if (data_received < 1000)
        return GNUNET_OK;
    }
    if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    {
      GNUNET_SCHEDULER_cancel (disconnect_task);
      disconnect_task =
          GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                        NULL);
    }
    break;
  default:
    break;
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming tunnel from %s to peer %d\n",
              GNUNET_i2s (initiator), (long) cls);
  ok++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  if ((long) cls == 2L)
    incoming_t = tunnel;
  else if ((long) cls == 3L)
    incoming_t2 = tunnel;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming tunnel for unknown client %lu\n", (long) cls);
  }
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers, NULL);
  }
  return NULL;
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming tunnel disconnected at peer %d\n",
              i);
  if (2L == i)
  {
    ok++;
    incoming_t = NULL;
  }
  else if (3L == i)
  {
    ok++;
    incoming_t2 = NULL;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unknown peer! %d\n", i);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  peers_in_tunnel--;
  if (peers_in_tunnel > 0)
    return;

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers, NULL);
  }

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
  struct GNUNET_PeerIdentity *dest;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "peer %s connected\n", GNUNET_i2s (peer));

  if (0 == memcmp (&d2->id, peer, sizeof (d2->id)) && (long) cls == 1L)
  {
    ok++;
  }
  if (test == MULTICAST && 0 == memcmp (&d3->id, peer, sizeof (d3->id)) &&
      (long) cls == 1L)
  {
    ok++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  switch (test)
  {
  case UNICAST:
  case SPEED:
  case SPEED_ACK:
    dest = &d2->id;
    break;
  case MULTICAST:
    peers_in_tunnel++;
    if (peers_in_tunnel < 2)
      return;
    dest = NULL;
    break;
  default:
    return;
  }
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending data...\n");
    peers_responded = 0;
    data_ack = 0;
    data_received = 0;
    data_sent = 0;
    start_time = GNUNET_TIME_absolute_get();
    GNUNET_MESH_notify_transmit_ready (t, GNUNET_NO, 0,
                                       GNUNET_TIME_UNIT_FOREVER_REL, dest,
                                       sizeof (struct GNUNET_MessageHeader),
                                       &tmt_rdy, (void *) 1L);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Disconnect already run?\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Aborting...\n");
  }
  return;
}


static void
do_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test_task\n");
  if (test == MULTICAST)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "add peer 3\n");
    GNUNET_MESH_peer_request_connect_add (t, &d3->id);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "add peer 2\n");
  GNUNET_MESH_peer_request_connect_add (t, &d2->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "schedule timeout in 90s\n");
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers, NULL);
  }
}


/**
 * connect_mesh_service: connect to the mesh service of one of the peers
 *
 */
static void
connect_mesh_service (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_MESH_ApplicationType app;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connect_mesh_service\n");

  d2 = GNUNET_TESTING_daemon_get (pg, 4);
  if (test == MULTICAST)
  {
    d3 = GNUNET_TESTING_daemon_get (pg, 3);
  }
  app = (GNUNET_MESH_ApplicationType) 0;

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connecting to mesh service of peer %s\n",
              GNUNET_i2s (&d1->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connecting to mesh service of peer %s\n",
              GNUNET_i2s (&d2->id));
  if (test == MULTICAST)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connecting to mesh service of peer %s\n",
                GNUNET_i2s (&d3->id));
  }
#endif
  h1 = GNUNET_MESH_connect (d1->cfg, 5, (void *) 1L, NULL, &tunnel_cleaner,
                            handlers, &app);
  h2 = GNUNET_MESH_connect (d2->cfg, 5, (void *) 2L, &incoming_tunnel,
                            &tunnel_cleaner, handlers, &app);
  if (test == MULTICAST)
  {
    h3 = GNUNET_MESH_connect (d3->cfg, 5, (void *) 3L, &incoming_tunnel,
                              &tunnel_cleaner, handlers, &app);
  }
  t = GNUNET_MESH_tunnel_create (h1, NULL, &ch, &dh, (void *) 1L);
  peers_in_tunnel = 0;
  test_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 1), &do_test,
                                    NULL);
}



/**
 * peergroup_ready: start test when all peers are connected
 * @param cls closure
 * @param emsg error message
 */
static void
peergroup_ready (void *cls, const char *emsg)
{
  char *buf;
  int buf_len;
  unsigned int i;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error from testing: `%s'\n", emsg);
    ok--;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "************************************************************\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer Group started successfully!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Have %u connections\n",
              total_connections);
#endif

  if (data_file != NULL)
  {
    buf = NULL;
    buf_len = GNUNET_asprintf (&buf, "CONNECTIONS_0: %u\n", total_connections);
    if (buf_len > 0)
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    GNUNET_free (buf);
  }
  peers_running = GNUNET_TESTING_daemons_running (pg);
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_PEER_Id peer_id;

    d1 = GNUNET_TESTING_daemon_get (pg, i);
    peer_id = GNUNET_PEER_intern (&d1->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %u: %s\n",
                peer_id, GNUNET_i2s (&d1->id));
  }
  d1 = GNUNET_TESTING_daemon_get (pg, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer looking: %s\n",
              GNUNET_i2s (&d1->id));
  pid1 = GNUNET_PEER_intern (&d1->id);

  GNUNET_SCHEDULER_add_now (&connect_mesh_service, NULL);
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (wait_time, &disconnect_mesh_peers, NULL);

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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Problem with new connection (%s)\n",
                emsg);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " (%s)\n", GNUNET_i2s (first));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " (%s)\n", GNUNET_i2s (second));
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
  char *temp_str;
  struct GNUNET_TESTING_Host *hosts;
  char *data_filename;

  ok = 0;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);

  GNUNET_log_setup ("test_mesh_small",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons.\n");
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

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (testing_cfg, "test_mesh_small",
                                           "WAIT_TIME", &wait_time))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option test_mesh_small:wait_time is required!\n");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "testing",
                                             "topology_output_file",
                                             &topology_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option test_mesh_small:topology_output_file is required!\n");
    return;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "test_mesh_small",
                                             "data_output_file",
                                             &data_filename))
  {
    data_file =
        GNUNET_DISK_file_open (data_filename,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (data_file == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  data_filename);
      GNUNET_free (data_filename);
    }
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "test_mesh_small",
                                             "output_file", &temp_str))
  {
    output_file =
        GNUNET_DISK_file_open (temp_str,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (output_file == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  temp_str);
  }
  GNUNET_free_non_null (temp_str);

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
 * test_mesh_small command line options
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
  char * argv2[] = {
    argv[0],
    "-c",
    "test_mesh_small.conf",
#if VERBOSE
    "-L",
    "DEBUG",
#endif
    NULL
  };
  int argc2 = (sizeof (argv2) / sizeof (char *)) - 1;

  /* Each peer is supposed to generate the following callbacks:
   * 1 incoming tunnel (@dest)
   * 1 connected peer (@orig)
   * 1 received data packet (@dest)
   * 1 received data packet (@orig)
   * 1 received tunnel destroy (@dest)
   * _________________________________
   * 5 x ok expected per peer
   */
  int ok_goal;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start\n");
  if (strstr (argv[0], "test_mesh_small_unicast") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "UNICAST\n");
    test = UNICAST;
    ok_goal = 5;
  }
  else if (strstr (argv[0], "test_mesh_small_multicast") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MULTICAST\n");
    test = MULTICAST;
    ok_goal = 10;
  }
  else if (strstr (argv[0], "test_mesh_small_speed_ack") != NULL)
  {
   /* Each peer is supposed to generate the following callbacks:
    * 1 incoming tunnel (@dest)
    * 1 connected peer (@orig)
    * 1000 received data packet (@dest)
    * 1000 received data packet (@orig)
    * 1 received tunnel destroy (@dest)
    * _________________________________
    * 5 x ok expected per peer
    */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED_ACK\n");
    test = SPEED_ACK;
    ok_goal = 2003;
    argv2 [3] = NULL; // remove -L DEBUG
#if VERBOSE
    argc2 -= 2;
#endif
  }
  else if (strstr (argv[0], "test_mesh_small_speed") != NULL)
  {
   /* Each peer is supposed to generate the following callbacks:
    * 1 incoming tunnel (@dest)
    * 1 connected peer (@orig)
    * 1000 received data packet (@dest)
    * 1 received tunnel destroy (@dest)
    * _________________________________
    * 5 x ok expected per peer
    */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED\n");
    test = SPEED;
    ok_goal = 1003;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "UNKNOWN\n");
    test = SETUP;
    ok_goal = 0;
  }

  GNUNET_PROGRAM_run (argc2, argv2,
                      "test_mesh_small",
                      gettext_noop ("Test mesh in a small network."), options,
                      &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/test_mesh_small");
#endif
  if (ok_goal > ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "FAILED! (%d/%d)\n", ok, ok_goal);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}

/* end of test_mesh_small.c */
