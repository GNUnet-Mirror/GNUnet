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
#include "mesh_test_lib.h"
#include "gnunet_mesh_service.h"

#define REMOVE_DIR GNUNET_YES
#define MESH_REGEX_PEERS 4

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Which strings have been found & connected.
 */
static int ok[MESH_REGEX_PEERS];

/**
 * How many connects have happened.
 */
static int regex_peers;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

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
 * Test context (to shut down).
 */
struct GNUNET_MESH_TEST_Context *test_ctx;

/**
 * Regular expressions for the announces.
 */
static char *regexes[MESH_REGEX_PEERS] = {"(0|1)"
                                          "(0|1)"
                                          "23456789ABC",

                                          "0123456789A*BC",

                                          "1234567890123456789012340*123456789ABC*",

                                          "GNUNETVPN0001000IPEX401110011101100100000111(0|1)*"};


/**
 * Service strings to look for.
 */
static char *strings[MESH_REGEX_PEERS] = {"1123456789ABC",

                                          "0123456789AABC",

                                          "12345678901234567890123400123456789ABCCCC",

                                          "GNUNETVPN0001000IPEX401110011101100100000111"};



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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Ending test.\n");
  shutdown_handle = GNUNET_SCHEDULER_NO_TASK;
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
  }
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
  }
  GNUNET_MESH_TEST_cleanup (test_ctx);
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
              GNUNET_i2s (initiator), i);
  if ( (i >= 10L) && (i < 10L + MESH_REGEX_PEERS))
  {
    incoming_t[i - 10L] = tunnel;
    ok[i - 10L] = GNUNET_OK;
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
  unsigned int i;
  long peer_number = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got data on peer %ld!\n", peer_number);
  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    if (GNUNET_OK != ok[i]) {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "data from peer %u still missing!\n", i + 10);
      return GNUNET_OK;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "test: EVERYONE GOT DATA, FINISHING!\n");
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
  }
  disconnect_task =
      GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
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
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_MESH_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param meshes Handle to each of the MESHs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_MESH_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **peers,
       struct GNUNET_MESH_Handle **meshes)
{
  unsigned int i;

  shutdown_handle = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &shutdown_task, NULL);
  test_ctx = ctx;
  if (16 != num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "running peers mismatch, aborting test!\n");
    GNUNET_MESH_TEST_cleanup (ctx);
    return;
  }
  peers_running = num_peers;
  disconnect_task =
    GNUNET_SCHEDULER_add_delayed (TIMEOUT, &disconnect_peers, NULL);

//   h1 = GNUNET_MESH_connect (d->cfg, (void *) 1L,
//                             NULL,
//                             NULL,
//                             handlers,
//                             &app);
  h1 = meshes[0];
  regex_peers = 0;
  for (i = 0; i < MESH_REGEX_PEERS; i++)
  {
    ok[i] = GNUNET_NO;
//     h2[i] = GNUNET_MESH_connect (d->cfg, (void *) (long) (i + 2),
//                                  &incoming_tunnel,
//                                  &tunnel_cleaner,
//                                  handlers,
//                                  &app);
    h2[i] = meshes[10 + i];
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Announce REGEX %u: %s\n", i, regexes[i]);
    GNUNET_MESH_announce_regex (h2[i], regexes[i], 1);
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
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  int result;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Start\n");

  GNUNET_MESH_TEST_run ("test_mesh_regex",
                        "test_mesh_2dtorus.conf",
                        16,
                        &tmain,
                        NULL,
                        &incoming_tunnel,
                        &tunnel_cleaner,
                        handlers,
                        NULL);

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
                "FAILED! %u connected peers\n",
                regex_peers);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "success :)\n");
  return 0;
}

/* end of test_mesh_regex.c */
