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
#include "mesh_test_lib.h"
#include "gnunet_mesh_service.h"
#include <gauger.h>


/**
 * How namy messages to send
 */
#define TOTAL_PACKETS 1000

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

/**
 * DIFFERENT TESTS TO RUN
 */
#define SETUP 0
#define UNICAST 1
#define MULTICAST 2
#define SPEED 3
#define SPEED_ACK 4
#define SPEED_MIN 5
#define SPEED_NOBUF 6
#define P2P_SIGNAL 10

/**
 * Which test are we running?
 */
static int test;

/**
 * String with test name
 */
char *test_name;

/**
 * Flag to send traffic leaf->root in speed tests to test BCK_ACK logic.
 */
static int test_backwards = GNUNET_NO;

/**
 * How many events have happened
 */
static int ok;

 /**
  * Each peer is supposed to generate the following callbacks:
  * 1 incoming tunnel (@dest)
  * 1 connected peer (@orig)
  * 1 received data packet (@dest)
  * 1 received data packet (@orig)
  * 1 received tunnel destroy (@dest)
  * _________________________________
  * 5 x ok expected per peer
  */
int ok_goal;


/**
 * Size of each test packet
 */
size_t size_payload = sizeof (struct GNUNET_MessageHeader) + sizeof (uint32_t);

/**
 * Operation to get peer ids.
 */
struct GNUNET_TESTBED_Operation *t_op[3];

/**
 * Peer ids.
 */
struct GNUNET_PeerIdentity *p_id[3];

/**
 * Peer ids counter.
 */
unsigned int p_ids;

/**
 * Is the setup initialized?
 */
static int initialized;

/**
 * Peers that have been connected
 */
static int peers_in_tunnel;

/**
 * Peers that have responded
 */
static int peers_responded;

/**
 * Number of payload packes sent
 */
static int data_sent;

/**
 * Number of payload packets received
 */
static int data_received;

/**
 * Number of payload packed explicitly (app level) acknowledged
 */
static int data_ack;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Test context (to shut down).
 */
struct GNUNET_MESH_TEST_Context *test_ctx;

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

/**
 * Mesh handle for the root peer
 */
static struct GNUNET_MESH_Handle *h1;

/**
 * Mesh handle for the first leaf peer
 */
static struct GNUNET_MESH_Handle *h2;

/**
 * Mesh handle for the second leaf peer
 */
static struct GNUNET_MESH_Handle *h3;

/**
 * Tunnel handle for the root peer
 */
static struct GNUNET_MESH_Tunnel *t;

/**
 * Tunnel handle for the first leaf peer
 */
static struct GNUNET_MESH_Tunnel *incoming_t;

/**
 * Tunnel handle for the second leaf peer
 */
static struct GNUNET_MESH_Tunnel *incoming_t2;

/**
 * Time we started the data transmission (after tunnel has been established
 * and initilized).
 */
static struct GNUNET_TIME_Absolute start_time;


/**
 * Show the results of the test (banwidth acheived) and log them to GAUGER
 */
static void
show_end_data (void)
{
  static struct GNUNET_TIME_Absolute end_time;
  static struct GNUNET_TIME_Relative total_time;

  end_time = GNUNET_TIME_absolute_get();
  total_time = GNUNET_TIME_absolute_get_difference(start_time, end_time);
  FPRINTF (stderr, "\nResults of test \"%s\"\n", test_name);
  FPRINTF (stderr, "Test time %llu ms\n",
            (unsigned long long) total_time.rel_value);
  FPRINTF (stderr, "Test bandwidth: %f kb/s\n",
            4 * TOTAL_PACKETS * 1.0 / total_time.rel_value); // 4bytes * ms
  FPRINTF (stderr, "Test throughput: %f packets/s\n\n",
            TOTAL_PACKETS * 1000.0 / total_time.rel_value); // packets * ms
  GAUGER ("MESH", test_name,
          TOTAL_PACKETS * 1000.0 / total_time.rel_value,
          "packets/s");
}


/**
 * Shut down peergroup, clean up.
 * 
 * @param cls Closure (unused).
 * @param tc Task Context.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");
  shutdown_handle = GNUNET_SCHEDULER_NO_TASK;
}


/**
 * Disconnect from mesh services af all peers, call shutdown.
 * 
 * @param cls Closure (unused).
 * @param tc Task Context.
 */
static void
disconnect_mesh_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  long line = (long) cls;
  unsigned int i;

  for (i = 0; i < 3; i++)
    if (NULL != t_op[i])
    {
      GNUNET_TESTBED_operation_done (t_op[i]);
      t_op[i] = NULL;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting mesh service of peers, called from line %ld\n",
              line);
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != t)
  {
    GNUNET_MESH_tunnel_destroy (t);
    t = NULL;
  }
  if (NULL != incoming_t)
  {
    GNUNET_MESH_tunnel_destroy (incoming_t);
    incoming_t = NULL;
  }
  if (NULL != incoming_t2)
  {
    GNUNET_MESH_tunnel_destroy (incoming_t2);
    incoming_t2 = NULL;
  }
  GNUNET_MESH_TEST_cleanup (test_ctx);
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
  }
  shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Abort test: schedule disconnect and shutdown immediately
 * 
 * @param line Line in the code the abort is requested from (__LINE__).
 */
void
abort_test (long line)
{
  if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
  }
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_mesh_peers,
                                                  (void *) line);
}

/**
 * Transmit ready callback.
 * 
 * @param cls Closure (message type).
 * @param size Size of the tranmist buffer.
 * @param buf Pointer to the beginning of the buffer.
 * 
 * @return Number of bytes written to buf.
 */
static size_t
tmt_rdy (void *cls, size_t size, void *buf);


/**
 * Task to schedule a new data transmission.
 * 
 * @param cls Closure (peer #).
 * @param tc Task Context.
 */
static void
data_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_Tunnel *tunnel;
  struct GNUNET_PeerIdentity *destination;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Data task\n");
  if (GNUNET_YES == test_backwards)
  {
    tunnel = incoming_t;
    destination = p_id[0];
  }
  else
  {
    tunnel = t;
    destination = p_id[2];
  }
  th = GNUNET_MESH_notify_transmit_ready (tunnel, GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          destination,
                                          size_payload,
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
 * @param cls Closure (message type).
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
size_t
tmt_rdy (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = buf;
  uint32_t *data;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " tmt_rdy called\n");
  if (size < size_payload || NULL == buf)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "size %u, buf %p, data_sent %u, data_received %u\n",
                size,
                buf,
                data_sent,
                data_received);
    return 0;
  }
  msg->size = htons (size);
  msg->type = htons ((long) cls);
  data = (uint32_t *) &msg[1];
  *data = htonl (data_sent);
  if (SPEED == test && GNUNET_YES == initialized)
  {
    data_sent++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Sent packet %d\n", data_sent);
    if (data_sent < TOTAL_PACKETS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Scheduling packet %d\n", data_sent + 1);
      GNUNET_SCHEDULER_add_now(&data_task, NULL);
    }
  }
  return size_payload;
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
  long expected_target_client;
  uint32_t *data;

  ok++;

  if ((ok % 20) == 0)
  {
    if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    {
      GNUNET_SCHEDULER_cancel (disconnect_task);
    }
    disconnect_task =
              GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                            (void *) __LINE__);
  }

  switch (client)
  {
  case 0L:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Root client got a message!\n");
    peers_responded++;
    if (test == MULTICAST && peers_responded < 2)
      return GNUNET_OK;
    break;
  case 3L:
  case 4L:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Leaf client %li got a message.\n",
                client);
    client = 4L;
    break;
  default:
    GNUNET_assert (0);
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: (%d/%d)\n", ok, ok_goal);
  data = (uint32_t *) &message[1];
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " payload: (%u)\n", ntohl (*data));
  if (SPEED == test && GNUNET_YES == test_backwards)
  {
    expected_target_client = 0L;
  }
  else
  {
    expected_target_client = 4L;
  }

  if (GNUNET_NO == initialized)
  {
    initialized = GNUNET_YES;
    start_time = GNUNET_TIME_absolute_get ();
    if (SPEED == test)
    {
      GNUNET_assert (4L == client);
      GNUNET_SCHEDULER_add_now (&data_task, NULL);
      return GNUNET_OK;
    }
  }

  if (client == expected_target_client) // Normally 3 or 4
  {
    data_received++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                " received data %u\n", data_received);
    if (SPEED != test || (ok_goal - 2) == ok)
    {
      GNUNET_MESH_notify_transmit_ready (tunnel, GNUNET_NO,
                                        GNUNET_TIME_UNIT_FOREVER_REL, sender,
                                               size_payload,
                                        &tmt_rdy, (void *) 1L);
      return GNUNET_OK;
    }
    else
    {
      if (data_received < TOTAL_PACKETS)
        return GNUNET_OK;
    }
  }
  else // Normally 0
  {
    if (test == SPEED_ACK || test == SPEED)
    {
      data_ack++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              " received ack %u\n", data_ack);
      GNUNET_MESH_notify_transmit_ready (tunnel, GNUNET_NO,
                                        GNUNET_TIME_UNIT_FOREVER_REL, sender,
                                               size_payload,
                                        &tmt_rdy, (void *) 1L);
      if (data_ack < TOTAL_PACKETS && SPEED != test)
        return GNUNET_OK;
      if (ok == 2 && SPEED == test)
        return GNUNET_OK;
      show_end_data();
    }
    if (test == P2P_SIGNAL)
    {
      GNUNET_MESH_tunnel_destroy (incoming_t);
      incoming_t = NULL;
    }
    else
    {
      GNUNET_MESH_tunnel_destroy (t);
      t = NULL;
    }
  }

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
  }
  disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                      (void *) __LINE__);

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
  if ((long) cls == 4L)
    incoming_t = tunnel;
  else if ((long) cls == 3L)
    incoming_t2 = tunnel;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming tunnel for unknown client %lu\n", (long) cls);
    GNUNET_break(0);
  }
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
  }
  disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                      (void *) __LINE__);

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
  if (4L == i)
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
  }
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers,
                                              (void *) __LINE__);

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
  if (P2P_SIGNAL == test)
  {
    ok ++;
    if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    {
      GNUNET_SCHEDULER_cancel (disconnect_task);
    }
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers,
                                                (void *) __LINE__);
  }
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
  long i = (long) cls;

  struct GNUNET_PeerIdentity *dest;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%ld peer %s connected\n", i, GNUNET_i2s (peer));

  if (0 == memcmp (p_id[2], peer, sizeof (struct GNUNET_PeerIdentity)) &&
      i == 0L)
  {
    ok++;
  }
  if (test == MULTICAST &&
      0 == memcmp (p_id[1], peer, sizeof (struct GNUNET_PeerIdentity)) &&
      i == 0L)
  {
    ok++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  switch (test)
  {
    case UNICAST:
    case P2P_SIGNAL:
    case SPEED:
    case SPEED_ACK:
      // incoming_t is NULL unless we send a relevant data packet
      dest = p_id[2];
      break;
    case MULTICAST:
      peers_in_tunnel++;
      if (peers_in_tunnel < 2)
        return;
      dest = NULL;
      break;
    default:
      GNUNET_assert (0);
      return;
  }
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
        GNUNET_SCHEDULER_add_delayed (SHORT_TIME, &disconnect_mesh_peers,
                                      (void *) __LINE__);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending data initializer...\n");
    peers_responded = 0;
    data_ack = 0;
    data_received = 0;
    data_sent = 0;
    GNUNET_MESH_notify_transmit_ready (t, GNUNET_NO,
                                       GNUNET_TIME_UNIT_FOREVER_REL, dest,
                                           size_payload,
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


/**
 * START THE TESTCASE ITSELF, AS WE ARE CONNECTED TO THE MESH SERVICES.
 * 
 * Testcase continues when the root receives confirmation of connected peers,
 * on callback funtion ch.
 * 
 * @param cls Closure (unsued).
 * @param tc Task Context.
 */
static void
do_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test_task\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "add peer 2\n");
  GNUNET_MESH_peer_request_connect_add (t, p_id[2]);

  if (test == MULTICAST)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "add peer 3\n");
    GNUNET_MESH_peer_request_connect_add (t, p_id[1]);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "schedule timeout in TIMEOUT\n");
  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
  }
  disconnect_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                  &disconnect_mesh_peers,
                                                  (void *) __LINE__);
}

/**
 * Callback to be called when the requested peer information is available
 *
 * @param cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed;
 *             NULL if the operation is successfull
 */
void
pi_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "id callback for %ld\n", i);
  if (NULL == pinfo || NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "pi_cb: %s\n", emsg);
    abort_test (__LINE__);
    return;
  }
  p_id[i] = pinfo->result.id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  id: %s\n", GNUNET_i2s (p_id[i]));
  p_ids++;
  if ((MULTICAST == test && p_ids < 3) || p_ids < 2)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got all IDs, starting test\n");
  test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &do_test, NULL);
}

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test main\n");
  ok = 0;
  test_ctx = ctx;
  peers_running = num_peers;
  h1 = meshes[0];
  h2 = meshes[num_peers - 1];
  t = GNUNET_MESH_tunnel_create (h1, NULL, &ch, &dh, (void *) 0L);
  if (SPEED_MIN == test)
  {
    GNUNET_MESH_tunnel_speed_min(t);
    test = SPEED;
  }
  if (SPEED_NOBUF == test)
  {
    GNUNET_MESH_tunnel_buffer(t, GNUNET_NO);
    test = SPEED;
  }
  peers_in_tunnel = 0;
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_mesh_peers,
                                                  (void *) __LINE__);
  shutdown_handle = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &shutdown_task, NULL);
  t_op[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb, (void *) 0L);
  t_op[2] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 1],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb, (void *) 2L);
  if (MULTICAST == test)
  {
    h3 = meshes[num_peers - 2];
    t_op[1] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 2],
                                                   GNUNET_TESTBED_PIT_IDENTITY,
                                                   &pi_cb, (void *) 1L);
  }
  else
  {
    t_op[1] = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requested peer ids\n");
}


/**
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  initialized = GNUNET_NO;

  GNUNET_log_setup ("test", "DEBUG", NULL);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start\n");
  if (strstr (argv[0], "test_mesh_small_unicast") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "UNICAST\n");
    test = UNICAST;
    test_name = "unicast";
    ok_goal = 5;
  }
  else if (strstr (argv[0], "test_mesh_small_multicast") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MULTICAST\n");
    test = MULTICAST;
    test_name = "multicast";
    ok_goal = 10;
  }
  else if (strstr (argv[0], "test_mesh_small_signal") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SIGNAL\n");
    test = P2P_SIGNAL;
    test_name = "signal";
    ok_goal = 5;
  }
  else if (strstr (argv[0], "test_mesh_small_speed_ack") != NULL)
  {
   /* Each peer is supposed to generate the following callbacks:
    * 1 incoming tunnel (@dest)
    * 1 connected peer (@orig)
    * TOTAL_PACKETS received data packet (@dest)
    * TOTAL_PACKETS received data packet (@orig)
    * 1 received tunnel destroy (@dest)
    * _________________________________
    * 5 x ok expected per peer
    */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED_ACK\n");
    test = SPEED_ACK;
    test_name = "speed ack";
    ok_goal = TOTAL_PACKETS * 2 + 3;
  }
  else if (strstr (argv[0], "test_mesh_small_speed") != NULL)
  {
   /* Each peer is supposed to generate the following callbacks:
    * 1 incoming tunnel (@dest)
    * 1 connected peer (@orig)
    * 1 initial packet (@dest)
    * TOTAL_PACKETS received data packet (@dest)
    * 1 received data packet (@orig)
    * 1 received tunnel destroy (@dest)
    * _________________________________
    */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED\n");
    ok_goal = TOTAL_PACKETS + 5;
    if (strstr (argv[0], "_min") != NULL)
    {
      test = SPEED_MIN;
      test_name = "speed min";
    }
    else if (strstr (argv[0], "_nobuf") != NULL)
    {
      test = SPEED_NOBUF;
      test_name = "speed nobuf";
    }
    else
    {
      test = SPEED;
      test_name = "speed";
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "UNKNOWN\n");
    test = SETUP;
    ok_goal = 0;
  }

  if (strstr (argv[0], "backwards") != NULL)
  {
    char *aux;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "BACKWARDS (LEAF TO ROOT)\n");
    test_backwards = GNUNET_YES;
    aux = GNUNET_malloc (32);
    sprintf (aux, "backwards %s", test_name);
    test_name = aux;
  }

  p_ids = 0;
  GNUNET_MESH_TEST_run ("test_mesh_small",
                        "test_mesh_small.conf",
                        5,
                        &tmain,
                        NULL,
                        &incoming_tunnel,
                        &tunnel_cleaner,
                        handlers,
                        NULL);

  if (ok_goal > ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "FAILED! (%d/%d)\n", ok, ok_goal);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}

/* end of test_mesh_small.c */
