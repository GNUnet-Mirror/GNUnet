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
 * @file mesh/gnunet-mesh-profiler.c
 *
 * @brief Profiler for mesh experiments.
 */
#include <stdio.h>
#include "platform.h"
#include "mesh_test_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_statistics_service.h"


#define PING 1
#define PONG 2

/**
 * How many peers to run
 */
#define TOTAL_PEERS 10

/**
 * How many peers do pinging
 */
#define PING_PEERS 1


/**
 * Duration of each round.
 */
#define ROUND_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Paximum ping period in milliseconds. Real period = rand (0, PING_PERIOD)
 */
#define PING_PERIOD 2000

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

static float rounds[] = {0.8, 0.7, 0.6, 0.5, 0.0};

struct MeshPeer
{
  /**
   * Testbed Operation (to get peer id, etc).
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Peer ID.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Mesh handle for the root peer
   */
  struct GNUNET_MESH_Handle *mesh;

  /**
   * Channel handle for the root peer
   */
  struct GNUNET_MESH_Channel *ch;

  /**
   * Channel handle for the dest peer
   */
  struct GNUNET_MESH_Channel *incoming_ch;

  /**
   * Number of payload packes sent
   */
  int data_sent;

  /**
   * Number of payload packets received
   */
  int data_received;

  int up;

  struct MeshPeer *dest;
  struct MeshPeer *incoming;
  GNUNET_SCHEDULER_TaskIdentifier ping_task;
  struct GNUNET_TIME_Absolute timestamp;
};

/**
 * GNUNET_PeerIdentity -> MeshPeer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *ids;

/**
 * Testbed peer handles.
 */
static struct GNUNET_TESTBED_Peer **testbed_handles;

/**
 * Testbed Operation (to get stats).
 */
static struct GNUNET_TESTBED_Operation *stats_op;

/**
 * How many events have happened
 */
static int ok;

/**
 * Number of events expected to conclude the test successfully.
 */
static int ok_goal;

/**
 * Size of each test packet
 */
size_t size_payload = sizeof (struct GNUNET_MessageHeader) + sizeof (uint32_t);

/**
 * Operation to get peer ids.
 */
struct MeshPeer peers[TOTAL_PEERS];

/**
 * Peer ids counter.
 */
static unsigned int p_ids;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Test context (to shut down).
 */
static struct GNUNET_MESH_TEST_Context *test_ctx;

/**
 * Task called to shutdown test.
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_handle;

/**
 * Task called to disconnect peers, before shutdown.
 */
static GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

/**
 * Task to perform tests
 */
static GNUNET_SCHEDULER_TaskIdentifier test_task;


/**
 * Flag to notify callbacks not to generate any new traffic anymore.
 */
static int test_finished;

/**
 * Calculate a random delay.
 *
 * @param max Exclusive maximum, in ms.
 *
 * @return A time between 0 a max-1 ms.
 */
static struct GNUNET_TIME_Relative
delay_ms_rnd (unsigned int max)
{
  unsigned int rnd;

  rnd = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, max);
  return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, rnd);
}


/**
 * Get the index of a peer in the peers array.
 *
 * @param peer Peer whose index to get.
 *
 * @return Index of peer in peers.
 */
static unsigned int
get_index (struct MeshPeer *peer)
{
  return peer - peers;
}


/**
 * Show the results of the test (banwidth acheived) and log them to GAUGER
 */
static void
show_end_data (void)
{
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Ending test.\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting mesh service, called from line %ld\n", line);
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  for (i = 0; i < TOTAL_PEERS; i++)
  {
    if (NULL != peers[i].op)
      GNUNET_TESTBED_operation_done (peers[i].op);

    if (peers[i].up != GNUNET_YES)
      continue;

    if (NULL != peers[i].ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u: channel %p\n", i, peers[i].ch);
      GNUNET_MESH_channel_destroy (peers[i].ch);
    }
    if (NULL != peers[i].incoming_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u: incoming channel %p\n",
                  i, peers[i].incoming_ch);
      GNUNET_MESH_channel_destroy (peers[i].incoming_ch);
    }
  }
  GNUNET_MESH_TEST_cleanup (test_ctx);
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_handle)
  {
    GNUNET_SCHEDULER_cancel (shutdown_handle);
  }
  shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Finish test normally: schedule disconnect and shutdown
 *
 * @param line Line in the code the abort is requested from (__LINE__).
 */
static void
abort_test (long line)
{
  if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers,
                                                (void *) line);
  }
}

/**
 * Stats callback. Finish the stats testbed operation and when all stats have
 * been iterated, shutdown the test.
 *
 * @param cls closure
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
stats_cont (void *cls, struct GNUNET_TESTBED_Operation *op, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "... collecting statistics done.\n");
  GNUNET_TESTBED_operation_done (stats_op);

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers,
                                              (void *) __LINE__);

}


/**
 * Process statistic values.
 *
 * @param cls closure
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
stats_iterator (void *cls, const struct GNUNET_TESTBED_Peer *peer,
                const char *subsystem, const char *name,
                uint64_t value, int is_persistent)
{
  uint32_t i;

  i = GNUNET_TESTBED_get_index (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " STATS %u - %s [%s]: %llu\n",
              i, subsystem, name, value);

  return GNUNET_OK;
}


/**
 * Task check that keepalives were sent and received.
 *
 * @param cls Closure (NULL).
 * @param tc Task Context.
 */
static void
collect_stats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start collecting statistics...\n");
  stats_op = GNUNET_TESTBED_get_statistics (TOTAL_PEERS, testbed_handles,
                                            NULL, NULL,
                                            stats_iterator, stats_cont, NULL);
}


/**
 * @brief Finish profiler normally. Signal finish and start collecting stats.
 *
 * @param cls Closure (unused).
 * @param tc Task context.
 */
static void
finish_profiler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  test_finished = GNUNET_YES;
  show_end_data();
  GNUNET_SCHEDULER_add_now (&collect_stats, NULL);
}

/**
 * Set the total number of running peers.
 *
 * @param target Desired number of running peers.
 */
static void
adjust_running_peers (unsigned int target)
{
  struct GNUNET_TESTBED_Operation *op;
  unsigned int delta;
  unsigned int run;
  unsigned int i;
  unsigned int r;

  GNUNET_assert (target <= TOTAL_PEERS);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "adjust peers to %u\n", target);
  if (target > peers_running)
  {
    delta = target - peers_running;
    run = GNUNET_YES;
  }
  else
  {
    delta = peers_running - target;
    run = GNUNET_NO;
  }

  for (i = 0; i < delta; i++)
  {
    do {
      r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                    TOTAL_PEERS - PING_PEERS);
      r += PING_PEERS;
    } while (peers[r].up == run || NULL != peers[r].incoming);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "St%s peer %u: %s\n",
                run ? "arting" : "opping", r, GNUNET_i2s (&peers[r].id));

    if (GNUNET_SCHEDULER_NO_TASK != peers[r].ping_task)
      GNUNET_SCHEDULER_cancel (peers[r].ping_task);
    peers[r].ping_task = GNUNET_SCHEDULER_NO_TASK;

    peers[r].up = run;

    if (NULL != peers[r].ch)
      GNUNET_MESH_channel_destroy (peers[r].ch);
    peers[r].ch = NULL;
    if (NULL != peers[r].dest)
    {
      if (NULL != peers[r].dest->incoming_ch)
        GNUNET_MESH_channel_destroy (peers[r].dest->incoming_ch);
      peers[r].dest->incoming_ch = NULL;
    }

    op = GNUNET_TESTBED_peer_manage_service (&peers[r], testbed_handles[r],
                                             "mesh", NULL, NULL, run);
    GNUNET_break (NULL != op);
    peers_running += run ? 1 : -1;
    GNUNET_assert (peers_running > 0);
  }
}


/**
 * @brief Move to next round.
 *
 * @param cls Closure (round #).
 * @param tc Task context.
 */
static void
next_rnd (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  long round = (long) cls;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ROUND %ld\n", round);
  if (0.0 == rounds[round])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Finishing\n");
    GNUNET_SCHEDULER_add_now (&finish_profiler, NULL);
    return;
  }
  adjust_running_peers (rounds[round] * TOTAL_PEERS);

  GNUNET_SCHEDULER_add_delayed (ROUND_TIME, &next_rnd, (void *) (round + 1));
}


/**
 * Transmit ready callback.
 *
 * @param cls Closure (peer for PING, NULL for PONG).
 * @param size Size of the tranmist buffer.
 * @param buf Pointer to the beginning of the buffer.
 *
 * @return Number of bytes written to buf.
 */
static size_t
tmt_rdy (void *cls, size_t size, void *buf);


/**
 * @brief Send a ping to destination
 *
 * @param cls Closure (peer).
 * @param tc Task context.
 */
static void
ping (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshPeer *peer = (struct MeshPeer *) cls;

  peer->ping_task = GNUNET_SCHEDULER_NO_TASK;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0
      || GNUNET_YES == test_finished
      || 0 != peer->timestamp.abs_value_us)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u -> %u\n",
              get_index (peer), get_index (peer->dest));

  GNUNET_MESH_notify_transmit_ready (peer->ch, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     size_payload, &tmt_rdy, peer);
}

/**
 * @brief Reply with a pong to origin.
 *
 * @param cls Closure (peer).
 * @param tc Task context.
 */
static void
pong (struct GNUNET_MESH_Channel *channel)
{
  GNUNET_MESH_notify_transmit_ready (channel, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     size_payload, &tmt_rdy, NULL);
}


/**
 * Transmit ready callback
 *
 * @param cls Closure (peer for PING, NULL for PONG).
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
static size_t
tmt_rdy (void *cls, size_t size, void *buf)
{
  struct MeshPeer *peer = (struct MeshPeer *) cls;
  struct GNUNET_MessageHeader *msg = buf;
  uint32_t *data;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tmt_rdy called, filling buffer\n");
  if (size < size_payload || NULL == buf)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "size %u, buf %p, data_sent %u, data_received %u\n",
                size, buf, peer->data_sent, peer->data_received);

    return 0;
  }
  msg->size = htons (size);
  if (NULL == peer)
  {
    msg->type = htons (PONG);
    return sizeof (*msg);
  }

  msg->type = htons (PING);
  data = (uint32_t *) &msg[1];
  *data = htonl (peer->data_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent: msg %d\n", peer->data_sent);
  peer->data_sent++;
  peer->timestamp = GNUNET_TIME_absolute_get ();
  peer->ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd (PING_PERIOD),
                                                  &ping, peer);

  return size_payload;
}


/**
 * Function is called whenever a PING message is received.
 *
 * @param cls closure (peer #, set from GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
ping_handler (void *cls, struct GNUNET_MESH_Channel *channel,
              void **channel_ctx,
              const struct GNUNET_MessageHeader *message)
{
  long n = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u got PING\n", n);
  GNUNET_MESH_receive_done (channel);
  if (GNUNET_NO == test_finished)
    pong (channel);

  return GNUNET_OK;
}


/**
 * Function is called whenever a PONG message is received.
 *
 * @param cls closure (peer #, set from GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
pong_handler (void *cls, struct GNUNET_MESH_Channel *channel,
              void **channel_ctx,
              const struct GNUNET_MessageHeader *message)
{
  long n = (long) cls;
  struct MeshPeer *peer;
  struct GNUNET_TIME_Relative latency;

  GNUNET_MESH_receive_done (channel);
  peer = &peers[n];

  GNUNET_break (0 != peer->timestamp.abs_value_us);
  latency = GNUNET_TIME_absolute_get_duration (peer->timestamp);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u <- %u latency: %s\n",
              get_index (peer), get_index (peer->dest),
              GNUNET_STRINGS_relative_time_to_string (latency, GNUNET_NO));

  if (GNUNET_SCHEDULER_NO_TASK == peer->ping_task)
  {
    peer->timestamp = GNUNET_TIME_absolute_get ();
    peer->ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd (60 * 1000),
                                                    &ping, peer);
  }
  else
  {
    peer->timestamp.abs_value_us = 0;
  }

  return GNUNET_OK;
}


/**
 * Handlers, for diverse services
 */
static struct GNUNET_MESH_MessageHandler handlers[] = {
  {&ping_handler, PING, sizeof (struct GNUNET_MessageHeader)},
  {&pong_handler, PONG, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 *
 * @param cls Closure.
 * @param channel New handle to the channel.
 * @param initiator Peer that started the channel.
 * @param port Port this channel is connected to.
 * @param options channel option flags
 * @return Initial channel context for the channel
 *         (can be NULL -- that's not an error).
 */
static void *
incoming_channel (void *cls, struct GNUNET_MESH_Channel *channel,
                 const struct GNUNET_PeerIdentity *initiator,
                 uint32_t port, enum GNUNET_MESH_ChannelOption options)
{
  long n = (long) cls;
  struct MeshPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (ids, initiator);
  GNUNET_assert (NULL != peer);
  GNUNET_assert (peer == peers[n].incoming);
  GNUNET_assert (peer->dest == &peers[n]);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u <= %u %p\n",
              n, get_index (peer), channel);
  peers[n].incoming_ch = channel;

  return NULL;
}

/**
 * Function called whenever an inbound channel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_cleaner (void *cls, const struct GNUNET_MESH_Channel *channel,
                 void *channel_ctx)
{
  long n = (long) cls;
  struct MeshPeer *peer = &peers[n];

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Channel %p disconnected at peer %ld\n", channel, n);
  if (peer->ch == channel)
    peer->ch = NULL;
}


static struct MeshPeer *
select_random_peer (struct MeshPeer *peer)
{
  unsigned int r;

  do
  {
    r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, TOTAL_PEERS);
  } while (NULL != peers[r].incoming);
  peers[r].incoming = peer;

  return &peers[r];
}

/**
 * START THE TEST ITSELF, AS WE ARE CONNECTED TO THE MESH SERVICES.
 *
 * Testcase continues when the root receives confirmation of connected peers,
 * on callback funtion ch.
 *
 * @param cls Closure (unsued).
 * @param tc Task Context.
 */
static void
start_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  enum GNUNET_MESH_ChannelOption flags;
  unsigned long i;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start profiler\n");

  flags = GNUNET_MESH_OPTION_DEFAULT;
  for (i = 0; i < PING_PEERS; i++)
  {

    peers[i].dest = select_random_peer (&peers[i]);
    peers[i].ch = GNUNET_MESH_channel_create (peers[i].mesh, NULL,
                                              &peers[i].dest->id,
                                              1, flags);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u => %u %p\n",
                i, get_index (peers[i].dest), peers[i].ch);
    peers[i].ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd (2000),
                                                       &ping, &peers[i]);
  }
  peers_running = TOTAL_PEERS;
  GNUNET_SCHEDULER_add_delayed (ROUND_TIME, &next_rnd, NULL);
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cls the closure from GNUNET_TESTBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed;
 *             NULL if the operation is successfull
 */
static void
peer_id_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  long n = (long) cls;

  if (NULL == pinfo || NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "pi_cb: %s\n", emsg);
    abort_test (__LINE__);
    return;
  }
  peers[n].id = *(pinfo->result.id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " %u  id: %s\n",
              n, GNUNET_i2s (&peers[n].id));
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (ids, &peers[n].id, &peers[n],
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

  GNUNET_TESTBED_operation_done (peers[n].op);
  peers[n].op = NULL;

  p_ids++;
  if (p_ids < TOTAL_PEERS)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got all IDs, starting profiler\n");
  test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &start_test, NULL);
}

/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_MESH_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param testbed_peers Array of peers.
 * @param meshes Handle to each of the MESHs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_MESH_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **testbed_peers,
       struct GNUNET_MESH_Handle **meshes)
{
  unsigned long i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test main\n");
  ok = 0;
  test_ctx = ctx;
  GNUNET_assert (TOTAL_PEERS > 2 * PING_PEERS);
  GNUNET_assert (TOTAL_PEERS == num_peers);
  peers_running = num_peers;
  testbed_handles = testbed_peers;
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_mesh_peers,
                                                  (void *) __LINE__);
  shutdown_handle = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &shutdown_task, NULL);
  for (i = 0; i < TOTAL_PEERS; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requesting id %ld\n", i);
    peers[i].up = GNUNET_YES;
    peers[i].mesh = meshes[i];
    peers[i].op =
      GNUNET_TESTBED_peer_get_information (testbed_handles[i],
                                           GNUNET_TESTBED_PIT_IDENTITY,
                                           &peer_id_cb, (void *) i);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requested peer ids\n");
  /* Continues from pi_cb -> do_test */
}


/**
 * Main: start profiler.
 */
int
main (int argc, char *argv[])
{
  static uint32_t ports[2];
  const char *config_file;

  config_file = "test_mesh.conf";

  ids = GNUNET_CONTAINER_multipeermap_create (2 * TOTAL_PEERS, GNUNET_YES);
  GNUNET_assert (NULL != ids);
  p_ids = 0;
  test_finished = GNUNET_NO;
  ports[0] = 1;
  ports[1] = 0;
  GNUNET_MESH_TEST_run ("mesh-profiler", config_file, TOTAL_PEERS,
                        &tmain, NULL, /* tmain cls */
                        &incoming_channel, &channel_cleaner,
                        handlers, ports);

  if (ok_goal > ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "FAILED! (%d/%d)\n", ok, ok_goal);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}

/* end of gnunet-mesh-profiler.c */

