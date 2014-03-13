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
 * @file mesh/mesh_profiler.c
 *
 * @brief Profiler for mesh experiments.
 */
#include <stdio.h>
#include "platform.h"
#include "mesh_test_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_statistics_service.h"


/**
 * How namy messages to send
 */
#define TOTAL_PACKETS 1000

/**
 * How namy peers to run
 */
#define TOTAL_PEERS 1000

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


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

  unsigned int dest;
  GNUNET_SCHEDULER_TaskIdentifier ping_task;
};

/**
 * Testbed peer handles.
 */
struct GNUNET_TESTBED_Peer **testbed_handles;

/**
 * Testbed Operation (to get stats).
 */
struct GNUNET_TESTBED_Operation *stats_op;

/**
 * How many events have happened
 */
static int ok;

/**
 * Number of events expected to conclude the test successfully.
 */
int ok_goal;

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
unsigned int p_ids;

/**
 * Is the setup initialized?
 */
static int initialized;

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
 * Time we started the data transmission (after channel has been established
 * and initilized).
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 *
 */
static unsigned int ka_sent;
static unsigned int ka_received;


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
  FPRINTF (stderr, "Test time %s\n",
	   GNUNET_STRINGS_relative_time_to_string (total_time,
						   GNUNET_YES));
  FPRINTF (stderr, "Test bandwidth: %f kb/s\n",
	   4 * TOTAL_PACKETS * 1.0 / (total_time.rel_value_us / 1000)); // 4bytes * ms
  FPRINTF (stderr, "Test throughput: %f packets/s\n\n",
	   TOTAL_PACKETS * 1000.0 / (total_time.rel_value_us / 1000)); // packets * ms
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting mesh service of peers, called from line %ld\n",
              line);
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  for (i = 0; i < TOTAL_PEERS; i++)
  {
    GNUNET_TESTBED_operation_done (peers[i].op);
    GNUNET_MESH_channel_destroy (peers[i].ch);
    GNUNET_MESH_channel_destroy (peers[i].incoming_ch);
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
  static const char *s_sent = "# keepalives sent";
  static const char *s_recv = "# keepalives received";
  uint32_t i;

  i = GNUNET_TESTBED_get_index (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %u - %s [%s]: %llu\n",
              i, subsystem, name, value);
  if (0 == strncmp (s_sent, name, strlen (s_sent)) && 0 == i)
    ka_sent = value;

  if (0 == strncmp(s_recv, name, strlen (s_recv)) && 4 == i)
  {
    ka_received = value;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " sent: %u, received: %u\n",
                ka_sent, ka_received);
    if (ka_sent < 2 || ka_sent > ka_received + 1)
      ok--;
  }

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

  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start collecting statistics...\n");
  stats_op = GNUNET_TESTBED_get_statistics (TOTAL_PEERS, testbed_handles,
                                            NULL, NULL,
                                            stats_iterator, stats_cont, NULL);
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
  struct GNUNET_MESH_Channel *channel;
  long n = (long) cls;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Data task\n");

  channel = peers[n].ch;
  th = GNUNET_MESH_notify_transmit_ready (channel, GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          size_payload, &tmt_rdy, (void *) 1L);
  if (NULL == th)
    GNUNET_abort ();
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tmt_rdy called, filling buffer\n");
  if (size < size_payload || NULL == buf)
  {
    GNUNET_break (ok >= ok_goal - 2);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "size %u, buf %p, data_sent %u, data_received %u\n",
                size, buf, data_sent, data_received);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ok %u, ok goal %u\n", ok, ok_goal);

    return 0;
  }
  msg->size = htons (size);
  msg->type = htons ((long) cls);
  data = (uint32_t *) &msg[1];
  *data = htonl (data_sent);
  if (GNUNET_NO == initialized)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending initializer\n");
  }
  else
  {
    data_sent++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Sent packet %d\n", data_sent);
    if (data_sent < TOTAL_PACKETS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Scheduling packet %d\n", data_sent + 1);
      GNUNET_SCHEDULER_add_now (&data_task, NULL);
    }
  }

  return size_payload;
}


/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
data_callback (void *cls, struct GNUNET_MESH_Channel *channel,
               void **channel_ctx,
               const struct GNUNET_MessageHeader *message)
{
//   long n = (long) cls;

  GNUNET_MESH_receive_done (channel);


  if (GNUNET_NO == initialized)
  {
    initialized = GNUNET_YES;
    start_time = GNUNET_TIME_absolute_get ();
    GNUNET_SCHEDULER_add_now (&data_task, NULL);
  }
  GNUNET_MESH_notify_transmit_ready (channel, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     size_payload, &tmt_rdy, (void *) 1L);

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                    &disconnect_mesh_peers,
                                                    (void *) __LINE__);
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel from %s to peer %ld\n",
              GNUNET_i2s (initiator), n);
  ok++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  peers[n].incoming_ch = channel;

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                    &disconnect_mesh_peers,
                                                    (void *) __LINE__);
  }

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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel disconnected at peer %ld\n", n);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_mesh_peers,
                                                (void *) __LINE__);
  }
}


/**
 * @brief Send data to destination
 *
 * @param cls Closure (peer).
 * @param tc Task context.
 */
static void
ping (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshPeer *peer = (struct MeshPeer *) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending data initializer...\n");

  GNUNET_MESH_notify_transmit_ready (peer->ch, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     size_payload, &tmt_rdy, (void *) 1L);
}


static struct GNUNET_TIME_Relative
delay_ms_rnd (unsigned int max)
{
  unsigned int rnd;

  rnd = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, max);
  return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, rnd);
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
  enum GNUNET_MESH_ChannelOption flags;
  unsigned long i;

  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start profiler\n");

  if (GNUNET_SCHEDULER_NO_TASK != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_mesh_peers,
                                                  (void *) __LINE__);

  flags = GNUNET_MESH_OPTION_DEFAULT;
  for (i = 0; i < TOTAL_PEERS; i++)
  {
    peers[i].dest = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                              TOTAL_PEERS);
    peers[i].ch = GNUNET_MESH_channel_create (peers[i].mesh, NULL,
                                              &peers[peers[i].dest].id,
                                              1, flags);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u -> %u\n", i, peers[i].dest);
    peers[i].ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd(2000),
                                                       &ping, &peers[i]);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending data initializer...\n");
  data_ack = 0;
  data_received = 0;
  data_sent = 0;

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " %u  id: %s\n",
              n, GNUNET_i2s (&peers[n].id));
  p_ids++;
  if (p_ids < TOTAL_PEERS)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got all IDs, starting profiler\n");
  test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &do_test, NULL);
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
  GNUNET_assert (TOTAL_PEERS == num_peers);
  peers_running = num_peers;
  testbed_handles = testbed_handles;
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_mesh_peers,
                                                  (void *) __LINE__);
  shutdown_handle = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &shutdown_task, NULL);
  for (i = 0; i < TOTAL_PEERS; i++)
  {
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
  initialized = GNUNET_NO;
  static uint32_t ports[2];
  const char *config_file;

  config_file = "test_mesh.conf";

  p_ids = 0;
  ports[0] = 1;
  ports[1] = 0;
  GNUNET_MESH_TEST_run ("mesh_profiler", config_file, TOTAL_PEERS,
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

/* end of test_mesh_small.c */

