/*
     This file is part of GNUnet.
     Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file cadet/gnunet-cadet-profiler.c
 *
 * @brief Profiler for cadet experiments.
 */
#include <stdio.h>
#include "platform.h"
#include "cadet_test_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"


#define PING 1
#define PONG 2


/**
 * Paximum ping period in milliseconds. Real period = rand (0, PING_PERIOD)
 */
#define PING_PERIOD 500

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * Total number of rounds.
 */
#define number_rounds sizeof(rounds)/sizeof(rounds[0])

/**
 * Ratio of peers active. First round always is 1.0.
 */
static float rounds[] = {0.8, 0.6, 0.8, 0.5, 0.3, 0.8, 0.0};

/**
 * Message type for pings.
 */
struct CadetPingMessage
{
  /**
   * Header. Type PING/PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message number.
   */
  uint32_t counter;

  /**
   * Time the message was sent.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Round number.
   */
  uint32_t round_number;
};

/**
 * Peer description.
 */
struct CadetPeer
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
   * Cadet handle for the root peer
   */
  struct GNUNET_CADET_Handle *cadet;

  /**
   * Channel handle for the root peer
   */
  struct GNUNET_CADET_Channel *ch;

  /**
   * Channel handle for the dest peer
   */
  struct GNUNET_CADET_Channel *incoming_ch;

  /**
   * Channel handle for a warmup channel.
   */
  struct GNUNET_CADET_Channel *warmup_ch;

  /**
   * Number of payload packes sent
   */
  int data_sent;

  /**
   * Number of payload packets received
   */
  int data_received;

  /**
   * Is peer up?
   */
  int up;

  /**
   * Destinaton to ping.
   */
  struct CadetPeer *dest;

  /**
   * Incoming channel for pings.
   */
  struct CadetPeer *incoming;

  /**
   * Task to do the next ping.
   */
  struct GNUNET_SCHEDULER_Task * ping_task;

  float mean[number_rounds];
  float var[number_rounds];
  unsigned int pongs[number_rounds];
  unsigned int pings[number_rounds];

};

/**
 * Duration of each round.
 */
static struct GNUNET_TIME_Relative round_time;

/**
 * GNUNET_PeerIdentity -> CadetPeer
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
 * Operation to get peer ids.
 */
struct CadetPeer *peers;

/**
 * Peer ids counter.
 */
static unsigned int p_ids;

/**
 * Total number of peers.
 */
static unsigned long long peers_total;

/**
 * Number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Number of peers doing pings.
 */
static unsigned long long peers_pinging;

/**
 * Test context (to shut down).
 */
static struct GNUNET_CADET_TEST_Context *test_ctx;

/**
 * Task called to shutdown test.
 */
static struct GNUNET_SCHEDULER_Task * shutdown_handle;

/**
 * Task called to disconnect peers, before shutdown.
 */
static struct GNUNET_SCHEDULER_Task * disconnect_task;

/**
 * Task to perform tests
 */
static struct GNUNET_SCHEDULER_Task * test_task;

/**
 * Round number.
 */
static unsigned int current_round;

/**
 * Do preconnect? (Each peer creates a tunnel to one other peer).
 */
static int do_warmup;

/**
 * Warmup progress.
 */
static unsigned int peers_warmup;

/**
 * Flag to notify callbacks not to generate any new traffic anymore.
 */
static int test_finished;


/**
 * START THE TEST ITSELF, AS WE ARE CONNECTED TO THE CADET SERVICES.
 *
 * Testcase continues when the root receives confirmation of connected peers,
 * on callback funtion ch.
 *
 * @param cls Closure (unsued).
 * @param tc Task Context.
 */
static void
start_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
get_index (struct CadetPeer *peer)
{
  return peer - peers;
}


/**
 * Show the results of the test (banwidth acheived) and log them to GAUGER
 */
static void
show_end_data (void)
{
  struct CadetPeer *peer;
  unsigned int i;
  unsigned int j;

  for (i = 0; i < number_rounds; i++)
  {
    for (j = 0; j < peers_pinging; j++)
    {
      peer = &peers[j];
      FPRINTF (stdout,
               "ROUND %3u PEER %3u: %10.2f / %10.2f, PINGS: %3u, PONGS: %3u\n",
               i, j, peer->mean[i], sqrt (peer->var[i] / (peer->pongs[i] - 1)),
               peer->pings[i], peer->pongs[i]);
    }
  }
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
  shutdown_handle = NULL;
}


/**
 * Disconnect from cadet services af all peers, call shutdown.
 *
 * @param cls Closure (unused).
 * @param tc Task Context.
 */
static void
disconnect_cadet_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  long line = (long) cls;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting cadet service, called from line %ld\n", line);
  disconnect_task = NULL;
  for (i = 0; i < peers_total; i++)
  {
    if (NULL != peers[i].op)
      GNUNET_TESTBED_operation_done (peers[i].op);

    if (peers[i].up != GNUNET_YES)
      continue;

    if (NULL != peers[i].ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u: channel %p\n", i, peers[i].ch);
      GNUNET_CADET_channel_destroy (peers[i].ch);
    }
    if (NULL != peers[i].warmup_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u: warmup channel %p\n",
                  i, peers[i].warmup_ch);
      GNUNET_CADET_channel_destroy (peers[i].warmup_ch);
    }
    if (NULL != peers[i].incoming_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u: incoming channel %p\n",
                  i, peers[i].incoming_ch);
      GNUNET_CADET_channel_destroy (peers[i].incoming_ch);
    }
  }
  GNUNET_CADET_TEST_cleanup (test_ctx);
  if (NULL != shutdown_handle)
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
  if (disconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
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

  if (NULL != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
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
  stats_op = GNUNET_TESTBED_get_statistics (peers_total, testbed_handles,
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

  GNUNET_assert (target <= peers_total);

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
                                    peers_total - peers_pinging);
      r += peers_pinging;
    } while (peers[r].up == run || NULL != peers[r].incoming);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "St%s peer %u: %s\n",
                run ? "arting" : "opping", r, GNUNET_i2s (&peers[r].id));

    if (NULL != peers[r].ping_task)
      GNUNET_SCHEDULER_cancel (peers[r].ping_task);
    peers[r].ping_task = NULL;

    peers[r].up = run;

    if (NULL != peers[r].ch)
      GNUNET_CADET_channel_destroy (peers[r].ch);
    peers[r].ch = NULL;
    if (NULL != peers[r].dest)
    {
      if (NULL != peers[r].dest->incoming_ch)
        GNUNET_CADET_channel_destroy (peers[r].dest->incoming_ch);
      peers[r].dest->incoming_ch = NULL;
    }

    op = GNUNET_TESTBED_peer_manage_service (&peers[r], testbed_handles[r],
                                             "cadet", NULL, NULL, run);
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
  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ROUND %ld\n", current_round);
  if (0.0 == rounds[current_round])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Finishing\n");
    GNUNET_SCHEDULER_add_now (&finish_profiler, NULL);
    return;
  }
  adjust_running_peers (rounds[current_round] * peers_total);
  current_round++;

  GNUNET_SCHEDULER_add_delayed (round_time, &next_rnd, NULL);
}


/**
 * Transmit ping callback.
 *
 * @param cls Closure (peer for PING, NULL for PONG).
 * @param size Size of the tranmist buffer.
 * @param buf Pointer to the beginning of the buffer.
 *
 * @return Number of bytes written to buf.
 */
static size_t
tmt_rdy_ping (void *cls, size_t size, void *buf);


/**
 * Transmit pong callback.
 *
 * @param cls Closure (copy of PING message, to be freed).
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
static size_t
tmt_rdy_pong (void *cls, size_t size, void *buf)
{
  struct CadetPingMessage *ping = cls;
  struct CadetPingMessage *pong;

  if (0 == size || NULL == buf)
  {
    GNUNET_free (ping);
    return 0;
  }
  pong = (struct CadetPingMessage *) buf;
  memcpy (pong, ping, sizeof (*ping));
  pong->header.type = htons (PONG);

  GNUNET_free (ping);
  return sizeof (*ping);
}


/**
 * @brief Send a ping to destination
 *
 * @param cls Closure (peer).
 * @param tc Task context.
 */
static void
ping (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeer *peer = (struct CadetPeer *) cls;

  peer->ping_task = NULL;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason)
      || GNUNET_YES == test_finished)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u -> %u (%u)\n",
              get_index (peer), get_index (peer->dest), peer->data_sent);

  GNUNET_CADET_notify_transmit_ready (peer->ch, GNUNET_NO,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      sizeof (struct CadetPingMessage),
                                      &tmt_rdy_ping, peer);
}

/**
 * @brief Reply with a pong to origin.
 *
 * @param cls Closure (peer).
 * @param tc Task context.
 */
static void
pong (struct GNUNET_CADET_Channel *channel, const struct CadetPingMessage *ping)
{
  struct CadetPingMessage *copy;

  copy = GNUNET_new (struct CadetPingMessage);
  memcpy (copy, ping, sizeof (*ping));
  GNUNET_CADET_notify_transmit_ready (channel, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     sizeof (struct CadetPingMessage),
                                     &tmt_rdy_pong, copy);
}


/**
 * Transmit ping callback
 *
 * @param cls Closure (peer).
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
static size_t
tmt_rdy_ping (void *cls, size_t size, void *buf)
{
  struct CadetPeer *peer = (struct CadetPeer *) cls;
  struct CadetPingMessage *msg = buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tmt_rdy called, filling buffer\n");
  if (size < sizeof (struct CadetPingMessage) || NULL == buf)
  {
    GNUNET_break (GNUNET_YES == test_finished);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "size %u, buf %p, data_sent %u, data_received %u\n",
                size, buf, peer->data_sent, peer->data_received);

    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending: msg %d\n", peer->data_sent);
  msg->header.size = htons (size);
  msg->header.type = htons (PING);
  msg->counter = htonl (peer->data_sent++);
  msg->round_number = htonl (current_round);
  msg->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  peer->pings[current_round]++;
  peer->ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd (PING_PERIOD),
                                                  &ping, peer);

  return sizeof (struct CadetPingMessage);
}


/**
 * Function is called whenever a PING message is received.
 *
 * @param cls closure (peer #, set from GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
ping_handler (void *cls, struct GNUNET_CADET_Channel *channel,
              void **channel_ctx,
              const struct GNUNET_MessageHeader *message)
{
  long n = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u got PING\n", n);
  GNUNET_CADET_receive_done (channel);
  if (GNUNET_NO == test_finished)
    pong (channel, (struct CadetPingMessage *) message);

  return GNUNET_OK;
}


/**
 * Function is called whenever a PONG message is received.
 *
 * @param cls closure (peer #, set from GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
pong_handler (void *cls, struct GNUNET_CADET_Channel *channel,
              void **channel_ctx,
              const struct GNUNET_MessageHeader *message)
{
  long n = (long) cls;
  struct CadetPeer *peer;
  struct CadetPingMessage *msg;
  struct GNUNET_TIME_Absolute send_time;
  struct GNUNET_TIME_Relative latency;
  unsigned int r /* Ping round */;
  float delta;

  GNUNET_CADET_receive_done (channel);
  peer = &peers[n];

  msg = (struct CadetPingMessage *) message;

  send_time = GNUNET_TIME_absolute_ntoh (msg->timestamp);
  latency = GNUNET_TIME_absolute_get_duration (send_time);
  r = ntohl (msg->round_number);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u <- %u (%u) latency: %s\n",
              get_index (peer), get_index (peer->dest), ntohl (msg->counter),
              GNUNET_STRINGS_relative_time_to_string (latency, GNUNET_NO));

  /* Online variance calculation */
  peer->pongs[r]++;
  delta = latency.rel_value_us - peer->mean[r];
  peer->mean[r] = peer->mean[r] + delta/peer->pongs[r];
  peer->var[r] += delta * (latency.rel_value_us - peer->mean[r]);

  return GNUNET_OK;
}


/**
 * Handlers, for diverse services
 */
static struct GNUNET_CADET_MessageHandler handlers[] = {
  {&ping_handler, PING, sizeof (struct CadetPingMessage)},
  {&pong_handler, PONG, sizeof (struct CadetPingMessage)},
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
incoming_channel (void *cls, struct GNUNET_CADET_Channel *channel,
                 const struct GNUNET_PeerIdentity *initiator,
                 uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  long n = (long) cls;
  struct CadetPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (ids, initiator);
  GNUNET_assert (NULL != peer);
  if (NULL == peers[n].incoming)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "WARMUP %3u: %u <= %u\n",
                peers_warmup, n, get_index (peer));
    peers_warmup++;
    if (peers_warmup < peers_total)
      return NULL;
    if (NULL != test_task)
    {
      GNUNET_SCHEDULER_cancel (test_task);
      test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                &start_test, NULL);
    }
    return NULL;
  }
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
 * @param cls closure (set from GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_cleaner (void *cls, const struct GNUNET_CADET_Channel *channel,
                 void *channel_ctx)
{
  long n = (long) cls;
  struct CadetPeer *peer = &peers[n];

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Channel %p disconnected at peer %ld\n", channel, n);
  if (peer->ch == channel)
    peer->ch = NULL;
}


/**
 * Select a random peer that has no incoming channel
 *
 * @param peer ID of the peer connecting. NULL if irrelevant (warmup).
 *
 * @return Random peer not yet connected to.
 */
static struct CadetPeer *
select_random_peer (struct CadetPeer *peer)
{
  unsigned int r;

  do
  {
    r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, peers_total);
  } while (NULL != peers[r].incoming);
  peers[r].incoming = peer;

  return &peers[r];
}

/**
 * START THE TEST ITSELF, AS WE ARE CONNECTED TO THE CADET SERVICES.
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
  enum GNUNET_CADET_ChannelOption flags;
  unsigned long i;

  test_task = NULL;
  if ((GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Start profiler\n");

  flags = GNUNET_CADET_OPTION_DEFAULT;
  for (i = 0; i < peers_pinging; i++)
  {
    peers[i].dest = select_random_peer (&peers[i]);
    peers[i].ch = GNUNET_CADET_channel_create (peers[i].cadet, NULL,
                                               &peers[i].dest->id,
                                               1, flags);
    if (NULL == peers[i].ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Channel %lu failed\n", i);
      GNUNET_CADET_TEST_cleanup (test_ctx);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u => %u %p\n",
                i, get_index (peers[i].dest), peers[i].ch);
    peers[i].ping_task = GNUNET_SCHEDULER_add_delayed (delay_ms_rnd (2000),
                                                       &ping, &peers[i]);
  }
  peers_running = peers_total;
  if (NULL != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(round_time,
                                                                number_rounds + 1),
                                  &disconnect_cadet_peers,
                                  (void *) __LINE__);
  GNUNET_SCHEDULER_add_delayed (round_time, &next_rnd, NULL);
}


/**
 * Do warmup: create some channels to spread information about the topology.
 */
static void
warmup (void)
{
  struct CadetPeer *peer;
  unsigned int i;

  for (i = 0; i < peers_total; i++)
  {
    peer = select_random_peer (NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "WARMUP %u => %u\n",
                i, get_index (peer));
    peers[i].warmup_ch =
      GNUNET_CADET_channel_create (peers[i].cadet, NULL, &peer->id,
                                  1, GNUNET_CADET_OPTION_DEFAULT);
    if (NULL == peers[i].warmup_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Warmup %u failed\n", i);
      GNUNET_CADET_TEST_cleanup (test_ctx);
      return;
    }
  }
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
  if (p_ids < peers_total)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got all IDs, starting profiler\n");
  if (do_warmup)
  {
    struct GNUNET_TIME_Relative delay;

    warmup();
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                           100 * peers_total);
    test_task = GNUNET_SCHEDULER_add_delayed (delay, &start_test, NULL);
    return; /* start_test from incoming_channel */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Starting in a second...\n");
  test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &start_test, NULL);
}

/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_CADET_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param testbed_peers Array of peers.
 * @param cadetes Handle to each of the CADETs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_CADET_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **testbed_peers,
       struct GNUNET_CADET_Handle **cadetes)
{
  unsigned long i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test main\n");
  test_ctx = ctx;
  GNUNET_assert (peers_total == num_peers);
  peers_running = num_peers;
  testbed_handles = testbed_peers;
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_cadet_peers,
                                                  (void *) __LINE__);
  shutdown_handle = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &shutdown_task, NULL);
  for (i = 0; i < peers_total; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requesting id %ld\n", i);
    peers[i].up = GNUNET_YES;
    peers[i].cadet = cadetes[i];
    peers[i].op =
      GNUNET_TESTBED_peer_get_information (testbed_handles[i],
                                           GNUNET_TESTBED_PIT_IDENTITY,
                                           &peer_id_cb, (void *) i);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "requested peer ids\n");
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

  config_file = ".profiler.conf";

  if (4 > argc)
  {
    fprintf (stderr, "usage: %s ROUND_TIME PEERS PINGS [DO_WARMUP]\n", argv[0]);
    fprintf (stderr, "example: %s 30s 16 1 Y\n", argv[0]);
    return 1;
  }

  if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_relative (argv[1], &round_time))
  {
    fprintf (stderr, "%s is not a valid time\n", argv[1]);
    return 1;
  }

  peers_total = atoll (argv[2]);
  if (2 > peers_total)
  {
    fprintf (stderr, "%s peers is not valid (> 2)\n", argv[1]);
    return 1;
  }
  peers = GNUNET_malloc (sizeof (struct CadetPeer) * peers_total);

  peers_pinging = atoll (argv[3]);

  if (peers_total < 2 * peers_pinging)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "not enough peers, total should be > 2 * peers_pinging\n");
    return 1;
  }

  do_warmup = (5 > argc || argv[4][0] != 'N');

  ids = GNUNET_CONTAINER_multipeermap_create (2 * peers_total, GNUNET_YES);
  GNUNET_assert (NULL != ids);
  p_ids = 0;
  test_finished = GNUNET_NO;
  ports[0] = 1;
  ports[1] = 0;
  GNUNET_CADET_TEST_run ("cadet-profiler", config_file, peers_total,
                        &tmain, NULL, /* tmain cls */
                        &incoming_channel, &channel_cleaner,
                        handlers, ports);
  GNUNET_free (peers);

  return 0;
}

/* end of gnunet-cadet-profiler.c */

