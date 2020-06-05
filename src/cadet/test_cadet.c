/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file cadet/test_cadet.c
 * @author Bart Polot
 * @author Christian Grothoff
 * @brief Test for the cadet service using mq API.
 */
#include <stdio.h>
#include "platform.h"
#include "cadet.h"
#include "cadet_test_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"
#include <gauger.h>


/**
 * Ugly workaround to unify data handlers on incoming and outgoing channels.
 */
struct CadetTestChannelWrapper
{
  /**
   * Channel pointer.
   */
  struct GNUNET_CADET_Channel *ch;
};

/**
 * How many messages to send by default.
 */
#define TOTAL_PACKETS 500       /* Cannot exceed 64k! */

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait by default  for stuff that should be rather fast.
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

/**
 * How fast do we send messages?
 */
#define SEND_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MILLISECONDS, 10)

/**
 * DIFFERENT TESTS TO RUN
 */
#define SETUP 0
#define FORWARD 1
#define KEEPALIVE 2
#define SPEED 3
#define SPEED_ACK 4
#define SPEED_REL 8
#define P2P_SIGNAL 10
#define REOPEN 11
#define DESTROY 12

/**
 * Active peer listing operation.
 */
static struct GNUNET_CADET_PeersLister *plo;

/*
 * Task called to check for existing tunnel and depending on that reopen channel
 */
static struct GNUNET_SCHEDULER_Task *get_peers_task;

/**
 * Which test are we running?
 */
static int test;

/**
 * String with test name
 */
static char *test_name;

/**
 * Flag to send traffic leaf->root in speed tests to test BCK_ACK logic.
 */
static int test_backwards = GNUNET_NO;

/**
 * How many packets to send.
 */
static unsigned int total_packets;

/**
 * Time to wait for fast operations.
 */
static struct GNUNET_TIME_Relative short_time;

/**
 * How many events have happened
 */
static int ok;

/**
 * Number of events expected to conclude the test successfully.
 */
static int ok_goal;

/**
 * Size of each test packet's payload
 */
static size_t size_payload = sizeof(uint32_t);

/**
 * Operation to get peer ids.
 */
static struct GNUNET_TESTBED_Operation *t_op[2];

/**
 * Peer ids.
 */
static struct GNUNET_PeerIdentity *testpeer_id[2];

/**
 * Peer ids.
 */
static struct GNUNET_CONFIGURATION_Handle *p_cfg[2];

/**
 * Port ID
 */
static struct GNUNET_HashCode port;

/**
 * Peer ids counter.
 */
static unsigned int peerinfo_task_cnt;

/**
 * Is the setup initialized?
 */
static int initialized;

/**
 * Number of payload packes sent.
 */
static int data_sent;

/**
 * Number of payload packets received.
 */
static int data_received;

/**
 * Number of payload packed acknowledgements sent.
 */
static int ack_sent;

/**
 * Number of payload packed explicitly (app level) acknowledged.
 */
static int ack_received;

/**
 * Total number of peers asked to run.
 */
static unsigned long long peers_requested;

/**
 * Number of currently running peers (should be same as @c peers_requested).
 */
static unsigned long long peers_running;

/**
 * Test context (to shut down).
 */
struct GNUNET_CADET_TEST_Context *test_ctx;

/**
 * Task called to disconnect peers.
 */
static struct GNUNET_SCHEDULER_Task *disconnect_task;

/**
 * Task called to reconnect peers.
 */
static struct GNUNET_SCHEDULER_Task *reconnect_task;

/**
 * Task To perform tests
 */
static struct GNUNET_SCHEDULER_Task *test_task;

/**
 * Task runnining #send_next_msg().
 */
static struct GNUNET_SCHEDULER_Task *send_next_msg_task;

/**
 * Channel handle for the root peer
 */
static struct GNUNET_CADET_Channel *outgoing_ch;

/**
 * Channel handle for the dest peer
 */
static struct GNUNET_CADET_Channel *incoming_ch;

/**
 * Time we started the data transmission (after channel has been established
 * and initilized).
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Peers handle.
 */
static struct GNUNET_TESTBED_Peer **testbed_peers;


struct GNUNET_CADET_Handle **cadets_running;

/**
 * Statistics operation handle.
 */
static struct GNUNET_TESTBED_Operation *stats_op;

/**
 * Keepalives sent.
 */
static unsigned int ka_sent;

/**
 * Keepalives received.
 */
static unsigned int ka_received;

/**
 * How many messages were dropped by CADET because of full buffers?
 */
static unsigned int msg_dropped;

/**
 * Drop the next cadet message of a given type..
 *
 * @param mq message queue
 * @param ccn client channel number.
 * @param type of cadet message to be dropped.
 */
void
GNUNET_CADET_drop_message (struct GNUNET_MQ_Handle *mq,
                           struct GNUNET_CADET_ClientChannelNumber ccn,
                           uint16_t type);

/******************************************************************************/


/******************************************************************************/


/**
 * Get the channel considered as the "target" or "receiver", depending on
 * the test type and size.
 *
 * @return Channel handle of the target client, either 0 (for backward tests)
 *         or the last peer in the line (for other tests).
 */
static struct GNUNET_CADET_Channel *
get_target_channel ()
{
  if ((SPEED == test) && (GNUNET_YES == test_backwards))
    return outgoing_ch;
  else
    return incoming_ch;
}


/**
 * Show the results of the test (banwidth acheived) and log them to GAUGER
 */
static void
show_end_data (void)
{
  static struct GNUNET_TIME_Absolute end_time;
  static struct GNUNET_TIME_Relative total_time;

  end_time = GNUNET_TIME_absolute_get ();
  total_time = GNUNET_TIME_absolute_get_difference (start_time, end_time);
  fprintf (stderr,
           "\nResults of test \"%s\"\n",
           test_name);
  fprintf (stderr,
           "Test time %s\n",
           GNUNET_STRINGS_relative_time_to_string (total_time, GNUNET_YES));
  fprintf (stderr,
           "Test bandwidth: %f kb/s\n",
           4 * total_packets * 1.0 / (total_time.rel_value_us / 1000));    // 4bytes * ms
  fprintf (stderr,
           "Test throughput: %f packets/s\n\n",
           total_packets * 1000.0 / (total_time.rel_value_us / 1000));     // packets * ms
  GAUGER ("CADET",
          test_name,
          total_packets * 1000.0 / (total_time.rel_value_us / 1000),
          "packets/s");
}


/**
 * Disconnect from cadet services af all peers, call shutdown.
 *
 * @param cls Closure (line number from which termination was requested).
 * @param tc Task Context.
 */
static void
disconnect_cadet_peers (void *cls)
{
  long line = (long) cls;

  disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "disconnecting cadet service of peers, called from line %ld\n",
              line);
  for (unsigned int i = 0; i < 2; i++)
  {
    GNUNET_TESTBED_operation_done (t_op[i]);
  }
  if (NULL != outgoing_ch)
  {
    GNUNET_CADET_channel_destroy (outgoing_ch);
    outgoing_ch = NULL;
  }
  if (NULL != incoming_ch)
  {
    GNUNET_CADET_channel_destroy (incoming_ch);
    incoming_ch = NULL;
  }
  GNUNET_CADET_TEST_cleanup (test_ctx);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Shut down peergroup, clean up.
 *
 * @param cls Closure (unused).
 * @param tc Task Context.
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ending test.\n");
  if (NULL != send_next_msg_task)
  {
    GNUNET_SCHEDULER_cancel (send_next_msg_task);
    send_next_msg_task = NULL;
  }
  if (NULL != test_task)
  {
    GNUNET_SCHEDULER_cancel (test_task);
    test_task = NULL;
  }
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
      GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                (void *) __LINE__);
  }
}


/**
 * Stats callback. Finish the stats testbed operation and when all stats have
 * been iterated, shutdown the test.
 *
 * @param cls Closure (line number from which termination was requested).
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
stats_cont (void *cls,
            struct GNUNET_TESTBED_Operation *op,
            const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "KA sent: %u, KA received: %u\n",
              ka_sent,
              ka_received);
  if (((KEEPALIVE == test) || (REOPEN == test)) &&
      ((ka_sent < 2) || (ka_sent > ka_received + 1)))
  {
    GNUNET_break (0);
    ok--;
  }
  GNUNET_TESTBED_operation_done (stats_op);

  if (NULL != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                              cls);
}


/**
 * Process statistic values.
 *
 * @param cls closure (line number, unused)
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
stats_iterator (void *cls,
                const struct GNUNET_TESTBED_Peer *peer,
                const char *subsystem,
                const char *name,
                uint64_t value,
                int is_persistent)
{
  static const char *s_sent = "# keepalives sent";
  static const char *s_recv = "# keepalives received";
  static const char *rdrops = "# messages dropped due to full buffer";
  static const char *cdrops = "# messages dropped due to slow client";
  uint32_t i;

  i = GNUNET_TESTBED_get_index (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "STATS PEER %u - %s [%s]: %llu\n", i,
              subsystem, name, (unsigned long long) value);
  if ((0 == strncmp (s_sent, name, strlen (s_sent))) && (0 == i))
    ka_sent = value;
  if ((0 == strncmp (s_recv, name, strlen (s_recv))) && (peers_requested - 1 ==
                                                         i) )
    ka_received = value;
  if (0 == strncmp (rdrops, name, strlen (rdrops)))
    msg_dropped += value;
  if (0 == strncmp (cdrops, name, strlen (cdrops)))
    msg_dropped += value;

  return GNUNET_OK;
}


/**
 * Task to gather all statistics.
 *
 * @param cls Closure (line from which the task was scheduled).
 */
static void
gather_stats_and_exit (void *cls)
{
  long l = (long) cls;

  disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "gathering statistics from line %ld\n",
              l);
  if (NULL != outgoing_ch)
  {
    GNUNET_CADET_channel_destroy (outgoing_ch);
    outgoing_ch = NULL;
  }
  stats_op = GNUNET_TESTBED_get_statistics (peers_running,
                                            testbed_peers,
                                            "cadet",
                                            NULL,
                                            &stats_iterator,
                                            stats_cont,
                                            cls);
}


/**
 * Send a message on the channel with the appropriate size and payload.
 *
 * Update the appropriate *_sent counter.
 *
 * @param channel Channel to send the message on.
 */
static void
send_test_message (struct GNUNET_CADET_Channel *channel);

/**
 * Check if payload is sane (size contains payload).
 *
 * @param cls should match #ch
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
check_data (void *cls,
            const struct GNUNET_MessageHeader *message);

/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_CADET_connect(), peer number)
 * @param message the actual message
 */
static void
handle_data (void *cls,
             const struct GNUNET_MessageHeader *message);

/**
 * Function called whenever an MQ-channel is destroyed, unless the destruction
 * was requested by #GNUNET_CADET_channel_destroy.
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * It should clean up any associated state, including cancelling any pending
 * transmission on this channel.
 *
 * @param cls Channel closure (channel wrapper).
 * @param channel Connection to the other end (henceforth invalid).
 */
static void
disconnect_handler (void *cls,
                    const struct GNUNET_CADET_Channel *channel);

static struct GNUNET_PeerIdentity *
get_from_p_ids ()
{
  if (0 < GNUNET_memcmp (testpeer_id[0], testpeer_id[1]))
  {
    return testpeer_id[1];
  }
  else
  {
    return testpeer_id[0];
  }
}

static struct GNUNET_CADET_Handle *
get_from_cadets ()
{

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "1\n");
  if (0 < GNUNET_memcmp (testpeer_id[0], testpeer_id[1]))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "standard peer\n");
    return cadets_running[0];
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "the other peer\n");
    return cadets_running[peers_running - 1];
  }

}

static unsigned int
get_peer_nr (int outgoing)
{
  if (0 < GNUNET_memcmp (testpeer_id[0], testpeer_id[1]))
  {
    return GNUNET_YES == outgoing ? 0 : peers_running - 1;
  }
  else
  {
    return GNUNET_YES == outgoing ? peers_running - 1 : 0;
  }
}

/**
 * Task to reconnect to other peer.
 *
 * @param cls Closure (line from which the task was scheduled).
 */
static void
reconnect_op (void *cls)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  long l = (long) cls;
  struct CadetTestChannelWrapper *ch;
  static struct GNUNET_PeerIdentity *p_id;
  static struct GNUNET_CADET_Handle *h1;

  reconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "reconnecting from line %ld\n",
              l);
  if (NULL != outgoing_ch)
  {
    GNUNET_CADET_channel_destroy (outgoing_ch);
    outgoing_ch = NULL;
  }
  ch = GNUNET_new (struct CadetTestChannelWrapper);

  p_id = get_from_p_ids ();
  h1 = get_from_cadets ();

  outgoing_ch = GNUNET_CADET_channel_create (h1,
                                             ch,
                                             p_id,
                                             &port,
                                             NULL,
                                             &disconnect_handler,
                                             handlers);
  ch->ch = outgoing_ch;
  send_test_message (outgoing_ch);
}

void
reopen_channel ()
{
  struct CadetTestChannelWrapper *ch;
  static struct GNUNET_CADET_Handle *h1;
  static struct GNUNET_PeerIdentity *p_id;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "creating channel again\n");
  p_id = get_from_p_ids ();
  h1 = get_from_cadets ();

  ch = GNUNET_new (struct CadetTestChannelWrapper);
  outgoing_ch = GNUNET_CADET_channel_create (h1,
                                             ch,
                                             p_id,
                                             &port,
                                             NULL,
                                             &disconnect_handler,
                                             handlers);
  ch->ch = outgoing_ch;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending second test data (after destroying the channel) on channel %p...\n",
              outgoing_ch);
  send_test_message (outgoing_ch);
}

static void
peers_callback (void *cls, const struct GNUNET_CADET_PeerListEntry *ple);

/**
 * We ask the monitoring api for all the peers.
 */
static void
get_peers (void *cls)
{

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "requesting peers info!\n");
  plo = GNUNET_CADET_list_peers (p_cfg[get_peer_nr (GNUNET_YES)],
                                 &peers_callback, NULL);

}

/**
 * Method called to retrieve information about all peers in CADET, called
 * once per peer.
 *
 * After last peer has been reported, an additional call with NULL is done.
 *
 * We check the peer we are interested in, if we have a tunnel. If not, we
 * reopen the channel
 *
 * @param cls Closure.
 * @param ple information about peer, or NULL on "EOF".
 */
static void
peers_callback (void *cls, const struct GNUNET_CADET_PeerListEntry *ple)
{

  const struct GNUNET_PeerIdentity *p_id;
  const struct GNUNET_PeerIdentity *peer;


  peer = &ple->peer;

  if (NULL == ple)
  {
    plo = NULL;
    return;
  }
  p_id = get_from_p_ids ();

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "ple->peer %s\n",
              GNUNET_i2s_full (&ple->peer));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "p_id %s\n",
              GNUNET_i2s_full (p_id));

  if ((0 == GNUNET_memcmp (&ple->peer, p_id))&& ple->have_tunnel)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "schedule get_peers again?\n");
    get_peers_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                   &get_peers,
                                                   NULL);

  }
  else if (0 == GNUNET_memcmp (&ple->peer, p_id) )
  {

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "reopen channel\n");

    reopen_channel ();

  }
}

/**
 * Function called whenever an MQ-channel is destroyed, unless the destruction
 * was requested by #GNUNET_CADET_channel_destroy.
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * It should clean up any associated state, including cancelling any pending
 * transmission on this channel.
 *
 * @param cls Channel closure (channel wrapper).
 * @param channel Connection to the other end (henceforth invalid).
 */
static void
disconnect_handler (void *cls,
                    const struct GNUNET_CADET_Channel *channel)
{
  struct CadetTestChannelWrapper *ch_w = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Channel disconnected at ok=%d\n",
              ok);
  GNUNET_assert (ch_w->ch == channel);

  if ((DESTROY == test) && (3 == ok))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Reopen channel task!\n");
    if (NULL == get_peers_task)
    {
      get_peers_task = GNUNET_SCHEDULER_add_now (&get_peers,
                                                 NULL);
    }
    return;
  }

  if (channel == incoming_ch)
  {
    ok++;
    incoming_ch = NULL;
  }
  else if (outgoing_ch == channel)
  {
    if (P2P_SIGNAL == test)
    {
      ok++;
    }
    outgoing_ch = NULL;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unknown channel! %p\n",
                channel);
  if ((NULL != disconnect_task) && (REOPEN != test))
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task =
      GNUNET_SCHEDULER_add_now (&gather_stats_and_exit,
                                (void *) __LINE__);
  }
  else if ((NULL != reconnect_task) && (REOPEN == test))
  {
    GNUNET_SCHEDULER_cancel (reconnect_task);
    reconnect_task =
      GNUNET_SCHEDULER_add_now (&reconnect_op,
                                (void *) __LINE__);
  }
  GNUNET_free (ch_w);
}


/**
 * Abort test: schedule disconnect and shutdown immediately
 *
 * @param line Line in the code the abort is requested from (__LINE__).
 */
static void
abort_test (long line)
{
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Aborting test from %ld\n",
                line);
    disconnect_task =
      GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                (void *) line);
  }
}


/**
 * Send a message on the channel with the appropriate size and payload.
 *
 * Update the appropriate *_sent counter.
 *
 * @param channel Channel to send the message on.
 */
static void
send_test_message (struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  uint32_t *data;
  int payload;
  int size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending test message on channel %u\n",
              channel->ccn.channel_of_client);
  size = size_payload;
  if (GNUNET_NO == initialized)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending INITIALIZER\n");
    size += 1000;
    payload = data_sent;
    if (SPEED_ACK == test)   // FIXME unify SPEED_ACK with an initializer
      data_sent++;
  }
  else if ((SPEED == test) || (SPEED_ACK == test))
  {
    if (get_target_channel () == channel)
    {
      payload = ack_sent;
      size += ack_sent;
      ack_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending ACK %u [%d bytes]\n",
                  payload, size);
    }
    else
    {
      payload = data_sent;
      size += data_sent;
      data_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending DATA %u [%d bytes]\n",
                  data_sent, size);
    }
  }
  else if (FORWARD == test)
  {
    payload = ack_sent;
  }
  else if (P2P_SIGNAL == test)
  {
    payload = data_sent;
  }
  else if (REOPEN == test)
  {
    payload = data_sent;
    data_sent++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending DATA %u [%d bytes]\n",
                data_sent, size);
  }
  else if (DESTROY == test)
  {
    payload = data_sent;
  }
  else
  {
    GNUNET_assert (0);
  }
  env = GNUNET_MQ_msg_extra (msg, size, GNUNET_MESSAGE_TYPE_DUMMY);

  data = (uint32_t *) &msg[1];
  *data = htonl (payload);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (channel), env);
}


/**
 * Task to request a new data transmission in a SPEED test, without waiting
 * for previous messages to be sent/arrrive.
 *
 * @param cls Closure (unused).
 */
static void
send_next_msg (void *cls)
{
  struct GNUNET_CADET_Channel *channel;

  send_next_msg_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending next message: %d\n",
              data_sent);

  channel = GNUNET_YES == test_backwards ? incoming_ch : outgoing_ch;
  GNUNET_assert (NULL != channel);
  GNUNET_assert (SPEED == test);
  send_test_message (channel);
  if (data_sent < total_packets)
  {
    /* SPEED test: Send all messages as soon as possible */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Scheduling message %d\n",
                data_sent + 1);
    send_next_msg_task =
      GNUNET_SCHEDULER_add_delayed (SEND_INTERVAL,
                                    &send_next_msg,
                                    NULL);
  }
}


/**
 * Every few messages cancel the timeout task and re-schedule it again, to
 * avoid timing out when traffic keeps coming.
 *
 * @param line Code line number to log if a timeout occurs.
 */
static void
reschedule_timeout_task (long line)
{
  if ((ok % 10) == 0)
  {
    if (NULL != disconnect_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "reschedule timeout every 10 messages\n");
      GNUNET_SCHEDULER_cancel (disconnect_task);
      disconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                      &gather_stats_and_exit,
                                                      (void *) line);
    }
  }
}


/**
 * Check if payload is sane (size contains payload).
 *
 * @param cls should match #ch
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
check_data (void *cls,
            const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;             /* all is well-formed */
}


/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_CADET_connect(), peer number)
 * @param message the actual message
 */
static void
handle_data (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  struct CadetTestChannelWrapper *ch = cls;
  struct GNUNET_CADET_Channel *channel = ch->ch;
  uint32_t *data;
  uint32_t payload;
  int *counter;

  ok++;
  GNUNET_CADET_receive_done (channel);
  counter = get_target_channel () == channel ? &data_received : &ack_received;

  reschedule_timeout_task ((long) __LINE__);

  if (channel == outgoing_ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Root client got a message.\n");
  }
  else if (channel == incoming_ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Leaf client got a message.\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown channel %p.\n",
                channel);
    GNUNET_assert (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "handle_data ok: (%d/%d)\n",
              ok,
              ok_goal);
  data = (uint32_t *) &message[1];
  payload = ntohl (*data);
  if (payload == *counter)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                " payload as expected: %u\n",
                payload);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                " payload %u, expected: %u\n",
                payload, *counter);
  }

  if (DESTROY == test)
  {
    if (2 == ok)
    {
      ok++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "dropping message ok: (%d/%d)\n",
                  ok,
                  ok_goal);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "TEST ID 0: %s\n",
                  GNUNET_i2s (testpeer_id[0]));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "TEST ID 1: %s\n",
                  GNUNET_i2s (testpeer_id[1]));

      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "dropping message\n");
      GNUNET_CADET_drop_message (GNUNET_CADET_get_mq (outgoing_ch),
                                 outgoing_ch->ccn,
                                 GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
      if (NULL != outgoing_ch)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Destroying channel %p...\n",
                    outgoing_ch);
        GNUNET_CADET_channel_destroy (outgoing_ch);
        outgoing_ch = NULL;
      }
    }
    else if (5 == ok)
    {
      ok++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "destroy test finished ok: (%d/%d)\n",
                  ok,
                  ok_goal);
      disconnect_task =
        GNUNET_SCHEDULER_add_now (&gather_stats_and_exit,
                                  (void *) __LINE__);
      // End of DESTROY test.
    }
  }

  if (GNUNET_NO == initialized)
  {
    initialized = GNUNET_YES;
    start_time = GNUNET_TIME_absolute_get ();
    if (SPEED == test)
    {
      GNUNET_assert (incoming_ch == channel);
      send_next_msg_task = GNUNET_SCHEDULER_add_now (&send_next_msg,
                                                     NULL);
      return;
    }
  }

  (*counter)++;
  if (get_target_channel () == channel)  /* Got "data" */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " received data %u\n", data_received);
    if ((DESTROY != test) && ((SPEED != test) || ( (ok_goal - 2) == ok)) )
    {
      /* Send ACK */
      send_test_message (channel);
      return;
    }
    else
    {
      if (data_received < total_packets)
        return;
    }
  }
  else /* Got "ack" */
  {
    if ((SPEED_ACK == test) || (SPEED == test) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, " received ack %u\n", ack_received);
      /* Send more data */
      send_test_message (channel);
      if ((ack_received < total_packets) && (SPEED != test) )
        return;
      if ((ok == 2) && (SPEED == test) )
        return;
      show_end_data ();
    }
    if (test == P2P_SIGNAL)
    {
      GNUNET_CADET_channel_destroy (incoming_ch);
      incoming_ch = NULL;
    }
    else
    {
      GNUNET_CADET_channel_destroy (outgoing_ch);
      outgoing_ch = NULL;
    }
  }
}


/**
 * Method called whenever a peer connects to a port in MQ-based CADET.
 *
 * @param cls Closure from #GNUNET_CADET_open_port (peer # as long).
 * @param channel New handle to the channel.
 * @param source Peer that started this channel.
 * @return Closure for the incoming @a channel. It's given to:
 *         - The #GNUNET_CADET_DisconnectEventHandler (given to
 *           #GNUNET_CADET_open_port) when the channel dies.
 *         - Each the #GNUNET_MQ_MessageCallback handlers for each message
 *           received on the @a channel.
 */
static void *
connect_handler (void *cls,
                 struct GNUNET_CADET_Channel *channel,
                 const struct GNUNET_PeerIdentity *source)
{
  struct CadetTestChannelWrapper *ch;
  long peer = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel from %s to %ld: %p\n",
              GNUNET_i2s (source),
              peer,
              channel);
  ok++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "connect_handler ok: (%d/%d)\n",
              ok,
              ok_goal);

  if (peer == get_peer_nr (GNUNET_NO))
  {
    if ((DESTROY != test)&&(NULL != incoming_ch))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Duplicate incoming channel for client %lu\n",
                  (long) cls);
      GNUNET_assert (0);
    }
    incoming_ch = channel;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming channel for unexpected peer #%lu\n",
                (long) cls);
    GNUNET_assert (0);
  }
  if ((NULL != disconnect_task) && (REOPEN != test) && (DESTROY != test))
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                    &gather_stats_and_exit,
                                                    (void *) __LINE__);
  }
  else if ((NULL != disconnect_task) && (REOPEN == test))
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (short_time, 2),
      &gather_stats_and_exit,
      (void *) __LINE__);
  }

  if ((NULL != reconnect_task) && (REOPEN == test))
  {
    GNUNET_SCHEDULER_cancel (reconnect_task);
    reconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                   &reconnect_op,
                                                   (void *) __LINE__);
  }


  /* TODO: cannot return channel as-is, in order to unify the data handlers */
  ch = GNUNET_new (struct CadetTestChannelWrapper);
  ch->ch = channel;

  return ch;
}


/**
 * START THE TESTCASE ITSELF, AS WE ARE CONNECTED TO THE CADET SERVICES.
 *
 * Testcase continues when the root receives confirmation of connected peers,
 * on callback function ch.
 *
 * @param cls Closure (unused).
 */
static void
start_test (void *cls)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct CadetTestChannelWrapper *ch;
  static struct GNUNET_CADET_Handle *h1;
  static struct GNUNET_PeerIdentity *p_id;

  test_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "start_test: %s\n", test_name);
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = NULL;
  }

  if (SPEED_REL == test)
  {
    test = SPEED;
  }

  p_id = get_from_p_ids ();
  h1 = get_from_cadets ();

  ch = GNUNET_new (struct CadetTestChannelWrapper);
  outgoing_ch = GNUNET_CADET_channel_create (h1,
                                             ch,
                                             p_id,
                                             &port,
                                             NULL,
                                             &disconnect_handler,
                                             handlers);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "channel created\n");

  ch->ch = outgoing_ch;

  if (DESTROY != test)
    disconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                    &gather_stats_and_exit,
                                                    (void *) __LINE__);
  if (KEEPALIVE == test)
    return;                     /* Don't send any data. */

  data_received = 0;
  data_sent = 0;
  ack_received = 0;
  ack_sent = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending data initializer on channel %p...\n",
              outgoing_ch);
  send_test_message (outgoing_ch);
  if (REOPEN == test)
  {
    reconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                   &reconnect_op,
                                                   (void *) __LINE__);
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (short_time, 2),
      &gather_stats_and_exit,
      (void *) __LINE__);
  }
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cls the closure from GNUNET_TESTBED_peer_getinformation()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed;
 *             NULL if the operation is successfull
 */
static void
pi_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  long i = (long) cls;

  if ((NULL == pinfo) ||
      (NULL != emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "pi_cb: %s\n",
                emsg);
    abort_test (__LINE__);
    return;
  }

  if (GNUNET_TESTBED_PIT_IDENTITY == pinfo->pit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ID callback for %ld\n",
                i);
    testpeer_id[i] = pinfo->result.id;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "id: %s\n",
                GNUNET_i2s (testpeer_id[i]));
  }
  else if (GNUNET_TESTBED_PIT_CONFIGURATION == pinfo->pit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "CFG callback for %ld\n",
                i);
    p_cfg[i] = pinfo->result.cfg;
  }
  else
  {
    GNUNET_break (0);
  }

  peerinfo_task_cnt++;
  if (peerinfo_task_cnt < 4)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got all peer information, starting test\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TEST ID 0: %s\n",
              GNUNET_i2s (testpeer_id[0]));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TEST ID 1: %s\n",
              GNUNET_i2s (testpeer_id[1]));
  test_task = GNUNET_SCHEDULER_add_now (&start_test, NULL);
}


/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_CADET_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param cadets Handle to each of the CADETs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_CADET_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **peers,
       struct GNUNET_CADET_Handle **cadets)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test main\n");
  ok = 0;
  test_ctx = ctx;
  peers_running = num_peers;
  GNUNET_assert (peers_running == peers_requested);
  testbed_peers = peers;
  cadets_running = cadets;

  disconnect_task = GNUNET_SCHEDULER_add_delayed (short_time,
                                                  &disconnect_cadet_peers,
                                                  (void *) __LINE__);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  t_op[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb,
                                                 (void *) 0L);
  t_op[1] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 1],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb,
                                                 (void *) 1L);
  t_op[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                 GNUNET_TESTBED_PIT_CONFIGURATION,
                                                 &pi_cb,
                                                 (void *) 0L);
  t_op[1] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 1],
                                                 GNUNET_TESTBED_PIT_CONFIGURATION,
                                                 &pi_cb,
                                                 (void *) 1L);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requested peer ids\n");
}


/**
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  static const struct GNUNET_HashCode *ports[2];
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  const char *config_file;
  char port_id[] = "test port";
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_relative_time ('t',
                                        "time",
                                        "short_time",
                                        gettext_noop ("set short timeout"),
                                        &short_time),
    GNUNET_GETOPT_option_uint ('m',
                               "messages",
                               "NUM_MESSAGES",
                               gettext_noop ("set number of messages to send"),
                               &total_packets),

    GNUNET_GETOPT_OPTION_END
  };


  initialized = GNUNET_NO;
  GNUNET_log_setup ("test", "DEBUG", NULL);

  total_packets = TOTAL_PACKETS;
  short_time = SHORT_TIME;
  if (-1 == GNUNET_GETOPT_run (argv[0], options, argc, argv))
  {
    fprintf (stderr, "test failed: problem with CLI parameters\n");
    exit (1);
  }

  config_file = "test_cadet.conf";
  GNUNET_CRYPTO_hash (port_id, sizeof(port_id), &port);

  /* Find out requested size */
  if (strstr (argv[0], "_2_") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DIRECT CONNECTIONs\n");
    peers_requested = 2;
  }
  else if (strstr (argv[0], "_5_") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "5 PEER LINE\n");
    peers_requested = 5;
  }
  else if (strstr (argv[0], "_6_") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "6 PEER LINE\n");
    peers_requested = 6;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "SIZE UNKNOWN, USING 2\n");
    peers_requested = 2;
  }

  /* Find out requested test */
  if (strstr (argv[0], "_forward") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "FORWARD\n");
    test = FORWARD;
    test_name = "unicast";
    ok_goal = 4;
  }
  else if (strstr (argv[0], "_signal") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SIGNAL\n");
    test = P2P_SIGNAL;
    test_name = "signal";
    ok_goal = 4;
  }
  else if (strstr (argv[0], "_speed_ack") != NULL)
  {
    /* Test is supposed to generate the following callbacks:
     * 1 incoming channel (@dest)
     * total_packets received data packet (@dest)
     * total_packets received data packet (@orig)
     * 1 received channel destroy (@dest) FIXME #5818
     */ok_goal = total_packets * 2 + 2;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED_ACK\n");
    test = SPEED_ACK;
    test_name = "speed ack";
  }
  else if (strstr (argv[0], "_speed") != NULL)
  {
    /* Test is supposed to generate the following callbacks:
     * 1 incoming channel (@dest)
     * 1 initial packet (@dest)
     * total_packets received data packet (@dest)
     * 1 received data packet (@orig)
     * 1 received channel destroy (@dest)  FIXME #5818
     */ok_goal = total_packets + 4;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED\n");
    if (strstr (argv[0], "_reliable") != NULL)
    {
      test = SPEED_REL;
      test_name = "speed reliable";
      config_file = "test_cadet_drop.conf";
    }
    else
    {
      test = SPEED;
      test_name = "speed";
    }
  }
  else if (strstr (argv[0], "_keepalive") != NULL)
  {
    test = KEEPALIVE;
    test_name = "keepalive";
    /* Test is supposed to generate the following callbacks:
     * 1 incoming channel (@dest)
     * [wait]
     * 1 received channel destroy (@dest)  FIXME #5818
     */ok_goal = 1;
  }
  else if (strstr (argv[0], "_reopen") != NULL)
  {
    test = REOPEN;
    test_name = "reopen";
    ///* Test is supposed to generate the following callbacks:
    // * 1 incoming channel (@dest)
    // * [wait]
    // * 1 received channel destroy (@dest)  FIXME #5818
    // */
    ok_goal = 6;
  }
  else if (strstr (argv[0], "_destroy") != NULL)
  {
    test = DESTROY;
    test_name = "destroy";
    ok_goal = 6;
    short_time = GNUNET_TIME_relative_multiply (short_time, 5);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "UNKNOWN\n");
    test = SETUP;
    ok_goal = 0;
  }

  if (strstr (argv[0], "backwards") != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "BACKWARDS (LEAF TO ROOT)\n");
    test_backwards = GNUNET_YES;
    GNUNET_asprintf (&test_name, "backwards %s", test_name);
  }

  peerinfo_task_cnt = 0;
  ports[0] = &port;
  ports[1] = NULL;
  GNUNET_CADET_TEST_ruN ("test_cadet_small",
                         config_file,
                         peers_requested,
                         &tmain,
                         NULL,        /* tmain cls */
                         &connect_handler,
                         NULL,
                         &disconnect_handler,
                         handlers,
                         ports);
  if (NULL != strstr (argv[0], "_reliable"))
    msg_dropped = 0;            /* dropped should be retransmitted */

  if (ok_goal > ok - msg_dropped)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "FAILED! (%d/%d)\n", ok, ok_goal);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}


/* end of test_cadet.c */
