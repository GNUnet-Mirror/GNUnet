/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

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
 * @file cadet/test_cadet.c
 *
 * @brief Test for the cadet service: retransmission of traffic.
 */
#include <stdio.h>
#include "platform.h"
#include "cadet_test_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"
#include <gauger.h>


/**
 * How many messages to send
 */
#define TOTAL_PACKETS 500 /* Cannot exceed 64k! */

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
#define FORWARD 1
#define KEEPALIVE 2
#define SPEED 3
#define SPEED_ACK 4
#define SPEED_REL 8
#define P2P_SIGNAL 10

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
static size_t size_payload = sizeof (struct GNUNET_MessageHeader) + sizeof (uint32_t);

/**
 * Operation to get peer ids.
 */
static struct GNUNET_TESTBED_Operation *t_op[2];

/**
 * Peer ids.
 */
static struct GNUNET_PeerIdentity *p_id[2];

/**
 * Port ID
 */
static struct GNUNET_HashCode port;

/**
 * Peer ids counter.
 */
static unsigned int p_ids;

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
 * Task To perform tests
 */
static struct GNUNET_SCHEDULER_Task *test_task;

/**
 * Task runnining #data_task().
 */
static struct GNUNET_SCHEDULER_Task *data_job;

/**
 * Cadet handle for the root peer
 */
static struct GNUNET_CADET_Handle *h1;

/**
 * Cadet handle for the first leaf peer
 */
static struct GNUNET_CADET_Handle *h2;

/**
 * Channel handle for the root peer
 */
static struct GNUNET_CADET_Channel *ch;

/**
 * Channel handle for the dest peer
 */
static struct GNUNET_CADET_Channel *incoming_ch;

/**
 * Transmit handle for root data calls
 */
static struct GNUNET_CADET_TransmitHandle *th;

/**
 * Transmit handle for root data calls
 */
static struct GNUNET_CADET_TransmitHandle *incoming_th;


/**
 * Time we started the data transmission (after channel has been established
 * and initilized).
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Peers handle.
 */
static struct GNUNET_TESTBED_Peer **testbed_peers;

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
 * Get the client number considered as the "target" or "receiver", depending on
 * the test type and size.
 *
 * @return Peer # of the target client, either 0 (for backward tests) or
 *         the last peer in the line (for other tests).
 */
static unsigned int
get_expected_target ()
{
  if (SPEED == test && GNUNET_YES == test_backwards)
    return 0;
  else
    return peers_requested - 1;
}


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
  FPRINTF (stderr, "Test time %s\n",
	   GNUNET_STRINGS_relative_time_to_string (total_time,
						   GNUNET_YES));
  FPRINTF (stderr, "Test bandwidth: %f kb/s\n",
	   4 * TOTAL_PACKETS * 1.0 / (total_time.rel_value_us / 1000)); // 4bytes * ms
  FPRINTF (stderr, "Test throughput: %f packets/s\n\n",
	   TOTAL_PACKETS * 1000.0 / (total_time.rel_value_us / 1000)); // packets * ms
  GAUGER ("CADET", test_name,
          TOTAL_PACKETS * 1000.0 / (total_time.rel_value_us / 1000),
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
  unsigned int i;

  disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "disconnecting cadet service of peers, called from line %ld\n",
	      line);
  for (i = 0; i < 2; i++)
  {
    GNUNET_TESTBED_operation_done (t_op[i]);
  }
  if (NULL != ch)
  {
    if (NULL != th)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (th);
      th = NULL;
    }
    GNUNET_CADET_channel_destroy (ch);
    ch = NULL;
  }
  if (NULL != incoming_ch)
  {
    if (NULL != incoming_th)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (incoming_th);
      incoming_th = NULL;
    }
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");
  if (NULL != data_job)
  {
    GNUNET_SCHEDULER_cancel (data_job);
    data_job = NULL;
  }
  if (NULL != test_task)
  {
    GNUNET_SCHEDULER_cancel (test_task);
    test_task = NULL;
  }
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
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
stats_cont (void *cls, struct GNUNET_TESTBED_Operation *op, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              " KA sent: %u, KA received: %u\n",
              ka_sent, ka_received);
  if ( (KEEPALIVE == test) &&
       ( (ka_sent < 2) ||
         (ka_sent > ka_received + 1)) )
    ok--;
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
  uint32_t i;

  i = GNUNET_TESTBED_get_index (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STATS PEER %u - %s [%s]: %llu\n",
              i,
              subsystem,
              name,
              (unsigned long long) value);
  if (0 == strncmp (s_sent, name, strlen (s_sent)) && 0 == i)
    ka_sent = value;

  if (0 == strncmp(s_recv, name, strlen (s_recv)) && peers_requested - 1 == i)
    ka_received = value;

  return GNUNET_OK;
}


/**
 * Task to gather all statistics.
 *
 * @param cls Closure (NULL).
 */
static void
gather_stats_and_exit (void *cls)
{
  long l = (long) cls;

  disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "gathering statistics from line %d\n",
	      (int) l);
  if (NULL != ch)
  {
    if (NULL != th)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (th);
      th = NULL;
    }
    GNUNET_CADET_channel_destroy (ch);
    ch = NULL;
  }
  stats_op = GNUNET_TESTBED_get_statistics (peers_running, testbed_peers,
                                            "cadet", NULL,
                                            stats_iterator, stats_cont, cls);
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
                "Aborting test from %ld\n", line);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                                (void *) line);
  }
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
 * Task to request a new data transmission.
 *
 * @param cls Closure (peer #).
 */
static void
data_task (void *cls)
{
  struct GNUNET_CADET_Channel *channel;
  static struct GNUNET_CADET_TransmitHandle **pth;
  long src;

  data_job = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Data task\n");
  if (GNUNET_YES == test_backwards)
  {
    channel = incoming_ch;
    pth = &incoming_th;
    src = peers_requested - 1;
  }
  else
  {
    channel = ch;
    pth = &th;
    src = 0;
  }

  GNUNET_assert (NULL != channel);
  GNUNET_assert (NULL == *pth);

  *pth = GNUNET_CADET_notify_transmit_ready (channel, GNUNET_NO,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             size_payload + data_sent,
                                             &tmt_rdy, (void *) src);
  if (NULL == *pth)
  {
    unsigned long i = (unsigned long) cls;

    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Retransmission\n");
    if (0 == i)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  in 1 ms\n");
      data_job = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
					       &data_task, (void *) 1L);
    }
    else
    {
      i++;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "in %llu ms\n",
                  (unsigned long long) i);
      data_job = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
									      i),
					       &data_task, (void *) i);
    }
  }
}


/**
 * Transmit ready callback
 *
 * @param cls Closure (peer # which is sending the data).
 * @param size Size of the buffer we have.
 * @param buf Buffer to copy data to.
 */
static size_t
tmt_rdy (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = buf;
  size_t msg_size;
  uint32_t *data;
  long id = (long) cls;
  unsigned int counter;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "tmt_rdy on %ld, filling buffer\n",
              id);
  if (0 == id)
    th = NULL;
  else if ((peers_requested - 1) == id)
    incoming_th = NULL;
  else
    GNUNET_assert (0);
  counter = get_expected_target () == id ? ack_sent : data_sent;
  msg_size = size_payload + counter;
  GNUNET_assert (msg_size > sizeof (struct GNUNET_MessageHeader));
  if ( (size < msg_size) ||
       (NULL == buf) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "size %u, buf %p, data_sent %u, ack_received %u\n",
                (unsigned int) size,
                buf,
                data_sent,
                ack_received);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ok %u, ok goal %u\n", ok, ok_goal);
    GNUNET_break (ok >= ok_goal - 2);

    return 0;
  }
  msg->size = htons (msg_size);
  msg->type = htons (GNUNET_MESSAGE_TYPE_DUMMY);
  data = (uint32_t *) &msg[1];
  *data = htonl (counter);
  if (GNUNET_NO == initialized)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending initializer\n");
    msg_size = size_payload + 1000;
    msg->size = htons (msg_size);
  if (SPEED_ACK == test)
      data_sent++;
  }
  else if ( (SPEED == test) ||
            (SPEED_ACK == test) )
  {
    if (get_expected_target() == id)
      ack_sent++;
    else
      data_sent++;
    counter++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                " Sent message %u size %u\n",
                counter,
                (unsigned int) msg_size);
    if ( (data_sent < TOTAL_PACKETS) &&
         (SPEED == test) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " Scheduling message %d\n",
                  counter + 1);
      data_job = GNUNET_SCHEDULER_add_now (&data_task, NULL);
    }
  }

  return msg_size;
}


/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_CADET_connect(), peer number)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
data_callback (void *cls,
               struct GNUNET_CADET_Channel *channel,
               void **channel_ctx,
               const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_TransmitHandle **pth;
  long client = (long) cls;
  long expected_target_client;
  uint32_t *data;
  uint32_t payload;
  unsigned int counter;

  ok++;
  counter = get_expected_target () == client ? data_received : ack_received;

  GNUNET_CADET_receive_done (channel);

  if ((ok % 10) == 0)
  {
    if (NULL != disconnect_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  " reschedule timeout\n");
      GNUNET_SCHEDULER_cancel (disconnect_task);
      disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                      &gather_stats_and_exit,
                                                      (void *) __LINE__);
    }
  }

  switch (client)
  {
  case 0L:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Root client got a message!\n");
    GNUNET_assert (channel == ch);
    pth = &th;
    break;
  case 1L:
  case 4L:
    GNUNET_assert (client == peers_requested - 1);
    GNUNET_assert (channel == incoming_ch);
    pth = &incoming_th;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Leaf client %ld got a message.\n",
                client);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Client %ld not valid.\n", client);
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: (%d/%d)\n", ok, ok_goal);
  data = (uint32_t *) &message[1];
  payload = ntohl (*data);
  if (payload == counter)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " payload as expected: %u\n", payload);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, " payload %u, expected: %u\n",
                payload, counter);
  }
  expected_target_client = get_expected_target ();

  if (GNUNET_NO == initialized)
  {
    initialized = GNUNET_YES;
    start_time = GNUNET_TIME_absolute_get ();
    if (SPEED == test)
    {
      GNUNET_assert (peers_requested - 1 == client);
      data_job = GNUNET_SCHEDULER_add_now (&data_task, NULL);
      return GNUNET_OK;
    }
  }

  counter++;
  if (client == expected_target_client) /* Normally 4 */
  {
    data_received++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, " received data %u\n", data_received);
    if (SPEED != test || (ok_goal - 2) == ok)
    {
      /* Send ACK */
      GNUNET_assert (NULL == *pth);
      *pth = GNUNET_CADET_notify_transmit_ready (channel, GNUNET_NO,
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 size_payload + ack_sent,
                                                 &tmt_rdy, (void *) client);
      return GNUNET_OK;
    }
    else
    {
      if (data_received < TOTAL_PACKETS)
        return GNUNET_OK;
    }
  }
  else /* Normally 0 */
  {
    if (SPEED_ACK == test || SPEED == test)
    {
      ack_received++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, " received ack %u\n", ack_received);
      /* send more data */
      GNUNET_assert (NULL == *pth);
      *pth = GNUNET_CADET_notify_transmit_ready (channel, GNUNET_NO,
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 size_payload + data_sent,
                                                 &tmt_rdy, (void *) client);
      if (ack_received < TOTAL_PACKETS && SPEED != test)
        return GNUNET_OK;
      if (ok == 2 && SPEED == test)
        return GNUNET_OK;
      show_end_data();
    }
    if (test == P2P_SIGNAL)
    {
      if (NULL != incoming_th)
      {
        GNUNET_CADET_notify_transmit_ready_cancel (incoming_th);
        incoming_th = NULL;
      }
      GNUNET_CADET_channel_destroy (incoming_ch);
      incoming_ch = NULL;
    }
    else
    {
      if (NULL != th)
      {
        GNUNET_CADET_notify_transmit_ready_cancel (th);
        th = NULL;
      }
      GNUNET_CADET_channel_destroy (ch);
      ch = NULL;
    }
  }

  return GNUNET_OK;
}


/**
 * Data handlers for every message type of CADET's payload.
 * {callback_function, message_type, size_expected}
 */
static struct GNUNET_CADET_MessageHandler handlers[] = {
  {&data_callback,
   GNUNET_MESSAGE_TYPE_DUMMY,
   sizeof (struct GNUNET_MessageHeader)},
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
incoming_channel (void *cls,
                  struct GNUNET_CADET_Channel *channel,
                  const struct GNUNET_PeerIdentity *initiator,
                  const struct GNUNET_HashCode *port,
                  enum GNUNET_CADET_ChannelOption options)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel from %s to peer %d:%s\n",
              GNUNET_i2s (initiator),
              (int) (long) cls, GNUNET_h2s (port));
  ok++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);
  if ((long) cls == peers_requested - 1)
  {
    if (NULL != incoming_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Duplicate incoming channel for client %lu\n",
                  (long) cls);
      GNUNET_break(0);
    }
    incoming_ch = channel;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming channel for unknown client %lu\n", (long) cls);
    GNUNET_break(0);
  }
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                    &gather_stats_and_exit,
                                                    (void *) __LINE__);
  }

  return NULL;
}


/**
 * Function called whenever an inbound channel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_CADET_connect, peer number)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_cleaner (void *cls,
                 const struct GNUNET_CADET_Channel *channel,
                 void *channel_ctx)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel disconnected at peer %ld\n",
              i);
  if (peers_running - 1 == i)
  {
    ok++;
    GNUNET_break (channel == incoming_ch);
    incoming_ch = NULL;
  }
  else if (0L == i)
  {
    if (P2P_SIGNAL == test)
    {
      ok++;
    }
    GNUNET_break (channel == ch);
    ch = NULL;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unknown peer! %d\n",
                (int) i);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " ok: %d\n", ok);

  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&gather_stats_and_exit,
                                                (void *) __LINE__);
  }
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
do_test (void *cls)
{
  enum GNUNET_CADET_ChannelOption flags;

  test_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "do_test\n");
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = NULL;
  }

  flags = GNUNET_CADET_OPTION_DEFAULT;
  if (SPEED_REL == test)
  {
    test = SPEED;
    flags |= GNUNET_CADET_OPTION_RELIABLE;
  }

  ch = GNUNET_CADET_channel_create (h1,
                                    NULL,
                                    p_id[1],
                                    &port,
                                    flags);

  disconnect_task
    = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                    &gather_stats_and_exit,
                                    (void *) __LINE__);
  if (KEEPALIVE == test)
    return; /* Don't send any data. */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending data initializer...\n");
  data_received = 0;
  data_sent = 0;
  ack_received = 0;
  ack_sent = 0;
  th = GNUNET_CADET_notify_transmit_ready (ch,
                                           GNUNET_NO,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           size_payload + 1000,
                                           &tmt_rdy, (void *) 0L);
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
pi_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "id callback for %ld\n", i);

  if ( (NULL == pinfo) ||
       (NULL != emsg) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "pi_cb: %s\n", emsg);
    abort_test (__LINE__);
    return;
  }
  p_id[i] = pinfo->result.id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  id: %s\n", GNUNET_i2s (p_id[i]));
  p_ids++;
  if (p_ids < 2)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got all IDs, starting test\n");
  test_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &do_test,
                                            NULL);
}


/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_CADET_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param cadetes Handle to each of the CADETs of the peers.
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
  h1 = cadets[0];
  h2 = cadets[num_peers - 1];
  disconnect_task = GNUNET_SCHEDULER_add_delayed (SHORT_TIME,
                                                  &disconnect_cadet_peers,
                                                  (void *) __LINE__);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  t_op[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb, (void *) 0L);
  t_op[1] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 1],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb, (void *) 1L);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "requested peer ids\n");
}


/**
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  initialized = GNUNET_NO;
  static const struct GNUNET_HashCode *ports[2];
  const char *config_file;
  char port_id[] = "test port";
  GNUNET_CRYPTO_hash (port_id, sizeof (port_id), &port);

  GNUNET_log_setup ("test", "DEBUG", NULL);
  config_file = "test_cadet.conf";

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start\n");

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
     * TOTAL_PACKETS received data packet (@dest)
     * TOTAL_PACKETS received data packet (@orig)
     * 1 received channel destroy (@dest)
     */
    ok_goal = TOTAL_PACKETS * 2 + 2;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "SPEED_ACK\n");
    test = SPEED_ACK;
    test_name = "speed ack";
  }
  else if (strstr (argv[0], "_speed") != NULL)
  {
    /* Test is supposed to generate the following callbacks:
     * 1 incoming channel (@dest)
     * 1 initial packet (@dest)
     * TOTAL_PACKETS received data packet (@dest)
     * 1 received data packet (@orig)
     * 1 received channel destroy (@dest)
     */
    ok_goal = TOTAL_PACKETS + 4;
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
    /* Test is supposed to generate the following callbacks:
     * 1 incoming channel (@dest)
     * [wait]
     * 1 received channel destroy (@dest)
     */
    ok_goal = 2;
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

  p_ids = 0;
  ports[0] = &port;
  ports[1] = NULL;
  GNUNET_CADET_TEST_run ("test_cadet_small",
                        config_file,
                        peers_requested,
                        &tmain,
                        NULL, /* tmain cls */
                        &incoming_channel,
                        &channel_cleaner,
                        handlers,
                        ports);

  if (ok_goal > ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "FAILED! (%d/%d)\n", ok, ok_goal);
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}

/* end of test_cadet.c */
