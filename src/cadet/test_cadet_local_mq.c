/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @file cadet/test_cadet_local.c
 * @brief test cadet local: test of cadet channels with just one peer
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_cadet_service.h"

#define TEST_MESSAGE_TYPE 1
#define TEST_PORT_ID 1

/**
 * Test message structure.
 */
struct GNUNET_CADET_TestMsg
{
  /**
   * Type: #TEST_MESSAGE_TYPE
   *
   * Size: sizeof(struct GNUNET_CADET_TestMsg)
   */
  struct GNUNET_MessageHeader header;

  /**
   * Test payload.
   */
  uint64_t payload;
};

struct GNUNET_TESTING_Peer *me;

static struct GNUNET_CADET_Handle *cadet_peer_1;

static struct GNUNET_CADET_Handle *cadet_peer_2;

static struct GNUNET_CADET_Channel *ch;

static int result = GNUNET_OK;

static int got_data = GNUNET_NO;

static struct GNUNET_SCHEDULER_Task *abort_task;

static struct GNUNET_SCHEDULER_Task *connect_task;


/**
 * Connect to other client and send data
 *
 * @param cls Closue (unused).
 */
static void
do_connect (void *cls);


/**
 * Shutdown nicely
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "shutdown\n");
  if (NULL != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
  }
  if (NULL != ch)
  {
    GNUNET_CADET_channel_destroy (ch);
    ch = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnect client 1\n");
  if (NULL != cadet_peer_1)
  {
    GNUNET_CADET_disconnect (cadet_peer_1);
    cadet_peer_1 = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnect client 2\n");
  if (NULL != cadet_peer_2)
  {
    GNUNET_CADET_disconnect (cadet_peer_2);
    cadet_peer_2 = NULL;
  }
  if (NULL != connect_task)
  {
    GNUNET_SCHEDULER_cancel (connect_task);
    connect_task = NULL;
  }
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ABORT from line %ld\n", (long) cls);
  result = GNUNET_SYSERR;
  abort_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * Method called whenever a peer connects to a port in MQ-based CADET.
 *
 * @param cls Closure from #GNUNET_CADET_open_porT.
 * @param channel New handle to the channel.
 * @param source Peer that started this channel.
 * @return Closure for the incoming @a channel. It's given to:
 *         - The #GNUNET_CADET_DisconnectEventHandler (given to
 *           #GNUNET_CADET_open_porT) when the channel dies.
 *         - Each the #GNUNET_MQ_MessageCallback handlers for each message
 *           received on the @a channel.
 */
static void *
connected (void *cls,
           struct GNUNET_CADET_Channel *channel,
           const struct GNUNET_PeerIdentity *source)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connected %s, cls: %p\n",
              GNUNET_i2s(source), cls);
  return channel;
}

/**
 * Function called whenever an MQ-channel is destroyed, even if the destruction
 * was requested by #GNUNET_CADET_channel_destroy.
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * It should clean up any associated state, including cancelling any pending
 * transmission on this channel.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 */
static void
disconnected (void *cls,
              const struct GNUNET_CADET_Channel *channel)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnected cls: %p\n",
              cls);
  if (channel == ch)
    ch = NULL;
}


/**
 * Handle test data
 *
 * @param h     The cadet handle
 * @param msg   A message with the details of the new incoming channel
 */
static void
handle_data_received (void *cls,
                      const struct GNUNET_CADET_TestMsg *msg)
{
  uint64_t payload;

  payload = GNUNET_ntohll (msg->payload);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Data callback payload %llu with cls: %p! Shutting down.\n",
              (unsigned long long) payload,
              cls);
  GNUNET_assert (42 == payload);
  got_data = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Signature of the main function of a task.
 *
 * @param cls Closure (unused).
 */
static void
message_sent (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "message sent\n");
}


/**
 * Connect to other client and send data
 *
 * @param cls Closure (unused).
 */
static void
do_connect (void *cls)
{
  struct GNUNET_PeerIdentity id;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TestMsg *msg;

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (data_received,
                             TEST_MESSAGE_TYPE,
                             struct GNUNET_CADET_TestMsg,
                             cadet_peer_1),
    GNUNET_MQ_handler_end ()
  };

  connect_task = NULL;
  GNUNET_TESTING_peer_get_identity (me, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "creating channel\n");
  ch = GNUNET_CADET_channel_creatE (cadet_peer_1, /* cadet handle */
                                    NULL,         /* channel cls */
                                    &id,          /* destination */
                                    GC_u2h (TEST_MESSAGE_TYPE), /* port */
                                    GNUNET_CADET_OPTION_DEFAULT, /* opt */
                                    NULL,          /* window change */
                                    &disconnected, /* disconnect handler */
                                    handlers       /* traffic handlers */
                                   );
  env = GNUNET_MQ_msg (msg, TEST_MESSAGE_TYPE);
  msg->payload = GNUNET_htonll (42);
  mq = GNUNET_CADET_get_mq (ch);
  GNUNET_MQ_notify_sent (env, &message_sent, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending message\n");
  GNUNET_MQ_send (mq, env);
}


/**
 * Initialize framework and start test
 *
 * @param cls Closure (unused).
 * @param cfg Configuration handle.
 * @param peer Testing peer handle.
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (data_received,
                             TEST_MESSAGE_TYPE,
                             struct GNUNET_CADET_TestMsg,
                             cadet_peer_2),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_TIME_Relative delay;

  me = peer;
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15);
  abort_task = GNUNET_SCHEDULER_add_delayed (delay,
                                             &do_abort,
                                             (void *) (long) __LINE__);
  cadet_peer_1 = GNUNET_CADET_connecT (cfg);
  cadet_peer_2 = GNUNET_CADET_connecT (cfg);

  if ( (NULL == cadet_peer_1) ||
       (NULL == cadet_peer_2) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Couldn't connect to cadet\n");
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CADET 1: %p\n", cadet_peer_1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CADET 2: %p\n", cadet_peer_2);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "handlers 2: %p\n", handlers);
  GNUNET_CADET_open_porT (cadet_peer_2,          /* cadet handle */
                          GC_u2h (TEST_PORT_ID), /* port id */
                          &connected,            /* connect handler */
                          (void *) 2L,           /* handle for #connected */
                          NULL,                  /* window size handler */
                          &disconnected,         /* disconnect handler */
                          handlers);             /* traffic handlers */
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2);
  if (NULL == connect_task)
    connect_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                 &do_connect,
                                                 NULL);
}


/**
 * Main
 */
int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-cadet-local",
                                    "test_cadet.conf",
                                &run, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "run failed\n");
    return 2;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Final result: %d\n", result);
  return (result == GNUNET_OK) ? 0 : 1;
}

/* end of test_cadet_local_1.c */
