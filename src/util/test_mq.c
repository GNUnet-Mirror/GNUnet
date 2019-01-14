/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2018 GNUnet e.V.

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
 * @file util/test_mq.c
 * @brief tests for mq
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define NUM_TRANSMISSIONS 500

/**
 * How long does the receiver take per message?
 */
#define RECEIVER_THROTTLE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 1)

static unsigned int received_cnt;


GNUNET_NETWORK_STRUCT_BEGIN

struct MyMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t x GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END

static int global_ret;

static struct GNUNET_SCHEDULER_Task *tt;

static struct GNUNET_SCHEDULER_Task *dt;

static struct GNUNET_MQ_Handle *cmq;


static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
  if (NULL != cmq)
  {
    GNUNET_MQ_destroy (cmq);
    cmq = NULL;
  }
}


static void
do_timeout (void *cls)
{
  (void) cls;
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
  global_ret = 1;
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure
 * @param error error code
 */
static void
error_cb (void *cls,
          enum GNUNET_MQ_Error error)
{
  GNUNET_break (0);
  global_ret = 3;
  GNUNET_SCHEDULER_shutdown ();
}


static void
client_continue (void *cls)
{
  struct GNUNET_SERVICE_Client *c = cls;

  dt = NULL;
  GNUNET_SERVICE_client_continue (c);
}


static void
handle_dummy (void *cls,
              const struct MyMessage *msg)
{
  struct GNUNET_SERVICE_Client *c = cls;

  GNUNET_assert (NULL == dt);
  /* artificially make receiver slower than sender */
  dt = GNUNET_SCHEDULER_add_delayed (RECEIVER_THROTTLE,
                                     &client_continue,
                                     c);
  if (received_cnt != ntohl (msg->x))
  {
    GNUNET_break (0);
    global_ret = 4;
    GNUNET_SCHEDULER_shutdown ();
  }
  received_cnt++;
}


static void
handle_dummy2 (void *cls,
               const struct MyMessage *msg)
{
  struct GNUNET_SERVICE_Client *c = cls;

  GNUNET_SERVICE_client_continue (c);
  if (NUM_TRANSMISSIONS != received_cnt)
  {
    GNUNET_break (0);
    global_ret = 5;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called whenever MQ has sent a message.
 */
static void
notify_sent_cb (void *cls)
{
  static unsigned int seen;
  unsigned int *cnt = cls;

  if (seen != *cnt)
  {
    GNUNET_break (0);
    global_ret = 6;
    GNUNET_SCHEDULER_shutdown ();
  }
  seen++;
  GNUNET_free (cnt);
}


/**
 * Start running the actual test.
 *
 * @param cls closure passed to #GNUNET_SERVICE_MAIN
 * @param cfg configuration to use for this service
 * @param sh handle to the newly create service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_MQ_MessageHandler ch[] = {
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct MyMessage *m;

  (void) cls;
  (void) sh;
  cmq = GNUNET_CLIENT_connect (cfg,
                               "test_client",
                               ch,
                               &error_cb,
                               NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                     &do_timeout,
                                     NULL);
  for (unsigned int i=0;i<NUM_TRANSMISSIONS;i++)
  {
    unsigned int *cnt;

    cnt = GNUNET_new (unsigned int);
    *cnt = i;
    env = GNUNET_MQ_msg (m,
                         GNUNET_MESSAGE_TYPE_DUMMY);
    GNUNET_MQ_notify_sent (env,
                           &notify_sent_cb,
                           cnt);
    m->x = htonl (i);
    GNUNET_MQ_send (cmq,
                    env);
  }
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DUMMY2);
  GNUNET_MQ_send (cmq,
                  env);
}


/**
 * Callback to be called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return the client-specific (`internal') closure
 */
static void *
connect_cb (void *cls,
            struct GNUNET_SERVICE_Client *c,
            struct GNUNET_MQ_Handle *mq)
{
  (void) cls;
  (void) mq;
  return c;
}


/**
 * Callback to be called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls the client-specific (`internal') closure
 */
static void
disconnect_cb (void *cls,
               struct GNUNET_SERVICE_Client *c,
               void *internal_cls)
{
  (void) cls;
  (void) c;
  (void) internal_cls;
}


static void
test1 ()
{
  struct GNUNET_MQ_Envelope *mqm;
  struct MyMessage *mm;

  mm = NULL;
  mqm = NULL;

  mqm = GNUNET_MQ_msg (mm,
                       GNUNET_MESSAGE_TYPE_DUMMY);
  GNUNET_assert (NULL != mqm);
  GNUNET_assert (NULL != mm);
  GNUNET_assert (GNUNET_MESSAGE_TYPE_DUMMY == ntohs (mm->header.type));
  GNUNET_assert (sizeof (struct MyMessage) == ntohs (mm->header.size));
  GNUNET_MQ_discard (mqm);
}


static void
test2 ()
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_MessageHeader *mh;

  mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_DUMMY);
  /* how could the above be checked? */

  GNUNET_MQ_discard (mqm);

  mqm = GNUNET_MQ_msg_header_extra (mh,
                                    20,
                                    GNUNET_MESSAGE_TYPE_DUMMY);
  GNUNET_assert (GNUNET_MESSAGE_TYPE_DUMMY == ntohs (mh->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) + 20 == ntohs (mh->size));
  GNUNET_MQ_discard (mqm);
}


int
main (int argc, char **argv)
{
  char * test_argv[] = {
    (char *) "test_client",
    "-c",
    "test_client_data.conf",
    NULL
  };
  struct GNUNET_MQ_MessageHandler mh[] = {
    GNUNET_MQ_hd_fixed_size (dummy,
                             GNUNET_MESSAGE_TYPE_DUMMY,
                             struct MyMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (dummy2,
                             GNUNET_MESSAGE_TYPE_DUMMY2,
                             struct MyMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  (void) argc;
  (void) argv;
  GNUNET_log_setup ("test-mq",
                    "INFO",
                    NULL);
  test1 ();
  test2 ();
  if (0 !=
      GNUNET_SERVICE_run_ (3,
                           test_argv,
                           "test_client",
                           GNUNET_SERVICE_OPTION_NONE,
                           &run,
                           &connect_cb,
                           &disconnect_cb,
                           NULL,
                           mh))
    return 1;
  return global_ret;
}
