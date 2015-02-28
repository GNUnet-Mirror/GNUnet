/*
  This file is part of GNUnet.
  Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"


#define NUM_MSG 5

/**
 * Has the test been successful?
 */
int result;

unsigned int num_received;

struct GNUNET_CORE_Handle *core;

struct GNUNET_MQ_Handle *mq;

struct GNUNET_PeerIdentity myself;


static void
init_cb (void *cls,
         const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  myself = *my_identity;
  mq = GNUNET_CORE_mq_create (core, my_identity);
}


static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s.\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (peer, &myself, sizeof (struct GNUNET_PeerIdentity)))
  {
    unsigned int i;
    struct GNUNET_MQ_Envelope *ev;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Queueing messages.\n");
    for (i = 0; i < NUM_MSG; i++)
    {
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_TEST);
      GNUNET_MQ_send (mq, ev);
    }
  }
}


static int
handle_test (void *cls,
             const struct GNUNET_PeerIdentity *other,
             const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got test message %d\n", num_received);
  num_received++;
  if (NUM_MSG == num_received)
  {
    result = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_SYSERR;
  }
  if (num_received > NUM_MSG)
  {
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  GNUNET_MQ_destroy (mq);
  GNUNET_CORE_disconnect (core);
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
  static const struct GNUNET_CORE_MessageHandler handlers[] = {
    {&handle_test, GNUNET_MESSAGE_TYPE_TEST, 0},
    {NULL, 0, 0}
  };
  core = GNUNET_CORE_connect (cfg,
                              NULL, &init_cb, &connect_cb, NULL,
                              NULL, GNUNET_NO, NULL,
                              GNUNET_NO, handlers);
  if (NULL == core)
  {
    GNUNET_assert (0);
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);
}

int
main (int argc, char *argv1[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-core-api-mq",
                                    "test_core_api_peer1.conf",
                                    &run, NULL))
    return 2;
  return (result == GNUNET_OK) ? 0 : 1;
}
