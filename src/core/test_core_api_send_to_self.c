/*
     This file is part of GNUnet.
     Copyright (C) 2010 Christian Grothoff

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
 * @file core/test_core_api_send_to_self.c
 * @brief
 * @author Philipp Toelke
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"

/**
 * Final status code.
 */
static int ret;

/**
 * Handle to the cleanup task.
 */
struct GNUNET_SCHEDULER_Task * die_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity myself;

/**
 * The handle to core
 */
struct GNUNET_CORE_Handle *core;


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  die_task = NULL;

  if (core != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting core.\n");
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");
}


static int
receive (void *cls, const struct GNUNET_PeerIdentity *other,
         const struct GNUNET_MessageHeader *message)
{
  if (die_task != NULL)
    GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message from peer %s\n",
              GNUNET_i2s (other));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_DUMMY == ntohs (message->type));
  GNUNET_assert (0 == memcmp (other, &myself, sizeof (myself)));
  GNUNET_SCHEDULER_add_now (&cleanup, NULL);
  ret = 0;
  return GNUNET_OK;
}


static size_t
send_message (void *cls, size_t size, void *buf)
{
  if (size == 0 || buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could not send; got 0 buffer\n");
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending!\n");
  struct GNUNET_MessageHeader *hdr = buf;

  hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
  hdr->type = htons (GNUNET_MESSAGE_TYPE_DUMMY);
  return ntohs (hdr->size);
}


static void
init (void *cls,
      const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Correctly connected to CORE; we are the peer %s.\n",
              GNUNET_i2s (my_identity));
  memcpy (&myself, my_identity, sizeof (struct GNUNET_PeerIdentity));
}


static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s.\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (peer, &myself, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connected to myself; sending message!\n");
    GNUNET_CORE_notify_transmit_ready (core, GNUNET_YES, 0,
                                       GNUNET_TIME_UNIT_FOREVER_REL, peer,
                                       sizeof (struct GNUNET_MessageHeader),
                                       send_message, NULL);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param cfg configuration
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  const static struct GNUNET_CORE_MessageHandler handlers[] = {
    {&receive, GNUNET_MESSAGE_TYPE_DUMMY, 0},
    {NULL, 0, 0}
  };
  core =
    GNUNET_CORE_connect (cfg, NULL, &init, &connect_cb, NULL, NULL,
			 0, NULL, 0, handlers);
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300), &cleanup,
                                    NULL);
}


/**
 * The main function to test sending a message to the local peer via core
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-core-api-send-to-self",
				    "test_core_api_peer1.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of test_core_api_send_to_self.c */
