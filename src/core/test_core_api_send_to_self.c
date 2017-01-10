/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2016 GNUnet e.V.

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
 * @file core/test_core_api_send_to_self.c
 * @brief test that sending a message to ourselves via CORE works
 * @author Philipp Toelke
 * @author Christian Grothoff
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
static struct GNUNET_SCHEDULER_Task *die_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity myself;

/**
 * The handle to core
 */
static struct GNUNET_CORE_Handle *core;


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls)
{
  if (NULL != die_task)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ending test.\n");
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
do_timeout (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test timeout.\n");
  die_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


static void
handle_test (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  GNUNET_SCHEDULER_shutdown ();
  ret = 0;
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
  GNUNET_memcpy (&myself,
		 my_identity,
		 sizeof (struct GNUNET_PeerIdentity));
}


static void *
connect_cb (void *cls,
            const struct GNUNET_PeerIdentity *peer,
	    struct GNUNET_MQ_Handle *mq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to peer %s.\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (peer,
                   &myself,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_MessageHeader *msg;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connected to myself; sending message!\n");
    env = GNUNET_MQ_msg (msg,
			 GNUNET_MESSAGE_TYPE_DUMMY);
    GNUNET_MQ_send (mq,
		    env);
  }
  return NULL;
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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test,
                             GNUNET_MESSAGE_TYPE_DUMMY,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  core =
    GNUNET_CORE_connect (cfg,
			 NULL,
			 &init,
                         &connect_cb,
			 NULL,
			 handlers);
  GNUNET_SCHEDULER_add_shutdown (&cleanup,
                                 NULL);
  die_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                           &do_timeout,
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
  ret = 1;
  if (0 != GNUNET_TESTING_peer_run ("test-core-api-send-to-self",
				    "test_core_api_peer1.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of test_core_api_send_to_self.c */
