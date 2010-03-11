/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file dv/gnunet-service-dv.c
 * @brief the distance vector service, primarily handles gossip of nearby
 * peers and sending/receiving DV messages from core and decapsulating
 * them
 *
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "dv.h"

/**
 * DV Service Context stuff goes here...
 */

/**
 * Handle to the core service api.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity *my_identity;

/**
 * The configuration for this service.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The scheduler for this service.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * The client, should be the DV plugin connected to us.  Hopefully
 * this client will never change, although if the plugin dies
 * and returns for some reason it may happen.
 */
static struct GNUNET_SERVER_Client * client_handle;

GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

/**
 * Core handler for dv data messages.  Whatever this message
 * contains all we really have to do is rip it out of its
 * DV layering and give it to our pal the DV plugin to report
 * in with.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void handle_dv_data_message (void *cls,
                             struct GNUNET_PeerIdentity *
                             peer,
                             const struct
                             GNUNET_MessageHeader *
                             message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message!\n", "dv", "DV DATA");
#endif

}

/**
 * Core handler for dv gossip messages.  These will be used
 * by us to create a HELLO message for the newly peer containing
 * which direct peer we can connect through, and what the cost
 * is.  This HELLO will then be scheduled for validation by the
 * transport service so that it can be used by all others.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void handle_dv_gossip_message (void *cls,
                               struct GNUNET_PeerIdentity * peer,
                               const struct GNUNET_MessageHeader * message,
                               struct GNUNET_TIME_Relative latency,
                               uint32_t distance)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message!\n", "dv", "DV GOSSIP");
#endif

}


/**
 * Service server's handler for message send requests (which come
 * bubbling up to us through the DV plugin).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void send_dv_message (void *cls,
                      struct GNUNET_SERVER_Client * client,
                      const struct GNUNET_MessageHeader * message)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message!\n", "dv", "SEND");
#endif
  if (client_handle == NULL)
  {
    client_handle = client;
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Setting initial client handle!\n", "dv");
#endif
  }
  else if (client_handle != client)
  {
    client_handle = client;
    /* What should we do in this case, assert fail or just log the warning? */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s: Setting client handle (was a different client!)!\n", "dv");
  }
}

/**
 * List of handlers for the messages understood by this
 * service.
 *
 * Hmm... will we need to register some handlers with core and
 * some handlers with our server here?  Because core should be
 * getting the incoming DV messages (from whichever lower level
 * transport) and then our server should be getting messages
 * from the dv_plugin, right?
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dv_data_message, GNUNET_MESSAGE_TYPE_DV_DATA, 0},
  {&handle_dv_gossip_message, GNUNET_MESSAGE_TYPE_DV_GOSSIP, 0},
  {NULL, 0, 0}
};

static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&send_dv_message, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND, 0},
  {NULL, NULL, 0, 0}
};


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  GNUNET_CORE_disconnect (coreAPI);
}

/**
 * To be called on core init/fail.
 */
void core_init (void *cls,
                struct GNUNET_CORE_Handle * server,
                const struct GNUNET_PeerIdentity *my_identity,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded * publicKey)
{

  if (server == NULL)
    {
      GNUNET_SCHEDULER_cancel(sched, cleanup_task);
      GNUNET_SCHEDULER_add_now(sched, &shutdown_task, NULL);
      return;
    }
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dv", GNUNET_i2s(my_identity));
#endif
  coreAPI = server;
}

/**
 * Method called whenever a given peer either connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other'
 */
void handle_core_connect (void *cls,
                          const struct GNUNET_PeerIdentity * peer,
                          struct GNUNET_TIME_Relative latency,
                          uint32_t distance)
{

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core connect message!\n", "dv");
#endif
}

/**
 * Method called whenever a given peer either connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other'
 */
void handle_core_disconnect (void *cls,
                             const struct GNUNET_PeerIdentity * peer)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core peer disconnect message!\n", "dv");
#endif
}


/**
 * Process dv requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *scheduler,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_TIME_Relative timeout;

  timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  sched = scheduler;
  cfg = c;
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  coreAPI =
  GNUNET_CORE_connect (sched,
                       cfg,
                       timeout,
                       NULL, /* FIXME: anything we want to pass around? */
                       &core_init,
                       NULL, /* Don't care about pre-connects */
                       &handle_core_connect,
                       &handle_core_disconnect,
                       NULL,
                       GNUNET_NO,
                       NULL,
                       GNUNET_NO,
                       core_handlers);

  if (coreAPI == NULL)
    return;
  /* load (server); Huh? */

  /* Scheduled the task to clean up when shutdown is called */

  cleanup_task = GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The main function for the dv service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "dv",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}
