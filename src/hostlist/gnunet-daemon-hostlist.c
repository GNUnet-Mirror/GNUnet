/*
     This file is part of GNUnet.
     Copyright (C) 2007, 2008, 2009, 2014 GNUnet e.V.

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
 * @file hostlist/gnunet-daemon-hostlist.c
 * @brief code for bootstrapping via hostlist servers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-daemon-hostlist_client.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"

#include "gnunet-daemon-hostlist_server.h"

/**
 * Set if we are allowed to advertise our hostlist to others.
 */
static int advertising;

/**
 * Set if the user wants us to run a hostlist server.
 */
static int provide_hostlist;

/**
 * Handle to hostlist server's connect handler
 */
static GNUNET_CORE_ConnectEventHandler server_ch;

/**
 * Set if we are allowed to learn about peers by accessing
 * hostlist servers.
 */
static int bootstrapping;

/**
 * Set if the user allows us to learn about new hostlists
 * from the network.
 */
static int learning;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (NULL until we've connected to it).
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Handle to the hostlist client's advertisement handler
 */
static GNUNET_HOSTLIST_UriHandler client_adv_handler;

/**
 * Handle to hostlist client's connect handler
 */
static GNUNET_CORE_ConnectEventHandler client_ch;

/**
 * Handle to hostlist client's disconnect handler
 */
static GNUNET_CORE_DisconnectEventHandler client_dh;

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A HOSTLIST_ADV message is used to exchange information about
 * hostlist advertisements.  This struct is always
 * followed by the actual url under which the hostlist can be obtained:
 *
 * 1) transport-name (0-terminated)
 * 2) address-length (uint32_t, network byte order; possibly
 *    unaligned!)
 * 3) address expiration (GNUNET_TIME_AbsoluteNBO); possibly
 *    unaligned!)
 * 4) address (address-length bytes; possibly unaligned!)
 */
struct GNUNET_HOSTLIST_ADV_Message
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero (for alignment).
   */
  uint32_t reserved GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Our own peer identity.
 */
static struct GNUNET_PeerIdentity me;


/**
 * Callback invoked once our connection to CORE service is up.
 *
 * @param cls NULL
 * @param my_identity our peer's identity
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *my_identity)
{
  me = *my_identity;
}


/**
 * Core handler for p2p hostlist advertisements
 *
 * @param cls closure
 * @param message advertisement message we got
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_advertisement (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  size_t size;
  size_t uri_size;
  const char *uri;

  size = ntohs (message->size);
  if (size <= sizeof(struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  uri = (const char *) &message[1];
  uri_size = size - sizeof(struct GNUNET_MessageHeader);
  if (uri[uri_size - 1] != '\0')
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p hostlist advertisements
 *
 * @param cls closure
 * @param message advertisement message we got
 * @return #GNUNET_OK on success
 */
static void
handle_advertisement (void *cls,
                      const struct GNUNET_MessageHeader *message)
{
  const char *uri = (const char *) &message[1];

  GNUNET_assert (NULL != client_adv_handler);
  (void) (*client_adv_handler)(uri);
}


/**
 * Method called whenever a given peer connects.  Wrapper to call both
 * client's and server's functions
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq queue for sending messages to @a peer
 * @return peer
 */
static void *
connect_handler (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  if (0 == GNUNET_memcmp (&me,
                          peer))
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "A new peer connected, notifying client and server\n");
  if (NULL != client_ch)
    GNUNET_assert (NULL ==
                   (*client_ch)(cls,
                                peer,
                                mq));
  if (NULL != server_ch)
    GNUNET_assert (NULL ==
                   (*server_ch)(cls,
                                peer,
                                mq));
  return (void *) peer;
}


/**
 * Method called whenever a given peer disconnects. Wrapper to call
 * both client's and server's functions
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
disconnect_handler (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *internal_cls)
{
  if (0 == GNUNET_memcmp (&me,
                          peer))
    return;
  /* call hostlist client disconnect handler */
  if (NULL != client_dh)
    (*client_dh)(cls,
                 peer,
                 NULL);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the other services.
 *
 * @param cls NULL
 */
static void
cleaning_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist daemon is shutting down\n");
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (bootstrapping)
  {
    GNUNET_HOSTLIST_client_stop ();
  }
  if (provide_hostlist)
  {
    GNUNET_HOSTLIST_server_stop ();
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
                               GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MQ_MessageHandler learn_handlers[] = {
    GNUNET_MQ_hd_var_size (advertisement,
                           GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_MessageHandler no_learn_handlers[] = {
    GNUNET_MQ_handler_end ()
  };

  if ((! bootstrapping) && (! learning)
      && (! provide_hostlist)
      )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ (
                  "None of the functions for the hostlist daemon were enabled.  I have no reason to run!\n"));
    return;
  }
  stats = GNUNET_STATISTICS_create ("hostlist", cfg);
  if (NULL == stats)
  {
    GNUNET_break (0);
    return;
  }
  if (bootstrapping)
    GNUNET_HOSTLIST_client_start (cfg,
                                  stats,
                                  &client_ch,
                                  &client_dh,
                                  &client_adv_handler,
                                  learning);
  core =
    GNUNET_CORE_connect (cfg,
                         NULL,
                         &core_init,
                         &connect_handler,
                         &disconnect_handler,
                         learning ? learn_handlers : no_learn_handlers);


  if (provide_hostlist)
    GNUNET_HOSTLIST_server_start (cfg,
                                  stats,
                                  core,
                                  &server_ch,
                                  advertising);
  GNUNET_SCHEDULER_add_shutdown (&cleaning_task,
                                 NULL);

  if (NULL == core)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to `%s' service.\n"), "core");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function for the hostlist daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('a',
                               "advertise",
                               gettext_noop (
                                 "advertise our hostlist to other peers"),
                               &advertising),
    GNUNET_GETOPT_option_flag ('b',
                               "bootstrap",
                               gettext_noop (
                                 "bootstrap using hostlists (it is highly recommended that you always use this option)"),
                               &bootstrapping),
    GNUNET_GETOPT_option_flag ('e',
                               "enable-learning",
                               gettext_noop (
                                 "enable learning about hostlist servers from other peers"),
                               &learning),
    GNUNET_GETOPT_option_flag ('p',
                               "provide-hostlist",
                               gettext_noop ("provide a hostlist server"),
                               &provide_hostlist),
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("hostlist", "WARNING", NULL);
  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc, argv,
                         "hostlist",
                         _ ("GNUnet hostlist server and client"),
                         options,
                         &run, NULL)) ? 0 : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-daemon-hostlist.c */
