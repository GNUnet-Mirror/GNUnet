/*
  This file is part of GNUnet.
  (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file identity/gnunet-service-identity.c
 * @brief identity management service
 * @author Christian Grothoff
 *
 * The purpose of this service is to manage private keys that
 * represent the various egos/pseudonyms/identities of a GNUnet user.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_identity_service.h"
#include "identity.h"


/**
 * Information we keep about each ego.
 */
struct Ego
{

  /**
   * We keep egos in a DLL.
   */ 
  struct Ego *next;

  /**
   * We keep egos in a DLL.
   */ 
  struct Ego *prev;

  /**
   * Private key of the ego.
   */
  struct GNUNET_CRYPTO_EccPrivateKey *pk;

  /**
   * String identifier for the ego.
   */
  char *identifier;

};


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to subsystem configuration which for each subsystem contains
 * the name of the default ego.
 */
static struct GNUNET_CONFIGURATION_Handle *subsystem_cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Directory where we store the identities.
 */
static char *ego_directory;

/**
 * Configuration file name where subsystem information is kept.
 */
static char *subsystem_cfg_file;

/**
 * Head of DLL of all egos.
 */
static struct Ego *ego_head;

/**
 * Tail of DLL of all egos.
 */
static struct Ego *ego_tail;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Ego *e;

  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  GNUNET_CONFIGURATION_destroy (subsystem_cfg);
  subsystem_cfg = NULL;
  GNUNET_free (subsystem_cfg_file);
  subsystem_cfg_file = NULL;
  GNUNET_free (ego_directory);
  ego_directory = NULL;
  while (NULL != (e = ego_head))
  {
    GNUNET_CONTAINER_DLL_remove (ego_head, ego_tail, e);
    GNUNET_CRYPTO_ecc_key_free (e->pk);
    GNUNET_free (e);
  }
}


/**
 * Handler for START message from client, sends information
 * about all identities to the client immediately and 
 * adds the client to the notification context for future
 * updates.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_start_message (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received START message from client\n");
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_break (0); // not implemented!
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for GET_DEFAULT message from client, returns
 * default identity for some service.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_get_default_message (void *cls, struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received GET_DEFAULT message from client\n");
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_break (0); // not implemented!
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handler for SET_DEFAULT message from client, updates
 * default identity for some service.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_set_default_message (void *cls, struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received SET_DEFAULT message from client\n");
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_break (0); // not implemented!
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handler for CREATE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_create_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received CREATE message from client\n");
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_break (0); // not implemented!
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}



/**
 * Handler for RENAME message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_rename_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received RENAME message from client\n");
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_break (0); // not implemented!
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handler for DELETE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_delete_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received DELETE message from client\n");
  // setup_estimate_message (&em);
  // GNUNET_SERVER_notification_context_unicast (nc, client, &em.header, GNUNET_YES);
  GNUNET_break (0); // not implemented!
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, 
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_START, sizeof (struct GNUNET_MessageHeader)},
    {&handle_get_default_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT, 0},
    {&handle_set_default_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT, 0},
    {&handle_create_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_CREATE, 0},
    {&handle_rename_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_RENAME, 0},
    {&handle_delete_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_DELETE, 0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "identity",
					       "EGODIR",
					       &ego_directory))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "identity", "EGODIR");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "identity",
					       "SUBSYSTEM_CFG",
					       &subsystem_cfg_file))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "identity", "SUBSYSTEM_CFG");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  subsystem_cfg = GNUNET_CONFIGURATION_create ();
  if ( (GNUNET_YES ==
	GNUNET_DISK_file_test (subsystem_cfg_file)) &&
       (GNUNET_OK != 
	GNUNET_CONFIGURATION_parse (subsystem_cfg,
				    subsystem_cfg_file)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to parse subsystem identity configuration file `%s'\n"),
		subsystem_cfg_file);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("identity", cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the network size estimation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "identity", 
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


/* end of gnunet-service-identity.c */
