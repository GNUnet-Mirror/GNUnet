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
 * @file psycstore/gnunet-service-psycstore.c
 * @brief PSYCstore service
 * @author Gabor X Toth
 * @author Christian Grothoff
 *
 * The purpose of this service is to manage private keys that
 * represent the various egos/pseudonyms/identities of a GNUnet user.
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_psycstore_plugin.h"
#include "psycstore.h"


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Database handle
 */
static struct GNUNET_PSYCSTORE_PluginFunctions *db;

/**
 * Name of the database plugin
 */
static char *db_lib_name;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
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
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, db));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
}


/**
 * Send a result code back to the client.
 *
 * @param client client that should receive the result code
 * @param result_code code to transmit
 * @param emsg error message to include (or NULL for none)
 */
static void
send_result_code (struct GNUNET_SERVER_Client *client,
		  uint32_t result_code,
		  const char *emsg)
{
  struct GNUNET_PSYCSTORE_ResultCodeMessage *rcm;
  size_t elen;

  if (NULL == emsg)
    elen = 0;
  else
    elen = strlen (emsg) + 1;
  rcm = GNUNET_malloc (sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage) + elen);
  rcm->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE);
  rcm->header.size = htons (sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage) + elen);
  rcm->result_code = htonl (result_code);
  memcpy (&rcm[1], emsg, elen);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending result %d (%s) to client\n",
	      (int) result_code,
	      emsg);
  GNUNET_SERVER_notification_context_unicast (nc, client, &rcm->header, GNUNET_NO);
  GNUNET_free (rcm);
}


/**
 * Handle PSYCstore clients.
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
    {NULL, NULL, 0, 0}
  };

  cfg = c;

  /* Loading database plugin */
  char *database;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "psycstore", "database",
                                             &database))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");
  }
  else
  {
    GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_psycstore_%s", database);
    db = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
    GNUNET_free (database);
  }
  if (NULL == db)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }

  stats = GNUNET_STATISTICS_create ("psycstore", cfg);
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
          GNUNET_SERVICE_run (argc, argv, "psycstore",
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


/* end of gnunet-service-psycstore.c */
