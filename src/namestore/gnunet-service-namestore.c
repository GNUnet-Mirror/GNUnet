/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_namestore_plugin.h"
#include "namestore.h"



/**
 * A namestore operation.
 */
struct GNUNET_NAMESTORE_Operation
{
  struct GNUNET_NAMESTORE_Operation *next;
  struct GNUNET_NAMESTORE_Operation *prev;

  uint64_t op_id;

  char *data; /*stub data pointer*/
};


/**
 * A namestore client
 */
struct GNUNET_NAMESTORE_Client
{
  struct GNUNET_NAMESTORE_Client *next;
  struct GNUNET_NAMESTORE_Client *prev;

  struct GNUNET_SERVER_Client * client;

  struct GNUNET_NAMESTORE_Operation *op_head;
  struct GNUNET_NAMESTORE_Operation *op_tail;
};



/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

static struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

static char *db_lib_name;

static struct GNUNET_NAMESTORE_Client *client_head;
static struct GNUNET_NAMESTORE_Client *client_tail;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping namestore service\n");

  struct GNUNET_NAMESTORE_Operation * no;
  struct GNUNET_NAMESTORE_Client * nc;

  for (nc = client_head; nc != NULL; nc = nc->next)
  {
    for (no = nc->op_head; no != NULL; no = no->next)
    {
      GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
      GNUNET_free (no);
    }
  }

  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);

  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
}

/**
 * Called whenever a client is disconnected.  Frees our
 * resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_NAMESTORE_Operation * no;
  struct GNUNET_NAMESTORE_Client * nc;
  if (NULL == client)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected \n", client);

  for (nc = client_head; nc != NULL; nc = nc->next)
  {
    if (client == nc->client)
      break;
  }
  if (NULL == client)
    return;

  for (no = nc->op_head; no != NULL; no = no->next)
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
  }

  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
}

static void handle_start (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n");

  struct GNUNET_NAMESTORE_Client * nc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Client));
  nc->client = client;

  GNUNET_CONTAINER_DLL_insert(client_head, client_tail, nc);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void handle_lookup_name (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "NAMESTORE_LOOKUP_NAME");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char * database;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_START, sizeof (struct StartMessage)},
    {&handle_lookup_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME, 0},
    {NULL, NULL, 0, 0}
  };

  GSN_cfg = cfg;

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namestore", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  if (GSN_database == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load database backend `%s'\n",
        db_lib_name);
  GNUNET_free (database);

  /* Configuring server handles */
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification,
                                   NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);

}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "namestore",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-namestore.c */
