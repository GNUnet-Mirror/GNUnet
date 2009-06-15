/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file datastore/gnunet-service-datastore.c
 * @brief Management for the datastore for files stored on a GNUnet node
 * @author Christian Grothoff
 *
 * TODO:
 * 1) transmit and transmit flow-control (when do we signal client 'success'?
 *    ALSO: async transmit will need to address ref-counting issues on client!
 * 2) efficient "update" for client to raise priority / expiration
 *    (not possible with current datastore API, but plugin API has support!);
 *    [ maybe integrate desired priority/expiration updates directly
 *      with 'GET' request? ]
 * 3) semantics of "PUT" (plugin) if entry exists (should likely
 *   be similar to "UPDATE" (need to specify in PLUGIN API!)
 * 4) quota management code!
 * 5) add bloomfilter for efficiency!
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "plugin_datastore.h"
#include "datastore.h"


/**
 * Our datastore plugin.
 */
struct DatastorePlugin
{

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_DATASTORE_PluginFunctions *api;

  /**
   * Short name for the plugin (i.e. "sqlite").
   */
  char *short_name;

  /**
   * Name of the library (i.e. "gnunet_plugin_datastore_sqlite").
   */
  char *lib_name;

  /**
   * Environment this transport service is using
   * for this plugin.
   */
  struct GNUNET_DATASTORE_PluginEnvironment env;

};


/**
 * Our datastore plugin (NULL if not available).
 */
static struct DatastorePlugin *plugin;


/**
 * Transmit the given message to the client.
 */
static void
transmit (struct GNUNET_SERVER_Client *client,
	  const struct GNUNET_MessageHeader *msg)
{
  /* FIXME! */
}


/**
 * Transmit the size of the current datastore to the client.
 */
static void
transmit_size (struct GNUNET_SERVER_Client *client)
{
  struct SizeMessage sm;
  
  sm.header.size = htons(sizeof(struct SizeMessage));
  sm.header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_SIZE);
  sm.reserved = htonl(0);
  sm.size = GNUNET_htonll(plugin->api->get_size (plugin->api->cls));
  transmit (client, &sm.header);
}


/**
 * Function that will transmit the given datastore entry
 * to the client.
 *
 * @param cls closure, pointer to the client (of type GNUNET_SERVER_Client).
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue,
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
transmit_item (void *cls,
	       const GNUNET_HashCode * key,
	       uint32_t size,
	       const void *data,
	       uint32_t type,
	       uint32_t priority,
	       uint32_t anonymity,
	       struct GNUNET_TIME_Absolute
	       expiration, unsigned long long uid)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader end;
  struct DataMessage *dm;

  if (key == NULL)
    {
      /* transmit 'DATA_END' */
      end.size = htons(sizeof(struct GNUNET_MessageHeader));
      end.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END);
      transmit (client, &end);
      return GNUNET_OK;
    }
  /* FIXME: make use of 'uid' for efficient priority/expiration update! */
  dm = GNUNET_malloc (sizeof(struct DataMessage) + size);
  dm->header.size = htons(sizeof(struct DataMessage) + size);
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DATA);
  dm->reserved = htonl(0);
  dm->size = htonl(size);
  dm->type = htonl(type);
  dm->priority = htonl(priority);
  dm->anonymity = htonl(anonymity);
  dm->expiration = GNUNET_TIME_absolute_hton(expiration);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  transmit (client, &dm->header);
  GNUNET_free (dm);
  return GNUNET_OK;
}


/**
 * Handle INIT-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_init (void *cls,
	     struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  transmit_size (client);
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Check that the given message is a valid data message.
 *
 * @return NULL if the message is not well-formed, otherwise the message
 */
static const struct DataMessage *
check_data (const struct GNUNET_MessageHeader *message)
{
  uint16_t size;
  uint32_t dsize;
  const struct DataMessage *dm;

  size = ntohs(message->size);
  if (size < sizeof(struct DataMessage))
    { 
      GNUNET_break (0);
      return NULL;
    }
  dm = (const struct DataMessage *) message;
  dsize = ntohl(dm->size);
  if (size != dsize + sizeof(struct DataMessage))
    {
      GNUNET_break (0);
      return NULL;
    }
  if ( (ntohl(dm->type) == 0) ||
       (ntohl(dm->reserved) != 0) )
    {
      GNUNET_break (0);
      return NULL;
    }
  return dm;
}


/**
 * Handle PUT-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_put (void *cls,
	    struct GNUNET_SERVER_Client *client,
	    const struct GNUNET_MessageHeader *message)
{
  const struct DataMessage *dm = check_data (message);
  if (dm == NULL)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  plugin->api->put (plugin->api->cls,
		    &dm->key,
		    ntohl(dm->size),
		    &dm[1],
		    ntohl(dm->type),
		    ntohl(dm->priority),
		    ntohl(dm->anonymity),
		    GNUNET_TIME_absolute_ntoh(dm->expiration));
  transmit_size (client);
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get (void *cls,
	     struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  const struct GetMessage *msg;
  uint16_t size;

  size = ntohs(message->size);
  if ( (size != sizeof(struct GetMessage)) &&
       (size != sizeof(struct GetMessage) - sizeof(GNUNET_HashCode)) )
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  msg = (const struct GetMessage*) message;
  plugin->api->get (plugin->api->cls,
		    ((size == sizeof(struct GetMessage)) ? &msg->key : NULL),
		    NULL,
		    ntohl(msg->type),
		    &transmit_item,
		    client);    
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle GET_RANDOM-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_random (void *cls,
		   struct GNUNET_SERVER_Client *client,
		   const struct GNUNET_MessageHeader *message)
{
  plugin->api->iter_migration_order (plugin->api->cls,
				     0,
				     &transmit_item,
				     client);  
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Callback function that will cause the item that is passed
 * in to be deleted (by returning GNUNET_NO).
 */
static int
remove_callback (void *cls,
		 const GNUNET_HashCode * key,
		 uint32_t size,
		 const void *data,
		 uint32_t type,
		 uint32_t priority,
		 uint32_t anonymity,
		 struct GNUNET_TIME_Absolute
		 expiration, unsigned long long uid)
{
  return GNUNET_NO;
}


/**
 * Handle REMOVE-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_remove (void *cls,
	     struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  const struct DataMessage *dm = check_data (message);
  GNUNET_HashCode vhash;

  if (dm == NULL)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_CRYPTO_hash (&dm[1],
		      ntohl(dm->size),
		      &vhash);
  plugin->api->get (plugin->api->cls,
		    &dm->key,
		    &vhash,
		    ntohl(dm->type),
		    &remove_callback,
		    NULL);
  transmit_size (client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle DROP-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_drop (void *cls,
	     struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  plugin->api->drop (plugin->api->cls);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_init, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_INIT, 
   sizeof(struct GNUNET_MessageHeader) }, 
  {&handle_put, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_PUT, 0 }, 
  {&handle_get, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_GET, 0 }, 
  {&handle_get_random, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_GET_RANDOM, 
   sizeof(struct GNUNET_MessageHeader) }, 
  {&handle_remove, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE, 0 }, 
  {&handle_drop, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_DROP, 
   sizeof(struct GNUNET_MessageHeader) }, 
  {NULL, NULL, 0, 0}
};



/**
 * Load the datastore plugin.
 */
static struct DatastorePlugin *
load_plugin (struct GNUNET_CONFIGURATION_Handle *cfg,
	     struct GNUNET_SCHEDULER_Handle *sched)
{
  struct DatastorePlugin *ret;
  char *libname;
  char *name;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "DATASTORE", "DATABASE", &name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("No `%s' specified for `%s' in configuration!\n"),
		  "DATABASE",
		  "DATASTORE");
      return NULL;
    }
  ret = GNUNET_malloc (sizeof(struct DatastorePlugin));
  ret->env.cfg = cfg;
  ret->env.sched = sched;  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  ret->short_name = GNUNET_strdup (name);
  ret->lib_name = libname;
  ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
  if (ret->api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load datastore plugin for `%s'\n"), name);
      GNUNET_free (ret->short_name);
      GNUNET_free (libname);
      GNUNET_free (ret);
      return NULL;
    }
  return ret;
}


/**
 * Function called when the service shuts
 * down.  Unloads our datastore plugin.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
unload_plugin (struct DatastorePlugin *plug)
{
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Datastore service is unloading plugin...\n");
#endif
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
  GNUNET_free (plug->lib_name);
  GNUNET_free (plug->short_name);
  GNUNET_free (plug);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unload_plugin (plugin);
  plugin = NULL;
}


/**
 * Process datastore requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     struct GNUNET_CONFIGURATION_Handle *cfg)
{
  plugin = load_plugin (cfg, sched);
  if (NULL == plugin)
    return;
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
}


/**
 * The main function for the datastore service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_SERVICE_run (argc,
                             argv,
                             "datastore", &run, NULL, NULL, NULL)) ? 0 : 1;
  return ret;
}


/* end of gnunet-service-datastore.c */
