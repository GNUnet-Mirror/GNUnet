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
 * quota management code:
 * - track storage use
 * - track reservations
 * - refuse above-quota
 * - content expiration job
 * - near-quota low-priority content discard job
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "plugin_datastore.h"
#include "datastore.h"

/**
 * How many messages do we queue at most per client?
 */
#define MAX_PENDING 1024


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
 * Linked list of active reservations.
 */
struct ReservationList 
{

  /**
   * This is a linked list.
   */
  struct ReservationList *next;

  /**
   * Client that made the reservation.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Number of bytes (still) reserved.
   */
  uint64_t size;

  /**
   * Number of items (still) reserved.
   */
  uint64_t items;

  /**
   * Reservation identifier.
   */
  int32_t rid;

};


/**
 * Our datastore plugin (NULL if not available).
 */
static struct DatastorePlugin *plugin;

/**
 * Linked list of space reservations made by clients.
 */
static struct ReservationList *reservations;

/**
 * Bloomfilter to quickly tell if we don't have the content.
 */
static struct GNUNET_CONTAINER_BloomFilter *filter;

/**
 * Static counter to produce reservation identifiers.
 */
static int reservation_gen;

/**
 * How much space are we allowed to use?
 */
static unsigned long long quota;


/**
 * Function called once the transmit operation has
 * either failed or succeeded.
 *
 * @param cls closure
 * @param status GNUNET_OK on success, GNUNET_SYSERR on error
 */
typedef void (*TransmitContinuation)(void *cls,
				     int status);

struct TransmitCallbackContext 
{
  /**
   * The message that we're asked to transmit.
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Client that we are transmitting to.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Function to call once msg has been transmitted
   * (or at least added to the buffer).
   */
  TransmitContinuation tc;

  /**
   * Closure for tc.
   */
  void *tc_cls;

  /**
   * GNUNET_YES if we are supposed to signal the server
   * completion of the client's request.
   */
  int end;
};


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_callback (void *cls,
		   size_t size, void *buf)
{
  struct TransmitCallbackContext *tcc = cls;
  size_t msize;
  
  msize = ntohs(tcc->msg->size);
  if (size == 0)
    {
      if (tcc->tc != NULL)
	tcc->tc (tcc->tc_cls, GNUNET_SYSERR);
      if (GNUNET_YES == tcc->end)
	GNUNET_SERVER_receive_done (tcc->client, GNUNET_SYSERR);
      GNUNET_free (tcc->msg);
      GNUNET_free (tcc);
      return 0;
    }
  GNUNET_assert (size >= msize);
  memcpy (buf, tcc->msg, msize);
  if (tcc->tc != NULL)
    tcc->tc (tcc->tc_cls, GNUNET_OK);
  if (GNUNET_YES == tcc->end)
    GNUNET_SERVER_receive_done (tcc->client, GNUNET_OK);     
  GNUNET_free (tcc->msg);
  GNUNET_free (tcc);
  return msize;
}


/**
 * Transmit the given message to the client.
 *
 * @param client target of the message
 * @param msg message to transmit, will be freed!
 * @param end is this the last response (and we should
 *        signal the server completion accodingly after
 *        transmitting this message)?
 */
static void
transmit (struct GNUNET_SERVER_Client *client,
	  struct GNUNET_MessageHeader *msg,
	  TransmitContinuation tc,
	  void *tc_cls,
	  int end)
{
  struct TransmitCallbackContext *tcc;

  tcc = GNUNET_malloc (sizeof(struct TransmitCallbackContext));
  tcc->msg = msg;
  tcc->client = client;
  tcc->tc = tc;
  tcc->tc_cls = tc_cls;
  tcc->end = end;

  if (NULL ==
      GNUNET_SERVER_notify_transmit_ready (client,
					   ntohs(msg->size),
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   &transmit_callback,
					   tcc))
    {
      GNUNET_break (0);
      if (GNUNET_YES == end)
	GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      if (NULL != tc)
	tc (tc_cls, GNUNET_SYSERR);
      GNUNET_free (msg);
      GNUNET_free (tcc);
    }
}


/**
 * Transmit a status code to the client.
 *
 * @param client receiver of the response
 * @param code status code
 * @param msg optional error message (can be NULL)
 */
static void
transmit_status (struct GNUNET_SERVER_Client *client,
		 int code,
		 const char *msg)
{
  struct StatusMessage *sm;
  size_t slen;

  slen = (msg == NULL) ? 0 : strlen(msg) + 1;  
  sm = GNUNET_malloc (sizeof(struct StatusMessage) + slen);
  sm->header.size = htons(sizeof(struct StatusMessage) + slen);
  sm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_STATUS);
  sm->status = htonl(code);
  memcpy (&sm[1], msg, slen);  
  transmit (client, &sm->header, NULL, NULL, GNUNET_YES);
}


/**
 * Function called once the transmit operation has
 * either failed or succeeded.
 *
 * @param cls closure
 * @param status GNUNET_OK on success, GNUNET_SYSERR on error
 */
static void 
get_next(void *next_cls,
	 int status)
{
  if (status != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Failed to transmit an item to the client; aborting iteration.\n"));    
      plugin->api->next_request (next_cls, GNUNET_YES);
      return;
    }
  plugin->api->next_request (next_cls, GNUNET_NO);
}


/**
 * Function that will transmit the given datastore entry
 * to the client.
 *
 * @param cls closure, pointer to the client (of type GNUNET_SERVER_Client).
 * @param next_cls closure to use to ask for the next item
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
	       void *next_cls,
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
  struct GNUNET_MessageHeader *end;
  struct DataMessage *dm;

  if (key == NULL)
    {
      /* transmit 'DATA_END' */
      end = GNUNET_malloc (sizeof(struct GNUNET_MessageHeader));
      end->size = htons(sizeof(struct GNUNET_MessageHeader));
      end->type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END);
      transmit (client, end, NULL, NULL, GNUNET_YES);
      GNUNET_SERVER_client_drop (client);
      return GNUNET_OK;
    }
  dm = GNUNET_malloc (sizeof(struct DataMessage) + size);
  dm->header.size = htons(sizeof(struct DataMessage) + size);
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DATA);
  dm->rid = htonl(0);
  dm->size = htonl(size);
  dm->type = htonl(type);
  dm->priority = htonl(priority);
  dm->anonymity = htonl(anonymity);
  dm->expiration = GNUNET_TIME_absolute_hton(expiration);
  dm->uid = GNUNET_htonll(uid);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  transmit (client, &dm->header, &get_next, next_cls, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Handle RESERVE-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_reserve (void *cls,
	     struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  const struct ReserveMessage *msg = (const struct ReserveMessage*) message;
  struct ReservationList *e;

  /* FIXME: check if we have that much space... */
  e = GNUNET_malloc (sizeof(struct ReservationList));
  e->next = reservations;
  reservations = e;
  e->client = client;
  e->size = GNUNET_ntohll(msg->size);
  e->items = GNUNET_ntohll(msg->items);
  e->rid = ++reservation_gen;
  if (reservation_gen < 0)
    reservation_gen = 0; /* wrap around */
  transmit_status (client, e->rid, NULL);
}


/**
 * Handle RELEASE_RESERVE-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_release_reserve (void *cls,
			struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
{
  const struct ReleaseReserveMessage *msg = (const struct ReleaseReserveMessage*) message;
  struct ReservationList *pos;
  struct ReservationList *prev;
  struct ReservationList *next;
  
  int rid = ntohl(msg->rid);
  next = reservations;
  prev = NULL;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if (rid == pos->rid)
	{
	  if (prev == NULL)
	    reservations = next;
	  else
	    prev->next = next;
	  /* FIXME: released remaining reserved space! */
	  GNUNET_free (pos);
	  transmit_status (client, GNUNET_OK, NULL);
	  return;
	}       
      prev = pos;
      pos = next;
    }
  transmit_status (client, GNUNET_SYSERR, "Could not find matching reservation");
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
  if (ntohl(dm->type) == 0) 
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
  char *msg;
  int ret;
  int rid;

  if (dm == NULL)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  rid = ntohl(dm->rid);
  if (rid > 0)
    {
      /* FIXME: find reservation, update remaining! */
    }
  msg = NULL;
  ret = plugin->api->put (plugin->api->cls,
			  &dm->key,
			  ntohl(dm->size),
			  &dm[1],
			  ntohl(dm->type),
			  ntohl(dm->priority),
			  ntohl(dm->anonymity),
			  GNUNET_TIME_absolute_ntoh(dm->expiration),
			  &msg);
  if (GNUNET_OK == ret)
    GNUNET_CONTAINER_bloomfilter_add (filter,
				      &dm->key);
  transmit_status (client, 
		   GNUNET_SYSERR == ret ? GNUNET_SYSERR : GNUNET_OK, 
		   msg);
  GNUNET_free_non_null (msg);
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
  static struct GNUNET_TIME_Absolute zero;
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
  if ( (size == sizeof(struct GetMessage)) &&
       (GNUNET_YES != GNUNET_CONTAINER_bloomfilter_test (filter,
							 &msg->key)) )
    {
      /* don't bother database... */
      transmit_item (client,
		     NULL, NULL, 0, NULL, 0, 0, 0, zero, 0);
      return;
    }
  GNUNET_SERVER_client_drop (client);
  plugin->api->get (plugin->api->cls,
		    ((size == sizeof(struct GetMessage)) ? &msg->key : NULL),
		    NULL,
		    ntohl(msg->type),
		    &transmit_item,
		    client);    
}


/**
 * Handle UPDATE-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_update (void *cls,
	       struct GNUNET_SERVER_Client *client,
	       const struct GNUNET_MessageHeader *message)
{
  const struct UpdateMessage *msg;
  int ret;
  char *emsg;

  msg = (const struct UpdateMessage*) message;
  emsg = NULL;
  ret = plugin->api->update (plugin->api->cls,
			     GNUNET_ntohll(msg->uid),
			     (int32_t) ntohl(msg->priority),
			     GNUNET_TIME_absolute_ntoh(msg->expiration),
			     &emsg);
  transmit_status (client, ret, emsg);
  GNUNET_free_non_null (emsg);
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
  GNUNET_SERVER_client_drop (client);
  plugin->api->iter_migration_order (plugin->api->cls,
				     0,
				     &transmit_item,
				     client);  
}


/**
 * Context for the 'remove_callback'.
 */
struct RemoveContext 
{
  /**
   * Client for whom we're doing the remvoing.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * GNUNET_YES if we managed to remove something.
   */
  int found;
};


/**
 * Callback function that will cause the item that is passed
 * in to be deleted (by returning GNUNET_NO).
 */
static int
remove_callback (void *cls,
		 void *next_cls,
		 const GNUNET_HashCode * key,
		 uint32_t size,
		 const void *data,
		 uint32_t type,
		 uint32_t priority,
		 uint32_t anonymity,
		 struct GNUNET_TIME_Absolute
		 expiration, unsigned long long uid)
{
  struct RemoveContext *rc = cls;
  if (key == NULL)
    {
      if (GNUNET_YES == rc->found)
	transmit_status (rc->client, GNUNET_OK, NULL);       
      else
	transmit_status (rc->client, GNUNET_SYSERR, _("Content not found"));       	
      GNUNET_SERVER_client_drop (rc->client);
      GNUNET_free (rc);
      return GNUNET_OK; /* last item */
    }
  rc->found = GNUNET_YES;
  plugin->api->next_request (next_cls, GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter,
				       key);
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
  struct RemoveContext *rc;

  if (dm == NULL)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  rc = GNUNET_malloc (sizeof(struct RemoveContext));
  GNUNET_SERVER_client_keep (client);
  rc->client = client;
  GNUNET_CRYPTO_hash (&dm[1],
		      ntohl(dm->size),
		      &vhash);
  plugin->api->get (plugin->api->cls,
		    &dm->key,
		    &vhash,
		    ntohl(dm->type),
		    &remove_callback,
		    rc);
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
  {&handle_reserve, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE, 
   sizeof(struct ReserveMessage) }, 
  {&handle_release_reserve, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE, 
   sizeof(struct ReleaseReserveMessage) }, 
  {&handle_put, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_PUT, 0 }, 
  {&handle_update, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE, 
   sizeof (struct UpdateMessage) }, 
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
 * @param plug plugin to unload
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
 * Function that removes all active reservations made
 * by the given client and releases the space for other
 * requests.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
cleanup_reservations (void *cls,
		      struct GNUNET_SERVER_Client
		      * client)
{
  /* FIXME */
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
  char *fn;
  unsigned int bf_size;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "DATASTORE", "QUOTA", &quota))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("No `%s' specified for `%s' in configuration!\n"),
		  "QUOTA",
		  "DATASTORE");
      return;
    }
  bf_size = quota / 32; /* 8 bit per entry, 1 bit per 32 kb in DB */
  fn = NULL;
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_filename (cfg,
						 "DATASTORE",
						 "BLOOMFILTER",
						 &fn)) ||
       (GNUNET_OK !=
	GNUNET_DISK_directory_create_for_file (fn)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Could not use specified filename `%s' for bloomfilter.\n"),
		  fn != NULL ? fn : "");
      GNUNET_free_non_null (fn);
      fn = NULL;
    }
  filter = GNUNET_CONTAINER_bloomfilter_load (fn, bf_size, 5);  /* approx. 3% false positives at max use */  
  GNUNET_free_non_null (fn);
  if (filter == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to initialize bloomfilter.\n"));
      return;
    }
  plugin = load_plugin (cfg, sched);
  if (NULL == plugin)
    {
      GNUNET_CONTAINER_bloomfilter_free (filter);
      return;
    }
  GNUNET_SERVER_disconnect_notify (server, &cleanup_reservations, NULL);
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
