/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file peerstore/gnunet-service-peerstore.c
 * @brief peerstore service implementation
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "peerstore.h"
#include "gnunet_peerstore_plugin.h"
#include "peerstore_common.h"


/**
 * Interval for expired records cleanup (in seconds)
 */
#define EXPIRED_RECORDS_CLEANUP_INTERVAL 300    /* 5mins */

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Database plugin library name
 */
static char *db_lib_name;

/**
 * Database handle
 */
static struct GNUNET_PEERSTORE_PluginFunctions *db;

/**
 * Hashmap with all watch requests
 */
static struct GNUNET_CONTAINER_MultiHashMap *watchers;

/**
 * Task run to clean up expired records.
 */
static struct GNUNET_SCHEDULER_Task *expire_task;

/**
 * Are we in the process of shutting down the service? #GNUNET_YES / #GNUNET_NO
 */
static int in_shutdown;

/**
 * Number of connected clients.
 */
static unsigned int num_clients;


/**
 * Perform the actual shutdown operations
 */
static void
do_shutdown ()
{
  if (NULL != db_lib_name)
  {
    GNUNET_break (NULL ==
                  GNUNET_PLUGIN_unload (db_lib_name,
                                        db));
    GNUNET_free (db_lib_name);
    db_lib_name = NULL;
  }
  if (NULL != watchers)
  {
    GNUNET_CONTAINER_multihashmap_destroy (watchers);
    watchers = NULL;
  }
  if (NULL != expire_task)
  {
    GNUNET_SCHEDULER_cancel (expire_task);
    expire_task = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  in_shutdown = GNUNET_YES;
  if (0 == num_clients)      /* Only when no connected clients. */
    do_shutdown ();
}


/* Forward declaration */
static void
expire_records_continuation (void *cls,
                             int success);


/**
 * Deletes any expired records from storage
 */
static void
cleanup_expired_records (void *cls)
{
  int ret;

  expire_task = NULL;
  GNUNET_assert (NULL != db);
  ret = db->expire_records (db->cls,
                            GNUNET_TIME_absolute_get (),
			    &expire_records_continuation,
                            NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_assert (NULL == expire_task);
    expire_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
						(GNUNET_TIME_UNIT_SECONDS,
						 EXPIRED_RECORDS_CLEANUP_INTERVAL),
						&cleanup_expired_records,
                                                NULL);
  }
}


/**
 * Continuation to expire_records called by the peerstore plugin
 *
 * @param cls unused
 * @param success count of records deleted or #GNUNET_SYSERR
 */
static void
expire_records_continuation (void *cls,
			     int success)
{
  if (success > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"%d records expired.\n",
		success);
  GNUNET_assert (NULL == expire_task);
  expire_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
					      (GNUNET_TIME_UNIT_SECONDS,
					       EXPIRED_RECORDS_CLEANUP_INTERVAL),
					      &cleanup_expired_records,
                                              NULL);
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param mq the message queue
 * @return
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  num_clients++;
  return client;
}


/**
 * Search for a disconnected client and remove it
 *
 * @param cls closuer, a `struct GNUNET_SERVICE_Client`
 * @param key hash of record key
 * @param value the watcher client, a `struct GNUNET_SERVICE_Client *`
 * @return #GNUNET_OK to continue iterating
 */
static int
client_disconnect_it (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  if (value == cls)
  {
    GNUNET_CONTAINER_multihashmap_remove (watchers,
                                          key,
                                          value);
    num_clients++;
  }
  return GNUNET_OK;
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "A client disconnected, cleaning up.\n");
  if (NULL != watchers)
    GNUNET_CONTAINER_multihashmap_iterate (watchers,
                                           &client_disconnect_it,
                                           client);
  num_clients--;
  if ( (0 == num_clients) &&
       in_shutdown)
    do_shutdown ();
}


/**
 * Function called by for each matching record.
 *
 * @param cls closure
 * @param record peerstore record found
 * @param emsg error message or NULL if no errors
 * @return #GNUNET_YES to continue iteration
 */
static void
record_iterator (void *cls,
                 const struct GNUNET_PEERSTORE_Record *record,
                 const char *emsg)
{
  struct GNUNET_PEERSTORE_Record *cls_record = cls;
  struct GNUNET_MQ_Envelope *env;

  if (NULL == record)
  {
    /* No more records */
    struct GNUNET_MessageHeader *endmsg;

    env = GNUNET_MQ_msg (endmsg,
                         GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (cls_record->client),
                    env);
    if (NULL == emsg)
      GNUNET_SERVICE_client_continue (cls_record->client);
    else
      GNUNET_SERVICE_client_drop (cls_record->client);
    PEERSTORE_destroy_record (cls_record);
    return;
  }

  env = PEERSTORE_create_record_mq_envelope (record->sub_system,
                                             record->peer,
                                             record->key,
                                             record->value,
                                             record->value_size,
                                             record->expiry,
                                             0,
                                             GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (cls_record->client),
                  env);
}


/**
 * Iterator over all watcher clients
 * to notify them of a new record
 *
 * @param cls closure, a `struct GNUNET_PEERSTORE_Record *`
 * @param key hash of record key
 * @param value the watcher client, a `struct GNUNET_SERVICE_Client *`
 * @return #GNUNET_YES to continue iterating
 */
static int
watch_notifier_it (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct GNUNET_PEERSTORE_Record *record = cls;
  struct GNUNET_SERVICE_Client *client = value;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found a watcher to update.\n");
  env = PEERSTORE_create_record_mq_envelope (record->sub_system,
                                             record->peer,
                                             record->key,
                                             record->value,
                                             record->value_size,
                                             record->expiry,
                                             0,
                                             GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  return GNUNET_YES;
}


/**
 * Given a new record, notifies watchers
 *
 * @param record changed record to update watchers with
 */
static void
watch_notifier (struct GNUNET_PEERSTORE_Record *record)
{
  struct GNUNET_HashCode keyhash;

  PEERSTORE_hash_key (record->sub_system,
                      record->peer,
                      record->key,
                      &keyhash);
  GNUNET_CONTAINER_multihashmap_get_multiple (watchers,
                                              &keyhash,
                                              &watch_notifier_it,
                                              record);
}


/**
 * Handle a watch cancel request from client
 *
 * @param cls identification of the client
 * @param hm the actual message
 */
static void
handle_watch_cancel (void *cls,
                     const struct StoreKeyHashMessage *hm)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a watch cancel request.\n");
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_remove (watchers,
                                            &hm->keyhash,
                                            client))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  num_clients++;
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle a watch request from client
 *
 * @param cls identification of the client
 * @param hm the actual message
 */
static void
handle_watch (void *cls,
              const struct StoreKeyHashMessage *hm)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a watch request.\n");
  num_clients--; /* do not count watchers */
  GNUNET_SERVICE_client_mark_monitor (client);
  GNUNET_CONTAINER_multihashmap_put (watchers,
                                     &hm->keyhash,
                                     client,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Check an iterate request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 * @return #GNUNET_OK if @a srm is well-formed
 */
static int
check_iterate (void *cls,
               const struct StoreRecordMessage *srm)
{
  struct GNUNET_PEERSTORE_Record *record;

  record = PEERSTORE_parse_record_message (srm);
  if (NULL == record)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == record->sub_system)
  {
    GNUNET_break (0);
    PEERSTORE_destroy_record (record);
    return GNUNET_SYSERR;
  }
  PEERSTORE_destroy_record (record);
  return GNUNET_OK;
}


/**
 * Handle an iterate request from client
 *
 * @param cls identification of the client
 * @param srm the actual message
 */
static void
handle_iterate (void *cls,
                const struct StoreRecordMessage *srm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_PEERSTORE_Record *record;

  record = PEERSTORE_parse_record_message (srm);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Iterate request: ss `%s', peer `%s', key `%s'\n",
              record->sub_system,
              (NULL == record->peer) ? "NULL" : GNUNET_i2s (record->peer),
              (NULL == record->key) ? "NULL" : record->key);
  record->client = client;
  if (GNUNET_OK !=
      db->iterate_records (db->cls,
                           record->sub_system,
                           record->peer,
                           record->key,
                           &record_iterator,
                           record))
  {
    GNUNET_SERVICE_client_drop (client);
    PEERSTORE_destroy_record (record);
  }
}


/**
 * Continuation of store_record called by the peerstore plugin
 *
 * @param cls closure
 * @param success result
 */
static void
store_record_continuation (void *cls,
                           int success)
{
  struct GNUNET_PEERSTORE_Record *record = cls;

  if (GNUNET_OK == success)
  {
    watch_notifier (record);
    GNUNET_SERVICE_client_continue (record->client);
  }
  else
  {
    GNUNET_SERVICE_client_drop (record->client);
  }
  PEERSTORE_destroy_record (record);
}


/**
 * Check a store request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 * @return #GNUNET_OK if @a srm is well-formed
 */
static int
check_store (void *cls,
              const struct StoreRecordMessage *srm)
{
  struct GNUNET_PEERSTORE_Record *record;

  record = PEERSTORE_parse_record_message (srm);
  if (NULL == record)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ( (NULL == record->sub_system) ||
       (NULL == record->peer) ||
       (NULL == record->key) )
  {
    GNUNET_break (0);
    PEERSTORE_destroy_record (record);
    return GNUNET_SYSERR;
  }
  PEERSTORE_destroy_record (record);
  return GNUNET_OK;
}


/**
 * Handle a store request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 */
static void
handle_store (void *cls,
              const struct StoreRecordMessage *srm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_PEERSTORE_Record *record;

  record = PEERSTORE_parse_record_message (srm);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received a store request. Sub system `%s' Peer `%s Key `%s' Options: %d.\n",
	      record->sub_system,
              GNUNET_i2s (record->peer),
	      record->key,
              ntohl (srm->options));
  record->client = client;
  if (GNUNET_OK !=
      db->store_record (db->cls,
                        record->sub_system,
                        record->peer,
                        record->key,
                        record->value,
                        record->value_size,
                        *record->expiry,
                        ntohl (srm->options),
                        &store_record_continuation,
                        record))
  {
    PEERSTORE_destroy_record (record);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
}


/**
 * Peerstore service runner.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  char *database;

  in_shutdown = GNUNET_NO;
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "peerstore",
                                             "DATABASE",
                                             &database))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "peerstore",
                               "DATABASE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_peerstore_%s",
                   database);
  db = GNUNET_PLUGIN_load (db_lib_name,
                           (void *) cfg);
  GNUNET_free (database);
  if (NULL == db)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not load database backend `%s'\n"),
		db_lib_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  watchers = GNUNET_CONTAINER_multihashmap_create (10,
                                                   GNUNET_NO);
  expire_task = GNUNET_SCHEDULER_add_now (&cleanup_expired_records,
					  NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("peerstore",
 GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (store,
                        GNUNET_MESSAGE_TYPE_PEERSTORE_STORE,
                        struct StoreRecordMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (iterate,
                        GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE,
                        struct StoreRecordMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (watch,
			  GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH,
			  struct StoreKeyHashMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (watch_cancel,
			  GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL,
			  struct StoreKeyHashMessage,
			  NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-peerstore.c */
