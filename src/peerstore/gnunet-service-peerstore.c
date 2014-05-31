/*
     This file is part of GNUnet.
     (C) 

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
 * Context of a PEERSTORE watch
 */
struct WatchContext
{

  /**
   * Hash of key of watched record
   */
  struct GNUNET_HashCode keyhash;

  /**
   * Client requested the watch
   */
  struct GNUNET_SERVER_Client *client;

};

/**
 * Interval for expired records cleanup (in seconds)
 */
#define CLEANUP_INTERVAL 300 /* 5mins */

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Database plugin library name
 */
char *db_lib_name;

/**
 * Database handle
 */
static struct GNUNET_PEERSTORE_PluginFunctions *db;

/**
 * Hashmap with all watch requests
 */
static struct GNUNET_CONTAINER_MultiHashMap *watchers;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

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
  if(NULL != db_lib_name)
  {
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, db));
    GNUNET_free (db_lib_name);
    db_lib_name = NULL;
  }
  GNUNET_SERVER_notification_context_destroy(nc);
  GNUNET_CONTAINER_multihashmap_destroy(watchers);
  GNUNET_SCHEDULER_shutdown();
}

/**
 * Deletes any expired records from storage
 */
static void
cleanup_expired_records(void *cls,
    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int deleted;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert(NULL != db);
  deleted = db->expire_records(db->cls, GNUNET_TIME_absolute_get());
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "%d records expired.\n", deleted);
  GNUNET_SCHEDULER_add_delayed(
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, CLEANUP_INTERVAL),
      &cleanup_expired_records, NULL);
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client
			  * client)
{
}

/**
 * Function called by for each matching record.
 *
 * @param cls closure
 * @param peer peer identity
 * @param sub_system name of the GNUnet sub system responsible
 * @param value stored value
 * @param size size of stored value
 */
int record_iterator(void *cls,
    struct GNUNET_PEERSTORE_Record *record,
    char *emsg)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct StoreRecordMessage *srm;

  srm = PEERSTORE_create_record_message(record->sub_system,
      record->peer,
      record->key,
      record->value,
      record->value_size,
      record->expiry,
      GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD);
  GNUNET_SERVER_transmit_context_append_message(tc, (const struct GNUNET_MessageHeader *)srm);
  return GNUNET_YES;
}

/**
 * Iterator over all watcher clients
 * to notify them of a new record
 *
 * @param cls closuer, a 'struct GNUNET_PEERSTORE_Record *'
 * @param key hash of record key
 * @param value the watcher client, a 'struct GNUNET_SERVER_Client *'
 * @return #GNUNET_YES to continue iterating
 */
int watch_notifier_it(void *cls,
    const struct GNUNET_HashCode *key,
    void *value)
{
  struct GNUNET_PEERSTORE_Record *record = cls;
  struct GNUNET_SERVER_Client *client = value;
  struct StoreRecordMessage *srm;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Found a watcher to update.\n");
  if(NULL == value)
  {
    GNUNET_CONTAINER_multihashmap_remove(watchers, key, value);
    return GNUNET_YES;
  }
  srm = PEERSTORE_create_record_message(record->sub_system,
      record->peer,
      record->key,
      record->value,
      record->value_size,
      record->expiry,
      GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD);
  GNUNET_SERVER_notification_context_unicast(nc, client,
      (const struct GNUNET_MessageHeader *)srm, GNUNET_YES);
  return GNUNET_YES;
}

/**
 * Given a new record, notifies watchers
 *
 * @cls closure, a 'struct GNUNET_PEERSTORE_Record *'
 * @tc unused
 */
void watch_notifier (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PEERSTORE_Record *record = cls;
  struct GNUNET_HashCode keyhash;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Sending update to any watchers.\n");
  PEERSTORE_hash_key(record->sub_system,
      record->peer,
      record->key,
      &keyhash);
  GNUNET_CONTAINER_multihashmap_get_multiple(watchers, &keyhash, &watch_notifier_it, record);
}

/**
 * Handle a watch cancel request from client
 *
 * @param cls unused
 * @param client identification of the client
 * @param message the actual message
 */
void handle_watch_cancel (void *cls,
    struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
  struct StoreKeyHashMessage *hm;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received a watch cancel request from client.\n");
  hm = (struct StoreKeyHashMessage *) message;
  GNUNET_CONTAINER_multihashmap_remove(watchers, &hm->keyhash, client);
  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Handle a watch request from client
 *
 * @param cls unused
 * @param client identification of the client
 * @param message the actual message
 */
void handle_watch (void *cls,
    struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
  struct StoreKeyHashMessage *hm;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received a watch request from client.\n");
  hm = (struct StoreKeyHashMessage *) message;
  GNUNET_SERVER_client_mark_monitor(client);
  GNUNET_SERVER_notification_context_add(nc, client);
  GNUNET_CONTAINER_multihashmap_put(watchers, &hm->keyhash,
     client, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Handle an iterate request from client
 *
 * @param cls unused
 * @param client identification of the client
 * @param message the actual message
 */
void handle_iterate (void *cls,
    struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_PEERSTORE_Record *record;
  struct GNUNET_SERVER_TransmitContext *tc;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received an iterate request from client.\n");
  record = PEERSTORE_parse_record_message(message);
  if(NULL == record)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Malformed iterate request from client\n");
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
    return;
  }
  if(NULL == record->sub_system)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Sub system not supplied in client iterate request\n");
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
    return;
  }
  tc = GNUNET_SERVER_transmit_context_create (client);
  if(GNUNET_OK == db->iterate_records(db->cls,
      record->sub_system,
      record->peer,
      record->key,
      &record_iterator,
      tc))
  {
    GNUNET_SERVER_transmit_context_append_data(tc, NULL, 0, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END);
    GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
  }
  else
  {
    GNUNET_free(tc);
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
  }
  GNUNET_free(record); /* FIXME: destroy record */
}

/**
 * Handle a store request from client
 *
 * @param cls unused
 * @param client identification of the client
 * @param message the actual message
 */
void handle_store (void *cls,
    struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_PEERSTORE_Record *record;
  struct GNUNET_SERVER_TransmitContext *tc;

  record = PEERSTORE_parse_record_message(message);
  if(NULL == record)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Malformed store request from client\n");
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
    return;
  }
  if(NULL == record->sub_system
      || NULL == record->peer
      || NULL == record->key)
  {
    /* FIXME: Destroy record */
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Full key not supplied in client store request\n");
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Received a store request (size: %lu) for sub system `%s', peer `%s', key `%s'\n",
      record->value_size,
      record->sub_system,
      GNUNET_i2s (record->peer),
      record->key);
  if(GNUNET_OK != db->store_record(db->cls,
      record->sub_system,
      record->peer,
      record->key,
      record->value,
      record->value_size,
      *record->expiry))
  {
    /* FIXME: Destroy record */
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to store requested value, sqlite database error.");
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
    return;
  }
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_SERVER_transmit_context_append_data(tc, NULL, 0, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_OK);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
  GNUNET_SCHEDULER_add_continuation(&watch_notifier, record, -1);
}

/**
 * Peerstore service runner.
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
      {&handle_store, NULL, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE, 0},
      {&handle_iterate, NULL, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE, 0},
      {&handle_watch, NULL, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH, sizeof(struct StoreKeyHashMessage)},
      {&handle_watch_cancel, NULL, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL, sizeof(struct StoreKeyHashMessage)},
      {NULL, NULL, 0, 0}
  };
  char *database;

  cfg = c;
  if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (cfg, "peerstore", "DATABASE",
                                               &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  else
  {
    GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_peerstore_%s", database);
    db = GNUNET_PLUGIN_load(db_lib_name, (void *) cfg);
    GNUNET_free(database);
  }
  if(NULL == db)
	  GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not load database backend `%s'\n", db_lib_name);
  else
  {
    nc = GNUNET_SERVER_notification_context_create (server, 16);
    watchers = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
    GNUNET_SCHEDULER_add_now(&cleanup_expired_records, NULL);
    GNUNET_SERVER_add_handlers (server, handlers);
    GNUNET_SERVER_disconnect_notify (server,
             &handle_client_disconnect,
             NULL);
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
}


/**
 * The main function for the peerstore service.
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
                              "peerstore",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-peerstore.c */
