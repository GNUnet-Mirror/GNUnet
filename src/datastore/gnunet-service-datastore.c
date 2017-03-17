/*
     This file is part of GNUnet
     Copyright (C) 2004-2014, 2016 GNUnet e.V.

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
 * @file datastore/gnunet-service-datastore.c
 * @brief Management for the datastore for files stored on a GNUnet node
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_datastore_plugin.h"
#include "datastore.h"

/**
 * How many messages do we queue at most per client?
 */
#define MAX_PENDING 1024

/**
 * Limit size of bloom filter to 2 GB.
 */
#define MAX_BF_SIZE ((uint32_t) (1LL << 31))

/**
 * How long are we at most keeping "expired" content
 * past the expiration date in the database?
 */
#define MAX_EXPIRE_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How fast are we allowed to query the database for deleting
 * expired content? (1 item per second).
 */
#define MIN_EXPIRE_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Name under which we store current space consumption.
 */
static char *quota_stat_name;

/**
 * Task to timeout stat GET.
 */
static struct GNUNET_SCHEDULER_Task *stat_timeout_task;

/**
 * After how many payload-changing operations
 * do we sync our statistics?
 */
#define MAX_STAT_SYNC_LAG 50


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
  struct GNUNET_SERVICE_Client *client;

  /**
   * Number of bytes (still) reserved.
   */
  uint64_t amount;

  /**
   * Number of items (still) reserved.
   */
  uint64_t entries;

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
 * Name of our plugin.
 */
static char *plugin_name;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * How much space are we using for the cache?  (space available for
 * insertions that will be instantly reclaimed by discarding less
 * important content --- or possibly whatever we just inserted into
 * the "cache").
 */
static unsigned long long cache_size;

/**
 * How much space have we currently reserved?
 */
static unsigned long long reserved;

/**
 * How much data are we currently storing
 * in the database?
 */
static unsigned long long payload;

/**
 * Identity of the task that is used to delete
 * expired content.
 */
static struct GNUNET_SCHEDULER_Task *expired_kill_task;

/**
 * Minimum time that content should have to not be discarded instantly
 * (time stamp of any content that we've been discarding recently to
 * stay below the quota).  FOREVER if we had to expire content with
 * non-zero priority.
 */
static struct GNUNET_TIME_Absolute min_expiration;

/**
 * How much space are we allowed to use?
 */
static unsigned long long quota;

/**
 * Should the database be dropped on exit?
 */
static int do_drop;

/**
 * Should we refresh the BF when the DB is loaded?
 */
static int refresh_bf;

/**
 * Number of updates that were made to the
 * payload value since we last synchronized
 * it with the statistics service.
 */
static unsigned int last_sync;

/**
 * Did we get an answer from statistics?
 */
static int stats_worked;


/**
 * Synchronize our utilization statistics with the
 * statistics service.
 */
static void
sync_stats ()
{
  GNUNET_STATISTICS_set (stats,
                         quota_stat_name,
                         payload,
                         GNUNET_YES);
  GNUNET_STATISTICS_set (stats,
                         "# utilization by current datastore",
                         payload,
                         GNUNET_NO);
  last_sync = 0;
}


/**
 * Have we already cleaned up the TCCs and are hence no longer
 * willing (or able) to transmit anything to anyone?
 */
static int cleaning_done;

/**
 * Handle for pending get request.
 */
static struct GNUNET_STATISTICS_GetHandle *stat_get;

/**
 * Handle to our server.
 */
static struct GNUNET_SERVICE_Handle *service;

/**
 * Task that is used to remove expired entries from
 * the datastore.  This task will schedule itself
 * again automatically to always delete all expired
 * content quickly.
 *
 * @param cls not used
 */
static void
delete_expired (void *cls);


/**
 * Iterate over the expired items stored in the datastore.
 * Delete all expired items; once we have processed all
 * expired items, re-schedule the "delete_expired" task.
 *
 * @param cls not used
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
 * @return #GNUNET_SYSERR to abort the iteration, #GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         #GNUNET_NO to delete the item and continue (if supported)
 */
static int
expired_processor (void *cls,
                   const struct GNUNET_HashCode *key,
                   uint32_t size,
                   const void *data,
                   enum GNUNET_BLOCK_Type type,
                   uint32_t priority,
                   uint32_t anonymity,
                   struct GNUNET_TIME_Absolute expiration,
                   uint64_t uid)
{
  struct GNUNET_TIME_Absolute now;

  if (NULL == key)
  {
    expired_kill_task =
        GNUNET_SCHEDULER_add_delayed_with_priority (MAX_EXPIRE_DELAY,
						    GNUNET_SCHEDULER_PRIORITY_IDLE,
						    &delete_expired, NULL);
    return GNUNET_SYSERR;
  }
  now = GNUNET_TIME_absolute_get ();
  if (expiration.abs_value_us > now.abs_value_us)
  {
    /* finished processing */
    expired_kill_task =
        GNUNET_SCHEDULER_add_delayed_with_priority (MAX_EXPIRE_DELAY,
						    GNUNET_SCHEDULER_PRIORITY_IDLE,
						    &delete_expired, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting content `%s' of type %u that expired %s ago\n",
              GNUNET_h2s (key), type,
	      GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (expiration,
											   now),
						      GNUNET_YES));
  min_expiration = now;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes expired"),
                            size,
                            GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter, key);
  expired_kill_task =
      GNUNET_SCHEDULER_add_delayed_with_priority (MIN_EXPIRE_DELAY,
						  GNUNET_SCHEDULER_PRIORITY_IDLE,
						  &delete_expired, NULL);
  return GNUNET_NO;
}


/**
 * Task that is used to remove expired entries from
 * the datastore.  This task will schedule itself
 * again automatically to always delete all expired
 * content quickly.
 *
 * @param cls not used
 */
static void
delete_expired (void *cls)
{
  expired_kill_task = NULL;
  plugin->api->get_expiration (plugin->api->cls,
			       &expired_processor,
			       NULL);
}


/**
 * An iterator over a set of items stored in the datastore
 * that deletes until we're happy with respect to our quota.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_SYSERR to abort the iteration, #GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         #GNUNET_NO to delete the item and continue (if supported)
 */
static int
quota_processor (void *cls,
                 const struct GNUNET_HashCode *key,
                 uint32_t size,
                 const void *data,
                 enum GNUNET_BLOCK_Type type,
                 uint32_t priority,
                 uint32_t anonymity,
                 struct GNUNET_TIME_Absolute expiration,
                 uint64_t uid)
{
  unsigned long long *need = cls;

  if (NULL == key)
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting %llu bytes of low-priority (%u) content `%s' of type %u at %s prior to expiration (still trying to free another %llu bytes)\n",
              (unsigned long long) (size + GNUNET_DATASTORE_ENTRY_OVERHEAD),
	      (unsigned int) priority,
              GNUNET_h2s (key), type,
	      GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (expiration),
						      GNUNET_YES),
	      *need);
  if (size + GNUNET_DATASTORE_ENTRY_OVERHEAD > *need)
    *need = 0;
  else
    *need -= size + GNUNET_DATASTORE_ENTRY_OVERHEAD;
  if (priority > 0)
    min_expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
  else
    min_expiration = expiration;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes purged (low-priority)"),
                            size, GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter, key);
  return GNUNET_NO;
}


/**
 * Manage available disk space by running tasks
 * that will discard content if necessary.  This
 * function will be run whenever a request for
 * "need" bytes of storage could only be satisfied
 * by eating into the "cache" (and we want our cache
 * space back).
 *
 * @param need number of bytes of content that were
 *        placed into the "cache" (and hence the
 *        number of bytes that should be removed).
 */
static void
manage_space (unsigned long long need)
{
  unsigned long long last;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to free up %llu bytes of cache space\n",
              need);
  last = 0;
  while ((need > 0) && (last != need))
  {
    last = need;
    plugin->api->get_expiration (plugin->api->cls,
                                 &quota_processor,
                                 &need);
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
transmit_status (struct GNUNET_SERVICE_Client *client,
                 int code,
                 const char *msg)
{
  struct GNUNET_MQ_Envelope *env;
  struct StatusMessage *sm;
  size_t slen;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' message with value %d and message `%s'\n",
              "STATUS", code, msg != NULL ? msg : "(none)");
  slen = (msg == NULL) ? 0 : strlen (msg) + 1;
  env = GNUNET_MQ_msg_extra (sm,
                             slen,
                             GNUNET_MESSAGE_TYPE_DATASTORE_STATUS);
  sm->status = htonl (code);
  sm->min_expiration = GNUNET_TIME_absolute_hton (min_expiration);
  GNUNET_memcpy (&sm[1],
                 msg,
                 slen);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
}


/**
 * Function that will transmit the given datastore entry
 * to the client.
 *
 * @param cls closure, pointer to the client (of type `struct GNUNET_SERVICE_Client`).
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_SYSERR to abort the iteration, #GNUNET_OK to continue,
 *         #GNUNET_NO to delete the item and continue (if supported)
 */
static int
transmit_item (void *cls,
               const struct GNUNET_HashCode *key,
               uint32_t size,
               const void *data,
               enum GNUNET_BLOCK_Type type,
               uint32_t priority,
               uint32_t anonymity,
               struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *end;
  struct DataMessage *dm;

  if (NULL == key)
  {
    /* transmit 'DATA_END' */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting DATA_END message\n");
    env = GNUNET_MQ_msg (end,
                         GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                    env);
    return GNUNET_OK;
  }
  GNUNET_assert (sizeof (struct DataMessage) + size <
                 GNUNET_MAX_MESSAGE_SIZE);
  env = GNUNET_MQ_msg_extra (dm,
                             size,
                             GNUNET_MESSAGE_TYPE_DATASTORE_DATA);
  dm->rid = htonl (0);
  dm->size = htonl (size);
  dm->type = htonl (type);
  dm->priority = htonl (priority);
  dm->anonymity = htonl (anonymity);
  dm->replication = htonl (0);
  dm->reserved = htonl (0);
  dm->expiration = GNUNET_TIME_absolute_hton (expiration);
  dm->uid = GNUNET_htonll (uid);
  dm->key = *key;
  GNUNET_memcpy (&dm[1],
                 data,
                 size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting DATA message for `%s' of type %u with expiration %s (in: %s)\n",
              GNUNET_h2s (key),
              type,
              GNUNET_STRINGS_absolute_time_to_string (expiration),
              GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (expiration),
						      GNUNET_YES));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# results found"),
                            1,
                            GNUNET_NO);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  return GNUNET_OK;
}


/**
 * Handle RESERVE-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_reserve (void *cls,
                const struct ReserveMessage *msg)
{
  /**
   * Static counter to produce reservation identifiers.
   */
  static int reservation_gen;
  struct GNUNET_SERVICE_Client *client = cls;
  struct ReservationList *e;
  unsigned long long used;
  unsigned long long req;
  uint64_t amount;
  uint32_t entries;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing RESERVE request\n");
  amount = GNUNET_ntohll (msg->amount);
  entries = ntohl (msg->entries);
  used = payload + reserved;
  req = amount + ((unsigned long long) GNUNET_DATASTORE_ENTRY_OVERHEAD) * entries;
  if (used + req > quota)
  {
    if (quota < used)
      used = quota;             /* cheat a bit for error message (to avoid negative numbers) */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Insufficient space (%llu bytes are available) to satisfy RESERVE request for %llu bytes\n"),
                quota - used,
                req);
    if (cache_size < req)
    {
      /* TODO: document this in the FAQ; essentially, if this
       * message happens, the insertion request could be blocked
       * by less-important content from migration because it is
       * larger than 1/8th of the overall available space, and
       * we only reserve 1/8th for "fresh" insertions */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("The requested amount (%llu bytes) is larger than the cache size (%llu bytes)\n"),
                  req,
                  cache_size);
      transmit_status (client,
                       0,
                       gettext_noop
                       ("Insufficient space to satisfy request and "
                        "requested amount is larger than cache size"));
    }
    else
    {
      transmit_status (client,
                       0,
                       gettext_noop ("Insufficient space to satisfy request"));
    }
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  reserved += req;
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# reserved"),
                         reserved,
                         GNUNET_NO);
  e = GNUNET_new (struct ReservationList);
  e->next = reservations;
  reservations = e;
  e->client = client;
  e->amount = amount;
  e->entries = entries;
  e->rid = ++reservation_gen;
  if (reservation_gen < 0)
    reservation_gen = 0;        /* wrap around */
  transmit_status (client,
                   e->rid,
                   NULL);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle RELEASE_RESERVE-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_release_reserve (void *cls,
                        const struct ReleaseReserveMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct ReservationList *pos;
  struct ReservationList *prev;
  struct ReservationList *next;
  int rid = ntohl (msg->rid);
  unsigned long long rem;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing RELEASE_RESERVE request\n");
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
      rem =
          pos->amount +
          ((unsigned long long) GNUNET_DATASTORE_ENTRY_OVERHEAD) * pos->entries;
      GNUNET_assert (reserved >= rem);
      reserved -= rem;
      GNUNET_STATISTICS_set (stats,
                             gettext_noop ("# reserved"),
                             reserved,
                             GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Returning %llu remaining reserved bytes to storage pool\n",
                  rem);
      GNUNET_free (pos);
      transmit_status (client,
                       GNUNET_OK,
                       NULL);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
    prev = pos;
  }
  GNUNET_break (0);
  transmit_status (client,
                   GNUNET_SYSERR,
                   gettext_noop ("Could not find matching reservation"));
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Check that the given message is a valid data message.
 *
 * @param dm message to check
 * @return #GNUNET_SYSERR is not well-formed, otherwise #GNUNET_OK
 */
static int
check_data (const struct DataMessage *dm)
{
  uint16_t size;
  uint32_t dsize;

  size = ntohs (dm->header.size);
  dsize = ntohl (dm->size);
  if (size != dsize + sizeof (struct DataMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Context for a PUT request used to see if the content is
 * already present.
 */
struct PutContext
{
  /**
   * Client to notify on completion.
   */
  struct GNUNET_SERVICE_Client *client;

#if ! HAVE_UNALIGNED_64_ACCESS
  void *reserved;
#endif

  /* followed by the 'struct DataMessage' */
};


/**
 * Put continuation.
 *
 * @param cls closure
 * @param key key for the item stored
 * @param size size of the item stored
 * @param status #GNUNET_OK or #GNUNET_SYSERROR
 * @param msg error message on error
 */
static void
put_continuation (void *cls,
		  const struct GNUNET_HashCode *key,
		  uint32_t size,
                  int status,
		  const char *msg)
{
  struct PutContext *pc = cls;

  if (GNUNET_OK == status)
  {
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# bytes stored"),
                              size,
                              GNUNET_YES);
    GNUNET_CONTAINER_bloomfilter_add (filter,
                                      key);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully stored %u bytes under key `%s'\n",
                size,
                GNUNET_h2s (key));
  }
  transmit_status (pc->client,
                   status,
                   msg);
  GNUNET_free (pc);
  if (quota - reserved - cache_size < payload)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Need %llu bytes more space (%llu allowed, using %llu)\n"),
                (unsigned long long) size + GNUNET_DATASTORE_ENTRY_OVERHEAD,
                (unsigned long long) (quota - reserved - cache_size),
                (unsigned long long) payload);
    manage_space (size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
  }
}


/**
 * Actually put the data message.
 *
 * @param pc put context
 */
static void
execute_put (struct PutContext *pc)
{
  const struct DataMessage *dm;

  dm = (const struct DataMessage *) &pc[1];
  plugin->api->put (plugin->api->cls,
                    &dm->key,
                    ntohl (dm->size),
                    &dm[1],
                    ntohl (dm->type),
                    ntohl (dm->priority),
                    ntohl (dm->anonymity),
                    ntohl (dm->replication),
                    GNUNET_TIME_absolute_ntoh (dm->expiration),
                    &put_continuation,
                    pc);
}


/**
 *
 * @param cls closure
 * @param status #GNUNET_OK or #GNUNET_SYSERR
 * @param msg error message on error
 */
static void
check_present_continuation (void *cls,
			    int status,
			    const char *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;

  transmit_status (client,
                   GNUNET_NO,
                   NULL);
}


/**
 * Function that will check if the given datastore entry
 * matches the put and if none match executes the put.
 *
 * @param cls closure, pointer to the client (of type `struct PutContext`).
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_OK usually
 *         #GNUNET_NO to delete the item
 */
static int
check_present (void *cls,
	       const struct GNUNET_HashCode *key,
	       uint32_t size,
               const void *data,
	       enum GNUNET_BLOCK_Type type,
	       uint32_t priority,
               uint32_t anonymity,
	       struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct PutContext *pc = cls;
  const struct DataMessage *dm;

  dm = (const struct DataMessage *) &pc[1];
  if (key == NULL)
  {
    execute_put (pc);
    return GNUNET_OK;
  }
  if ( (GNUNET_BLOCK_TYPE_FS_DBLOCK == type) ||
       (GNUNET_BLOCK_TYPE_FS_IBLOCK == type) ||
       ( (size == ntohl (dm->size)) &&
         (0 == memcmp (&dm[1],
                       data,
                       size)) ) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Result already present in datastore\n");
    /* FIXME: change API to allow increasing 'replication' counter */
    if ((ntohl (dm->priority) > 0) ||
        (GNUNET_TIME_absolute_ntoh (dm->expiration).abs_value_us >
         expiration.abs_value_us))
      plugin->api->update (plugin->api->cls,
			   uid,
                           ntohl (dm->priority),
                           GNUNET_TIME_absolute_ntoh (dm->expiration),
                           &check_present_continuation,
			   pc->client);
    else
    {
      transmit_status (pc->client,
                       GNUNET_NO,
                       NULL);
    }
    GNUNET_free (pc);
  }
  else
  {
    execute_put (pc);
  }
  return GNUNET_OK;
}


/**
 * Verify PUT-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 * @return #GNUNET_OK if @a dm is well-formed
 */
static int
check_put (void *cls,
           const struct DataMessage *dm)
{
  if (GNUNET_OK != check_data (dm))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle PUT-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_put (void *cls,
            const struct DataMessage *dm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  int rid;
  struct ReservationList *pos;
  struct PutContext *pc;
  struct GNUNET_HashCode vhash;
  uint32_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing PUT request for `%s' of type %u\n",
              GNUNET_h2s (&dm->key),
              (uint32_t) ntohl (dm->type));
  rid = ntohl (dm->rid);
  size = ntohl (dm->size);
  if (rid > 0)
  {
    pos = reservations;
    while ((NULL != pos) && (rid != pos->rid))
      pos = pos->next;
    GNUNET_break (pos != NULL);
    if (NULL != pos)
    {
      GNUNET_break (pos->entries > 0);
      GNUNET_break (pos->amount >= size);
      pos->entries--;
      pos->amount -= size;
      reserved -= (size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
      GNUNET_STATISTICS_set (stats,
                             gettext_noop ("# reserved"),
                             reserved,
                             GNUNET_NO);
    }
  }
  pc = GNUNET_malloc (sizeof (struct PutContext) + size +
                      sizeof (struct DataMessage));
  pc->client = client;
  GNUNET_memcpy (&pc[1],
                 dm,
                 size + sizeof (struct DataMessage));
  if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (filter,
                                                       &dm->key))
  {
    GNUNET_CRYPTO_hash (&dm[1],
                        size,
                        &vhash);
    plugin->api->get_key (plugin->api->cls,
			  0,
			  &dm->key,
			  &vhash,
                          ntohl (dm->type),
			  &check_present,
			  pc);
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  execute_put (pc);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_DATASTORE_GET-message.
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_get (void *cls,
            const struct GetMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing GET request of type %u\n",
              (uint32_t) ntohl (msg->type));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# GET requests received"),
                            1,
                            GNUNET_NO);
  plugin->api->get_key (plugin->api->cls,
                        GNUNET_ntohll (msg->offset),
                        NULL,
                        NULL,
                        ntohl (msg->type),
                        &transmit_item,
                        client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY-message.
 *
 * @param cls closure
 * @param msg the actual message
 */
static void
handle_get_key (void *cls,
                const struct GetKeyMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing GET request for `%s' of type %u\n",
              GNUNET_h2s (&msg->key),
              (uint32_t) ntohl (msg->type));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# GET KEY requests received"),
                            1,
                            GNUNET_NO);
  if (GNUNET_YES !=
      GNUNET_CONTAINER_bloomfilter_test (filter,
                                         &msg->key))
  {
    /* don't bother database... */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Empty result set for GET request for `%s' (bloomfilter).\n",
                GNUNET_h2s (&msg->key));
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# requests filtered by bloomfilter"),
                              1,
                              GNUNET_NO);
    transmit_item (client,
                   NULL, 0, NULL, 0, 0, 0,
                   GNUNET_TIME_UNIT_ZERO_ABS,
                   0);
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  plugin->api->get_key (plugin->api->cls,
                        GNUNET_ntohll (msg->offset),
                        &msg->key,
                        NULL,
                        ntohl (msg->type),
                        &transmit_item,
                        client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle GET_REPLICATION-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_get_replication (void *cls,
                        const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing GET_REPLICATION request\n");
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# GET REPLICATION requests received"),
                            1,
                            GNUNET_NO);
  plugin->api->get_replication (plugin->api->cls,
                                &transmit_item,
                                client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle GET_ZERO_ANONYMITY-message.
 *
 * @param cls client identification of the client
 * @param message the actual message
 */
static void
handle_get_zero_anonymity (void *cls,
                           const struct GetZeroAnonymityMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  enum GNUNET_BLOCK_Type type;

  type = (enum GNUNET_BLOCK_Type) ntohl (msg->type);
  if (type == GNUNET_BLOCK_TYPE_ANY)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing GET_ZERO_ANONYMITY request\n");
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# GET ZERO ANONYMITY requests received"),
                            1,
                            GNUNET_NO);
  plugin->api->get_zero_anonymity (plugin->api->cls,
                                   GNUNET_ntohll (msg->offset),
                                   type,
                                   &transmit_item,
                                   client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Callback function that will cause the item that is passed
 * in to be deleted (by returning #GNUNET_NO).
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum
 * @return #GNUNET_OK to keep the item
 *         #GNUNET_NO to delete the item
 */
static int
remove_callback (void *cls,
                 const struct GNUNET_HashCode *key,
                 uint32_t size,
                 const void *data,
                 enum GNUNET_BLOCK_Type type,
                 uint32_t priority,
                 uint32_t anonymity,
                 struct GNUNET_TIME_Absolute expiration,
                 uint64_t uid)
{
  struct GNUNET_SERVICE_Client *client = cls;

  if (NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No further matches for REMOVE request.\n");
    transmit_status (client,
                     GNUNET_NO,
                     _("Content not found"));
    return GNUNET_OK;           /* last item */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Item %llu matches REMOVE request for key `%s' and type %u.\n",
              (unsigned long long) uid,
              GNUNET_h2s (key),
              type);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes removed (explicit request)"),
                            size,
                            GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter,
                                       key);
  transmit_status (client,
                   GNUNET_OK,
                   NULL);
  return GNUNET_NO;
}


/**
 * Verify REMOVE-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 * @return #GNUNET_OK if @a dm is well-formed
 */
static int
check_remove (void *cls,
              const struct DataMessage *dm)
{
  if (GNUNET_OK != check_data (dm))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
               const struct DataMessage *dm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_HashCode vhash;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# REMOVE requests received"),
                            1, GNUNET_NO);
  GNUNET_CRYPTO_hash (&dm[1],
                      ntohl (dm->size),
                      &vhash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing REMOVE request for `%s' of type %u\n",
              GNUNET_h2s (&dm->key),
              (uint32_t) ntohl (dm->type));
  plugin->api->get_key (plugin->api->cls,
                        0,
                        &dm->key,
                        &vhash,
                        (enum GNUNET_BLOCK_Type) ntohl (dm->type),
                        &remove_callback,
                        client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle DROP-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_drop (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing DROP request\n");
  do_drop = GNUNET_YES;
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Function called by plugins to notify us about a
 * change in their disk utilization.
 *
 * @param cls closure (NULL)
 * @param delta change in disk utilization,
 *        0 for "reset to empty"
 */
static void
disk_utilization_change_cb (void *cls,
                            int delta)
{
  if ((delta < 0) && (payload < -delta))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Datastore payload must have been inaccurate (%lld < %lld). Recomputing it.\n"),
                (long long) payload,
                (long long) -delta);
    plugin->api->estimate_size (plugin->api->cls,
                                &payload);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("New payload: %lld\n"),
                (long long) payload);
     sync_stats ();
    return;
  }
  payload += delta;
  last_sync++;
  if (last_sync >= MAX_STAT_SYNC_LAG)
    sync_stats ();
}


/**
 * Callback function to process statistic values.
 *
 * @param cls closure (struct Plugin*)
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
process_stat_in (void *cls,
                 const char *subsystem,
                 const char *name,
                 uint64_t value,
                 int is_persistent)
{
  GNUNET_assert (GNUNET_NO == stats_worked);
  stats_worked = GNUNET_YES;
  payload += value;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notification from statistics about existing payload (%llu), new payload is %llu\n",
              (unsigned long long) value,
              (unsigned long long) payload);
  return GNUNET_OK;
}


/**
 * Load the datastore plugin.
 */
static struct DatastorePlugin *
load_plugin ()
{
  struct DatastorePlugin *ret;
  char *libname;

  ret = GNUNET_new (struct DatastorePlugin);
  ret->env.cfg = cfg;
  ret->env.duc = &disk_utilization_change_cb;
  ret->env.cls = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname,
                   "libgnunet_plugin_datastore_%s",
                   plugin_name);
  ret->short_name = GNUNET_strdup (plugin_name);
  ret->lib_name = libname;
  ret->api = GNUNET_PLUGIN_load (libname,
                                 &ret->env);
  if (NULL == ret->api)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load datastore plugin for `%s'\n"),
                plugin_name);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Datastore service is unloading plugin...\n");
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
  GNUNET_free (plug->lib_name);
  GNUNET_free (plug->short_name);
  GNUNET_free (plug);
}


/**
 * Initialization complete, start operating the service.
 */
static void
begin_service ()
{
  GNUNET_SERVICE_resume (service);
  expired_kill_task
    = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                          &delete_expired,
                                          NULL);
}


/**
 * Adds a given @a key to the bloomfilter in @a cls @a count times.
 *
 * @param cls the bloomfilter
 * @param key key to add
 * @param count number of times to add key
 */
static void
add_key_to_bloomfilter (void *cls,
			const struct GNUNET_HashCode *key,
			unsigned int count)
{
  struct GNUNET_CONTAINER_BloomFilter *bf = cls;

  if (NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Bloomfilter construction complete.\n"));
    begin_service ();
    return;
  }

  while (0 < count--)
    GNUNET_CONTAINER_bloomfilter_add (bf,
                                      key);
}


/**
 * We finished receiving the statistic.  Initialize the plugin; if
 * loading the statistic failed, run the estimator.
 *
 * @param cls NULL
 * @param success #GNUNET_NO if we failed to read the stat
 */
static void
process_stat_done (void *cls,
                   int success)
{
  stat_get = NULL;
  if (NULL != stat_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (stat_timeout_task);
    stat_timeout_task = NULL;
  }
  plugin = load_plugin ();
  if (NULL == plugin)
  {
    GNUNET_CONTAINER_bloomfilter_free (filter);
    filter = NULL;
    if (NULL != stats)
    {
      GNUNET_STATISTICS_destroy (stats,
                                 GNUNET_YES);
      stats = NULL;
    }
    return;
  }

  if (GNUNET_NO == stats_worked)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to obtain value from statistics service, recomputing it\n");
    plugin->api->estimate_size (plugin->api->cls,
                                &payload);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("New payload: %lld\n"),
                (long long) payload);
  }

  if (GNUNET_YES == refresh_bf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Rebuilding bloomfilter.  Please be patient.\n"));
    if (NULL != plugin->api->get_keys)
    {
      plugin->api->get_keys (plugin->api->cls,
                             &add_key_to_bloomfilter,
                             filter);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Plugin does not support get_keys function. Please fix!\n"));
    }
  }
  begin_service ();
}


/**
 * Fetching stats took to long, run without.
 *
 * @param cls NULL
 */
static void
stat_timeout (void *cls)
{
  stat_timeout_task = NULL;
  GNUNET_STATISTICS_get_cancel (stat_get);
  process_stat_done (NULL,
                     GNUNET_NO);
}


/**
 * Task run during shutdown.
 */
static void
cleaning_task (void *cls)
{
  cleaning_done = GNUNET_YES;
  if (NULL != expired_kill_task)
  {
    GNUNET_SCHEDULER_cancel (expired_kill_task);
    expired_kill_task = NULL;
  }
  if (GNUNET_YES == do_drop)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping database!\n");
    plugin->api->drop (plugin->api->cls);
    payload = 0;
    last_sync++;
  }
  if (NULL != plugin)
  {
    unload_plugin (plugin);
    plugin = NULL;
  }
  if (NULL != filter)
  {
    GNUNET_CONTAINER_bloomfilter_free (filter);
    filter = NULL;
  }
  if (NULL != stat_get)
  {
    GNUNET_STATISTICS_get_cancel (stat_get);
    stat_get = NULL;
  }
  if (NULL != stat_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (stat_timeout_task);
    stat_timeout_task = NULL;
  }
  GNUNET_free_non_null (plugin_name);
  plugin_name = NULL;
  if (last_sync > 0)
    sync_stats ();
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
                               GNUNET_YES);
    stats = NULL;
  }
  GNUNET_free (quota_stat_name);
  quota_stat_name = NULL;
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  return client;
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx must match @a client
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct ReservationList *pos;
  struct ReservationList *prev;
  struct ReservationList *next;

  GNUNET_assert (app_ctx == client);
  prev = NULL;
  pos = reservations;
  while (NULL != pos)
  {
    next = pos->next;
    if (pos->client == client)
    {
      if (NULL == prev)
        reservations = next;
      else
        prev->next = next;
      reserved -= pos->amount + pos->entries * GNUNET_DATASTORE_ENTRY_OVERHEAD;
      GNUNET_free (pos);
    }
    else
    {
      prev = pos;
    }
    pos = next;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# reserved"),
                         reserved,
                         GNUNET_NO);

}


/**
 * Process datastore requests.
 *
 * @param cls closure
 * @param serv the initialized service
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *serv)
{
  char *fn;
  char *pfn;
  unsigned int bf_size;

  service = serv;
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "DATASTORE",
                                             "DATABASE",
                                             &plugin_name))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "DATABASE",
                               "DATASTORE");
    return;
  }
  GNUNET_asprintf (&quota_stat_name,
		   _("# bytes used in file-sharing datastore `%s'"),
		   plugin_name);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg,
                                           "DATASTORE",
                                           "QUOTA",
                                           &quota))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "QUOTA",
                               "DATASTORE");
    return;
  }
  stats = GNUNET_STATISTICS_create ("datastore",
                                    cfg);
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# quota"),
                         quota,
                         GNUNET_NO);
  cache_size = quota / 8;       /* Or should we make this an option? */
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# cache size"),
                         cache_size,
                         GNUNET_NO);
  if (quota / (32 * 1024LL) > MAX_BF_SIZE)
    bf_size = MAX_BF_SIZE;
  else
    bf_size = quota / (32 * 1024LL);         /* 8 bit per entry, 1 bit per 32 kb in DB */
  fn = NULL;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                "DATASTORE",
                                                "BLOOMFILTER",
                                                &fn)) ||
      (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not use specified filename `%s' for bloomfilter.\n"),
                NULL != fn ? fn : "");
    GNUNET_free_non_null (fn);
    fn = NULL;
  }
  if (NULL != fn)
  {
    GNUNET_asprintf (&pfn, "%s.%s", fn, plugin_name);
    if (GNUNET_YES == GNUNET_DISK_file_test (pfn))
    {
      filter = GNUNET_CONTAINER_bloomfilter_load (pfn, bf_size, 5);        /* approx. 3% false positives at max use */
      if (NULL == filter)
      {
	/* file exists but not valid, remove and try again, but refresh */
	if (0 != UNLINK (pfn))
	{
	  /* failed to remove, run without file */
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Failed to remove bogus bloomfilter file `%s'\n"),
		      pfn);
	  GNUNET_free (pfn);
	  pfn = NULL;
	  filter = GNUNET_CONTAINER_bloomfilter_load (NULL, bf_size, 5);        /* approx. 3% false positives at max use */
	  refresh_bf = GNUNET_YES;
	}
	else
	{
	  /* try again after remove */
	  filter = GNUNET_CONTAINER_bloomfilter_load (pfn, bf_size, 5);        /* approx. 3% false positives at max use */
	  refresh_bf = GNUNET_YES;
	  if (NULL == filter)
	  {
	    /* failed yet again, give up on using file */
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			_("Failed to remove bogus bloomfilter file `%s'\n"),
			pfn);
	    GNUNET_free (pfn);
	    pfn = NULL;
	    filter = GNUNET_CONTAINER_bloomfilter_init (NULL, bf_size, 5);        /* approx. 3% false positives at max use */
	  }
	}
      }
      else
      {
	/* normal case: have an existing valid bf file, no need to refresh */
	refresh_bf = GNUNET_NO;
      }
    }
    else
    {
      filter = GNUNET_CONTAINER_bloomfilter_load (pfn, bf_size, 5);        /* approx. 3% false positives at max use */
      refresh_bf = GNUNET_YES;
    }
    GNUNET_free (pfn);
  }
  else
  {
    filter = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                bf_size,
                                                5);      /* approx. 3% false positives at max use */
    refresh_bf = GNUNET_YES;
  }
  GNUNET_free_non_null (fn);
  if (NULL == filter)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to initialize bloomfilter.\n"));
    if (NULL != stats)
    {
      GNUNET_STATISTICS_destroy (stats,
                                 GNUNET_YES);
      stats = NULL;
    }
    return;
  }
  GNUNET_SERVICE_suspend (service);
  stat_get =
      GNUNET_STATISTICS_get (stats,
                             "datastore",
                             quota_stat_name,
                             &process_stat_done,
                             &process_stat_in,
                             NULL);
  if (NULL == stat_get)
    process_stat_done (NULL,
                       GNUNET_SYSERR);
  else
    stat_timeout_task
      = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &stat_timeout,
                                      NULL);
  GNUNET_SCHEDULER_add_shutdown (&cleaning_task,
				 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("datastore",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (reserve,
                          GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE,
                          struct ReserveMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (release_reserve,
                          GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE,
                          struct ReleaseReserveMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (put,
                        GNUNET_MESSAGE_TYPE_DATASTORE_PUT,
                        struct DataMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (get,
                          GNUNET_MESSAGE_TYPE_DATASTORE_GET,
                          struct GetMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (get_key,
                          GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY,
                          struct GetKeyMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (get_replication,
                          GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_fixed_size (get_zero_anonymity,
                          GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY,
                          struct GetZeroAnonymityMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (remove,
                        GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE,
                        struct DataMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (drop,
                          GNUNET_MESSAGE_TYPE_DATASTORE_DROP,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-datastore.c */
