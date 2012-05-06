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
  struct GNUNET_SERVER_Client *client;

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
 * How much space are we allowed to use?
 */
static unsigned long long quota;

/**
 * Should the database be dropped on exit?
 */
static int do_drop;

/**
 * Name of our plugin.
 */
static char *plugin_name;

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
 * Number of updates that were made to the
 * payload value since we last synchronized
 * it with the statistics service.
 */
static unsigned int lastSync;

/**
 * Did we get an answer from statistics?
 */
static int stats_worked;

/**
 * Identity of the task that is used to delete
 * expired content.
 */
static GNUNET_SCHEDULER_TaskIdentifier expired_kill_task;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Minimum time that content should have to not be discarded instantly
 * (time stamp of any content that we've been discarding recently to
 * stay below the quota).  FOREVER if we had to expire content with
 * non-zero priority.
 */
static struct GNUNET_TIME_Absolute min_expiration;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;


/**
 * Synchronize our utilization statistics with the
 * statistics service.
 */
static void
sync_stats ()
{
  GNUNET_STATISTICS_set (stats, quota_stat_name, payload, GNUNET_YES);
  GNUNET_STATISTICS_set (stats, "# utilization by current datastore", payload, GNUNET_NO);
  lastSync = 0;
}



/**
 * Context for transmitting replies to clients.
 */
struct TransmitCallbackContext
{

  /**
   * We keep these in a doubly-linked list (for cleanup).
   */
  struct TransmitCallbackContext *next;

  /**
   * We keep these in a doubly-linked list (for cleanup).
   */
  struct TransmitCallbackContext *prev;

  /**
   * The message that we're asked to transmit.
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Handle for the transmission request.
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Client that we are transmitting to.
   */
  struct GNUNET_SERVER_Client *client;

};


/**
 * Head of the doubly-linked list (for cleanup).
 */
static struct TransmitCallbackContext *tcc_head;

/**
 * Tail of the doubly-linked list (for cleanup).
 */
static struct TransmitCallbackContext *tcc_tail;

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
 * Task that is used to remove expired entries from
 * the datastore.  This task will schedule itself
 * again automatically to always delete all expired
 * content quickly.
 *
 * @param cls not used
 * @param tc task context
 */
static void
delete_expired (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
expired_processor (void *cls, const GNUNET_HashCode * key, uint32_t size,
                   const void *data, enum GNUNET_BLOCK_Type type,
                   uint32_t priority, uint32_t anonymity,
                   struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct GNUNET_TIME_Absolute now;

  if (key == NULL)
  {
    expired_kill_task =
        GNUNET_SCHEDULER_add_delayed_with_priority (MAX_EXPIRE_DELAY,
						    GNUNET_SCHEDULER_PRIORITY_IDLE,
						    &delete_expired, NULL);
    return GNUNET_SYSERR;
  }
  now = GNUNET_TIME_absolute_get ();
  if (expiration.abs_value > now.abs_value)
  {
    /* finished processing */
    expired_kill_task =
        GNUNET_SCHEDULER_add_delayed_with_priority (MAX_EXPIRE_DELAY,
						    GNUNET_SCHEDULER_PRIORITY_IDLE,
						    &delete_expired, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting content `%s' of type %u that expired %llu ms ago\n",
              GNUNET_h2s (key), type,
              (unsigned long long) (now.abs_value - expiration.abs_value));
  min_expiration = now;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes expired"), size,
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
 * @param tc task context
 */
static void
delete_expired (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  expired_kill_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->api->get_expiration (plugin->api->cls, &expired_processor, NULL);
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
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
quota_processor (void *cls, const GNUNET_HashCode * key, uint32_t size,
                 const void *data, enum GNUNET_BLOCK_Type type,
                 uint32_t priority, uint32_t anonymity,
                 struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  unsigned long long *need = cls;

  if (NULL == key)
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting %llu bytes of low-priority (%u) content `%s' of type %u at %llu ms prior to expiration (still trying to free another %llu bytes)\n",
              (unsigned long long) (size + GNUNET_DATASTORE_ENTRY_OVERHEAD),
	      (unsigned int) priority,
              GNUNET_h2s (key), type, 
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (expiration).rel_value,
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
              "Asked to free up %llu bytes of cache space\n", need);
  last = 0;
  while ((need > 0) && (last != need))
  {
    last = need;
    plugin->api->get_expiration (plugin->api->cls, &quota_processor, &need);
  }
}


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
transmit_callback (void *cls, size_t size, void *buf)
{
  struct TransmitCallbackContext *tcc = cls;
  size_t msize;

  tcc->th = NULL;
  GNUNET_CONTAINER_DLL_remove (tcc_head, tcc_tail, tcc);
  msize = ntohs (tcc->msg->size);
  if (size == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Transmission to client failed!\n"));
    GNUNET_SERVER_receive_done (tcc->client, GNUNET_SYSERR);
    GNUNET_SERVER_client_drop (tcc->client);
    GNUNET_free (tcc->msg);
    GNUNET_free (tcc);
    return 0;
  }
  GNUNET_assert (size >= msize);
  memcpy (buf, tcc->msg, msize);
  GNUNET_SERVER_receive_done (tcc->client, GNUNET_OK);
  GNUNET_SERVER_client_drop (tcc->client);
  GNUNET_free (tcc->msg);
  GNUNET_free (tcc);
  return msize;
}


/**
 * Transmit the given message to the client.
 *
 * @param client target of the message
 * @param msg message to transmit, will be freed!
 */
static void
transmit (struct GNUNET_SERVER_Client *client, struct GNUNET_MessageHeader *msg)
{
  struct TransmitCallbackContext *tcc;

  if (GNUNET_YES == cleaning_done)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Shutdown in progress, aborting transmission.\n"));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free (msg);
    return;
  }
  tcc = GNUNET_malloc (sizeof (struct TransmitCallbackContext));
  tcc->msg = msg;
  tcc->client = client;
  if (NULL ==
      (tcc->th =
       GNUNET_SERVER_notify_transmit_ready (client, ntohs (msg->size),
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            &transmit_callback, tcc)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free (msg);
    GNUNET_free (tcc);
    return;
  }
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (tcc_head, tcc_tail, tcc);
}


/**
 * Transmit a status code to the client.
 *
 * @param client receiver of the response
 * @param code status code
 * @param msg optional error message (can be NULL)
 */
static void
transmit_status (struct GNUNET_SERVER_Client *client, int code, const char *msg)
{
  struct StatusMessage *sm;
  size_t slen;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' message with value %d and message `%s'\n",
              "STATUS", code, msg != NULL ? msg : "(none)");
  slen = (msg == NULL) ? 0 : strlen (msg) + 1;
  sm = GNUNET_malloc (sizeof (struct StatusMessage) + slen);
  sm->header.size = htons (sizeof (struct StatusMessage) + slen);
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_STATUS);
  sm->status = htonl (code);
  sm->min_expiration = GNUNET_TIME_absolute_hton (min_expiration);
  if (slen > 0)
    memcpy (&sm[1], msg, slen);
  transmit (client, &sm->header);
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
transmit_item (void *cls, const GNUNET_HashCode * key, uint32_t size,
               const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
               uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader *end;
  struct DataMessage *dm;

  if (key == NULL)
  {
    /* transmit 'DATA_END' */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting `%s' message\n",
                "DATA_END");
    end = GNUNET_malloc (sizeof (struct GNUNET_MessageHeader));
    end->size = htons (sizeof (struct GNUNET_MessageHeader));
    end->type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END);
    transmit (client, end);
    GNUNET_SERVER_client_drop (client);
    return GNUNET_OK;
  }
  GNUNET_assert (sizeof (struct DataMessage) + size <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
  dm = GNUNET_malloc (sizeof (struct DataMessage) + size);
  dm->header.size = htons (sizeof (struct DataMessage) + size);
  dm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_DATA);
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
  memcpy (&dm[1], data, size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' message for `%s' of type %u with expiration %llu (now: %llu)\n",
              "DATA", GNUNET_h2s (key), type,
              (unsigned long long) expiration.abs_value,
              (unsigned long long) GNUNET_TIME_absolute_get ().abs_value);
  GNUNET_STATISTICS_update (stats, gettext_noop ("# results found"), 1,
                            GNUNET_NO);
  transmit (client, &dm->header);
  GNUNET_SERVER_client_drop (client);
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
handle_reserve (void *cls, struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  /**
   * Static counter to produce reservation identifiers.
   */
  static int reservation_gen;

  const struct ReserveMessage *msg = (const struct ReserveMessage *) message;
  struct ReservationList *e;
  unsigned long long used;
  unsigned long long req;
  uint64_t amount;
  uint32_t entries;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request\n", "RESERVE");
  amount = GNUNET_ntohll (msg->amount);
  entries = ntohl (msg->entries);
  used = payload + reserved;
  req =
      amount + ((unsigned long long) GNUNET_DATASTORE_ENTRY_OVERHEAD) * entries;
  if (used + req > quota)
  {
    if (quota < used)
      used = quota;             /* cheat a bit for error message (to avoid negative numbers) */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Insufficient space (%llu bytes are available) to satisfy `%s' request for %llu bytes\n"),
                quota - used, "RESERVE", req);
    if (cache_size < req)
    {
      /* TODO: document this in the FAQ; essentially, if this
       * message happens, the insertion request could be blocked
       * by less-important content from migration because it is
       * larger than 1/8th of the overall available space, and
       * we only reserve 1/8th for "fresh" insertions */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("The requested amount (%llu bytes) is larger than the cache size (%llu bytes)\n"),
                  req, cache_size);
      transmit_status (client, 0,
                       gettext_noop
                       ("Insufficient space to satisfy request and "
                        "requested amount is larger than cache size"));
    }
    else
    {
      transmit_status (client, 0,
                       gettext_noop ("Insufficient space to satisfy request"));
    }
    return;
  }
  reserved += req;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# reserved"), reserved,
                         GNUNET_NO);
  e = GNUNET_malloc (sizeof (struct ReservationList));
  e->next = reservations;
  reservations = e;
  e->client = client;
  e->amount = amount;
  e->entries = entries;
  e->rid = ++reservation_gen;
  if (reservation_gen < 0)
    reservation_gen = 0;        /* wrap around */
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
handle_release_reserve (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct ReleaseReserveMessage *msg =
      (const struct ReleaseReserveMessage *) message;
  struct ReservationList *pos;
  struct ReservationList *prev;
  struct ReservationList *next;
  int rid = ntohl (msg->rid);
  unsigned long long rem;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request\n",
              "RELEASE_RESERVE");
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
      GNUNET_STATISTICS_set (stats, gettext_noop ("# reserved"), reserved,
                             GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Returning %llu remaining reserved bytes to storage pool\n",
                  rem);
      GNUNET_free (pos);
      transmit_status (client, GNUNET_OK, NULL);
      return;
    }
    prev = pos;
  }
  GNUNET_break (0);
  transmit_status (client, GNUNET_SYSERR,
                   gettext_noop ("Could not find matching reservation"));
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

  size = ntohs (message->size);
  if (size < sizeof (struct DataMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  dm = (const struct DataMessage *) message;
  dsize = ntohl (dm->size);
  if (size != dsize + sizeof (struct DataMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  return dm;
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
  struct GNUNET_SERVER_Client *client;

#if ! HAVE_UNALIGNED_64_ACCESS
  void *reserved;
#endif

  /* followed by the 'struct DataMessage' */
};


/**
 * Actually put the data message.
 *
 * @param client sender of the message
 * @param dm message with the data to store
 */
static void
execute_put (struct GNUNET_SERVER_Client *client, const struct DataMessage *dm)
{
  uint32_t size;
  char *msg;
  int ret;

  size = ntohl (dm->size);
  msg = NULL;
  ret =
      plugin->api->put (plugin->api->cls, &dm->key, size, &dm[1],
                        ntohl (dm->type), ntohl (dm->priority),
                        ntohl (dm->anonymity), ntohl (dm->replication),
                        GNUNET_TIME_absolute_ntoh (dm->expiration), &msg);
  if (GNUNET_OK == ret)
  {
    GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes stored"), size,
                              GNUNET_YES);
    GNUNET_CONTAINER_bloomfilter_add (filter, &dm->key);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully stored %u bytes of type %u under key `%s'\n",
                size, ntohl (dm->type), GNUNET_h2s (&dm->key));
  }
  transmit_status (client, ret, msg);
  GNUNET_free_non_null (msg);
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
 * Function that will check if the given datastore entry
 * matches the put and if none match executes the put.
 *
 * @param cls closure, pointer to the client (of type 'struct PutContext').
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
 * @return GNUNET_OK usually
 *         GNUNET_NO to delete the item
 */
static int
check_present (void *cls, const GNUNET_HashCode * key, uint32_t size,
               const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
               uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct PutContext *pc = cls;
  const struct DataMessage *dm;

  dm = (const struct DataMessage *) &pc[1];
  if (key == NULL)
  {
    execute_put (pc->client, dm);
    GNUNET_SERVER_client_drop (pc->client);
    GNUNET_free (pc);
    return GNUNET_OK;
  }
  if ((GNUNET_BLOCK_TYPE_FS_DBLOCK == type) ||
      (GNUNET_BLOCK_TYPE_FS_IBLOCK == type) || ((size == ntohl (dm->size)) &&
                                                (0 ==
                                                 memcmp (&dm[1], data, size))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Result already present in datastore\n");
    /* FIXME: change API to allow increasing 'replication' counter */
    if ((ntohl (dm->priority) > 0) ||
        (GNUNET_TIME_absolute_ntoh (dm->expiration).abs_value >
         expiration.abs_value))
      plugin->api->update (plugin->api->cls, uid,
                           (int32_t) ntohl (dm->priority),
                           GNUNET_TIME_absolute_ntoh (dm->expiration), NULL);
    transmit_status (pc->client, GNUNET_NO, NULL);
    GNUNET_SERVER_client_drop (pc->client);
    GNUNET_free (pc);
  }
  else
  {
    execute_put (pc->client, dm);
    GNUNET_SERVER_client_drop (pc->client);
    GNUNET_free (pc);
  }
  return GNUNET_OK;
}


/**
 * Handle PUT-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_put (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  const struct DataMessage *dm = check_data (message);
  int rid;
  struct ReservationList *pos;
  struct PutContext *pc;
  GNUNET_HashCode vhash;
  uint32_t size;

  if ((dm == NULL) || (ntohl (dm->type) == 0))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing `%s' request for `%s' of type %u\n", "PUT",
              GNUNET_h2s (&dm->key), ntohl (dm->type));
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
      GNUNET_STATISTICS_set (stats, gettext_noop ("# reserved"), reserved,
                             GNUNET_NO);
    }
  }
  if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (filter, &dm->key))
  {
    GNUNET_CRYPTO_hash (&dm[1], size, &vhash);
    pc = GNUNET_malloc (sizeof (struct PutContext) + size +
                        sizeof (struct DataMessage));
    pc->client = client;
    GNUNET_SERVER_client_keep (client);
    memcpy (&pc[1], dm, size + sizeof (struct DataMessage));
    plugin->api->get_key (plugin->api->cls, 0, &dm->key, &vhash,
                          ntohl (dm->type), &check_present, pc);
    return;
  }
  execute_put (client, dm);
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  const struct GetMessage *msg;
  uint16_t size;

  size = ntohs (message->size);
  if ((size != sizeof (struct GetMessage)) &&
      (size != sizeof (struct GetMessage) - sizeof (GNUNET_HashCode)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GetMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing `%s' request for `%s' of type %u\n", "GET",
              GNUNET_h2s (&msg->key), ntohl (msg->type));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# GET requests received"), 1,
                            GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
  if ((size == sizeof (struct GetMessage)) &&
      (GNUNET_YES != GNUNET_CONTAINER_bloomfilter_test (filter, &msg->key)))
  {
    /* don't bother database... */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Empty result set for `%s' request for `%s' (bloomfilter).\n",
                "GET", GNUNET_h2s (&msg->key));
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# requests filtered by bloomfilter"), 1,
                              GNUNET_NO);
    transmit_item (client, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS,
                   0);
    return;
  }
  plugin->api->get_key (plugin->api->cls, GNUNET_ntohll (msg->offset),
                        ((size ==
                          sizeof (struct GetMessage)) ? &msg->key : NULL), NULL,
                        ntohl (msg->type), &transmit_item, client);
}


/**
 * Handle UPDATE-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_update (void *cls, struct GNUNET_SERVER_Client *client,
               const struct GNUNET_MessageHeader *message)
{
  const struct UpdateMessage *msg;
  int ret;
  char *emsg;

  GNUNET_STATISTICS_update (stats, gettext_noop ("# UPDATE requests received"),
                            1, GNUNET_NO);
  msg = (const struct UpdateMessage *) message;
  emsg = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request for %llu\n",
              "UPDATE", (unsigned long long) GNUNET_ntohll (msg->uid));
  ret =
      plugin->api->update (plugin->api->cls, GNUNET_ntohll (msg->uid),
                           (int32_t) ntohl (msg->priority),
                           GNUNET_TIME_absolute_ntoh (msg->expiration), &emsg);
  transmit_status (client, ret, emsg);
  GNUNET_free_non_null (emsg);
}


/**
 * Handle GET_REPLICATION-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_replication (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request\n",
              "GET_REPLICATION");
  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# GET REPLICATION requests received"), 1,
                            GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
  plugin->api->get_replication (plugin->api->cls, &transmit_item, client);
}


/**
 * Handle GET_ZERO_ANONYMITY-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_zero_anonymity (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
  const struct GetZeroAnonymityMessage *msg =
      (const struct GetZeroAnonymityMessage *) message;
  enum GNUNET_BLOCK_Type type;

  type = (enum GNUNET_BLOCK_Type) ntohl (msg->type);
  if (type == GNUNET_BLOCK_TYPE_ANY)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request\n",
              "GET_ZERO_ANONYMITY");
  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# GET ZERO ANONYMITY requests received"), 1,
                            GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
  plugin->api->get_zero_anonymity (plugin->api->cls,
                                   GNUNET_ntohll (msg->offset), type,
                                   &transmit_item, client);
}


/**
 * Callback function that will cause the item that is passed
 * in to be deleted (by returning GNUNET_NO).
 */
static int
remove_callback (void *cls, const GNUNET_HashCode * key, uint32_t size,
                 const void *data, enum GNUNET_BLOCK_Type type,
                 uint32_t priority, uint32_t anonymity,
                 struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct GNUNET_SERVER_Client *client = cls;

  if (key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No further matches for `%s' request.\n", "REMOVE");
    transmit_status (client, GNUNET_NO, _("Content not found"));
    GNUNET_SERVER_client_drop (client);
    return GNUNET_OK;           /* last item */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Item %llu matches `%s' request for key `%s' and type %u.\n",
              (unsigned long long) uid, "REMOVE", GNUNET_h2s (key), type);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes removed (explicit request)"),
                            size, GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter, key);
  transmit_status (client, GNUNET_OK, NULL);
  GNUNET_SERVER_client_drop (client);
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
handle_remove (void *cls, struct GNUNET_SERVER_Client *client,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing `%s' request for `%s' of type %u\n", "REMOVE",
              GNUNET_h2s (&dm->key), ntohl (dm->type));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# REMOVE requests received"),
                            1, GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
  GNUNET_CRYPTO_hash (&dm[1], ntohl (dm->size), &vhash);
  plugin->api->get_key (plugin->api->cls, 0, &dm->key, &vhash,
                        (enum GNUNET_BLOCK_Type) ntohl (dm->type),
                        &remove_callback, client);
}


/**
 * Handle DROP-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_drop (void *cls, struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing `%s' request\n", "DROP");
  do_drop = GNUNET_YES;
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
disk_utilization_change_cb (void *cls, int delta)
{
  if ((delta < 0) && (payload < -delta))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Datastore payload inaccurate (%lld < %lld).  Trying to fix.\n"),
                (long long) payload, (long long) -delta);
    payload = plugin->api->estimate_size (plugin->api->cls);
    sync_stats ();
    return;
  }
  payload += delta;
  lastSync++;
  if (lastSync >= MAX_STAT_SYNC_LAG)
    sync_stats ();
}


/**
 * Callback function to process statistic values.
 *
 * @param cls closure (struct Plugin*)
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
process_stat_in (void *cls, const char *subsystem, const char *name,
                 uint64_t value, int is_persistent)
{
  GNUNET_assert (stats_worked == GNUNET_NO);
  stats_worked = GNUNET_YES;
  payload += value;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notification from statistics about existing payload (%llu), new payload is %llu\n",
              value, payload);
  return GNUNET_OK;
}


static void
process_stat_done (void *cls, int success)
{
  struct DatastorePlugin *plugin = cls;

  stat_get = NULL;
  if (stats_worked == GNUNET_NO)
    payload = plugin->api->estimate_size (plugin->api->cls);
}


/**
 * Load the datastore plugin.
 */
static struct DatastorePlugin *
load_plugin ()
{
  struct DatastorePlugin *ret;
  char *libname;

  ret = GNUNET_malloc (sizeof (struct DatastorePlugin));
  ret->env.cfg = cfg;
  ret->env.duc = &disk_utilization_change_cb;
  ret->env.cls = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' datastore plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", plugin_name);
  ret->short_name = GNUNET_strdup (plugin_name);
  ret->lib_name = libname;
  ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
  if (ret->api == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load datastore plugin for `%s'\n"), plugin_name);
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
  GNUNET_free (quota_stat_name);
  quota_stat_name = NULL;
}


/**
 * Final task run after shutdown.  Unloads plugins and disconnects us from
 * statistics.
 */
static void
unload_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (lastSync > 0)
    sync_stats ();
  if (GNUNET_YES == do_drop)
    plugin->api->drop (plugin->api->cls);
  unload_plugin (plugin);
  plugin = NULL;
  if (filter != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_free (filter);
    filter = NULL;
  }
  if (stat_get != NULL)
  {
    GNUNET_STATISTICS_get_cancel (stat_get);
    stat_get = NULL;
  }
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  GNUNET_free_non_null (plugin_name);
  plugin_name = NULL;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TransmitCallbackContext *tcc;

  cleaning_done = GNUNET_YES;
  while (NULL != (tcc = tcc_head))
  {
    GNUNET_CONTAINER_DLL_remove (tcc_head, tcc_tail, tcc);
    if (tcc->th != NULL)
    {
      GNUNET_SERVER_notify_transmit_ready_cancel (tcc->th);
      GNUNET_SERVER_client_drop (tcc->client);
    }
    GNUNET_free (tcc->msg);
    GNUNET_free (tcc);
  }
  if (expired_kill_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (expired_kill_task);
    expired_kill_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_continuation (&unload_task, NULL,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
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
cleanup_reservations (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ReservationList *pos;
  struct ReservationList *prev;
  struct ReservationList *next;

  if (client == NULL)
    return;
  prev = NULL;
  pos = reservations;
  while (NULL != pos)
  {
    next = pos->next;
    if (pos->client == client)
    {
      if (prev == NULL)
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
  GNUNET_STATISTICS_set (stats, gettext_noop ("# reserved"), reserved,
                         GNUNET_NO);
}


/**
 * Adds a given key to the bloomfilter 'count' times.
 *
 * @param cls the bloomfilter
 * @param key key to add
 * @param count number of times to add key
 */
static void
add_key_to_bloomfilter (void *cls,
			const GNUNET_HashCode *key,
			unsigned int count)
{
  struct GNUNET_CONTAINER_BloomFilter *bf = cls;
  while (0 < count--)
    GNUNET_CONTAINER_bloomfilter_add (bf, key);
}


/**
 * Process datastore requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_reserve, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE,
     sizeof (struct ReserveMessage)},
    {&handle_release_reserve, NULL,
     GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE,
     sizeof (struct ReleaseReserveMessage)},
    {&handle_put, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_PUT, 0},
    {&handle_update, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE,
     sizeof (struct UpdateMessage)},
    {&handle_get, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_GET, 0},
    {&handle_get_replication, NULL,
     GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_get_zero_anonymity, NULL,
     GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY,
     sizeof (struct GetZeroAnonymityMessage)},
    {&handle_remove, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE, 0},
    {&handle_drop, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_DROP,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };
  char *fn;  
  char *pfn;
  unsigned int bf_size;
  int refresh_bf;

  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "DATASTORE", "DATABASE",
                                             &plugin_name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No `%s' specified for `%s' in configuration!\n"), "DATABASE",
                "DATASTORE");
    return;
  }
  GNUNET_asprintf (&quota_stat_name,
		   _("# bytes used in file-sharing datastore `%s'"),
		   plugin_name);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg, "DATASTORE", "QUOTA", &quota))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No `%s' specified for `%s' in configuration!\n"), "QUOTA",
                "DATASTORE");
    return;
  }
  stats = GNUNET_STATISTICS_create ("datastore", cfg);
  GNUNET_STATISTICS_set (stats, gettext_noop ("# quota"), quota, GNUNET_NO);
  cache_size = quota / 8;       /* Or should we make this an option? */
  GNUNET_STATISTICS_set (stats, gettext_noop ("# cache size"), cache_size,
                         GNUNET_NO);
  if (quota / (32 * 1024LL) > (1 << 31)) 
    bf_size = (1 << 31);          /* absolute limit: ~2 GB, beyond that BF just won't help anyway */
  else
    bf_size = quota / (32 * 1024LL);         /* 8 bit per entry, 1 bit per 32 kb in DB */
  fn = NULL;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (cfg, "DATASTORE", "BLOOMFILTER",
                                                &fn)) ||
      (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not use specified filename `%s' for bloomfilter.\n"),
                fn != NULL ? fn : "");
    GNUNET_free_non_null (fn);
    fn = NULL;
  }
  if (fn != NULL)
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
	    filter = GNUNET_CONTAINER_bloomfilter_load (NULL, bf_size, 5);        /* approx. 3% false positives at max use */
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
    filter = GNUNET_CONTAINER_bloomfilter_init (NULL, bf_size, 5);      /* approx. 3% false positives at max use */
    refresh_bf = GNUNET_YES;
  }
  GNUNET_free_non_null (fn);
  if (filter == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to initialize bloomfilter.\n"));
    if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
      stats = NULL;
    }
    return;
  }
  plugin = load_plugin ();
  if (NULL == plugin)
  {
    GNUNET_CONTAINER_bloomfilter_free (filter);
    filter = NULL;
    if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
      stats = NULL;
    }
    return;
  }
  stat_get =
      GNUNET_STATISTICS_get (stats, "datastore", quota_stat_name,
                             GNUNET_TIME_UNIT_SECONDS, &process_stat_done,
                             &process_stat_in, plugin);
  GNUNET_SERVER_disconnect_notify (server, &cleanup_reservations, NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  if (GNUNET_YES == refresh_bf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Rebuilding bloomfilter.  Please be patient.\n"));
    if (NULL != plugin->api->get_keys)
      plugin->api->get_keys (plugin->api->cls, &add_key_to_bloomfilter, filter);  
    else
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Plugin does not support get_keys function. Please fix!\n"));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Bloomfilter construction complete.\n"));
  }
  expired_kill_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                          &delete_expired, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleaning_task,
                                NULL);
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

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "datastore", GNUNET_SERVICE_OPTION_NONE,
                           &run, NULL)) ? 0 : 1;
  return ret;
}


/* end of gnunet-service-datastore.c */
