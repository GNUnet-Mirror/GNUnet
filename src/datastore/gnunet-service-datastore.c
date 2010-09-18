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
#include "plugin_datastore.h"
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

#define QUOTA_STAT_NAME gettext_noop ("# bytes used in file-sharing datastore")

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
 * Our scheduler.
 */
struct GNUNET_SCHEDULER_Handle *sched; 

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
  GNUNET_STATISTICS_set (stats,
			 QUOTA_STAT_NAME,
			 payload,
			 GNUNET_YES);
  lastSync = 0;
}




/**
 * Function called once the transmit operation has
 * either failed or succeeded.
 *
 * @param cls closure
 * @param status GNUNET_OK on success, GNUNET_SYSERR on error
 */
typedef void (*TransmitContinuation)(void *cls,
				     int status);


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
  struct GNUNET_CONNECTION_TransmitHandle *th;

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
delete_expired (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Iterate over the expired items stored in the datastore.
 * Delete all expired items; once we have processed all
 * expired items, re-schedule the "delete_expired" task.
 *
 * @param cls not used
 * @param next_cls closure to pass to the "next" function.
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
expired_processor (void *cls,
		   void *next_cls,
		   const GNUNET_HashCode * key,
		   uint32_t size,
		   const void *data,
		   enum GNUNET_BLOCK_Type type,
		   uint32_t priority,
		   uint32_t anonymity,
		   struct GNUNET_TIME_Absolute
		   expiration, 
		   uint64_t uid)
{
  struct GNUNET_TIME_Absolute now;

  if (key == NULL) 
    {
      expired_kill_task 
	= GNUNET_SCHEDULER_add_delayed (sched,
					MAX_EXPIRE_DELAY,
					&delete_expired,
					NULL);
      return GNUNET_SYSERR;
    }
  now = GNUNET_TIME_absolute_get ();
  if (expiration.value > now.value)
    {
      /* finished processing */
      plugin->api->next_request (next_cls, GNUNET_YES);
      return GNUNET_SYSERR;
    }
  plugin->api->next_request (next_cls, GNUNET_NO);
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Deleting content `%s' of type %u that expired %llu ms ago\n",
	      GNUNET_h2s (key),
	      type,
	      (unsigned long long) (now.value - expiration.value));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes expired"),
			    size,
			    GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter,
				       key);
  return GNUNET_NO; /* delete */
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
delete_expired (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  expired_kill_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->api->iter_ascending_expiration (plugin->api->cls, 
					  0,
					  &expired_processor,
					  NULL);
}


/**
 * An iterator over a set of items stored in the datastore.
 *
 * @param cls closure
 * @param next_cls closure to pass to the "next" function.
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
manage (void *cls,
	void *next_cls,
	const GNUNET_HashCode * key,
	uint32_t size,
	const void *data,
	enum GNUNET_BLOCK_Type type,
	uint32_t priority,
	uint32_t anonymity,
	struct GNUNET_TIME_Absolute
	expiration, 
	uint64_t uid)
{
  unsigned long long *need = cls;

  if (NULL == key)
    {
      GNUNET_free (need);
      return GNUNET_SYSERR;
    }
  if (size + GNUNET_DATASTORE_ENTRY_OVERHEAD > *need)
    *need = 0;
  else
    *need -= size + GNUNET_DATASTORE_ENTRY_OVERHEAD;
  plugin->api->next_request (next_cls, 
			     (0 == *need) ? GNUNET_YES : GNUNET_NO);
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Deleting %llu bytes of low-priority content `%s' of type %u (still trying to free another %llu bytes)\n",
	      (unsigned long long) (size + GNUNET_DATASTORE_ENTRY_OVERHEAD),
	      GNUNET_h2s (key),
	      type,
	      *need);
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes purged (low-priority)"),
			    size,
			    GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter,
				       key);
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
  unsigned long long *n;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to free up %llu bytes of cache space\n",
	      need);
#endif
  n = GNUNET_malloc (sizeof(unsigned long long));
  *n = need;
  plugin->api->iter_low_priority (plugin->api->cls,
				  0,
				  &manage,
				  n);
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
transmit_callback (void *cls,
		   size_t size, void *buf)
{
  struct TransmitCallbackContext *tcc = cls;
  size_t msize;
  
  tcc->th = NULL;
  GNUNET_CONTAINER_DLL_remove (tcc_head,
			       tcc_tail,
			       tcc);
  msize = ntohs(tcc->msg->size);
  if (size == 0)
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Transmission failed.\n");
#endif
      if (tcc->tc != NULL)
	tcc->tc (tcc->tc_cls, GNUNET_SYSERR);
      if (GNUNET_YES == tcc->end)
	GNUNET_SERVER_receive_done (tcc->client, GNUNET_SYSERR);       
      GNUNET_SERVER_client_drop (tcc->client);
      GNUNET_free (tcc->msg);
      GNUNET_free (tcc);
      return 0;
    }
  GNUNET_assert (size >= msize);
  memcpy (buf, tcc->msg, msize);
  if (tcc->tc != NULL)
    tcc->tc (tcc->tc_cls, GNUNET_OK);
  if (GNUNET_YES == tcc->end)
    {
      GNUNET_SERVER_receive_done (tcc->client, GNUNET_OK);
    }
  else
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Response transmitted, more pending!\n");
#endif
    }
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
 * @param tc function to call afterwards
 * @param tc_cls closure for tc
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

  if (GNUNET_YES == cleaning_done)
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Shutdown in progress, aborting transmission.\n");
#endif
      GNUNET_free (msg);
      if (NULL != tc)
	tc (tc_cls, GNUNET_SYSERR);
      return;
    }
  tcc = GNUNET_malloc (sizeof(struct TransmitCallbackContext));
  tcc->msg = msg;
  tcc->client = client;
  tcc->tc = tc;
  tcc->tc_cls = tc_cls;
  tcc->end = end;
  if (NULL ==
      (tcc->th = GNUNET_SERVER_notify_transmit_ready (client,
						      ntohs(msg->size),
						      GNUNET_TIME_UNIT_FOREVER_REL,
						      &transmit_callback,
						      tcc)))
    {
      GNUNET_break (0);
      if (GNUNET_YES == end)
	{
#if DEBUG_DATASTORE
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      "Disconnecting client.\n");
#endif	  
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	}
      if (NULL != tc)
	tc (tc_cls, GNUNET_SYSERR);
      GNUNET_free (msg);
      GNUNET_free (tcc);
      return;
    }
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (tcc_head,
			       tcc_tail,
			       tcc);
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

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting `%s' message with value %d and message `%s'\n",
	      "STATUS",
	      code,
	      msg != NULL ? msg : "(none)");
#endif
  slen = (msg == NULL) ? 0 : strlen(msg) + 1;  
  sm = GNUNET_malloc (sizeof(struct StatusMessage) + slen);
  sm->header.size = htons(sizeof(struct StatusMessage) + slen);
  sm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_STATUS);
  sm->status = htonl(code);
  if (slen > 0)
    memcpy (&sm[1], msg, slen);  
  transmit (client, &sm->header, NULL, NULL, GNUNET_YES);
}


/**
 * Function called once the transmit operation has
 * either failed or succeeded.
 *
 * @param next_cls closure for calling "next_request" callback
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
      if (plugin != NULL)
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
	       enum GNUNET_BLOCK_Type type,
	       uint32_t priority,
	       uint32_t anonymity,
	       struct GNUNET_TIME_Absolute
	       expiration, uint64_t uid)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader *end;
  struct DataMessage *dm;

  if (key == NULL)
    {
      /* transmit 'DATA_END' */
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting `%s' message\n",
		  "DATA_END");
#endif
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
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting `%s' message for `%s' of type %u\n",
	      "DATA",
	      GNUNET_h2s (key),
	      type);
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# results found"),
			    1,
			    GNUNET_NO);
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
  /**
   * Static counter to produce reservation identifiers.
   */
  static int reservation_gen;

  const struct ReserveMessage *msg = (const struct ReserveMessage*) message;
  struct ReservationList *e;
  unsigned long long used;
  unsigned long long req;
  uint64_t amount;
  uint32_t entries;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request\n",
	      "RESERVE");
#endif
  amount = GNUNET_ntohll(msg->amount);
  entries = ntohl(msg->entries);
  used = payload + reserved;
  req = amount + ((unsigned long long) GNUNET_DATASTORE_ENTRY_OVERHEAD) * entries;
  if (used + req > quota)
    {
      if (quota < used)
	used = quota; /* cheat a bit for error message (to avoid negative numbers) */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Insufficient space (%llu bytes are available) to satisfy `%s' request for %llu bytes\n"),
		  quota - used,
		  "RESERVE",
		  req);
      if (cache_size < req)
	{
	  /* TODO: document this in the FAQ; essentially, if this
	     message happens, the insertion request could be blocked
	     by less-important content from migration because it is
	     larger than 1/8th of the overall available space, and
	     we only reserve 1/8th for "fresh" insertions */
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("The requested amount (%llu bytes) is larger than the cache size (%llu bytes)\n"),
		      req,
		      cache_size);
	  transmit_status (client, 0, 
			   gettext_noop ("Insufficient space to satisfy request and "
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
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# reserved"),
			 reserved,
			 GNUNET_NO);
  e = GNUNET_malloc (sizeof(struct ReservationList));
  e->next = reservations;
  reservations = e;
  e->client = client;
  e->amount = amount;
  e->entries = entries;
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
  unsigned long long rem;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request\n",
	      "RELEASE_RESERVE");
#endif
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
	  rem = pos->amount + ((unsigned long long) GNUNET_DATASTORE_ENTRY_OVERHEAD) * pos->entries;
	  GNUNET_assert (reserved >= rem);
	  reserved -= rem;
	  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# reserved"),
				 reserved,
				 GNUNET_NO);
#if DEBUG_DATASTORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Returning %llu remaining reserved bytes to storage pool\n",
		      rem);
#endif	  
	  GNUNET_free (pos);
	  transmit_status (client, GNUNET_OK, NULL);
	  return;
	}       
      prev = pos;
    }
  GNUNET_break (0);
  transmit_status (client, GNUNET_SYSERR, gettext_noop ("Could not find matching reservation"));
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
  return dm;
}


/**
 * Context for a put request used to see if the content is
 * already present.
 */
struct PutContext
{
  /**
   * Client to notify on completion.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Did we find the data already in the database?
   */
  int is_present;
  
  /* followed by the 'struct DataMessage' */
};


/**
 * Actually put the data message.
 */
static void
execute_put (struct GNUNET_SERVER_Client *client,
	     const struct DataMessage *dm)
{
  uint32_t size;
  char *msg;
  int ret;

  size = ntohl(dm->size);
  msg = NULL;
  ret = plugin->api->put (plugin->api->cls,
			  &dm->key,
			  size,
			  &dm[1],
			  ntohl(dm->type),
			  ntohl(dm->priority),
			  ntohl(dm->anonymity),
			  GNUNET_TIME_absolute_ntoh(dm->expiration),
			  &msg);
  if (GNUNET_OK == ret)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes stored"),
				size,
				GNUNET_YES);
      GNUNET_CONTAINER_bloomfilter_add (filter,
					&dm->key);
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Successfully stored %u bytes of type %u under key `%s'\n",
		  size,
		  ntohl(dm->type),
		  GNUNET_h2s (&dm->key));
#endif
    }
  transmit_status (client, 
		   (GNUNET_SYSERR == ret) ? GNUNET_SYSERR : GNUNET_OK, 
		   msg);
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
check_present (void *cls,
	       void *next_cls,
	       const GNUNET_HashCode * key,
	       uint32_t size,
	       const void *data,
	       enum GNUNET_BLOCK_Type type,
	       uint32_t priority,
	       uint32_t anonymity,
	       struct GNUNET_TIME_Absolute
	       expiration, uint64_t uid)
{
  struct PutContext *pc = cls;
  const struct DataMessage *dm;

  dm = (const struct DataMessage*) &pc[1];
  if (key == NULL)
    {
      if (pc->is_present == GNUNET_YES)	
	transmit_status (pc->client, GNUNET_OK, NULL);
      else
	execute_put (pc->client, dm);
      GNUNET_SERVER_client_drop (pc->client);
      GNUNET_free (pc);
      return GNUNET_SYSERR;
    }
  if ( (GNUNET_BLOCK_TYPE_FS_DBLOCK == type) ||
       (GNUNET_BLOCK_TYPE_FS_IBLOCK == type) ||
       ( (size == ntohl(dm->size)) &&
	 (0 == memcmp (&dm[1],
		       data,
		       size)) ) )
    {
      pc->is_present = GNUNET_YES;
      plugin->api->next_request (next_cls, GNUNET_YES);
    }
  else
    {
      plugin->api->next_request (next_cls, GNUNET_NO);
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
handle_put (void *cls,
	    struct GNUNET_SERVER_Client *client,
	    const struct GNUNET_MessageHeader *message)
{
  const struct DataMessage *dm = check_data (message);
  int rid;
  struct ReservationList *pos;
  struct PutContext *pc;
  uint32_t size;

  if ( (dm == NULL) ||
       (ntohl(dm->type) == 0) ) 
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request for `%s' of type %u\n",
	      "PUT",
	      GNUNET_h2s (&dm->key),
	      ntohl (dm->type));
#endif
  rid = ntohl(dm->rid);
  size = ntohl(dm->size);
  if (rid > 0)
    {
      pos = reservations;
      while ( (NULL != pos) &&
	      (rid != pos->rid) )
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
  if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (filter,
						       &dm->key))
    {
      pc = GNUNET_malloc (sizeof (struct PutContext) + size + sizeof (struct DataMessage));
      pc->client = client;
      GNUNET_SERVER_client_keep (client);
      memcpy (&pc[1], dm, size + sizeof (struct DataMessage));
      plugin->api->get (plugin->api->cls,
			&dm->key,
			NULL,
			ntohl (dm->type),
			&check_present,
			pc);      
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
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request for `%s' of type %u\n",
	      "GET",
	      GNUNET_h2s (&msg->key),
	      ntohl (msg->type));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# GET requests received"),
			    1,
			    GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
  if ( (size == sizeof(struct GetMessage)) &&
       (GNUNET_YES != GNUNET_CONTAINER_bloomfilter_test (filter,
							 &msg->key)) )
    {
      /* don't bother database... */
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Empty result set for `%s' request for `%s' (bloomfilter).\n",
		  "GET",
		  GNUNET_h2s (&msg->key));
#endif	
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests filtered by bloomfilter"),
				1,
				GNUNET_NO);
      transmit_item (client,
		     NULL, NULL, 0, NULL, 0, 0, 0, 
		     GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
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

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# UPDATE requests received"),
			    1,
			    GNUNET_NO);
  msg = (const struct UpdateMessage*) message;
  emsg = NULL;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request for %llu\n",
	      "UPDATE",
	      (unsigned long long) GNUNET_ntohll (msg->uid));
#endif
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
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request\n",
	      "GET_RANDOM");
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# GET RANDOM requests received"),
			    1,
			    GNUNET_NO);
  GNUNET_SERVER_client_keep (client);
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
		 enum GNUNET_BLOCK_Type type,
		 uint32_t priority,
		 uint32_t anonymity,
		 struct GNUNET_TIME_Absolute
		 expiration, uint64_t uid)
{
  struct RemoveContext *rc = cls;

  if (key == NULL)
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No further matches for `%s' request.\n",
		  "REMOVE");
#endif	
      if (GNUNET_YES == rc->found)
	transmit_status (rc->client, GNUNET_OK, NULL);       
      else
	transmit_status (rc->client, GNUNET_NO, _("Content not found"));       	
      GNUNET_SERVER_client_drop (rc->client);
      GNUNET_free (rc);
      return GNUNET_OK; /* last item */
    }
  rc->found = GNUNET_YES;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Item %llu matches `%s' request for key `%s' and type %u.\n",
	      (unsigned long long) uid,
	      "REMOVE",
	      GNUNET_h2s (key),
	      type);
#endif	
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes removed (explicit request)"),
			    size,
			    GNUNET_YES);
  GNUNET_CONTAINER_bloomfilter_remove (filter,
				       key);
  plugin->api->next_request (next_cls, GNUNET_YES);
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
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request for `%s' of type %u\n",
	      "REMOVE",
	      GNUNET_h2s (&dm->key),
	      ntohl (dm->type));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# REMOVE requests received"),
			    1,
			    GNUNET_NO);
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
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' request\n",
	      "DROP");
#endif
  plugin->api->drop (plugin->api->cls);
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
disk_utilization_change_cb (void *cls,
			    int delta)
{
  if ( (delta < 0) &&
       (payload < -delta) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Datastore payload inaccurate (%lld < %lld).  Trying to fix.\n"),
		  (long long) payload,
		  (long long) -delta);
      payload = plugin->api->get_size (plugin->api->cls);
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
process_stat_in (void *cls,
		 const char *subsystem,
		 const char *name,
		 uint64_t value,
		 int is_persistent)
{
  GNUNET_assert (stats_worked == GNUNET_NO);
  stats_worked = GNUNET_YES;
  payload += value;
#if DEBUG_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Notification from statistics about existing payload (%llu), new payload is %llu\n",
	      value,
	      payload);
#endif
  return GNUNET_OK;
}


static void
process_stat_done (void *cls,
		   int success)
{
  struct DatastorePlugin *plugin = cls;

  stat_get = NULL;
  if (stats_worked == GNUNET_NO) 
    payload = plugin->api->get_size (plugin->api->cls);
}


/**
 * Load the datastore plugin.
 */
static struct DatastorePlugin *
load_plugin () 
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
  ret->env.duc = &disk_utilization_change_cb;
  ret->env.cls = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  ret->short_name = name;
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
 * Final task run after shutdown.  Unloads plugins and disconnects us from
 * statistics.
 */
static void
unload_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unload_plugin (plugin);
  plugin = NULL;
  if (filter != NULL)
    {
      GNUNET_CONTAINER_bloomfilter_free (filter);
      filter = NULL;
    }
  if (lastSync > 0)
    sync_stats ();
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
      GNUNET_CONTAINER_DLL_remove (tcc_head,
				   tcc_tail,
				   tcc);
      if (tcc->th != NULL)
	{
	  GNUNET_CONNECTION_notify_transmit_ready_cancel (tcc->th);
	  GNUNET_SERVER_client_drop (tcc->client);
	}
      if (NULL != tcc->tc)
	tcc->tc (tcc->tc_cls, GNUNET_SYSERR);
      GNUNET_free (tcc->msg);
      GNUNET_free (tcc);
    }
  if (expired_kill_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched,
			       expired_kill_task);
      expired_kill_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_SCHEDULER_add_continuation (sched,
				     &unload_task,
				     NULL,
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
cleanup_reservations (void *cls,
		      struct GNUNET_SERVER_Client
		      * client)
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
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# reserved"),
			 reserved,
			 GNUNET_NO);
}


/**
 * Process datastore requests.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
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
  char *fn;
  unsigned int bf_size;

  sched = s;
  cfg = c;
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
  stats = GNUNET_STATISTICS_create (sched, "datastore", cfg);
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# quota"),
			 quota,
			 GNUNET_NO);
  cache_size = quota / 8; /* Or should we make this an option? */
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# cache size"),
			 cache_size,
			 GNUNET_NO);
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
  stat_get = GNUNET_STATISTICS_get (stats,
				    "datastore",
				    QUOTA_STAT_NAME,
				    GNUNET_TIME_UNIT_SECONDS,
				    &process_stat_done,
				    &process_stat_in,
				    plugin);
  GNUNET_SERVER_disconnect_notify (server, &cleanup_reservations, NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  expired_kill_task
    = GNUNET_SCHEDULER_add_with_priority (sched,
					  GNUNET_SCHEDULER_PRIORITY_IDLE,
					  &delete_expired, NULL);
  GNUNET_SCHEDULER_add_delayed (sched,
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
                             "datastore",
			     GNUNET_SERVICE_OPTION_NONE,
			     &run, NULL)) ? 0 : 1;
  return ret;
}


/* end of gnunet-service-datastore.c */
