/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns.c
 * @brief GNU Name System (main service)
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_shorten.h"
#include "gnunet-service-gns_interceptor.h"
#include "gnunet_protocols.h"

/**
 * The initial interval in milliseconds btween puts in
 * a zone iteration
 */
#define INITIAL_PUT_INTERVAL GNUNET_TIME_UNIT_MILLISECONDS

/**
 * The upper bound for the zone iteration interval in milliseconds
 */
#define MINIMUM_ZONE_ITERATION_INTERVAL GNUNET_TIME_UNIT_SECONDS

/**
 * The default put interval for the zone iteration. In case
 * no option is found
 */
#define DEFAULT_ZONE_PUBLISH_TIME_WINDOW GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * The factor the current zone iteration interval is divided by for each
 * additional new record
 */
#define LATE_ITERATION_SPEEDUP_FACTOR 2

/**
 * How long until a DHT PUT attempt should time out?
 */
#define DHT_OPERATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * What replication level do we use for DHT PUT operations?
 */
#define DHT_GNS_REPLICATION_LEVEL 5


/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *next;

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *prev;

  /**
   * Handle to the requesting client
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Active handle for the lookup.
   */
  struct GNS_ResolverHandle *lookup;

  /**
   * request id
   */
  uint32_t request_id;

};


/**
 * Handle for DHT PUT activity triggered from the namestore monitor.
 */
struct MonitorActivity
{
  /**
   * Kept in a DLL.
   */
  struct MonitorActivity *next;

  /**
   * Kept in a DLL.
   */
  struct MonitorActivity *prev;

  /**
   * Handle for the DHT PUT operation.
   */
  struct GNUNET_DHT_PutHandle *ph;
};


/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Active DHT put operation (or NULL)
 */
static struct GNUNET_DHT_PutHandle *active_put;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache_handle;

/**
 * Our handle to the identity service
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Our handle to the identity operation to find the master zone
 * for intercepted queries.
 */
static struct GNUNET_IDENTITY_Operation *identity_op;

/**
 * Handle to iterate over our authoritative zone in namestore
 */
static struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * Handle to monitor namestore changes to instant propagation.
 */
static struct GNUNET_NAMESTORE_ZoneMonitor *zmon;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Head of the DLL.
 */
static struct ClientLookupHandle *clh_head;

/**
 * Tail of the DLL.
 */
static struct ClientLookupHandle *clh_tail;

/**
 * Head of monitor activities; kept in a DLL.
 */
static struct MonitorActivity *ma_head;

/**
 * Tail of monitor activities; kept in a DLL.
 */
static struct MonitorActivity *ma_tail;

/**
 * Useful for zone update for DHT put
 */
static unsigned long long num_public_records;

/**
 * Last seen record count
 */
static unsigned long long last_num_public_records;

/**
 * Minimum relative expiration time of records seem during the current
 * zone iteration.
 */
static struct GNUNET_TIME_Relative min_relative_record_time;

/**
 * Zone iteration PUT interval.
 */
static struct GNUNET_TIME_Relative put_interval;

/**
 * Default time window for zone iteration
 */
static struct GNUNET_TIME_Relative zone_publish_time_window_default;

/**
 * Time window for zone iteration, adjusted based on relative record
 * expiration times in our zone.
 */
static struct GNUNET_TIME_Relative zone_publish_time_window;

/**
 * zone publish task
 */
static struct GNUNET_SCHEDULER_Task * zone_publish_task;

/**
 * #GNUNET_YES if zone has never been published before
 */
static int first_zone_iteration;

/**
 * #GNUNET_YES if ipv6 is supported
 */
static int v6_enabled;

/**
 * #GNUNET_YES if ipv4 is supported
 */
static int v4_enabled;

/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;


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
  struct ClientLookupHandle *clh;
  struct MonitorActivity *ma;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutting down!\n");
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  while (NULL != (clh = clh_head))
  {
    GNUNET_SERVER_client_set_user_context (clh->client, NULL);
    GNS_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (clh_head, clh_tail, clh);
    GNUNET_free (clh);
  }

  GNS_interceptor_done ();
  if (NULL != identity_op)
  {
    GNUNET_IDENTITY_cancel (identity_op);
    identity_op = NULL;
  }
  if (NULL != identity_handle)
  {
    GNUNET_IDENTITY_disconnect (identity_handle);
    identity_handle = NULL;
  }
  GNS_resolver_done ();
  GNS_shorten_done ();
  while (NULL != (ma = ma_head))
  {
    GNUNET_DHT_put_cancel (ma->ph);
    GNUNET_CONTAINER_DLL_remove (ma_head,
                                 ma_tail,
                                 ma);
    GNUNET_free (ma);
  }
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics, GNUNET_NO);
    statistics = NULL;
  }
  if (NULL != zone_publish_task)
  {
    GNUNET_SCHEDULER_cancel (zone_publish_task);
    zone_publish_task = NULL;
  }
  if (NULL != namestore_iter)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    namestore_iter = NULL;
  }
  if (NULL != zmon)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zmon);
    zmon = NULL;
  }
  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
  }
  if (NULL != namecache_handle)
  {
    GNUNET_NAMECACHE_disconnect (namecache_handle);
    namecache_handle = NULL;
  }
  if (NULL != active_put)
  {
    GNUNET_DHT_put_cancel (active_put);
    active_put = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Method called periodically that triggers iteration over authoritative records
 *
 * @param cls closure
 * @param tc task context
 */
static void
publish_zone_dht_next (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  zone_publish_task = NULL;
  GNUNET_NAMESTORE_zone_iterator_next (namestore_iter);
}


/**
 * Periodically iterate over our zone and store everything in dht
 *
 * @param cls NULL
 * @param tc task context
 */
static void
publish_zone_dht_start (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Continuation called from DHT once the PUT operation is done.
 *
 * @param cls closure, NULL if called from regular iteration,
 *        `struct MonitorActivity` if called from #handle_monitor_event.
 * @param success #GNUNET_OK on success
 */
static void
dht_put_continuation (void *cls,
		      int success)
{
  struct MonitorActivity *ma = cls;
  struct GNUNET_TIME_Relative next_put_interval;

  num_public_records++;
  if (NULL == ma)
  {
    active_put = NULL;
    if ( (num_public_records > last_num_public_records) &&
         (GNUNET_NO == first_zone_iteration) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Last record count was lower than current record count.  Reducing interval.\n");
      put_interval = GNUNET_TIME_relative_divide (zone_publish_time_window,
                                                  num_public_records);
      next_put_interval = GNUNET_TIME_relative_divide (put_interval,
                                                       LATE_ITERATION_SPEEDUP_FACTOR);
    }
    else
      next_put_interval = put_interval;

    GNUNET_STATISTICS_set (statistics,
                           "Current zone iteration interval (ms)",
                           next_put_interval.rel_value_us / 1000LL,
                           GNUNET_NO);
    zone_publish_task = GNUNET_SCHEDULER_add_delayed (next_put_interval,
                                                      &publish_zone_dht_next,
                                                      NULL);
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (ma_head,
                                 ma_tail,
                                 ma);
    GNUNET_free (ma);
  }
}


/**
 * Convert namestore records from the internal format to that
 * suitable for publication (removes private records, converts
 * to absolute expiration time).
 *
 * @param rd input records
 * @param rd_count size of the @a rd and @a rd_public arrays
 * @param rd_public where to write the converted records
 * @return number of records written to @a rd_public
 */
static unsigned int
convert_records_for_export (const struct GNUNET_GNSRECORD_Data *rd,
                            unsigned int rd_count,
                            struct GNUNET_GNSRECORD_Data *rd_public)
{
  struct GNUNET_TIME_Absolute now;
  unsigned int rd_public_count;
  unsigned int i;

  rd_public_count = 0;
  now = GNUNET_TIME_absolute_get ();
  for (i=0;i<rd_count;i++)
    if (0 == (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE))
    {
      rd_public[rd_public_count] = rd[i];
      if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
      {
        /* GNUNET_GNSRECORD_block_create will convert to absolute time;
           we just need to adjust our iteration frequency */
        min_relative_record_time.rel_value_us =
          GNUNET_MIN (rd_public[rd_public_count].expiration_time,
                      min_relative_record_time.rel_value_us);
      }
      else if (rd_public[rd_public_count].expiration_time < now.abs_value_us)
      {
        /* record already expired, skip it */
        continue;
      }
      rd_public_count++;
    }
  return rd_public_count;
}


/**
 * Store GNS records in the DHT.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 * @param pc_arg closure argument to pass to the #dht_put_continuation
 * @return DHT PUT handle, NULL on error
 */
static struct GNUNET_DHT_PutHandle *
perform_dht_put (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                 const char *label,
                 const struct GNUNET_GNSRECORD_Data *rd_public,
                 unsigned int rd_public_count,
                 void *pc_arg)
{
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_HashCode query;
  struct GNUNET_TIME_Absolute expire;
  size_t block_size;
  struct GNUNET_DHT_PutHandle *ret;

  expire = GNUNET_GNSRECORD_record_get_expiration_time (rd_public_count,
							rd_public);
  block = GNUNET_GNSRECORD_block_create (key,
					 expire,
					 label,
					 rd_public,
					 rd_public_count);
  if (NULL == block)
    return NULL; /* whoops */
  block_size = ntohl (block->purpose.size)
    + sizeof (struct GNUNET_CRYPTO_EcdsaSignature)
    + sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  GNUNET_GNSRECORD_query_from_private_key (key,
					   label,
					   &query);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing %u record(s) for label `%s' in DHT with expiration `%s' under key %s\n",
              rd_public_count,
              label,
              GNUNET_STRINGS_absolute_time_to_string (expire),
              GNUNET_h2s (&query));
  ret = GNUNET_DHT_put (dht_handle, &query,
                        DHT_GNS_REPLICATION_LEVEL,
                        GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                        GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                        block_size,
                        block,
                        expire,
                        DHT_OPERATION_TIMEOUT,
                        &dht_put_continuation,
                        pc_arg);
  GNUNET_free (block);
  return ret;
}


/**
 * Function used to put all records successively into the DHT.
 *
 * @param cls the closure (NULL)
 * @param key the private key of the authority (ours)
 * @param label the name of the records, NULL once the iteration is done
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
put_gns_record (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                const char *label,
                unsigned int rd_count,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rd_public[rd_count];
  unsigned int rd_public_count;

  if (NULL == label)
  {
    /* we're done with one iteration, calculate when to do the next one */
    namestore_iter = NULL;
    last_num_public_records = num_public_records;
    first_zone_iteration = GNUNET_NO;
    if (0 == num_public_records)
    {
      /**
       * If no records are known (startup) or none present
       * we can safely set the interval to the value for a single
       * record
       */
      put_interval = zone_publish_time_window;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
		  "No records in namestore database.\n");
    }
    else
    {
      /* If records are present, next publication is based on the minimum
       * relative expiration time of the records published divided by 4
       */
      zone_publish_time_window = GNUNET_TIME_relative_min (
          GNUNET_TIME_relative_divide (min_relative_record_time, 4),
          zone_publish_time_window_default);
      put_interval = GNUNET_TIME_relative_divide (zone_publish_time_window,
          num_public_records);
    }
    /* reset for next iteration */
    min_relative_record_time = GNUNET_TIME_UNIT_FOREVER_REL;
    put_interval = GNUNET_TIME_relative_max (MINIMUM_ZONE_ITERATION_INTERVAL,
					     put_interval);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Zone iteration finished. Adjusted zone iteration interval to %s\n",
		GNUNET_STRINGS_relative_time_to_string (put_interval, GNUNET_YES));
    GNUNET_STATISTICS_set (statistics,
                           "Current zone iteration interval (in ms)",
                           put_interval.rel_value_us / 1000LL,
                           GNUNET_NO);
    GNUNET_STATISTICS_update (statistics,
                              "Number of zone iterations",
			      1,
			      GNUNET_NO);
    GNUNET_STATISTICS_set (statistics,
                           "Number of public records in DHT",
                           last_num_public_records,
                           GNUNET_NO);
    if (0 == num_public_records)
      zone_publish_task = GNUNET_SCHEDULER_add_delayed (put_interval,
							&publish_zone_dht_start,
							NULL);
    else
      zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start,
						    NULL);
    return;
  }

  rd_public_count = convert_records_for_export (rd,
                                                rd_count,
                                                rd_public);

  /* We got a set of records to publish */
  if (0 == rd_public_count)
  {
    zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_next,
                                                   NULL);
    return;
  }

  active_put = perform_dht_put (key,
                                label,
                                rd_public,
                                rd_public_count,
                                NULL);
  if (NULL == active_put)
  {
    GNUNET_break (0);
    dht_put_continuation (NULL, GNUNET_NO);
  }
}


/**
 * Periodically iterate over all zones and store everything in DHT
 *
 * @param cls NULL
 * @param tc task context
 */
static void
publish_zone_dht_start (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  zone_publish_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting DHT zone update!\n");
  /* start counting again */
  num_public_records = 0;
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (namestore_handle,
      NULL, /* All zones */
      &put_gns_record, NULL );
}


/**
 * Process a record that was stored in the namestore
 * (invoked by the monitor).
 *
 * @param cls closure, NULL
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
handle_monitor_event (void *cls,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                      const char *label,
                      unsigned int rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rd_public[rd_count];
  unsigned int rd_public_count;
  struct MonitorActivity *ma;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for label `%s' via namestore monitor\n",
              rd_count,
              label);
  /* filter out records that are not public, and convert to
     absolute expiration time. */
  rd_public_count = convert_records_for_export (rd, rd_count,
                                                rd_public);
  if (0 == rd_public_count)
    return; /* nothing to do */
  ma = GNUNET_new (struct MonitorActivity);
  ma->ph = perform_dht_put (zone, label,
                            rd, rd_count,
                            ma);
  if (NULL == ma->ph)
  {
    /* PUT failed, do not remember operation */
    GNUNET_free (ma);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (ma_head,
                               ma_tail,
                               ma);
}


/* END DHT ZONE PROPAGATION */


/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
send_lookup_response (void* cls,
		      uint32_t rd_count,
		      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ClientLookupHandle *clh = cls;
  struct GNUNET_GNS_ClientLookupResultMessage *rmsg;
  size_t len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending `%s' message with %d results\n",
              "LOOKUP_RESULT",
	      rd_count);

  len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  rmsg = GNUNET_malloc (len + sizeof (struct GNUNET_GNS_ClientLookupResultMessage));
  rmsg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->header.size = htons (len + sizeof(struct GNUNET_GNS_ClientLookupResultMessage));
  rmsg->id = clh->request_id;
  rmsg->rd_count = htonl (rd_count);
  GNUNET_GNSRECORD_records_serialize (rd_count, rd, len,
				      (char*) &rmsg[1]);
  GNUNET_SERVER_notification_context_unicast (nc,
					      clh->client,
					      &rmsg->header,
					      GNUNET_NO);
  GNUNET_free (rmsg);
  GNUNET_CONTAINER_DLL_remove (clh_head, clh_tail, clh);
  GNUNET_SERVER_client_set_user_context (clh->client, NULL);
  GNUNET_free (clh);
  GNUNET_STATISTICS_update (statistics,
                            "Completed lookups", 1,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (statistics,
			    "Records resolved",
			    rd_count,
			    GNUNET_NO);
}


/**
 * Handle lookup requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_lookup (void *cls,
	       struct GNUNET_SERVER_Client *client,
	       const struct GNUNET_MessageHeader *message)
{
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH + 1];
  struct ClientLookupHandle *clh;
  char *nameptr = name;
  const char *utf_in;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *key;
  uint16_t msg_size;
  const struct GNUNET_GNS_ClientLookupMessage *sh_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "LOOKUP");
  msg_size = ntohs (message->size);
  if (msg_size < sizeof (struct GNUNET_GNS_ClientLookupMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sh_msg = (const struct GNUNET_GNS_ClientLookupMessage *) message;
  GNUNET_SERVER_notification_context_add (nc, client);
  if (GNUNET_YES == ntohs (sh_msg->have_key))
    key = &sh_msg->shorten_key;
  else
    key = NULL;
  utf_in = (const char *) &sh_msg[1];
  if ( ('\0' != utf_in[msg_size - sizeof (struct GNUNET_GNS_ClientLookupMessage) - 1]) ||
       (strlen (utf_in) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_STRINGS_utf8_tolower (utf_in, nameptr);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  clh = GNUNET_new (struct ClientLookupHandle);
  GNUNET_SERVER_client_set_user_context (client, clh);
  GNUNET_CONTAINER_DLL_insert (clh_head, clh_tail, clh);
  clh->client = client;
  clh->request_id = sh_msg->id;
  if ( (GNUNET_DNSPARSER_TYPE_A == ntohl (sh_msg->type)) &&
       (GNUNET_OK != v4_enabled) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"LOOKUP: Query for A record but AF_INET not supported!");
    send_lookup_response (clh, 0, NULL);
    return;
  }
  if ( (GNUNET_DNSPARSER_TYPE_AAAA == ntohl (sh_msg->type)) &&
       (GNUNET_OK != v6_enabled) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for AAAA record but AF_INET6 not supported!");
    send_lookup_response (clh, 0, NULL);
    return;
  }
  clh->lookup = GNS_resolver_lookup (&sh_msg->zone,
				     ntohl (sh_msg->type),
				     name,
				     key,
				     (enum GNUNET_GNS_LocalOptions) ntohs (sh_msg->options),
				     &send_lookup_response, clh);
  GNUNET_STATISTICS_update (statistics,
                            "Lookup attempts",
			    1, GNUNET_NO);
}


/**
 * One of our clients disconnected, clean up after it.
 *
 * @param cls NULL
 * @param client the client that disconnected
 */
static void
notify_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client *client)
{
  struct ClientLookupHandle *clh;

  if (NULL == client)
    return;
  clh = GNUNET_SERVER_client_get_user_context (client, struct ClientLookupHandle);
  if (NULL == clh)
    return;
  GNS_resolver_lookup_cancel (clh->lookup);
  GNUNET_CONTAINER_DLL_remove (clh_head, clh_tail, clh);
  GNUNET_free (clh);
}


/**
 * The zone monitor is now in SYNC with the current state of the
 * name store.  Start to perform periodic iterations.
 *
 * @param cls NULL
 */
static void
monitor_sync_event (void *cls)
{
  zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start,
						NULL);
}


/**
 * Method called to inform about the ego to be used for the master zone
 * for DNS interceptions.
 *
 * This function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate that interception is not configured.
 * If @a ego is non-NULL, we should start to intercept DNS queries
 * and resolve ".gnu" queries using the given ego as the master zone.
 *
 * @param cls closure, our `const struct GNUNET_CONFIGURATION_Handle *c`
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_intercept_cb (void *cls,
                       struct GNUNET_IDENTITY_Ego *ego,
                       void **ctx,
                       const char *name)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey dns_root;

  identity_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("No ego configured for `%s`\n"),
		"gns-intercept");
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
				      &dns_root);
  if (GNUNET_SYSERR ==
      GNS_interceptor_init (&dns_root, cfg))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }
}


/**
 * Process GNS requests.
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
    { &handle_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_LOOKUP, 0},
    {NULL, NULL, 0, 0}
  };
  unsigned long long max_parallel_bg_queries = 0;

  v6_enabled = GNUNET_NETWORK_test_pf (PF_INET6);
  v4_enabled = GNUNET_NETWORK_test_pf (PF_INET);
  min_relative_record_time = GNUNET_TIME_UNIT_FOREVER_REL;
  namestore_handle = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to the namestore!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  namecache_handle = GNUNET_NAMECACHE_connect (c);
  if (NULL == namecache_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to the namecache!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  put_interval = INITIAL_PUT_INTERVAL;
  zone_publish_time_window_default = DEFAULT_ZONE_PUBLISH_TIME_WINDOW;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_time (c, "gns",
					   "ZONE_PUBLISH_TIME_WINDOW",
					   &zone_publish_time_window_default))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Time window for zone iteration: %s\n",
		GNUNET_STRINGS_relative_time_to_string (zone_publish_time_window,
                                                        GNUNET_YES));
  }
  zone_publish_time_window = zone_publish_time_window_default;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (c, "gns",
                                            "MAX_PARALLEL_BACKGROUND_QUERIES",
                                            &max_parallel_bg_queries))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Number of allowed parallel background queries: %llu\n",
		max_parallel_bg_queries);
  }

  dht_handle = GNUNET_DHT_connect (c,
				   (unsigned int) max_parallel_bg_queries);
  if (NULL == dht_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not connect to DHT!\n"));
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }

  identity_handle = GNUNET_IDENTITY_connect (c,
                                             NULL,
                                             NULL);
  if (NULL == identity_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Could not connect to identity service!\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Looking for gns-intercept ego\n");
    identity_op = GNUNET_IDENTITY_get (identity_handle,
                                       "gns-intercept",
                                       &identity_intercept_cb,
                                       (void *) c);
  }
  GNS_resolver_init (namecache_handle,
                     dht_handle,
		     c,
		     max_parallel_bg_queries);
  GNS_shorten_init (namestore_handle,
                    namecache_handle,
                    dht_handle);
  GNUNET_SERVER_disconnect_notify (server,
				   &notify_client_disconnect,
				   NULL);
  /* Schedule periodic put for our records. */
  first_zone_iteration = GNUNET_YES;
  GNUNET_SERVER_add_handlers (server, handlers);
  statistics = GNUNET_STATISTICS_create ("gns", c);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  zmon = GNUNET_NAMESTORE_zone_monitor_start (c,
                                              NULL,
                                              GNUNET_NO,
                                              &handle_monitor_event,
                                              &monitor_sync_event,
                                              NULL);
  GNUNET_break (NULL != zmon);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
}


/**
 * The main function for the GNS service.
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
       GNUNET_SERVICE_run (argc, argv, "gns", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-service-gns.c */
