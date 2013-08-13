/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gns.h"
#include "gns_common.h"
#include "gnunet-service-gns_resolver.h"
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
 * No option is found
 */
#define DEFAULT_ZONE_PUBLISH_TIME_WINDOW GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * The factor the current zone iteration interval is divided by for each
 * additional new record
 */
#define LATE_ITERATION_SPEEDUP_FACTOR 2


/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{

  /**
   * Handle to the requesting client
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * optional zone private key used for shorten
   */
  struct GNUNET_CRYPTO_EccPrivateKey *shorten_key;

  /**
   * the name to look up
   */
  char *name; 

  /**
   * The zone we look up in
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * request id 
   */
  uint32_t request_id;

  /**
   * GNUNET_YES if we only want to lookup from local cache
   */
  int only_cached;

  /**
   * request type
   */
  int type;
};


/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our zone's private key
 */
static struct GNUNET_CRYPTO_EccPrivateKey *zone_key;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to iterate over our authoritative zone in namestore
 */
static struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Our zone hash
 */
static struct GNUNET_CRYPTO_ShortHashCode zone_hash;

/**
 * Useful for zone update for DHT put
 */
static unsigned long long num_public_records;

/**
 * Last seen record count
 */
static unsigned long long last_num_public_records;

/**
 * Zone iteration PUT interval.
 */
static struct GNUNET_TIME_Relative put_interval;

/**
 * Time window for zone iteration
 */
static struct GNUNET_TIME_Relative zone_publish_time_window;

/**
 * zone publish task
 */
static GNUNET_SCHEDULER_TaskIdentifier zone_publish_task;

/**
 * GNUNET_YES if automatic pkey import for name shortening
 * is enabled
 */
static int auto_import_pkey;

/**
 * GNUNET_YES if zone has never been published before
 */
static int first_zone_iteration;

/**
 * The lookup timeout
 */
static struct GNUNET_TIME_Relative default_lookup_timeout;

/**
 * GNUNET_YES if ipv6 is supported
 */
static int v6_enabled;

/**
 * GNUNET_YES if ipv4 is supported
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
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientShortenHandle *csh_tmp;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Shutting down!\n");
  GNUNET_SERVER_notification_context_destroy (nc);  
  gns_interceptor_stop ();
  gns_resolver_cleanup ();
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics, GNUNET_NO);
    statistics = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != zone_publish_task)
  {
    GNUNET_SCHEDULER_cancel (zone_publish_task);
    zone_publish_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != namestore_iter)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    namestore_iter = NULL;
  }
  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
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
  zone_publish_task = GNUNET_SCHEDULER_NO_TASK;
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
 * Function used to put all records successively into the DHT.
 *
 * @param cls the closure (NULL)
 * @param key the public key of the authority (ours)
 * @param expiration lifetime of the namestore entry
 * @param name the name of the records
 * @param rd_count the number of records in data
 * @param rd the record data
 * @param signature the signature for the record data
 */
static void
put_gns_record (void *cls,
                const struct GNUNET_CRYPTO_EccPublicKey *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_EccSignature *signature)
{  
  struct GNSNameRecordBlock *nrb;
  struct GNUNET_CRYPTO_ShortHashCode zhash;
  struct GNUNET_HashCode dht_key;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  size_t namelen;
  struct GNUNET_TIME_Relative next_put_interval; 

  if (NULL == name)
  {
    /* we're done */
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
		  "No records in db.\n");
    }
    else
    {
      put_interval = GNUNET_TIME_relative_divide (zone_publish_time_window,
						  num_public_records);
    }
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
                              "Number of zone iterations", 1, GNUNET_NO);
    GNUNET_STATISTICS_set (statistics,
                           "Number of public records in DHT",
                           last_num_public_records,
                           GNUNET_NO);
    if (0 == num_public_records)
      zone_publish_task = GNUNET_SCHEDULER_add_delayed (put_interval,
                                                         &publish_zone_dht_start,
                                                         NULL);
    else
      zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start, NULL);
    return;
  }
  
  namelen = strlen (name) + 1;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"No records for name `%s'! Skipping.\n",
		name);
    zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_next,
                                                   NULL);
    return;
  }
  if (NULL == signature)
  {
    GNUNET_break (0);
    zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_next,
                                                   NULL);
    return;
  }
  
  /* TODO 2) AB: New publishing
   *
   * - Use new signature S_d
   * - Obtain new derived public key V = H(H(i,Q) * Q)
   * - Obtain HKDF(i,Q)
   * - Compute encrypte record block E with HKDF(i,Q) (rd, rd_count)
   * - Create block B = |V,E,S_d|
   * - Compute new DHT key H(V) in TODO 3)
   *
   * -> Put (H(V), B)
   */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Putting records for `%s' into the DHT\n", name); 
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (rd_count, rd); 
  nrb = GNUNET_malloc (rd_payload_length + namelen
		       + sizeof (struct GNSNameRecordBlock));
  nrb->signature = *signature;
  nrb->public_key = *key;
  nrb->rd_count = htonl (rd_count);
  memcpy (&nrb[1], name, namelen);
  nrb_data = (char *) &nrb[1];
  nrb_data += namelen;
  rd_payload_length += sizeof(struct GNSNameRecordBlock) + namelen;
  GNUNET_CRYPTO_short_hash (key,
			    sizeof (struct GNUNET_CRYPTO_EccPublicKey),
			    &zhash);
  if (-1 == GNUNET_NAMESTORE_records_serialize (rd_count,
                                                rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Records for name `%s' in zone %s too large to fit into DHT"),
		name,
		GNUNET_short_h2s (&zhash));
    GNUNET_free (nrb);
    zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_next,
                                                   NULL);
    return;
  }
  /* TODO AB: Here records are put in the DHT: modify dht_key to H(key) = H(H(name,zone) * zone) */
  GNUNET_GNS_get_key_for_record (name, &zhash, &dht_key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "putting %u records from zone %s for `%s' under key: %s with size %u and timeout %s\n",
	      rd_count,
	      GNUNET_short_h2s (&zhash),
	      name, 
	      GNUNET_h2s (&dht_key), 
	      (unsigned int) rd_payload_length,
	      GNUNET_STRINGS_relative_time_to_string (DHT_OPERATION_TIMEOUT, GNUNET_YES));
  
  GNUNET_STATISTICS_update (statistics,
                            "Record bytes put into DHT", 
			    rd_payload_length, GNUNET_NO);

  (void) GNUNET_DHT_put (dht_handle, &dht_key,
			 DHT_GNS_REPLICATION_LEVEL,
			 GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
			 GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
			 rd_payload_length,
			 (char*)nrb,
			 expiration,
			 DHT_OPERATION_TIMEOUT,
			 NULL,
			 NULL); 
  GNUNET_free (nrb);

  num_public_records++;  
  if ( (num_public_records > last_num_public_records)
       && (GNUNET_NO == first_zone_iteration) )
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


/**
 * Periodically iterate over our zone and store everything in dht
 *
 * @param cls NULL
 * @param tc task context
 */
static void
publish_zone_dht_start (void *cls, 
			const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  zone_publish_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Scheduling DHT zone update!\n");  
  /* start counting again */
  num_public_records = 0;
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (namestore_handle,
							  NULL, /* All zones */
							  GNUNET_NAMESTORE_RF_AUTHORITY,
							  GNUNET_NAMESTORE_RF_PRIVATE,
							  &put_gns_record,
							  NULL);
}


/* END DHT ZONE PROPAGATION */


/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rd_count the number of records
 * @param rd the record data
 */
static void
send_lookup_response (void* cls,
		      uint32_t rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientLookupHandle* clh = cls;
  struct GNUNET_GNS_ClientLookupResultMessage *rmsg;
  size_t len;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %d results\n",
              "LOOKUP_RESULT", rd_count);
  
  len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  rmsg = GNUNET_malloc (len + sizeof (struct GNUNET_GNS_ClientLookupResultMessage));
  
  rmsg->id = clh->request_id;
  rmsg->rd_count = htonl(rd_count);
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->header.size = 
    htons(len+sizeof(struct GNUNET_GNS_ClientLookupResultMessage));
  
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, len, (char*)&rmsg[1]);
  
  GNUNET_SERVER_notification_context_unicast (nc, clh->client,
                                (const struct GNUNET_MessageHeader *) rmsg,
                                GNUNET_NO);
  GNUNET_SERVER_receive_done (clh->client, GNUNET_OK);
  
  GNUNET_free(rmsg);
  GNUNET_free(clh->name);
  
  if (NULL != clh->shorten_key)
    GNUNET_CRYPTO_ecc_key_free (clh->shorten_key);
  GNUNET_free (clh);
  GNUNET_STATISTICS_update (statistics,
                            "Completed lookups", 1, GNUNET_NO);
  if (NULL != rd)
    GNUNET_STATISTICS_update (statistics,
                              "Records resolved", rd_count, GNUNET_NO);
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
	       struct GNUNET_SERVER_Client * client,
	       const struct GNUNET_MessageHeader * message)
{
  size_t namelen;
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  struct ClientLookupHandle *clh;
  char* nameptr = name;
  const char *utf_in;
  int only_cached;
  const struct GNUNET_CRYPTO_EccPrivateKey *key;
  uint16_t msg_size;
  const struct GNUNET_GNS_ClientLookupMessage *sh_msg;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", "LOOKUP");
  msg_size = ntohs(message->size);
  if (msg_size < sizeof (struct GNUNET_GNS_ClientLookupMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sh_msg = (const struct GNUNET_GNS_ClientLookupMessage *) message;
  GNUNET_SERVER_notification_context_add (nc, client);
  if (GNUNET_YES == ntohl (sh_msg->have_key))
  {
    key = &sh_msg->shorten_key;
  }
  else
  {
    key = NULL;
  }
  utf_in = (const char *) &sh_msg[1];
  if ('\0' != utf_in[msg_size - sizeof (struct GNUNET_GNS_ClientLookupMessage) - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }  
  GNUNET_STRINGS_utf8_tolower (utf_in, &nameptr);
  
  namelen = strlen (name) + 1;
  clh = GNUNET_malloc (sizeof (struct ClientLookupHandle));
  memset (clh, 0, sizeof (struct ClientLookupHandle));
  clh->client = client;
  clh->name = GNUNET_malloc (namelen);
  strcpy (clh->name, name);
  clh->request_id = sh_msg->id;
  clh->type = ntohl (sh_msg->type);
  if (NULL != key)
  {
    clh->shorten_key = GNUNET_new (struct GNUNET_CRYPTO_EccPrivateKey);
    *clh->shorten_key = *key;
  }
  only_cached = ntohl (sh_msg->only_cached);
  
  if (strlen (name) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: %s is too long", name);
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }

  if ((GNUNET_DNSPARSER_TYPE_A == clh->type) &&
      (GNUNET_OK != v4_enabled))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "LOOKUP: Query for A record but AF_INET not supported!");
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }
  
  if ((GNUNET_DNSPARSER_TYPE_AAAA == clh->type) &&
      (GNUNET_OK != v6_enabled))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for AAAA record but AF_INET6 not supported!");
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }
  
  if (GNUNET_NO == ntohl (sh_msg->have_zone))
    clh->zone = zone_hash;  /* Default zone */
  else
    clh->zone = sh_msg->zone;
  
  if (GNUNET_YES == auto_import_pkey)
  {
    gns_resolver_lookup_record (clh->zone, clh->zone, clh->type, clh->name,
                                clh->shorten_key,
                                default_lookup_timeout,
                                clh->only_cached,
                                &send_lookup_response, clh);  
  }
  else
  {
    gns_resolver_lookup_record (clh->zone, clh->zone, clh->type, name,
                                NULL,
                                default_lookup_timeout,
                                only_cached,
                                &send_lookup_response, clh);
  }
  GNUNET_STATISTICS_update (statistics,
                            "Record lookup attempts", 1, GNUNET_NO);
}


/**
 * Process GNS requests.
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
    { &handle_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_LOOKUP, 0},
    {NULL, NULL, 0, 0}
  };
  struct GNUNET_CRYPTO_EccPublicKey pkey;
  unsigned long long max_parallel_bg_queries = 0;
  int ignore_pending = GNUNET_NO;

  v6_enabled = GNUNET_NETWORK_test_pf (PF_INET6);
  v4_enabled = GNUNET_NETWORK_test_pf (PF_INET);

  namestore_handle = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to the namestore!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  
  auto_import_pkey = GNUNET_NO;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (c, "gns",
                                            "AUTO_IMPORT_PKEY"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Automatic PKEY import is enabled.\n");
    auto_import_pkey = GNUNET_YES;
  }
  put_interval = INITIAL_PUT_INTERVAL;
  zone_publish_time_window = DEFAULT_ZONE_PUBLISH_TIME_WINDOW;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_time (c, "gns",
					   "ZONE_PUBLISH_TIME_WINDOW",
					   &zone_publish_time_window))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Time window for zone iteration: %s\n",
		GNUNET_STRINGS_relative_time_to_string (zone_publish_time_window, GNUNET_YES));
  }
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (c, "gns",
                                            "MAX_PARALLEL_BACKGROUND_QUERIES",
                                            &max_parallel_bg_queries))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Number of allowed parallel background queries: %llu\n",
		max_parallel_bg_queries);
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (c, "gns",
                                            "AUTO_IMPORT_CONFIRMATION_REQ"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Auto import requires user confirmation\n");
    ignore_pending = GNUNET_YES;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_time (c, "gns",
					   "DEFAULT_LOOKUP_TIMEOUT",
					   &default_lookup_timeout))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Default lookup timeout: %s\n",
		GNUNET_STRINGS_relative_time_to_string (default_lookup_timeout,
							GNUNET_YES));
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
  
  if (GNUNET_SYSERR ==
      gns_resolver_init (namestore_handle, dht_handle, zone_hash, c,
			 max_parallel_bg_queries,
			 ignore_pending))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Unable to initialize resolver!\n"));
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (c, "gns", "HIJACK_DNS"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"DNS hijacking enabled. Connecting to DNS service.\n");

    if (GNUNET_SYSERR ==
	gns_interceptor_init (zone_hash, zone_key, c))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to enable the DNS interceptor!\n");
    }
  }
  
  /**
   * Schedule periodic put for our records We have roughly an hour for
   * all records;
   */
  first_zone_iteration = GNUNET_YES;
  zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start, NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  statistics = GNUNET_STATISTICS_create ("gns", c);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
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
