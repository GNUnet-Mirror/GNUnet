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
#include "block_gns.h"
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
 * Handle to a shorten operation from api
 */
struct ClientShortenHandle
{

  /**
   * List for all shorten requests
   */
  struct ClientShortenHandle *next;

  /**
   * List for all shorten requests
   */
  struct ClientShortenHandle *prev;

  /**
   * Handle to the requesting client
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Namestore lookup task
   */
  struct GNUNET_NAMESTORE_QueueEntry *namestore_task;

  /**
   * master zone
   */
  struct GNUNET_CRYPTO_ShortHashCode root_zone;

  /**
   * private zone
   */
  struct GNUNET_CRYPTO_ShortHashCode private_zone;
  
  /**
   * shorten zone
   */
  struct GNUNET_CRYPTO_ShortHashCode shorten_zone;
  
  /**
   * The request id
   */
  uint32_t request_id;

  /**
   * request type
   */
  enum GNUNET_GNS_RecordType type;

  /** 
   * name to shorten
   */
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * name of private zone (relative to root)
   */
  char private_zone_id[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  
  /**
   * name of shorten zone (relative to root)
   */
  char shorten_zone_id[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

};


/**
 * Handle to a get authority operation from api
 */
struct ClientGetAuthHandle
{
  /**
   * Handle to the requesting client 
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * name to lookup authority
   */
  char *name;

  /**
   * request id
   */
  uint32_t request_id;

};


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
  struct GNUNET_CRYPTO_RsaPrivateKey *shorten_key;

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
  enum GNUNET_GNS_RecordType type;
};


/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our zone's private key
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *zone_key;

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
 * List for shorten requests
 */
static struct ClientShortenHandle *csh_head;

/**
 * List for shorten requests
 */
static struct ClientShortenHandle *csh_tail;

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
             "Shutting down!");
  while (NULL != (csh_tmp = csh_head))
  {
    GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh_tmp);
    GNUNET_free (csh_tmp);
  }
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
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
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
                           put_interval.rel_value,
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
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
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
			 next_put_interval.rel_value,
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
 * Send shorten response back to client
 * 
 * @param cls the closure containing a client shorten handle
 * @param name the shortened name result or NULL if cannot be shortened
 */
static void
send_shorten_response (void* cls, const char* name)
{
  struct ClientShortenHandle *csh = cls;
  struct GNUNET_GNS_ClientShortenResultMessage *rmsg;
  size_t name_len;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message with %s\n",
              "SHORTEN_RESULT", name);
  if (NULL == name)
    name_len = 0;
  else
    name_len = strlen (name) + 1;
  GNUNET_STATISTICS_update (statistics,
                            "Name shorten results", 1, GNUNET_NO);

  rmsg = GNUNET_malloc (sizeof (struct GNUNET_GNS_ClientShortenResultMessage) +
			name_len);
  
  rmsg->id = csh->request_id;
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT);
  rmsg->header.size = 
    htons(sizeof(struct GNUNET_GNS_ClientShortenResultMessage) +
          name_len);
  memcpy (&rmsg[1], name, name_len);
  GNUNET_SERVER_notification_context_unicast (nc, csh->client,
					      &rmsg->header,
					      GNUNET_NO);
  if (NULL != csh->namestore_task)
    GNUNET_NAMESTORE_cancel (csh->namestore_task); 
  GNUNET_free (rmsg);
  GNUNET_free (csh);
}


/**
 * Lookup the zone infos and shorten name
 *
 * @param cls the client shorten handle
 * @param key key of the zone
 * @param expiration expiration of record
 * @param name name found or null if no result
 * @param rd_count number of records found
 * @param rd record data
 * @param signature
 *
 */
static void
process_shorten_in_private_zone_lookup (void *cls,
					const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
					struct GNUNET_TIME_Absolute expiration,
					const char *name,
					unsigned int rd_count,
					const struct GNUNET_NAMESTORE_RecordData *rd,
					const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ClientShortenHandle *csh = cls;
  struct GNUNET_CRYPTO_ShortHashCode *szone = &csh->shorten_zone;
  struct GNUNET_CRYPTO_ShortHashCode *pzone = &csh->private_zone;

  csh->namestore_task = NULL;
  if (0 == strcmp (csh->private_zone_id, ""))
    pzone = NULL;  
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No shorten zone in private zone!\n");
    strcpy (csh->shorten_zone_id, "");
    szone = NULL;
  }
  else
  {
    GNUNET_break (1 == rd_count);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shorten zone %s found in private zone %s\n",
                name, csh->private_zone_id);

    sprintf (csh->shorten_zone_id, "%s.%s", name, csh->private_zone_id);
  }
  GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh);
  gns_resolver_shorten_name (&csh->root_zone,
                             pzone,
                             szone,
                             csh->name,
                             csh->private_zone_id,
                             csh->shorten_zone_id,
                             &send_shorten_response, csh);

}


/**
 * Lookup the zone infos and shorten name
 *
 * @param cls the shorten handle
 * @param key key of the zone
 * @param expiration expiration of record
 * @param name name found or null if no result
 * @param rd_count number of records found
 * @param rd record data
 * @param signature
 *
 */
static void
process_shorten_in_root_zone_lookup (void *cls,
				     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
				     struct GNUNET_TIME_Absolute expiration,
				     const char *name,
				     unsigned int rd_count,
				     const struct GNUNET_NAMESTORE_RecordData *rd,
				     const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ClientShortenHandle *csh = cls;
  struct GNUNET_CRYPTO_ShortHashCode *szone = &csh->shorten_zone;
  struct GNUNET_CRYPTO_ShortHashCode *pzone = &csh->private_zone;
  
  csh->namestore_task = NULL;
  if (0 == strcmp (csh->private_zone_id, ""))
    pzone = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No shorten zone in zone and no private zone!\n");

    strcpy (csh->shorten_zone_id, "");
    GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh);
    szone = NULL;
    gns_resolver_shorten_name (&csh->root_zone,
                               pzone,
                               szone,
                               csh->name,
                               csh->private_zone_id,
                               csh->shorten_zone_id,
                               &send_shorten_response, csh);
    return;
  }
  GNUNET_break (rd_count == 1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Private zone %s found in root zone\n", name);
  strcpy (csh->private_zone_id, name);
  csh->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
						       pzone,
						       szone,
						       &process_shorten_in_private_zone_lookup,
						       csh);
}


/**
 * Lookup the zone infos and shorten name
 *
 * @param cls the shorten handle
 * @param key key of the zone
 * @param expiration expiration of record
 * @param name name found or null if no result
 * @param rd_count number of records found
 * @param rd record data
 * @param signature
 */
static void
process_private_in_root_zone_lookup (void *cls,
				     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
				     struct GNUNET_TIME_Absolute expiration,
				     const char *name,
				     unsigned int rd_count,
				     const struct GNUNET_NAMESTORE_RecordData *rd,
				     const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ClientShortenHandle *csh = cls;

  csh->namestore_task = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No private zone in root zone\n");
    strcpy (csh->private_zone_id, "");
    csh->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
							 &csh->root_zone,
							 &csh->shorten_zone,
							 &process_shorten_in_root_zone_lookup,
							 csh);
    return;
  }
  GNUNET_break (1 == rd_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Private zone `%s' found in root zone\n", 
	      name);
  strcpy (csh->private_zone_id, name);
  csh->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
						       &csh->private_zone,
						       &csh->shorten_zone,
						       &process_shorten_in_private_zone_lookup,
						       csh);
}


/**
 * Handle a shorten message from the api
 *
 * @param cls the closure (unused)
 * @param client the client
 * @param message the message
 */
static void 
handle_shorten (void *cls,
		struct GNUNET_SERVER_Client * client,
		const struct GNUNET_MessageHeader * message)
{
  struct ClientShortenHandle *csh;
  const char *utf_in;
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  char* nameptr = name;
  uint16_t msg_size;
  const struct GNUNET_GNS_ClientShortenMessage *sh_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n", "SHORTEN");
  msg_size = ntohs (message->size);
  if (msg_size < sizeof (struct GNUNET_GNS_ClientShortenMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sh_msg = (const struct GNUNET_GNS_ClientShortenMessage *) message;
  utf_in = (const char *) &sh_msg[1];
  if ('\0' != utf_in[msg_size - sizeof (struct GNUNET_GNS_ClientShortenMessage) - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  csh = GNUNET_malloc(sizeof (struct ClientShortenHandle));
  csh->client = client;
  csh->request_id = sh_msg->id;
  GNUNET_CONTAINER_DLL_insert (csh_head, csh_tail, csh); 
  GNUNET_STRINGS_utf8_tolower (utf_in, &nameptr);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	     "SHORTEN: Converted `%s' to `%s'\n", 
	     utf_in, 
	     nameptr);
  GNUNET_SERVER_notification_context_add (nc, client);  
  if (strlen (name) < strlen (GNUNET_GNS_TLD)) 
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "SHORTEN: %s is too short\n", name);
    GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh);
    send_shorten_response(csh, name);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (strlen (name) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) 
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "SHORTEN: %s is too long\n", name);
    GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh);
    send_shorten_response(csh, name);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }  
  if ( (! is_gads_tld (name)) && 
       (! is_zkey_tld (name)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is not our domain. Returning\n", name);
    GNUNET_CONTAINER_DLL_remove (csh_head, csh_tail, csh);
    send_shorten_response (csh, name);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  csh->shorten_zone = sh_msg->shorten_zone;
  csh->private_zone = sh_msg->private_zone;
  strcpy (csh->name, name);  
  if (1 == ntohl(sh_msg->use_default_zone))
    csh->root_zone = zone_hash; //Default zone
  else
    csh->root_zone = sh_msg->zone;
  csh->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
						       &csh->root_zone,
						       &csh->private_zone,
						       &process_private_in_root_zone_lookup,
						       csh);
  GNUNET_STATISTICS_update (statistics,
                            "Name shorten attempts", 1, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send get authority response back to client
 * 
 * @param cls the closure containing a client get auth handle
 * @param name the name of the authority, or NULL on error
 */
static void 
send_get_auth_response (void *cls, 
			const char* name)
{
  struct ClientGetAuthHandle *cah = cls;
  struct GNUNET_GNS_ClientGetAuthResultMessage *rmsg;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message with `%s'\n",
              "GET_AUTH_RESULT", name);
  if (NULL != name)
  {
    GNUNET_STATISTICS_update (statistics,
                              "Authorities resolved", 1, GNUNET_NO);
  }  
  if (NULL == name)  
    name = "";  
  rmsg = GNUNET_malloc (sizeof (struct GNUNET_GNS_ClientGetAuthResultMessage)
			+ strlen (name) + 1);
  
  rmsg->id = cah->request_id;
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_GET_AUTH_RESULT);
  rmsg->header.size = 
    htons(sizeof(struct GNUNET_GNS_ClientGetAuthResultMessage) +
          strlen (name) + 1);
  strcpy ((char*)&rmsg[1], name);

  GNUNET_SERVER_notification_context_unicast (nc, cah->client,
					      &rmsg->header,
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (cah->client, GNUNET_OK);
  GNUNET_free(rmsg);
  GNUNET_free_non_null(cah->name);
  GNUNET_free(cah);  
}


/**
 * Handle a get authority message from the api
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void 
handle_get_authority (void *cls,
		      struct GNUNET_SERVER_Client * client,
		      const struct GNUNET_MessageHeader * message)
{
  struct ClientGetAuthHandle *cah;
  const char *utf_in;
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  char* nameptr = name;
  uint16_t msg_size;
  const struct GNUNET_GNS_ClientGetAuthMessage *sh_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", "GET_AUTH");
  msg_size = ntohs(message->size);
  if (msg_size < sizeof (struct GNUNET_GNS_ClientGetAuthMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_notification_context_add (nc, client);
  sh_msg = (const struct GNUNET_GNS_ClientGetAuthMessage *) message;
  utf_in = (const char *) &sh_msg[1];
  if ('\0' != utf_in[msg_size - sizeof (struct GNUNET_GNS_ClientGetAuthMessage) - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }  
  GNUNET_STRINGS_utf8_tolower(utf_in, &nameptr);
  cah = GNUNET_malloc(sizeof(struct ClientGetAuthHandle));
  cah->client = client;
  cah->request_id = sh_msg->id;
  if (strlen (name) < strlen(GNUNET_GNS_TLD))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GET_AUTH: `%s' is too short. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }  
  if (strlen (name) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) 
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GET_AUTH: `%s' is too long", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }  
  if (0 != strcmp (name + strlen (name) - strlen (GNUNET_GNS_TLD),
		   GNUNET_GNS_TLD))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GET_AUTH: %s is not our domain. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response (cah, name);
    return;
  }

  if (0 == strcmp (name, GNUNET_GNS_TLD))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GET_AUTH: %s is us. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }
  
  cah->name = GNUNET_malloc (strlen (name)
                            - strlen (GNUNET_GNS_TLD) + 1);
  memcpy (cah->name, name,
	  strlen (name) - strlen (GNUNET_GNS_TLD));

  /* Start delegation resolution in our namestore */
  gns_resolver_get_authority (zone_hash, zone_hash, name,
                              &send_get_auth_response, cah);
  GNUNET_STATISTICS_update (statistics,
                            "Authority lookup attempts", 1, GNUNET_NO);
}


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
    GNUNET_CRYPTO_rsa_key_free (clh->shorten_key);
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
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *pkey;
  char* tmp_pkey;
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
    pkey = (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *) &sh_msg[1];
    tmp_pkey = (char*) &sh_msg[1];
    key = GNUNET_CRYPTO_rsa_decode_key (tmp_pkey, ntohs (pkey->len));
    GNUNET_STRINGS_utf8_tolower (&tmp_pkey[ntohs (pkey->len)], &nameptr);
  }
  else
  {
    key = NULL;
    utf_in = (const char *) &sh_msg[1];
    if ('\0' != utf_in[msg_size - sizeof (struct GNUNET_GNS_ClientLookupMessage) - 1])
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }  
    GNUNET_STRINGS_utf8_tolower (utf_in, &nameptr);
  }
  
  namelen = strlen (name) + 1;
  clh = GNUNET_malloc (sizeof (struct ClientLookupHandle));
  memset (clh, 0, sizeof (struct ClientLookupHandle));
  clh->client = client;
  clh->name = GNUNET_malloc (namelen);
  strcpy (clh->name, name);
  clh->request_id = sh_msg->id;
  clh->type = ntohl (sh_msg->type);
  clh->shorten_key = key;

  only_cached = ntohl (sh_msg->only_cached);
  
  if (strlen (name) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: %s is too long", name);
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }

  if ((GNUNET_GNS_RECORD_A == clh->type) &&
      (GNUNET_OK != v4_enabled))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "LOOKUP: Query for A record but AF_INET not supported!");
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }
  
  if ((GNUNET_GNS_RECORD_AAAA == clh->type) &&
      (GNUNET_OK != v6_enabled))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for AAAA record but AF_INET6 not supported!");
    clh->name = NULL;
    send_lookup_response (clh, 0, NULL);
    return;
  }
  
  if (1 == ntohl (sh_msg->use_default_zone))
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
    {&handle_shorten, NULL, GNUNET_MESSAGE_TYPE_GNS_SHORTEN, 0},
    {&handle_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_LOOKUP, 0},
    {&handle_get_authority, NULL, GNUNET_MESSAGE_TYPE_GNS_GET_AUTH, 0}
  };
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  unsigned long long max_parallel_bg_queries = 0;
  int ignore_pending = GNUNET_NO;

  v6_enabled = GNUNET_NETWORK_test_pf (PF_INET6);
  v4_enabled = GNUNET_NETWORK_test_pf (PF_INET);

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "gns",
							    "ZONEKEY", &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No private key for root zone specified!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Using keyfile %s for root zone.\n", keyfile);

  zone_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (zone_key, &pkey);
  GNUNET_CRYPTO_short_hash(&pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_free(keyfile);
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
   * Schedule periodic put
   * for our records
   * We have roughly an hour for all records;
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
