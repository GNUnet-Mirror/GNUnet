/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_signatures.h"
#include "namestore.h"

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


/**
 * A namestore client
 */
struct NamestoreClient;


/**
 * A namestore iteration operation.
 */
struct ZoneIteration
{
  /**
   * Next element in the DLL
   */
  struct ZoneIteration *next;

  /**
   * Previous element in the DLL
   */
  struct ZoneIteration *prev;

  /**
   * Namestore client which intiated this zone iteration
   */
  struct NamestoreClient *client;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_EccPrivateKey zone;

  /**
   * The operation id fot the zone iteration in the response for the client
   */
  uint32_t request_id;

  /**
   * Offset of the zone iteration used to address next result of the zone
   * iteration in the store
   *
   * Initialy set to 0 in handle_iteration_start
   * Incremented with by every call to handle_iteration_next
   */
  uint32_t offset;

};


/**
 * A namestore client
 */
struct NamestoreClient
{
  /**
   * Next element in the DLL
   */
  struct NamestoreClient *next;

  /**
   * Previous element in the DLL
   */
  struct NamestoreClient *prev;

  /**
   * The client
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Head of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct ZoneIteration *op_head;

  /**
   * Tail of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct ZoneIteration *op_tail;
};


/**
 * A namestore monitor.
 */
struct ZoneMonitor
{
  /**
   * Next element in the DLL
   */
  struct ZoneMonitor *next;

  /**
   * Previous element in the DLL
   */
  struct ZoneMonitor *prev;

  /**
   * Namestore client which intiated this zone monitor
   */
  struct NamestoreClient *nc;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_EccPrivateKey zone;

  /**
   * The operation id fot the zone iteration in the response for the client
   */
  uint32_t request_id;

  /**
   * Task active during initial iteration.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Offset of the zone iteration used to address next result of the zone
   * iteration in the store
   *
   * Initialy set to 0.
   * Incremented with by every call to #handle_iteration_next
   */
  uint32_t offset;

};


/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
 * Database handle
 */
static struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

/**
 * Name of the database plugin
 */
static char *db_lib_name;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *snc;

/**
 * Head of the Client DLL
 */
static struct NamestoreClient *client_head;

/**
 * Tail of the Client DLL
 */
static struct NamestoreClient *client_tail;

/**
 * First active zone monitor.
 */
static struct ZoneMonitor *monitor_head;

/**
 * Last active zone monitor.
 */
static struct ZoneMonitor *monitor_tail;

/**
 * Notification context shared by all monitors.
 */
static struct GNUNET_SERVER_NotificationContext *monitor_nc;



/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ZoneIteration *no;
  struct NamestoreClient *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stopping namestore service\n");
  if (NULL != snc)
  {
    GNUNET_SERVER_notification_context_destroy (snc);
    snc = NULL;
  }
  while (NULL != (nc = client_head))
  {
    while (NULL != (no = nc->op_head))
    {
      GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
      GNUNET_free (no);
    }
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
    GNUNET_SERVER_client_set_user_context (nc->client, NULL);
    GNUNET_free (nc);
  }
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
  if (NULL != monitor_nc)
  {
    GNUNET_SERVER_notification_context_destroy (monitor_nc);
    monitor_nc = NULL;
  }
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls, 
				struct GNUNET_SERVER_Client *client)
{
  struct ZoneIteration *no;
  struct NamestoreClient *nc;
  struct ZoneMonitor *zm;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Client %p disconnected\n", 
	      client);
  if (NULL == (nc = GNUNET_SERVER_client_get_user_context (client, struct NamestoreClient)))
    return;
  while (NULL != (no = nc->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
  }
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
  for (zm = monitor_head; NULL != zm; zm = zm->next)
  {
    if (client == zm->nc->client)
    {
      GNUNET_CONTAINER_DLL_remove (monitor_head,
				   monitor_tail,
				   zm);
      if (GNUNET_SCHEDULER_NO_TASK != zm->task)
      {
	GNUNET_SCHEDULER_cancel (zm->task);
	zm->task = GNUNET_SCHEDULER_NO_TASK;
      }
      GNUNET_free (zm);
      break;
    }
  }
}


/**
 * Add a client to our list of active clients, if it is not yet
 * in there.
 *
 * @param client client to add
 * @return internal namestore client structure for this client
 */
static struct NamestoreClient *
client_lookup (struct GNUNET_SERVER_Client *client)
{
  struct NamestoreClient *nc;

  nc = GNUNET_SERVER_client_get_user_context (client, struct NamestoreClient);
  if (NULL != nc)
    return nc;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Client %p connected\n",
	      client);
  nc = GNUNET_new (struct NamestoreClient);
  nc->client = client;
  GNUNET_SERVER_notification_context_add (snc, client);
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, nc);
  GNUNET_SERVER_client_set_user_context (client, nc);
  return nc;
}


/**
 * Context for name lookups passed from #handle_lookup_block to
 * #handle_lookup_block_it as closure
 */
struct LookupBlockContext
{
  /**
   * The client to send the response to
   */
  struct NamestoreClient *nc;

  /**
   * Operation id for the name lookup
   */
  uint32_t request_id;

};


/**
 * A #GNUNET_NAMESTORE_BlockCallback for name lookups in #handle_lookup_block
 *
 * @param cls a `struct LookupNameContext *` with information about the request
 * @param block the block
 */
static void
handle_lookup_block_it (void *cls,
			const struct GNUNET_NAMESTORE_Block *block)
{
  struct LookupBlockContext *lnc = cls;
  struct LookupBlockResponseMessage *r;
  size_t esize;

  esize = ntohl (block->purpose.size)
    - sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) 
    - sizeof (struct GNUNET_TIME_AbsoluteNBO);
  r = GNUNET_malloc (sizeof (struct LookupBlockResponseMessage) + esize);
  r->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_BLOCK_RESPONSE);
  r->gns_header.header.size = htons (sizeof (struct LookupBlockResponseMessage) + esize);
  r->gns_header.r_id = htonl (lnc->request_id);
  r->expire = block->expiration_time;
  r->signature = block->signature;
  r->derived_key = block->derived_key;  
  memcpy (&r[1], &block[1], esize);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", 
	      "NAMESTORE_LOOKUP_BLOCK_RESPONSE");
  GNUNET_SERVER_notification_context_unicast (snc, 
					      lnc->nc->client, 
					      &r->gns_header.header, 
					      GNUNET_NO);
  GNUNET_free (r);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_BLOCK message
 *
 * @param cls unused
 * @param client client sending the message
 * @param message message of type 'struct LookupNameMessage'
 */
static void
handle_lookup_block (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct LookupBlockMessage *ln_msg;
  struct LookupBlockContext lnc;
  struct NamestoreClient *nc;
  struct LookupBlockResponseMessage zir_end;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", 
	      "NAMESTORE_LOOKUP_BLOCK");
  nc = client_lookup(client);
  ln_msg = (const struct LookupBlockMessage *) message;
  lnc.request_id = ntohl (ln_msg->gns_header.r_id);
  lnc.nc = nc;
  if (GNUNET_SYSERR ==
      (ret = GSN_database->lookup_block (GSN_database->cls, 
					 &ln_msg->query,
					 &handle_lookup_block_it, &lnc)))
  {
    /* internal error (in database plugin); might be best to just hang up on
       plugin rather than to signal that there are 'no' results, which 
       might also be false... */
    GNUNET_break (0); 
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }  
  if (0 == ret)
  {
    /* no records match at all, generate empty response */
    memset (&zir_end, 0, sizeof (zir_end));
    zir_end.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_BLOCK_RESPONSE);
    zir_end.gns_header.header.size = htons (sizeof (struct LookupBlockResponseMessage));
    zir_end.gns_header.r_id = ln_msg->gns_header.r_id;
    GNUNET_SERVER_notification_context_unicast (snc, 
						client, 
						&zir_end.gns_header.header, 
						GNUNET_NO);

  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_BLOCK_CACHE message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct BlockCacheMessage'
 */
static void
handle_block_cache (void *cls,
		     struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *message)
{
  struct NamestoreClient *nc;
  const struct BlockCacheMessage *rp_msg;  
  struct BlockCacheResponseMessage rpr_msg;
  struct GNUNET_NAMESTORE_Block *block;
  size_t esize;
  int res;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "NAMESTORE_BLOCK_CACHE");
  nc = client_lookup (client);
  if (ntohs (message->size) < sizeof (struct BlockCacheMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rp_msg = (const struct BlockCacheMessage *) message;
  esize = ntohs (rp_msg->gns_header.header.size) - sizeof (struct BlockCacheMessage);

  block = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Block) + esize);
  block->signature = rp_msg->signature;
  block->derived_key = rp_msg->derived_key;
  block->purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
			       esize);
  block->expiration_time = rp_msg->expire;
  memcpy (&block[1], &rp_msg[1], esize);
  res = GSN_database->cache_block (GSN_database->cls,
				   block);
  GNUNET_free (block);

  rpr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_BLOCK_CACHE_RESPONSE);
  rpr_msg.gns_header.header.size = htons (sizeof (struct BlockCacheResponseMessage));
  rpr_msg.gns_header.r_id = rp_msg->gns_header.r_id;
  rpr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, 
					      nc->client, 
					      &rpr_msg.gns_header.header, 
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Generate a 'struct LookupNameResponseMessage' and send it to the
 * given client using the given notification context.
 *
 * @param nc notification context to use
 * @param client client to unicast to
 * @param request_id request ID to use
 * @param zone_key zone key of the zone
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd array of records
 */
static void
send_lookup_response (struct GNUNET_SERVER_NotificationContext *nc,			
		      struct GNUNET_SERVER_Client *client,
		      uint32_t request_id,
		      const struct GNUNET_CRYPTO_EccPrivateKey *zone_key,
		      const char *name,
		      unsigned int rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordResultMessage *zir_msg;
  size_t name_len;
  size_t rd_ser_len;
  size_t msg_size;
  char *name_tmp;
  char *rd_ser;

  name_len = strlen (name) + 1;
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);  
  msg_size = sizeof (struct RecordResultMessage) + name_len + rd_ser_len;

  zir_msg = GNUNET_malloc (msg_size);
  zir_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT);
  zir_msg->gns_header.header.size = htons (msg_size);
  zir_msg->gns_header.r_id = htonl (request_id);
  zir_msg->name_len = htons (name_len);
  zir_msg->rd_count = htons (rd_count);
  zir_msg->rd_len = htons (rd_ser_len);
  zir_msg->private_key = *zone_key;
  name_tmp = (char *) &zir_msg[1];
  memcpy (name_tmp, name, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message with size %u\n", 
	      "RECORD_RESULT",
	      msg_size);
  GNUNET_SERVER_notification_context_unicast (nc,
					      client, 
					      &zir_msg->gns_header.header,
					      GNUNET_NO);
  GNUNET_free (zir_msg);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE message
 *
 * @param cls unused
 * @param client client sending the message
 * @param message message of type 'struct RecordCreateMessage'
 */
static void
handle_record_store (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct NamestoreClient *nc;
  const struct RecordStoreMessage *rp_msg;
  struct RecordStoreResponseMessage rcr_msg;
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  size_t rd_ser_len;
  uint32_t rid;
  const char *name_tmp;
  char *conv_name;
  const char *rd_ser;
  unsigned int rd_count;
  int res;
  struct GNUNET_CRYPTO_EccPublicSignKey pubkey;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", 
	      "NAMESTORE_RECORD_STORE");
  if (ntohs (message->size) < sizeof (struct RecordStoreMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  nc = client_lookup (client);
  rp_msg = (const struct RecordStoreMessage *) message;
  rid = ntohl (rp_msg->gns_header.r_id);
  name_len = ntohs (rp_msg->name_len);
  msg_size = ntohs (message->size);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs (rp_msg->rd_len);
  GNUNET_break (0 == ntohs (rp_msg->reserved));
  msg_size_exp = sizeof (struct RecordStoreMessage) + name_len + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if ((0 == name_len) || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  name_tmp = (const char *) &rp_msg[1];
  rd_ser = &name_tmp[name_len];
  if ('\0' != name_tmp[name_len -1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];

	if (GNUNET_OK !=
			GNUNET_NAMESTORE_records_deserialize (rd_ser_len, rd_ser, rd_count, rd))
	{
		GNUNET_break (0);
		GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
		return;
	}

    /* Extracting and converting private key */
    GNUNET_CRYPTO_ecc_key_get_public_for_signature (&rp_msg->private_key,
				      &pubkey);
    conv_name = GNUNET_NAMESTORE_normalize_string (name_tmp);
    if (NULL == conv_name)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n", name_tmp);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Creating %u records for name `%s' in zone `%s'\n",
		(unsigned int) rd_count,
		conv_name,
		GNUNET_NAMESTORE_z2s (&pubkey));

    if ((rd_count == 0) && (GNUNET_NO == GSN_database->iterate_records (GSN_database->cls, &rp_msg->private_key, 0, NULL, 0)))
    {
    	/* This name does not exist, so cannot be removed */
    	res = GNUNET_NO;
    }
    else
    {
    res = GSN_database->store_records (GSN_database->cls,
				       &rp_msg->private_key,
				       conv_name,				       
				       rd_count, rd);    
    if (GNUNET_OK == res)
    {
      struct ZoneMonitor *zm;
      struct GNUNET_NAMESTORE_Block *block;

      if (0 == rd_count)
      		block = GNUNET_NAMESTORE_block_create (&rp_msg->private_key,
					       GNUNET_TIME_UNIT_ZERO_ABS,
					       conv_name,
					       rd, rd_count);
      else
      		block = GNUNET_NAMESTORE_block_create (&rp_msg->private_key,
					       GNUNET_TIME_UNIT_FOREVER_ABS,
					       conv_name,
					       rd, rd_count);
      if (GNUNET_OK !=
      		GSN_database->cache_block (GSN_database->cls,
				     block))
      {
      	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
      			_("Failed to cache encrypted block of my own zone!\n"));
      	res = GNUNET_SYSERR;
      }
      GNUNET_free (block);
      
      for (zm = monitor_head; NULL != zm; zm = zm->next)    
      		if (0 == memcmp (&rp_msg->private_key, &zm->zone,
      				sizeof (struct GNUNET_CRYPTO_EccPrivateKey)))
      			send_lookup_response (monitor_nc,
								zm->nc->client,
								zm->request_id,
								&rp_msg->private_key,
								conv_name,
								rd_count, rd);
    }    
    GNUNET_free (conv_name);
  }
  
  /* Send response */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", 
	      "RECORD_STORE_RESPONSE");
  rcr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE);
  rcr_msg.gns_header.header.size = htons (sizeof (struct RecordStoreResponseMessage));
  rcr_msg.gns_header.r_id = htonl (rid);
  rcr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client,
					      &rcr_msg.gns_header.header,
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Context for record remove operations passed from #handle_zone_to_name to
 * #handle_zone_to_name_it as closure
 */
struct ZoneToNameCtx
{
  /**
   * Namestore client
   */
  struct NamestoreClient *nc;

  /**
   * Request id (to be used in the response to the client).
   */
  uint32_t rid;

  /**
   * Set to #GNUNET_OK on success, #GNUNET_SYSERR on error.  Note that
   * not finding a name for the zone still counts as a 'success' here,
   * as this field is about the success of executing the IPC protocol.
   */
  int success;
};


/**
 * Zone to name iterator
 *
 * @param cls struct ZoneToNameCtx *
 * @param zone_key the zone key
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd record data
 */
static void
handle_zone_to_name_it (void *cls,
			const struct GNUNET_CRYPTO_EccPrivateKey *zone_key,
			const char *name,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ZoneToNameCtx *ztn_ctx = cls;
  struct ZoneToNameResponseMessage *ztnr_msg;
  int16_t res;
  size_t name_len;
  size_t rd_ser_len;
  size_t msg_size;
  char *name_tmp;
  char *rd_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Found result for zone-to-name lookup: `%s'\n", 
	      name);
  res = GNUNET_YES;
  name_len = (NULL == name) ? 0 : strlen (name) + 1;
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  msg_size = sizeof (struct ZoneToNameResponseMessage) + name_len + rd_ser_len;
  if (msg_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    ztn_ctx->success = GNUNET_SYSERR;
    return;
  }
  ztnr_msg = GNUNET_malloc (msg_size);
  ztnr_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
  ztnr_msg->gns_header.header.size = htons (msg_size);
  ztnr_msg->gns_header.r_id = htonl (ztn_ctx->rid);
  ztnr_msg->res = htons (res);
  ztnr_msg->rd_len = htons (rd_ser_len);
  ztnr_msg->rd_count = htons (rd_count);
  ztnr_msg->name_len = htons (name_len);
  ztnr_msg->zone = *zone_key;
  name_tmp = (char *) &ztnr_msg[1];
  if (NULL != name)
    memcpy (name_tmp, name, name_len);
  rd_tmp = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_tmp);
  ztn_ctx->success = GNUNET_OK;
  GNUNET_SERVER_notification_context_unicast (snc, ztn_ctx->nc->client,
					      &ztnr_msg->gns_header.header,
					      GNUNET_NO);
  GNUNET_free (ztnr_msg);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME message
 *
 * @param cls unused
 * @param client client sending the message
 * @param message message of type 'struct ZoneToNameMessage'
 */
static void
handle_zone_to_name (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  struct NamestoreClient *nc;
  const struct ZoneToNameMessage *ztn_msg;
  struct ZoneToNameCtx ztn_ctx;
  struct ZoneToNameResponseMessage ztnr_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "ZONE_TO_NAME");
  ztn_msg = (const struct ZoneToNameMessage *) message;
  nc = client_lookup (client);
  ztn_ctx.rid = ntohl (ztn_msg->gns_header.r_id);
  ztn_ctx.nc = nc;
  ztn_ctx.success = GNUNET_NO;
  if (GNUNET_SYSERR ==
      GSN_database->zone_to_name (GSN_database->cls, 
				  &ztn_msg->zone,
				  &ztn_msg->value_zone,
				  &handle_zone_to_name_it, &ztn_ctx))
  {
    /* internal error, hang up instead of signalling something
       that might be wrong */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;    
  }
  if (GNUNET_NO == ztn_ctx.success)
  {
    /* no result found, send empty response */
    memset (&ztnr_msg, 0, sizeof (ztnr_msg));
    ztnr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
    ztnr_msg.gns_header.header.size = htons (sizeof (ztnr_msg));
    ztnr_msg.gns_header.r_id = ztn_msg->gns_header.r_id;
    ztnr_msg.res = htons (GNUNET_NO);
    GNUNET_SERVER_notification_context_unicast (snc,
						client,
						&ztnr_msg.gns_header.header,
						GNUNET_NO);
  }
  GNUNET_SERVER_receive_done (client, ztn_ctx.success);
}


/**
 * Zone iteration processor result
 */
enum ZoneIterationResult
{
  /**
   * Iteration start.
   */
  IT_START = 0,

  /**
   * Found records,
   * Continue to iterate with next iteration_next call
   */
  IT_SUCCESS_MORE_AVAILABLE = 1,

  /**
   * Iteration complete
   */
  IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE = 2
};


/**
 * Context for record remove operations passed from
 * #run_zone_iteration_round to #zone_iteraterate_proc as closure
 */
struct ZoneIterationProcResult
{
  /**
   * The zone iteration handle
   */
  struct ZoneIteration *zi;

  /**
   * Iteration result: iteration done?
   * #IT_SUCCESS_MORE_AVAILABLE:  if there may be more results overall but
   * we got one for now and have sent it to the client
   * #IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE: if there are no further results,
   * #IT_START: if we are still trying to find a result.
   */
  int res_iteration_finished;

};


/**
 * Process results for zone iteration from database
 *
 * @param cls struct ZoneIterationProcResult *proc
 * @param zone_key the zone key
 * @param name name
 * @param rd_count number of records for this name
 * @param rd record data
 */
static void
zone_iteraterate_proc (void *cls,
                       const struct GNUNET_CRYPTO_EccPrivateKey *zone_key,
                       const char *name,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ZoneIterationProcResult *proc = cls;

  if ((NULL == zone_key) && (NULL == name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Iteration done\n");
    proc->res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
    return;
  }
  if ((NULL == zone_key) || (NULL == name)) 
  {
    /* what is this!? should never happen */
    proc->res_iteration_finished = IT_START;
    GNUNET_break (0);
    return;    
  }
  proc->res_iteration_finished = IT_SUCCESS_MORE_AVAILABLE;
  send_lookup_response (snc,
			proc->zi->client->client,
			proc->zi->request_id,
			zone_key,
			name,
			rd_count,
			rd);
}


/**
 * Perform the next round of the zone iteration.
 *
 * @param zi zone iterator to process
 */
static void
run_zone_iteration_round (struct ZoneIteration *zi)
{
  static struct GNUNET_CRYPTO_EccPrivateKey zero;
  struct ZoneIterationProcResult proc;
  struct RecordResultMessage rrm;
  int ret;

  memset (&proc, 0, sizeof (proc));
  proc.zi = zi;
  proc.res_iteration_finished = IT_START;
  while (IT_START == proc.res_iteration_finished)
  {
    if (GNUNET_SYSERR ==
	(ret = GSN_database->iterate_records (GSN_database->cls, 
					      (0 == memcmp (&zi->zone, &zero, sizeof (zero))) 
					      ? NULL 
					      : &zi->zone,
					      zi->offset, 
					      &zone_iteraterate_proc, &proc)))
    {
      GNUNET_break (0);
      break;
    }
    if (GNUNET_NO == ret)
      proc.res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
    zi->offset++;
  }
  if (IT_SUCCESS_MORE_AVAILABLE == proc.res_iteration_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "More results available\n");
    return; /* more results later */
  }
  /* send empty response to indicate end of list */
  memset (&rrm, 0, sizeof (rrm));
  rrm.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT);
  rrm.gns_header.header.size = htons (sizeof (rrm));
  rrm.gns_header.r_id = htonl (zi->request_id);
  GNUNET_SERVER_notification_context_unicast (snc,
					      zi->client->client, 
					      &rrm.gns_header.header,
					      GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (zi->client->op_head, 
			       zi->client->op_tail,
			       zi);
  GNUNET_free (zi);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START message
 *
 * @param cls unused
 * @param client the client sending the message
 * @param message message of type 'struct ZoneIterationStartMessage'
 */
static void
handle_iteration_start (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct ZoneIterationStartMessage *zis_msg;
  struct NamestoreClient *nc;
  struct ZoneIteration *zi;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_START");
  if (NULL == (nc = client_lookup (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationStartMessage *) message;
  zi = GNUNET_new (struct ZoneIteration);
  zi->request_id = ntohl (zis_msg->gns_header.r_id);
  zi->offset = 0;
  zi->client = nc;
  zi->zone = zis_msg->zone;
  GNUNET_CONTAINER_DLL_insert (nc->op_head, nc->op_tail, zi);
  run_zone_iteration_round (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneIterationStopMessage'
 */
static void
handle_iteration_stop (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct NamestoreClient *nc;
  struct ZoneIteration *zi;
  const struct ZoneIterationStopMessage *zis_msg;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "ZONE_ITERATION_STOP");
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationStopMessage *) message;
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, zi);
  GNUNET_free (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneIterationNextMessage'
 */
static void
handle_iteration_next (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct NamestoreClient *nc;
  struct ZoneIteration *zi;
  const struct ZoneIterationNextMessage *zis_msg;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_NEXT");
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationNextMessage *) message;
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  run_zone_iteration_round (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send 'sync' message to zone monitor, we're now in sync.
 *
 * @param zm monitor that is now in sync
 */ 
static void
monitor_sync (struct ZoneMonitor *zm)
{
  struct GNUNET_MessageHeader sync;

  sync.size = htons (sizeof (struct GNUNET_MessageHeader));
  sync.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC);
  GNUNET_SERVER_notification_context_unicast (monitor_nc,
					      zm->nc->client,
					      &sync,
					      GNUNET_NO);
}


/**
 * Obtain the next datum during the zone monitor's zone intiial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 * @param tc scheduler context
 */
static void
monitor_next (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * A #GNUNET_NAMESTORE_RecordIterator for monitors.
 *
 * @param cls a 'struct ZoneMonitor *' with information about the monitor
 * @param zone_key zone key of the zone
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd array of records
 */
static void
monitor_iterate_cb (void *cls,
		    const struct GNUNET_CRYPTO_EccPrivateKey *zone_key,
		    const char *name,
		    unsigned int rd_count,
		    const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ZoneMonitor *zm = cls;

  if (NULL == name)
  {
    /* finished with iteration */
    monitor_sync (zm);
    return;
  }
  send_lookup_response (monitor_nc,
			zm->nc->client,
			zm->request_id,
			zone_key,
			name,
			rd_count,
			rd);
  zm->task = GNUNET_SCHEDULER_add_now (&monitor_next, zm);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneMonitorStartMessage'
 */
static void
handle_monitor_start (void *cls,
		      struct GNUNET_SERVER_Client *client,
		      const struct GNUNET_MessageHeader *message)
{
  const struct ZoneMonitorStartMessage *zis_msg;
  struct ZoneMonitor *zm;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "ZONE_MONITOR_START");
  zis_msg = (const struct ZoneMonitorStartMessage *) message;
  zm = GNUNET_new (struct ZoneMonitor);
  zm->request_id = ntohl (zis_msg->gns_header.r_id);
  zm->offset = 0;
  zm->nc = client_lookup (client);
  zm->zone = zis_msg->zone;
  GNUNET_CONTAINER_DLL_insert (monitor_head, monitor_tail, zm);
  GNUNET_SERVER_client_mark_monitor (client);
  GNUNET_SERVER_disable_receive_done_warning (client);
  GNUNET_SERVER_notification_context_add (monitor_nc,
					  client);
  zm->task = GNUNET_SCHEDULER_add_now (&monitor_next, zm);  
}


/**
 * Obtain the next datum during the zone monitor's zone intiial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 * @param tc scheduler context
 */
static void
monitor_next (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ZoneMonitor *zm = cls;
  int ret;
  
  zm->task = GNUNET_SCHEDULER_NO_TASK;
  ret = GSN_database->iterate_records (GSN_database->cls,
				       &zm->zone,
				       zm->offset++,
				       &monitor_iterate_cb, zm);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_SERVER_client_disconnect (zm->nc->client);
    return;
  }
  if (GNUNET_NO == ret)
  {
    /* empty zone */
    monitor_sync (zm);
    return;
  }
}


/**
 * Process namestore requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_lookup_block, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_BLOCK, sizeof (struct LookupBlockMessage)},
    {&handle_block_cache, NULL,
    GNUNET_MESSAGE_TYPE_NAMESTORE_BLOCK_CACHE, 0},
    {&handle_record_store, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE, 0},
    {&handle_zone_to_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME, sizeof (struct ZoneToNameMessage) },
    {&handle_iteration_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START, sizeof (struct ZoneIterationStartMessage) },
    {&handle_iteration_next, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT, sizeof (struct ZoneIterationNextMessage) },
    {&handle_iteration_stop, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP, sizeof (struct ZoneIterationStopMessage) },
    {&handle_monitor_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START, sizeof (struct ZoneMonitorStartMessage) },
    {NULL, NULL, 0, 0}
  };
  char *database;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");
  GSN_cfg = cfg;
  monitor_nc = GNUNET_SERVER_notification_context_create (server, 1);

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namestore", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  GNUNET_free (database);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }

  /* Configuring server handles */
  GNUNET_SERVER_add_handlers (server, handlers);
  snc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification,
                                   NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "namestore",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-namestore.c */

