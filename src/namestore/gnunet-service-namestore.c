/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014 GNUnet e.V.

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_namecache_service.h"
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
  struct NamestoreClient *nc;

  /**
   * The nick to add to the records
   */
  struct GNUNET_GNSRECORD_Data *nick;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone;

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
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;
  
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
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone;

  /**
   * Task active during initial iteration.
   */
  struct GNUNET_SCHEDULER_Task *task;

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
 * Pending operation on the namecache.
 */
struct CacheOperation
{

  /**
   * Kept in a DLL.
   */
  struct CacheOperation *prev;

  /**
   * Kept in a DLL.
   */
  struct CacheOperation *next;

  /**
   * Handle to namecache queue.
   */
  struct GNUNET_NAMECACHE_QueueEntry *qe;

  /**
   * Client to notify about the result.
   */
  struct NamestoreClient *nc;

  /**
   * Client's request ID.
   */
  uint32_t rid;
};


/**
 * Public key of all zeros.
 */
static const struct GNUNET_CRYPTO_EcdsaPrivateKey zero;

/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
 * Namecache handle.
 */
static struct GNUNET_NAMECACHE_Handle *namecache;

/**
 * Database handle
 */
static struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

/**
 * Name of the database plugin
 */
static char *db_lib_name;

/**
 * Head of cop DLL.
 */
static struct CacheOperation *cop_head;

/**
 * Tail of cop DLL.
 */
static struct CacheOperation *cop_tail;

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
static struct GNUNET_NotificationContext *monitor_nc;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  struct CacheOperation *cop;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stopping namestore service\n");
  while (NULL != (cop = cop_head))
  {
    GNUNET_NAMECACHE_cancel (cop->qe);
    GNUNET_CONTAINER_DLL_remove (cop_head,
                                 cop_tail,
                                 cop);
    GNUNET_free (cop);
  }
  GNUNET_NAMECACHE_disconnect (namecache);
  namecache = NULL;
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, 
					      GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
  if (NULL != monitor_nc)
  {
    GNUNET_notification_context_destroy (monitor_nc);
    monitor_nc = NULL;
  }
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx the `struct NamestoreClient` of @a client
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct NamestoreClient *nc = app_ctx;
  struct ZoneIteration *no;
  struct ZoneMonitor *zm;
  struct CacheOperation *cop;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p disconnected\n",
	      client);
  for (zm = monitor_head; NULL != zm; zm = zm->next)
  {
    if (nc == zm->nc)
    {
      GNUNET_CONTAINER_DLL_remove (monitor_head,
				   monitor_tail,
				   zm);
      if (NULL != zm->task)
      {
	GNUNET_SCHEDULER_cancel (zm->task);
	zm->task = NULL;
      }
      GNUNET_free (zm);
      break;
    }
  }
  while (NULL != (no = nc->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head,
				 nc->op_tail,
				 no);
    GNUNET_free (no);
  }
  for (cop = cop_head; NULL != cop; cop = cop->next)
    if (nc == cop->nc)
      cop->nc = NULL;
  GNUNET_free (nc);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct NamestoreClient *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p connected\n",
	      client);
  nc = GNUNET_new (struct NamestoreClient);
  nc->client = client;
  nc->mq = mq;
  return nc;
}


/**
 * Function called with the records for the #GNUNET_GNS_MASTERZONE_STR
 * label in the zone.  Used to locate the #GNUNET_GNSRECORD_TYPE_NICK
 * record, which (if found) is then copied to @a cls for future use.
 *
 * @param cls a `struct GNUNET_GNSRECORD_Data **` for storing the nick (if found)
 * @param private_key the private key of the zone (unused)
 * @param label should be #GNUNET_GNS_MASTERZONE_STR
 * @param rd_count number of records in @a rd
 * @param rd records stored under @a label in the zone
 */
static void
lookup_nick_it (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPrivateKey *private_key,
                const char *label,
                unsigned int rd_count,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data **res = cls;

  if (0 != strcmp (label, GNUNET_GNS_MASTERZONE_STR))
  {
    GNUNET_break (0);
    return;
  }
  for (unsigned int c = 0; c < rd_count; c++)
  {
    if (GNUNET_GNSRECORD_TYPE_NICK == rd[c].record_type)
    {
      (*res) = GNUNET_malloc (rd[c].data_size + sizeof (struct GNUNET_GNSRECORD_Data));
      (*res)->data = &(*res)[1];
      GNUNET_memcpy ((void *) (*res)->data,
                     rd[c].data,
                     rd[c].data_size);
      (*res)->data_size = rd[c].data_size;
      (*res)->expiration_time = rd[c].expiration_time;
      (*res)->flags = rd[c].flags;
      (*res)->record_type = GNUNET_GNSRECORD_TYPE_NICK;
      return;
    }
  }
  (*res) = NULL;
}


/**
 * Return the NICK record for the zone (if it exists).
 *
 * @param zone private key for the zone to look for nick
 * @return NULL if no NICK record was found
 */
static struct GNUNET_GNSRECORD_Data *
get_nick_record (const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_GNSRECORD_Data *nick;
  int res;

  res = GSN_database->lookup_records (GSN_database->cls, zone,
                                      GNUNET_GNS_MASTERZONE_STR,
                                      &lookup_nick_it, &nick);
  if ( (GNUNET_OK != res) ||
       (NULL == nick) )
  {
    GNUNET_CRYPTO_ecdsa_key_get_public (zone, &pub);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
                "No nick name set for zone `%s'\n",
                GNUNET_GNSRECORD_z2s (&pub));
    return NULL;
  }
  return nick;
}


static void
merge_with_nick_records (const struct GNUNET_GNSRECORD_Data *nick_rd,
                         unsigned int rdc2,
                         const struct GNUNET_GNSRECORD_Data *rd2,
                         unsigned int *rdc_res,
                         struct GNUNET_GNSRECORD_Data **rd_res)
{
  uint64_t latest_expiration;
  size_t req;
  char *data;
  int record_offset;
  size_t data_offset;

  (*rdc_res) = 1 + rdc2;
  if (0 == 1 + rdc2)
  {
    (*rd_res) = NULL;
    return;
  }

  req = 0;
  for (unsigned int c=0; c< 1; c++)
    req += sizeof (struct GNUNET_GNSRECORD_Data) + nick_rd[c].data_size;
  for (unsigned int c=0; c< rdc2; c++)
    req += sizeof (struct GNUNET_GNSRECORD_Data) + rd2[c].data_size;
  (*rd_res) = GNUNET_malloc (req);
  data = (char *) &(*rd_res)[1 + rdc2];
  data_offset = 0;
  latest_expiration = 0;

  for (unsigned int c=0; c< rdc2; c++)
  {
    if (0 != (rd2[c].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      if ((GNUNET_TIME_absolute_get().abs_value_us + rd2[c].expiration_time) >
        latest_expiration)
          latest_expiration = rd2[c].expiration_time;
    }
    else if (rd2[c].expiration_time > latest_expiration)
      latest_expiration = rd2[c].expiration_time;
    (*rd_res)[c] = rd2[c];
    (*rd_res)[c].data = (void *) &data[data_offset];
    GNUNET_memcpy ((void *) (*rd_res)[c].data,
                   rd2[c].data,
                   rd2[c].data_size);
    data_offset += (*rd_res)[c].data_size;
  }
  record_offset = rdc2;
  for (unsigned int c=0; c< 1; c++)
  {
    (*rd_res)[c+record_offset] = nick_rd[c];
    (*rd_res)[c+record_offset].expiration_time = latest_expiration;
    (*rd_res)[c+record_offset].data = (void *) &data[data_offset];
    GNUNET_memcpy ((void *) (*rd_res)[c+record_offset].data,
                   nick_rd[c].data,
                   nick_rd[c].data_size);
    data_offset += (*rd_res)[c+record_offset].data_size;
  }
  GNUNET_assert (req == (sizeof (struct GNUNET_GNSRECORD_Data)) * (*rdc_res) + data_offset);
}


/**
 * Generate a `struct LookupNameResponseMessage` and send it to the
 * given client using the given notification context.
 *
 * @param nc client to unicast to
 * @param request_id request ID to use
 * @param zone_key zone key of the zone
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd array of records
 */
static void
send_lookup_response (struct NamestoreClient *nc,
		      uint32_t request_id,
		      const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		      const char *name,
		      unsigned int rd_count,
		      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_MQ_Envelope *env;
  struct RecordResultMessage *zir_msg;
  struct GNUNET_GNSRECORD_Data *nick;
  struct GNUNET_GNSRECORD_Data *res;
  unsigned int res_count;
  size_t name_len;
  size_t rd_ser_len;
  char *name_tmp;
  char *rd_ser;

  nick = get_nick_record (zone_key);
  if ((NULL != nick) && (0 != strcmp(name, GNUNET_GNS_MASTERZONE_STR)))
  {
    nick->flags = (nick->flags | GNUNET_GNSRECORD_RF_PRIVATE) ^ GNUNET_GNSRECORD_RF_PRIVATE;
    merge_with_nick_records (nick,
                             rd_count,
                             rd,
                             &res_count,
                             &res);
    GNUNET_free (nick);
  }
  else
  {
    res_count = rd_count;
    res = (struct GNUNET_GNSRECORD_Data *) rd;
  }

  name_len = strlen (name) + 1;
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (res_count, res);
  env = GNUNET_MQ_msg_extra (zir_msg,
			     name_len + rd_ser_len,
			     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT);
  zir_msg->gns_header.r_id = htonl (request_id);
  zir_msg->name_len = htons (name_len);
  zir_msg->rd_count = htons (res_count);
  zir_msg->rd_len = htons (rd_ser_len);
  zir_msg->private_key = *zone_key;
  name_tmp = (char *) &zir_msg[1];
  GNUNET_memcpy (name_tmp,
		 name,
		 name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_GNSRECORD_records_serialize (res_count,
				      res,
				      rd_ser_len,
				      rd_ser);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending RECORD_RESULT message with %u records\n",
	      res_count);
  GNUNET_MQ_send (nc->mq,
		  env);
  if (rd != res)
    GNUNET_free (res);
}


/**
 * Send response to the store request to the client.
 *
 * @param client client to talk to
 * @param res status of the operation
 * @param rid client's request ID
 */
static void
send_store_response (struct NamestoreClient *nc,
                     int res,
                     uint32_t rid)
{
  struct GNUNET_MQ_Envelope *env;
  struct RecordStoreResponseMessage *rcr_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending RECORD_STORE_RESPONSE message\n");
  env = GNUNET_MQ_msg (rcr_msg,
		       GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE);
  rcr_msg->gns_header.r_id = htonl (rid);
  rcr_msg->op_result = htonl (res);
  GNUNET_MQ_send (nc->mq,
		  env);
}


/**
 * Cache operation complete, clean up.
 *
 * @param cls the `struct CacheOperation`
 * @param success success
 * @param emsg error messages
 */
static void
finish_cache_operation (void *cls,
                        int32_t success,
                        const char *emsg)
{
  struct CacheOperation *cop = cls;

  if (NULL != emsg)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to replicate block in namecache: %s\n"),
                emsg);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "CACHE operation completed\n");
  GNUNET_CONTAINER_DLL_remove (cop_head,
                               cop_tail,
                               cop);
  if (NULL != cop->nc)
    send_store_response (cop->nc,
                         success,
                         cop->rid);
  GNUNET_free (cop);
}


/**
 * We just touched the plaintext information about a name in our zone;
 * refresh the corresponding (encrypted) block in the namecache.
 *
 * @param nc client responsible for the request, can be NULL
 * @param rid request ID of the client
 * @param zone_key private key of the zone
 * @param name label for the records
 * @param rd_count number of records
 * @param rd records stored under the given @a name
 */
static void
refresh_block (struct NamestoreClient *nc,
               uint32_t rid,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
               const char *name,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Block *block;
  struct CacheOperation *cop;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_GNSRECORD_Data *nick;
  struct GNUNET_GNSRECORD_Data *res;
  unsigned int res_count;

  nick = get_nick_record (zone_key);
  res_count = rd_count;
  res = (struct GNUNET_GNSRECORD_Data *) rd; /* fixme: a bit unclean... */
  if (NULL != nick)
  {
    nick->flags = (nick->flags | GNUNET_GNSRECORD_RF_PRIVATE) ^ GNUNET_GNSRECORD_RF_PRIVATE;
    merge_with_nick_records (nick,
			     rd_count,rd,
			     &res_count,
			     &res);
    GNUNET_free (nick);
  }

  if (0 == res_count)
    block = GNUNET_GNSRECORD_block_create (zone_key,
                                           GNUNET_TIME_UNIT_ZERO_ABS,
                                           name,
                                           res, rd_count);
  else
    block = GNUNET_GNSRECORD_block_create (zone_key,
                                           GNUNET_GNSRECORD_record_get_expiration_time (res_count,
                                               res),
                                           name,
                                           res, res_count);
  GNUNET_assert (NULL != block);
  GNUNET_CRYPTO_ecdsa_key_get_public (zone_key,
                                      &pkey);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Caching block for label `%s' with %u records in zone `%s' in namecache\n",
              name,
              res_count,
              GNUNET_GNSRECORD_z2s (&pkey));
  cop = GNUNET_new (struct CacheOperation);
  cop->nc = nc;
  cop->rid = rid;
  GNUNET_CONTAINER_DLL_insert (cop_head,
                               cop_tail,
                               cop);
  cop->qe = GNUNET_NAMECACHE_block_cache (namecache,
                                          block,
                                          &finish_cache_operation,
                                          cop);
  GNUNET_free (block);
}


/**
 * Closure for #lookup_it().
 */
struct RecordLookupContext
{
  const char *label;

  int found;

  unsigned int res_rd_count;

  size_t rd_ser_len;

  char *res_rd;

  struct GNUNET_GNSRECORD_Data *nick;
};


static void
lookup_it (void *cls,
           const struct GNUNET_CRYPTO_EcdsaPrivateKey *private_key,
           const char *label,
           unsigned int rd_count,
           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RecordLookupContext *rlc = cls;
  struct GNUNET_GNSRECORD_Data *rd_res;
  unsigned int rdc_res;

  if (0 == strcmp (label, rlc->label))
  {
    rlc->found = GNUNET_YES;
    if (0 != rd_count)
    {
      if ( (NULL != rlc->nick) &&
           (0 != strcmp (label,
                         GNUNET_GNS_MASTERZONE_STR)) )
      {
        /* Merge */
        rd_res = NULL;
        rdc_res = 0;
        rlc->nick->flags = (rlc->nick->flags | GNUNET_GNSRECORD_RF_PRIVATE) ^ GNUNET_GNSRECORD_RF_PRIVATE;
        merge_with_nick_records (rlc->nick,
                                 rd_count, rd,
                                 &rdc_res, &rd_res);

        rlc->rd_ser_len = GNUNET_GNSRECORD_records_get_size (rdc_res,
                                                             rd_res);
        rlc->res_rd_count = rdc_res;
        rlc->res_rd = GNUNET_malloc (rlc->rd_ser_len);
        GNUNET_GNSRECORD_records_serialize (rdc_res,
                                            rd_res,
                                            rlc->rd_ser_len,
                                            rlc->res_rd);

        GNUNET_free  (rd_res);
        GNUNET_free  (rlc->nick);
        rlc->nick = NULL;
      }
      else
      {
        rlc->rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                             rd);
        rlc->res_rd_count = rd_count;
        rlc->res_rd = GNUNET_malloc (rlc->rd_ser_len);
        GNUNET_GNSRECORD_records_serialize (rd_count,
                                            rd,
                                            rlc->rd_ser_len,
                                            rlc->res_rd);
      }
    }
    else
    {
      rlc->rd_ser_len = 0;
      rlc->res_rd_count = 0;
      rlc->res_rd = NULL;
    }
  }
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct LabelLookupMessage`
 * @return #GNUNET_OK if @a ll_msg is well-formed
 */
static int
check_record_lookup (void *cls,
		     const struct LabelLookupMessage *ll_msg)
{
  uint32_t name_len;
  size_t src_size;
  const char *name_tmp;

  name_len = ntohl (ll_msg->label_len);
  src_size = ntohs (ll_msg->gns_header.header.size);
  if (name_len != src_size - sizeof (struct LabelLookupMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  name_tmp = (const char *) &ll_msg[1];
  if ('\0' != name_tmp[name_len -1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct LabelLookupMessage`
 */
static void
handle_record_lookup (void *cls,
		      const struct LabelLookupMessage *ll_msg)
{
  struct NamestoreClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct LabelLookupResponseMessage *llr_msg;
  struct RecordLookupContext rlc;
  const char *name_tmp;
  char *res_name;
  char *conv_name;
  uint32_t name_len;
  int res;

  name_len = ntohl (ll_msg->label_len);
  name_tmp = (const char *) &ll_msg[1];
  GNUNET_SERVICE_client_continue (nc->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received NAMESTORE_RECORD_LOOKUP message for name `%s'\n",
              name_tmp);

  conv_name = GNUNET_GNSRECORD_string_to_lowercase (name_tmp);
  if (NULL == conv_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error converting name `%s'\n",
                name_tmp);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  rlc.label = conv_name;
  rlc.found = GNUNET_NO;
  rlc.res_rd_count = 0;
  rlc.res_rd = NULL;
  rlc.rd_ser_len = 0;
  rlc.nick = get_nick_record (&ll_msg->zone);
  res = GSN_database->lookup_records (GSN_database->cls,
                                      &ll_msg->zone,
                                      conv_name,
                                      &lookup_it,
                                      &rlc);
  GNUNET_free (conv_name);
  env = GNUNET_MQ_msg_extra (llr_msg,
			     name_len + rlc.rd_ser_len,
			     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE);
  llr_msg->gns_header.r_id = ll_msg->gns_header.r_id;
  llr_msg->private_key = ll_msg->zone;
  llr_msg->name_len = htons (name_len);
  llr_msg->rd_count = htons (rlc.res_rd_count);
  llr_msg->rd_len = htons (rlc.rd_ser_len);
  res_name = (char *) &llr_msg[1];
  if  ((GNUNET_YES == rlc.found) && (GNUNET_OK == res))
    llr_msg->found = ntohs (GNUNET_YES);
  else
    llr_msg->found = ntohs (GNUNET_NO);
  GNUNET_memcpy (&llr_msg[1],
                 name_tmp,
                 name_len);
  GNUNET_memcpy (&res_name[name_len],
                 rlc.res_rd,
                 rlc.rd_ser_len);
  GNUNET_MQ_send (nc->mq,
		  env);
  GNUNET_free_non_null (rlc.res_rd);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE message
 *
 * @param cls client sending the message
 * @param rp_msg message of type `struct RecordStoreMessage`
 * @return #GNUNET_OK if @a rp_msg is well-formed
 */
static int
check_record_store (void *cls,
		    const struct RecordStoreMessage *rp_msg)
{
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  size_t rd_ser_len;
  const char *name_tmp;

  name_len = ntohs (rp_msg->name_len);
  msg_size = ntohs (rp_msg->gns_header.header.size);
  rd_ser_len = ntohs (rp_msg->rd_len);
  msg_size_exp = sizeof (struct RecordStoreMessage) + name_len + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ((0 == name_len) || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_tmp = (const char *) &rp_msg[1];
  if ('\0' != name_tmp[name_len -1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE message
 *
 * @param cls client sending the message
 * @param rp_msg message of type `struct RecordStoreMessage`
 */
static void
handle_record_store (void *cls,
		     const struct RecordStoreMessage *rp_msg)
{
  struct NamestoreClient *nc = cls;
  size_t name_len;
  size_t rd_ser_len;
  uint32_t rid;
  const char *name_tmp;
  char *conv_name;
  const char *rd_ser;
  unsigned int rd_count;
  int res;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;
  struct ZoneMonitor *zm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received NAMESTORE_RECORD_STORE message\n");
  rid = ntohl (rp_msg->gns_header.r_id);
  name_len = ntohs (rp_msg->name_len);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs (rp_msg->rd_len);
  GNUNET_break (0 == ntohs (rp_msg->reserved));
  name_tmp = (const char *) &rp_msg[1];
  rd_ser = &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK !=
	GNUNET_GNSRECORD_records_deserialize (rd_ser_len,
                                              rd_ser,
                                              rd_count,
                                              rd))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (nc->client);
      return;
    }

    /* Extracting and converting private key */
    GNUNET_CRYPTO_ecdsa_key_get_public (&rp_msg->private_key,
                                        &pubkey);
    conv_name = GNUNET_GNSRECORD_string_to_lowercase (name_tmp);
    if (NULL == conv_name)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n",
                  name_tmp);
      GNUNET_SERVICE_client_drop (nc->client);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Creating %u records for name `%s' in zone `%s'\n",
		(unsigned int) rd_count,
		conv_name,
		GNUNET_GNSRECORD_z2s (&pubkey));

    if ( (0 == rd_count) &&
         (GNUNET_NO ==
          GSN_database->iterate_records (GSN_database->cls,
                                         &rp_msg->private_key,
                                         0,
                                         NULL,
                                         0)) )
    {
      /* This name does not exist, so cannot be removed */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Name `%s' does not exist, no deletion required\n",
                  conv_name);
      res = GNUNET_NO;
    }
    else
    {
      struct GNUNET_GNSRECORD_Data rd_clean[rd_count];
      unsigned int rd_clean_off;

      /* remove "NICK" records, unless this is for the "+" label */
      rd_clean_off = 0;
      for (unsigned int i=0;i<rd_count;i++)
      {
        rd_clean[rd_clean_off] = rd[i];
        if ( (0 == strcmp (GNUNET_GNS_MASTERZONE_STR,
                           conv_name)) ||
             (GNUNET_GNSRECORD_TYPE_NICK != rd[i].record_type) )
          rd_clean_off++;
      }
      res = GSN_database->store_records (GSN_database->cls,
					 &rp_msg->private_key,
					 conv_name,
					 rd_clean_off,
                                         rd_clean);
      if (GNUNET_OK == res)
      {
        for (zm = monitor_head; NULL != zm; zm = zm->next)
        {
          if ( (0 == memcmp (&rp_msg->private_key, &zm->zone,
                             sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey))) ||
               (0 == memcmp (&zm->zone,
                             &zero,
                             sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey))) )
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Notifying monitor about changes under label `%s'\n",
                        conv_name);
            send_lookup_response (zm->nc,
                                  0,
                                  &rp_msg->private_key,
                                  conv_name,
                                  rd_count, rd);
          }
          else
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Monitor is for another zone\n");
        }
        if (NULL == monitor_head)
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "No monitors active\n");
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Error storing record: %d\n",
                    res);
      }
    }
    if (GNUNET_OK == res)
    {
      refresh_block (nc,
		     rid,
                     &rp_msg->private_key,
                     conv_name,
                     rd_count,
		     rd);
      GNUNET_SERVICE_client_continue (nc->client);
      GNUNET_free (conv_name);
      return;
    }
    GNUNET_free (conv_name);
  }
  send_store_response (nc,
                       res,
                       rid);
  GNUNET_SERVICE_client_continue (nc->client);
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
			const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
			const char *name,
			unsigned int rd_count,
			const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneToNameCtx *ztn_ctx = cls;
  struct GNUNET_MQ_Envelope *env;
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
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  msg_size = sizeof (struct ZoneToNameResponseMessage) + name_len + rd_ser_len;
  if (msg_size >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    ztn_ctx->success = GNUNET_SYSERR;
    return;
  }
  env = GNUNET_MQ_msg_extra (ztnr_msg,
			     name_len + rd_ser_len,
			     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
  ztnr_msg->gns_header.header.size = htons (msg_size);
  ztnr_msg->gns_header.r_id = htonl (ztn_ctx->rid);
  ztnr_msg->res = htons (res);
  ztnr_msg->rd_len = htons (rd_ser_len);
  ztnr_msg->rd_count = htons (rd_count);
  ztnr_msg->name_len = htons (name_len);
  ztnr_msg->zone = *zone_key;
  name_tmp = (char *) &ztnr_msg[1];
  GNUNET_memcpy (name_tmp,
		 name,
		 name_len);
  rd_tmp = &name_tmp[name_len];
  GNUNET_GNSRECORD_records_serialize (rd_count,
				      rd,
				      rd_ser_len,
				      rd_tmp);
  ztn_ctx->success = GNUNET_OK;
  GNUNET_MQ_send (ztn_ctx->nc->mq,
		  env);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME message
 *
 * @param cls client client sending the message
 * @param ztn_msg message of type 'struct ZoneToNameMessage'
 */
static void
handle_zone_to_name (void *cls,
                     const struct ZoneToNameMessage *ztn_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneToNameCtx ztn_ctx;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneToNameResponseMessage *ztnr_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "ZONE_TO_NAME");
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
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  if (GNUNET_NO == ztn_ctx.success)
  {
    /* no result found, send empty response */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found no result for zone-to-name lookup.\n");
    env = GNUNET_MQ_msg (ztnr_msg,
			 GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
    ztnr_msg->gns_header.r_id = ztn_msg->gns_header.r_id;
    ztnr_msg->res = htons (GNUNET_NO);
    GNUNET_MQ_send (nc->mq,
		    env);
  }
  GNUNET_SERVICE_client_continue (nc->client);
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
 * #run_zone_iteration_round to #zone_iterate_proc as closure
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
zone_iterate_proc (void *cls,
		   const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		   const char *name,
		   unsigned int rd_count,
		   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneIterationProcResult *proc = cls;
  int do_refresh_block;

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
  send_lookup_response (proc->zi->nc,
			proc->zi->request_id,
			zone_key,
			name,
			rd_count,
			rd);
  do_refresh_block = GNUNET_NO;
  for (unsigned int i=0;i<rd_count;i++)
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      do_refresh_block = GNUNET_YES;
      break;
    }
  if (GNUNET_YES == do_refresh_block)
    refresh_block (NULL,
		   0,
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
  struct ZoneIterationProcResult proc;
  struct GNUNET_MQ_Envelope *env;
  struct RecordResultMessage *rrm;
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
					      &zone_iterate_proc, &proc)))
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
  env = GNUNET_MQ_msg (rrm,
		       GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT);
  rrm->gns_header.r_id = htonl (zi->request_id);
  GNUNET_MQ_send (zi->nc->mq,
		  env);
  GNUNET_CONTAINER_DLL_remove (zi->nc->op_head,
			       zi->nc->op_tail,
			       zi);
  GNUNET_free (zi);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_start (void *cls,
			const struct ZoneIterationStartMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received ZONE_ITERATION_START message\n");
  zi = GNUNET_new (struct ZoneIteration);
  zi->request_id = ntohl (zis_msg->gns_header.r_id);
  zi->offset = 0;
  zi->nc = nc;
  zi->zone = zis_msg->zone;

  GNUNET_CONTAINER_DLL_insert (nc->op_head,
			       nc->op_tail,
			       zi);
  run_zone_iteration_round (zi);
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_stop (void *cls,
		       const struct ZoneIterationStopMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "ZONE_ITERATION_STOP");
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (nc->op_head,
			       nc->op_tail,
			       zi);
  GNUNET_free (zi);
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT message
 *
 * @param cls the client sending the message
 * @param message message from the client
 */
static void
handle_iteration_next (void *cls,
		       const struct ZoneIterationNextMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_ITERATION_NEXT message\n");
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  run_zone_iteration_round (zi);
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Send 'sync' message to zone monitor, we're now in sync.
 *
 * @param zm monitor that is now in sync
 */
static void
monitor_sync (struct ZoneMonitor *zm)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *sync;

  env = GNUNET_MQ_msg (sync,
		       GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC);
  GNUNET_MQ_send (zm->nc->mq,
		  env);
}


/**
 * Obtain the next datum during the zone monitor's zone intiial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 */
static void
monitor_next (void *cls);


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
		    const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		    const char *name,
		    unsigned int rd_count,
		    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneMonitor *zm = cls;

  if (NULL == name)
  {
    /* finished with iteration */
    monitor_sync (zm);
    return;
  }
  send_lookup_response (zm->nc,
			0,
			zone_key,
			name,
			rd_count,
			rd);
  zm->task = GNUNET_SCHEDULER_add_now (&monitor_next,
				       zm);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START message
 *
 * @param cls the client sending the message
 * @param message message from the client
 */
static void
handle_monitor_start (void *cls,
		      const struct ZoneMonitorStartMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneMonitor *zm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received ZONE_MONITOR_START message\n");
  zm = GNUNET_new (struct ZoneMonitor);
  zm->nc = nc;
  zm->zone = zis_msg->zone;
  GNUNET_CONTAINER_DLL_insert (monitor_head,
			       monitor_tail,
			       zm);
  GNUNET_SERVICE_client_mark_monitor (nc->client);
  GNUNET_SERVICE_client_disable_continue_warning (nc->client);
  GNUNET_notification_context_add (monitor_nc,
				   nc->mq);
  if (GNUNET_YES == ntohl (zis_msg->iterate_first))
    zm->task = GNUNET_SCHEDULER_add_now (&monitor_next,
					 zm);
  else
    monitor_sync (zm);
}


/**
 * Obtain the next datum during the zone monitor's zone intiial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 */
static void
monitor_next (void *cls)
{
  struct ZoneMonitor *zm = cls;
  int ret;

  zm->task = NULL;
  ret = GSN_database->iterate_records (GSN_database->cls,
                                       (0 == memcmp (&zm->zone,
						     &zero,
						     sizeof (zero)))
                                       ? NULL
                                       : &zm->zone,
				       zm->offset++,
				       &monitor_iterate_cb,
				       zm);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_SERVICE_client_drop (zm->nc->client);
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
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  char *database;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting namestore service\n");
  GSN_cfg = cfg;
  monitor_nc = GNUNET_notification_context_create (1);
  namecache = GNUNET_NAMECACHE_connect (cfg);
  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "namestore",
                                             "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_namestore_%s",
                   database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name,
                                     (void *) GSN_cfg);
  GNUNET_free (database);
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
				 NULL);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("namestore",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (record_store,
			GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE,
			struct RecordStoreMessage,
			NULL),
 GNUNET_MQ_hd_var_size (record_lookup,
			GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP,
			struct LabelLookupMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (zone_to_name,
			  GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME,
			  struct ZoneToNameMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (iteration_start, 
			  GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START,
			  struct ZoneIterationStartMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (iteration_next, 
			  GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT,
			  struct ZoneIterationNextMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (iteration_stop, 
			  GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP,
			  struct ZoneIterationStopMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (monitor_start, 
			  GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START,
			  struct ZoneMonitorStartMessage,
			  NULL),
 GNUNET_MQ_handler_end ());
			  

/* end of gnunet-service-namestore.c */
