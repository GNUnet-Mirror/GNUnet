/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 *    - Write xquery and block plugin
 *    - The smaller FIXME issues all around
 *
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
#include "block_gns.h"
#include "gns.h"

/* Ignore for now not used anyway and probably never will */
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT 24

/**
 * Handle to a currenty pending resolution
 */
struct GNUNET_GNS_ResolverHandle
{
  /* The name to resolve */
  char *name;

  /* the request handle to reply to */
  struct GNUNET_DNS_RequestHandle *request_handle;
  
  /* the dns parser packet received */
  struct GNUNET_DNSPARSER_Packet *packet;
  
  /* the query parsed from the packet */

  struct GNUNET_DNSPARSER_Query *query;
  
  /* has this query been answered? how many matches */
  int answered;

  /* the authoritative zone to query */
  GNUNET_HashCode authority;

  /* the name of the authoritative zone to query */
  char *authority_name;

  /**
   * we have an authority in namestore that
   * may be able to resolve
   */
  int authority_found;

  /* a handle for dht lookups. should be NULL if no lookups are in progress */
  struct GNUNET_DHT_GetHandle *get_handle;

};


/**
 * Our handle to the DNS handler library
 */
struct GNUNET_DNS_Handle *dns_handle;

/**
 * Our handle to the DHT
 */
struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our zone's private key
 */
struct GNUNET_CRYPTO_RsaPrivateKey *zone_key;

/**
 * Our handle to the namestore service
 * FIXME maybe need a second handle for iteration
 */
struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to iterate over our authoritative zone in namestore
 */
struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * The configuration the GNS service is running with
 */
const struct GNUNET_CONFIGURATION_Handle *GNS_cfg;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Our zone hash
 */
GNUNET_HashCode zone_hash;

/**
 * Our tld. Maybe get from config file
 */
const char* gnunet_tld = ".gnunet";

/**
 * Useful for zone update for DHT put
 */
static int num_public_records =  3600;
struct GNUNET_TIME_Relative dht_update_interval;
GNUNET_SCHEDULER_TaskIdentifier zone_update_taskid = GNUNET_SCHEDULER_NO_TASK;

/* Prototypes */
void reply_to_dns(struct GNUNET_GNS_ResolverHandle *answer, uint32_t rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd);
void resolve_name(struct GNUNET_GNS_ResolverHandle *rh);

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* Kill zone task for it may make the scheduler hang */
  GNUNET_SCHEDULER_cancel(zone_update_taskid);

  GNUNET_DNS_disconnect(dns_handle);
  GNUNET_NAMESTORE_disconnect(namestore_handle, 0);
  GNUNET_DHT_disconnect(dht_handle);
}

/**
 * Callback when record data is put into namestore
 *
 * @param cls the closure
 * @param success GNUNET_OK on success
 * @param emsg the error message. NULL if SUCCESS==GNUNET_OK
 */
void
on_namestore_record_put_result(void *cls,
                               int32_t success,
                               const char *emsg)
{
  if (GNUNET_NO == success)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "records already in namestore\n");
    return;
  }
  else if (GNUNET_YES == success)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "records successfully put in namestore\n");
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
             "Error putting records into namestore: %s\n", emsg);
}

/**
 * Function called when we get a result from the dht
 * for our query
 *
 * @param cls the request handle
 * @param exp lifetime
 * @param key the key the record was stored under
 * @param get_path get path
 * @param get_path_length get path length
 * @param put_path put path
 * @param put_path_length put path length
 * @param type the block type
 * @param size the size of the record
 * @param data the record data
 */
void
process_authority_dht_result(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct GNSNameRecordBlock *nrb;
  struct GNSRecordBlock *rb;
  uint32_t num_records;
  char* name = NULL;
  int i;
  GNUNET_HashCode zone, name_hash;
  
  if (data == NULL)
    return;
  
  //FIXME check expiration?
  
  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  nrb = (struct GNSNameRecordBlock*)data;
  
  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  num_records = ntohl(nrb->rd_count);
  struct GNUNET_NAMESTORE_RecordData rd[num_records];
  name = (char*)&nrb[1];
  rb = (struct GNSRecordBlock *)&name[strlen(name) + 1];

  for (i=0; i<num_records; i++)
  {
  
    rd[i].record_type = ntohl(rb->type);
    rd[i].data_size = ntohl(rb->data_length);
    rd[i].data = &rb[1];
    rd[i].expiration = GNUNET_TIME_absolute_ntoh(rb->expiration);
    rd[i].flags = ntohl(rb->flags);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got name: %s (wanted %s)\n", name, rh->authority_name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got type: %d raw %d (wanted %d)\n",
               rd[i].record_type, rb->type, GNUNET_GNS_RECORD_PKEY);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got data length: %d\n", rd[i].data_size);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got flag %d\n", rd[i].flags);

    if ((strcmp(name, rh->authority_name) == 0) &&
        (rd[i].record_type == GNUNET_GNS_RECORD_PKEY))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Authority found in DHT\n");
      rh->answered = 1;
      GNUNET_CRYPTO_hash(
                 (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *)rd[i].data,
                 rd[i].data_size,
                 &rh->authority);
    }
    rb = (struct GNSRecordBlock*)((char*)&rb[1] + rd[i].data_size);

  }

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(key, &name_hash, &zone);

  /* Save to namestore */
  if (0 == GNUNET_CRYPTO_hash_cmp(&zone_hash, &zone))
  {
    GNUNET_NAMESTORE_record_put (namestore_handle,
                               &nrb->public_key,
                               name,
                               exp,
                               num_records,
                               rd,
                               &nrb->signature,
                               &on_namestore_record_put_result, //cont
                               NULL); //cls
  }
  
  if (rh->answered)
  {
    rh->answered = 0;
    resolve_name(rh);
    return;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "No authority in records\n");
  reply_to_dns(rh, 0, NULL);
}

/**
 * Start DHT lookup for a name -> PKEY (compare NS) record in
 * query->authority's zone
 *
 * @param rh the pending gns query
 * @param name the name of the PKEY record
 */
void
resolve_authority_dht(struct GNUNET_GNS_ResolverHandle *rh)
{
  uint32_t xquery;
  struct GNUNET_TIME_Relative timeout;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  GNUNET_CRYPTO_hash(rh->authority_name,
                     strlen(rh->authority_name),
                     &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, &rh->authority, &lookup_key);

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);
  
  xquery = htonl(GNUNET_GNS_RECORD_PKEY);
  //FIXME how long to wait for results?
  rh->get_handle = GNUNET_DHT_get_start(dht_handle, timeout,
                       GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                       &lookup_key,
                       5, //Replication level FIXME
                       GNUNET_DHT_RO_NONE,
                       &xquery,
                       sizeof(xquery),
                       &process_authority_dht_result,
                       rh);

}

/**
 * Function called when we get a result from the dht
 * for our query
 *
 * @param cls the request handle
 * @param exp lifetime
 * @param key the key the record was stored under
 * @param get_path get path
 * @param get_path_length get path length
 * @param put_path put path
 * @param put_path_length put path length
 * @param type the block type
 * @param size the size of the record
 * @param data the record data
 */
void
process_name_dht_result(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct GNSNameRecordBlock *nrb;
  struct GNSRecordBlock *rb;
  uint32_t num_records;
  char* name = NULL;
  int i;
  GNUNET_HashCode zone, name_hash;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "got dht result (size=%d)\n", size);
  
  if (data == NULL)
    return;

  //FIXME maybe check expiration here, check block type
  
  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  nrb = (struct GNSNameRecordBlock*)data;

  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  num_records = ntohl(nrb->rd_count);
  struct GNUNET_NAMESTORE_RecordData rd[num_records];

  name = (char*)&nrb[1];
  rb = (struct GNSRecordBlock*)&name[strlen(name) + 1];
  
  for (i=0; i<num_records; i++)
  {
    rd[i].record_type = ntohl(rb->type);
    rd[i].data_size = ntohl(rb->data_length);
    rd[i].data = (char*)&rb[1];
    rd[i].expiration = GNUNET_TIME_absolute_ntoh(rb->expiration);
    rd[i].flags = ntohl(rb->flags);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got name: %s (wanted %s)\n", name, rh->name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got type: %d raw %d (wanted %d)\n",
               rd[i].record_type, rb->type, rh->query->type);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got data length: %d\n", rd[i].data_size);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got flag %d\n", rd[i].flags);
    
    /* FIXME class? */
    if ((strcmp(name, rh->name) == 0) &&
       (rd[i].record_type == rh->query->type))
    {
      rh->answered++;
    }

    rb = (struct GNSRecordBlock*)((char*)&rb[1] + rd[i].data_size);

  }

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(key, &name_hash, &zone);
  
  /**
   * FIXME check pubkey against existing key in namestore?
   * https://gnunet.org/bugs/view.php?id=2179
   */

  /* Save to namestore */
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &nrb->public_key,
                               name,
                               exp,
                               num_records,
                               rd,
                               &nrb->signature,
                               &on_namestore_record_put_result, //cont
                               NULL); //cls
  
  if (rh->answered)
    reply_to_dns(rh, num_records, rd);
  else
    reply_to_dns(rh, 0, NULL);

}

/**
 * Start DHT lookup for a (name -> query->record_type) record in
 * query->authority's zone
 *
 * @param rh the pending gns query context
 * @param name the name to query record
 */
void
resolve_name_dht(struct GNUNET_GNS_ResolverHandle *rh, const char* name)
{
  uint32_t xquery;
  struct GNUNET_TIME_Relative timeout;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;
  struct GNUNET_CRYPTO_HashAsciiEncoded lookup_key_string;

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, &rh->authority, &lookup_key);
  GNUNET_CRYPTO_hash_to_enc (&lookup_key, &lookup_key_string);
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "starting dht lookup for %s with key: %s\n",
             name, (char*)&lookup_key_string);

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);
  
  xquery = htonl(rh->query->type);
  //FIXME how long to wait for results?
  rh->get_handle = GNUNET_DHT_get_start(dht_handle, timeout,
                       GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                       &lookup_key,
                       5, //Replication level FIXME
                       GNUNET_DHT_RO_NONE,
                       &xquery, //xquery FIXME is this bad?
                       sizeof(xquery),
                       &process_name_dht_result,
                       rh);

}

//Prototype
void
resolve_name(struct GNUNET_GNS_ResolverHandle *rh);

/**
 * This is a callback function that should give us only PKEY
 * records. Used to query the namestore for the authority (PKEY)
 * for 'name'
 *
 * @param cls the pending query
 * @param key the key of the zone we did the lookup
 * @param expiration expiration date of the record data set in the namestore
 * @param name the name for which we need an authority
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 * @param signature the signature of the authority for the record data
 */
void
process_authority_lookup(void* cls,
                   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                   struct GNUNET_TIME_Absolute expiration,
                   const char *name,
                   unsigned int rd_count,
                   const struct GNUNET_NAMESTORE_RecordData *rd,
                   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct GNUNET_TIME_Relative remaining_time;
  GNUNET_HashCode zone;

  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  GNUNET_CRYPTO_hash(key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);
  
  /**
   * No authority found in namestore.
   */
  if (rd_count == 0)
  {
    /**
     * We did not find an authority in the namestore
     * _IF_ the current authoritative zone is us we cannot resolve
     * _ELSE_ we can still check the _expired_ dht
     */
    if (0 != GNUNET_CRYPTO_hash_cmp(&zone, &zone_hash) &&
        (remaining_time.rel_value == 0))
    {
      resolve_authority_dht(rh);
      return;
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Authority %s unknown\n",
               rh->authority_name);
    reply_to_dns(rh, 0, NULL);
    return;
  }

  //Note only 1 pkey should have been returned.. anything else would be strange
  /**
   * We found an authority that may be able to help us
   * move on with query
   */
  int i;
  for (i=0; i<rd_count;i++)
  {
  
    if (rd[i].record_type != GNUNET_GNS_RECORD_PKEY)
      continue;
    
      if ((GNUNET_TIME_absolute_get_remaining (rd[i].expiration)).rel_value
          == 0)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This pkey is expired.\n");
        if (remaining_time.rel_value == 0)
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                     "This dht entry is expired. Refreshing\n");
          resolve_authority_dht(rh);
        }

        continue;
      }

      /**
       * Resolve rest of query with new authority
       */
      GNUNET_assert(rd[i].record_type == GNUNET_GNS_RECORD_PKEY);
      GNUNET_CRYPTO_hash(rd[i].data,
                         sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                         &rh->authority);
      resolve_name(rh);
      return;
      
  }
    
  /**
   * no answers found
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Authority lookup successful but no PKEY... never get here\n");
  reply_to_dns(rh, 0, NULL);
}


/**
 * Reply to client with the result from our lookup.
 *
 * @param rh the request handle of the lookup
 * @param rd_count the number of records to return
 * @param rd the record data
 */
void
reply_to_dns(struct GNUNET_GNS_ResolverHandle *rh, uint32_t rd_count,
             const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  size_t len;
  int ret;
  char *buf;
  struct GNUNET_DNSPARSER_Packet *packet = rh->packet;
  struct GNUNET_DNSPARSER_Record answer_records[rh->answered];
  struct GNUNET_DNSPARSER_Record additional_records[rd_count-(rh->answered)];
  packet->answers = answer_records;
  packet->additional_records = additional_records;
  
  /**
   * Put records in the DNS packet and modify it
   * to a response
   */
  len = sizeof(struct GNUNET_DNSPARSER_Record*);
  for (i=0; i < rd_count; i++)
  {
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Adding type %d to DNS response\n", rd[i].record_type);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Name: %s\n", rh->name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "QName: %s\n", rh->query->name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record %d/%d\n", i+1, rd_count);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record len %d\n", rd[i].data_size);
    
    if (rd[i].record_type == rh->query->type)
    {
      answer_records[i].name = rh->query->name;
      answer_records[i].type = rd[i].record_type;
      answer_records[i].data.raw.data_len = rd[i].data_size;
      answer_records[i].data.raw.data = (char*)rd[i].data;
      answer_records[i].expiration_time = rd[i].expiration;
      answer_records[i].class = GNUNET_DNSPARSER_CLASS_INTERNET;//hmmn
    }
    else
    {
      additional_records[i].name = rh->query->name;
      additional_records[i].type = rd[i].record_type;
      additional_records[i].data.raw.data_len = rd[i].data_size;
      additional_records[i].data.raw.data = (char*)rd[i].data;
      additional_records[i].expiration_time = rd[i].expiration;
      additional_records[i].class = GNUNET_DNSPARSER_CLASS_INTERNET;//hmmn
    }
  }
  
  packet->num_answers = rh->answered;
  packet->num_additional_records = rd_count-(rh->answered);
  
  if (0 == GNUNET_CRYPTO_hash_cmp(&rh->authority, &zone_hash))
    packet->flags.authoritative_answer = 1;
  else
    packet->flags.authoritative_answer = 0;

  if (rd == NULL)
    packet->flags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NAME_ERROR;
  else
    packet->flags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NO_ERROR;
  
  packet->flags.query_or_response = 1;

  
  /**
   * Reply to DNS
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Building DNS response\n");
  ret = GNUNET_DNSPARSER_pack (packet,
                               1024, /* FIXME magic from dns redirector */
                               &buf,
                               &len);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Built DNS response! (ret=%d,len=%d)\n", ret, len);
  if (ret == GNUNET_OK)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Answering DNS request\n");
    GNUNET_DNS_request_answer(rh->request_handle,
                              len,
                              buf);
    //GNUNET_free(answer);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Answered DNS request\n");
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Error building DNS response! (ret=%d)", ret);
  }

  GNUNET_free(rh->name);
  GNUNET_free(rh);
}


/**
 * Namestore calls this function if we have record for this name.
 * (or with rd_count=0 to indicate no matches)
 *
 * @param cls the pending query
 * @param key the key of the zone we did the lookup
 * @param expiration expiration date of the namestore entry
 * @param name the name for which we need an authority
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 * @param signature the signature of the authority for the record data
 */
static void
process_authoritative_result(void* cls,
                  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                  struct GNUNET_TIME_Absolute expiration,
                  const char *name, unsigned int rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd,
                  const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct GNUNET_TIME_Relative remaining_time;
  GNUNET_HashCode zone;

  rh = (struct GNUNET_GNS_ResolverHandle *) cls;
  GNUNET_CRYPTO_hash(key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);

  if (rd_count == 0)
  {
    /**
     * Lookup terminated and no results
     * -> DHT Phase unless data is recent
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Namestore lookup for %s terminated without results\n", name);
    
    /**
     * if this is not our zone we cannot rely on the namestore to be
     * complete. -> Query DHT
     */
    if (GNUNET_CRYPTO_hash_cmp(&zone, &zone_hash))
    {
      if (remaining_time.rel_value == 0)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "trying dht...\n");
        resolve_name_dht(rh, name);
        return;
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "Record is still recent. No DHT lookup\n");
      }
    }

    /**
     * Our zone and no result? Cannot resolve TT
     */
    GNUNET_assert(rh->answered == 0);
    reply_to_dns(rh, 0, NULL);
    return;

  }
  else
  {
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Processing additional result %s from namestore\n", name);
    int i;
    for (i=0; i<rd_count;i++)
    {
      
      if ((strcmp(name, rh->query->name) == 0)
          && (rd[i].record_type != rh->query->type))
        continue;
      
      if ((GNUNET_TIME_absolute_get_remaining (rd[i].expiration)).rel_value
          == 0)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This record is expired. Skipping\n");
        continue;
      }
      
      rh->answered++;
      
    }
    
    /**
     * no answers found
     * consult dht if expired
     */
    if ((remaining_time.rel_value == 0) && (rh->answered == 0))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
                 "This dht entry is old. Refreshing.\n");
      resolve_name_dht(rh, name);
      return;
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Found %d answer(s) to query!\n",
               rh->answered);

    reply_to_dns(rh, rd_count, rd);
  }
}

/**
 * Determine if this name is canonical.
 * i.e.
 * a.b.gnunet  = not canonical
 * a           = canonical
 *
 * @param name the name to test
 * @return 1 if canonical
 */
int
is_canonical(char* name)
{
  uint32_t len = strlen(name);
  int i;

  for (i=0; i<len; i++)
  {
    if (*(name+i) == '.')
      return 0;
  }
  return 1;
}

/**
 * Move one level up in the domain hierarchy and return the
 * passed top level domain.
 *
 * @param name the domain
 * @return the tld
 */
char* pop_tld(char* name)
{
  uint32_t len;

  if (is_canonical(name))
    return NULL;

  for (len = strlen(name); len > 0; len--)
  {
    if (*(name+len) == '.')
      break;
  }

  if (len == 0)
    return NULL;

  name[len] = '\0';

  return (name+len+1);
}


/**
 * The first phase of resolution.
 * First check if the name is canonical.
 * If it is then try to resolve directly.
 * If not then we first have to resolve the authoritative entities.
 *
 * @param rh the pending lookup
 */
void
resolve_name(struct GNUNET_GNS_ResolverHandle *rh)
{
  if (is_canonical(rh->name))
  {
    /* We only need to check the current zone's ns */
    GNUNET_NAMESTORE_lookup_record(namestore_handle,
                               &rh->authority,
                               rh->name,
                               rh->query->type,
                               &process_authoritative_result,
                               rh);
  }
  else
  {
    /* We have to resolve the authoritative entity first */
    rh->authority_name = pop_tld(rh->name);
    GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 &rh->authority,
                                 rh->authority_name,
                                 GNUNET_GNS_RECORD_PKEY,
                                 &process_authority_lookup,
                                 rh);
  }
}

/**
 * Entry point for name resolution
 * Setup a new query and try to resolve
 *
 * @param request the request handle of the DNS request from a client
 * @param p the DNS query packet we received
 * @param q the DNS query we received parsed from p
 */
void
start_resolution(struct GNUNET_DNS_RequestHandle *request,
                 struct GNUNET_DNSPARSER_Packet *p,
                 struct GNUNET_DNSPARSER_Query *q)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting resolution for (%s)!\n",
              q->name);
  
  rh = GNUNET_malloc(sizeof (struct GNUNET_GNS_ResolverHandle));
  rh->packet = p;
  rh->query = q;
  rh->authority = zone_hash;
  
  rh->name = GNUNET_malloc(strlen(q->name)
                              - strlen(gnunet_tld) + 1);
  memset(rh->name, 0,
         strlen(q->name)-strlen(gnunet_tld) + 1);
  memcpy(rh->name, q->name,
         strlen(q->name)-strlen(gnunet_tld));

  rh->request_handle = request;

  /* Start resolution in our zone */
  resolve_name(rh);
}

/**
 * The DNS request handler
 * Called for every incoming DNS request.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
void
handle_dns_request(void *cls,
                   struct GNUNET_DNS_RequestHandle *rh,
                   size_t request_length,
                   const char *request)
{
  struct GNUNET_DNSPARSER_Packet *p;
  char *tldoffset;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hijacked a DNS request...processing\n");
  p = GNUNET_DNSPARSER_parse (request, request_length);
  
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    return;
  }
  
  /**
   * Check tld and decide if we or
   * legacy dns is responsible
   *
   * FIXME now in theory there could be more than 1 query in the request
   * but if this is case we get into trouble:
   * either we query the GNS or the DNS. We cannot do both!
   * So I suggest to either only allow a single query per request or
   * only allow GNS or DNS requests.
   * The way it is implemented here now is buggy and will lead to erratic
   * behaviour (if multiple queries are present).
   */
  if (p->num_queries == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No Queries in DNS packet... forwarding\n");
    GNUNET_DNS_request_forward (rh);
  }

  if (p->num_queries > 1)
  {
    /* Note: We could also look for .gnunet */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">1 queriy in DNS packet... odd. We only process #1\n");
  }

  
  /**
   * Check for .gnunet
   */
  tldoffset = p->queries[0].name + strlen(p->queries[0].name);

  while ((*tldoffset) != '.')
    tldoffset--;
  
  if (0 == strcmp(tldoffset, gnunet_tld))
  {
    start_resolution(rh, p, p->queries);
  }
  else
  {
    /**
     * This request does not concern us. Forward to real DNS.
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Request for %s is forwarded to DNS\n", p->queries[0].name);
    GNUNET_DNS_request_forward (rh);
  }

}

/**
 * test function that stores some data in the namestore
 * This will also be replaced by a test progrm that
 * directl interfaces with the namestore
 */
void
put_some_records(void)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Populating namestore\n");
  /* put an A record into namestore FIXME use gnunet.org */
  char* ipB = "5.6.7.8";

  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  struct GNUNET_NAMESTORE_RecordData rdb_web;

  GNUNET_assert(1 == inet_pton (AF_INET, ipB, web));

  rdb_web.data_size = sizeof(struct in_addr);
  rdb_web.data = web;
  rdb_web.record_type = GNUNET_DNSPARSER_TYPE_A;
  rdb_web.expiration = GNUNET_TIME_absolute_get_forever ();
  
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  zone_key,
                                  "www",
                                  &rdb_web,
                                  NULL,
                                  NULL);
}

/**
 * Method called periodicattluy that triggers
 * iteration over root zone
 *
 * @param cls closure
 * @param tc task context
 */
void
update_zone_dht_next(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_zone_iterator_next(namestore_iter);
}

/**
 * Continuation for DHT put
 *
 * @param cls closure
 * @param tc task context
 */
void
record_dht_put(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "put request transmitted\n");
}

/* prototype */
static void
update_zone_dht_start(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function used to put all records successively into the DHT.
 * FIXME bug here
 *
 * @param cls the closure (NULL)
 * @param key the public key of the authority (ours)
 * @param expiration lifetime of the namestore entry
 * @param name the name of the records
 * @param rd_count the number of records in data
 * @param rd the record data
 * @param signature the signature for the record data
 */
void
put_gns_record(void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Putting records for %s into the DHT\n", name);
  struct GNUNET_TIME_Relative timeout;
  struct GNSNameRecordBlock *nrb;
  struct GNSRecordBlock *rb;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;
  struct GNUNET_CRYPTO_HashAsciiEncoded xor_hash_string;
  int i;
  uint32_t rd_payload_length;

  /* we're done */
  if (NULL == name)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Zone iteration finished\n");
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_start,
                                                   NULL);
    return;
  }
  
  rd_payload_length = rd_count * sizeof(struct GNSRecordBlock);
  rd_payload_length += strlen(name) + 1 + sizeof(struct GNSNameRecordBlock);
  
  /* calculate payload size */
  for (i=0; i<rd_count; i++)
  {
    rd_payload_length += rd[i].data_size;
  }
  
  nrb = GNUNET_malloc(rd_payload_length);
  
  if (signature != NULL)
    memcpy(&nrb->signature, signature,
         sizeof(struct GNUNET_CRYPTO_RsaSignature));
  //FIXME signature purpose
  memcpy(&nrb->public_key, key,
         sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  nrb->rd_count = htonl(rd_count);

  memcpy(&nrb[1], name, strlen(name) + 1); //FIXME is this 0 terminated??

  rb = (struct GNSRecordBlock *)((char*)&nrb[1] + strlen(name) + 1);

  for (i=0; i<rd_count; i++)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Read record with type %d\n",
               rd[i].record_type);
    rb->type = htonl(rd[i].record_type);
    rb->expiration = GNUNET_TIME_absolute_hton(rd[i].expiration);
    rb->data_length = htonl(rd[i].data_size);
    rb->flags = htonl(rd[i].flags);
    memcpy(&rb[1], rd[i].data, rd[i].data_size);
    rb = &rb[1] + rd[i].data_size;
  }

  /**
   * FIXME magic number 20 move to config file
   * DHT_WAIT_TIMEOUT
   */
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20);
  
  /*
   * calculate DHT key: H(name) xor H(pubkey)
   */
  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&zone_hash, &name_hash, &xor_hash);
  GNUNET_CRYPTO_hash_to_enc (&xor_hash, &xor_hash_string);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "putting records for %s under key: %s with size %d\n",
             name, (char*)&xor_hash_string, rd_payload_length);

  GNUNET_DHT_put (dht_handle, &xor_hash,
                  5, //replication level
                  GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD, //FIXME todo block plugin
                  rd_payload_length,
                  (char*)nrb,
                  expiration,
                  timeout,
                  &record_dht_put, //FIXME continuation needed? success check? yes ofc
                  NULL); //cls for cont
  
  num_public_records++;

  /**
   * Reschedule periodic put
   */
  zone_update_taskid = GNUNET_SCHEDULER_add_delayed (dht_update_interval,
                                &update_zone_dht_next,
                                NULL);

}

/**
 * Puts a single trusted entity into the
 * namestore. Will be replaced in a testcase
 * that directly interacts with a persistent
 * namestore.
 *
 * @param name name of entity
 * @param keyfile keyfile
 */
void
put_trusted(char* name, char* keyfile)
{
  struct GNUNET_NAMESTORE_RecordData rd;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey;
  pkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (key, pkey);
  rd.data = pkey;
  rd.expiration = GNUNET_TIME_absolute_get_forever ();
  rd.data_size = sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded);
  rd.record_type = GNUNET_GNS_RECORD_PKEY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  zone_key,
                                  name,
                                  &rd,
                                  NULL,
                                  NULL);
}



/**
 * Periodically iterate over our zone and store everything in dht
 *
 * @param cls NULL
 * @param tc task context
 */
static void
update_zone_dht_start(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Starting DHT zone update!\n");
  if (0 == num_public_records)
  {
    dht_update_interval = GNUNET_TIME_relative_multiply(
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                      1);
  }
  else
  {
    dht_update_interval = GNUNET_TIME_relative_multiply(
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                     (3600/num_public_records));
  }
  num_public_records = 0; //start counting again
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (namestore_handle,
                                                          &zone_hash,
                                                          GNUNET_NAMESTORE_RF_AUTHORITY,
                                                          GNUNET_NAMESTORE_RF_PRIVATE,
                                                          &put_gns_record,
                                                          NULL);
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
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Initializing GNS\n");

  char* keyfile;
  char* trusted_entities;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (c, "gns",
                                             "ZONEKEY", &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No private key for root zone specified%s!\n", keyfile);
    GNUNET_SCHEDULER_shutdown(0);
    return;
  }

  zone_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (zone_key, &pkey);

  GNUNET_CRYPTO_hash(&pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (c, "gns",
                                            "HIJACK_DNS"))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "DNS hijacking enabled... connecting to service.\n");
    /**
     * Do gnunet dns init here
     */
    dns_handle = GNUNET_DNS_connect(c,
                                    GNUNET_DNS_FLAG_PRE_RESOLUTION,
                                    &handle_dns_request, /* rh */
                                    NULL); /* Closure */
    if (NULL == dns_handle)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to connect to the dnsservice!\n");
    }
  }

  

  /**
   * handle to our local namestore
   */
  namestore_handle = GNUNET_NAMESTORE_connect(c);

  if (NULL == namestore_handle)
  {
    //FIXME do error handling;
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to connect to the namestore!\n");
    GNUNET_SCHEDULER_shutdown(0);
    return;
  }
  
  char* trusted_start;
  char* trusted_name;
  char *trusted_key;
  int trusted_len;
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (c, "gns",
                                                      "TRUSTED",
                                                      &trusted_entities))
  {
    trusted_start = trusted_entities;
    trusted_len = strlen(trusted_entities);
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Found trusted entities in config file, importing\n");
    while ((trusted_entities-trusted_start) < trusted_len)
    {
      trusted_name = trusted_entities;
      while (*trusted_entities != ':')
        trusted_entities++;
      *trusted_entities = '\0';
      trusted_entities++;
      trusted_key = trusted_entities;
      while (*trusted_entities != ',' && (*trusted_entities != '\0'))
        trusted_entities++;
      *trusted_entities = '\0';
      trusted_entities++;
      
      if (GNUNET_YES == GNUNET_DISK_file_test (trusted_key))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Adding %s:%s to root zone\n",
                 trusted_name,
                 trusted_key);
        put_trusted(trusted_name, trusted_key);
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Keyfile %s does not exist!\n",
                   trusted_key);
        //put_trusted(trusted_name, trusted_key); //FIXME for testing
      }
    }

  }

  /**
   * handle to the dht
   */
  dht_handle = GNUNET_DHT_connect(c, 1); //FIXME get ht_len from cfg

  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not connect to DHT!\n");
  }

  put_some_records(); //FIXME for testing
  
  /**
   * Schedule periodic put
   * for our records
   * We have roughly an hour for all records;
   */
  dht_update_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                                      1);
  zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_start, NULL);

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
