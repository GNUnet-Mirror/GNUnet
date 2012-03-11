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

#define DHT_OPERATION_TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)
#define DHT_LOOKUP_TIMEOUT DHT_OPERATION_TIMEOUT
#define DHT_GNS_REPLICATION_LEVEL 5
#define MAX_DNS_LABEL_LENGTH 63

/* Ignore for now not used anyway and probably never will */
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT 24
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN 25
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT 26


struct AuthorityChain
{
  struct AuthorityChain *prev;

  struct AuthorityChain *next;

  GNUNET_HashCode zone;

  /* (local) name of the authority */
  char* name;

  /* was the ns entry fresh */
  int fresh;
};

/* handle to a resolution process */
struct GNUNET_GNS_ResolverHandle;

/**
 * processor for a resultion result
 *
 * @param cls the closure
 * @param rh the resolution handle
 * @param rd_count number of results
 * @pram rd resukt data
 */
typedef void (*ResolutionResultProcessor) (void *cls,
                                  struct GNUNET_GNS_ResolverHandle *rh,
                                  uint32_t rd_count,
                                  const struct GNUNET_NAMESTORE_RecordData *rd);

/**
 * Resoltion status indicator
 * EXISTS: the name to lookup exists
 * EXPIRED: the name in the record expired
 */
enum ResolutionStatus
{
  EXISTS = 1,
  EXPIRED = 2
};

/**
 * Handle to a currenty pending resolution
 */
struct GNUNET_GNS_ResolverHandle
{
  /* The name to resolve */
  char *name;

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

  /* timeout task for dht lookups */
  GNUNET_SCHEDULER_TaskIdentifier dht_timeout_task;

  /* called when resolution phase finishes */
  ResolutionResultProcessor proc;
  
  /* closure passed to proc */
  void* proc_cls;

  /* DLL to store the authority chain */
  struct AuthorityChain *authority_chain_head;

  /* DLL to store the authority chain */
  struct AuthorityChain *authority_chain_tail;
  
  /* status of the resolution result */
  enum ResolutionStatus status;

};

/**
 * Handle to a record lookup
 */
struct RecordLookupHandle
{
  /* the record type to look up */
  enum GNUNET_GNS_RecordType record_type;

  /* the name to look up */
  char *name;

  /* Method to call on record resolution result */
  ResolutionResultProcessor proc;

  /* closure to pass to proc */
  void* proc_cls;

};

/**
 * Handle to a shorten operation from api
 */
struct ClientShortenHandle
{
  /* the requesting client that */
  struct GNUNET_SERVER_Client *client;

  /* request id */
  uint64_t unique_id;

  /* request type */
  enum GNUNET_GNS_RecordType type;

  /* name to shorten */
  char* name;

};

/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{
  /* the requesting client that */
  struct GNUNET_SERVER_Client *client;

  /* request id */
  uint64_t unique_id;

  /* request type */
  enum GNUNET_GNS_RecordType type;

  /* the name to look up */
  char* name; //Needed?
};

/**
 * Handle to a DNS intercepted
 * reslution request
 */
struct InterceptLookupHandle
{
  /* the request handle to reply to */
  struct GNUNET_DNS_RequestHandle *request_handle;
  
  /* the dns parser packet received */
  struct GNUNET_DNSPARSER_Packet *packet;
  
  /* the query parsed from the packet */
  struct GNUNET_DNSPARSER_Query *query;
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

/* dht update interval FIXME define? */
static struct GNUNET_TIME_Relative dht_update_interval;

/* zone update task */
GNUNET_SCHEDULER_TaskIdentifier zone_update_taskid = GNUNET_SCHEDULER_NO_TASK;

/**
 * Helper function to free resolver handle
 *
 * @rh the handle to free
 */
static void
free_resolver_handle(struct GNUNET_GNS_ResolverHandle* rh)
{
  struct AuthorityChain *ac;
  struct AuthorityChain *ac_next;

  if (NULL == rh)
    return;

  GNUNET_free_non_null (rh->name);
  GNUNET_free_non_null (rh->authority_name);

  ac = rh->authority_chain_head;

  while (NULL != ac)
  {
    ac_next = ac->next;
    GNUNET_free_non_null (ac->name);
    GNUNET_free(ac);
    ac = ac_next;
  }
  GNUNET_free(rh);
}


/**
 * Reply to dns request with the result from our lookup.
 *
 * @param cls the closure to the request (an InterceptLookupHandle)
 * @param rh the request handle of the lookup
 * @param rd_count the number of records to return
 * @param rd the record data
 */
static void
reply_to_dns(void* cls, struct GNUNET_GNS_ResolverHandle *rh, uint32_t rd_count,
             const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  size_t len;
  int ret;
  char *buf;
  struct InterceptLookupHandle* ilh = (struct InterceptLookupHandle*)cls;
  struct GNUNET_DNSPARSER_Packet *packet = ilh->packet;
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
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "QName: %s\n", ilh->query->name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record %d/%d\n", i+1, rd_count);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record len %d\n", rd[i].data_size);
    
    if (rd[i].record_type == ilh->query->type)
    {
      answer_records[i].name = ilh->query->name;
      answer_records[i].type = rd[i].record_type;
      answer_records[i].data.raw.data_len = rd[i].data_size;
      answer_records[i].data.raw.data = (char*)rd[i].data;
      answer_records[i].expiration_time = rd[i].expiration;
      answer_records[i].class = GNUNET_DNSPARSER_CLASS_INTERNET;//hmmn
    }
    else
    {
      additional_records[i].name = ilh->query->name;
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
    GNUNET_DNS_request_answer(ilh->request_handle,
                              len,
                              buf);

    GNUNET_free(buf);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Answered DNS request\n");
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Error building DNS response! (ret=%d)", ret);
  }
  
  packet->num_answers = 0;
  packet->answers = NULL;
  packet->num_additional_records = 0;
  packet->additional_records = NULL;
  GNUNET_DNSPARSER_free_packet(packet);
  //FIXME free more!
  GNUNET_free((struct RecordLookupHandle*)rh->proc_cls);
  free_resolver_handle(rh);
  GNUNET_free(ilh);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Shutting down!");
  /* Kill zone task for it may make the scheduler hang */
  if (zone_update_taskid)
    GNUNET_SCHEDULER_cancel(zone_update_taskid);
  
  GNUNET_SERVER_notification_context_destroy (nc);
  
  if (dns_handle)
    GNUNET_DNS_disconnect(dns_handle);
  
  GNUNET_NAMESTORE_disconnect(namestore_handle, 1);
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
 * Handle timeout for DHT requests
 *
 * @param cls the request handle as closure
 * @param tc the task context
 */
static void
dht_lookup_timeout(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_ResolverHandle *rh = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "dht lookup for query %s timed out.\n",
             rh->name);

  GNUNET_DHT_get_stop (rh->get_handle);
  rh->proc(rh->proc_cls, rh, 0, NULL);
}


/**
 * Function called when we get a result from the dht
 * for our record query
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
static void
process_record_dht_result(void* cls,
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
  struct RecordLookupHandle *rlh;
  struct GNSNameRecordBlock *nrb;
  uint32_t num_records;
  char* name = NULL;
  char* rd_data = (char*)data;
  int i;
  int rd_size;
  
  GNUNET_HashCode zone, name_hash;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "got dht result (size=%d)\n", size);
  
  if (data == NULL)
    return;

  //FIXME maybe check expiration here, check block type
  
  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  rlh = (struct RecordLookupHandle *) rh->proc_cls;
  nrb = (struct GNSNameRecordBlock*)data;
  
  /* stop lookup and timeout task */
  GNUNET_DHT_get_stop (rh->get_handle);
  GNUNET_SCHEDULER_cancel(rh->dht_timeout_task);
  
  rh->get_handle = NULL;
  name = (char*)&nrb[1];
  num_records = ntohl(nrb->rd_count);
  {
    struct GNUNET_NAMESTORE_RecordData rd[num_records];

    rd_data += strlen(name) + 1 + sizeof(struct GNSNameRecordBlock);
    rd_size = size - strlen(name) - 1 - sizeof(struct GNSNameRecordBlock);
  
    if (GNUNET_SYSERR == GNUNET_NAMESTORE_records_deserialize (rd_size,
                                                               rd_data,
                                                               num_records,
                                                               rd))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error deserializing data!\n");
      return;
    }

    for (i=0; i<num_records; i++)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got name: %s (wanted %s)\n", name, rh->name);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got type: %d\n",
               rd[i].record_type);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got data length: %d\n", rd[i].data_size);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got flag %d\n", rd[i].flags);
    
     if ((strcmp(name, rh->name) == 0) &&
         (rd[i].record_type == rlh->record_type))
      {
        rh->answered++;
      }

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
      rh->proc(rh->proc_cls, rh, num_records, rd);
    else
      rh->proc(rh->proc_cls, rh, 0, NULL);
  }

}


/**
 * Start DHT lookup for a (name -> query->record_type) record in
 * rh->authority's zone
 *
 * @param rh the pending gns query context
 */
static void
resolve_record_dht(struct GNUNET_GNS_ResolverHandle *rh)
{
  uint32_t xquery;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;
  struct GNUNET_CRYPTO_HashAsciiEncoded lookup_key_string;
  struct RecordLookupHandle *rlh = (struct RecordLookupHandle *)rh->proc_cls;

  GNUNET_CRYPTO_hash(rh->name, strlen(rh->name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, &rh->authority, &lookup_key);
  GNUNET_CRYPTO_hash_to_enc (&lookup_key, &lookup_key_string);
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "starting dht lookup for %s with key: %s\n",
             rh->name, (char*)&lookup_key_string);

  rh->dht_timeout_task = GNUNET_SCHEDULER_add_delayed(DHT_LOOKUP_TIMEOUT,
                                                      &dht_lookup_timeout, rh);

  xquery = htonl(rlh->record_type);
  rh->get_handle = GNUNET_DHT_get_start(dht_handle, 
                       DHT_OPERATION_TIMEOUT,
                       GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                       &lookup_key,
                       DHT_GNS_REPLICATION_LEVEL,
                       GNUNET_DHT_RO_NONE,
                       &xquery, 
                       sizeof(xquery),
                       &process_record_dht_result,
                       rh);

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
process_record_lookup_ns(void* cls,
                  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                  struct GNUNET_TIME_Absolute expiration,
                  const char *name, unsigned int rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd,
                  const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct RecordLookupHandle *rlh;
  struct GNUNET_TIME_Relative remaining_time;
  GNUNET_HashCode zone;

  rh = (struct GNUNET_GNS_ResolverHandle *) cls;
  rlh = (struct RecordLookupHandle *)rh->proc_cls;
  GNUNET_CRYPTO_hash(key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);

  rh->status = 0;
  
  if (name != NULL)
  {
    rh->status |= EXISTS;
  }
  
  if (remaining_time.rel_value == 0)
  {
    rh->status |= EXPIRED;
  }
  
  if (rd_count == 0)
  {
    /**
     * Lookup terminated and no results
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Namestore lookup for %s terminated without results\n", name);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Record %s unknown in namestore\n",
               rh->name);
    /**
     * Our zone and no result? Cannot resolve TT
     */
    rh->proc(rh->proc_cls, rh, 0, NULL);
    return;

  }
  else
  {
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Processing additional result %s from namestore\n", name);
    int i;
    for (i=0; i<rd_count;i++)
    {
      
      if (rd[i].record_type != rlh->record_type)
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
     */
    if (rh->answered == 0)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
                 "No answers found. This is odd!\n");
      rh->proc(rh->proc_cls, rh, 0, NULL);
      return;
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Found %d answer(s) to query!\n",
               rh->answered);

    rh->proc(rh->proc_cls, rh, rd_count, rd);
  }
}


/**
 * The final phase of resolution.
 * rh->name is a name that is canonical and we do not have a delegation.
 * Query namestore for this record
 *
 * @param rh the pending lookup
 */
static void
resolve_record_ns(struct GNUNET_GNS_ResolverHandle *rh)
{
  struct RecordLookupHandle *rlh = (struct RecordLookupHandle *)rh->proc_cls;
  
  /**
   * Try to resolve this record in our namestore.
   * The name to resolve is now in rh->authority_name
   * since we tried to resolve it to an authority
   * and failed.
   **/
  GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 &rh->authority,
                                 rh->name,
                                 rlh->record_type,
                                 &process_record_lookup_ns,
                                 rh);
}


/**
 * Handle timeout for DHT requests
 *
 * @param cls the request handle as closure
 * @param tc the task context
 */
static void
dht_authority_lookup_timeout(void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_ResolverHandle *rh = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "dht lookup for query %s timed out.\n",
             rh->name);

  GNUNET_DHT_get_stop (rh->get_handle);
  if (strcmp(rh->name, "") == 0)
  {
    /*
     * promote authority back to name and try to resolve record
     */
    strcpy(rh->name, rh->authority_name);
  }
  rh->proc(rh->proc_cls, rh, 0, NULL);
}

/* Prototype */
static void resolve_delegation_dht(struct GNUNET_GNS_ResolverHandle *rh);

/**
 * Function called when we get a result from the dht
 * for our query. Recursively tries to resolve authorities
 * for name in DHT.
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
static void
process_delegation_result_dht(void* cls,
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
  uint32_t num_records;
  char* name = NULL;
  char* rd_data = (char*) data;
  int i;
  int rd_size;
  GNUNET_HashCode zone, name_hash;
  
  if (data == NULL)
    return;
  
  //FIXME check expiration?
  
  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  nrb = (struct GNSNameRecordBlock*)data;
  
  /* stop dht lookup and timeout task */
  GNUNET_DHT_get_stop (rh->get_handle);
  GNUNET_SCHEDULER_cancel(rh->dht_timeout_task);

  rh->get_handle = NULL;
  num_records = ntohl(nrb->rd_count);
  name = (char*)&nrb[1];
  {
    struct GNUNET_NAMESTORE_RecordData rd[num_records];
    
    rd_data += strlen(name) + 1 + sizeof(struct GNSNameRecordBlock);
    rd_size = size - strlen(name) - 1 - sizeof(struct GNSNameRecordBlock);
  
    if (GNUNET_SYSERR == GNUNET_NAMESTORE_records_deserialize (rd_size,
                                                               rd_data,
                                                               num_records,
                                                               rd))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error deserializing data!\n");
      return;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got name: %s (wanted %s)\n", name, rh->authority_name);
    for (i=0; i<num_records; i++)
    {
    
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                "Got name: %s (wanted %s)\n", name, rh->authority_name);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Got type: %d (wanted %d)\n",
                 rd[i].record_type, GNUNET_GNS_RECORD_PKEY);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Got data length: %d\n", rd[i].data_size);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Got flag %d\n", rd[i].flags);

      if ((strcmp(name, rh->authority_name) == 0) &&
          (rd[i].record_type == GNUNET_GNS_RECORD_PKEY))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Authority found in DHT\n");
        rh->answered = 1;
        memcpy(&rh->authority, rd[i].data, sizeof(GNUNET_HashCode));
        struct AuthorityChain *auth =
          GNUNET_malloc(sizeof(struct AuthorityChain));
        auth->zone = rh->authority;
        auth->name = GNUNET_malloc(strlen(rh->authority_name)+1);
        memset(auth->name, 0, strlen(rh->authority_name)+1);
        strcpy(auth->name, rh->authority_name);
        GNUNET_CONTAINER_DLL_insert (rh->authority_chain_head,
                                     rh->authority_chain_tail,
                                     auth);
      }

    }


    GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
    GNUNET_CRYPTO_hash_xor(key, &name_hash, &zone);

    /* Save to namestore */
    if (0 != GNUNET_CRYPTO_hash_cmp(&zone_hash, &zone))
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
  }
  
  if (rh->answered)
  {
    rh->answered = 0;
    /**
     * delegate
     * FIXME in this case. should we ask namestore again?
     */
    if (strcmp(rh->name, "") == 0)
      rh->proc(rh->proc_cls, rh, 0, NULL);
    else
      resolve_delegation_dht(rh);
    return;
  }

  /**
   * should never get here unless false dht key/put
   * block plugin should handle this
   **/
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "DHT authority lookup error!\n");
  GNUNET_break(0);
}


/**
 * Process DHT lookup result for record.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results (always 0)
 * @param rd record data (always NULL)
 */
static void
process_record_result_dht(void* cls, struct GNUNET_GNS_ResolverHandle *rh,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*)cls;
  if (rd_count == 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "No records for %s found in DHT. Aborting\n",
               rh->name);
    /* give up, cannot resolve */
    rlh->proc(rlh->proc_cls, rh, 0, NULL);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Record resolved from namestore!");
  rlh->proc(rlh->proc_cls, rh, rd_count, rd);

}


/**
 * Process namestore lookup result for record.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results (always 0)
 * @param rd record data (always NULL)
 */
static void
process_record_result_ns(void* cls, struct GNUNET_GNS_ResolverHandle *rh,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  if (rd_count == 0)
  {
    /* ns entry expired. try dht */
    if (rh->status & (EXPIRED | !EXISTS))
    {
      rh->proc = &process_record_result_dht;
      resolve_record_dht(rh);
      return;
    }
    /* give up, cannot resolve */
    rlh->proc(rlh->proc_cls, rh, 0, NULL);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Record resolved from namestore!");
  rlh->proc(rlh->proc_cls, rh, rd_count, rd);

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
static int
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
 * @param dest the destination where the tld will be put
 */
void
pop_tld(char* name, char* dest)
{
  uint32_t len;

  if (is_canonical(name))
  {
    strcpy(dest, name);
    strcpy(name, "");
    return;
  }

  for (len = strlen(name); len > 0; len--)
  {
    if (*(name+len) == '.')
      break;
  }
  
  //Was canonical?
  if (len == 0)
    return;

  name[len] = '\0';

  strcpy(dest, (name+len+1));
}

/**
 * DHT resolution for delegation finished. Processing result.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results (always 0)
 * @param rd record data (always NULL)
 */
static void
process_delegation_dht(void* cls, struct GNUNET_GNS_ResolverHandle *rh,
                          unsigned int rd_count,
                          const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  
  if (strcmp(rh->name, "") == 0)
  {
    /* We resolved full name for delegation. resolving record */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Resolved full name for delegation via DHT. resolving record '' in ns\n");
    rh->proc = &process_record_result_ns;
    resolve_record_ns(rh);
    return;
  }

  /**
   * we still have some left
   **/
  if (is_canonical(rh->name))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Resolving canonical record %s in ns\n", rh->name);
    rh->proc = &process_record_result_ns;
    resolve_record_ns(rh);
    return;
  }
  /* give up, cannot resolve */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Cannot fully resolve delegation for %s via DHT!\n",
             rh->name);
  rlh->proc(rlh->proc_cls, rh, 0, NULL);
}


/**
 * Start DHT lookup for a name -> PKEY (compare NS) record in
 * rh->authority's zone
 *
 * @param rh the pending gns query
 * @param name the name of the PKEY record
 */
static void
resolve_delegation_dht(struct GNUNET_GNS_ResolverHandle *rh)
{
  uint32_t xquery;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  GNUNET_CRYPTO_hash(rh->authority_name,
                     strlen(rh->authority_name),
                     &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, &rh->authority, &lookup_key);

  rh->dht_timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
                                                  &dht_authority_lookup_timeout,
                                                       rh);

  xquery = htonl(GNUNET_GNS_RECORD_PKEY);
  
  rh->get_handle = GNUNET_DHT_get_start(dht_handle,
                       DHT_OPERATION_TIMEOUT,
                       GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                       &lookup_key,
                       DHT_GNS_REPLICATION_LEVEL,
                       GNUNET_DHT_RO_NONE,
                       &xquery,
                       sizeof(xquery),
                       &process_delegation_result_dht,
                       rh);

}


/**
 * Namestore resolution for delegation finished. Processing result.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results (always 0)
 * @param rd record data (always NULL)
 */
static void
process_delegation_ns(void* cls, struct GNUNET_GNS_ResolverHandle *rh,
                          unsigned int rd_count,
                          const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  
  if (strcmp(rh->name, "") == 0)
  {
    /* We resolved full name for delegation. resolving record */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Resolved full name for delegation. resolving record ''\n");
    rh->proc = &process_record_result_ns;
    resolve_record_ns(rh);
    return;
  }

  /**
   * we still have some left
   * check if ns entry is fresh
   **/
  if (rh->status & (EXISTS | !EXPIRED))
  {
    if (is_canonical(rh->name))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Resolving canonical record %s\n", rh->name);
      rh->proc = &process_record_result_ns;
      resolve_record_ns(rh);
    }
    else
    {
      /* give up, cannot resolve */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Cannot fully resolve delegation for %s!\n",
                 rh->name);
      rlh->proc(rlh->proc_cls, rh, 0, NULL);
    }
    return;
  }
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Trying to resolve delegation for %s via DHT\n",
             rh->name);
  rh->proc = &process_delegation_dht;
  resolve_delegation_dht(rh);
}

//Prototype
static void resolve_delegation_ns(struct GNUNET_GNS_ResolverHandle *rh);

/**
 * This is a callback function that should give us only PKEY
 * records. Used to query the namestore for the authority (PKEY)
 * for 'name'. It will recursively try to resolve the
 * authority for a given name from the namestore.
 *
 * @param cls the pending query
 * @param key the key of the zone we did the lookup
 * @param expiration expiration date of the record data set in the namestore
 * @param name the name for which we need an authority
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 * @param signature the signature of the authority for the record data
 */
static void
process_delegation_result_ns(void* cls,
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
  char* new_name;
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got %d records from authority lookup\n",
             rd_count);

  rh = (struct GNUNET_GNS_ResolverHandle *)cls;
  GNUNET_CRYPTO_hash(key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);
  
  rh->status = 0;
  
  if (name != NULL)
  {
    rh->status |= EXISTS;
  }
  
  if (remaining_time.rel_value == 0)
  {
    rh->status |= EXPIRED;
  }
  
  /**
   * No authority found in namestore.
   */
  if (rd_count == 0)
  {
    /**
     * We did not find an authority in the namestore
     */
    
    /**
     * No PKEY in zone.
     * Promote this authority back to a name maybe it is
     * our record.
     */
    if (strcmp(rh->name, "") == 0)
    {
      /* simply promote back */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Promoting %s back to name\n", rh->authority_name);
      strcpy(rh->name, rh->authority_name);
    }
    else
    {
      /* add back to existing name */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Adding %s back to %s\n",
                 rh->authority_name, rh->name);
      new_name = GNUNET_malloc(strlen(rh->name)
                               + strlen(rh->authority_name) + 2);
      memset(new_name, 0, strlen(rh->name) + strlen(rh->authority_name) + 2);
      strcpy(new_name, rh->name);
      strcpy(new_name+strlen(new_name)+1, ".");
      strcpy(new_name+strlen(new_name)+2, rh->authority_name);
      GNUNET_free(rh->name);
      rh->name = new_name;
    }
    rh->proc(rh->proc_cls, rh, 0, NULL);
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
                   "This dht entry is expired.\n");
        rh->authority_chain_head->fresh = 0;
        rh->proc(rh->proc_cls, rh, 0, NULL);
        return;
      }

      continue;
    }

    /**
     * Resolve rest of query with new authority
     */
    GNUNET_assert(rd[i].record_type == GNUNET_GNS_RECORD_PKEY);
    memcpy(&rh->authority, rd[i].data, sizeof(GNUNET_HashCode));
    struct AuthorityChain *auth = GNUNET_malloc(sizeof(struct AuthorityChain));
    auth->zone = rh->authority;
    auth->name = GNUNET_malloc(strlen(rh->authority_name)+1);
    memset(auth->name, 0, strlen(rh->authority_name)+1);
    strcpy(auth->name, rh->authority_name);
    GNUNET_CONTAINER_DLL_insert (rh->authority_chain_head,
                                 rh->authority_chain_tail,
                                 auth);
    
    /**
     * We are done with PKEY resolution if name is empty
     * else resolve again with new authority
     */
    if (strcmp(rh->name, "") == 0)
      rh->proc(rh->proc_cls, rh, 0, NULL);
    else
      resolve_delegation_ns(rh);
    return;
  }
    
  /**
   * no answers found
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Authority lookup successful but no PKEY... never get here\n");
  rh->proc(rh->proc_cls, rh, 0, NULL);
}


/**
 * Resolve the delegation chain for the request in our namestore
 *
 * @param rh the resolver handle
 */
static void
resolve_delegation_ns(struct GNUNET_GNS_ResolverHandle *rh)
{
  
  pop_tld(rh->name, rh->authority_name);
  GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 &rh->authority,
                                 rh->authority_name,
                                 GNUNET_GNS_RECORD_PKEY,
                                 &process_delegation_result_ns,
                                 rh);

}

/**
 * Entry point for name resolution
 * Setup a new query and try to resolve
 *
 * @param request the request handle of the DNS request from a client
 * @param p the DNS query packet we received
 * @param q the DNS query we received parsed from p
 */
static void
start_resolution_for_dns(struct GNUNET_DNS_RequestHandle *request,
                          struct GNUNET_DNSPARSER_Packet *p,
                          struct GNUNET_DNSPARSER_Query *q)
{
  struct GNUNET_GNS_ResolverHandle *rh;
  struct RecordLookupHandle* rlh;
  struct InterceptLookupHandle* ilh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              q->name, q->type);
  
  rh = GNUNET_malloc(sizeof (struct GNUNET_GNS_ResolverHandle));
  rlh = GNUNET_malloc(sizeof(struct RecordLookupHandle));
  ilh = GNUNET_malloc(sizeof(struct InterceptLookupHandle));
  ilh->packet = p;
  ilh->query = q;
  ilh->request_handle = request;
  
  rh->authority = zone_hash;

  rlh->record_type = q->type;
  rlh->name = q->name;
  rlh->proc = &reply_to_dns;
  rlh->proc_cls = ilh;

  rh->proc_cls = rlh;
  
  rh->name = GNUNET_malloc(strlen(q->name)
                              - strlen(gnunet_tld) + 1);
  memset(rh->name, 0,
         strlen(q->name)-strlen(gnunet_tld) + 1);
  memcpy(rh->name, q->name,
         strlen(q->name)-strlen(gnunet_tld));

  rh->authority_name = GNUNET_malloc(sizeof(char)*MAX_DNS_LABEL_LENGTH);
  
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_head->prev = NULL;
  rh->authority_chain_head->next = NULL;
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone_hash;

  /* Start resolution in our zone */
  rh->proc = &process_delegation_ns;
  resolve_delegation_ns(rh);
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
static void
handle_dns_request(void *cls,
                   struct GNUNET_DNS_RequestHandle *rh,
                   size_t request_length,
                   const char *request)
{
  struct GNUNET_DNSPARSER_Packet *p;
  int i;
  char *tldoffset;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hijacked a DNS request...processing\n");
  p = GNUNET_DNSPARSER_parse (request, request_length);
  
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (p);
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
    GNUNET_DNSPARSER_free_packet(p);
    return;
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
  tldoffset = p->queries[0].name + strlen(p->queries[0].name) - 1;
  
  for (i=0; i<strlen(p->queries[0].name); i++)
  {
    if (*(tldoffset-i) == '.')
      break;
  }
  
  if ((i==strlen(gnunet_tld)-1) && (0 == strcmp(tldoffset-i, gnunet_tld)))
  {
    start_resolution_for_dns(rh, p, p->queries);
  }
  else
  {
    /**
     * This request does not concern us. Forward to real DNS.
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Request for %s is forwarded to DNS\n", p->queries[0].name);
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (p);
  }

}

/**
 * Method called periodicattluy that triggers
 * iteration over root zone
 *
 * @param cls closure
 * @param tc task context
 */
static void
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
static void
record_dht_put(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "put request transmitted\n");
}

/* prototype */
static void
update_zone_dht_start(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

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
put_gns_record(void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  
  struct GNSNameRecordBlock *nrb;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;
  struct GNUNET_CRYPTO_HashAsciiEncoded xor_hash_string;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;

  /* we're done */
  if (NULL == name)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Zone iteration finished\n");
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_start,
                                                   NULL);
    return;
  }
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Putting records for %s into the DHT\n", name);
  
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  
  nrb = GNUNET_malloc(rd_payload_length + strlen(name) + 1 
                      + sizeof(struct GNSNameRecordBlock));
  
  if (signature != NULL)
    nrb->signature = *signature;
  
  nrb->public_key = *key;

  nrb->rd_count = htonl(rd_count);
  
  memset(&nrb[1], 0, strlen(name) + 1);
  memcpy(&nrb[1], name, strlen(name));

  nrb_data = (char*)&nrb[1];
  nrb_data += strlen(name) + 1;

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen(name) + 1;

  if (-1 == GNUNET_NAMESTORE_records_serialize (rd_count,
                                                rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Record serialization failed!\n");
    GNUNET_free(nrb);
    return;
    //FIXME what to do
  }


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
                  DHT_GNS_REPLICATION_LEVEL,
                  GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
                  expiration,
                  DHT_OPERATION_TIMEOUT,
                  &record_dht_put,
                  NULL); //cls for cont
  
  num_public_records++;

  /**
   * Reschedule periodic put
   */
  zone_update_taskid = GNUNET_SCHEDULER_add_delayed (dht_update_interval,
                                &update_zone_dht_next,
                                NULL);

  GNUNET_free(nrb);

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

//Prototype
static void send_shorten_response(const char* name,
                                  struct ClientShortenHandle *csh);
static void
process_shorten_pseu_lookup_ns(void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_ResolverHandle *rh = 
    (struct GNUNET_GNS_ResolverHandle *)cls;
  struct GNUNET_TIME_Relative remaining_time;

  GNUNET_TIME_absolute_get_remaining (expire);
  rh->status = 0;
  
  if (name != NULL)
  {
    rh->status |= EXISTS;
  }
  
  if (remaining_time.rel_value == 0)
  {
    rh->status |= EXPIRED;
  }

  rh->proc(rh->proc_cls, rh, rd_len, rd);
}


/**
 * Start DHT lookup for a PSEUdonym record in
 * rh->authority's zone
 *
 * @param rh the pending gns query
 */
static void
resolve_pseu_dht(struct GNUNET_GNS_ResolverHandle *rh)
{
  uint32_t xquery;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  //Empty string
  GNUNET_CRYPTO_hash("",
                     1,
                     &name_hash);

  GNUNET_CRYPTO_hash_xor(&name_hash, &rh->authority, &lookup_key);

  rh->dht_timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
                                                  &dht_lookup_timeout,
                                                  rh);

  xquery = htonl(GNUNET_GNS_RECORD_PSEU);
  
  rh->get_handle = GNUNET_DHT_get_start(dht_handle,
                       DHT_OPERATION_TIMEOUT,
                       GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                       &lookup_key,
                       DHT_GNS_REPLICATION_LEVEL,
                       GNUNET_DHT_RO_NONE,
                       &xquery,
                       sizeof(xquery),
                       &process_delegation_result_dht,
                       rh);

}

//Prototype
static void
handle_shorten_pseu_ns_result(void* cls,
                              struct GNUNET_GNS_ResolverHandle *rh,
                              uint32_t rd_count,
                              const struct GNUNET_NAMESTORE_RecordData *rd);

static void
handle_shorten_zone_to_name(void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_ResolverHandle *rh = 
    (struct GNUNET_GNS_ResolverHandle *)cls;
  struct ClientShortenHandle* csh = (struct ClientShortenHandle*) rh->proc_cls;

  char* result;
  size_t answer_len;
  
  /* we found a match in our own zone */
  if (rd_len != 0)
  {
    answer_len = strlen(rh->name) + strlen(name) + strlen(gnunet_tld) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, name);
    strcpy(result+strlen(rh->name)+strlen(name), gnunet_tld);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending shorten result %s\n", result);

    send_shorten_response(result, csh);
    free_resolver_handle(rh);
    GNUNET_free(result);
  }
  else
  {
    /**
     * Nothing in our zone
     * check PSEU for this authority in namestore
     */
    rh->proc = &handle_shorten_pseu_ns_result;
    GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                   &rh->authority_chain_head->zone,
                                   "",
                                   GNUNET_GNS_RECORD_PSEU,
                                   &process_shorten_pseu_lookup_ns,
                                   rh);
  }
}

/**
 * Process result from namestore delegation lookup
 * for shorten operation
 *
 * @param cls the client shorten handle
 * @param rh the resolver handle
 * @param rd_count number of results (0)
 * @param rd data (NULL)
 */
void
handle_shorten_pseu_dht_result(void* cls,
                      struct GNUNET_GNS_ResolverHandle *rh,
                      uint32_t rd_len,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientShortenHandle* csh = (struct ClientShortenHandle*) cls;
  struct AuthorityChain *auth_chain;
  char* pseu;
  char* result;
  char* new_name;
  size_t answer_len;
  int i;
  
  /**
   * PSEU found
   */
  if (rd_len != 0)
  {
    for (i=0; i < rd_len; i++)
    {
      if (rd[i].record_type == GNUNET_GNS_RECORD_PSEU)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "Found PSEU %s\n", (char*) rd[i].data);
        break;
      }
    }

    pseu = (char*) rd[i].data;
    answer_len = strlen(rh->name) + strlen(pseu) + strlen(gnunet_tld) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, pseu);
    strcpy(result+strlen(rh->name)+strlen(pseu), gnunet_tld);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending pseudonym shorten result %s\n", result);
    
    send_shorten_response(result, csh);
    free_resolver_handle(rh);
    GNUNET_free(result);
    return;
  }
  
  /**
   * No PSEU found.
   * continue with next authority
   * backtrack
   */
  auth_chain = rh->authority_chain_head;

  if ((auth_chain->next->next == NULL) &&
      GNUNET_CRYPTO_hash_cmp(&auth_chain->next->zone, &zone_hash) == 0)
  {
    /**
     * Our zone is next
     */
    answer_len = strlen(rh->name) + strlen(auth_chain->name)
      + strlen(gnunet_tld) + 2;

    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, auth_chain->name);
    strcpy(result+strlen(rh->name)+strlen(auth_chain->name)+1, gnunet_tld);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending non pseudonym shorten result %s\n", result);
    
    send_shorten_response(result, csh);
    free_resolver_handle(rh);
    GNUNET_free(result);
    return;
  }

  /**
   * Continue with next authority
   */
  new_name = GNUNET_malloc(strlen(rh->name)+
                           strlen(auth_chain->name) + 2);
  memset(new_name, 0, strlen(rh->name)+
                      strlen(auth_chain->name) + 2);
  strcpy(new_name, rh->name);
  strcpy(new_name+strlen(rh->name)+1, ".");
  strcpy(new_name+strlen(rh->name)+2, auth_chain->name);
  GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                              rh->authority_chain_tail,
                              auth_chain);
  GNUNET_free(rh->name);
  rh->name = new_name;
  GNUNET_free(auth_chain->name);
  GNUNET_free(auth_chain);
  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &zone_hash,
                                 &rh->authority_chain_head->zone,
                                 &handle_shorten_zone_to_name,
                                 rh);

}



/**
 * Process result from namestore PSEU lookup
 * for shorten operation
 * FIXME do we need to check for own zone here?
 *
 * @param cls the client shorten handle
 * @param rh the resolver handle
 * @param rd_count number of results (0 if none found)
 * @param rd data (NULL if none found)
 */
static void
handle_shorten_pseu_ns_result(void* cls,
                      struct GNUNET_GNS_ResolverHandle *rh,
                      uint32_t rd_len,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientShortenHandle* csh = (struct ClientShortenHandle*) cls;
  struct AuthorityChain *auth_chain;
  char* pseu;
  char* result;
  char* new_name;
  size_t answer_len;
  int i;
  
  /**
   * PSEU found
   */
  if (rd_len != 0)
  {
    for (i=0; i < rd_len; i++)
    {
      if (rd[i].record_type == GNUNET_GNS_RECORD_PSEU)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "Found PSEU %s\n", (char*) rd[i].data);
        break;
      }
    }
    
    pseu = (char*) rd[i].data;
    answer_len = strlen(rh->name) + strlen(pseu) + strlen(gnunet_tld) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, pseu);
    strcpy(result+strlen(rh->name)+strlen(pseu)+1, gnunet_tld);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending shorten result %s\n", result);
    
    send_shorten_response(result, csh);
    free_resolver_handle(rh);
    GNUNET_free(result);
    return;
  }
  
  /**
   * No PSEU found. Ask DHT if expired.
   * Else contunue with next authority
   */
  if (rh->status & (EXISTS | !EXPIRED))
  {
    /**
     * backtrack
     */
    auth_chain = rh->authority_chain_head;
    new_name = GNUNET_malloc(strlen(rh->name)+
                             strlen(auth_chain->name) + 2);
    memset(new_name, 0, strlen(rh->name)+
                        strlen(auth_chain->name) + 2);
    strcpy(new_name, rh->name);
    strcpy(new_name+strlen(rh->name)+1, ".");
    strcpy(new_name+strlen(rh->name)+2, auth_chain->name);
    
    GNUNET_free(rh->name);
    rh->name = new_name;
    GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                                rh->authority_chain_tail,
                                auth_chain);

    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   &zone_hash,
                                   &rh->authority_chain_head->zone,
                                   &handle_shorten_zone_to_name,
                                   rh);
    return;
  }

  /**
   * Ask DHT
   */
  rh->authority = rh->authority_chain_head->zone;
  rh->proc = &handle_shorten_pseu_dht_result;
  resolve_pseu_dht(rh);

}



/**
 * Process result from namestore delegation lookup
 * for shorten operation
 *
 * @param cls the client shorten handle
 * @param rh the resolver handle
 * @param rd_count number of results (0)
 * @param rd data (NULL)
 */
void
handle_shorten_delegation_result(void* cls,
                      struct GNUNET_GNS_ResolverHandle *rh,
                      uint32_t rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientShortenHandle* csh = (struct ClientShortenHandle*) cls;
  struct AuthorityChain *auth_chain;
  char* result;
  size_t answer_len;
  
  /**
   * At this point rh->name contains the part of the name
   * that we do not have a PKEY in our namestore to resolve.
   * The authority chain in the resolver handle is now
   * useful to backtrack if needed
   */
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "PKEY resolved as far as possible in ns up to %s!\n", rh->name);

  if (GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_head->zone,
                             &zone_hash) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     **/
    
    answer_len = strlen(rh->name) + strlen(gnunet_tld) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, gnunet_tld);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Sending name as shorten result %s\n", rh->name);
    
    send_shorten_response(rh->name, csh); //FIXME +.gnunet!
    free_resolver_handle(rh);
    GNUNET_free(csh->name);
    GNUNET_free(csh);
    GNUNET_free(result);
    return;
  }
  
  auth_chain = rh->authority_chain_head;
  /* backtrack authorities for pseu */
  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &zone_hash, //ours
                                 &auth_chain->zone,
                                 &handle_shorten_zone_to_name,
                                 rh);

}

typedef void (*ShortenResponseProc) (void* cls, const char* name);

/**
 * Shorten a given name
 *
 * @param name the name to shorten
 * @param csh the shorten handle of the request
 */
static void
shorten_name(char* name, struct ClientShortenHandle* csh)
{

  struct GNUNET_GNS_ResolverHandle *rh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              name, GNUNET_GNS_RECORD_PKEY);
  
  rh = GNUNET_malloc(sizeof (struct GNUNET_GNS_ResolverHandle));
  rh->authority = zone_hash;
  
  rh->name = GNUNET_malloc(strlen(name)
                              - strlen(gnunet_tld) + 1);
  memset(rh->name, 0,
         strlen(name)-strlen(gnunet_tld) + 1);
  memcpy(rh->name, name,
         strlen(name)-strlen(gnunet_tld));

  csh->name = GNUNET_malloc(strlen(name)
                            - strlen(gnunet_tld) + 1);
  memset(rh->name, 0,
         strlen(name)-strlen(gnunet_tld) + 1);
  memcpy(rh->name, name,
         strlen(name)-strlen(gnunet_tld));

  rh->authority_name = GNUNET_malloc(sizeof(char)*MAX_DNS_LABEL_LENGTH);

  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone_hash;
  rh->proc = &handle_shorten_delegation_result;
  rh->proc_cls = (void*)csh;

  /* Start delegation resolution in our namestore */
  resolve_delegation_ns(rh);

}

/**
 * Send shorten response back to client
 * 
 * @param name the shortened name result or NULL if cannot be shortened
 * @param csh the handle to the shorten request
 */
static void
send_shorten_response(const char* name, struct ClientShortenHandle *csh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %s\n",
              "SHORTEN_RESULT", name);
  struct GNUNET_GNS_ClientShortenResultMessage *rmsg;
  
  if (name == NULL)
  {
    name = "";
  }

  rmsg = GNUNET_malloc(sizeof(struct GNUNET_GNS_ClientShortenResultMessage)
                       + strlen(name) + 1);
  
  rmsg->id = csh->unique_id;
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT);
  rmsg->header.size = 
    htons(sizeof(struct GNUNET_GNS_ClientShortenResultMessage) +
          strlen(name) + 1);

  strcpy((char*)&rmsg[1], name);

  GNUNET_SERVER_notification_context_unicast (nc, csh->client,
                              (const struct GNUNET_MessageHeader *) rmsg,
                              GNUNET_NO);
  GNUNET_SERVER_receive_done (csh->client, GNUNET_OK);
  
  GNUNET_free(rmsg);
  GNUNET_free(csh->name);
  GNUNET_free(csh);

}

/**
 * Handle a shorten message from the api
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void handle_shorten(void *cls,
                           struct GNUNET_SERVER_Client * client,
                           const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "SHORTEN");

  size_t msg_size = 0;
  struct ClientShortenHandle *csh;

  if (ntohs (message->size) < sizeof (struct GNUNET_GNS_ClientShortenMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_SERVER_notification_context_add (nc, client);

  struct GNUNET_GNS_ClientShortenMessage *sh_msg =
    (struct GNUNET_GNS_ClientShortenMessage *) message;
  
  msg_size = ntohs(message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  csh = GNUNET_malloc(sizeof(struct ClientShortenHandle));
  csh->client = client;
  csh->unique_id = sh_msg->id;
  
  shorten_name((char*)&sh_msg[1], csh);

}

/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rh the request handle of the lookup
 * @param rd_count the number of records
 * @param rd the record data
 */
static void
reply_to_client(void* cls, struct GNUNET_GNS_ResolverHandle *rh,
                uint32_t rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientLookupHandle* clh = (struct ClientLookupHandle*)cls;
  struct GNUNET_GNS_ClientLookupResultMessage *rmsg;
  size_t len;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %d results\n",
              "LOOKUP_RESULT", rd_count);
  
  len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  rmsg = GNUNET_malloc(len+sizeof(struct GNUNET_GNS_ClientLookupResultMessage));
  
  rmsg->id = clh->unique_id;
  rmsg->rd_count = htonl(rd_count);
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->header.size = 
    htons(len+sizeof(struct GNUNET_GNS_ClientLookupResultMessage));

  GNUNET_NAMESTORE_records_serialize (rd_count, rd, len, (char*)&rmsg[1]);
  
  GNUNET_SERVER_notification_context_unicast (nc, clh->client,
                                (const struct GNUNET_MessageHeader *) rmsg,
                                GNUNET_NO);
  GNUNET_SERVER_receive_done (clh->client, GNUNET_OK);
  
  GNUNET_free(rh->proc_cls);
  free_resolver_handle(rh);
  GNUNET_free(rmsg);
  GNUNET_free(clh->name);
  GNUNET_free(clh);

}

/**
 * Lookup a given name
 *
 * @param name the name to looku[
 * @param clh the client lookup handle
 */
static void
lookup_name(char* name, struct ClientLookupHandle* clh)
{

  struct GNUNET_GNS_ResolverHandle *rh;
  struct RecordLookupHandle* rlh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              name, clh->type);
  
  rh = GNUNET_malloc(sizeof (struct GNUNET_GNS_ResolverHandle));
  rlh = GNUNET_malloc(sizeof(struct RecordLookupHandle));
  
  rh->authority = zone_hash;

  rlh->record_type = clh->type;
  rlh->name = clh->name;
  rlh->proc = &reply_to_client;
  rlh->proc_cls = clh;

  rh->proc_cls = rlh;
  
  rh->name = GNUNET_malloc(strlen(name)
                              - strlen(gnunet_tld) + 1);
  memset(rh->name, 0,
         strlen(name)-strlen(gnunet_tld) + 1);
  memcpy(rh->name, name,
         strlen(name)-strlen(gnunet_tld));

  rh->authority_name = GNUNET_malloc(sizeof(char)*MAX_DNS_LABEL_LENGTH);
  
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_head->prev = NULL;
  rh->authority_chain_head->next = NULL;
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone_hash;

  /* Start resolution in our zone */
  rh->proc = &process_delegation_ns;
  resolve_delegation_ns(rh);
}


/**
 * Handle lookup requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_lookup(void *cls,
              struct GNUNET_SERVER_Client * client,
              const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "LOOKUP");

  size_t msg_size = 0;
  struct ClientLookupHandle *clh;

  if (ntohs (message->size) < sizeof (struct GNUNET_GNS_ClientLookupMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_SERVER_notification_context_add (nc, client);

  struct GNUNET_GNS_ClientLookupMessage *sh_msg =
    (struct GNUNET_GNS_ClientLookupMessage *) message;
  
  msg_size = ntohs(message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  clh = GNUNET_malloc(sizeof(struct ClientLookupHandle));
  clh->client = client;
  clh->name = GNUNET_malloc(strlen((char*)&sh_msg[1]) + 1);
  strcpy(clh->name, (char*)&sh_msg[1]);
  clh->unique_id = sh_msg->id;
  clh->type = ntohl(sh_msg->type);
  
  lookup_name((char*)&sh_msg[1], clh);
}

/**
 * Process GNS requests.
 *
 * @param cls closure)
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Initializing GNS\n");

  char* keyfile;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_shorten, NULL, GNUNET_MESSAGE_TYPE_GNS_SHORTEN, 0},
    {&handle_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_LOOKUP, 0}
  };

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
  GNUNET_free(keyfile);
  

  dns_handle = NULL;
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
  
  /**
   * handle to the dht
   */
  dht_handle = GNUNET_DHT_connect(c, 1); //FIXME get ht_len from cfg

  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not connect to DHT!\n");
  }

  //put_some_records(); //FIXME for testing
  
  /**
   * Schedule periodic put
   * for our records
   * We have roughly an hour for all records;
   */
  dht_update_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                                      1);
  //zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_start, NULL);

  GNUNET_SERVER_add_handlers (server, handlers);
  
  //FIXME
  //GNUNET_SERVER_disconnect_notify (server,
  //                                 &client_disconnect_notification,
  //                                 NULL);

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
