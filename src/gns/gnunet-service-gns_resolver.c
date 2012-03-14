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
 *
 * @file gns/gns_resolver.c
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "block_gns.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"

#define DHT_OPERATION_TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)
#define DHT_LOOKUP_TIMEOUT DHT_OPERATION_TIMEOUT
#define DHT_GNS_REPLICATION_LEVEL 5
#define MAX_DNS_LABEL_LENGTH 63


/**
 * Our handle to the namestore service
 * FIXME maybe need a second handle for iteration
 */
struct GNUNET_NAMESTORE_Handle *namestore_handle;

struct GNUNET_DHT_Handle *dht_handle;

static void
connect_to_dht()
{
  //FIXME
}

/**
 * Helper function to free resolver handle
 *
 * @rh the handle to free
 */
static void
free_resolver_handle(struct ResolverHandle* rh)
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
  struct ResolverHandle *rh = cls;

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
process_record_result_dht(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  struct ResolverHandle *rh;
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
  
  rh = (struct ResolverHandle *)cls;
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
resolve_record_dht(struct ResolverHandle *rh)
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
                       &process_record_result_dht,
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
process_record_result_ns(void* cls,
                  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                  struct GNUNET_TIME_Absolute expiration,
                  const char *name, unsigned int rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd,
                  const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh;
  struct RecordLookupHandle *rlh;
  struct GNUNET_TIME_Relative remaining_time;
  GNUNET_HashCode zone;

  rh = (struct ResolverHandle *) cls;
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
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "This record is expired. Skipping\n");
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
resolve_record_ns(struct ResolverHandle *rh)
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
                                 &process_record_result_ns,
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
  struct ResolverHandle *rh = cls;

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
static void resolve_delegation_dht(struct ResolverHandle *rh);

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
  struct ResolverHandle *rh;
  struct GNSNameRecordBlock *nrb;
  uint32_t num_records;
  char* name = NULL;
  char* rd_data = (char*) data;
  int i;
  int rd_size;
  GNUNET_HashCode zone, name_hash;
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got DHT result\n");

  if (data == NULL)
    return;
  
  //FIXME check expiration?
  
  rh = (struct ResolverHandle *)cls;
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
    if (0 != GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_tail->zone, &zone))
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
handle_record_dht(void* cls, struct ResolverHandle *rh,
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
    rlh->proc(rlh->proc_cls, 0, NULL);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Record resolved from namestore!");
  rlh->proc(rlh->proc_cls, rd_count, rd);

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
handle_record_ns(void* cls, struct ResolverHandle *rh,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  if (rd_count == 0)
  {
    /* ns entry expired and not ours. try dht */
    if (rh->status & (EXPIRED | !EXISTS) &&
        GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_head->zone,
                               &rh->authority_chain_tail->zone))
    {
      rh->proc = &handle_record_dht;
      resolve_record_dht(rh);
      return;
    }
    /* give up, cannot resolve */
    rlh->proc(rlh->proc_cls, 0, NULL);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Record resolved from namestore!");
  rlh->proc(rlh->proc_cls, rd_count, rd);

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
handle_delegation_dht(void* cls, struct ResolverHandle *rh,
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
    rh->proc = &handle_record_ns;
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
    rh->proc = &handle_record_ns;
    resolve_record_ns(rh);
    return;
  }
  /* give up, cannot resolve */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Cannot fully resolve delegation for %s via DHT!\n",
             rh->name);
  rlh->proc(rlh->proc_cls, 0, NULL);
}


/**
 * Start DHT lookup for a name -> PKEY (compare NS) record in
 * rh->authority's zone
 *
 * @param rh the pending gns query
 * @param name the name of the PKEY record
 */
static void
resolve_delegation_dht(struct ResolverHandle *rh)
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
handle_delegation_ns(void* cls, struct ResolverHandle *rh,
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
    rh->proc = &handle_record_ns;
    resolve_record_ns(rh);
    return;
  }

  /**
   * we still have some left
   * check if ns entry is fresh
   **/

  if ((rh->status & (EXISTS | !EXPIRED)) ||
      !GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_head->zone,
                             &rh->authority_chain_tail->zone))
  {
    if (is_canonical(rh->name))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Resolving canonical record %s\n", rh->name);
      rh->proc = &handle_record_ns;
      resolve_record_ns(rh);
    }
    else
    {
      /* give up, cannot resolve */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Cannot fully resolve delegation for %s!\n",
                 rh->name);
      rlh->proc(rlh->proc_cls, 0, NULL);
    }
    return;
  }
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Trying to resolve delegation for %s via DHT\n",
             rh->name);
  rh->proc = &handle_delegation_dht;
  resolve_delegation_dht(rh);
}

//Prototype
static void resolve_delegation_ns(struct ResolverHandle *rh);


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
  struct ResolverHandle *rh;
  struct GNUNET_TIME_Relative remaining_time;
  GNUNET_HashCode zone;
  char* new_name;
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got %d records from authority lookup\n",
             rd_count);

  rh = (struct ResolverHandle *)cls;
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
resolve_delegation_ns(struct ResolverHandle *rh)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Resolving delegation for %s\n", rh->name);
  pop_tld(rh->name, rh->authority_name);
  GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 &rh->authority,
                                 rh->authority_name,
                                 GNUNET_GNS_RECORD_PKEY,
                                 &process_delegation_result_ns,
                                 rh);

}


/**
 * Lookup of a record in a specific zone
 * calls lookup result processor on result
 *
 * @param zone the root zone
 * @param record_type the record type to look up
 * @param proc the processor to call
 * @param cls the closure to pass to proc
 */
void
gns_resolver_lookup_record(GNUNET_HashCode zone,
                           uint32_t record_type,
                           const char* name,
                           RecordLookupProcessor proc,
                           void* cls)
{
  struct ResolverHandle *rh;
  struct RecordLookupHandle* rlh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              name, record_type);

  rlh = GNUNET_malloc(sizeof(struct RecordLookupHandle));
  rh = GNUNET_malloc(sizeof (struct ResolverHandle));

  rh->authority = zone;
  rh->proc_cls = rlh;
  rh->name = GNUNET_malloc(strlen(name)
                           - strlen(GNUNET_GNS_TLD));
  memset(rh->name, 0,
         strlen(name)-strlen(GNUNET_GNS_TLD));
  memcpy(rh->name, name,
         strlen(name)-strlen(GNUNET_GNS_TLD) - 1);
  rh->authority_name = GNUNET_malloc(sizeof(char)*MAX_DNS_LABEL_LENGTH);
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_head->prev = NULL;
  rh->authority_chain_head->next = NULL;
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone;

  rlh->record_type = record_type;
  rlh->name = (char*)name; //FIXME
  rlh->proc = proc;
  rlh->proc_cls = cls;

  rh->proc = &handle_delegation_ns;
  resolve_delegation_ns(rh);
}

/******** END Record Resolver ***********/


static void
process_pseu_result_ns_shorten(void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = 
    (struct ResolverHandle *)cls;
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
process_pseu_dht_result(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  struct ResolverHandle *rh;
  struct RecordLookupHandle *rlh;
  struct GNSNameRecordBlock *nrb;
  uint32_t num_records;
  char* name = NULL;
  char* rd_data = (char*)data;
  int i;
  int rd_size;
  
  GNUNET_HashCode zone, name_hash;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "got PSEU dht result (size=%d)\n", size);
  
  if (data == NULL)
    return;

  //FIXME maybe check expiration here, check block type
  
  rh = (struct ResolverHandle *)cls;
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
    
     if ((strcmp(name, "+") == 0) &&
         (rd[i].record_type == GNUNET_GNS_RECORD_PSEU))
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
 * Start DHT lookup for a PSEUdonym record in
 * rh->authority's zone
 *
 * @param rh the pending gns query
 */
static void
resolve_pseu_dht(struct ResolverHandle *rh)
{
  uint32_t xquery;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  GNUNET_CRYPTO_hash("+",
                     strlen("+"),
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
                       &process_pseu_dht_result,
                       rh);

}

//Prototype
static void
handle_shorten_pseu_ns_result(void* cls,
                              struct ResolverHandle *rh,
                              uint32_t rd_count,
                              const struct GNUNET_NAMESTORE_RecordData *rd);

static void
process_zone_to_name_shorten(void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = 
    (struct ResolverHandle *)cls;
  struct NameShortenHandle* nsh = (struct NameShortenHandle*)rh->proc_cls;
  struct AuthorityChain *next_authority;

  char* result;
  char* next_authority_name;
  size_t answer_len;
  
  /* we found a match in our own zone */
  if (rd_len != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "result strlen %d\n", strlen(name));
    answer_len = strlen(rh->name) + strlen(name) + strlen(GNUNET_GNS_TLD) + 3;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, name);
    strcpy(result+strlen(rh->name)+strlen(name)+1, ".");
    strcpy(result+strlen(rh->name)+strlen(name)+2, GNUNET_GNS_TLD);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending shorten result %s\n", result);

    nsh->proc(nsh->proc_cls, result);
    free_resolver_handle(rh);
    GNUNET_free(result);
  }
  else if (GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_head->zone,
                                  &rh->authority_chain_tail->zone))
  {
    /* our zone, just append .gnunet */
    answer_len = strlen(rh->name) + strlen(GNUNET_GNS_TLD) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, GNUNET_GNS_TLD);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Sending name as shorten result %s\n", rh->name);
    
    nsh->proc(nsh->proc_cls, result); //FIXME +.gnunet!
    free_resolver_handle(rh);
    GNUNET_free(result);
  }
  else
  {
    /**
     * No PSEU found.
     * continue with next authority
     */
    next_authority = rh->authority_chain_head;
    next_authority_name = GNUNET_malloc(strlen(rh->name)+
                             strlen(next_authority->name) + 2);
    memset(next_authority_name, 0, strlen(rh->name)+
                      strlen(next_authority->name) + 2);
    strcpy(next_authority_name, rh->name);
    strcpy(next_authority_name+strlen(rh->name)+1, ".");
    strcpy(next_authority_name+strlen(rh->name)+2, next_authority->name);
  
    GNUNET_free(rh->name);
    rh->name = next_authority_name;
    GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                              rh->authority_chain_tail,
                              next_authority);

    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   &rh->authority_chain_tail->zone,
                                   &rh->authority_chain_head->zone,
                                   &process_zone_to_name_shorten,
                                   rh);
  }
}


/**
 * Process result from namestore PSEU lookup
 * for shorten operation
 *
 * @param cls the client shorten handle
 * @param rh the resolver handle
 * @param rd_count number of results (0 if none found)
 * @param rd data (NULL if none found)
 */
static void
handle_pseu_ns_result_shorten(void* cls,
                      struct ResolverHandle *rh,
                      uint32_t rd_len,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct NameShortenHandle* nsh = (struct NameShortenHandle*) cls;
  struct AuthorityChain *next_authority;
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
                   "Found PSEU %s len %d\n", (char*) rd[i].data,
                   strlen((char*) rd[i].data));
        break;
      }
    }
    
    pseu = (char*) rd[i].data;
    answer_len = strlen(rh->name) + strlen(pseu) + strlen(GNUNET_GNS_TLD) + 3;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, pseu);
    strcpy(result+strlen(rh->name)+strlen(pseu)+1, ".");
    strcpy(result+strlen(rh->name)+strlen(pseu)+2, GNUNET_GNS_TLD);
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Sending shorten result %s\n", result);
    
    nsh->proc(nsh->proc_cls, result);
    free_resolver_handle(rh);
    GNUNET_free(result);
    return;
  }
  
  /**
   * No PSEU found.
   * continue with next authority
   * Note that we never have <2 authorities
   * in our list at this point since tail is always our root
   * And we filter fot this in handle_delegation_ns_shorten
   */
  next_authority = rh->authority_chain_head;
  new_name = GNUNET_malloc(strlen(rh->name)+
                           strlen(next_authority->name) + 2);
  memset(new_name, 0, strlen(rh->name)+
                      strlen(next_authority->name) + 2);
  strcpy(new_name, rh->name);
  strcpy(new_name+strlen(rh->name)+1, ".");
  strcpy(new_name+strlen(rh->name)+2, next_authority->name);
  
  GNUNET_free(rh->name);
  rh->name = new_name;
  GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                              rh->authority_chain_tail,
                              next_authority);

  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &rh->authority_chain_tail->zone,
                                 &rh->authority_chain_head->zone,
                                 &process_zone_to_name_shorten,
                                 rh);

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
handle_delegation_ns_shorten(void* cls,
                      struct ResolverHandle *rh,
                      uint32_t rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct NameShortenHandle *nsh;
  char* result;
  size_t answer_len;

  nsh = (struct NameShortenHandle *)cls;
  
  /**
   * At this point rh->name contains the part of the name
   * that we do not have a PKEY in our namestore to resolve.
   * The authority chain in the resolver handle is now
   * useful to backtrack if needed
   */
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "PKEY resolved as far as possible in ns up to %s!\n", rh->name);

  if (GNUNET_CRYPTO_hash_cmp(&rh->authority_chain_head->zone,
                             &rh->authority_chain_tail->zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     **/
    
    answer_len = strlen(rh->name) + strlen(GNUNET_GNS_TLD) + 2;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, rh->name);
    strcpy(result+strlen(rh->name), ".");
    strcpy(result+strlen(rh->name)+1, GNUNET_GNS_TLD);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Sending name as shorten result %s\n", rh->name);
    
    nsh->proc(nsh->proc_cls, result); //FIXME +.gnunet!
    free_resolver_handle(rh);
    GNUNET_free(result);
    return;
  }
  
  /* backtrack authorities for names */
  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &rh->authority_chain_tail->zone, //ours
                                 &rh->authority_chain_head->zone,
                                 &process_zone_to_name_shorten,
                                 rh);

}

/**
 * Shorten api from resolver
 *
 * @param zone the zone to use
 * @param name the name to shorten
 * @param proc the processor to call with result
 * @param cls closure to pass to proc
 */
void
gns_resolver_shorten_name(GNUNET_HashCode zone,
                          const char* name,
                          ShortenResultProcessor proc,
                          void* cls)
{
  struct ResolverHandle *rh;
  struct NameShortenHandle *nsh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting shorten for %s!\n", name);
  
  nsh = GNUNET_malloc(sizeof (struct NameShortenHandle));
  rh = GNUNET_malloc(sizeof (struct ResolverHandle));
  rh->authority = zone;
  rh->name = GNUNET_malloc(strlen(name)
                           - strlen(GNUNET_GNS_TLD));
  memset(rh->name, 0,
         strlen(name)-strlen(GNUNET_GNS_TLD));
  memcpy(rh->name, name,
         strlen(name)-strlen(GNUNET_GNS_TLD)-1);

  rh->authority_name = GNUNET_malloc(sizeof(char)*MAX_DNS_LABEL_LENGTH);
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone;
  rh->proc = &handle_delegation_ns_shorten;
  rh->proc_cls = nsh;

  nsh->proc = proc;
  nsh->proc_cls = cls;
  
  /* Start delegation resolution in our namestore */
  resolve_delegation_ns(rh);
}

/*********** END NAME SHORTEN ********************/


/**
 * Process result from namestore delegation lookup
 * for get authority operation
 *
 * @param cls the client get auth handle
 * @param rh the resolver handle
 * @param rd_count number of results (0)
 * @param rd data (NULL)
 */
void
handle_delegation_result_ns_get_auth(void* cls,
                      struct ResolverHandle *rh,
                      uint32_t rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetNameAuthorityHandle* nah;
  char* result;
  size_t answer_len;

  nah = (struct GetNameAuthorityHandle*) rh->proc_cls;
  
  /**
   * At this point rh->name contains the part of the name
   * that we do not have a PKEY in our namestore to resolve.
   * The authority chain in the resolver handle is now
   * useful to backtrack if needed
   */
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "PKEY resolved as far as possible in ns up to %s!\n", rh->name);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Building response!\n");
  if (is_canonical(rh->name))
  {
    /**
     * We successfully resolved the authority in the ns
     * FIXME for our purposes this is fine
     * but maybe we want to have an api that also looks
     * into the dht (i.e. option in message)
     **/
    if (strlen(rh->name) > strlen(nah->name))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Record name longer than original lookup name... odd!\n");
      //FIXME to sth here
    }

    answer_len = strlen(nah->name) - strlen(rh->name)
      + strlen(GNUNET_GNS_TLD) + 1;
    result = GNUNET_malloc(answer_len);
    memset(result, 0, answer_len);
    strcpy(result, nah->name + strlen(rh->name) + 1);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got authority result %s\n", result);
    
    nah->proc(nah->proc_cls, result);
    free_resolver_handle(rh);
    GNUNET_free(result);
    GNUNET_free(nah);
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Unable to resolve authority for remaining %s!\n", rh->name);
    nah->proc(nah->proc_cls, "");
    free_resolver_handle(rh);
    GNUNET_free(nah);
  }


}


/**
 * Tries to resolve the authority for name
 * in our namestore
 *
 * @param zone the root zone to look up for
 * @param name the name to lookup up
 * @param proc the processor to call when finished
 * @param cls the closure to pass to the processor
 */
void
gns_resolver_get_authority(GNUNET_HashCode zone,
                           const char* name,
                           GetAuthorityResultProcessor proc,
                           void* cls)
{
  struct ResolverHandle *rh;
  struct GetNameAuthorityHandle *nah;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting authority resolution for %s!\n", name);

  nah = GNUNET_malloc(sizeof (struct GetNameAuthorityHandle));
  rh = GNUNET_malloc(sizeof (struct ResolverHandle));
  rh->authority = zone;

  rh->name = GNUNET_malloc(strlen(name)
                           - strlen(GNUNET_GNS_TLD));
  memset(rh->name, 0,
         strlen(name)-strlen(GNUNET_GNS_TLD));
  memcpy(rh->name, name,
         strlen(name)-strlen(GNUNET_GNS_TLD) - 1);

  nah->name = GNUNET_malloc(strlen(name)+1);
  memset(nah->name, 0,
         strlen(name)+1);
  strcpy(nah->name, name);
  
  rh->authority_name = GNUNET_malloc(MAX_DNS_LABEL_LENGTH);

  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone;
  rh->proc = &handle_delegation_result_ns_get_auth;
  rh->proc_cls = (void*)nah;

  nah->proc = proc;
  nah->proc_cls = cls;

  /* Start delegation resolution in our namestore */
  resolve_delegation_ns(rh);

}

/******** END GET AUTHORITY *************/

/* end of gns_resolver.c */
