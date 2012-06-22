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
 * @file gns/gnunet-service-gns_resolver.c
 * @brief GNUnet GNS resolver logic
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_vpn_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "block_gns.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"

#define DHT_LOOKUP_TIMEOUT DHT_OPERATION_TIMEOUT
#define DHT_GNS_REPLICATION_LEVEL 5
#define MAX_DNS_LABEL_LENGTH 63


/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Our handle to the vpn service
 */
static struct GNUNET_VPN_Handle *vpn_handle;

/**
 * Resolver handle to the dht
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Heap for parallel DHT lookups
 */
static struct GNUNET_CONTAINER_Heap *dht_lookup_heap;

/**
 * Maximum amount of parallel queries in background
 */
static unsigned long long max_allowed_background_queries;

/**
 * Wheather or not to ignore pending records
 */
static int ignore_pending_records;

/**
 * Our local zone
 */
static struct GNUNET_CRYPTO_ShortHashCode local_zone;

/**
 * Background shortening handles
 */
static struct GetPseuAuthorityHandle *gph_head;

/**
 * Background shortening handles
 */
static struct GetPseuAuthorityHandle *gph_tail;

/**
 * a resolution identifier pool variable
 * FIXME overflow?
 * This is a non critical identifier useful for debugging
 */
static unsigned long long rid = 0;

static int
is_srv (char* name)
{
  char* ndup;
  int ret = 1;

  if (*name != '_')
    return 0;
  if (NULL == strstr (name, "._"))
    return 0;

  ndup = GNUNET_strdup (name);
  strtok (ndup, ".");

  if (NULL == strtok (NULL, "."))
    ret = 0;

  if (NULL == strtok (NULL, "."))
    ret = 0;

  if (NULL != strtok (NULL, "."))
    ret = 0;

  return ret;
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
  char* ndup;
  char* tok;

  ndup = GNUNET_strdup (name);
  tok = strtok (ndup, ".");

  for (tok = strtok (NULL, "."); tok != NULL; tok = strtok (NULL, "."))
  {
    /*
     * probably srv
     */
    if (*tok == '_')
      continue;
    GNUNET_free (ndup);
    return 0;
  }
  GNUNET_free (ndup);
  return 1;
}


/**
 * Callback that shortens authorities
 *
 * @param gph the handle containing the name to shorten
 */
static void
shorten_authority_chain (struct GetPseuAuthorityHandle *gph);


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
process_pseu_lookup_ns (void* cls,
                      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                      struct GNUNET_TIME_Absolute expiration,
                      const char *name, unsigned int rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd,
                      const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GetPseuAuthorityHandle* gph = (struct GetPseuAuthorityHandle*)cls;
  struct GNUNET_NAMESTORE_RecordData new_pkey;
  struct AuthorityChain *iter;

  if (rd_count > 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_AUTO_PSEU: Name %s already taken in NS!\n", name);
    if (0 == strcmp (gph->name, name))
    {
      if (gph->ahead->next != NULL)
      {
        if (GNUNET_CRYPTO_short_hash_cmp (&gph->ahead->next->zone,
                                          &gph->our_zone))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: trying next!\n");
          iter = gph->ahead->next;
          GNUNET_free (gph->ahead);
          gph->ahead = iter;
          shorten_authority_chain (gph);
          return;
        }
      }

      /* Clean up */
      do
      {
        iter = gph->ahead->next;
        GNUNET_free (gph->ahead);
        gph->ahead = iter;
      } while (iter != NULL);
      GNUNET_CRYPTO_rsa_key_free (gph->key);
      GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
      GNUNET_free (gph);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_AUTO_PSEU: Trying delegated name %s\n", gph->name);
    memcpy (gph->test_name, gph->name, strlen (gph->name)+1);
    GNUNET_NAMESTORE_lookup_record (namestore_handle,
                                    &gph->our_zone,
                                    gph->test_name,
                                    GNUNET_NAMESTORE_TYPE_ANY,
                                    &process_pseu_lookup_ns,
                                    gph);
    return;
  }

  /* name is free */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "GNS_AUTO_PSEU: Name %s not taken in NS! Adding\n", gph->test_name);

  new_pkey.expiration_time = UINT64_MAX;
  new_pkey.data_size = sizeof (struct GNUNET_CRYPTO_ShortHashCode);
  new_pkey.data = &gph->ahead->zone;
  new_pkey.record_type = GNUNET_GNS_RECORD_PKEY;
  new_pkey.flags = GNUNET_NAMESTORE_RF_AUTHORITY
                 | GNUNET_NAMESTORE_RF_PRIVATE
                 | GNUNET_NAMESTORE_RF_PENDING;
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  gph->key,
                                  gph->test_name,
                                  &new_pkey,
                                  NULL, //cont
                                  NULL); //cls
  do
  {
    iter = gph->ahead->next;
    GNUNET_free (gph->ahead);
    gph->ahead = iter;
  } while (iter != NULL);
  GNUNET_CRYPTO_rsa_key_free (gph->key);
  GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
  GNUNET_free (gph);

}

/**
 * process result of a dht pseu lookup
 *
 * @param gph the handle
 * @param name the pseu result or NULL
 */
static void
process_pseu_result (struct GetPseuAuthorityHandle* gph, char* name)
{
  if (NULL == name)
  {
    memcpy (gph->test_name, gph->ahead->name, strlen (gph->ahead->name)+1);
  }
  else
  {
    memcpy (gph->test_name, name, strlen(name)+1);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_AUTO_PSEU: Checking %s for collision in NS\n",
              gph->test_name);

  /**
   * Check for collision
   */
  GNUNET_NAMESTORE_lookup_record (namestore_handle,
                                  &gph->our_zone,
                                  gph->test_name,
                                  GNUNET_NAMESTORE_TYPE_ANY,
                                  &process_pseu_lookup_ns,
                                  gph);
}

/**
 * Handle timeout for dht request
 *
 * @param cls the request handle as closure
 * @param tc the task context
 */
static void
handle_auth_discovery_timeout(void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPseuAuthorityHandle* gph = (struct GetPseuAuthorityHandle*)cls;
  struct AuthorityChain *iter;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_GET_AUTH: dht lookup for query PSEU timed out.\n");
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  
  if (gph->ahead->next != NULL)
  {
    if (GNUNET_CRYPTO_short_hash_cmp (&gph->ahead->next->zone,
                                      &gph->our_zone))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: trying next!\n");
      iter = gph->ahead->next;
      GNUNET_free (gph->ahead);
      gph->ahead = iter;
      shorten_authority_chain (gph);
      return;
    }
  }
  
  process_pseu_result (gph, NULL);
}

/**
 * Function called when we find a PSEU entry in the DHT
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
process_auth_discovery_dht_result(void* cls,
                                  struct GNUNET_TIME_Absolute exp,
                                  const struct GNUNET_HashCode * key,
                                  const struct GNUNET_PeerIdentity *get_path,
                                  unsigned int get_path_length,
                                  const struct GNUNET_PeerIdentity *put_path,
                                  unsigned int put_path_length,
                                  enum GNUNET_BLOCK_Type type,
                                  size_t size, const void *data)
{
  struct GetPseuAuthorityHandle* gph = (struct GetPseuAuthorityHandle*)cls;
  struct AuthorityChain *iter;
  struct GNSNameRecordBlock *nrb;
  char* rd_data = (char*)data;
  char* name;
  int num_records;
  size_t rd_size;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_GET_AUTH: got dht result (size=%d)\n", size);

  
  /* stop lookup and timeout task */
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  GNUNET_SCHEDULER_cancel (gph->timeout);
  
  if (data == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "GNS_GET_AUTH: got dht result null!\n", size);
    
    do
    {
      iter = gph->ahead->next;
      GNUNET_free (gph->ahead);
      gph->ahead = iter;
    } while (iter != NULL);
    GNUNET_CRYPTO_rsa_key_free (gph->key);
    GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
    GNUNET_free (gph);
    return;
  }
  
  nrb = (struct GNSNameRecordBlock*)data;



  nrb = (struct GNSNameRecordBlock*)data;
  
  name = (char*)&nrb[1];
  num_records = ntohl (nrb->rd_count);
  {
    struct GNUNET_NAMESTORE_RecordData rd[num_records];

    rd_data += strlen (name) + 1 + sizeof (struct GNSNameRecordBlock);
    rd_size = size - strlen (name) - 1 - sizeof (struct GNSNameRecordBlock);

    if (GNUNET_SYSERR == GNUNET_NAMESTORE_records_deserialize (rd_size,
                                                               rd_data,
                                                               num_records,
                                                               rd))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "GNS_GET_AUTH: Error deserializing data!\n");
    }
    else
    {
      for (i=0; i < num_records; i++)
      {
        if ((strcmp (name, "+") == 0) &&
            (rd[i].record_type == GNUNET_GNS_RECORD_PSEU))
        {
          /* found pseu */
          process_pseu_result (gph, (char*)rd[i].data);
          return;
        }
      }
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: no pseu in dht!\n");

  if (gph->ahead->next != NULL)
  {
    if (GNUNET_CRYPTO_short_hash_cmp (&gph->ahead->next->zone,
                                      &gph->our_zone))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: trying next!\n");
      iter = gph->ahead->next;
      GNUNET_free (gph->ahead);
      gph->ahead = iter;
      shorten_authority_chain (gph);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_GET_AUTH: finished shorten, no results!\n");
  process_pseu_result (gph, NULL);
}

/**
 * Process PSEU discovery for shorten via namestore
 *
 * @param cls the GetPseuAuthorityHandle
 * @param key the public key
 * @param expiration recorddata expiration
 * @param name the looked up name
 * @param rd_count number of records in set
 * @param rd record data
 * @param signature the signature
 */
static void
process_auth_discovery_ns_result(void* cls,
                      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                      struct GNUNET_TIME_Absolute expiration,
                      const char *name,
                      unsigned int rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd,
                      const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  uint32_t xquery;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_HashCode lookup_key;
  struct GNUNET_CRYPTO_HashAsciiEncoded lookup_key_string;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  int i;
  struct GetPseuAuthorityHandle* gph = (struct GetPseuAuthorityHandle*)cls;
  struct AuthorityChain *iter;
  
  /* no pseu found */
  if (rd_count == 0)
  {
    /**
     * check dht
     */
    GNUNET_CRYPTO_short_hash ("+", strlen ("+"), &name_hash);
    GNUNET_CRYPTO_short_hash_double (&name_hash, &name_hash_double);
    GNUNET_CRYPTO_short_hash_double (&gph->ahead->zone, &zone_hash_double);
    GNUNET_CRYPTO_hash_xor (&name_hash_double, &zone_hash_double, &lookup_key);
    GNUNET_CRYPTO_hash_to_enc (&lookup_key, &lookup_key_string);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "GNS_AUTO_PSEU: starting dht lookup for %s with key: %s\n",
               "+", (char*)&lookup_key_string);

    gph->timeout = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
                                         &handle_auth_discovery_timeout, gph);

    xquery = htonl (GNUNET_GNS_RECORD_PSEU);
    
    GNUNET_assert (gph->get_handle == NULL);

    gph->get_handle = GNUNET_DHT_get_start(dht_handle,
                                           GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                                           &lookup_key,
                                           DHT_GNS_REPLICATION_LEVEL,
                                           GNUNET_DHT_RO_NONE,
                                           &xquery,
                                           sizeof(xquery),
                                           &process_auth_discovery_dht_result,
                                           gph);
    return;
  }

  for (i=0; i < rd_count; i++)
  {
    if ((strcmp (name, "+") == 0) &&
        (rd[i].record_type == GNUNET_GNS_RECORD_PSEU))
    {
      /* found pseu */
      process_pseu_result (gph, (char*)rd[i].data);
      return;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: no pseu in namestore!\n");
  
  if (gph->ahead->next != NULL)
  {
    if (GNUNET_CRYPTO_short_hash_cmp (&gph->ahead->next->zone,
                                      &gph->our_zone))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS_GET_AUTH: trying next!\n");
      iter = gph->ahead->next;
      GNUNET_free (gph->ahead);
      gph->ahead = iter;
      shorten_authority_chain (gph);
      return;
    }
  }
  
  process_pseu_result (gph, NULL);
}

/**
 * Callback called by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_discover (void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GetPseuAuthorityHandle* gph = (struct GetPseuAuthorityHandle*)cls;
  struct AuthorityChain *iter;

  /* we found a match in our own zone */
  if (rd_len != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_AUTO_PSEU: name for zone in our root %s\n", name);

    iter = gph->ahead;
    do
    {
      iter = gph->ahead->next;
      GNUNET_free (gph->ahead);
      gph->ahead = iter;
    } while (iter != NULL);
    GNUNET_CRYPTO_rsa_key_free (gph->key);
    GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
    GNUNET_free (gph);
  }
  else
  {

    GNUNET_NAMESTORE_lookup_record (namestore_handle,
                                    &gph->ahead->zone,
                                    "+",
                                    GNUNET_GNS_RECORD_PSEU,
                                    &process_auth_discovery_ns_result,
                                    gph);
  }

}


/**
 * Callback that shortens authorities
 *
 * @param gph the handle to the shorten request
 */
static void
shorten_authority_chain (struct GetPseuAuthorityHandle *gph)
{

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_AUTO_PSEU: New authority %s discovered\n",
              gph->ahead->name);

  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &gph->our_zone,
                                 &gph->ahead->zone,
                                 &process_zone_to_name_discover,
                                 gph);

}

static void
start_shorten (struct AuthorityChain *atail,
               struct GNUNET_CRYPTO_RsaPrivateKey *key)
{
  struct AuthorityChain *new_head = NULL;
  struct AuthorityChain *new_tail = NULL;
  struct AuthorityChain *iter;
  struct AuthorityChain *acopy;
  struct GetPseuAuthorityHandle *gph;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *pb_key;

  /* First copy the authority chain in reverse order */
  for (iter = atail; iter != NULL; iter = iter->prev)
  {
    acopy = GNUNET_malloc (sizeof (struct AuthorityChain));
    memcpy (acopy, iter, sizeof (struct AuthorityChain));
    acopy->next = NULL;
    acopy->prev = NULL;
    GNUNET_CONTAINER_DLL_insert (new_head, new_tail, acopy);
  }

  gph = GNUNET_malloc (sizeof (struct GetPseuAuthorityHandle));

  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  pb_key = GNUNET_CRYPTO_rsa_encode_key (key);
  gph->key = GNUNET_CRYPTO_rsa_decode_key ((char*)pb_key, ntohs (pb_key->len));
  //gph->key = key;//GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  //memcpy (gph->key, key, sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  
  GNUNET_CRYPTO_short_hash (&pkey,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &gph->our_zone);
  gph->ahead = new_head;

  GNUNET_CONTAINER_DLL_insert (gph_head, gph_tail, gph);

  shorten_authority_chain (gph);
}

/**
 * Initialize the resolver
 *
 * @param nh the namestore handle
 * @param dh the dht handle
 * @param lz the local zone's hash
 * @param cfg configuration handle
 * @param max_bg_queries maximum number of parallel background queries in dht
 * @param ignore_pending ignore records that still require user confirmation
 *        on lookup
 * @return GNUNET_OK on success
 */
int
gns_resolver_init(struct GNUNET_NAMESTORE_Handle *nh,
                  struct GNUNET_DHT_Handle *dh,
                  struct GNUNET_CRYPTO_ShortHashCode lz,
                  const struct GNUNET_CONFIGURATION_Handle *cfg,
                  unsigned long long max_bg_queries,
                  int ignore_pending)
{
  namestore_handle = nh;
  dht_handle = dh;
  local_zone = lz;
  dht_lookup_heap =
    GNUNET_CONTAINER_heap_create(GNUNET_CONTAINER_HEAP_ORDER_MIN);
  max_allowed_background_queries = max_bg_queries;
  ignore_pending_records = ignore_pending;

  gph_head = NULL;
  gph_tail = NULL;

  GNUNET_RESOLVER_connect (cfg);
  
  if (NULL == vpn_handle)
  {
    vpn_handle = GNUNET_VPN_connect (cfg);
    if (NULL == vpn_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_INIT: Error connecting to VPN!\n");

      return GNUNET_SYSERR;
    }
  }

  if ((namestore_handle != NULL) && (dht_handle != NULL))
  {
    return GNUNET_OK;
  }

  return GNUNET_SYSERR;
}

/**
 * Cleanup background lookups
 *
 * @param cls closure to iterator
 * @param node heap nodes
 * @param element the resolver handle
 * @param cost heap cost
 * @return always GNUNET_YES
 */
static int
cleanup_pending_background_queries(void* cls,
                                   struct GNUNET_CONTAINER_HeapNode *node,
                                   void *element,
                                   GNUNET_CONTAINER_HeapCostType cost)
{
  struct ResolverHandle *rh = (struct ResolverHandle *)element;
  ResolverCleanupContinuation cont = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_CLEANUP-%llu: Terminating background lookup for %s\n",
             rh->id, rh->name);
  GNUNET_DHT_get_stop(rh->get_handle);
  rh->get_handle = NULL;
  rh->proc(rh->proc_cls, rh, 0, NULL);

  GNUNET_CONTAINER_heap_remove_node(node);

  if (GNUNET_CONTAINER_heap_get_size(dht_lookup_heap) == 0)
    cont();


  return GNUNET_YES;
}


/**
 * Shutdown resolver
 */
void
gns_resolver_cleanup(ResolverCleanupContinuation cont)
{
  unsigned int s = GNUNET_CONTAINER_heap_get_size(dht_lookup_heap);
  struct GetPseuAuthorityHandle *tmp;
  struct AuthorityChain *iter;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_CLEANUP: %d pending background queries to terminate\n", s);
  
  tmp = gph_head;
  for (tmp = gph_head; tmp != NULL; tmp = gph_head)
  {
    if (tmp->get_handle != NULL)
      GNUNET_DHT_get_stop (tmp->get_handle);
    tmp->get_handle = NULL;
    if (tmp->timeout != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (tmp->timeout);
    tmp->timeout = GNUNET_SCHEDULER_NO_TASK;
    
    iter = tmp->ahead;
    do
    {
      iter = tmp->ahead->next;
      GNUNET_free (tmp->ahead);
      tmp->ahead = iter;
    } while (iter != NULL);
    
    GNUNET_CRYPTO_rsa_key_free (tmp->key);
    GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, tmp);
    GNUNET_free (tmp);
  }
  
  
  if (0 != s)
    GNUNET_CONTAINER_heap_iterate (dht_lookup_heap,
                                   &cleanup_pending_background_queries,
                                   cont);
  else
    cont();
}


/**
 * Helper function to free resolver handle
 *
 * @param rh the handle to free
 */
static void
free_resolver_handle(struct ResolverHandle* rh)
{
  struct AuthorityChain *ac;
  struct AuthorityChain *ac_next;

  if (NULL == rh)
    return;

  ac = rh->authority_chain_head;

  while (NULL != ac)
  {
    ac_next = ac->next;
    GNUNET_free(ac);
    ac = ac_next;
  }

  if (NULL != rh->dns_raw_packet)
    GNUNET_free (rh->dns_raw_packet);

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
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_NS: records already in namestore\n");
    return;
  }
  else if (GNUNET_YES == success)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_NS: records successfully put in namestore\n");
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
             "GNS_NS: Error putting records into namestore: %s\n", emsg);
}

static void
handle_lookup_timeout(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ResolverHandle *rh = cls;

  if (rh->timeout_cont)
    rh->timeout_cont(rh->timeout_cont_cls, tc);
}

/**
 * Processor for background lookups in the DHT
 *
 * @param cls closure (NULL)
 * @param rd_count number of records found (not 0)
 * @param rd record data
 */
static void
background_lookup_result_processor(void *cls,
                                   uint32_t rd_count,
                                   const struct GNUNET_NAMESTORE_RecordData *rd)
{
  //We could do sth verbose/more useful here but it doesn't make any difference
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_BG: background dht lookup finished. (%d results)\n",
             rd_count);
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
  struct RecordLookupHandle *rlh = (struct RecordLookupHandle *)rh->proc_cls;
  char new_name[MAX_DNS_NAME_LENGTH];

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: dht lookup for query %s (%ds)timed out.\n",
             rh->id, rh->name, rh->timeout.rel_value);
  /**
   * Start resolution in bg
   */
  //strcpy(new_name, rh->name);
  //memcpy(new_name+strlen(new_name), GNUNET_GNS_TLD, strlen(GNUNET_GNS_TLD));
  GNUNET_snprintf(new_name, MAX_DNS_NAME_LENGTH, "%s.%s",
                  rh->name, GNUNET_GNS_TLD);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: Starting background lookup for %s type %d\n",
             rh->id, new_name, rlh->record_type);

  gns_resolver_lookup_record(rh->authority,
                             rh->private_local_zone,
                             rlh->record_type,
                             new_name,
                             rh->priv_key,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             GNUNET_NO,
                             &background_lookup_result_processor,
                             NULL);
  rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
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
                          const struct GNUNET_HashCode * key,
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

  rh = (struct ResolverHandle *)cls;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: got dht result (size=%d)\n", rh->id, size);

  //FIXME maybe check expiration here, check block type


  rlh = (struct RecordLookupHandle *) rh->proc_cls;
  nrb = (struct GNSNameRecordBlock*)data;

  /* stop lookup and timeout task */
  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;

  if (rh->dht_heap_node != NULL)
  {
    GNUNET_CONTAINER_heap_remove_node(rh->dht_heap_node);
    rh->dht_heap_node = NULL;
  }

  if (rh->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

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
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 "GNS_PHASE_REC-%d: Error deserializing data!\n", rh->id);
      return;
    }

    for (i=0; i<num_records; i++)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Got name: %s (wanted %s)\n",
                 rh->id, name, rh->name);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Got type: %d (wanted %d)\n",
                 rh->id, rd[i].record_type, rlh->record_type);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Got data length: %d\n",
                 rh->id, rd[i].data_size);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Got flag %d\n",
                 rh->id, rd[i].flags);

      if ((strcmp(name, rh->name) == 0) &&
          (rd[i].record_type == rlh->record_type))
      {
        rh->answered++;
      }

    }

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
resolve_record_dht (struct ResolverHandle *rh)
{
  uint32_t xquery;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_HashCode lookup_key;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  struct GNUNET_CRYPTO_HashAsciiEncoded lookup_key_string;
  struct RecordLookupHandle *rlh = (struct RecordLookupHandle *)rh->proc_cls;
  struct ResolverHandle *rh_heap_root;

  GNUNET_CRYPTO_short_hash(rh->name, strlen(rh->name), &name_hash);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double(&rh->authority, &zone_hash_double);
  GNUNET_CRYPTO_hash_xor(&name_hash_double, &zone_hash_double, &lookup_key);
  GNUNET_CRYPTO_hash_to_enc (&lookup_key, &lookup_key_string);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: starting dht lookup for %s with key: %s\n",
             rh->id, rh->name, (char*)&lookup_key_string);

  //rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  rh->dht_heap_node = NULL;

  if (rh->timeout.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
  {
    /**
     * Update timeout if necessary
     */
    if (rh->timeout_task == GNUNET_SCHEDULER_NO_TASK)
    {

      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Adjusting timeout\n", rh->id);
      /*
       * Set timeout for authority lookup phase to 1/2
       */
      rh->timeout_task = GNUNET_SCHEDULER_add_delayed(
                                                      GNUNET_TIME_relative_divide(rh->timeout, 2),
                                                      &handle_lookup_timeout,
                                                      rh);
    }
    //rh->timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
    //                                                   &dht_lookup_timeout,
    //                                                   rh);
    rh->timeout_cont = &dht_lookup_timeout;
    rh->timeout_cont_cls = rh;
  }
  else 
  {
    if (max_allowed_background_queries <=
        GNUNET_CONTAINER_heap_get_size (dht_lookup_heap))
    {
      rh_heap_root = GNUNET_CONTAINER_heap_remove_root (dht_lookup_heap);
      GNUNET_DHT_get_stop(rh_heap_root->get_handle);
      rh_heap_root->get_handle = NULL;
      rh_heap_root->dht_heap_node = NULL;

      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Replacing oldest background query for %s\n",
                 rh->id, rh_heap_root->name);
      rh_heap_root->proc(rh_heap_root->proc_cls,
                         rh_heap_root,
                         0,
                         NULL);
    }
    rh->dht_heap_node = GNUNET_CONTAINER_heap_insert (dht_lookup_heap,
                                                      rh,
                                                      GNUNET_TIME_absolute_get().abs_value);
  }

  xquery = htonl(rlh->record_type);

  GNUNET_assert(rh->get_handle == NULL);
  rh->get_handle = GNUNET_DHT_get_start(dht_handle, 
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
process_record_result_ns (void* cls,
                          const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                          struct GNUNET_TIME_Absolute expiration,
                          const char *name, unsigned int rd_count,
                          const struct GNUNET_NAMESTORE_RecordData *rd,
                          const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh;
  struct RecordLookupHandle *rlh;
  struct GNUNET_TIME_Relative remaining_time;
  struct GNUNET_CRYPTO_ShortHashCode zone;
  struct GNUNET_TIME_Absolute et;
  unsigned int i;

  rh = (struct ResolverHandle *) cls;
  rlh = (struct RecordLookupHandle *)rh->proc_cls;
  GNUNET_CRYPTO_short_hash(key,
                           sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                           &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);



  rh->status = 0;

  if (name != NULL)
  {
    rh->status |= RSL_RECORD_EXISTS;

    if (remaining_time.rel_value == 0)
    {
      rh->status |= RSL_RECORD_EXPIRED;
    }
  }

  if (rd_count == 0)
  {
    /**
     * Lookup terminated and no results
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Namestore lookup for %s terminated without results\n",
               rh->id, name);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Record %s unknown in namestore\n",
               rh->id, rh->name);
    /**
     * Our zone and no result? Cannot resolve TT
     */
    rh->proc(rh->proc_cls, rh, 0, NULL);
    return;

  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Processing additional result %s from namestore\n",
               rh->id, name);
    for (i=0; i<rd_count;i++)
    {
      if (rd[i].record_type != rlh->record_type)
        continue;

      if (ignore_pending_records &&
          (rd[i].flags & GNUNET_NAMESTORE_RF_PENDING))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_REC-%d: Record %s is awaiting user confirmation. Skipping\n",
                   rh->id, name);
        continue;
      }

      GNUNET_break (0 == (rd[i].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION));
      et.abs_value = rd[i].expiration_time;
      if ((GNUNET_TIME_absolute_get_remaining (et)).rel_value
          == 0)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_REC-%d: This record is expired. Skipping\n",
                   rh->id);
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
                 "GNS_PHASE_REC-%d: No answers found. This is odd!\n", rh->id);
      rh->proc(rh->proc_cls, rh, 0, NULL);
      return;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Found %d answer(s) to query in %d records!\n",
               rh->id, rh->answered, rd_count);

    rh->proc(rh->proc_cls, rh, rd_count, rd);
  }
}


/**
 * VPN redirect result callback
 *
 * @param cls the resolver handle
 * @param af the requested address family
 * @param address in_addr(6) respectively
 */
static void
process_record_result_vpn (void* cls, int af, const void *address)
{
  struct ResolverHandle *rh = cls;
  struct RecordLookupHandle *rlh;
  struct GNUNET_NAMESTORE_RecordData rd;

  rlh = (struct RecordLookupHandle *)rh->proc_cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_VPN-%d: Got answer from VPN to query!\n",
             rh->id);
  if (af == AF_INET)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Answer is IPv4!\n",
               rh->id);
    if (rlh->record_type != GNUNET_GNS_RECORD_TYPE_A)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Requested record is not IPv4!\n",
                 rh->id);
      rh->proc (rh->proc_cls, rh, 0, NULL);
      return;
    }
    rd.record_type = GNUNET_GNS_RECORD_TYPE_A;
    rd.expiration_time = UINT64_MAX; /* FIXME: should probably pick something shorter... */
    rd.data = address;
    rd.data_size = sizeof (struct in_addr);
    rd.flags = 0;
    rh->proc (rh->proc_cls, rh, 1, &rd);
    return;
  }
  else if (af == AF_INET6)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: Answer is IPv6!\n",
               rh->id);
    if (rlh->record_type != GNUNET_GNS_RECORD_AAAA)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%d: Requested record is not IPv6!\n",
                 rh->id);
      rh->proc (rh->proc_cls, rh, 0, NULL);
      return;
    }
    rd.record_type = GNUNET_GNS_RECORD_AAAA;
    rd.expiration_time = UINT64_MAX; /* FIXME: should probably pick something shorter... */
    rd.data = address;
    rd.data_size = sizeof (struct in6_addr);
    rd.flags = 0;
    rh->proc (rh->proc_cls, rh, 1, &rd);
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: Got garbage from VPN!\n",
             rh->id);
  rh->proc (rh->proc_cls, rh, 0, NULL);
}


/**
 * finish lookup
 *
 * @param rh resolver handle
 * @param rlh record lookup handle
 * @param rd_count number of results
 * @param rd results
 */
static void
finish_lookup(struct ResolverHandle *rh,
              struct RecordLookupHandle* rlh,
              unsigned int rd_count,
              const struct GNUNET_NAMESTORE_RecordData *rd);

/**
 * Process VPN lookup result for record
 *
 * @param cls the record lookup handle
 * @param rh resolver handle
 * @param rd_count number of results (1)
 * @param rd record data containing the result
 */
static void
handle_record_vpn (void* cls, struct ResolverHandle *rh,
                   unsigned int rd_count,
                   const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh = (struct RecordLookupHandle*) cls;
  
  if (rd_count == 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC_VPN-%d: VPN returned no records. (status: %d)!\n",
               rh->id,
               rh->status);
    /* give up, cannot resolve */
    finish_lookup(rh, rlh, 0, NULL);
    free_resolver_handle(rh);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_VPN-%d: Record resolved from VPN!", rh->id);

  finish_lookup(rh, rlh, rd_count, rd);

  free_resolver_handle(rh);
}


/**
 * Sends a UDP dns query to a nameserver specified in the rh
 * 
 * @param rh the resolver handle
 */
static void
send_dns_packet (struct ResolverHandle *rh);


static void
handle_dns_resolver (void *cls,
                     const struct sockaddr *addr,
                     socklen_t addrlen)
{
  struct ResolverHandle *rh = cls;
  struct RecordLookupHandle *rlh = rh->proc_cls;
  struct GNUNET_NAMESTORE_RecordData rd;
  struct sockaddr_in *sai;
  struct sockaddr_in6 *sai6;

  if (NULL == addr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No address found in DNS!\n");
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }
  
  if (addrlen == sizeof (struct sockaddr_in))
  {
    sai = (struct sockaddr_in*) addr;
    rd.record_type = GNUNET_GNS_RECORD_TYPE_A;
    rd.data_size = sizeof (struct in_addr);
    rd.data = &sai->sin_addr;
  }
  else
  {
    sai6 = (struct sockaddr_in6*) addr;
    rd.record_type = GNUNET_GNS_RECORD_AAAA;
    rd.data_size = sizeof (struct in6_addr);
    rd.data = &sai6->sin6_addr;
  }
  
  rd.expiration_time = UINT64_MAX; /* FIXME: should probably pick something shorter */
  rd.flags = 0;

  finish_lookup (rh, rlh, 1, &rd);
  GNUNET_RESOLVER_request_cancel (rh->dns_resolver_handle);
  free_resolver_handle (rh);
}

/**
 * Resolve DNS name via local stub resolver
 *
 * @param rh the resolver handle
 */
static void
resolve_dns_name (struct ResolverHandle *rh)
{
  struct RecordLookupHandle *rlh = rh->proc_cls;
  int af;

  if ((rlh->record_type != GNUNET_GNS_RECORD_TYPE_A) &&
      (rlh->record_type != GNUNET_GNS_RECORD_AAAA))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Can only resolve A/AAAA via stub... abort\n");
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }

  if (rlh->record_type == GNUNET_GNS_RECORD_TYPE_A)
    af = AF_INET;
  else
    af = AF_INET6;

  //GNUNET_RESOLVER_connect (cfg); FIXME into init

  rh->dns_resolver_handle = GNUNET_RESOLVER_ip_get (rh->dns_name,
                                                    af,
                                                    rh->timeout,
                                                    &handle_dns_resolver,
                                                    rh);
}


/**
 * Read DNS udp packet from socket
 *
 * @param cls the resolver handle
 * @param tc task context
 */
static void
read_dns_response (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ResolverHandle *rh = cls;
  struct RecordLookupHandle *rlh = rh->proc_cls;
  char buf[UINT16_MAX];
  ssize_t r;
  struct sockaddr_in addr;
  socklen_t addrlen;
  struct GNUNET_DNSPARSER_Packet *packet;
  struct GNUNET_NAMESTORE_RecordData rd;
  int found_delegation = GNUNET_NO;
  int found_cname = GNUNET_NO;
  char* delegation_name = NULL;
  int zone_offset = 0;
  int i;

  rh->dns_read_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    /* timeout or shutdown */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Terminating DNS query\n");
    finish_lookup (rh, rlh, 0, NULL);
    GNUNET_NETWORK_socket_close (rh->dns_sock);
    free_resolver_handle (rh);
    return;
  }

  addrlen = sizeof (addr);
  r = GNUNET_NETWORK_socket_recvfrom (rh->dns_sock,
                                      buf, sizeof (buf),
                                      (struct sockaddr*) &addr,
                                      &addrlen);

  if (-1 == r)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "recvfrom");
    finish_lookup (rh, rlh, 0, NULL);
    GNUNET_NETWORK_socket_close (rh->dns_sock);
    free_resolver_handle (rh);
    return;
  }

  packet = GNUNET_DNSPARSER_parse (buf, r);
  
  if (NULL == packet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to parse DNS reply!\n");
    finish_lookup (rh, rlh, 0, NULL);
    GNUNET_NETWORK_socket_close (rh->dns_sock);
    free_resolver_handle (rh);
    return;
  }

  for (i = 0; i < packet->num_answers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "Got record type %d (want %d)\n",
               packet->answers[i].type,
               rlh->record_type);
    /* http://tools.ietf.org/html/rfc1034#section-3.6.2 */
    if (packet->answers[i].type == GNUNET_GNS_RECORD_TYPE_CNAME)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "CNAME... restarting query with %s\n",
                  packet->answers[i].data.hostname
                 );
      strcpy (rh->dns_name, packet->answers[i].data.hostname);
      found_cname = GNUNET_YES;
      //send_dns_packet (rh);
      //GNUNET_DNSPARSER_free_packet (packet);
      continue;
    }
    
    if ((packet->answers[i].type == rlh->record_type) &&
        (0 == strcmp (packet->answers[i].name, rh->dns_name)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found record!\n");
      rd.data = packet->answers[i].data.raw.data;
      rd.data_size = packet->answers[i].data.raw.data_len;
      rd.record_type = packet->answers[i].type;
      rd.flags = 0;
      rd.expiration_time = packet->answers[i].expiration_time.abs_value;
      finish_lookup (rh, rlh, 1, &rd);
      GNUNET_NETWORK_socket_close (rh->dns_sock);
      GNUNET_DNSPARSER_free_packet (packet);
      free_resolver_handle (rh);
      return;
    }
  }

  if (GNUNET_YES == found_cname)
  {
    zone_offset = strlen (rh->dns_name) - strlen (rh->dns_zone) - 1;
    
    if (0 > zone_offset)
      zone_offset = 0;

    /* restart query with CNAME */
    if (0 == strcmp (rh->dns_name+zone_offset, rh->dns_zone))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Asking same server for %s\n", rh->dns_name);
      send_dns_packet (rh);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Trying system resolver for %s\n", rh->dns_name);
      resolve_dns_name (rh);
    }

    GNUNET_DNSPARSER_free_packet (packet);
    return;
  }

  for (i = 0; i < packet->num_authority_records; i++)
  {
    
    if (packet->authority_records[i].type == GNUNET_GNS_RECORD_TYPE_NS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found NS delegation!\n");
      found_delegation = GNUNET_YES;
      delegation_name = packet->authority_records[i].data.hostname;
      break;
    }
  }

  for (i = 0; i < packet->num_additional_records; i++)
  {
    if (found_delegation == GNUNET_NO)
      break;

    if ((packet->additional_records[i].type == GNUNET_GNS_RECORD_TYPE_A) &&
        (0 == strcmp (packet->additional_records[i].name, delegation_name)))
    {
      GNUNET_assert (sizeof (struct in_addr) ==
                     packet->authority_records[i].data.raw.data_len);
      
      rh->dns_addr.sin_addr =
        *((struct in_addr*)packet->authority_records[i].data.raw.data);
      send_dns_packet (rh);
      GNUNET_DNSPARSER_free_packet (packet);
      return;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Nothing useful in DNS reply!\n");
  finish_lookup (rh, rlh, 0, NULL);
  GNUNET_NETWORK_socket_close (rh->dns_sock);
  free_resolver_handle (rh);
  GNUNET_DNSPARSER_free_packet (packet);
  return;
}

/**
 * Sends a UDP dns query to a nameserver specified in the rh
 * 
 * @param rh the request handle
 */
static void
send_dns_packet (struct ResolverHandle *rh)
{
  struct GNUNET_NETWORK_FDSet *rset = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (rset, rh->dns_sock);
  
  GNUNET_NETWORK_socket_sendto (rh->dns_sock,
                                rh->dns_raw_packet,
                                rh->dns_raw_packet_size,
                                (struct sockaddr*)&rh->dns_addr,
                                sizeof (struct sockaddr_in));

  rh->dns_read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                                    rh->timeout, //FIXME less?
                                                    rset,
                                                    NULL,
                                                    &read_dns_response,
                                                    rh);

  GNUNET_NETWORK_fdset_destroy (rset);

}

/**
 * The final phase of resoution.
 * We found a NS RR and want to resolve via DNS
 *
 * @param rh the pending lookup handle
 * @param rd_count length of record data
 * @param rd record data containing VPN RR
 */
static void
resolve_record_dns (struct ResolverHandle *rh,
                    int rd_count,
                    const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_DNSPARSER_Query query;
  struct GNUNET_DNSPARSER_Packet packet;
  struct GNUNET_DNSPARSER_Flags flags;
  struct in_addr dnsip;
  struct sockaddr_in addr;
  struct sockaddr *sa;
  int i;
  struct RecordLookupHandle *rlh = rh->proc_cls;

  memset (&packet, 0, sizeof (struct GNUNET_DNSPARSER_Packet));
  
  /* We cancel here as to not include the ns lookup in the timeout */
  if (rh->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Start shortening */
  if ((rh->priv_key != NULL) && is_canonical (rh->name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_DNS-%llu: Trying to shorten authority chain\n",
             rh->id);
    start_shorten (rh->authority_chain_tail,
                   rh->priv_key);
  }

  for (i = 0; i < rd_count; i++)
  {
    /* Synthesize dns name */
    if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_NS)
    {
      strcpy (rh->dns_zone, (char*)rd[i].data);
      if (0 == strcmp (rh->name, ""))
        strcpy (rh->dns_name, (char*)rd[i].data);
      else
        sprintf (rh->dns_name, "%s.%s", rh->name, (char*)rd[i].data);
    }
    /* The glue */
    if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_A)
      dnsip = *((struct in_addr*)rd[i].data);
  }
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_PHASE_REC_DNS-%llu: Looking up %s from %s\n",
              rh->id,
              rh->dns_name,
              inet_ntoa (dnsip));
  rh->dns_sock = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
  if (rh->dns_sock == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_DNS-%llu: Error creating udp socket for dns!\n",
                rh->id);
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }

  memset (&addr, 0, sizeof (struct sockaddr_in));
  sa = (struct sockaddr *) &addr;
  sa->sa_family = AF_INET;
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (rh->dns_sock,
                                               sa,
                                               sizeof (struct sockaddr_in)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_DNS-%llu: Error binding udp socket for dns!\n",
                rh->id);
    GNUNET_NETWORK_socket_close (rh->dns_sock);
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }
  
  /*TODO create dnsparser query, serialize, sendto, handle reply*/
  query.name = rh->dns_name;
  query.type = rlh->record_type;
  query.class = GNUNET_DNSPARSER_CLASS_INTERNET;
  memset (&flags, 0, sizeof (flags));
  flags.recursion_desired = 1;
  flags.checking_disabled = 1;
  packet.queries = &query;
  packet.answers = NULL;
  packet.authority_records = NULL;
  packet.num_queries = 1;
  packet.num_answers = 0;
  packet.num_authority_records = 0;
  packet.num_additional_records = 0;
  packet.flags = flags;
  packet.id = rh->id;
  if (GNUNET_OK != GNUNET_DNSPARSER_pack (&packet,
                                          UINT16_MAX,
                                          &rh->dns_raw_packet,
                                          &rh->dns_raw_packet_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_DNS-%llu: Creating raw dns packet!\n",
                rh->id);
    GNUNET_NETWORK_socket_close (rh->dns_sock);
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }

  rh->dns_addr.sin_family = AF_INET;
  rh->dns_addr.sin_port = htons (53); //domain
  rh->dns_addr.sin_addr = dnsip;
#if HAVE_SOCKADDR_IN_SIN_LEN
  rh->dns_addr.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif

  send_dns_packet (rh);
}


/**
 * The final phase of resoution.
 * We found a VPN RR and want to request an IPv4/6 address
 *
 * @param rh the pending lookup handle
 * @param rd_count length of record data
 * @param rd record data containing VPN RR
 */
static void
resolve_record_vpn (struct ResolverHandle *rh,
                    int rd_count,
                    const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int af;
  int proto;
  struct GNUNET_HashCode peer_id;
  struct GNUNET_CRYPTO_HashAsciiEncoded s_pid;
  struct GNUNET_HashCode serv_desc;
  struct GNUNET_CRYPTO_HashAsciiEncoded s_sd;
  char* pos;
  size_t len = (sizeof (uint32_t) * 2) + (sizeof (struct GNUNET_HashCode) * 2);
  
  /* We cancel here as to not include the ns lookup in the timeout */
  if (rh->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Start shortening */
  if ((rh->priv_key != NULL) && is_canonical (rh->name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_VPN-%llu: Trying to shorten authority chain\n",
             rh->id);
    start_shorten (rh->authority_chain_tail,
                   rh->priv_key);
  }

  /* Extracting VPN information FIXME rd parsing with NS API?*/
  if (len != rd->data_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_VPN-%llu: Error parsing VPN RR!\n",
                rh->id);
    finish_lookup (rh, rh->proc_cls, 0, NULL);
    free_resolver_handle (rh);
    return;
  }

  pos = (char*)rd;
  memcpy (&af, pos, sizeof (uint32_t));
  pos += sizeof (uint32_t);
  memcpy (&proto, pos, sizeof (uint32_t));
  pos += sizeof (uint32_t);
  memcpy (&s_pid, pos, sizeof (struct GNUNET_HashCode));
  pos += sizeof (struct GNUNET_HashCode);
  memcpy (&s_sd, pos, sizeof (struct GNUNET_HashCode));


  if ((GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char*)&s_pid, &peer_id)) ||
      (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char*)&s_sd, &serv_desc)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_VPN-%llu: Error parsing VPN RR hashes!\n",
                rh->id);
    finish_lookup (rh, rh->proc_cls, 0, NULL);
    free_resolver_handle (rh);
    return;
  }

  rh->proc = &handle_record_vpn;

  if (NULL == vpn_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_REC_VPN-%llu: VPN not connected!\n",
                rh->id);
    finish_lookup (rh, rh->proc_cls, 0, NULL);
    free_resolver_handle (rh);
    return;
  }
  
  //FIXME timeout??
  rh->vpn_handle = GNUNET_VPN_redirect_to_peer (vpn_handle,
                                          af, proto,
                                          (struct GNUNET_PeerIdentity*)&peer_id,
                                          &serv_desc,
                                          GNUNET_NO, //nac
                                          GNUNET_TIME_UNIT_FOREVER_ABS, //FIXME
                                          &process_record_result_vpn,
                                          rh);

}

/**
 * The final phase of resolution.
 * rh->name is a name that is canonical and we do not have a delegation.
 * Query namestore for this record
 *
 * @param rh the pending lookup handle
 */
static void
resolve_record_ns(struct ResolverHandle *rh)
{
  struct RecordLookupHandle *rlh = (struct RecordLookupHandle *)rh->proc_cls;
  
  /* We cancel here as to not include the ns lookup in the timeout */
  if (rh->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Start shortening */
  if ((rh->priv_key != NULL) && is_canonical (rh->name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%llu: Trying to shorten authority chain\n",
             rh->id);
    start_shorten (rh->authority_chain_tail,
                   rh->priv_key);
  }
  
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
  struct RecordLookupHandle *rlh = rh->proc_cls;
  char new_name[MAX_DNS_NAME_LENGTH];

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
         "GNS_PHASE_DELEGATE_DHT-%llu: dht lookup for query %s (%ds)timed out.\n",
         rh->id, rh->authority_name, rh->timeout.rel_value);

  rh->status |= RSL_TIMED_OUT;

  rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  
  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  
  if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_DELEGATE_DHT-%llu: Got shutdown\n",
               rh->id);
    rh->proc(rh->proc_cls, rh, 0, NULL);
    return;
  }

  if (strcmp(rh->name, "") == 0)
  {
    /*
     * promote authority back to name and try to resolve record
     */
    strcpy(rh->name, rh->authority_name);
    rh->proc(rh->proc_cls, rh, 0, NULL);
    return;
  }
  
  /**
   * Start resolution in bg
   */
  GNUNET_snprintf(new_name, MAX_DNS_NAME_LENGTH,
                  "%s.%s.%s", rh->name, rh->authority_name, GNUNET_GNS_TLD);
  //strcpy(new_name, rh->name);
  //strcpy(new_name+strlen(new_name), ".");
  //memcpy(new_name+strlen(new_name), GNUNET_GNS_TLD, strlen(GNUNET_GNS_TLD));
  
  strcpy(rh->name, new_name);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "GNS_PHASE_DELEGATE_DHT-%llu: Starting background query for %s type %d\n",
        rh->id, rh->name, rlh->record_type);

  gns_resolver_lookup_record(rh->authority,
                             rh->private_local_zone,
                             rlh->record_type,
                             new_name,
                             rh->priv_key,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             GNUNET_NO,
                             &background_lookup_result_processor,
                             NULL);

  rh->proc(rh->proc_cls, rh, 0, NULL);
}

/* Prototype */
static void resolve_delegation_dht(struct ResolverHandle *rh);

/* Prototype */
static void resolve_delegation_ns(struct ResolverHandle *rh);


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
                          const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * This is a callback function that checks for key revocation
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
process_pkey_revocation_result_ns (void *cls,
                    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                    struct GNUNET_TIME_Absolute expiration,
                    const char *name,
                    unsigned int rd_count,
                    const struct GNUNET_NAMESTORE_RecordData *rd,
                    const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = cls;
  struct GNUNET_TIME_Relative remaining_time;
  int i;
  
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);
  
  for (i = 0; i < rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_GNS_RECORD_REV)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_REV-%llu: Zone has been revoked.\n",
                 rh->id);
      rh->status |= RSL_PKEY_REVOKED;
      rh->proc (rh->proc_cls, rh, 0, NULL);
      return;
    }
  }
  
  if ((name == NULL) ||
      (remaining_time.rel_value == 0))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "GNS_PHASE_DELEGATE_REV-%llu: + Records don't exist or are expired.\n",
          rh->id, name);

    if (rh->timeout.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "GNS_PHASE_DELEGATE_REV-%d: Starting background lookup for %s type %d\n",
        rh->id, "+.gnunet", GNUNET_GNS_RECORD_REV);

      gns_resolver_lookup_record(rh->authority,
                                 rh->private_local_zone,
                                 GNUNET_GNS_RECORD_REV,
                                 GNUNET_GNS_TLD,
                                 rh->priv_key,
                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                 GNUNET_NO,
                                 &background_lookup_result_processor,
                                 NULL);
    }
  }
 GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_REV-%llu: Revocation checkpassed\n",
             rh->id);
  /**
   * We are done with PKEY resolution if name is empty
   * else resolve again with new authority
   */
  if (strcmp (rh->name, "") == 0)
    rh->proc (rh->proc_cls, rh, 0, NULL);
  else
    resolve_delegation_ns (rh);
  return;
}


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
                 const struct GNUNET_HashCode * key,
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
  struct GNUNET_CRYPTO_ShortHashCode zone, name_hash;
  struct GNUNET_HashCode zone_hash_double, name_hash_double;

  rh = (struct ResolverHandle *)cls;
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_DHT-%llu: Got DHT result\n", rh->id);

  if (data == NULL)
    return;
  
  nrb = (struct GNSNameRecordBlock*)data;
  
  /* stop dht lookup and timeout task */
  GNUNET_DHT_get_stop (rh->get_handle);

  rh->get_handle = NULL;

  if (rh->dht_heap_node != NULL)
  {
    GNUNET_CONTAINER_heap_remove_node(rh->dht_heap_node);
    rh->dht_heap_node = NULL;
  }

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
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 "GNS_PHASE_DELEGATE_DHT-%llu: Error deserializing data!\n",
                 rh->id);
      return;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_DELEGATE_DHT-%llu: Got name: %s (wanted %s)\n",
               rh->id, name, rh->authority_name);
    for (i=0; i<num_records; i++)
    {
    
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_DELEGATE_DHT-%llu: Got name: %s (wanted %s)\n",
                rh->id, name, rh->authority_name);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_DHT-%llu: Got type: %d (wanted %d)\n",
                 rh->id, rd[i].record_type, GNUNET_GNS_RECORD_PKEY);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_DHT-%llu: Got data length: %d\n",
                 rh->id, rd[i].data_size);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_DHT-%llu: Got flag %d\n",
                 rh->id, rd[i].flags);
      
      if ((rd[i].record_type == GNUNET_GNS_RECORD_VPN) ||
          (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_NS) ||
          (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_CNAME))
      {
        /**
         * This is a VPN,NS,CNAME entry. Let namestore handle this after caching
         */
        if (strcmp(rh->name, "") == 0)
          strcpy(rh->name, rh->authority_name);
        else
          GNUNET_snprintf(rh->name, MAX_DNS_NAME_LENGTH, "%s.%s",
                 rh->name, rh->authority_name); //FIXME ret
        rh->answered = 1;
        break;
      }

      if ((strcmp(name, rh->authority_name) == 0) &&
          (rd[i].record_type == GNUNET_GNS_RECORD_PKEY))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_DELEGATE_DHT-%llu: Authority found in DHT\n",
                   rh->id);
        rh->answered = 1;
        memcpy(&rh->authority, rd[i].data, sizeof(struct GNUNET_CRYPTO_ShortHashCode));
        struct AuthorityChain *auth =
          GNUNET_malloc(sizeof(struct AuthorityChain));
        auth->zone = rh->authority;
        memset(auth->name, 0, strlen(rh->authority_name)+1);
        strcpy(auth->name, rh->authority_name);
        GNUNET_CONTAINER_DLL_insert (rh->authority_chain_head,
                                     rh->authority_chain_tail,
                                     auth);

        /** try to import pkey if private key available */
        //if (rh->priv_key && is_canonical (rh->name))
        //  process_discovered_authority(name, auth->zone,
        //                               rh->authority_chain_tail->zone,
        //                               rh->priv_key);
      }

    }


    GNUNET_CRYPTO_short_hash(name, strlen(name), &name_hash);
    GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
    GNUNET_CRYPTO_hash_xor(key, &name_hash_double, &zone_hash_double);
    GNUNET_CRYPTO_short_hash_from_truncation (&zone_hash_double, &zone);

    /* Save to namestore */
    if (0 != GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_tail->zone,
                                          &zone))
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
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "GNS_PHASE_DELEGATE_DHT-%llu: Answer from DHT for %s. Yet to resolve: %s\n",
      rh->id, rh->authority_name, rh->name);

    if (strcmp(rh->name, "") == 0)
    {
      /* Start shortening */
      if ((rh->priv_key != NULL) && is_canonical (rh->name))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_DHT-%llu: Trying to shorten authority chain\n",
             rh->id);
        start_shorten (rh->authority_chain_tail,
                       rh->priv_key);
      }
    }
    else
      rh->proc = &handle_delegation_ns;

    /* Check for key revocation and delegate */
    GNUNET_NAMESTORE_lookup_record (namestore_handle,
                                    &rh->authority,
                                    "+",
                                    GNUNET_GNS_RECORD_REV,
                                    &process_pkey_revocation_result_ns,
                                    rh);   
    
    /*if (strcmp(rh->name, "") == 0)
    {
      if ((rh->priv_key != NULL) && is_canonical (rh->name))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_DHT-%llu: Trying to shorten authority chain\n",
             rh->id);
        start_shorten (rh->authority_chain_tail,
                       rh->priv_key);
      }
      
      rh->proc(rh->proc_cls, rh, 0, NULL);
    }
    else
    {
      rh->proc = &handle_delegation_ns;
      resolve_delegation_ns (rh);
    }
    */
    return;
  }
  
  /**
   * No pkey but name exists
   * promote back
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_DHT-%llu: Adding %s back to %s\n",
             rh->id, rh->authority_name, rh->name);
  if (strcmp(rh->name, "") == 0)
    strcpy(rh->name, rh->authority_name);
  else
    GNUNET_snprintf(rh->name, MAX_DNS_NAME_LENGTH, "%s.%s",
                  rh->name, rh->authority_name); //FIXME ret
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_DHT-%llu: %s restored\n", rh->id, rh->name);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
           "GNS_PHASE_DELEGATE_DHT-%llu: DHT authority lookup found no match!\n",
           rh->id);
  rh->proc(rh->proc_cls, rh, 0, NULL);
}

#define MAX_SOA_LENGTH sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)\
                        +(MAX_DNS_NAME_LENGTH*2)
#define MAX_MX_LENGTH sizeof(uint16_t)+MAX_DNS_NAME_LENGTH
#define MAX_SRV_LENGTH (sizeof(uint16_t)*3)+MAX_DNS_NAME_LENGTH


static void
expand_plus(char** dest, char* src, char* repl)
{
  char* pos;
  unsigned int s_len = strlen(src)+1;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_POSTPROCESS: Got %s to expand with %s\n", src, repl);

  if (s_len < 3)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: %s to short\n", src);

    /* no postprocessing */
    memcpy(*dest, src, s_len+1);
    return;
  }
  
  if (0 == strcmp(src+s_len-3, ".+"))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: Expanding .+ in %s\n", src);
    memset(*dest, 0, s_len+strlen(repl)+strlen(GNUNET_GNS_TLD));
    strcpy(*dest, src);
    pos = *dest+s_len-2;
    strcpy(pos, repl);
    pos += strlen(repl);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: Expanded to %s\n", *dest);
  }
  else
  {
    memcpy(*dest, src, s_len+1);
  }
}

/**
 * finish lookup
 */
static void
finish_lookup(struct ResolverHandle *rh,
              struct RecordLookupHandle* rlh,
              unsigned int rd_count,
              const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  char new_rr_data[MAX_DNS_NAME_LENGTH];
  char new_mx_data[MAX_MX_LENGTH];
  char new_soa_data[MAX_SOA_LENGTH];
  char new_srv_data[MAX_SRV_LENGTH];
  struct GNUNET_NAMESTORE_RecordData p_rd[rd_count];
  char* repl_string;
  char* pos;
  unsigned int offset;

  if (rh->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (rd_count > 0)
    memcpy(p_rd, rd, rd_count*sizeof(struct GNUNET_NAMESTORE_RecordData));

  for (i = 0; i < rd_count; i++)
  {
    
    if (rd[i].record_type != GNUNET_GNS_RECORD_TYPE_NS &&
        rd[i].record_type != GNUNET_GNS_RECORD_TYPE_CNAME &&
        rd[i].record_type != GNUNET_GNS_RECORD_MX &&
        rd[i].record_type != GNUNET_GNS_RECORD_TYPE_SOA &&
        rd[i].record_type != GNUNET_GNS_RECORD_TYPE_SRV)
    {
      p_rd[i].data = rd[i].data;
      continue;
    }

    /**
     * for all those records we 'should'
     * also try to resolve the A/AAAA records (RFC1035)
     * This is a feature and not important
     */
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: Postprocessing\n");

    if (strcmp(rh->name, "+") == 0)
      repl_string = rlh->name;
    else
      repl_string = rlh->name+strlen(rh->name)+1;

    offset = 0;
    if (rd[i].record_type == GNUNET_GNS_RECORD_MX)
    {
      memcpy (new_mx_data, (char*)rd[i].data, sizeof(uint16_t));
      offset = sizeof(uint16_t);
      pos = new_mx_data+offset;
      expand_plus(&pos, (char*)rd[i].data+sizeof(uint16_t),
                  repl_string);
      offset += strlen(new_mx_data+sizeof(uint16_t))+1;
      p_rd[i].data = new_mx_data;
      p_rd[i].data_size = offset;
    }
    else if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_SRV)
    {
      /*
       * Prio, weight and port
       */
      memcpy (new_srv_data, (char*)rd[i].data, sizeof (uint16_t) * 3);
      offset = sizeof (uint16_t) * 3;
      pos = new_srv_data+offset;
      expand_plus(&pos, (char*)rd[i].data+(sizeof(uint16_t)*3),
                  repl_string);
      offset += strlen(new_srv_data+(sizeof(uint16_t)*3))+1;
      p_rd[i].data = new_srv_data;
      p_rd[i].data_size = offset;
    }
    else if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_SOA)
    {
      /* expand mname and rname */
      pos = new_soa_data;
      expand_plus(&pos, (char*)rd[i].data, repl_string);
      offset = strlen(new_soa_data)+1;
      pos = new_soa_data+offset;
      expand_plus(&pos, (char*)rd[i].data+offset, repl_string);
      offset += strlen(new_soa_data+offset)+1;
      /* cpy the 4 numbers serial refresh retry and expire */
      memcpy(new_soa_data+offset, (char*)rd[i].data+offset, sizeof(uint32_t)*5);
      offset += sizeof(uint32_t)*5;
      p_rd[i].data_size = offset;
      p_rd[i].data = new_soa_data;
    }
    else
    {
      pos = new_rr_data;
      expand_plus(&pos, (char*)rd[i].data, repl_string);
      p_rd[i].data_size = strlen(new_rr_data)+1;
      p_rd[i].data = new_rr_data;
    }
    
  }

  rlh->proc(rlh->proc_cls, rd_count, p_rd);
  GNUNET_free(rlh);
  
}

/**
 * Process DHT lookup result for record.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results
 * @param rd record data
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
               "GNS_PHASE_REC-%d: No records for %s found in DHT. Aborting\n",
               rh->id, rh->name);
    /* give up, cannot resolve */
    finish_lookup(rh, rlh, 0, NULL);
    free_resolver_handle(rh);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: Record resolved from DHT!", rh->id);

  finish_lookup(rh, rlh, rd_count, rd);
  free_resolver_handle(rh);

}




/**
 * Process namestore lookup result for record.
 *
 * @param cls the closure
 * @param rh resolver handle
 * @param rd_count number of results
 * @param rd record data
 */
static void
handle_record_ns (void* cls, struct ResolverHandle *rh,
                  unsigned int rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  int check_dht = GNUNET_YES;

  if (rd_count == 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%d: NS returned no records. (status: %d)!\n",
               rh->id,
               rh->status);
    
    /**
     * There are 5 conditions that have to met for us to consult the DHT:
     * 1. The entry in the DHT is RSL_RECORD_EXPIRED OR
     * 2. No entry in the NS existed AND
     * 3. The zone queried is not the local resolver's zone AND
     * 4. The name that was looked up is '+'
     *    because if it was any other canonical name we either already queried
     *    the DHT for the authority in the authority lookup phase (and thus
     *    would already have an entry in the NS for the record)
     * 5. We are not in cache only mode
     */
    if (((rh->status & RSL_RECORD_EXPIRED) != 0) &&
        ((rh->status & RSL_RECORD_EXISTS) == 0) )
      check_dht = GNUNET_NO;
    
    if (0 != GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                          &rh->private_local_zone))
      check_dht = GNUNET_NO;
    
    if ((strcmp (rh->name, "+") != 0) && (is_srv (rh->name) != 0))
        check_dht = GNUNET_NO;


    if (rh->only_cached == GNUNET_YES)
      check_dht = GNUNET_NO;
    
    if (GNUNET_YES == check_dht)
    {
      rh->proc = &handle_record_dht;
      resolve_record_dht(rh);
      return;
    }
    /* give up, cannot resolve */
    finish_lookup(rh, rlh, 0, NULL);
    free_resolver_handle(rh);
    return;
  }

  /* results found yay */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%d: Record resolved from namestore!", rh->id);

  finish_lookup(rh, rlh, rd_count, rd);

  free_resolver_handle(rh);

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

  if (is_canonical (name))
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
 * Checks if name is in tld
 *
 * @param name the name to check
 * @param tld the TLD to check for
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tld(const char* name, const char* tld)
{
  int offset = 0;

  if (strlen(name) <= strlen(tld))
  {
    return GNUNET_NO;
  }
  
  offset = strlen(name)-strlen(tld);
  if (strcmp(name+offset, tld) != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "%s is not in .%s TLD\n", name, tld);
    return GNUNET_NO;
  }
  return GNUNET_YES;
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
    if ((rlh->record_type == GNUNET_GNS_RECORD_PKEY))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_DHT-%llu: Resolved queried PKEY via DHT.\n",
                 rh->id);
      finish_lookup(rh, rlh, rd_count, rd);
      free_resolver_handle(rh);
      return;
    }
    /* We resolved full name for delegation. resolving record */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
     "GNS_PHASE_DELEGATE_DHT-%llu: Resolved full name for delegation via DHT.\n",
     rh->id);
    strcpy(rh->name, "+\0");
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
             "GNS_PHASE_DELEGATE_DHT-%llu: Resolving canonical record %s in ns\n",
             rh->id,
             rh->name);
    rh->proc = &handle_record_ns;
    resolve_record_ns(rh);
    return;
  }
  /* give up, cannot resolve */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
 "GNS_PHASE_DELEGATE_DHT-%llu: Cannot fully resolve delegation for %s via DHT!\n",
 rh->id, rh->name);
  finish_lookup(rh, rlh, 0, NULL);
  free_resolver_handle(rh);
}


/**
 * Start DHT lookup for a name -> PKEY (compare NS) record in
 * rh->authority's zone
 *
 * @param rh the pending gns query
 */
static void
resolve_delegation_dht(struct ResolverHandle *rh)
{
  uint32_t xquery;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  struct GNUNET_HashCode lookup_key;
  struct ResolverHandle *rh_heap_root;
  
  pop_tld(rh->name, rh->authority_name); 
  GNUNET_CRYPTO_short_hash(rh->authority_name,
                     strlen(rh->authority_name),
                     &name_hash);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double(&rh->authority, &zone_hash_double);
  GNUNET_CRYPTO_hash_xor(&name_hash_double, &zone_hash_double, &lookup_key);
  
  rh->dht_heap_node = NULL;

  if (rh->timeout.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
  {
    //rh->timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
    //                                          &dht_authority_lookup_timeout,
    //                                                   rh);
    rh->timeout_cont = &dht_authority_lookup_timeout;
    rh->timeout_cont_cls = rh;
  }
  else 
  {
    if (max_allowed_background_queries <=
        GNUNET_CONTAINER_heap_get_size (dht_lookup_heap))
    {
      /* terminate oldest lookup */
      rh_heap_root = GNUNET_CONTAINER_heap_remove_root (dht_lookup_heap);
      GNUNET_DHT_get_stop(rh_heap_root->get_handle);
      rh_heap_root->dht_heap_node = NULL;
      
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "GNS_PHASE_DELEGATE_DHT-%llu: Replacing oldest background query for %s\n",
        rh->id, rh_heap_root->authority_name);
      
      rh_heap_root->proc(rh_heap_root->proc_cls,
                         rh_heap_root,
                         0,
                         NULL);
    }
    rh->dht_heap_node = GNUNET_CONTAINER_heap_insert (dht_lookup_heap,
                                         rh,
                                         GNUNET_TIME_absolute_get().abs_value);
  }
  
  xquery = htonl(GNUNET_GNS_RECORD_PKEY);
  
  GNUNET_assert(rh->get_handle == NULL);
  rh->get_handle = GNUNET_DHT_get_start(dht_handle,
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
handle_delegation_ns (void* cls, struct ResolverHandle *rh,
                      unsigned int rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle* rlh;
  rlh = (struct RecordLookupHandle*) cls;
  int check_dht = GNUNET_YES;
  int s_len = 0;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_NS-%llu: Resolution status: %d.\n",
             rh->id, rh->status);

  if (rh->status & RSL_PKEY_REVOKED)
  {
    finish_lookup (rh, rlh, 0, NULL);
    free_resolver_handle (rh);
    return;
  }
  
  if (strcmp(rh->name, "") == 0)
  {
    
    /* We resolved full name for delegation. resolving record */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
              "GNS_PHASE_DELEGATE_NS-%llu: Resolved full name for delegation.\n",
              rh->id);
    if (rh->status & RSL_CNAME_FOUND)
    {
      if (rlh->record_type == GNUNET_GNS_RECORD_TYPE_CNAME)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: Resolved queried CNAME in NS.\n",
                  rh->id);
        strcpy (rh->name, rh->authority_name);
        finish_lookup (rh, rlh, rd_count, rd);
        free_resolver_handle (rh);
        return;
      }
      
      /* A .+ CNAME  */
      if (is_tld ((char*)rd->data, GNUNET_GNS_TLD_PLUS))
      {
        s_len = strlen (rd->data) - 2;
        memcpy (rh->name, rd->data, s_len);
        rh->name[s_len] = '\0';
        resolve_delegation_ns (rh);
        return;
      }
      else if (is_tld ((char*)rd->data, GNUNET_GNS_TLD_ZKEY))
      {
        gns_resolver_lookup_record (rh->authority,
                                    rh->private_local_zone,
                                    rlh->record_type,
                                    (char*)rd->data,
                                    rh->priv_key,
                                    rh->timeout,
                                    rh->only_cached,
                                    rlh->proc,
                                    rlh->proc_cls);
        GNUNET_free (rlh);
        free_resolver_handle (rh);
        return;
      }
      else
      {
        //Try DNS resolver
        strcpy (rh->dns_name, (char*)rd->data);
        resolve_dns_name (rh);
        return;
      }

    }
    else if (rh->status & RSL_DELEGATE_VPN)
    {
      if (rlh->record_type == GNUNET_GNS_RECORD_VPN)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: Resolved queried VPNRR in NS.\n",
                 rh->id);
        finish_lookup(rh, rlh, rd_count, rd);
        free_resolver_handle(rh);
        return;
      }
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_NS-%llu: VPN delegation starting.\n",
             rh->id);
      GNUNET_assert (NULL != rd);
      rh->proc = &handle_record_vpn;
      resolve_record_vpn (rh, rd_count, rd);
      return;
    }
    else if (rh->status & RSL_DELEGATE_NS)
    {
      if (rlh->record_type == GNUNET_GNS_RECORD_TYPE_NS)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_DELEGATE_NS-%llu: Resolved queried NSRR in NS.\n",
                   rh->id);
        finish_lookup(rh, rlh, rd_count, rd);
        free_resolver_handle(rh);
        return;
      }
      
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: NS delegation starting.\n",
                 rh->id);
      GNUNET_assert (NULL != rd);
      rh->proc = &handle_record_ns;
      resolve_record_dns (rh, rd_count, rd);
      return;
    }
    else if (rh->status & RSL_DELEGATE_PKEY)
    {
      if (rh->status & RSL_PKEY_REVOKED)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_DELEGATE_NS-%llu: Resolved PKEY is revoked.\n",
                   rh->id);
        finish_lookup (rh, rlh, 0, NULL);
        free_resolver_handle (rh);
        return;
      }
      else if (rlh->record_type == GNUNET_GNS_RECORD_PKEY)
      {
        GNUNET_assert(rd_count == 1);
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                   "GNS_PHASE_DELEGATE_NS-%llu: Resolved queried PKEY in NS.\n",
                   rh->id);
        finish_lookup(rh, rlh, rd_count, rd);
        free_resolver_handle(rh);
        return;
      }
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_DELEGATE_NS-%llu: Resolving record +\n",
               rh->id);
    strcpy(rh->name, "+\0");
    rh->proc = &handle_record_ns;
    resolve_record_ns(rh);
    return;
  }
  
  if (rh->status & RSL_DELEGATE_NS)
  {
    if (rlh->record_type == GNUNET_GNS_RECORD_TYPE_NS)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: Resolved queried NSRR in NS.\n",
                 rh->id);
      finish_lookup(rh, rlh, rd_count, rd);
      free_resolver_handle(rh);
      return;
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_DELEGATE_NS-%llu: NS delegation starting.\n",
               rh->id);
    GNUNET_assert (NULL != rd);
    rh->proc = &handle_record_ns;
    resolve_record_dns (rh, rd_count, rd);
    return;
  }
  
  /**
   * we still have some left
   * check if authority in ns is fresh
   * and exists
   * or we are authority
   **/

  if ((rh->status & RSL_RECORD_EXISTS) &&
       !(rh->status & RSL_RECORD_EXPIRED))
    check_dht = GNUNET_NO;

  if (0 == GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        &rh->private_local_zone))
    check_dht = GNUNET_NO;

  if (rh->only_cached == GNUNET_YES)
    check_dht = GNUNET_NO;

  if (check_dht == GNUNET_NO)
  {
    if (is_canonical(rh->name))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: Resolving canonical record %s\n",
                 rh->id,
                 rh->name);
      rh->proc = &handle_record_ns;
      resolve_record_ns(rh);
    }
    else
    {
      /* give up, cannot resolve */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "GNS_PHASE_DELEGATE_NS-%llu: Cannot fully resolve delegation for %s!\n",
          rh->id,
          rh->name);
      finish_lookup(rh, rlh, rd_count, rd);
      //rlh->proc(rlh->proc_cls, 0, NULL);
    }
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "GNS_PHASE_DELEGATE_NS-%llu: Trying to resolve delegation for %s via DHT\n",
      rh->id, rh->name);
  rh->proc = &handle_delegation_dht;
  resolve_delegation_dht(rh);
}


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
process_delegation_result_ns (void* cls,
                   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                   struct GNUNET_TIME_Absolute expiration,
                   const char *name,
                   unsigned int rd_count,
                   const struct GNUNET_NAMESTORE_RecordData *rd,
                   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh;
  struct GNUNET_TIME_Relative remaining_time;
  struct GNUNET_CRYPTO_ShortHashCode zone;
  char new_name[MAX_DNS_NAME_LENGTH];
  unsigned int i;
  struct GNUNET_TIME_Absolute et;
 
  rh = (struct ResolverHandle *)cls; 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "GNS_PHASE_DELEGATE_NS-%llu: Got %d records from authority lookup\n",
          rh->id, rd_count);

  GNUNET_CRYPTO_short_hash (key,
                      sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &zone);
  remaining_time = GNUNET_TIME_absolute_get_remaining (expiration);
  
  rh->status = 0;
  
  if (name != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS_PHASE_DELEGATE_NS-%llu: Records with name %s exist.\n",
                rh->id, name);
    rh->status |= RSL_RECORD_EXISTS;
  
    if (remaining_time.rel_value == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: Record set %s expired.\n",
                  rh->id, name);
      rh->status |= RSL_RECORD_EXPIRED;
    }
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
    if (strcmp (rh->name, "") == 0)
    {
      /* simply promote back */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: Promoting %s back to name\n",
                  rh->id, rh->authority_name);
      strcpy (rh->name, rh->authority_name);
    }
    else
    {
      /* add back to existing name */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: Adding %s back to %s\n",
                  rh->id, rh->authority_name, rh->name);
      GNUNET_snprintf (new_name, MAX_DNS_NAME_LENGTH, "%s.%s",
                       rh->name, rh->authority_name);
      strcpy (rh->name, new_name);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: %s restored\n",
                  rh->id, rh->name);
    }

    rh->proc (rh->proc_cls, rh, 0, NULL);
    return;
  }

  /**
   * We found an authority that may be able to help us
   * move on with query
   * Note only 1 pkey should have been returned.. anything else would be strange
   */
  for (i=0; i < rd_count;i++)
  {
    
    /**
     * A CNAME. Like regular DNS this means the is no other record for this
     * name.
     */
    if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_CNAME)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: CNAME found.\n",
                 rh->id);

      rh->status |= RSL_CNAME_FOUND;
      rh->proc (rh->proc_cls, rh, rd_count, rd);
      return;
    }

    /**
     * Redirect via VPN
     */
    if (rd[i].record_type == GNUNET_GNS_RECORD_VPN)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: VPN found.\n",
                 rh->id);
      rh->status |= RSL_DELEGATE_VPN;
      rh->proc (rh->proc_cls, rh, rd_count, rd);
      return;
    }

    /**
     * Redirect via NS
     * FIXME make optional
     */
    if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_NS)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_DELEGATE_NS-%llu: NS found.\n",
                 rh->id);
      rh->status |= RSL_DELEGATE_NS;
      rh->proc (rh->proc_cls, rh, rd_count, rd);
      return;
    }
  
    if (rd[i].record_type != GNUNET_GNS_RECORD_PKEY)
      continue;

    rh->status |= RSL_DELEGATE_PKEY;

    if ((ignore_pending_records != 0) &&
        (rd[i].flags & GNUNET_NAMESTORE_RF_PENDING))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
     "GNS_PHASE_DELEGATE_NS-%llu: PKEY for %s is pending user confirmation.\n",
        rh->id,
        name);
      continue;
    }
    
    GNUNET_break (0 == (rd[i].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION));
    et.abs_value = rd[i].expiration_time;
    if ((GNUNET_TIME_absolute_get_remaining (et)).rel_value
         == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_DELEGATE_NS-%llu: This pkey is expired.\n",
                  rh->id);
      if (remaining_time.rel_value == 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "GNS_PHASE_DELEGATE_NS-%llu: This dht entry is expired.\n",
                    rh->id);
        rh->authority_chain_head->fresh = 0;
        rh->proc (rh->proc_cls, rh, 0, NULL);
        return;
      }

      continue;
    }

    /**
     * Resolve rest of query with new authority
     */
    GNUNET_assert (rd[i].record_type == GNUNET_GNS_RECORD_PKEY);
    memcpy (&rh->authority, rd[i].data,
            sizeof (struct GNUNET_CRYPTO_ShortHashCode));
    struct AuthorityChain *auth = GNUNET_malloc(sizeof (struct AuthorityChain));
    auth->zone = rh->authority;
    memset (auth->name, 0, strlen (rh->authority_name)+1);
    strcpy (auth->name, rh->authority_name);
    GNUNET_CONTAINER_DLL_insert (rh->authority_chain_head,
                                 rh->authority_chain_tail,
                                 auth);
    
    /* Check for key revocation and delegate */
    GNUNET_NAMESTORE_lookup_record (namestore_handle,
                                    &rh->authority,
                                    "+",
                                    GNUNET_GNS_RECORD_REV,
                                    &process_pkey_revocation_result_ns,
                                    rh);
    return;
  
  }
  
  /**
   * no answers found
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
    "GNS_PHASE_DELEGATE_NS-%llu: Authority lookup and no PKEY...\n", rh->id);
  /**
   * If we have found some records for the LAST label
   * we return the results. Else null.
   */
  if (strcmp(rh->name, "") == 0)
  {
    /* Start shortening */
    if ((rh->priv_key != NULL) && is_canonical (rh->name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_PHASE_DELEGATE_NS-%llu: Trying to shorten authority chain\n",
              rh->id);
      start_shorten (rh->authority_chain_tail,
                    rh->priv_key);
    }
    /* simply promote back */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_DELEGATE_NS-%llu: Promoting %s back to name\n",
               rh->id, rh->authority_name);
    strcpy(rh->name, rh->authority_name);
    rh->proc(rh->proc_cls, rh, rd_count, rd);
  }
  else
  {
    rh->proc(rh->proc_cls, rh, 0, NULL);
  }
}


/**
 * Resolve the delegation chain for the request in our namestore
 *
 * @param rh the resolver handle
 */
static void
resolve_delegation_ns (struct ResolverHandle *rh)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_DELEGATE_NS-%llu: Resolving delegation for %s\n",
             rh->id, rh->name);
  pop_tld(rh->name, rh->authority_name);
  GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 &rh->authority,
                                 rh->authority_name,
                                 GNUNET_GNS_RECORD_ANY,
                                 &process_delegation_result_ns,
                                 rh);

}


/**
 * Lookup of a record in a specific zone
 * calls lookup result processor on result
 *
 * @param zone the root zone
 * @param pzone the private local zone
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param key a private key for use with PSEU import (can be NULL)
 * @param timeout timeout for resolution
 * @param only_cached GNUNET_NO to only check locally not DHT for performance
 * @param proc the processor to call on result
 * @param cls the closure to pass to proc
 */
void
gns_resolver_lookup_record (struct GNUNET_CRYPTO_ShortHashCode zone,
                            struct GNUNET_CRYPTO_ShortHashCode pzone,
                            uint32_t record_type,
                            const char* name,
                            struct GNUNET_CRYPTO_RsaPrivateKey *key,
                            struct GNUNET_TIME_Relative timeout,
                            int only_cached,
                            RecordLookupProcessor proc,
                            void* cls)
{
  struct ResolverHandle *rh;
  struct RecordLookupHandle* rlh;
  char string_hash[MAX_DNS_LABEL_LENGTH];
  char nzkey[MAX_DNS_LABEL_LENGTH];
  char* nzkey_ptr = nzkey;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              name, record_type);

  
  if (is_canonical((char*)name) && (strcmp(GNUNET_GNS_TLD, name) != 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is canonical and not gnunet -> cannot resolve!\n", name);
    proc(cls, 0, NULL);
    return;
  }
  
  rlh = GNUNET_malloc(sizeof(struct RecordLookupHandle));
  rh = GNUNET_malloc(sizeof (struct ResolverHandle));

  rh->authority = zone;
  rh->id = rid++;
  rh->proc_cls = rlh;
  rh->priv_key = key;
  rh->timeout = timeout;
  rh->get_handle = NULL;
  rh->private_local_zone = pzone;
  rh->only_cached = only_cached;
  
  if (NULL == key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No shorten key for resolution\n");
  }

  if (timeout.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
  {
    /*
     * Set timeout for authority lookup phase to 1/2
     */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout for lookup set to %ds\n", rh->timeout.rel_value);
    rh->timeout_task = GNUNET_SCHEDULER_add_delayed(
                                GNUNET_TIME_relative_divide(timeout, 2),
                                                &handle_lookup_timeout,
                                                rh);
    rh->timeout_cont = &dht_authority_lookup_timeout;
    rh->timeout_cont_cls = rh;
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "No timeout for query!\n");
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  
  if (strcmp(GNUNET_GNS_TLD, name) == 0)
  {
    /**
     * Only 'gnunet' given
     */
    strcpy(rh->name, "\0");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Checking for TLD...\n");
    if (is_zkey_tld(name) == GNUNET_YES)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "TLD is zkey\n");
      /**
       * This is a zkey tld
       * build hash and use as initial authority
       */
      memset(rh->name, 0,
             strlen(name)-strlen(GNUNET_GNS_TLD_ZKEY));
      memcpy(rh->name, name,
             strlen(name)-strlen(GNUNET_GNS_TLD_ZKEY) - 1);
      pop_tld(rh->name, string_hash);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ZKEY is %s!\n", string_hash);
      
      GNUNET_STRINGS_utf8_toupper(string_hash, &nzkey_ptr);

      if (GNUNET_OK != GNUNET_CRYPTO_short_hash_from_string(nzkey,
                                                      &rh->authority))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Cannot convert ZKEY %s to hash!\n", string_hash);
        GNUNET_free(rh);
        GNUNET_free(rlh);
        proc(cls, 0, NULL);
        return;
      }

    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "TLD is gnunet\n");
      /**
       * Presumably GNUNET tld
       */
      memset(rh->name, 0,
             strlen(name)-strlen(GNUNET_GNS_TLD));
      memcpy(rh->name, name,
             strlen(name)-strlen(GNUNET_GNS_TLD) - 1);
    }
  }
  
  /**
   * Initialize authority chain
   */
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_head->prev = NULL;
  rh->authority_chain_head->next = NULL;
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = rh->authority;
  
  /**
   * Copy original query into lookup handle
   */
  rlh->record_type = record_type;
  memset(rlh->name, 0, strlen(name) + 1);
  strcpy(rlh->name, name);
  rlh->proc = proc;
  rlh->proc_cls = cls;

  rh->proc = &handle_delegation_ns;
  resolve_delegation_ns(rh);
}

/******** END Record Resolver ***********/

/**
 * Callback calles by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_shorten_root (void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature);


/**
 * Callback called by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_shorten_shorten (void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = (struct ResolverHandle *)cls;
  struct NameShortenHandle* nsh = (struct NameShortenHandle*)rh->proc_cls;
  struct AuthorityChain *next_authority;

  char result[MAX_DNS_NAME_LENGTH];
  char tmp_name[MAX_DNS_NAME_LENGTH];
  size_t answer_len;
  
  /* we found a match in our own root zone */
  if (rd_len != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "result strlen %d\n", strlen(name));
    answer_len = strlen(rh->name) + strlen(name) + strlen(GNUNET_GNS_TLD) + 3;
    memset(result, 0, answer_len);

    if (strlen(rh->name) > 0)
    {
      sprintf (result, "%s.%s.%s.%s.%s",
               rh->name, name,
               nsh->shorten_zone_name, nsh->private_zone_name,
               GNUNET_GNS_TLD);
    }
    else
    {
      sprintf (result, "%s.%s.%s.%s", name,
               nsh->shorten_zone_name, nsh->private_zone_name,
               GNUNET_GNS_TLD);
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Found shorten result %s\n", result);
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  else if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        nsh->shorten_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s.%s.%s",
             rh->name,
             nsh->shorten_zone_name, nsh->private_zone_name,
             GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Found %s as shorten result\n", result);
    
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
    //nsh->proc(nsh->proc_cls, result);
    //GNUNET_free(nsh);
    //free_resolver_handle(rh);
    //return;
  }
  
  
  /**
   * No PSEU found.
   * continue with next authority if exists
   */
  if ((rh->authority_chain_head->next == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending %s as shorten result\n", nsh->result);
    nsh->proc(nsh->proc_cls, nsh->result);
    GNUNET_free (nsh);
    free_resolver_handle (rh);
    return;
  }
  next_authority = rh->authority_chain_head;
  
  GNUNET_snprintf(tmp_name, MAX_DNS_NAME_LENGTH,
                  "%s.%s", rh->name, next_authority->name);
  
  strcpy(rh->name, tmp_name);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "No PSEU found for authority %s. Promoting back: %s\n",
             next_authority->name, rh->name);
  
  GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                            rh->authority_chain_tail,
                            next_authority);

  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 &rh->authority_chain_tail->zone,
                                 &rh->authority_chain_head->zone,
                                 &process_zone_to_name_shorten_root,
                                 rh);
}

/**
 * Callback calles by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_shorten_private (void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = (struct ResolverHandle *)cls;
  struct NameShortenHandle* nsh = (struct NameShortenHandle*)rh->proc_cls;
  struct AuthorityChain *next_authority;

  char result[MAX_DNS_NAME_LENGTH];
  char tmp_name[MAX_DNS_NAME_LENGTH];
  size_t answer_len;
  
  /* we found a match in our own root zone */
  if (rd_len != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "result strlen %d\n", strlen(name));
    answer_len = strlen(rh->name) + strlen(name) + strlen(GNUNET_GNS_TLD) + 3;
    memset(result, 0, answer_len);

    if (strlen(rh->name) > 0)
    {
      sprintf (result, "%s.%s.%s", rh->name, name, GNUNET_GNS_TLD);
    }
    else
    {
      sprintf (result, "%s.%s", name, GNUNET_GNS_TLD);
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Found shorten result %s\n", result);
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  else if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        nsh->private_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s.%s",
             rh->name, nsh->private_zone_name, GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our private zone: Found %s as shorten result %s\n", result);
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  
  if (nsh->shorten_zone != NULL)
  {
    /* backtrack authorities for names in priv zone */
    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   nsh->shorten_zone,
                                   &rh->authority_chain_head->zone,
                                   &process_zone_to_name_shorten_shorten,
                                   rh);
  }
  else
  {
    /**
     * No PSEU found.
     * continue with next authority if exists
     */
    if ((rh->authority_chain_head->next == NULL))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Sending %s as shorten result\n", nsh->result);
      nsh->proc(nsh->proc_cls, nsh->result);
      GNUNET_free(nsh);
      free_resolver_handle(rh);
      return;
    }
    next_authority = rh->authority_chain_head;
    
    GNUNET_snprintf(tmp_name, MAX_DNS_NAME_LENGTH,
                    "%s.%s", rh->name, next_authority->name);
    
    strcpy(rh->name, tmp_name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "No PSEU found for authority %s. Promoting back: %s\n",
               next_authority->name, rh->name);
    
    GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                              rh->authority_chain_tail,
                              next_authority);

    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   &rh->authority_chain_tail->zone,
                                   &rh->authority_chain_head->zone,
                                   &process_zone_to_name_shorten_root,
                                   rh);
  }
}

/**
 * Callback calles by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_shorten_root (void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = (struct ResolverHandle *)cls;
  struct NameShortenHandle* nsh = (struct NameShortenHandle*)rh->proc_cls;
  struct AuthorityChain *next_authority;

  char result[MAX_DNS_NAME_LENGTH];
  char tmp_name[MAX_DNS_NAME_LENGTH];
  size_t answer_len;
  
  /* we found a match in our own root zone */
  if (rd_len != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "result strlen %d\n", strlen(name));
    answer_len = strlen(rh->name) + strlen(name) + strlen(GNUNET_GNS_TLD) + 3;
    memset(result, 0, answer_len);

    if (strlen(rh->name) > 0)
    {
      sprintf (result, "%s.%s.%s", rh->name, name, GNUNET_GNS_TLD);
    }
    else
    {
      sprintf (result, "%s.%s", name, GNUNET_GNS_TLD);
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Found shorten result %s\n", result);
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  else if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        nsh->root_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s", rh->name, GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Found %s as shorten result\n", result);
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  
  if (nsh->private_zone != NULL)
  {
    /* backtrack authorities for names in priv zone */
    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   nsh->private_zone,
                                   &rh->authority_chain_head->zone,
                                   &process_zone_to_name_shorten_private,
                                   rh);
  }
  else
  {
    /**
     * No PSEU found.
     * continue with next authority if exists
     */
    if ((rh->authority_chain_head->next == NULL))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Sending %s as shorten result\n", nsh->result);
      nsh->proc(nsh->proc_cls, nsh->result);
      GNUNET_free(nsh);
      free_resolver_handle(rh);
      return;
    }
    next_authority = rh->authority_chain_head;
    
    GNUNET_snprintf(tmp_name, MAX_DNS_NAME_LENGTH,
                    "%s.%s", rh->name, next_authority->name);
    
    strcpy(rh->name, tmp_name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "No PSEU found for authority %s. Promoting back: %s\n",
               next_authority->name, rh->name);
    
    GNUNET_CONTAINER_DLL_remove(rh->authority_chain_head,
                              rh->authority_chain_tail,
                              next_authority);

    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   &rh->authority_chain_tail->zone,
                                   &rh->authority_chain_head->zone,
                                   &process_zone_to_name_shorten_root,
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
handle_delegation_ns_shorten (void* cls,
                      struct ResolverHandle *rh,
                      uint32_t rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct NameShortenHandle *nsh;
  char result[MAX_DNS_NAME_LENGTH];

  nsh = (struct NameShortenHandle *)cls;
  
  /**
   * At this point rh->name contains the part of the name
   * that we do not have a PKEY in our namestore to resolve.
   * The authority chain in the resolver handle is now
   * useful to backtrack if needed
   */
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "PKEY resolved as far as possible in ns up to %s!\n", rh->name);
  memset(result, 0, sizeof (result));

  if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                   nsh->root_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s", rh->name, GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Found %s as shorten result\n", result);
    
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);

  }
  else if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        nsh->private_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s.%s",
             rh->name, nsh->private_zone_name, GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Found %s as shorten result %s\n", result);
    
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  else if (GNUNET_CRYPTO_short_hash_cmp(&rh->authority_chain_head->zone,
                                        nsh->shorten_zone) == 0)
  {
    /**
     * This is our zone append .gnunet unless name is empty
     * (it shouldn't be, usually FIXME what happens if we
     * shorten to our zone to a "" record??)
     */
    
    sprintf (result, "%s.%s.%s",
             rh->name, nsh->private_zone_name, GNUNET_GNS_TLD);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Our zone: Found %s as shorten result\n", result);
    
    if (strlen (nsh->result) > strlen (result))
      strcpy (nsh->result, result);
  }
  
  
  /* backtrack authorities for names */
  GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                 nsh->root_zone,
                                 &rh->authority_chain_head->zone,
                                 &process_zone_to_name_shorten_root,
                                 rh);
  
}


/**
 * Callback calles by namestore for a zone to name
 * result
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param expire the expiration time of the name
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 * @param signature the signature for the record data
 */
static void
process_zone_to_name_zkey(void *cls,
                 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                 struct GNUNET_TIME_Absolute expire,
                 const char *name,
                 unsigned int rd_len,
                 const struct GNUNET_NAMESTORE_RecordData *rd,
                 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ResolverHandle *rh = cls;
  struct NameShortenHandle *nsh = rh->proc_cls;
  struct GNUNET_CRYPTO_ShortHashAsciiEncoded enc;
  char new_name[MAX_DNS_NAME_LENGTH];

  /* zkey not in our zone */
  if (name == NULL)
  {
    /**
     * In this case we have not given this PKEY a name (yet)
     * It is either just not in our zone or not even cached
     * Since we do not know at this point we will not try to shorten
     * because PKEY import will happen if the user follows the zkey
     * link.
     */
    GNUNET_CRYPTO_short_hash_to_enc ((struct GNUNET_CRYPTO_ShortHashCode*)rd,
                                     &enc);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "No name found for zkey %s returning verbatim!\n", enc);
    if (strcmp(rh->name, "") != 0)
      GNUNET_snprintf(new_name, MAX_DNS_NAME_LENGTH, "%s.%s.%s",
                      rh->name, enc, GNUNET_GNS_TLD_ZKEY);
    else
      GNUNET_snprintf(new_name, MAX_DNS_NAME_LENGTH, "%s.%s",
                      enc, GNUNET_GNS_TLD_ZKEY);

    strcpy (nsh->result, new_name);

    nsh->proc(nsh->proc_cls, new_name);
    GNUNET_free(nsh);
    free_resolver_handle(rh);
    return;
  }
  
  if (strcmp(rh->name, "") != 0)
    GNUNET_snprintf(new_name, MAX_DNS_NAME_LENGTH, "%s.%s",
                    rh->name, name);
  else
    strcpy(new_name, name);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Continue shorten for %s!\n", new_name);

  strcpy(rh->name, new_name);
  
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = rh->authority;
  
  
  /* Start delegation resolution in our namestore */
  resolve_delegation_ns(rh);
}


/**
 * Shorten api from resolver
 *
 * @param zone the root zone to use
 * @param pzone the private zone to use
 * @param szone the shorten zone to use
 * @param name the name to shorten
 * @param private_zone_name name of the private zone
 * @param shorten_zone_name name of the shorten zone
 * @param proc the processor to call with result
 * @param proc_cls closure to pass to proc
 */
void
gns_resolver_shorten_name (struct GNUNET_CRYPTO_ShortHashCode *zone,
                           struct GNUNET_CRYPTO_ShortHashCode *pzone,
                           struct GNUNET_CRYPTO_ShortHashCode *szone,
                           const char* name,
                           const char* private_zone_name,
                           const char* shorten_zone_name,
                           ShortenResultProcessor proc,
                           void* proc_cls)
{
  struct ResolverHandle *rh;
  struct NameShortenHandle *nsh;
  char string_hash[MAX_DNS_LABEL_LENGTH];
  struct GNUNET_CRYPTO_ShortHashCode zkey;
  char nzkey[MAX_DNS_LABEL_LENGTH];
  char* nzkey_ptr = nzkey;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting shorten for %s!\n", name);
  
  if (is_canonical ((char*)name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is canonical. Returning verbatim\n", name);
    proc (proc_cls, name);
    return;
  }

  nsh = GNUNET_malloc (sizeof (struct NameShortenHandle));

  nsh->proc = proc;
  nsh->proc_cls = proc_cls;
  nsh->root_zone = zone;
  nsh->private_zone = pzone;
  nsh->shorten_zone = szone;
  strcpy (nsh->private_zone_name, private_zone_name);
  strcpy (nsh->shorten_zone_name, shorten_zone_name);
  strcpy (nsh->result, name);
  
  rh = GNUNET_malloc (sizeof (struct ResolverHandle));
  rh->authority = *zone;
  rh->id = rid++;
  rh->priv_key = NULL;
  rh->proc = &handle_delegation_ns_shorten;
  rh->proc_cls = nsh;
  rh->id = rid++;
  rh->private_local_zone = *zone;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Checking for TLD...\n");
  if (is_zkey_tld (name) == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "TLD is zkey\n");
    /**
     * This is a zkey tld
     * build hash and use as initial authority
     * FIXME sscanf
     */
    memset (rh->name, 0,
            strlen (name)-strlen (GNUNET_GNS_TLD_ZKEY));
    memcpy (rh->name, name,
            strlen(name)-strlen (GNUNET_GNS_TLD_ZKEY) - 1);
    pop_tld (rh->name, string_hash);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ZKEY is %s!\n", string_hash);
    
    GNUNET_STRINGS_utf8_toupper (string_hash, &nzkey_ptr);

    if (GNUNET_OK != GNUNET_CRYPTO_short_hash_from_string (nzkey,
                                                           &zkey))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Cannot convert ZKEY %s to hash!\n", nzkey);
      GNUNET_free (rh);
      GNUNET_free (nsh);
      proc (proc_cls, name);
      return;
    }

    GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                   zone, //ours
                                   &zkey,
                                   &process_zone_to_name_zkey,
                                   rh);
    return;

  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "TLD is gnunet\n");
    /**
     * Presumably GNUNET tld
     */
    memset (rh->name, 0,
            strlen (name)-strlen (GNUNET_GNS_TLD));
    memcpy (rh->name, name,
            strlen (name)-strlen (GNUNET_GNS_TLD) - 1);
  }

  rh->authority_chain_head = GNUNET_malloc (sizeof (struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = *zone;
  
  
  /* Start delegation resolution in our namestore */
  resolve_delegation_ns (rh);
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
  char result[MAX_DNS_NAME_LENGTH];
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
    memset(result, 0, answer_len);
    strcpy(result, nah->name + strlen(rh->name) + 1);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Got authority result %s\n", result);
    
    nah->proc(nah->proc_cls, result);
    GNUNET_free(nah);
    free_resolver_handle(rh);
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Unable to resolve authority for remaining %s!\n", rh->name);
    nah->proc(nah->proc_cls, "");
    GNUNET_free(nah);
    free_resolver_handle(rh);
  }


}


/**
 * Tries to resolve the authority for name
 * in our namestore
 *
 * @param zone the root zone to look up for
 * @param pzone the private local zone
 * @param name the name to lookup up
 * @param proc the processor to call when finished
 * @param proc_cls the closure to pass to the processor
 */
void
gns_resolver_get_authority(struct GNUNET_CRYPTO_ShortHashCode zone,
                           struct GNUNET_CRYPTO_ShortHashCode pzone,
                           const char* name,
                           GetAuthorityResultProcessor proc,
                           void* proc_cls)
{
  struct ResolverHandle *rh;
  struct GetNameAuthorityHandle *nah;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting authority resolution for %s!\n", name);

  nah = GNUNET_malloc(sizeof (struct GetNameAuthorityHandle));
  rh = GNUNET_malloc(sizeof (struct ResolverHandle));
  rh->authority = zone;
  rh->id = rid++;
  rh->private_local_zone = pzone;
  
  if (strcmp(GNUNET_GNS_TLD, name) == 0)
  {
    strcpy(rh->name, "\0");
  }
  else
  {
    memset(rh->name, 0,
           strlen(name)-strlen(GNUNET_GNS_TLD));
    memcpy(rh->name, name,
           strlen(name)-strlen(GNUNET_GNS_TLD) - 1);
  }

  memset(nah->name, 0,
         strlen(name)+1);
  strcpy(nah->name, name);
  
  rh->authority_chain_head = GNUNET_malloc(sizeof(struct AuthorityChain));
  rh->authority_chain_tail = rh->authority_chain_head;
  rh->authority_chain_head->zone = zone;
  rh->proc = &handle_delegation_result_ns_get_auth;
  rh->proc_cls = (void*)nah;

  nah->proc = proc;
  nah->proc_cls = proc_cls;

  /* Start delegation resolution in our namestore */
  resolve_delegation_ns(rh);

}

/******** END GET AUTHORITY *************/

/* end of gnunet-service-gns_resolver.c */
