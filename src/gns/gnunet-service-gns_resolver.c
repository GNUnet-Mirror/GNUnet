/*
     This file is part of GNUnet.
     (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_resolver.c
 * @brief GNUnet GNS resolver logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 *
 * TODO:
 * - GNS: handle CNAME records (idea: manipulate rh->name)
 * - GNS: handle VPN records (easy)
 * - GNS: handle special SRV names --- no delegation, direct lookup;
 *        can likely be done in 'resolver_lookup_get_next_label'.
 * - recursive DNS resolution
 * - shortening triggers
 * - revocation checks (make optional: privacy!)
 *
 * Issues:
 * - We currently go to the DHT simply if we find no local reply; this
 *   is incorrect; the correct rules for going to DHT are:
 *
 * 1. The entry in the DHT is RSL_RECORD_EXPIRED OR
 * 2. No entry in the NS existed AND
 * 3. The zone queried is not the local resolver's zone AND
 * 4. The name that was looked up is '+'
 *    because if it was any other canonical name we either already queried
 *    the DHT for the authority in the authority lookup phase (and thus
 *    would already have an entry in the NS for the record)
 * 5. We are not in cache only mode
 *
 * - We currently never look "into" the records; for example,
 *   MX, SRV and SOA records may include ".+" that need to be
 *   handled
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dnsstub_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet_vpn_service.h"


/**
 * Default DHT timeout for lookups.
 */
#define DHT_LOOKUP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Default timeout for DNS lookups.
 */
#define DNS_LOOKUP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * DHT replication level
 */
#define DHT_GNS_REPLICATION_LEVEL 5

/**
 * How deep do we allow recursions to go before we abort?
 */
#define MAX_RECURSION 256


/**
 * DLL to hold the authority chain we had to pass in the resolution
 * process.
 */
struct AuthorityChain
{
  /**
   * This is a DLL.
   */
  struct AuthorityChain *prev;

  /**
   * This is a DLL.
   */
  struct AuthorityChain *next;

  /**
   * Resolver handle this entry in the chain belongs to.
   */
  struct GNS_ResolverHandle *rh;

  /**
   * label/name corresponding to the authority 
   */
  char *label;
  
  /**
   * #GNUNET_YES if the authority was a GNS authority,
   * #GNUNET_NO if the authority was a DNS authority.
   */
  int gns_authority;

  /**
   * Information about the resolver authority for this label.
   */
  union
  {

    /**
     * The zone of the GNS authority 
     */
    struct GNUNET_CRYPTO_EccPublicKey gns_authority;

    struct
    {
      /**
       * Domain of the DNS resolver that is the authority.
       * (appended to construct the DNS name to resolve;
       * this is NOT the DNS name of the DNS server!).
       */
      char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH + 1];

      /**
       * IP address of the DNS resolver that is authoritative.
       * (this implementation currently only supports one
       * IP at a time).
       */
      struct sockaddr_storage dns_ip;

    } dns_authority;

  } authority_info;
  
};


/**
 * Resolution status indicator
 */
enum ResolutionStatus
{
  /**
   * the name to lookup exists
   */
  RSL_RECORD_EXISTS = 1,

  /**
   * the name in the record expired
   */
  RSL_RECORD_EXPIRED = 2,
 
  /**
   * resolution timed out
   */
  RSL_TIMED_OUT = 4,
 
  /**
   * Found VPN delegation
   */
  RSL_DELEGATE_VPN = 8,
 
  /**
   * Found NS delegation
   */
  RSL_DELEGATE_NS = 16,
 
  /**
   * Found PKEY delegation
   */
  RSL_DELEGATE_PKEY = 32,
  
  /**
   * Found CNAME record
   */
  RSL_CNAME_FOUND = 64,
  
  /**
   * Found PKEY has been revoked
   */
  RSL_PKEY_REVOKED = 128
};


/**
 * A result we got from DNS.
 */
struct DnsResult
{

  /**
   * Kept in DLL.
   */
  struct DnsResult *next;

  /**
   * Kept in DLL.
   */
  struct DnsResult *prev;

  /**
   * Binary value stored in the DNS record (appended to this struct)
   */
  const void *data;

  /**
   * Expiration time for the DNS record, 0 if we didn't
   * get anything useful (i.e. 'gethostbyname' was used).
   */
  uint64_t expiration_time;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

};


/**
 * Handle to a currenty pending resolution.  On result (positive or
 * negative) the #GNS_ResultProcessor is called.  
 */
struct GNS_ResolverHandle
{

  /**
   * DLL 
   */
  struct GNS_ResolverHandle *next;

  /**
   * DLL 
   */
  struct GNS_ResolverHandle *prev;

  /**
   * The top-level GNS authoritative zone to query 
   */
  struct GNUNET_CRYPTO_EccPublicKey authority_zone;

  /**
   * called when resolution phase finishes 
   */
  GNS_ResultProcessor proc;
  
  /**
   * closure passed to proc 
   */
  void* proc_cls;

  /**
   * Handle for DHT lookups. should be NULL if no lookups are in progress 
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * Handle to a VPN request, NULL if none is active.
   */
  struct GNUNET_VPN_RedirectionRequest *vpn_handle;

  /**
   * Socket for a DNS request, NULL if none is active.
   */
  struct GNUNET_DNSSTUB_RequestSocket *dns_request;

  /**
   * Handle for standard DNS resolution, NULL if none is active.
   */
  struct GNUNET_RESOLVER_RequestHandle *std_resolve;

  /**
   * Pending Namestore task
   */
  struct GNUNET_NAMESTORE_QueueEntry *namestore_qe;

  /**
   * Heap node associated with this lookup.  Used to limit number of
   * concurrent requests.
   */
  struct GNUNET_CONTAINER_HeapNode *dht_heap_node;

  /**
   * DLL to store the authority chain 
   */
  struct AuthorityChain *ac_head;

  /**
   * DLL to store the authority chain 
   */
  struct AuthorityChain *ac_tail;

  /**
   * Private key of the shorten zone, NULL to not shorten.
   */
  struct GNUNET_CRYPTO_EccPrivateKey *shorten_key;

  /**
   * ID of a task associated with the resolution process.
   */
  GNUNET_SCHEDULER_TaskIdentifier task_id;

  /**
   * The name to resolve 
   */
  char *name;

  /**
   * DLL of results we got from DNS.
   */
  struct DnsResult *dns_result_head;

  /**
   * DLL of results we got from DNS.
   */
  struct DnsResult *dns_result_tail;

  /**
   * Current offset in 'name' where we are resolving.
   */
  size_t name_resolution_pos;

  /**
   * Use only cache 
   */
  int only_cached;

  /**
   * Desired type for the resolution.
   */
  int record_type;

  /**
   * We increment the loop limiter for each step in a recursive
   * resolution.  If it passes our threshold (i.e. due to 
   * self-recursion in the resolution, i.e CNAME fun), we stop.
   */
  unsigned int loop_limiter;

};


/**
 * Handle for a PSEU lookup used to shorten names.
 */
struct GetPseuAuthorityHandle
{
  /**
   * DLL
   */
  struct GetPseuAuthorityHandle *next;

  /**
   * DLL
   */
  struct GetPseuAuthorityHandle *prev;

  /**
   * Private key of the (shorten) zone to store the resulting
   * pseudonym in.
   */
  struct GNUNET_CRYPTO_EccPrivateKey shorten_zone_key;

  /**
   * Original label (used if no PSEU record is found).
   */
  char label[GNUNET_DNSPARSER_MAX_LABEL_LENGTH + 1];

  /**
   * Label we are currently trying out (during #perform_pseu_lookup).
   */
  char *current_label;

  /**
   * The zone for which we are trying to find the PSEU record.
   */
  struct GNUNET_CRYPTO_EccPublicKey target_zone;

  /**
   * Handle for DHT lookups. Should be NULL if no lookups are in progress 
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * Handle to namestore request 
   */
  struct GNUNET_NAMESTORE_QueueEntry *namestore_task;

  /**
   * Task to abort DHT lookup operation.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


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
 * Handle to perform DNS lookups.
 */
static struct GNUNET_DNSSTUB_Context *dns_handle;

/**
 * Heap for limiting parallel DHT lookups
 */
static struct GNUNET_CONTAINER_Heap *dht_lookup_heap;

/**
 * Maximum amount of parallel queries to the DHT
 */
static unsigned long long max_allowed_background_queries;

/**
 * Head of PSEU/shorten operations list.
 */
struct GetPseuAuthorityHandle *gph_head;

/**
 * Tail of PSEU/shorten operations list.
 */
struct GetPseuAuthorityHandle *gph_tail;

/**
 * Head of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_head;

/**
 * Tail of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_tail;

/**
 * Global configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Check if name is in srv format (_x._y.xxx)
 *
 * @param name
 * @return GNUNET_YES if true
 */
static int
is_srv (const char *name)
{
  char *ndup;
  int ret;

  if (*name != '_')
    return GNUNET_NO;
  if (NULL == strstr (name, "._"))
    return GNUNET_NO;
  ret = GNUNET_YES;
  ndup = GNUNET_strdup (name);
  strtok (ndup, ".");
  if (NULL == strtok (NULL, "."))
    ret = GNUNET_NO;
  if (NULL == strtok (NULL, "."))
    ret = GNUNET_NO;
  if (NULL != strtok (NULL, "."))
    ret = GNUNET_NO;
  GNUNET_free (ndup);
  return ret;
}


/**
 * Determine if this name is canonical (is a legal name in a zone, without delegation);
 * note that we do not test that the name does not contain illegal characters, we only
 * test for delegation.  Note that service records (i.e. _foo._srv) are canonical names
 * even though they consist of multiple labels.
 *
 * Examples:
 * a.b.gnu  = not canonical
 * a         = canonical
 * _foo._srv = canonical
 * _f.bar    = not canonical
 *
 * @param name the name to test
 * @return GNUNET_YES if canonical
 */
static int
is_canonical (const char *name)
{
  const char *pos;
  const char *dot;

  if (NULL == strchr (name, '.'))
    return GNUNET_YES;
  if ('_' != name[0])
    return GNUNET_NO;
  pos = &name[1];
  while (NULL != (dot = strchr (pos, '.')))    
    if ('_' != dot[1])
      return GNUNET_NO;
    else
      pos = dot + 1;
  return GNUNET_YES;
}


/* ******************** Shortening logic ************************ */


/**
 * Cleanup a 'struct GetPseuAuthorityHandle', terminating all
 * pending activities.
 *
 * @param gph handle to terminate
 */
static void
free_get_pseu_authority_handle (struct GetPseuAuthorityHandle *gph)
{
  if (NULL != gph->get_handle)
  {
    GNUNET_DHT_get_stop (gph->get_handle);
    gph->get_handle = NULL;
  }
  if (NULL != gph->namestore_task)
  {
    GNUNET_NAMESTORE_cancel (gph->namestore_task);
    gph->namestore_task = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != gph->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (gph->timeout_task);
    gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
  GNUNET_free_non_null (gph->current_label);
  GNUNET_free (gph);
}


/**
 * Continuation for pkey record creation (shorten)
 *
 * @param cls a GetPseuAuthorityHandle
 * @param success unused
 * @param emsg unused
 */
static void
create_pkey_cont (void* cls, 
		  int32_t success, 
		  const char *emsg)
{
  struct GetPseuAuthorityHandle* gph = cls;

  gph->namestore_task = NULL;
  free_get_pseu_authority_handle (gph);
}


/**
 * Namestore calls this function if we have record for this name.
 * (or with rd_count=0 to indicate no matches).
 *
 * @param cls the pending query
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 */
static void
process_pseu_lookup_ns (void *cls,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * We obtained a result for our query to the shorten zone from
 * the namestore.  Try to decrypt.
 *
 * @param cls the handle to our shorten operation
 * @param block resulting encrypted block
 */
static void
process_pseu_block_ns (void *cls,
		       const struct GNUNET_NAMESTORE_Block *block)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_CRYPTO_EccPublicKey pub;

  gph->namestore_task = NULL;
  if (NULL == block)
  {
    process_pseu_lookup_ns (gph, 0, NULL);
    return;
  }
  GNUNET_CRYPTO_ecc_key_get_public (&gph->shorten_zone_key,
				    &pub);
  if (GNUNET_OK != 
      GNUNET_NAMESTORE_block_decrypt (block,
				      &pub,
				      gph->current_label,
				      &process_pseu_lookup_ns,
				      gph))
  {
    GNUNET_break (0);
    free_get_pseu_authority_handle (gph);
    return;
  }
}


/**
 * Lookup in the namestore for the shorten zone the given label.
 *
 * @param gph the handle to our shorten operation
 * @param label the label to lookup
 */
static void 
perform_pseu_lookup (struct GetPseuAuthorityHandle *gph,
		     const char *label)
{ 
  struct GNUNET_CRYPTO_EccPublicKey pub;
  struct GNUNET_HashCode query;

  GNUNET_CRYPTO_ecc_key_get_public (&gph->shorten_zone_key,
				    &pub);
  GNUNET_free_non_null (gph->current_label);
  gph->current_label = GNUNET_strdup (label);
  GNUNET_NAMESTORE_query_from_public_key (&pub,
					  label,
					  &query);
  gph->namestore_task = GNUNET_NAMESTORE_lookup_block (namestore_handle,
						       &query,
						       &process_pseu_block_ns,
						       gph);
}


/**
 * Namestore calls this function if we have record for this name.
 * (or with rd_count=0 to indicate no matches).
 *
 * @param cls the pending query
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 */
static void
process_pseu_lookup_ns (void *cls,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_NAMESTORE_RecordData new_pkey;

  gph->namestore_task = NULL;
  if (rd_count > 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Name `%s' already taken, cannot shorten.\n", 
	       gph->current_label);
    /* if this was not yet the original label, try one more
       time, this time not using PSEU but the original label */
    if (0 == strcmp (gph->current_label,
		     gph->label))
    {
      free_get_pseu_authority_handle (gph);
    }
    else
    {
      perform_pseu_lookup (gph, gph->label);
    }
    return;
  }
  /* name is available */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shortening `%s' to `%s'\n", 
	      GNUNET_NAMESTORE_z2s (&gph->target_zone),
	      gph->current_label);
  new_pkey.expiration_time = UINT64_MAX;
  new_pkey.data_size = sizeof (struct GNUNET_CRYPTO_EccPublicKey);
  new_pkey.data = &gph->target_zone;
  new_pkey.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
  new_pkey.flags = GNUNET_NAMESTORE_RF_AUTHORITY
                 | GNUNET_NAMESTORE_RF_PRIVATE
                 | GNUNET_NAMESTORE_RF_PENDING;
  gph->namestore_task 
    = GNUNET_NAMESTORE_records_store (namestore_handle,
				      &gph->shorten_zone_key,
				      gph->current_label,
				      1, &new_pkey,
				      &create_pkey_cont, gph);
}


/**
 * Process result of a DHT lookup for a PSEU record.
 *
 * @param gph the handle to our shorten operation
 * @param pseu the pseu result or NULL
 */
static void
process_pseu_result (struct GetPseuAuthorityHandle* gph, 
		     const char *pseu)
{
  if (NULL == pseu)
  {
    /* no PSEU found, try original label */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No PSEU found, trying original label `%s' instead.\n",
		gph->label);
    perform_pseu_lookup (gph, gph->label);
    return;
  }  
  /* check if 'pseu' is taken */
  perform_pseu_lookup (gph, pseu);
}


/**
 * Handle timeout for DHT request during shortening.
 *
 * @param cls the request handle as closure
 * @param tc the task context
 */
static void
handle_auth_discovery_timeout (void *cls,
                               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPseuAuthorityHandle *gph = cls;

  gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DHT lookup for PSEU query timed out.\n");
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  process_pseu_result (gph, NULL);
}


/**
 * Handle decrypted records from DHT result.
 *
 * @param cls closure with our 'struct GetPseuAuthorityHandle'
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 */
static void
process_auth_records (void *cls,
		      unsigned int rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle *gph = cls;
  unsigned int i;

  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_NAMESTORE_TYPE_PSEU == rd[i].record_type)
    {
      /* found pseu */
      process_pseu_result (gph, 
			   (const char *) rd[i].data);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "No PSEU record found in DHT reply.\n");
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
process_auth_discovery_dht_result (void* cls,
                                   struct GNUNET_TIME_Absolute exp,
                                   const struct GNUNET_HashCode *key,
                                   const struct GNUNET_PeerIdentity *get_path,
                                   unsigned int get_path_length,
                                   const struct GNUNET_PeerIdentity *put_path,
                                   unsigned int put_path_length,
                                   enum GNUNET_BLOCK_Type type,
                                   size_t size,
                                   const void *data)
{
  struct GetPseuAuthorityHandle *gph = cls;
  const struct GNUNET_NAMESTORE_Block *block;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got DHT result for PSEU request\n");
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  GNUNET_SCHEDULER_cancel (gph->timeout_task);
  gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL == data)
  {
    /* is this allowed!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;
  }
  if (size < sizeof (struct GNUNET_NAMESTORE_Block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;   
  }
  block = data;
  if (size !=
      ntohs (block->purpose.size) + 
      sizeof (struct GNUNET_CRYPTO_EccPublicKey) +
      sizeof (struct GNUNET_CRYPTO_EccSignature))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;   
  }
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_block_decrypt (block,
				      &gph->target_zone,
				      GNUNET_GNS_TLD_PLUS,
				      &process_auth_records,
				      gph))
  {
    /* other peer encrypted invalid block, complain */
    GNUNET_break_op (0);
    process_pseu_result (gph, NULL);
    return;   
  }
}


/**
 * Callback called by namestore for a zone to name result.  We're
 * trying to see if a short name for a given zone already exists.
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 */
static void
process_zone_to_name_discover (void *cls,
			       const struct GNUNET_CRYPTO_EccPrivateKey *zone_key,
			       const char *name,
			       unsigned int rd_len,
			       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle* gph = cls;
  struct GNUNET_HashCode lookup_key;
  
  gph->namestore_task = NULL;
  if (0 != rd_len)
  {
    /* we found a match in our own zone */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Shortening aborted, name `%s' already reserved for the zone\n",
		name);
    free_get_pseu_authority_handle (gph);
    return;
  }
  /* record does not yet exist, go into DHT to find PSEU record */
  GNUNET_NAMESTORE_query_from_public_key (&gph->target_zone,
					  GNUNET_GNS_TLD_PLUS, 					  
					  &lookup_key);
  gph->timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
						    &handle_auth_discovery_timeout, 
						    gph);
  gph->get_handle = GNUNET_DHT_get_start (dht_handle,
					  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
					  &lookup_key,
					  DHT_GNS_REPLICATION_LEVEL,
					  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
					  NULL, 0,
					  &process_auth_discovery_dht_result,
					  gph);
}


/**
 * Start shortening algorithm, try to allocate a nice short
 * canonical name for @a pub in @a shorten_zone, using
 * @a original_label as one possible suggestion.
 *
 * @param original_label original label for the zone
 * @param pub public key of the zone to shorten
 * @param shorten_zone private key of the target zone for the new record
 */
static void
start_shorten (const char *original_label,
	       const struct GNUNET_CRYPTO_EccPublicKey *pub,
               const struct GNUNET_CRYPTO_EccPrivateKey *shorten_zone)
{
  struct GetPseuAuthorityHandle *gph;
  
  if (strlen (original_label) > GNUNET_DNSPARSER_MAX_LABEL_LENGTH)
  {
    GNUNET_break (0);
    return;
  }
  gph = GNUNET_new (struct GetPseuAuthorityHandle);
  gph->shorten_zone_key = *shorten_zone;
  gph->target_zone = *pub;
  strcpy (gph->label, original_label);
  GNUNET_CONTAINER_DLL_insert (gph_head, gph_tail, gph);
  /* first, check if we *already* have a record for this zone */
  gph->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                                       shorten_zone,
                                                       pub,
                                                       &process_zone_to_name_discover,
                                                       gph);
}


/* ************************** Resolution **************************** */

#if 0


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
  struct RecordLookupHandle *rlh = rh->proc_cls;
  struct GNUNET_NAMESTORE_RecordData rd;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_VPN-%llu: Got answer from VPN to query!\n",
             rh->id);
  if (AF_INET == af)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%llu: Answer is IPv4!\n",
               rh->id);
    if (GNUNET_DNSPARSER_TYPE_A != rlh->record_type)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%llu: Requested record is not IPv4!\n",
                 rh->id);
      rh->proc (rh->proc_cls, rh, 0, NULL);
      return;
    }
    rd.record_type = GNUNET_DNSPARSER_TYPE_A;
    rd.expiration_time = UINT64_MAX; /* FIXME: should probably pick something shorter... */
    rd.data = address;
    rd.data_size = sizeof (struct in_addr);
    rd.flags = 0;
    rh->proc (rh->proc_cls, rh, 1, &rd);
    return;
  }
  else if (AF_INET6 == af)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_PHASE_REC-%llu: Answer is IPv6!\n",
               rh->id);
    if (GNUNET_DNSPARSER_TYPE_AAAA != rlh->record_type)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "GNS_PHASE_REC-%llu: Requested record is not IPv6!\n",
                 rh->id);
      rh->proc (rh->proc_cls, rh, 0, NULL);
      return;
    }
    rd.record_type = GNUNET_DNSPARSER_TYPE_AAAA;
    rd.expiration_time = UINT64_MAX; /* FIXME: should probably pick something shorter... */
    rd.data = address;
    rd.data_size = sizeof (struct in6_addr);
    rd.flags = 0;
    rh->proc (rh->proc_cls, rh, 1, &rd);
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC-%llu: Got garbage from VPN!\n",
             rh->id);
  rh->proc (rh->proc_cls, rh, 0, NULL);
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
                    unsigned int rd_count,
                    const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct RecordLookupHandle *rlh = rh->proc_cls;
  struct GNUNET_HashCode serv_desc;
  struct GNUNET_TUN_GnsVpnRecord* vpn;
  int af;
  
  /* We cancel here as to not include the ns lookup in the timeout */
  if (GNUNET_SCHEDULER_NO_TASK != rh->timeout_task)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Start shortening */
  if ((NULL != rh->priv_key) &&
      (GNUNET_YES == is_canonical (rh->name)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             "GNS_PHASE_REC_VPN-%llu: Trying to shorten authority chain\n",
             rh->id);
    start_shorten (rh->authority_chain_head,
                   rh->priv_key);
  }

  vpn = (struct GNUNET_TUN_GnsVpnRecord*)rd->data;
  GNUNET_CRYPTO_hash ((char*)&vpn[1],
                      strlen ((char*)&vpn[1]) + 1,
                      &serv_desc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_PHASE_REC_VPN-%llu: proto %hu peer %s!\n",
              rh->id,
              ntohs (vpn->proto),
              GNUNET_h2s (&vpn->peer));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS_PHASE_REC_VPN-%llu: service %s -> %s!\n",
              rh->id,
              (char*)&vpn[1],
              GNUNET_h2s (&serv_desc));
  rh->proc = &handle_record_vpn;
  if (GNUNET_DNSPARSER_TYPE_A == rlh->record_type)
    af = AF_INET;
  else
    af = AF_INET6;
#ifndef WINDOWS
  if (NULL == vpn_handle)
  {
    vpn_handle = GNUNET_VPN_connect (cfg);
    if (NULL == vpn_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "GNS_PHASE_INIT: Error connecting to VPN!\n");
      finish_lookup (rh, rh->proc_cls, 0, NULL);
      return;
    }
  }

  rh->vpn_handle = GNUNET_VPN_redirect_to_peer (vpn_handle,
						af, ntohs (vpn->proto),
						(struct GNUNET_PeerIdentity *)&vpn->peer,
						&serv_desc,
						GNUNET_NO, //nac
						GNUNET_TIME_UNIT_FOREVER_ABS, //FIXME
						&process_record_result_vpn,
						rh);
#else
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Error connecting to VPN (not available on W32 yet)\n");
  finish_lookup (rh, rh->proc_cls, 0, NULL);  
#endif
}


//FIXME maybe define somewhere else?
#define MAX_SOA_LENGTH sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)\
                        +(GNUNET_DNSPARSER_MAX_NAME_LENGTH*2)
#define MAX_MX_LENGTH sizeof(uint16_t)+GNUNET_DNSPARSER_MAX_NAME_LENGTH
#define MAX_SRV_LENGTH (sizeof(uint16_t)*3)+GNUNET_DNSPARSER_MAX_NAME_LENGTH


/**
 * Exands a name ending in .+ with the zone of origin.
 * FIXME: funky api: 'dest' must be large enough to hold
 * the result; this is a bit yucky...
 *
 * @param dest destination buffer
 * @param src the .+ name
 * @param repl the string to replace the + with
 */
static void
expand_plus (char* dest, 
	     const char* src, 
	     const char* repl)
{
  char* pos;
  size_t s_len = strlen (src) + 1;

  //Eh? I guess this is at least strlen ('x.+') == 3 FIXME
  if (3 > s_len)
  {
    /* no postprocessing */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: %s too short\n", src);
    memcpy (dest, src, s_len);
    return;
  }
  if (0 == strcmp (src + s_len - 3, ".+"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"GNS_POSTPROCESS: Expanding .+ in %s\n", 
		src);
    memset (dest, 0, s_len + strlen (repl) + strlen(GNUNET_GNS_TLD));
    strcpy (dest, src);
    pos = dest + s_len - 2;
    strcpy (pos, repl);
    pos += strlen (repl);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"GNS_POSTPROCESS: Expanded to %s\n", 
		dest);
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "GNS_POSTPROCESS: No postprocessing for %s\n", src);
    memcpy (dest, src, s_len);
  }
}


/**
 * finish lookup
 */
static void
finish_lookup (struct ResolverHandle *rh,
               struct RecordLookupHandle* rlh,
               unsigned int rd_count,
               const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int i;
  char new_rr_data[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  char new_mx_data[MAX_MX_LENGTH];
  char new_soa_data[MAX_SOA_LENGTH];
  char new_srv_data[MAX_SRV_LENGTH];
  struct GNUNET_TUN_DnsSrvRecord *old_srv;
  struct GNUNET_TUN_DnsSrvRecord *new_srv;
  struct GNUNET_TUN_DnsSoaRecord *old_soa;
  struct GNUNET_TUN_DnsSoaRecord *new_soa;
  struct GNUNET_NAMESTORE_RecordData p_rd[rd_count];
  char* repl_string;
  char* pos;
  unsigned int offset;

  if (GNUNET_SCHEDULER_NO_TASK != rh->timeout_task)
  {
    GNUNET_SCHEDULER_cancel(rh->timeout_task);
    rh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_CONTAINER_DLL_remove (rlh_head, rlh_tail, rh);

  if (0 < rd_count)
    memcpy(p_rd, rd, rd_count*sizeof(struct GNUNET_NAMESTORE_RecordData));

  for (i = 0; i < rd_count; i++)
  {
    
    if ((GNUNET_DNSPARSER_TYPE_NS != rd[i].record_type) &&
        (GNUNET_DNSPARSER_TYPE_PTR != rd[i].record_type) &&
        (GNUNET_DNSPARSER_TYPE_CNAME != rd[i].record_type) &&
        (GNUNET_DNSPARSER_TYPE_MX != rd[i].record_type) &&
        (GNUNET_DNSPARSER_TYPE_SOA != rd[i].record_type) &&
        (GNUNET_DNSPARSER_TYPE_SRV != rd[i].record_type))
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
    if (0 == strcmp(rh->name, GNUNET_GNS_MASTERZONE_STR))
      repl_string = rlh->name;
    else
      repl_string = rlh->name+strlen(rh->name)+1;

    offset = 0;
    if (GNUNET_DNSPARSER_TYPE_MX == rd[i].record_type)
    {
      memcpy (new_mx_data, (char*)rd[i].data, sizeof(uint16_t));
      offset = sizeof (uint16_t);
      pos = new_mx_data + offset;
      // FIXME: how do we know that 'pos' has enough space for the new name?
      expand_plus (pos, (char*)rd[i].data+sizeof(uint16_t),
		   repl_string);
      offset += strlen(new_mx_data+sizeof(uint16_t)) + 1;
      p_rd[i].data = new_mx_data;
      p_rd[i].data_size = offset;
    }
    else if (GNUNET_DNSPARSER_TYPE_SRV == rd[i].record_type)
    {
      /*
       * Prio, weight and port
       */
      new_srv = (struct GNUNET_TUN_DnsSrvRecord*)new_srv_data;
      old_srv = (struct GNUNET_TUN_DnsSrvRecord*)rd[i].data;
      new_srv->prio = old_srv->prio;
      new_srv->weight = old_srv->weight;
      new_srv->port = old_srv->port;
      // FIXME: how do we know that '&new_srv[1]' has enough space for the new name?
      expand_plus((char*)&new_srv[1], (char*)&old_srv[1],
                  repl_string);
      p_rd[i].data = new_srv_data;
      p_rd[i].data_size = sizeof (struct GNUNET_TUN_DnsSrvRecord) + strlen ((char*)&new_srv[1]) + 1;
    }
    else if (GNUNET_DNSPARSER_TYPE_SOA == rd[i].record_type)
    {
      /* expand mname and rname */
      old_soa = (struct GNUNET_TUN_DnsSoaRecord*)rd[i].data;
      new_soa = (struct GNUNET_TUN_DnsSoaRecord*)new_soa_data;
      memcpy (new_soa, old_soa, sizeof (struct GNUNET_TUN_DnsSoaRecord));
      // FIXME: how do we know that 'new_soa[1]' has enough space for the new name?
      expand_plus((char*)&new_soa[1], (char*)&old_soa[1], repl_string);
      offset = strlen ((char*)&new_soa[1]) + 1;
      // FIXME: how do we know that 'new_soa[1]' has enough space for the new name?
      expand_plus((char*)&new_soa[1] + offset,
                  (char*)&old_soa[1] + strlen ((char*)&old_soa[1]) + 1,
                  repl_string);
      p_rd[i].data_size = sizeof (struct GNUNET_TUN_DnsSoaRecord)
                          + offset
                          + strlen ((char*)&new_soa[1] + offset);
      p_rd[i].data = new_soa_data;
    }
    else
    {
      pos = new_rr_data;
      // FIXME: how do we know that 'rd[i].data' has enough space for the new name?
      expand_plus(pos, (char*)rd[i].data, repl_string);
      p_rd[i].data_size = strlen(new_rr_data)+1;
      p_rd[i].data = new_rr_data;
    }
    
  }

  rlh->proc(rlh->proc_cls, rd_count, p_rd);
  GNUNET_free(rlh);
  free_resolver_handle (rh);
}


#endif

///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * Task scheduled to asynchronously fail a resolution.
 *
 * @param cls the 'struct GNS_ResolverHandle' of the resolution to fail
 * @param tc task context
 */
static void
fail_resolution (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = GNUNET_SCHEDULER_NO_TASK;
  rh->proc (rh->proc_cls, 0, NULL);
  GNS_resolver_lookup_cancel (rh);
}

#ifdef WINDOWS
/* Don't have this on W32, here's a naive implementation */
void *memrchr (const void *s, int c, size_t n)
{
  size_t i;
  unsigned char *ucs = (unsigned char *) s;
  for (i = n - 1; i >= 0; i--)
    if (ucs[i] == c)
      return (void *) &ucs[i];
  return NULL;
}
#endif

/**
 * Get the next, rightmost label from the name that we are trying to resolve,
 * and update the resolution position accordingly.
 *
 * @param rh handle to the resolution operation to get the next label from
 * @return NULL if there are no more labels
 */
static char *
resolver_lookup_get_next_label (struct GNS_ResolverHandle *rh)
{
  const char *rp;
  const char *dot;
  size_t len;

  if (0 == rh->name_resolution_pos)
    return NULL;
  dot = memrchr (rh->name, (int) '.', rh->name_resolution_pos);
  if (NULL == dot)
  {
    /* done, this was the last one */
    len = rh->name_resolution_pos;
    rp = rh->name;
    rh->name_resolution_pos = 0; 
  }
  else
  {
    /* advance by one label */
    len = rh->name_resolution_pos - (dot - rh->name) - 1;
    rp = dot + 1;
    rh->name_resolution_pos = dot - rh->name;
  }  
  return GNUNET_strndup (rp, len);  
}


/**
 * Gives the cummulative result obtained to the callback and clean up the request.
 *
 * @param rh resolution process that has culminated in a result
 */
static void
transmit_lookup_dns_result (struct GNS_ResolverHandle *rh)
{
  struct DnsResult *pos;
  unsigned int n;
  unsigned int i;

  n = 0;
  for (pos = rh->dns_result_head; NULL != pos; pos = pos->next)
    n++;
  {
    struct GNUNET_NAMESTORE_RecordData rd[n];

    i = 0;
    for (pos = rh->dns_result_head; NULL != pos; pos = pos->next)
    {
      rd[i].data = pos->data;
      rd[i].data_size = pos->data_size;
      rd[i].record_type = pos->record_type;
      if (0 == pos->expiration_time)
      {
	rd[i].flags = GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
	rd[i].expiration_time = 0;
      }
      else
      {
	rd[i].flags = GNUNET_NAMESTORE_RF_NONE;
	rd[i].expiration_time = pos->expiration_time;
      }
    }      
    rh->proc (rh->proc_cls,
	      n,
	      rd);
  }
  GNS_resolver_lookup_cancel (rh);
}


/**
 * Add a result from DNS to the records to be returned to the application.
 *
 * @param rh resolution request to extend with a result
 * @param expiration_time expiration time for the answer
 * @param record_type DNS record type of the answer
 * @param data_size number of bytes in @a data
 * @param data binary data to return in DNS record
 */
static void
add_dns_result (struct GNS_ResolverHandle *rh,
		uint64_t expiration_time,
		uint32_t record_type,
		size_t data_size,
		const void *data)
{
  struct DnsResult *res;

  res = GNUNET_malloc (sizeof (struct DnsResult) + data_size);
  res->expiration_time = expiration_time;
  res->data_size = data_size;
  res->record_type = record_type;
  res->data = &res[1];
  memcpy (&res[1], data, data_size);
  GNUNET_CONTAINER_DLL_insert (rh->dns_result_head,
			       rh->dns_result_tail,
			       res);
}


/**
 * We had to do a DNS lookup.  Convert the result (if any) and return
 * it.
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
handle_dns_result (void *cls,
		   const struct sockaddr *addr,
		   socklen_t addrlen)
{
  struct GNS_ResolverHandle *rh = cls;
  const struct sockaddr_in *sa4;
  const struct sockaddr_in6 *sa6;

  rh->std_resolve = NULL;
  if (NULL == addr)
  {
    transmit_lookup_dns_result (rh);
    return;
  }
  switch (addr->sa_family)
  {
  case AF_INET:
    sa4 = (const struct sockaddr_in *) addr;
    add_dns_result (rh,
		    0 /* expiration time is unknown */,
		    GNUNET_DNSPARSER_TYPE_A,
		    sizeof (struct in_addr),
		    &sa4->sin_addr);
    break;
  case AF_INET6:
    sa6 = (const struct sockaddr_in6 *) addr;
    add_dns_result (rh,
		    0 /* expiration time is unknown */,
		    GNUNET_DNSPARSER_TYPE_AAAA,
		    sizeof (struct in6_addr),
		    &sa6->sin6_addr);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Task scheduled to continue with the resolution process.
 *
 * @param cls the 'struct GNS_ResolverHandle' of the resolution
 * @param tc task context
 */
static void
recursive_resolution (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls the request handle of the resolution that
 *        we were attempting to make
 * @param rs socket that received the response
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in 'dns'
 */
static void
dns_result_parser (void *cls,
		   struct GNUNET_DNSSTUB_RequestSocket *rs,
		   const struct GNUNET_TUN_DnsHeader *dns,
		   size_t dns_len)
{
  struct GNS_ResolverHandle *rh = cls;
  struct GNUNET_DNSPARSER_Packet *p;

  rh->dns_request = NULL;
  GNUNET_SCHEDULER_cancel (rh->task_id);
  rh->task_id = GNUNET_SCHEDULER_NO_TASK;
  p = GNUNET_DNSPARSER_parse ((const char *) dns, 
			      dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to parse DNS response\n"));
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  // FIXME: 
  // Check if the packet is the final answer, or
  // just pointing us to another NS or another name (CNAME), or another domain (DNAME);
  // then do the right thing (TM) -- possibly using "recursive_dns_resolution".
  GNUNET_break (0);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      _("NOT IMPLEMENTED\n"));
  rh->proc (rh->proc_cls, 0, NULL);
  GNS_resolver_lookup_cancel (rh);

  
  GNUNET_DNSPARSER_free_packet (p);
}


/**
 * Perform recursive DNS resolution.  Asks the given DNS resolver to
 * resolve "rh->dns_name", possibly recursively proceeding following
 * NS delegations, CNAMES, etc., until 'rh->loop_limiter' bounds us or
 * we find the answer.
 *
 * @param rh resolution information
 */
static void
recursive_dns_resolution (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac;
  socklen_t sa_len;
  struct GNUNET_DNSPARSER_Query *query;
  struct GNUNET_DNSPARSER_Packet *p;
  char *dns_request;
  size_t dns_request_length;

  ac = rh->ac_tail;
  GNUNET_assert (NULL != ac);
  GNUNET_assert (GNUNET_NO == ac->gns_authority);
  switch (((const struct sockaddr *) &ac->authority_info.dns_authority.dns_ip)->sa_family)
  {
  case AF_INET:
    sa_len = sizeof (struct sockaddr_in);
    break;
  case AF_INET6:
    sa_len = sizeof (struct sockaddr_in6);
    break;
  default:
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  query = GNUNET_new (struct GNUNET_DNSPARSER_Query);
  query->name = GNUNET_strdup (ac->label);
  query->type = rh->record_type;
  query->class = GNUNET_TUN_DNS_CLASS_INTERNET;
  p = GNUNET_new (struct GNUNET_DNSPARSER_Packet);
  p->queries = query;
  p->num_queries = 1;
  p->id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
					       UINT16_MAX);
  p->flags.opcode = GNUNET_TUN_DNS_OPCODE_QUERY;
  p->flags.recursion_desired = 1;
  if (GNUNET_OK != 
      GNUNET_DNSPARSER_pack (p, 1024, &dns_request, &dns_request_length))
  {
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
  }
  else
  {
    rh->dns_request = GNUNET_DNSSTUB_resolve (dns_handle,
					      (const struct sockaddr *) &ac->authority_info.dns_authority.dns_ip,
					      sa_len,
					      dns_request,
					      dns_request_length,
					      &dns_result_parser,
					      rh);
    rh->task_id = GNUNET_SCHEDULER_add_delayed (DNS_LOOKUP_TIMEOUT,
						&fail_resolution,
						rh);
  }
  GNUNET_free (dns_request);
  GNUNET_DNSPARSER_free_packet (p);
}


/**
 * We encountered a CNAME record during our resolution.
 * Merge it into our chain.
 *
 * @param rh resolution we are performing
 * @param cname value of the cname record we got for the current 
 *        authority chain tail
 */
static void
handle_gns_cname_result (struct GNS_ResolverHandle *rh,
			 const char *cname)
{
  // FIXME: not implemented
  GNUNET_break (0);
  rh->proc (rh->proc_cls, 0, NULL);
  GNS_resolver_lookup_cancel (rh);
}


/**
 * Process a records that were decrypted from a block.
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
handle_gns_resolution_result (void *cls,
			      unsigned int rd_count,
			      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac;
  unsigned int i;
  unsigned int j;
  struct sockaddr *sa;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  size_t sa_len;
  char *cname;
   
  if (0 == rh->name_resolution_pos)
  {
    /* top-level match, are we done yet? */
    if ( (rd_count > 0) &&
	 (GNUNET_DNSPARSER_TYPE_CNAME == rd[0].record_type) &&
	 (GNUNET_DNSPARSER_TYPE_CNAME != rh->record_type) )
    {
      cname = GNUNET_strndup (rd[0].data,
			      rd[0].data_size);
      handle_gns_cname_result (rh, 
			       cname);
      GNUNET_free (cname);
      return;     
    }
    /* FIXME: if A/AAAA was requested, but we got a VPN
       record, we should interact with GNUnet VPN here */
    
    /* yes, we are done, return result */
    rh->proc (rh->proc_cls, rd_count, rd);
    GNS_resolver_lookup_cancel (rh);
    return;         
  }
  /* need to recurse, check if we can */
  for (i=0;i<rd_count;i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_NAMESTORE_TYPE_PKEY:
      /* delegation to another zone */
      if (sizeof (struct GNUNET_CRYPTO_EccPublicKey) !=
	  rd[i].data_size)
      {
	GNUNET_break_op (0);
	rh->proc (rh->proc_cls, 0, NULL);
	GNS_resolver_lookup_cancel (rh);
	return;     
      }
      /* expand authority chain */
      ac = GNUNET_new (struct AuthorityChain);
      ac->rh = rh;
      ac->gns_authority = GNUNET_YES;
      memcpy (&ac->authority_info.gns_authority,
	      rd[i].data,
	      sizeof (struct GNUNET_CRYPTO_EccPublicKey));
      ac->label = resolver_lookup_get_next_label (rh);
      GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
					rh->ac_tail,
					ac);
      /* recurse */
      rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
					      rh);
      break;
    case GNUNET_DNSPARSER_TYPE_NS:
      /* resolution continues within DNS */
      if (GNUNET_DNSPARSER_MAX_NAME_LENGTH < rd[i].data_size)
      {
	GNUNET_break_op (0);
	rh->proc (rh->proc_cls, 0, NULL);
	GNS_resolver_lookup_cancel (rh);
	return;     
      }
      /* find associated A/AAAA record */
      sa = NULL;
      for (j=0;j<rd_count;j++)
      {
	switch (rd[j].record_type)
	{
	case GNUNET_DNSPARSER_TYPE_A:
	  if (sizeof (struct in_addr) != rd[i].data_size)
	  {
	    GNUNET_break_op (0);
	    rh->proc (rh->proc_cls, 0, NULL);
	    GNS_resolver_lookup_cancel (rh);
	    return;     
	  }
	  /* FIXME: might want to check if we support IPv4 here,
	     and otherwise skip this one and hope we find another */
	  memset (&v4, 0, sizeof (v4));
	  sa_len = sizeof (v4);
	  v4.sin_family = AF_INET;
	  v4.sin_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
	  v4.sin_len = (u_char) sa_len;
#endif
	  memcpy (&v4.sin_addr,
		  rd[j].data,
		  sizeof (struct in_addr));
	  sa = (struct sockaddr *) &v4;
	  break;
	case GNUNET_DNSPARSER_TYPE_AAAA:
	  if (sizeof (struct in6_addr) != rd[i].data_size)
	  {
	    GNUNET_break_op (0);
	    rh->proc (rh->proc_cls, 0, NULL);
	    GNS_resolver_lookup_cancel (rh);
	    return;     
	  }
	  /* FIXME: might want to check if we support IPv6 here,
	     and otherwise skip this one and hope we find another */
	  memset (&v6, 0, sizeof (v6));
	  sa_len = sizeof (v6);
	  v6.sin6_family = AF_INET6;
	  v6.sin6_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
	  v6.sin6_len = (u_char) sa_len;
#endif
	  memcpy (&v6.sin6_addr,
		  rd[j].data,
		  sizeof (struct in6_addr));
	  sa = (struct sockaddr *) &v6;
	  break;
	}
	if (NULL != sa)
	  break;
      }
      /* expand authority chain */
      ac = GNUNET_new (struct AuthorityChain);
      ac->rh = rh;
      strncpy (ac->authority_info.dns_authority.name,
	       rd[i].data,
	       rd[i].data_size);
      ac->authority_info.dns_authority.name[rd[i].data_size] = '\0';
      memcpy (&ac->authority_info.dns_authority.dns_ip,
	      sa,
	      sa_len);
      /* for DNS recursion, the label is the full DNS name,
	 created from the remainder of the GNS name and the
	 name in the NS record */
      GNUNET_asprintf (&ac->label,
		       "%.*s%s",
		       (int) rh->name_resolution_pos,
		       rh->name,
		       ac->authority_info.dns_authority.name);
      GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
					rh->ac_tail,
					ac);
      if (strlen (ac->label) > GNUNET_DNSPARSER_MAX_NAME_LENGTH)
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("GNS lookup resulted in DNS name that is too long (`%s')\n"),
		    ac->label);
	rh->proc (rh->proc_cls, 0, NULL);
	GNS_resolver_lookup_cancel (rh);
	return;
      }
      /* recurse */
      rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
					      rh);
      return;
    case GNUNET_DNSPARSER_TYPE_CNAME:
      cname = GNUNET_strndup (rd[i].data,
			      rd[i].data_size);
      handle_gns_cname_result (rh, 
			       cname);
      GNUNET_free (cname);
      return;
      /* FIXME: handle DNAME */
    default:
      /* skip */
      break;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      _("GNS lookup recursion failed (no delegation record found)\n"));
  rh->proc (rh->proc_cls, 0, NULL);
  GNS_resolver_lookup_cancel (rh);
}


/**
 * Function called once the namestore has completed the request for
 * caching a block.
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param success #GNUNET_OK on success
 * @param emsg error message
 */
static void
namestore_cache_continuation (void *cls,
			      int32_t success,
			      const char *emsg)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->namestore_qe = NULL;
  if (NULL != emsg)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to cache GNS resolution: %s\n"),
		emsg);
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in get_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
handle_dht_response (void *cls,
		     struct GNUNET_TIME_Absolute exp,
		     const struct GNUNET_HashCode * key,
		     const struct GNUNET_PeerIdentity *get_path,
		     unsigned int get_path_length,
		     const struct GNUNET_PeerIdentity *put_path, 
		     unsigned int put_path_length,
		     enum GNUNET_BLOCK_Type type,
		     size_t size, const void *data)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;
  const struct GNUNET_NAMESTORE_Block *block;
  
  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  GNUNET_CONTAINER_heap_remove_node (rh->dht_heap_node);
  rh->dht_heap_node = NULL;  
  if (size < sizeof (struct GNUNET_NAMESTORE_Block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;   
  }
  block = data; 
  if (size !=
      ntohs (block->purpose.size) + 
      sizeof (struct GNUNET_CRYPTO_EccPublicKey) +
      sizeof (struct GNUNET_CRYPTO_EccSignature))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;   
  }
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_block_decrypt (block,
				      &ac->authority_info.gns_authority,
				      ac->label,
				      &handle_gns_resolution_result,
				      rh))
  {
    GNUNET_break_op (0); /* block was ill-formed */
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  /* Cache well-formed blocks */
  rh->namestore_qe = GNUNET_NAMESTORE_block_cache (namestore_handle,
						   block,
						   &namestore_cache_continuation,
						   rh);
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param block block that was stored in the namestore
 */
static void 
handle_namestore_block_response (void *cls,
				 const struct GNUNET_NAMESTORE_Block *block)
{
  struct GNS_ResolverHandle *rh = cls;
  struct GNS_ResolverHandle *rx;
  struct AuthorityChain *ac = rh->ac_tail;
  const char *label = ac->label;
  const struct GNUNET_CRYPTO_EccPublicKey *auth = &ac->authority_info.gns_authority;
  struct GNUNET_HashCode query;

  GNUNET_NAMESTORE_query_from_public_key (auth,
					  label,
					  &query);
  rh->namestore_qe = NULL;
  if (NULL == block)
  {
    /* Namestore knows nothing; try DHT lookup */
    rh->get_handle = GNUNET_DHT_get_start (dht_handle,
					   GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
					   &query,
					   DHT_GNS_REPLICATION_LEVEL,
					   GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
					   NULL, 0,
					   &handle_dht_response, rh);
    rh->dht_heap_node = GNUNET_CONTAINER_heap_insert (dht_lookup_heap,
						      rh,
						      GNUNET_TIME_absolute_get ().abs_value_us);
    if (GNUNET_CONTAINER_heap_get_size (dht_lookup_heap) > max_allowed_background_queries)
    {
      /* fail longest-standing DHT request */
      rx = GNUNET_CONTAINER_heap_peek (dht_lookup_heap);
      rx->proc (rx->proc_cls, 0, NULL);
      GNS_resolver_lookup_cancel (rx);
    }
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_block_decrypt (block,
				      auth,
				      label,
				      &handle_gns_resolution_result,
				      rh))
  {
    GNUNET_break_op (0); /* block was ill-formed */
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
}


/**
 * Lookup tail of our authority chain in the namestore.
 *
 * @param rh query we are processing
 */
static void
recursive_gns_resolution_namestore (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac = rh->ac_tail;
  struct GNUNET_HashCode query;

  GNUNET_NAMESTORE_query_from_public_key (&ac->authority_info.gns_authority,
					  ac->label,
					  &query);
  rh->namestore_qe = GNUNET_NAMESTORE_lookup_block (namestore_handle,
						    &query,
						    &handle_namestore_block_response,
						    rh);
}


/**
 * Task scheduled to continue with the resolution process.
 *
 * @param cls the 'struct GNS_ResolverHandle' of the resolution
 * @param tc task context
 */
static void
recursive_resolution (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = GNUNET_SCHEDULER_NO_TASK;
  if (MAX_RECURSION < rh->loop_limiter++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Encountered unbounded recursion resolving `%s'\n",
		rh->name);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  if (GNUNET_YES == rh->ac_tail->gns_authority)
    recursive_gns_resolution_namestore (rh);
  else
    recursive_dns_resolution (rh);
}


/**
 * Lookup of a record in a specific zone calls lookup result processor
 * on result.
 *
 * @param zone the zone to perform the lookup in
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param shorten_key a private key for use with PSEU import (can be NULL)
 * @param only_cached GNUNET_NO to only check locally not DHT for performance
 * @param proc the processor to call on result
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ResolverHandle *
GNS_resolver_lookup (const struct GNUNET_CRYPTO_EccPublicKey *zone,
		     uint32_t record_type,
		     const char *name,
		     const struct GNUNET_CRYPTO_EccPrivateKey *shorten_key,
		     int only_cached,
		     GNS_ResultProcessor proc, void *proc_cls)
{
  struct GNS_ResolverHandle *rh;
  struct AuthorityChain *ac;
  char *x;
  char *y;
  char *pkey;

  rh = GNUNET_new (struct GNS_ResolverHandle);
  GNUNET_CONTAINER_DLL_insert (rlh_head,
			       rlh_tail,
			       rh);
  rh->authority_zone = *zone;
  rh->proc = proc;
  rh->proc_cls = proc_cls;
  rh->only_cached = only_cached;
  rh->record_type = record_type;
  rh->name = GNUNET_strdup (name);
  rh->name_resolution_pos = strlen (name);
  if (NULL != shorten_key)
  {
    rh->shorten_key = GNUNET_new (struct GNUNET_CRYPTO_EccPrivateKey);
    *rh->shorten_key = *shorten_key;
  }

  if ( ( (GNUNET_YES == is_canonical (name)) &&
	 (0 != strcmp (GNUNET_GNS_TLD, name)) ) ||
       ( (GNUNET_YES != is_gnu_tld (name)) &&
	 (GNUNET_YES != is_zkey_tld (name)) ) )
  {
    /* use standard DNS lookup */
    int af;

    switch (record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      af = AF_INET;
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      af = AF_INET6;
      break;
    default:
      af = AF_UNSPEC;
      break;
    }
    rh->std_resolve = GNUNET_RESOLVER_ip_get (name, 
					      af,
					      DNS_LOOKUP_TIMEOUT,
					      &handle_dns_result,
					      rh);
    return rh;
  }
  if (is_zkey_tld (name))
  {
    /* Name ends with ".zkey", try to replace authority zone with zkey
       authority */
    GNUNET_free (resolver_lookup_get_next_label (rh)); /* will return "zkey" */
    x = resolver_lookup_get_next_label (rh); /* will return 'x' coordinate */
    y = resolver_lookup_get_next_label (rh); /* will return 'y' coordinate */
    GNUNET_asprintf (&pkey,
		     "%s%s",
		     x, y);
    if ( (NULL == x) ||
	 (NULL == y) ||
	 (GNUNET_OK !=
	  GNUNET_CRYPTO_ecc_public_key_from_string (pkey,
						    strlen (pkey),
						    &rh->authority_zone)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Hostname `%s' is not well-formed, resolution fails\n"),
		  name);
      rh->task_id = GNUNET_SCHEDULER_add_now (&fail_resolution, rh);
    }
    GNUNET_free_non_null (x);
    GNUNET_free_non_null (y);
    GNUNET_free (pkey);
  }
  else
  {
    /* Name ends with ".gnu", eat ".gnu" and continue with resolution */
    GNUNET_free (resolver_lookup_get_next_label (rh));
  }
  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  ac->label = resolver_lookup_get_next_label (rh);
  if (NULL == ac->label)
    /* name was just "gnu", so we default to label '+' */
    ac->label = GNUNET_strdup (GNUNET_GNS_MASTERZONE_STR);
  ac->gns_authority = GNUNET_YES;
  ac->authority_info.gns_authority = rh->authority_zone;
  GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
				    rh->ac_tail,
				    ac);
  rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
					  rh);
  return rh;
}


/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_resolver_lookup_cancel (struct GNS_ResolverHandle *rh)
{
  struct DnsResult *dr;
  struct AuthorityChain *ac;

  GNUNET_CONTAINER_DLL_remove (rlh_head,
			       rlh_tail,
			       rh);
  while (NULL != (ac = rh->ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->ac_head,
				 rh->ac_tail,
				 ac);
    GNUNET_free (ac->label);
    GNUNET_free (ac);
  }
  if (GNUNET_SCHEDULER_NO_TASK != rh->task_id)
  {
    GNUNET_SCHEDULER_cancel (rh->task_id);
    rh->task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != rh->get_handle)
  {
    GNUNET_DHT_get_stop (rh->get_handle);
    rh->get_handle = NULL;
  }
  if (NULL != rh->dht_heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (rh->dht_heap_node);
    rh->dht_heap_node = NULL;
  }
  if (NULL != rh->dns_request)
  {
    GNUNET_DNSSTUB_resolve_cancel (rh->dns_request);
    rh->dns_request = NULL;
  }
  if (NULL != rh->namestore_qe)
  {
    GNUNET_NAMESTORE_cancel (rh->namestore_qe);
    rh->namestore_qe = NULL;
  }
  if (NULL != rh->std_resolve)
  {
    GNUNET_RESOLVER_request_cancel (rh->std_resolve);
    rh->std_resolve = NULL;
  }
  while (NULL != (dr = rh->dns_result_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->dns_result_head,
				 rh->dns_result_tail,
				 dr);
    GNUNET_free (dr);
  }
  GNUNET_free_non_null (rh->shorten_key);
  GNUNET_free (rh->name);
  GNUNET_free (rh);
}


/* ***************** Resolver initialization ********************* */


/**
 * Initialize the resolver
 *
 * @param nh the namestore handle
 * @param dht the dht handle
 * @param c configuration handle
 * @param max_bg_queries maximum number of parallel background queries in dht
 */
void
GNS_resolver_init (struct GNUNET_NAMESTORE_Handle *nh,
		   struct GNUNET_DHT_Handle *dht,
		   const struct GNUNET_CONFIGURATION_Handle *c,
		   unsigned long long max_bg_queries)
{
  char *dns_ip;

  cfg = c;
  namestore_handle = nh;
  dht_handle = dht;
  dht_lookup_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  max_allowed_background_queries = max_bg_queries;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (c,
					     "gns",
					     "DNS_RESOLVER",
					     &dns_ip))
  {
    /* user did not specify DNS resolver, use 8.8.8.8 */
    dns_ip = GNUNET_strdup ("8.8.8.8");
  }
  dns_handle = GNUNET_DNSSTUB_start (dns_ip);
  GNUNET_free (dns_ip);
}


/**
 * Shutdown resolver
 */
void
GNS_resolver_done ()
{
  struct GNS_ResolverHandle *rh;

  /* abort active resolutions */
  while (NULL != (rh = rlh_head))
  {
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);    
  }
  /* abort active shorten operations */
  while (NULL != gph_head)
    free_get_pseu_authority_handle (gph_head);
  GNUNET_CONTAINER_heap_destroy (dht_lookup_heap);
  dht_lookup_heap = NULL;
  GNUNET_DNSSTUB_stop (dns_handle);
  dns_handle = NULL;
}


/* *************** common helper functions (do not really belong here) *********** */

/**
 * Checks if "name" ends in ".tld"
 *
 * @param name the name to check
 * @param tld the TLD to check for
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tld (const char* name, const char* tld)
{
  size_t offset = 0;

  if (strlen (name) <= strlen (tld))
    return GNUNET_NO;
  offset = strlen (name) - strlen (tld);
  if (0 != strcmp (name + offset, tld))
    return GNUNET_NO;
  return GNUNET_YES;
}


/* end of gnunet-service-gns_resolver.c */
