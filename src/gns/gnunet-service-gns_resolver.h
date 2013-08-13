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
 * @file gns/gnunet-service-gns_resolver.h
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_RESOLVER_H
#define GNS_RESOLVER_H

#include "gns.h"
#include "gnunet_dht_service.h"

#define DHT_OPERATION_TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define GNUNET_GNS_DEFAULT_LOOKUP_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define DHT_LOOKUP_TIMEOUT DHT_OPERATION_TIMEOUT

#define DHT_GNS_REPLICATION_LEVEL 5

#define GNUNET_GNS_MAX_PARALLEL_LOOKUPS 500

#define GNUNET_GNS_MAX_NS_TASKS 500

/*
 * DLL to hold the authority chain
 * we had to pass in the resolution process
 */
struct AuthorityChain
{
  struct AuthorityChain *prev;

  struct AuthorityChain *next;
  
  /**
   * the zone hash of the authority 
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * (local) name of the authority 
   */
  char name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];

  /**
   * was the ns entry fresh 
   */
  int fresh;
};


/**
 * handle to a resolution process 
 */
struct ResolverHandle;


/**
 * processor for a record lookup result
 *
 * @param cls the closure
 * @param rd_count number of results
 * @param rd result data
 */
typedef void (*RecordLookupProcessor) (void *cls,
				       uint32_t rd_count,
				       const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * processor for a shorten result
 *
 * @param cls the closure
 * @param name shortened name
 */
typedef void (*ShortenResultProcessor) (void *cls, 
					const char* name);


/**
 * processor for an authority result
 *
 * @param cls the closure
 * @param name name of the authority
 */
typedef void (*GetAuthorityResultProcessor) (void *cls, 
					     const char* name);

/**
 * processor for a resolution result
 *
 * @param cls the closure
 * @param rh the resolution handle
 * @param rd_count number of results
 * @param rd result data (array of 'rd_count' records)
 */
typedef void (*ResolutionResultProcessor) (void *cls,
					   struct ResolverHandle *rh,
					   uint32_t rd_count,
					   const struct GNUNET_NAMESTORE_RecordData *rd);


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
 * Handle to a currenty pending resolution
 * a ResolverHandle is passed to, for example
 * resolve_record_ns to resolve a record in the namestore.
 * On result (positive or negative) the ResolutionResultProcessor
 * is called.
 * If a timeout is set timeout_cont will be called.
 * If no timeout is set (ie timeout forever) then background resolutions
 * might be triggered.
 */
struct ResolverHandle
{

  /**
   * DLL 
   */
  struct ResolverHandle *next;

  /**
   * DLL 
   */
  struct ResolverHandle *prev;

  /**
   * Last record data found 
   */
  struct GNUNET_NAMESTORE_RecordData rd;

  /**
   * Number of last record data found 
   */
  unsigned int rd_count;

  /**
   * The name to resolve 
   */
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * has this query been answered? how many matches 
   */
  int answered;

  /**
   * Use only cache 
   */
  int only_cached;

  /**
   * the authoritative zone to query 
   */
  struct GNUNET_CRYPTO_ShortHashCode authority;

  /**
   * the name of the authoritative zone to query 
   */
  char authority_name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];

  /**
   * a handle for dht lookups. should be NULL if no lookups are in progress 
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * timeout set for this lookup task 
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * a handle to a vpn request 
   */
  struct GNUNET_VPN_RedirectionRequest *vpn_handle;

  /**
   * a socket for a dns request 
   */
  struct GNUNET_NETWORK_Handle *dns_sock;

  /**
   * a synthesized dns name 
   */
  char dns_name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * the authoritative dns zone 
   */
  char dns_zone[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * the address of the DNS server FIXME not needed? 
   */
  struct sockaddr_in dns_addr;

  /**
   * handle to the local stub resolver request
   */
  struct GNUNET_RESOLVER_RequestHandle *dns_resolver_handle;

  /**
   * select task for DNS 
   */
  GNUNET_SCHEDULER_TaskIdentifier dns_read_task;

  /**
   * pointer to raw dns query payload FIXME needs to be freed/NULL 
   */
  char *dns_raw_packet;

  /**
   * size of the raw dns query 
   */
  size_t dns_raw_packet_size;

  /**
   * timeout task for the lookup 
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * continuation to call on timeout 
   */
  GNUNET_SCHEDULER_Task timeout_cont;

  /**
   * closure for timeout cont 
   */
  void* timeout_cont_cls;

  /**
   * called when resolution phase finishes 
   */
  ResolutionResultProcessor proc;
  
  /**
   * closure passed to proc 
   */
  void* proc_cls;

  /**
   * DLL to store the authority chain 
   */
  struct AuthorityChain *authority_chain_head;

  /**
   * DLL to store the authority chain 
   */
  struct AuthorityChain *authority_chain_tail;

  /**
   * status of the resolution result 
   */
  enum ResolutionStatus status;

  /**
   * The provate local zone of this request 
   */
  struct GNUNET_CRYPTO_ShortHashCode private_local_zone;

  /**
   * private key of an/our authoritative zone
   * can be NULL but automatical PKEY import will not work
   */
  struct GNUNET_CRYPTO_EccPrivateKey *priv_key;

  /**
   * the heap node associated with this lookup, null if timeout is set
   * used for DHT background lookups.
   */
  struct GNUNET_CONTAINER_HeapNode *dht_heap_node;

  /**
   * Id for resolution process
   */
  unsigned long long id;

  /**
   * Pending Namestore task
   */
  struct GNUNET_NAMESTORE_QueueEntry *namestore_task;

};


/**
 * Handle to a record lookup
 */
struct RecordLookupHandle
{
  /**
   * the record type to look up 
   */
  int record_type;

  /**
   * the name to look up 
   */
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * Method to call on record resolution result 
   */
  RecordLookupProcessor proc;

  /**
   * closure to pass to proc 
   */
  void* proc_cls;

};


/**
 * Handle to a shorten context
 */
struct NameShortenHandle
{
  /**
   * Method to call on shorten result 
   */
  ShortenResultProcessor proc;

  /**
   * closure to pass to proc 
   */
  void* proc_cls;

  /**
   * result of shorten 
   */
  char result[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * root zone 
   */
  struct GNUNET_CRYPTO_ShortHashCode *root_zone;

  /**
   * private zone 
   */
  struct GNUNET_CRYPTO_ShortHashCode *private_zone;

  /**
   * name of private zone 
   */
  char private_zone_name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];

  /**
   * shorten zone 
   */
  struct GNUNET_CRYPTO_ShortHashCode *shorten_zone;

  /**
   * name of shorten zone 
   */
  char shorten_zone_name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];

};


/**
 * Handle to a get authority context
 */
struct GetNameAuthorityHandle
{
  /**
   * the name to look up authority for 
   */
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * the result 
   */
  char result[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  
  /**
   * Method to call on result 
   */
  GetAuthorityResultProcessor proc;

  /**
   * closure to pass to proc 
   */
  void* proc_cls;
};


/**
 * Handle to a pseu lookup
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
   * the name to store the zone under 
   */
  char name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];

  /**
   * test name to store the zone under 
   */
  char test_name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];
  
  /**
   * the zone of our authority 
   */
  struct GNUNET_CRYPTO_ShortHashCode our_zone;

  /**
   * the private key of the zone to store the pseu in 
   */
  struct GNUNET_CRYPTO_EccPrivateKey *key;

  /**
   * a handle for dht lookups. should be NULL if no lookups are in progress 
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * timeout task for lookup 
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout;

  /**
   * Authority to shorten 
   */
  struct AuthorityChain *auth;

  /**
   * handle to namestore request 
   */
  struct GNUNET_NAMESTORE_QueueEntry* namestore_task;
};


/**
 * Namestore queue entries in background
 */
struct NamestoreBGTask
{
  /**
   * node in heap 
   */
  struct GNUNET_CONTAINER_HeapNode *node;

  /**
   * queue entry 
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;
};


/**
 * Initialize the resolver
 * MUST be called before other gns_resolver_* methods
 *
 * @param nh handle to the namestore
 * @param dh handle to the dht
 * @param lz the local zone
 * @param c configuration handle
 * @param max_bg_queries maximum amount of background queries
 * @param ignore_pending ignore records that still require user confirmation
 *        on lookup
 * @returns GNUNET_OK on success
 */
int
gns_resolver_init (struct GNUNET_NAMESTORE_Handle *nh,
		   struct GNUNET_DHT_Handle *dh,
		   struct GNUNET_CRYPTO_ShortHashCode lz,
		   const struct GNUNET_CONFIGURATION_Handle *c,
		   unsigned long long max_bg_queries,
		   int ignore_pending);


/**
 * Cleanup resolver: Terminate pending lookups
 */
void
gns_resolver_cleanup (void);


/**
 * Lookup of a record in a specific zone
 * calls RecordLookupProcessor on result or timeout
 *
 * @param zone the root zone
 * @param pzone the private local zone
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param key optional private key for authority caching
 * @param timeout timeout for the resolution
 * @param only_cached GNUNET_NO to only check locally not DHT for performance
 * @param proc the processor to call
 * @param cls the closure to pass to proc
 */
void
gns_resolver_lookup_record (struct GNUNET_CRYPTO_ShortHashCode zone,
			    struct GNUNET_CRYPTO_ShortHashCode pzone,
			    uint32_t record_type,
			    const char* name,
			    struct GNUNET_CRYPTO_EccPrivateKey *key,
			    struct GNUNET_TIME_Relative timeout,
			    int only_cached,
			    RecordLookupProcessor proc,
			    void* cls);


/**
 * Shortens a name if possible. If the shortening fails
 * name will be returned as shortened string. Else
 * a shorter version of the name will be returned.
 * There is no guarantee that the shortened name will
 * actually be canonical/short etc.
 *
 * @param zone the root zone to use
 * @param pzone the private zone to use
 * @param szone the shorten zone to use
 * @param name name to shorten
 * @param private_zone_name name of the private zone
 * @param shorten_zone_name name of the shorten zone
 * @param proc the processor to call on shorten result
 * @param proc_cls the closure to pass to proc
 */
void
gns_resolver_shorten_name (struct GNUNET_CRYPTO_ShortHashCode *zone,
			   struct GNUNET_CRYPTO_ShortHashCode *pzone,
			   struct GNUNET_CRYPTO_ShortHashCode *szone,
			   const char* name,
			   const char* private_zone_name,
			   const char* shorten_zone_name,
			   ShortenResultProcessor proc,
			   void* proc_cls);


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
gns_resolver_get_authority (struct GNUNET_CRYPTO_ShortHashCode zone,
			    struct GNUNET_CRYPTO_ShortHashCode pzone,
			    const char* name,
			    GetAuthorityResultProcessor proc,
			    void* proc_cls);


/**
 * Generic function to check for TLDs.  Checks if "name" ends in ".tld"
 *
 * @param name the name to check
 * @param tld the tld to check
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tld (const char* name, 
	const char* tld);



/**
 * Checks for gads/zkey
 */
#define is_gads_tld(name) is_tld(name, GNUNET_GNS_TLD)
#define is_zkey_tld(name) is_tld(name, GNUNET_GNS_TLD_ZKEY)


#endif
