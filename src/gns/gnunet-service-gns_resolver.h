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

/*
 * DLL to hold the authority chain
 * we had to pass in the resolution process
 */
struct AuthorityChain
{
  struct AuthorityChain *prev;

  struct AuthorityChain *next;
  
  /* the zone hash of the authority */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /* (local) name of the authority */
  char name[MAX_DNS_LABEL_LENGTH];

  /* was the ns entry fresh */
  int fresh;
};

/* handle to a resolution process */
struct ResolverHandle;

/**
 * continuation called when cleanup of resolver finishes
 */
typedef void (*ResolverCleanupContinuation) (void);

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
typedef void (*ShortenResultProcessor) (void *cls, const char* name);


/**
 * processor for an authority result
 *
 * @param cls the closure
 * @param name name
 */
typedef void (*GetAuthorityResultProcessor) (void *cls, const char* name);

/**
 * processor for a resolution result
 *
 * @param cls the closure
 * @param rh the resolution handle
 * @param rd_count number of results
 * @param rd result data
 */
typedef void (*ResolutionResultProcessor) (void *cls,
                                  struct ResolverHandle *rh,
                                  uint32_t rd_count,
                                  const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * Resolution status indicator
 * RSL_RECORD_EXISTS: the name to lookup exists
 * RSL_RECORD_EXPIRED: the name in the record expired
 * RSL_TIMED_OUT: resolution timed out
 */
enum ResolutionStatus
{
  RSL_RECORD_EXISTS = 1,
  RSL_RECORD_EXPIRED = 2,
  RSL_TIMED_OUT = 4
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
  /* The name to resolve */
  char name[MAX_DNS_NAME_LENGTH];

  /* has this query been answered? how many matches */
  int answered;

  /* the authoritative zone to query */
  struct GNUNET_CRYPTO_ShortHashCode authority;

  /* the name of the authoritative zone to query */
  char authority_name[MAX_DNS_LABEL_LENGTH];

  /* a handle for dht lookups. should be NULL if no lookups are in progress */
  struct GNUNET_DHT_GetHandle *get_handle;

  /* timeout set for this lookup task */
  struct GNUNET_TIME_Relative timeout;

  /* timeout task for the lookup */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /* continuation to call on timeout */
  GNUNET_SCHEDULER_Task timeout_cont;

  /* closure for timeout cont */
  void* timeout_cont_cls;

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

  /* The provate local zone of this request */
  struct GNUNET_CRYPTO_ShortHashCode private_local_zone;

  /**
   * private key of an/our authoritative zone
   * can be NULL but automatical PKEY import will not work
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *priv_key;

  /**
   * the heap node associated with this lookup, null if timeout is set
   * used for DHT background lookups.
   */
  struct GNUNET_CONTAINER_HeapNode *dht_heap_node;

  /**
   * Id for resolution process
   */
  unsigned long long id;

};


/**
 * Handle to a record lookup
 */
struct RecordLookupHandle
{
  /* the record type to look up */
  enum GNUNET_GNS_RecordType record_type;

  /* the name to look up */
  char name[MAX_DNS_NAME_LENGTH];

  /* Method to call on record resolution result */
  RecordLookupProcessor proc;

  /* closure to pass to proc */
  void* proc_cls;

};


/**
 * Handle to a shorten context
 */
struct NameShortenHandle
{
  /* Method to call on shorten result */
  ShortenResultProcessor proc;

  /* closure to pass to proc */
  void* proc_cls;
};

/**
 * Handle to a get authority context
 */
struct GetNameAuthorityHandle
{
  /* the name to look up authority for */
  char name[MAX_DNS_NAME_LENGTH];
  
  /* Method to call on result */
  GetAuthorityResultProcessor proc;

  /* closure to pass to proc */
  void* proc_cls;
};

/**
 * Handle to a pseu lookup
 */
struct GetPseuAuthorityHandle
{
  /* the name given from delegation */
  char name[MAX_DNS_LABEL_LENGTH];

  /* name to store the pseu under */
  char new_name[MAX_DNS_LABEL_LENGTH];
  
  /* the zone of discovered authority */
  struct GNUNET_CRYPTO_ShortHashCode new_zone;

  /* the zone of our authority */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /* the private key of the zone to store the pseu in */
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  /* a handle for dht lookups. should be NULL if no lookups are in progress */
  struct GNUNET_DHT_GetHandle *get_handle;

  /* timeout task for lookup */
  GNUNET_SCHEDULER_TaskIdentifier timeout;
};

/**
 * Initialize the resolver
 * MUST be called before other gns_resolver_* methods
 *
 * @param nh handle to the namestore
 * @param dh handle to the dht
 * @param lz the local zone
 * @param max_bg_queries maximum amount of background queries
 * @param ignore_pending ignore records that still require user confirmation
 *        on lookup
 * @returns GNUNET_OK on success
 */
int
gns_resolver_init(struct GNUNET_NAMESTORE_Handle *nh,
                  struct GNUNET_DHT_Handle *dh,
                  struct GNUNET_CRYPTO_ShortHashCode lz,
                  unsigned long long max_bg_queries,
                  int ignore_pending);

/**
 * Cleanup resolver: Terminate pending lookups
 * 
 * @param cont continuation to call when finished
 */
void
gns_resolver_cleanup(ResolverCleanupContinuation cont);

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
 * @param proc the processor to call
 * @param cls the closure to pass to proc
 */
void
gns_resolver_lookup_record(struct GNUNET_CRYPTO_ShortHashCode zone,
                           struct GNUNET_CRYPTO_ShortHashCode pzone,
                           uint32_t record_type,
                           const char* name,
                           struct GNUNET_CRYPTO_RsaPrivateKey *key,
                           struct GNUNET_TIME_Relative timeout,
                           RecordLookupProcessor proc,
                           void* cls);

/**
 * Shortens a name if possible. If the shortening fails
 * name will be returned as shortened string. Else
 * a shorter version of the name will be returned.
 * There is no guarantee that the shortened name will
 * actually be canonical/short etc.
 *
 * @param zone the zone to perform the operation in
 * @param pzone the private local zone
 * @param name name to shorten
 * @param key optional private key for background lookups and PSEU import
 * @param proc the processor to call on shorten result
 * @param proc_cls the closure to pass to proc
 */
void
gns_resolver_shorten_name(struct GNUNET_CRYPTO_ShortHashCode zone,
                          struct GNUNET_CRYPTO_ShortHashCode pzone,
                          const char* name,
                          struct GNUNET_CRYPTO_RsaPrivateKey *key,
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
gns_resolver_get_authority(struct GNUNET_CRYPTO_ShortHashCode zone,
                           struct GNUNET_CRYPTO_ShortHashCode pzone,
                           const char* name,
                           GetAuthorityResultProcessor proc,
                           void* proc_cls);

/**
 * Generic function to check for TLDs
 *
 * @param name the name to check
 * @param tld the tld to check
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tld(const char* name, const char* tld);

/**
 * Checks for gnunet/zkey
 */
#define is_gnunet_tld(name) is_tld(name, GNUNET_GNS_TLD)
#define is_zkey_tld(name) is_tld(name, GNUNET_GNS_TLD_ZKEY)


#endif
