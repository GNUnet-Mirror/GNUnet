#ifndef GNS_RESOLVER_H
#define GNS_RESOLVER_H

#include "gns.h"
#include "gnunet_dht_service.h"

#define DHT_OPERATION_TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)
#define DHT_LOOKUP_TIMEOUT DHT_OPERATION_TIMEOUT
#define DHT_GNS_REPLICATION_LEVEL 5
#define MAX_DNS_LABEL_LENGTH 63
#define MAX_DNS_NAME_LENGTH 253

/*
 * DLL to hold the authority chain
 * we had to pass in the resolution process
 */
struct AuthorityChain
{
  struct AuthorityChain *prev;

  struct AuthorityChain *next;
  
  /* the zone hash of the authority */
  GNUNET_HashCode zone;

  /* (local) name of the authority */
  char name[MAX_DNS_LABEL_LENGTH];

  /* was the ns entry fresh */
  int fresh;
};

/* handle to a resolution process */
struct ResolverHandle;


/**
 * processor for a resultion result
 *
 * @param cls the closure
 * @param rh the resolution handle
 * @param rd_count number of results
 * @pram rd resukt data
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
 * processor for a resultion result
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
struct ResolverHandle
{
  /* The name to resolve */
  char name[MAX_DNS_NAME_LENGTH];

  /* has this query been answered? how many matches */
  int answered;

  /* the authoritative zone to query */
  GNUNET_HashCode authority;

  /* the name of the authoritative zone to query */
  char authority_name[MAX_DNS_LABEL_LENGTH];

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

  struct GNUNET_CRYPTO_RsaPrivateKey *priv_key;

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
  GNUNET_HashCode new_zone;

  /* the zone of our authority */
  GNUNET_HashCode zone;

  /* the private key of the zone to store the pseu in */
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  /* a handle for dht lookups. should be NULL if no lookups are in progress */
  struct GNUNET_DHT_GetHandle *get_handle;

  /* timeout task for dht lookups */
  GNUNET_SCHEDULER_TaskIdentifier dht_timeout;
};

/**
 * Initialize the resolver
 *
 * @param nh handle to the namestore
 * @param dh handle to the dht
 * @returns GNUNET_OK on success
 */
int
gns_resolver_init(struct GNUNET_NAMESTORE_Handle *nh,
                  struct GNUNET_DHT_Handle *dh);

/**
 * Lookup of a record in a specific zone
 * calls lookup result processor on result
 *
 * @param zone the root zone
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param key optional private key for authority caching
 * @param proc the processor to call
 * @param cls the closure to pass to proc
 */
void
gns_resolver_lookup_record(GNUNET_HashCode zone,
                           uint32_t record_type,
                           const char* name,
                           struct GNUNET_CRYPTO_RsaPrivateKey *key,
                           RecordLookupProcessor proc,
                           void* cls);

void
gns_resolver_shorten_name(GNUNET_HashCode zone,
                          const char* name,
                          ShortenResultProcessor proc,
                          void* cls);

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
                           void* cls);

#endif
