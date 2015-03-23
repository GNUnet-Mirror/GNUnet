/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
 * @brief GNU Name System resolver logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsstub_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_revocation_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"
#include "gnunet_gns_service.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_shorten.h"
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
 * Default timeout for VPN redirections.
 */
#define VPN_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

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
   * label/name suggested for shortening to the authority
   */
  char *suggested_shortening_label;

  /**
   * Do we already try to shorten this authority?
   */
  int shortening_started;

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
    struct GNUNET_CRYPTO_EcdsaPublicKey gns_authority;

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
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

};


/**
 * Closure for #vpn_allocation_cb.
 */
struct VpnContext
{

  /**
   * Which resolution process are we processing.
   */
  struct GNS_ResolverHandle *rh;

  /**
   * Handle to the VPN request that we were performing.
   */
  struct GNUNET_VPN_RedirectionRequest *vpn_request;

  /**
   * Number of records serialized in @e rd_data.
   */
  unsigned int rd_count;

  /**
   * Serialized records.
   */
  char *rd_data;

  /**
   * Number of bytes in @e rd_data.
   */
  size_t rd_data_size;
};


/**
 * Information we keep during the resolution of an
 * IP address for a DNS server while handling a
 * GNS2DNS record.
 */
struct Gns2DnsContext
{

  /**
   * DNS domain in which the resolution will continue
   * (first part of the GNS2DNS record).
   */
  char *ns;

  /**
   * Handle for the resolution of the IP part of the
   * GNS2DNS record.  Will return to us the addresses
   * of the DNS resolver to use.
   */
  struct GNS_ResolverHandle *rh;

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
  struct GNUNET_CRYPTO_EcdsaPublicKey authority_zone;

  /**
   * called when resolution phase finishes
   */
  GNS_ResultProcessor proc;

  /**
   * closure passed to @e proc
   */
  void* proc_cls;

  /**
   * Handle used during GNS2DNS resolution for looking up the
   * IP address of the DNS server.
   */
  struct Gns2DnsContext *g2dc;

  /**
   * Handle for DHT lookups. should be NULL if no lookups are in progress
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * Handle to a VPN request, NULL if none is active.
   */
  struct VpnContext *vpn_ctx;

  /**
   * Socket for a DNS request, NULL if none is active.
   */
  struct GNUNET_DNSSTUB_RequestSocket *dns_request;

  /**
   * Handle for standard DNS resolution, NULL if none is active.
   */
  struct GNUNET_RESOLVER_RequestHandle *std_resolve;

  /**
   * Pending Namecache lookup task
   */
  struct GNUNET_NAMECACHE_QueueEntry *namecache_qe;

  /**
   * Pending revocation check.
   */
  struct GNUNET_REVOCATION_Query *rev_check;

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
  struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_key;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task * task_id;

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
  enum GNUNET_GNS_LocalOptions options;

  /**
   * For SRV and TLSA records, the number of the
   * protocol specified in the name.  0 if no protocol was given.
   */
  int protocol;

  /**
   * For SRV and TLSA records, the number of the
   * service specified in the name.  0 if no service was given.
   */
  int service;

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
 * Active namestore caching operations.
 */
struct CacheOps
{

  /**
   * Organized in a DLL.
   */
  struct CacheOps *next;

  /**
   * Organized in a DLL.
   */
  struct CacheOps *prev;

  /**
   * Pending Namestore caching task.
   */
  struct GNUNET_NAMECACHE_QueueEntry *namecache_qe_cache;

};


/**
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache_handle;

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
 * Head of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_head;

/**
 * Tail of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_tail;

/**
 * Organized in a DLL.
 */
static struct CacheOps *co_head;

/**
 * Organized in a DLL.
 */
static struct CacheOps *co_tail;

/**
 * Use namecache
 */
static int use_cache;

/**
 * Global configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


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
 * @return #GNUNET_YES if canonical
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

/* ************************** Resolution **************************** */

/**
 * Expands a name ending in .+ with the zone of origin.
 *
 * @param rh resolution context
 * @param name name to modify (to be free'd or returned)
 * @return updated name
 */
static char *
translate_dot_plus (struct GNS_ResolverHandle *rh,
		    char *name)
{
  char *ret;
  size_t s_len = strlen (name);

  if (0 != strcmp (&name[s_len - 2],
		   ".+"))
    return name; /* did not end in ".+" */
  GNUNET_assert (GNUNET_YES == rh->ac_tail->gns_authority);
  GNUNET_asprintf (&ret,
		   "%.*s.%s",
		   (int) (s_len - 2),
		   name,
		   GNUNET_GNSRECORD_pkey_to_zkey (&rh->ac_tail->authority_info.gns_authority));
  GNUNET_free (name);
  return ret;
}


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

  rh->task_id = NULL;
  rh->proc (rh->proc_cls, 0, NULL);
  GNS_resolver_lookup_cancel (rh);
}


#if (defined WINDOWS) || (defined DARWIN)
/* Don't have this on W32, here's a naive implementation
 * Was somehow removed on OS X ...  */
static void *
memrchr (const void *s,
	 int c,
	 size_t n)
{
  const unsigned char *ucs = s;
  ssize_t i;

  for (i = n - 1; i >= 0; i--)
    if (c == (int) ucs[i])
      return (void *) &ucs[i];
  return NULL;
}
#endif


/**
 * Get the next, rightmost label from the name that we are trying to resolve,
 * and update the resolution position accordingly.  Labels usually consist
 * of up to 63 characters without a period ("."); however, we use a special
 * convention to support SRV and TLSA records where the domain name
 * includes an encoding for a service and protocol in the name.  The
 * syntax (see RFC 2782) here is "_Service._Proto.Name" and in this
 * special case we include the "_Service._Proto" in the rightmost label.
 * Thus, for "_443._tcp.foo.bar" we first return the label "bar" and then
 * the label "_443._tcp.foo".  The special case is detected by the
 * presence of labels beginning with an underscore.  Whenever a label
 * begins with an underscore, it is combined with the label to its right
 * (and the "." is preserved).
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
  char *ret;
  char *srv_name;
  char *proto_name;
  struct protoent *pe;
  struct servent *se;

  if (0 == rh->name_resolution_pos)
    return NULL;
  dot = memrchr (rh->name,
                 (int) '.',
                 rh->name_resolution_pos);
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
  rh->protocol = 0;
  rh->service = 0;
  ret = GNUNET_strndup (rp, len);
  /* If we have labels starting with underscore with label on
   * the right (SRV/DANE/BOX case), determine port/protocol;
   * The format of `rh->name` must be "_PORT._PROTOCOL".
   */
  if ( ('_' == rh->name[0]) &&
       (NULL != (dot = memrchr (rh->name,
                                (int) '.',
                                rh->name_resolution_pos))) &&
       ('_' == dot[1]) &&
       (NULL == memrchr (rh->name,
                         (int) '.',
                         dot - rh->name)) )
  {
    srv_name = GNUNET_strndup (&rh->name[1],
                               (dot - rh->name) - 1);
    proto_name = GNUNET_strndup (&dot[2],
                                 rh->name_resolution_pos - (dot - rh->name) - 1);
    rh->name_resolution_pos = 0;
    pe = getprotobyname (proto_name);
    if (NULL == pe)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Protocol `%s' unknown, skipping labels.\n"),
                  proto_name);
      GNUNET_free (proto_name);
      GNUNET_free (srv_name);
      return ret;
    }
    se = getservbyname (srv_name,
                        proto_name);
    if (NULL == se)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Service `%s' unknown for protocol `%s', skipping labels.\n"),
                  srv_name,
                  proto_name);
      GNUNET_free (proto_name);
      GNUNET_free (srv_name);
      return ret;
    }
    rh->protocol = pe->p_proto;
    rh->service = se->s_port;
  }
  return ret;
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
    struct GNUNET_GNSRECORD_Data rd[n];

    i = 0;
    for (pos = rh->dns_result_head; NULL != pos; pos = pos->next)
    {
      rd[i].data = pos->data;
      rd[i].data_size = pos->data_size;
      rd[i].record_type = pos->record_type;
      if (0 == pos->expiration_time)
      {
	rd[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
	rd[i].expiration_time = 0;
      }
      else
      {
	rd[i].flags = GNUNET_GNSRECORD_RF_NONE;
	rd[i].expiration_time = pos->expiration_time;
      }
      i++;
    }
    GNUNET_assert (i == n);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Transmitting standard DNS result with %u records\n",
		n);
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
 * @param cls closure with the `struct GNS_ResolverHandle`
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

  if (NULL == addr)
  {
    rh->std_resolve = NULL;
    transmit_lookup_dns_result (rh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %u bytes of DNS IP data\n",
	      addrlen);
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
 * Begin the resolution process from 'name', starting with
 * the identification of the zone specified by 'name'.
 *
 * @param rh resolution to perform
 */
static void
start_resolver_lookup (struct GNS_ResolverHandle *rh);


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls the request handle of the resolution that
 *        we were attempting to make
 * @param rs socket that received the response
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
dns_result_parser (void *cls,
		   struct GNUNET_DNSSTUB_RequestSocket *rs,
		   const struct GNUNET_TUN_DnsHeader *dns,
		   size_t dns_len)
{
  struct GNS_ResolverHandle *rh = cls;
  struct GNUNET_DNSPARSER_Packet *p;
  const struct GNUNET_DNSPARSER_Record *rec;
  unsigned int rd_count;
  unsigned int i;

  rh->dns_request = NULL;
  GNUNET_SCHEDULER_cancel (rh->task_id);
  rh->task_id = NULL;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received DNS response for `%s' with %u answers\n",
	      rh->ac_tail->label,
	      (unsigned int) p->num_answers);
  if ( (p->num_answers > 0) &&
       (GNUNET_DNSPARSER_TYPE_CNAME == p->answers[0].type) &&
       (GNUNET_DNSPARSER_TYPE_CNAME != rh->record_type) )
    {
      GNUNET_free (rh->name);
      rh->name = GNUNET_strdup (p->answers[0].data.hostname);
      rh->name_resolution_pos = strlen (rh->name);
      start_resolver_lookup (rh);
      GNUNET_DNSPARSER_free_packet (p);
      return;
    }

  /* convert from (parsed) DNS to (binary) GNS format! */
  rd_count = p->num_answers + p->num_authority_records + p->num_additional_records;
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];
    unsigned int skip;
    char buf[UINT16_MAX];
    size_t buf_off;
    size_t buf_start;

    buf_off = 0;
    skip = 0;
    memset (rd, 0, sizeof (rd));
    for (i=0;i<rd_count;i++)
    {
      if (i < p->num_answers)
	rec = &p->answers[i];
      else if (i < p->num_answers + p->num_authority_records)
	rec = &p->authority_records[i - p->num_answers];
      else
	rec = &p->additional_records[i - p->num_answers - p->num_authority_records];
      /* As we copied the full DNS name to 'rh->ac_tail->label', this
	 should be the correct check to see if this record is actually
	 a record for our label... */
      if (0 != strcmp (rec->name,
		       rh->ac_tail->label))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Dropping record `%s', does not match desired name `%s'\n",
		    rec->name,
		    rh->ac_tail->label);
	skip++;
	continue;
      }
      rd[i - skip].record_type = rec->type;
      rd[i - skip].expiration_time = rec->expiration_time.abs_value_us;
      switch (rec->type)
      {
      case GNUNET_DNSPARSER_TYPE_A:
	if (rec->data.raw.data_len != sizeof (struct in_addr))
	{
	  GNUNET_break_op (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = rec->data.raw.data_len;
	rd[i - skip].data = rec->data.raw.data;
	break;
      case GNUNET_DNSPARSER_TYPE_AAAA:
	if (rec->data.raw.data_len != sizeof (struct in6_addr))
	{
	  GNUNET_break_op (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = rec->data.raw.data_len;
	rd[i - skip].data = rec->data.raw.data;
	break;
      case GNUNET_DNSPARSER_TYPE_CNAME:
      case GNUNET_DNSPARSER_TYPE_PTR:
      case GNUNET_DNSPARSER_TYPE_NS:
	buf_start = buf_off;
	if (GNUNET_OK !=
	    GNUNET_DNSPARSER_builder_add_name (buf,
					       sizeof (buf),
					       &buf_off,
					       rec->data.hostname))
	{
	  GNUNET_break (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = buf_off - buf_start;
	rd[i - skip].data = &buf[buf_start];
	break;
      case GNUNET_DNSPARSER_TYPE_SOA:
	buf_start = buf_off;
	if (GNUNET_OK !=
	    GNUNET_DNSPARSER_builder_add_soa (buf,
					       sizeof (buf),
					       &buf_off,
					       rec->data.soa))
	{
	  GNUNET_break (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = buf_off - buf_start;
	rd[i - skip].data = &buf[buf_start];
	break;
      case GNUNET_DNSPARSER_TYPE_MX:
	buf_start = buf_off;
	if (GNUNET_OK !=
	    GNUNET_DNSPARSER_builder_add_mx (buf,
					     sizeof (buf),
					     &buf_off,
					     rec->data.mx))
	{
	  GNUNET_break (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = buf_off - buf_start;
	rd[i - skip].data = &buf[buf_start];
	break;
      case GNUNET_DNSPARSER_TYPE_SRV:
	buf_start = buf_off;
	if (GNUNET_OK !=
	    GNUNET_DNSPARSER_builder_add_srv (buf,
					      sizeof (buf),
					      &buf_off,
					      rec->data.srv))
	{
	  GNUNET_break (0);
	  skip++;
	  continue;
	}
	rd[i - skip].data_size = buf_off - buf_start;
	rd[i - skip].data = &buf[buf_start];
	break;
      default:
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Skipping record of unsupported type %d\n"),
		    rec->type);
	skip++;
	continue;
      }
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning DNS response for `%s' with %u answers\n",
                rh->ac_tail->label,
                (unsigned int) p->num_answers);
    rh->proc (rh->proc_cls, rd_count - skip, rd);
    GNS_resolver_lookup_cancel (rh);
  }
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting DNS lookup for `%s'\n",
	      ac->label);
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
  query->dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;
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
  size_t nlen;
  char *res;
  struct AuthorityChain *ac;

  nlen = strlen (cname);
  if ( (nlen > 2) &&
       (0 == strcmp (".+",
		     &cname[nlen - 2])) )
  {
    /* CNAME resolution continues relative to current domain */
    if (0 == rh->name_resolution_pos)
    {
      res = GNUNET_strndup (cname, nlen - 2);
      rh->name_resolution_pos = nlen - 2;
    }
    else
    {
      GNUNET_asprintf (&res,
		       "%.*s.%.*s",
		       (int) rh->name_resolution_pos,
		       rh->name,
		       (int) (nlen - 2),
		       cname);
      rh->name_resolution_pos = strlen (res);
    }
    GNUNET_free (rh->name);
    rh->name = res;
    ac = GNUNET_new (struct AuthorityChain);
    ac->rh = rh;
    ac->gns_authority = GNUNET_YES;
    ac->authority_info.gns_authority = rh->ac_tail->authority_info.gns_authority;
    ac->label = resolver_lookup_get_next_label (rh);
    ac->suggested_shortening_label = NULL;
    ac->shortening_started = GNUNET_NO;
    /* add AC to tail */
    GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
				      rh->ac_tail,
				      ac);
    rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
					    rh);
    return;
  }
  /* name is absolute, start from the beginning */
  GNUNET_free (rh->name);
  rh->name = GNUNET_strdup (cname);
  rh->name_resolution_pos = strlen (rh->name);
  start_resolver_lookup (rh);
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
			      const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination.  Replaces the "VPN" record
 * with the respective A/AAAA record and continues processing.
 *
 * @param cls closure
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the
 *                specified target peer; NULL on error
 */
static void
vpn_allocation_cb (void *cls,
		   int af,
		   const void *address)
{
  struct VpnContext *vpn_ctx = cls;
  struct GNS_ResolverHandle *rh = vpn_ctx->rh;
  struct GNUNET_GNSRECORD_Data rd[vpn_ctx->rd_count];
  unsigned int i;

  vpn_ctx->vpn_request = NULL;
  rh->vpn_ctx = NULL;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_GNSRECORD_records_deserialize (vpn_ctx->rd_data_size,
						       vpn_ctx->rd_data,
						       vpn_ctx->rd_count,
						       rd));
  for (i=0;i<vpn_ctx->rd_count;i++)
  {
    if (GNUNET_GNSRECORD_TYPE_VPN == rd[i].record_type)
    {
      switch (af)
      {
      case AF_INET:
	rd[i].record_type = GNUNET_DNSPARSER_TYPE_A;
	rd[i].data_size = sizeof (struct in_addr);
	rd[i].expiration_time = GNUNET_TIME_relative_to_absolute (VPN_TIMEOUT).abs_value_us;
	rd[i].flags = 0;
	rd[i].data = address;
	break;
      case AF_INET6:
	rd[i].record_type = GNUNET_DNSPARSER_TYPE_AAAA;
	rd[i].expiration_time = GNUNET_TIME_relative_to_absolute (VPN_TIMEOUT).abs_value_us;
	rd[i].flags = 0;
	rd[i].data = address;
	rd[i].data_size = sizeof (struct in6_addr);
	break;
      default:
	GNUNET_assert (0);
      }
      break;
    }
  }
  GNUNET_assert (i < vpn_ctx->rd_count);
  handle_gns_resolution_result (rh,
				vpn_ctx->rd_count,
				rd);
  GNUNET_free (vpn_ctx->rd_data);
  GNUNET_free (vpn_ctx);
}


/**
 * We've resolved the IP address for the DNS resolver to use
 * after encountering a GNS2DNS record.
 *
 * TODO: Right now we only foward the request to ONE DNS resolver,
 * even if we get multiple IP addresses back; a correct implementation
 * should try all DNS resolvers.
 *
 * @param cls the `struct GNS_ResolverHandle` where we encountered
 *            the GNS2DNS record
 * @param rd_count number of records in @a rd
 * @param rd addresses for the DNS resolver  (presumably)
 */
static void
handle_gns2dns_result (void *cls,
                       unsigned int rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac;
  unsigned int j;
  struct sockaddr *sa;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  size_t sa_len;

  /* find suitable A/AAAA record */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u results for IP address of DNS server for GNS2DNS transition\n",
              rd_count);
  /* enable cleanup of 'rh' handle that comes next... */
  GNUNET_CONTAINER_DLL_insert (rlh_head,
			       rlh_tail,
			       rh->g2dc->rh);
  rh->g2dc->rh = NULL;
  sa = NULL;
  sa_len = 0;
  for (j=0;j<rd_count;j++)
  {
    switch (rd[j].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      if (sizeof (struct in_addr) != rd[j].data_size)
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
      if (sizeof (struct in6_addr) != rd[j].data_size)
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
    default:
      break;
    }
    if (NULL != sa)
      break;
  }
  if (NULL == sa)
  {
    /* we cannot continue; NS without A/AAAA */
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  /* expand authority chain */
  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  strcpy (ac->authority_info.dns_authority.name,
          rh->g2dc->ns);
  memcpy (&ac->authority_info.dns_authority.dns_ip,
          sa,
          sa_len);
  /* for DNS recursion, the label is the full DNS name,
     created from the remainder of the GNS name and the
     name in the NS record */
  GNUNET_asprintf (&ac->label,
                   "%.*s%s%s",
                   (int) rh->name_resolution_pos,
                   rh->name,
                   (0 != rh->name_resolution_pos) ? "." : "",
                   rh->g2dc->ns);
  GNUNET_free (rh->g2dc->ns);
  GNUNET_free (rh->g2dc);
  rh->g2dc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Will continue resolution using DNS server `%s' to resolve `%s'\n",
              GNUNET_a2s (sa, sa_len),
              ac->label);
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
}


/**
 * Process a records that were decrypted from a block.
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
handle_gns_resolution_result (void *cls,
			      unsigned int rd_count,
			      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac;
  struct AuthorityChain *shorten_ac;
  unsigned int i;
  char *cname;
  struct VpnContext *vpn_ctx;
  const struct GNUNET_TUN_GnsVpnRecord *vpn;
  const char *vname;
  struct GNUNET_HashCode vhash;
  int af;
  char scratch[UINT16_MAX];
  size_t scratch_off;
  size_t scratch_start;
  size_t off;
  struct GNUNET_GNSRECORD_Data rd_new[rd_count];
  unsigned int rd_off;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Resolution succeeded for `%s' in zone %s, got %u records\n",
	      rh->ac_tail->label,
	      GNUNET_GNSRECORD_z2s (&rh->ac_tail->authority_info.gns_authority),
	      rd_count);
  if (0 == rh->name_resolution_pos)
  {
    /* top-level match, are we done yet? */
    if ( (rd_count > 0) &&
	 (GNUNET_DNSPARSER_TYPE_CNAME == rd[0].record_type) &&
	 (GNUNET_DNSPARSER_TYPE_CNAME != rh->record_type) )
    {
      off = 0;
      cname = GNUNET_DNSPARSER_parse_name (rd[0].data,
					   rd[0].data_size,
					   &off);
      if ( (NULL == cname) ||
	   (off != rd[0].data_size) )
      {
	GNUNET_break_op (0);
	rh->proc (rh->proc_cls, 0, NULL);
	GNS_resolver_lookup_cancel (rh);
        GNUNET_free_non_null (cname);
	return;
      }
      handle_gns_cname_result (rh,
			       cname);
      GNUNET_free (cname);
      return;
    }
    /* If A/AAAA was requested, but we got a VPN
       record, we convert it to A/AAAA using GNUnet VPN */
    if ( (GNUNET_DNSPARSER_TYPE_A == rh->record_type) ||
	 (GNUNET_DNSPARSER_TYPE_AAAA == rh->record_type) )
    {
      for (i=0;i<rd_count;i++)
      {
	switch (rd[i].record_type)
	{
	case GNUNET_GNSRECORD_TYPE_VPN:
	  {
	    af = (GNUNET_DNSPARSER_TYPE_A == rh->record_type) ? AF_INET : AF_INET6;
	    if (sizeof (struct GNUNET_TUN_GnsVpnRecord) >
		rd[i].data_size)
	    {
	      GNUNET_break_op (0);
	      rh->proc (rh->proc_cls, 0, NULL);
	      GNS_resolver_lookup_cancel (rh);
	      return;
	    }
	    vpn = (const struct GNUNET_TUN_GnsVpnRecord *) rd[i].data;
	    vname = (const char *) &vpn[1];
	    if ('\0' != vname[rd[i].data_size - 1 - sizeof (struct GNUNET_TUN_GnsVpnRecord)])
	    {
	      GNUNET_break_op (0);
	      rh->proc (rh->proc_cls, 0, NULL);
	      GNS_resolver_lookup_cancel (rh);
	      return;
	    }
	    GNUNET_TUN_service_name_to_hash (vname,
                                             &vhash);
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Attempting VPN allocation for %s-%s (AF: %d, proto %d)\n",
                        GNUNET_i2s (&vpn->peer),
                        vname,
                        (int) af,
                        (int) ntohs (vpn->proto));
	    vpn_ctx = GNUNET_new (struct VpnContext);
	    rh->vpn_ctx = vpn_ctx;
	    vpn_ctx->rh = rh;
	    vpn_ctx->rd_data_size = GNUNET_GNSRECORD_records_get_size (rd_count,
								       rd);
	    vpn_ctx->rd_data = GNUNET_malloc (vpn_ctx->rd_data_size);
            vpn_ctx->rd_count = rd_count;
	    GNUNET_assert (vpn_ctx->rd_data_size ==
                           GNUNET_GNSRECORD_records_serialize (rd_count,
                                                               rd,
                                                               vpn_ctx->rd_data_size,
                                                               vpn_ctx->rd_data));
	    vpn_ctx->vpn_request = GNUNET_VPN_redirect_to_peer (vpn_handle,
								af,
								ntohs (vpn->proto),
								&vpn->peer,
								&vhash,
								GNUNET_TIME_relative_to_absolute (VPN_TIMEOUT),
								&vpn_allocation_cb,
								vpn_ctx);
	    return;
	  }
	case GNUNET_GNSRECORD_TYPE_GNS2DNS:
	  {
	    /* delegation to DNS */
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Found GNS2DNS record, delegating to DNS!\n");
	    goto do_recurse;
	  }
	default:
	  break;
	} /* end: switch */
      } /* end: for rd */
    } /* end: name_resolution_pos */
    /* convert relative names in record values to absolute names,
       using 'scratch' array for memory allocations */
    scratch_off = 0;
    rd_off = 0;
    shorten_ac = rh->ac_tail;
    for (i=0;i<rd_count;i++)
    {
      if ( (0 != rh->protocol) &&
           (0 != rh->service) &&
           (GNUNET_GNSRECORD_TYPE_BOX != rd[i].record_type) )
        continue; /* we _only_ care about boxed records */

      rd_new[rd_off] = rd[i];
      /* Check if the embedded name(s) end in "+", and if so,
	 replace the "+" with the zone at "ac_tail", changing the name
	 to a ".zkey".  The name is allocated on the 'scratch' array,
	 so we can free it afterwards. */
      switch (rd[i].record_type)
      {
      case GNUNET_DNSPARSER_TYPE_CNAME:
	{
	  char *cname;

	  off = 0;
	  cname = GNUNET_DNSPARSER_parse_name (rd[i].data,
					       rd[i].data_size,
					       &off);
	  if ( (NULL == cname) ||
	       (off != rd[i].data_size) )
	  {
	    GNUNET_break_op (0); /* record not well-formed */
	  }
	  else
	  {
	    cname = translate_dot_plus (rh, cname);
            GNUNET_break (NULL != cname);
	    scratch_start = scratch_off;
	    if (GNUNET_OK !=
		GNUNET_DNSPARSER_builder_add_name (scratch,
						   sizeof (scratch),
						   &scratch_off,
						   cname))
	    {
	      GNUNET_break (0);
	    }
	    else
	    {
	      rd_new[rd_off].data = &scratch[scratch_start];
	      rd_new[rd_off].data_size = scratch_off - scratch_start;
	      rd_off++;
	    }
	  }
	  GNUNET_free_non_null (cname);
	}
	break;
      case GNUNET_DNSPARSER_TYPE_SOA:
	{
	  struct GNUNET_DNSPARSER_SoaRecord *soa;

	  off = 0;
	  soa = GNUNET_DNSPARSER_parse_soa (rd[i].data,
					    rd[i].data_size,
					    &off);
	  if ( (NULL == soa) ||
	       (off != rd[i].data_size) )
	  {
	    GNUNET_break_op (0); /* record not well-formed */
	  }
	  else
	  {
	    soa->mname = translate_dot_plus (rh, soa->mname);
	    soa->rname = translate_dot_plus (rh, soa->rname);
	    scratch_start = scratch_off;
	    if (GNUNET_OK !=
		GNUNET_DNSPARSER_builder_add_soa (scratch,
						  sizeof (scratch),
						  &scratch_off,
						  soa))
	    {
	      GNUNET_break (0);
	    }
	    else
	    {
	      rd_new[rd_off].data = &scratch[scratch_start];
	      rd_new[rd_off].data_size = scratch_off - scratch_start;
	      rd_off++;
	    }
	  }
	  if (NULL != soa)
	    GNUNET_DNSPARSER_free_soa (soa);
	}
	break;
      case GNUNET_DNSPARSER_TYPE_MX:
	{
	  struct GNUNET_DNSPARSER_MxRecord *mx;

	  off = 0;
	  mx = GNUNET_DNSPARSER_parse_mx (rd[i].data,
					  rd[i].data_size,
					  &off);
	  if ( (NULL == mx) ||
	       (off != rd[i].data_size) )
	  {
	    GNUNET_break_op (0); /* record not well-formed */
	  }
	  else
	  {
	    mx->mxhost = translate_dot_plus (rh, mx->mxhost);
	    scratch_start = scratch_off;
	    if (GNUNET_OK !=
		GNUNET_DNSPARSER_builder_add_mx (scratch,
						 sizeof (scratch),
						 &scratch_off,
						 mx))
	    {
	      GNUNET_break (0);
	    }
	    else
	    {
	      rd_new[rd_off].data = &scratch[scratch_start];
	      rd_new[rd_off].data_size = scratch_off - scratch_start;
	      rd_off++;
	    }
	  }
	  if (NULL != mx)
	    GNUNET_DNSPARSER_free_mx (mx);
	}
	break;
      case GNUNET_DNSPARSER_TYPE_SRV:
	{
	  struct GNUNET_DNSPARSER_SrvRecord *srv;

	  off = 0;
	  srv = GNUNET_DNSPARSER_parse_srv (rd[i].data,
					    rd[i].data_size,
					    &off);
	  if ( (NULL == srv) ||
	       (off != rd[i].data_size) )
	  {
	    GNUNET_break_op (0); /* record not well-formed */
	  }
	  else
	  {
	    srv->target = translate_dot_plus (rh, srv->target);
	    scratch_start = scratch_off;
	    if (GNUNET_OK !=
		GNUNET_DNSPARSER_builder_add_srv (scratch,
						  sizeof (scratch),
						  &scratch_off,
						  srv))
	    {
	      GNUNET_break (0);
	    }
	    else
	    {
	      rd_new[rd_off].data = &scratch[scratch_start];
	      rd_new[rd_off].data_size = scratch_off - scratch_start;
	      rd_off++;
	    }
	  }
	  if (NULL != srv)
	    GNUNET_DNSPARSER_free_srv (srv);
	}
	break;

      case GNUNET_GNSRECORD_TYPE_NICK:
        {
          const char *nick;

          nick = rd[i].data;
          if ((rd[i].data_size > 0) &&
              (nick[rd[i].data_size -1] != '\0'))
          {
            GNUNET_break_op (0);
            break;
          }
          if (NULL == shorten_ac->suggested_shortening_label)
            shorten_ac->suggested_shortening_label = GNUNET_strdup (nick);
          break;
        }
      case GNUNET_GNSRECORD_TYPE_PKEY:
        {
	  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

	  if (rd[i].data_size != sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))
	  {
	    GNUNET_break_op (0);
	    break;
	  }
	  memcpy (&pub, rd[i].data, rd[i].data_size);
          rd_off++;
          if (GNUNET_GNSRECORD_TYPE_PKEY != rh->record_type)
          {
            /* try to resolve "+" */
            struct AuthorityChain *ac;

            ac = GNUNET_new (struct AuthorityChain);
            ac->rh = rh;
            ac->gns_authority = GNUNET_YES;
            ac->authority_info.gns_authority = pub;
            ac->label = GNUNET_strdup (GNUNET_GNS_MASTERZONE_STR);
            ac->suggested_shortening_label = NULL;
            ac->shortening_started = GNUNET_NO;
            GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                              rh->ac_tail,
                                              ac);
            rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                                    rh);
            return;
          }
        }
	break;
      case GNUNET_GNSRECORD_TYPE_GNS2DNS:
        {
          /* delegation to DNS */
          if (GNUNET_GNSRECORD_TYPE_GNS2DNS == rh->record_type)
          {
            rd_off++;
            break; /* do not follow to DNS, we wanted the GNS2DNS record! */
          }
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Found GNS2DNS record, delegating to DNS!\n");
          goto do_recurse;
        }
      case GNUNET_GNSRECORD_TYPE_BOX:
        {
          /* unbox SRV/TLSA records if a specific one was requested */
          if ( (0 != rh->protocol) &&
               (0 != rh->service) &&
               (rd[i].data_size >= sizeof (struct GNUNET_GNSRECORD_BoxRecord)) )
          {
            const struct GNUNET_GNSRECORD_BoxRecord *box;

            box = rd[i].data;
            if ( (ntohs (box->protocol) == rh->protocol) &&
                 (ntohs (box->service) == rh->service) )
            {
              /* Box matches, unbox! */
              rd_new[rd_off].record_type = ntohl (box->record_type);
              rd_new[rd_off].data_size -= sizeof (struct GNUNET_GNSRECORD_BoxRecord);
              rd_new[rd_off].data = &box[1];
              rd_off++;
            }
          }
          else
          {
            /* no specific protocol/service specified, preserve all BOX
               records (for modern, GNS-enabled applications) */
            rd_off++;
          }
        }
      default:
	rd_off++;
	break;
      } /* end: switch */
    } /* end: for rd_count */

    /* trigger shortening */
    if ((NULL != rh->shorten_key) &&
        (NULL != shorten_ac) &&
        (GNUNET_NO == shorten_ac->shortening_started) &&
        (NULL != shorten_ac->suggested_shortening_label))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Start shortening for label `%s' based on nick `%s'\n",
                    shorten_ac->label,
                    shorten_ac->suggested_shortening_label);
        shorten_ac->shortening_started = GNUNET_YES;
        GNS_shorten_start (shorten_ac->label,
                         shorten_ac->suggested_shortening_label,
                         &shorten_ac->authority_info.gns_authority,
                         rh->shorten_key);
    }

    /* yes, we are done, return result */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning GNS response for `%s' with %u answers\n",
                rh->ac_tail->label,
                rd_off);
    rh->proc (rh->proc_cls, rd_off, rd_new);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
 do_recurse:
  /* need to recurse, check if we can */
  for (i=0;i<rd_count;i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_GNSRECORD_TYPE_PKEY:
      /* delegation to another zone */
      if (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) !=
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
      ac->suggested_shortening_label = NULL;
      ac->shortening_started = GNUNET_NO;
      memcpy (&ac->authority_info.gns_authority,
	      rd[i].data,
	      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
      ac->label = resolver_lookup_get_next_label (rh);
      /* add AC to tail */
      GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
					rh->ac_tail,
					ac);
      /* recurse */
      rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
					      rh);
      return;
    case GNUNET_GNSRECORD_TYPE_GNS2DNS:
      {
	/* resolution continues within DNS */
        struct Gns2DnsContext *g2dc;
        char *ip;
        char *ns;

        off = 0;
        ns = GNUNET_DNSPARSER_parse_name (rd[i].data,
                                          rd[i].data_size,
                                          &off);
        ip = GNUNET_DNSPARSER_parse_name (rd[i].data,
                                          rd[i].data_size,
                                          &off);
        if ( (NULL == ns) ||
             (NULL == ip) ||
             (off != rd[i].data_size) )
        {
          GNUNET_break_op (0);
          GNUNET_free_non_null (ns);
          GNUNET_free_non_null (ip);
	  rh->proc (rh->proc_cls, 0, NULL);
	  GNS_resolver_lookup_cancel (rh);
          return;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Resolving `%s' to determine IP address of DNS server for GNS2DNS transition\n",
                    ip);
        /* resolve 'ip' to determine the IP(s) of the DNS
           resolver to use */
        g2dc = GNUNET_new (struct Gns2DnsContext);
        g2dc->ns = ns;

        g2dc->rh = GNUNET_new (struct GNS_ResolverHandle);
        g2dc->rh->authority_zone = rh->ac_tail->authority_info.gns_authority;
        ip = translate_dot_plus (rh, ip);
        g2dc->rh->name = ip;
        g2dc->rh->name_resolution_pos = strlen (ip);
        g2dc->rh->proc = &handle_gns2dns_result;
        g2dc->rh->proc_cls = rh;
        g2dc->rh->record_type = GNUNET_GNSRECORD_TYPE_ANY;
        g2dc->rh->options = GNUNET_GNS_LO_DEFAULT;
        g2dc->rh->loop_limiter = rh->loop_limiter + 1;
        rh->g2dc = g2dc;
        start_resolver_lookup (g2dc->rh);
	return;
      }
    case GNUNET_DNSPARSER_TYPE_CNAME:
      {
	char *cname;

	off = 0;
	cname = GNUNET_DNSPARSER_parse_name (rd[i].data,
					     rd[i].data_size,
					     &off);
	if ( (NULL == cname) ||
	     (off != rd[i].data_size) )
	{
	  GNUNET_break_op (0); /* record not well-formed */
	  rh->proc (rh->proc_cls, 0, NULL);
	  GNS_resolver_lookup_cancel (rh);
	  GNUNET_free_non_null (cname);
	  return;
	}
	handle_gns_cname_result (rh,
				 cname);
	GNUNET_free (cname);
	return;
      }
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
 * @param cls closure with the `struct CacheOps`
 * @param success #GNUNET_OK on success
 * @param emsg error message
 */
static void
namecache_cache_continuation (void *cls,
			      int32_t success,
			      const char *emsg)
{
  struct CacheOps *co = cls;

  co->namecache_qe_cache = NULL;
  if (NULL != emsg)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to cache GNS resolution: %s\n"),
		emsg);
  GNUNET_CONTAINER_DLL_remove (co_head,
			       co_tail,
			       co);
  GNUNET_free (co);
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
handle_dht_response (void *cls,
		     struct GNUNET_TIME_Absolute exp,
		     const struct GNUNET_HashCode *key,
		     const struct GNUNET_PeerIdentity *get_path,
		     unsigned int get_path_length,
		     const struct GNUNET_PeerIdentity *put_path,
		     unsigned int put_path_length,
		     enum GNUNET_BLOCK_Type type,
		     size_t size, const void *data)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;
  const struct GNUNET_GNSRECORD_Block *block;
  struct CacheOps *co;

  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  GNUNET_CONTAINER_heap_remove_node (rh->dht_heap_node);
  rh->dht_heap_node = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Handling response from the DHT\n");
  if (size < sizeof (struct GNUNET_GNSRECORD_Block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  block = data;
  if (size !=
      ntohl (block->purpose.size) +
      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
      sizeof (struct GNUNET_CRYPTO_EcdsaSignature))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_decrypt (block,
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
  if (0 == GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh (block->expiration_time)).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received expired block from the DHT, will not cache it.\n");
    return;
  }
  /* Cache well-formed blocks */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Caching response from the DHT in namecache\n");
  co = GNUNET_new (struct CacheOps);
  co->namecache_qe_cache = GNUNET_NAMECACHE_block_cache (namecache_handle,
							 block,
							 &namecache_cache_continuation,
							 co);
  GNUNET_CONTAINER_DLL_insert (co_head,
			       co_tail,
			       co);
}


/**
 * Initiate a DHT query for a set of GNS records.
 *
 * @param rh resolution handle
 * @param query key to use in the DHT lookup
 */
static void
start_dht_request (struct GNS_ResolverHandle *rh,
                   const struct GNUNET_HashCode *query)
{
  struct GNS_ResolverHandle *rx;

  GNUNET_assert (NULL == rh->get_handle);
  rh->get_handle = GNUNET_DHT_get_start (dht_handle,
                                         GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                                         query,
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
    GNUNET_assert (NULL != rx);
    rx->proc (rx->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rx);
  }
}


/**
 * Process a records that were decrypted from a block that we got from
 * the namecache.  Simply calls #handle_gns_resolution_result().
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
handle_gns_namecache_resolution_result (void *cls,
                                        unsigned int rd_count,
                                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ResolverHandle *rh = cls;

  handle_gns_resolution_result (rh,
                                rd_count,
                                rd);
}


/**
 * Process a record that was stored in the namecache.
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param block block that was stored in the namecache
 */
static void
handle_namecache_block_response (void *cls,
				 const struct GNUNET_GNSRECORD_Block *block)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;
  const char *label = ac->label;
  const struct GNUNET_CRYPTO_EcdsaPublicKey *auth = &ac->authority_info.gns_authority;
  struct GNUNET_HashCode query;

  GNUNET_assert (NULL != rh->namecache_qe);
  rh->namecache_qe = NULL;
  if ( ( (GNUNET_GNS_LO_DEFAULT == rh->options) ||
	 ( (GNUNET_GNS_LO_LOCAL_MASTER == rh->options) &&
	   (ac != rh->ac_head) ) ) &&
       ( (NULL == block) ||
	 (0 == GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh (block->expiration_time)).rel_value_us) ) )
  {
    /* namecache knows nothing; try DHT lookup */
    GNUNET_GNSRECORD_query_from_public_key (auth,
                                            label,
                                            &query);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting DHT lookup for `%s' in zone `%s' under key `%s'\n",
                ac->label,
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority),
                GNUNET_h2s (&query));
    start_dht_request (rh, &query);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received result from namecache for label `%s'\n",
              ac->label);

  if ( (NULL == block) ||
       (0 == GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh (block->expiration_time)).rel_value_us) )
  {
    /* DHT not permitted and no local result, fail */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Resolution failed for `%s' in zone %s (DHT lookup not permitted by configuration)\n",
		ac->label,
		GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_decrypt (block,
				      auth,
				      label,
				      &handle_gns_namecache_resolution_result,
				      rh))
  {
    GNUNET_break_op (0); /* block was ill-formed */
    /* try DHT instead */
    GNUNET_GNSRECORD_query_from_public_key (auth,
                                            label,
                                            &query);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting DHT lookup for `%s' in zone `%s' under key `%s'\n",
                ac->label,
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority),
                GNUNET_h2s (&query));
    start_dht_request (rh, &query);
    return;
  }
}


/**
 * Lookup tail of our authority chain in the namecache.
 *
 * @param rh query we are processing
 */
static void
recursive_gns_resolution_namecache (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac = rh->ac_tail;
  struct GNUNET_HashCode query;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting GNS resolution for `%s' in zone %s\n",
	      ac->label,
	      GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
  GNUNET_GNSRECORD_query_from_public_key (&ac->authority_info.gns_authority,
					  ac->label,
					  &query);
  if (GNUNET_YES == use_cache)
  {
    rh->namecache_qe
      = GNUNET_NAMECACHE_lookup_block (namecache_handle,
                                       &query,
                                       &handle_namecache_block_response,
                                       rh);
    GNUNET_assert (NULL != rh->namecache_qe);
  }
  else
  {
    start_dht_request (rh, &query);
  }
}


/**
 * Function called with the result from a revocation check.
 *
 * @param cls the `struct GNS_ResovlerHandle`
 * @param is_valid #GNUNET_YES if the zone was not yet revoked
 */
static void
handle_revocation_result (void *cls,
                          int is_valid)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;

  rh->rev_check = NULL;
  if (GNUNET_YES != is_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Zone %s was revoked, resolution fails\n"),
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  recursive_gns_resolution_namecache (rh);
}


/**
 * Perform revocation check on tail of our authority chain.
 *
 * @param rh query we are processing
 */
static void
recursive_gns_resolution_revocation (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac = rh->ac_tail;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting revocation check for zone %s\n",
	      GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
  rh->rev_check = GNUNET_REVOCATION_query (cfg,
                                           &ac->authority_info.gns_authority,
                                           &handle_revocation_result,
                                           rh);
  GNUNET_assert (NULL != rh->rev_check);
}


/**
 * Task scheduled to continue with the resolution process.
 *
 * @param cls the `struct GNS_ResolverHandle` of the resolution
 * @param tc task context
 */
static void
recursive_resolution (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = NULL;
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
    recursive_gns_resolution_revocation (rh);
  else
    recursive_dns_resolution (rh);
}


/**
 * Begin the resolution process from 'name', starting with
 * the identification of the zone specified by 'name'.
 *
 * @param rh resolution to perform
 */
static void
start_resolver_lookup (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac;
  char *y;
  struct in_addr v4;
  struct in6_addr v6;

  if (1 == inet_pton (AF_INET,
                      rh->name,
                      &v4))
  {
    /* name is IPv4 address, pretend it's an A record */
    struct GNUNET_GNSRECORD_Data rd;

    rd.data = &v4;
    rd.data_size = sizeof (v4);
    rd.expiration_time = UINT64_MAX;
    rd.record_type = GNUNET_DNSPARSER_TYPE_A;
    rd.flags = 0;
    rh->proc (rh->proc_cls, 1, &rd);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  if (1 == inet_pton (AF_INET6,
                      rh->name,
                      &v6))
  {
    /* name is IPv6 address, pretend it's an AAAA record */
    struct GNUNET_GNSRECORD_Data rd;

    rd.data = &v6;
    rd.data_size = sizeof (v6);
    rd.expiration_time = UINT64_MAX;
    rd.record_type = GNUNET_DNSPARSER_TYPE_AAAA;
    rd.flags = 0;
    rh->proc (rh->proc_cls, 1, &rd);
    GNS_resolver_lookup_cancel (rh);
    return;
  }
  if ( ( (GNUNET_YES == is_canonical (rh->name)) &&
	 (0 != strcmp (GNUNET_GNS_TLD, rh->name)) ) ||
       ( (GNUNET_YES != is_gnu_tld (rh->name)) &&
	 (GNUNET_YES != is_zkey_tld (rh->name)) ) )
  {
    /* use standard DNS lookup */
    int af;

    switch (rh->record_type)
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Doing standard DNS lookup for `%s'\n",
		rh->name);
    rh->std_resolve = GNUNET_RESOLVER_ip_get (rh->name,
					      af,
					      DNS_LOOKUP_TIMEOUT,
					      &handle_dns_result,
					      rh);
    return;
  }
  if (is_zkey_tld (rh->name))
  {
    /* Name ends with ".zkey", try to replace authority zone with zkey
       authority */
    GNUNET_free (resolver_lookup_get_next_label (rh)); /* will return "zkey" */
    y = resolver_lookup_get_next_label (rh); /* will return 'y' coordinate */
    if ( (NULL == y) ||
	 (GNUNET_OK !=
	  GNUNET_CRYPTO_ecdsa_public_key_from_string (y,
                                                      strlen (y),
                                                      &rh->authority_zone)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Hostname `%s' is not well-formed, resolution fails\n"),
		  rh->name);
      rh->task_id = GNUNET_SCHEDULER_add_now (&fail_resolution, rh);
    }
    GNUNET_free_non_null (y);
  }
  else
  {
    /* Name ends with ".gnu", eat ".gnu" and continue with resolution */
    GNUNET_free (resolver_lookup_get_next_label (rh));
  }
  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  ac->label = resolver_lookup_get_next_label (rh);
  ac->suggested_shortening_label = NULL;
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
}


/**
 * Lookup of a record in a specific zone calls lookup result processor
 * on result.
 *
 * @param zone the zone to perform the lookup in
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param shorten_key a private key for use with PSEU import (can be NULL)
 * @param options local options to control local lookup
 * @param proc the processor to call on result
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ResolverHandle *
GNS_resolver_lookup (const struct GNUNET_CRYPTO_EcdsaPublicKey *zone,
		     uint32_t record_type,
		     const char *name,
		     const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_key,
		     enum GNUNET_GNS_LocalOptions options,
		     GNS_ResultProcessor proc, void *proc_cls)
{
  struct GNS_ResolverHandle *rh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      (NULL == shorten_key)
	      ? "Starting lookup for `%s' with shortening disabled\n"
	      : "Starting lookup for `%s' with shortening enabled\n",
	      name);
  rh = GNUNET_new (struct GNS_ResolverHandle);
  GNUNET_CONTAINER_DLL_insert (rlh_head,
			       rlh_tail,
			       rh);
  rh->authority_zone = *zone;
  rh->proc = proc;
  rh->proc_cls = proc_cls;
  rh->options = options;
  rh->record_type = record_type;
  rh->name = GNUNET_strdup (name);
  rh->name_resolution_pos = strlen (name);
  if (NULL != shorten_key)
  {
    rh->shorten_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
    *rh->shorten_key = *shorten_key;
  }
  start_resolver_lookup (rh);
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
  struct VpnContext *vpn_ctx;

  GNUNET_CONTAINER_DLL_remove (rlh_head,
			       rlh_tail,
			       rh);
  while (NULL != (ac = rh->ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->ac_head,
				 rh->ac_tail,
				 ac);
    GNUNET_free (ac->label);
    GNUNET_free_non_null (ac->suggested_shortening_label);
    GNUNET_free (ac);
  }
  if (NULL != rh->g2dc)
  {
    /* rh->g2dc->rh is NOT in the DLL yet, so to enable us
       using GNS_resolver_lookup_cancel here, we need to
       add it first... */
    if (NULL != rh->g2dc->rh)
    {
      GNUNET_CONTAINER_DLL_insert (rlh_head,
                                   rlh_tail,
                                   rh->g2dc->rh);
      GNS_resolver_lookup_cancel (rh->g2dc->rh);
      rh->g2dc->rh = NULL;
    }
    GNUNET_free (rh->g2dc->ns);
    GNUNET_free (rh->g2dc);
    rh->g2dc = NULL;
  }
  if (NULL != rh->task_id)
  {
    GNUNET_SCHEDULER_cancel (rh->task_id);
    rh->task_id = NULL;
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
  if (NULL != (vpn_ctx = rh->vpn_ctx))
  {
    GNUNET_VPN_cancel_request (vpn_ctx->vpn_request);
    GNUNET_free (vpn_ctx->rd_data);
    GNUNET_free (vpn_ctx);
  }
  if (NULL != rh->dns_request)
  {
    GNUNET_DNSSTUB_resolve_cancel (rh->dns_request);
    rh->dns_request = NULL;
  }
  if (NULL != rh->namecache_qe)
  {
    GNUNET_NAMECACHE_cancel (rh->namecache_qe);
    rh->namecache_qe = NULL;
  }
  if (NULL != rh->rev_check)
  {
    GNUNET_REVOCATION_query_cancel (rh->rev_check);
    rh->rev_check = NULL;
  }
  if (NULL != rh->std_resolve)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Canceling standard DNS resolution\n");
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
 * @param nc the namecache handle
 * @param dht the dht handle
 * @param c configuration handle
 * @param max_bg_queries maximum number of parallel background queries in dht
 */
void
GNS_resolver_init (struct GNUNET_NAMECACHE_Handle *nc,
		   struct GNUNET_DHT_Handle *dht,
		   const struct GNUNET_CONFIGURATION_Handle *c,
		   unsigned long long max_bg_queries)
{
  char *dns_ip;

  cfg = c;
  namecache_handle = nc;
  dht_handle = dht;
  dht_lookup_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  max_allowed_background_queries = max_bg_queries;
  if (GNUNET_SYSERR == (use_cache = GNUNET_CONFIGURATION_get_value_yesno (c,
                                             "gns",
                                             "USE_CACHE")))
    use_cache = GNUNET_YES;
  if (GNUNET_NO == use_cache)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Namecache disabled\n");

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
  vpn_handle = GNUNET_VPN_connect (cfg);
}


/**
 * Shutdown resolver
 */
void
GNS_resolver_done ()
{
  struct GNS_ResolverHandle *rh;
  struct CacheOps *co;

  /* abort active resolutions */
  while (NULL != (rh = rlh_head))
  {
    rh->proc (rh->proc_cls, 0, NULL);
    GNS_resolver_lookup_cancel (rh);
  }
  while (NULL != (co = co_head))
  {
    GNUNET_CONTAINER_DLL_remove (co_head,
				 co_tail,
				 co);
    GNUNET_NAMECACHE_cancel (co->namecache_qe_cache);
    GNUNET_free (co);
  }
  GNUNET_CONTAINER_heap_destroy (dht_lookup_heap);
  dht_lookup_heap = NULL;
  GNUNET_DNSSTUB_stop (dns_handle);
  dns_handle = NULL;
  GNUNET_VPN_disconnect (vpn_handle);
  vpn_handle = NULL;
  dht_handle = NULL;
  namecache_handle = NULL;
}


/* *************** common helper functions (do not really belong here) *********** */

/**
 * Checks if @a name ends in ".TLD"
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
