/*
     This file is part of GNUnet.
     Copyright (C) 2007-2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file util/gnunet-service-resolver.c
 * @brief code to do DNS resolution
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "resolver.h"


/**
 * How long do we wait for DNS answers?
 */
#define DNS_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Maximum number of hostnames we cache results for.
 */
#define MAX_CACHE 1024

/**
 * Entry in list of cached DNS records for a hostname.
 */
struct RecordListEntry
{
  /**
   * This is a doubly linked list.
   */
  struct RecordListEntry *next;

  /**
   * This is a doubly linked list.
   */
  struct RecordListEntry *prev;

  /**
   * Cached data.
   */
  struct GNUNET_DNSPARSER_Record *record;
};


/**
 * A cached DNS lookup result.
 */
struct ResolveCache
{
  /**
   * This is a doubly linked list.
   */
  struct ResolveCache *next;

  /**
   * This is a doubly linked list.
   */
  struct ResolveCache *prev;

  /**
   * Which hostname is this cache for?
   */
  char *hostname;

  /**
   * head of a double linked list containing the lookup results
   */
  struct RecordListEntry *records_head;

  /**
   * tail of a double linked list containing the lookup results
   */
  struct RecordListEntry *records_tail;

};


/**
 * Information about pending lookups.
 */
struct ActiveLookup
{
  /**
   * Stored in a DLL.
   */
  struct ActiveLookup *next;

  /**
   * Stored in a DLL.
   */
  struct ActiveLookup *prev;

  /**
   * The client that queried the records contained in this cache entry.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * handle for cancelling a request
   */
  struct GNUNET_DNSSTUB_RequestSocket *resolve_handle;

  /**
   * handle for the resolution timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Which hostname are we resolving?
   */
  char *hostname;

  /**
   * type of queried DNS record
   */
  uint16_t record_type;

  /**
   * Unique request ID of a client if a query for this hostname/record_type
   * is currently pending, undefined otherwise.
   */
  uint16_t request_id;

  /**
   * Unique DNS request ID of a client if a query for this hostname/record_type
   * is currently pending, undefined otherwise.
   */
  uint16_t dns_id;

};


/**
 * Start of the linked list of cached DNS lookup results.
 */
static struct ResolveCache *cache_head;

/**
 * Tail of the linked list of cached DNS lookup results.
 */
static struct ResolveCache *cache_tail;

/**
 * Start of the linked list of active DNS lookups.
 */
static struct ActiveLookup *lookup_head;

/**
 * Tail of the linked list of active DNS lookups.
 */
static struct ActiveLookup *lookup_tail;

/**
 * context of dnsstub library
 */
static struct GNUNET_DNSSTUB_Context *dnsstub_ctx;

/**
 * How many entries do we have in #cache_head DLL?
 */
static unsigned int cache_size;

/**
 * Remove @a entry from cache.
 *
 * @param rc entry to free
 */
static void
free_cache_entry (struct ResolveCache *rc)
{
  struct RecordListEntry *pos;

  while (NULL != (pos = rc->records_head))
  {
    GNUNET_CONTAINER_DLL_remove (rc->records_head,
				 rc->records_tail,
		       		 pos);
    GNUNET_DNSPARSER_free_record (pos->record);
    GNUNET_free (pos->record);
    GNUNET_free (pos);
  }
  GNUNET_free_non_null (rc->hostname);
  GNUNET_CONTAINER_DLL_remove (cache_head,
                               cache_tail,
                               rc);
  cache_size--;
  GNUNET_free (rc);
}


/**
 * Release resources associated with @a al
 *
 * @param al an active lookup
 */
static void
free_active_lookup (struct ActiveLookup *al)
{
  GNUNET_CONTAINER_DLL_remove (lookup_head,
                               lookup_tail,
                               al);
  if (NULL != al->resolve_handle)
  {
    GNUNET_DNSSTUB_resolve_cancel (al->resolve_handle);
    al->resolve_handle = NULL;
  }
  if (NULL != al->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (al->timeout_task);
    al->timeout_task = NULL;
  }
  GNUNET_free_non_null (al->hostname);
  GNUNET_free (al);
}



/**
 * Find out if the configuration file line contains a string
 * starting with "nameserver ", and if so, return a copy of
 * the nameserver's IP.
 *
 * @param line line to parse
 * @param line_len number of characters in @a line
 * @return NULL if no nameserver is configured in this @a line
 */
static char *
extract_dns_server (const char* line,
                    size_t line_len)
{
  if (0 == strncmp (line,
                    "nameserver ",
                    strlen ("nameserver ")))
    return GNUNET_strndup (line + strlen ("nameserver "),
                           line_len - strlen ("nameserver "));
  return NULL;
}


/**
 * Reads the list of nameservers from /etc/resolve.conf
 *
 * @param server_addrs[out] a list of null-terminated server address strings
 * @return the number of server addresses in @server_addrs, -1 on error
 */
static int
lookup_dns_servers (char ***server_addrs)
{
  struct GNUNET_DISK_FileHandle *fh;
  char buf[2048];
  ssize_t bytes_read;
  size_t read_offset;
  unsigned int num_dns_servers;

  fh = GNUNET_DISK_file_open ("/etc/resolv.conf",
			      GNUNET_DISK_OPEN_READ,
			      GNUNET_DISK_PERM_NONE);
  if (NULL == fh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not open /etc/resolv.conf. "
		"DNS resolution will not be possible.\n");
    return -1;
  }
  bytes_read = GNUNET_DISK_file_read (fh,
				      buf,
				      sizeof (buf));
  *server_addrs = NULL;
  read_offset = 0;
  num_dns_servers = 0;
  while (read_offset < bytes_read)
  {
    const char *newline;
    size_t line_len;
    char *dns_server;

    newline = strchr (buf + read_offset,
                      '\n');
    if (NULL == newline)
      break;
    line_len = newline - buf - read_offset;
    dns_server = extract_dns_server (buf + read_offset,
                                     line_len);
    if (NULL != dns_server)
      GNUNET_array_append (*server_addrs,
			   num_dns_servers,
  			   dns_server);
    read_offset += line_len + 1;
  }
  GNUNET_DISK_file_close (fh);
  return (int) num_dns_servers;
}


/**
 * Compute name to use for DNS reverse lookups from @a ip.
 *
 * @param ip IP address to resolve, in binary format, network byte order
 * @param af address family of @a ip, AF_INET or AF_INET6
 */
static char *
make_reverse_hostname (const void *ip,
                       int af)
{
  char *buf = GNUNET_new_array (80,
                                char);
  int pos = 0;

  if (AF_INET == af)
  {
    struct in_addr *addr = (struct in_addr *)ip;
    uint32_t ip_int = addr->s_addr;

    for (int i = 3; i >= 0; i--)
    {
      int n = GNUNET_snprintf (buf + pos,
			       80 - pos,
			       "%u.",
			       ((uint8_t *)&ip_int)[i]);
      if (n < 0)
      {
	GNUNET_free (buf);
	return NULL;
      }
      pos += n;
    }
    pos += GNUNET_snprintf (buf + pos,
                            80 - pos,
                            "in-addr.arpa");
  }
  else if (AF_INET6 == af)
  {
    struct in6_addr *addr = (struct in6_addr *)ip;
    for (int i = 15; i >= 0; i--)
    {
      int n = GNUNET_snprintf (buf + pos,
                               80 - pos,
                               "%x.",
                               addr->s6_addr[i] & 0xf);
      if (n < 0)
      {
	GNUNET_free (buf);
	return NULL;
      }
      pos += n;
      n = GNUNET_snprintf (buf + pos,
                           80 - pos,
                           "%x.",
                           addr->s6_addr[i] >> 4);
      if (n < 0)
      {
	GNUNET_free (buf);
	return NULL;
      }
      pos += n;
    }
    pos += GNUNET_snprintf (buf + pos,
                            80 - pos,
                            "ip6.arpa");
  }
  buf[pos] = '\0';
  return buf;
}


/**
 * Send DNS @a record back to our @a client.
 *
 * @param record information to transmit
 * @param record_type requested record type from client
 * @param request_id to which request are we responding
 * @param client where to send @a record
 * @return #GNUNET_YES if we sent a reply,
 *         #GNUNET_NO if the record type is not understood or
 *         does not match @a record_type
 */
static int
send_reply (struct GNUNET_DNSPARSER_Record *record,
            uint16_t record_type,
	    uint16_t request_id,
	    struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_RESOLVER_ResponseMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  const void *payload;
  size_t payload_len;

  switch (record->type)
  {
  case GNUNET_DNSPARSER_TYPE_CNAME:
    if (GNUNET_DNSPARSER_TYPE_CNAME != record_type)
      return GNUNET_NO;
    payload = record->data.hostname;
    payload_len = strlen (record->data.hostname) + 1;
    break;
  case GNUNET_DNSPARSER_TYPE_PTR:
    if (GNUNET_DNSPARSER_TYPE_PTR != record_type)
      return GNUNET_NO;
    payload = record->data.hostname;
    payload_len = strlen (record->data.hostname) + 1;
    break;
  case GNUNET_DNSPARSER_TYPE_A:
    if ( (GNUNET_DNSPARSER_TYPE_A != record_type) &&
         (GNUNET_DNSPARSER_TYPE_ALL != record_type) )
      return GNUNET_NO;
    payload = record->data.raw.data;
    payload_len = record->data.raw.data_len;
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if ( (GNUNET_DNSPARSER_TYPE_AAAA != record_type) &&
         (GNUNET_DNSPARSER_TYPE_ALL != record_type) )
      return GNUNET_NO;
    payload = record->data.raw.data;
    payload_len = record->data.raw.data_len;
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cannot handle DNS response type %u: not supported here\n",
                record->type);
    return GNUNET_NO;
  }
  env = GNUNET_MQ_msg_extra (msg,
        		     payload_len,
        		     GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  msg->id = request_id;
  GNUNET_memcpy (&msg[1],
        	 payload,
        	 payload_len);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
        	  env);
  return GNUNET_YES;
}


/**
 * Send message to @a client that we transmitted all
 * responses for @a request_id
 *
 * @param request_id to which request are we responding
 * @param client where to send @a record
 */
static void
send_end_msg (uint16_t request_id,
	      struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_RESOLVER_ResponseMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending END message\n");
  env = GNUNET_MQ_msg (msg,
        	       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  msg->id = request_id;
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
        	  env);
}


/**
 * Remove expired entries from @a rc
 *
 * @param rc entry in resolver cache
 * @return #GNUNET_YES if @a rc was completely expired
 *         #GNUNET_NO if some entries are left
 */
static int
remove_expired (struct ResolveCache *rc)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct RecordListEntry *n;

  for (struct RecordListEntry *pos = rc->records_head;
       NULL != pos;
       pos = n)
  {
    n = pos->next;
    if (now.abs_value_us > pos->record->expiration_time.abs_value_us)
      GNUNET_CONTAINER_DLL_remove (rc->records_head,
                                   rc->records_tail,
                                   pos);
  }
  if (NULL == rc->records_head)
  {
    free_cache_entry (rc);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Process DNS request for @a hostname with request ID @a request_id
 * from @a client demanding records of type @a record_type.
 *
 * @param hostname DNS name to resolve
 * @param record_type desired record type
 * @param request_id client's request ID
 * @param client who should get the result?
 */
static void
process_get (const char *hostname,
	     uint16_t record_type,
	     uint16_t request_id,
	     struct GNUNET_SERVICE_Client *client);


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param hostname what hostname was to be resolved
 * @param record_type what type of record was requested
 * @param request_id unique identification of the client's request
 * @param client handle to the client making the request (for sending the reply)
 */
static int
try_cache (const char *hostname,
           uint16_t record_type,
	   uint16_t request_id,
	   struct GNUNET_SERVICE_Client *client)
{
  struct ResolveCache *pos;
  struct ResolveCache *next;
  int found;

  next = cache_head;
  for (pos = next; NULL != pos; pos = next)
  {
    next = pos->next;
    if (GNUNET_YES == remove_expired (pos))
      continue;
    if (0 == strcmp (pos->hostname,
                     hostname))
      break;
  }
  if (NULL == pos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No cache entry for '%s'\n",
                hostname);
    return GNUNET_NO;
  }
  if (cache_head != pos)
  {
    /* move result to head to achieve LRU for cache eviction */
    GNUNET_CONTAINER_DLL_remove (cache_head,
                                 cache_tail,
                                 pos);
    GNUNET_CONTAINER_DLL_insert (cache_head,
                                 cache_tail,
                                 pos);
  }
  found = GNUNET_NO;
  for (struct RecordListEntry *rle = pos->records_head;
       NULL != rle;
       rle = rle->next)
  {
    const struct GNUNET_DNSPARSER_Record *record = rle->record;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found cache entry for '%s', record type '%u'\n",
                hostname,
                record_type);
    if ( (GNUNET_DNSPARSER_TYPE_CNAME == record->type) &&
         (GNUNET_DNSPARSER_TYPE_CNAME != record_type) &&
         (GNUNET_NO == found) )
    {
      const char *hostname = record->data.hostname;

      process_get (hostname,
                   record_type,
                   request_id,
                   client);
      return GNUNET_YES; /* counts as a cache "hit" */
    }
    found |= send_reply (rle->record,
                         record_type,
                         request_id,
                         client);
  }
  if (GNUNET_NO == found)
    return GNUNET_NO; /* had records, but none matched! */
  send_end_msg (request_id,
                client);
  return GNUNET_YES;
}


/**
 * We got a result from DNS. Add it to the cache and
 * see if we can make our client happy...
 *
 * @param cls the `struct ActiveLookup`
 * @param dns the DNS response
 * @param dns_len number of bytes in @a dns
 */
static void
handle_resolve_result (void *cls,
		       const struct GNUNET_TUN_DnsHeader *dns,
                       size_t dns_len)
{
  struct ActiveLookup *al = cls;
  struct GNUNET_DNSPARSER_Packet *parsed;
  struct ResolveCache *rc;

  parsed = GNUNET_DNSPARSER_parse ((const char *)dns,
				   dns_len);
  if (NULL == parsed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to parse DNS reply (hostname %s, request ID %u)\n",
                al->hostname,
		al->dns_id);
    return;
  }
  if (al->dns_id != ntohs (parsed->id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Request ID in DNS reply does not match\n");
    GNUNET_DNSPARSER_free_packet (parsed);
    return;
  }
  if (0 == parsed->num_answers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS reply (hostname %s, request ID %u) contains no answers\n",
                al->hostname,
		al->request_id);
    GNUNET_DNSPARSER_free_packet (parsed);
    send_end_msg (al->request_id,
                  al->client);
    free_active_lookup (al);
    return;
  }
  /* LRU-based cache eviction: we remove from tail */
  while (cache_size > MAX_CACHE)
    free_cache_entry (cache_tail);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got reply for hostname %s and request ID %u\n",
              al->hostname,
              al->request_id);
  /* add to cache */
  for (unsigned int i = 0; i != parsed->num_answers; i++)
  {
    struct GNUNET_DNSPARSER_Record *record = &parsed->answers[i];
    struct RecordListEntry *rle;

    for (rc = cache_head; NULL != rc; rc = rc->next)
      if (0 == strcasecmp (rc->hostname,
                           record->name))
        break;
    if (NULL == rc)
    {
      rc = GNUNET_new (struct ResolveCache);
      rc->hostname = GNUNET_strdup (record->name);
      GNUNET_CONTAINER_DLL_insert (cache_head,
                                   cache_tail,
                                   rc);
      cache_size++;
    }
    /* TODO: ought to check first if we have this exact record
       already in the cache! */
    rle = GNUNET_new (struct RecordListEntry);
    rle->record = GNUNET_DNSPARSER_duplicate_record (record);
    GNUNET_CONTAINER_DLL_insert (rc->records_head,
                                 rc->records_tail,
                                 rle);
  }

  /* resume by trying again from cache */
  if (GNUNET_NO ==
      try_cache (al->hostname,
                 al->record_type,
                 al->request_id,
                 al->client))
    /* cache failed, tell client we could not get an answer */
    send_end_msg (al->request_id,
                  al->client);
  free_active_lookup (al);
  GNUNET_DNSPARSER_free_packet (parsed);
}


/**
 * We encountered a timeout trying to perform a
 * DNS lookup.
 *
 * @param cls a `struct ActiveLookup`
 */
static void
handle_resolve_timeout (void *cls)
{
  struct ActiveLookup *al = cls;

  al->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DNS lookup timeout!\n");
  send_end_msg (al->request_id,
                al->client);
  free_active_lookup (al);
}


/**
 * Initiate an active lookup, then cache the result and
 * try to then complete the resolution.
 *
 * @param hostname DNS name to resolve
 * @param record_type record type to locate
 * @param request_id client request ID
 * @param client handle to the client
 */
static int
resolve_and_cache (const char* hostname,
		   uint16_t record_type,
	 	   uint16_t request_id,
		   struct GNUNET_SERVICE_Client *client)
{
  char *packet_buf;
  size_t packet_size;
  struct GNUNET_DNSPARSER_Query query;
  struct GNUNET_DNSPARSER_Packet packet;
  struct ActiveLookup *al;
  uint16_t dns_id;

  dns_id =(uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
					       UINT16_MAX);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "resolve_and_cache\n");
  query.name = (char *)hostname;
  query.type = record_type;
  query.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;
  memset (&packet,
	  0,
	  sizeof (packet));
  packet.num_queries = 1;
  packet.queries = &query;
  packet.id = htons (dns_id);
  packet.flags.recursion_desired = 1;
  if (GNUNET_OK !=
      GNUNET_DNSPARSER_pack (&packet,
			     UINT16_MAX,
			     &packet_buf,
			     &packet_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to pack query for hostname `%s'\n",
                hostname);
    return GNUNET_SYSERR;

  }
  al = GNUNET_new (struct ActiveLookup);
  al->hostname = GNUNET_strdup (hostname);
  al->record_type = record_type;
  al->request_id = request_id;
  al->dns_id = dns_id;
  al->client = client;
  al->timeout_task = GNUNET_SCHEDULER_add_delayed (DNS_TIMEOUT,
                                                   &handle_resolve_timeout,
                                                   al);
  al->resolve_handle =
    GNUNET_DNSSTUB_resolve (dnsstub_ctx,
          		    packet_buf,
          		    packet_size,
          		    &handle_resolve_result,
          		    al);
  GNUNET_free (packet_buf);
  GNUNET_CONTAINER_DLL_insert (lookup_head,
			       lookup_tail,
			       al);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Resolving %s, request_id = %u, dns_id = %u\n",
	      hostname,
              (unsigned int) request_id,
	      (unsigned int) dns_id);
  return GNUNET_OK;
}


/**
 * Process DNS request for @a hostname with request ID @a request_id
 * from @a client demanding records of type @a record_type.
 *
 * @param hostname DNS name to resolve
 * @param record_type desired record type
 * @param request_id client's request ID
 * @param client who should get the result?
 */
static void
process_get (const char *hostname,
	     uint16_t record_type,
	     uint16_t request_id,
	     struct GNUNET_SERVICE_Client *client)
{
  if (GNUNET_NO ==
      try_cache (hostname,
                 record_type,
                 request_id,
                 client))
  {
    if (GNUNET_OK !=
        resolve_and_cache (hostname,
                           record_type,
                           request_id,
                           client))
    {
      send_end_msg (request_id,
                    client);
    }
  }
}


/**
 * Verify well-formedness of GET-message.
 *
 * @param cls closure, unused
 * @param get the actual message
 * @return #GNUNET_OK if @a get is well-formed
 */
static int
check_get (void *cls,
	   const struct GNUNET_RESOLVER_GetMessage *get)
{
  uint16_t size;
  int direction;
  int af;

  (void) cls;
  size = ntohs (get->header.size) - sizeof (*get);
  direction = ntohl (get->direction);
  if (GNUNET_NO == direction)
  {
    /* IP from hostname */
    const char *hostname;

    hostname = (const char *) &get[1];
    if (hostname[size - 1] != '\0')
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  af = ntohl (get->af);
  switch (af)
  {
  case AF_INET:
    if (size != sizeof (struct in_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;
  case AF_INET6:
    if (size != sizeof (struct in6_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle GET-message.
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_get (void *cls,
	    const struct GNUNET_RESOLVER_GetMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  int direction;
  int af;
  uint16_t request_id;
  char *hostname;

  direction = ntohl (msg->direction);
  af = ntohl (msg->af);
  request_id = ntohs (msg->id);
  if (GNUNET_NO == direction)
  {
    /* IP from hostname */
    hostname = GNUNET_strdup ((const char *) &msg[1]);
    switch (af)
    {
      case AF_UNSPEC:
      {
	process_get (hostname,
                     GNUNET_DNSPARSER_TYPE_ALL,
                     request_id,
                     client);
	break;
      }
      case AF_INET:
      {
	process_get (hostname,
                     GNUNET_DNSPARSER_TYPE_A,
                     request_id,
                     client);
        break;
      }
      case AF_INET6:
      {
	process_get (hostname,
                     GNUNET_DNSPARSER_TYPE_AAAA,
                     request_id,
                     client);
        break;
      }
      default:
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          	  "got invalid af: %d\n",
          	  af);
        GNUNET_assert (0);
      }
    }
  }
  else
  {
    /* hostname from IP */
    hostname = make_reverse_hostname (&msg[1],
                                      af);
    process_get (hostname,
                 GNUNET_DNSPARSER_TYPE_PTR,
                 request_id,
                 client);
  }
  GNUNET_free_non_null (hostname);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Service is shutting down, clean up.
 *
 * @param cls NULL, unused
 */
static void
shutdown_task (void *cls)
{
  (void) cls;

  while (NULL != lookup_head)
    free_active_lookup (lookup_head);
  while (NULL != cache_head)
    free_cache_entry (cache_head);
  GNUNET_DNSSTUB_stop (dnsstub_ctx);
}


/**
 * Service is starting, initialize everything.
 *
 * @param cls NULL, unused
 * @param cfg our configuration
 * @param sh service handle
 */
static void
init_cb (void *cls,
	 const struct GNUNET_CONFIGURATION_Handle *cfg,
	 struct GNUNET_SERVICE_Handle *sh)
{
  char **dns_servers;
  int num_dns_servers;

  (void) cfg;
  (void) sh;
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 cls);
  dnsstub_ctx = GNUNET_DNSSTUB_start (128);
  num_dns_servers = lookup_dns_servers (&dns_servers);
  if (0 >= num_dns_servers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	        _("No DNS server available. DNS resolution will not be possible.\n"));
  }
  for (int i = 0; i < num_dns_servers; i++)
  {
    int result = GNUNET_DNSSTUB_add_dns_ip (dnsstub_ctx, dns_servers[i]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	        "Adding DNS server '%s': %s\n",
		dns_servers[i],
		GNUNET_OK == result ? "success" : "failure");
    GNUNET_free (dns_servers[i]);
  }
  GNUNET_free_non_null (dns_servers);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service, unused
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
connect_cb (void *cls,
	    struct GNUNET_SERVICE_Client *c,
	    struct GNUNET_MQ_Handle *mq)
{
  (void) cls;
  (void) mq;

  return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
disconnect_cb (void *cls,
	       struct GNUNET_SERVICE_Client *c,
	       void *internal_cls)
{
  struct ActiveLookup *n;
  (void) cls;

  GNUNET_assert (c == internal_cls);
  n = lookup_head;
  for (struct ActiveLookup *al = n;
       NULL != al;
       al = n)
  {
    n = al->next;
    if (al->client == c)
      free_active_lookup (al);
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("resolver",
 GNUNET_SERVICE_OPTION_NONE,
 &init_cb,
 &connect_cb,
 &disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (get,
			GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST,
			struct GNUNET_RESOLVER_GetMessage,
			NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_RESOLVER_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-service-resolver.c */
