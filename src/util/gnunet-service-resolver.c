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


struct Record
{
  struct Record *next;

  struct Record *prev;

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
   * type of queried DNS record
   */
  uint16_t record_type;

  /**
   * a pointer to the request_id if a query for this hostname/record_type
   * is currently pending, NULL otherwise.
   */
  int16_t *request_id;

  struct GNUNET_SERVICE_Client *client;

  /**
   * head of a double linked list containing the lookup results
   */
  struct Record *records_head;

  /**
   * tail of a double linked list containing the lookup results
   */
  struct Record *records_tail;

  /**
   * handle for cancelling a request
   */
  struct GNUNET_DNSSTUB_RequestSocket *resolve_handle;

  /**
   * handle for the resolution timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

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
 * context of dnsstub library
 */
static struct GNUNET_DNSSTUB_Context *dnsstub_ctx;


void free_cache_entry (struct ResolveCache *entry)
{
  struct Record *pos;
  struct Record *next;
 
  next = entry->records_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    GNUNET_CONTAINER_DLL_remove (entry->records_head,
				 entry->records_tail,
		       		 pos);
    if (NULL != pos->record)
    {
      GNUNET_DNSPARSER_free_record (pos->record);
      GNUNET_free (pos->record);
    }
    GNUNET_free (pos);
  }
  if (NULL != entry->resolve_handle)
  {
    GNUNET_DNSSTUB_resolve_cancel (entry->resolve_handle);
    entry->resolve_handle = NULL;
  }
  if (NULL != entry->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (entry->timeout_task);
    entry->timeout_task = NULL;
  }
  GNUNET_free_non_null (entry->request_id);
  GNUNET_free (entry);
}


static char*
extract_dns_server (const char* line, size_t line_len)
{
  if (0 == strncmp (line, "nameserver ", 11))
    return GNUNET_strndup (line + 11, line_len - 11);
  return NULL;
}

 
/**
 * reads the list of nameservers from /etc/resolve.conf
 *
 * @param server_addrs[out] a list of null-terminated server address strings
 * @return the number of server addresses in @server_addrs, -1 on error
 */
static ssize_t
lookup_dns_servers (char ***server_addrs)
{
  struct GNUNET_DISK_FileHandle *fh;
  char buf[2048];
  ssize_t bytes_read;
  size_t read_offset = 0;
  unsigned int num_dns_servers = 0;
    
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
  while (read_offset < bytes_read)
  {
    char *newline;
    size_t line_len;
    char *dns_server;
    
    newline = strchr (buf + read_offset, '\n');
    if (NULL == newline)
    {
      break;
    }
    line_len = newline - buf - read_offset;
    dns_server = extract_dns_server (buf + read_offset, line_len);
    if (NULL != dns_server)
    {
      GNUNET_array_append (*server_addrs,
			   num_dns_servers,
  			   dns_server);
    }
    read_offset += line_len + 1;
  }
  GNUNET_DISK_file_close (fh);
  return num_dns_servers;
}


static char *
make_reverse_hostname (const void *ip, int af)
{
  char *buf = GNUNET_new_array (80, char);
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
    pos += GNUNET_snprintf (buf + pos, 80 - pos, "in-addr.arpa");
  }
  else if (AF_INET6 == af)
  {
    struct in6_addr *addr = (struct in6_addr *)ip;
    for (int i = 15; i >= 0; i--)
    {
      int n = GNUNET_snprintf (buf + pos, 80 - pos, "%x.", addr->s6_addr[i] & 0xf);
      if (n < 0)
      {
	GNUNET_free (buf);
	return NULL;
      }
      pos += n;
      n = GNUNET_snprintf (buf + pos, 80 - pos, "%x.", addr->s6_addr[i] >> 4);
      if (n < 0)
      {
	GNUNET_free (buf);
	return NULL;
      }
      pos += n;
    }
    pos += GNUNET_snprintf (buf + pos, 80 - pos, "ip6.arpa");
  }
  buf[pos] = '\0';
  return buf;
}


static void
send_reply (struct GNUNET_DNSPARSER_Record *record,
	    uint16_t request_id,
	    struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_RESOLVER_ResponseMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  void *payload;
  size_t payload_len;

  switch (record->type)
  {
    case GNUNET_DNSPARSER_TYPE_PTR:
    {
      char *hostname = record->data.hostname;
      payload = hostname;
      payload_len = strlen (hostname) + 1;
      break;
    }
    case GNUNET_DNSPARSER_TYPE_A:
    case GNUNET_DNSPARSER_TYPE_AAAA:
    {
      payload = record->data.raw.data;
      payload_len = record->data.raw.data_len;
      break;         
    }
    default:
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Cannot handle DNS response type: unimplemented\n");
      return;
    }
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
}


static void
send_end_msg (uint16_t request_id,
	      struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_RESOLVER_ResponseMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending end message\n");
  env = GNUNET_MQ_msg (msg,
        	       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  msg->id = request_id;
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
        	  env);
}


static void
handle_resolve_result (void *cls,
		       const struct GNUNET_TUN_DnsHeader *dns,
                       size_t dns_len)
{
  struct ResolveCache *cache = cls;
  struct GNUNET_DNSPARSER_Packet *parsed;
  uint16_t request_id = *cache->request_id;
  struct GNUNET_SERVICE_Client *client = cache->client;

  parsed = GNUNET_DNSPARSER_parse ((const char *)dns,
				   dns_len);
  if (NULL == parsed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to parse DNS reply (request ID %u\n",
		request_id);
    return;
  }
  if (request_id != ntohs (parsed->id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Request ID in DNS reply does not match\n");
    return;
  }
  else if (0 == parsed->num_answers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS reply (request ID %u) contains no answers\n",
		request_id);
    GNUNET_CONTAINER_DLL_remove (cache_head,
				 cache_tail,
		       		 cache);
    free_cache_entry (cache);
    cache = NULL;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Got reply for request ID %u\n",
		request_id);
    for (unsigned int i = 0; i != parsed->num_answers; i++)
    {
      struct Record *cache_entry = GNUNET_new (struct Record);
      struct GNUNET_DNSPARSER_Record *record = &parsed->answers[i];
      cache_entry->record = GNUNET_DNSPARSER_duplicate_record (record);
      GNUNET_CONTAINER_DLL_insert (cache->records_head,
          			   cache->records_tail,
          			   cache_entry);
      send_reply (cache_entry->record,
		  request_id,
          	  cache->client);
    }
    GNUNET_free_non_null (cache->request_id);
    cache->request_id = NULL;
  }
  send_end_msg (request_id,
		client);
  if (NULL != cache)
    cache->client = NULL;
  GNUNET_SCHEDULER_cancel (cache->timeout_task);
  GNUNET_DNSSTUB_resolve_cancel (cache->resolve_handle);
  cache->timeout_task = NULL;
  cache->resolve_handle = NULL;
  GNUNET_DNSPARSER_free_packet (parsed);
}


static void
handle_resolve_timeout (void *cls)
{
  struct ResolveCache *cache = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "timeout!\n");
  if (NULL != cache->resolve_handle)
  {
    GNUNET_DNSSTUB_resolve_cancel (cache->resolve_handle);
    cache->resolve_handle = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (cache_head,
			       cache_tail,
			       cache);
  free_cache_entry (cache);
}


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
  struct ResolveCache *cache;
  struct GNUNET_TIME_Relative timeout =
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);

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
  packet.id = htons (request_id);
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
  cache = GNUNET_malloc (sizeof (struct ResolveCache));
  cache->record_type = record_type;
  cache->request_id = GNUNET_memdup (&request_id, sizeof (request_id));
  cache->client = client;
  cache->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout,
						      &handle_resolve_timeout,
						      cache);
  cache->resolve_handle = 
    GNUNET_DNSSTUB_resolve (dnsstub_ctx,
          		    packet_buf,
          		    packet_size,
          		    &handle_resolve_result,
          		    cache);
  GNUNET_CONTAINER_DLL_insert (cache_head,
			       cache_tail,
			       cache);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "resolve %s, request_id = %u\n",
	      hostname,
	      request_id);
  GNUNET_free (packet_buf);
  return GNUNET_OK;
}


static const char *
get_hostname (struct ResolveCache *cache_entry)
{
  if (NULL != cache_entry->records_head)
  {
    GNUNET_assert (NULL != cache_entry->records_head);
    GNUNET_assert (NULL != cache_entry->records_head->record);
    GNUNET_assert (NULL != cache_entry->records_head->record->name);
    return cache_entry->records_head->record->name;
  }
  return NULL;
}


static const uint16_t *
get_record_type (struct ResolveCache *cache_entry)
{
  if (NULL != cache_entry->records_head)
    return &cache_entry->record_type;
  return NULL; 
}


static const struct GNUNET_TIME_Absolute *
get_expiration_time (struct ResolveCache *cache_entry)
{
  if (NULL != cache_entry->records_head)
    return &cache_entry->records_head->record->expiration_time;
  return NULL;
}


static int
remove_if_expired (struct ResolveCache *cache_entry)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  if ( (NULL != cache_entry->records_head) &&
       (now.abs_value_us > get_expiration_time (cache_entry)->abs_value_us) )
  {
    GNUNET_CONTAINER_DLL_remove (cache_head,
				 cache_tail,
		       		 cache_entry);
    free_cache_entry (cache_entry);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param client handle to the client making the request (for sending the reply)
 * @param af AF_INET or AF_INET6
 * @param ip `struct in_addr` or `struct in6_addr`
 */
static int
try_cache (const char *hostname,
           uint16_t record_type,
	   uint16_t request_id,
	   struct GNUNET_SERVICE_Client *client)
{
  struct ResolveCache *pos;
  struct ResolveCache *next;

  next = cache_head;
  while ( (NULL != (pos = next)) &&
	  ( (NULL == pos->records_head) ||
	    (0 != strcmp (get_hostname (pos), hostname)) ||
	    (*get_record_type (pos) != record_type) ) )
  {
    next = pos->next;
    remove_if_expired (pos);
  }
  if (NULL != pos)
  {
    if (GNUNET_NO == remove_if_expired (pos))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  		  "found cache entry for '%s', record type '%u'\n",
  		  hostname,
		  record_type);
      struct Record *cache_pos = pos->records_head;
      while (NULL != cache_pos)
      {
	send_reply (cache_pos->record,
		    request_id,
		    client);
	cache_pos = cache_pos->next;
      }
      send_end_msg (request_id,
		    client);
      return GNUNET_YES;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "no cache entry for '%s'\n",
	      hostname);
  return GNUNET_NO;
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


static void
process_get (const char *hostname,
	     uint16_t record_type,
	     uint16_t request_id,
	     struct GNUNET_SERVICE_Client *client)
{
  if (GNUNET_NO == try_cache (hostname, record_type, request_id, client))
  {
    int result = resolve_and_cache (hostname,
				    record_type,
		       		    request_id,
		       		    client);
    GNUNET_assert (GNUNET_OK == result);
  }
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
  const char *hostname;

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
	process_get (hostname, GNUNET_DNSPARSER_TYPE_ALL, request_id, client);
	break;
      }
      case AF_INET:
      {
	process_get (hostname, GNUNET_DNSPARSER_TYPE_A, request_id, client);
        break;
      }
      case AF_INET6:
      {
	process_get (hostname, GNUNET_DNSPARSER_TYPE_AAAA, request_id, client);
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
    hostname = make_reverse_hostname (&msg[1], af); 
    process_get (hostname, GNUNET_DNSPARSER_TYPE_PTR, request_id, client);
  }
  GNUNET_free_non_null ((char *)hostname);
  GNUNET_SERVICE_client_continue (client);
}


static void 
shutdown_task (void *cls)
{
  (void) cls;
  struct ResolveCache *pos;

  while (NULL != (pos = cache_head))
  {
    GNUNET_CONTAINER_DLL_remove (cache_head,
				 cache_tail,
				 pos);
    free_cache_entry (pos);
  }
  GNUNET_DNSSTUB_stop (dnsstub_ctx);
}


static void
init_cb (void *cls,
	 const struct GNUNET_CONFIGURATION_Handle *cfg,
	 struct GNUNET_SERVICE_Handle *sh)
{
  (void) cfg;
  (void) sh;

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 cls);
  dnsstub_ctx = GNUNET_DNSSTUB_start (128);
  char **dns_servers;
  ssize_t num_dns_servers = lookup_dns_servers (&dns_servers);
  if (0 == num_dns_servers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	        "no DNS server available. DNS resolution will not be possible.\n");
  }
  for (int i = 0; i != num_dns_servers; i++)
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
  (void) cls;
  struct ResolveCache *pos = cache_head; 

  while (NULL != pos)
  {
    if (pos->client == c)
    {
      pos->client = NULL;
    }
    pos = pos->next;
  }
  GNUNET_assert (c == internal_cls);
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
