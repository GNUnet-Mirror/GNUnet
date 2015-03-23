/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dns/gnunet-service-dns.c
 * @brief service to intercept and modify DNS queries (and replies) of this system
 * @author Christian Grothoff
 *
 * For "secure" interaction with the legacy DNS system, we permit
 * replies only to arrive within a 5s window (and they must match
 * ports, IPs and request IDs).  Furthermore, we let the OS pick a
 * source port, opening up to 128 sockets per address family (IPv4 or
 * IPv6).  Those sockets are closed if they are not in use for 5s
 * (which means they will be freshly randomized afterwards).  For new
 * requests, we pick a random slot in the array with 128 socket slots
 * (and re-use an existing socket if the slot is still in use).  Thus
 * each request will be given one of 128 random source ports, and the
 * 128 random source ports will also change "often" (less often if the
 * system is very busy, each time if we are mostly idle).  At the same
 * time, the system will never use more than 256 UDP sockets.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_applications.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "dns.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dnsstub_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_tun_lib.h"

/**
 * Port number for DNS
 */
#define DNS_PORT 53


/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "dns", __VA_ARGS__);


/**
 * Phases each request goes through.
 */
enum RequestPhase
{
  /**
   * Request has just been received.
   */
  RP_INIT,

  /**
   * Showing the request to all monitor clients.  If
   * client list is empty, will enter QUERY phase.
   */
  RP_REQUEST_MONITOR,

  /**
   * Showing the request to PRE-RESOLUTION clients to find an answer.
   * If client list is empty, will trigger global DNS request.
   */
  RP_QUERY,

  /**
   * Global Internet query is now pending.
   */
  RP_INTERNET_DNS,

  /**
   * Client (or global DNS request) has resulted in a response.
   * Forward to all POST-RESOLUTION clients.  If client list is empty,
   * will enter RESPONSE_MONITOR phase.
   */
  RP_MODIFY,

  /**
   * Showing the request to all monitor clients.  If
   * client list is empty, give the result to the hijacker (and be done).
   */
  RP_RESPONSE_MONITOR,

  /**
   * Some client has told us to drop the request.
   */
  RP_DROP
};


/**
 * Entry we keep for each client.
 */
struct ClientRecord
{
  /**
   * Kept in doubly-linked list.
   */
  struct ClientRecord *next;

  /**
   * Kept in doubly-linked list.
   */
  struct ClientRecord *prev;

  /**
   * Handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Flags for the client.
   */
  enum GNUNET_DNS_Flags flags;

};


/**
 * Entry we keep for each active request.
 */
struct RequestRecord
{

  /**
   * List of clients that still need to see this request (each entry
   * is set to NULL when the client is done).
   */
  struct ClientRecord **client_wait_list;

  /**
   * Payload of the UDP packet (the UDP payload), can be either query
   * or already the response.
   */
  char *payload;

  /**
   * Socket we are using to transmit this request (must match if we receive
   * a response).
   */
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  /**
   * Source address of the original request (for sending response).
   */
  struct sockaddr_storage src_addr;

  /**
   * Destination address of the original request (for potential use as exit).
   */
  struct sockaddr_storage dst_addr;

  /**
   * ID of this request, also basis for hashing.  Lowest 16 bit will
   * be our message ID when doing a global DNS request and our index
   * into the 'requests' array.
   */
  uint64_t request_id;

  /**
   * Number of bytes in payload.
   */
  size_t payload_length;

  /**
   * Length of the client wait list.
   */
  unsigned int client_wait_list_length;

  /**
   * In which phase this this request?
   */
  enum RequestPhase phase;

};


/**
 * Global return value from 'main'.
 */
static int global_ret;

/**
 * The configuration to use
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to DNS hijacker helper process ("gnunet-helper-dns").
 */
static struct GNUNET_HELPER_Handle *hijacker;

/**
 * Command-line arguments we are giving to the hijacker process.
 */
static char *helper_argv[7];

/**
 * Head of DLL of clients we consult.
 */
static struct ClientRecord *clients_head;

/**
 * Tail of DLL of clients we consult.
 */
static struct ClientRecord *clients_tail;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Array of all open requests.
 */
static struct RequestRecord requests[UINT16_MAX + 1];

/**
 * Generator for unique request IDs.
 */
static uint64_t request_id_gen;

/**
 * Handle to the DNS Stub resolver.
 */
static struct GNUNET_DNSSTUB_Context *dnsstub;


/**
 * We're done processing a DNS request, free associated memory.
 *
 * @param rr request to clean up
 */
static void
cleanup_rr (struct RequestRecord *rr)
{
  GNUNET_free_non_null (rr->payload);
  rr->payload = NULL;
  rr->payload_length = 0;
  GNUNET_array_grow (rr->client_wait_list,
		     rr->client_wait_list_length,
		     0);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls GNUNET_UNUSED,
              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  if (NULL != hijacker)
  {
    GNUNET_HELPER_stop (hijacker, GNUNET_NO);
    hijacker = NULL;
  }
  for (i=0;i<7;i++)
    GNUNET_free_non_null (helper_argv[i]);
  for (i=0;i<=UINT16_MAX;i++)
    cleanup_rr (&requests[i]);
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (NULL != dnsstub)
  {
    GNUNET_DNSSTUB_stop (dnsstub);
    dnsstub = NULL;
  }
}


/**
 * We're done with some request, finish processing.
 *
 * @param rr request send to the network or just clean up.
 */
static void
request_done (struct RequestRecord *rr)
{
  struct GNUNET_MessageHeader *hdr;
  size_t reply_len;
  uint16_t source_port;
  uint16_t destination_port;

  GNUNET_array_grow (rr->client_wait_list,
		     rr->client_wait_list_length,
		     0);
  if (RP_RESPONSE_MONITOR != rr->phase)
  {
    /* no response, drop */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Got no response for request %llu, dropping\n",
	 (unsigned long long) rr->request_id);
    cleanup_rr (rr);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting response for request %llu\n",
       (unsigned long long) rr->request_id);
  /* send response via hijacker */
  reply_len = sizeof (struct GNUNET_MessageHeader);
  reply_len += sizeof (struct GNUNET_TUN_Layer2PacketHeader);
  switch (rr->src_addr.ss_family)
  {
  case AF_INET:
    reply_len += sizeof (struct GNUNET_TUN_IPv4Header);
    break;
  case AF_INET6:
    reply_len += sizeof (struct GNUNET_TUN_IPv6Header);
    break;
  default:
    GNUNET_break (0);
    cleanup_rr (rr);
    return;
  }
  reply_len += sizeof (struct GNUNET_TUN_UdpHeader);
  reply_len += rr->payload_length;
  if (reply_len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    /* response too big, drop */
    GNUNET_break (0); /* how can this be? */
    cleanup_rr(rr);
    return;
  }
  {
    char buf[reply_len] GNUNET_ALIGN;
    size_t off;
    struct GNUNET_TUN_IPv4Header ip4;
    struct GNUNET_TUN_IPv6Header ip6;

    /* first, GNUnet message header */
    hdr = (struct GNUNET_MessageHeader*) buf;
    hdr->type = htons (GNUNET_MESSAGE_TYPE_DNS_HELPER);
    hdr->size = htons ((uint16_t) reply_len);
    off = sizeof (struct GNUNET_MessageHeader);

    /* first, TUN header */
    {
      struct GNUNET_TUN_Layer2PacketHeader tun;

      tun.flags = htons (0);
      if (rr->src_addr.ss_family == AF_INET)
	tun.proto = htons (ETH_P_IPV4);
      else
	tun.proto = htons (ETH_P_IPV6);
      memcpy (&buf[off], &tun, sizeof (struct GNUNET_TUN_Layer2PacketHeader));
      off += sizeof (struct GNUNET_TUN_Layer2PacketHeader);
    }

    /* now IP header */
    switch (rr->src_addr.ss_family)
    {
    case AF_INET:
      {
	struct sockaddr_in *src = (struct sockaddr_in *) &rr->src_addr;
	struct sockaddr_in *dst = (struct sockaddr_in *) &rr->dst_addr;

	source_port = dst->sin_port;
	destination_port = src->sin_port;
	GNUNET_TUN_initialize_ipv4_header (&ip4,
					   IPPROTO_UDP,
					   reply_len - off - sizeof (struct GNUNET_TUN_IPv4Header),
					   &dst->sin_addr,
					   &src->sin_addr);
	memcpy (&buf[off], &ip4, sizeof (ip4));
	off += sizeof (ip4);
      }
      break;
    case AF_INET6:
      {
	struct sockaddr_in6 *src = (struct sockaddr_in6 *) &rr->src_addr;
	struct sockaddr_in6 *dst = (struct sockaddr_in6 *) &rr->dst_addr;

	source_port = dst->sin6_port;
	destination_port = src->sin6_port;
	GNUNET_TUN_initialize_ipv6_header (&ip6,
					   IPPROTO_UDP,
					   reply_len - sizeof (struct GNUNET_TUN_IPv6Header),
					   &dst->sin6_addr,
					   &src->sin6_addr);
	memcpy (&buf[off], &ip6, sizeof (ip6));
	off += sizeof (ip6);
      }
      break;
    default:
      GNUNET_assert (0);
    }

    /* now UDP header */
    {
      struct GNUNET_TUN_UdpHeader udp;

      udp.source_port = source_port;
      udp.destination_port = destination_port;
      udp.len = htons (reply_len - off);
      if (AF_INET == rr->src_addr.ss_family)
	GNUNET_TUN_calculate_udp4_checksum (&ip4,
					    &udp,
					    rr->payload,
					    rr->payload_length);
      else
	GNUNET_TUN_calculate_udp6_checksum (&ip6,
					    &udp,
					    rr->payload,
					    rr->payload_length);
      memcpy (&buf[off], &udp, sizeof (udp));
      off += sizeof (udp);
    }

    /* now DNS payload */
    {
      memcpy (&buf[off], rr->payload, rr->payload_length);
      off += rr->payload_length;
    }
    /* final checks & sending */
    GNUNET_assert (off == reply_len);
    (void) GNUNET_HELPER_send (hijacker,
			       hdr,
			       GNUNET_YES,
			       NULL, NULL);
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests answered via TUN interface"),
			      1, GNUNET_NO);
  }
  /* clean up, we're done */
  cleanup_rr (rr);
}


/**
 * Show the payload of the given request record to the client
 * (and wait for a response).
 *
 * @param rr request to send to client
 * @param client client to send the response to
 */
static void
send_request_to_client (struct RequestRecord *rr,
			struct GNUNET_SERVER_Client *client)
{
  char buf[sizeof (struct GNUNET_DNS_Request) + rr->payload_length] GNUNET_ALIGN;
  struct GNUNET_DNS_Request *req;

  if (sizeof (buf) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    cleanup_rr (rr);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending information about request %llu to local client\n",
       (unsigned long long) rr->request_id);
  req = (struct GNUNET_DNS_Request*) buf;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST);
  req->header.size = htons (sizeof (buf));
  req->reserved = htonl (0);
  req->request_id = rr->request_id;
  memcpy (&req[1], rr->payload, rr->payload_length);
  GNUNET_SERVER_notification_context_unicast (nc,
					      client,
					      &req->header,
					      GNUNET_NO);
}



/**
 * Callback called from DNSSTUB resolver when a resolution
 * succeeded.
 *
 * @param cls NULL
 * @param rs the socket that received the response
 * @param dns the response itself
 * @param r number of bytes in dns
 */
static void
process_dns_result (void *cls,
		    struct GNUNET_DNSSTUB_RequestSocket *rs,
		    const struct GNUNET_TUN_DnsHeader *dns,
		    size_t r);


/**
 * A client has completed its processing for this
 * request.  Move on.
 *
 * @param rr request to process further
 */
static void
next_phase (struct RequestRecord *rr)
{
  struct ClientRecord *cr;
  int nz;
  unsigned int j;
  socklen_t salen;

  if (rr->phase == RP_DROP)
  {
    cleanup_rr (rr);
    return;
  }
  nz = -1;
  for (j=0;j<rr->client_wait_list_length;j++)
  {
    if (NULL != rr->client_wait_list[j])
    {
      nz = (int) j;
      break;
    }
  }
  if (-1 != nz)
  {
    send_request_to_client (rr, rr->client_wait_list[nz]->client);
    return;
  }
  /* done with current phase, advance! */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Request %llu now in phase %d\n",
       rr->request_id,
       rr->phase);
  switch (rr->phase)
  {
  case RP_INIT:
    rr->phase = RP_REQUEST_MONITOR;
    for (cr = clients_head; NULL != cr; cr = cr->next)
    {
      if (0 != (cr->flags & GNUNET_DNS_FLAG_REQUEST_MONITOR))
	GNUNET_array_append (rr->client_wait_list,
			     rr->client_wait_list_length,
			     cr);
    }
    next_phase (rr);
    return;
  case RP_REQUEST_MONITOR:
    rr->phase = RP_QUERY;
    for (cr = clients_head; NULL != cr; cr = cr->next)
    {
      if (0 != (cr->flags & GNUNET_DNS_FLAG_PRE_RESOLUTION))
	GNUNET_array_append (rr->client_wait_list,
			     rr->client_wait_list_length,
			     cr);
    }
    next_phase (rr);
    return;
  case RP_QUERY:
    switch (rr->dst_addr.ss_family)
    {
    case AF_INET:
      salen = sizeof (struct sockaddr_in);
      break;
    case AF_INET6:
      salen = sizeof (struct sockaddr_in6);
      break;
    default:
      GNUNET_assert (0);
    }

    rr->phase = RP_INTERNET_DNS;
    rr->rs = GNUNET_DNSSTUB_resolve (dnsstub,
				     (struct sockaddr*) &rr->dst_addr,
				     salen,
				     rr->payload,
				     rr->payload_length,
				     &process_dns_result,
				     NULL);
    if (NULL == rr->rs)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# DNS exit failed (failed to open socket)"),
				1, GNUNET_NO);
      cleanup_rr (rr);
      return;
    }
    return;
  case RP_INTERNET_DNS:
    rr->phase = RP_MODIFY;
    for (cr = clients_head; NULL != cr; cr = cr->next)
    {
      if (0 != (cr->flags & GNUNET_DNS_FLAG_POST_RESOLUTION))
	GNUNET_array_append (rr->client_wait_list,
			     rr->client_wait_list_length,
			     cr);
    }
    next_phase (rr);
    return;
  case RP_MODIFY:
    rr->phase = RP_RESPONSE_MONITOR;
    for (cr = clients_head; NULL != cr; cr = cr->next)
    {
      if (0 != (cr->flags & GNUNET_DNS_FLAG_RESPONSE_MONITOR))
	GNUNET_array_append (rr->client_wait_list,
			     rr->client_wait_list_length,
			     cr);
    }
    next_phase (rr);
    return;
 case RP_RESPONSE_MONITOR:
    request_done (rr);
    break;
  case RP_DROP:
    cleanup_rr (rr);
    break;
  default:
    GNUNET_break (0);
    cleanup_rr (rr);
    break;
  }
}


/**
 * A client disconnected, clean up after it.
 *
 * @param cls unused
 * @param client handle of client that disconnected
 */
static void
client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientRecord *cr;
  struct RequestRecord *rr;
  unsigned int i;
  unsigned int j;

  for (cr = clients_head; NULL != cr; cr = cr->next)
  {
    if (cr->client == client)
    {
      GNUNET_SERVER_client_drop (client);
      GNUNET_CONTAINER_DLL_remove (clients_head,
				   clients_tail,
				   cr);
      for (i=0;i<UINT16_MAX;i++)
      {
	rr = &requests[i];
	if (0 == rr->client_wait_list_length)
	  continue; /* not in use */
	for (j=0;j<rr->client_wait_list_length;j++)
	{
	  if (rr->client_wait_list[j] == cr)
	  {
	    rr->client_wait_list[j] = NULL;
	    next_phase (rr);
	  }
	}
      }
      GNUNET_free (cr);
      return;
    }
  }
}


/**
 * Callback called from DNSSTUB resolver when a resolution
 * succeeded.
 *
 * @param cls NULL
 * @param rs the socket that received the response
 * @param dns the response itself
 * @param r number of bytes in dns
 */
static void
process_dns_result (void *cls,
		    struct GNUNET_DNSSTUB_RequestSocket *rs,
		    const struct GNUNET_TUN_DnsHeader *dns,
		    size_t r)
{
  struct RequestRecord *rr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing DNS result from stub resolver\n");
  GNUNET_assert (NULL == cls);
  rr = &requests[dns->id];
  if ( (rr->phase != RP_INTERNET_DNS) ||
       (rr->rs != rs) )
  {
    /* unexpected / bogus reply */
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# External DNS response discarded (no matching request)"),
			      1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received DNS reply that does not match any pending request.  Dropping.\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a response from the stub resolver for DNS request %llu intercepted locally!\n",
       (unsigned long long) rr->request_id);
  GNUNET_free_non_null (rr->payload);
  rr->payload = GNUNET_malloc (r);
  memcpy (rr->payload, dns, r);
  rr->payload_length = r;
  next_phase (rr);
}


/**
 * We got a new client.  Make sure all new DNS requests pass by its desk.
 *
 * @param cls unused
 * @param client the new client
 * @param message the init message (unused)
 */
static void
handle_client_init (void *cls GNUNET_UNUSED,
		    struct GNUNET_SERVER_Client *client,
		    const struct GNUNET_MessageHeader *message)
{
  struct ClientRecord *cr;
  const struct GNUNET_DNS_Register *reg = (const struct GNUNET_DNS_Register*) message;

  cr = GNUNET_new (struct ClientRecord);
  cr->client = client;
  cr->flags = (enum GNUNET_DNS_Flags) ntohl (reg->flags);
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (clients_head,
			       clients_tail,
			       cr);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * We got a response from a client.
 *
 * @param cls unused
 * @param client the client
 * @param message the response
 */
static void
handle_client_response (void *cls GNUNET_UNUSED,
			struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DNS_Response *resp;
  struct RequestRecord *rr;
  unsigned int i;
  uint16_t msize;
  uint16_t off;

  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_DNS_Response))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  resp = (const struct GNUNET_DNS_Response*) message;
  off = (uint16_t) resp->request_id;
  rr = &requests[off];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received DNS response with ID %llu from local client!\n",
       (unsigned long long) resp->request_id);
  if (rr->request_id != resp->request_id)
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# Client response discarded (no matching request)"),
			      1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  for (i=0;i<rr->client_wait_list_length;i++)
  {
    if (NULL == rr->client_wait_list[i])
      continue;
    if (rr->client_wait_list[i]->client != client)
      continue;
    rr->client_wait_list[i] = NULL;
    switch (ntohl (resp->drop_flag))
    {
    case 0: /* drop */
      rr->phase = RP_DROP;
      break;
    case 1: /* no change */
      break;
    case 2: /* update */
      msize -= sizeof (struct GNUNET_DNS_Response);
      if ( (sizeof (struct GNUNET_TUN_DnsHeader) > msize) ||
	   (RP_REQUEST_MONITOR == rr->phase) ||
	   (RP_RESPONSE_MONITOR == rr->phase) )
      {
	GNUNET_break (0);
	GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	next_phase (rr);
	return;
      }
      GNUNET_free_non_null (rr->payload);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Changing DNS reply according to client specifications\n");
      rr->payload = GNUNET_malloc (msize);
      rr->payload_length = msize;
      memcpy (rr->payload, &resp[1], msize);
      if (rr->phase == RP_QUERY)
      {
	/* clear wait list, we're moving to MODIFY phase next */
	GNUNET_array_grow (rr->client_wait_list,
			   rr->client_wait_list_length,
			   0);
      }
      /* if query changed to answer, move past DNS resolution phase... */
      if ( (RP_QUERY == rr->phase) &&
	   (rr->payload_length > sizeof (struct GNUNET_TUN_DnsHeader)) &&
	   ((struct GNUNET_TUN_DnsFlags*)&(((struct GNUNET_TUN_DnsHeader*) rr->payload)->flags))->query_or_response == 1)
      {
	rr->phase = RP_INTERNET_DNS;
	GNUNET_array_grow (rr->client_wait_list,
			   rr->client_wait_list_length,
			   0);
      }
      break;
    }
    next_phase (rr);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  /* odd, client was not on our list for the request, that ought
     to be an error */
  GNUNET_break (0);
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Functions with this signature are called whenever a complete
 * message is received by the tokenizer from the DNS hijack process.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, a DNS request we should handle
 */
static int
process_helper_messages (void *cls GNUNET_UNUSED, void *client,
			 const struct GNUNET_MessageHeader *message)
{
  uint16_t msize;
  const struct GNUNET_TUN_Layer2PacketHeader *tun;
  const struct GNUNET_TUN_IPv4Header *ip4;
  const struct GNUNET_TUN_IPv6Header *ip6;
  const struct GNUNET_TUN_UdpHeader *udp;
  const struct GNUNET_TUN_DnsHeader *dns;
  struct RequestRecord *rr;
  struct sockaddr_in *srca4;
  struct sockaddr_in6 *srca6;
  struct sockaddr_in *dsta4;
  struct sockaddr_in6 *dsta6;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Intercepted message via DNS hijacker\n");
  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_MessageHeader) + sizeof (struct GNUNET_TUN_Layer2PacketHeader) + sizeof (struct GNUNET_TUN_IPv4Header))
  {
    /* non-IP packet received on TUN!? */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  msize -= sizeof (struct GNUNET_MessageHeader);
  tun = (const struct GNUNET_TUN_Layer2PacketHeader *) &message[1];
  msize -= sizeof (struct GNUNET_TUN_Layer2PacketHeader);
  switch (ntohs (tun->proto))
  {
  case ETH_P_IPV4:
    ip4 = (const struct GNUNET_TUN_IPv4Header *) &tun[1];
    ip6 = NULL; /* make compiler happy */
    if ( (msize < sizeof (struct GNUNET_TUN_IPv4Header)) ||
	 (ip4->version != 4) ||
	 (ip4->header_length != sizeof (struct GNUNET_TUN_IPv4Header) / 4) ||
	 (ntohs(ip4->total_length) != msize) ||
	 (ip4->protocol != IPPROTO_UDP) )
    {
      /* non-IP/UDP packet received on TUN (or with options) */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Received malformed IPv4-UDP packet on TUN interface.\n"));
      return GNUNET_OK;
    }
    udp = (const struct GNUNET_TUN_UdpHeader*) &ip4[1];
    msize -= sizeof (struct GNUNET_TUN_IPv4Header);
    break;
  case ETH_P_IPV6:
    ip4 = NULL; /* make compiler happy */
    ip6 = (const struct GNUNET_TUN_IPv6Header *) &tun[1];
    if ( (msize < sizeof (struct GNUNET_TUN_IPv6Header)) ||
	 (ip6->version != 6) ||
	 (ntohs (ip6->payload_length) != msize) ||
	 (ip6->next_header != IPPROTO_UDP) )
    {
      /* non-IP/UDP packet received on TUN (or with extensions) */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Received malformed IPv6-UDP packet on TUN interface.\n"));
      return GNUNET_OK;
    }
    udp = (const struct GNUNET_TUN_UdpHeader*) &ip6[1];
    msize -= sizeof (struct GNUNET_TUN_IPv6Header);
    break;
  default:
    /* non-IP packet received on TUN!? */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Got non-IP packet with %u bytes and protocol %u from TUN\n"),
		(unsigned int) msize,
		ntohs (tun->proto));
    return GNUNET_OK;
  }
  if ( (msize <= sizeof (struct GNUNET_TUN_UdpHeader) + sizeof (struct GNUNET_TUN_DnsHeader)) ||
       (DNS_PORT != ntohs (udp->destination_port)) )
  {
    /* non-DNS packet received on TUN, ignore */
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# Non-DNS UDP packet received via TUN interface"),
			      1, GNUNET_NO);
    return GNUNET_OK;
  }
  msize -= sizeof (struct GNUNET_TUN_UdpHeader);
  dns = (const struct GNUNET_TUN_DnsHeader*) &udp[1];
  rr = &requests[dns->id];

  /* clean up from previous request */
  GNUNET_free_non_null (rr->payload);
  rr->payload = NULL;
  GNUNET_array_grow (rr->client_wait_list,
		     rr->client_wait_list_length,
		     0);

  /* setup new request */
  rr->phase = RP_INIT;
  switch (ntohs (tun->proto))
  {
  case ETH_P_IPV4:
    {
      srca4 = (struct sockaddr_in*) &rr->src_addr;
      dsta4 = (struct sockaddr_in*) &rr->dst_addr;
      memset (srca4, 0, sizeof (struct sockaddr_in));
      memset (dsta4, 0, sizeof (struct sockaddr_in));
      srca4->sin_family = AF_INET;
      dsta4->sin_family = AF_INET;
      srca4->sin_addr = ip4->source_address;
      dsta4->sin_addr = ip4->destination_address;
      srca4->sin_port = udp->source_port;
      dsta4->sin_port = udp->destination_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
      srca4->sin_len = sizeof (struct sockaddr_in);
      dsta4->sin_len = sizeof (struct sockaddr_in);
#endif
    }
    break;
  case ETH_P_IPV6:
    {
      srca6 = (struct sockaddr_in6*) &rr->src_addr;
      dsta6 = (struct sockaddr_in6*) &rr->dst_addr;
      memset (srca6, 0, sizeof (struct sockaddr_in6));
      memset (dsta6, 0, sizeof (struct sockaddr_in6));
      srca6->sin6_family = AF_INET6;
      dsta6->sin6_family = AF_INET6;
      srca6->sin6_addr = ip6->source_address;
      dsta6->sin6_addr = ip6->destination_address;
      srca6->sin6_port = udp->source_port;
      dsta6->sin6_port = udp->destination_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
      srca6->sin6_len = sizeof (struct sockaddr_in6);
      dsta6->sin6_len = sizeof (struct sockaddr_in6);
#endif
    }
  break;
  default:
    GNUNET_assert (0);
  }
  rr->payload = GNUNET_malloc (msize);
  rr->payload_length = msize;
  memcpy (rr->payload, dns, msize);
  rr->request_id = dns->id | (request_id_gen << 16);
  request_id_gen++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new DNS request %llu\n",
       (unsigned long long) rr->request_id);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests received via TUN interface"),
			    1, GNUNET_NO);
  /* start request processing state machine */
  next_phase (rr);
  return GNUNET_OK;
}


/**
 * @param cls closure
 * @param server the initialized server
 * @param cfg_ configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    /* callback, cls, type, size */
    {&handle_client_init, NULL, GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT,
     sizeof (struct GNUNET_DNS_Register)},
    {&handle_client_response, NULL, GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE, 0},
    {NULL, NULL, 0, 0}
  };
  char *ifc_name;
  char *ipv4addr;
  char *ipv4mask;
  char *ipv6addr;
  char *ipv6prefix;
  struct in_addr dns_exit4;
  struct in6_addr dns_exit6;
  char *dns_exit;
  char *binary;

  cfg = cfg_;
  stats = GNUNET_STATISTICS_create ("dns", cfg);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleanup_task,
                                cls);
  dns_exit = NULL;
  if ( ( (GNUNET_OK !=
	  GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "dns",
						 "DNS_EXIT",
						 &dns_exit)) ||
	 ( (1 != inet_pton (AF_INET, dns_exit, &dns_exit4)) &&
	   (1 != inet_pton (AF_INET6, dns_exit, &dns_exit6)) ) ) )
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "dns",
                               "DNS_EXIT",
			       _("need a valid IPv4 or IPv6 address\n"));
    GNUNET_free_non_null (dns_exit);
    dns_exit = NULL;
  }
  dnsstub = GNUNET_DNSSTUB_start (dns_exit);
  GNUNET_free_non_null (dns_exit);
  GNUNET_SERVER_add_handlers (server,
                              handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect,
                                   NULL);
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-dns");
  if (GNUNET_YES !=
      GNUNET_OS_check_helper_binary (binary,
                                     GNUNET_YES,
                                     NULL)) // TODO: once we have a windows-testcase, add test parameters here
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("`%s' must be installed SUID, will not run DNS interceptor\n"),
		binary);
    global_ret = 1;
    GNUNET_free (binary);
    return;
  }
  GNUNET_free (binary);

  helper_argv[0] = GNUNET_strdup ("gnunet-dns");
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "IFNAME", &ifc_name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IFNAME' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[1] = ifc_name;
  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "IPV6ADDR",
					       &ipv6addr)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[2] = ipv6addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "IPV6PREFIX",
                                             &ipv6prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[3] = ipv6prefix;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "IPV4ADDR",
                                             &ipv4addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[4] = ipv4addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "IPV4MASK",
                                             &ipv4mask))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4MASK' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[5] = ipv4mask;
  helper_argv[6] = NULL;
  hijacker = GNUNET_HELPER_start (GNUNET_NO,
				  "gnunet-helper-dns",
				  helper_argv,
				  &process_helper_messages,
				  NULL, NULL);
}


/**
 * The main function for the dns service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  /* make use of SGID capabilities on POSIX */
  /* FIXME: this might need a port on systems without 'getresgid' */
#if HAVE_GETRESGID
  gid_t rgid;
  gid_t egid;
  gid_t sgid;

  if (-1 == getresgid (&rgid, &egid, &sgid))
  {
    fprintf (stderr,
	     "getresgid failed: %s\n",
	     strerror (errno));
  }
  else if (sgid != rgid)
  {
    if (-1 ==  setregid (sgid, sgid))
      fprintf (stderr, "setregid failed: %s\n", strerror (errno));
  }
#endif
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "dns", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? global_ret : 1;
}


/* end of gnunet-service-dns.c */
