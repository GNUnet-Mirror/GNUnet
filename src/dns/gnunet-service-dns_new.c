/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dns/gnunet-service-dns_new.c
 * @author Christian Grothoff
 */
// current thoughts:
// - for full compatibility to DNS and to avoid going insane here parsing/generating DNS packets,
//   how about literally attaching the "original" DNS packet (request/response) to the IPC traffic?
//   that way, clients can literally do arbitrary modifications and we are done with that issue here.
//   All we'd do in here is add the IP/UDP headers and be DONE with it.
// => minor modifications to API and IPC protocol
// => minor modifications to our data structures
// => major gains in terms of simplicity here and what can (at least theoretically) be done with the service
// => can test much more quickly
// => but: need to really write a good libgnunetdnsparse to avoid making MANY clients really complicated
//    (not the worst of worlds either, other than deferring this mess some...)
//    -> also positive: can be tested independently of the rest of the mess


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
//#include "gnunet_dnsparser_lib.h"
#include "gnunet_signatures.h"
#include "dns_new.h"

GNUNET_NETWORK_STRUCT_BEGIN
struct ip4_hdr
{
  unsigned hdr_lngth:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;

  uint8_t diff_serv;
  uint16_t tot_lngth GNUNET_PACKED;

  uint16_t ident GNUNET_PACKED;
  unsigned flags:3 GNUNET_PACKED;
  unsigned frag_off:13 GNUNET_PACKED;

  uint8_t ttl;
  uint8_t proto;
  uint16_t chks GNUNET_PACKED;

  struct in_addr sadr GNUNET_PACKED;
  struct in_addr dadr GNUNET_PACKED;
};

struct ip6_hdr
{
  unsigned tclass_h:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  unsigned tclass_l:4 GNUNET_PACKED;
  unsigned flowlbl:20 GNUNET_PACKED;
  uint16_t paylgth GNUNET_PACKED;
  uint8_t nxthdr;
  uint8_t hoplmt;
  struct in6_addr sadr GNUNET_PACKED;
  struct in6_addr dadr GNUNET_PACKED;
};

struct udp_pkt
{
  uint16_t spt GNUNET_PACKED;
  uint16_t dpt GNUNET_PACKED;
  uint16_t len GNUNET_PACKED;
  uint16_t crc GNUNET_PACKED;
};

struct dns_pkt
{
  uint16_t id GNUNET_PACKED;

  unsigned rd:1 GNUNET_PACKED;  // recursion desired (client -> server)
  unsigned tc:1 GNUNET_PACKED;  // message is truncated
  unsigned aa:1 GNUNET_PACKED;  // authoritative answer
  unsigned op:4 GNUNET_PACKED;  // query:0, inverse q.:1, status: 2
  unsigned qr:1 GNUNET_PACKED;  // query:0, response:1

  unsigned rcode:4 GNUNET_PACKED;       // 0 No error
  // 1 Format error
  // 2 Server failure
  // 3 Name Error
  // 4 Not Implemented
  // 5 Refused
  unsigned z:3 GNUNET_PACKED;   // reserved
  unsigned ra:1 GNUNET_PACKED;  // recursion available (server -> client)

  uint16_t qdcount GNUNET_PACKED;       // number of questions
  uint16_t ancount GNUNET_PACKED;       // number of answers
  uint16_t nscount GNUNET_PACKED;       // number of authority-records
  uint16_t arcount GNUNET_PACKED;       // number of additional records
};

struct dns_query_line
{
  uint16_t type;
  uint16_t class;
};

struct dns_record_line
{
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t data_len;
};
GNUNET_NETWORK_STRUCT_END


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

};


/**
 * Entry we keep for each active request.
 */ 
struct RequestRecord
{

  /**
   * Name for the request.
   */
  char *name;

  /**
   * Response data, or NULL if not known.
   */ 
  char *rdata;

  /**
   * List of clients that still need to see this request (each entry
   * is set to NULL when the client is done).
   */
  struct ClientRecord **client_wait_list;

  /**
   * Length of the client wait list.
   */
  unsigned int client_wait_list_length;

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
   * TTL if we know it, or 0.
   */
  uint32_t dns_ttl;

  /**
   * Number of bytes in rdata.
   */ 
  uint16_t rdata_length;

  /**
   * Length of the 'name' string, including 0-terminator.
   */
  uint16_t name_length;

  /**
   * The DNS type (i.e. 1 == 'A').
   */
  uint16_t dns_type;

  /**
   * The DNS class (i.e. 1 == Internet)
   */
  uint16_t dns_class;

  /**
   * Original DNS Id we got from the client.
   */
  uint16_t original_dns_id;

};


/**
 * The IPv4 UDP-Socket through which DNS-Resolves will be sent if they are not to be
 * sent through gnunet. The port of this socket will not be hijacked.
 */
static struct GNUNET_NETWORK_Handle *dnsout4;

/**
 * The IPv6 UDP-Socket through which DNS-Resolves will be sent if they are not to be
 * sent through gnunet. The port of this socket will not be hijacked.
 */
static struct GNUNET_NETWORK_Handle *dnsout6;

/**
 * Task for reading from dnsout4.
 */
static GNUNET_SCHEDULER_TaskIdentifier read4_task;

/**
 * Task for reading from dnsout6.
 */
static GNUNET_SCHEDULER_TaskIdentifier read6_task;

/**
 * The port bound to the socket dnsout (and/or dnsout6).  We always (try) to bind
 * both sockets to the same port.
 */
static uint16_t dnsoutport;

/**
 * The configuration to use
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to DNS hijacker helper process ("gnunet-helper-dns").
 */
static struct GNUNET_HELPER_Handle *hijacker;

/**
 * Command-line arguments we are giving to the hijacker process.
 */
static char *helper_argv[8];

/**
 * Head of DLL of clients we consult.
 */
static struct ClientRecord *clients_head;

/**
 * Tail of DLL of clients we consult.
 */
static struct ClientRecord *clients_tail;

/**
 * Array of all open requests.
 */
static struct RequestRecord requests[UINT16_MAX];

/**
 * Generator for unique request IDs.
 */
static uint64_t request_id_gen;


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
  struct RequestRecord *rr;

  GNUNET_HELPER_stop (hijacker);
  hijacker = NULL;
  for (i=0;i<8;i++)
    GNUNET_free_non_null (helper_argv[i]);
  if (NULL != dnsout4)
  {
    GNUNET_NETWORK_socket_close (dnsout4);
    dnsout4 = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != read4_task)
  {
    GNUNET_SCHEDULER_cancel (read4_task);
    read4_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != dnsout6)
  {
    GNUNET_NETWORK_socket_close (dnsout6);
    dnsout6 = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != read6_task)
  {
    GNUNET_SCHEDULER_cancel (read6_task);
    read6_task = GNUNET_SCHEDULER_NO_TASK;
  }
  for (i=0;i<65536;i++)
  {
    rr = &requests[i];
    GNUNET_free (rr->name);
    GNUNET_free_non_null (rr->rdata);
    GNUNET_array_grow (rr->client_wait_list,
		       rr->client_wait_list_length,
		       0);
  }
}


/**
 * We're done with some request, finish processing.
 */
static void
request_done (struct RequestRecord *rr)
{
  struct GNUNET_MessageHeader *hdr;
  size_t reply_len;
  uint16_t spt;
  uint16_t dpt;

  GNUNET_array_grow (rr->client_wait_list,
		     rr->client_wait_list_length,
		     0); 
  if (NULL == rr->rdata)
  {
    /* no response, drop */
    GNUNET_free (rr->name);
    rr->name = NULL;
    return;
  }
  
  /* send response via hijacker */
  reply_len = sizeof (struct GNUNET_MessageHeader);
  switch (rr->src_addr.ss_family)
  {
  case AF_INET:
    reply_len += sizeof (struct ip4_hdr);
    break;
  case AF_INET6:
    reply_len += sizeof (struct ip6_hdr);
    break;
  default:
    GNUNET_break (0);
    GNUNET_free (rr->name);
    rr->name = NULL;
    return;   
  }
  reply_len += sizeof (struct udp_pkt);
  reply_len += sizeof (struct dns_pkt);
  reply_len += rr->name_length;
  reply_len += sizeof (struct dns_record_line);
  reply_len += rr->rdata_length;
  if (reply_len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    /* response too big, drop */
    GNUNET_break (0); /* how can this be? */
    GNUNET_free (rr->name);
    rr->name = NULL;
    return;    
  }
  {
    char buf[reply_len];
    size_t off;

    /* first, GNUnet message header */
    hdr = (struct GNUNET_MessageHeader*) buf;
    hdr->type = htons (GNUNET_MESSAGE_TYPE_DNS_HELPER);
    hdr->size = htons ((uint16_t) reply_len);
    off = sizeof (struct GNUNET_MessageHeader);

    /* now IP header */
    switch (rr->src_addr.ss_family)
    {
    case AF_INET:
      {
	struct sockaddr_in *src = (struct sockaddr_in *) &rr->src_addr;
	struct sockaddr_in *dst = (struct sockaddr_in *) &rr->dst_addr;
	struct ip4_hdr ip;
	
	spt = dst->sin_port;
	dpt = src->sin_port;
	// FIXME: fill in IP header!
	memcpy (&buf[off], &ip, sizeof (ip));
	off += sizeof (ip);
	break;
      }
    case AF_INET6:
      {
	struct sockaddr_in6 *src = (struct sockaddr_in6 *) &rr->src_addr;
	struct sockaddr_in6 *dst = (struct sockaddr_in6 *) &rr->dst_addr;
	struct ip6_hdr ip;

	spt = dst->sin6_port;
	dpt = src->sin6_port;
	// FIXME: fill in IP header!
	memcpy (&buf[off], &ip, sizeof (ip));
	off += sizeof (ip);
      }
      break;
    default:
      GNUNET_assert (0);
    }
    /* now UDP header */
    {
      struct udp_pkt udp;

      udp.spt = spt;
      udp.dpt = dpt;
      udp.len = htons (reply_len - off);
      udp.crc = 0; /* checksum is optional */
      memcpy (&buf[off], &udp, sizeof (udp));
      off += sizeof (udp);
    }

    /* now DNS header */
    {
      struct dns_pkt dns;

      dns.id = rr->original_dns_id;
      dns.rd = 1; /* recursion desired / supported */
      dns.tc = 0; /* not truncated */
      dns.aa = 1; /* are we authoritative!? I say yes. */
      dns.op = 0; /* standard query */
      dns.qr = 1; /* this is a response */
      dns.rcode = 0; /* no error */
      dns.z = 0; /* reserved */
      dns.ra = 1; /* recursion available */
      dns.qdcount = htons (0); /* no queries */
      dns.ancount = htons (1); /* one answer */
      dns.nscount = htons (0); /* no authorities yet (fixme) */
      dns.arcount = htons (0); /* no additinal records yet (fixme) */
      memcpy (&buf[off], &dns, sizeof (dns));
      off += sizeof (dns);
    }

    /* now DNS name */
    {
      // FIXME: fill in DNS name!
      off += rr->name_length;
    }


    /* now DNS record line */
    {
      struct dns_record_line drl;
      
      drl.type = htons (rr->dns_type);
      drl.class = htons (rr->dns_class);
      drl.ttl = htonl (rr->dns_ttl);
      drl.data_len = htons (rr->rdata_length);
      memcpy (&buf[off], &drl, sizeof (drl));
      off += sizeof (drl);
    }

    /* now DNS rdata */
    {
      memcpy (&buf[off], rr->rdata, rr->rdata_length);
      off += rr->rdata_length;
    }
    
    /* final checks & sending */
    GNUNET_assert (off == reply_len);
    GNUNET_HELPER_send (hijacker,
			hdr,
			GNUNET_YES,
			NULL, NULL);
  }
  /* clean up, we're done */
  GNUNET_free (rr->name);
  rr->name = NULL;
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
  int az;

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
	az = 1;
	for (j=0;j<rr->client_wait_list_length;j++)
	{
	  if (rr->client_wait_list[j] == cr)
	    rr->client_wait_list[j] = NULL;
	  if (rr->client_wait_list[j] != NULL)
	    az = 0;
	}
	if (1 == az)
	  request_done (rr); /* this was the last client... */
      }
      GNUNET_free (cr);
      return;
    }
  }
}


/**
 * Read a DNS response from the (unhindered) UDP-Socket
 *
 * @param cls socket to read from
 * @param tc scheduler context (must be shutdown or read ready)
 */
static void
read_response (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NETWORK_Handle *dnsout = cls;
  struct sockaddr_in addr4;
  struct sockaddr_in6 addr6;
  struct sockaddr *addr;
  socklen_t addrlen;
  ssize_t r;
  int len;

  if (dnsout == dnsout4)
  {
    addrlen = sizeof (struct sockaddr_in);
    addr = (struct sockaddr* ) &addr4;
    read4_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, 
						dnsout,
						&read_response, 
						dnsout);
  }
  else
  {
    addrlen = sizeof (struct sockaddr_in6);
    addr = (struct sockaddr* ) &addr6;
    read6_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, 
						dnsout,
						&read_response, 
						dnsout);
  }
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

#ifndef MINGW
  if (0 != ioctl (GNUNET_NETWORK_get_fd (dnsout), FIONREAD, &len))
  {
    /* conservative choice: */
    len = 65536;
  }
#else
  /* port the code above? */
  len = 65536;
#endif

  {
    unsigned char buf[len];

    memset (addr, 0, addrlen);  
    r = GNUNET_NETWORK_socket_recvfrom (dnsout, 
					buf, sizeof (buf),
					addr, &addrlen);
    if (-1 == r)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "recvfrom");
      return;
    }
    // NOTE: struct dns_pkt *dns = (struct dns_pkt *) buf;
    // FIXME: handle_response (buf, r, addr, addrlen);
  }
}


/**
 * Open source port for sending DNS request on IPv4.
 *
 * @return GNUNET_OK on success
 */ 
static int
open_port4 ()
{
  struct sockaddr_in addr;
  socklen_t addrlen;

  dnsout4 = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
  if (dnsout4 == NULL)
    return GNUNET_SYSERR;

  memset (&addr, 0, sizeof (struct sockaddr_in));
  addr.sin_family = AF_INET;
  int err = GNUNET_NETWORK_socket_bind (dnsout4,
                                        (struct sockaddr *) &addr,
                                        sizeof (struct sockaddr_in));

  if (err != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Could not bind to any port: %s\n"),
		STRERROR (errno));
    GNUNET_NETWORK_socket_close (dnsout4);
    dnsout4 = NULL;
    return GNUNET_SYSERR;
  }

  /* Read the port we bound to */
  addrlen = sizeof (struct sockaddr_in);
  if (0 != getsockname (GNUNET_NETWORK_get_fd (dnsout4), 
			(struct sockaddr *) &addr,
			&addrlen))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Could not determine port I got: %s\n"),
		STRERROR (errno));
    GNUNET_NETWORK_socket_close (dnsout4);
    dnsout4 = NULL;
    return GNUNET_SYSERR;
  }
  dnsoutport = htons (addr.sin_port);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("GNUnet DNS will exit on source port %u\n"),
	      (unsigned int) dnsoutport);
  read4_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, 
					      dnsout4,
					      &read_response, dnsout4);
  return GNUNET_OK;
}


/**
 * Open source port for sending DNS request on IPv6.  Should be 
 * called AFTER open_port4.
 *
 * @return GNUNET_OK on success
 */ 
static int
open_port6 ()
{
  struct sockaddr_in6 addr;
  socklen_t addrlen;

  dnsout6 = GNUNET_NETWORK_socket_create (AF_INET6, SOCK_DGRAM, 0);
  if (dnsout6 == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Could not create IPv6 socket: %s\n"),
		STRERROR (errno));
    return GNUNET_SYSERR;
  }
  memset (&addr, 0, sizeof (struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (dnsoutport);
  int err = GNUNET_NETWORK_socket_bind (dnsout6,
                                        (struct sockaddr *) &addr,
                                        sizeof (struct sockaddr_in6));

  if (err != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not bind to port %u: %s\n"),
		(unsigned int) dnsoutport,
		STRERROR (errno));
    GNUNET_NETWORK_socket_close (dnsout6);
    dnsout6 = NULL;
    return GNUNET_SYSERR;
  }
  if (0 == dnsoutport)
  {
    addrlen = sizeof (struct sockaddr_in6);
    if (0 != getsockname (GNUNET_NETWORK_get_fd (dnsout6), 
			  (struct sockaddr *) &addr,
			  &addrlen))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  _("Could not determine port I got: %s\n"),
		  STRERROR (errno));
      GNUNET_NETWORK_socket_close (dnsout6);
      dnsout6 = NULL;
      return GNUNET_SYSERR;
    }
  }
  dnsoutport = htons (addr.sin6_port);
  read6_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					      dnsout6,
					      &read_response, dnsout6);
  return GNUNET_YES;
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
		    const struct GNUNET_MessageHeader *message GNUNET_UNUSED)
{
  struct ClientRecord *cr;

  cr = GNUNET_malloc (sizeof (struct ClientRecord));
  cr->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (clients_head,
			       clients_tail,
			       cr);
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
			const struct GNUNET_MessageHeader *message GNUNET_UNUSED)
{
  // FIXME: validate and parse response, process response
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions with this signature are called whenever a complete
 * message is received by the tokenizer from the DNS hijack process.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, a DNS request we should handle
 */
static void
process_helper_messages (void *cls, void *client,
			 const struct GNUNET_MessageHeader *message)
{
  /* FIXME: parse message, create record, start processing! */
  /* FIXME: put request into queue for clients / system DNS */
  request_id_gen++;
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
    {&handle_client_init, NULL, GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT, sizeof (struct GNUNET_MessageHeader)},
    {&handle_client_response, NULL, GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE, 0},
    {NULL, NULL, 0, 0}
  };
  char port_s[6];
  char *ifc_name;
  char *ipv4addr;
  char *ipv4mask;
  char *ipv6addr;
  char *ipv6prefix;

  cfg = cfg_;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                cls);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg_, "dns", "PROVIDE_EXIT"))
  {
    if ( (GNUNET_OK != open_port4 ()) &&
	 (GNUNET_OK != open_port6 ()) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to open any port to provide DNS exit\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }

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
	GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6ADDR",
					       &ipv6addr)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[2] = ipv6addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6PREFIX",
                                             &ipv6prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[3] = ipv6prefix;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4ADDR",
                                             &ipv4addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[4] = ipv4addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4MASK",
                                             &ipv4mask))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4MASK' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_argv[5] = ipv4mask;
  GNUNET_snprintf (port_s, 
		   sizeof (port_s), 
		   "%u", 
		   (unsigned int) dnsoutport);
  helper_argv[6] = GNUNET_strdup (port_s);
  helper_argv[7] = NULL;
  hijacker = GNUNET_HELPER_start ("gnunet-helper-dns",
				  helper_argv,
				  &process_helper_messages,
				  NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
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
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "dns", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


/* end of gnunet-service-dns_new.c */
