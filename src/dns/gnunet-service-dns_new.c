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
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_signatures.h"
#include "dns_new.h"


/**
 * Entry we keep for each active request.
 */ 
struct RequestRecord
{


  /**
   * Entry of this request record in the heap (for fast removal).
   */
  struct GNUNET_CONTAINER_HeapNode *hentry;

  /**
   * Array of clients and their answers.
   */ 
  struct GNUNET_SERVER_Client *client;

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
 * Hash map of open requests.
 */
static struct GNUNET_CONTAINER_MultiHashMap *request_map;

/**
 * Heap with open requests (sorted by time received, oldest on top).
 */
static struct GNUNET_CONTAINER_Heap *request_heap;



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
    GNUNET_NETWORK_socket_destroy (dnsout4);
    dnsout4 = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != read4_task)
  {
    GNUNET_SCHEDULER_cancel (read4_task);
    read4_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != dnsout6)
  {
    GNUNET_NETWORK_socket_destroy (dnsout6);
    dnsout6 = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != read6_task)
  {
    GNUNET_SCHEDULER_cancel (read6_task);
    read6_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != request_heap)
  {
    while (NULL != (rr = GNUNET_CONTAINER_heap_remove_root (request_heap)))
    {
      // FIXME: free rest of 'rr'
      GNUNET_free (rr);
    }
    GNUNET_CONTAINER_heap_destroy (request_heap);
    request_heap = NULL;
  }
  if (NULL != request_map)
  {
    GNUNET_CONTAINER_multihashmap_destroy (request_map);
    request_map = NULL;
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

  /* FIXME: clean up after client */
  for (cr = clients_head; NULL != cr; cr = cr->next)
  {
    if (cr->client == client)
    {
      GNUNET_SERVER_client_drop (client);
      GNUNET_CONTAINER_DLL_remove (clients_head,
				   clients_tail,
				   cr);
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
    GNUNET_NETWORK_socket_destroy (dnsout4);
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
    GNUNET_NETWORK_socket_destroy (dnsout4);
    dnsout4 = NULL;
    return GNUNET_SYSERR;
  }
  dnsoutport = htons (addr.sin_port);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("GNUnet DNS will exit on source port %u\n"),
	      (unsigned int) dnsoutport);
  read4_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, 
					      dnsout,
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
      GNUNET_NETWORK_socket_destroy (dnsout6);
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
  char *virt_dns;
  struct GNUNET_OS_Process *proc;
  char *ifc_name;
  char *ipv4_addr;
  char *ipv4_mask;
  char *ipv6_addr;
  char *ipv6_mask;

  cfg = cfg_;
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

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dns", "VIRTIFC", &ifc_name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'VIRTDNS' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  /* FIXME: get all config options we need here! */
  request_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  request_map = GNUNET_CONTAINER_multihashmap_create (1024 * 16);
  GNUNET_snprintf (port_s, 
		   sizeof (port_s), 
		   "%u", 
		   (unsigned int) dnsoutport);
  helper_argv[0] = GNUNET_strdup ("gnunet-dns");
  helper_argv[1] = ifc_name;
  helper_argv[2] = ipv6_addr;
  helper_argv[3] = ipv6_mask;
  helper_argv[4] = ipv4_addr;
  helper_argv[5] = ipv4_mask;
  helper_argv[6] = GNUNET_strdup (port_s);
  helper_argv[7] = NULL;
  hijacker = GNUNET_HELPER_start ("gnunet-helper-dns",
				  helper_argv,
				  &process_helper_messages,
				  NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                cls);
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
