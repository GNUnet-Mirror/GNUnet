/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * This code provides some support for doing STUN transactions.
 * We send simplest possible packet ia REQUEST with BIND to a STUN server.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 *
 * This code was based on ministun.c.
 *
 * @file nat/nat_api_stun.c
 * @brief Functions for STUN functionality
 * @author Bruno Souza Cabral
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_lib.h"


#include "nat_stun.h"

#define LOG(kind,...) GNUNET_log_from (kind, "stun", __VA_ARGS__)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_NAT_STUN_Handle
{

  /**
   * Handle to a pending DNS lookup request.
   */
  struct GNUNET_RESOLVER_RequestHandle *dns_active;

  /**
   * Handle to the listen socket
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Stun server address
   */
  char *stun_server;

  /**
   * Function to call when a error occours
   */
  GNUNET_NAT_STUN_ErrorCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Do we got a DNS resolution successfully?
   */
  int dns_success;

  /**
   * STUN port
   */
  uint16_t stun_port;

};


/**
 * Encode a class and method to a compatible STUN format
 *
 * @param msg_class class to be converted
 * @param method method to be converted
 * @return message in a STUN compatible format
 */
static int
encode_message (enum StunClasses msg_class,
                enum StunMethods method)
{
  return ((msg_class & 1) << 4) | ((msg_class & 2) << 7) |
    (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f800) << 2);
}


/**
 * Fill the stun_header with a random request_id
 *
 * @param req, stun header to be filled
 */
static void
generate_request_id (struct stun_header *req)
{
  req->magic = htonl(STUN_MAGIC_COOKIE);
  for (unsigned int x = 0; x < 3; x++)
    req->id.id[x] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT32_MAX);
}


/**
 * Try to establish a connection given the specified address.
 *
 * @param cls our `struct GNUNET_NAT_STUN_Handle *`
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of @a addr
 */
static void
stun_dns_callback (void *cls,
                   const struct sockaddr *addr,
                   socklen_t addrlen)
{
  struct GNUNET_NAT_STUN_Handle *rh = cls;
  struct stun_header req;
  struct sockaddr_in server;

  if (NULL == addr)
  {
    rh->dns_active = NULL;
    if (GNUNET_NO == rh->dns_success)
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Error resolving host %s\n",
           rh->stun_server);
      rh->cb (rh->cb_cls,
              GNUNET_NAT_ERROR_NOT_ONLINE);
    }
    else if (GNUNET_SYSERR == rh->dns_success)
    {
      rh->cb (rh->cb_cls,
	      GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR);
    }
    else
    {
      rh->cb (rh->cb_cls,
	      GNUNET_NAT_ERROR_SUCCESS);
    }
    GNUNET_NAT_stun_make_request_cancel (rh);
    return;
  }

  rh->dns_success = GNUNET_YES;
  memset (&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr = ((struct sockaddr_in *)addr)->sin_addr;
  server.sin_port = htons (rh->stun_port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  server.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif

  /* Craft the simplest possible STUN packet. A request binding */
  generate_request_id (&req);
  req.msglen = htons (0);
  req.msgtype = htons (encode_message (STUN_REQUEST,
				       STUN_BINDING));

  /* Send the packet */
  if (-1 ==
      GNUNET_NETWORK_socket_sendto (rh->sock,
				    &req,
				    sizeof (req),
				    (const struct sockaddr *) &server,
				    sizeof (server)))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "sendto");
    rh->dns_success = GNUNET_SYSERR;
    return;
  }
}


/**
 * Make Generic STUN request. Sends a generic stun request to the
 * server specified using the specified socket.  
 *
 * @param server the address of the stun server
 * @param port port of the stun server, in host byte order
 * @param sock the socket used to send the request
 * @param cb callback in case of error
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_NAT_STUN_Handle *
GNUNET_NAT_stun_make_request (const char *server,
                              uint16_t port,
                              struct GNUNET_NETWORK_Handle *sock,
                              GNUNET_NAT_STUN_ErrorCallback cb,
                              void *cb_cls)
{
  struct GNUNET_NAT_STUN_Handle *rh;

  rh = GNUNET_new (struct GNUNET_NAT_STUN_Handle);
  rh->sock = sock;
  rh->cb = cb;
  rh->cb_cls = cb_cls;
  rh->stun_server = GNUNET_strdup (server);
  rh->stun_port = port;
  rh->dns_success = GNUNET_NO;
  rh->dns_active = GNUNET_RESOLVER_ip_get (rh->stun_server,
                                           AF_INET,
                                           TIMEOUT,
                                           &stun_dns_callback,
					   rh);
  if (NULL == rh->dns_active)
  {
    GNUNET_NAT_stun_make_request_cancel (rh);
    return NULL;
  }
  return rh;
}


/**
 * Cancel active STUN request. Frees associated resources
 * and ensures that the callback is no longer invoked.
 *
 * @param rh request to cancel
 */
void
GNUNET_NAT_stun_make_request_cancel (struct GNUNET_NAT_STUN_Handle *rh)
{
  if (NULL != rh->dns_active)
  {
    GNUNET_RESOLVER_request_cancel (rh->dns_active);
    rh->dns_active = NULL;
  }
  GNUNET_free (rh->stun_server);
  GNUNET_free (rh);
}


/* end of nat_stun.c */
