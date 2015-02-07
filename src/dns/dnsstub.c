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
 * @file dns/dnsstub.c
 * @brief DNS stub resolver which sends DNS requests to an actual resolver
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsstub_lib.h"

/**
 * Timeout for an external (Internet-DNS) DNS resolution
 */
#define REQUEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How many DNS sockets do we open at most at the same time?
 * (technical socket maximum is this number x2 for IPv4+IPv6)
 */
#define DNS_SOCKET_MAX 128


/**
 * UDP socket we are using for sending DNS requests to the Internet.
 */
struct GNUNET_DNSSTUB_RequestSocket
{

  /**
   * UDP socket we use for this request for IPv4
   */
  struct GNUNET_NETWORK_Handle *dnsout4;

  /**
   * UDP socket we use for this request for IPv6
   */
  struct GNUNET_NETWORK_Handle *dnsout6;

  /**
   * Function to call with result.
   */
  GNUNET_DNSSTUB_ResultCallback rc;

  /**
   * Closure for @e rc.
   */
  void *rc_cls;

  /**
   * Task for reading from dnsout4 and dnsout6.
   */
  struct GNUNET_SCHEDULER_Task * read_task;

  /**
   * When should this request time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Address we sent the DNS request to.
   */
  struct sockaddr_storage addr;

  /**
   * Number of bytes in @e addr.
   */
  socklen_t addrlen;

};


/**
 * Handle to the stub resolver.
 */
struct GNUNET_DNSSTUB_Context
{

  /**
   * Array of all open sockets for DNS requests.
   */
  struct GNUNET_DNSSTUB_RequestSocket sockets[DNS_SOCKET_MAX];

  /**
   * IP address to use for the DNS server if we are a DNS exit service
   * (for VPN via cadet); otherwise NULL.
   */
  char *dns_exit;
};



/**
 * We're done with a `struct GNUNET_DNSSTUB_RequestSocket`, close it for now.
 *
 * @param rs request socket to clean up
 */
static void
cleanup_rs (struct GNUNET_DNSSTUB_RequestSocket *rs)
{
  if (NULL != rs->dnsout4)
  {
    GNUNET_NETWORK_socket_close (rs->dnsout4);
    rs->dnsout4 = NULL;
  }
  if (NULL != rs->dnsout6)
  {
    GNUNET_NETWORK_socket_close (rs->dnsout6);
    rs->dnsout6 = NULL;
  }
  if (NULL != rs->read_task)
  {
    GNUNET_SCHEDULER_cancel (rs->read_task);
    rs->read_task = NULL;
  }
}


/**
 * Open source port for sending DNS requests
 *
 * @param af AF_INET or AF_INET6
 * @return #GNUNET_OK on success
 */
static struct GNUNET_NETWORK_Handle *
open_socket (int af)
{
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  struct sockaddr *sa;
  socklen_t alen;
  struct GNUNET_NETWORK_Handle *ret;

  ret = GNUNET_NETWORK_socket_create (af, SOCK_DGRAM, 0);
  if (NULL == ret)
    return NULL;
  switch (af)
  {
  case AF_INET:
    memset (&a4, 0, alen = sizeof (struct sockaddr_in));
    sa = (struct sockaddr *) &a4;
    break;
  case AF_INET6:
    memset (&a6, 0, alen = sizeof (struct sockaddr_in6));
    sa = (struct sockaddr *) &a6;
    break;
  default:
    GNUNET_break (0);
    GNUNET_NETWORK_socket_close (ret);
    return NULL;
  }
  sa->sa_family = af;
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (ret,
					       sa,
					       alen))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not bind to any port: %s\n"),
		STRERROR (errno));
    GNUNET_NETWORK_socket_close (ret);
    return NULL;
  }
  return ret;
}


/**
 * Read a DNS response from the (unhindered) UDP-Socket
 *
 * @param cls socket to read from
 * @param tc scheduler context (must be shutdown or read ready)
 */
static void
read_response (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Get a socket of the specified address family to send out a
 * UDP DNS request to the Internet.
 *
 * @param ctx the DNSSTUB context
 * @param af desired address family
 * @return NULL on error (given AF not "supported")
 */
static struct GNUNET_DNSSTUB_RequestSocket *
get_request_socket (struct GNUNET_DNSSTUB_Context *ctx,
		    int af)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs;
  struct GNUNET_NETWORK_FDSet *rset;

  rs = &ctx->sockets[GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
					       DNS_SOCKET_MAX)];
  rs->timeout = GNUNET_TIME_relative_to_absolute (REQUEST_TIMEOUT);
  switch (af)
  {
  case AF_INET:
    if (NULL == rs->dnsout4)
      rs->dnsout4 = open_socket (AF_INET);
    break;
  case AF_INET6:
    if (NULL == rs->dnsout6)
      rs->dnsout6 = open_socket (AF_INET6);
    break;
  default:
    return NULL;
  }
  if (NULL != rs->read_task)
  {
    GNUNET_SCHEDULER_cancel (rs->read_task);
    rs->read_task = NULL;
  }
  if ( (NULL == rs->dnsout4) &&
       (NULL == rs->dnsout6) )
    return NULL;
  rset = GNUNET_NETWORK_fdset_create ();
  if (NULL != rs->dnsout4)
    GNUNET_NETWORK_fdset_set (rset, rs->dnsout4);
  if (NULL != rs->dnsout6)
    GNUNET_NETWORK_fdset_set (rset, rs->dnsout6);
  rs->read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					       REQUEST_TIMEOUT,
					       rset,
					       NULL,
					       &read_response, rs);
  GNUNET_NETWORK_fdset_destroy (rset);
  return rs;
}


/**
 * Perform DNS resolution.
 *
 * @param ctx stub resolver to use
 * @param sa the socket address
 * @param sa_len the socket length
 * @param request DNS request to transmit
 * @param request_len number of bytes in msg
 * @param rc function to call with result
 * @param rc_cls closure for 'rc'
 * @return socket used for the request, NULL on error
 */
struct GNUNET_DNSSTUB_RequestSocket *
GNUNET_DNSSTUB_resolve (struct GNUNET_DNSSTUB_Context *ctx,
			const struct sockaddr *sa,
			socklen_t sa_len,
			const void *request,
			size_t request_len,
			GNUNET_DNSSTUB_ResultCallback rc,
			void *rc_cls)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs;
  struct GNUNET_NETWORK_Handle *ret;
  int af;

  af = sa->sa_family;
  if (NULL == (rs = get_request_socket (ctx, af)))
    return NULL;
  if (NULL != rs->dnsout4)
    ret = rs->dnsout4;
  else
    ret = rs->dnsout6;
  GNUNET_assert (NULL != ret);
  memcpy (&rs->addr,
	  sa,
	  sa_len);
  rs->addrlen = sa_len;
  rs->rc = rc;
  rs->rc_cls = rc_cls;
  if (GNUNET_SYSERR ==
      GNUNET_NETWORK_socket_sendto (ret,
				    request,
				    request_len,
				    sa,
				    sa_len))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to send DNS request to %s\n"),
		GNUNET_a2s (sa, sa_len));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		_("Sent DNS request to %s\n"),
		GNUNET_a2s (sa, sa_len));
  return rs;
}


/**
 * Perform DNS resolution using our default IP from init.
 *
 * @param ctx stub resolver to use
 * @param request DNS request to transmit
 * @param request_len number of bytes in msg
 * @param rc function to call with result
 * @param rc_cls closure for 'rc'
 * @return socket used for the request, NULL on error
 */
struct GNUNET_DNSSTUB_RequestSocket *
GNUNET_DNSSTUB_resolve2 (struct GNUNET_DNSSTUB_Context *ctx,
			 const void *request,
			 size_t request_len,
			 GNUNET_DNSSTUB_ResultCallback rc,
			 void *rc_cls)
{
  int af;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  struct sockaddr *sa;
  socklen_t salen;
  struct GNUNET_NETWORK_Handle *dnsout;
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  memset (&v4, 0, sizeof (v4));
  memset (&v6, 0, sizeof (v6));
  if (1 == inet_pton (AF_INET, ctx->dns_exit, &v4.sin_addr))
  {
    salen = sizeof (v4);
    v4.sin_family = AF_INET;
    v4.sin_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4.sin_len = (u_char) salen;
#endif
    sa = (struct sockaddr *) &v4;
    af = AF_INET;
  }
  else if (1 == inet_pton (AF_INET6, ctx->dns_exit, &v6.sin6_addr))
  {
    salen = sizeof (v6);
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6.sin6_len = (u_char) salen;
#endif
    sa = (struct sockaddr *) &v6;
    af = AF_INET6;
  }
  else
  {
    GNUNET_break (0);
    return NULL;
  }
  if (NULL == (rs = get_request_socket (ctx, af)))
    return NULL;
  if (NULL != rs->dnsout4)
    dnsout = rs->dnsout4;
  else
    dnsout = rs->dnsout6;
  if (NULL == dnsout)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Configured DNS exit `%s' is not working / valid.\n"),
		ctx->dns_exit);
    return NULL;
  }
  memcpy (&rs->addr,
	  sa,
	  salen);
  rs->addrlen = salen;
  rs->rc = rc;
  rs->rc_cls = rc_cls;
  if (GNUNET_SYSERR ==
      GNUNET_NETWORK_socket_sendto (dnsout,
				    request,
				    request_len, sa, salen))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to send DNS request to %s\n"),
		GNUNET_a2s (sa, salen));
  rs->timeout = GNUNET_TIME_relative_to_absolute (REQUEST_TIMEOUT);

  return rs;

}


/**
 * Actually do the reading of a DNS packet from our UDP socket and see
 * if we have a valid, matching, pending request.
 *
 * @param rs request socket with callback details
 * @param dnsout socket to read from
 * @return #GNUNET_OK on success, #GNUNET_NO on drop, #GNUNET_SYSERR on IO-errors (closed socket)
 */
static int
do_dns_read (struct GNUNET_DNSSTUB_RequestSocket *rs,
	     struct GNUNET_NETWORK_Handle *dnsout)
{
  struct sockaddr_storage addr;
  socklen_t addrlen;
  struct GNUNET_TUN_DnsHeader *dns;
  ssize_t r;
  int len;

#ifndef MINGW
  if (0 != ioctl (GNUNET_NETWORK_get_fd (dnsout), FIONREAD, &len))
  {
    /* conservative choice: */
    len = UINT16_MAX;
  }
#else
  /* port the code above? */
  len = UINT16_MAX;
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Receiving %d byte DNS reply\n",
	      len);
  {
    unsigned char buf[len] GNUNET_ALIGN;

    addrlen = sizeof (addr);
    memset (&addr, 0, sizeof (addr));
    r = GNUNET_NETWORK_socket_recvfrom (dnsout,
					buf, sizeof (buf),
					(struct sockaddr*) &addr, &addrlen);
    if (-1 == r)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "recvfrom");
      GNUNET_NETWORK_socket_close (dnsout);
      return GNUNET_SYSERR;
    }
    if (sizeof (struct GNUNET_TUN_DnsHeader) > r)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Received DNS response that is too small (%u bytes)"),
		  r);
      return GNUNET_NO;
    }
    dns = (struct GNUNET_TUN_DnsHeader *) buf;
    if ( (addrlen != rs->addrlen) ||
	 (0 != memcmp (&rs->addr,
		       &addr,
		       addrlen)) ||
       (0 == GNUNET_TIME_absolute_get_remaining (rs->timeout).rel_value_us) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Request timeout or invalid sender address; ignoring reply\n");
      return GNUNET_NO;
    }
    if (NULL != rs->rc)
      rs->rc (rs->rc_cls,
	      rs,
	      dns,
	      r);
  }
  return GNUNET_OK;
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
  struct GNUNET_DNSSTUB_RequestSocket *rs = cls;
  struct GNUNET_NETWORK_FDSet *rset;

  rs->read_task = NULL;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    /* timeout or shutdown */
    cleanup_rs (rs);
    return;
  }
  /* read and process ready sockets */
  if ((NULL != rs->dnsout4) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, rs->dnsout4)) &&
      (GNUNET_SYSERR == do_dns_read (rs, rs->dnsout4)))
    rs->dnsout4 = NULL;
  if ((NULL != rs->dnsout6) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, rs->dnsout6)) &&
      (GNUNET_SYSERR == do_dns_read (rs, rs->dnsout6)))
    rs->dnsout6 = NULL;

  /* re-schedule read task */
  rset = GNUNET_NETWORK_fdset_create ();
  if (NULL != rs->dnsout4)
    GNUNET_NETWORK_fdset_set (rset, rs->dnsout4);
  if (NULL != rs->dnsout6)
    GNUNET_NETWORK_fdset_set (rset, rs->dnsout6);
  rs->read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					       GNUNET_TIME_absolute_get_remaining (rs->timeout),
					       rset,
					       NULL,
					       &read_response, rs);
  GNUNET_NETWORK_fdset_destroy (rset);
}


/**
 * Cancel DNS resolution.
 *
 * @param rs resolution to cancel
 */
void
GNUNET_DNSSTUB_resolve_cancel (struct GNUNET_DNSSTUB_RequestSocket *rs)
{
  rs->rc = NULL;
}


/**
 * Start a DNS stub resolver.
 *
 * @param dns_ip target IP address to use
 * @return NULL on error
 */
struct GNUNET_DNSSTUB_Context *
GNUNET_DNSSTUB_start (const char *dns_ip)
{
  struct GNUNET_DNSSTUB_Context *ctx;

  ctx = GNUNET_new (struct GNUNET_DNSSTUB_Context);
  if (NULL != dns_ip)
    ctx->dns_exit = GNUNET_strdup (dns_ip);
  return ctx;
}


/**
 * Cleanup DNSSTUB resolver.
 *
 * @param ctx stub resolver to clean up
 */
void
GNUNET_DNSSTUB_stop (struct GNUNET_DNSSTUB_Context *ctx)
{
  unsigned int i;

  for (i=0;i<DNS_SOCKET_MAX;i++)
    cleanup_rs (&ctx->sockets[i]);
  if (NULL != ctx->dns_exit)
  {
    GNUNET_free (ctx->dns_exit);
    ctx->dns_exit = NULL;
  }
  GNUNET_free (ctx);
}


/* end of dnsstub.c */
