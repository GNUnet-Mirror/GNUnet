/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2018 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file dns/dnsstub.c
 * @brief DNS stub resolver which sends DNS requests to an actual resolver
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Timeout for retrying DNS queries.
 */
#define DNS_RETRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)


/**
 * DNS Server used for resolution.
 */
struct DnsServer;


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
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * Task for retrying transmission of the query.
   */
  struct GNUNET_SCHEDULER_Task *retry_task;

  /**
   * Next address we sent the DNS request to.
   */
  struct DnsServer *ds_pos;

  /**
   * Context this request executes in.
   */
  struct GNUNET_DNSSTUB_Context *ctx;

  /**
   * Query we sent to @e addr.
   */
  void *request;

  /**
   * Number of bytes in @a request.
   */
  size_t request_len;

};


/**
 * DNS Server used for resolution.
 */
struct DnsServer
{

  /**
   * Kept in a DLL.
   */
  struct DnsServer *next;

  /**
   * Kept in a DLL.
   */
  struct DnsServer *prev;

  /**
   * IP address of the DNS resolver.
   */
  struct sockaddr_storage ss;
};


/**
 * Handle to the stub resolver.
 */
struct GNUNET_DNSSTUB_Context
{

  /**
   * Array of all open sockets for DNS requests.
   */
  struct GNUNET_DNSSTUB_RequestSocket *sockets;

  /**
   * DLL of DNS resolvers we use.
   */
  struct DnsServer *dns_head;

  /**
   * DLL of DNS resolvers we use.
   */
  struct DnsServer *dns_tail;

  /**
   * How frequently do we retry requests?
   */
  struct GNUNET_TIME_Relative retry_freq;

  /**
   * Length of @e sockets array.
   */
  unsigned int num_sockets;

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
  if (NULL != rs->retry_task)
  {
    GNUNET_SCHEDULER_cancel (rs->retry_task);
    rs->retry_task = NULL;
  }
  if (NULL != rs->request)
  {
    GNUNET_free (rs->request);
    rs->request = NULL;
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
 * Get a socket of the specified address family to send out a
 * UDP DNS request to the Internet.
 *
 * @param ctx the DNSSTUB context
 * @return NULL on error
 */
static struct GNUNET_DNSSTUB_RequestSocket *
get_request_socket (struct GNUNET_DNSSTUB_Context *ctx)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  for (unsigned int i=0;i<256;i++)
  {
    rs = &ctx->sockets[GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                 ctx->num_sockets)];
    if (NULL == rs->rc)
      break;
  }
  if (NULL != rs->rc)
  {
    /* signal "failure" */
    rs->rc (rs->rc_cls,
            NULL,
            0);
    rs->rc = NULL;
  }
  if (NULL != rs->read_task)
  {
    GNUNET_SCHEDULER_cancel (rs->read_task);
    rs->read_task = NULL;
  }
  if (NULL != rs->retry_task)
  {
    GNUNET_SCHEDULER_cancel (rs->retry_task);
    rs->retry_task = NULL;
  }
  if (NULL != rs->request)
  {
    GNUNET_free (rs->request);
    rs->request = NULL;
  }
  rs->ctx = ctx;
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
  struct GNUNET_DNSSTUB_Context *ctx = rs->ctx;
  ssize_t r;
  int len;

#ifndef MINGW
  if (0 != ioctl (GNUNET_NETWORK_get_fd (dnsout),
                  FIONREAD,
                  &len))
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
    int found;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct GNUNET_TUN_DnsHeader *dns;

    addrlen = sizeof (addr);
    memset (&addr,
            0,
            sizeof (addr));
    r = GNUNET_NETWORK_socket_recvfrom (dnsout,
					buf,
                                        sizeof (buf),
					(struct sockaddr*) &addr,
                                        &addrlen);
    if (-1 == r)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                           "recvfrom");
      GNUNET_NETWORK_socket_close (dnsout);
      return GNUNET_SYSERR;
    }
    found = GNUNET_NO;
    for (struct DnsServer *ds = ctx->dns_head; NULL != ds; ds = ds->next)
    {
      if (0 == memcmp (&addr,
                       &ds->ss,
                       GNUNET_MIN (sizeof (struct sockaddr_storage),
                                   addrlen)))
      {
        found = GNUNET_YES;
        break;
      }
    }
    if (GNUNET_NO == found)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received DNS response from server we never asked (ignored)");
      return GNUNET_NO;
    }
    if (sizeof (struct GNUNET_TUN_DnsHeader) > (size_t) r)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Received DNS response that is too small (%u bytes)"),
		  (unsigned int) r);
      return GNUNET_NO;
    }
    dns = (struct GNUNET_TUN_DnsHeader *) buf;
    if (NULL == rs->rc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Request timeout or cancelled; ignoring reply\n");
      return GNUNET_NO;
    }
    rs->rc (rs->rc_cls,
            dns,
            r);
  }
  return GNUNET_OK;
}


/**
 * Read a DNS response from the (unhindered) UDP-Socket
 *
 * @param cls socket to read from
 */
static void
read_response (void *cls);


/**
 * Schedule #read_response() task for @a rs.
 *
 * @param rs request to schedule read operation for
 */
static void
schedule_read (struct GNUNET_DNSSTUB_RequestSocket *rs)
{
  struct GNUNET_NETWORK_FDSet *rset;

  if (NULL != rs->read_task)
    GNUNET_SCHEDULER_cancel (rs->read_task);
  rset = GNUNET_NETWORK_fdset_create ();
  if (NULL != rs->dnsout4)
    GNUNET_NETWORK_fdset_set (rset,
                              rs->dnsout4);
  if (NULL != rs->dnsout6)
    GNUNET_NETWORK_fdset_set (rset,
                              rs->dnsout6);
  rs->read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       rset,
					       NULL,
					       &read_response,
                                               rs);
  GNUNET_NETWORK_fdset_destroy (rset);
}


/**
 * Read a DNS response from the (unhindered) UDP-Socket
 *
 * @param cls `struct GNUNET_DNSSTUB_RequestSocket` to read from
 */
static void
read_response (void *cls)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  rs->read_task = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  /* read and process ready sockets */
  if ( (NULL != rs->dnsout4) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                    rs->dnsout4)) &&
       (GNUNET_SYSERR ==
        do_dns_read (rs,
                     rs->dnsout4)) )
    rs->dnsout4 = NULL;
  if ( (NULL != rs->dnsout6) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                    rs->dnsout6)) &&
       (GNUNET_SYSERR ==
        do_dns_read (rs,
                     rs->dnsout6)) )
    rs->dnsout6 = NULL;
  /* re-schedule read task */
  schedule_read (rs);
}


/**
 * Task to (re)transmit the DNS query, possibly repeatedly until
 * we succeed.
 *
 * @param cls our `struct GNUNET_DNSSTUB_RequestSocket *`
 */
static void
transmit_query (void *cls)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs = cls;
  struct GNUNET_DNSSTUB_Context *ctx = rs->ctx;
  const struct sockaddr *sa;
  socklen_t salen;
  struct DnsServer *ds;
  struct GNUNET_NETWORK_Handle *dnsout;

  rs->retry_task = GNUNET_SCHEDULER_add_delayed (ctx->retry_freq,
                                                 &transmit_query,
                                                 rs);
  ds = rs->ds_pos;
  rs->ds_pos = ds->next;
  if (NULL == rs->ds_pos)
    rs->ds_pos = ctx->dns_head;
  GNUNET_assert (NULL != ds);
  dnsout = NULL;
  switch (ds->ss.ss_family)
  {
  case AF_INET:
    if (NULL == rs->dnsout4)
      rs->dnsout4 = open_socket (AF_INET);
    dnsout = rs->dnsout4;
    sa = (const struct sockaddr *) &ds->ss;
    salen = sizeof (struct sockaddr_in);
    break;
  case AF_INET6:
    if (NULL == rs->dnsout6)
      rs->dnsout6 = open_socket (AF_INET6);
    dnsout = rs->dnsout6;
    sa = (const struct sockaddr *) &ds->ss;
    salen = sizeof (struct sockaddr_in6);
    break;
  default:
    return;
  }
  if (NULL == dnsout)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to use configure DNS server, skipping\n");
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_NETWORK_socket_sendto (dnsout,
				    rs->request,
				    rs->request_len,
                                    sa,
                                    salen))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to send DNS request to %s: %s\n"),
		GNUNET_a2s (sa,
                            salen),
                STRERROR (errno));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		_("Sent DNS request to %s\n"),
		GNUNET_a2s (sa,
                            salen));
  schedule_read (rs);
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
GNUNET_DNSSTUB_resolve (struct GNUNET_DNSSTUB_Context *ctx,
			 const void *request,
			 size_t request_len,
			 GNUNET_DNSSTUB_ResultCallback rc,
			 void *rc_cls)
{
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  if (NULL == ctx->dns_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No DNS server configured for resolution\n");
    return NULL;
  }
  if (NULL == (rs = get_request_socket (ctx)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No request socket available for DNS resolution\n");
    return NULL;
  }
  rs->ds_pos = ctx->dns_head;
  rs->rc = rc;
  rs->rc_cls = rc_cls;
  rs->request = GNUNET_memdup (request,
                               request_len);
  rs->request_len = request_len;
  rs->retry_task = GNUNET_SCHEDULER_add_now (&transmit_query,
                                             rs);
  return rs;
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
  if (NULL != rs->retry_task)
  {
    GNUNET_SCHEDULER_cancel (rs->retry_task);
    rs->retry_task = NULL;
  }
  if (NULL != rs->read_task)
  {
    GNUNET_SCHEDULER_cancel (rs->read_task);
    rs->read_task = NULL;
  }
}


/**
 * Start a DNS stub resolver.
 *
 * @param num_sockets how many sockets should we open
 *        in parallel for DNS queries for this stub?
 * @return NULL on error
 */
struct GNUNET_DNSSTUB_Context *
GNUNET_DNSSTUB_start (unsigned int num_sockets)
{
  struct GNUNET_DNSSTUB_Context *ctx;

  if (0 == num_sockets)
  {
    GNUNET_break (0);
    return NULL;
  }
  ctx = GNUNET_new (struct GNUNET_DNSSTUB_Context);
  ctx->num_sockets = num_sockets;
  ctx->sockets = GNUNET_new_array (num_sockets,
                                   struct GNUNET_DNSSTUB_RequestSocket);
  ctx->retry_freq = DNS_RETRANSMIT_DELAY;
  return ctx;
}


/**
 * Add nameserver for use by the DNSSTUB.  We will use
 * all provided nameservers for resolution (round-robin).
 *
 * @param ctx resolver context to modify
 * @param dns_ip target IP address to use (as string)
 * @return #GNUNET_OK on success
 */
int
GNUNET_DNSSTUB_add_dns_ip (struct GNUNET_DNSSTUB_Context *ctx,
                           const char *dns_ip)
{
  struct DnsServer *ds;
  struct in_addr i4;
  struct in6_addr i6;

  ds = GNUNET_new (struct DnsServer);
  if (1 == inet_pton (AF_INET,
                      dns_ip,
                      &i4))
  {
    struct sockaddr_in *s4 = (struct sockaddr_in *) &ds->ss;

    s4->sin_family = AF_INET;
    s4->sin_port = htons (53);
    s4->sin_addr = i4;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s4->sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
  }
  else if (1 == inet_pton (AF_INET6,
                           dns_ip,
                           &i6))
  {
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &ds->ss;

    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons (53);
    s6->sin6_addr = i6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s6->sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Malformed IP address `%s' for DNS server\n",
                dns_ip);
    GNUNET_free (ds);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_DLL_insert (ctx->dns_head,
                               ctx->dns_tail,
                               ds);
  return GNUNET_OK;
}


/**
 * Add nameserver for use by the DNSSTUB.  We will use
 * all provided nameservers for resolution (round-robin).
 *
 * @param ctx resolver context to modify
 * @param sa socket address of DNS resolver to use
 * @return #GNUNET_OK on success
 */
int
GNUNET_DNSSTUB_add_dns_sa (struct GNUNET_DNSSTUB_Context *ctx,
                           const struct sockaddr *sa)
{
  struct DnsServer *ds;

  ds = GNUNET_new (struct DnsServer);
  switch (sa->sa_family)
  {
  case AF_INET:
    GNUNET_memcpy (&ds->ss,
                   sa,
                   sizeof (struct sockaddr_in));
    break;
  case AF_INET6:
    GNUNET_memcpy (&ds->ss,
                   sa,
                   sizeof (struct sockaddr_in6));
    break;
  default:
    GNUNET_break (0);
    GNUNET_free (ds);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_DLL_insert (ctx->dns_head,
                               ctx->dns_tail,
                               ds);
  return GNUNET_OK;
}


/**
 * How long should we try requests before timing out?
 * Only effective for requests issued after this call.
 *
 * @param ctx resolver context to modify
 * @param retry_freq how long to wait between retries
 */
void
GNUNET_DNSSTUB_set_retry (struct GNUNET_DNSSTUB_Context *ctx,
                          struct GNUNET_TIME_Relative retry_freq)
{
  ctx->retry_freq = retry_freq;
}


/**
 * Cleanup DNSSTUB resolver.
 *
 * @param ctx stub resolver to clean up
 */
void
GNUNET_DNSSTUB_stop (struct GNUNET_DNSSTUB_Context *ctx)
{
  struct DnsServer *ds;

  while (NULL != (ds = ctx->dns_head))
  {
    GNUNET_CONTAINER_DLL_remove (ctx->dns_head,
                                 ctx->dns_tail,
                                 ds);
    GNUNET_free (ds);
  }
  for (unsigned int i=0;i<ctx->num_sockets;i++)
    cleanup_rs (&ctx->sockets[i]);
  GNUNET_free (ctx->sockets);
  GNUNET_free (ctx);
}


/* end of dnsstub.c */
