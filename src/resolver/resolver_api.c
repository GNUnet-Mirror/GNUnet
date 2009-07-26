/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file resolver/resolver_api.c
 * @brief resolver for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "resolver.h"


struct GetAddressContext
{
  GNUNET_RESOLVER_AddressCallback callback;
  void *cls;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_TIME_Absolute timeout;
};



/**
 * Convert IP address to string without DNS resolution.
 */
static char *
no_resolve (const struct sockaddr *sa, socklen_t salen)
{
  char *ret;
  char inet4[INET_ADDRSTRLEN];
  char inet6[INET6_ADDRSTRLEN];

  if (salen < sizeof (struct sockaddr))
    return NULL;
  switch (sa->sa_family)
    {
    case AF_INET:
      if (salen != sizeof (struct sockaddr_in))
        return NULL;
      inet_ntop (AF_INET,
                 &((struct sockaddr_in *) sa)->sin_addr,
                 inet4, INET_ADDRSTRLEN);
      ret = GNUNET_strdup (inet4);
      break;
    case AF_INET6:
      if (salen != sizeof (struct sockaddr_in6))
        return NULL;
      inet_ntop (AF_INET6,
                 &((struct sockaddr_in6 *) sa)->sin6_addr,
                 inet6, INET6_ADDRSTRLEN);
      ret = GNUNET_strdup (inet6);
      break;
    default:
      ret = NULL;
      break;
    }
  return ret;
}


static void
handle_address_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GetAddressContext *gac = cls;
  uint16_t size;
  const struct sockaddr *sa;
  socklen_t salen;


  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Timeout trying to resolve hostname.\n"));
      gac->callback (gac->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (gac->client);
      GNUNET_free (gac);
      return;
    }
  if (GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE != ntohs (msg->type))
    {
      GNUNET_break (0);
      gac->callback (gac->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (gac->client);
      GNUNET_free (gac);
      return;
    }

  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received end message resolving hostname.\n"));
#endif
      gac->callback (gac->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (gac->client);
      GNUNET_free (gac);
      return;
    }
  sa = (const struct sockaddr *) &msg[1];
  salen = size - sizeof (struct GNUNET_MessageHeader);
  if (salen < sizeof (struct sockaddr))
    {
      GNUNET_break (0);
      gac->callback (gac->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (gac->client);
      GNUNET_free (gac);
      return;
    }
#if DEBUG_RESOLVER
  {
    char *ips = no_resolve (sa, salen);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Resolver returns `%s'.\n"), ips);
    GNUNET_free (ips);
  }
#endif
  gac->callback (gac->cls, sa, salen);
  GNUNET_CLIENT_receive (gac->client,
                         &handle_address_response,
                         gac,
                         GNUNET_TIME_absolute_get_remaining (gac->timeout));
}


static size_t
transmit_get_ip (void *cls, size_t size, void *buf)
{
  struct GetAddressContext *actx = cls;
  uint16_t ms;

  if (buf == NULL)
    {
      /* timeout / error */
      GNUNET_free (actx->msg);
      actx->callback (actx->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (actx->client);
      GNUNET_free (actx);
      return 0;
    }
  ms = ntohs (actx->msg->header.size);
  GNUNET_assert (size >= ms);
  memcpy (buf, actx->msg, ms);
  GNUNET_free (actx->msg);
  actx->msg = NULL;
  GNUNET_CLIENT_receive (actx->client,
                         &handle_address_response,
                         actx,
                         GNUNET_TIME_absolute_get_remaining (actx->timeout));
  return ms;
}



/**
 * Convert a string to one or more IP addresses.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param hostname the hostname to resolve
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param cls closure for callback
 * @param timeout how long to try resolving
 */
void
GNUNET_RESOLVER_ip_get (struct GNUNET_SCHEDULER_Handle *sched,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const char *hostname,
                        int domain,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_RESOLVER_AddressCallback callback, void *cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GetAddressContext *actx;
  size_t slen;

  slen = strlen (hostname) + 1;
  if (slen + sizeof (struct GNUNET_RESOLVER_GetMessage) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      callback (cls, NULL, 0);
      return;
    }
  client = GNUNET_CLIENT_connect (sched, "resolver", cfg);
  if (client == NULL)
    {
      callback (cls, NULL, 0);
      return;
    }
  msg = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_GetMessage) + slen);
  msg->header.size =
    htons (sizeof (struct GNUNET_RESOLVER_GetMessage) + slen);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST);
  msg->direction = htonl (GNUNET_NO);
  msg->domain = htonl (domain);
  memcpy (&msg[1], hostname, slen);
  actx = GNUNET_malloc (sizeof (struct GetAddressContext));
  actx->callback = callback;
  actx->cls = cls;
  actx->client = client;
  actx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  actx->msg = msg;

#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolver requests DNS resolution of hostname `%s'.\n"),
              hostname);
#endif
  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (client,
                                           slen +
                                           sizeof (struct
                                                   GNUNET_RESOLVER_GetMessage),
                                           timeout, &transmit_get_ip, actx))
    {
      GNUNET_free (msg);
      GNUNET_free (actx);
      callback (cls, NULL, 0);
      GNUNET_CLIENT_disconnect (client);
      return;
    }
}


struct GetHostnameContext
{
  GNUNET_RESOLVER_HostnameCallback callback;
  void *cls;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_TIME_Absolute timeout;
};


static void
handle_hostname_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GetHostnameContext *ghc = cls;
  uint16_t size;
  const char *hostname;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Timeout trying to resolve IP address.\n"));
      ghc->callback (ghc->cls, NULL);
      GNUNET_CLIENT_disconnect (ghc->client);
      GNUNET_free (ghc);
      return;
    }
  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received end message resolving IP address.\n"));
#endif
      ghc->callback (ghc->cls, NULL);
      GNUNET_CLIENT_disconnect (ghc->client);
      GNUNET_free (ghc);
      return;
    }
  hostname = (const char *) &msg[1];
  if (hostname[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
    {
      GNUNET_break (0);
      ghc->callback (ghc->cls, NULL);
      GNUNET_CLIENT_disconnect (ghc->client);
      GNUNET_free (ghc);
      return;
    }
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolver returns `%s'.\n"), hostname);
#endif
  ghc->callback (ghc->cls, hostname);
  GNUNET_CLIENT_receive (ghc->client,
                         &handle_hostname_response,
                         ghc,
                         GNUNET_TIME_absolute_get_remaining (ghc->timeout));
}


static size_t
transmit_get_hostname (void *cls, size_t size, void *buf)
{
  struct GetHostnameContext *hctx = cls;
  uint16_t msize;

  if (buf == NULL)
    {
      GNUNET_free (hctx->msg);
      hctx->callback (hctx->cls, NULL);
      GNUNET_CLIENT_disconnect (hctx->client);
      GNUNET_free (hctx);
      return 0;
    }
  msize = ntohs (hctx->msg->header.size);
  GNUNET_assert (size >= msize);
  memcpy (buf, hctx->msg, msize);
  GNUNET_free (hctx->msg);
  hctx->msg = NULL;
  GNUNET_CLIENT_receive (hctx->client,
                         &handle_hostname_response,
                         hctx,
                         GNUNET_TIME_absolute_get_remaining (hctx->timeout));
  return msize;
}




/**
 * Get an IP address as a string.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param sa host address
 * @param salen length of host address
 * @param do_resolve use GNUNET_NO to return numeric hostname
 * @param timeout how long to try resolving
 * @param callback function to call with hostnames
 * @param cls closure for callback
 */
void
GNUNET_RESOLVER_hostname_get (struct GNUNET_SCHEDULER_Handle *sched,
                              const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct sockaddr *sa,
                              socklen_t salen,
                              int do_resolve,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_RESOLVER_HostnameCallback callback,
                              void *cls)
{
  char *result;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GetHostnameContext *hctx;

  if (GNUNET_NO == do_resolve)
    {
      result = no_resolve (sa, salen);
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Resolver returns `%s'.\n"), result);
#endif
      callback (cls, result);
      if (result != NULL)
        {
          GNUNET_free (result);
          callback (cls, NULL);
        }
      return;
    }
  if (salen + sizeof (struct GNUNET_RESOLVER_GetMessage) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      callback (cls, NULL);
      return;
    }
  client = GNUNET_CLIENT_connect (sched, "resolver", cfg);
  if (client == NULL)
    {
      callback (cls, NULL);
      return;
    }
  msg = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_GetMessage) + salen);
  msg->header.size =
    htons (sizeof (struct GNUNET_RESOLVER_GetMessage) + salen);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST);
  msg->direction = htonl (GNUNET_YES);
  msg->domain = htonl (sa->sa_family);
  memcpy (&msg[1], sa, salen);
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolver requests DNS resolution of IP address.\n"));
#endif
  hctx = GNUNET_malloc (sizeof (struct GetHostnameContext));
  hctx->callback = callback;
  hctx->cls = cls;
  hctx->client = client;
  hctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  hctx->msg = msg;
  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (client,
                                           sizeof (struct
                                                   GNUNET_RESOLVER_GetMessage)
                                           + salen, timeout,
                                           &transmit_get_hostname, hctx))
    {
      GNUNET_free (msg);
      callback (cls, NULL);
      GNUNET_CLIENT_disconnect (client);
      GNUNET_free (hctx);
    }
}

/**
 * Maximum supported length of hostname
 */
#define MAX_HOSTNAME 1024


/**
 * Resolve our hostname to an IP address.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param cls closure for callback
 * @param timeout how long to try resolving
 */
void
GNUNET_RESOLVER_hostname_resolve (struct GNUNET_SCHEDULER_Handle *sched,
                                  const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  int domain,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_RESOLVER_AddressCallback callback,
                                  void *cls)
{
  char hostname[MAX_HOSTNAME];

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR |
                           GNUNET_ERROR_TYPE_BULK, "gethostname");
      callback (cls, NULL, 0);
      return;
    }
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolving our hostname `%s'\n"), hostname);
#endif
  GNUNET_RESOLVER_ip_get (sched,
                          cfg, hostname, domain, timeout, callback, cls);
}




/* end of resolver_api.c */
