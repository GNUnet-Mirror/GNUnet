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
 * @file util/resolver_api.c
 * @brief resolver for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "resolver.h"


/**
 * Maximum supported length for a hostname
 */
#define MAX_HOSTNAME 1024


/**
 * Possible hostnames for "loopback".
 */
static const char *loopback[] = {
  "localhost",
  "ip6-localnet",
  NULL
};


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_RESOLVER_RequestHandle
{

  /**
   * Callback if this is an name resolution request,
   * otherwise NULL.
   */
  GNUNET_RESOLVER_AddressCallback addr_callback;

  /**
   * Callback if this is a reverse lookup request,
   * otherwise NULL.
   */
  GNUNET_RESOLVER_HostnameCallback name_callback;

  /**
   * Closure for the respective "callback".
   */
  void *cls;

  /**
   * Our connection to the resolver service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Name of the host that we are resolving.
   */
  const char *hostname;

  /**
   * When should this request time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task handle for numeric lookups.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Desired address family.
   */
  int domain;

  /**
   * Length of the "struct sockaddr" that follows this
   * struct (only for reverse lookup).
   */
  socklen_t salen;
};


/**
 * Check that the resolver service runs on localhost
 * (or equivalent).
 */
static void
check_config (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *hostname;
  unsigned int i;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

  memset (&v4, 0, sizeof (v4));
  v4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v4.sin_len = sizeof (v4);
#endif
  memset (&v6, 0, sizeof (v6));
  v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v6.sin6_len = sizeof (v6);
#endif
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "resolver",
                                             "HOSTNAME", &hostname))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Must specify `%s' for `%s' in configuration!\n"),
                  "HOSTNAME", "resolver");
      GNUNET_assert (0);
    }
  if ((1 != inet_pton (AF_INET,
                       hostname,
                       &v4)) || (1 != inet_pton (AF_INET6, hostname, &v6)))
    {
      GNUNET_free (hostname);
      return;
    }
  i = 0;
  while (loopback[i] != NULL)
    if (0 == strcasecmp (loopback[i++], hostname))
      {
        GNUNET_free (hostname);
        return;
      }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              _
              ("Must specify `%s' or numeric IP address for `%s' of `%s' in configuration!\n"),
              "localhost", "HOSTNAME", "resolver");
  GNUNET_free (hostname);
  GNUNET_assert (0);
}


/**
 * Convert IP address to string without DNS resolution.
 *
 * @param sa the address 
 * @param salen number of bytes in sa
 * @return address as a string, NULL on error
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


/**
 * Process the reply from the resolver (which is presumably
 * the numeric IP address for a name resolution request).
 *
 * @param cls the "GNUNET_RESOLVER_RequestHandle" for which this is a reply
 * @param msg reply from the resolver or NULL on error
 */
static void
handle_address_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  uint16_t size;
  const struct sockaddr *sa;
  socklen_t salen;


  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Timeout trying to resolve hostname `%s'.\n"),
		  rh->hostname);
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
  if (GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE != ntohs (msg->type))
    {
      GNUNET_break (0);
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }

  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received end message resolving hostname `%s'.\n"),
		  rh->hostname);
#endif
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
  sa = (const struct sockaddr *) &msg[1];
  salen = size - sizeof (struct GNUNET_MessageHeader);
  if (salen < sizeof (struct sockaddr))
    {
      GNUNET_break (0);
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
#if DEBUG_RESOLVER
  {
    char *ips = no_resolve (sa, salen);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Resolver returns `%s' for `%s'.\n", ips,
		rh->hostname);
    GNUNET_free (ips);
  }
#endif
  rh->addr_callback (rh->cls, sa, salen);
  GNUNET_CLIENT_receive (rh->client,
                         &handle_address_response,
                         rh,
                         GNUNET_TIME_absolute_get_remaining (rh->timeout));
}


/**
 * We've been asked to lookup the address for a hostname and were 
 * given a valid numeric string.  Perform the callbacks for the
 * numeric addresses.
 *
 * @param cls struct GNUNET_RESOLVER_RequestHandle for the request
 * @param tc unused scheduler context
 */
static void
numeric_resolution (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

  memset (&v4, 0, sizeof (v4));
  v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v4.sin_len = sizeof (v4);
#endif
  memset (&v6, 0, sizeof (v6));
  v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v6.sin6_len = sizeof (v6);
#endif

  if (((rh->domain == AF_UNSPEC) || (rh->domain == AF_INET)) &&
      (1 == inet_pton (AF_INET, rh->hostname, &v4.sin_addr)))
    {
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v4, sizeof (v4));
      if ((rh->domain == AF_UNSPEC) &&
          (1 == inet_pton (AF_INET6, rh->hostname, &v6.sin6_addr)))
        {
          /* this can happen on some systems IF "hostname" is "localhost" */
          rh->addr_callback (rh->cls,
                             (const struct sockaddr *) &v6, sizeof (v6));
        }
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_free (rh);
      return;
    }
  if (((rh->domain == AF_UNSPEC) || (rh->domain == AF_INET6)) &&
      (1 == inet_pton (AF_INET6, rh->hostname, &v6.sin6_addr)))
    {
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v6, sizeof (v6));
      rh->addr_callback (rh->cls, NULL, 0);
      GNUNET_free (rh);
      return;
    }
  /* why are we here? this task should not have been scheduled! */
  GNUNET_assert (0);
  GNUNET_free (rh);
}



/**
 * We've been asked to lookup the address for a hostname and were 
 * given a variant of "loopback".  Perform the callbacks for the
 * respective loopback numeric addresses.
 *
 * @param cls struct GNUNET_RESOLVER_RequestHandle for the request
 * @param tc unused scheduler context
 */
static void
loopback_resolution (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

  memset (&v4, 0, sizeof (v4));
  v4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v4.sin_len = sizeof (v4);
#endif
  memset (&v6, 0, sizeof (v6));
  v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  v6.sin6_len = sizeof (v6);
#endif
  v6.sin6_addr = in6addr_loopback;
  switch (rh->domain)
    {
    case AF_INET:
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v4, sizeof (v4));
      break;
    case AF_INET6:
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v6, sizeof (v6));
      break;
    case AF_UNSPEC:
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v6, sizeof (v6));
      rh->addr_callback (rh->cls, (const struct sockaddr *) &v4, sizeof (v4));
      break;
    default:
      GNUNET_break (0);
      break;
    }
  rh->addr_callback (rh->cls, NULL, 0);
  GNUNET_free (rh);
}


/**
 * Convert a string to one or more IP addresses.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param hostname the hostname to resolve
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param callback_cls closure for callback
 * @param timeout how long to try resolving
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_ip_get (struct GNUNET_SCHEDULER_Handle *sched,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const char *hostname,
                        int domain,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_RESOLVER_AddressCallback callback,
                        void *callback_cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GNUNET_RESOLVER_RequestHandle *rh;
  size_t slen;
  unsigned int i;
  struct in_addr v4;
  struct in6_addr v6;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  check_config (cfg);
  slen = strlen (hostname) + 1;
  if (slen + sizeof (struct GNUNET_RESOLVER_GetMessage) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return NULL;
    }
  rh = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_RequestHandle) + slen);
  rh->sched = sched;
  rh->domain = domain;
  rh->addr_callback = callback;
  rh->cls = callback_cls;
  memcpy (&rh[1], hostname, slen);
  rh->hostname = (const char *) &rh[1];
  rh->timeout = GNUNET_TIME_relative_to_absolute (timeout);

  /* first, check if this is a numeric address */
  if (((1 == inet_pton (AF_INET,
                        hostname,
                        &v4)) &&
       ((domain == AF_INET) || (domain == AF_UNSPEC))) ||
      ((1 == inet_pton (AF_INET6,
                        hostname,
                        &v6)) &&
       ((domain == AF_INET6) || (domain == AF_UNSPEC))))
    {
      rh->task = GNUNET_SCHEDULER_add_now (sched,
					   &numeric_resolution, rh);
      return rh;
    }
  /* then, check if this is a loopback address */
  i = 0;
  while (loopback[i] != NULL)
    if (0 == strcasecmp (loopback[i++], hostname))
      {
        rh->task = GNUNET_SCHEDULER_add_now (sched,
					     &loopback_resolution, rh);
        return rh;
      }

  client = GNUNET_CLIENT_connect (sched, "resolver", cfg);
  if (client == NULL)
    {
      GNUNET_free (rh);
      return NULL;
    }
  rh->client = client;

  msg = (struct GNUNET_RESOLVER_GetMessage *) buf;
  msg->header.size =
    htons (sizeof (struct GNUNET_RESOLVER_GetMessage) + slen);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST);
  msg->direction = htonl (GNUNET_NO);
  msg->domain = htonl (domain);
  memcpy (&msg[1], hostname, slen);

#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolver requests DNS resolution of hostname `%s'.\n"),
              hostname);
#endif
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (client,
                                               &msg->header,
                                               timeout,
                                               GNUNET_YES,
                                               &handle_address_response, rh))
    {
      GNUNET_free (rh);
      GNUNET_CLIENT_disconnect (client, GNUNET_NO);
      return NULL;
    }
  return rh;
}


/**
 * Process response with a hostname for a reverse DNS lookup.
 *
 * @param cls our "struct GNUNET_RESOLVER_RequestHandle" context
 * @param msg message with the hostname, NULL on error
 */
static void
handle_hostname_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  uint16_t size;
  const char *hostname;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Timeout trying to resolve IP address `%s'.\n"),
		  GNUNET_a2s ((const void*) &rh[1], rh->salen));
      rh->name_callback (rh->cls, NULL);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received end message resolving IP address `%s'.\n"),
		  GNUNET_a2s ((const void*) &rh[1], rh->salen));
#endif
      rh->name_callback (rh->cls, NULL);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
  hostname = (const char *) &msg[1];
  if (hostname[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
    {
      GNUNET_break (0);
      rh->name_callback (rh->cls, NULL);
      GNUNET_CLIENT_disconnect (rh->client, GNUNET_NO);
      GNUNET_free (rh);
      return;
    }
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolver returns `%s' for IP `%s'.\n"), 
	      hostname,
	      GNUNET_a2s ((const void*) &rh[1], rh->salen));
#endif
  rh->name_callback (rh->cls, hostname);
  GNUNET_CLIENT_receive (rh->client,
                         &handle_hostname_response,
                         rh,
                         GNUNET_TIME_absolute_get_remaining (rh->timeout));
}



/**
 * We've been asked to convert an address to a string without
 * a reverse lookup.  Do it.
 *
 * @param cls struct GNUNET_RESOLVER_RequestHandle for the request
 * @param tc unused scheduler context
 */
static void
numeric_reverse (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  char *result;

  result = no_resolve ((const struct sockaddr *) &rh[1], rh->salen);
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Resolver returns `%s'.\n"), result);
#endif
  if (result != NULL)
    {
      rh->name_callback (rh->cls, result);
      GNUNET_free (result);
    }
  rh->name_callback (rh->cls, NULL);
  GNUNET_free (rh);
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
 * @return handle that can be used to cancel the request
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_get (struct GNUNET_SCHEDULER_Handle *sched,
                              const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct sockaddr *sa,
                              socklen_t salen,
                              int do_resolve,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_RESOLVER_HostnameCallback callback,
                              void *cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GNUNET_RESOLVER_RequestHandle *rh;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  check_config (cfg);
  rh = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_RequestHandle) + salen);
  rh->name_callback = callback;
  rh->cls = cls;
  rh->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  rh->sched = sched;
  rh->salen = salen;
  memcpy (&rh[1], sa, salen);

  if (GNUNET_NO == do_resolve)
    {
      rh->task = GNUNET_SCHEDULER_add_now (sched,
					   &numeric_reverse, rh);
      return rh;
    }
  if (salen + sizeof (struct GNUNET_RESOLVER_GetMessage) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      GNUNET_free (rh);
      return NULL;
    }
  client = GNUNET_CLIENT_connect (sched, "resolver", cfg);
  if (client == NULL)
    {
      GNUNET_free (rh);
      return NULL;
    }
  rh->client = client;

  msg = (struct GNUNET_RESOLVER_GetMessage *) buf;
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
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (client,
                                               &msg->header,
                                               timeout,
                                               GNUNET_YES,
                                               &handle_hostname_response, rh))
    {
      GNUNET_CLIENT_disconnect (client, GNUNET_NO);
      GNUNET_free (rh);
      return NULL;
    }
  return rh;
}


/**
 * Get local hostname
 *
 * @param
 */
char *
GNUNET_RESOLVER_local_hostname_get ( )
{

  char hostname[GNUNET_OS_get_hostname_max_length() + 1];


  if (0 != gethostname (hostname, sizeof (hostname) - 1))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR |
                           GNUNET_ERROR_TYPE_BULK, "gethostname");
      return NULL;
    }
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolving our hostname `%s'\n"), hostname);
#endif
  return GNUNET_strdup (hostname);
}

/**
 * Looking our own hostname.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param cls closure for callback
 * @param timeout how long to try resolving
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_resolve (struct GNUNET_SCHEDULER_Handle *sched,
                                  const struct GNUNET_CONFIGURATION_Handle
                                  *cfg, int domain,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_RESOLVER_AddressCallback callback,
                                  void *cls)
{
  char hostname[GNUNET_OS_get_hostname_max_length() + 1];

  check_config (cfg);
  if (0 != gethostname (hostname, sizeof (hostname) - 1))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR |
                           GNUNET_ERROR_TYPE_BULK, "gethostname");
      return NULL;
    }
#if DEBUG_RESOLVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Resolving our hostname `%s'\n"), hostname);
#endif
  return GNUNET_RESOLVER_ip_get (sched,
                                 cfg, hostname, domain, timeout, callback,
                                 cls);
}


/**
 * Cancel a request that is still pending with the resolver.
 * Note that a client MUST NOT cancel a request that has
 * been completed (i.e, the callback has been called to
 * signal timeout or the final result).
 *
 * @param h handle of request to cancel
 */
void
GNUNET_RESOLVER_request_cancel (struct GNUNET_RESOLVER_RequestHandle *h)
{
  if (h->client != NULL)
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  if (h->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched, h->task);
  GNUNET_free (h);
}



/* end of resolver_api.c */
