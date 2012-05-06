/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * A cached DNS lookup result.
 */
struct IPCache
{
  /**
   * This is a doubly linked list.
   */
  struct IPCache *next;

  /**
   * This is a doubly linked list.
   */
  struct IPCache *prev;

  /**
   * Hostname in human-readable form.
   */
  char *addr;

  /**
   * Binary IP address, allocated at the end of this struct.
   */
  const void *ip;

  /**
   * Last time this entry was updated.
   */
  struct GNUNET_TIME_Absolute last_refresh;

  /**
   * Last time this entry was requested.
   */
  struct GNUNET_TIME_Absolute last_request;

  /**
   * Number of bytes in ip.
   */
  size_t ip_len;

  /**
   * Address family of the IP.
   */
  int af;
};


/**
 * Start of the linked list of cached DNS lookup results.
 */
static struct IPCache *cache_head;

/**
 * Tail of the linked list of cached DNS lookup results.
 */
static struct IPCache *cache_tail;


#if HAVE_GETNAMEINFO
/**
 * Resolve the given request using getnameinfo
 *
 * @param cache the request to resolve (and where to store the result)
 */
static void
getnameinfo_resolve (struct IPCache *cache)
{
  char hostname[256];
  const struct sockaddr *sa;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  size_t salen;

  switch (cache->af)
  {
  case AF_INET:
    GNUNET_assert (cache->ip_len == sizeof (struct in_addr));
    sa = (const struct sockaddr*) &v4;
    memset (&v4, 0, sizeof (v4));
    v4.sin_addr = * (const struct in_addr*) cache->ip;
    v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4.sin_len = sizeof (v4);
#endif
    salen = sizeof (v4);
    break;
  case AF_INET6:
    GNUNET_assert (cache->ip_len == sizeof (struct in6_addr));
    sa = (const struct sockaddr*) &v6;
    memset (&v6, 0, sizeof (v6));
    v6.sin6_addr = * (const struct in6_addr*) cache->ip;
    v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6.sin6_len = sizeof (v6);
#endif
    salen = sizeof (v6);
    break;
  default:
    GNUNET_assert (0);
  }

  if (0 ==
      getnameinfo (sa, salen, hostname, sizeof (hostname), NULL,
                   0, 0))
    cache->addr = GNUNET_strdup (hostname);
}
#endif


#if HAVE_GETHOSTBYADDR
/**
 * Resolve the given request using gethostbyaddr
 *
 * @param cache the request to resolve (and where to store the result)
 */
static void
gethostbyaddr_resolve (struct IPCache *cache)
{
  struct hostent *ent;

  ent = gethostbyaddr (cache->ip,
		       cache->ip_len,
		       cache->af);
  if (ent != NULL)
    cache->addr = GNUNET_strdup (ent->h_name);
}
#endif


/**
 * Resolve the given request using the available methods.
 *
 * @param cache the request to resolve (and where to store the result)
 */
static void
cache_resolve (struct IPCache *cache)
{
#if HAVE_GETNAMEINFO
  if (cache->addr == NULL)
    getnameinfo_resolve (cache);
#endif
#if HAVE_GETHOSTBYADDR
  if (cache->addr == NULL)
    gethostbyaddr_resolve (cache);
#endif
}


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param client handle to the client making the request (for sending the reply)
 * @param af AF_INET or AF_INET6
 * @param ip 'struct in_addr' or 'struct in6_addr'
 */
static void
get_ip_as_string (struct GNUNET_SERVER_Client *client,
                  int af,
		  const void *ip)
{
  struct IPCache *pos;
  struct IPCache *next;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_SERVER_TransmitContext *tc;
  size_t ip_len;

  switch (af)
  {
  case AF_INET:
    ip_len = sizeof (struct in_addr);
    break;
  case AF_INET6:
    ip_len = sizeof (struct in6_addr);
    break;
  default:
    GNUNET_assert (0);
  }
  now = GNUNET_TIME_absolute_get ();
  next = cache_head;
  while ( (NULL != (pos = next)) &&
	  ( (pos->af != af) ||
	    (pos->ip_len != ip_len) || 
	    (0 != memcmp (pos->ip, ip, ip_len))) )
  {
    next = pos->next;
    if (GNUNET_TIME_absolute_get_duration (pos->last_request).rel_value <
        60 * 60 * 1000)
    {
      GNUNET_CONTAINER_DLL_remove (cache_head,
				   cache_tail,
				   pos);
      GNUNET_free_non_null (pos->addr);
      GNUNET_free (pos);
      continue;
    }
  }
  if (pos != NULL)
  {
    pos->last_request = now;
    if (GNUNET_TIME_absolute_get_duration (pos->last_request).rel_value <
        60 * 60 * 1000)
    {
      GNUNET_free_non_null (pos->addr);
      pos->addr = NULL;
      cache_resolve (pos);
    }
  }
  else
  {
    pos = GNUNET_malloc (sizeof (struct IPCache) + ip_len);
    pos->ip = &pos[1];
    memcpy (&pos[1], ip, ip_len);
    pos->last_request = now;
    pos->last_refresh = now;
    pos->ip_len = ip_len;
    pos->af = af;
    GNUNET_CONTAINER_DLL_insert (cache_head,
				 cache_tail,
				 pos);
    cache_resolve (pos);
  }
  tc = GNUNET_SERVER_transmit_context_create (client);
  if (pos->addr != NULL)
    GNUNET_SERVER_transmit_context_append_data (tc, pos->addr,
                                                strlen (pos->addr) + 1,
                                                GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


#if HAVE_GETADDRINFO
static int
getaddrinfo_resolve (struct GNUNET_SERVER_TransmitContext *tc,
                     const char *hostname, int af)
{
  int s;
  struct addrinfo hints;
  struct addrinfo *result;
  struct addrinfo *pos;

  memset (&hints, 0, sizeof (struct addrinfo));
// FIXME in PlibC
#ifndef MINGW
  hints.ai_family = af;
#else
  hints.ai_family = AF_INET;
#endif
  hints.ai_socktype = SOCK_STREAM;      /* go for TCP */

  if (0 != (s = getaddrinfo (hostname, NULL, &hints, &result)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Could not resolve `%s' (%s): %s\n"),
                hostname,
                (af ==
                 AF_INET) ? "IPv4" : ((af == AF_INET6) ? "IPv6" : "any"),
                gai_strerror (s));
    if ((s == EAI_BADFLAGS) || (s == EAI_MEMORY)
#ifndef MINGW
        || (s == EAI_SYSTEM)
#else
        // FIXME NILS
        || 1
#endif
        )
      return GNUNET_NO;         /* other function may still succeed */
    return GNUNET_SYSERR;
  }
  if (result == NULL)
    return GNUNET_SYSERR;
  pos = result;
  while (pos != NULL)
  {
    switch (pos->ai_family)
    {
    case AF_INET:
      GNUNET_SERVER_transmit_context_append_data (tc,
						  &((struct sockaddr_in*) pos->ai_addr)->sin_addr,
						  sizeof (struct in_addr),
						  GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
      break;
    case AF_INET6:
      GNUNET_SERVER_transmit_context_append_data (tc,
						  &((struct sockaddr_in6*) pos->ai_addr)->sin6_addr,
						  sizeof (struct in6_addr),
						  GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
      break;
    default:
      /* unsupported, skip */
      break;
    }     
    pos = pos->ai_next;
  }
  freeaddrinfo (result);
  return GNUNET_OK;
}
#endif


#if HAVE_GETHOSTBYNAME2
static int
gethostbyname2_resolve (struct GNUNET_SERVER_TransmitContext *tc,
                        const char *hostname, int af)
{
  struct hostent *hp;
  int ret1;
  int ret2;

  if (af == AF_UNSPEC)
  {
    ret1 = gethostbyname2_resolve (tc, hostname, AF_INET);
    ret2 = gethostbyname2_resolve (tc, hostname, AF_INET6);
    if ((ret1 == GNUNET_OK) || (ret2 == GNUNET_OK))
      return GNUNET_OK;
    if ((ret1 == GNUNET_SYSERR) || (ret2 == GNUNET_SYSERR))
      return GNUNET_SYSERR;
    return GNUNET_NO;
  }
  hp = gethostbyname2 (hostname, af);
  if (hp == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Could not find IP of host `%s': %s\n"), hostname,
                hstrerror (h_errno));
    return GNUNET_SYSERR;
  }
  GNUNET_assert (hp->h_addrtype == af);
  switch (af)
  {
  case AF_INET:
    GNUNET_assert (hp->h_length == sizeof (struct in_addr));
    GNUNET_SERVER_transmit_context_append_data (tc, 
						hp->h_addr_list[0], 
						hp->h_length,
                                                GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
    break;
  case AF_INET6:
    GNUNET_assert (hp->h_length == sizeof (struct in6_addr));
    GNUNET_SERVER_transmit_context_append_data (tc, 
						hp->h_addr_list[0], 
						hp->h_length,
                                                GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}
#endif


#if HAVE_GETHOSTBYNAME
static int
gethostbyname_resolve (struct GNUNET_SERVER_TransmitContext *tc,
                       const char *hostname)
{
  struct hostent *hp;

  hp = GETHOSTBYNAME (hostname);
  if (hp == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Could not find IP of host `%s': %s\n"), hostname,
                hstrerror (h_errno));
    return GNUNET_SYSERR;
  }
  if (hp->h_addrtype != AF_INET)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (hp->h_length == sizeof (struct in_addr));
  GNUNET_SERVER_transmit_context_append_data (tc, 
					      hp->h_addr_list[0],
					      hp->h_length,
                                              GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  return GNUNET_OK;
}
#endif


/**
 * Convert a string to an IP address.
 *
 * @param client where to send the IP address
 * @param hostname the hostname to resolve
 * @param af AF_INET or AF_INET6; use AF_UNSPEC for "any"
 */
static void
get_ip_from_hostname (struct GNUNET_SERVER_Client *client, const char *hostname,
                      int af)
{
  int ret;
  struct GNUNET_SERVER_TransmitContext *tc;

  tc = GNUNET_SERVER_transmit_context_create (client);
  ret = GNUNET_NO;
#if HAVE_GETADDRINFO
  if (ret == GNUNET_NO)
    ret = getaddrinfo_resolve (tc, hostname, af);
#endif
#if HAVE_GETHOSTBYNAME2
  if (ret == GNUNET_NO)
    ret = gethostbyname2_resolve (tc, hostname, af);
#endif
#if HAVE_GETHOSTBYNAME
  if ((ret == GNUNET_NO) && ((af == AF_UNSPEC) || (af == PF_INET)))
    gethostbyname_resolve (tc, hostname);
#endif
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  uint16_t msize;
  const struct GNUNET_RESOLVER_GetMessage *msg;
  const void *ip;
  uint16_t size;
  int direction;
  int af;

  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_RESOLVER_GetMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_RESOLVER_GetMessage *) message;
  size = msize - sizeof (struct GNUNET_RESOLVER_GetMessage);
  direction = ntohl (msg->direction);
  af = ntohl (msg->af);
  if (direction == GNUNET_NO)
  {
    /* IP from hostname */
    const char *hostname;
  
    hostname = (const char *) &msg[1];
    if (hostname[size - 1] != '\0')
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Resolver asked to look up `%s'.\n",
                hostname);
    get_ip_from_hostname (client, hostname, af);
    return;
  }
  ip = &msg[1];
  switch (af)
  {
  case AF_INET:
    if (size != sizeof (struct in_addr))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    break;
  case AF_INET6:
    if (size != sizeof (struct in6_addr))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  {
    char buf[INET6_ADDRSTRLEN];
    
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Resolver asked to look up IP address `%s'.\n", 
		inet_ntop (af, ip, buf, sizeof (buf)));
  }
  get_ip_as_string (client, af, ip);  
}


/**
 * Process resolver requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_get, NULL, GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST, 0},
    {NULL, NULL, 0, 0}
  };
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * The main function for the resolver service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct IPCache *pos;
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "resolver", GNUNET_SERVICE_OPTION_NONE,
                           &run, NULL)) ? 0 : 1;
  while (NULL != (pos = cache_head))
  {
    GNUNET_CONTAINER_DLL_remove (cache_head,
				 cache_tail,
				 pos);
    GNUNET_free_non_null (pos->addr);
    GNUNET_free (pos);
  }
  return ret;
}

/* end of gnunet-service-resolver.c */
