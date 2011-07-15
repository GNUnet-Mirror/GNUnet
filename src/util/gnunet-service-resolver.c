/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include "resolver.h"

/**
 * A cached DNS lookup result.
 */
struct IPCache
{
  /**
   * This is a linked list.
   */
  struct IPCache *next;

  /**
   * Hostname in human-readable form.
   */
  char *addr;

  /**
   * Hostname in binary format.
   */
  struct sockaddr *sa;

  /**
   * Last time this entry was updated.
   */
  struct GNUNET_TIME_Absolute last_refresh;

  /**
   * Last time this entry was requested.
   */
  struct GNUNET_TIME_Absolute last_request;

  /**
   * Number of bytes in sa.
   */
  socklen_t salen;
};


/**
 * Start of the linked list of cached DNS lookup results.
 */
static struct IPCache *head;


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

  if (0 == getnameinfo (cache->sa,
                        cache->salen,
                        hostname, sizeof (hostname), NULL, 0, 0))
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

  switch (cache->sa->sa_family)
    {
    case AF_INET:
      ent = gethostbyaddr (&((struct sockaddr_in *) cache->sa)->sin_addr,
                           sizeof (struct in_addr), AF_INET);
      break;
    case AF_INET6:
      ent = gethostbyaddr (&((struct sockaddr_in6 *) cache->sa)->sin6_addr,
                           sizeof (struct in6_addr), AF_INET6);
      break;
    default:
      ent = NULL;
    }
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
 * @param sa should be of type "struct sockaddr*"
 * @param salen number of bytes in sa
 */
static void
get_ip_as_string (struct GNUNET_SERVER_Client *client,
                  const struct sockaddr *sa, socklen_t salen)
{
  struct IPCache *cache;
  struct IPCache *prev;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_SERVER_TransmitContext *tc;

  if (salen < sizeof (struct sockaddr))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  now = GNUNET_TIME_absolute_get ();
  cache = head;
  prev = NULL;
  while ((cache != NULL) &&
         ((cache->salen != salen) || (0 != memcmp (cache->sa, sa, salen))))
    {
      if (GNUNET_TIME_absolute_get_duration (cache->last_request).rel_value <
          60 * 60 * 1000)
        {
          if (prev != NULL)
            {
              prev->next = cache->next;
              GNUNET_free_non_null (cache->addr);
              GNUNET_free (cache->sa);
              GNUNET_free (cache);
              cache = prev->next;
            }
          else
            {
              head = cache->next;
              GNUNET_free_non_null (cache->addr);
              GNUNET_free (cache->sa);
              GNUNET_free (cache);
              cache = head;
            }
          continue;
        }
      prev = cache;
      cache = cache->next;
    }
  if (cache != NULL)
    {
      cache->last_request = now;
      if (GNUNET_TIME_absolute_get_duration (cache->last_request).rel_value <
          60 * 60 * 1000)
        {
          GNUNET_free_non_null (cache->addr);
          cache->addr = NULL;
          cache->salen = 0;
          cache_resolve (cache);
        }
    }
  else
    {
      cache = GNUNET_malloc (sizeof (struct IPCache));
      cache->next = head;
      cache->salen = salen;
      cache->sa = GNUNET_malloc (salen);
      memcpy (cache->sa, sa, salen);
      cache->last_request = GNUNET_TIME_absolute_get ();
      cache->last_refresh = GNUNET_TIME_absolute_get ();
      cache->addr = NULL;
      cache_resolve (cache);
      head = cache;
    }
  tc = GNUNET_SERVER_transmit_context_create (client);
  if (cache->addr != NULL)
    GNUNET_SERVER_transmit_context_append_data (tc,
						cache->addr,
						strlen (cache->addr) + 1,
						GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
					      GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


#if HAVE_GETADDRINFO
static int
getaddrinfo_resolve (struct GNUNET_SERVER_TransmitContext *tc,
                     const char *hostname, int domain)
{
  int s;
  struct addrinfo hints;
  struct addrinfo *result;
  struct addrinfo *pos;

  memset (&hints, 0, sizeof (struct addrinfo));
// FIXME in PlibC
#ifndef MINGW
  hints.ai_family = domain;
#else
  hints.ai_family = AF_INET;
#endif
  hints.ai_socktype = SOCK_STREAM;      /* go for TCP */

  if (0 != (s = getaddrinfo (hostname, NULL, &hints, &result)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Could not resolve `%s' (%s): %s\n"), hostname,
                  (domain ==
                   AF_INET) ? "IPv4" : ((domain ==
                                         AF_INET6) ? "IPv6" : "any"),
                  gai_strerror (s));
      if ((s == EAI_BADFLAGS) || (s == EAI_MEMORY) 
#ifndef MINGW
          || (s == EAI_SYSTEM)
#else
          // FIXME NILS
          || 1
#endif
        )
        return GNUNET_NO;       /* other function may still succeed */
      return GNUNET_SYSERR;
    }
  if (result == NULL)
    return GNUNET_SYSERR;
  pos = result;
  while (pos != NULL)
    {
      GNUNET_SERVER_transmit_context_append_data (tc,
						  pos->ai_addr,
						  pos->ai_addrlen,
						  GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
      pos = pos->ai_next;
    }
  freeaddrinfo (result);
  return GNUNET_OK;
}
#endif

#if HAVE_GETHOSTBYNAME2
static int
gethostbyname2_resolve (struct GNUNET_SERVER_TransmitContext *tc,
                        const char *hostname, int domain)
{
  struct hostent *hp;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  int ret1;
  int ret2;

  if (domain == AF_UNSPEC)
    {
      ret1 = gethostbyname2_resolve (tc, hostname, AF_INET);
      ret2 = gethostbyname2_resolve (tc, hostname, AF_INET6);
      if ((ret1 == GNUNET_OK) || (ret2 == GNUNET_OK))
        return GNUNET_OK;
      if ((ret1 == GNUNET_SYSERR) || (ret2 == GNUNET_SYSERR))
        return GNUNET_SYSERR;
      return GNUNET_NO;
    }
  hp = gethostbyname2 (hostname, domain);
  if (hp == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Could not find IP of host `%s': %s\n"),
                  hostname, hstrerror (h_errno));
      return GNUNET_SYSERR;
    }
  GNUNET_assert (hp->h_addrtype == domain);
  if (domain == AF_INET)
    {
      GNUNET_assert (hp->h_length == sizeof (struct in_addr));
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
      a4.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
      memcpy (&a4.sin_addr, hp->h_addr_list[0], hp->h_length);
      GNUNET_SERVER_transmit_context_append_data (tc,
						  &a4,
						  sizeof (a4),
						  GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
    }
  else
    {
      GNUNET_assert (hp->h_length == sizeof (struct in6_addr));
      memset (&a6, 0, sizeof (a6));
      a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
      a6.sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
      memcpy (&a6.sin6_addr, hp->h_addr_list[0], hp->h_length);
      GNUNET_SERVER_transmit_context_append_data (tc,
						  &a6,
						  sizeof (a6),
						  GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
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
  struct sockaddr_in addr;

  hp = GETHOSTBYNAME (hostname);
  if (hp == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Could not find IP of host `%s': %s\n"),
                  hostname, hstrerror (h_errno));
      return GNUNET_SYSERR;
    }
  if (hp->h_addrtype != AF_INET)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_assert (hp->h_length == sizeof (struct in_addr));
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  addr.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
  memcpy (&addr.sin_addr, hp->h_addr_list[0], hp->h_length);
  GNUNET_SERVER_transmit_context_append_data (tc,
					      &addr,
					      sizeof (addr),
					      GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  return GNUNET_OK;
}
#endif


/**
 * Convert a string to an IP address.
 *
 * @param client where to send the IP address
 * @param hostname the hostname to resolve
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 */
static void
get_ip_from_hostname (struct GNUNET_SERVER_Client *client,
                      const char *hostname, int domain)
{
  int ret;
  struct GNUNET_SERVER_TransmitContext *tc;

  tc = GNUNET_SERVER_transmit_context_create (client);
  ret = GNUNET_NO;
#if HAVE_GETADDRINFO
  if (ret == GNUNET_NO)
    ret = getaddrinfo_resolve (tc, hostname, domain);
#endif
#if HAVE_GETHOSTBYNAME2
  if (ret == GNUNET_NO)
    ret = gethostbyname2_resolve (tc, hostname, domain);
#endif
#if HAVE_GETHOSTBYNAME
  if ((ret == GNUNET_NO) && ((domain == AF_UNSPEC) || (domain == PF_INET)))
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
handle_get (void *cls,
            struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  uint16_t msize;
  const struct GNUNET_RESOLVER_GetMessage *msg;
  const char *hostname;
  const struct sockaddr *sa;
  uint16_t size;
  int direction;
  int domain;

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
  domain = ntohl (msg->domain);
  if (direction == GNUNET_NO)
    {
      /* IP from hostname */
      hostname = (const char *) &msg[1];
      if (hostname[size - 1] != '\0')
        {
          GNUNET_break (0);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Resolver asked to look up `%s'.\n"), hostname);
#endif
      get_ip_from_hostname (client, hostname, domain);
    }
  else
    {
#if DEBUG_RESOLVER      
      char buf[INET6_ADDRSTRLEN];
#endif
      if (size < sizeof (struct sockaddr))
	{
	  GNUNET_break (0);
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	  return;
	}
      sa = (const struct sockaddr*) &msg[1];
      switch (sa->sa_family)
	{
	case AF_INET:
	  if (size != sizeof (struct sockaddr_in))
	    {
	      GNUNET_break (0);
	      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	      return;
	    }
#if DEBUG_RESOLVER      
	  inet_ntop (AF_INET, sa, buf, size);
#endif
	  break;
	case AF_INET6:
	  if (size != sizeof (struct sockaddr_in6))
	    {
	      GNUNET_break (0);
	      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	      return;
	    }
#if DEBUG_RESOLVER      
	  inet_ntop (AF_INET6, sa, buf, size);
#endif
	  break;
	default:
	  GNUNET_break (0);
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	  return;
	}      
#if DEBUG_RESOLVER      
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Resolver asked to look up IP address `%s'.\n"),
		  buf);
#endif
      get_ip_as_string (client, sa, size);
    }
}


/**
 * Process resolver requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
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
  int ret;
  struct IPCache *pos;

  ret = (GNUNET_OK ==
         GNUNET_SERVICE_run (argc,
                             argv,
                             "resolver", GNUNET_SERVICE_OPTION_NONE,
                             &run, NULL)) ? 0 : 1;

  while (head != NULL)
    {
      pos = head->next;
      GNUNET_free_non_null (head->addr);
      GNUNET_free (head->sa);
      GNUNET_free (head);
      head = pos;
    }
  return ret;
}

/* end of gnunet-service-resolver.c */
