/*
     This file is part of GNUnet.
     Copyright (C) 2007-2016 GNUnet e.V.

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
 * A cached DNS lookup result (for reverse lookup).
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
  int ret;

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
      (ret = getnameinfo (sa, salen,
                          hostname, sizeof (hostname),
                          NULL,
                          0, 0)))
  {
    cache->addr = GNUNET_strdup (hostname);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "getnameinfo failed: %s\n",
                gai_strerror (ret));
  }
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
  if (NULL != ent)
  {
    cache->addr = GNUNET_strdup (ent->h_name);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "gethostbyaddr failed: %s\n",
                hstrerror (h_errno));
  }
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
  if (NULL == cache->addr)
    getnameinfo_resolve (cache);
#endif
#if HAVE_GETHOSTBYADDR
  if (NULL == cache->addr)
    gethostbyaddr_resolve (cache);
#endif
}


/**
 * Function called after the replies for the request have all
 * been transmitted to the client, and we can now read the next
 * request from the client.
 *
 * @param cls the `struct GNUNET_SERVICE_Client` to continue with
 */
static void
notify_service_client_done (void *cls)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_SERVICE_client_continue (client);
}


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param client handle to the client making the request (for sending the reply)
 * @param af AF_INET or AF_INET6
 * @param ip `struct in_addr` or `struct in6_addr`
 */
static void
get_ip_as_string (struct GNUNET_SERVICE_Client *client,
                  int af,
		  const void *ip)
{
  struct IPCache *pos;
  struct IPCache *next;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MessageHeader *msg;
  size_t ip_len;
  struct in6_addr ix;
  size_t alen;

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
    if (GNUNET_TIME_absolute_get_duration (pos->last_request).rel_value_us <
        60 * 60 * 1000 * 1000LL)
    {
      GNUNET_CONTAINER_DLL_remove (cache_head,
				   cache_tail,
				   pos);
      GNUNET_free_non_null (pos->addr);
      GNUNET_free (pos);
      continue;
    }
  }
  if (NULL != pos)
  {
    if ( (1 == inet_pton (af,
                          pos->ip,
                          &ix)) &&
         (GNUNET_TIME_absolute_get_duration (pos->last_request).rel_value_us >
          120 * 1000 * 1000LL) )
    {
      /* try again if still numeric AND 2 minutes have expired */
      GNUNET_free_non_null (pos->addr);
      pos->addr = NULL;
      cache_resolve (pos);
      pos->last_request = now;
    }
  }
  else
  {
    pos = GNUNET_malloc (sizeof (struct IPCache) + ip_len);
    pos->ip = &pos[1];
    GNUNET_memcpy (&pos[1],
		   ip,
		   ip_len);
    pos->last_request = now;
    pos->last_refresh = now;
    pos->ip_len = ip_len;
    pos->af = af;
    GNUNET_CONTAINER_DLL_insert (cache_head,
				 cache_tail,
				 pos);
    cache_resolve (pos);
  }
  if (NULL != pos->addr)
    alen = strlen (pos->addr) + 1;
  else
    alen = 0;
  mq = GNUNET_SERVICE_client_get_mq (client);
  env = GNUNET_MQ_msg_extra (msg,
			     alen,
			     GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_memcpy (&msg[1],
		 pos->addr,
		 alen);
  GNUNET_MQ_send (mq,
		  env);
  env = GNUNET_MQ_msg (msg,
		       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_MQ_notify_sent (env,
			 &notify_service_client_done,
			 client);
  GNUNET_MQ_send (mq,
		  env);
}


#if HAVE_GETADDRINFO
static int
getaddrinfo_resolve (struct GNUNET_MQ_Handle *mq,
                     const char *hostname,
		     int af)
{
  int s;
  struct addrinfo hints;
  struct addrinfo *result;
  struct addrinfo *pos;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

#ifdef WINDOWS
  /* Due to a bug, getaddrinfo will not return a mix of different families */
  if (AF_UNSPEC == af)
  {
    int ret1;
    int ret2;
    ret1 = getaddrinfo_resolve (mq,
				hostname,
				AF_INET);
    ret2 = getaddrinfo_resolve (mq,
				hostname,
				AF_INET6);
    if ( (ret1 == GNUNET_OK) ||
	 (ret2 == GNUNET_OK) )
      return GNUNET_OK;
    if ( (ret1 == GNUNET_SYSERR) ||
	 (ret2 == GNUNET_SYSERR) )
      return GNUNET_SYSERR;
    return GNUNET_NO;
  }
#endif

  memset (&hints,
	  0,
	  sizeof (struct addrinfo));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;      /* go for TCP */

  if (0 != (s = getaddrinfo (hostname,
			     NULL,
			     &hints,
			     &result)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Could not resolve `%s' (%s): %s\n"),
                hostname,
                (af ==
                 AF_INET) ? "IPv4" : ((af == AF_INET6) ? "IPv6" : "any"),
                gai_strerror (s));
    if ( (s == EAI_BADFLAGS) ||
#ifndef WINDOWS
	 (s == EAI_SYSTEM) ||
#endif
	 (s == EAI_MEMORY) )
      return GNUNET_NO;         /* other function may still succeed */
    return GNUNET_SYSERR;
  }
  if (NULL == result)
    return GNUNET_SYSERR;
  for (pos = result; pos != NULL; pos = pos->ai_next)
  {
    switch (pos->ai_family)
    {
    case AF_INET:
      env = GNUNET_MQ_msg_extra (msg,
				 sizeof (struct in_addr),
				 GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
      GNUNET_memcpy (&msg[1],
		     &((struct sockaddr_in*) pos->ai_addr)->sin_addr,
		     sizeof (struct in_addr));
      GNUNET_MQ_send (mq,
		      env);
      break;
    case AF_INET6:
      env = GNUNET_MQ_msg_extra (msg,
				 sizeof (struct in6_addr),
				 GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
      GNUNET_memcpy (&msg[1],
		     &((struct sockaddr_in6*) pos->ai_addr)->sin6_addr,
		     sizeof (struct in6_addr));
      GNUNET_MQ_send (mq,
		      env);
      break;
    default:
      /* unsupported, skip */
      break;
    }
  }
  freeaddrinfo (result);
  return GNUNET_OK;
}


#elif HAVE_GETHOSTBYNAME2


static int
gethostbyname2_resolve (struct GNUNET_MQ_Handle *mq,
                        const char *hostname,
                        int af)
{
  struct hostent *hp;
  int ret1;
  int ret2;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

#ifdef WINDOWS
  /* gethostbyname2() in plibc is a compat dummy that calls gethostbyname(). */
  return GNUNET_NO;
#endif

  if (af == AF_UNSPEC)
  {
    ret1 = gethostbyname2_resolve (mq,
				   hostname,
				   AF_INET);
    ret2 = gethostbyname2_resolve (mq,
				   hostname,
				   AF_INET6);
    if ( (ret1 == GNUNET_OK) ||
	 (ret2 == GNUNET_OK) )
      return GNUNET_OK;
    if ( (ret1 == GNUNET_SYSERR) ||
	 (ret2 == GNUNET_SYSERR) )
      return GNUNET_SYSERR;
    return GNUNET_NO;
  }
  hp = gethostbyname2 (hostname,
		       af);
  if (hp == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Could not find IP of host `%s': %s\n"),
		hostname,
                hstrerror (h_errno));
    return GNUNET_SYSERR;
  }
  GNUNET_assert (hp->h_addrtype == af);
  switch (af)
  {
  case AF_INET:
    GNUNET_assert (hp->h_length == sizeof (struct in_addr));
    env = GNUNET_MQ_msg_extra (msg,
			       hp->h_length,
			       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
    GNUNET_memcpy (&msg[1],
		   hp->h_addr_list[0],
		   hp->h_length);
    GNUNET_MQ_send (mq,
		    env);
    break;
  case AF_INET6:
    GNUNET_assert (hp->h_length == sizeof (struct in6_addr));
    env = GNUNET_MQ_msg_extra (msg,
			       hp->h_length,
			       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
    GNUNET_memcpy (&msg[1],
		   hp->h_addr_list[0],
		   hp->h_length);
    GNUNET_MQ_send (mq,
		    env);
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

#elif HAVE_GETHOSTBYNAME


static int
gethostbyname_resolve (struct GNUNET_MQ_Handle *mq,
		       const char *hostname)
{
  struct hostent *hp;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  hp = GETHOSTBYNAME (hostname);
  if (NULL == hp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Could not find IP of host `%s': %s\n"),
                hostname,
                hstrerror (h_errno));
    return GNUNET_SYSERR;
  }
  if (hp->h_addrtype != AF_INET)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (hp->h_length == sizeof (struct in_addr));
  env = GNUNET_MQ_msg_extra (msg,
			     hp->h_length,
			     GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_memcpy (&msg[1],
		 hp->h_addr_list[0],
		 hp->h_length);
  GNUNET_MQ_send (mq,
		  env);
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
get_ip_from_hostname (struct GNUNET_SERVICE_Client *client,
                      const char *hostname,
                      int af)
{
  int ret;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  mq = GNUNET_SERVICE_client_get_mq (client);
  ret = GNUNET_NO;
#if HAVE_GETADDRINFO
  if (ret == GNUNET_NO)
    ret = getaddrinfo_resolve (mq,
			       hostname,
			       af);
#elif HAVE_GETHOSTBYNAME2
  if (ret == GNUNET_NO)
    ret = gethostbyname2_resolve (mq,
				  hostname,
				  af);
#elif HAVE_GETHOSTBYNAME
  if ( (ret == GNUNET_NO) &&
       ( (af == AF_UNSPEC) ||
	 (af == PF_INET) ) )
    gethostbyname_resolve (mq,
			   hostname);
#endif
  env = GNUNET_MQ_msg (msg,
		       GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE);
  GNUNET_MQ_notify_sent (env,
			 &notify_service_client_done,
			 client);
  GNUNET_MQ_send (mq,
		  env);
}


/**
 * Verify well-formedness of GET-message.
 *
 * @param cls closure
 * @param get the actual message
 * @return #GNUNET_OK if @a get is well-formed
 */
static int
check_get (void *cls,
	   const struct GNUNET_RESOLVER_GetMessage *get)
{
  uint16_t size;
  int direction;
  int af;

  size = ntohs (get->header.size) - sizeof (*get);
  direction = ntohl (get->direction);
  if (GNUNET_NO == direction)
  {
    /* IP from hostname */
    const char *hostname;

    hostname = (const char *) &get[1];
    if (hostname[size - 1] != '\0')
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  af = ntohl (get->af);
  switch (af)
  {
  case AF_INET:
    if (size != sizeof (struct in_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;
  case AF_INET6:
    if (size != sizeof (struct in6_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}
  

/**
 * Handle GET-message.
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_get (void *cls,
	    const struct GNUNET_RESOLVER_GetMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  const void *ip;
  int direction;
  int af;

  direction = ntohl (msg->direction);
  af = ntohl (msg->af);
  if (GNUNET_NO == direction)
  {
    /* IP from hostname */
    const char *hostname;

    hostname = (const char *) &msg[1];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Resolver asked to look up `%s'.\n",
                hostname);
    get_ip_from_hostname (client,
			  hostname,
			  af);
    return;
  }
  ip = &msg[1];
  
#if !defined(GNUNET_CULL_LOGGING)
  {
    char buf[INET6_ADDRSTRLEN];

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Resolver asked to look up IP address `%s'.\n",
		inet_ntop (af,
			   ip,
			   buf,
			   sizeof (buf)));
  }
#endif
  get_ip_as_string (client,
		    af,
		    ip);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
connect_cb (void *cls,
	    struct GNUNET_SERVICE_Client *c,
	    struct GNUNET_MQ_Handle *mq)
{
  return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
disconnect_cb (void *cls,
	       struct GNUNET_SERVICE_Client *c,
	       void *internal_cls)
{
  GNUNET_assert (c == internal_cls);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("resolver",
 GNUNET_SERVICE_OPTION_NONE,
 NULL,
 &connect_cb,
 &disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (get,
			GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST,
			struct GNUNET_RESOLVER_GetMessage,
			NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_RESOLVER_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/**
 * Free globals on exit.
 */
void __attribute__ ((destructor))
GNUNET_RESOLVER_memory_done ()
{
  struct IPCache *pos;

  while (NULL != (pos = cache_head))
  {
    GNUNET_CONTAINER_DLL_remove (cache_head,
				 cache_tail,
				 pos);
    GNUNET_free_non_null (pos->addr);
    GNUNET_free (pos);
  }
}


/* end of gnunet-service-resolver.c */
