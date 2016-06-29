/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @file util/resolver_api.c
 * @brief resolver for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "resolver.h"

#define LOG(kind,...) GNUNET_log_from (kind, "resolver-api", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "resolver-api", syscall)

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
 * Configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *resolver_cfg;

/**
 * Our connection to the resolver service, created on-demand, but then
 * persists until error or shutdown.
 */
static struct GNUNET_MQ_Handle *mq;

/**
 * Head of DLL of requests.
 */
static struct GNUNET_RESOLVER_RequestHandle *req_head;

/**
 * Tail of DLL of requests.
 */
static struct GNUNET_RESOLVER_RequestHandle *req_tail;

/**
 * How long should we wait to reconnect?
 */
static struct GNUNET_TIME_Relative backoff;

/**
 * Task for reconnecting.
 */
static struct GNUNET_SCHEDULER_Task *r_task;

/**
 * Task ID of shutdown task; only present while we have a
 * connection to the resolver service.
 */
static struct GNUNET_SCHEDULER_Task *s_task;


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_RESOLVER_RequestHandle
{

  /**
   * Next entry in DLL of requests.
   */
  struct GNUNET_RESOLVER_RequestHandle *next;

  /**
   * Previous entry in DLL of requests.
   */
  struct GNUNET_RESOLVER_RequestHandle *prev;

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
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * When should this request time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task handle for making reply callbacks in numeric lookups
   * asynchronous, and for timeout handling.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Desired address family.
   */
  int af;

  /**
   * Has this request been transmitted to the service?
   * #GNUNET_YES if transmitted
   * #GNUNET_YES if not transmitted
   * #GNUNET_SYSERR when request was canceled
   */
  int was_transmitted;

  /**
   * Did we add this request to the queue?
   */
  int was_queued;

  /**
   * Desired direction (IP to name or name to IP)
   */
  int direction;

  /**
   * #GNUNET_YES if a response was received
   */
  int received_response;

  /**
   * Length of the data that follows this struct.
   */
  size_t data_len;
};


/**
 * Check that the resolver service runs on localhost
 * (or equivalent).
 *
 * @return #GNUNET_OK if the resolver is properly configured,
 *         #GNUNET_SYSERR otherwise.
 */
static int
check_config ()
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
      GNUNET_CONFIGURATION_get_value_string (resolver_cfg,
                                             "resolver",
                                             "HOSTNAME",
                                             &hostname))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Missing `%s' for `%s' in configuration, DNS resolution will be unavailable.\n"),
         "HOSTNAME",
         "resolver");
    return GNUNET_SYSERR;
  }
  if ((1 == inet_pton (AF_INET, hostname, &v4)) ||
      (1 == inet_pton (AF_INET6, hostname, &v6)))
  {
    GNUNET_free (hostname);
    return GNUNET_OK;
  }
  i = 0;
  while (NULL != loopback[i])
    if (0 == strcasecmp (loopback[i++], hostname))
    {
      GNUNET_free (hostname);
      return GNUNET_OK;
    }
  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Missing `%s' or numeric IP address for `%s' of `%s' in configuration, DNS resolution will be unavailable.\n"),
       "localhost",
       "HOSTNAME",
       "resolver");
  GNUNET_free (hostname);
  return GNUNET_SYSERR;
}


/**
 * Create the connection to the resolver service.
 *
 * @param cfg configuration to use
 */
void
GNUNET_RESOLVER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (NULL != cfg);
  backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  resolver_cfg = cfg;
}


/**
 * Destroy the connection to the resolver service.
 */
void
GNUNET_RESOLVER_disconnect ()
{
  GNUNET_assert (NULL == req_head);
  GNUNET_assert (NULL == req_tail);
  if (NULL != mq)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Disconnecting from DNS service\n");
    GNUNET_MQ_destroy (mq);
    mq = NULL;
  }
  if (NULL != r_task)
  {
    GNUNET_SCHEDULER_cancel (r_task);
    r_task = NULL;
  }
  if (NULL != s_task)
  {
    GNUNET_SCHEDULER_cancel (s_task);
    s_task = NULL;
  }
}


/**
 * Convert IP address to string without DNS resolution.
 *
 * @param af address family
 * @param ip the address
 * @param ip_len number of bytes in @a ip
 * @return address as a string, NULL on error
 */
static char *
no_resolve (int af,
	    const void *ip,
            socklen_t ip_len)
{
  char buf[INET6_ADDRSTRLEN];

  switch (af)
  {
  case AF_INET:
    if (ip_len != sizeof (struct in_addr))
      return NULL;
    if (NULL ==
        inet_ntop (AF_INET, ip, buf, sizeof (buf)))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                    "inet_ntop");
      return NULL;
    }
    break;
  case AF_INET6:
    if (ip_len != sizeof (struct in6_addr))
      return NULL;
    if (NULL ==
        inet_ntop (AF_INET6, ip, buf, sizeof (buf)))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                    "inet_ntop");
      return NULL;
    }
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  return GNUNET_strdup (buf);
}


/**
 * Adjust exponential back-off and reconnect to the service.
 */
static void
reconnect (void);


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls NULL
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  GNUNET_MQ_destroy (mq);
  mq = NULL;
  reconnect ();
}


/**
 * Task executed on system shutdown.
 */
static void
shutdown_task (void *cls)
{
  s_task = NULL;
  GNUNET_RESOLVER_disconnect ();
  backoff = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Process pending requests to the resolver.
 */
static void
process_requests ()
{
  struct GNUNET_RESOLVER_GetMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_RESOLVER_RequestHandle *rh = req_head;

  if (NULL == mq)
  {
    reconnect ();
    return;
  }
  if (NULL == rh)
  {
    /* nothing to do, release socket really soon if there is nothing
     * else happening... */
    s_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                    &shutdown_task,
                                    NULL);
    return;
  }
  if (GNUNET_NO != rh->was_transmitted)
    return;                     /* waiting for reply */
  env = GNUNET_MQ_msg_extra (msg,
                             rh->data_len,
                             GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST);
  msg->direction = htonl (rh->direction);
  msg->af = htonl (rh->af);
  memcpy (&msg[1],
          &rh[1],
          rh->data_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting DNS resolution request to DNS service\n");
  GNUNET_MQ_send (mq,
                  env);
  rh->was_transmitted = GNUNET_YES;
}


/**
 * Check validity of response with a hostname for a DNS lookup.
 *
 * @param cls NULL
 * @param msg message with the hostname
 */
static int
check_response (void *cls,
                const struct GNUNET_MessageHeader *msg)
{
  /* implemented in #handle_response() for now */
  return GNUNET_OK;
}


/**
 * Check validity of response with a hostname for a DNS lookup.
 * NOTE: right now rather messy, might want to use different
 * message types for different response formats in the future.
 *
 * @param cls NULL
 * @param msg message with the response
 */
static void
handle_response (void *cls,
                 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = req_head;
  uint16_t size;
  char *nret;

  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received empty response from DNS service\n");
    /* message contains not data, just header; end of replies */
    /* check if request was canceled */
    if (GNUNET_SYSERR != rh->was_transmitted)
    {
      /* no reverse lookup was successful, return IP as string */
      if (NULL != rh->name_callback)
      {
        if (GNUNET_NO == rh->received_response)
        {
          nret = no_resolve (rh->af,
                             &rh[1],
                             rh->data_len);
          rh->name_callback (rh->cls, nret);
          GNUNET_free (nret);
        }
        /* finally, make termination call */
        rh->name_callback (rh->cls,
                           NULL);
      }
      if (NULL != rh->addr_callback)
        rh->addr_callback (rh->cls,
                           NULL,
                           0);
    }
    rh->was_transmitted = GNUNET_NO;
    GNUNET_RESOLVER_request_cancel (rh);
    process_requests ();
    return;
  }
  /* return reverse lookup results to caller */
  if (NULL != rh->name_callback)
  {
    const char *hostname;

    hostname = (const char *) &msg[1];
    if (hostname[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
    {
      GNUNET_break (0);
      if (GNUNET_SYSERR != rh->was_transmitted)
        rh->name_callback (rh->cls,
                           NULL);
      rh->was_transmitted = GNUNET_NO;
      GNUNET_RESOLVER_request_cancel (rh);
      GNUNET_MQ_destroy (mq);
      mq = NULL;
      reconnect ();
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Resolver returns `%s' for IP `%s'.\n",
         hostname,
         GNUNET_a2s ((const void *) &rh[1],
                     rh->data_len));
    if (rh->was_transmitted != GNUNET_SYSERR)
      rh->name_callback (rh->cls,
                         hostname);
    rh->received_response = GNUNET_YES;
  }
  /* return lookup results to caller */
  if (NULL != rh->addr_callback)
  {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    const struct sockaddr *sa;
    socklen_t salen;
    const void *ip;
    size_t ip_len;

    ip = &msg[1];
    ip_len = size - sizeof (struct GNUNET_MessageHeader);
    if (ip_len == sizeof (struct in_addr))
    {
      memset (&v4, 0, sizeof (v4));
      v4.sin_family = AF_INET;
      v4.sin_addr = *(struct in_addr*) ip;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4.sin_len = sizeof (v4);
#endif
      salen = sizeof (v4);
      sa = (const struct sockaddr *) &v4;
    }
    else if (ip_len == sizeof (struct in6_addr))
    {
      memset (&v6, 0, sizeof (v6));
      v6.sin6_family = AF_INET6;
      v6.sin6_addr = *(struct in6_addr*) ip;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6.sin6_len = sizeof (v6);
#endif
      salen = sizeof (v6);
      sa = (const struct sockaddr *) &v6;
    }
    else
    {
      GNUNET_break (0);
      if (GNUNET_SYSERR != rh->was_transmitted)
        rh->addr_callback (rh->cls,
                           NULL,
                           0);
      rh->was_transmitted = GNUNET_NO;
      GNUNET_RESOLVER_request_cancel (rh);
      GNUNET_MQ_destroy (mq);
      mq = NULL;
      reconnect ();
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received IP from DNS service\n");
    if (GNUNET_SYSERR != rh->was_transmitted)
      rh->addr_callback (rh->cls,
                         sa,
                         salen);
  }
}


/**
 * We've been asked to lookup the address for a hostname and were
 * given a valid numeric string.  Perform the callbacks for the
 * numeric addresses.
 *
 * @param cls `struct GNUNET_RESOLVER_RequestHandle` for the request
 */
static void
numeric_resolution (void *cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  const char *hostname;

  rh->task = NULL;
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
  hostname = (const char *) &rh[1];
  if (((rh->af == AF_UNSPEC) || (rh->af == AF_INET)) &&
      (1 == inet_pton (AF_INET, hostname, &v4.sin_addr)))
  {
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v4,
                       sizeof (v4));
    if ((rh->af == AF_UNSPEC) &&
        (1 == inet_pton (AF_INET6, hostname, &v6.sin6_addr)))
    {
      /* this can happen on some systems IF "hostname" is "localhost" */
      rh->addr_callback (rh->cls,
                         (const struct sockaddr *) &v6,
                         sizeof (v6));
    }
    rh->addr_callback (rh->cls,
                       NULL,
                       0);
    GNUNET_free (rh);
    return;
  }
  if ( ( (rh->af == AF_UNSPEC) ||
         (rh->af == AF_INET6) ) &&
       (1 == inet_pton (AF_INET6, hostname, &v6.sin6_addr) ) )
  {
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v6,
                       sizeof (v6));
    rh->addr_callback (rh->cls,
                       NULL,
                       0);
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
 * @param cls `struct GNUNET_RESOLVER_RequestHandle` for the request
 */
static void
loopback_resolution (void *cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

  rh->task = NULL;
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
  switch (rh->af)
  {
  case AF_INET:
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v4,
                       sizeof (v4));
    break;
  case AF_INET6:
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v6,
                       sizeof (v6));
    break;
  case AF_UNSPEC:
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v6,
                       sizeof (v6));
    rh->addr_callback (rh->cls,
                       (const struct sockaddr *) &v4,
                       sizeof (v4));

    break;
  default:
    GNUNET_break (0);
    break;
  }
  rh->addr_callback (rh->cls,
                     NULL,
                     0);
  GNUNET_free (rh);
}


/**
 * Now try to reconnect to the resolver service.
 *
 * @param cls NULL
 */
static void
reconnect_task (void *cls)
{
  GNUNET_MQ_hd_var_size (response,
                         GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE,
                         struct GNUNET_MessageHeader);
  struct GNUNET_MQ_MessageHandler handlers[] = {
     make_response_handler (NULL),
     GNUNET_MQ_handler_end ()
  };

  r_task = NULL;
  if (NULL == req_head)
    return;                     /* no work pending */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect to DNS service\n");
  mq = GNUNET_CLIENT_connecT (resolver_cfg,
                              "resolver",
                              handlers,
                              &mq_error_handler,
                              NULL);
  if (NULL == mq)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failed to connect, will try again later\n");
    reconnect ();
    return;
  }
  process_requests ();
}


/**
 * Adjust exponential back-off and reconnect to the service.
 */
static void
reconnect ()
{
  struct GNUNET_RESOLVER_RequestHandle *rh;

  if (NULL != r_task)
    return;
  GNUNET_assert (NULL == mq);
  if (NULL != (rh = req_head))
  {
    switch (rh->was_transmitted)
    {
    case GNUNET_NO:
      /* nothing more to do */
      break;
    case GNUNET_YES:
      /* disconnected, transmit again! */
      rh->was_transmitted = GNUNET_NO;
      break;
    case GNUNET_SYSERR:
      /* request was cancelled, remove entirely */
      GNUNET_CONTAINER_DLL_remove (req_head,
				   req_tail,
				   rh);
      GNUNET_free (rh);
      break;
    default:
      GNUNET_assert (0);
      break;
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Will try to connect to DNS service in %s\n",
       GNUNET_STRINGS_relative_time_to_string (backoff,
                                               GNUNET_YES));
  GNUNET_assert (NULL != resolver_cfg);
  r_task = GNUNET_SCHEDULER_add_delayed (backoff,
                                         &reconnect_task,
                                         NULL);
  backoff = GNUNET_TIME_STD_BACKOFF (backoff);
}


/**
 * A DNS resolution timed out. Notify the application.
 *
 * @param cls the `struct GNUNET_RESOLVER_RequestHandle *`
 */
static void
handle_lookup_timeout (void *cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;

  rh->task = NULL;
  if (GNUNET_NO == rh->direction)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Timeout trying to resolve hostname `%s'.\n"),
         (const char *) &rh[1]);
    if (NULL != rh->addr_callback)
      rh->addr_callback (rh->cls,
                         NULL,
                         0);
  }
  else
  {
    char buf[INET6_ADDRSTRLEN];

    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Timeout trying to resolve IP address `%s'.\n"),
         inet_ntop (rh->af,
                    (const void *) &rh[1],
                    buf,
                    sizeof(buf)));
    if (GNUNET_NO == rh->received_response)
    {
      char *nret;

      nret = no_resolve (rh->af,
                         &rh[1],
                         rh->data_len);
      if (NULL != rh->name_callback)
        rh->name_callback (rh->cls, nret);
      GNUNET_free (nret);
    }
    /* finally, make termination call */
    if (NULL != rh->name_callback)
      rh->name_callback (rh->cls,
                         NULL);
  }
  rh->was_transmitted = GNUNET_NO;
  GNUNET_RESOLVER_request_cancel (rh);
  process_requests ();
}


/**
 * Convert a string to one or more IP addresses.
 *
 * @param hostname the hostname to resolve
 * @param af AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param callback_cls closure for @a callback
 * @param timeout how long to try resolving
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_ip_get (const char *hostname,
                        int af,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_RESOLVER_AddressCallback callback,
                        void *callback_cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh;
  size_t slen;
  unsigned int i;
  struct in_addr v4;
  struct in6_addr v6;

  slen = strlen (hostname) + 1;
  if (slen + sizeof (struct GNUNET_RESOLVER_GetMessage) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  rh = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_RequestHandle) + slen);
  rh->af = af;
  rh->addr_callback = callback;
  rh->cls = callback_cls;
  memcpy (&rh[1],
          hostname,
          slen);
  rh->data_len = slen;
  rh->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  rh->direction = GNUNET_NO;
  /* first, check if this is a numeric address */
  if (((1 == inet_pton (AF_INET, hostname, &v4)) &&
       ((af == AF_INET) || (af == AF_UNSPEC))) ||
      ((1 == inet_pton (AF_INET6, hostname, &v6)) &&
       ((af == AF_INET6) || (af == AF_UNSPEC))))
  {
    rh->task = GNUNET_SCHEDULER_add_now (&numeric_resolution,
                                         rh);
    return rh;
  }
  /* then, check if this is a loopback address */
  i = 0;
  while (NULL != loopback[i])
    if (0 == strcasecmp (loopback[i++],
                         hostname))
    {
      rh->task = GNUNET_SCHEDULER_add_now (&loopback_resolution,
                                           rh);
      return rh;
    }
  if (GNUNET_OK != check_config ())
  {
    GNUNET_free (rh);
    return NULL;
  }
  rh->task = GNUNET_SCHEDULER_add_delayed (timeout,
                                           &handle_lookup_timeout,
                                           rh);
  GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                    req_tail,
                                    rh);
  rh->was_queued = GNUNET_YES;
  if (NULL != s_task)
  {
    GNUNET_SCHEDULER_cancel (s_task);
    s_task = NULL;
  }
  process_requests ();
  return rh;
}


/**
 * We've been asked to convert an address to a string without
 * a reverse lookup, either because the client asked for it
 * or because the DNS lookup hit a timeout.  Do the numeric
 * conversion and invoke the callback.
 *
 * @param cls `struct GNUNET_RESOLVER_RequestHandle` for the request
 */
static void
numeric_reverse (void *cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh = cls;
  char *result;

  rh->task = NULL;
  result = no_resolve (rh->af,
                       &rh[1],
                       rh->data_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resolver returns `%s'.\n",
       result);
  if (NULL != result)
  {
    rh->name_callback (rh->cls,
                       result);
    GNUNET_free (result);
  }
  rh->name_callback (rh->cls,
                     NULL);
  if (NULL != rh->task)
  {
    GNUNET_SCHEDULER_cancel (rh->task);
    rh->task = NULL;
  }
  GNUNET_free (rh);
}


/**
 * Get an IP address as a string.
 *
 * @param sa host address
 * @param salen length of host address in @a sa
 * @param do_resolve use #GNUNET_NO to return numeric hostname
 * @param timeout how long to try resolving
 * @param callback function to call with hostnames
 *        last callback is NULL when finished
 * @param cls closure for @a callback
 * @return handle that can be used to cancel the request
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_get (const struct sockaddr *sa,
                              socklen_t salen,
                              int do_resolve,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_RESOLVER_HostnameCallback callback,
                              void *cls)
{
  struct GNUNET_RESOLVER_RequestHandle *rh;
  size_t ip_len;
  const void *ip;

  if (GNUNET_OK != check_config ())
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Resolver not configured correctly.\n"));
    return NULL;
  }

  switch (sa->sa_family)
  {
  case AF_INET:
    GNUNET_assert (salen == sizeof (struct sockaddr_in));
    ip_len = sizeof (struct in_addr);
    ip = &((const struct sockaddr_in*)sa)->sin_addr;
    break;
  case AF_INET6:
    GNUNET_assert (salen == sizeof (struct sockaddr_in6));
    ip_len = sizeof (struct in6_addr);
    ip = &((const struct sockaddr_in6*)sa)->sin6_addr;
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  rh = GNUNET_malloc (sizeof (struct GNUNET_RESOLVER_RequestHandle) + salen);
  rh->name_callback = callback;
  rh->cls = cls;
  rh->af = sa->sa_family;
  rh->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  memcpy (&rh[1],
          ip,
          ip_len);
  rh->data_len = ip_len;
  rh->direction = GNUNET_YES;
  rh->received_response = GNUNET_NO;
  if (GNUNET_NO == do_resolve)
  {
    rh->task = GNUNET_SCHEDULER_add_now (&numeric_reverse,
                                         rh);
    return rh;
  }
  rh->task = GNUNET_SCHEDULER_add_delayed (timeout,
                                           &handle_lookup_timeout,
                                           rh);
  GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                    req_tail,
                                    rh);
  rh->was_queued = GNUNET_YES;
  if (NULL != s_task)
  {
    GNUNET_SCHEDULER_cancel (s_task);
    s_task = NULL;
  }
  process_requests ();
  return rh;
}


/**
 * Get local fully qualified af name
 *
 * @return fqdn
 */
char *
GNUNET_RESOLVER_local_fqdn_get ()
{
  char hostname[GNUNET_OS_get_hostname_max_length () + 1];

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "gethostname");
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resolving our FQDN `%s'\n",
       hostname);
#if HAVE_GETADDRINFO
  {
    struct addrinfo *ai;
    int ret;
    char *rval;

    if (0 != (ret = getaddrinfo (hostname, NULL, NULL, &ai)))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Could not resolve our FQDN: %s\n"),
           gai_strerror (ret));
      return NULL;
    }
    if (NULL != ai->ai_canonname)
      rval = GNUNET_strdup (ai->ai_canonname);
    else
      rval = GNUNET_strdup (hostname);
    freeaddrinfo (ai);
    return rval;
  }
#elif HAVE_GETHOSTBYNAME2
  {
    struct hostent *host;

    host = gethostbyname2 (hostname, AF_INET);
    if (NULL == host)
      host = gethostbyname2 (hostname, AF_INET6);
    if (NULL == host)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Could not resolve our FQDN: %s\n"),
             hstrerror (h_errno));
        return NULL;
      }
    return GNUNET_strdup (host->h_name);
  }
#elif HAVE_GETHOSTBYNAME
  {
    struct hostent *host;

    host = gethostbyname (hostname);
    if (NULL == host)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Could not resolve our FQDN: %s\n"),
             hstrerror (h_errno));
        return NULL;
      }
    return GNUNET_strdup (host->h_name);
  }
#else
  /* fallback: just hope name is already FQDN */
  return GNUNET_strdup (hostname);
#endif
}


/**
 * Looking our own hostname.
 *
 * @param af AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param timeout how long to try resolving
 * @param callback function to call with addresses
 * @param cls closure for @a callback
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_resolve (int af,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_RESOLVER_AddressCallback callback,
                                  void *cls)
{
  char hostname[GNUNET_OS_get_hostname_max_length () + 1];

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "gethostname");
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resolving our hostname `%s'\n",
       hostname);
  return GNUNET_RESOLVER_ip_get (hostname,
                                 af,
                                 timeout,
                                 callback,
                                 cls);
}


/**
 * Cancel a request that is still pending with the resolver.
 * Note that a client MUST NOT cancel a request that has
 * been completed (i.e, the callback has been called to
 * signal timeout or the final result).
 *
 * @param rh handle of request to cancel
 */
void
GNUNET_RESOLVER_request_cancel (struct GNUNET_RESOLVER_RequestHandle *rh)
{
  if (NULL != rh->task)
  {
    GNUNET_SCHEDULER_cancel (rh->task);
    rh->task = NULL;
  }
  if (GNUNET_NO == rh->was_transmitted)
  {
    if (GNUNET_YES == rh->was_queued)
      GNUNET_CONTAINER_DLL_remove (req_head,
                                   req_tail,
                                   rh);
    GNUNET_free (rh);
    return;
  }
  GNUNET_assert (GNUNET_YES == rh->was_transmitted);
  rh->was_transmitted = GNUNET_SYSERR;  /* mark as cancelled */
}


/* end of resolver_api.c */
