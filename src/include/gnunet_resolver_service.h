/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_resolver_service.h
 * @brief functions related to doing DNS lookups
 * @author Christian Grothoff
 */

#ifndef GNUNET_RESOLVER_SERVICE_H
#define GNUNET_RESOLVER_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"


/**
 * Function called by the resolver for each address obtained from DNS.
 *
 * @param cls closure
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
typedef void (*GNUNET_RESOLVER_AddressCallback) (void *cls,
                                                 const struct sockaddr * addr,
                                                 socklen_t addrlen);


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.
 */
struct GNUNET_RESOLVER_RequestHandle;

/**
 * Create the connection to the resolver service.
 *
 * @param cfg configuration to use
 */
void
GNUNET_RESOLVER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy the connection to the resolver service.
 */
void
GNUNET_RESOLVER_disconnect (void);


/**
 * Convert a string to one or more IP addresses.
 *
 * @param hostname the hostname to resolve
 * @param af AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param callback_cls closure for callback
 * @param timeout how long to try resolving
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_ip_get (const char *hostname, int af,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_RESOLVER_AddressCallback callback,
                        void *callback_cls);


/**
 * Resolve our hostname to an IP address.
 *
 * @param af AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param callback function to call with addresses
 * @param cls closure for callback
 * @param timeout how long to try resolving
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_resolve (int af,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_RESOLVER_AddressCallback callback,
                                  void *cls);


/**
 * Function called by the resolver for each hostname obtained from DNS.
 *
 * @param cls closure
 * @param hostname one of the names for the host, NULL
 *        on the last call to the callback
 */
typedef void (*GNUNET_RESOLVER_HostnameCallback) (void *cls,
                                                  const char *hostname);

/**
 * Get local fully qualified domain name
 *
 * @return local hostname, caller must free
 */
char *
GNUNET_RESOLVER_local_fqdn_get (void);


/**
 * Perform a reverse DNS lookup.
 *
 * @param sa host address
 * @param salen length of host address
 * @param do_resolve use GNUNET_NO to return numeric hostname
 * @param timeout how long to try resolving
 * @param callback function to call with hostnames
 * @param cls closure for callback
 * @return handle that can be used to cancel the request, NULL on error
 */
struct GNUNET_RESOLVER_RequestHandle *
GNUNET_RESOLVER_hostname_get (const struct sockaddr *sa, socklen_t salen,
                              int do_resolve,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_RESOLVER_HostnameCallback callback,
                              void *cls);


/**
 * Cancel a request that is still pending with the resolver.
 * Note that a client MUST NOT cancel a request that has
 * been completed (i.e, the callback has been called to
 * signal timeout or the final result).
 *
 * @param rh handle of request to cancel
 */
void
GNUNET_RESOLVER_request_cancel (struct GNUNET_RESOLVER_RequestHandle *rh);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_RESOLVER_SERVICE_H */
#endif
/* end of gnunet_resolver_service.h */
