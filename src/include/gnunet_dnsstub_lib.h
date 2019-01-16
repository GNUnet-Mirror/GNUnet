/*
      This file is part of GNUnet
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
 * @author Christian Grothoff
 *
 * @file
 * API for helper library to send DNS requests to DNS resolver
 *
 * @defgroup dns-stub  DNS Stub library
 * Helper library to send DNS requests to DNS resolver
 * @{
 */
#ifndef GNUNET_DNSSTUB_LIB_H
#define GNUNET_DNSSTUB_LIB_H

#include "gnunet_util_lib.h"

/**
 * Opaque handle to the stub resolver.
 */
struct GNUNET_DNSSTUB_Context;

/**
 * Opaque handle to a socket doing UDP requests.
 */
struct GNUNET_DNSSTUB_RequestSocket;


/**
 * Start a DNS stub resolver.
 *
 * @param num_sockets how many sockets should we open
 *        in parallel for DNS queries for this stub?
 * @return NULL on error
 */
struct GNUNET_DNSSTUB_Context *
GNUNET_DNSSTUB_start (unsigned int num_sockets);


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
                           const char *dns_ip);


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
                           const struct sockaddr *sa);


/**
 * How long should we try requests before timing out?
 * Only effective for requests issued after this call.
 *
 * @param ctx resolver context to modify
 * @param retry_frequ how long to wait between retries
 */
void
GNUNET_DNSSTUB_set_retry (struct GNUNET_DNSSTUB_Context *ctx,
                          struct GNUNET_TIME_Relative retry_freq);

/**
 * Cleanup DNSSTUB resolver.
 *
 * @param ctx stub resolver to clean up
 */
void
GNUNET_DNSSTUB_stop (struct GNUNET_DNSSTUB_Context *ctx);


/**
 * Function called with the result of a DNS resolution.
 * Once this function is called, the resolution request
 * is automatically cancelled / cleaned up.  In particular,
 * the function will only be called once.
 *
 * @param cls closure
 * @param dns dns response, NULL on hard error (i.e. timeout)
 * @param dns_len number of bytes in @a dns
 */
typedef void
(*GNUNET_DNSSTUB_ResultCallback)(void *cls,
                                 const struct GNUNET_TUN_DnsHeader *dns,
                                 size_t dns_len);


/**
 * Perform DNS resolution using our default IP from init.
 *
 * @param ctx stub resolver to use
 * @param request DNS request to transmit
 * @param request_len number of bytes in msg
 * @param rc function to call with result (once)
 * @param rc_cls closure for @a rc
 * @return socket used for the request, NULL on error
 */
struct GNUNET_DNSSTUB_RequestSocket *
GNUNET_DNSSTUB_resolve (struct GNUNET_DNSSTUB_Context *ctx,
                        const void *request,
                        size_t request_len,
                        GNUNET_DNSSTUB_ResultCallback rc,
                        void *rc_cls);


/**
 * Cancel DNS resolution.
 *
 * @param rs resolution to cancel
 */
void
GNUNET_DNSSTUB_resolve_cancel (struct GNUNET_DNSSTUB_RequestSocket *rs);


#endif

/** @} */  /* end of group */
