/*
      This file is part of GNUnet
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
 * @file include/gnunet_dnsstub_lib.h
 * @brief API for helper library to send DNS requests to DNS resolver
 * @author Christian Grothoff
 */
#ifndef GNUNET_DNSSTUB_LIB_H
#define GNUNET_DNSSTUB_LIB_H

#include "gnunet_common.h"
#include "gnunet_tun_lib.h"

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
 * @param dns_ip target IP address to use
 * @return NULL on error
 */
struct GNUNET_DNSSTUB_Context *
GNUNET_DNSSTUB_start (const char *dns_ip);


/**
 * Cleanup DNSSTUB resolver.
 *
 * @param ctx stub resolver to clean up
 */
void
GNUNET_DNSSTUB_stop (struct GNUNET_DNSSTUB_Context *ctx);


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls closure
 * @param rs socket that received the response
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in 'dns'
 */
typedef void (*GNUNET_DNSSTUB_ResultCallback)(void *cls,
					      struct GNUNET_DNSSTUB_RequestSocket *rs,
					      const struct GNUNET_TUN_DnsHeader *dns,
					      size_t dns_len);


/**
 * Perform DNS resolution using given address.
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
			void *rc_cls);


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
			 void *rc_cls);


/**
 * Cancel DNS resolution.
 *
 * @param rs resolution to cancel
 */
void
GNUNET_DNSSTUB_resolve_cancel (struct GNUNET_DNSSTUB_RequestSocket *rs);

#endif
