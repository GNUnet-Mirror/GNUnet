/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dns_service-new.h
 * @brief API to access the DNS service. 
 * @author Christian Grothoff
 */
#ifndef GNUNET_DNS_SERVICE_NEW_H
#define GNUNET_DNS_SERVICE_NEW_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"


/**
 * Opaque DNS handle
 */
struct GNUNET_DNS_Handle;

/**
 * Handle to identify an individual DNS request.
 */
struct GNUNET_DNS_RequestHandle;


/**
 * Signature of a function that is called whenever the DNS service
 * encounters a DNS request and needs to do something with it.  The
 * function has then the chance to generate or modify the response by
 * calling one of the three "GNUNET_DNS_request_*" continuations.
 *
 * When a request is intercepted, this function is called first to
 * give the client a chance to do the complete address resolution;
 * "rdata" will be NULL for this first call for a DNS request, unless
 * some other client has already filled in a response.
 *
 * If multiple clients exist, all of them are called before the global
 * DNS.  The global DNS is only called if all of the clients'
 * functions call GNUNET_DNS_request_forward.  Functions that call
 * GNUNET_DNS_request_forward will be called again before a final
 * response is returned to the application.  If any of the clients'
 * functions call GNUNET_DNS_request_drop, the response is dropped.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
typedef void (*GNUNET_DNS_RequestHandler)(void *cls,
					  struct GNUNET_DNS_RequestHandle *rh,
					  size_t request_length,
					  const char *request);


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * given to other clients or the global DNS for resolution.  Once a
 * global response has been obtained, the request handler is AGAIN
 * called to give it a chance to observe and modify the response after
 * the "normal" resolution.  It is not legal for the request handler
 * to call this function if a response is already present.
 *
 * @param rh request that should now be forwarded
 */
void
GNUNET_DNS_request_forward (struct GNUNET_DNS_RequestHandle *rh);


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * to be dropped and no response should be generated.
 *
 * @param rh request that should now be dropped
 */
void
GNUNET_DNS_request_drop (struct GNUNET_DNS_RequestHandle *rh);


/**
 * If a GNUNET_DNS_RequestHandler calls this function, the request is
 * supposed to be answered with the data provided to this call (with
 * the modifications the function might have made).
 *
 * @param rh request that should now be answered
 * @param reply_length size of reply (uint16_t to force sane size)
 * @param reply reply data
 */
void
GNUNET_DNS_request_answer (struct GNUNET_DNS_RequestHandle *rh,		   
			   uint16_t reply_length,
			   const char *reply);


/**
 * Connect to the service-dns
 *
 * @param cfg configuration to use
 * @param rh function to call with DNS requests
 * @param rh_cls closure to pass to rh
 * @return DNS handle 
 */
struct GNUNET_DNS_Handle *
GNUNET_DNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    GNUNET_DNS_RequestHandler rh,
		    void *rh_cls);


/**
 * Disconnect from the DNS service.
 *
 * @param dh DNS handle
 */
void
GNUNET_DNS_disconnect (struct GNUNET_DNS_Handle *dh);

#endif
