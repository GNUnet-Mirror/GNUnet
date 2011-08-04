/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_validation.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_VALIDATION_H
#define GNUNET_SERVICE_TRANSPORT_VALIDATION_H

#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"


/**
 *
 */
void 
GST_validation_start (void);


/**
 *
 */
void
GST_validation_stop (void);


/**
 *
 */
int
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len);

/**
 *
 */
int
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len);


/**
 *
 */
void
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello);


struct GST_ValidationIteratorContext;

/**
 * @param last_validated_at is FOREVER if the address has not been validated (we're currently checking)
 *                          is ZERO if the address was validated a long time ago (from PEERINFO)
 *                          is a time in the past if this process validated the address
 * @param validation_block  is FOREVER if the address is for an unsupported plugin (from PEERINFO)
 *                          is ZERO if the address is considered valid (no validation needed)
 *                          is a time in the future if we're currently denying re-validation
 */
typedef void (*GST_ValidationAddressCallback)(void *cls,
					      const struct GNUNET_PeerIdentity *target,
					      struct GNUNET_TIME_Absolute last_validated_at,
					      struct GNUNET_TIME_Absolute validation_block,
					      const char *plugin_name,
					      const void *plugin_address,
					      size_t plugin_address_len);

struct GST_ValidationIteratorContext *
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
			      GST_ValidationAddressCallback cb,
			      void *cb_cls);



void
GST_validation_get_addresses_cancel (struct GST_ValidationIteratorContext *ctx);



#endif
/* end of file gnunet-service-transport_validation.h */
