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
 * @brief address validation API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_VALIDATION_H
#define GNUNET_SERVICE_TRANSPORT_VALIDATION_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_util_lib.h"


/**
 * Start the validation subsystem.
 */
void 
GST_validation_start (void);


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop (void);


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param plugin_name name of plugin that received the PING
 * @param session session we got the PING from
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    struct Session *session,
			    const void *sender_address,
			    size_t sender_address_len);


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 * @param plugin_name name of plugin that received the PONG
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len);


/**
 * We've received a HELLO, check which addresses are new and trigger
 * validation.
 *
 * @param hello the HELLO we received
 */
void
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello);


/**
 * Opaque handle to stop incremental validation address callbacks.
 */
struct GST_ValidationIteratorContext;


/**
 * Function called for each address (or address status change) that
 * the validation module is aware of (for the given target).
 *
 * @param cls closure
 * @param public_key public key for the peer, never NULL
 * @param target peer this change is about, never NULL
 * @param valid_until is ZERO if we never validated the address,
 *                    otherwise a time up to when we consider it (or was) valid
 * @param validation_block  is FOREVER if the address is for an unsupported plugin (from PEERINFO)
 *                          is ZERO if the address is considered valid (no validation needed)
 *                          otherwise a time in the future if we're currently denying re-validation
 * @param plugin_name name of the plugin
 * @param plugin_address binary address
 * @param plugin_address_len length of address
 */
typedef void (*GST_ValidationAddressCallback)(void *cls,
					      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
					      const struct GNUNET_PeerIdentity *target,
					      struct GNUNET_TIME_Absolute valid_until,
					      struct GNUNET_TIME_Absolute validation_block,
					      const char *plugin_name,
					      const void *plugin_address,
					      size_t plugin_address_len);


/**
 * Call the given function for each address for the given target.
 * Can either give a snapshot (synchronous API) or be continuous.
 *
 * @param target peer information is requested for
 * @param snapshot_only GNUNET_YES to iterate over addresses once, GNUNET_NO to
 *                      continue to give information about addresses as it evolves
 * @param cb function to call; will not be called after this function returns
 *                             if snapshot_only is GNUNET_YES
 * @param cb_cls closure for 'cb'
 * @return context to cancel, NULL if 'snapshot_only' is GNUNET_YES
 */
struct GST_ValidationIteratorContext *
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
			      int snapshot_only,
			      GST_ValidationAddressCallback cb,
			      void *cb_cls);


/**
 * Cancel an active validation address iteration.
 *
 * @param ctx the context of the operation that is cancelled
 */
void
GST_validation_get_addresses_cancel (struct GST_ValidationIteratorContext *ctx);



#endif
/* end of file gnunet-service-transport_validation.h */
