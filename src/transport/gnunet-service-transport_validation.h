/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 GNUnet e.V.

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
 * @file transport/gnunet-service-transport_validation.h
 * @brief address validation API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_VALIDATION_H
#define GNUNET_SERVICE_TRANSPORT_VALIDATION_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"

/**
 * Start the validation subsystem.
 *
 * @param max_fds maximum number of fds to use
 */
void
GST_validation_start (unsigned int max_fds);


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop (void);


/**
 * Update if we are using an address for a connection actively right now.
 * Based on this, the validation module will measure latency for the
 * address more or less often.
 *
 * @param address the address that we are now using (or not)
 * @param in_use #GNUNET_YES if we are now using the address for a connection,
 *               #GNUNET_NO if we are no longer using the address for a connection
 */
void
GST_validation_set_address_use (const struct GNUNET_HELLO_Address *address,
                                int in_use);


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param sender_address address of the sender, NULL if we did not initiate
 * @param session session we got the PING from
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
                            const struct GNUNET_MessageHeader *hdr,
                            const struct GNUNET_HELLO_Address *sender_address,
                            struct GNUNET_ATS_Session *session);


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
                            const struct GNUNET_MessageHeader *hdr);


/**
 * We've received a HELLO, check which addresses are new and trigger
 * validation.
 *
 * @param hello the HELLO we received
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello);


/**
 * Validate an individual address.
 *
 * @param address address we should try to validate
 */
void
GST_validation_handle_address (const struct GNUNET_HELLO_Address *address);


/**
 * Function called for each address (or address status change) that
 * the validation module is aware of (for the given target).
 *
 * @param cls closure
 * @param public_key public key for the peer, never NULL
 * @param valid_until is ZERO if we never validated the address,
 *                    otherwise a time up to when we consider it (or was) valid
 * @param validation_block  is FOREVER if the address is for an unsupported plugin (from PEERINFO)
 *                          is ZERO if the address is considered valid (no validation needed)
 *                          otherwise a time in the future if we're currently denying re-validation
 * @param address the address
 */
typedef void
(*GST_ValidationAddressCallback) (void *cls,
                                  struct GNUNET_TIME_Absolute valid_until,
                                  struct GNUNET_TIME_Absolute validation_block,
                                  const struct GNUNET_HELLO_Address *address);


/**
 * Call the given function for each address for the given target.
 *
 * @param target peer information is requested for
 * @param cb function to call; will not be called after this function returns
 * @param cb_cls closure for @a cb
 */
void
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
                              GST_ValidationAddressCallback cb, void *cb_cls);


#endif
/* end of file gnunet-service-transport_validation.h */
