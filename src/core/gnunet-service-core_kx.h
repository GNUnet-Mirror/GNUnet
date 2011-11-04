/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_kx.h
 * @brief code for managing the key exchange (SET_KEY, PING, PONG) with other peers
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_KX_H
#define GNUNET_SERVICE_CORE_KX_H

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"


/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo;


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the set key message we received
 */
void
GSC_KX_handle_set_key (struct GSC_KeyExchangeInfo *kx,
                       const struct GNUNET_MessageHeader *msg);


/**
 * We received a PING message.  Validate and transmit
 * a PONG message.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the encrypted PING message itself
 */
void
GSC_KX_handle_ping (struct GSC_KeyExchangeInfo *kx,
                    const struct GNUNET_MessageHeader *msg);


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the encrypted PONG message itself
 */
void
GSC_KX_handle_pong (struct GSC_KeyExchangeInfo *kx,
                    const struct GNUNET_MessageHeader *msg);


/**
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param payload payload of the message
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload, size_t payload_size);


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param kx key exchange information context
 * @param msg encrypted message
 * @param atsi performance data
 * @param atsi_count number of entries in ats (excluding 0-termination)
 */
void
GSC_KX_handle_encrypted_message (struct GSC_KeyExchangeInfo *kx,
                                 const struct GNUNET_MessageHeader *msg,
                                 const struct GNUNET_ATS_Information *atsi,
                                 uint32_t atsi_count);


/**
 * Start the key exchange with the given peer.
 *
 * @param pid identity of the peer to do a key exchange with
 * @return key exchange information context
 */
struct GSC_KeyExchangeInfo *
GSC_KX_start (const struct GNUNET_PeerIdentity *pid);


/**
 * Stop key exchange with the given peer.  Clean up key material.
 *
 * @param kx key exchange to stop
 */
void
GSC_KX_stop (struct GSC_KeyExchangeInfo *kx);


/**
 * Initialize KX subsystem.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GSC_KX_init (void);


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done (void);

#endif
/* end of gnunet-service-core_kx.h */
