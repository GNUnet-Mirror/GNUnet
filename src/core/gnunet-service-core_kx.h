/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param payload payload of the message
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload,
			     size_t payload_size);


#ifdef MEASURE_CRYPTO_DELAY
void
GSC_KX_encrypt_and_transmit_measure_encryption_delay (struct GSC_KeyExchangeInfo *kx,
                                                      const void *payload,
			                              size_t payload_size);
#endif


/**
 * Initialize KX subsystem.
 *
 * @param pk private key to use for the peer
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GSC_KX_init (struct GNUNET_CRYPTO_EddsaPrivateKey *pk);


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done (void);


/**
 * Check if the given neighbour has excess bandwidth available.
 *
 * @param target neighbour to check
 * @return #GNUNET_YES if excess bandwidth is available, #GNUNET_NO if not
 */
int
GSC_NEIGHBOURS_check_excess_bandwidth (const struct GSC_KeyExchangeInfo *target);


/**
 * Check how many messages are queued for the given neighbour.
 *
 * @param target neighbour to check
 * @return number of items in the message queue
 */
unsigned int
GSC_NEIGHBOURS_get_queue_length (const struct GSC_KeyExchangeInfo *target);


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS request.  For this
 * request type, the client does not have to have transmitted an INIT
 * request.  All current peers are returned, regardless of which
 * message types they accept.
 *
 * @param mq message queue to add for monitoring
 */
void
GSC_KX_handle_client_monitor_peers (struct GNUNET_MQ_Handle *mq);


#endif
/* end of gnunet-service-core_kx.h */
