
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_connection.h
 * @brief
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_CONNECTION_H
#define GNUNET_SERVICE_CADET_CONNECTION_H

#define NEW_CADET

#include "gnunet_util_lib.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_peer.h"
#include "cadet_protocol.h"

/**
 * Is the given connection currently ready for transmission?
 *
 * @param cc connection to transmit on
 * @return #GNUNET_YES if we could transmit
 */
int
GCC_is_ready (struct CadetConnection *cc);


/**
 * Destroy a connection.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy (struct CadetConnection *cc);


/**
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ct which tunnel uses this connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
struct CadetConnection *
GCC_create (struct CadetPeer *destination,
            struct CadetPeerPath *path,
            struct CadetTConnection *ct,
            GNUNET_SCHEDULER_TaskCallback ready_cb,
            void *ready_cb_cls);


/**
 * Transmit message @a msg via connection @a cc.  Must only be called
 * (once) after the connection has signalled that it is ready via the
 * `ready_cb`.  Clients can also use #GCC_is_ready() to check if the
 * connection is right now ready for transmission.
 *
 * @param cc connection identification
 * @param env envelope with message to transmit;
 *            the #GNUNET_MQ_notify_send() must not have yet been used
 *            for the envelope.  Also, the message better match the
 *            connection identifier of this connection...
 */
void
GCC_transmit (struct CadetConnection *cc,
              struct GNUNET_MQ_Envelope *env);


/**
 * An ACK was received for this connection, process it.
 *
 * @param cc the connection that got the ACK.
 */
void
GCC_handle_connection_ack (struct CadetConnection *cc);


/**
 * Handle KX message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx (struct CadetConnection *cc,
               const struct GNUNET_CADET_KX *msg);


/**
 * Handle encrypted message.
 *
 * @param cc connection that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCC_handle_encrypted (struct CadetConnection *cc,
                      const struct GNUNET_CADET_Encrypted *msg);


/**
 * Return the tunnel associated with this connection.
 *
 * @param cc connection to query
 * @return corresponding entry in the tunnel's connection list
 */
struct CadetTConnection *
GCC_get_ct (struct CadetConnection *cc);


/**
 * Obtain the path used by this connection.
 *
 * @param cc connection
 * @return path to @a cc
 */
struct CadetPeerPath *
GCC_get_path (struct CadetConnection *cc);


/**
 * Obtain unique ID for the connection.
 *
 * @param cc connection.
 * @return unique number of the connection
 */
const struct GNUNET_CADET_ConnectionTunnelIdentifier *
GCC_get_id (struct CadetConnection *cc);


/**
 * Get the connection ID as a full hash.
 *
 * @param cc Connection to get the ID from.
 * @return full hash ID of the connection.
 * @deprecated try to replace use of full hash codes eventually...
 */
const struct GNUNET_HashCode *
GCC_get_h (const struct CadetConnection *cc);


/**
 * Expand the shorter CADET hash to a full GNUnet hash.
 *
 * @param id hash to expand
 * @return expanded hash
 * @param deprecated
 */
const struct GNUNET_HashCode *
GCC_h2hc (const struct GNUNET_CADET_Hash *id);


/**
 * Log connection info.
 *
 * @param cc connection
 * @param level Debug level to use.
 */
void
GCC_debug (struct CadetConnection *cc,
           enum GNUNET_ErrorType level);


#endif
