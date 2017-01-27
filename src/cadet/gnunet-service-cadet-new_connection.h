
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

#include "gnunet_util_lib.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_peer.h"
#include "cadet_protocol.h"


/**
 * Function called to notify tunnel about change in our readyness.
 *
 * @param cls closure
 * @param is_ready #GNUNET_YES if the connection is now ready for transmission,
 *                 #GNUNET_NO if the connection is no longer ready for transmission
 */
typedef void
(*GCC_ReadyCallback)(void *cls,
                     int is_ready);


/**
 * Destroy a connection, called when the CORE layer is already done
 * (i.e. has received a BROKEN message), but if we still have to
 * communicate the destruction of the connection to the tunnel (if one
 * exists).
 *
 * @param cc connection to destroy
 */
void
GCC_destroy_without_core (struct CadetConnection *cc);


/**
 * Destroy a connection, called if the tunnel association with the
 * connection was already broken, but we still need to notify the CORE
 * layer about the breakage.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy_without_tunnel (struct CadetConnection *cc);


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
            GCC_ReadyCallback ready_cb,
            void *ready_cb_cls);


/**
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.  This
 * is an inbound tunnel, so we must use the existing @a cid
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ct which tunnel uses this connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection, NULL if we already have
 *         a connection that takes precedence on @a path
 */
struct CadetConnection *
GCC_create_inbound (struct CadetPeer *destination,
                    struct CadetPeerPath *path,
                    struct CadetTConnection *ct,
                    const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                    GCC_ReadyCallback ready_cb,
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
 * A CREATE_ACK was received for this connection, process it.
 *
 * @param cc the connection that got the ACK.
 */
void
GCC_handle_connection_create_ack (struct CadetConnection *cc);


/**
 * We got a #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE for a
 * connection that we already have.  Either our ACK got lost
 * or something is fishy.  Consider retransmitting the ACK.
 *
 * @param cc connection that got the duplicate CREATE
 */
void
GCC_handle_duplicate_create (struct CadetConnection *cc);


/**
 * Handle KX message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx (struct CadetConnection *cc,
               const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg);


/**
 * Handle encrypted message.
 *
 * @param cc connection that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCC_handle_encrypted (struct CadetConnection *cc,
                      const struct GNUNET_CADET_TunnelEncryptedMessage *msg);


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
 * Get a (static) string for a connection.
 *
 * @param cc Connection.
 */
const char *
GCC_2s (const struct CadetConnection *cc);


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
