/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_connection.h
 * @brief A connection is a live end-to-end messaging mechanism
 *       where the peers are identified by a path and know how
 *       to forward along the route using a connection identifier
 *       for routing the data.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_CONNECTION_H
#define GNUNET_SERVICE_CADET_CONNECTION_H

#include "gnunet_util_lib.h"
#include "gnunet-service-cadet.h"
#include "gnunet-service-cadet_peer.h"
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
 * Lookup a connection by its identifier.
 *
 * @param cid identifier to resolve
 * @return NULL if connection was not found
 */
struct CadetConnection *
GCC_lookup (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid);


/**
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param off offset of @a destination on @a path
 * @param ct which tunnel uses this connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
struct CadetConnection *
GCC_create (struct CadetPeer *destination,
            struct CadetPeerPath *path,
            unsigned int off,
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
 * Handle KX_AUTH message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx_auth (struct CadetConnection *cc,
                    const struct
                    GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg);

/**
 * Purpose for the signature of a monotime.
 */
struct CadetConnectionCreatePS
{

  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_CADET_CONNECTION_INITIATOR
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Time at the initiator when generating the signature.
   *
   * Note that the receiver MUST IGNORE the absolute time, and only interpret
   * the value as a mononic time and reject "older" values than the last one
   * observed.  This is necessary as we do not want to require synchronized
   * clocks and may not have a bidirectional communication channel.
   *
   * Even with this, there is no real guarantee against replay achieved here,
   * unless the latest timestamp is persisted.  Persistence should be
   * provided via PEERSTORE if possible.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

};

/**
 * Performance metrics for a connection.
 */
struct CadetConnectionMetrics
{
  /**
   * Our current best estimate of the latency, based on a weighted
   * average of at least @a latency_datapoints values.
   */
  struct GNUNET_TIME_Relative aged_latency;

  /**
   * When was this connection first established? (by us sending or
   * receiving the CREATE_ACK for the first time)
   */
  struct GNUNET_TIME_Absolute age;

  /**
   * When was this connection last used? (by us sending or
   * receiving a PAYLOAD message on it)
   */
  struct GNUNET_TIME_Absolute last_use;

  /**
   * How many packets that ought to generate an ACK did we send via
   * this connection?
   */
  unsigned long long num_acked_transmissions;

  /**
   * Number of packets that were sent via this connection did actually
   * receive an ACK?  (Note: ACKs may be transmitted and lost via
   * other connections, so this value should only be interpreted
   * relative to @e num_acked_transmissions and in relation to other
   * connections.)
   */
  unsigned long long num_successes;
};


/**
 * Obtain performance @a metrics from @a cc.
 *
 * @param cc connection to query
 * @return the metrics
 */
const struct CadetConnectionMetrics *
GCC_get_metrics (struct CadetConnection *cc);


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
 * We sent a message for which we expect to receive an ACK via
 * the connection identified by @a cti.
 *
 * @param cid connection identifier where we expect an ACK
 */
void
GCC_ack_expected (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid);


/**
 * We observed an ACK for a message that was originally sent via
 * the connection identified by @a cti.
 *
 * @param cid connection identifier where we got an ACK for a message
 *            that was originally sent via this connection (the ACK
 *            may have gotten back to us via a different connection).
 */
void
GCC_ack_observed (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid);


/**
 * We observed some the given @a latency on the connection
 * identified by @a cti.  (The same connection was taken
 * in both directions.)
 *
 * @param cti connection identifier where we measured latency
 * @param latency the observed latency
 */
void
GCC_latency_observed (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti,
                      struct GNUNET_TIME_Relative latency);


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
 * @param off[out] set to offset in this path where the connection @a cc ends
 * @return path to @a cc
 */
struct CadetPeerPath *
GCC_get_path (struct CadetConnection *cc,
              unsigned int *off);


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
