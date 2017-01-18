/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_peer.h
 * @brief cadet service; dealing with remote peers
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMP (Gnunet Cadet Peer)
 */

#ifndef GNUNET_SERVICE_CADET_PEER_H
#define GNUNET_SERVICE_CADET_PEER_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet_path.h"

/**
 * Struct containing all information regarding a given peer
 */
struct CadetPeer;

/**
 * Handle to queued messages on a peer level.
 */
struct CadetPeerQueue;

#include "gnunet-service-cadet_connection.h"


/**
 * Callback called when a queued message is sent.
 *
 * @param cls Closure.
 * @param c Connection this message was on.
 * @param fwd Was this a FWD going message?
 * @param sent Was it really sent? (Could have been canceled)
 * @param type Type of message sent.
 * @param payload_type Type of payload, if applicable.
 * @param pid Message ID, or 0 if not applicable (create, destroy, etc).
 * @param size Size of the message.
 * @param wait Time spent waiting for core (only the time for THIS message)
 */
typedef void
(*GCP_sent) (void *cls,
             struct CadetConnection *c,
             int fwd,
             int sent,
             uint16_t type,
             uint16_t payload_type,
             struct CadetEncryptedMessageIdentifier pid,
             size_t size,
             struct GNUNET_TIME_Relative wait);

/**
 * Peer path iterator.
 *
 * @param cls Closure.
 * @param peer Peer this path is towards.
 * @param path Path itself
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 */
typedef int
(*GCP_path_iterator) (void *cls,
                      struct CadetPeer *peer,
                      struct CadetPeerPath *path);


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize peer subsystem.
 *
 * @param c Configuration.
 */
void
GCP_init (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shut down the peer subsystem.
 */
void
GCP_shutdown (void);


/**
 * Retrieve the CadetPeer stucture associated with the peer. Optionally create
 * one and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO otherwise.
 *
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id, int create);


/**
 * Retrieve the CadetPeer stucture associated with the peer. Optionally create
 * one and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO otherwise.
 *
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get_short (const GNUNET_PEER_Id peer, int create);


/**
 * Try to establish a new connection to this peer (in its tunnel).
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE CONNECTION towards it.
 *
 * @param peer Peer to connect to.
 */
void
GCP_connect (struct CadetPeer *peer);

/**
 * @brief Send a message to another peer (using CORE).
 *
 * @param peer Peer towards which to queue the message.
 * @param message Message to send.
 * @param payload_type Type of the message's payload, for debug messages.
 *                     0 if the message is a retransmission (unknown payload).
 *                     UINT16_MAX if the message does not have payload.
 * @param payload_id ID of the payload (MID, ACK #, etc)
 * @param c Connection this message belongs to (can be NULL).
 * @param fwd Is this a message going root->dest? (FWD ACK are NOT FWD!)
 * @param cont Continuation to be called once CORE has sent the message.
 * @param cont_cls Closure for @c cont.
 */
struct CadetPeerQueue *
GCP_send (struct CadetPeer *peer,
          const struct GNUNET_MessageHeader *message,
          uint16_t payload_type,
          struct CadetEncryptedMessageIdentifier payload_id,
          struct CadetConnection *c,
          int fwd,
          GCP_sent cont,
          void *cont_cls);

/**
 * Cancel sending a message. Message must have been sent with
 * #GCP_send before.  May not be called after the notify sent
 * callback has been called.
 *
 * It does NOT call the continuation given to #GCP_send.
 *
 * @param q Queue handle to cancel
 */
void
GCP_send_cancel (struct CadetPeerQueue *q);

/**
 * Set tunnel.
 *
 * @param peer Peer.
 * @param t Tunnel.
 */
void
GCP_set_tunnel (struct CadetPeer *peer, struct CadetTunnel *t);


/**
 * Check whether there is a direct (core level)  connection to peer.
 *
 * @param peer Peer to check.
 *
 * @return #GNUNET_YES if there is a direct connection.
 */
int
GCP_is_neighbor (const struct CadetPeer *peer);


/**
 * Create and initialize a new tunnel towards a peer, in case it has none.
 *
 * Does not generate any traffic, just creates the local data structures.
 *
 * @param peer Peer towards which to create the tunnel.
 */
void
GCP_add_tunnel (struct CadetPeer *peer);


/**
 * Add a connection to a neighboring peer.
 *
 * Store that the peer is the first hop of the connection in one
 * direction and that on peer disconnect the connection must be
 * notified and destroyed, for it will no longer be valid.
 *
 * @param peer Peer to add connection to.
 * @param c Connection to add.
 * @param pred #GNUNET_YES if we are predecessor, #GNUNET_NO if we are successor
 */
void
GCP_add_connection (struct CadetPeer *peer,
                    struct CadetConnection *c,
                    int pred);


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 * @param trusted Do we trust that this path is real?
 *
 * @return path if path was taken, pointer to existing duplicate if exists
 *         NULL on error.
 */
struct CadetPeerPath *
GCP_add_path (struct CadetPeer *peer,
              struct CadetPeerPath *p,
              int trusted);


/**
 * Add the path to the origin peer and update the path used to reach it in case
 * this is the shortest.
 * The path is given in peer_info -> destination, therefore we turn the path
 * upside down first.
 *
 * @param peer Peer to add the path to, being the origin of the path.
 * @param path New path to add after being inversed.
 *             Path will be either used or freed.
 * @param trusted Do we trust that this path is real?
 *
 * @return path if path was taken, pointer to existing duplicate if exists
 *         NULL on error.
 */
struct CadetPeerPath *
GCP_add_path_to_origin (struct CadetPeer *peer,
                        struct CadetPeerPath *path,
                        int trusted);

/**
 * Adds a path to the info of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
void
GCP_add_path_to_all (const struct CadetPeerPath *p, int confirmed);


/**
 * Remove any path to the peer that has the extact same peers as the one given.
 *
 * @param peer Peer to remove the path from.
 * @param path Path to remove. Is always destroyed .
 */
void
GCP_remove_path (struct CadetPeer *peer,
                 struct CadetPeerPath *path);


/**
 * Check that we are aware of a connection from a neighboring peer.
 *
 * @param peer Peer to the connection is with
 * @param c Connection that should be in the map with this peer.
 */
void
GCP_check_connection (const struct CadetPeer *peer,
                      const struct CadetConnection *c);


/**
 * Remove a connection from a neighboring peer.
 *
 * @param peer Peer to remove connection from.
 * @param c Connection to remove.
 */
void
GCP_remove_connection (struct CadetPeer *peer,
                       const struct CadetConnection *c);


/**
 * Start the DHT search for new paths towards the peer: we don't have
 * enough good connections.
 *
 * @param peer Destination peer.
 */
void
GCP_start_search (struct CadetPeer *peer);


/**
 * Stop the DHT search for new paths towards the peer: we already have
 * enough good connections.
 *
 * @param peer Destination peer.
 */
void
GCP_stop_search (struct CadetPeer *peer);


/**
 * Get the Full ID of a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Full ID of peer.
 */
const struct GNUNET_PeerIdentity *
GCP_get_id (const struct CadetPeer *peer);


/**
 * Get the Short ID of a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Short ID of peer.
 */
GNUNET_PEER_Id
GCP_get_short_id (const struct CadetPeer *peer);


/**
 * Get the tunnel towards a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (const struct CadetPeer *peer);


/**
 * Set the hello message.
 *
 * @param peer Peer whose message to set.
 * @param hello Hello message.
 */
void
GCP_set_hello (struct CadetPeer *peer,
               const struct GNUNET_HELLO_Message *hello);


/**
 * Get the hello message.
 *
 * @param peer Peer whose message to get.
 *
 * @return Hello message.
 */
struct GNUNET_HELLO_Message *
GCP_get_hello (struct CadetPeer *peer);


/**
 * Try to connect to a peer on TRANSPORT level.
 *
 * @param peer Peer to whom to connect.
 */
void
GCP_try_connect (struct CadetPeer *peer);

/**
 * Notify a peer that a link between two other peers is broken. If any path
 * used that link, eliminate it.
 *
 * @param peer Peer affected by the change.
 * @param peer1 Peer whose link is broken.
 * @param peer2 Peer whose link is broken.
 */
void
GCP_notify_broken_link (struct CadetPeer *peer,
                        const struct GNUNET_PeerIdentity *peer1,
                        const struct GNUNET_PeerIdentity *peer2);


/**
 * Count the number of known paths toward the peer.
 *
 * @param peer Peer to get path info.
 *
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *peer);

/**
 * Iterate over the paths to a peer.
 *
 * @param peer Peer to get path info.
 * @param callback Function to call for every path.
 * @param cls Closure for @a callback.
 *
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *peer,
                   GCP_path_iterator callback,
                   void *cls);


/**
 * Iterate all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter,
                 void *cls);


/**
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
const char *
GCP_2s (const struct CadetPeer *peer);


/**
 * Log all kinds of info about a peer.
 *
 * @param peer Peer.
 */
void
GCP_debug (const struct CadetPeer *p,
           enum GNUNET_ErrorType level);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_PEER_H */
#endif
/* end of gnunet-cadet-service_peer.h */
