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
 * @file cadet/gnunet-service-cadet_peer.h
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_PEER_H
#define GNUNET_SERVICE_CADET_PEER_H

#include "gnunet-service-cadet.h"
#include "gnunet_hello_lib.h"


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
 * Retrieve the CadetPeer stucture associated with the
 * peer. Optionally create one and insert it in the appropriate
 * structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO to return NULL if peer is unknown.
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id,
         int create);


/**
 * Calculate how desirable a path is for @a cp if
 * @a cp is at offset @a off in the path.
 *
 * @param cp a peer reachable via a path
 * @param off offset of @a cp in a path
 * @return score how useful a path is to reach @a cp,
 *         positive scores mean path is more desirable
 */
double
GCP_get_desirability_of_path (struct CadetPeer *cp,
                              unsigned int off);


/**
 * Obtain the peer identity for a `struct CadetPeer`.
 *
 * @param cp our peer handle
 * @return the peer identity
 */
const struct GNUNET_PeerIdentity *
GCP_get_id (struct CadetPeer *cp);


/**
 * Iterate over all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter,
                 void *cls);


/**
 * Count the number of known paths toward the peer.
 *
 * @param cp Peer to get path info.
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *cp);


/**
 * Drop all paths owned by this peer, and do not
 * allow new ones to be added: We are shutting down.
 *
 * @param cp peer to drop paths to
 */
void
GCP_drop_owned_paths (struct CadetPeer *cp);


/**
 * Peer path iterator.
 *
 * @param cls Closure.
 * @param path Path itself
 * @param off offset of the target peer in @a path
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 */
typedef int
(*GCP_PathIterator) (void *cls,
                     struct CadetPeerPath *path,
                     unsigned int off);


/**
 * Iterate over the paths to a peer.
 *
 * @param cp Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *cp,
                   GCP_PathIterator callback,
                   void *callback_cls);

/**
 * Iterate over the paths to a peer without direct link.
 *
 * @param cp Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_indirect_paths (struct CadetPeer *cp,
                            GCP_PathIterator callback,
                            void *callback_cls);


/**
 * Iterate over the paths to @a peer where
 * @a peer is at distance @a dist from us.
 *
 * @param cp Peer to get path info.
 * @param dist desired distance of @a peer to us on the path
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths_at (struct CadetPeer *cp,
                      unsigned int dist,
                      GCP_PathIterator callback,
                      void *callback_cls);


/**
 * Remove an entry from the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_remove (struct CadetPeer *cp,
                       struct CadetPeerPathEntry *entry,
                       unsigned int off);


/**
 * Add an entry to the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_add (struct CadetPeer *cp,
                    struct CadetPeerPathEntry *entry,
                    unsigned int off);


/**
 * Get the tunnel towards a peer.
 *
 * @param cp Peer to get from.
 * @param create #GNUNET_YES to create a tunnel if we do not have one
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (struct CadetPeer *cp,
                int create);


/**
 * The tunnel to the given peer no longer exists, remove it from our
 * data structures, and possibly clean up the peer itself.
 *
 * @param cp the peer affected
 * @param t the dead tunnel
 */
void
GCP_drop_tunnel (struct CadetPeer *cp,
                 struct CadetTunnel *t);


/**
 * Try adding a @a path to this @a cp.  If the peer already
 * has plenty of paths, return NULL.
 *
 * @param cp peer to which the @a path leads to
 * @param path a path looking for an owner; may not be fully initialized yet!
 * @param off offset of @a cp in @a path
 * @param force for attaching the path
 * @return NULL if this peer does not care to become a new owner,
 *         otherwise the node in the peer's path heap for the @a path.
 */
struct GNUNET_CONTAINER_HeapNode *
GCP_attach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 unsigned int off,
                 int force);


/**
 * This peer can no longer own @a path as the path
 * has been extended and a peer further down the line
 * is now the new owner.
 *
 * @param cp old owner of the @a path
 * @param path path where the ownership is lost
 * @param hn note in @a cp's path heap that must be deleted
 */
void
GCP_detach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 struct GNUNET_CONTAINER_HeapNode *hn);


/**
 * Add a @a connection to this @a cp.
 *
 * @param cp peer via which the @a connection goes
 * @param cc the connection to add
 */
void
GCP_add_connection (struct CadetPeer *cp,
                    struct CadetConnection *cc);


/**
 * Remove a @a connection that went via this @a cp.
 *
 * @param cp peer via which the @a connection went
 * @param cc the connection to remove
 */
void
GCP_remove_connection (struct CadetPeer *cp,
                       struct CadetConnection *cc);


/**
 * We got a HELLO for a @a cp, remember it, and possibly
 * trigger adequate actions (like trying to connect).
 *
 * @param cp the peer we got a HELLO for
 * @param hello the HELLO to remember
 */
void
GCP_set_hello (struct CadetPeer *cp,
               const struct GNUNET_HELLO_Message *hello);


/**
 * Clean up all entries about all peers.
 * Must only be called after all tunnels, CORE-connections and
 * connections are down.
 */
void
GCP_destroy_all_peers (void);


/**
 * Data structure used to track whom we have to notify about changes
 * in our ability to transmit to a given peer.
 *
 * All queue managers will be given equal chance for sending messages
 * to @a cp.  This construct this guarantees fairness for access to @a
 * cp among the different message queues.  Each connection or route
 * will have its respective message queue managers for each direction.
 */
struct GCP_MessageQueueManager;


/**
 * Function to call with updated message queue object.
 *
 * @param cls closure
 * @param available #GNUNET_YES if sending is now possible,
 *                  #GNUNET_NO if sending is no longer possible
 *                  #GNUNET_SYSERR if sending is no longer possible
 *                                 and the last envelope was discarded
 */
typedef void
(*GCP_MessageQueueNotificationCallback)(void *cls,
                                        int available);


/**
 * Start message queue change notifications.  Will create a new slot
 * to manage the message queue to the given @a cp.
 *
 * @param cp peer to notify for
 * @param cb function to call if mq becomes available or unavailable
 * @param cb_cls closure for @a cb
 * @return handle to cancel request
 */
struct GCP_MessageQueueManager *
GCP_request_mq (struct CadetPeer *cp,
                GCP_MessageQueueNotificationCallback cb,
                void *cb_cls);


/**
 * Test if @a cp has a core-level connection
 *
 * @param cp peer to test
 * @return #GNUNET_YES if @a cp has a core-level connection
 */
int
GCP_has_core_connection (struct CadetPeer *cp);


/**
 * Send the message in @a env via a @a mqm.  Must only be called at
 * most once after the respective
 * #GCP_MessageQueueNotificationCallback was called with `available`
 * set to #GNUNET_YES, and not after the callback was called with
 * `available` set to #GNUNET_NO or #GNUNET_SYSERR.
 *
 * @param mqm message queue manager for the transmission
 * @param env envelope with the message to send; must NOT
 *            yet have a #GNUNET_MQ_notify_sent() callback attached to it
 */
void
GCP_send (struct GCP_MessageQueueManager *mqm,
          struct GNUNET_MQ_Envelope *env);


/**
 * Send the message in @a env to @a cp, overriding queueing logic.
 * This function should only be used to send error messages outside
 * of flow and congestion control, similar to ICMP.  Note that
 * the envelope may be silently discarded as well.
 *
 * @param cp peer to send the message to
 * @param env envelope with the message to send
 */
void
GCP_send_ooo (struct CadetPeer *cp,
              struct GNUNET_MQ_Envelope *env);


/**
 * Stops message queue change notifications and sends a last message.
 * In practice, this is implemented by sending that @a last_env
 * message immediately (if any), ignoring queue order.
 *
 * @param mqm handle matching request to cancel
 * @param last_env final message to transmit, or NULL
 */
void
GCP_request_mq_cancel (struct GCP_MessageQueueManager *mqm,
                       struct GNUNET_MQ_Envelope *last_env);


/**
 * Set the message queue to @a mq for peer @a cp and notify watchers.
 *
 * @param cp peer to modify
 * @param mq message queue to set (can be NULL)
 */
void
GCP_set_mq (struct CadetPeer *cp,
            struct GNUNET_MQ_Handle *mq);

/**
 * Checking the signature for a monotime of a GNUNET_CADET_ConnectionCreateMessage.
 *
 * @param peer The peer that signed the monotime value.
 * @param msg The GNUNET_CADET_ConnectionCreateMessage with the monotime value.
 * @return GNUNET_OK if the signature is good, GNUNET_SYSERR if not.
 */
int
GCP_check_monotime_sig (struct CadetPeer *peer, const struct
                        GNUNET_CADET_ConnectionCreateMessage *msg);

/**
 * Checking if a monotime value is newer than the last monotime value received from a peer. If the time value is newer it will be stored at the peer.
 *
 * @param peer The peer we received a new time value from.
 * @param monotime Time value we check against the last time value we received from a peer.
 * @return GNUNET_YES if monotime is newer than the last received time value, GNUNET_NO if monotime is not newer.
 */
int
GCP_check_and_update_monotime (struct CadetPeer *peer,
                               struct GNUNET_TIME_AbsoluteNBO monotime);

#endif
