/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 GNUnet e.V.

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
 * @file transport/gnunet-service-transport.h
 * @brief globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_H
#define GNUNET_SERVICE_TRANSPORT_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"

#define VERBOSE_VALIDATION GNUNET_YES

/**
 * Statistics handle.
 */
extern struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
extern struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
extern struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Our private key.
 */
extern struct GNUNET_CRYPTO_EddsaPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
extern struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * ATS connectivity handle.
 */
extern struct GNUNET_ATS_ConnectivityHandle *GST_ats_connect;

/**
 * Interface scanner determines our LAN address range(s).
 */
extern struct GNUNET_ATS_InterfaceScanner *GST_is;


/**
 * Function to call when a peer's address has changed
 *
 * @param cls closure
 * @param peer peer this update is about,
 * @param address address, NULL for disconnect notification
 */
typedef void
(*GNUNET_TRANSPORT_NeighbourChangeCallback) (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address,
    enum GNUNET_TRANSPORT_PeerState state,
    struct GNUNET_TIME_Absolute state_timeout,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


/**
 * Continuation called from a blacklist test.
 *
 * @param cls closure
 * @param peer identity of peer that was tested
 * @param address address associated with the request
 * @param session session associated with the request
 * @param result #GNUNET_OK if the connection is allowed,
 *               #GNUNET_NO if not,
 *               #GNUNET_SYSERR if operation was aborted
 */
typedef void
(*GST_BlacklistTestContinuation) (void *cls,
                                  const struct GNUNET_PeerIdentity *peer,
				  const struct GNUNET_HELLO_Address *address,
				  struct GNUNET_ATS_Session *session,
                                  int result);


/**
 * Add the given peer to the blacklist (for the given transport).
 *
 * @param peer peer to blacklist
 * @param transport_name transport to blacklist for this peer, NULL for all
 */
void
GST_blacklist_add_peer (const struct GNUNET_PeerIdentity *peer,
                        const char *transport_name);


/**
 * Handle to an active blacklist check.
 */
struct GST_BlacklistCheck;



/**
 * Test if a peer/transport combination is blacklisted.
 *
 * @param peer the identity of the peer to test
 * @param transport_name name of the transport to test, never NULL
 * @param cont function to call with result
 * @param cont_cls closure for @a cont
 * @param address address to pass back to @a cont, can be NULL
 * @param session session to pass back to @a cont, can be NULL
 * @return handle to the blacklist check, NULL if the decision
 *        was made instantly and @a cont was already called
 */
struct GST_BlacklistCheck *
GST_blacklist_test_allowed (const struct GNUNET_PeerIdentity *peer,
                            const char *transport_name,
                            GST_BlacklistTestContinuation cont, 
			    void *cont_cls,
			    const struct GNUNET_HELLO_Address *address,
			    struct GNUNET_ATS_Session *session);


/**
 * Abort blacklist if @a address and @a session match.
 *
 * @param address address used to abort matching checks
 * @param session session used to abort matching checks
 */
void
GST_blacklist_abort_matching (const struct GNUNET_HELLO_Address *address,
			      struct GNUNET_ATS_Session *session);

/**
 * Cancel a blacklist check.
 *
 * @param bc check to cancel
 */
void
GST_blacklist_test_cancel (struct GST_BlacklistCheck *bc);


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param address address and (claimed) identity of the other peer
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
struct GNUNET_TIME_Relative
GST_receive_callback (void *cls,
                      const struct GNUNET_HELLO_Address *address,
                      struct GNUNET_ATS_Session *session,
                      const struct GNUNET_MessageHeader *message);

/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 * @param may_drop #GNUNET_YES if the message can be dropped / is payload
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg,
                       int may_drop);


/**
 * Broadcast the new active address to all clients monitoring the peer.
 *
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL on disconnect
 * @param state the current state of the peer
 * @param state_timeout the time out for the state
 */
void
GST_clients_broadcast_peer_notification (const struct GNUNET_PeerIdentity *peer,
                                         const struct GNUNET_HELLO_Address *address,
                                         enum GNUNET_TRANSPORT_PeerState state,
                                         struct GNUNET_TIME_Absolute state_timeout);


/**
 * Notify all clients about a disconnect, and cancel
 * pending SEND_OK messages for this peer.
 *
 * @param peer peer that disconnected
 */
void
GST_clients_broadcast_disconnect (const struct GNUNET_PeerIdentity *peer);




#endif
/* end of file gnunet-service-transport_plugins.h */
