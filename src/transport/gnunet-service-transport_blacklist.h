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
 * @file transport/gnunet-service-transport_blacklist.h
 * @brief blacklisting API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_BLACKLIST_H
#define GNUNET_SERVICE_TRANSPORT_BLACKLIST_H

#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"

/**
 * Start blacklist subsystem.
 *
 * @param server server used to accept clients from
 */
void
GST_blacklist_start (struct GNUNET_SERVER_Handle *server);


/**
 * Stop blacklist subsystem.
 */
void
GST_blacklist_stop (void);


/**
 * Initialize a blacklisting client.  We got a blacklist-init
 * message from this client, add him to the list of clients
 * to query for blacklisting.
 *
 * @param cls unused
 * @param client the client
 * @param message the blacklist-init message that was sent
 */
void
GST_blacklist_handle_init (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message);


/**
 * A blacklisting client has sent us reply. Process it.
 *
 * @param cls unused
 * @param client the client
 * @param message the blacklist-init message that was sent
 */
void
GST_blacklist_handle_reply (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message);


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
 * Continuation called from a blacklist test.
 *
 * @param cls closure
 * @param peer identity of peer that was tested
 * @param result GNUNET_OK if the connection is allowed,
 *               GNUNET_NO if not
 */
typedef void (*GST_BlacklistTestContinuation) (void *cls,
                                               const struct GNUNET_PeerIdentity
                                               * peer, int result);


/**
 * Test if a peer/transport combination is blacklisted.
 *
 * @param peer the identity of the peer to test
 * @param transport_name name of the transport to test, never NULL
 * @param cont function to call with result
 * @param cont_cls closure for 'cont'
 * @return handle to the blacklist check, NULL if the decision
 *        was made instantly and 'cont' was already called
 */
struct GST_BlacklistCheck *
GST_blacklist_test_allowed (const struct GNUNET_PeerIdentity *peer,
                            const char *transport_name,
                            GST_BlacklistTestContinuation cont, void *cont_cls);


/**
 * Cancel a blacklist check.
 *
 * @param bc check to cancel
 */
void
GST_blacklist_test_cancel (struct GST_BlacklistCheck *bc);

#endif
/* end of file gnunet-service-transport_blacklist.h */
