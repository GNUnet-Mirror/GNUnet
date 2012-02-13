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
 * @file include/gnunet_transport_service.h
 * @brief low-level P2P IO
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRANSPORT_SERVICE_H
#define GNUNET_TRANSPORT_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_VERSION 0x00000000


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
typedef void (*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                                  const struct
                                                  GNUNET_PeerIdentity * peer,
                                                  const struct
                                                  GNUNET_MessageHeader *
                                                  message,
                                                  const struct
                                                  GNUNET_ATS_Information * ats,
                                                  uint32_t ats_count);


/**
 * Opaque handle to the service.
 */
struct GNUNET_TRANSPORT_Handle;


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
typedef void (*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                                const struct GNUNET_PeerIdentity
                                                * peer,
                                                const struct
                                                GNUNET_ATS_Information * ats,
                                                uint32_t ats_count);

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
typedef void (*GNUNET_TRANSPORT_NotifyDisconnect) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * peer);


/**
 * Function to call with a textual representation of an address.
 * This function will be called several times with different possible
 * textual representations, and a last time with NULL to signal the end
 * of the iteration.
 *
 * @param cls closure
 * @param address NULL on error or end of iteration,
 *        otherwise 0-terminated printable UTF-8 string
 */
typedef void (*GNUNET_TRANSPORT_AddressToStringCallback) (void *cls,
                                                          const char *address);


/**
 * Function to call with a binary format of an address
 *
 * @param cls closure
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL for disconnect notification in monitor mode
 */
typedef void (*GNUNET_TRANSPORT_PeerIterateCallback) (void *cls,
                                                      const struct
                                                      GNUNET_PeerIdentity *
                                                      peer,
                                                      const struct
                                                      GNUNET_HELLO_Address *
                                                      address);


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param nd function to call on disconnect events
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_PeerIdentity *self, void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/**
 * Ask the transport service to establish a connection to
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 */
void
GNUNET_TRANSPORT_try_connect (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_PeerIdentity *target);


/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle;


/**
 * Check if we could queue a message of the given size for
 * transmission.  The transport service will take both its internal
 * buffers and bandwidth limits imposed by the other peer into
 * consideration when answering this query.
 *
 * @param handle connection to transport service
 * @param target who should receive the message
 * @param size how big is the message we want to transmit?
 * @param priority how important is the message? @deprecated - remove?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using GNUNET_TRANSPORT_notify_transmit_ready_cancel)
 */
struct GNUNET_TRANSPORT_TransmitHandle *
GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle *handle,
                                        const struct GNUNET_PeerIdentity
                                        *target, size_t size, uint32_t priority,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_CONNECTION_TransmitReadyNotify
                                        notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle of the transmission notification request to cancel
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *th);



/**
 * Function called whenever there is an update to the
 * HELLO of this peer.
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
typedef void (*GNUNET_TRANSPORT_HelloUpdateCallback) (void *cls,
                                                      const struct
                                                      GNUNET_MessageHeader *
                                                      hello);


/**
 * Handle to cancel a 'GNUNET_TRANSPORT_get_hello' operation.
 */
struct GNUNET_TRANSPORT_GetHelloHandle;


/**
 * Obtain updates on changes to the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO
 * @param rec_cls closure for rec
 * @return handle to cancel the operation
 */
struct GNUNET_TRANSPORT_GetHelloHandle *
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls);


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param ghh handle returned from 'GNUNET_TRANSPORT_get_hello')
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_GetHelloHandle *ghh);


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent
 * @param cls closure for continuation
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_Task cont, void *cls);


/**
 * Handle to cancel a pending address lookup.
 */
struct GNUNET_TRANSPORT_AddressToStringContext;


/**
 * Convert a binary address into a human readable address.
 *
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param numeric should (IP) addresses be displayed in numeric form
 *                (otherwise do reverse DNS lookup)
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for aluc
 * @return handle to cancel the operation, NULL on error
 */
struct GNUNET_TRANSPORT_AddressToStringContext *
GNUNET_TRANSPORT_address_to_string (const struct GNUNET_CONFIGURATION_Handle
                                    *cfg,
                                    const struct GNUNET_HELLO_Address *address,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressToStringCallback
                                    aluc, void *aluc_cls);


/**
 * Cancel request for address conversion.
 *
 * @param alc handle for the request to cancel
 */
void
GNUNET_TRANSPORT_address_to_string_cancel (struct
                                           GNUNET_TRANSPORT_AddressToStringContext
                                           *alc);


/**
 * Return all the known addresses for a specific peer or all peers.
 * Returns continously all address if one_shot is set to GNUNET_NO
 *
 * CHANGE: Returns the address(es) that we are currently using for this
 * peer.  Upon completion, the 'AddressLookUpCallback' is called one more
 * time with 'NULL' for the address and the peer.  After this, the operation must no
 * longer be explicitly cancelled.
 *
 * @param cfg configuration to use
 * @param peer peer identity to look up the addresses of, CHANGE: allow NULL for all (connected) peers
 * @param one_shot GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 GNUNET_NO to monitor the set of addresses used (continuously, must be explicitly canceled, NOT implemented yet!)
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_address_callback function to call with the results
 * @param peer_address_callback_cls closure for peer_address_callback
 */
struct GNUNET_TRANSPORT_PeerIterateContext *
GNUNET_TRANSPORT_peer_get_active_addresses (const struct
                                            GNUNET_CONFIGURATION_Handle *cfg,
                                            const struct GNUNET_PeerIdentity
                                            *peer, int one_shot,
                                            struct GNUNET_TIME_Relative timeout,
                                            GNUNET_TRANSPORT_PeerIterateCallback
                                            peer_address_callback,
                                            void *peer_address_callback_cls);


/**
 * Cancel request for peer lookup.
 *
 * @param alc handle for the request to cancel
 */
void
GNUNET_TRANSPORT_peer_get_active_addresses_cancel (struct
                                                   GNUNET_TRANSPORT_PeerIterateContext
                                                   *alc);


/**
 * Handle for blacklisting peers.
 */
struct GNUNET_TRANSPORT_Blacklist;


/**
 * Function that decides if a connection is acceptable or not.
 *
 * @param cls closure
 * @param pid peer to approve or disapproave
 * @return GNUNET_OK if the connection is allowed, GNUNET_SYSERR if not
 */
typedef int (*GNUNET_TRANSPORT_BlacklistCallback) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * pid);


/**
 * Install a blacklist callback.  The service will be queried for all
 * existing connections as well as any fresh connections to check if
 * they are permitted.  If the blacklisting callback is unregistered,
 * all hosts that were denied in the past will automatically be
 * whitelisted again.  Cancelling the blacklist handle is also the
 * only way to re-enable connections from peers that were previously
 * blacklisted.
 *
 * @param cfg configuration to use
 * @param cb callback to invoke to check if connections are allowed
 * @param cb_cls closure for cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_Blacklist *
GNUNET_TRANSPORT_blacklist (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_TRANSPORT_BlacklistCallback cb,
                            void *cb_cls);


/**
 * Abort the blacklist.  Note that this function is the only way for
 * removing a peer from the blacklist.
 *
 * @param br handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_cancel (struct GNUNET_TRANSPORT_Blacklist *br);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_SERVICE_H */
#endif
/* end of gnunet_transport_service.h */
