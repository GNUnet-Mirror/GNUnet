/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 *
 * TODO:
 * - define API for blacklisting, un-blacklisting and notifications
 *   about blacklisted peers
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

#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

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
 * @param latency estimated latency for communicating with the
 *             given peer (round-trip)
 * @param distance in overlay hops, as given by transport plugin
 */
typedef void (*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                                  const struct
                                                  GNUNET_PeerIdentity * peer,
                                                  const struct
                                                  GNUNET_MessageHeader *
                                                  message,
						  struct GNUNET_TIME_Relative
                                                  latency,
						  uint32_t distance);


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
 * @param latency estimated latency for communicating with the
 *             given peer (round-trip)
 * @param distance in overlay hops, as given by transport plugin
 */
typedef void
  (*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                     const struct GNUNET_PeerIdentity * peer,
                                     struct GNUNET_TIME_Relative latency,
				     uint32_t distance);

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
typedef void
  (*GNUNET_TRANSPORT_NotifyDisconnect) (void *cls,
                                        const struct GNUNET_PeerIdentity *
                                        peer);


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
typedef void
(*GNUNET_TRANSPORT_AddressLookUpCallback) (void *cls,
					   const char *address);


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param nd function to call on disconnect events
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *GNUNET_TRANSPORT_connect (struct
                                                          GNUNET_SCHEDULER_Handle
                                                          *sched,
                                                          const struct
                                                          GNUNET_CONFIGURATION_Handle
                                                          *cfg, void *cls,
                                                          GNUNET_TRANSPORT_ReceiveCallback
                                                          rec,
                                                          GNUNET_TRANSPORT_NotifyConnect
                                                          nc,
                                                          GNUNET_TRANSPORT_NotifyDisconnect
                                                          nd);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/**
 * Set the share of incoming/outgoing bandwidth for the given
 * peer to the specified amount.
 *
 * @param handle connection to transport service
 * @param target who's bandwidth quota is being changed
 * @param quota_in incoming bandwidth quota in bytes per ms
 * @param quota_out outgoing bandwidth quota in bytes per ms
 * @param timeout how long to wait until signaling failure if
 *        we can not communicate the quota change
 * @param cont continuation to call when done, will be called
 *        either with reason "TIMEOUT" or with reason "PREREQ_DONE"
 * @param cont_cls closure for continuation
 */
void
GNUNET_TRANSPORT_set_quota (struct GNUNET_TRANSPORT_Handle *handle,
                            const struct GNUNET_PeerIdentity *target,
                            uint32_t quota_in,
                            uint32_t quota_out,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_SCHEDULER_Task cont, void *cont_cls);


/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle;


/**
 * Check if we could queue a message of the given size for
 * transmission.  The transport service will take both its
 * internal buffers and bandwidth limits imposed by the
 * other peer into consideration when answering this query.
 *
 * @param handle connection to transport service
 * @param target who should receive the message
 * @param size how big is the message we want to transmit?
 * @param priority how important is the message?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using GNUNET_TRANSPORT_notify_transmit_ready_cancel)
 */
struct GNUNET_TRANSPORT_TransmitHandle
  *GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle
                                           *handle,
                                           const struct GNUNET_PeerIdentity
                                           *target, size_t size,
					   uint32_t priority,
                                           struct GNUNET_TIME_Relative
                                           timeout,
                                           GNUNET_CONNECTION_TransmitReadyNotify
                                           notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param h handle of the transmission notification request to cancel
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *h);



/**
 * Function called whenever there is an update to the
 * HELLO of this peer.
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
typedef void (*GNUNET_TRANSPORT_HelloUpdateCallback)(void *cls,
						     const struct GNUNET_MessageHeader *hello);


/**
 * Obtain updates on changes to the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls);


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param handle connection to transport service
 * @param rec function previously registered to be called with the HELLOs
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_Handle *handle,
				   GNUNET_TRANSPORT_HelloUpdateCallback rec,
				   void *rec_cls);


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.  If the HELLO
 * is working, we should add it to PEERINFO.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello);


/**
 * Convert a binary address into a human readable address.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param addressLen number of bytes in address
 * @param numeric should (IP) addresses be displayed in numeric form 
 *                (otherwise do reverse DNS lookup)
 * @param nameTrans name of the transport to which the address belongs
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for aluc
 */
void
GNUNET_TRANSPORT_address_lookup (struct GNUNET_SCHEDULER_Handle *sched,
                                 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char * address,
                                 size_t addressLen,
				 int numeric,
                                 const char * nameTrans,
				 struct GNUNET_TIME_Relative timeout,
				 GNUNET_TRANSPORT_AddressLookUpCallback aluc,
				 void *aluc_cls);



/**
 * Handle for blacklisting requests.
 */
struct GNUNET_TRANSPORT_BlacklistRequest;


/**
 * Blacklist a peer for a given period of time.  All connections
 * (inbound and outbound) to a peer that is blacklisted will be
 * dropped (as soon as we learn who the connection is for).  A second
 * call to this function for the same peer overrides previous
 * blacklisting requests.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param peer identity of peer to blacklist
 * @param duration how long to blacklist, use GNUNET_TIME_UNIT_ZERO to
 *        re-enable connections
 * @param timeout when should this operation (trying to establish the
 *        blacklisting time out)
 * @param cont continuation to call once the request has been processed
 * @param cont_cls closure for cont
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_BlacklistRequest *
GNUNET_TRANSPORT_blacklist (struct GNUNET_SCHEDULER_Handle *sched,
			    const struct GNUNET_CONFIGURATION_Handle *cfg,
			    const struct GNUNET_PeerIdentity *peer,
			    struct GNUNET_TIME_Relative duration,
			    struct GNUNET_TIME_Relative timeout,
			    GNUNET_SCHEDULER_Task cont,
			    void *cont_cls);


/**
 * Abort transmitting the blacklist request.  Note that this function
 * is NOT for removing a peer from the blacklist (for that, call 
 * GNUNET_TRANSPORT_blacklist with a duration of zero).  This function
 * is only for aborting the transmission of a blacklist request
 * (i.e. because of shutdown).
 *
 * @param br handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_cancel (struct GNUNET_TRANSPORT_BlacklistRequest * br);


/**
 * Handle for blacklist notifications.
 */
struct GNUNET_TRANSPORT_BlacklistNotification;


/**
 * Signature of function called whenever the blacklist status of
 * a peer changes.  This includes changes to the duration of the
 * blacklist status as well as the expiration of an existing
 * blacklist status.
 *
 * @param cls closure
 * @param peer identity of peer with the change
 * @param until GNUNET_TIME_UNIT_ZERO_ABS if the peer is no
 *              longer blacklisted, otherwise the time at
 *              which the current blacklisting will expire
 */
typedef void (*GNUNET_TRANSPORT_BlacklistCallback)(void *cls,
						   const struct GNUNET_PeerIdentity *peer,
						   struct GNUNET_TIME_Absolute until);


/**
 * Call a function whenever a peer's blacklisting status changes.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param bc function to call on status changes
 * @param bc_cls closure for bc
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_BlacklistNotification *
GNUNET_TRANSPORT_blacklist_notify (struct GNUNET_SCHEDULER_Handle *sched,
				   const struct GNUNET_CONFIGURATION_Handle *cfg,
				   GNUNET_TRANSPORT_BlacklistCallback bc,
				   void *bc_cls);


/**
 * Stop calling the notification callback associated with
 * the given blacklist notification.
 *
 * @param bn handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_notify_cancel (struct GNUNET_TRANSPORT_BlacklistNotification * bn);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_SERVICE_H */
#endif
/* end of gnunet_transport_service.h */
