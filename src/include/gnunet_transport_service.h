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
 * @param latency estimated latency for communicating with the
 *             given peer
 * @param peer (claimed) identity of the other peer
 * @param message the message
 */
typedef void (*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                                  struct GNUNET_TIME_Relative
                                                  latency,
                                                  const struct
                                                  GNUNET_PeerIdentity * peer,
                                                  const struct
                                                  GNUNET_MessageHeader *
                                                  message);


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
 * @param latency current latency of the connection
 */
typedef void
  (*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                     const struct GNUNET_PeerIdentity * peer,
                                     struct GNUNET_TIME_Relative latency);

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
 */
void GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/**
 * Set the share of incoming/outgoing bandwidth for the given
 * peer to the specified amount.
 *
 * @param handle connection to transport service
 * @param target who's bandwidth quota is being changed
 * @param quota_in incoming bandwidth quota in bytes per ms; 0 can
 *        be used to force all traffic to be discarded
 * @param quota_out outgoing bandwidth quota in bytes per ms; 0 can
 *        be used to force all traffic to be discarded
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
					                       unsigned int priority,
                                           struct GNUNET_TIME_Relative
                                           timeout,
                                           GNUNET_CONNECTION_TransmitReadyNotify
                                           notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready
 * notification.
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *h);


/**
 * Obtain the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param timeout how long to wait for the HELLO
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_TRANSPORT_ReceiveCallback rec,
                            void *rec_cls);


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello);

/**
 *  Obtain a AddressLookupMessage from a client and return to client all the host addresses of other peers.
 *
 *  @param handle connection to transport service
 *  @param addLUmsg the address-lookup message
 */
void
GNUNET_TRANSPORT_address_lookup (struct GNUNET_TRANSPORT_Handle *handle,
                                 const char * address,
                                 size_t addressLen,
                                 const char * nameTrans,
		                         struct GNUNET_TIME_Relative timeout,
		                         GNUNET_TRANSPORT_AddressLookUpCallback aluc,
		                         void *aluc_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_SERVICE_H */
#endif
/* end of gnunet_transport_service.h */


