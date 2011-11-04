/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_core_service.h
 * @brief core service; this is the main API for encrypted P2P
 *        communications
 * @author Christian Grothoff
 */

#ifndef GNUNET_CORE_SERVICE_H
#define GNUNET_CORE_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"

/**
 * Version number of GNUnet-core API.
 */
#define GNUNET_CORE_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_Handle;


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 */
typedef void (*GNUNET_CORE_ConnectEventHandler) (void *cls,
                                                 const struct
                                                 GNUNET_PeerIdentity * peer,
                                                 const struct
                                                 GNUNET_ATS_Information * atsi,
                                                 unsigned int atsi_count);


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void (*GNUNET_CORE_DisconnectEventHandler) (void *cls,
                                                    const struct
                                                    GNUNET_PeerIdentity * peer);


/**
 * Functions with this signature are called whenever a message is
 * received or transmitted.
 *
 * @param cls closure (set from GNUNET_CORE_connect)
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
typedef int (*GNUNET_CORE_MessageCallback) (void *cls,
                                            const struct GNUNET_PeerIdentity *
                                            other,
                                            const struct GNUNET_MessageHeader *
                                            message,
                                            const struct GNUNET_ATS_Information
                                            * atsi, unsigned int atsi_count);


/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_CORE_MessageHandler
{
  /**
   * Function to call for messages of "type".
   */
  GNUNET_CORE_MessageCallback callback;

  /**
   * Type of the message this handler covers.
   */
  uint16_t type;

  /**
   * Expected size of messages of this type.  Use 0 for variable-size.
   * If non-zero, messages of the given type will be discarded if they
   * do not have the right size.
   */
  uint16_t expected_size;

};


/**
 * Function called after GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 */
typedef void (*GNUNET_CORE_StartupCallback) (void *cls,
                                             struct GNUNET_CORE_Handle * server,
                                             const struct GNUNET_PeerIdentity *
                                             my_identity);


/**
 * Connect to the core service.  Note that the connection may complete
 * (or fail) asynchronously.  This function primarily causes the given
 * callback notification functions to be invoked whenever the
 * specified event happens.  The maximum number of queued
 * notifications (queue length) is per client but the queue is shared
 * across all types of notifications.  So a slow client that registers
 * for 'outbound_notify' also risks missing 'inbound_notify' messages.
 * Certain events (such as connect/disconnect notifications) are not
 * subject to queue size limitations.
 *
 * @param cfg configuration to use
 * @param queue_size size of the per-peer message queue
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call on timeout or once we have successfully
 *        connected to the core service; note that timeout is only meaningful if init is not NULL
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param inbound_hdr_only set to GNUNET_YES if inbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if inbound_notify is NULL
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param outbound_notify function to call for all outbound messages, can be NULL;
 *                note that the core is allowed to drop notifications about outbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param outbound_hdr_only set to GNUNET_YES if outbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if outbound_notify is NULL
 *                note that the core is allowed to drop notifications about outbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param handlers callbacks for messages we care about, NULL-terminated
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @return handle to the core service (only useful for disconnect until 'init' is called),
 *           NULL on error (in this case, init is never called)
 */
struct GNUNET_CORE_Handle *
GNUNET_CORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     unsigned int queue_size, void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers);


/**
 * Disconnect from the core service.    This function can only
 * be called *after* all pending 'GNUNET_CORE_notify_transmit_ready'
 * requests have been explicitly cancelled.
 *
 * @param handle connection to core to disconnect
 */
void
GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle);


/**
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle;


/**
 * Ask the core to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".   Must only be
 * called after a connection to the respective peer has been
 * established (and the client has been informed about this).
 *
 *
 * @param handle connection to core service
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target who should receive the message,
 *        use NULL for this peer (loopback)
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout or if the overall queue
 *        for this peer is larger than queue_size and this is currently
 *        the message with the lowest priority; will also be called
 *        with 'NULL' buf if the peer disconnects; since the disconnect
 *        signal will be emmitted even later, clients MUST cancel
 *        all pending transmission requests DURING the disconnect
 *        handler (unless they ensure that 'notify' never calls
 *        'GNUNET_CORE_notify_transmit_ready').
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct GNUNET_CORE_Handle *handle, int cork,
                                   uint32_t priority,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   const struct GNUNET_PeerIdentity *target,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *th);





/**
 * Iterate over all connected peers.  Calls peer_cb with each
 * connected peer, and then once with NULL to indicate that all peers
 * have been handled.  Normal users of the CORE API are not expected
 * to use this function.  It is different in that it truly lists
 * all connections, not just those relevant to the application.  This
 * function is used by special applications for diagnostics.  This
 * function is NOT part of the 'versioned', 'official' API.
 *
 * FIXME: we should probably make it possible to 'cancel' the
 * operation...
 *
 * @param cfg configuration handle
 * @param peer_cb function to call with the peer information
 * @param cb_cls closure for peer_cb
 * @return GNUNET_OK on success, GNUNET_SYSERR on errors
 */
int
GNUNET_CORE_iterate_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CORE_ConnectEventHandler peer_cb,
                           void *cb_cls);


/**
 * Check if the given peer is currently connected and return information
 * about the session if so.  This function is for special cirumstances
 * (GNUNET_TESTING uses it), normal users of the CORE API are
 * expected to track which peers are connected based on the
 * connect/disconnect callbacks from GNUNET_CORE_connect.  This
 * function is NOT part of the 'versioned', 'official' API.
 *
 * FIXME: we should probably make it possible to 'cancel' the
 * operation...
 *
 * @param cfg configuration to use
 * @param peer the specific peer to check for
 * @param peer_cb function to call with the peer information
 * @param cb_cls closure for peer_cb
 * @return GNUNET_OK if iterating, GNUNET_SYSERR on error
 */
int
GNUNET_CORE_is_peer_connected (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               struct GNUNET_PeerIdentity *peer,
                               GNUNET_CORE_ConnectEventHandler peer_cb,
                               void *cb_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_SERVICE_H */
#endif
/* end of gnunet_core_service.h */
