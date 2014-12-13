/*
     This file is part of GNUnet.
     (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * @defgroup core encrypted direct communication between peers
 * @{
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
#define GNUNET_CORE_VERSION 0x00000001

/**
 * Traffic priorities.
 */
enum GNUNET_CORE_Priority
{

  /**
   * Lowest priority, i.e. background traffic (i.e. fs)
   */
  GNUNET_CORE_PRIO_BACKGROUND = 0,

  /**
   * Normal traffic (i.e. cadet/dv relay, DHT)
   */
  GNUNET_CORE_PRIO_BEST_EFFORT = 1,

  /**
   * Urgent traffic (local peer, i.e. conversation).
   */
  GNUNET_CORE_PRIO_URGENT = 2,

  /**
   * Highest priority, control traffic (i.e. NSE, Core/Cadet KX).
   */
  GNUNET_CORE_PRIO_CRITICAL_CONTROL = 3


};


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_Handle;


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void
(*GNUNET_CORE_ConnectEventHandler) (void *cls,
                                    const struct GNUNET_PeerIdentity *peer);


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void
(*GNUNET_CORE_DisconnectEventHandler) (void *cls,
                                       const struct GNUNET_PeerIdentity *peer);


/**
 * Functions with this signature are called whenever a message is
 * received or transmitted.
 *
 * @param cls closure (set from #GNUNET_CORE_connect)
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close connection to the peer (signal serious error)
 */
typedef int
(*GNUNET_CORE_MessageCallback) (void *cls,
                                const struct GNUNET_PeerIdentity *other,
                                const struct GNUNET_MessageHeader *message);


/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_CORE_MessageHandler
{
  /**
   * Function to call for messages of @e type.
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
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
typedef void
(*GNUNET_CORE_StartupCallback) (void *cls,
                                const struct GNUNET_PeerIdentity *my_identity);


/**
 * Connect to the core service.  Note that the connection may complete
 * (or fail) asynchronously.  This function primarily causes the given
 * callback notification functions to be invoked whenever the
 * specified event happens.  The maximum number of queued
 * notifications (queue length) is per client; the queue is shared
 * across all types of notifications.  So a slow client that registers
 * for @a outbound_notify also risks missing @a inbound_notify messages.
 * Certain events (such as connect/disconnect notifications) are not
 * subject to queue size limitations.
 *
 * @param cfg configuration to use
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call once we have successfully
 *        connected to the core service
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param inbound_hdr_only set to #GNUNET_YES if @a inbound_notify will only read the
 *                `struct GNUNET_MessageHeader` and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if inbound_notify is NULL
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param outbound_notify function to call for all outbound messages, can be NULL;
 *                note that the core is allowed to drop notifications about outbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param outbound_hdr_only set to #GNUNET_YES if @a outbound_notify will only read the
 *                `struct GNUNET_MessageHeader` and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if outbound_notify is NULL
 *                note that the core is allowed to drop notifications about outbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param handlers callbacks for messages we care about, NULL-terminated
 *                note that the core is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @return handle to the core service (only useful for disconnect until @a init is called),
 *           NULL on error (in this case, init is never called)
 */
struct GNUNET_CORE_Handle *
GNUNET_CORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
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
 * be called *after* all pending #GNUNET_CORE_notify_transmit_ready
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
 * Ask the core to call @a notify once it is ready to transmit the
 * given number of bytes to the specified @a target.  Must only be
 * called after a connection to the respective peer has been
 * established (and the client has been informed about this).  You may
 * have one request of this type pending for each connected peer at
 * any time.  If a peer disconnects, the application MUST call
 * #GNUNET_CORE_notify_transmit_ready_cancel() on the respective
 * transmission request, if one such request is pending.
 *
 * @param handle connection to core service
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait? Only effective if @a cork is #GNUNET_YES
 * @param target who should receive the message, never NULL (can be this peer's identity for loopback)
 * @param notify_size how many bytes of buffer space does @a notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout; clients MUST cancel
 *        all pending transmission requests DURING the disconnect
 *        handler
 * @param notify_cls closure for @a notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (request already pending);
 *         if NULL is returned, @a notify will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct GNUNET_CORE_Handle *handle,
                                   int cork,
                                   enum GNUNET_CORE_Priority priority,
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
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle *th);


/**
 * Handle to a CORE monitoring operation.
 */
struct GNUNET_CORE_MonitorHandle;


/**
 * State machine for our P2P encryption handshake.  Everyone starts in
 * #GNUNET_CORE_KX_STATE_DOWN, if we receive the other peer's key
 * (other peer initiated) we start in state
 * #GNUNET_CORE_KX_STATE_KEY_RECEIVED (since we will immediately send
 * our own); otherwise we start in #GNUNET_CORE_KX_STATE_KEY_SENT.  If
 * we get back a PONG from within either state, we move up to
 * #GNUNET_CORE_KX_STATE_UP (the PONG will always be sent back
 * encrypted with the key we sent to the other peer).  Eventually,
 * we will try to rekey, for this we will enter
 * #GNUNET_CORE_KX_STATE_REKEY_SENT until the rekey operation is
 * confirmed by a PONG from the other peer.
 */
enum GNUNET_CORE_KxState
{
  /**
   * No handshake yet.
   */
  GNUNET_CORE_KX_STATE_DOWN,

  /**
   * We've sent our session key.
   */
  GNUNET_CORE_KX_STATE_KEY_SENT,

  /**
   * We've received the other peers session key.
   */
  GNUNET_CORE_KX_STATE_KEY_RECEIVED,

  /**
   * The other peer has confirmed our session key + PING with a PONG
   * message encrypted with his session key (which we got).  Key
   * exchange is done.
   */
  GNUNET_CORE_KX_STATE_UP,

  /**
   * We're rekeying (or had a timeout), so we have sent the other peer
   * our new ephemeral key, but we did not get a matching PONG yet.
   * This is equivalent to being #GNUNET_CORE_KX_STATE_KEY_RECEIVED,
   * except that the session is marked as 'up' with sessions (as we
   * don't want to drop and re-establish P2P connections simply due to
   * rekeying).
   */
  GNUNET_CORE_KX_STATE_REKEY_SENT,

  /**
   * Last state of a KX (when it is being terminated).  Set
   * just before CORE frees the internal state for this peer.
   */
  GNUNET_CORE_KX_PEER_DISCONNECT,

  /**
   * This is not a state in a peer's state machine, but a special
   * value used with the #GNUNET_CORE_MonitorCallback to indicate
   * that we finished the initial iteration over the peers.
   */
  GNUNET_CORE_KX_ITERATION_FINISHED,

  /**
   * This is not a state in a peer's state machine, but a special
   * value used with the #GNUNET_CORE_MonitorCallback to indicate
   * that we lost the connection to the CORE service (and will try
   * to reconnect).  If this happens, most likely the CORE service
   * crashed and thus all connection state should be assumed lost.
   */
  GNUNET_CORE_KX_CORE_DISCONNECT

};


/**
 * Function called by the monitor callback whenever
 * a peer's connection status changes.
 *
 * @param cls closure
 * @param pid identity of the peer this update is about
 * @param state current key exchange state of the peer
 * @param timeout when does the current state expire
 */
typedef void
(*GNUNET_CORE_MonitorCallback)(void *cls,
                               const struct GNUNET_PeerIdentity *pid,
                               enum GNUNET_CORE_KxState state,
                               struct GNUNET_TIME_Absolute timeout);


/**
 * Monitor connectivity and KX status of all peers known to CORE.
 * Calls @a peer_cb with the current status for each connected peer,
 * and then once with NULL to indicate that all peers that are
 * currently active have been handled.  After that, the iteration
 * continues until it is cancelled.  Normal users of the CORE API are
 * not expected to use this function.  It is different in that it
 * truly lists all connections (including those where the KX is in
 * progress), not just those relevant to the application.  This
 * function is used by special applications for diagnostics.
 *
 * @param cfg configuration handle
 * @param peer_cb function to call with the peer information
 * @param peer_cb_cls closure for @a peer_cb
 * @return NULL on error
 */
struct GNUNET_CORE_MonitorHandle *
GNUNET_CORE_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CORE_MonitorCallback peer_cb,
                           void *peer_cb_cls);


/**
 * Stop monitoring CORE activity.
 *
 * @param mh monitor to stop
 */
void
GNUNET_CORE_monitor_stop (struct GNUNET_CORE_MonitorHandle *mh);


/**
 * Check if the given peer is currently connected. This function is for special
 * cirumstances (GNUNET_TESTBED uses it), normal users of the CORE API are
 * expected to track which peers are connected based on the connect/disconnect
 * callbacks from #GNUNET_CORE_connect.  This function is NOT part of the
 * 'versioned', 'official' API.  This function returns
 * synchronously after looking in the CORE API cache.
 *
 * @param h the core handle
 * @param pid the identity of the peer to check if it has been connected to us
 * @return #GNUNET_YES if the peer is connected to us; #GNUNET_NO if not
 */
int
GNUNET_CORE_is_peer_connected_sync (const struct GNUNET_CORE_Handle *h,
                                    const struct GNUNET_PeerIdentity *pid);


/**
 * Create a message queue for sending messages to a peer with CORE.
 * Messages may only be queued with #GNUNET_MQ_send once the init callback has
 * been called for the given handle.
 * There must only be one queue per peer for each core handle.
 * The message queue can only be used to transmit messages,
 * not to receive them.
 *
 * @param h the core handle
 * @param target the target peer for this queue, may not be NULL
 * @return a message queue for sending messages over the core handle
 *         to the target peer
 */
struct GNUNET_MQ_Handle *
GNUNET_CORE_mq_create (struct GNUNET_CORE_Handle *h,
                       const struct GNUNET_PeerIdentity *target);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/** @} */ /* end of group core */

/* ifndef GNUNET_CORE_SERVICE_H */
#endif
/* end of gnunet_core_service.h */
