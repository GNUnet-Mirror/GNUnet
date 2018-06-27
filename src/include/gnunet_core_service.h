/*
     This file is part of GNUnet.
     Copyright (C) 2009-2017 GNUnet e.V.

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
*/
/**
 * @author Christian Grothoff
 *
 * @file include/gnunet_core_service.h
 * Core service; the main API for encrypted P2P communications
 *
 * @defgroup core  Core service
 * Encrypted direct communication between peers
 *
 * @see [Documentation](https://gnunet.org/gnunet-core-subsystem)
 *
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
typedef void *
(*GNUNET_CORE_ConnectEventHandler) (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
				    struct GNUNET_MQ_Handle *mq);


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void
(*GNUNET_CORE_DisconnectEventHandler) (void *cls,
                                       const struct GNUNET_PeerIdentity *peer,
				       void *peer_cls);


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
                     const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Disconnect from the core service.
 *
 * @param handle connection to core to disconnect
 */
void
GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle);


/**
 * Inquire with CORE what options should be set for a message
 * so that it is transmitted with the given @a priority and
 * the given @a cork value.
 *
 * @param cork desired corking
 * @param priority desired message priority
 * @param[out] flags set to `flags` value for #GNUNET_MQ_set_options()
 * @return `extra` argument to give to #GNUNET_MQ_set_options()
 */
const void *
GNUNET_CORE_get_mq_options (int cork,
			    enum GNUNET_CORE_Priority priority,
			    uint64_t *flags);


/**
 * Obtain the message queue for a connected peer.
 *
 * @param h the core handle
 * @param pid the identity of the peer
 * @return NULL if @a pid is not connected
 */
struct GNUNET_MQ_Handle *
GNUNET_CORE_get_mq (const struct GNUNET_CORE_Handle *h,
		    const struct GNUNET_PeerIdentity *pid);


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
  GNUNET_CORE_KX_STATE_DOWN = 0,

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
   * message encrypted with their session key (which we got).  Key
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

/* ifndef GNUNET_CORE_SERVICE_H */
#endif

/** @} */  /* end of group core */

/* end of gnunet_core_service.h */
