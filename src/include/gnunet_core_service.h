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
 */
typedef void (*GNUNET_CORE_ConnectEventHandler) (void *cls,
						 const struct
						 GNUNET_PeerIdentity *peer,
						 const struct GNUNET_TRANSPORT_ATS_Information *atsi);


/**
 * Method called whenever a given peer has a status change.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param timeout absolute time when this peer will time out
 *        unless we see some further activity from it
 * @param bandwidth_in available amount of inbound bandwidth
 * @param bandwidth_out available amount of outbound bandwidth
 * @param atsi performance data for the connection
 */
typedef void (*GNUNET_CORE_PeerStatusEventHandler) (void *cls,
						    const struct
						    GNUNET_PeerIdentity * peer,
						    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
						    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
						    struct GNUNET_TIME_Absolute timeout,
						    const struct GNUNET_TRANSPORT_ATS_Information *atsi);


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void (*GNUNET_CORE_DisconnectEventHandler) (void *cls,
						    const struct
						    GNUNET_PeerIdentity *peer);


/**
 * Functions with this signature are called whenever a message is
 * received or transmitted.
 *
 * @param cls closure (set from GNUNET_CORE_connect)
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
typedef int
  (*GNUNET_CORE_MessageCallback) (void *cls,
                                  const struct GNUNET_PeerIdentity *other,
                                  const struct GNUNET_MessageHeader *message,
                                  const struct GNUNET_TRANSPORT_ATS_Information *atsi);


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
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).  Note that the private key of the
 * peer is intentionally not exposed here; if you need it,
 * your process should try to read the private key file
 * directly (which should work if you are authorized...).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 * @param publicKey public key of this peer, NULL if we failed
 */
typedef void
  (*GNUNET_CORE_StartupCallback) (void *cls,
                                  struct GNUNET_CORE_Handle * server,
                                  const struct GNUNET_PeerIdentity *
                                  my_identity,
                                  const struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
                                  publicKey);


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
 * @param status_events function to call on peer status changes, can be NULL
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
		     unsigned int queue_size,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
		     GNUNET_CORE_PeerStatusEventHandler status_events,
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
void GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle);


/**
 * Handle for a request to the core to connect or disconnect
 * from a particular peer.  Can be used to cancel the request
 * (before the 'cont'inuation is called).
 */
struct GNUNET_CORE_PeerRequestHandle;


/**
 * Type of function called upon completion.
 *
 * @param cls closure
 * @param success GNUNET_OK on success (which for request_connect
 *        ONLY means that we transmitted the connect request to CORE,
 *        it does not mean that we are actually now connected!);
 *        GNUNET_NO on timeout,
 *        GNUNET_SYSERR if core was shut down
 */
typedef void (*GNUNET_CORE_ControlContinuation)(void *cls, int success);


/**
 * Request that the core should try to connect to a particular peer.
 * Once the request has been transmitted to the core, the continuation
 * function will be called.  Note that this does NOT mean that a
 * connection was successfully established -- it only means that the
 * core will now try.  Successful establishment of the connection
 * will be signalled to the 'connects' callback argument of
 * 'GNUNET_CORE_connect' only.  If the core service does not respond
 * to our connection attempt within the given time frame, 'cont' will
 * be called with the TIMEOUT reason code.
 *
 * @param h core handle
 * @param timeout how long to try to talk to core
 * @param peer who should we connect to
 * @param cont function to call once the request has been completed (or timed out)
 * @param cont_cls closure for cont
 * @return NULL on error (cont will not be called), otherwise handle for cancellation
 */
struct GNUNET_CORE_PeerRequestHandle *
GNUNET_CORE_peer_request_connect (struct GNUNET_CORE_Handle *h,
				  struct GNUNET_TIME_Relative timeout,
				  const struct GNUNET_PeerIdentity * peer,
				  GNUNET_CORE_ControlContinuation cont,
				  void *cont_cls);


/**
 * Cancel a pending request to connect to a particular peer.  Must not
 * be called after the 'cont' function was invoked.
 *
 * @param req request handle that was returned for the original request
 */
void
GNUNET_CORE_peer_request_connect_cancel (struct GNUNET_CORE_PeerRequestHandle *req);


/**
 * Function called with perference change information about the given peer.
 *
 * @param cls closure
 * @param peer identifies the peer
 * @param bandwidth_out available amount of outbound bandwidth
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param preference current traffic preference for the given peer
 */
typedef void
  (*GNUNET_CORE_PeerConfigurationInfoCallback) (void *cls,
                                                const struct
                                                GNUNET_PeerIdentity * peer,
						struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
						int amount,
                                                uint64_t preference);



/**
 * Context that can be used to cancel a peer information request.
 */
struct GNUNET_CORE_InformationRequestContext;


/**
 * Obtain statistics and/or change preferences for the given peer.
 * You can only have one such pending request per peer.
 *
 * @param h core handle
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bw_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bpm_out" to "-1" to avoid changing
 *                the current value; otherwise "bw_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bw_out" might not increase
 *                as specified since the upper bound is generally
 *                determined by the other peer!
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 * @return NULL on error
 */
struct GNUNET_CORE_InformationRequestContext *
GNUNET_CORE_peer_change_preference (struct GNUNET_CORE_Handle *h,
				    const struct GNUNET_PeerIdentity *peer,
				    struct GNUNET_TIME_Relative timeout,
				    struct GNUNET_BANDWIDTH_Value32NBO bw_out,
				    int32_t amount,
				    uint64_t preference,
				    GNUNET_CORE_PeerConfigurationInfoCallback info,
				    void *info_cls);


/**
 * Cancel request for getting information about a peer.
 * Note that an eventual change in preference, trust or bandwidth
 * assignment MAY have already been committed at the time, 
 * so cancelling a request is NOT sure to undo the original
 * request.  The original request may or may not still commit.
 * The only thing cancellation ensures is that the callback
 * from the original request will no longer be called.
 *
 * @param irc context returned by the original GNUNET_CORE_peer_get_info call
 */
void
GNUNET_CORE_peer_change_preference_cancel (struct GNUNET_CORE_InformationRequestContext *irc);


/**
 * Iterate over all connected peers.
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
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle;


/**
 * Ask the core to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".  If we are not yet
 * connected to the specified peer, a call to this function will cause
 * us to try to establish a connection.
 *
 * @param handle connection to core service
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target who should receive the message,
 *        use NULL for this peer (loopback)
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout or if the overall queue
 *        for this peer is larger than queue_size and this is currently
 *        the message with the lowest priority
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct
				   GNUNET_CORE_Handle
				   *handle,
				   uint32_t priority,
				   struct
				   GNUNET_TIME_Relative
				   maxdelay,
				   const
				   struct
				   GNUNET_PeerIdentity
				   *target,
				   size_t
				   notify_size,
				   GNUNET_CONNECTION_TransmitReadyNotify
				   notify,
				   void
				   *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *th);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_SERVICE_H */
#endif
/* end of gnunet_core_service.h */
