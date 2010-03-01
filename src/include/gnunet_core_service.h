/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

/**
 * Version number of GNUnet-core API.
 */
#define GNUNET_CORE_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_Handle;


/**
 * Method called whenever a given peer either connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 */
typedef void (*GNUNET_CORE_ConnectEventHandler) (void *cls,
						 const struct
						 GNUNET_PeerIdentity * peer,
						 struct GNUNET_TIME_Relative latency,
						 uint32_t distance);



/**
 * Method called whenever a given peer either disconnects.
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
 * @param cls closure
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
typedef int
  (*GNUNET_CORE_MessageCallback) (void *cls,
                                  const struct GNUNET_PeerIdentity * other,
                                  const struct GNUNET_MessageHeader *
                                  message,
				  struct GNUNET_TIME_Relative latency,
				  uint32_t distance);


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
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout after how long should we give up trying to connect to the core service?
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call on timeout or once we have successfully
 *        connected to the core service; note that timeout is only meaningful if init is not NULL
 * @param pre_connects function to call on peer pre-connect (no session key yet), can be NULL
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
GNUNET_CORE_connect (struct GNUNET_SCHEDULER_Handle *sched,
                     const struct GNUNET_CONFIGURATION_Handle *cfg,
                     struct GNUNET_TIME_Relative timeout,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
		     GNUNET_CORE_ConnectEventHandler pre_connects,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers);


/**
 * Disconnect from the core service.
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
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout how long to try to talk to core
 * @param peer who should we connect to
 * @param cont function to call once the request has been completed (or timed out)
 * @param cont_cls closure for cont
 * @return NULL on error (cont will not be called), otherwise handle for cancellation
 */
struct GNUNET_CORE_PeerRequestHandle *
GNUNET_CORE_peer_request_connect (struct GNUNET_SCHEDULER_Handle *sched,
				  const struct GNUNET_CONFIGURATION_Handle *cfg,
				  struct GNUNET_TIME_Relative timeout,
				  const struct GNUNET_PeerIdentity * peer,
				  GNUNET_SCHEDULER_Task cont,
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
 * Function called with statistics about the given peer.
 *
 * @param cls closure
 * @param peer identifies the peer
 * @param bpm_in set to the current bandwidth limit (receiving) for this peer
 * @param bpm_out set to the current bandwidth limit (sending) for this peer
 * @param latency current latency estimate, "FOREVER" if we have been
 *                disconnected
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param preference current traffic preference for the given peer
 */
typedef void
  (*GNUNET_CORE_PeerConfigurationInfoCallback) (void *cls,
                                                const struct
                                                GNUNET_PeerIdentity * peer,
                                                unsigned int bpm_in,
                                                unsigned int bpm_out,
						int amount,
                                                uint64_t preference);



/**
 * Context that can be used to cancel a peer information request.
 */
struct GNUNET_CORE_InformationRequestContext;


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bpm_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bpm_out" to "-1" to avoid changing
 *                the current value; otherwise "bpm_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bpm_out" might not increase
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
GNUNET_CORE_peer_change_preference (struct GNUNET_SCHEDULER_Handle *sched,
				    const struct GNUNET_CONFIGURATION_Handle *cfg,
				    const struct GNUNET_PeerIdentity *peer,
				    struct GNUNET_TIME_Relative timeout,
				    uint32_t bpm_out,
				    int32_t amount,
				    uint64_t preference,
				    GNUNET_CORE_PeerConfigurationInfoCallback info,
				    void *info_cls);


/**
 * Cancel request for getting information about a peer.
 *
 * @param irc context returned by the original GNUNET_CORE_peer_get_info call
 */
void
GNUNET_CORE_peer_change_preference_cancel (struct GNUNET_CORE_InformationRequestContext *irc);


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
 * @param notify function to call when buffer space is available
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
 * @param h handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_SERVICE_H */
#endif
/* end of gnunet_core_service.h */
