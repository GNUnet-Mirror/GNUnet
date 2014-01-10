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
 * Possible state of a neighbour.  Initially, we are #S_NOT_CONNECTED.
 *
 * Then, there are two main paths. If we receive a CONNECT message, we
 * first run a check against the blacklist (#S_CONNECT_RECV_BLACKLIST_INBOUND).
 * If this check is successful, we give the inbound address to ATS.
 * After the check we ask ATS for a suggestion (S_CONNECT_RECV_ATS).
 * If ATS makes a suggestion, we ALSO give that suggestion to the blacklist
 * (#S_CONNECT_RECV_BLACKLIST).  Once the blacklist approves the
 * address we got from ATS, we send our CONNECT_ACK and go to
 * #S_CONNECT_RECV_ACK.  If we receive a SESSION_ACK, we go to
 * #S_CONNECTED (and notify everyone about the new connection).  If the
 * operation times out, we go to #S_DISCONNECT.
 *
 * The other case is where we transmit a CONNECT message first.  We
 * start with #S_INIT_ATS.  If we get an address, we enter
 * #S_INIT_BLACKLIST and check the blacklist.  If the blacklist is OK
 * with the connection, we actually send the CONNECT message and go to
 * state S_CONNECT_SENT.  Once we receive a CONNECT_ACK, we go to
 * #S_CONNECTED (and notify everyone about the new connection and send
 * back a SESSION_ACK).  If the operation times out, we go to
 * #S_DISCONNECT.
 *
 * If the session is in trouble (i.e. transport-level disconnect or
 * timeout), we go to #S_RECONNECT_ATS where we ask ATS for a new
 * address (we don't notify anyone about the disconnect yet).  Once we
 * have a new address, we go to #S_RECONNECT_BLACKLIST to check the new
 * address against the blacklist.  If the blacklist approves, we enter
 * #S_RECONNECT_SENT and send a CONNECT message.  If we receive a
 * CONNECT_ACK, we go to #S_CONNECTED and nobody noticed that we had
 * trouble; we also send a SESSION_ACK at this time just in case.  If
 * the operation times out, we go to S_DISCONNECT (and notify everyone
 * about the lost connection).
 *
 * If ATS decides to switch addresses while we have a normal
 * connection, we go to #S_CONNECTED_SWITCHING_BLACKLIST to check the
 * new address against the blacklist.  If the blacklist approves, we
 * go to #S_CONNECTED_SWITCHING_CONNECT_SENT and send a
 * SESSION_CONNECT.  If we get a SESSION_ACK back, we switch the
 * primary connection to the suggested alternative from ATS, go back
 * to #S_CONNECTED and send a SESSION_ACK to the other peer just to be
 * sure.  If the operation times out (or the blacklist disapproves),
 * we go to #S_CONNECTED (and notify ATS that the given alternative
 * address is "invalid").
 *
 * Once a session is in #S_DISCONNECT, it is cleaned up and then goes
 * to (#S_DISCONNECT_FINISHED).  If we receive an explicit disconnect
 * request, we can go from any state to #S_DISCONNECT, possibly after
 * generating disconnect notifications.
 *
 * Note that it is quite possible that while we are in any of these
 * states, we could receive a 'CONNECT' request from the other peer.
 * We then enter a 'weird' state where we pursue our own primary state
 * machine (as described above), but with the 'send_connect_ack' flag
 * set to 1.  If our state machine allows us to send a 'CONNECT_ACK'
 * (because we have an acceptable address), we send the 'CONNECT_ACK'
 * and set the 'send_connect_ack' to 2.  If we then receive a
 * 'SESSION_ACK', we go to #S_CONNECTED (and reset 'send_connect_ack'
 * to 0).
 *
 */
enum GNUNET_TRANSPORT_PeerState
{
  /**
   * Fresh peer or completely disconnected
   */
  GNUNET_TRANSPORT_PS_NOT_CONNECTED = 0,

  /**
   * Asked to initiate connection, trying to get address from ATS
   */
  GNUNET_TRANSPORT_PS_INIT_ATS,

  /**
   * Asked to initiate connection, trying to get address approved
   * by blacklist.
   */
  GNUNET_TRANSPORT_PS_INIT_BLACKLIST,

  /**
   * Sent CONNECT message to other peer, waiting for CONNECT_ACK
   */
  GNUNET_TRANSPORT_PS_CONNECT_SENT,

  /**
   * Received a CONNECT, do a blacklist check for inbound address
   */
  GNUNET_TRANSPORT_PS_CONNECT_RECV_BLACKLIST_INBOUND,

  /**
   * Received a CONNECT, asking ATS about address suggestions.
   */
  GNUNET_TRANSPORT_PS_CONNECT_RECV_ATS,

  /**
   * Received CONNECT from other peer, got an address, checking with blacklist.
   */
  GNUNET_TRANSPORT_PS_CONNECT_RECV_BLACKLIST,

  /**
   * CONNECT request from other peer was SESSION_ACK'ed, waiting for
   * SESSION_ACK.
   */
  GNUNET_TRANSPORT_PS_CONNECT_RECV_ACK,

  /**
   * Got our CONNECT_ACK/SESSION_ACK, connection is up.
   */
  GNUNET_TRANSPORT_PS_CONNECTED,

  /**
   * Connection got into trouble, rest of the system still believes
   * it to be up, but we're getting a new address from ATS.
   */
  GNUNET_TRANSPORT_PS_RECONNECT_ATS,

  /**
   * Connection got into trouble, rest of the system still believes
   * it to be up; we are checking the new address against the blacklist.
   */
  GNUNET_TRANSPORT_PS_RECONNECT_BLACKLIST,

  /**
   * Sent CONNECT over new address (either by ATS telling us to switch
   * addresses or from RECONNECT_ATS); if this fails, we need to tell
   * the rest of the system about a disconnect.
   */
  GNUNET_TRANSPORT_PS_RECONNECT_SENT,

  /**
   * We have some primary connection, but ATS suggested we switch
   * to some alternative; we're now checking the alternative against
   * the blacklist.
   */
  GNUNET_TRANSPORT_PS_CONNECTED_SWITCHING_BLACKLIST,

  /**
   * We have some primary connection, but ATS suggested we switch
   * to some alternative; we now sent a CONNECT message for the
   * alternative session to the other peer and waiting for a
   * CONNECT_ACK to make this our primary connection.
   */
  GNUNET_TRANSPORT_PS_CONNECTED_SWITCHING_CONNECT_SENT,

  /**
   * Disconnect in progress (we're sending the DISCONNECT message to the
   * other peer; after that is finished, the state will be cleaned up).
   */
  GNUNET_TRANSPORT_PS_DISCONNECT,

  /**
   * We're finished with the disconnect; and are cleaning up the state
   * now!  We put the struct into this state when we are really in the
   * task that calls 'free' on it and are about to remove the record
   * from the map.  We should never find a 'struct NeighbourMapEntry'
   * in this state in the map.  Accessing a 'struct NeighbourMapEntry'
   * in this state virtually always means using memory that has been
   * freed (the exception being the cleanup code in #free_neighbour()).
   */
  GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED
};



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
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
typedef void (*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                                const struct GNUNET_PeerIdentity
                                                * peer);

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
 * Function to call with result of the try connect request.
 *
 *
 * @param cls closure
 * @param result GNUNET_OK if message was transmitted to transport service
 *               GNUNET_SYSERR if message was not transmitted to transport service
 */
typedef void (*GNUNET_TRANSPORT_TryConnectCallback) (void *cls,
                                                     const int result);


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
 * Function to call with information about a peer
 *
 * If one_shot was set to GNUNET_YES to iterate over all peers once,
 * a final call with NULL for peer and address will follow when done.
 * In this case state and timeout do not contain valid values.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel call MUST not be called from
 * within this function!
 *
 *
 * @param cls closure
 * @param peer peer this update is about,
 *      NULL if this is the final last callback for a iteration operation
 * @param address address, NULL for disconnect notification in monitor mode
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 */
typedef void (*GNUNET_TRANSPORT_PeerIterateCallback) (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_HELLO_Address *address,
                                    enum GNUNET_TRANSPORT_PeerState state,
                                    struct GNUNET_TIME_Absolute state_timeout);


/**
 * Function to call with validation information about a peer
 *
 * @param cls closure
 * @param peer peer this update is about,
 *      NULL if this is the final last callback for a iteration operation
 * @param address address, NULL for disconnect notification in monitor mode
 * @param valid_until when does this address expire
 * @param next_validation time of the next validation operation
 *
 */
typedef void (*GNUNET_TRANSPORT_ValidationIterateCallback) (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_HELLO_Address *address,
                                    struct GNUNET_TIME_Absolute valid_until,
                                    struct GNUNET_TIME_Absolute next_validation);



/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec receive function to call, or NULL
 * @param nc function to call on connect events, or NULL
 * @param nd function to call on disconnect events, or NULL
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
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TryConnectHandle;


/**
 * Ask the transport service to establish a connection to
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 * @param cb callback to be called when request was transmitted to transport
 *         service
 * @param cb_cls closure for the callback
 * @return a GNUNET_TRANSPORT_TryConnectHandle handle or
 *         NULL on failure (cb will not be called)
 */
struct GNUNET_TRANSPORT_TryConnectHandle *
GNUNET_TRANSPORT_try_connect (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_PeerIdentity *target,
                              GNUNET_TRANSPORT_TryConnectCallback cb,
                              void *cb_cls);


/**
 * Cancel the request to transport to try a connect
 * Callback will not be called
 *
 * @param tch GNUNET_TRANSPORT_TryConnectHandle handle to cancel
 */
void
GNUNET_TRANSPORT_try_connect_cancel (struct GNUNET_TRANSPORT_TryConnectHandle *tch);


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
 * Checks if a given peer is connected to us
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return #GNUNET_YES (connected) or #GNUNET_NO (disconnected)
 */
int
GNUNET_TRANSPORT_check_peer_connected (struct GNUNET_TRANSPORT_Handle *handle,
                                            const struct GNUNET_PeerIdentity *peer);


/**
 * Set transport metrics for a peer and a direction
 *
 * @param handle transport handle
 * @param peer the peer to set the metric for
 * @param inbound set inbound direction (GNUNET_YES or GNUNET_NO)
 * @param outbound set outbound direction (GNUNET_YES or GNUNET_NO)
 * @param ats the metric as ATS information
 * @param ats_count the number of metrics
 *
 * Supported ATS values:
 * GNUNET_ATS_QUALITY_NET_DELAY  (value in ms)
 * GNUNET_ATS_QUALITY_NET_DISTANCE (value in count(hops))
 *
 * Example
 * To enforce a delay of 10 ms for peer p1 in sending direction use:
 *
 * struct GNUNET_ATS_Information ats;
 * ats.type = ntohl (GNUNET_ATS_QUALITY_NET_DELAY);
 * ats.value = ntohl (10);
 * GNUNET_TRANSPORT_set_traffic_metric (th, p1, TM_SEND, &ats, 1);
 *
 * Note:
 * Delay restrictions in receiving direction will be enforced with
 * 1 message delay.
 */
void
GNUNET_TRANSPORT_set_traffic_metric (struct GNUNET_TRANSPORT_Handle *handle,
				     const struct GNUNET_PeerIdentity *peer,
				     int inbound,
				     int outbound,
				     const struct GNUNET_ATS_Information *ats,
				     size_t ats_count);


/**
 * Obtain updates on changes to the HELLO message for this peer. The callback
 * given in this function is never called synchronously.
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
 * @param ghh handle to cancel
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
 * @param cont continuation to call when HELLO has been sent,
 *      tc reason GNUNET_SCHEDULER_REASON_TIMEOUT for fail
 *      tc reasong GNUNET_SCHEDULER_REASON_READ_READY for success
 * @param cls closure for continuation
 * @return a GNUNET_TRANSPORT_OfferHelloHandle handle or NULL on failure,
 *      in case of failure cont will not be called
 *
 */
struct GNUNET_TRANSPORT_OfferHelloHandle *
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_Task cont, void *cls);


/**
 * Cancel the request to transport to offer the HELLO message
 *
 * @param ohh the GNUNET_TRANSPORT_OfferHelloHandle to cancel
 */
void
GNUNET_TRANSPORT_offer_hello_cancel (struct GNUNET_TRANSPORT_OfferHelloHandle *ohh);


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
 * @param pic the context handle
 */
void
GNUNET_TRANSPORT_address_to_string_cancel (struct
                                           GNUNET_TRANSPORT_AddressToStringContext
                                           *pic);

/**
 * Convert a transport state to a human readable string.
 *
 * @param state the state
 */
const char *
GNUNET_TRANSPORT_p2s (enum GNUNET_TRANSPORT_PeerState state);


/**
 * Check if a state is defined as connected
 *
 * @param state the state value
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_TRANSPORT_is_connected (enum GNUNET_TRANSPORT_PeerState state);


/**
 * Return information about a specific peer or all peers currently known to
 * transport service once or in monitoring mode. To obtain information about
 * a specific peer, a peer identity can be passed. To obtain information about
 * all peers currently known to transport service, NULL can be passed as peer
 * identity.
 *
 * For each peer, the callback is called with information about the address used
 * to communicate with this peer, the state this peer is currently in and the
 * the current timeout for this state.
 *
 * Upon completion, the 'GNUNET_TRANSPORT_PeerIterateCallback' is called one
 * more time with 'NULL'. After this, the operation must no longer be
 * explicitly canceled.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel call MUST not be called in the
 * the peer_callback!
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain information for,
 *      NULL for all peers
 * @param one_shot GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 GNUNET_NO to monitor peers continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_callback function to call with the results
 * @param peer_callback_cls closure for peer_address_callback
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext *
GNUNET_TRANSPORT_monitor_peers (const struct
                                GNUNET_CONFIGURATION_Handle *cfg,
                                const struct GNUNET_PeerIdentity *peer,
                                int one_shot,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TRANSPORT_PeerIterateCallback peer_callback,
                                void *peer_callback_cls);


/**
 * Cancel request to monitor peers
 *
 * @param pic handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_peers_cancel (struct GNUNET_TRANSPORT_PeerMonitoringContext *pic);



/**
 * Return information about pending address validation operations for a specific
 * or all peers
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain validation entries for,
 *      NULL for all peers
 * @param one_shot GNUNET_YES to return all entries and then end (with NULL+NULL),
 *                 GNUNET_NO to monitor validation entries continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param validation_callback function to call with the results
 * @param validation_callback_cls closure for peer_address_callback
 */
struct GNUNET_TRANSPORT_ValidationMonitoringContext *
GNUNET_TRANSPORT_monitor_validation_entries (const struct
                                GNUNET_CONFIGURATION_Handle *cfg,
                                const struct GNUNET_PeerIdentity *peer,
                                int one_shot,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TRANSPORT_ValidationIterateCallback validation_callback,
                                void *validation_callback_cls);


/**
 * Return information about all current pending validation operations
 *
 * @param vic handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_validation_entries_cancel (struct GNUNET_TRANSPORT_ValidationMonitoringContext *vic);



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
