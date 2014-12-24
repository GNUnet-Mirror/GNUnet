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
#define GNUNET_TRANSPORT_VERSION 0x00000001


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 */
typedef void
(*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message);


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
 */
typedef void
(*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                   const struct GNUNET_PeerIdentity *peer);

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
typedef void
(*GNUNET_TRANSPORT_NotifyDisconnect) (void *cls,
                                      const struct GNUNET_PeerIdentity *peer);


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
                          const struct GNUNET_PeerIdentity *self,
                          void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd);


/**
 * Function called if we have "excess" bandwidth to a peer.
 * The notification will happen the first time we have excess
 * bandwidth, and then only again after the client has performed
 * some transmission to the peer.
 *
 * Excess bandwidth is defined as being allowed (by ATS) to send
 * more data, and us reaching the limit of the capacity build-up
 * (which, if we go past it, means we don't use available bandwidth).
 * See also the "max carry" in `struct GNUNET_BANDWIDTH_Tracker`.
 *
 * @param cls the closure
 * @param neighbour peer that we have excess bandwidth to
 */
typedef void
(*GNUNET_TRANSPORT_NotifyExcessBandwidth)(void *cls,
                                          const struct GNUNET_PeerIdentity *neighbour);


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
 * @param neb function to call if we have excess bandwidth to a peer
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const struct GNUNET_PeerIdentity *self,
                           void *cls,
                           GNUNET_TRANSPORT_ReceiveCallback rec,
                           GNUNET_TRANSPORT_NotifyConnect nc,
                           GNUNET_TRANSPORT_NotifyDisconnect nd,
                           GNUNET_TRANSPORT_NotifyExcessBandwidth neb);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/* ************************* Connections *********************** */

/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TryConnectHandle;

/**
 * Function to call with result of the try connect request.
 *
 * @param cls closure
 * @param result #GNUNET_OK if message was transmitted to transport service
 *               #GNUNET_SYSERR if message was not transmitted to transport service
 */
typedef void
(*GNUNET_TRANSPORT_TryConnectCallback) (void *cls,
                                        int result);


/**
 * Ask the transport service to establish a connection to
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 * @param cb callback to be called when request was transmitted to transport
 *         service
 * @param cb_cls closure for the callback @a cb
 * @return a `struct GNUNET_TRANSPORT_TryConnectHandle` handle or
 *         NULL on failure (@a cb will not be called)
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
 * @param tch handle to cancel
 */
void
GNUNET_TRANSPORT_try_connect_cancel (struct GNUNET_TRANSPORT_TryConnectHandle *tch);


/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TryDisconnectHandle;

/**
 * Function to call with result of the try connect request.
 *
 * @param cls closure
 * @param result #GNUNET_OK if message was transmitted to transport service
 *               #GNUNET_SYSERR if message was not transmitted to transport service
 */
typedef void
(*GNUNET_TRANSPORT_TryDisconnectCallback) (void *cls,
                                           int result);


/**
 * Ask the transport service to disconnect from the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to disconnect from
 * @param cb callback to be called when request was transmitted to transport
 *         service
 * @param cb_cls closure for the callback @a cb
 * @return a `struct GNUNET_TRANSPORT_TryConnectHandle` handle or
 *         NULL on failure (@a cb will not be called)
 */
struct GNUNET_TRANSPORT_TryDisconnectHandle *
GNUNET_TRANSPORT_try_disconnect (struct GNUNET_TRANSPORT_Handle *handle,
                                 const struct GNUNET_PeerIdentity *target,
                                 GNUNET_TRANSPORT_TryDisconnectCallback cb,
                                 void *cb_cls);


/**
 * Cancel the request to transport to disconnect.
 * Callback will not be called anymore.
 *
 * @param tdh handle for operation to cancel
 */
void
GNUNET_TRANSPORT_try_disconnect_cancel (struct GNUNET_TRANSPORT_TryDisconnectHandle *tdh);


/* ************************* Sending *************************** */

/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle;


/**
 * Function called to notify a client about the connection begin ready
 * to queue more data.  @a buf will be NULL and @a size zero if the
 * connection was closed for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
typedef size_t
(*GNUNET_TRANSPORT_TransmitReadyNotify) (void *cls,
                                         size_t size,
                                         void *buf);


/**
 * Check if we could queue a message of the given size for
 * transmission.  The transport service will take both its internal
 * buffers and bandwidth limits imposed by the other peer into
 * consideration when answering this query.
 *
 * @param handle connection to transport service
 * @param target who should receive the message
 * @param size how big is the message we want to transmit?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for @a notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using #GNUNET_TRANSPORT_notify_transmit_ready_cancel())
 */
struct GNUNET_TRANSPORT_TransmitHandle *
GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle *handle,
                                        const struct GNUNET_PeerIdentity *target,
                                        size_t size,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_TransmitReadyNotify notify,
                                        void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle of the transmission notification request to cancel
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct GNUNET_TRANSPORT_TransmitHandle *th);


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



/* *********************** Metric manipulation ***************** */

/**
 * Set transport metrics for a peer and a direction
 *
 * @param handle transport handle
 * @param peer the peer to set the metric for
 * @param inbound set inbound direction (#GNUNET_YES or #GNUNET_NO)
 * @param outbound set outbound direction (#GNUNET_YES or #GNUNET_NO)
 * @param ats the metric as ATS information
 * @param ats_count the number of metrics
 *
 * Supported ATS values:
 * #GNUNET_ATS_QUALITY_NET_DELAY  (value in ms)
 * #GNUNET_ATS_QUALITY_NET_DISTANCE (value in count(hops))
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


/* *************************** HELLO *************************** */


/**
 * Function called whenever there is an update to the
 * HELLO of this peer.
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
typedef void
(*GNUNET_TRANSPORT_HelloUpdateCallback) (void *cls,
                                         const struct GNUNET_MessageHeader *hello);


/**
 * Handle to cancel a #GNUNET_TRANSPORT_get_hello() operation.
 */
struct GNUNET_TRANSPORT_GetHelloHandle;


/**
 * Obtain updates on changes to the HELLO message for this peer. The callback
 * given in this function is never called synchronously.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO
 * @param rec_cls closure for @a rec
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
 * Handle for a #GNUNET_TRANSPORT_offer_hello operation
 */
struct GNUNET_TRANSPORT_OfferHelloHandle;


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent,
 *      tc reason #GNUNET_SCHEDULER_REASON_TIMEOUT for fail
 *      tc reasong #GNUNET_SCHEDULER_REASON_READ_READY for success
 * @param cls closure for continuation
 * @return a GNUNET_TRANSPORT_OfferHelloHandle handle or NULL on failure,
 *      in case of failure cont will not be called
 *
 */
struct GNUNET_TRANSPORT_OfferHelloHandle *
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_TaskCallback cont, void *cls);


/**
 * Cancel the request to transport to offer the HELLO message
 *
 * @param ohh the `struct GNUNET_TRANSPORT_OfferHelloHandle` to cancel
 */
void
GNUNET_TRANSPORT_offer_hello_cancel (struct GNUNET_TRANSPORT_OfferHelloHandle *ohh);


/* *********************** Address to String ******************* */

/**
 * Handle to cancel a pending address lookup.
 */
struct GNUNET_TRANSPORT_AddressToStringContext;


/**
 * Function to call with a textual representation of an address.  This
 * function will be called several times with different possible
 * textual representations, and a last time with @a address being NULL
 * to signal the end of the iteration.  Note that @a address NULL
 * always is the last call, regardless of the value in @a res.
 *
 * @param cls closure
 * @param address NULL on end of iteration,
 *        otherwise 0-terminated printable UTF-8 string,
 *        in particular an empty string if @a res is #GNUNET_NO
 * @param res result of the address to string conversion:
 *        if #GNUNET_OK: conversion successful
 *        if #GNUNET_NO: address was invalid (or not supported)
 *        if #GNUNET_SYSERR: communication error (IPC error)
 */
typedef void
(*GNUNET_TRANSPORT_AddressToStringCallback) (void *cls,
                                             const char *address,
                                             int res);


/**
 * Convert a binary address into a human readable address.
 *
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param numeric should (IP) addresses be displayed in numeric form
 *                (otherwise do reverse DNS lookup)
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for @a aluc
 * @return handle to cancel the operation, NULL on error
 */
struct GNUNET_TRANSPORT_AddressToStringContext *
GNUNET_TRANSPORT_address_to_string (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                    const struct GNUNET_HELLO_Address *address,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressToStringCallback aluc,
                                    void *aluc_cls);


/**
 * Cancel request for address conversion.
 *
 * @param pic the context handle
 */
void
GNUNET_TRANSPORT_address_to_string_cancel (struct GNUNET_TRANSPORT_AddressToStringContext *pic);


/* *********************** Monitoring ************************** */


/**
 * Possible state of a neighbour.  Initially, we are #GNUNET_TRANSPORT_PS_NOT_CONNECTED.
 *
 * Then, there are two main paths. If we receive a SYN message, we give
 * the inbound address to ATS. After the check we ask ATS for a suggestion
 * (#GNUNET_TRANSPORT_PS_CONNECT_RECV_ATS). If ATS makes a suggestion, we
 * send our SYN_ACK and go to #GNUNET_TRANSPORT_PS_CONNECT_RECV_ACK.
 * If we receive a ACK, we go to #GNUNET_TRANSPORT_PS_CONNECTED
 * (and notify everyone about the new connection). If the operation times out,
 * we go to #GNUNET_TRANSPORT_PS_DISCONNECT.
 *
 * The other case is where we transmit a SYN message first.  We
 * start with #GNUNET_TRANSPORT_PS_INIT_ATS.  If we get an address, we send
 * the SYN message and go to state #GNUNET_TRANSPORT_PS_CONNECT_SENT.
 * Once we receive a SYN_ACK, we go to #GNUNET_TRANSPORT_PS_CONNECTED
 * (and notify everyone about the new connection and send
 * back a ACK).  If the operation times out, we go to
 * #GNUNET_TRANSPORT_PS_DISCONNECT.
 *
 * If the session is in trouble (i.e. transport-level disconnect or
 * timeout), we go to #GNUNET_TRANSPORT_PS_RECONNECT_ATS where we ask ATS for a new
 * address (we don't notify anyone about the disconnect yet).  Once we
 * have a new address, we enter #GNUNET_TRANSPORT_PS_RECONNECT_SENT and send a
 * SYN message.  If we receive a
 * SYN_ACK, we go to #GNUNET_TRANSPORT_PS_CONNECTED and nobody noticed that we had
 * trouble; we also send a ACK at this time just in case.  If
 * the operation times out, we go to #GNUNET_TRANSPORT_PS_DISCONNECT (and notify everyone
 * about the lost connection).
 *
 * If ATS decides to switch addresses while we have a normal
 * connection, we go to #GNUNET_TRANSPORT_PS_CONNECTED_SWITCHING_SYN_SENT
 * and send a SESSION_CONNECT.  If we get a ACK back, we switch the
 * primary connection to the suggested alternative from ATS, go back
 * to #GNUNET_TRANSPORT_PS_CONNECTED and send a ACK to the other peer just to be
 * sure.  If the operation times out
 * we go to #GNUNET_TRANSPORT_PS_CONNECTED (and notify ATS that the given alternative
 * address is "invalid").
 *
 * Once a session is in #GNUNET_TRANSPORT_PS_DISCONNECT, it is cleaned up and then goes
 * to (#GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED).  If we receive an explicit disconnect
 * request, we can go from any state to #GNUNET_TRANSPORT_PS_DISCONNECT, possibly after
 * generating disconnect notifications.
 *
 * Note that it is quite possible that while we are in any of these
 * states, we could receive a 'SYN' request from the other peer.
 * We then enter a 'weird' state where we pursue our own primary state
 * machine (as described above), but with the 'send_connect_ack' flag
 * set to 1.  If our state machine allows us to send a 'SYN_ACK'
 * (because we have an acceptable address), we send the 'SYN_ACK'
 * and set the 'send_connect_ack' to 2.  If we then receive a
 * 'ACK', we go to #GNUNET_TRANSPORT_PS_CONNECTED (and reset 'send_connect_ack'
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
   * Sent SYN message to other peer, waiting for SYN_ACK
   */
  GNUNET_TRANSPORT_PS_SYN_SENT,

  /**
   * Received a SYN, asking ATS about address suggestions.
   */
  GNUNET_TRANSPORT_PS_SYN_RECV_ATS,

  /**
   * SYN request from other peer was SYN_ACK'ed, waiting for ACK.
   */
  GNUNET_TRANSPORT_PS_SYN_RECV_ACK,

  /**
   * Got our SYN_ACK/ACK, connection is up.
   */
  GNUNET_TRANSPORT_PS_CONNECTED,

  /**
   * Connection got into trouble, rest of the system still believes
   * it to be up, but we're getting a new address from ATS.
   */
  GNUNET_TRANSPORT_PS_RECONNECT_ATS,

  /**
   * Sent SYN over new address (either by ATS telling us to switch
   * addresses or from RECONNECT_ATS); if this fails, we need to tell
   * the rest of the system about a disconnect.
   */
  GNUNET_TRANSPORT_PS_RECONNECT_SENT,

  /**
   * We have some primary connection, but ATS suggested we switch
   * to some alternative; we now sent a SYN message for the
   * alternative session to the other peer and waiting for a
   * SYN_ACK to make this our primary connection.
   */
  GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT,

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
 * Convert a transport state to a human readable string.
 *
 * @param state the state
 */
const char *
GNUNET_TRANSPORT_ps2s (enum GNUNET_TRANSPORT_PeerState state);


/**
 * Check if a state is defined as connected
 *
 * @param state the state value
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GNUNET_TRANSPORT_is_connected (enum GNUNET_TRANSPORT_PeerState state);


/**
 * Handle for a #GNUNET_TRANSPORT_monitor_peers operation.
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext;


/**
 * Function to call with information about a peer
 *
 * If one_shot was set to #GNUNET_YES to iterate over all peers once,
 * a final call with NULL for peer and address will follow when done.
 * In this case state and timeout do not contain valid values.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel() call MUST not be called from
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
typedef void
(*GNUNET_TRANSPORT_PeerIterateCallback) (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         const struct GNUNET_HELLO_Address *address,
                                         enum GNUNET_TRANSPORT_PeerState state,
                                         struct GNUNET_TIME_Absolute state_timeout);


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
 * Upon completion, the #GNUNET_TRANSPORT_PeerIterateCallback is called one
 * more time with `NULL`. After this, the operation must no longer be
 * explicitly canceled.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel call MUST not be called in the
 * the peer_callback!
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain information for,
 *      NULL for all peers
 * @param one_shot #GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 #GNUNET_NO to monitor peers continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_callback function to call with the results
 * @param peer_callback_cls closure for @a peer_callback
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext *
GNUNET_TRANSPORT_monitor_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
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
 * Handle for a #GNUNET_TRANSPORT_monitor_validation_entries() operation.
 */
struct GNUNET_TRANSPORT_ValidationMonitoringContext;


/**
 * Current state of a validation process.
 *
 * FIXME: what state is used to indicate that a validation
 * was successful? If that is clarified/determined, "UGH" in
 * ~gnunet-peerinfo-gtk.c:1103 should be resolved.
 */
enum GNUNET_TRANSPORT_ValidationState
{
  /**
   * Undefined state
   *
   * Used for final callback indicating operation done
   */
  GNUNET_TRANSPORT_VS_NONE,

  /**
   * Fresh validation entry
   *
   * Entry was just created, no validation process was executed
   */
  GNUNET_TRANSPORT_VS_NEW,

  /**
   * Updated validation entry
   *
   * This is an update for an existing validation entry
   */
  GNUNET_TRANSPORT_VS_UPDATE,

  /**
   * Timeout for validation entry
   *
   * A timeout occured during the validation process
   */
  GNUNET_TRANSPORT_VS_TIMEOUT,

  /**
   * Validation entry is removed
   *
   * The validation entry is getting removed due to a failed validation
   */
  GNUNET_TRANSPORT_VS_REMOVE
};


/**
 * Function to call with validation information about a peer
 *
 * This function is called by the transport validation monitoring api to
 * indicate a change to a validation entry. The information included represent
 * the current state of the validation entry,
 *
 * If the monitoring was called with `one_shot==GNUNET_YES`, a final callback
 * with `peer==NULL` and `address==NULL` is executed.
 *
 * @param cls closure
 * @param peer peer this update is about,
 *      NULL if this is the final last callback for a iteration operation
 * @param address address,
 *      NULL for disconnect notification in monitor mode
 * @param last_validation when was this address last validated
 * @param valid_until when does this address expire
 * @param next_validation time of the next validation operation
 * @param state state in the validation state machine
 */
typedef void
(*GNUNET_TRANSPORT_ValidationIterateCallback) (void *cls,
                                               const struct GNUNET_PeerIdentity *peer,
                                               const struct GNUNET_HELLO_Address *address,
                                               struct GNUNET_TIME_Absolute last_validation,
                                               struct GNUNET_TIME_Absolute valid_until,
                                               struct GNUNET_TIME_Absolute next_validation,
                                               enum GNUNET_TRANSPORT_ValidationState state);


/**
 * Convert validation state to human-readable string.
 *
 * @param state the state value
 * @return corresponding string
 */
const char *
GNUNET_TRANSPORT_vs2s (enum GNUNET_TRANSPORT_ValidationState state);


/**
 * Return information about pending address validation operations for a specific
 * or all peers
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain validation entries for,
 *      NULL for all peers
 * @param one_shot #GNUNET_YES to return all entries and then end (with NULL+NULL),
 *                 #GNUNET_NO to monitor validation entries continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param validation_callback function to call with the results
 * @param validation_callback_cls closure for @a validation_callback
 */
struct GNUNET_TRANSPORT_ValidationMonitoringContext *
GNUNET_TRANSPORT_monitor_validation_entries (const struct GNUNET_CONFIGURATION_Handle *cfg,
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


/* *********************** Blacklisting ************************ */

/**
 * Handle for blacklisting peers.
 */
struct GNUNET_TRANSPORT_Blacklist;


/**
 * Function that decides if a connection is acceptable or not.
 *
 * @param cls closure
 * @param pid peer to approve or disapproave
 * @return #GNUNET_OK if the connection is allowed, #GNUNET_SYSERR if not
 */
typedef int
(*GNUNET_TRANSPORT_BlacklistCallback) (void *cls,
                                       const struct GNUNET_PeerIdentity *pid);


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
 * @param cb_cls closure for @a cb
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


/**
 * Handle for a plugin session state monitor.
 */
struct GNUNET_TRANSPORT_PluginMonitor;

/**
 * Abstract representation of a plugin's session.
 * Corresponds to the `struct Session` within the TRANSPORT service.
 */
struct GNUNET_TRANSPORT_PluginSession;


/**
 * Possible states of a session in a plugin.
 */
enum GNUNET_TRANSPORT_SessionState
{

  /**
   * The session was created (first call for each session object).
   */
  GNUNET_TRANSPORT_SS_INIT,

  /**
   * Initial session handshake is in progress.
   */
  GNUNET_TRANSPORT_SS_HANDSHAKE,

  /**
   * Session is fully UP.
   */
  GNUNET_TRANSPORT_SS_UP,

  /**
   * This is just an update about the session,
   * the state did not change.
   */
  GNUNET_TRANSPORT_SS_UPDATE,

  /**
   * Session is being torn down and about to disappear.
   * Last call for each session object.
   */
  GNUNET_TRANSPORT_SS_DONE

};


/**
 * Information about a plugin's session.
 */
struct GNUNET_TRANSPORT_SessionInfo
{

  /**
   * New state of the session.
   */
  enum GNUNET_TRANSPORT_SessionState state;

  /**
   * #GNUNET_YES if this is an inbound connection,
   * #GNUNET_NO if this is an outbound connection,
   * #GNUNET_SYSERR if connections of this plugin
   *             are so fundamentally bidirectional
   *             that they have no 'initiator'
   */
  int is_inbound;

  /**
   * Number of messages pending transmission for this session.
   */
  uint32_t num_msg_pending;

  /**
   * Number of bytes pending transmission for this session.
   */
  uint32_t num_bytes_pending;

  /**
   * Until when does this plugin refuse to receive to manage
   * staying within the inbound quota?  ZERO if receive is
   * active.
   */
  struct GNUNET_TIME_Absolute receive_delay;

  /**
   * At what time will this session timeout (unless activity
   * happens)?
   */
  struct GNUNET_TIME_Absolute session_timeout;

  /**
   * Address used by the session.  Can be NULL if none is available.
   */
  const struct GNUNET_HELLO_Address *address;
};


/**
 * Function called by the plugin with information about the
 * current sessions managed by the plugin (for monitoring).
 *
 * @param cls closure
 * @param session session handle this information is about,
 *        NULL to indicate that we are "in sync" (initial
 *        iteration complete)
 * @param session_ctx storage location where the application
 *        can store data; will point to NULL on #GNUNET_TRANSPORT_SS_INIT,
 *        and must be reset to NULL on #GNUNET_TRANSPORT_SS_DONE
 * @param info information about the state of the session,
 *        NULL if @a session is also NULL and we are
 *        merely signalling that the initial iteration is over;
 *        NULL with @a session being non-NULL if the monitor
 *        was being cancelled while sessions were active
 */
typedef void
(*GNUNET_TRANSPORT_SessionMonitorCallback) (void *cls,
                                            struct GNUNET_TRANSPORT_PluginSession *session,
                                            void **session_ctx,
                                            const struct GNUNET_TRANSPORT_SessionInfo *info);


/**
 * Install a plugin session state monitor callback.  The callback
 * will be notified whenever the session changes.
 *
 * @param cfg configuration to use
 * @param cb callback to invoke on events
 * @param cb_cls closure for @a cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_PluginMonitor *
GNUNET_TRANSPORT_monitor_plugins (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  GNUNET_TRANSPORT_SessionMonitorCallback cb,
                                  void *cb_cls);


/**
 * Cancel monitoring the plugin session state.  The callback will be
 * called once for each session that is up with the "info" argument
 * being NULL (this is just to enable client-side cleanup).
 *
 * @param pm handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_monitor_plugins_cancel (struct GNUNET_TRANSPORT_PluginMonitor *pm);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_SERVICE_H */
#endif
/* end of gnunet_transport_service.h */


