/*
     This file is part of GNUnet.
     Copyright (C) 2009-2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @author Christian Grothoff
 * @author Bart Polot
 *
 * @file
 * CADET service; establish channels to distant peers
 *
 * @defgroup cadet  CADET service
 * Confidential Ad-hoc Decentralized End-to-End Transport
 *
 * @see [Documentation](https://gnunet.org/cadet-subsystem)
 * @see [Paper](https://gnunet.org/cadet)
 *
 * @{
 */
#ifndef GNUNET_CADET_SERVICE_H
#define GNUNET_CADET_SERVICE_H

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
 * Version number of GNUnet-cadet API.
 */
#define GNUNET_CADET_VERSION 0x00000005


/**
 * Opaque handle to the service.
 */
struct GNUNET_CADET_Handle;

/**
 * Opaque handle to a channel.
 */
struct GNUNET_CADET_Channel;

/**
 * Opaque handle to a port.
 */
struct GNUNET_CADET_Port;


/**
 * Hash uniquely identifying a connection below a tunnel.
 */
struct GNUNET_CADET_ConnectionTunnelIdentifier
{
  struct GNUNET_ShortHashCode connection_of_tunnel;
};


/**
 * Number identifying a CADET channel within a tunnel.
 */
struct GNUNET_CADET_ChannelTunnelNumber
{
  /**
   * Which number does this channel have that uniquely identfies
   * it within its tunnel, in network byte order.
   *
   * Given two peers, both may initiate channels over the same tunnel.
   * The @e cn must be greater or equal to 0x80000000 (high-bit set)
   * for tunnels initiated with the peer that has the larger peer
   * identity as compared using #GNUNET_CRYPTO_cmp_peer_identity().
   */
  uint32_t cn GNUNET_PACKED;
};


/**
 * Channel options.  Second line indicates filed in the
 * CadetChannelInfo union carrying the answer.
 */
enum GNUNET_CADET_ChannelOption
{
  /**
   * Default options: unreliable, default buffering, not out of order.
   */
  GNUNET_CADET_OPTION_DEFAULT    = 0x0,

  /**
   * Disable buffering on intermediate nodes (for minimum latency).
   * Yes/No.
   */
  GNUNET_CADET_OPTION_NOBUFFER   = 0x1,

  /**
   * Enable channel reliability, lost messages will be retransmitted.
   * Yes/No.
   */
  GNUNET_CADET_OPTION_RELIABLE   = 0x2,

  /**
   * Enable out of order delivery of messages.
   * Set bit for out-of-order delivery.
   */
  GNUNET_CADET_OPTION_OUT_OF_ORDER = 0x4,

  /**
   * Who is the peer at the other end of the channel.
   * Only for use in @c GNUNET_CADET_channel_get_info
   * struct GNUNET_PeerIdentity *peer
   */
  GNUNET_CADET_OPTION_PEER       = 0x8

};


/**
 * Method called whenever a peer connects to a port in MQ-based CADET.
 *
 * @param cls Closure from #GNUNET_CADET_open_port.
 * @param channel New handle to the channel.
 * @param source Peer that started this channel.
 * @return Closure for the incoming @a channel. It's given to:
 *         - The #GNUNET_CADET_DisconnectEventHandler (given to
 *           #GNUNET_CADET_open_port) when the channel dies.
 *         - Each the #GNUNET_MQ_MessageCallback handlers for each message
 *           received on the @a channel.
 */
typedef void *
(*GNUNET_CADET_ConnectEventHandler) (void *cls,
                                     struct GNUNET_CADET_Channel *channel,
                                     const struct GNUNET_PeerIdentity *source);


/**
 * Function called whenever an MQ-channel is destroyed, even if the destruction
 * was requested by #GNUNET_CADET_channel_destroy.
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * It should clean up any associated state, including cancelling any pending
 * transmission on this channel.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 */
typedef void
(*GNUNET_CADET_DisconnectEventHandler) (void *cls,
                                        const struct GNUNET_CADET_Channel *channel);


/**
 * Function called whenever an MQ-channel's transmission window size changes.
 *
 * The first callback in an outgoing channel will be with a non-zero value
 * and will mean the channel is connected to the destination.
 *
 * For an incoming channel it will be called immediately after the
 * #GNUNET_CADET_ConnectEventHandler, also with a non-zero value.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end --- FIXME: drop?
 * @param window_size New window size. If the is more messages than buffer size
 *                    this value will be negative. -- FIXME: make unsigned, we never call negative?
 */
typedef void
(*GNUNET_CADET_WindowSizeEventHandler) (void *cls,
                                        const struct GNUNET_CADET_Channel *channel,
                                        int window_size);


/**
 * Connect to the MQ-based cadet service.
 *
 * @param cfg Configuration to use.
 * @return Handle to the cadet service NULL on error.
 */
struct GNUNET_CADET_Handle *
GNUNET_CADET_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the cadet service. All channels will be destroyed. All channel
 * disconnect callbacks will be called on any still connected peers, notifying
 * about their disconnection. The registered inbound channel cleaner will be
 * called should any inbound channels still exist.
 *
 * @param handle connection to cadet to disconnect
 */
void
GNUNET_CADET_disconnect (struct GNUNET_CADET_Handle *handle);


/**
 * Open a port to receive incomming MQ-based channels.
 *
 * @param h CADET handle.
 * @param port Hash identifying the port.
 * @param connects Function called when an incoming channel is connected.
 * @param connects_cls Closure for the @a connects handler.
 * @param window_changes Function called when the transmit window size changes.
 *                       Can be NULL.
 * @param disconnects Function called when a channel is disconnected.
 * @param handlers Callbacks for messages we care about, NULL-terminated.
 * @return Port handle, NULL if port is in use
 */
struct GNUNET_CADET_Port *
GNUNET_CADET_open_port (struct GNUNET_CADET_Handle *h,
                        const struct GNUNET_HashCode *port,
                        GNUNET_CADET_ConnectEventHandler connects,
                        void *connects_cls,
                        GNUNET_CADET_WindowSizeEventHandler window_changes,
                        GNUNET_CADET_DisconnectEventHandler disconnects,
                        const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Close a port opened with @a GNUNET_CADET_open_port.
 * The @a new_channel callback will no longer be called.
 *
 * @param p Port handle.
 */
void
GNUNET_CADET_close_port (struct GNUNET_CADET_Port *p);


/**
 * Create a new channel towards a remote peer.
 *
 * If the destination port is not open by any peer or the destination peer
 * does not accept the channel, @a disconnects will be called
 * for this channel.
 *
 * @param h CADET handle.
 * @param channel_cls Closure for the channel. It's given to:
 *                    - The management handler @a window_changes.
 *                    - The disconnect handler @a disconnects
 *                    - Each message type callback in @a handlers
 * @param destination Peer identity the channel should go to.
 * @param port Identification of the destination port.
 * @param options CadetOption flag field, with all desired option bits set to 1.
 * @param window_changes Function called when the transmit window size changes.
 *                       Can be NULL if this data is of no interest.
 * TODO                  Not yet implemented.
 * @param disconnects Function called when the channel is disconnected.
 * @param handlers Callbacks for messages we care about, NULL-terminated.
 * @return Handle to the channel.
 */
struct GNUNET_CADET_Channel *
GNUNET_CADET_channel_create (struct GNUNET_CADET_Handle *h,
                             void *channel_cls,
                             const struct GNUNET_PeerIdentity *destination,
                             const struct GNUNET_HashCode *port,
                             enum GNUNET_CADET_ChannelOption options,
                             GNUNET_CADET_WindowSizeEventHandler window_changes,
                             GNUNET_CADET_DisconnectEventHandler disconnects,
                             const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Destroy an existing channel.
 *
 * The existing end callback for the channel will be called immediately.
 * Any pending outgoing messages will be sent but no incoming messages will be
 * accepted and no data callbacks will be called.
 *
 * @param channel Channel handle, becomes invalid after this call.
 */
void
GNUNET_CADET_channel_destroy (struct GNUNET_CADET_Channel *channel);


/**
 * Obtain the message queue for a connected channel.
 *
 * @param channel The channel handle from which to get the MQ.
 * @return The message queue of the channel.
 */
struct GNUNET_MQ_Handle *
GNUNET_CADET_get_mq (const struct GNUNET_CADET_Channel *channel);


/**
 * Indicate readiness to receive the next message on a channel.
 *
 * Should only be called once per handler called.
 *
 * @param channel Channel that will be allowed to call another handler.
 */
void
GNUNET_CADET_receive_done (struct GNUNET_CADET_Channel *channel);


/******************************************************************************/
/********************       MONITORING /DEBUG API     *************************/
/******************************************************************************/
/* The following calls are not useful for normal CADET operation, but for      */
/* debug and monitoring of the cadet state. They can be safely ignored.        */
/* The API can change at any point without notice.                            */
/* Please contact the developer if you consider any of this calls useful for  */
/* normal cadet applications.                                                  */
/******************************************************************************/


/**
 * Transitional function to convert an unsigned int port to a hash value.
 * WARNING: local static value returned, NOT reentrant!
 * WARNING: do not use this function for new code!
 *
 * @param port Numerical port (unsigned int format).
 *
 * @return A GNUNET_HashCode usable for the new CADET API.
 */
const struct GNUNET_HashCode *
GC_u2h (uint32_t port);



/**
 * Struct to retrieve info about a channel.
 */
union GNUNET_CADET_ChannelInfo
{

  /**
   * #GNUNET_YES / #GNUNET_NO, for binary flags.
   */
  int yes_no;

  /**
   * Peer on the other side of the channel
   */
  const struct GNUNET_PeerIdentity peer;
};


/**
 * Get information about a channel.
 *
 * @param channel Channel handle.
 * @param option Query type GNUNET_CADET_OPTION_*
 * @param ... dependant on option, currently not used
 * @return Union with an answer to the query.
 */
const union GNUNET_CADET_ChannelInfo *
GNUNET_CADET_channel_get_info (struct GNUNET_CADET_Channel *channel,
                              enum GNUNET_CADET_ChannelOption option,
                               ...);


/**
 * Method called to retrieve information about a specific channel the cadet peer
 * is aware of, including all transit nodes.
 *
 * @param cls Closure.
 * @param root Root of the channel.
 * @param dest Destination of the channel.
 * @param port Destination port of the channel.
 * @param root_channel_number Local number for root, if known.
 * @param dest_channel_number Local number for dest, if known.
 * @param public_channel_numbe Number for P2P, always known.
 */
typedef void
(*GNUNET_CADET_ChannelCB) (void *cls,
                           const struct GNUNET_PeerIdentity *root,
                           const struct GNUNET_PeerIdentity *dest,
                           uint32_t /* UGH */ port,
                           uint32_t /* ugh */ root_channel_number,
                           uint32_t /* ugh */ dest_channel_number,
                           uint32_t /* ugh */ public_channel_number);

/**
 * Method called to retrieve information about all peers in CADET, called
 * once per peer.
 *
 * After last peer has been reported, an additional call with NULL is done.
 *
 * @param cls Closure.
 * @param peer Peer, or NULL on "EOF".
 * @param tunnel Do we have a tunnel towards this peer?
 * @param n_paths Number of known paths towards this peer.
 * @param best_path How long is the best path?
 *                  (0 = unknown, 1 = ourselves, 2 = neighbor)
 */
typedef void
(*GNUNET_CADET_PeersCB) (void *cls,
                         const struct GNUNET_PeerIdentity *peer,
                         int tunnel,
                         unsigned int n_paths,
                         unsigned int best_path);

/**
 * Method called to retrieve information about a specific peer
 * known to the service.
 *
 * @param cls Closure.
 * @param peer Peer ID.
 * @param tunnel Do we have a tunnel towards this peer? #GNUNET_YES/#GNUNET_NO
 * @param neighbor Is this a direct neighbor? #GNUNET_YES/#GNUNET_NO
 * @param n_paths Number of paths known towards peer.
 * @param paths Array of PEER_IDs representing all paths to reach the peer.
 *              Each path starts with the first hop (local peer not included).
 *              Each path ends with the destination peer (given in @c peer).
 */
typedef void
(*GNUNET_CADET_PeerCB) (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        int tunnel,
                        int neighbor,
                        unsigned int n_paths,
                        const struct GNUNET_PeerIdentity *paths);


/**
 * Method called to retrieve information about all tunnels in CADET, called
 * once per tunnel.
 *
 * After last tunnel has been reported, an additional call with NULL is done.
 *
 * @param cls Closure.
 * @param peer Destination peer, or NULL on "EOF".
 * @param channels Number of channels.
 * @param connections Number of connections.
 * @param estate Encryption state.
 * @param cstate Connectivity state.
 */
typedef void
(*GNUNET_CADET_TunnelsCB) (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
                           unsigned int channels,
                           unsigned int connections,
                           uint16_t estate,
                           uint16_t cstate);


/**
 * Method called to retrieve information about a specific tunnel the cadet peer
 * has established, o`r is trying to establish.
 *
 * @param cls Closure.
 * @param peer Peer towards whom the tunnel is directed.
 * @param n_channels Number of channels.
 * @param n_connections Number of connections.
 * @param channels Channels.
 * @param connections Connections.
 * @param estate Encryption state.
 * @param cstate Connectivity state.
 */
typedef void
(*GNUNET_CADET_TunnelCB) (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          unsigned int n_channels,
                          unsigned int n_connections,
                          const struct GNUNET_CADET_ChannelTunnelNumber *channels,
                          const struct GNUNET_CADET_ConnectionTunnelIdentifier *connections,
                          unsigned int estate,
                          unsigned int cstate);


/**
 * Request information about a specific channel of the running cadet peer.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param peer ID of the other end of the channel.
 * @param channel_number Channel number.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_CADET_get_channel (struct GNUNET_CADET_Handle *h,
                          struct GNUNET_PeerIdentity *peer,
                          uint32_t /* UGH */ channel_number,
                          GNUNET_CADET_ChannelCB callback,
                          void *callback_cls);


/**
 * Request a debug dump on the service's STDERR.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h cadet handle
 */
void
GNUNET_CADET_request_dump (struct GNUNET_CADET_Handle *h);


/**
 * Request information about peers known to the running cadet service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_peers (struct GNUNET_CADET_Handle *h,
                        GNUNET_CADET_PeersCB callback,
                        void *callback_cls);


/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Cadet handle.
 *
 * @return Closure that was given to #GNUNET_CADET_get_peers().
 */
void *
GNUNET_CADET_get_peers_cancel (struct GNUNET_CADET_Handle *h);


/**
 * Request information about a peer known to the running cadet peer.
 * The callback will be called for the tunnel once.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_peer (struct GNUNET_CADET_Handle *h,
                      const struct GNUNET_PeerIdentity *id,
                      GNUNET_CADET_PeerCB callback,
                      void *callback_cls);


/**
 * Request information about tunnels of the running cadet peer.
 * The callback will be called for every tunnel of the service.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_tunnels (struct GNUNET_CADET_Handle *h,
                          GNUNET_CADET_TunnelsCB callback,
                          void *callback_cls);


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param h Cadet handle.
 *
 * @return Closure given to #GNUNET_CADET_get_tunnels(), if any.
 */
void *
GNUNET_CADET_get_tunnels_cancel (struct GNUNET_CADET_Handle *h);


/**
 * Request information about a tunnel of the running cadet peer.
 * The callback will be called for the tunnel once.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_tunnel (struct GNUNET_CADET_Handle *h,
                         const struct GNUNET_PeerIdentity *id,
                         GNUNET_CADET_TunnelCB callback,
                         void *callback_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_cadet_service.h */
