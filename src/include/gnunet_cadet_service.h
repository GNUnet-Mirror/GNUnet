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

     SPDX-License-Identifier: AGPL3.0-or-later
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
   * identity as compared using #GNUNET_memcmp().
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
 * Function called whenever an MQ-channel is destroyed, unless the destruction
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
 * The existing end callback for the channel will NOT be called.
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
 * Union to retrieve info about a channel.
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
 * Internal details about a channel.
 */
struct GNUNET_CADET_ChannelInternals
{
  /**
   * Root of the channel
   */
  struct GNUNET_PeerIdentity root;

  /**
   * Destination of the channel
   */
  struct GNUNET_PeerIdentity dest;

  // to be expanded!
};


/**
 * Method called to retrieve information about a specific channel the cadet peer
 * is aware of, including all transit nodes.
 *
 * @param cls Closure.
 * @param info internal details, NULL for end of list
 */
typedef void
(*GNUNET_CADET_ChannelCB) (void *cls,
                           const struct GNUNET_CADET_ChannelInternals *info);


/**
 * Operation handle.
 */
struct GNUNET_CADET_ChannelMonitor;


/**
 * Request information about channels to @a peer from the local peer.
 *
 * @param cfg configuration to use
 * @param peer ID of the other end of the channel.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
struct GNUNET_CADET_ChannelMonitor *
GNUNET_CADET_get_channel (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_PeerIdentity *peer,
                          GNUNET_CADET_ChannelCB callback,
                          void *callback_cls);


/**
 * Cancel a channel monitor request. The callback will not be called (anymore).
 *
 * @param h Cadet handle.
 * @return Closure that was given to #GNUNET_CADET_get_channel().
 */
void *
GNUNET_CADET_get_channel_cancel (struct GNUNET_CADET_ChannelMonitor *cm);


/**
 * Information we return per peer.
 */
struct GNUNET_CADET_PeerListEntry
{
  /**
   * Which peer is the information about?
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Do we have a tunnel to this peer?
   */
  int have_tunnel;

  /**
   * Number of disjoint known paths to @e peer.
   */
  unsigned int n_paths;

  /**
   * Length of the shortest path (0 = unknown, 1 = ourselves, 2 = direct neighbour).
   */
  unsigned int best_path_length;
};


/**
 * Method called to retrieve information about all peers in CADET, called
 * once per peer.
 *
 * After last peer has been reported, an additional call with NULL is done.
 *
 * @param cls Closure.
 * @param ple information about a peer, or NULL on "EOF".
 */
typedef void
(*GNUNET_CADET_PeersCB) (void *cls,
			 const struct GNUNET_CADET_PeerListEntry *ple);


/**
 * Operation handle.
 */
struct GNUNET_CADET_PeersLister;


/**
 * Request information about peers known to the running cadet service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 * @param cfg configuration to use
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_PeersLister *
GNUNET_CADET_list_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 GNUNET_CADET_PeersCB callback,
			 void *callback_cls);


/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * @param pl operation handle
 * @return Closure that was given to #GNUNET_CADET_list_peers().
 */
void *
GNUNET_CADET_list_peers_cancel (struct GNUNET_CADET_PeersLister *pl);


/**
 * Detailed information we return per peer.
 */
struct GNUNET_CADET_PeerPathDetail
{
  /**
   * Peer this is about.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Offset of the target peer on the @e path.
   */
  unsigned int target_offset;

  /**
   * Number of entries on the @e path.
   */
  unsigned int path_length;

  /**
   * Array of PEER_IDs representing all paths to reach the peer.  Each
   * path starts with the first hop (local peer not included).  Each
   * path ends with the destination peer (given in @e peer).
   */
  const struct GNUNET_PeerIdentity *path;

};


/**
 * Method called to retrieve information about a specific path
 * known to the service.
 *
 * @param cls Closure.
 * @param ppd details about a path to the peer, NULL for end of information
 */
typedef void
(*GNUNET_CADET_PathCB) (void *cls,
			const struct GNUNET_CADET_PeerPathDetail *ppd);


/**
 * Handle to cancel #GNUNET_CADET_get_path() operation.
 */
struct GNUNET_CADET_GetPath;


/**
 * Request information about a peer known to the running cadet peer.
 *
 * @param cfg configuration to use
 * @param id Peer whose paths we want to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_GetPath *
GNUNET_CADET_get_path (const struct GNUNET_CONFIGURATION_Handle *cfg,
		       const struct GNUNET_PeerIdentity *id,
		       GNUNET_CADET_PathCB callback,
		       void *callback_cls);


/**
 * Cancel @a gp operation.
 *
 * @param gp operation to cancel
 * @return closure from #GNUNET_CADET_get_path().
 */
void *
GNUNET_CADET_get_path_cancel (struct GNUNET_CADET_GetPath *gp);


/**
 * Details about a tunnel managed by CADET.
 */
struct GNUNET_CADET_TunnelDetails
{
  /**
   * Target of the tunnel.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How many channels use the tunnel.
   */
  uint32_t channels;

  /**
   * How many connections support the tunnel.
   */
  uint32_t connections;

  /**
   * What is our encryption state?
   */
  uint16_t estate;

  /**
   * What is our connectivity state?
   */
  uint16_t cstate;
};


/**
 * Method called to retrieve information about all tunnels in CADET, called
 * once per tunnel.
 *
 * After last tunnel has been reported, an additional call with NULL is done.
 *
 * @param cls Closure.
 * @param td tunnel details, NULL for end of list
 */
typedef void
(*GNUNET_CADET_TunnelsCB) (void *cls,
			   const struct GNUNET_CADET_TunnelDetails *td);


/**
 * Operation handle.
 */
struct GNUNET_CADET_ListTunnels;


/**
 * Request information about tunnels of the running cadet peer.
 * The callback will be called for every tunnel of the service.
 * Only one info request (of any kind) can be active at once.
 *
 * @param cfg configuration to use
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_ListTunnels *
GNUNET_CADET_list_tunnels (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   GNUNET_CADET_TunnelsCB callback,
			   void *callback_cls);


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param lt operation handle
 * @return Closure given to #GNUNET_CADET_list_tunnels(), if any.
 */
void *
GNUNET_CADET_list_tunnels_cancel (struct GNUNET_CADET_ListTunnels *lt);


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
