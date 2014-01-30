/*
     This file is part of GNUnet.
     (C) 2009 - 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_mesh_service.h
 * @brief mesh service; establish channels to distant peers
 * @author Christian Grothoff
 */

#ifndef GNUNET_MESH_SERVICE_H
#define GNUNET_MESH_SERVICE_H

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
 * Version number of GNUnet-mesh API.
 */
#define GNUNET_MESH_VERSION 0x00000003


/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle;

/**
 * Opaque handle to a channel.
 */
struct GNUNET_MESH_Channel;


/**
 * Channel options.
 * Second line indicates filed in the MeshChannelInfo union carrying the answer.
 */
enum GNUNET_MESH_ChannelOption
{
  /**
   * Default options: unreliable, default buffering, not out of order.
   */
  GNUNET_MESH_OPTION_DEFAULT    = 0x0,

  /**
   * Disable buffering on intermediate nodes (for minimum latency).
   * Yes/No.
   */
  GNUNET_MESH_OPTION_NOBUFFER   = 0x1,

  /**
   * Enable channel reliability, lost messages will be retransmitted.
   * Yes/No.
   */
  GNUNET_MESH_OPTION_RELIABLE   = 0x2,

  /**
   * Enable out of order delivery of messages.
   * Yes/No.
   */
  GNUNET_MESH_OPTION_OOORDER    = 0x4,

  /**
   * Who is the peer at the other end of the channel.
   * Only for use in @c GNUNET_MESH_channel_get_info
   * struct GNUNET_PeerIdentity *peer
   */
  GNUNET_MESH_OPTION_PEER       = 0x8

};


/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * Each time the function must call #GNUNET_MESH_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_MESH_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
typedef int (*GNUNET_MESH_MessageCallback) (void *cls,
                                            struct GNUNET_MESH_Channel *channel,
                                            void **channel_ctx,
                                            const struct GNUNET_MessageHeader *message);


/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_MESH_MessageHandler
{
  /**
   * Function to call for messages of "type".
   */
  GNUNET_MESH_MessageCallback callback;

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
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_MESH_connect.
 *
 * A call to #GNUNET_MESH_channel_destroy causes te channel to be ignored. In
 * this case the handler MUST return NULL.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port Port this channel is for.
 * @param options MeshOption flag field, with all active option bits set to 1.
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
typedef void *(GNUNET_MESH_InboundChannelNotificationHandler) (void *cls,
                                                               struct
                                                               GNUNET_MESH_Channel
                                                               * channel,
                                                               const struct
                                                               GNUNET_PeerIdentity
                                                               * initiator,
                                                               uint32_t port,
                                                               enum GNUNET_MESH_ChannelOption
                                                               options);


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_MESH_channel_destroy on the channel.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
typedef void (GNUNET_MESH_ChannelEndHandler) (void *cls,
                                              const struct GNUNET_MESH_Channel *
                                              channel,
                                              void *channel_ctx);


/**
 * Connect to the mesh service.
 *
 * @param cfg Configuration to use.
 * @param cls Closure for the various callbacks that follow (including
 *            handlers in the handlers array).
 * @param new_channel Function called when an *incoming* channel is created.
 *                    Can be NULL if no inbound channels are desired.
 *                    See @a ports.
 * @param cleaner Function called when a channel is destroyed by the remote peer.
 *                It is NOT called if #GNUNET_MESH_channel_destroy is called on
 *                the channel.
 * @param handlers Callbacks for messages we care about, NULL-terminated. Each
 *                 one must call #GNUNET_MESH_receive_done on the channel to
 *                 receive the next message.  Messages of a type that is not
 *                 in the handlers array are ignored if received.
 * @param ports NULL or 0-terminated array of port numbers for incoming channels.
 *              See @a new_channel.
 *
 * @return handle to the mesh service NULL on error
 *         (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, void *cls,
                     GNUNET_MESH_InboundChannelNotificationHandler new_channel,
                     GNUNET_MESH_ChannelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const uint32_t *ports);


/**
 * Disconnect from the mesh service. All channels will be destroyed. All channel
 * disconnect callbacks will be called on any still connected peers, notifying
 * about their disconnection. The registered inbound channel cleaner will be
 * called should any inbound channels still exist.
 *
 * @param handle connection to mesh to disconnect
 */
void
GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle);


/**
 * Create a new channel towards a remote peer.
 *
 * If the destination port is not open by any peer or the destination peer
 * does not accept the channel, #GNUNET_MESH_ChannelEndHandler will be called
 * for this channel.
 *
 * @param h mesh handle
 * @param channel_ctx client's channel context to associate with the channel
 * @param peer peer identity the channel should go to
 * @param port Port number.
 * @param options MeshOption flag field, with all desired option bits set to 1.
 *
 * @return handle to the channel
 */
struct GNUNET_MESH_Channel *
GNUNET_MESH_channel_create (struct GNUNET_MESH_Handle *h,
                            void *channel_ctx,
                            const struct GNUNET_PeerIdentity *peer,
                            uint32_t port,
                            enum GNUNET_MESH_ChannelOption options);


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
GNUNET_MESH_channel_destroy (struct GNUNET_MESH_Channel *channel);


/**
 * Struct to retrieve info about a channel.
 */
union GNUNET_MESH_ChannelInfo
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
 * @param option Query type GNUNET_MESH_OPTION_*
 * @param ... dependant on option, currently not used
 * @return Union with an answer to the query.
 */
const union GNUNET_MESH_ChannelInfo *
GNUNET_MESH_channel_get_info (struct GNUNET_MESH_Channel *channel,
                              enum GNUNET_MESH_ChannelOption option, ...);


/**
 * Handle for a transmission request.
 */
struct GNUNET_MESH_TransmitHandle;


/**
 * Ask the mesh to call @a notify once it is ready to transmit the
 * given number of bytes to the specified channel.
 * Only one call can be active at any time, to issue another request,
 * wait for the callback or cancel the current request.
 *
 * @param channel channel to use for transmission
 * @param cork is corking allowed for this transmission?
 * @param maxdelay how long can the message wait?
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout or if the overall queue
 *        for this peer is larger than queue_size and this is currently
 *        the message with the lowest priority
 * @param notify_cls closure for @a notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, @a notify will NOT be called.
 */
struct GNUNET_MESH_TransmitHandle *
GNUNET_MESH_notify_transmit_ready (struct GNUNET_MESH_Channel *channel,
                                   int cork,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle
                                          *th);


/**
 * Indicate readiness to receive the next message on a channel.
 *
 * Should only be called once per handler called.
 *
 * @param channel Channel that will be allowed to call another handler.
 */
void
GNUNET_MESH_receive_done (struct GNUNET_MESH_Channel *channel);



/******************************************************************************/
/********************       MONITORING /DEBUG API     *************************/
/******************************************************************************/
/* The following calls are not useful for normal MESH operation, but for      */
/* debug and monitoring of the mesh state. They can be safely ignored.        */
/* The API can change at any point without notice.                            */
/* Please contact the developer if you consider any of this calls useful for  */
/* normal mesh applications.                                                  */
/******************************************************************************/


/**
 * Method called to retrieve information about a specific channel the mesh peer
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
typedef void (*GNUNET_MESH_ChannelCB) (void *cls,
                                       const struct GNUNET_PeerIdentity *root,
                                       const struct GNUNET_PeerIdentity *dest,
                                       uint32_t port,
                                       uint32_t root_channel_number,
                                       uint32_t dest_channel_number,
                                       uint32_t public_channel_number);

/**
 * Method called to retrieve information about all peers in MESH, called
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
typedef void (*GNUNET_MESH_PeersCB) (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     int tunnel, unsigned int n_paths,
                                     unsigned int best_path);


/**
 * Method called to retrieve information about all tunnels in MESH, called
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
typedef void (*GNUNET_MESH_TunnelsCB) (void *cls,
                                       const struct GNUNET_PeerIdentity *peer,
                                       unsigned int channels,
                                       unsigned int connections,
                                       uint16_t estate,
                                       uint16_t cstate);



/**
 * Method called to retrieve information about a specific tunnel the mesh peer
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
typedef void (*GNUNET_MESH_TunnelCB) (void *cls,
                                      const struct GNUNET_PeerIdentity *peer,
                                      unsigned int n_channels,
                                      unsigned int n_connections,
                                      uint32_t *channels,
                                      struct GNUNET_HashCode *connections,
                                      unsigned int estate,
                                      unsigned int cstate);

/**
 * Request information about a specific channel of the running mesh peer.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param peer ID of the other end of the channel.
 * @param channel_number Channel number.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_channel (struct GNUNET_MESH_Handle *h,
                         struct GNUNET_PeerIdentity *peer,
                         uint32_t channel_number,
                         GNUNET_MESH_ChannelCB callback,
                         void *callback_cls);


/**
 * Request information about peers known to the running mesh service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_MESH_get_peers (struct GNUNET_MESH_Handle *h,
                       GNUNET_MESH_PeersCB callback,
                       void *callback_cls);

/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Mesh handle.
 *
 * @return Closure given to GNUNET_MESH_get_peers.
 */
void *
GNUNET_MESH_get_peers_cancel (struct GNUNET_MESH_Handle *h);

/**
 * Request information about tunnels of the running mesh peer.
 * The callback will be called for every tunnel of the service.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_MESH_get_tunnels (struct GNUNET_MESH_Handle *h,
                         GNUNET_MESH_TunnelsCB callback,
                         void *callback_cls);

/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param h Mesh handle.
 *
 * @return Closure given to GNUNET_MESH_monitor, if any.
 */
void *
GNUNET_MESH_get_tunnels_cancel (struct GNUNET_MESH_Handle *h);


/**
 * Request information about a tunnel of the running mesh peer.
 * The callback will be called for the tunnel once.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 *
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_MESH_get_tunnel (struct GNUNET_MESH_Handle *h,
                        const struct GNUNET_PeerIdentity *id,
                        GNUNET_MESH_TunnelCB callback,
                        void *callback_cls);

/**
 * Create a message queue for a mesh channel.
 * The message queue can only be used to transmit messages,
 * not to receive them.
 *
 * @param channel the channel to create the message qeue for
 * @return a message queue to messages over the channel
 */
struct GNUNET_MQ_Handle *
GNUNET_MESH_mq_create (struct GNUNET_MESH_Channel *channel);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_H */
#endif
/* end of gnunet_mesh_service.h */
