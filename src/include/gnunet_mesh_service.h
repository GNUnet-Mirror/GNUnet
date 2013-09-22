/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @brief mesh service; establish tunnels to distant peers
 * @author Christian Grothoff
 *
 * TODO:
 * - need to do sanity check that this is consistent
 *   with current ideas for the multicast layer's needs
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
#define GNUNET_MESH_VERSION 0x00000002


/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle;

/**
 * Opaque handle to a tunnel.
 */
struct GNUNET_MESH_Tunnel;


/**
 * Options for querying a tunnel.
 * Second line indicates filed in the MeshTunnelInfo union carrying the answer.
 */
enum MeshTunnelOption
{
  /**
   * Disable buffering on intermediate nodes (for minimum latency).
   * Yes/No.
   */
  GNUNET_MESH_OPTION_NOBUFFER   = 0x1,

  /**
   * Enable tunnel reliability, lost messages will be retransmitted.
   * Yes/No.
   */
  GNUNET_MESH_OPTION_RELIABLE   = 0x2,

  /**
   * Enable out of order delivery of messages.
   * Yes/No.
   */
  GNUNET_MESH_OPTION_OOORDER    = 0x4,

  /**
   * Who is the peer at the other end of the tunnel.
   * struct GNUNET_PeerIdentity *peer
   */
  GNUNET_MESH_OPTION_PEER       = 0x8

};


/**
 * Functions with this signature are called whenever a message is
 * received.
 * 
 * Each time the function must call #GNUNET_MESH_receive_done on the tunnel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_MESH_connect).
 * @param tunnel Connection to the other end.
 * @param tunnel_ctx Place to store local state associated with the tunnel.
 * @param message The actual message.
 * 
 * @return #GNUNET_OK to keep the tunnel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
typedef int (*GNUNET_MESH_MessageCallback) (void *cls,
                                            struct GNUNET_MESH_Tunnel *tunnel,
                                            void **tunnel_ctx,
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
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_MESH_connect. A call to #GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param port Port this tunnel is for.
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
typedef void *(GNUNET_MESH_InboundTunnelNotificationHandler) (void *cls,
                                                              struct GNUNET_MESH_Tunnel *tunnel,
                                                              const struct
                                                              GNUNET_PeerIdentity
                                                              * initiator,
                                                              uint32_t port);


/**
 * Function called whenever a tunnel is destroyed.  Should clean up
 * any associated state. 
 * 
 * It must NOT call #GNUNET_MESH_tunnel_destroy on the tunnel.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
typedef void (GNUNET_MESH_TunnelEndHandler) (void *cls,
                                             const struct GNUNET_MESH_Tunnel *
                                             tunnel, void *tunnel_ctx);


/**
 * Connect to the mesh service.
 *
 * @param cfg Configuration to use.
 * @param cls Closure for the various callbacks that follow (including 
 *            handlers in the handlers array).
 * @param new_tunnel Function called when an *incoming* tunnel is created.
 *                   Can be NULL if no inbound tunnels are desired.
 *                   See @c ports.
 * @param cleaner Function called when a tunnel is destroyed by the remote peer.
 *                It is NOT called if #GNUNET_MESH_tunnel_destroy is called on
 *                the tunnel.
 * @param handlers Callbacks for messages we care about, NULL-terminated. Each
 *                 one must call #GNUNET_MESH_receive_done on the tunnel to
 *                 receive the next message.  Messages of a type that is not
 *                 in the handlers array are ignored if received. 
 * @param ports NULL or 0-terminated array of port numbers for incoming tunnels.
 *              See @c new_tunnel.
 * 
 * @return handle to the mesh service NULL on error
 *         (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, 
		     void *cls,
                     GNUNET_MESH_InboundTunnelNotificationHandler new_tunnel,
                     GNUNET_MESH_TunnelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const uint32_t *ports);


/**
 * Disconnect from the mesh service. All tunnels will be destroyed. All tunnel
 * disconnect callbacks will be called on any still connected peers, notifying
 * about their disconnection. The registered inbound tunnel cleaner will be
 * called should any inbound tunnels still exist.
 *
 * @param handle connection to mesh to disconnect
 */
void
GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle);


/**
 * Create a new tunnel (we're initiator and will be allowed to add/remove peers
 * and to broadcast).
 *
 * @param h mesh handle
 * @param tunnel_ctx client's tunnel context to associate with the tunnel
 * @param peer peer identity the tunnel should go to
 * @param port Port number.
 * @param nobuffer Flag for disabling buffering on relay nodes.
 * @param reliable Flag for end-to-end reliability.
 * @return handle to the tunnel
 */
struct GNUNET_MESH_Tunnel *
GNUNET_MESH_tunnel_create (struct GNUNET_MESH_Handle *h, 
                           void *tunnel_ctx,
                           const struct GNUNET_PeerIdentity *peer,
                           uint32_t port,
                           int nobuffer,
                           int reliable);


/**
 * Destroy an existing tunnel.
 * 
 * The existing end callback for the tunnel will be called immediately.
 * Any pending outgoing messages will be sent but no incoming messages will be
 * accepted and no data callbacks will be called.
 *
 * @param tunnel Tunnel handle, becomes invalid after this call.
 */
void
GNUNET_MESH_tunnel_destroy (struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Struct to retrieve info about a tunnel.
 */
union GNUNET_MESH_TunnelInfo 
{

  /**
   * #GNUNET_YES / #GNUNET_NO, for binary flags.
   */
  int yes_no;

  /**
   * Peer on the other side of the tunnel
   */
  const struct GNUNET_PeerIdentity *peer;
};


/**
 * Get information about a tunnel.
 *
 * @param tunnel Tunnel handle.
 * @param option Query, as listed in src/mesh/mesh.h (GNUNET_MESH_OPTION_*)
 * @param ... dependant on option, currently not used
 *
 * @return Union with an answer to the query.
 */
const union GNUNET_MESH_TunnelInfo *
GNUNET_MESH_tunnel_get_info (struct GNUNET_MESH_Tunnel *tunnel,
                             enum MeshTunnelOption option, ...);


/**
 * Handle for a transmission request.
 */
struct GNUNET_MESH_TransmitHandle;


/**
 * Ask the mesh to call @a notify once it is ready to transmit the
 * given number of bytes to the specified tunnel.
 * Only one call can be active at any time, to issue another request,
 * wait for the callback or cancel the current request.
 *
 * @param tunnel tunnel to use for transmission
 * @param cork is corking allowed for this transmission?
 * @param maxdelay how long can the message wait?
 * @param notify_size how many bytes of buffer space does @a notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout or if the overall queue
 *        for this peer is larger than queue_size and this is currently
 *        the message with the lowest priority
 * @param notify_cls closure for @a notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_MESH_TransmitHandle *
GNUNET_MESH_notify_transmit_ready (struct GNUNET_MESH_Tunnel *tunnel, int cork,
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
 * Indicate readiness to receive the next message on a tunnel.
 * 
 * Should only be called once per handler called.
 *
 * @param tunnel Tunnel that will be allowed to call another handler.
 */
void
GNUNET_MESH_receive_done (struct GNUNET_MESH_Tunnel *tunnel);



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
 * Method called to retrieve information about each tunnel the mesh peer
 * is aware of.
 *
 * @param cls Closure.
 * @param tunnel_number Tunnel number.
 * @param origin that started the tunnel (owner).
 * @param target other endpoint of the tunnel
 */
typedef void (*GNUNET_MESH_TunnelsCB) (void *cls,
                                       uint32_t tunnel_number,
                                       const struct GNUNET_PeerIdentity *origin,
                                       const struct GNUNET_PeerIdentity *target);


/**
 * Method called to retrieve information about a specific tunnel the mesh peer
 * is aware of, including all transit nodes.
 *
 * @param cls Closure.
 * @param peer Peer in the tunnel's tree.
 * @param parent Parent of the current peer. All 0 when peer is root.
 */
typedef void (*GNUNET_MESH_TunnelCB) (void *cls,
                                      const struct GNUNET_PeerIdentity *peer,
                                      const struct GNUNET_PeerIdentity *parent);


/**
 * Request information about the running mesh peer.
 * The callback will be called for every tunnel known to the service,
 * listing all active peers that belong to the tunnel.
 *
 * If called again on the same handle, it will overwrite the previous
 * callback and cls. To retrieve the cls, monitor_cancel must be
 * called first.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_tunnels (struct GNUNET_MESH_Handle *h,
                         GNUNET_MESH_TunnelsCB callback,
                         void *callback_cls);


/**
 * Request information about a specific tunnel of the running mesh peer.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param initiator ID of the owner of the tunnel.
 * @param tunnel_number Tunnel number.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @a callback.
 */
void
GNUNET_MESH_show_tunnel (struct GNUNET_MESH_Handle *h,
                         struct GNUNET_PeerIdentity *initiator,
                         uint32_t tunnel_number,
                         GNUNET_MESH_TunnelCB callback,
                         void *callback_cls);


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Mesh handle.
 *
 * @return Closure given to GNUNET_MESH_monitor, if any.
 */
void *
GNUNET_MESH_get_tunnels_cancel (struct GNUNET_MESH_Handle *h);


/**
 * Create a message queue for a mesh tunnel.
 * The message queue can only be used to transmit messages,
 * not to receive them.
 *
 * @param tunnel the tunnel to create the message qeue for
 * @return a message queue to messages over the tunnel
 */
struct GNUNET_MQ_Handle *
GNUNET_MESH_mq_create (struct GNUNET_MESH_Tunnel *tunnel);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_H */
#endif
/* end of gnunet_mesh_service.h */
