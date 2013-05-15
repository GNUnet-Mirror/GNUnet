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
 * @file include/gnunet_mesh_service.h
 * @brief mesh service; establish tunnels to distant peers
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
#define GNUNET_MESH_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle;

/**
 * Opaque handle to a tunnel.
 */
struct GNUNET_MESH_Tunnel;

/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
typedef int (*GNUNET_MESH_MessageCallback) (void *cls,
                                            struct GNUNET_MESH_Tunnel * tunnel,
                                            void **tunnel_ctx,
                                            const struct GNUNET_PeerIdentity *
                                            sender,
                                            const struct GNUNET_MessageHeader *
                                            message,
                                            const struct GNUNET_ATS_Information
                                            * atsi);


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
 * subscribed to in GNUNET_MESH_connect. A call to GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
typedef void *(GNUNET_MESH_InboundTunnelNotificationHandler) (void *cls,
                                                              struct
                                                              GNUNET_MESH_Tunnel
                                                              * tunnel,
                                                              const struct
                                                              GNUNET_PeerIdentity
                                                              * initiator,
                                                              const struct
                                                              GNUNET_ATS_Information
                                                              * atsi);


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
typedef void (GNUNET_MESH_TunnelEndHandler) (void *cls,
                                             const struct GNUNET_MESH_Tunnel *
                                             tunnel, void *tunnel_ctx);


/**
 * Type for an application.  Values defined in gnunet_applications.h
 * DEPRECATED - not present in mesh2
 */
typedef uint32_t GNUNET_MESH_ApplicationType;


/**
 * Connect to the mesh service.
 *
 * @param cfg configuration to use
 * @param cls closure for the various callbacks that follow
 *            (including handlers in the handlers array)
 * @param new_tunnel function called when an *inbound* tunnel is created
 * @param cleaner function called when an *inbound* tunnel is destroyed by the
 *                remote peer, it is *not* called if GNUNET_MESH_tunnel_destroy
 *                is called on the tunnel
 * @param handlers callbacks for messages we care about, NULL-terminated
 *                note that the mesh is allowed to drop notifications about
 *                inbound messages if the client does not process them fast
 *                enough (for this notification type, a bounded queue is used)
 * @param stypes list of the applications that this client claims to provide
 * @return handle to the mesh service NULL on error
 *         (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, void *cls,
                     GNUNET_MESH_InboundTunnelNotificationHandler new_tunnel,
                     GNUNET_MESH_TunnelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const GNUNET_MESH_ApplicationType *stypes);


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
 * Method called whenever a peer has disconnected from the tunnel.
 * Implementations of this callback must NOT call
 * GNUNET_MESH_tunnel_destroy immediately, but instead schedule those
 * to run in some other task later.  However, calling 
 * "GNUNET_MESH_notify_transmit_ready_cancel" is allowed.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
typedef void (*GNUNET_MESH_PeerDisconnectHandler) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * peer);


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 *
 * TODO: change to return int to let client allow the new peer or not?
 */
typedef void (*GNUNET_MESH_PeerConnectHandler) (void *cls,
                                                const struct GNUNET_PeerIdentity
                                                * peer,
                                                const struct
                                                GNUNET_ATS_Information * atsi);


/**
 * Announce to ther peer the availability of services described by the regex,
 * in order to be reachable to other peers via connect_by_string.
 * 
 * Note that the first GNUNET_REGEX_INITIAL_BYTES characters are considered
 * to be part of a prefix, (for instance 'gnunet://').
 * If you put a variable part in there (*, +. ()), all matching strings
 * will be stored in the DHT.
 *
 * @param h Handle to mesh.
 * @param regex String with the regular expression describing local services.
 * @param compression_characters How many characters can be assigned to one
 *                               edge of the graph. The bigger the variability
 *                               of the data, the smaller this parameter should
 *                               be (down to 1).
 *                               For maximum compression, use strlen (regex)
 *                               or 0 (special value). Use with care!
 */
void
GNUNET_MESH_announce_regex (struct GNUNET_MESH_Handle *h,
                            const char *regex,
                            unsigned int compression_characters);


/**
 * Create a new tunnel (we're initiator and will be allowed to add/remove peers
 * and to broadcast).
 *
 * @param h mesh handle
 * @param tunnel_ctx client's tunnel context to associate with the tunnel
 * @param connect_handler function to call when peers are actually connected
 * @param disconnect_handler function to call when peers are disconnected
 * @param handler_cls closure for connect/disconnect handlers
 */
struct GNUNET_MESH_Tunnel *
GNUNET_MESH_tunnel_create (struct GNUNET_MESH_Handle *h, void *tunnel_ctx,
                           GNUNET_MESH_PeerConnectHandler connect_handler,
                           GNUNET_MESH_PeerDisconnectHandler disconnect_handler,
                           void *handler_cls);

/**
 * Destroy an existing tunnel. The existing callback for the tunnel will NOT
 * be called.
 *
 * @param tunnel tunnel handle
 */
void
GNUNET_MESH_tunnel_destroy (struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Request that the tunnel data rate is limited to the speed of the slowest
 * receiver.
 * 
 * @param tunnel Tunnel affected.
 */
void
GNUNET_MESH_tunnel_speed_min (struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Request that the tunnel data rate is limited to the speed of the fastest
 * receiver. This is the default behavior.
 * 
 * @param tunnel Tunnel affected.
 */
void
GNUNET_MESH_tunnel_speed_max (struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Turn on/off the buffering status of the tunnel.
 * 
 * @param tunnel Tunnel affected.
 * @param buffer GNUNET_YES to turn buffering on (default),
 *               GNUNET_NO otherwise.
 */
void
GNUNET_MESH_tunnel_buffer (struct GNUNET_MESH_Tunnel *tunnel, int buffer);


/**
 * Request that a peer should be added to the tunnel.  The connect handler
 * will be called when the peer connects
 *
 * @param tunnel handle to existing tunnel
 * @param peer peer to add
 */
void
GNUNET_MESH_peer_request_connect_add (struct GNUNET_MESH_Tunnel *tunnel,
                                      const struct GNUNET_PeerIdentity *peer);


/**
 * Request that a peer should be removed from the tunnel.  The existing
 * disconnect handler will be called ONCE if we were connected.
 *
 * @param tunnel handle to existing tunnel
 * @param peer peer to remove
 */
void
GNUNET_MESH_peer_request_connect_del (struct GNUNET_MESH_Tunnel *tunnel,
                                      const struct GNUNET_PeerIdentity *peer);


/**
 * Request that the mesh should try to connect to a peer supporting the given
 * message type.
 *
 * @param tunnel handle to existing tunnel
 * @param app_type application type that must be supported by the peer
 *                 (MESH should discover peer in proximity handling this type)
 */
void
GNUNET_MESH_peer_request_connect_by_type (struct GNUNET_MESH_Tunnel *tunnel,
                                          GNUNET_MESH_ApplicationType app_type);


/**
 * Request that the mesh should try to connect to a peer matching the
 * description given in the service string.
 *
 * @param tunnel handle to existing tunnel
 * @param description string describing the destination node requirements
 */
void
GNUNET_MESH_peer_request_connect_by_string (struct GNUNET_MESH_Tunnel *tunnel,
                                            const char *description);


/**
 * Request that the given peer isn't added to this tunnel in calls to
 * connect_by_* calls, (due to misbehaviour, bad performance, ...).
 *
 * @param tunnel handle to existing tunnel.
 * @param peer peer identity of the peer which should be blacklisted
 *                  for the tunnel.
 */
void
GNUNET_MESH_peer_blacklist (struct GNUNET_MESH_Tunnel *tunnel,
                            const struct GNUNET_PeerIdentity *peer);


/**
 * Request that the given peer isn't blacklisted anymore from this tunnel,
 * and therefore can be added in future calls to connect_by_*.
 * The peer must have been previously blacklisted for this tunnel.
 *
 * @param tunnel handle to existing tunnel.
 * @param peer peer identity of the peer which shouldn't be blacklisted
 *                  for the tunnel anymore.
 */
void
GNUNET_MESH_peer_unblacklist (struct GNUNET_MESH_Tunnel *tunnel,
                              const struct GNUNET_PeerIdentity *peer);


/**
 * Handle for a transmission request.
 */
struct GNUNET_MESH_TransmitHandle;


/**
 * Ask the mesh to call "notify" once it is ready to transmit the
 * given number of bytes to the specified tunnel or target.
 * Only one call can be active at any time, to issue another request,
 * wait for the callback or cancel the current request.
 *
 * @param tunnel tunnel to use for transmission
 * @param cork is corking allowed for this transmission?
 * @param maxdelay how long can the message wait?
 * @param target destination for the message
 *               NULL for multicast to all tunnel targets
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
struct GNUNET_MESH_TransmitHandle *
GNUNET_MESH_notify_transmit_ready (struct GNUNET_MESH_Tunnel *tunnel, int cork,
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
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle
                                          *th);


/**
 * Method called to retrieve information about each tunnel the mesh peer
 * is aware of.
 *
 * @param cls Closure.
 * @param initiator Peer that started the tunnel (owner).
 * @param tunnel_number Tunnel number.
 * @param peers Array of peer identities that participate in the tunnel.
 * @param npeers Number of peers in peers.
 */
typedef void (*GNUNET_MESH_TunnelsCB) (void *cls,
                                       const struct GNUNET_PeerIdentity *owner,
                                       unsigned int tunnel_number,
                                       const struct GNUNET_PeerIdentity *peers,
                                       unsigned int npeers);


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
 * listing all active peers that blong to the tunnel.
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
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_show_tunnel (struct GNUNET_MESH_Handle *h,
                         struct GNUNET_PeerIdentity *initiator,
                         unsigned int tunnel_number,
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
 * Transition API for tunnel ctx management
 * 
 * FIXME deprecated
 */
void
GNUNET_MESH_tunnel_set_data (struct GNUNET_MESH_Tunnel *tunnel, void *data);

/**
 * Transition API for tunnel ctx management
 * 
 * FIXME deprecated
 */
void *
GNUNET_MESH_tunnel_get_data (struct GNUNET_MESH_Tunnel *tunnel);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_H */
#endif
/* end of gnunet_mesh_service.h */
