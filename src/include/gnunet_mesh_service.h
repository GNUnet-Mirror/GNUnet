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
 * received or transmitted.
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
typedef int
    (*GNUNET_MESH_MessageCallback) (void *cls,
                                    struct GNUNET_MESH_Tunnel * tunnel,
                                    void **tunnel_ctx,
                                    const struct GNUNET_PeerIdentity * sender,
                                    const struct GNUNET_MessageHeader * message,
                                    const struct
                                    GNUNET_TRANSPORT_ATS_Information * atsi);


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
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated with the tunnel is stored
 */
typedef void (GNUNET_MESH_TunnelEndHandler) (void *cls,
                                             const struct GNUNET_MESH_Tunnel *
                                             tunnel, void **tunnel_ctx);


/**
 * Type for an application.  Values defined in gnunet_applications.h
 */
typedef uint32_t GNUNET_MESH_ApplicationType;


/**
 * Connect to the mesh service.
 *
 * @param cfg configuration to use
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param cleaner function called when an *inbound* tunnel is destroyed
 * @param handlers callbacks for messages we care about, NULL-terminated
 *                note that the mesh is allowed to drop notifications about inbound
 *                messages if the client does not process them fast enough (for this
 *                notification type, a bounded queue is used)
 * @param stypes Application Types the client claims to offer
 * @return handle to the mesh service 
 *           NULL on error (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *GNUNET_MESH_connect (const struct
                                                GNUNET_CONFIGURATION_Handle
                                                *cfg, void *cls,
                                                GNUNET_MESH_TunnelEndHandler
                                                cleaner,
                                                const struct
                                                GNUNET_MESH_MessageHandler
                                                *handlers,
                                                const
                                                GNUNET_MESH_ApplicationType
                                                *stypes);

/**
 * Get the peer on the other side of this tunnel if it is just one. Return NULL otherwise
 * 
 * @param tunnel the tunnel
 * @return the peer or NULL
 */
const struct GNUNET_PeerIdentity *GNUNET_MESH_get_peer (const struct
                                                        GNUNET_MESH_Tunnel
                                                        *tunnel);


/**
 * Disconnect from the mesh service.
 *
 * @param handle connection to mesh to disconnect
 */
void GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle);





/**
 * Method called whenever a tunnel falls apart.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
typedef void (*GNUNET_MESH_TunnelDisconnectHandler) (void *cls,
                                                     const struct
                                                     GNUNET_PeerIdentity *
                                                     peer);


/**
 * Method called whenever a tunnel is established.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
typedef void (*GNUNET_MESH_TunnelConnectHandler) (void *cls,
                                                  const struct
                                                  GNUNET_PeerIdentity * peer,
                                                  const struct
                                                  GNUNET_TRANSPORT_ATS_Information
                                                  * atsi);



/**
 * Handle for a request to the mesh to connect or disconnect
 * from a particular peer.  Can be used to cancel the request
 * (before the 'cont'inuation is called).
 */
struct GNUNET_MESH_PeerRequestHandle;


/**
 * Request that the mesh should try to connect to any of the given peers.
 *
 * @param h mesh handle
 * @param timeout how long to try to establish a connection
 * @param num_peers length of the peers array
 * @param peers list of candidates to connect to
 * @param connect_handler function to call on successful connect (or timeout)
 * @param disconnect_handler function to call on disconnect
 * @param handler_cls closure for handler
 * @return NULL on error (handler will not be called), otherwise handle for cancellation
 */
struct GNUNET_MESH_Tunnel *GNUNET_MESH_peer_request_connect_any (struct
                                                                 GNUNET_MESH_Handle
                                                                 *h,
                                                                 struct
                                                                 GNUNET_TIME_Relative
                                                                 timeout,
                                                                 unsigned int
                                                                 num_peers,
                                                                 const struct
                                                                 GNUNET_PeerIdentity
                                                                 *peers,
                                                                 GNUNET_MESH_TunnelConnectHandler
                                                                 connect_handler,
                                                                 GNUNET_MESH_TunnelDisconnectHandler
                                                                 disconnect_handler,
                                                                 void
                                                                 *handler_cls);


/**
 * Request that the mesh should try to connect to all of the given peers.
 * Messages send to the tunnel will be broadcast.
 *
 * @param h mesh handle
 * @param timeout how long to try to establish a connection
 * @param num_peers length of the peers array
 * @param peers list of candidates to connect to
 * @param connect_handler function to call on successful connect (or timeout);
 *                will be called for EACH of the peers in the list and
 *                once at the end with 'NULL' on timeout or once we've connected
 *                to each of the peers in the list
 * @param disconnect_handler function called if a peer drops out of the tunnel;
 *                the mesh will NOT try to add it back automatically
 * @param handler_cls closure for handler
 * @return NULL on error (handler will not be called), otherwise handle for cancellation
 */
struct GNUNET_MESH_Tunnel *GNUNET_MESH_peer_request_connect_all (struct
                                                                 GNUNET_MESH_Handle
                                                                 *h,
                                                                 struct
                                                                 GNUNET_TIME_Relative
                                                                 timeout,
                                                                 unsigned int
                                                                 num_peers,
                                                                 const struct
                                                                 GNUNET_PeerIdentity
                                                                 *peers,
                                                                 GNUNET_MESH_TunnelConnectHandler
                                                                 connect_handler,
                                                                 GNUNET_MESH_TunnelDisconnectHandler
                                                                 disconnect_handler,
                                                                 void
                                                                 *handler_cls);


/**
 * Request that a peer should be added to the tunnel.  The existing
 * connect handler will be called ONCE with either success or failure.
 *
 * @param tunnel handle to existing tunnel
 * @param timeout how long to try to establish a connection
 * @param peer peer to add
 */
void
GNUNET_MESH_peer_request_connect_add (struct GNUNET_MESH_Tunnel *tunnel,
                                      struct GNUNET_TIME_Relative timeout,
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
 * @param h mesh handle
 * @param timeout how long to try to establish a connection
 * @param app_type application type that must be supported by the peer (MESH should
 *                discover peer in proximity handling this type)
 * @param connect_handler function to call on successful connect (or timeout);
 *                will be called for EACH of the peers in the list and
 *                once at the end with 'NULL' on timeout or once we've connected
 *                to each of the peers in the list
 * @param disconnect_handler function called if a peer drops out of the tunnel;
 *                the mesh will NOT try to add it back automatically
 * @param handler_cls closure for handler
 * @return NULL on error (handler will not be called), otherwise handle for cancellation
 */
struct GNUNET_MESH_Tunnel *GNUNET_MESH_peer_request_connect_by_type (struct
                                                                     GNUNET_MESH_Handle
                                                                     *h,
                                                                     struct
                                                                     GNUNET_TIME_Relative
                                                                     timeout,
                                                                     GNUNET_MESH_ApplicationType
                                                                     app_type,
                                                                     GNUNET_MESH_TunnelConnectHandler
                                                                     connect_handler,
                                                                     GNUNET_MESH_TunnelDisconnectHandler
                                                                     disconnect_handler,
                                                                     void
                                                                     *handler_cls);


/**
 * Cancel a pending request to connect to a particular peer.  Destroys the
 * tunnel. 
 *
 * @param req request handle that was returned for the original request
 */
void GNUNET_MESH_peer_request_connect_cancel (struct GNUNET_MESH_Tunnel *req);


/**
 * Handle for a transmission request.
 */
struct GNUNET_MESH_TransmitHandle;


/**
 * Ask the mesh to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".  If we are not yet
 * connected to the specified peer, a call to this function will cause
 * us to try to establish a connection.
 *
 * @param tunnel tunnel to use for transmission
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target destination for the message, NULL for multicast to all tunnel targets 
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
struct GNUNET_MESH_TransmitHandle *GNUNET_MESH_notify_transmit_ready (struct
                                                                      GNUNET_MESH_Tunnel
                                                                      *tunnel,
                                                                      int cork,
                                                                      uint32_t
                                                                      priority,
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
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle
                                          *th);

void GNUNET_MESH_tunnel_set_head (struct GNUNET_MESH_Tunnel *tunnel,
                                  void *head);
void GNUNET_MESH_tunnel_set_tail (struct GNUNET_MESH_Tunnel *tunnel,
                                  void *tail);
void *GNUNET_MESH_tunnel_get_head (struct GNUNET_MESH_Tunnel *tunnel);
void *GNUNET_MESH_tunnel_get_tail (struct GNUNET_MESH_Tunnel *tunnel);

void GNUNET_MESH_tunnel_set_data (struct GNUNET_MESH_Tunnel *tunnel,
                                  void *data);
void *GNUNET_MESH_tunnel_get_data (struct GNUNET_MESH_Tunnel *tunnel);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_H */
#endif
/* end of gnunet_mesh_service.h */
