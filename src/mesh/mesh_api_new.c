/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/mesh_api_new.c
 * @brief mesh api: client implementation of mesh service
 * @author Bartlomiej Polot
 */

#ifdef __cplusplus

extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include <stdint.h>
#include "gnunet_mesh_service.h"

/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle {
    struct GNUNET_MESH_Tunnel           *head;
    struct GNUNET_MESH_Tunnel           *tail;
    GNUNET_MESH_TunnelEndHandler        cleaner;
};

/**
 * Opaque handle to a tunnel.
 */
struct GNUNET_MESH_Tunnel {
    GNUNET_PEER_Id                              owner;
    GNUNET_PEER_Id                              destination;
    GNUNET_MESH_TunnelConnectHandler            connect_handler;
    GNUNET_MESH_TunnelDisconnectHandler         disconnect_handler;
    GNUNET_PEER_Id                              *peers;
};


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
 * @return handle to the mesh service 
 *           NULL on error (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
                     GNUNET_MESH_TunnelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers, 
                     const GNUNET_MESH_ApplicationType *stypes) {
    GNUNET_MESH_Handle *h;
    h = GNUNET_malloc(sizeof(GNUNET_MESH_Handle));

    h->cleaner = cleaner;
    return h;
}

/**
 * Disconnect from the mesh service.
 *
 * @param handle connection to mesh to disconnect
 */
void GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle) {
    return;
}

/**
 * Create a new tunnel (we're initiator and will be allowed to add/remove peers and
 * to broadcast).
 *
 * @param h mesh handle
 * @param connect_handler function to call when peers are actually connected
 * @param disconnect_handler function to call when peers are disconnected
 * @param handler_cls closure for connect/disconnect handlers
 */
struct GNUNET_MESH_Tunnel *
GNUNET_MESH_tunnel_create (struct GNUNET_MESH_Handle *h,
                           GNUNET_MESH_TunnelConnectHandler connect_handler,
                           GNUNET_MESH_TunnelDisconnectHandler disconnect_handler,
                           void *handler_cls) {
    GNUNET_MESH_Tunnel *tunnel;
    tunnel = GNUNET_malloc(sizeof(GNUNET_MESH_Tunnel));

    tunnel->connect_handler = connect_handler;
    tunnel->disconnect_handler = disconnect_handler;
    tunnel->peers = NULL;

    return tunnel;
}

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif