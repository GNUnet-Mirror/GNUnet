/*
     This file is part of GNUnet.
     (C) 2001 - 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-service-mesh.c
 * @brief GNUnet MESH service
 * @author Bartlomiej Polot
 */

#include <stdint.h>
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include <netinet/in.h>

/**
 * All the states a peer participating in a tunnel can be in.
 */
enum PeerState
{
    /**
     * Request sent, not yet answered.
     */
    MESH_PEER_WAITING,

    /**
     * Peer connected and ready to accept data
     */
    MESH_PEER_READY,

    /**
     * Peer connected previosly but not responding
     */
    MESH_PEER_UNAVAILABLE,

    /**
     * Peer requested but not ever connected
     */
    MESH_PEER_UNREACHABLE
};

/**
 * Struct containing all information regarding a given peer
 */
struct PeerInfo
{
    /**
     * ID of the peer
     */
    struct GNUNET_PeerIdentity id;

    /**
     * Is the peer reachable? Is the peer even connected?
     */
    struct PeerState state;

    /**
     * Who to send the data to
     */
    uint32_t first_hop;

    /**
     * Max data rate to this peer
     */
    uint32_t max_speed;
};

/**
 * Information regarding a path
 */
struct Path
{
    /**
     * Id of the path, in case it's needed
     */
    uint32_t id;

    /**
     * Whether the path is serving traffic in a tunnel or is a backup
     */
    int in_use;

    /**
     * List of all the peers that form the path from origin to target
     */
    PeerInfo *peers;
};

/**
 * Struct containing all information regarding a tunnel
 * For an intermediate node the improtant info used will be:
 * - OID        \ To identify
 * - TID        / the tunnel
 * - paths[0]   | To know where to send it next
 * - metainfo: ready, speeds, accounting
 * For an end node more fields will be needed (client-handling)
 */
struct MESH_tunnel
{
    /**
     * Origin ID: Node that created the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Tunnel number (unique for a given oid)
     */
    uint32_t tid;

    /**
     * Whether the tunnel is in state to transmit data
     */
    int ready;

    /**
     * Minimal speed for this tunnel in kb/s
     */
    uint32_t speed_min;

    /**
     * Maximal speed for this tunnel in kb/s
     */
    uint32_t speed_max;

    /**
     * Last time the tunnel was used
     */
    struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnel, for future optimizations
     */
    struct PeerInfo *peers;

    /**
     * Paths (used and backup)
     */
    struct Path *paths;

    /**
     * Messages ready to transmit
     */
    struct GNUNET_MessageHeader *msg_out;

    /**
     * Messages received and not processed
     */
    struct GNUNET_MessageHeader *msg_in;

    /**
     * FIXME Clients. Is anyone to be notified for traffic here?
     */
};

/**
 * So, I'm an endpoint. Why am I receiveing traffic?
 * Who is interested in this? How to communicate with them?
 */
struct Clients
{
    /**
     * FIXME add structures needed to handle client connections
     */
    int fixme;
};

/**
 * Handler for requests of creating new path
 *
 * @param cls closure
 * @param client the client this message is from
 * @param message the message received
 */
static void
handle_mesh_path_create (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    return;
}

/**
 * Handler for client disconnection
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
    /* Remove client from list, delete all timers and queues associated */
    return;
}

/**
 * Core handler for path creation
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 */
static int
handle_mesh_path_create (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{
    /* Extract path */
    return GNUNET_OK;
}

/**
 * Core handler for mesh network traffic
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 */
static int
handle_mesh_network_traffic (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{
    if(GNUNET_MESSAGE_TYPE_MESH_DATA_GO == ntohs(message->type)) {
        /* Retransmit to next in path of tunnel identified by message */
        return GNUNET_OK;
    } else { /* GNUNET_MESSAGE_TYPE_MESH_DATA_BACK */
        /* Retransmit to previous in path of tunnel identified by message */
        return GNUNET_OK;
    }
}

/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, NULL, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_GO, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_BACK, 0},
  {NULL, 0, 0}
};

/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_local_path_create, NULL, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_local_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_GO, 0},
  {&handle_local_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_BACK, 0},
  {NULL, NULL, 0, 0}
};

/**
 * Process mesh requests. FIXME NON FUNCTIONAL, COPIED FROM DHT!!
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_TIME_Relative next_send_time;
  unsigned long long temp_config_num;
  char *converge_modifier_buf;
  GNUNET_CORE_Handle *coreAPI;

  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  coreAPI = GNUNET_CORE_connect (c,   /* Main configuration */
                                 32,       /* queue size */
                                 NULL,  /* Closure passed to DHT functions */
                                 NULL,    /* Call core_init once connected */
                                 NULL,  /* Handle connects */
                                 NULL,       /* remove peers on disconnects */
                                 NULL,  /* Do we care about "status" updates? */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */

  if (coreAPI == NULL)
    return;
}

/**
 * The main function for the mesh service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_SERVICE_run (argc,
                             argv,
                             "mesh",
                             GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
  return ret;
}