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
 *
 * TODO:
 * - soft stateing (keep-alive (CHANGE?) / timeout / disconnect) -- not a message issue
 * - error reporting (CREATE/CHANGE/ADD/DEL?) -- new message!
 * - partial disconnect reporting -- same as error reporting?
 * - add vs create? change vs. keep-alive? same msg or different ones? -- thinking...
 * - speed requirement specification (change?) in mesh API -- API call
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "mesh.h"


/******************************************************************************/
/********************      MESH NETWORK MESSAGES     **************************/
/******************************************************************************/

/**
 * Message for mesh path management
 */
struct GNUNET_MESH_ManipulatePath
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_[CREATE|CHANGE|ADD|DEL]
     *
     * Size: sizeof(struct GNUNET_MESH_ManipulatePath) + path_length * sizeof (struct GNUNET_PeerIdentity)
     */
    struct GNUNET_MessageHeader header;

    /**
     * (global) Id of the tunnel this path belongs to, unique in conjunction with the origin.
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * Information about speed requirements.  If the tunnel cannot sustain the 
     * minimum bandwidth, packets are to be dropped.
     */
    uint32_t speed_min GNUNET_PACKED;

    /**
     * 64-bit alignment.
     */
    uint32_t reserved GNUNET_PACKED;

    /**
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
  // struct GNUNET_PeerIdentity peers[path_length];
};

/**
 * Message for mesh data traffic to all tunnel targets.
 */
struct GNUNET_MESH_OriginMulticast
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MULTICAST
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic to a particular destination from origin.
 */
struct GNUNET_MESH_DataMessageFromOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_FROM_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Destination.
     */
    struct GNUNET_PeerIdentity destination;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic from a tunnel participant to origin.
 */
struct GNUNET_MESH_DataMessageToOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Sender of the message.
     */
    struct GNUNET_PeerIdentity sender;

    /**
     * Payload follows
     */
};

/**
 * Message for mesh flow control
 */
struct GNUNET_MESH_SpeedNotify
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_SPEED_NOTIFY
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Slowest link down the path (above minimum speed requirement).
     */
    uint32_t speed_min;

};

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

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
    GNUNET_PEER_Id id;

    /**
     * Is the peer reachable? Is the peer even connected?
     */
    enum PeerState state;

    /**
     * Who to send the data to --- what about multiple (alternate) paths?
     */
    GNUNET_PEER_Id first_hop;

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
    GNUNET_PEER_Id *peers;
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

  struct MESH_tunnel *next;

  struct MESH_tunnel *prev;

    /**
     * Origin ID: Node that created the tunnel
     */
    GNUNET_PEER_Id oid;

    /**
     * Tunnel number (unique for a given oid)
     */
    uint32_t tid;

    /**
     * Whether the tunnel is in  a state to transmit data
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
     * Messages ready to transmit??? -- real queues needed
     */
    struct GNUNET_MessageHeader *msg_out;

    /**
     * Messages received and not processed??? -- real queues needed
     */
    struct GNUNET_MessageHeader *msg_in;

    /**
     * If this tunnel was created by a local client, what's its handle?
     */
    struct GNUNET_SERVER_Client *initiator;
};

/**
 * So, I'm an endpoint. Why am I receiveing traffic?
 * Who is interested in this? How to communicate with them?
 */
struct Client
{

  struct Client *next;

  struct Client *prev;

  struct MESH_tunnel *my_tunnels_head;

  struct MESH_tunnel *my_tunnels_tail;

    /**
     * If this tunnel was created by a local client, what's its handle?
     */
    struct GNUNET_SERVER_Client *handle;

  unsigned int messages_subscribed_counter;

  uint16_t *messages_subscribed;

};


// static struct MESH_tunnel *tunnel_participation_head;

// static struct MESH_tunnel *tunnel_participation_tail;




/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/

/**
 * Core handler for path creation
 * struct GNUNET_CORE_MessageHandler
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 */
static int
handle_mesh_path_create (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{
  /*
   * EXAMPLE OF USING THE API
   * NOT ACTUAL CODE!!!!!
   */
  /*client *c;
  tunnel *t;

  t = new;
  GNUNET_CONTAINER_DLL_insert (c->my_tunnels_head,
			       c->my_tunnels_tail,
			       t);

  while (NULL != (t = c->my_tunnels_head))
    {
      GNUNET_CONTAINER_DLL_remove (c->my_tunnels_head,
				   c->my_tunnels_tail,
				   t);
      GNUNET_free (t);
    }
  */


    /* Extract path */
    /* Find origin & self */
    /* Search for origin in local tunnels */
    /* Create tunnel / add path */
    /* Retransmit to next link in chain, if any (core_notify + callback) */
    return GNUNET_OK;
}

/**
 * Core handler for mesh network traffic
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
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
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_GO, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_BACK, 0},
  {NULL, 0, 0}
};



/******************************************************************************/
/*********************       MESH LOCAL HANDLES      **************************/
/******************************************************************************/

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
 * Handler for new clients
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, which includes messages the client wants
 */
static void
handle_local_new_client (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    return;
}

/**
 * Handler for connection requests
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_connect (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    return;
}

/**
 * Handler for client traffic
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_network_traffic (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    return;
}

/**
 * Functions to handle messages from clients
 */
/* MESSAGES DEFINED:
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT              272
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ANY     273
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ALL     274
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ADD     275
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_DEL     276
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE 277
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_CANCEL  278
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_TRANSMIT_READY       279
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATED       280
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROYED     281
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA                 282
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST       283
 */
static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_local_new_client, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ANY, 0},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ALL, 0},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ADD, 0},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_DEL, 0},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE, sizeof(struct GNUNET_MESH_ConnectPeerByType)},
  {&handle_local_connect, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_CANCEL, 0},
  {&handle_local_network_traffic, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_TRANSMIT_READY, 0},
  {&handle_local_network_traffic, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA, 0}, /* FIXME needed? */
  {&handle_local_network_traffic, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST, 0}, /* FIXME needed? */
  {NULL, NULL, 0, 0}
};


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
static void
core_init (void *cls,
           struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
    return;
}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 */
static void
core_connect (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
    return;
}

/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect (void *cls,
                const struct
                GNUNET_PeerIdentity *peer)
{
    return;
}

/**
 * Process mesh requests. FIXME NON FUNCTIONAL, SKELETON
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
  struct GNUNET_CORE_Handle *core;

  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  core = GNUNET_CORE_connect (c,   /* Main configuration */
                            32,       /* queue size */
                            NULL,  /* Closure passed to MESH functions */
                            &core_init,    /* Call core_init once connected */
                            &core_connect,  /* Handle connects */
                            &core_disconnect,       /* remove peers on disconnects */
                            NULL,  /* Do we care about "status" updates? */
                            NULL,  /* Don't want notified about all incoming messages */
                            GNUNET_NO,     /* For header only inbound notification */
                            NULL,  /* Don't want notified about all outbound messages */
                            GNUNET_NO,     /* For header only outbound notification */
                            core_handlers);        /* Register these handlers */

  if (core == NULL)
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
