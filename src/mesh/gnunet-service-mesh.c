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
 * STRUCTURE:
 * - DATA STRUCTURES
 * - GLOBAL VARIABLES
 * - MESH NETWORK HANDLER HELPERS
 * - MESH NETWORK HANDLES
 * - MESH LOCAL HANDLER HELPERS
 * - MESH LOCAL HANDLES
 * - PERIODIC FUNCTIONS
 * - MAIN FUNCTIONS (main & run)
 * 
 * TODO:
 * - error reporting (CREATE/CHANGE/ADD/DEL?) -- new message!
 * - partial disconnect reporting -- same as error reporting?
 * - add vs create? change vs. keep-alive? same msg or different ones? -- thinking...
 * - speed requirement specification (change?) in mesh API -- API call
 * - add ping message (connection confirmation, others?)
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"

#include "mesh.h"
#include "mesh_protocol.h"
#include "gnunet_dht_service.h"

#define REFRESH_PATH_TIME GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    300)


/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a path
 */
struct MeshPath
{

    /**
     * Linked list
     */
    struct MeshPath             *next;
    struct MeshPath             *prev;

    /**
     * Whether the path is serving traffic in a tunnel or is a backup
     */
    int                         in_use;

    /**
     * List of all the peers that form the path from origin to target
     */
    GNUNET_PEER_Id              *peers;

    /**
     * Number of peers (hops) in the path
     */
    unsigned int                length;
};


/**
 * All the states a peer participating in a tunnel can be in.
 */
enum MeshPeerState
{
    /**
     * Path to the peer not known yet
     */
    MESH_PEER_SEARCHING,

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
    MESH_PEER_RECONNECTING
};


/**
 * Struct containing all information regarding a given peer
 */
struct MeshPeerInfo
{
    /**
     * ID of the peer
     */
    GNUNET_PEER_Id              id;

    /**
     * Is the peer reachable? Is the peer even connected?
     */
    enum MeshPeerState          state;

    /**
     * Last time we heard from this peer
     */
    struct GNUNET_TIME_Absolute last_contact;

    /**
     * Number of attempts to reconnect so far
     */
    int                         n_reconnect_attempts;

    /**
     * Paths to reach the peer
     */
    struct MeshPath             *path;
    struct MeshPath             *path_tail;

    /**
     * Handle to stop the DHT search for a path to this peer
     */
    struct GNUNET_DHT_GetHandle *dhtget;
};


/**
 * Data scheduled to transmit (to local client or remote peer)
 */
struct MeshQueue
{
    /**
     * Double linked list
     */
    struct MeshQueue            *next;
    struct MeshQueue            *prev;

    /**
     * Target of the data (NULL if target is client)
     */
    struct MeshPeerInfo         *peer;

    /**
     * Client to send the data to (NULL if target is peer)
     */
    struct MeshClient           *client;

    /**
     * Size of the message to transmit
     */
    unsigned int                size;

    /**
     * How old is the data?
     */
    struct GNUNET_TIME_Absolute timestamp;

    /**
     * Data itself
     */
    struct GNUNET_MessageHeader *data;
};

/**
 * Globally unique tunnel identification (owner + number)
 * DO NOT USE OVER THE NETWORK
 */
struct MESH_TunnelID {
    /**
     * Node that owns the tunnel
     */
    GNUNET_PEER_Id      oid;

    /**
     * Tunnel number to differentiate all the tunnels owned by the node oid
     * ( tid < GNUNET_MESH_LOCAL_TUNNEL_ID_MARK )
     */
    MESH_TunnelNumber   tid;
};


struct MeshClient; /* FWD declaration */
/**
 * Struct containing all information regarding a tunnel
 * For an intermediate node the improtant info used will be:
 * - id        Tunnel unique identification
 * - paths[0]  To know where to send it next
 * - metainfo: ready, speeds, accounting
 */
struct MeshTunnel
{
    /**
     * Tunnel ID
     */
    struct MESH_TunnelID        id;

    /**
     * Local tunnel number ( >= GNUNET_MESH_LOCAL_TUNNEL_ID_MARK or 0 )
     */
    MESH_TunnelNumber           local_tid;

    /**
     * Last time the tunnel was used
     */
    struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnelindexed by PeerIdentity (MeshPeerInfo)
     */
    struct GNUNET_CONTAINER_MultiHashMap* peers;

    /**
     * Number of peers that are connected and potentially ready to receive data
     */
    unsigned int                peers_ready;

    /**
     * Number of peers that have been added to the tunnel
     */
    unsigned int                peers_total;


    /**
     * Client owner of the tunnel, if any
     */
    struct MeshClient           *client;

    /**
     * Messages ready to transmit
     */
    struct MeshQueue            *queue_head;
    struct MeshQueue            *queue_tail;

};

/**
 * Struct containing information about a client of the service
 */
struct MeshClient
{
    /**
     * Linked list
     */
    struct MeshClient           *next;
    struct MeshClient           *prev;

    /**
     * Tunnels that belong to this client, indexed by local id
     */
    struct GNUNET_CONTAINER_MultiHashMap* tunnels;

    /**
     * Handle to communicate with the client
     */
    struct GNUNET_SERVER_Client *handle;

    /**
     * Applications that this client has claimed to provide
     */
    GNUNET_MESH_ApplicationType *apps;
    unsigned int                app_counter;

    /**
     * Messages that this client has declared interest in
     */
    uint16_t                    *types;
    unsigned int                type_counter;

};

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/**
 * All the clients
 */
static struct MeshClient                *clients;
static struct MeshClient                *clients_tail;

/**
 * Tunnels known, indexed by MESH_TunnelID (MeshTunnel)
 */
static struct GNUNET_CONTAINER_MultiHashMap     *tunnels;

/**
 * Peers known, indexed by PeerIdentity (MeshPeerInfo)
 */
static struct GNUNET_CONTAINER_MultiHashMap     *peers;

/**
 * Handle to communicate with core
 */
static struct GNUNET_CORE_Handle        *core_handle;

/**
 * Handle to use DHT
 */
static struct GNUNET_DHT_Handle         *dht_handle;

/**
 * Local peer own ID (memory efficient handle)
 */
static GNUNET_PEER_Id                   myid;

/**
 * Tunnel ID for the next created tunnel (global tunnel number)
 */
static MESH_TunnelNumber                next_tid;

/******************************************************************************/
/******************      GENERAL HELPER FUNCTIONS      ************************/
/******************************************************************************/

/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and inster it in the appropiate structures if the peer is not known yet.
 * @param peer Identity of the peer
 * @return Existing or newly created peer info
 */
static struct MeshPeerInfo *
get_peer_info (const struct GNUNET_PeerIdentity *peer)
{
    struct MeshPeerInfo *       peer_info;

    peer_info = GNUNET_CONTAINER_multihashmap_get(peers,
                                                  &peer->hashPubKey);
    if (NULL == peer_info) {
        peer_info = (struct MeshPeerInfo *)
                    GNUNET_malloc(sizeof(struct MeshPeerInfo));
        GNUNET_CONTAINER_multihashmap_put(peers,
                            &peer->hashPubKey,
                            peer_info,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
        peer_info->id = GNUNET_PEER_intern(peer);
        peer_info->state = MESH_PEER_SEARCHING;
    }

    return peer_info;
}

/**
 * Find the first peer whom to send a packet to go down this path
 * @param path The path to use
 * @return short id of the next peer, myid in case of local delivery,
 * or 0 in case of error
 */
static GNUNET_PEER_Id
get_first_hop (struct MeshPath *path)
{
    unsigned int        i;

    while (NULL != path) {
        if (path->in_use) break;
        path = path->next;
    }
    if (NULL == path) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "tried to get the next hop from an invalid path\n");
        return 0;
    }

    for (i = 0; i < path->length; i++) {
        if (path->peers[i] == myid) {
            if (i < path->length - 1) {
                return path->peers[i+1];
            } else {
                return myid;
            }
        }
    }
    return 0;
}


/**
 * Get the cost of the path.
 * @param path The path to analyze
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 */
static unsigned int
get_path_cost(struct MeshPath *path)
{
    unsigned int        i;

    if (NULL == path) return UINT_MAX;
    for (i = 0; i < path->length; i++) {
        if (path->peers[i] == myid) {
            return path->length - i;
        }
    }
    return UINT_MAX;
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 */
static void
add_path_to_peer(struct MeshPeerInfo *peer_info, struct MeshPath *path)
{
    unsigned int        i;
    unsigned int        new_cost;
    unsigned int        best_cost;
    struct MeshPath     *aux;
    struct MeshPath     *best;

    if (NULL == peer_info || NULL == path) return;

    new_cost = get_path_cost(path);
    best_cost = UINT_MAX;
    best = NULL;
    for (aux = peer_info->path; aux != NULL; aux = aux->next) {
        if ((i = get_path_cost(aux)) < best_cost) {
            best = aux;
            best_cost = i;
        }
    }
    if (best_cost < new_cost) {
        path->in_use = 0;
        GNUNET_CONTAINER_DLL_insert_tail(peer_info->path,
                                         peer_info->path_tail,
                                         path);
    } else {
        if (NULL != best) best->in_use = 0;
        path->in_use = 1;
        GNUNET_CONTAINER_DLL_insert(peer_info->path,
                                    peer_info->path_tail,
                                    path);
    }
    return;
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest. The path is given in reverse, the destination peer is
 * path[0]. The function modifies the path, inverting it to use the origin as
 * destination.
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. First peer must be the peer in arg 1.
 */
static void
add_path_to_origin(struct MeshPeerInfo *peer_info, struct MeshPath *path)
{
    GNUNET_PEER_Id      aux;
    unsigned int        i;

    for (i = 0; i < path->length/2; i++) {
        aux = path->peers[i];
        path->peers[i] = path->peers[path->length - i - 1];
        path->peers[path->length - i - 1] = aux;
    }
    add_path_to_peer(peer_info, path);
}


/**
 * Check if client has registered with the service and has not disconnected
 * @param client the client to check
 * @return non-NULL if client exists in the global DLL
 */
static struct MeshClient *
retrieve_client (struct GNUNET_SERVER_Client *client)
{
    struct MeshClient       *c;

    c = clients; 
    while (NULL != c) {
        if (c->handle == client) return c;
        c = c->next;
    }
    return NULL;
}


/**
 * Checks if a given client has subscribed to certain message type
 * @param message_type Type of message to check
 * @param c Client to check
 * @return GNUNET_YES or GNUNET_NO, depending on subscription status
 */
static int
is_client_subscribed(uint16_t message_type, struct MeshClient *c)
{
    unsigned int        i;

    for (i = 0; i < c->type_counter; i++) {
        if (c->types[i] == message_type) return GNUNET_YES;
    }
    return GNUNET_NO;
}


/**
 * Search for a tunnel among the tunnels for a client
 * @param client the client whose tunnels to search in
 * @param tid the local id of the tunnel
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
retrieve_tunnel_by_local_id (struct MeshClient *c, MESH_TunnelNumber tid)
{
    GNUNET_HashCode hash;

    GNUNET_CRYPTO_hash(&tid, sizeof(MESH_TunnelNumber), &hash);
    return GNUNET_CONTAINER_multihashmap_get(c->tunnels, &hash);
}

/**
 * Search for a tunnel by global ID using PEER_ID
 * @param pi owner of the tunnel
 * @param tid global tunnel number
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
retrieve_tunnel_by_pi (GNUNET_PEER_Id pi, MESH_TunnelNumber tid)
{
    struct MESH_TunnelID        id;
    GNUNET_HashCode             hash;

    id.oid = pi;
    id.tid = tid;

    GNUNET_CRYPTO_hash(&id, sizeof(struct MESH_TunnelID), &hash);
    return GNUNET_CONTAINER_multihashmap_get(tunnels, &hash);
}



/**
 * Search for a tunnel by global ID using full PeerIdentities
 * @param oid owner of the tunnel
 * @param tid global tunnel number
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
retrieve_tunnel (struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid)
{
    return retrieve_tunnel_by_pi(GNUNET_PEER_search(oid), tid);
}


/**
 * Destroy the path and free any allocated resources linked to it
 * @param t tunnel the path belongs to
 * @param p the path to destroy
 * @return GNUNET_OK on success
 */
static int
destroy_path(struct MeshPath *p)
{
    GNUNET_PEER_decrement_rcs(p->peers, p->length);
    GNUNET_free(p->peers);
    GNUNET_free(p);
    return GNUNET_OK;
}

#if LATER
/**
 * Destroy the peer_info and free any allocated resources linked to it
 * @param t tunnel the path belongs to
 * @param pi the peer_info to destroy
 * @return GNUNET_OK on success
 */
static int
destroy_peer_info(struct MeshPeerInfo *pi)
{
    GNUNET_HashCode                     hash;
    struct GNUNET_PeerIdentity          id;

    GNUNET_PEER_resolve(pi->id, &id);
    GNUNET_PEER_change_rc(pi->id, -1);
    GNUNET_CRYPTO_hash(&id, sizeof(struct GNUNET_PeerIdentity), &hash);

    GNUNET_CONTAINER_multihashmap_remove(peers, &hash, pi);
    GNUNET_free(pi);
    return GNUNET_OK;
}
#endif


/**
 * Destroy the tunnel and free any allocated resources linked to it
 * @param c client the tunnel belongs to
 * @param t the tunnel to destroy
 * @return GNUNET_OK on success
 */
static int
destroy_tunnel(struct MeshTunnel  *t)
{
    struct MeshClient           *c;
    GNUNET_HashCode             hash;
    int                         r;

    if (NULL == t) return GNUNET_OK;

    c = t->client;

    GNUNET_CRYPTO_hash(&t->id, sizeof(struct MESH_TunnelID), &hash);
    if(GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove(tunnels, &hash, t)) {
        r = GNUNET_SYSERR;
    }

    GNUNET_CRYPTO_hash(&t->local_tid, sizeof(MESH_TunnelNumber), &hash);
    if(GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap_remove(c->tunnels, &hash, t))
    {
        r = GNUNET_SYSERR;
    }
    GNUNET_free(t);
    return r;
}

/******************************************************************************/
/****************      MESH NETWORK HANDLER HELPERS     ***********************/
/******************************************************************************/

/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_create_path_for_peer (void *cls, size_t size, void *buf)
{
    struct MeshPeerInfo                 *peer_info = cls;
    struct GNUNET_MESH_ManipulatePath   *msg;
    struct MeshPath                     *p;
    struct GNUNET_PeerIdentity          *peer_ptr;
    struct GNUNET_PeerIdentity          id;
    size_t                              size_needed;
    int                                 i;

    if (0 == size && NULL == buf) {
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Retransmitting create path\n");
        GNUNET_PEER_resolve(get_first_hop(peer_info->path), &id);
        GNUNET_CORE_notify_transmit_ready(core_handle,
                            0,
                            0,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            &id,
                            sizeof(struct GNUNET_MESH_ManipulatePath)
                            + (peer_info->path->length
                            * sizeof (struct GNUNET_PeerIdentity)),
                            &send_core_create_path_for_peer,
                            peer_info);
        return 0;
    }
    p = peer_info->path;
    while (NULL != p) {
        if (p->in_use) {
            break;
        }
        p = p->next;
    }
    if (p == NULL) return 0; // TODO Notify ERROR Path not found

    size_needed = sizeof(struct GNUNET_MESH_ManipulatePath)
                  + p->length * sizeof(struct GNUNET_PeerIdentity);
    if (size < size_needed) {
        // TODO retry? cancel?
        return 0;
    }

    msg = (struct GNUNET_MESH_ManipulatePath *) buf;
    msg->header.size = htons(size_needed);
    msg->header.type = htons(GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE);

    peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
    for (i = 0; i < p->length; i++) {
        GNUNET_PEER_resolve(p->peers[i], peer_ptr++);
    }

    peer_info->state = MESH_PEER_WAITING;

    return size_needed;
}

/**
 * FIXME / COMMENT
 * There are several options to send a "data to origin" or similar packet.
 * The core callback function needs to know at least: ID of tunnel and the
 * data itself, so one parameter (cls) is not enough.
 * 1. Build the message inside the original funtction, call core_ntfy_trnsmt_rdy
 *    passing the created message as cls
 *    - # memcpy: 2 (function X: to message struct, callback: from cls to buf)
 *    - Very messy, original function becomes huge and ugly
 *      (see "handle_mesh_path_create" for example)
 * 2. Create a helper function to build the packet, then call
 *    core_ntfy_trnsmt_rdy with message as cls.
 *    - # memcpy: 2 (in helper function data->msg and in callback cls->buf)
 * 3- Define new container, pass container with pointers
 *    - # memcpy = 1 (in callback, cls->buf)
 *    - Noise: extra containers defined per type of message
 */
struct info_for_data_to_origin
{
    struct MESH_TunnelID        *origin;
    void                        *data;
    size_t                      size;
};

/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (info_for_data_to_origin with all info to build packet)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_data_to_origin (void *cls, size_t size, void *buf)
{
    struct info_for_data_to_origin              *info = cls;
    struct GNUNET_MESH_DataMessageToOrigin      *msg = buf;
    size_t                                      total_size;

    GNUNET_assert(NULL != info);
    total_size = sizeof(struct GNUNET_MESH_DataMessageToOrigin) + info->size;
    GNUNET_assert(total_size < (uint16_t) -1); /* FIXME */

    if (total_size > size) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "not enough buffer to send data to origin\n");
        return 0;
    }
    msg->header.size = htons(total_size);
    msg->header.type = htons(GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN);
    GNUNET_PEER_resolve(info->origin->oid, &msg->oid);
    msg->tid = htonl(info->origin->tid);
    if (0 != info->size && NULL != info->data) {
        memcpy(&msg[1], info->data, info->size);
    }
    GNUNET_free(info);
    return total_size;
}

/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (data itself)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_data_raw (void *cls, size_t size, void *buf)
{
    struct GNUNET_MessageHeader *msg = cls;
    size_t                      total_size;

    GNUNET_assert(NULL != msg);
    total_size = ntohs(msg->size);

    if (total_size > size) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "not enough buffer to send data futher\n");
        return 0;
    }
    memcpy(msg, buf, total_size);
    return total_size;
}


#if LATER
/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (data itself)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_data_multicast (void *cls, size_t size, void *buf)
{
    struct GNUNET_MESH_DataMessageFromOrigin    *msg = cls;
    size_t                                      total_size;

    GNUNET_assert(NULL != msg);
    total_size = ntohs(msg->header.size);

    if (total_size > size) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "not enough buffer to send data futher\n");
        return 0;
    }
    memcpy(msg, buf, total_size);
    return total_size;
}


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (data itself)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_data_to_peer (void *cls, size_t size, void *buf)
{
    struct info_for_data_to_origin              *info = cls;
    struct GNUNET_MESH_DataMessageToOrigin      *msg = buf;
    size_t                                      total_size;

    GNUNET_assert(NULL != info);
    total_size = sizeof(struct GNUNET_MESH_DataMessageToOrigin) + info->size;
    /* FIXME better constant? short >= 16 bits, not == 16 bits... */
    GNUNET_assert(total_size < USHRT_MAX);

    if (total_size > size) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "not enough buffer to send data to origin\n");
        return 0;
    }
    msg->header.size = htons(total_size);
    msg->header.type = htons(GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN);
    GNUNET_PEER_resolve(info->origin->oid, &msg->oid);
    msg->tid = htonl(info->origin->tid);
    if (0 != info->size && NULL != info->data) {
        memcpy(&msg[1], info->data, info->size);
    }
    GNUNET_free(info);
    return total_size;
}


/**
 * Send another peer a notification to destroy a tunnel
 * @param cls The tunnel to destroy
 * @param size Size in the buffer
 * @param buf Memory where to put the data to transmit
 * @return Size of data put in buffer
 */
static size_t
send_p2p_tunnel_destroy(void *cls, size_t size, void *buf)
{
    struct MeshTunnel                   *t = cls;
    struct MeshClient                   *c;
    struct GNUNET_MESH_TunnelMessage    *msg;

    c = t->client;
    msg = buf;
    msg->header.type = htons(GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY); /*FIXME*/
    msg->header.size = htons(sizeof(struct GNUNET_MESH_TunnelMessage));
    msg->tunnel_id = htonl(t->id.tid);

    destroy_tunnel(c, t);
    return sizeof(struct GNUNET_MESH_TunnelMessage);
}
#endif


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t
send_client_raw (void *cls, size_t size, void *buf)
{
    struct GNUNET_MessageHeader *msg = cls;
    size_t                      msg_size;

    msg_size = ntohs(msg->size);
    if (msg_size > size) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "deliver to client failed: buffer too small\n");
        return 0;
    }
    memcpy(buf, cls, msg_size);
    return msg_size;
}


/**
 * Iterator over hash map peer entries to resend a data packet to all peers
 * down the tunnel.
 *
 * @param cls closure (original message)
 * @param key current key code (peer id hash)
 * @param value value in the hash map (peer_info)
 * @return GNUNET_YES if we should continue to iterate, GNUNET_NO if not.
 */
static int iterate_resend_multicast (void *cls,
                                     const GNUNET_HashCode * key,
                                     void *value)
{
    struct GNUNET_MESH_DataMessageMulticast     *msg = cls;
    struct GNUNET_PeerIdentity                  id;
    struct MeshPeerInfo                         *peer_info = value;

    if (peer_info->id == myid) {
//         TODO retransmit to interested clients
        return GNUNET_YES;
    }
    GNUNET_PEER_resolve(get_first_hop(peer_info->path), &id);
    GNUNET_CORE_notify_transmit_ready(core_handle,
                                      0,
                                      0,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      &id,
                                      ntohs(msg->header.size),
                                      &send_core_data_raw,
                                      msg);
    return GNUNET_YES;
}


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
    unsigned int                        own_pos;
    uint16_t                            size;
    uint16_t                            i;
    MESH_TunnelNumber                   tid;
    struct GNUNET_MESH_ManipulatePath   *msg;
    struct GNUNET_PeerIdentity          *pi;
    struct GNUNET_PeerIdentity          id;
    GNUNET_HashCode                     hash;
    struct MeshPath                     *path;
    struct MeshPeerInfo                 *dest_peer_info;
    struct MeshPeerInfo                 *orig_peer_info;
    struct MeshTunnel                   *t;


    size = ntohs(message->size);
    if (size < sizeof(struct GNUNET_MESH_ManipulatePath)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "received create path message too short\n");
        return GNUNET_OK;
    }

    size -= sizeof(struct GNUNET_MESH_ManipulatePath);
    if (size < 2 * sizeof(struct GNUNET_PeerIdentity)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "create path message lacks enough peers\n");
        return GNUNET_OK;
    }
    if (size % sizeof(struct GNUNET_PeerIdentity)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "create path message of wrong size\n");
        return GNUNET_OK;
    }
    msg = (struct GNUNET_MESH_ManipulatePath *) message;
    size /= sizeof(struct GNUNET_PeerIdentity);

    tid = ntohl(msg->tid);
    pi = (struct GNUNET_PeerIdentity *) &msg[1];
    t = retrieve_tunnel(pi, tid);

    if (NULL == t) {
        t = GNUNET_malloc(sizeof(struct MeshTunnel));
        t->id.oid = GNUNET_PEER_intern(pi);
        t->id.tid = tid;
        t->local_tid = 0;
        t->client = NULL;
        t->peers = GNUNET_CONTAINER_multihashmap_create(32);

        GNUNET_CRYPTO_hash(&t->id, sizeof(struct MESH_TunnelID), &hash);
        if (GNUNET_OK !=
            GNUNET_CONTAINER_multihashmap_put(tunnels,
                            &hash,
                            t,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
        {
            GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "create path: could not store tunnel in hashmap\n");
            return GNUNET_OK;
        }

    }
    dest_peer_info = GNUNET_CONTAINER_multihashmap_get(peers,
                                                  &pi[size - 1].hashPubKey);
    if (NULL == dest_peer_info) {
        dest_peer_info = GNUNET_malloc(sizeof(struct MeshPeerInfo));
        dest_peer_info->id = GNUNET_PEER_intern(&pi[size - 1]);
        dest_peer_info->state = MESH_PEER_WAITING;
        GNUNET_CONTAINER_multihashmap_put(peers,
                            &pi[size - 1].hashPubKey,
                            dest_peer_info,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
    orig_peer_info = GNUNET_CONTAINER_multihashmap_get(peers, &pi->hashPubKey);
    if (NULL == orig_peer_info) {
        orig_peer_info = GNUNET_malloc(sizeof(struct MeshPeerInfo));
        orig_peer_info->id = GNUNET_PEER_intern(pi);
        orig_peer_info->state = MESH_PEER_WAITING;
        GNUNET_CONTAINER_multihashmap_put(peers,
                            &pi->hashPubKey,
                            orig_peer_info,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }


    path = GNUNET_malloc(sizeof(struct MeshPath));
    path->length = size;
    path->peers = GNUNET_malloc(size * sizeof(GNUNET_PEER_Id));
    own_pos = 0;
    for (i = 0; i < size; i++) {
        path->peers[i] = GNUNET_PEER_intern(&pi[i]);
        if (path->peers[i] == myid) own_pos = i;
    }
    if (own_pos == 0) { /* cannot be self, must be 'not found' */
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "create path: self not found in path through self\n");
        destroy_path(path);
        /* FIXME error. destroy tunnel? leave for timeout? */
        return 0;
    }
    if (own_pos == size - 1) { /* it is for us! */
        add_path_to_origin(orig_peer_info, path);           /* inverts path!  */
        GNUNET_PEER_resolve(get_first_hop(path), &id); /* path is inverted :) */
        /* FIXME / COMMENT 
         * is it allowed/desired to declare variables this way?
         * (style, best practices, etc)
         * This variable is short lived and completely irrelevant for the rest
         * of the function
         */
        struct info_for_data_to_origin *info =
            GNUNET_malloc(sizeof(struct info_for_data_to_origin));
        info->origin = &t->id;
        info->data = NULL;
        info->size = 0;
        GNUNET_CORE_notify_transmit_ready(core_handle,
                                0,
                                0,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &id,
                                sizeof(struct GNUNET_MessageHeader),
                                &send_core_data_to_origin,
                                info);
    } else {
        add_path_to_peer(dest_peer_info, path);
        GNUNET_PEER_resolve(get_first_hop(path), &id);
        GNUNET_CORE_notify_transmit_ready(core_handle,
                                0,
                                0,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &id,
                                sizeof(struct GNUNET_MessageHeader),
                                &send_core_create_path_for_peer,
                                dest_peer_info);
    }
    return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to a peer
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_unicast (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information
                          *atsi)
{
    struct GNUNET_MESH_DataMessageFromOrigin    *msg;
    struct GNUNET_PeerIdentity                  id;
    struct MeshTunnel                           *t;
    struct MeshPeerInfo                         *pi;
    struct MeshClient                           *c;
    size_t                                      size;
    uint16_t                                    payload_type;

    size = ntohs(message->size);
    if (size < sizeof(struct GNUNET_MESH_DataMessageFromOrigin)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                "got data from origin packet: too short\n");
        return GNUNET_OK; // FIXME maybe SYSERR? peer misbehaving?
    }
    msg = (struct GNUNET_MESH_DataMessageFromOrigin *) message;
    t = retrieve_tunnel(&msg->oid, ntohl(msg->tid));
    if (NULL == t) {
        /* TODO: are we so nice that we try to send it to OID anyway? We *could*
         * know how to reach it, from the global peer hashmap
         */
        return GNUNET_OK;
    }
    pi = GNUNET_CONTAINER_multihashmap_get(t->peers,
                                        &msg->destination.hashPubKey);
    if (NULL == pi) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                   "got invalid data from origin packet: wrong destination\n");
        /* TODO are we so nice to try to deliver it anyway? maybe we missed
         * a Create_Path packet that added the peer but we have it in the
         * _global_ peer pool anyway...
         */
        return GNUNET_OK;
    }
    if (pi->id == myid) {
        payload_type = ntohs(msg[1].header.type);
        for (c = clients; NULL != c; c = c->next) {
            if (is_client_subscribed(payload_type, c)) {
                GNUNET_SERVER_notify_transmit_ready(c->handle,
                    size - sizeof(struct GNUNET_MESH_DataMessageFromOrigin),
                    GNUNET_TIME_UNIT_FOREVER_REL,
                    send_client_raw,
                    &msg[1]);
            }
        }
        return GNUNET_OK;
    }
    GNUNET_PEER_resolve(get_first_hop(pi->path), &id);
    GNUNET_CORE_notify_transmit_ready(core_handle,
        0,
        0,
        GNUNET_TIME_UNIT_FOREVER_REL,
        &id,
        size,
        &send_core_data_raw,
        msg);
    return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to all peers
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_multicast (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information
                          *atsi)
{
    struct GNUNET_MESH_DataMessageMulticast    *msg;
    struct MeshTunnel                           *t;
    size_t                                      size;

    size = ntohs(message->size);
    if (size < sizeof(struct GNUNET_MESH_DataMessageMulticast)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                "got multicast packet: too short\n");
        return GNUNET_OK; // FIXME maybe SYSERR? peer misbehaving?
    }
    msg = (struct GNUNET_MESH_DataMessageMulticast *) message;
    t = retrieve_tunnel(&msg->oid, ntohl(msg->tid));

    if (NULL == t) {
        return GNUNET_OK;
    }

    GNUNET_CONTAINER_multihashmap_iterate(t->peers,
                                          &iterate_resend_multicast,
                                          msg);

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
handle_mesh_data_to_orig (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information
                          *atsi)
{
    struct GNUNET_MESH_DataMessageToOrigin      *msg;
    struct GNUNET_PeerIdentity                  id;
    struct MeshTunnel                           *t;
    struct MeshPeerInfo                         *peer_info;
    size_t                                      size;

    size = ntohs(message->size);
    if (size < sizeof(struct GNUNET_MESH_DataMessageToOrigin)) {
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                "got invalid data to origin packet: too short\n");
        return GNUNET_OK; // FIXME maybe SYSERR? peer misbehaving?
    }
    msg = (struct GNUNET_MESH_DataMessageToOrigin *) message;
    t = retrieve_tunnel(&msg->oid, ntohl(msg->tid));

    if (NULL == t) {
        /* TODO: are we so nice that we try to send it to OID anyway? We *could*
         * know how to reach it, from the global peer hashmap
         */
        return GNUNET_OK;
    }

    if (t->id.oid == myid) {
        if (NULL == t->client) {
            GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                "got data packet for ownerless tunnel\n");
            return GNUNET_OK;
        }
        //         TODO retransmit to client owner
        return GNUNET_OK;
    }
    peer_info = get_peer_info(&msg->oid);
    if (NULL == peer_info) {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                "unknown origin of tunnel\n");
        return GNUNET_OK;
    }
    GNUNET_PEER_resolve(get_first_hop(peer_info->path), &id);
    GNUNET_CORE_notify_transmit_ready(core_handle,
                                      0,
                                      0,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      &id,
                                      size,
                                      &send_core_data_raw,
                                      msg);

    return GNUNET_OK;
}


/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_data_unicast, GNUNET_MESSAGE_TYPE_DATA_MESSAGE_FROM_ORIGIN, 0},
  {&handle_mesh_data_multicast, GNUNET_MESSAGE_TYPE_DATA_MULTICAST, 0},
  {&handle_mesh_data_to_orig, GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN, 0},
  {NULL, 0, 0}
};



/******************************************************************************/
/****************       MESH LOCAL HANDLER HELPERS      ***********************/
/******************************************************************************/

/**
 * delete_tunnel_entry: iterator for deleting each tunnel that belongs to a
 * client when the client disconnects.
 * @param cls closure (client that is disconnecting)
 * @param key the hash of the local tunnel id (used to access the hashmap)
 * @param value the value stored at the key (tunnel to destroy)
 * @return GNUNET_OK on success
 */
static int
delete_tunnel_entry (void *cls, const GNUNET_HashCode * key, void *value) {
    int r;
    r = destroy_tunnel((struct MeshTunnel *) value);
    return r;
}

#if LATER
/**
 * notify_client_connection_failure: notify a client that the connection to the
 * requested remote peer is not possible (for instance, no route found)
 * Function called when the socket is ready to queue more data. "buf" will be
 * NULL and "size" zero if the socket was closed for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
notify_client_connection_failure (void *cls, size_t size, void *buf)
{
    int                                 size_needed;
    struct MeshPeerInfo                 *peer_info;
    struct GNUNET_MESH_PeerControl      *msg;
    struct GNUNET_PeerIdentity          id;

    if (0 == size && NULL == buf) {
        // TODO retry? cancel?
        return 0;
    }

    size_needed = sizeof(struct GNUNET_MESH_PeerControl);
    peer_info = (struct MeshPeerInfo *) cls;
    msg = (struct GNUNET_MESH_PeerControl *) buf;
    msg->header.size = htons(sizeof(struct GNUNET_MESH_PeerControl));
    msg->header.type = htons(GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DISCONNECTED);
//     msg->tunnel_id = htonl(peer_info->t->tid);
    GNUNET_PEER_resolve(peer_info->id, &id);
    memcpy(&msg->peer, &id, sizeof(struct GNUNET_PeerIdentity));

    return size_needed;
}
#endif


/**
 * Send keepalive packets for a peer
 *
 * @param cls unused
 * @param tc unused
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
    struct MeshPeerInfo         *peer_info = cls;
    struct GNUNET_PeerIdentity  id;

    if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN) return;
    GNUNET_PEER_resolve(get_first_hop(peer_info->path), &id);
    GNUNET_CORE_notify_transmit_ready(core_handle,
                                0,
                                0,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &id,
                                sizeof(struct GNUNET_MESH_ManipulatePath)
                                + (peer_info->path->length
                                * sizeof (struct GNUNET_PeerIdentity)),
                                &send_core_create_path_for_peer,
                                peer_info);

    return;
}


/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_response_handler(void *cls,
                        struct GNUNET_TIME_Absolute exp,
                        const GNUNET_HashCode * key,
                        const struct GNUNET_PeerIdentity * const *get_path,
                        const struct GNUNET_PeerIdentity * const *put_path,
                        enum GNUNET_BLOCK_Type type,
                        size_t size,
                        const void *data)
{
    struct MeshPeerInfo         *peer_info = cls;
    struct MeshPath             *p;
    struct GNUNET_PeerIdentity  pi;
    int                         i;

    if ((NULL == get_path || NULL == put_path) && NULL == peer_info->path) {
        // Find ourselves some alternate initial path to the destination: retry
        GNUNET_DHT_get_stop(peer_info->dhtget);
        GNUNET_PEER_resolve(peer_info->id, &pi);
        peer_info->dhtget = GNUNET_DHT_get_start(dht_handle,
                                    GNUNET_TIME_UNIT_FOREVER_REL,
                                    GNUNET_BLOCK_TYPE_ANY,
                                    &pi.hashPubKey,
                                    4,    /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE,
                                    NULL, /* bloom filter */
                                    0,    /* mutator */
                                    NULL, /* xquery */
                                    0,    /* xquery bits */
                                    dht_get_response_handler,
                                    (void *)peer_info);
    }

    p = GNUNET_malloc(sizeof(struct MeshPath));
    for (i = 0; get_path[i] != NULL; i++);
    for (i--; i >= 0; i--) {
        p->peers = GNUNET_realloc(p->peers,
                                   sizeof(GNUNET_PEER_Id) * (p->length + 1));
        p->peers[p->length] = GNUNET_PEER_intern(get_path[i]);
        p->length++;
    }
    for (i = 0; put_path[i] != NULL; i++);
    for (i--; i >= 0; i--) {
        p->peers = GNUNET_realloc(p->peers,
                                  sizeof(GNUNET_PEER_Id) * (p->length + 1));
        p->peers[p->length] = GNUNET_PEER_intern(put_path[i]);
        p->length++;
    }
    add_path_to_peer(peer_info, p);
    GNUNET_CORE_notify_transmit_ready(core_handle,
                                      0,
                                      0,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      get_path[1],
                                      sizeof(struct GNUNET_MESH_ManipulatePath)
                                        + (p->length
                                        * sizeof (struct GNUNET_PeerIdentity)),
                                      &send_core_create_path_for_peer,
                                      peer_info);
    GNUNET_SCHEDULER_add_delayed(REFRESH_PATH_TIME, &path_refresh, peer_info);
    return;
}


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
    struct MeshClient   *c;
    struct MeshClient   *next;

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "client disconnected\n");
    c = clients;
    while (NULL != c) {
        if (c->handle == client) {
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               " matching client found, cleaning\n");
            GNUNET_CONTAINER_multihashmap_iterate(c->tunnels,
                                                  &delete_tunnel_entry,
                                                  c);
            GNUNET_CONTAINER_multihashmap_destroy(c->tunnels);
            if(0 != c->app_counter) GNUNET_free (c->apps);
            if(0 != c->type_counter) GNUNET_free (c->types);
            GNUNET_CONTAINER_DLL_remove(clients, clients_tail, c);
            next = c->next;
            GNUNET_free (c);
            c = next;
        } else {
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "   ... searching\n");
            c = c->next;
        }
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "   done!\n");
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
    struct GNUNET_MESH_ClientConnect    *cc_msg;
    struct MeshClient                   *c;
    unsigned int                        size;
    uint16_t                            types;
    uint16_t                            apps;

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "new client connected\n");
    /* Check data sanity */
    size = ntohs(message->size) - sizeof(struct GNUNET_MESH_ClientConnect);
    cc_msg = (struct GNUNET_MESH_ClientConnect *) message;
    types = ntohs(cc_msg->types);
    apps = ntohs(cc_msg->applications);
    if (size !=
        types * sizeof(uint16_t) + apps * sizeof(GNUNET_MESH_ApplicationType))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Create new client structure */
    c = GNUNET_malloc(sizeof(struct MeshClient));
    c->handle = client;
    if (types != 0) {
        c->type_counter = types;
        c->types = GNUNET_malloc(types * sizeof(uint16_t));
        memcpy(c->types, &message[1], types * sizeof(uint16_t));
    }
    if (apps != 0) {
        c->app_counter = apps;
        c->apps = GNUNET_malloc(apps * sizeof(GNUNET_MESH_ApplicationType));
        memcpy(c->apps,
               &message[1] + types * sizeof(uint16_t),
               apps * sizeof(GNUNET_MESH_ApplicationType));
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               " client has %u+%u subscriptions\n",
               c->type_counter,
               c->app_counter);

    GNUNET_CONTAINER_DLL_insert(clients, clients_tail, c);
    c->tunnels = GNUNET_CONTAINER_multihashmap_create(32);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);

}


/**
 * Handler for requests of new tunnels
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_tunnel_create (void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_TunnelMessage    *t_msg;
    struct MeshTunnel                   *t;
    struct MeshClient                   *c;
    GNUNET_HashCode                     hash;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Message sanity check */
    if (sizeof(struct GNUNET_MESH_TunnelMessage) != ntohs(message->size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    t_msg = (struct GNUNET_MESH_TunnelMessage *) message;
    /* Sanity check for tunnel numbering */
    if (0 == (ntohl(t_msg->tunnel_id) & GNUNET_MESH_LOCAL_TUNNEL_ID_MARK)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    /* Sanity check for duplicate tunnel IDs */
    if(NULL != retrieve_tunnel_by_local_id(c, ntohl(t_msg->tunnel_id))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    t = GNUNET_malloc(sizeof(struct MeshTunnel));
    while (NULL != retrieve_tunnel_by_pi(myid, next_tid))
        next_tid = (next_tid + 1) % GNUNET_MESH_LOCAL_TUNNEL_ID_MARK;
    t->id.tid = next_tid++;
    t->id.oid = myid;
    t->local_tid = ntohl(t_msg->tunnel_id);
    t->client = c;
    t->peers = GNUNET_CONTAINER_multihashmap_create(32);

    GNUNET_CRYPTO_hash(&t->local_tid, sizeof(MESH_TunnelNumber), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put(c->tunnels, &hash, t,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    GNUNET_CRYPTO_hash(&t->id, sizeof(struct MESH_TunnelID), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put(tunnels, &hash, t,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for requests of deleting tunnels
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_tunnel_destroy (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_TunnelMessage    *tunnel_msg;
    struct MeshClient                   *c;
    struct MeshTunnel                   *t;
    MESH_TunnelNumber                   tid;
    GNUNET_HashCode                     hash;


    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    /* Message sanity check */
    if (sizeof(struct GNUNET_MESH_TunnelMessage) != ntohs(message->size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;

    /* Retrieve tunnel */
    tid = ntohl(tunnel_msg->tunnel_id);

    /* Remove from local id hashmap */
    GNUNET_CRYPTO_hash(&tid, sizeof(MESH_TunnelNumber), &hash);
    t = GNUNET_CONTAINER_multihashmap_get(c->tunnels, &hash);
    GNUNET_CONTAINER_multihashmap_remove(c->tunnels, &hash, t);

    /* Remove from global id hashmap */
    GNUNET_CRYPTO_hash(&t->id, sizeof(struct MESH_TunnelID), &hash);
    GNUNET_CONTAINER_multihashmap_remove(tunnels, &hash, t);

//     notify_tunnel_destroy(t);
    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for connection requests to new peers
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 */
static void
handle_local_connect_add (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_PeerControl      *peer_msg;
    struct MeshClient                   *c;
    struct MeshTunnel                   *t;
    MESH_TunnelNumber                   tid;
    struct MeshPeerInfo                 *peer_info;


    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    peer_msg = (struct GNUNET_MESH_PeerControl *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl)
        != ntohs(peer_msg->header.size))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(peer_msg->tunnel_id);
    t = retrieve_tunnel_by_local_id(c, tid);
    if (NULL == t) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Does client own tunnel? */
    if (t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    t->peers_total++;
    peer_info = get_peer_info(&peer_msg->peer);

    /* Start DHT search if needed */
    if(MESH_PEER_READY != peer_info->state && NULL == peer_info->dhtget) {
        peer_info->dhtget = GNUNET_DHT_get_start(dht_handle,
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            GNUNET_BLOCK_TYPE_ANY,
                                            &peer_msg->peer.hashPubKey,
                                            4,    /* replication level */
                                            GNUNET_DHT_RO_RECORD_ROUTE,
                                            NULL, /* bloom filter */
                                            0,    /* mutator */
                                            NULL, /* xquery */
                                            0,    /* xquery bits */
                                            dht_get_response_handler,
                                            (void *)peer_info);
    }

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for disconnection requests of peers in a tunnel
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 */
static void
handle_local_connect_del (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_PeerControl      *peer_msg;
    struct MeshClient                   *c;
    struct MeshTunnel                   *t;
    MESH_TunnelNumber                   tid;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    peer_msg = (struct GNUNET_MESH_PeerControl *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl)
        != ntohs(peer_msg->header.size))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(peer_msg->tunnel_id);
    t = retrieve_tunnel_by_local_id(c, tid);
    if (NULL == t) {
            GNUNET_break(0);
            GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
            return;
        }

    /* Does client own tunnel? */
    if (t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Ok, delete peer from tunnel */
    GNUNET_CONTAINER_multihashmap_remove_all(t->peers,
                                             &peer_msg->peer.hashPubKey);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for connection requests to new peers by type
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (ConnectPeerByType)
 */
static void
handle_local_connect_by_type (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_ConnectPeerByType        *connect_msg;
    MESH_TunnelNumber                           tid;
    GNUNET_MESH_ApplicationType                 application;
    struct MeshClient                           *c;
    struct MeshTunnel                           *t;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    connect_msg = (struct GNUNET_MESH_ConnectPeerByType *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl) !=
            ntohs(connect_msg->header.size))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(connect_msg->tunnel_id);
    t = retrieve_tunnel_by_local_id(c, tid);
    if (NULL == t) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Does client own tunnel? */
    if (t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Ok, lets find a peer offering the service */
    application = ntohl(connect_msg->type);
    application++; // FIXME silence warnings

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for client traffic directed to one peer
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
    struct MeshClient                           *c;
    struct MeshTunnel                           *t;
    struct MeshPeerInfo                         *pi;
    struct GNUNET_MESH_Data                     *data_msg;
    struct GNUNET_PeerIdentity                  next_hop;
    MESH_TunnelNumber                           tid;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    data_msg = (struct GNUNET_MESH_Data *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl) !=
            ntohs(data_msg->header.size))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(data_msg->tunnel_id);
    t = retrieve_tunnel_by_local_id(c, tid);
    if (NULL == t) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /*  Is it a local tunnel? Then, does client own the tunnel? */
    if (t->client->handle != NULL && t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    pi = GNUNET_CONTAINER_multihashmap_get(t->peers,
                                           &data_msg->peer_id.hashPubKey);
    /* Is the selected peer in the tunnel? */
    if (NULL == pi) {
        /* TODO
         * Are we SO nice that we automatically try to add him to the tunnel?
         */
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    GNUNET_PEER_resolve(get_first_hop(pi->path), &next_hop);
    GNUNET_CORE_notify_transmit_ready(core_handle,
                            0,
                            0,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            &next_hop,
                            /* FIXME re-check types */
                            message->size - sizeof(struct GNUNET_MESH_Data)
                            + sizeof(struct GNUNET_MESH_DataMessageFromOrigin),
                            &send_core_data_to_origin, /* FIXME re-check */
                            NULL);

    GNUNET_SERVER_receive_done(client, GNUNET_OK); /* FIXME not yet */
    return;
}

/**
 * Handler for client traffic directed to all peers in a tunnel
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_network_traffic_bcast (void *cls,
                                    struct GNUNET_SERVER_Client *client,
                                    const struct GNUNET_MessageHeader *message)
{
    struct MeshClient                           *c;
    struct MeshTunnel                           *t;
    struct GNUNET_MESH_DataBroadcast            *data_msg;
    MESH_TunnelNumber                           tid;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    data_msg = (struct GNUNET_MESH_DataBroadcast *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl)
        != ntohs(data_msg->header.size))
    {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(data_msg->tunnel_id);
    t = retrieve_tunnel_by_local_id(c, tid);
    if (NULL == t) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Does client own tunnel? */
    if (t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /*  TODO */

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}

/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_local_new_client, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
  {&handle_local_tunnel_create, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE,
   sizeof(struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_destroy, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY,
   sizeof(struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_connect_add, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ADD,
   sizeof(struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_del, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_DEL,
   sizeof(struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_by_type, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE,
   sizeof(struct GNUNET_MESH_ConnectPeerByType)},
  {&handle_local_network_traffic, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA, 0},
  {&handle_local_network_traffic_bcast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST, 0},
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Core init\n");
    core_handle = server;
    myid = GNUNET_PEER_intern(identity);
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
//     GNUNET_PEER_Id              pid;
    struct MeshPeerInfo         *peer_info;
    struct MeshPath             *path;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer connected\n");
    peer_info = get_peer_info(peer);
    if (myid == peer_info->id) {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "     (self)\n");
    }
    path = GNUNET_malloc(sizeof(struct MeshPath));
    path->length = 2;
    path->peers = GNUNET_malloc(sizeof(GNUNET_PEER_Id) * 2);
    path->peers[0] = myid;
    path->peers[1] = peer_info->id;
    add_path_to_peer(peer_info, path);
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
    GNUNET_PEER_Id      pid;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer disconnected\n");
    pid = GNUNET_PEER_search(peer);
    if (myid == pid) {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "     (self)\n");
    }
    return;
}


/******************************************************************************/
/************************      MAIN FUNCTIONS      ****************************/
/******************************************************************************/

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "shutting down\n");
    if (core_handle != NULL) {
        GNUNET_CORE_disconnect (core_handle);
        core_handle = NULL;
    }
    if (dht_handle != NULL) {
        GNUNET_DHT_disconnect (dht_handle);
        dht_handle = NULL;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "shut down\n");
}

/**
 * Process mesh requests.
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "starting to run\n");
    GNUNET_SERVER_add_handlers (server, plugin_handlers);
    GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
    core_handle = GNUNET_CORE_connect (c,               /* Main configuration */
                            1,                                  /* queue size */
                            NULL,         /* Closure passed to MESH functions */
                            &core_init,      /* Call core_init once connected */
                            &core_connect,                 /* Handle connects */
                            &core_disconnect,  /* remove peers on disconnects */
                            NULL,       /* Do we care about "status" updates? */
                            NULL, /* Don't notify about all incoming messages */
                            GNUNET_NO,     /* For header only in notification */
                            NULL, /* Don't notify about all outbound messages */
                            GNUNET_NO,    /* For header-only out notification */
                            core_handlers);        /* Register these handlers */
    if (core_handle == NULL) {
        GNUNET_break(0);
    }
    dht_handle = GNUNET_DHT_connect(c, 64);
    if (dht_handle == NULL) {
        GNUNET_break(0);
    }
    next_tid = 0;

    tunnels = GNUNET_CONTAINER_multihashmap_create(32);
    peers = GNUNET_CONTAINER_multihashmap_create(32);
    clients = NULL;
    clients_tail = NULL;

    /* Scheduled the task to clean up when shutdown is called */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &shutdown_task, NULL);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "end if run()\n");
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
                               GNUNET_SERVICE_OPTION_NONE,
                               &run, NULL)) ? 0 : 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "end of main()\n");
    return ret;
}
