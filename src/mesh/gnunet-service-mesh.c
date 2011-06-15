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
 * - MAIN FUNCTIONS (main & run)
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
#include "mesh_protocol.h"
#include "gnunet_dht_service.h"


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
     * When to try to establish contact again?
     */
    struct GNUNET_TIME_Absolute next_reconnect_attempt;

    /**
     * Number of attempts to reconnect so far
     */
    int                         n_reconnect_attempts;

    /**
     * Paths to reach the peer
     */
    struct MeshPath             *path;

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

/**
 * Tunnels known, indexed by MESH_TunnelID (MeshTunnel)
 */
struct GNUNET_CONTAINER_MultiHashMap    *tunnels;

/**
 * Peers known, indexed by PeerIdentity (MeshPeerInfo)
 */
struct GNUNET_CONTAINER_MultiHashMap    *peers;

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


#if LATER
/**
 * Search for a tunnel by global ID using full PeerIdentities
 * @param oid owner of the tunnel
 * @param tid global tunnel number
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
retrieve_tunnel (struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid)
{
    GNUNET_PEER_Id              pi;

    pi = GNUNET_PEER_intern(oid);
    GNUNET_PEER_change_rc(pi, -1);
    return retrieve_tunnel_by_pi(pi, tid);
}


/**
 * Destroy the path and free any allocated resources linked to it
 * @param t tunnel the path belongs to
 * @param p the path to destroy
 * @return GNUNET_OK on success
 */
static int
destroy_path(struct MeshTunnel  *t, struct MeshPath *p)
{
    GNUNET_PEER_decrement_rcs(p->peers, p->length);
    GNUNET_free(p->peers);
    GNUNET_free(p);
    return GNUNET_OK;
}


/**
 * Destroy the peer_info and free any allocated resources linked to it
 * @param t tunnel the path belongs to
 * @param pi the peer_info to destroy
 * @return GNUNET_OK on success
 */
// static int
// destroy_peer_info(struct MeshTunnel  *t, struct MeshPeerInfo *pi)
// {
//     GNUNET_PEER_change_rc(pi->id, -1);
//     /* FIXME delete from list */
//     GNUNET_free(pi);
//     return GNUNET_OK;
// }
#endif


/**
 * Destroy the tunnel and free any allocated resources linked to it
 * @param c client the tunnel belongs to
 * @param t the tunnel to destroy
 * @return GNUNET_OK on success
 */
static int
destroy_tunnel(struct MeshClient *c, struct MeshTunnel  *t)
{
//     struct MeshPath         *path;
    GNUNET_HashCode         hash;
    int                     r;

    if (NULL == t) return GNUNET_OK;

    // FIXME
//     for (path = t->paths_head; path != NULL; path = t->paths_head) {
//         if(GNUNET_OK != destroy_path(t, path)) r = GNUNET_SYSERR;
//     }

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
    size_t                              size_needed;
    int                                 i;

    if (0 == size && NULL == buf) {
        // TODO retry? cancel?
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

#if LATER
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
    if (GNUNET_MESSAGE_TYPE_MESH_DATA_GO == ntohs(message->type)) {
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
    r = destroy_tunnel((struct MeshClient *) cls, (struct MeshTunnel *) value);
    return r;
}

#if LATER
/**
 * notify_client_connection_failure: notify a client that the connection to the
 * requested remote peer is not possible (for instance, no route found)
 * Function called when the socket is ready to queue more data."buf" will be
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
    struct MeshPath             *aux;
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
    if (NULL == peer_info->path) {
        p->in_use = 1;
        peer_info->path = p;
    } else {
        p->in_use = 0;
        aux = peer_info->path;
        while (NULL != aux->next) aux = aux->next;
        aux->next = p;
    }
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
               "MESH: client disconnected\n");
    c = clients;
    while (NULL != c) {
        if (c->handle == client) {
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "MESH: matching client found, cleaning\n");
            GNUNET_CONTAINER_multihashmap_iterate(c->tunnels,
                                                  &delete_tunnel_entry,
                                                  c);
            GNUNET_CONTAINER_multihashmap_destroy(c->tunnels);
            if(0 != c->app_counter) GNUNET_free (c->apps);
            if(0 != c->type_counter) GNUNET_free (c->types);
            next = c->next;
            GNUNET_free (c);
            c = next;
        } else {
            c = c->next;
        }
    }
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

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MESH: new client connected\n");
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
               "MESH:  client has %u+%u subscriptions\n",
               c->type_counter,
               c->app_counter);

    c->next = clients;
    clients = c;
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
    // FIXME: what if all 2^32 ID are taken?
    while (NULL != retrieve_tunnel_by_pi(myid, next_tid)) next_tid++;
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

    /* Ok, add peer to tunnel */
    peer_info = GNUNET_CONTAINER_multihashmap_get(peers,
                                                  &peer_msg->peer.hashPubKey);
    if (NULL == peer_info) {
        peer_info = (struct MeshPeerInfo *)
                    GNUNET_malloc(sizeof(struct MeshPeerInfo));
        GNUNET_CONTAINER_multihashmap_put(peers,
                            &peer_msg->peer.hashPubKey,
                            peer_info,
                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
        peer_info->id = GNUNET_PEER_intern(&peer_msg->peer);
        peer_info->state = MESH_PEER_SEARCHING;
    }

    t->peers_total++;
    /* FIXME insert */
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
    GNUNET_PEER_Id                      peer_id;

    /* Sanity check for client registration */
    if (NULL == (c = retrieve_client(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    peer_msg = (struct GNUNET_MESH_PeerControl *)message;
    /* Sanity check for message size */
    if (sizeof(struct GNUNET_MESH_PeerControl) != ntohs(peer_msg->header.size)) {
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
    peer_id = GNUNET_PEER_intern(&peer_msg->peer);

    /* FIXME Delete paths */
    /* FIXME Delete peer info */

    GNUNET_PEER_change_rc(peer_id, -1);

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
    struct GNUNET_MESH_Data                     *data_msg;
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

    /* Does client own tunnel? */
    if (t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* TODO */

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
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
    if (sizeof(struct GNUNET_MESH_PeerControl) != ntohs(data_msg->header.size)) {
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
    GNUNET_PEER_Id      pid;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer connected\n");
    pid = GNUNET_PEER_intern(peer);
    if (myid == pid) {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "     (self)\n");
    }
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer disconnected\n");
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
                "MESH shutting down\n");
    if (core_handle != NULL) {
        GNUNET_CORE_disconnect (core_handle);
        core_handle = NULL;
    }
    if (dht_handle != NULL) {
        GNUNET_DHT_disconnect (dht_handle);
        dht_handle = NULL;
    } 
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
                "MESH starting to run\n");
    GNUNET_SERVER_add_handlers (server, plugin_handlers);
    GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
    core_handle = GNUNET_CORE_connect (c,               /* Main configuration */
                            32,                                 /* queue size */
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

    /* Scheduled the task to clean up when shutdown is called */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &shutdown_task, NULL);

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
    return ret;
}
