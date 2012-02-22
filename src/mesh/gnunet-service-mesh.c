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
 * - GENERAL HELPERS
 * - PERIODIC FUNCTIONS
 * - MESH NETWORK HANDLER HELPERS
 * - MESH NETWORK HANDLES
 * - MESH LOCAL HANDLER HELPERS
 * - MESH LOCAL HANDLES
 * - MAIN FUNCTIONS (main & run)
 *
 * TODO:
 * - error reporting (CREATE/CHANGE/ADD/DEL?) -- new message!
 * - partial disconnect reporting -- same as error reporting?
 * - add vs create? change vs. keep-alive? same msg or different ones? -- thinking...
 * - speed requirement specification (change?) in mesh API -- API call
 * - add ping message
 * - relay corking down to core
 * - set ttl relative to tree depth
 * TODO END
 */

#include "platform.h"
#include "mesh.h"
#include "mesh_protocol.h"
#include "gnunet_dht_service.h"
#include "mesh_tunnel_tree.h"

/* TODO: move into configuration file */
#define REFRESH_PATH_TIME       GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    300)
#define APP_ANNOUNCE_TIME       GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    5)

#define ID_ANNOUNCE_TIME        GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    5)

#define UNACKNOWLEDGED_WAIT     GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    2)
#define DEFAULT_TTL     64

/* TODO END */

#define MESH_DEBUG_DHT GNUNET_YES
#define MESH_DEBUG_CONNECTION GNUNET_NO

#if MESH_DEBUG_CONNECTION
#define DEBUG_CONN(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)
#else
#define DEBUG_CONN(...)
#endif

#if MESH_DEBUG_DHT
#define DEBUG_DHT(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)
#else
#define DEBUG_DHT(...)
#endif

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/** FWD declaration */
struct MeshPeerInfo;


/**
 * Struct representing a piece of data being sent to other peers
 */
struct MeshData
{
  /** Tunnel it belongs to. */
  struct MeshTunnel *t;

  /** In case of a multicast, task to allow a client to send more data if
   * some neighbor is too slow. */
  GNUNET_SCHEDULER_TaskIdentifier *task;

  /** How many remaining neighbors we need to send this to. */
  unsigned int *reference_counter;

  /** Size of the data. */
  size_t data_len;

  /** Data itself */
  void *data;
};


/**
 * Struct containing all info possibly needed to build a package when called
 * back by core.
 */
struct MeshTransmissionDescriptor
{
    /** ID of the tunnel this packet travels in */
  struct MESH_TunnelID *origin;

    /** Who was this message being sent to */
  struct MeshPeerInfo *peer;

    /** Ultimate destination of the packet */
  GNUNET_PEER_Id destination;

    /** Which handler was used to request the transmission */
  unsigned int handler_n;

    /** Data descriptor */
  struct MeshData* mesh_data;
};


/**
 * Struct containing all information regarding a given peer
 */
struct MeshPeerInfo
{
    /**
     * ID of the peer
     */
  GNUNET_PEER_Id id;

    /**
     * Last time we heard from this peer
     */
  struct GNUNET_TIME_Absolute last_contact;

    /**
     * Number of attempts to reconnect so far
     */
  int n_reconnect_attempts;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_head;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_tail;

    /**
     * Handle to stop the DHT search for a path to this peer
     */
  struct GNUNET_DHT_GetHandle *dhtget;

    /**
     * Closure given to the DHT GET
     */
  struct MeshPathInfo *dhtgetcls;

    /**
     * Handles to stop queued transmissions for this peer
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit[CORE_QUEUE_SIZE];

    /**
     * Pointer to info stuctures used as cls for queued transmissions
     */
  void *infos[CORE_QUEUE_SIZE];

    /**
     * Type of message being in each transmission
     */
  uint16_t types[CORE_QUEUE_SIZE];

    /**
     * Array of tunnels this peer participates in
     * (most probably a small amount, therefore not a hashmap)
     * When the path to the peer changes, notify these tunnels to let them
     * re-adjust their path trees.
     */
  struct MeshTunnel **tunnels;

    /**
     * Number of tunnels this peers participates in
     */
  unsigned int ntunnels;
};


/**
 * Data scheduled to transmit (to local client or remote peer)
 */
struct MeshQueue
{
    /**
     * Double linked list
     */
  struct MeshQueue *next;
  struct MeshQueue *prev;

    /**
     * Target of the data (NULL if target is client)
     */
  struct MeshPeerInfo *peer;

    /**
     * Client to send the data to (NULL if target is peer)
     */
  struct MeshClient *client;

    /**
     * Size of the message to transmit
     */
  unsigned int size;

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
struct MESH_TunnelID
{
    /**
     * Node that owns the tunnel
     */
  GNUNET_PEER_Id oid;

    /**
     * Tunnel number to differentiate all the tunnels owned by the node oid
     * ( tid < GNUNET_MESH_LOCAL_TUNNEL_ID_CLI )
     */
  MESH_TunnelNumber tid;
};


struct MeshClient;              /* FWD declaration */

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
  struct MESH_TunnelID id;

    /**
     * Local tunnel number ( >= GNUNET_MESH_LOCAL_TUNNEL_ID_CLI or 0 )
     */
  MESH_TunnelNumber local_tid;

    /**
     * Local tunnel number for local destination clients (incoming number)
     * ( >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV or 0). All clients share the same
     * number.
     */
  MESH_TunnelNumber local_tid_dest;

    /**
     * ID of the last multicast packet seen/sent.
     */
  uint32_t mid;

    /**
     * Last time the tunnel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnel, indexed by PeerIdentity -> (MeshPeerInfo)
     * containing peers added by id or by type, not intermediate peers.
     */
  struct GNUNET_CONTAINER_MultiHashMap *peers;

    /**
     * Number of peers that are connected and potentially ready to receive data
     */
  unsigned int peers_ready;

    /**
     * Number of peers that have been added to the tunnel
     */
  unsigned int peers_total;

    /**
     * Client owner of the tunnel, if any
     */
  struct MeshClient *owner;

    /**
     * Clients that have been informed about the tunnel, if any
     */
  struct MeshClient **clients;

    /**
     * Number of elements in clients
     */
  unsigned int nclients;

    /**
     * Clients that have requested to leave the tunnel
     */
  struct MeshClient **ignore;

    /**
     * Number of elements in clients
     */
  unsigned int nignore;

    /**
     * Messages ready to transmit
     */
  struct MeshQueue *queue_head;
  struct MeshQueue *queue_tail;

  /**
   * Tunnel paths
   */
  struct MeshTunnelTree *tree;

  /**
   * Application type we are looking for in this tunnel
   */
  GNUNET_MESH_ApplicationType type;

    /**
     * Used to search peers offering a service
     */
  struct GNUNET_DHT_GetHandle *dht_get_type;

  /**
   * Task to keep the used paths alive
   */
  GNUNET_SCHEDULER_TaskIdentifier path_refresh_task;

  /**
   * Task to destroy the tunnel after timeout
   *
   * FIXME: merge the two? a tunnel will have either
   * a path refresh OR a timeout, never both!
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};


/**
 * Info needed to work with tunnel paths and peers
 */
struct MeshPathInfo
{
  /**
   * Tunnel
   */
  struct MeshTunnel *t;

  /**
   * Neighbouring peer to whom we send the packet to
   */
  struct MeshPeerInfo *peer;

  /**
   * Path itself
   */
  struct MeshPeerPath *path;

  /**
   * Position in peer's transmit queue
   */
  unsigned int pos;
};


/**
 * Struct containing information about a client of the service
 */
struct MeshClient
{
    /**
     * Linked list next
     */
  struct MeshClient *next;

    /**
     * Linked list prev
     */
  struct MeshClient *prev;

    /**
     * Tunnels that belong to this client, indexed by local id
     */
  struct GNUNET_CONTAINER_MultiHashMap *own_tunnels;

   /**
     * Tunnels this client has accepted, indexed by incoming local id
     */
  struct GNUNET_CONTAINER_MultiHashMap *incoming_tunnels;

   /**
     * Tunnels this client has rejected, indexed by incoming local id
     */
  struct GNUNET_CONTAINER_MultiHashMap *ignore_tunnels;
    /**
     * Handle to communicate with the client
     */
  struct GNUNET_SERVER_Client *handle;

    /**
     * Applications that this client has claimed to provide
     */
  struct GNUNET_CONTAINER_MultiHashMap *apps;

    /**
     * Messages that this client has declared interest in
     */
  struct GNUNET_CONTAINER_MultiHashMap *types;

    /**
     * Whether the client is active or shutting down (don't send confirmations
     * to a client that is shutting down.
     */
  int shutting_down;

    /**
     * ID of the client, mainly for debug messages
     */
  unsigned int id;

};



/******************************************************************************/
/************************      DEBUG FUNCTIONS     ****************************/
/******************************************************************************/

#if MESH_DEBUG
/**
 * GNUNET_SCHEDULER_Task for printing a message after some operation is done
 * @param cls string to print
 * @param tc task context
 */
static void
mesh_debug (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *s = cls;

  if (NULL != tc && GNUNET_SCHEDULER_REASON_SHUTDOWN == tc->reason)
  {
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s\n", s);
}
#endif

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/**
 * All the clients
 */
static struct MeshClient *clients;
static struct MeshClient *clients_tail;

/**
 * Tunnels known, indexed by MESH_TunnelID (MeshTunnel)
 */
static struct GNUNET_CONTAINER_MultiHashMap *tunnels;

/**
 * Tunnels incoming, indexed by MESH_TunnelNumber
 * (which is greater than GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
 */
static struct GNUNET_CONTAINER_MultiHashMap *incoming_tunnels;

/**
 * Peers known, indexed by PeerIdentity (MeshPeerInfo)
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/**
 * Handle to communicate with core
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Handle to communicate with transport
 */
// static struct GNUNET_TRANSPORT_Handle *transport_handle;

/**
 * Handle to use DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to server
 */
static struct GNUNET_SERVER_Handle *server_handle;

/**
 * Notification context, to send messages to local clients
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Local peer own ID (memory efficient handle)
 */
static GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value)
 */
static struct GNUNET_PeerIdentity my_full_id;

/**
 * Own private key
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Own public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Tunnel ID for the next created tunnel (global tunnel number)
 */
static MESH_TunnelNumber next_tid;

/**
 * Tunnel ID for the next incoming tunnel (local tunnel number)
 */
static MESH_TunnelNumber next_local_tid;

/**
 * All application types provided by this peer
 */
static struct GNUNET_CONTAINER_MultiHashMap *applications;

/**
 * All message types clients of this peer are interested in
 */
static struct GNUNET_CONTAINER_MultiHashMap *types;

/**
 * Task to periodically announce provided applications
 */
GNUNET_SCHEDULER_TaskIdentifier announce_applications_task;

/**
 * Task to periodically announce itself in the network
 */
GNUNET_SCHEDULER_TaskIdentifier announce_id_task;

/**
 * Next ID to assign to a client
 */
unsigned int next_client_id;



/******************************************************************************/
/************************         ITERATORS        ****************************/
/******************************************************************************/

/* FIXME move iterators here */


/******************************************************************************/
/************************    PERIODIC FUNCTIONS    ****************************/
/******************************************************************************/

/**
 * Announce iterator over for each application provided by the peer
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
announce_application (void *cls, const GNUNET_HashCode * key, void *value)
{
  /* FIXME are hashes in multihash map equal on all aquitectures? */
  GNUNET_DHT_put (dht_handle, key, 10U,
                  GNUNET_DHT_RO_RECORD_ROUTE |
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, GNUNET_BLOCK_TYPE_TEST,
                  sizeof (struct GNUNET_PeerIdentity),
                  (const char *) &my_full_id,
#if MESH_DEBUG
                  GNUNET_TIME_UNIT_FOREVER_ABS, GNUNET_TIME_UNIT_FOREVER_REL,
                  &mesh_debug, "DHT_put for app completed");
#else
                  GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                            APP_ANNOUNCE_TIME),
                  APP_ANNOUNCE_TIME, NULL, NULL);
#endif
  return GNUNET_OK;
}


/**
 * Periodically announce what applications are provided by local clients
 *
 * @param cls closure
 * @param tc task context
 */
static void
announce_applications (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
 
  DEBUG_DHT ("Starting PUT for apps\n");

  GNUNET_CONTAINER_multihashmap_iterate (applications, &announce_application,
                                         NULL);
  announce_applications_task =
      GNUNET_SCHEDULER_add_delayed (APP_ANNOUNCE_TIME, &announce_applications,
                                    cls);
  DEBUG_DHT ("Finished PUT for apps\n");

  return;
}


/**
 * Periodically announce self id in the DHT
 *
 * @param cls closure
 * @param tc task context
 */
static void
announce_id (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    announce_id_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  /* TODO
   * - Set data expiration in function of X
   * - Adapt X to churn
   */
  DEBUG_DHT ("DHT_put for ID %s started.\n", GNUNET_i2s (&my_full_id));

  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &my_full_id.hashPubKey,       /* Key to use */
                  10U,          /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,    /* DHT options */
                  GNUNET_BLOCK_TYPE_TEST,       /* Block type */
                  sizeof (my_full_id),  /* Size of the data */
                  (char *) &my_full_id, /* Data itself */
                  GNUNET_TIME_absolute_get_forever (),  /* Data expiration */
                  GNUNET_TIME_UNIT_FOREVER_REL, /* Retry time */
#if MESH_DEBUG_DHT
                  &mesh_debug, "DHT_put for id completed");
#else
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
#endif
  announce_id_task =
      GNUNET_SCHEDULER_add_delayed (ID_ANNOUNCE_TIME, &announce_id, cls);
}


/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data);


/******************************************************************************/
/******************      GENERAL HELPER FUNCTIONS      ************************/
/******************************************************************************/

/**
 * Search for a tunnel by global ID using full PeerIdentities
 *
 * @param oid owner of the tunnel
 * @param tid global tunnel number
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
tunnel_get (struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid);


/**
 * Delete an active client from the tunnel.
 * 
 * @param t Tunnel.
 * @param c Client.
 */
static void
tunnel_delete_active_client (struct MeshTunnel *t, const struct MeshClient *c);

/**
 * Notify a tunnel that a connection has broken that affects at least
 * some of its peers.
 *
 * @param t Tunnel affected.
 * @param p1 Peer that got disconnected from p2.
 * @param p2 Peer that got disconnected from p1.
 *
 * @return Short ID of the peer disconnected (either p1 or p2).
 *         0 if the tunnel remained unaffected.
 */
static GNUNET_PEER_Id
tunnel_notify_connection_broken (struct MeshTunnel *t, GNUNET_PEER_Id p1,
                                 GNUNET_PEER_Id p2);


/**
 * Check if client has registered with the service and has not disconnected
 *
 * @param client the client to check
 *
 * @return non-NULL if client exists in the global DLL
 */
static struct MeshClient *
client_get (struct GNUNET_SERVER_Client *client)
{
  struct MeshClient *c;

  c = clients;
  while (NULL != c)
  {
    if (c->handle == client)
      return c;
    c = c->next;
  }
  return NULL;
}


/**
 * Checks if a given client has subscribed to certain message type
 *
 * @param message_type Type of message to check
 * @param c Client to check
 *
 * @return GNUNET_YES or GNUNET_NO, depending on subscription status
 *
 * TODO inline?
 */
static int
client_is_subscribed (uint16_t message_type, struct MeshClient *c)
{
  GNUNET_HashCode hc;

  GNUNET_CRYPTO_hash (&message_type, sizeof (uint16_t), &hc);
  return GNUNET_CONTAINER_multihashmap_contains (c->types, &hc);
}


/**
 * Allow a client to send more data after transmitting a multicast message
 * which some neighbor has not yet accepted altough a reasonable time has
 * passed.
 *
 * @param cls Closure (DataDescriptor containing the task identifier)
 * @param tc Task Context
 * 
 * FIXME reference counter cshould be just int
 */
static void
client_allow_send (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshData *mdata = cls;

  if (GNUNET_SCHEDULER_REASON_SHUTDOWN == tc->reason)
    return;
  GNUNET_assert (NULL != mdata->reference_counter);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CLIENT ALLOW SEND DESPITE %u COPIES PENDING\n",
              *(mdata->reference_counter));
  *(mdata->task) = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SERVER_receive_done (mdata->t->owner->handle, GNUNET_OK);
}


/**
 * Check whether client wants traffic from a tunnel.
 *
 * @param c Client to check.
 * @param t Tunnel to be found.
 *
 * @return GNUNET_YES if client knows tunnel.
 * 
 * TODO look in client hashmap
 */
static int
client_wants_tunnel (struct MeshClient *c, struct MeshTunnel *t)
{
  unsigned int i;

  for (i = 0; i < t->nclients; i++)
    if (t->clients[i] == c)
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Check whether client has been informed about a tunnel.
 *
 * @param c Client to check.
 * @param t Tunnel to be found.
 *
 * @return GNUNET_YES if client knows tunnel.
 * 
 * TODO look in client hashmap
 */
static int
client_knows_tunnel (struct MeshClient *c, struct MeshTunnel *t)
{
  unsigned int i;

  for (i = 0; i < t->nignore; i++)
    if (t->ignore[i] == c)
      return GNUNET_YES;
  return client_wants_tunnel(c, t);
}


/**
 * Marks a client as uninterested in traffic from the tunnel, updating both
 * client and tunnel to reflect this.
 *
 * @param c Client that doesn't want traffic anymore.
 * @param t Tunnel which should be ignored.
 *
 * FIXME when to delete an incoming tunnel?
 */
static void
client_ignore_tunnel (struct MeshClient *c, struct MeshTunnel *t)
{
  GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash(&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (c->incoming_tunnels,
                                                      &hash, t));
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (c->ignore_tunnels, &hash, t,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  tunnel_delete_active_client (t, c);
  GNUNET_array_append (t->ignore, t->nignore, c);
}


/**
 * Deletes a tunnel from a client (either owner or destination). To be used on
 * tunnel destroy, otherwise, use client_ignore_tunnel.
 *
 * @param c Client whose tunnel to delete.
 * @param t Tunnel which should be deleted.
 */
static void
client_delete_tunnel (struct MeshClient *c, struct MeshTunnel *t)
{
  GNUNET_HashCode hash;

  if (c == t->owner)
  {
    GNUNET_CRYPTO_hash(&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (c->own_tunnels,
                                                         &hash,
                                                         t));
  }
  else
  {
    GNUNET_CRYPTO_hash(&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
    // FIXME XOR?
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (c->incoming_tunnels,
                                                         &hash,
                                                         t) ||
                   GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (c->ignore_tunnels,
                                                         &hash,
                                                         t));
  }
    
}


/**
 * Send the message to all clients that have subscribed to its type
 *
 * @param msg Pointer to the message itself
 * @param payload Pointer to the payload of the message.
 * @return number of clients this message was sent to
 */
static unsigned int
send_subscribed_clients (const struct GNUNET_MessageHeader *msg,
                         const struct GNUNET_MessageHeader *payload)
{
  struct GNUNET_PeerIdentity *oid;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber *tid;
  unsigned int count;
  uint16_t type;
  char cbuf[htons (msg->size)];

  type = ntohs (payload->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending to clients...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "message of type %u\n", type);

  memcpy (cbuf, msg, sizeof (cbuf));
  switch (htons (msg->type))
  {
    struct GNUNET_MESH_Unicast *uc;
    struct GNUNET_MESH_Multicast *mc;
    struct GNUNET_MESH_ToOrigin *to;

  case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    uc = (struct GNUNET_MESH_Unicast *) cbuf;
    tid = &uc->tid;
    oid = &uc->oid;
    break;
  case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
    mc = (struct GNUNET_MESH_Multicast *) cbuf;
    tid = &mc->tid;
    oid = &mc->oid;
    break;
  case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
    to = (struct GNUNET_MESH_ToOrigin *) cbuf;
    tid = &to->tid;
    oid = &to->oid;
    break;
  default:
    GNUNET_break (0);
    return 0;
  }
  t = tunnel_get (oid, ntohl (*tid));
  if (NULL == t)
  {
    GNUNET_break (0);
    return 0;
  }

  for (count = 0, c = clients; c != NULL; c = c->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   client %u\n", c->id);
    if (client_is_subscribed (type, c))
    {
      if (htons (msg->type) == GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN)
      {
        if (c != t->owner)
          continue;
        *tid = htonl (t->local_tid);
      }
      else
      {
        if (GNUNET_NO == client_knows_tunnel (c, t))
        {
          /* This client doesn't know the tunnel */
          struct GNUNET_MESH_TunnelNotification tmsg;
          GNUNET_HashCode hash;

          tmsg.header.size = htons (sizeof (tmsg));
          tmsg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
          GNUNET_PEER_resolve (t->id.oid, &tmsg.peer);
          tmsg.tunnel_id = htonl (t->local_tid_dest);
          GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                                      &tmsg.header, GNUNET_NO);
          GNUNET_array_append (t->clients, t->nclients, c);
          GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber),
                              &hash);
          GNUNET_break (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (
                                       c->incoming_tunnels, &hash, t,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
        }
        *tid = htonl (t->local_tid_dest);
      }

      /* Check if the client wants to get traffic from the tunnel */
      if (GNUNET_NO == client_wants_tunnel(c, t))
        continue;
      count++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "     sending\n");
      GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                                  (struct GNUNET_MessageHeader
                                                   *) cbuf, GNUNET_YES);
    }
  }
  return count;
}


/**
 * Notify the client that owns the tunnel that a peer has connected to it
 * (the requested path to it has been confirmed).
 *
 * @param t Tunnel whose owner to notify
 * @param id Short id of the peer that has connected
 */
static void
send_client_peer_connected (const struct MeshTunnel *t, const GNUNET_PEER_Id id)
{
  struct GNUNET_MESH_PeerControl pc;

  pc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD);
  pc.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
  pc.tunnel_id = htonl (t->local_tid);
  GNUNET_PEER_resolve (id, &pc.peer);
  GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle, &pc.header,
                                              GNUNET_NO);
}


/**
 * Notify all clients (not depending on registration status) that the incoming
 * tunnel is no longer valid.
 *
 * @param t Tunnel that was destroyed.
 */
static void
send_clients_tunnel_destroy (struct MeshTunnel *t)
{
  struct GNUNET_MESH_TunnelMessage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.tunnel_id = htonl (t->local_tid_dest);
  GNUNET_SERVER_notification_context_broadcast (nc, &msg.header, GNUNET_NO);
}


/**
 * Notify clients of tunnel disconnections, if needed.
 * In case the origin disconnects, the destination clients get a tunnel destroy
 * notification. If the last destination disconnects (only one remaining client
 * in tunnel), the origin gets a (local ID) peer disconnected.
 * Note that the function must be called BEFORE removing the client from
 * the tunnel.
 *
 * @param t Tunnel that was destroyed.
 * @param c Client that disconnected.
 */
static void
send_client_tunnel_disconnect (struct MeshTunnel *t, struct MeshClient *c)
{
  unsigned int i;

  if (c == t->owner)
  {
    struct GNUNET_MESH_TunnelMessage msg;

    msg.header.size = htons (sizeof (msg));
    msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
    msg.tunnel_id = htonl (t->local_tid_dest);
    for (i = 0; i < t->nclients; i++)
      GNUNET_SERVER_notification_context_unicast (nc, t->clients[i]->handle,
                                                  &msg.header, GNUNET_NO);
  }
  // FIXME when to disconnect an incoming tunnel?
  else if (1 == t->nclients && NULL != t->owner)
  {
    struct GNUNET_MESH_PeerControl msg;

    msg.header.size = htons (sizeof (msg));
    msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
    msg.tunnel_id = htonl (t->local_tid);
    msg.peer = my_full_id;
    GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle,
                                                &msg.header, GNUNET_NO);
  }
}


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
send_core_create_path (void *cls, size_t size, void *buf);


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (data itself)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 *
 * @return number of bytes written to buf
 */
static size_t
send_core_data_multicast (void *cls, size_t size, void *buf);


/**
 * Decrements the reference counter and frees all resources if needed
 *
 * @param mesh_data Data Descriptor used in a multicast message.
 *                  Freed no longer needed (last message).
 */
static void
data_descriptor_decrement_multicast (struct MeshData *mesh_data)
{
  /* Make sure it's a multicast packet */
  GNUNET_assert (NULL != mesh_data->reference_counter);

  if (0 == --(*(mesh_data->reference_counter)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Last copy!\n");
    if (NULL != mesh_data->task)
    {
      if (GNUNET_SCHEDULER_NO_TASK != *(mesh_data->task))
      {
        GNUNET_SCHEDULER_cancel (*(mesh_data->task));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " notifying client...\n");
        GNUNET_SERVER_receive_done (mesh_data->t->owner->handle, GNUNET_OK);
      }
      GNUNET_free (mesh_data->task);
    }
    GNUNET_free (mesh_data->reference_counter);
    GNUNET_free (mesh_data->data);
    GNUNET_free (mesh_data);
  }
}


/**
 * Cancel a core transmission that was already requested and free all resources
 * associated to the request.
 *
 * @param peer PeeInfo of the peer whose transmission is cancelled.
 * @param i Position of the transmission to be cancelled.
 */
static void
peer_info_cancel_transmission (struct MeshPeerInfo *peer, unsigned int i)
{
  if (NULL != peer->core_transmit[i])
  {
    struct MeshTransmissionDescriptor *dd;
    struct MeshPathInfo *path_info;

#if MESH_DEBUG
    {
      struct GNUNET_PeerIdentity id;

      GNUNET_PEER_resolve (peer->id, &id);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "  Cancelling data transmission at %s [%u]\n",
                  GNUNET_i2s (&id), i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   message type %u\n",
                  peer->types[i]);
    }
#endif
    /* TODO: notify that tranmission has failed */
    switch (peer->types[i])
    {
    case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type payload\n");
      dd = peer->infos[i];
      data_descriptor_decrement_multicast (dd->mesh_data);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type create path\n");
      path_info = peer->infos[i];
      path_destroy (path_info->path);
      break;
    default:
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type unknown!\n");
    }
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit[i]);
    peer->core_transmit[i] = NULL;
    GNUNET_free (peer->infos[i]);
  }
}


/**
 * Get a unused CORE slot to transmit a message to a peer. If all the slots
 * are used, cancel one and return it's position.
 *
 * @param peer PeerInfo of the neighbor we want to transmit to.
 *
 * @return The index of an available slot to transmit to the neighbor.
 */
static unsigned int
peer_info_transmit_slot (struct MeshPeerInfo *peer)
{
  unsigned int i;

  for (i = 0; peer->core_transmit[i]; i++)
  {
    if (i == (CORE_QUEUE_SIZE - 1))
    {
      /* All positions are taken! Overwriting! */
      GNUNET_break (0);
      peer_info_cancel_transmission (peer, 0);
      return 0;
    }
  }
  return i;
}


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropiate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_info_get (const struct GNUNET_PeerIdentity *peer)
{
  struct MeshPeerInfo *peer_info;

  peer_info = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == peer_info)
  {
    peer_info =
        (struct MeshPeerInfo *) GNUNET_malloc (sizeof (struct MeshPeerInfo));
    GNUNET_CONTAINER_multihashmap_put (peers, &peer->hashPubKey, peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    peer_info->id = GNUNET_PEER_intern (peer);
  }

  return peer_info;
}


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropiate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_info_get_short (const GNUNET_PEER_Id peer)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer, &id);
  return peer_info_get (&id);
}


/**
 * Iterator to remove the tunnel from the list of tunnels a peer participates
 * in.
 *
 * @param cls Closure (tunnel info)
 * @param key GNUNET_PeerIdentity of the peer (unused)
 * @param value PeerInfo of the peer
 *
 * @return always GNUNET_YES, to keep iterating
 */
static int
peer_info_delete_tunnel (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer = value;
  unsigned int i;

  for (i = 0; i < peer->ntunnels; i++)
  {
    if (0 ==
        memcmp (&peer->tunnels[i]->id, &t->id, sizeof (struct MESH_TunnelID)))
    {
      peer->ntunnels--;
      peer->tunnels[i] = peer->tunnels[peer->ntunnels];
      peer->tunnels = GNUNET_realloc (peer->tunnels, peer->ntunnels);
      return GNUNET_YES;
    }
  }
  return GNUNET_YES;
}


/**
  * Core callback to write a
  *
  * @param cls Closure (MeshTransmissionDescriptor with data in "data" member).
  * @param size Number of bytes available in buf.
  * @param buf Where the to write the message.
  *
  * @return number of bytes written to buf
  */
static size_t
send_core_data_raw (void *cls, size_t size, void *buf)
{
  struct MeshTransmissionDescriptor *info = cls;
  struct GNUNET_MessageHeader *msg;
  size_t total_size;

  GNUNET_assert (NULL != info);
  GNUNET_assert (NULL != info->mesh_data);
  msg = (struct GNUNET_MessageHeader *) info->mesh_data->data;
  total_size = ntohs (msg->size);

  if (total_size > size)
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (info->peer->id, &id);
    info->peer->core_transmit[info->handler_n] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 100,
                                           GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                           size, &send_core_data_raw, info);
    return 0;
  }
  info->peer->core_transmit[info->handler_n] = NULL;
  memcpy (buf, msg, total_size);
  GNUNET_free (info->mesh_data);
  GNUNET_free (info);
  return total_size;
}


/**
 * Sends an already built message to a peer, properly registrating
 * all used resources.
 *
 * @param message Message to send. Fucntion makes a copy of it.
 * @param peer Short ID of the neighbor whom to send the message.
 *
 * FIXME tunnel?
 */
static void
send_message (const struct GNUNET_MessageHeader *message,
              const struct GNUNET_PeerIdentity *peer)
{
  struct MeshTransmissionDescriptor *info;
  struct MeshPeerInfo *neighbor;
  struct MeshPeerPath *p;
  unsigned int i;
  size_t size;

//   GNUNET_TRANSPORT_try_connect();

  size = ntohs (message->size);
  info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));
  info->mesh_data = GNUNET_malloc (sizeof (struct MeshData));
  info->mesh_data->data = GNUNET_malloc (size);
  memcpy (info->mesh_data->data, message, size);
  info->mesh_data->data_len = size;
  neighbor = peer_info_get (peer);
  for (p = neighbor->path_head; NULL != p; p = p->next)
  {
    if (2 == p->length)
    {
      break;
    }
  }
  if (NULL == p)
  {
    GNUNET_break (0);
    GNUNET_free (info->mesh_data->data);
    GNUNET_free (info->mesh_data);
    GNUNET_free (info);
    return;
  }
  i = peer_info_transmit_slot (neighbor);
  info->handler_n = i;
  info->peer = neighbor;
  neighbor->types[i] = GNUNET_MESSAGE_TYPE_MESH_UNICAST;
  neighbor->infos[i] = info;
  neighbor->core_transmit[i] =
      GNUNET_CORE_notify_transmit_ready (core_handle, 0, 100,
                                         GNUNET_TIME_UNIT_FOREVER_REL, peer,
                                         size, &send_core_data_raw, info);

}


/**
 * Sends a CREATE PATH message for a path to a peer, properly registrating
 * all used resources.
 *
 * @param peer PeerInfo of the final peer for whom this path is being created.
 * @param p Path itself.
 * @param t Tunnel for which the path is created.
 */
static void
send_create_path (struct MeshPeerInfo *peer, struct MeshPeerPath *p,
                  struct MeshTunnel *t)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPathInfo *path_info;
  struct MeshPeerInfo *neighbor;
  unsigned int i;

  if (NULL == p)
  {
    p = tree_get_path_to_peer (t->tree, peer->id);
    if (NULL == p)
    {
      GNUNET_break (0);
      return;
    }
  }
  for (i = 0; i < p->length; i++)
  {
    if (p->peers[i] == myid)
      break;
  }
  if (i >= p->length - 1)
  {
    path_destroy (p);
    GNUNET_break (0);
    return;
  }
  GNUNET_PEER_resolve (p->peers[i + 1], &id);

  path_info = GNUNET_malloc (sizeof (struct MeshPathInfo));
  path_info->path = p;
  path_info->t = t;
  neighbor = peer_info_get (&id);
  path_info->peer = neighbor;
  path_info->pos = peer_info_transmit_slot (neighbor);
  neighbor->types[path_info->pos] = GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE;
  neighbor->infos[path_info->pos] = path_info;
  neighbor->core_transmit[path_info->pos] =
    GNUNET_CORE_notify_transmit_ready (core_handle,     /* handle */
                                       0,       /* cork */
                                       0,       /* priority */
                                       GNUNET_TIME_UNIT_FOREVER_REL,    /* timeout */
                                       &id,     /* target */
                                       sizeof (struct GNUNET_MESH_ManipulatePath) +
                                         (p->length * sizeof (struct GNUNET_PeerIdentity)),  /*size */
                                       &send_core_create_path,  /* callback */
                                       path_info);      /* cls */
}


/**
 * Sends a DESTROY PATH message to free resources for a path in a tunnel
 *
 * @param t Tunnel whose path to destroy.
 * @param destination Short ID of the peer to whom the path to destroy.
 */
static void
send_destroy_path (struct MeshTunnel *t, GNUNET_PEER_Id destination)
{
  struct MeshPeerPath *p;
  size_t size;

  p = tree_get_path_to_peer (t->tree, destination);
  if (NULL == p)
  {
    GNUNET_break (0);
    return;
  }
  size = sizeof (struct GNUNET_MESH_ManipulatePath);
  size += p->length * sizeof (struct GNUNET_PeerIdentity);
  {
    struct GNUNET_MESH_ManipulatePath *msg;
    struct GNUNET_PeerIdentity *pi;
    char cbuf[size];
    unsigned int i;

    msg = (struct GNUNET_MESH_ManipulatePath *) cbuf;
    msg->header.size = htons (size);
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY);
    msg->tid = htonl (t->id.tid);
    pi = (struct GNUNET_PeerIdentity *) &msg[1];
    for (i = 0; i < p->length; i++)
    {
      GNUNET_PEER_resolve (p->peers[i], &pi[i]);
    }
    send_message (&msg->header, tree_get_first_hop (t->tree, destination));
  }
  path_destroy (p);
}


/**
 * Try to establish a new connection to this peer.
 * Use the best path for the given tunnel.
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE PATH towards it.
 *
 * @param peer PeerInfo of the peer.
 * @param t Tunnel for which to create the path, if possible.
 */
static void
peer_info_connect (struct MeshPeerInfo *peer, struct MeshTunnel *t)
{
  struct MeshPeerPath *p;
  struct MeshPathInfo *path_info;

  if (NULL != peer->path_head)
  {
    p = tree_get_path_to_peer (t->tree, peer->id);
    if (NULL == p)
    {
      GNUNET_break (0);
      return;
    }

    // FIXME always send create path to self
    if (p->length > 1)
    {
      send_create_path (peer, p, t);
    }
    else
    {
      GNUNET_HashCode hash;

      path_destroy (p);
      send_client_peer_connected (t, myid);
      t->local_tid_dest = next_local_tid++;
      GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber),
                          &hash);
      if (GNUNET_OK !=
          GNUNET_CONTAINER_multihashmap_put (incoming_tunnels, &hash, t,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      {
        GNUNET_break (0);
        return;
      }
    }
  }
  else if (NULL == peer->dhtget)
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer->id, &id);
    path_info = GNUNET_malloc (sizeof (struct MeshPathInfo));
    path_info->peer = peer;
    path_info->t = t;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", GNUNET_i2s (&id));
    peer->dhtgetcls = path_info;
    peer->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                         GNUNET_TIME_UNIT_FOREVER_REL,  /* timeout */
                                         GNUNET_BLOCK_TYPE_TEST,        /* type */
                                         &id.hashPubKey,        /* key to search */
                                         10U,     /* replication level */
                                         GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL,       /* xquery */
                                         0,     /* xquery bits */
                                         &dht_get_id_handler, path_info);
  }
  /* Otherwise, there is no path but the DHT get is already started. */
}


/**
 * Task to delay the connection of a peer
 *
 * @param cls Closure (path info with tunnel and peer to connect).
 *            Will be free'd on exection.
 * @param tc TaskContext
 */
static void
peer_info_connect_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshPathInfo *path_info = cls;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free (cls);
    return;
  }
  peer_info_connect (path_info->peer, path_info->t);
  GNUNET_free (cls);
}


/**
 * Destroy the peer_info and free any allocated resources linked to it
 *
 * @param pi The peer_info to destroy.
 *
 * @return GNUNET_OK on success
 */
static int
peer_info_destroy (struct MeshPeerInfo *pi)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPeerPath *p;
  struct MeshPeerPath *nextp;
  unsigned int i;

  GNUNET_PEER_resolve (pi->id, &id);
  GNUNET_PEER_change_rc (pi->id, -1);

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_remove (peers, &id.hashPubKey, pi))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "removing peer %s, not in hashmap\n", GNUNET_i2s (&id));
  }
  if (NULL != pi->dhtget)
  {
    GNUNET_DHT_get_stop (pi->dhtget);
    GNUNET_free (pi->dhtgetcls);
  }
  for (i = 0; i < CORE_QUEUE_SIZE; i++)
  {
    peer_info_cancel_transmission (pi, i);
  }
  p = pi->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (pi->path_head, pi->path_tail, p);
    path_destroy (p);
    p = nextp;
  }
  GNUNET_free (pi);
  return GNUNET_OK;
}


/**
 * Remove all paths that rely on a direct connection between p1 and p2
 * from the peer itself and notify all tunnels about it.
 *
 * @param peer PeerInfo of affected peer.
 * @param p1 GNUNET_PEER_Id of one peer.
 * @param p2 GNUNET_PEER_Id of another peer that was connected to the first and
 *           no longer is.
 *
 * TODO: optimize (see below)
 */
static void
peer_info_remove_path (struct MeshPeerInfo *peer, GNUNET_PEER_Id p1,
                       GNUNET_PEER_Id p2)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *aux;
  struct MeshPeerInfo *peer_d;
  GNUNET_PEER_Id d;
  unsigned int destroyed;
  unsigned int best;
  unsigned int cost;
  unsigned int i;

  destroyed = 0;
  p = peer->path_head;
  while (NULL != p)
  {
    aux = p->next;
    for (i = 0; i < (p->length - 1); i++)
    {
      if ((p->peers[i] == p1 && p->peers[i + 1] == p2) ||
          (p->peers[i] == p2 && p->peers[i + 1] == p1))
      {
        GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, p);
        path_destroy (p);
        destroyed++;
        break;
      }
    }
    p = aux;
  }
  if (0 == destroyed)
    return;

  for (i = 0; i < peer->ntunnels; i++)
  {
    d = tunnel_notify_connection_broken (peer->tunnels[i], p1, p2);
    if (0 == d)
      continue;
    /* TODO
     * Problem: one or more peers have been deleted from the tunnel tree.
     * We don't know who they are to try to add them again.
     * We need to try to find a new path for each of the disconnected peers.
     * Some of them might already have a path to reach them that does not
     * involve p1 and p2. Adding all anew might render in a better tree than
     * the trivial immediate fix.
     *
     * Trivial immiediate fix: try to reconnect to the disconnected node. All
     * its children will be reachable trough him.
     */
    peer_d = peer_info_get_short (d);
    best = UINT_MAX;
    aux = NULL;
    for (p = peer_d->path_head; NULL != p; p = p->next)
    {
      if ((cost = tree_get_path_cost (peer->tunnels[i]->tree, p)) < best)
      {
        best = cost;
        aux = p;
      }
    }
    if (NULL != aux)
    {
      /* No callback, as peer will be already disconnected and a connection
       * scheduled by tunnel_notify_connection_broken.
       */
      tree_add_path (peer->tunnels[i]->tree, aux, NULL, NULL);
    }
    else
    {
      peer_info_connect (peer_d, peer->tunnels[i]);
    }
  }
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 * @param trusted Do we trust that this path is real?
 */
void
peer_info_add_path (struct MeshPeerInfo *peer_info, struct MeshPeerPath *path,
                    int trusted)
{
  struct MeshPeerPath *aux;
  unsigned int l;
  unsigned int l2;

  if ((NULL == peer_info) || (NULL == path))
  {
    GNUNET_break (0);
    path_destroy (path);
    return;
  }
  if (path->peers[path->length - 1] != peer_info->id)
  {
    GNUNET_break (0);
    path_destroy (path);
    return;
  }
  if (path->length <= 2 && GNUNET_NO == trusted)
  {
    /* Only allow CORE to tell us about direct paths */
    path_destroy (path);
    return;
  }
  GNUNET_assert (peer_info->id == path->peers[path->length - 1]);
  for (l = 1; l < path->length; l++)
  {
    if (path->peers[l] == myid)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shortening path by %u\n", l);
      for (l2 = 0; l2 < path->length - l; l2++)
      {
        path->peers[l2] = path->peers[l + l2];
      }
      path->length -= l;
      l = 1;
      path->peers =
          GNUNET_realloc (path->peers, path->length * sizeof (GNUNET_PEER_Id));
    }
  }
#if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer_info->id, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "adding path [%u] to peer %s\n",
                path->length, GNUNET_i2s (&id));
  }
#endif
  l = path_get_length (path);
  if (0 == l)
  {
    GNUNET_free (path);
    return;
  }

  GNUNET_assert (peer_info->id == path->peers[path->length - 1]);
  for (aux = peer_info->path_head; aux != NULL; aux = aux->next)
  {
    l2 = path_get_length (aux);
    if (l2 > l)
    {
      GNUNET_CONTAINER_DLL_insert_before (peer_info->path_head,
                                          peer_info->path_tail, aux, path);
      return;
    }
    else
    {
      if (l2 == l && memcmp (path->peers, aux->peers, l) == 0)
      {
        path_destroy (path);
        return;
      }
    }
  }
  GNUNET_CONTAINER_DLL_insert_tail (peer_info->path_head, peer_info->path_tail,
                                    path);
  return;
}


/**
 * Add the path to the origin peer and update the path used to reach it in case
 * this is the shortest.
 * The path is given in peer_info -> destination, therefore we turn the path
 * upside down first.
 *
 * @param peer_info Peer to add the path to, being the origin of the path.
 * @param path New path to add after being inversed.
 * @param trusted Do we trust that this path is real?
 */
static void
peer_info_add_path_to_origin (struct MeshPeerInfo *peer_info,
                              struct MeshPeerPath *path, int trusted)
{
  path_invert (path);
  peer_info_add_path (peer_info, path, trusted);
}


/**
 * Build a PeerPath from the paths returned from the DHT, reversing the paths
 * to obtain a local peer -> destination path and interning the peer ids.
 *
 * @return Newly allocated and created path
 */
static struct MeshPeerPath *
path_build_from_dht (const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  struct MeshPeerPath *p;
  GNUNET_PEER_Id id;
  int i;

  p = path_new (1);
  p->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  i = get_path_length;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   GET has %d hops.\n", i);
  for (i--; i >= 0; i--)
  {
    id = GNUNET_PEER_intern (&get_path[i]);
    if (p->length > 0 && id == p->peers[p->length - 1])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Optimizing 1 hop out.\n");
      GNUNET_PEER_change_rc (id, -1);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Adding from GET: %s.\n",
                  GNUNET_i2s (&get_path[i]));
      p->length++;
      p->peers = GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * p->length);
      p->peers[p->length - 1] = id;
    }
  }
  i = put_path_length;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   PUT has %d hops.\n", i);
  for (i--; i >= 0; i--)
  {
    id = GNUNET_PEER_intern (&put_path[i]);
    if (id == myid)
    {
      /* PUT path went through us, so discard the path up until now and start
       * from here to get a much shorter (and loop-free) path.
       */
      path_destroy (p);
      p = path_new (0);
    }
    if (p->length > 0 && id == p->peers[p->length - 1])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Optimizing 1 hop out.\n");
      GNUNET_PEER_change_rc (id, -1);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Adding from PUT: %s.\n",
                  GNUNET_i2s (&put_path[i]));
      p->length++;
      p->peers = GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * p->length);
      p->peers[p->length - 1] = id;
    }
  }
#if MESH_DEBUG
  if (get_path_length > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (first of GET: %s)\n",
                GNUNET_i2s (&get_path[0]));
  if (put_path_length > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (first of PUT: %s)\n",
                GNUNET_i2s (&put_path[0]));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   In total: %d hops\n",
              p->length);
  for (i = 0; i < p->length; i++)
  {
    struct GNUNET_PeerIdentity peer_id;

    GNUNET_PEER_resolve (p->peers[i], &peer_id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "       %u: %s\n", p->peers[i],
                GNUNET_i2s (&peer_id));
  }
#endif
  return p;
}


/**
 * Adds a path to the peer_infos of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not. FIXME use
 */
static void
path_add_to_peers (struct MeshPeerPath *p, int confirmed)
{
  unsigned int i;

  /* TODO: invert and add */
  for (i = 0; i < p->length && p->peers[i] != myid; i++) /* skip'em */ ;
  for (i++; i < p->length; i++)
  {
    struct MeshPeerInfo *aux;
    struct MeshPeerPath *copy;

    aux = peer_info_get_short (p->peers[i]);
    copy = path_duplicate (p);
    copy->length = i + 1;
    peer_info_add_path (aux, copy, GNUNET_NO);
  }
}


/**
 * Send keepalive packets for a peer
 *
 * @param cls Closure (tunnel for which to send the keepalive).
 * @param tc Notification context.
 *
 * TODO: implement explicit multicast keepalive?
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Search for a tunnel among the incoming tunnels
 *
 * @param tid the local id of the tunnel
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
tunnel_get_incoming (MESH_TunnelNumber tid)
{
  GNUNET_HashCode hash;

  GNUNET_assert (tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV);
  GNUNET_CRYPTO_hash (&tid, sizeof (MESH_TunnelNumber), &hash);
  return GNUNET_CONTAINER_multihashmap_get (incoming_tunnels, &hash);
}


/**
 * Search for a tunnel among the tunnels for a client
 *
 * @param c the client whose tunnels to search in
 * @param tid the local id of the tunnel
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
tunnel_get_by_local_id (struct MeshClient *c, MESH_TunnelNumber tid)
{
  if (tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    return tunnel_get_incoming (tid);
  }
  else
  {
    GNUNET_HashCode hash;

    GNUNET_CRYPTO_hash (&tid, sizeof (MESH_TunnelNumber), &hash);
    return GNUNET_CONTAINER_multihashmap_get (c->own_tunnels, &hash);
  }
}


/**
 * Search for a tunnel by global ID using PEER_ID
 *
 * @param pi owner of the tunnel
 * @param tid global tunnel number
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
tunnel_get_by_pi (GNUNET_PEER_Id pi, MESH_TunnelNumber tid)
{
  struct MESH_TunnelID id;
  GNUNET_HashCode hash;

  id.oid = pi;
  id.tid = tid;

  GNUNET_CRYPTO_hash (&id, sizeof (struct MESH_TunnelID), &hash);
  return GNUNET_CONTAINER_multihashmap_get (tunnels, &hash);
}


/**
 * Search for a tunnel by global ID using full PeerIdentities
 *
 * @param oid owner of the tunnel
 * @param tid global tunnel number
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshTunnel *
tunnel_get (struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid)
{
  return tunnel_get_by_pi (GNUNET_PEER_search (oid), tid);
}


/**
 * Delete an active client from the tunnel.
 * 
 * @param t Tunnel.
 * @param c Client.
 */
static void
tunnel_delete_active_client (struct MeshTunnel *t, const struct MeshClient *c)
{
  unsigned int i;

  for (i = 0; i < t->nclients; i++)
  {
    if (t->clients[i] == c)
    {
      t->clients[i] = t->clients[t->nclients - 1];
      GNUNET_array_grow (t->clients, t->nclients, t->nclients - 1);
      break;
    }
  }
}


/**
 * Delete an ignored client from the tunnel.
 * 
 * @param t Tunnel.
 * @param c Client.
 */
static void
tunnel_delete_ignored_client (struct MeshTunnel *t, const struct MeshClient *c)
{
  unsigned int i;

  for (i = 0; i < t->nignore; i++)
  {
    if (t->ignore[i] == c)
    {
      t->ignore[i] = t->ignore[t->nignore - 1];
      GNUNET_array_grow (t->ignore, t->nignore, t->nignore - 1);
      break;
    }
  }
}


/**
 * Delete a client from the tunnel. It should be only done on
 * client disconnection, otherwise use client_ignore_tunnel.
 * 
 * @param t Tunnel.
 * @param c Client.
 */
static void
tunnel_delete_client (struct MeshTunnel *t, const struct MeshClient *c)
{
  tunnel_delete_ignored_client (t, c);
  tunnel_delete_active_client (t, c);
}


/**
 * Callback used to notify a client owner of a tunnel that a peer has
 * disconnected, most likely because of a path change.
 *
 * @param cls Closure (tunnel this notification is about).
 * @param peer_id Short ID of disconnected peer.
 */
void
notify_peer_disconnected (void *cls, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer;
  struct MeshPathInfo *path_info;

  if (NULL != t->owner && NULL != nc)
  {
    struct GNUNET_MESH_PeerControl msg;

    msg.header.size = htons (sizeof (msg));
    msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
    msg.tunnel_id = htonl (t->local_tid);
    GNUNET_PEER_resolve (peer_id, &msg.peer);
    GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle,
                                                &msg.header, GNUNET_NO);
  }
  peer = peer_info_get_short (peer_id);
  path_info = GNUNET_malloc (sizeof (struct MeshPathInfo));
  path_info->peer = peer;
  path_info->t = t;
  GNUNET_SCHEDULER_add_now (&peer_info_connect_task, path_info);
}


/**
 * Add a peer to a tunnel, accomodating paths accordingly and initializing all
 * needed rescources.
 * If peer already exists, reevaluate shortest path and change if different.
 *
 * @param t Tunnel we want to add a new peer to
 * @param peer PeerInfo of the peer being added
 *
 */
static void
tunnel_add_peer (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPeerPath *best_p;
  struct MeshPeerPath *p;
  unsigned int best_cost;
  unsigned int cost;

  GNUNET_PEER_resolve (peer->id, &id);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (t->peers, &id.hashPubKey))
  {
    t->peers_total++;
    GNUNET_array_append (peer->tunnels, peer->ntunnels, t);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (t->peers, &id.hashPubKey,
                                                      peer,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  }

  if (NULL != (p = peer->path_head))
  {
    best_p = p;
    best_cost = tree_get_path_cost (t->tree, p);
    while (NULL != p)
    {
      if ((cost = tree_get_path_cost (t->tree, p)) < best_cost)
      {
        best_cost = cost;
        best_p = p;
      }
      p = p->next;
    }
    tree_add_path (t->tree, best_p, &notify_peer_disconnected, t);
    if (GNUNET_SCHEDULER_NO_TASK == t->path_refresh_task)
      t->path_refresh_task =
          GNUNET_SCHEDULER_add_delayed (REFRESH_PATH_TIME, &path_refresh, t);
  }
  else
  {
    /* Start a DHT get */
    peer_info_connect (peer, t);
  }
}

/**
 * Add a path to a tunnel which we don't own, just to remember the next hop.
 * If destination node was already in the tunnel, the first hop information
 * will be replaced with the new path.
 *
 * @param t Tunnel we want to add a new peer to
 * @param p Path to add
 * @param own_pos Position of local node in path.
 *
 */
static void
tunnel_add_path (struct MeshTunnel *t, struct MeshPeerPath *p,
                 unsigned int own_pos)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_assert (0 != own_pos);
  tree_add_path (t->tree, p, NULL, NULL);
  if (own_pos < p->length - 1)
  {
    GNUNET_PEER_resolve (p->peers[own_pos + 1], &id);
    tree_update_first_hops (t->tree, myid, &id);
  }
}


/**
 * Notifies a tunnel that a connection has broken that affects at least
 * some of its peers. Sends a notification towards the root of the tree.
 * In case the peer is the owner of the tree, notifies the client that owns
 * the tunnel and tries to reconnect.
 *
 * @param t Tunnel affected.
 * @param p1 Peer that got disconnected from p2.
 * @param p2 Peer that got disconnected from p1.
 *
 * @return Short ID of the peer disconnected (either p1 or p2).
 *         0 if the tunnel remained unaffected.
 */
static GNUNET_PEER_Id
tunnel_notify_connection_broken (struct MeshTunnel *t, GNUNET_PEER_Id p1,
                                 GNUNET_PEER_Id p2)
{
  GNUNET_PEER_Id pid;

  pid =
      tree_notify_connection_broken (t->tree, p1, p2, &notify_peer_disconnected,
                                     t);
  if (myid != p1 && myid != p2)
  {
    return pid;
  }
  if (pid != myid)
  {
    if (tree_get_predecessor (t->tree) != 0)
    {
      /* We are the peer still connected, notify owner of the disconnection. */
      struct GNUNET_MESH_PathBroken msg;
      struct GNUNET_PeerIdentity neighbor;

      msg.header.size = htons (sizeof (msg));
      msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN);
      GNUNET_PEER_resolve (t->id.oid, &msg.oid);
      msg.tid = htonl (t->id.tid);
      msg.peer1 = my_full_id;
      GNUNET_PEER_resolve (pid, &msg.peer2);
      GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &neighbor);
      send_message (&msg.header, &neighbor);
    }
  }
  return pid;
}


/**
 * Send a multicast packet to a neighbor.
 *
 * @param cls Closure (Info about the multicast packet)
 * @param neighbor_id Short ID of the neighbor to send the packet to.
 */
static void
tunnel_send_multicast_iterator (void *cls, GNUNET_PEER_Id neighbor_id)
{
  struct MeshData *mdata = cls;
  struct MeshTransmissionDescriptor *info;
  struct GNUNET_PeerIdentity neighbor;
  unsigned int i;

  info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));

  info->mesh_data = mdata;
  (*(mdata->reference_counter)) ++;
  info->destination = neighbor_id;
  GNUNET_PEER_resolve (neighbor_id, &neighbor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   sending to %s...\n",
              GNUNET_i2s (&neighbor));
  info->peer = peer_info_get (&neighbor);
  GNUNET_assert (NULL != info->peer);
  i = peer_info_transmit_slot (info->peer);
  info->handler_n = i;
  info->peer->infos[i] = info;
  info->peer->types[i] = GNUNET_MESSAGE_TYPE_MESH_MULTICAST;
  info->peer->core_transmit[i] =
      GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         &neighbor, info->mesh_data->data_len,
                                         &send_core_data_multicast, info);
}

/**
 * Send a message in a tunnel in multicast, sending a copy to each child node
 * down the local one in the tunnel tree.
 *
 * @param t Tunnel in which to send the data.
 * @param msg Message to be sent.
 * @param internal Has the service generated this message?
 */
static void
tunnel_send_multicast (struct MeshTunnel *t,
                       const struct GNUNET_MessageHeader *msg,
                       int internal)
{
  struct MeshData *mdata;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " sending a multicast packet...\n");
  mdata = GNUNET_malloc (sizeof (struct MeshData));
  mdata->data_len = ntohs (msg->size);
  mdata->reference_counter = GNUNET_malloc (sizeof (unsigned int));
  mdata->t = t;
  mdata->data = GNUNET_malloc (mdata->data_len);
  memcpy (mdata->data, msg, mdata->data_len);
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_MESH_MULTICAST)
  {
    struct GNUNET_MESH_Multicast *mcast;

    mcast = (struct GNUNET_MESH_Multicast *) mdata->data;
    mcast->ttl = htonl (ntohl (mcast->ttl) - 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  data packet, ttl: %u\n",
                ntohl (mcast->ttl));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  not a data packet, no ttl\n");
  }
  if (NULL != t->owner && GNUNET_YES != t->owner->shutting_down
      && GNUNET_NO == internal)
  {
    mdata->task = GNUNET_malloc (sizeof (GNUNET_SCHEDULER_TaskIdentifier));
    (*(mdata->task)) =
        GNUNET_SCHEDULER_add_delayed (UNACKNOWLEDGED_WAIT, &client_allow_send,
                                      mdata);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "timeout task %u\n",
                *(mdata->task));
  }

  tree_iterate_children (t->tree, &tunnel_send_multicast_iterator, mdata);
  if (*(mdata->reference_counter) == 0)
  {
    GNUNET_free (mdata->data);
    GNUNET_free (mdata->reference_counter);
    if (NULL != mdata->task)
    {
      GNUNET_SCHEDULER_cancel(*(mdata->task));
      GNUNET_free (mdata->task);
      GNUNET_SERVER_receive_done(t->owner->handle, GNUNET_OK);
    }
    // FIXME change order?
    GNUNET_free (mdata);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " sending a multicast packet done\n");
  return;
}


/**
 * Send a message to all peers in this tunnel that the tunnel is no longer
 * valid.
 *
 * @param t The tunnel whose peers to notify.
 */
static void
tunnel_send_destroy (struct MeshTunnel *t)
{
  struct GNUNET_MESH_TunnelDestroy msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY);
  GNUNET_PEER_resolve (t->id.oid, &msg.oid);
  msg.tid = htonl (t->id.tid);
  tunnel_send_multicast (t, &msg.header, GNUNET_NO);
}



/**
 * Destroy the tunnel and free any allocated resources linked to it.
 *
 * @param t the tunnel to destroy
 *
 * @return GNUNET_OK on success
 */
static int
tunnel_destroy (struct MeshTunnel *t)
{
  struct MeshClient *c;
  struct MeshQueue *q;
  struct MeshQueue *qn;
  GNUNET_HashCode hash;
  unsigned int i;
  int r;

  if (NULL == t)
    return GNUNET_OK;

  r = GNUNET_OK;
  c = t->owner;
#if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (t->id.oid, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s [%x]\n",
                GNUNET_i2s (&id), t->id.tid);
    if (NULL != c)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);
  }
#endif

  GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &hash, t))
  {
    r = GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
  if (NULL != c &&
      GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_remove (c->own_tunnels, &hash, t))
  {
    r = GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
  for (i = 0; i < t->nclients; i++)
  {
    c = t->clients[i];
    if (GNUNET_YES !=
          GNUNET_CONTAINER_multihashmap_remove (c->incoming_tunnels, &hash, t))
    {
      r = GNUNET_SYSERR;
    }
  }
  for (i = 0; i < t->nignore; i++)
  {
    c = t->ignore[i];
    if (GNUNET_YES !=
          GNUNET_CONTAINER_multihashmap_remove (c->ignore_tunnels, &hash, t))
    {
      r = GNUNET_SYSERR;
    }
  }
  if (t->nclients > 0)
  {
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap_remove (incoming_tunnels, &hash, t))
    {
      r = GNUNET_SYSERR;
    }
    GNUNET_free (t->clients);
  }
  if (NULL != t->peers)
  {
    GNUNET_CONTAINER_multihashmap_iterate (t->peers, &peer_info_delete_tunnel,
                                           t);
    GNUNET_CONTAINER_multihashmap_destroy (t->peers);
  }
  q = t->queue_head;
  while (NULL != q)
  {
    if (NULL != q->data)
      GNUNET_free (q->data);
    qn = q->next;
    GNUNET_free (q);
    q = qn;
    /* TODO cancel core transmit ready in case it was active */
  }
  tree_destroy (t->tree);
  if (NULL != t->dht_get_type)
    GNUNET_DHT_get_stop (t->dht_get_type);
  if (GNUNET_SCHEDULER_NO_TASK != t->timeout_task)
    GNUNET_SCHEDULER_cancel (t->timeout_task);
  if (GNUNET_SCHEDULER_NO_TASK != t->path_refresh_task)
    GNUNET_SCHEDULER_cancel (t->path_refresh_task);
  GNUNET_free (t);
  return r;
}


/**
 * Removes an explicit path from a tunnel, freeing all intermediate nodes
 * that are no longer needed, as well as nodes of no longer reachable peers.
 * The tunnel itself is also destoyed if results in a remote empty tunnel.
 *
 * @param t Tunnel from which to remove the path.
 * @param peer Short id of the peer which should be removed.
 */
static void
tunnel_delete_peer (struct MeshTunnel *t, GNUNET_PEER_Id peer)
{
  if (GNUNET_NO == tree_del_peer (t->tree, peer, NULL, NULL))
    tunnel_destroy (t);
}


/**
 * tunnel_destroy_iterator: iterator for deleting each tunnel that belongs to a
 * client when the client disconnects. If the client is not the owner, the
 * owner will get notified if no more clients are in the tunnel and the client
 * get removed from the tunnel's list.
 *
 * @param cls closure (client that is disconnecting)
 * @param key the hash of the local tunnel id (used to access the hashmap)
 * @param value the value stored at the key (tunnel to destroy)
 *
 * @return GNUNET_OK on success
 */
static int
tunnel_destroy_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MeshTunnel *t = value;
  struct MeshClient *c = cls;
  int r;

  send_client_tunnel_disconnect(t, c);
  if (c != t->owner)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client %u is destination, keeping the tunnel alive.\n", c->id);
    tunnel_delete_client(t, c);
    client_delete_tunnel(c, t);
    return GNUNET_OK;
  }
  tunnel_send_destroy(t);
  r = tunnel_destroy (t);
  return r;
}


/**
 * Timeout function, destroys tunnel if called
 *
 * @param cls Closure (tunnel to destroy).
 * @param tc TaskContext
 */
static void
tunnel_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;

  if (GNUNET_SCHEDULER_REASON_SHUTDOWN == tc->reason)
    return;
  t->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  tunnel_destroy (t);
}

/**
 * Resets the tunnel timeout. Starts it if no timeout was running.
 *
 * @param t Tunnel whose timeout to reset.
 */
static void
tunnel_reset_timeout (struct MeshTunnel *t)
{
  if (GNUNET_SCHEDULER_NO_TASK != t->timeout_task)
    GNUNET_SCHEDULER_cancel (t->timeout_task);
  t->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (REFRESH_PATH_TIME, 4), &tunnel_timeout, t);
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
send_core_create_path (void *cls, size_t size, void *buf)
{
  struct MeshPathInfo *info = cls;
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct MeshPeerInfo *peer = info->peer;
  struct MeshTunnel *t = info->t;
  struct MeshPeerPath *p = info->path;
  size_t size_needed;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATE PATH sending...\n");
  size_needed =
      sizeof (struct GNUNET_MESH_ManipulatePath) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "create path retransmit!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  buf:  %p\n", buf);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  size: (%u/%u)\n", size,
                size_needed);
    info->peer->core_transmit[info->pos] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           tree_get_first_hop (t->tree,
                                                               peer->id),
                                           size_needed, &send_core_create_path,
                                           info);
    return 0;
  }
  info->peer->core_transmit[info->pos] = NULL;
#if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer->id, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  setting core_transmit %s [%u] to NULL\n",
                GNUNET_i2s (&id), info->pos);
  }
#endif
  msg = (struct GNUNET_MESH_ManipulatePath *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE);
  msg->tid = ntohl (t->id.tid);

  peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[i], peer_ptr++);
  }

  path_destroy (p);
  GNUNET_free (info);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CREATE PATH (%u bytes long) sent!\n", size_needed);
  return size_needed;
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
 *
 * @return number of bytes written to buf
 */
static size_t
send_core_data_multicast (void *cls, size_t size, void *buf)
{
  struct MeshTransmissionDescriptor *info = cls;
  size_t total_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Multicast callback.\n");
  GNUNET_assert (NULL != info);
  GNUNET_assert (NULL != info->peer);
  total_size = info->mesh_data->data_len;
  GNUNET_assert (total_size < GNUNET_SERVER_MAX_MESSAGE_SIZE);

  if (total_size > size)
  {
    /* Retry */
    struct GNUNET_PeerIdentity id;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Multicast: retransmitting... (%u/%u)\n", size,
                total_size);
    GNUNET_PEER_resolve (info->peer->id, &id);
    info->peer->core_transmit[info->handler_n] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                           GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                           total_size,
                                           &send_core_data_multicast, info);
    return 0;
  }
  info->peer->core_transmit[info->handler_n] = NULL;
  info->peer->infos[info->handler_n] = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " copying data...\n");
  memcpy (buf, info->mesh_data->data, total_size);
#if MESH_DEBUG
  {
    struct GNUNET_MESH_Multicast *mc;
    struct GNUNET_MessageHeader *mh;

    mh = buf;
    if (ntohs (mh->type) == GNUNET_MESSAGE_TYPE_MESH_MULTICAST)
    {
      mc = (struct GNUNET_MESH_Multicast *) mh;
      mh = (struct GNUNET_MessageHeader *) &mc[1];
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " multicast, payload type %u\n", ntohs (mh->type));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " multicast, payload size %u\n", ntohs (mh->size));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " type %u\n",
                  ntohs (mh->type));
    }
  }
#endif
  data_descriptor_decrement_multicast (info->mesh_data);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "freeing info...\n");
  GNUNET_free (info);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "return %u\n", total_size);
  return total_size;
}


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (MeshTransmissionDescriptor)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_path_ack (void *cls, size_t size, void *buf)
{
  struct MeshTransmissionDescriptor *info = cls;
  struct GNUNET_MESH_PathACK *msg = buf;

  GNUNET_assert (NULL != info);
  if (info->peer)
  {
    info->peer->core_transmit[info->handler_n] = NULL;
  }
  if (sizeof (struct GNUNET_MESH_PathACK) > size)
  {
    GNUNET_break (0);
    return 0;
  }
  msg->header.size = htons (sizeof (struct GNUNET_MESH_PathACK));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_ACK);
  GNUNET_PEER_resolve (info->origin->oid, &msg->oid);
  msg->tid = htonl (info->origin->tid);
  msg->peer_id = my_full_id;
  GNUNET_free (info);
  /* TODO add signature */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PATH ACK sent!\n");
  return sizeof (struct GNUNET_MESH_PathACK);
}


/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/


/**
 * Core handler for path creation
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information *atsi,
                         unsigned int atsi_count)
{
  unsigned int own_pos;
  uint16_t size;
  uint16_t i;
  MESH_TunnelNumber tid;
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *pi;
  GNUNET_HashCode hash;
  struct MeshPeerPath *path;
  struct MeshPeerInfo *dest_peer_info;
  struct MeshPeerInfo *orig_peer_info;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a path create msg [%s]\n",
              GNUNET_i2s (&my_full_id));
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ManipulatePath))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  size -= sizeof (struct GNUNET_MESH_ManipulatePath);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  size /= sizeof (struct GNUNET_PeerIdentity);
  if (size < 2)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    path has %u hops.\n", size);
  msg = (struct GNUNET_MESH_ManipulatePath *) message;

  tid = ntohl (msg->tid);
  pi = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    path is for tunnel %s [%X].\n", GNUNET_i2s (pi), tid);
  t = tunnel_get (pi, tid);
  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating tunnel\n");
    t = GNUNET_malloc (sizeof (struct MeshTunnel));
    t->id.oid = GNUNET_PEER_intern (pi);
    t->id.tid = tid;
    while (NULL != tunnel_get_incoming (next_local_tid))
      next_local_tid = (next_local_tid + 1) | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
    t->local_tid_dest = next_local_tid++;
    next_local_tid = next_local_tid | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
    t->tree = tree_new (t->id.oid);

    GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (tunnels, &hash, t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      tunnel_destroy (t);
      GNUNET_break (0);
      return GNUNET_OK;
    }
    tunnel_reset_timeout (t);
    GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (incoming_tunnels, &hash, t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      tunnel_destroy (t);
      GNUNET_break (0);
      return GNUNET_OK;
    }
  }
  dest_peer_info =
      GNUNET_CONTAINER_multihashmap_get (peers, &pi[size - 1].hashPubKey);
  if (NULL == dest_peer_info)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Creating PeerInfo for destination.\n");
    dest_peer_info = GNUNET_malloc (sizeof (struct MeshPeerInfo));
    dest_peer_info->id = GNUNET_PEER_intern (&pi[size - 1]);
    GNUNET_CONTAINER_multihashmap_put (peers, &pi[size - 1].hashPubKey,
                                       dest_peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  orig_peer_info = GNUNET_CONTAINER_multihashmap_get (peers, &pi->hashPubKey);
  if (NULL == orig_peer_info)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Creating PeerInfo for origin.\n");
    orig_peer_info = GNUNET_malloc (sizeof (struct MeshPeerInfo));
    orig_peer_info->id = GNUNET_PEER_intern (pi);
    GNUNET_CONTAINER_multihashmap_put (peers, &pi->hashPubKey, orig_peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
  path = path_new (size);
  own_pos = 0;
  for (i = 0; i < size; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ... adding %s\n",
                GNUNET_i2s (&pi[i]));
    path->peers[i] = GNUNET_PEER_intern (&pi[i]);
    if (path->peers[i] == myid)
      own_pos = i;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Own position: %u\n", own_pos);
  if (own_pos == 0)
  {
    /* cannot be self, must be 'not found' */
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    /* FIXME error. destroy tunnel? leave for timeout? */
    return 0;
  }
  path_add_to_peers (path, GNUNET_NO);
  tunnel_add_path (t, path, own_pos);
  if (own_pos == size - 1)
  {
    /* It is for us! Send ack. */
    struct MeshTransmissionDescriptor *info;
    unsigned int j;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    peer_info_add_path_to_origin (orig_peer_info, path, GNUNET_NO);
    if (NULL == t->peers)
    {
      /* New tunnel! Notify clients on data. */
      t->peers = GNUNET_CONTAINER_multihashmap_create (4);
    }
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_put (t->peers,
                                                     &my_full_id.hashPubKey,
                                                     peer_info_get
                                                     (&my_full_id),
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
    /* FIXME use send_message */
    info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));
    info->origin = &t->id;
    info->peer = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
    GNUNET_assert (NULL != info->peer);
    j = peer_info_transmit_slot (info->peer);
    info->handler_n = j;
    info->peer->types[j] = GNUNET_MESSAGE_TYPE_MESH_PATH_ACK;
    info->peer->infos[j] = info;
    info->peer->core_transmit[j] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 100,
                                           GNUNET_TIME_UNIT_FOREVER_REL, peer,
                                           sizeof (struct GNUNET_MESH_PathACK),
                                           &send_core_path_ack, info);
  }
  else
  {
    struct MeshPeerPath *path2;

    /* It's for somebody else! Retransmit. */
    path2 = path_duplicate (path);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    peer_info_add_path (dest_peer_info, path2, GNUNET_NO);
    path2 = path_duplicate (path);
    peer_info_add_path_to_origin (orig_peer_info, path2, GNUNET_NO);
    send_create_path (dest_peer_info, path, t);
  }
  return GNUNET_OK;
}


/**
 * Core handler for path destruction
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          unsigned int atsi_count)
{
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *pi;
  struct MeshPeerPath *path;
  struct MeshTunnel *t;
  unsigned int own_pos;
  unsigned int i;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a PATH DESTROY msg from %s\n", GNUNET_i2s (peer));
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ManipulatePath))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  size -= sizeof (struct GNUNET_MESH_ManipulatePath);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  size /= sizeof (struct GNUNET_PeerIdentity);
  if (size < 2)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    path has %u hops.\n", size);

  msg = (struct GNUNET_MESH_ManipulatePath *) message;
  pi = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    path is for tunnel %s [%X].\n", GNUNET_i2s (pi),
              msg->tid);
  t = tunnel_get (pi, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify back: we don't know this tunnel */
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
  path = path_new (size);
  own_pos = 0;
  for (i = 0; i < size; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ... adding %s\n",
                GNUNET_i2s (&pi[i]));
    path->peers[i] = GNUNET_PEER_intern (&pi[i]);
    if (path->peers[i] == myid)
      own_pos = i;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Own position: %u\n", own_pos);
  if (own_pos < path->length - 1)
    send_message (message, &pi[own_pos + 1]);
  else
    send_client_tunnel_disconnect(t, NULL);

  tunnel_delete_peer (t, path->peers[path->length - 1]);
  path_destroy (path);
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken paths
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_broken (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information *atsi,
                         unsigned int atsi_count)
{
  struct GNUNET_MESH_PathBroken *msg;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a PATH BROKEN msg from %s\n", GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_PathBroken *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer1));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer2));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  tunnel_notify_connection_broken (t, GNUNET_PEER_search (&msg->peer1),
                                   GNUNET_PEER_search (&msg->peer2));
  return GNUNET_OK;

}


/**
 * Core handler for tunnel destruction
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_tunnel_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message,
                            const struct GNUNET_ATS_Information *atsi,
                            unsigned int atsi_count)
{
  struct GNUNET_MESH_TunnelDestroy *msg;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a TUNNEL DESTROY packet from %s\n", GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_TunnelDestroy *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  for tunnel %s [%u]\n",
              GNUNET_i2s (&msg->oid), ntohl (msg->tid));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* Probably already got the message from another path,
     * destroyed the tunnel and retransmitted to children.
     * Safe to ignore.
     */
    return GNUNET_OK;
  }
  if (t->id.oid == myid)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  if (t->local_tid_dest >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    /* Tunnel was incoming, notify clients */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "INCOMING TUNNEL %X %X\n",
                t->local_tid, t->local_tid_dest);
    send_clients_tunnel_destroy (t);
  }
  tunnel_send_destroy (t);
  tunnel_destroy (t);
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to a peer
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param message message
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_unicast (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          unsigned int atsi_count)
{
  struct GNUNET_MESH_Unicast *msg;
  struct MeshTunnel *t;
  GNUNET_PEER_Id pid;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a unicast packet from %s\n",
              GNUNET_i2s (peer));
  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Unicast) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Unicast *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " of type %u\n",
              ntohs (msg[1].header.type));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify back: we don't know this tunnel */
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  tunnel_reset_timeout (t);
  pid = GNUNET_PEER_search (&msg->destination);
  if (pid == myid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  it's for us! sending to clients...\n");
    send_subscribed_clients (message, (struct GNUNET_MessageHeader *) &msg[1]);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  not for us, retransmitting...\n");
  send_message (message, tree_get_first_hop (t->tree, pid));
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to all peers
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 * TODO: Check who we got this from, to validate route.
 */
static int
handle_mesh_data_multicast (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message,
                            const struct GNUNET_ATS_Information *atsi,
                            unsigned int atsi_count)
{
  struct GNUNET_MESH_Multicast *msg;
  struct MeshTunnel *t;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a multicast packet from %s\n",
              GNUNET_i2s (peer));
  size = ntohs (message->size);
  if (sizeof (struct GNUNET_MESH_Multicast) +
      sizeof (struct GNUNET_MessageHeader) > size)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Multicast *) message;
  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know that tunnel */
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  if (t->mid == ntohl (msg->mid))
  {
    /* FIXME: already seen this packet, log dropping */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                " Already seen mid %u, DROPPING!\n", t->mid);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " mid %u not seen yet, forwarding\n", ntohl (msg->mid));
  }
  t->mid = ntohl (msg->mid);
  tunnel_reset_timeout (t);

  /* Transmit to locally interested clients */
  if (NULL != t->peers &&
      GNUNET_CONTAINER_multihashmap_contains (t->peers, &my_full_id.hashPubKey))
  {
    send_subscribed_clients (message, &msg[1].header);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ntohl (msg->ttl));
  if (ntohl (msg->ttl) == 0)
  {
    /* FIXME: ttl is 0, log dropping */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    return GNUNET_OK;
  }
  tunnel_send_multicast (t, message, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic toward the owner of a tunnel
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_to_orig (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          unsigned int atsi_count)
{
  struct GNUNET_MESH_ToOrigin *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerInfo *peer_info;
  struct MeshTunnel *t;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a ToOrigin packet from %s\n",
              GNUNET_i2s (peer));
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ToOrigin) +     /* Payload must be */
      sizeof (struct GNUNET_MessageHeader))     /* at least a header */
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_ToOrigin *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " of type %u\n",
              ntohs (msg[1].header.type));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  if (t->id.oid == myid)
  {
    char cbuf[size];
    struct GNUNET_MESH_ToOrigin *copy;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  it's for us! sending to clients...\n");
    if (NULL == t->owner)
    {
      /* got data packet for ownerless tunnel */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  no clients!\n");
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    /* TODO signature verification */
    memcpy (cbuf, message, size);
    copy = (struct GNUNET_MESH_ToOrigin *) cbuf;
    copy->tid = htonl (t->local_tid);
    GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle,
                                                &copy->header, GNUNET_YES);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  not for us, retransmitting...\n");

  peer_info = peer_info_get (&msg->oid);
  if (NULL == peer_info)
  {
    /* unknown origin of tunnel */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &id);
  send_message (message, &id);

  return GNUNET_OK;
}


/**
 * Core handler for path ACKs
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  struct GNUNET_MESH_PathACK *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *p;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received a path ACK msg [%s]\n",
              GNUNET_i2s (&my_full_id));
  msg = (struct GNUNET_MESH_PathACK *) message;
  t = tunnel_get (&msg->oid, msg->tid);
  if (NULL == t)
  {
    /* TODO notify that we don't know the tunnel */
    return GNUNET_OK;
  }

  peer_info = peer_info_get (&msg->peer_id);

  /* Add paths to peers? */
  p = tree_get_path_to_peer (t->tree, peer_info->id);
  if (NULL != p)
  {
    path_add_to_peers (p, GNUNET_YES);
    path_destroy (p);
  }
  else
  {
    GNUNET_break (0);
  }

  /* Message for us? */
  if (0 == memcmp (&msg->oid, &my_full_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    if (NULL == t->owner)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    if (NULL != t->dht_get_type)
    {
      GNUNET_DHT_get_stop (t->dht_get_type);
      t->dht_get_type = NULL;
    }
    if (tree_get_status (t->tree, peer_info->id) != MESH_PEER_READY)
    {
      tree_set_status (t->tree, peer_info->id, MESH_PEER_READY);
      send_client_peer_connected (t, peer_info->id);
    }
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  not for us, retransmitting...\n");
  GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &id);
  peer_info = peer_info_get (&msg->oid);
  if (NULL == peer_info)
  {
    /* If we know the tunnel, we should DEFINITELY know the peer */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  send_message (message, &id);
  return GNUNET_OK;
}


/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_path_destroy, GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY, 0},
  {&handle_mesh_path_broken, GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN,
   sizeof (struct GNUNET_MESH_PathBroken)},
  {&handle_mesh_tunnel_destroy, GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY, 0},
  {&handle_mesh_data_unicast, GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_mesh_data_multicast, GNUNET_MESSAGE_TYPE_MESH_MULTICAST, 0},
  {&handle_mesh_data_to_orig, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
  {&handle_mesh_path_ack, GNUNET_MESSAGE_TYPE_MESH_PATH_ACK,
   sizeof (struct GNUNET_MESH_PathACK)},
  {NULL, 0, 0}
};



/******************************************************************************/
/****************       MESH LOCAL HANDLER HELPERS      ***********************/
/******************************************************************************/

/**
 * deregister_app: iterator for removing each application registered by a client
 *
 * @param cls closure
 * @param key the hash of the application id (used to access the hashmap)
 * @param value the value stored at the key (client)
 *
 * @return GNUNET_OK on success
 */
static int
deregister_app (void *cls, const GNUNET_HashCode * key, void *value)
{
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (applications, key,
                                                      value));
  return GNUNET_OK;
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
  int size_needed;
  struct MeshPeerInfo *peer_info;
  struct GNUNET_MESH_PeerControl *msg;
  struct GNUNET_PeerIdentity id;

  if (0 == size && NULL == buf)
  {
    // TODO retry? cancel?
    return 0;
  }

  size_needed = sizeof (struct GNUNET_MESH_PeerControl);
  peer_info = (struct MeshPeerInfo *) cls;
  msg = (struct GNUNET_MESH_PeerControl *) buf;
  msg->header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DISCONNECTED);
//     msg->tunnel_id = htonl(peer_info->t->tid);
  GNUNET_PEER_resolve (peer_info->id, &id);
  memcpy (&msg->peer, &id, sizeof (struct GNUNET_PeerIdentity));

  return size_needed;
}
#endif


/**
 * Send keepalive packets for a peer
 *
 * @param cls Closure (tunnel for which to send the keepalive).
 * @param tc Notification context.
 *
 * TODO: implement explicit multicast keepalive?
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;
  struct GNUNET_MessageHeader *payload;
  struct GNUNET_MESH_Multicast *msg;
  size_t size =
      sizeof (struct GNUNET_MESH_Multicast) +
      sizeof (struct GNUNET_MessageHeader);
  char cbuf[size];

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  t->path_refresh_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending keepalive for tunnel %d\n", t->id.tid);

  msg = (struct GNUNET_MESH_Multicast *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_MULTICAST);
  msg->oid = my_full_id;
  msg->tid = htonl (t->id.tid);
  msg->ttl = htonl (DEFAULT_TTL);
  msg->mid = htonl (t->mid + 1);
  t->mid++;
  payload = (struct GNUNET_MessageHeader *) &msg[1];
  payload->size = htons (sizeof (struct GNUNET_MessageHeader));
  payload->type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE);
  tunnel_send_multicast (t, &msg->header, GNUNET_YES);

  t->path_refresh_task =
      GNUNET_SCHEDULER_add_delayed (REFRESH_PATH_TIME, &path_refresh, t);
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
 * @param get_path path of the get request
 * @param get_path_length lenght of get_path
 * @param put_path path of the put request
 * @param put_path_length length of the put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 *
 * TODO: re-issue the request after certain time? cancel after X results?
 */
static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data)
{
  struct MeshPathInfo *path_info = cls;
  struct MeshPeerPath *p;
  struct GNUNET_PeerIdentity pi;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got results from DHT!\n");
  GNUNET_PEER_resolve (path_info->peer->id, &pi);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  for %s\n", GNUNET_i2s (&pi));

  p = path_build_from_dht (get_path, get_path_length, put_path,
                           put_path_length);
  path_add_to_peers (p, GNUNET_NO);
  path_destroy(p);
  for (i = 0; i < path_info->peer->ntunnels; i++)
  {
    tunnel_add_peer (path_info->peer->tunnels[i], path_info->peer);
    peer_info_connect (path_info->peer, path_info->t);
  }

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
 * @param get_path path of the get request
 * @param get_path_length lenght of get_path
 * @param put_path path of the put request
 * @param put_path_length length of the put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_type_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                      const GNUNET_HashCode * key,
                      const struct GNUNET_PeerIdentity *get_path,
                      unsigned int get_path_length,
                      const struct GNUNET_PeerIdentity *put_path,
                      unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                      size_t size, const void *data)
{
  const struct GNUNET_PeerIdentity *pi = data;
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *p;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got type DHT result!\n");
  if (size != sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_assert (NULL != t->owner);
  peer_info = peer_info_get (pi);
  (void) GNUNET_CONTAINER_multihashmap_put (t->peers, &pi->hashPubKey,
                                            peer_info,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  p = path_build_from_dht (get_path, get_path_length, put_path,
                           put_path_length);
  path_add_to_peers (p, GNUNET_NO);
  path_destroy(p);
  tunnel_add_peer (t, peer_info);
  peer_info_connect (peer_info, t);
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
handle_local_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct MeshClient *c;
  struct MeshClient *next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected\n");
  if (client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (SERVER DOWN)\n");
    return;
  }
  c = clients;
  while (NULL != c)
  {
    if (c->handle != client)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ... searching\n");
      c = c->next;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u)\n",
                c->id);
    GNUNET_SERVER_client_drop (c->handle);
    c->shutting_down = GNUNET_YES;
    GNUNET_assert (NULL != c->own_tunnels);
    GNUNET_assert (NULL != c->incoming_tunnels);
    GNUNET_CONTAINER_multihashmap_iterate (c->own_tunnels,
                                           &tunnel_destroy_iterator, c);
    GNUNET_CONTAINER_multihashmap_iterate (c->incoming_tunnels,
                                           &tunnel_destroy_iterator, c);
    GNUNET_CONTAINER_multihashmap_iterate (c->ignore_tunnels,
                                           &tunnel_destroy_iterator, c);
    GNUNET_CONTAINER_multihashmap_destroy (c->own_tunnels);
    GNUNET_CONTAINER_multihashmap_destroy (c->incoming_tunnels);
    GNUNET_CONTAINER_multihashmap_destroy (c->ignore_tunnels);

    /* deregister clients applications */
    if (NULL != c->apps)
    {
      GNUNET_CONTAINER_multihashmap_iterate (c->apps, &deregister_app, NULL);
      GNUNET_CONTAINER_multihashmap_destroy (c->apps);
    }
    if (0 == GNUNET_CONTAINER_multihashmap_size (applications) &&
        GNUNET_SCHEDULER_NO_TASK != announce_applications_task)
    {
      GNUNET_SCHEDULER_cancel (announce_applications_task);
      announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != c->types)
      GNUNET_CONTAINER_multihashmap_destroy (c->types);
    next = c->next;
    GNUNET_CONTAINER_DLL_remove (clients, clients_tail, c);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  CLIENT FREE at %p\n", c);
    GNUNET_free (c);
    c = next;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   done!\n");
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
handle_local_new_client (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ClientConnect *cc_msg;
  struct MeshClient *c;
  GNUNET_MESH_ApplicationType *a;
  unsigned int size;
  uint16_t ntypes;
  uint16_t *t;
  uint16_t napps;
  uint16_t i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new client connected\n");
  /* Check data sanity */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_ClientConnect);
  cc_msg = (struct GNUNET_MESH_ClientConnect *) message;
  ntypes = ntohs (cc_msg->types);
  napps = ntohs (cc_msg->applications);
  if (size !=
      ntypes * sizeof (uint16_t) + napps * sizeof (GNUNET_MESH_ApplicationType))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Create new client structure */
  c = GNUNET_malloc (sizeof (struct MeshClient));
  c->id = next_client_id++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  CLIENT NEW %u\n", c->id);
  c->handle = client;
  GNUNET_SERVER_client_keep (client);
  a = (GNUNET_MESH_ApplicationType *) &cc_msg[1];
  if (napps > 0)
  {
    GNUNET_MESH_ApplicationType at;
    GNUNET_HashCode hc;

    c->apps = GNUNET_CONTAINER_multihashmap_create (napps);
    for (i = 0; i < napps; i++)
    {
      at = ntohl (a[i]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  app type: %u\n", at);
      GNUNET_CRYPTO_hash (&at, sizeof (at), &hc);
      /* store in clients hashmap */
      GNUNET_CONTAINER_multihashmap_put (c->apps, &hc, c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      /* store in global hashmap, for announcements */
      GNUNET_CONTAINER_multihashmap_put (applications, &hc, c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
    if (GNUNET_SCHEDULER_NO_TASK == announce_applications_task)
      announce_applications_task =
          GNUNET_SCHEDULER_add_now (&announce_applications, NULL);

  }
  if (ntypes > 0)
  {
    uint16_t u16;
    GNUNET_HashCode hc;

    t = (uint16_t *) & a[napps];
    c->types = GNUNET_CONTAINER_multihashmap_create (ntypes);
    for (i = 0; i < ntypes; i++)
    {
      u16 = ntohs (t[i]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  msg type: %u\n", u16);
      GNUNET_CRYPTO_hash (&u16, sizeof (u16), &hc);

      /* store in clients hashmap */
      GNUNET_CONTAINER_multihashmap_put (c->types, &hc, c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      /* store in global hashmap */
      GNUNET_CONTAINER_multihashmap_put (types, &hc, c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " client has %u+%u subscriptions\n", napps, ntypes);

  GNUNET_CONTAINER_DLL_insert (clients, clients_tail, c);
  c->own_tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  c->incoming_tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  c->ignore_tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  GNUNET_SERVER_notification_context_add (nc, client);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new client processed\n");
}


/**
 * Handler for requests of new tunnels
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_tunnel_create (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelMessage *t_msg;
  struct MeshTunnel *t;
  struct MeshClient *c;
  GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new tunnel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_TunnelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  t_msg = (struct GNUNET_MESH_TunnelMessage *) message;
  /* Sanity check for tunnel numbering */
  if (0 == (ntohl (t_msg->tunnel_id) & GNUNET_MESH_LOCAL_TUNNEL_ID_CLI))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* Sanity check for duplicate tunnel IDs */
  if (NULL != tunnel_get_by_local_id (c, ntohl (t_msg->tunnel_id)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  t = GNUNET_malloc (sizeof (struct MeshTunnel));
  while (NULL != tunnel_get_by_pi (myid, next_tid))
    next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  t->id.tid = next_tid++;
  next_tid = next_tid & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  t->id.oid = myid;
  t->local_tid = ntohl (t_msg->tunnel_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATED TUNNEL %s [%x] (%x)\n",
              GNUNET_i2s (&my_full_id), t->id.tid, t->local_tid);
  t->owner = c;
  t->peers = GNUNET_CONTAINER_multihashmap_create (32);

  GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (c->own_tunnels, &hash, t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (tunnels, &hash, t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  t->tree = tree_new (myid);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new tunnel created\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_tunnel_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelMessage *tunnel_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a DESTROY TUNNEL from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_TunnelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);
  tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;

  /* Retrieve tunnel */
  tid = ntohl (tunnel_msg->tunnel_id);
  t = tunnel_get_by_local_id(c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  tunnel %X not found\n", tid);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  send_client_tunnel_disconnect(t, c);
  if (c != t->owner)
  {
    client_ignore_tunnel (c, t);
#if 0
    // TODO: when to destroy incoming tunnel?
    if (t->nclients == 0)
    {
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap_remove (incoming_tunnels,
                                                           &hash, t));
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap_remove (t->peers,
                                                           &my_full_id.hashPubKey,
                                                           t));
    }
#endif
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  client_delete_tunnel(c, t);

  /* Don't try to ACK the client about the tunnel_destroy multicast packet */
  t->owner = NULL;
  tunnel_send_destroy (t);
  tunnel_destroy (t);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_connect_add (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PeerControl *peer_msg;
  struct MeshPeerInfo *peer_info;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got connection request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  peer_msg = (struct GNUNET_MESH_PeerControl *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_PeerControl) != ntohs (peer_msg->header.size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (peer_msg->tunnel_id);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Does client own tunnel? */
  if (t->owner->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "     for %s\n",
              GNUNET_i2s (&peer_msg->peer));
  peer_info = peer_info_get (&peer_msg->peer);

  tunnel_add_peer (t, peer_info);
  peer_info_connect (peer_info, t);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_connect_del (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PeerControl *peer_msg;
  struct MeshPeerInfo *peer_info;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a PEER DEL request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  peer_msg = (struct GNUNET_MESH_PeerControl *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_PeerControl) != ntohs (peer_msg->header.size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (peer_msg->tunnel_id);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on tunnel %X\n", t->id.tid);

  /* Does client own tunnel? */
  if (t->owner->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  for peer %s\n",
              GNUNET_i2s (&peer_msg->peer));
  /* Is the peer in the tunnel? */
  peer_info =
      GNUNET_CONTAINER_multihashmap_get (t->peers, &peer_msg->peer.hashPubKey);
  if (NULL == peer_info)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Ok, delete peer from tunnel */
  GNUNET_CONTAINER_multihashmap_remove_all (t->peers,
                                            &peer_msg->peer.hashPubKey);

  send_destroy_path (t, peer_info->id);
  tunnel_delete_peer (t, peer_info->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_connect_by_type (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectPeerByType *connect_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  GNUNET_HashCode hash;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got connect by type request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  connect_msg = (struct GNUNET_MESH_ConnectPeerByType *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_ConnectPeerByType) !=
      ntohs (connect_msg->header.size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (connect_msg->tunnel_id);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Does client own tunnel? */
  if (t->owner->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Do WE have the service? */
  t->type = ntohl (connect_msg->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " type requested: %u\n", t->type);
  GNUNET_CRYPTO_hash (&t->type, sizeof (GNUNET_MESH_ApplicationType), &hash);
  if (GNUNET_CONTAINER_multihashmap_contains (applications, &hash) ==
      GNUNET_YES)
  {
    /* Yes! Fast forward, add ourselves to the tunnel and send the
     * good news to the client, and alert the destination client of
     * an incoming tunnel.
     *
     * FIXME send a path create to self, avoid code duplication
     */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " available locally\n");
    GNUNET_CONTAINER_multihashmap_put (t->peers, &my_full_id.hashPubKey,
                                       peer_info_get (&my_full_id),
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " notifying client\n");
    send_client_peer_connected (t, myid);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Done\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);

    t->local_tid_dest = next_local_tid++;
    GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
    GNUNET_CONTAINER_multihashmap_put (incoming_tunnels, &hash, t,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

    return;
  }
  /* Ok, lets find a peer offering the service */
  if (NULL != t->dht_get_type)
  {
    GNUNET_DHT_get_stop (t->dht_get_type);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " looking in DHT for %s\n",
              GNUNET_h2s (&hash));
  t->dht_get_type =
      GNUNET_DHT_get_start (dht_handle, GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_BLOCK_TYPE_TEST, &hash, 10U,
                            GNUNET_DHT_RO_RECORD_ROUTE |
                            GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL, 0,
                            &dht_get_type_handler, t);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_unicast (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct MeshClient *c;
  struct MeshTunnel *t;
  struct MeshPeerInfo *pi;
  struct GNUNET_MESH_Unicast *data_msg;
  MESH_TunnelNumber tid;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a unicast request from a client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  data_msg = (struct GNUNET_MESH_Unicast *) message;
  /* Sanity check for message size */
  size = ntohs (message->size);
  if (sizeof (struct GNUNET_MESH_Unicast) +
      sizeof (struct GNUNET_MessageHeader) > size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (data_msg->tid);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /*  Is it a local tunnel? Then, does client own the tunnel? */
  if (t->owner->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  pi = GNUNET_CONTAINER_multihashmap_get (t->peers,
                                          &data_msg->destination.hashPubKey);
  /* Is the selected peer in the tunnel? */
  if (NULL == pi)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Ok, everything is correct, send the message
   * (pretend we got it from a mesh peer)
   */
  {
    char buf[ntohs (message->size)];
    struct GNUNET_MESH_Unicast *copy;

    /* Work around const limitation */
    copy = (struct GNUNET_MESH_Unicast *) buf;
    memcpy (buf, data_msg, size);
    copy->oid = my_full_id;
    copy->tid = htonl (t->id.tid);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    handle_mesh_data_unicast (NULL, &my_full_id, &copy->header, NULL, 0);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}


/**
 * Handler for client traffic directed to the origin
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_to_origin (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ToOrigin *data_msg;
  struct GNUNET_PeerIdentity id;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;
  size_t size;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  data_msg = (struct GNUNET_MESH_ToOrigin *) message;
  /* Sanity check for message size */
  size = ntohs (message->size);
  if (sizeof (struct GNUNET_MESH_ToOrigin) +
      sizeof (struct GNUNET_MessageHeader) > size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (data_msg->tid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a ToOrigin request from a client! Tunnel %X\n", tid);
  if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /*  It should be sent by someone who has this as incoming tunnel. */
  if (-1 == client_knows_tunnel (c, t))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_PEER_resolve (t->id.oid, &id);

  /* Ok, everything is correct, send the message
   * (pretend we got it from a mesh peer)
   */
  {
    char buf[ntohs (message->size)];
    struct GNUNET_MESH_ToOrigin *copy;

    /* Work around const limitation */
    copy = (struct GNUNET_MESH_ToOrigin *) buf;
    memcpy (buf, data_msg, size);
    copy->oid = id;
    copy->tid = htonl (t->id.tid);
    copy->sender = my_full_id;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    handle_mesh_data_to_orig (NULL, &my_full_id, &copy->header, NULL, 0);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_multicast (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  struct MeshClient *c;
  struct MeshTunnel *t;
  struct GNUNET_MESH_Multicast *data_msg;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a multicast request from a client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  data_msg = (struct GNUNET_MESH_Multicast *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_Multicast) +
      sizeof (struct GNUNET_MessageHeader) > ntohs (data_msg->header.size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (data_msg->tid);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Does client own tunnel? */
  if (t->owner->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  {
    char buf[ntohs (message->size)];
    struct GNUNET_MESH_Multicast *copy;

    copy = (struct GNUNET_MESH_Multicast *) buf;
    memcpy (buf, message, ntohs (message->size));
    copy->oid = my_full_id;
    copy->tid = htonl (t->id.tid);
    copy->ttl = htonl (DEFAULT_TTL);
    copy->mid = htonl (t->mid + 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    handle_mesh_data_multicast (client, &my_full_id, &copy->header, NULL, 0);
  }

  /* receive done gets called when last copy is sent to a neighbor */
  return;
}

/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler client_handlers[] = {
  {&handle_local_new_client, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
  {&handle_local_tunnel_create, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_destroy, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_connect_add, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_del, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_by_type, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE,
   sizeof (struct GNUNET_MESH_ConnectPeerByType)},
  {&handle_local_unicast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_local_to_origin, NULL,
   GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
  {&handle_local_multicast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_MULTICAST, 0},
  {NULL, NULL, 0, 0}
};


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core init\n");
  core_handle = server;
  if (0 != memcmp (identity, &my_full_id, sizeof (my_full_id)) ||
      NULL == server)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Wrong CORE service\n"));
    GNUNET_SCHEDULER_shutdown ();
  }
  return;
}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 */
static void
core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_ATS_Information *atsi,
              unsigned int atsi_count)
{
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *path;

  DEBUG_CONN ("Peer connected\n");
  DEBUG_CONN ("     %s\n", GNUNET_i2s (&my_full_id));
  peer_info = peer_info_get (peer);
  if (myid == peer_info->id)
  {
    DEBUG_CONN ("     (self)\n");
    return;
  }
  else
  {
    DEBUG_CONN ("     %s\n", GNUNET_i2s (peer));
  }
  path = path_new (2);
  path->peers[0] = myid;
  path->peers[1] = peer_info->id;
  GNUNET_PEER_change_rc (myid, 1);
  GNUNET_PEER_change_rc (peer_info->id, 1);
  peer_info_add_path (peer_info, path, GNUNET_YES);
  return;
}

/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct MeshPeerInfo *pi;
  unsigned int i;

  DEBUG_CONN ("Peer disconnected\n");
  pi = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pi)
  {
    GNUNET_break (0);
    return;
  }
  for (i = 0; i < CORE_QUEUE_SIZE; i++)
  {
    /* TODO: notify that the transmission failed */
    peer_info_cancel_transmission (pi, i);
  }
  peer_info_remove_path (pi, pi->id, myid);
  if (myid == pi->id)
  {
    DEBUG_CONN ("     (self)\n");
  }
  return;
}


/******************************************************************************/
/************************      MAIN FUNCTIONS      ****************************/
/******************************************************************************/

/**
 * Iterator over tunnel hash map entries to destroy the tunnel during shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
shutdown_tunnel (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MeshTunnel *t = value;

  tunnel_destroy (t);
  return GNUNET_YES;
}

/**
 * Iterator over peer hash map entries to destroy the tunnel during shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
shutdown_peer (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MeshPeerInfo *p = value;

  peer_info_destroy (p);
  return GNUNET_YES;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down\n");

  if (core_handle != NULL)
  {
    GNUNET_CORE_disconnect (core_handle);
    core_handle = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (tunnels, &shutdown_tunnel, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (peers, &shutdown_peer, NULL);
  if (dht_handle != NULL)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
  if (nc != NULL)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != announce_id_task)
  {
    GNUNET_SCHEDULER_cancel (announce_id_task);
    announce_id_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shut down\n");
}

/**
 * Process mesh requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct MeshPeerInfo *peer;
  struct MeshPeerPath *p;
  char *keyfile;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting to run\n");
  server_handle = server;
  core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                     CORE_QUEUE_SIZE,   /* queue size */
                                     NULL,      /* Closure passed to MESH functions */
                                     &core_init,        /* Call core_init once connected */
                                     &core_connect,     /* Handle connects */
                                     &core_disconnect,  /* remove peers on disconnects */
                                     NULL,      /* Don't notify about all incoming messages */
                                     GNUNET_NO, /* For header only in notification */
                                     NULL,      /* Don't notify about all outbound messages */
                                     GNUNET_NO, /* For header-only out notification */
                                     core_handlers);    /* Register these handlers */

  if (core_handle == NULL)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c, "GNUNETD", "HOSTKEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Mesh service is lacking key configuration settings.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Mesh service could not access hostkey.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_full_id.hashPubKey);
  myid = GNUNET_PEER_intern (&my_full_id);

// //   transport_handle = GNUNET_TRANSPORT_connect(c,
// //                                               &my_full_id,
// //                                               NULL,
// //                                               NULL,
// //                                               NULL,
// //                                               NULL);

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (dht_handle == NULL)
  {
    GNUNET_break (0);
  }

  next_tid = 0;
  next_local_tid = GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;

  tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  incoming_tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  peers = GNUNET_CONTAINER_multihashmap_create (32);
  applications = GNUNET_CONTAINER_multihashmap_create (32);
  types = GNUNET_CONTAINER_multihashmap_create (32);

  GNUNET_SERVER_add_handlers (server_handle, client_handlers);
  nc = GNUNET_SERVER_notification_context_create (server_handle,
                                                  LOCAL_QUEUE_SIZE);
  GNUNET_SERVER_disconnect_notify (server_handle,
                                   &handle_local_client_disconnect, NULL);


  clients = NULL;
  clients_tail = NULL;
  next_client_id = 0;

  announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, cls);

  /* Create a peer_info for the local peer */
  peer = peer_info_get (&my_full_id);
  p = path_new (1);
  p->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  peer_info_add_path (peer, p, GNUNET_YES);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "end of run()\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "mesh", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");

  return ret;
}
