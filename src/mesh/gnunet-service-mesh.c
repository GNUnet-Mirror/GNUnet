/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 *  FIXME in progress:
 * - when sending in-order buffered data, wait for client ACKs
 *
 * TODO:
 * - relay corking down to core
 * - set ttl relative to path length
 * - add signatures
 * - add encryption
 * TODO END
 */

#include "platform.h"
#include "mesh.h"
#include "mesh_protocol.h"
#include "mesh_path.h"
#include "block_mesh.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"

#define MESH_BLOOM_SIZE         128

#define MESH_DEBUG_DHT          GNUNET_NO
#define MESH_DEBUG_CONNECTION   GNUNET_NO
#define MESH_DEBUG_TIMING       __LINUX__ && GNUNET_NO

#define MESH_MAX_POLL_TIME      GNUNET_TIME_relative_multiply (\
                                  GNUNET_TIME_UNIT_MINUTES,\
                                  10)
#define MESH_RETRANSMIT_TIME    GNUNET_TIME_UNIT_SECONDS
#define MESH_RETRANSMIT_MARGIN  4

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

#if MESH_DEBUG_TIMING
#include <time.h>
double __sum;
uint64_t __count;
struct timespec __mesh_start;
struct timespec __mesh_end;
#define INTERVAL_START clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(__mesh_start))
#define INTERVAL_END \
do {\
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(__mesh_end));\
  double __diff = __mesh_end.tv_nsec - __mesh_start.tv_nsec;\
  if (__diff < 0) __diff += 1000000000;\
  __sum += __diff;\
  __count++;\
} while (0)
#define INTERVAL_SHOW \
if (0 < __count)\
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "AVG process time: %f ns\n", __sum/__count)
#else
#define INTERVAL_START
#define INTERVAL_END
#define INTERVAL_SHOW
#endif

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/** FWD declaration */
struct MeshPeerInfo;
struct MeshClient;


/**
 * Struct containing info about a queued transmission to this peer
 */
struct MeshPeerQueue
{
    /**
      * DLL next
      */
  struct MeshPeerQueue *next;

    /**
      * DLL previous
      */
  struct MeshPeerQueue *prev;

    /**
     * Peer this transmission is directed to.
     */
  struct MeshPeerInfo *peer;

    /**
     * Tunnel this message belongs to.
     */
  struct MeshTunnel *tunnel;

    /**
     * Pointer to info stucture used as cls.
     */
  void *cls;

    /**
     * Type of message
     */
  uint16_t type;

    /**
     * Size of the message
     */
  size_t size;
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
     * Array of tunnels this peer is the target of.
     * Most probably a small amount, therefore not a hashmap.
     * When the path to the peer changes, notify these tunnels to let them
     * re-adjust their path trees.
     */
  struct MeshTunnel **tunnels;

    /**
     * Number of tunnels this peers participates in
     */
  unsigned int ntunnels;

   /**
    * Transmission queue to core DLL head
    */
  struct MeshPeerQueue *queue_head;

   /**
    * Transmission queue to core DLL tail
    */
   struct MeshPeerQueue *queue_tail;

   /**
    * How many messages are in the queue to this peer.
    */
   unsigned int queue_n;

   /**
    * Handle for queued transmissions
    */
  struct GNUNET_CORE_TransmitHandle *core_transmit;
};


/**
 * Struct to encapsulate all the Flow Control information to a peer in the
 * context of a tunnel: Same peer in different tunnels will have independent
 * flow control structures, allowing to choke/free tunnels according to its
 * own criteria.
 */
struct MeshFlowControl
{
  /**
   * ID of the last packet sent towards the peer.
   */
  uint32_t last_pid_sent;

  /**
   * ID of the last packet received from the peer.
   */
  uint32_t last_pid_recv;

  /**
   * Last ACK sent to the peer (peer can't send more than this PID).
   */
  uint32_t last_ack_sent;

  /**
   * Last ACK sent towards the origin (for traffic towards leaf node).
   */
  uint32_t last_ack_recv;

  /**
   * How many payload messages are in the queue towards this peer.
   */
  uint32_t queue_n;

  /**
   * Task to poll the peer in case of a lost ACK causes stall.
   */
  GNUNET_SCHEDULER_TaskIdentifier poll_task;

  /**
   * How frequently to poll for ACKs.
   */
  struct GNUNET_TIME_Relative poll_time;

  /**
   * On which tunnel to poll.
   * Using an explicit poll_ctx would not help memory wise,
   * since the allocated context would have to be stored in the
   * fc struct in order to free it upon cancelling poll_task.
   */
  struct MeshTunnel *t;
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


/**
 * Data needed for reliable tunnel endpoint retransmission management.
 */
struct MeshTunnelReliability;


/**
 * Info needed to retry a message in case it gets lost.
 */
struct MeshReliableMessage
{
    /**
     * Double linked list, FIFO style
     */
  struct MeshReliableMessage    *next;
  struct MeshReliableMessage    *prev;

    /**
     * Tunnel Reliability queue this message is in.
     */
  struct MeshTunnelReliability  *rel;

    /**
     * ID of the message (ACK needed to free)
     */
  uint32_t                      mid;

    /**
     * When was this message issued (to calculate ACK delay) FIXME update with traffic
     */
  struct GNUNET_TIME_Absolute   timestamp;

  /* struct GNUNET_MESH_Data with payload */
};


struct MeshTunnelReliability
{
    /**
     * Tunnel this is about.
     */
  struct MeshTunnel *t;

    /**
     * DLL of messages sent and not yet ACK'd.
     */
  struct MeshReliableMessage        *head_sent;
  struct MeshReliableMessage        *tail_sent;

    /**
     * Messages pending
     */
  unsigned int                      n_sent;

    /**
     * Next MID to use.
     */
  uint32_t                          mid_sent;

    /**
     * DLL of messages received out of order.
     */
  struct MeshReliableMessage        *head_recv;
  struct MeshReliableMessage        *tail_recv;

    /**
     * Next MID expected.
     */
  uint32_t                          mid_recv;

    /**
     * Task to resend/poll in case no ACK is received.
     */
  GNUNET_SCHEDULER_TaskIdentifier   retry_task;

    /**
     * Counter for exponential backoff.
     */
  struct GNUNET_TIME_Relative       retry_timer;

    /**
     * How long does it usually take to get an ACK. FIXME update with traffic
     */
  struct GNUNET_TIME_Relative       expected_delay;
};


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
     * Port of the tunnel.
     */
  uint32_t port;

    /**
     * State of the tunnel.
     */
  enum MeshTunnelState state;

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
     * Is the tunnel bufferless (minimum latency)?
     */
  int nobuffer;

    /**
     * Is the tunnel reliable?
     */
  int reliable;

    /**
     * Force sending ACK? Flag to allow duplicate ACK on POLL.
     */
  int force_ack;

    /**
     * How many messages do we accept in the forward queue.
     */
  unsigned int queue_max;

    /**
     * Last time the tunnel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Destination of the tunnel.
     */
  GNUNET_PEER_Id dest;

    /**
     * Next hop in the tunnel. If 0, @c client must be set.
     */
  GNUNET_PEER_Id next_hop;

    /**
     * Previous hop in the tunnel. If 0, @c owner must be set.
     */
  GNUNET_PEER_Id prev_hop;

    /**
     * Flow control information about @c next_hop or @c client.
     */
  struct MeshFlowControl next_fc;

  /**
   * Flow control information about @c prev_hop or @c owner.
   */
  struct MeshFlowControl prev_fc;

    /**
     * Client owner of the tunnel, if any
     */
  struct MeshClient *owner;

    /**
     * Client destination of the tunnel, if any.
     */
  struct MeshClient *client;

    /**
     * Task to keep the used paths alive at the owner,
     * time tunnel out on all the other peers.
     */
  GNUNET_SCHEDULER_TaskIdentifier maintenance_task;

    /**
     * Path being used for the tunnel.
     */
  struct MeshPeerPath *path;

    /**
     * Flag to signal the destruction of the tunnel.
     * If this is set GNUNET_YES the tunnel will be destroyed
     * when the queue is empty.
     */
  int destroy;

    /**
     * Total messages pending for this tunnels, payload or not.
     */
  unsigned int pending_messages;

    /**
     * Reliability data.
     * Only present (non-NULL) at the owner of a tunnel.
     */
  struct MeshTunnelReliability *fwd_rel;

    /**
     * Reliability data.
     * Only present (non-NULL) at the destination of a tunnel.
     */
  struct MeshTunnelReliability *bck_rel;
};


/**
 * Struct containing information about a client of the service
 * 
 * TODO: add a list of 'waiting' ports
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
  struct GNUNET_CONTAINER_MultiHashMap32 *own_tunnels;

   /**
     * Tunnels this client has accepted, indexed by incoming local id
     */
  struct GNUNET_CONTAINER_MultiHashMap32 *incoming_tunnels;

    /**
     * Handle to communicate with the client
     */
  struct GNUNET_SERVER_Client *handle;

    /**
     * Ports that this client has declared interest in.
     * Indexed by port, contains *Client.
     */
  struct GNUNET_CONTAINER_MultiHashMap32 *ports;

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
 * @param success  GNUNET_OK if the PUT was transmitted,
 *                GNUNET_NO on timeout,
 *                GNUNET_SYSERR on disconnect from service
 *                after the PUT message was transmitted
 *                (so we don't know if it was received or not)
 */

#if 0
static void
mesh_debug (void *cls, int success)
{
  char *s = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s (%d)\n", s, success);
}
#endif

#endif

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/************************** Configuration parameters **************************/

/**
 * How often to send tunnel keepalives. Tunnels timeout after 4 missed.
 */
static struct GNUNET_TIME_Relative refresh_path_time;

/**
 * How often to PUT own ID in the DHT.
 */
static struct GNUNET_TIME_Relative id_announce_time;

/**
 * Maximum time allowed to connect to a peer found by string.
 */
static struct GNUNET_TIME_Relative connect_timeout;

/**
 * Default TTL for payload packets.
 */
static unsigned long long default_ttl;

/**
 * DHT replication level, see DHT API: GNUNET_DHT_get_start, GNUNET_DHT_put.
 */
static unsigned long long dht_replication_level;

/**
 * How many tunnels are we willing to maintain.
 * Local tunnels are always allowed, even if there are more tunnels than max.
 */
static unsigned long long max_tunnels;

/**
 * How many messages *in total* are we willing to queue, divided by number of 
 * tunnels to get tunnel queue size.
 */
static unsigned long long max_msgs_queue;

/**
 * How many peers do we want to remember?
 */
static unsigned long long max_peers;

/**
 * Percentage of messages that will be dropped (for test purposes only).
 */
static unsigned long long drop_percent;

/*************************** Static global variables **************************/

/**
 * DLL with all the clients, head.
 */
static struct MeshClient *clients_head;

/**
 * DLL with all the clients, tail.
 */
static struct MeshClient *clients_tail;

/**
 * Tunnels known, indexed by MESH_TunnelID (MeshTunnel).
 */
static struct GNUNET_CONTAINER_MultiHashMap *tunnels;

/**
 * Number of tunnels known.
 */
static unsigned long long n_tunnels;

/**
 * Tunnels incoming, indexed by MESH_TunnelNumber
 * (which is greater than GNUNET_MESH_LOCAL_TUNNEL_ID_SERV).
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *incoming_tunnels;

/**
 * Peers known, indexed by PeerIdentity (MeshPeerInfo).
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/*
 * Handle to communicate with transport
 */
// static struct GNUNET_TRANSPORT_Handle *transport_handle;

/**
 * Handle to communicate with core.
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Handle to use DHT.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to server.
 */
static struct GNUNET_SERVER_Handle *server_handle;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, to send messages to local clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Local peer own ID (memory efficient handle).
 */
static GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
static struct GNUNET_PeerIdentity my_full_id;

/**
 * Own private key.
 */
static struct GNUNET_CRYPTO_EccPrivateKey *my_private_key;

/**
 * Own public key.
 */
static struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded my_public_key;

/**
 * Tunnel ID for the next created tunnel (global tunnel number).
 */
static MESH_TunnelNumber next_tid;

/**
 * Tunnel ID for the next incoming tunnel (local tunnel number).
 */
static MESH_TunnelNumber next_local_tid;

/**
 * All ports clients of this peer have opened.
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *ports;

/**
 * Task to periodically announce itself in the network.
 */
GNUNET_SCHEDULER_TaskIdentifier announce_id_task;

/**
 * Next ID to assign to a client.
 */
unsigned int next_client_id;


/******************************************************************************/
/***********************         DECLARATIONS        **************************/
/******************************************************************************/

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
                    const struct GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data);


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_get (const struct GNUNET_PeerIdentity *peer);


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_get_short (const GNUNET_PEER_Id peer);


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
                     unsigned int put_path_length);


/**
 * Adds a path to the peer_infos of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
static void
path_add_to_peers (struct MeshPeerPath *p, int confirmed);



/**
 * Search for a tunnel by global ID using full PeerIdentities.
 *
 * @param oid owner of the tunnel.
 * @param tid global tunnel number.
 *
 * @return tunnel handler, NULL if doesn't exist.
 */
static struct MeshTunnel *
tunnel_get (const struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid);


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
 * @brief Use the given path for the tunnel.
 * Update the next and prev hops (and RCs).
 * (Re)start the path refresh in case the tunnel is locally owned.
 * 
 * @param t Tunnel to update.
 * @param p Path to use.
 */
static void
tunnel_use_path (struct MeshTunnel *t, struct MeshPeerPath *p);

/**
 * Tunnel is empty: destroy it.
 * 
 * Notifies all participants (peers, cleints) about the destruction.
 * 
 * @param t Tunnel to destroy. 
 */
static void
tunnel_destroy_empty (struct MeshTunnel *t);

/**
 * @brief Queue and pass message to core when possible.
 * 
 * If type is payload (UNICAST, TO_ORIGIN, MULTICAST) checks for queue status
 * and accounts for it. In case the queue is full, the message is dropped and
 * a break issued.
 * 
 * Otherwise, message is treated as internal and allowed to go regardless of 
 * queue status.
 *
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
 * @param size Size of the message.
 * @param dst Neighbor to send message to.
 * @param t Tunnel this message belongs to.
 */
static void
queue_add (void *cls, uint16_t type, size_t size,
           struct MeshPeerInfo *dst, struct MeshTunnel *t);


/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
static void
queue_destroy (struct MeshPeerQueue *queue, int clear_cls);


/**
 * @brief Get the next transmittable message from the queue.
 *
 * This will be the head, except in the case of being a data packet
 * not allowed by the destination peer.
 *
 * @param peer Destination peer.
 *
 * @return The next viable MeshPeerQueue element to send to that peer.
 *         NULL when there are no transmittable messages.
 */
struct MeshPeerQueue *
queue_get_next (const struct MeshPeerInfo *peer);


/**
 * Core callback to write a queued packet to core buffer
 *
 * @param cls Closure (peer info).
 * @param size Number of bytes available in buf.
 * @param buf Where the to write the message.
 *
 * @return number of bytes written to buf
 */
static size_t
queue_send (void *cls, size_t size, void *buf);


/******************************************************************************/
/************************    PERIODIC FUNCTIONS    ****************************/
/******************************************************************************/

/**
 * Periodically announce self id in the DHT
 *
 * @param cls closure
 * @param tc task context
 */
static void
announce_id (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PBlock block;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    announce_id_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  /* TODO
   * - Set data expiration in function of X
   * - Adapt X to churn
   */
  DEBUG_DHT ("DHT_put for ID %s started.\n", GNUNET_i2s (&my_full_id));

  block.id = my_full_id;
  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &my_full_id.hashPubKey,       /* Key to use */
                  dht_replication_level,     /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,    /* DHT options */
                  GNUNET_BLOCK_TYPE_MESH_PEER,       /* Block type */
                  sizeof (block),  /* Size of the data */
                  (const char *) &block, /* Data itself */
                  GNUNET_TIME_UNIT_FOREVER_ABS,  /* Data expiration */
                  GNUNET_TIME_UNIT_FOREVER_REL, /* Retry time */
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
  announce_id_task =
      GNUNET_SCHEDULER_add_delayed (id_announce_time, &announce_id, cls);
}


/******************************************************************************/
/******************      GENERAL HELPER FUNCTIONS      ************************/
/******************************************************************************/


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
  return GNUNET_SERVER_client_get_user_context (client, struct MeshClient);
}


/**
 * Deletes a tunnel from a client (either owner or destination). To be used on
 * tunnel destroy.
 *
 * @param c Client whose tunnel to delete.
 * @param t Tunnel which should be deleted.
 */
static void
client_delete_tunnel (struct MeshClient *c, struct MeshTunnel *t)
{
  if (c == t->owner)
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap32_remove (c->own_tunnels,
                                                           t->local_tid,
                                                           t));
  }
  if (c == t->client)
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap32_remove (c->incoming_tunnels,
                                                           t->local_tid_dest,
                                                           t));
  }
}

/**
 * Notify the appropriate client that a new incoming tunnel was created.
 *
 * @param t Tunnel that was created.
 */
static void
send_client_tunnel_create (struct MeshTunnel *t)
{
  struct GNUNET_MESH_TunnelMessage msg;

  if (NULL == t->client)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
  msg.tunnel_id = htonl (t->local_tid_dest);
  msg.port = htonl (t->port);
  msg.opt = 0;
  msg.opt |= GNUNET_YES == t->reliable ? GNUNET_MESH_OPTION_RELIABLE : 0;
  msg.opt |= GNUNET_YES == t->nobuffer ? GNUNET_MESH_OPTION_NOBUFFER : 0;
  msg.opt = htonl (msg.opt);
  GNUNET_PEER_resolve (t->id.oid, &msg.peer);
  GNUNET_SERVER_notification_context_unicast (nc, t->client->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Notify dest client that the incoming tunnel is no longer valid.
 *
 * @param t Tunnel that is destroyed.
 * @param fwd Forward notification (owner->dest)?
 */
static void
send_client_tunnel_destroy (struct MeshTunnel *t, int fwd)
{
  struct GNUNET_MESH_TunnelMessage msg;
  struct MeshClient *c;

  c = fwd ? t->client : t->owner;
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.tunnel_id = htonl (fwd ? t->local_tid_dest : t->local_tid);
  msg.port = htonl (0);
  memset (&msg.peer, 0, sizeof (msg.peer));
  msg.opt = htonl (0);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Iterator over all the peers to remove the oldest not-used entry.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 *
 * FIXME implement
 */
static int
peer_info_timeout (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  return GNUNET_YES;
}

/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_get (const struct GNUNET_PeerIdentity *peer)
{
  struct MeshPeerInfo *peer_info;

  peer_info = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == peer_info)
  {
    peer_info =
        (struct MeshPeerInfo *) GNUNET_malloc (sizeof (struct MeshPeerInfo));
    if (GNUNET_CONTAINER_multihashmap_size (peers) > max_peers)
    {
      GNUNET_CONTAINER_multihashmap_iterate (peers,
                                             &peer_info_timeout,
                                             NULL);
    }
    GNUNET_CONTAINER_multihashmap_put (peers, &peer->hashPubKey, peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    peer_info->id = GNUNET_PEER_intern (peer);
  }
  peer_info->last_contact = GNUNET_TIME_absolute_get();

  return peer_info;
}


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_get_short (const GNUNET_PEER_Id peer)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer, &id);
  return peer_get (&id);
}


/**
 * Select which PID to POLL for, to compensate for lost messages.
 *
 * @param pi Peer we want to poll.
 * @param t Tunnel about which we want to poll.
 * 
 * @return PID to use, either last sent or first_in_queue - 1
 */
static uint32_t
peer_get_first_payload_pid (struct MeshPeerInfo *pi, struct MeshTunnel *t)
{
  struct MeshPeerQueue *q;
  uint16_t type;

  type = pi->id == t->next_hop ? GNUNET_MESSAGE_TYPE_MESH_UNICAST :
                                 GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN;

  for (q = pi->queue_head; NULL != q; q = q->next)
  {
    if (q->type == type && q->tunnel == t)
    {
      struct GNUNET_MESH_Data *msg = q->cls;

      /* Pretend that the last one sent was the previous to this */
      return ntohl (msg->pid) - 1;
    }
  }

  /* No data in queue, use last sent */
  {
    struct MeshFlowControl *fc;

    fc = pi->id == t->next_hop ? &t->next_fc : &t->prev_fc;
    return fc->last_pid_sent;
  }
}


/**
 * Choose the best path towards a peer considering the tunnel properties.
 * 
 * @param peer The destination peer.
 * @param t The tunnel the path is for.
 *
 * @return Best current known path towards the peer, if any.
 */
static struct MeshPeerPath *
peer_get_best_path (const struct MeshPeerInfo *peer, const struct MeshTunnel *t)
{
  struct MeshPeerPath *best_p;
  struct MeshPeerPath *p;
  unsigned int best_cost;
  unsigned int cost;

  best_p = p = peer->path_head;
  best_cost = cost = p->length;
  while (NULL != p)
  {
    if ((cost = p->length) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
        p = p->next;
  }
  return best_p;
}

/**
  * Core callback to write a pre-constructed data packet to core buffer
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
  struct GNUNET_MessageHeader *msg = cls;
  size_t total_size;

  GNUNET_assert (NULL != msg);
  total_size = ntohs (msg->size);

  if (total_size > size)
  {
    GNUNET_break (0);
    return 0;
  }
  memcpy (buf, msg, total_size);
  GNUNET_free (cls);
  return total_size;
}


/**
 * Sends an already built message to a peer, properly registrating
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param peer Short ID of the neighbor whom to send the message.
 * @param t Tunnel on which this message is transmitted.
 */
static void
send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                       GNUNET_PEER_Id peer,
                       struct MeshTunnel *t)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPeerInfo *neighbor;
  struct MeshPeerPath *p;
  void *data;
  size_t size;
  uint16_t type;

//   GNUNET_TRANSPORT_try_connect(); FIXME use?

  if (0 == peer)
    return;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs(message->type);
  if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == type ||
      GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == type)
  {
    struct GNUNET_MESH_Data *u;

    u = (struct GNUNET_MESH_Data *) data;
    u->ttl = htonl (ntohl (u->ttl) - 1);
  }
  GNUNET_PEER_resolve (peer, &id);
  neighbor = peer_get (&id);
  for (p = neighbor->path_head; NULL != p; p = p->next)
  {
    if (2 >= p->length)
    {
      break;
    }
  }
  if (NULL == p)
  {
#if MESH_DEBUG
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  %s IS NOT DIRECTLY CONNECTED\n",
                GNUNET_i2s(&id));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  PATHS TO %s:\n",
                GNUNET_i2s(&id));
    for (p = neighbor->path_head; NULL != p; p = p->next)
    {
      struct GNUNET_PeerIdentity debug_id;
      unsigned int i;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "    path with %u hops through:\n",
                  p->length);
      for (i = 0; i < p->length; i++)
      {
        GNUNET_PEER_resolve(p->peers[i], &debug_id);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "      hop %u: %s\n",
                    i, GNUNET_i2s(&debug_id));
      }
    }
#endif
    GNUNET_break (0); // FIXME sometimes fails (testing disconnect?)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    " no direct connection to %s\n",
                    GNUNET_i2s (&id));
    GNUNET_free (data);
    return;
  }
  if (GNUNET_MESSAGE_TYPE_MESH_PATH_ACK == type)
    type = 0;
  queue_add (data,
             type,
             size,
             neighbor,
             t);
}


/**
 * Sends a CREATE PATH message for a path to a peer, properly registrating
 * all used resources.
 *
 * @param t Tunnel for which the path is created.
 */
static void
send_create_path (struct MeshTunnel *t)
{
  struct MeshPeerInfo *neighbor;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send create path\n");
  neighbor = peer_get_short (t->next_hop);
  queue_add (t,
             GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE,
             sizeof (struct GNUNET_MESH_CreateTunnel) +
                (t->path->length * sizeof (struct GNUNET_PeerIdentity)),
             neighbor,
             t);
  t->state = MESH_TUNNEL_WAITING;
}


/**
 * Sends a PATH ACK message in reponse to a received PATH_CREATE directed to us.
 *
 * @param t Tunnel which to confirm.
 */
static void
send_path_ack (struct MeshTunnel *t) 
{
  struct MeshPeerInfo *peer;

  peer = peer_get_short (t->prev_hop);

  queue_add (t,
             GNUNET_MESSAGE_TYPE_MESH_PATH_ACK,
             sizeof (struct GNUNET_MESH_PathACK),
             peer,
             t);
}


/**
 * Try to establish a new connection to this peer in the given tunnel.
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE PATH towards it.
 *
 * @param peer PeerInfo of the peer.
 * @param t Tunnel for which to create the path, if possible.
 */
static void
peer_connect (struct MeshPeerInfo *peer, struct MeshTunnel *t)
{
  struct MeshPeerPath *p;

  if (NULL != peer->path_head)
  {
    p = peer_get_best_path (peer, t);
    tunnel_use_path (t, p);
    send_create_path (t);
  }
  else if (NULL == peer->dhtget)
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer->id, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", GNUNET_i2s (&id));
    peer->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                         GNUNET_BLOCK_TYPE_MESH_PEER, /* type */
                                         &id.hashPubKey,     /* key to search */
                                         dht_replication_level, /* replication level */
                                         GNUNET_DHT_RO_RECORD_ROUTE |
                                         GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                         NULL,       /* xquery */
                                         0,     /* xquery bits */
                                         &dht_get_id_handler, peer);
    t->state = MESH_TUNNEL_SEARCHING;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "There is no path but the DHT GET is already started.\n");
  }
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
  }
  p = pi->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (pi->path_head, pi->path_tail, p);
    path_destroy (p);
    p = nextp;
  }
  for (i = 0; i < pi->ntunnels; i++)
    tunnel_destroy_empty (pi->tunnels[i]);
  GNUNET_array_grow (pi->tunnels, pi->ntunnels, 0);
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
peer_remove_path (struct MeshPeerInfo *peer, GNUNET_PEER_Id p1,
                       GNUNET_PEER_Id p2)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *next;
  struct MeshPeerInfo *peer_d;
  GNUNET_PEER_Id d;
  unsigned int destroyed;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer_info_remove_path\n");
  destroyed = 0;
  for (p = peer->path_head; NULL != p; p = next)
  {
    next = p->next;
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
  }
  if (0 == destroyed)
    return;

  for (i = 0; i < peer->ntunnels; i++)
  {
    d = tunnel_notify_connection_broken (peer->tunnels[i], p1, p2);
    if (0 == d)
      continue;

    peer_d = peer_get_short (d);
    next = peer_get_best_path (peer_d, peer->tunnels[i]);
    tunnel_use_path (peer->tunnels[i], next);
    peer_connect (peer_d, peer->tunnels[i]);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer_info_remove_path END\n");
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
  if (2 >= path->length && GNUNET_NO == trusted)
  {
    /* Only allow CORE to tell us about direct paths */
    path_destroy (path);
    return;
  }
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
    path_destroy (path);
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
 *             Path will be either used or freed.
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
 * Add a tunnel to the list of tunnels a peer participates in.
 * Update the tunnel's destination.
 * 
 * @param p Peer to add to.
 * @param t Tunnel to add.
 */
static void
peer_info_add_tunnel (struct MeshPeerInfo *p, struct MeshTunnel *t)
{
  if (0 != t->dest)
  {
    GNUNET_break (t->dest == p->id);
    return;
  }
  t->dest = p->id;
  GNUNET_PEER_change_rc (t->dest, 1);
  GNUNET_array_append (p->tunnels, p->ntunnels, t);
}


/**
 * Remove a tunnel from the list of tunnels a peer participates in.
 * Free the tunnel's destination.
 * 
 * @param p Peer to clean.
 * @param t Tunnel to remove.
 */
static void
peer_info_remove_tunnel (struct MeshPeerInfo *p, struct MeshTunnel *t)
{
  unsigned int i;

  if (t->dest == p->id)
  {
      GNUNET_PEER_change_rc (t->dest, -1);
      t->dest = 0;
  }
  for (i = 0; i < p->ntunnels; i++)
  {
    if (p->tunnels[i] == t)
    {
      p->tunnels[i] = p->tunnels[p->ntunnels - 1];
      GNUNET_array_grow (p->tunnels, p->ntunnels, p->ntunnels - 1);
      return;
    }
  }
}


/**
 * Function called if the connection to the peer has been stalled for a while,
 * possibly due to a missed ACK. Poll the peer about its ACK status.
 *
 * @param cls Closure (poll ctx).
 * @param tc TaskContext.
 */
static void
tunnel_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshFlowControl *fc = cls;
  struct GNUNET_MESH_Poll msg;
  struct MeshTunnel *t = fc->t;
  GNUNET_PEER_Id peer;

  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");

  GNUNET_PEER_resolve (t->id.oid, &msg.oid);

  if (fc == &t->prev_fc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** prev peer!\n");
    peer = t->prev_hop;
  }
  else if (fc == &t->next_fc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** next peer!\n");
    peer = t->next_hop;
  }
  else
  {
    GNUNET_break (0);
    return;
  }
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  msg.tid = htonl (t->id.tid);
  msg.pid = htonl (peer_get_first_payload_pid (peer_get_short (peer), t));
  send_prebuilt_message (&msg.header, peer, t);
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &tunnel_poll, fc);
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
 * @param confirmed Whether we know if the path works or not.
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

    aux = peer_get_short (p->peers[i]);
    copy = path_duplicate (p);
    copy->length = i + 1;
    peer_info_add_path (aux, copy, p->length < 3 ? GNUNET_NO : confirmed);
  }
}


/**
 * Send keepalive packets for a peer
 *
 * @param cls Closure (tunnel for which to send the keepalive).
 * @param tc Notification context.
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
  GNUNET_assert (tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV);
  return GNUNET_CONTAINER_multihashmap32_get (incoming_tunnels, tid);
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
    GNUNET_assert (tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_CLI);
    return GNUNET_CONTAINER_multihashmap32_get (c->own_tunnels, tid);
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
  struct GNUNET_HashCode hash;

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
tunnel_get (const struct GNUNET_PeerIdentity *oid, MESH_TunnelNumber tid)
{
  return tunnel_get_by_pi (GNUNET_PEER_search (oid), tid);
}


/**
 * Add a client to a tunnel, initializing all needed data structures.
 * 
 * @param t Tunnel to which add the client.
 * @param c Client which to add to the tunnel.
 */
static void
tunnel_add_client (struct MeshTunnel *t, struct MeshClient *c)
{
  if (NULL != t->client)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap32_put (c->incoming_tunnels,
                                           t->local_tid_dest, t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap32_put (incoming_tunnels,
                                           t->local_tid_dest, t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }
  t->client = c;
}


static void
tunnel_use_path (struct MeshTunnel *t, struct MeshPeerPath *p)
{
  unsigned int own_pos;

  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    return;
  }

  if (own_pos < p->length - 1)
    t->next_hop = p->peers[own_pos + 1];
  else
    t->next_hop = p->peers[own_pos];
  GNUNET_PEER_change_rc (t->next_hop, 1);
  if (0 < own_pos)
    t->prev_hop = p->peers[own_pos - 1];
  else
    t->prev_hop = p->peers[0];
  GNUNET_PEER_change_rc (t->prev_hop, 1);

  if (NULL != t->path)
    path_destroy (t->path);
  t->path = path_duplicate (p);
  if (0 == own_pos)
  {
    if (GNUNET_SCHEDULER_NO_TASK != t->maintenance_task)
      GNUNET_SCHEDULER_cancel (t->maintenance_task);
    t->maintenance_task = GNUNET_SCHEDULER_add_delayed (refresh_path_time,
                                                        &path_refresh, t);
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
//   if (myid != p1 && myid != p2) FIXME
//   {
//     return;
//   }
// 
//   if (tree_get_predecessor (t->tree) != 0)
//   {
//     /* We are the peer still connected, notify owner of the disconnection. */
//     struct GNUNET_MESH_PathBroken msg;
//     struct GNUNET_PeerIdentity neighbor;
// 
//     msg.header.size = htons (sizeof (msg));
//     msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN);
//     GNUNET_PEER_resolve (t->id.oid, &msg.oid);
//     msg.tid = htonl (t->id.tid);
//     msg.peer1 = my_full_id;
//     GNUNET_PEER_resolve (pid, &msg.peer2);
//     GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &neighbor);
//     send_prebuilt_message (&msg.header, &neighbor, t);
//   }
  return 0;
}


/**
 * Build a local ACK message and send it to a local client.
 * 
 * @param t Tunnel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param is_fwd Set to GNUNET_YES for FWD ACK (dest->owner)
 */
static void
send_local_ack (struct MeshTunnel *t,
                struct MeshClient *c,
                int is_fwd)
{
  struct GNUNET_MESH_LocalAck msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.tunnel_id = htonl (is_fwd ? t->local_tid : t->local_tid_dest);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              c->handle,
                                              &msg.header,
                                              GNUNET_NO);
}

/**
 * Build an ACK message and queue it to send to the given peer.
 * 
 * @param t Tunnel on which to send the ACK.
 * @param peer Peer to whom send the ACK.
 * @param ack Value of the ACK.
 */
static void
send_ack (struct MeshTunnel *t, GNUNET_PEER_Id peer,  uint32_t ack)
{
  struct GNUNET_MESH_ACK msg;

  GNUNET_PEER_resolve (t->id.oid, &msg.oid);
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.pid = htonl (ack);
  msg.tid = htonl (t->id.tid);

  send_prebuilt_message (&msg.header, peer, t);
}


/**
 * Send an end-to-end FWD ACK message for the most recent in-sequence payload.
 * 
 * @param t Tunnel this is about.
 * @param fwd Is for FWD traffic? (ACK dest->owner)
 */
static void
tunnel_send_data_ack (struct MeshTunnel *t, int fwd)
{
  struct GNUNET_MESH_DataACK msg;
  struct MeshTunnelReliability *rel;
  struct MeshReliableMessage *copy;
  GNUNET_PEER_Id hop;
  uint64_t mask;
  unsigned int delta;

  rel = fwd ? t->bck_rel  : t->fwd_rel;
  hop = fwd ? t->prev_hop : t->next_hop;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send_data_ack for %u\n",
              rel->mid_recv - 1);

  if (GNUNET_NO == t->reliable)
  {
    GNUNET_break_op (0);
    return;
  }
  msg.header.type = htons (fwd ? GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK :
                                 GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK);
  msg.header.size = htons (sizeof (msg));
  msg.tid = htonl (t->id.tid);
  GNUNET_PEER_resolve (t->id.oid, &msg.oid);
  msg.mid = htonl (rel->mid_recv - 1);
  msg.futures = 0;
  for (copy = rel->head_recv; NULL != copy; copy = copy->next)
  {
    delta = copy->mid - rel->mid_recv;
    if (63 < delta)
      break;
    mask = 0x1LL << delta;
    msg.futures |= mask;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " setting bit for %u (delta %u) (%llX) -> %llX\n",
                copy->mid, delta, mask, msg.futures);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " final futures %llX\n", msg.futures);

  send_prebuilt_message (&msg.header, hop, t);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_data_ack END\n");
}


/**
 * Send an ACK informing the predecessor about the available buffer space.
 * In case there is no predecessor, inform the owning client.
 * If buffering is off, send only on behalf of children or self if endpoint.
 * If buffering is on, send when sent to children and buffer space is free.
 * Note that although the name is fwd_ack, the FWD mean forward *traffic*,
 * the ACK itself goes "back" (towards root).
 * 
 * @param t Tunnel on which to send the ACK.
 * @param type Type of message that triggered the ACK transmission.
 * @param fwd Is this FWD ACK? (Going dest->owner)
 */
static void
tunnel_send_ack (struct MeshTunnel *t, uint16_t type, int fwd)
{
  struct MeshTunnelReliability *rel;
  struct MeshFlowControl *next_fc;
  struct MeshFlowControl *prev_fc;
  struct MeshClient *c;
  struct MeshClient *o;
  GNUNET_PEER_Id hop;
  uint32_t delta_mid;
  uint32_t ack;
  int delta;

  rel     = fwd ? t->fwd_rel  : t->bck_rel;
  c       = fwd ? t->client   : t->owner;
  o       = fwd ? t->owner    : t->client;
  next_fc = fwd ? &t->next_fc : &t->prev_fc;
  prev_fc = fwd ? &t->prev_fc : &t->next_fc;
  hop     = fwd ? t->prev_hop : t->next_hop;

  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ACK due to %s\n",
                  GNUNET_MESH_DEBUG_M2S (type));
      if (GNUNET_YES == t->nobuffer)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, nobuffer\n");
        return;
      }
      if (GNUNET_YES == t->reliable && NULL != c)
        tunnel_send_data_ack (t, fwd);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK:
      break;
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
    case GNUNET_MESSAGE_TYPE_MESH_PATH_ACK:
      t->force_ack = GNUNET_YES;
      break;
    default:
      GNUNET_break (0);
  }

  /* Check if we need to transmit the ACK */
  /* FIXME unlock */
  if (0 && NULL == o && 
      t->queue_max > next_fc->queue_n * 4 &&
      GMC_is_pid_bigger (prev_fc->last_ack_sent, prev_fc->last_pid_recv) &&
      GNUNET_NO == t->force_ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer free\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  t->qmax: %u, t->qn: %u\n",
                t->queue_max, next_fc->queue_n);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  t->pid: %u, t->ack: %u\n",
                prev_fc->last_pid_recv, prev_fc->last_ack_sent);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  delta = t->queue_max - next_fc->queue_n;
  if (NULL != o && GNUNET_YES == t->reliable && NULL != rel->head_sent)
    delta_mid = rel->mid_sent - rel->head_sent->mid;
  else
    delta_mid = 0;
  if (0 > delta || (GNUNET_YES == t->reliable && 
                    NULL != o &&
                    (10 < rel->n_sent || 64 <= delta_mid)))
    delta = 0;
  if (NULL != o && delta > 1)
    delta = 1;
  ack = prev_fc->last_pid_recv + delta;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " last pid %u, last ack %u, qmax %u, q %u\n",
              prev_fc->last_pid_recv, prev_fc->last_ack_sent,
              t->queue_max, next_fc->queue_n);
  if (ack == prev_fc->last_ack_sent && GNUNET_NO == t->force_ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
    return;
  }

  prev_fc->last_ack_sent = ack;
  if (NULL != o)
    send_local_ack (t, o, fwd);
  else if (0 != hop)
    send_ack (t, hop, ack);
  else
    GNUNET_break (GNUNET_YES == t->destroy);
  t->force_ack = GNUNET_NO;
}


/**
 * Modify the mesh message TID from global to local and send to client.
 * 
 * @param t Tunnel on which to send the message.
 * @param msg Message to modify and send.
 * @param c Client to send to.
 * @param tid Tunnel ID to use (c can be both owner and client).
 */
static void
tunnel_send_client_to_tid (struct MeshTunnel *t,
                           const struct GNUNET_MESH_Data *msg,
                           struct MeshClient *c, MESH_TunnelNumber tid)
{
  struct GNUNET_MESH_LocalData *copy;
  uint16_t size = ntohs (msg->header.size) - sizeof (struct GNUNET_MESH_Data);
  char cbuf[size + sizeof (struct GNUNET_MESH_LocalData)];

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  copy = (struct GNUNET_MESH_LocalData *) cbuf;
  memcpy (&copy[1], &msg[1], size);
  copy->header.size = htons (sizeof (struct GNUNET_MESH_LocalData) + size);
  copy->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA);
  copy->tid = htonl (tid);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &copy->header, GNUNET_NO);
}

/**
 * Modify the unicast message TID from global to local and send to client.
 * 
 * @param t Tunnel on which to send the message.
 * @param msg Message to modify and send.
 * @param fwd Forward?
 */
static void
tunnel_send_client_data (struct MeshTunnel *t,
                         const struct GNUNET_MESH_Data *msg,
                         int fwd)
{
  if (fwd)
    tunnel_send_client_to_tid (t, msg, t->client, t->local_tid_dest);
  else
    tunnel_send_client_to_tid (t, msg, t->owner, t->local_tid);
}


/**
 * Send up to 64 buffered messages to the client for in order delivery.
 * 
 * @param t Tunnel on which to empty the message buffer.
 * @param c Client to send to.
 * @param rel Reliability structure to corresponding peer.
 *            If rel == t->bck_rel, this is FWD data.
 */
static void
tunnel_send_client_buffered_data (struct MeshTunnel *t, struct MeshClient *c,
                                  struct MeshTunnelReliability *rel)
{
  ;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data\n");
  for (copy = rel->head_recv; NULL != copy; copy = next)
  {
    next = copy->next;
    if (copy->mid == rel->mid_recv)
    {
      struct GNUNET_MESH_Data *msg = (struct GNUNET_MESH_Data *) &copy[1];

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " have %u! now expecting %u\n",
                  copy->mid, rel->mid_recv + 1);
      tunnel_send_client_data (t, msg, (rel == t->bck_rel));
      rel->mid_recv++;
      GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
      GNUNET_free (copy);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " don't have %u, next is %u\n",
                  rel->mid_recv,
                  copy->mid);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data END\n");
}


/**
 * We have received a message out of order, buffer it until we receive
 * the missing one and we can feed the rest to the client.
 * 
 * @param t Tunnel to add to.
 * @param msg Message to buffer.
 * @param rel Reliability data to the corresponding direction.
 */
static void
tunnel_add_buffered_data (struct MeshTunnel *t,
                           const struct GNUNET_MESH_Data *msg,
                          struct MeshTunnelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *prev;
  uint32_t mid;
  uint16_t size;

  size = ntohs (msg->header.size);
  mid = ntohl (msg->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data %u\n", mid);

  copy = GNUNET_malloc (sizeof (*copy) + size);
  copy->mid = mid;
  copy->rel = rel;
  memcpy (&copy[1], msg, size);

  // FIXME do something better than O(n), although n < 64...
  // FIXME start from the end (most messages are the latest ones)
  for (prev = rel->head_recv; NULL != prev; prev = prev->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " prev %u\n", prev->mid);
    if (GMC_is_pid_bigger (prev->mid, mid))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " bingo!\n");
      GNUNET_CONTAINER_DLL_insert_before (rel->head_recv, rel->tail_recv,
                                          prev, copy);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " insert at tail!\n");
  GNUNET_CONTAINER_DLL_insert_tail (rel->head_recv, rel->tail_recv, copy);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data END\n");
}


/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 * 
 * @param copy Message that is no longer needed: remote peer got it.
 */
static void
tunnel_free_reliable_message (struct MeshReliableMessage *copy)
{
  struct MeshTunnelReliability *rel;
  struct GNUNET_TIME_Relative time;

  rel = copy->rel;
  time = GNUNET_TIME_absolute_get_duration (copy->timestamp);
  rel->expected_delay.rel_value *= 7;
  rel->expected_delay.rel_value += time.rel_value;
  rel->expected_delay.rel_value /= 8;
  rel->n_sent--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! Freeing %u\n", copy->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    n_sent %u\n", rel->n_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  took %s\n",
              GNUNET_STRINGS_relative_time_to_string (time, GNUNET_NO));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  new expected delay %s\n",
              GNUNET_STRINGS_relative_time_to_string (rel->expected_delay,
                                                      GNUNET_NO));
  rel->retry_timer = rel->expected_delay;
  GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
  GNUNET_free (copy);
}


/**
 * Mark future messages as ACK'd.
 *
 * @param t Tunnel whose sent buffer to clean.
 * @param msg DataACK message with a bitfield of future ACK'd messages.
 * @param rel Reliability data.
 */
static void
tunnel_free_sent_reliable (struct MeshTunnel *t,
                           const struct GNUNET_MESH_DataACK *msg,
                           struct MeshTunnelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;
  uint64_t bitfield;
  uint64_t mask;
  uint32_t mid;
  uint32_t target;
  unsigned int i;

  bitfield = msg->futures;
  mid = ntohl (msg->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "free_sent_reliable %u %llX\n",
              mid, bitfield);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " rel %p, head %p\n",
              rel, rel->head_sent);
  for (i = 0, copy = rel->head_sent;
       i < 64 && NULL != copy && 0 != bitfield;
       i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " trying bit %u (mid %u)\n",
                i, mid + i + 1);
    mask = 0x1LL << i;
    if (0 == (bitfield & mask))
     continue;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " set!\n");
    /* Bit was set, clear the bit from the bitfield */
    bitfield &= ~mask;

    /* The i-th bit was set. Do we have that copy? */
    /* Skip copies with mid < target */
    target = mid + i + 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " target %u\n", target);
    while (NULL != copy && GMC_is_pid_bigger (target, copy->mid))
     copy = copy->next;

    /* Did we run out of copies? (previously freed, it's ok) */
    if (NULL == copy)
    {
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "run out of copies...\n");
     return;
    }

    /* Did we overshoot the target? (previously freed, it's ok) */
    if (GMC_is_pid_bigger (copy->mid, target))
    {
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " next copy %u\n", copy->mid);
     continue;
    }

    /* Now copy->mid == target, free it */
    next = copy->next;
    tunnel_free_reliable_message (copy);
    copy = next;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "free_sent_reliable END\n");
}


/**
 * We haven't received an ACK after a certain time: restransmit the message.
 *
 * @param cls Closure (MeshReliableMessage with the message to restransmit)
 * @param tc TaskContext.
 */
static void
tunnel_retransmit_message (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnelReliability *rel = cls;
  struct MeshReliableMessage *copy;
  struct MeshFlowControl *fc;
  struct MeshPeerQueue *q;
  struct MeshPeerInfo *pi;
  struct MeshTunnel *t;
  struct GNUNET_MESH_Data *payload;
  GNUNET_PEER_Id hop;

  rel->retry_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  t = rel->t;
  copy = rel->head_sent;
  if (NULL == copy)
  {
    GNUNET_break (0);
    return;
  }

  /* Search the message to be retransmitted in the outgoing queue */
  payload = (struct GNUNET_MESH_Data *) &copy[1];
  hop = rel == t->fwd_rel ? t->next_hop : t->prev_hop;
  fc  = rel == t->fwd_rel ? &t->prev_fc : &t->next_fc;
  pi  = peer_get_short (hop);
  for (q = pi->queue_head; NULL != q; q = q->next)
  {
    if (ntohs (payload->header.type) == q->type)
    {
      struct GNUNET_MESH_Data *queued_data = q->cls;

      if (queued_data->mid == payload->mid)
        break;
    }
  }

  /* Message not found in the queue */
  if (NULL == q)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! RETRANSMIT %u\n", copy->mid);

    fc->last_ack_sent++;
    fc->last_pid_recv++;
    payload->pid = htonl (fc->last_pid_recv);
    send_prebuilt_message (&payload->header, hop, t);
    GNUNET_STATISTICS_update (stats, "# data retransmitted", 1, GNUNET_NO);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! STILL IN QUEUE %u\n", copy->mid);
  }

  rel->retry_timer = GNUNET_TIME_STD_BACKOFF (rel->retry_timer);
  rel->retry_task = GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                                  &tunnel_retransmit_message,
                                                  cls);
}


/**
 * @brief Re-initiate traffic to this peer if necessary.
 *
 * Check if there is traffic queued towards this peer
 * and the core transmit handle is NULL (traffic was stalled).
 * If so, call core tmt rdy.
 *
 * @param peer_id Short ID of peer to which initiate traffic.
 */
static void
peer_unlock_queue(GNUNET_PEER_Id peer_id)
{
  struct MeshPeerInfo *peer;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerQueue *q;
  size_t size;

  peer = peer_get_short (peer_id);
  if (NULL != peer->core_transmit)
    return;

  q = queue_get_next (peer);
  if (NULL == q)
  {
    /* Might br multicast traffic already sent to this particular peer but
     * not to other children in this tunnel.
     * This way t->queue_n would be > 0 but the queue of this particular peer
     * would be empty.
     */
    return;
  }
  size = q->size;
  GNUNET_PEER_resolve (peer->id, &id);
  peer->core_transmit =
        GNUNET_CORE_notify_transmit_ready(core_handle,
                                          0,
                                          0,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          &id,
                                          size,
                                          &queue_send,
                                          peer);
        return;
}


/**
 * Send a message to all peers and clients in this tunnel that the tunnel
 * is no longer valid. If some peer or client should not receive the message,
 * should be zero'ed out before calling this function.
 *
 * @param t The tunnel whose peers and clients to notify.
 */
static void
tunnel_send_destroy (struct MeshTunnel *t)
{
  struct GNUNET_MESH_TunnelDestroy msg;
  struct GNUNET_PeerIdentity id;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY);
  GNUNET_PEER_resolve (t->id.oid, &msg.oid);
  msg.tid = htonl (t->id.tid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending tunnel destroy for tunnel: %s [%X]\n",
              GNUNET_i2s (&msg.oid), t->id.tid);

  if (NULL == t->client && 0 != t->next_hop)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  child: %u\n", t->next_hop);
    GNUNET_PEER_resolve (t->next_hop, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  sending forward to %s\n",
                GNUNET_i2s (&id));
    send_prebuilt_message (&msg.header, t->next_hop, t);
  }
  if (NULL == t->owner && 0 != t->prev_hop)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  parent: %u\n", t->prev_hop);
    GNUNET_PEER_resolve (t->prev_hop, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  sending back to %s\n",
                GNUNET_i2s (&id));
    send_prebuilt_message (&msg.header, t->prev_hop, t);
  }
  if (NULL != t->owner)
  {
    send_client_tunnel_destroy (t, GNUNET_NO);
  }
  if (NULL != t->client)
  {
    send_client_tunnel_destroy (t, GNUNET_YES);
  }
}


/**
 * Cancel all transmissions towards a neighbor that belongs to a certain tunnel.
 *
 * @param t Tunnel which to cancel.
 * @param neighbor Short ID of the neighbor to whom cancel the transmissions.
 */
static void
peer_cancel_queues (GNUNET_PEER_Id neighbor, struct MeshTunnel *t)
{
  struct MeshPeerInfo *peer_info;
  struct MeshPeerQueue *pq;
  struct MeshPeerQueue *next;

  if (0 == neighbor)
    return; /* Was local peer, 0'ed in tunnel_destroy_iterator */
  peer_info = peer_get_short (neighbor);
  for (pq = peer_info->queue_head; NULL != pq; pq = next)
  {
    next = pq->next;
    if (pq->tunnel == t)
    {
      if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == pq->type ||
          GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == pq->type)
      {
        /* Should have been removed on destroy children */
        GNUNET_break (0);
      }
      queue_destroy (pq, GNUNET_YES);
    }
  }
  if (NULL == peer_info->queue_head && NULL != peer_info->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel(peer_info->core_transmit);
    peer_info->core_transmit = NULL;
  }
}


/**
 * Destroy the tunnel.
 * 
 * This function does not generate any warning traffic to clients or peers.
 * 
 * Tasks:
 * Remove the tunnel from peer_info's and clients' hashmaps.
 * Cancel messages belonging to this tunnel queued to neighbors.
 * Free any allocated resources linked to the tunnel.
 *
 * @param t the tunnel to destroy
 *
 * @return GNUNET_OK on success
 */
static int
tunnel_destroy (struct MeshTunnel *t)
{
  struct MeshClient *c;
  struct GNUNET_HashCode hash;
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
    GNUNET_break (0);
    r = GNUNET_SYSERR;
  }

  if (NULL != c)
  {
    if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap32_remove (c->own_tunnels, t->local_tid, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
  }

  if (NULL != t->client)
  {
    c = t->client;
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap32_remove (c->incoming_tunnels,
                                                t->local_tid_dest, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
    if (GNUNET_YES != 
        GNUNET_CONTAINER_multihashmap32_remove (incoming_tunnels,
                                                t->local_tid_dest, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
  }

  if (0 != t->prev_hop)
  {
    peer_cancel_queues (t->prev_hop, t);
    GNUNET_PEER_change_rc (t->prev_hop, -1);
  }
  if (0 != t->next_hop)
  {
    peer_cancel_queues (t->next_hop, t);
    GNUNET_PEER_change_rc (t->next_hop, -1);
  }
  if (GNUNET_SCHEDULER_NO_TASK != t->next_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (t->next_fc.poll_task);
    t->next_fc.poll_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != t->prev_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (t->prev_fc.poll_task);
    t->prev_fc.poll_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (0 != t->dest) {
      peer_info_remove_tunnel (peer_get_short (t->dest), t);
  }

  if (GNUNET_SCHEDULER_NO_TASK != t->maintenance_task)
    GNUNET_SCHEDULER_cancel (t->maintenance_task);

  n_tunnels--;
  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  path_destroy (t->path);
  GNUNET_free (t);
  return r;
}

/**
 * Tunnel is empty: destroy it.
 * 
 * Notifies all participants (peers, cleints) about the destruction.
 * 
 * @param t Tunnel to destroy. 
 */
static void
tunnel_destroy_empty (struct MeshTunnel *t)
{
  #if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (t->id.oid, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "executing destruction of empty tunnel %s [%X]\n",
                GNUNET_i2s (&id), t->id.tid);
  }
  #endif

  if (GNUNET_NO == t->destroy)
    tunnel_send_destroy (t);
  if (0 == t->pending_messages)
    tunnel_destroy (t);
  else
    t->destroy = GNUNET_YES;
}

/**
 * Initialize a Flow Control structure to the initial state.
 * 
 * @param fc Flow Control structure to initialize.
 */
static void
fc_init (struct MeshFlowControl *fc)
{
  fc->last_pid_sent = (uint32_t) -1; /* Next (expected) = 0 */
  fc->last_pid_recv = (uint32_t) -1;
  fc->last_ack_sent = (uint32_t) -1; /* No traffic allowed yet */
  fc->last_ack_recv = (uint32_t) -1;
  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  fc->queue_n = 0;
}

/**
 * Create a new tunnel
 * 
 * @param owner Who is the owner of the tunnel (short ID).
 * @param tid Tunnel Number of the tunnel.
 * @param client Clients that owns the tunnel, NULL for foreign tunnels.
 * @param local Tunnel Number for the tunnel, for the client point of view.
 * 
 * @return A new initialized tunnel. NULL on error.
 */
static struct MeshTunnel *
tunnel_new (GNUNET_PEER_Id owner,
            MESH_TunnelNumber tid,
            struct MeshClient *client,
            MESH_TunnelNumber local)
{
  struct MeshTunnel *t;
  struct GNUNET_HashCode hash;

  if (n_tunnels >= max_tunnels && NULL == client)
    return NULL;

  t = GNUNET_malloc (sizeof (struct MeshTunnel));
  t->id.oid = owner;
  t->id.tid = tid;
  t->queue_max = (max_msgs_queue / max_tunnels) + 1;
  t->owner = client;
  fc_init (&t->next_fc);
  fc_init (&t->prev_fc);
  t->local_tid = local;
  n_tunnels++;
  GNUNET_STATISTICS_update (stats, "# tunnels", 1, GNUNET_NO);

  GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (tunnels, &hash, t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    tunnel_destroy (t);
    if (NULL != client)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client->handle, GNUNET_SYSERR);
    }
    return NULL;
  }

  if (NULL != client)
  {
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap32_put (client->own_tunnels,
                                             t->local_tid, t,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      tunnel_destroy (t);
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client->handle, GNUNET_SYSERR);
      return NULL;
    }
  }

  return t;
}


/**
 * Set options in a tunnel, extracted from a bit flag field
 * 
 * @param t Tunnel to set options to.
 * @param options Bit array in host byte order.
 */
static void
tunnel_set_options (struct MeshTunnel *t, uint32_t options)
{
  t->nobuffer = (options & GNUNET_MESH_OPTION_NOBUFFER) != 0 ?
                 GNUNET_YES : GNUNET_NO;
  t->reliable = (options & GNUNET_MESH_OPTION_RELIABLE) != 0 ?
                 GNUNET_YES : GNUNET_NO;
}


/**
 * Iterator for deleting each tunnel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local tunnel id (used to access the hashmap).
 * @param value The value stored at the key (tunnel to destroy).
 *
 * @return GNUNET_OK, keep iterating.
 */
static int
tunnel_destroy_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct MeshTunnel *t = value;
  struct MeshClient *c = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Tunnel %X / %X destroy, due to client %u shutdown.\n",
              t->local_tid, t->local_tid_dest, c->id);
  client_delete_tunnel (c, t);
  if (c == t->client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is destination.\n", c->id);
    t->client = NULL;
    if (0 != t->next_hop) { /* destroy could come before a path is used */
        GNUNET_PEER_change_rc (t->next_hop, -1);
        t->next_hop = 0;
    }
  }
  if (c == t->owner)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is owner.\n", c->id);
    t->owner = NULL;
    if (0 != t->prev_hop) { /* destroy could come before a path is used */
        GNUNET_PEER_change_rc (t->prev_hop, -1);
        t->prev_hop = 0;
    }
  }

  tunnel_destroy_empty (t);

  return GNUNET_OK;
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
  struct GNUNET_PeerIdentity id;

  t->maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_PEER_resolve(t->id.oid, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Tunnel %s [%X] timed out. Destroying.\n",
              GNUNET_i2s(&id), t->id.tid);
  if (NULL != t->client)
    send_client_tunnel_destroy (t, GNUNET_YES);
  tunnel_destroy (t); /* Do not notify other */
}


/**
 * Resets the tunnel timeout. Starts it if no timeout was running.
 *
 * @param t Tunnel whose timeout to reset.
 * @param fwd Is this forward?
 *
 * TODO use heap to improve efficiency of scheduler.
 * FIXME use fwd, keep 2 timers
 */
static void
tunnel_reset_timeout (struct MeshTunnel *t, int fwd)
{
  if (NULL != t->owner || 0 != t->local_tid || 0 == t->prev_hop)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != t->maintenance_task)
    GNUNET_SCHEDULER_cancel (t->maintenance_task);
  t->maintenance_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (refresh_path_time, 4), &tunnel_timeout, t);
}


/******************************************************************************/
/****************      MESH NETWORK HANDLER HELPERS     ***********************/
/******************************************************************************/

/**
 * Function to send a create path packet to a peer.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_path_create (void *cls, size_t size, void *buf)
{
  struct MeshTunnel *t = cls;
  struct GNUNET_MESH_CreateTunnel *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct MeshPeerPath *p = t->path;
  size_t size_needed;
  uint32_t opt;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATE PATH sending...\n");
  size_needed =
      sizeof (struct GNUNET_MESH_CreateTunnel) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  msg = (struct GNUNET_MESH_CreateTunnel *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE);
  msg->tid = ntohl (t->id.tid);

  opt = 0;
  if (GNUNET_YES == t->nobuffer)
    opt |= GNUNET_MESH_OPTION_NOBUFFER;
  if (GNUNET_YES == t->reliable)
    opt |= GNUNET_MESH_OPTION_RELIABLE;
  msg->opt = htonl (opt);
  msg->port = htonl (t->port);

  peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[i], peer_ptr++);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CREATE PATH (%u bytes long) sent!\n", size_needed);
  return size_needed;
}


/**
 * Creates a path ack message in buf and frees all unused resources.
 *
 * @param cls closure (MeshTransmissionDescriptor)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_path_ack (void *cls, size_t size, void *buf)
{
  struct MeshTunnel *t = cls;
  struct GNUNET_MESH_PathACK *msg = buf;

  GNUNET_assert (NULL != t);
  if (sizeof (struct GNUNET_MESH_PathACK) > size)
  {
    GNUNET_break (0);
    return 0;
  }
  t->prev_fc.last_ack_sent = t->nobuffer ? 0 : t->queue_max - 1;
  msg->header.size = htons (sizeof (struct GNUNET_MESH_PathACK));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_ACK);
  GNUNET_PEER_resolve (t->id.oid, &msg->oid);
  msg->tid = htonl (t->id.tid);
  msg->peer_id = my_full_id;
  msg->ack = htonl (t->prev_fc.last_ack_sent);

  /* TODO add signature */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PATH ACK sent!\n");
  return sizeof (struct GNUNET_MESH_PathACK);
}


/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
static void
queue_destroy (struct MeshPeerQueue *queue, int clear_cls)
{
  struct MeshFlowControl *fc;

  if (GNUNET_YES == clear_cls)
  {
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "   cancelling TUNNEL_DESTROY\n");
        GNUNET_break (GNUNET_YES == queue->tunnel->destroy);
        /* fall through */
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "   prebuilt message\n");
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "   type %s\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
        break;
      case GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type create path\n");
        break;
      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "   type %s unknown!\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
    }
    GNUNET_free_non_null (queue->cls);
  }
  GNUNET_CONTAINER_DLL_remove (queue->peer->queue_head,
                               queue->peer->queue_tail,
                               queue);

  /* Delete from appropriate fc in the tunnel */
  if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == queue->type ||
      GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == queue->type )
  {
    if (queue->peer->id == queue->tunnel->prev_hop)
      fc = &queue->tunnel->prev_fc;
    else if (queue->peer->id == queue->tunnel->next_hop)
      fc = &queue->tunnel->next_fc;
    else
    {
      GNUNET_break (0);
      GNUNET_free (queue);
      return;
    }
    fc->queue_n--;
  }
  GNUNET_free (queue);
}


/**
 * @brief Get the next transmittable message from the queue.
 *
 * This will be the head, except in the case of being a data packet
 * not allowed by the destination peer.
 *
 * @param peer Destination peer.
 *
 * @return The next viable MeshPeerQueue element to send to that peer.
 *         NULL when there are no transmittable messages.
 */
struct MeshPeerQueue *
queue_get_next (const struct MeshPeerInfo *peer)
{
  struct MeshPeerQueue *q;

  struct GNUNET_MESH_Data *dmsg;
  struct MeshTunnel* t;
  uint32_t pid;
  uint32_t ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   selecting message\n");
  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    t = q->tunnel;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*     %s\n",
                GNUNET_MESH_DEBUG_M2S (q->type));
    dmsg = (struct GNUNET_MESH_Data *) q->cls;
    pid = ntohl (dmsg->pid);
    switch (q->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
        ack = t->next_fc.last_ack_recv;
        break;
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
        ack = t->prev_fc.last_ack_recv;
        break;
      default:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "*   OK!\n");
        return q;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*     ACK: %u, PID: %u, MID: %u\n",
                ack, pid, ntohl (dmsg->mid));
    if (GNUNET_NO == GMC_is_pid_bigger (pid, ack))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   OK!\n");
      return q;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*     NEXT!\n");
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*   nothing found\n");
  return NULL;
}


static size_t
queue_send (void *cls, size_t size, void *buf)
{
  struct MeshPeerInfo *peer = cls;
  struct GNUNET_MessageHeader *msg;
  struct MeshPeerQueue *queue;
  struct MeshTunnel *t;
  struct GNUNET_PeerIdentity dst_id;
  struct MeshFlowControl *fc;
  size_t data_size;
  uint32_t pid;
  uint16_t type;

  peer->core_transmit = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Queue send\n");
  queue = queue_get_next (peer);

  /* Queue has no internal mesh traffic nor sendable payload */
  if (NULL == queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   not ready, return\n");
    if (NULL == peer->queue_head)
      GNUNET_break (0); /* Core tmt_rdy should've been canceled */
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   not empty\n");

  GNUNET_PEER_resolve (peer->id, &dst_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "*   towards %s\n",
              GNUNET_i2s (&dst_id));
  /* Check if buffer size is enough for the message */
  if (queue->size > size)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   not enough room, reissue\n");
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO,
                                             0,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &dst_id,
                                             queue->size,
                                             &queue_send,
                                             peer);
      return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   size ok\n");

  t = queue->tunnel;
  GNUNET_assert (0 < t->pending_messages);
  t->pending_messages--;
  type = 0;

  /* Fill buf */
  switch (queue->type)
  {
    case 0:
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
    case GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN:
    case GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   raw: %s\n",
                  GNUNET_MESH_DEBUG_M2S (queue->type));
      /* Fall through */
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      data_size = send_core_data_raw (queue->cls, size, buf);
      msg = (struct GNUNET_MessageHeader *) buf;
      type = ntohs (msg->type);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path create\n");
      data_size = send_core_path_create (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_PATH_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path ack\n");
      data_size = send_core_path_ack (queue->cls, size, buf);
      break;
    default:
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "*   type unknown: %u\n",
                  queue->type);
      data_size = 0;
  }

  if (0 < drop_percent &&
      GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Dropping message of type %s\n",
                GNUNET_MESH_DEBUG_M2S(queue->type));
    data_size = 0;
  }
  /* Free queue, but cls was freed by send_core_* */
  queue_destroy (queue, GNUNET_NO);

  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  pid = ((struct GNUNET_MESH_Data *) buf)->pid;
  pid = ntohl (pid);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      t->next_fc.last_pid_sent = pid;
      tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_UNICAST, GNUNET_YES);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "!!! FWD  %u\n",
                  ntohl ( ((struct GNUNET_MESH_Data *) buf)->mid ) );
      break;
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      t->prev_fc.last_pid_sent = pid;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "!!! BCK  %u\n",
                  ntohl ( ((struct GNUNET_MESH_Data *) buf)->mid ) );
      tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, GNUNET_NO);
      break;
    default:
      break;
  }

  /* If more data in queue, send next */
  queue = queue_get_next (peer);
  if (NULL != queue)
  {
      struct GNUNET_PeerIdentity id;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   more data!\n");
      GNUNET_PEER_resolve (peer->id, &id);
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready(core_handle,
                                            0,
                                            0,
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            &id,
                                            queue->size,
                                            &queue_send,
                                            peer);
  }
  if (peer->id == t->next_hop)
    fc = &t->next_fc;
  else if (peer->id == t->prev_hop)
    fc = &t->prev_fc;
  else
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "id: %u, next: %u, prev: %u\n",
                peer->id, t->next_hop, t->prev_hop);
    return data_size;
  }
  if (NULL != peer->queue_head)
  {
    if (GNUNET_SCHEDULER_NO_TASK == fc->poll_task && fc->queue_n > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "*   %s starting poll timeout\n",
                  GNUNET_i2s (&my_full_id));
      fc->t = t;
      fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                    &tunnel_poll, fc);
    }
  }
  else
  {
    if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    {
      GNUNET_SCHEDULER_cancel (fc->poll_task);
      fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
  if (GNUNET_YES == t->destroy && 0 == t->pending_messages)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying tunnel!\n");
    tunnel_destroy (t);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  Return %d\n", data_size);
  return data_size;
}


/**
 * @brief Queue and pass message to core when possible.
 * 
 * If type is payload (UNICAST, TO_ORIGIN) checks for queue status and
 * accounts for it. In case the queue is full, the message is dropped and
 * a break issued.
 * 
 * Otherwise, message is treated as internal and allowed to go regardless of 
 * queue status.
 *
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
 * @param size Size of the message.
 * @param dst Neighbor to send message to.
 * @param t Tunnel this message belongs to.
 */
static void
queue_add (void *cls, uint16_t type, size_t size,
           struct MeshPeerInfo *dst, struct MeshTunnel *t)
{
  struct MeshPeerQueue *queue;
  struct GNUNET_PeerIdentity id;
  struct MeshFlowControl *fc;
  int priority;

  fc = NULL;
  priority = GNUNET_NO;
  if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == type)
  {
    fc = &t->next_fc;
  }
  else if (GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == type)
  {
    fc = &t->prev_fc;
  }
  if (NULL != fc)
  {
    if (fc->queue_n >= t->queue_max)
    {
      /* If this isn't a retransmission, drop the message */
      if (GNUNET_NO == t->reliable ||
          (NULL == t->owner && GNUNET_MESSAGE_TYPE_MESH_UNICAST == type) ||
          (NULL == t->client && GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == type))
      {
        GNUNET_STATISTICS_update (stats, "# messages dropped (buffer full)",
                                  1, GNUNET_NO);
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "queue full: %u/%u\n",
                    fc->queue_n, t->queue_max);
        return; /* Drop this message */
      }
      priority = GNUNET_YES;
    }
    fc->queue_n++;
    if (GMC_is_pid_bigger(fc->last_pid_sent + 1, fc->last_ack_recv) &&
        GNUNET_SCHEDULER_NO_TASK == fc->poll_task)
      fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                    &tunnel_poll,
                                                    fc);
  }
  queue = GNUNET_malloc (sizeof (struct MeshPeerQueue));
  queue->cls = cls;
  queue->type = type;
  queue->size = size;
  queue->peer = dst;
  queue->tunnel = t;
  if (GNUNET_YES == priority)
  {
    struct GNUNET_MESH_Data *d;
    uint32_t prev;
    uint32_t next;

    GNUNET_CONTAINER_DLL_insert (dst->queue_head, dst->queue_tail, queue);
    d = (struct GNUNET_MESH_Data *) queue->cls;
    prev = d->pid;
    for (queue = dst->queue_tail; NULL != queue; queue = queue->prev)
    {
      if (queue->type != type)
        continue;
      d = (struct GNUNET_MESH_Data *) queue->cls;
      next = d->pid;
      d->pid = prev;
      prev = next;
    }
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (dst->queue_head, dst->queue_tail, queue);
  
  if (NULL == dst->core_transmit)
  {
    GNUNET_PEER_resolve (dst->id, &id);
    dst->core_transmit =
        GNUNET_CORE_notify_transmit_ready (core_handle,
                                           0,
                                           0,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &id,
                                           size,
                                           &queue_send,
                                           dst);
  }
  t->pending_messages++;
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
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message)
{
  unsigned int own_pos;
  uint16_t size;
  uint16_t i;
  MESH_TunnelNumber tid;
  struct GNUNET_MESH_CreateTunnel *msg;
  struct GNUNET_PeerIdentity *pi;
  struct MeshPeerPath *path;
  struct MeshPeerInfo *dest_peer_info;
  struct MeshPeerInfo *orig_peer_info;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a path create msg [%s]\n",
              GNUNET_i2s (&my_full_id));
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_CreateTunnel))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  size -= sizeof (struct GNUNET_MESH_CreateTunnel);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  size /= sizeof (struct GNUNET_PeerIdentity);
  if (size < 1)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    path has %u hops.\n", size);
  msg = (struct GNUNET_MESH_CreateTunnel *) message;

  tid = ntohl (msg->tid);
  pi = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    path is for tunnel %s[%X].\n", GNUNET_i2s (pi), tid);
  t = tunnel_get (pi, tid);
  if (NULL == t) /* might be a local tunnel */
  {
    uint32_t opt;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating tunnel\n");
    t = tunnel_new (GNUNET_PEER_intern (pi), tid, NULL, 0);
    if (NULL == t)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
    t->port = ntohl (msg->port);
    opt = ntohl (msg->opt);
    if (0 != (opt & GNUNET_MESH_OPTION_NOBUFFER))
    {
      t->nobuffer = GNUNET_YES;
      t->queue_max = 1;
    }
    if (0 != (opt & GNUNET_MESH_OPTION_RELIABLE))
    {
      t->reliable = GNUNET_YES;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  nobuffer:%d\n", t->nobuffer);

    tunnel_reset_timeout (t, GNUNET_YES); // FIXME
  }
  t->state = MESH_TUNNEL_WAITING;
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
  if (own_pos == 0 && path->peers[own_pos] != myid)
  {
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    tunnel_destroy (t);
    return GNUNET_OK;
  }
  path_add_to_peers (path, GNUNET_NO);
  tunnel_use_path (t, path);

  peer_info_add_tunnel (dest_peer_info, t);

  if (own_pos == size - 1)
  {
    struct MeshClient *c;

    /* Find target client */
    c = GNUNET_CONTAINER_multihashmap32_get (ports, t->port);
    if (NULL == c)
    {
      /* TODO send reject */
      return GNUNET_OK;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    peer_info_add_path_to_origin (orig_peer_info, path, GNUNET_YES);

    /* Assign local tid */
    while (NULL != tunnel_get_incoming (next_local_tid))
      next_local_tid = (next_local_tid + 1) | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
    t->local_tid_dest = next_local_tid++;
    next_local_tid = next_local_tid | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;

    if (GNUNET_YES == t->reliable)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! Reliable\n");
      t->bck_rel = GNUNET_malloc (sizeof (struct MeshTunnelReliability));
      t->bck_rel->t = t;
      t->bck_rel->expected_delay = MESH_RETRANSMIT_TIME;
    }

    tunnel_add_client (t, c);
    send_client_tunnel_create (t);
    send_path_ack (t);
  }
  else
  {
    struct MeshPeerPath *path2;

    t->next_hop = path->peers[own_pos + 1];
    GNUNET_PEER_change_rc(t->next_hop, 1);

    /* It's for somebody else! Retransmit. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    path2 = path_duplicate (path);
    peer_info_add_path (dest_peer_info, path2, GNUNET_NO);
    peer_info_add_path_to_origin (orig_peer_info, path, GNUNET_NO);
    send_create_path (t);
  }
  return GNUNET_OK;
}



/**
 * Core handler for path ACKs
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PathACK *msg;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *p;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received a path ACK msg [%s]\n",
              GNUNET_i2s (&my_full_id));
  msg = (struct GNUNET_MESH_PathACK *) message;
  t = tunnel_get (&msg->oid, ntohl(msg->tid));
  if (NULL == t)
  {
    /* TODO notify that we don't know the tunnel */
    GNUNET_STATISTICS_update (stats, "# control on unknown tunnel", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  don't know the tunnel %s [%X]!\n",
                GNUNET_i2s (&msg->oid), ntohl(msg->tid));
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on tunnel %s [%X]\n",
              GNUNET_i2s (&msg->oid), ntohl(msg->tid));

  peer_info = peer_get (&msg->peer_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by peer %s\n",
              GNUNET_i2s (&msg->peer_id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n",
              GNUNET_i2s (peer));

  /* Add path to peers? */
  p = t->path;
  if (NULL != p)
  {
    path_add_to_peers (p, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }
  t->state = MESH_TUNNEL_READY;
  t->next_fc.last_ack_recv = (NULL == t->client) ? ntohl (msg->ack) : 0;
  t->prev_fc.last_ack_sent = ntohl (msg->ack);

  /* Message for us? */
  if (0 == memcmp (&msg->oid, &my_full_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    if (NULL == t->owner)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    if (NULL != peer_info->dhtget)
    {
      GNUNET_DHT_get_stop (peer_info->dhtget);
      peer_info->dhtget = NULL;
    }
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_PATH_ACK, GNUNET_YES);
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_PATH_ACK, GNUNET_NO);
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  not for us, retransmitting...\n");
  peer_info = peer_get (&msg->oid);
  send_prebuilt_message (message, t->prev_hop, t);
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken paths
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_path_broken (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message)
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
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_tunnel_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelDestroy *msg;
  struct MeshTunnel *t;

  msg = (struct GNUNET_MESH_TunnelDestroy *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a TUNNEL DESTROY packet from %s\n",
              GNUNET_i2s (peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  for tunnel %s [%u]\n",
              GNUNET_i2s (&msg->oid), ntohl (msg->tid));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* Probably already got the message from another path,
     * destroyed the tunnel and retransmitted to children.
     * Safe to ignore.
     */
    GNUNET_STATISTICS_update (stats, "# control on unknown tunnel",
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  if (t->local_tid_dest >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "INCOMING TUNNEL %X %X\n",
                t->local_tid, t->local_tid_dest);
  }
  if (GNUNET_PEER_search (peer) == t->prev_hop)
  {
    // TODO check owner's signature
    // TODO add owner's signatue to tunnel for retransmission
    peer_cancel_queues (t->prev_hop, t);
    GNUNET_PEER_change_rc (t->prev_hop, -1);
    t->prev_hop = 0;
  }
  else if (GNUNET_PEER_search (peer) == t->next_hop)
  {
    // TODO check dest's signature
    // TODO add dest's signatue to tunnel for retransmission
    peer_cancel_queues (t->next_hop, t);
    GNUNET_PEER_change_rc (t->next_hop, -1);
    t->next_hop = 0;
  }
  else
  {
    GNUNET_break_op (0);
    // TODO check both owner AND destination's signature to see which matches
    // TODO restransmit in appropriate direction
    return GNUNET_OK;
  }
  tunnel_destroy_empty (t);

  // TODO: add timeout to destroy the tunnel anyway
  return GNUNET_OK;
}


/**
 * Generic handler for mesh network payload traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param message Data message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data (const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_MessageHeader *message,
                  int fwd)
{
  struct GNUNET_MESH_Data *msg;
  struct MeshFlowControl *fc;
  struct MeshTunnelReliability *rel;
  struct MeshTunnel *t;
  struct MeshClient *c;
  GNUNET_PEER_Id hop;
  uint32_t pid;
  uint32_t ttl;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a %s message from %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (message->type)),
              GNUNET_i2s (peer));
  /* Check size */
  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Data) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Data *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " payload of type %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (msg[1].header.type)));
  /* Check tunnel */
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify back: we don't know this tunnel */
    GNUNET_STATISTICS_update (stats, "# data on unknown tunnel", 1, GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /*  Initialize FWD/BCK data */
  pid = ntohl (msg->pid);
  fc =  fwd ? &t->prev_fc : &t->next_fc;
  c =   fwd ? t->client   : t->owner;
  rel = fwd ? t->bck_rel  : t->fwd_rel;
  hop = fwd ? t->next_hop : t->prev_hop;
  if (GMC_is_pid_bigger (pid, fc->last_ack_sent))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited data", 1, GNUNET_NO);
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received PID %u, (prev %u), ACK %u\n",
                pid, fc->last_pid_recv, fc->last_ack_sent);
    return GNUNET_OK;
  }

  tunnel_reset_timeout (t, fwd);
  if (NULL != c)
  {
    /* TODO signature verification */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  it's for us! sending to client\n");
    GNUNET_STATISTICS_update (stats, "# data received", 1, GNUNET_NO);
    if (GMC_is_pid_bigger (pid, fc->last_pid_recv))
    {
      uint32_t mid;

      mid = ntohl (msg->mid);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " pid %u (mid %u) not seen yet\n", pid, mid);
      fc->last_pid_recv = pid;

      if (GNUNET_NO == t->reliable ||
          ( !GMC_is_pid_bigger (rel->mid_recv, mid) &&
            GMC_is_pid_bigger (rel->mid_recv + 64, mid) ) )
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "!!! RECV %u\n", ntohl (msg->mid));
        if (GNUNET_YES == t->reliable)
        {
          /* Is this the exact next expected messasge? */
          if (mid == rel->mid_recv)
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "as expected\n");
            rel->mid_recv++;
            tunnel_send_client_data (t, msg, fwd);
            tunnel_send_client_buffered_data (t, c, rel);
          }
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "save for later\n");
            tunnel_add_buffered_data (t, msg, rel);
          }
        }
        else /* Tunnel unreliable, send to clients directly */
        {
          tunnel_send_client_data (t, msg, fwd);
        }
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    " MID %u not expected (%u - %u), dropping!\n",
                    ntohl (msg->mid), rel->mid_recv, rel->mid_recv + 64);
      }
    }
    else
    {
//       GNUNET_STATISTICS_update (stats, "# duplicate PID", 1, GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " Pid %u not expected (%u+), dropping!\n",
                  pid, fc->last_pid_recv + 1);
    }
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_UNICAST, fwd);
    return GNUNET_OK;
  }
  fc->last_pid_recv = pid;
  if (0 == hop)
  {
    GNUNET_STATISTICS_update (stats, "# data on dying tunnel", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "data on dying tunnel %s[%X]\n",
                GNUNET_PEER_resolve2 (t->id.oid), ntohl (msg->tid));
    return GNUNET_OK; /* Next hop has destoyed the tunnel, drop */
  }
  ttl = ntohl (msg->ttl);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ttl);
  if (ttl == 0)
  {
    GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK, fwd);
    return GNUNET_OK;
  }

  if (myid != hop)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
    send_prebuilt_message (message, hop, t);
    GNUNET_STATISTICS_update (stats, "# unicast forwarded", 1, GNUNET_NO);
  }
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to a peer
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_unicast (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_data (peer, message, GNUNET_YES);
}

/**
 * Core handler for mesh network traffic towards the owner of a tunnel.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_to_orig (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_data (peer, message, GNUNET_NO);
}


/**
 * Core handler for mesh network traffic end-to-end ACKs.
 *
 * @param cls Closure.
 * @param message Message.
 * @param peer Peer identity this notification is about.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_DataACK *msg;
  struct MeshTunnelReliability *rel;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;
  struct MeshTunnel *t;
  GNUNET_PEER_Id id;
  uint32_t ack;
  uint16_t type;
  int work;

  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a %s message from %s!\n",
              GNUNET_MESH_DEBUG_M2S (type), GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_DataACK *) message;

  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_STATISTICS_update (stats, "# ack on unknown tunnel", 1, GNUNET_NO);
    return GNUNET_OK;
  }
  ack = ntohl (msg->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ACK %u\n", ack);

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  if (t->next_hop == id && GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK == type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    if (NULL == t->owner)
    {
      send_prebuilt_message (message, t->prev_hop, t);
      return GNUNET_OK;
    }
    rel = t->fwd_rel;
  }
  else if (t->prev_hop == id && GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK == type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    if (NULL == t->client)
    {
      send_prebuilt_message (message, t->next_hop, t);
      return GNUNET_OK;
    }
    rel = t->bck_rel;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! ACK %u\n", ack);
  for (work = GNUNET_NO, copy = rel->head_sent; copy != NULL; copy = next)
  {
   if (GMC_is_pid_bigger (copy->mid, ack))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  head %u, out!\n", copy->mid);
      tunnel_free_sent_reliable (t, msg, rel);
      break;
    }
    work = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  id %u\n", copy->mid);
    next = copy->next;
    tunnel_free_reliable_message (copy);
  }
  /* Once buffers have been free'd, send ACK */
  tunnel_send_ack (t, type, GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK == type);

  /* If some message was free'd, update the retransmission delay*/
  if (GNUNET_YES == work)
  {
    if (GNUNET_SCHEDULER_NO_TASK != rel->retry_task)
    {
      GNUNET_SCHEDULER_cancel (rel->retry_task);
      if (NULL == rel->head_sent)
      {
        rel->retry_task = GNUNET_SCHEDULER_NO_TASK;
      }
      else
      {
        struct GNUNET_TIME_Absolute new_target;
        struct GNUNET_TIME_Relative delay;

        delay = GNUNET_TIME_relative_multiply (rel->retry_timer,
                                               MESH_RETRANSMIT_MARGIN);
        new_target = GNUNET_TIME_absolute_add (rel->head_sent->timestamp,
                                               delay);
        delay = GNUNET_TIME_absolute_get_remaining (new_target);
        rel->retry_task =
            GNUNET_SCHEDULER_add_delayed (delay,
                                          &tunnel_retransmit_message,
                                          rel);
      }
    }
    else
      GNUNET_break (0);
  }
  return GNUNET_OK;
}

/**
 * Core handler for mesh network traffic point-to-point acks.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ACK *msg;
  struct MeshTunnel *t;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got an ACK packet from %s!\n",
              GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_ACK *) message;

  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_STATISTICS_update (stats, "# ack on unknown tunnel", 1, GNUNET_NO);
    return GNUNET_OK;
  }
  ack = ntohl (msg->pid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ACK %u\n", ack);

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  if (t->next_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    fc = &t->next_fc;
  }
  else if (t->prev_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    fc = &t->prev_fc;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task &&
      GMC_is_pid_bigger (ack, fc->last_ack_recv))
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  }
  fc->last_ack_recv = ack;
  peer_unlock_queue (id);

  tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK, t->next_hop == id);

  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic point-to-point ack polls.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_Poll *msg;
  struct MeshTunnel *t;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t pid;
  uint32_t old;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got an POLL packet from %s!\n",
              GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_Poll *) message;

  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_STATISTICS_update (stats, "# poll on unknown tunnel", 1, GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search(peer);
  pid = ntohl (msg->pid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  PID %u\n", pid);
  if (t->next_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from FWD\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  was %u\n", t->next_fc.last_pid_recv);
    fc = &t->next_fc;
    old = fc->last_pid_recv;
    fc->last_pid_recv = pid;
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_POLL, GNUNET_NO);
  }
  else if (t->prev_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from BCK\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  was %u\n", t->prev_fc.last_pid_recv);
    fc = &t->prev_fc;
    old = fc->last_pid_recv;
    fc->last_pid_recv = pid;
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_POLL, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }

  if (GNUNET_YES == t->reliable)
    fc->last_pid_recv = old;

  return GNUNET_OK;
}


/**
 * Core handler for mesh keepalives.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 * TODO: Check who we got this from, to validate route.
 */
static int
handle_mesh_keepalive (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelKeepAlive *msg;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a keepalive packet from %s\n",
              GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_TunnelKeepAlive *) message;
  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know that tunnel */
    GNUNET_STATISTICS_update (stats, "# keepalive on unknown tunnel", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  tunnel_reset_timeout (t, GNUNET_YES); // FIXME
  if (NULL != t->client || 0 == t->next_hop || myid == t->next_hop)
    return GNUNET_OK;

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  send_prebuilt_message (message, t->next_hop, t);
  return GNUNET_OK;
  }



/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_path_broken, GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN,
   sizeof (struct GNUNET_MESH_PathBroken)},
  {&handle_mesh_tunnel_destroy, GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY,
   sizeof (struct GNUNET_MESH_TunnelDestroy)},
  {&handle_mesh_unicast, GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_mesh_to_orig, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
  {&handle_mesh_data_ack, GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK,
    sizeof (struct GNUNET_MESH_DataACK)},
  {&handle_mesh_data_ack, GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK,
    sizeof (struct GNUNET_MESH_DataACK)},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE,
    sizeof (struct GNUNET_MESH_TunnelKeepAlive)},
  {&handle_mesh_ack, GNUNET_MESSAGE_TYPE_MESH_ACK,
    sizeof (struct GNUNET_MESH_ACK)},
  {&handle_mesh_poll, GNUNET_MESSAGE_TYPE_MESH_POLL,
    sizeof (struct GNUNET_MESH_Poll)},
  {&handle_mesh_path_ack, GNUNET_MESSAGE_TYPE_MESH_PATH_ACK,
   sizeof (struct GNUNET_MESH_PathACK)},
  {NULL, 0, 0}
};



/******************************************************************************/
/****************       MESH LOCAL HANDLER HELPERS      ***********************/
/******************************************************************************/


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
 * Send keepalive packets for a tunnel.
 *
 * @param cls Closure (tunnel for which to send the keepalive).
 * @param tc Notification context.
 * 
 * FIXME: add a refresh reset in case of normal unicast traffic is doing the job
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;
  struct GNUNET_MESH_TunnelKeepAlive *msg;
  size_t size = sizeof (struct GNUNET_MESH_TunnelKeepAlive);
  char cbuf[size];

  t->maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) ||
      NULL == t->owner || 0 == t->local_tid)
  {
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending keepalive for tunnel %d\n", t->id.tid);

  msg = (struct GNUNET_MESH_TunnelKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE);
  msg->oid = my_full_id;
  msg->tid = htonl (t->id.tid);
  send_prebuilt_message (&msg->header, t->next_hop, t);

  t->maintenance_task =
      GNUNET_SCHEDULER_add_delayed (refresh_path_time, &path_refresh, t);
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
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const struct GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data)
{
  struct MeshPeerInfo *peer = cls;
  struct MeshPeerPath *p;
  struct GNUNET_PeerIdentity pi;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got results from DHT!\n");
  GNUNET_PEER_resolve (peer->id, &pi);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  for %s\n", GNUNET_i2s (&pi));

  p = path_build_from_dht (get_path, get_path_length,
                           put_path, put_path_length);
  path_add_to_peers (p, GNUNET_NO);
  path_destroy (p);
  for (i = 0; i < peer->ntunnels; i++)
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (peer->tunnels[i]->id.oid, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ... tunnel %s:%X (%X / %X)\n",
                GNUNET_i2s (&id), peer->tunnels[i]->id.tid,
                peer->tunnels[i]->local_tid, 
                peer->tunnels[i]->local_tid_dest);
    if (peer->tunnels[i]->state == MESH_TUNNEL_SEARCHING)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ... connect!\n");
      peer_connect (peer, peer->tunnels[i]);
    }
  }

  return;
}


/******************************************************************************/
/*********************       MESH LOCAL HANDLES      **************************/
/******************************************************************************/


/**
 * Handler for client connection.
 *
 * @param cls Closure (unused).
 * @param client Client handler.
 */
static void
handle_local_client_connect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct MeshClient *c;

  if (NULL == client)
    return;
  c = GNUNET_malloc (sizeof (struct MeshClient));
  c->handle = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_client_set_user_context (client, c);
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, c);
}


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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected: %p\n", client);
  if (client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (SERVER DOWN)\n");
    return;
  }

  c = client_get (client);
  if (NULL != c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u)\n",
                c->id);
    GNUNET_SERVER_client_drop (c->handle);
    c->shutting_down = GNUNET_YES;
    if (NULL != c->own_tunnels)
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->own_tunnels,
                                               &tunnel_destroy_iterator, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->own_tunnels);
    }

    if (NULL != c->incoming_tunnels)
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->incoming_tunnels,
                                             &tunnel_destroy_iterator, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->incoming_tunnels);
    }

    if (NULL != c->ports)
      GNUNET_CONTAINER_multihashmap32_destroy (c->ports);
    next = c->next;
    GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  CLIENT FREE at %p\n", c);
    GNUNET_free (c);
    GNUNET_STATISTICS_update (stats, "# clients", -1, GNUNET_NO);
    c = next;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " context NULL!\n");
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "done!\n");
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
  unsigned int size;
  uint32_t *p;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new client connected %p\n", client);

  /* Check data sanity */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_ClientConnect);
  cc_msg = (struct GNUNET_MESH_ClientConnect *) message;
  if (0 != (size % sizeof (uint32_t)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  size /= sizeof (uint32_t);

  /* Initialize new client structure */
  c = GNUNET_SERVER_client_get_user_context (client, struct MeshClient);
  c->id = next_client_id++; /* overflow not important: just for debug */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  client id %u\n", c->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  client has %u ports\n", size);
  if (size > 0)
  {
    uint32_t u32;

    p = (uint32_t *) &cc_msg[1];
    c->ports = GNUNET_CONTAINER_multihashmap32_create (size);
    for (i = 0; i < size; i++)
    {
      u32 = ntohl (p[i]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    port: %u\n", u32);

      /* store in client's hashmap */
      GNUNET_CONTAINER_multihashmap32_put (c->ports, u32, c,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
      /* store in global hashmap */
      /* FIXME only allow one client to have the port open,
       *       have a backup hashmap with waiting clients */
      GNUNET_CONTAINER_multihashmap32_put (ports, u32, c,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }

  c->own_tunnels = GNUNET_CONTAINER_multihashmap32_create (32);
  c->incoming_tunnels = GNUNET_CONTAINER_multihashmap32_create (32);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_STATISTICS_update (stats, "# clients", 1, GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new client processed\n");
}


/**
 * Handler for requests of new tunnels
 *
 * @param cls Closure.
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_tunnel_create (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelMessage *t_msg;
  struct MeshPeerInfo *peer_info;
  struct MeshTunnel *t;
  struct MeshClient *c;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new tunnel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof (struct GNUNET_MESH_TunnelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  t_msg = (struct GNUNET_MESH_TunnelMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  towards %s\n",
              GNUNET_i2s (&t_msg->peer));
  /* Sanity check for tunnel numbering */
  tid = ntohl (t_msg->tunnel_id);
  if (0 == (tid & GNUNET_MESH_LOCAL_TUNNEL_ID_CLI))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* Sanity check for duplicate tunnel IDs */
  if (NULL != tunnel_get_by_local_id (c, tid))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Create tunnel */
  while (NULL != tunnel_get_by_pi (myid, next_tid))
    next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  t = tunnel_new (myid, next_tid, c, tid);
  next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  t->port = ntohl (t_msg->port);
  tunnel_set_options (t, ntohl (t_msg->opt));
  if (GNUNET_YES == t->reliable)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! Reliable\n");
    t->fwd_rel = GNUNET_malloc (sizeof (struct MeshTunnelReliability));
    t->fwd_rel->t = t;
    t->fwd_rel->expected_delay = MESH_RETRANSMIT_TIME;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATED TUNNEL %s[%x]:%u (%x)\n",
              GNUNET_i2s (&my_full_id), t->id.tid, t->port, t->local_tid);

  peer_info = peer_get (&t_msg->peer);
  peer_info_add_tunnel (peer_info, t);
  peer_connect (peer_info, t);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_TunnelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;

  /* Retrieve tunnel */
  tid = ntohl (tunnel_msg->tunnel_id);
  t = tunnel_get_by_local_id(c, tid);
  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  tunnel %X not found\n", tid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Cleanup after the tunnel */
  client_delete_tunnel (c, t);
  if (c == t->client)
  {
    t->client = NULL;
  }
  if (c == t->owner)
  {
    peer_info_remove_tunnel (peer_get_short (t->dest), t);
    t->owner = NULL;
  }

  /* The tunnel will be destroyed when the last message is transmitted. */
  tunnel_destroy_empty (t);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_local_data (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_LocalData *data_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  struct MeshFlowControl *fc;
  MESH_TunnelNumber tid;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got data from a client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  data_msg = (struct GNUNET_MESH_LocalData *) message;

  /* Sanity check for message size */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_LocalData);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (data_msg->tid);
  if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_CLI)
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

  /* Is the client in the tunnel? */
  if ( !( (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV &&
           t->owner &&
           t->owner->handle == client)
         ||
          (tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV &&
           t->client && 
           t->client->handle == client) ) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Ok, everything is correct, send the message
   * (pretend we got it from a mesh peer)
   */
  {
    struct GNUNET_MESH_Data *payload;
    char cbuf[sizeof(struct GNUNET_MESH_Data) + size];

    fc = tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV ? &t->prev_fc : &t->next_fc;
    if (GNUNET_YES == t->reliable)
    {
      struct MeshTunnelReliability *rel;
      struct MeshReliableMessage *copy;

      rel = (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV) ? t->fwd_rel : t->bck_rel;
      copy = GNUNET_malloc (sizeof (struct MeshReliableMessage)
                            + sizeof(struct GNUNET_MESH_Data)
                            + size);
      copy->mid = rel->mid_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! DATA %u\n", copy->mid);
      copy->timestamp = GNUNET_TIME_absolute_get ();
      copy->rel = rel;
      rel->n_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " n_sent %u\n", rel->n_sent);
      GNUNET_CONTAINER_DLL_insert_tail (rel->head_sent, rel->tail_sent, copy);
      if (GNUNET_SCHEDULER_NO_TASK == rel->retry_task)
      {
        rel->retry_timer =
            GNUNET_TIME_relative_multiply (rel->expected_delay,
                                           MESH_RETRANSMIT_MARGIN);
        rel->retry_task =
            GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                          &tunnel_retransmit_message,
                                          rel);
      }
      payload = (struct GNUNET_MESH_Data *) &copy[1];
      payload->mid = htonl (copy->mid);
    }
    else
    {
      payload = (struct GNUNET_MESH_Data *) cbuf;
      payload->mid = htonl (fc->last_pid_recv + 1);
    }
    memcpy (&payload[1], &data_msg[1], size);
    payload->header.size = htons (sizeof (struct GNUNET_MESH_Data) + size);
    payload->header.type = htons (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV ?
                                  GNUNET_MESSAGE_TYPE_MESH_UNICAST :
                                  GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN);
    GNUNET_PEER_resolve(t->id.oid, &payload->oid);;
    payload->tid = htonl (t->id.tid);
    payload->ttl = htonl (default_ttl);
    payload->pid = htonl (fc->last_pid_recv + 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
      handle_mesh_unicast (NULL, &my_full_id, &payload->header);
    else
      handle_mesh_to_orig (NULL, &my_full_id, &payload->header);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "receive done OK\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
}


/**
 * Handler for client's ACKs for payload traffic.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_ack (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_LocalAck *msg;
  struct MeshTunnel *t;
  struct MeshClient *c;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a local ACK\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  msg = (struct GNUNET_MESH_LocalAck *) message;

  /* Tunnel exists? */
  tid = ntohl (msg->tunnel_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on tunnel %X\n", tid);
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tunnel %X unknown.\n", tid);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Does client own tunnel? I.E: Is this an ACK for BCK traffic? */
  if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    /* The client owns the tunnel, ACK is for data to_origin, send BCK ACK. */
    t->prev_fc.last_ack_recv++;
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK, GNUNET_NO);
  }
  else
  {
    /* The client doesn't own the tunnel, this ACK is for FWD traffic. */
    t->next_fc.last_ack_recv++;
    tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK, GNUNET_YES);
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
}



/**
 * Iterator over all tunnels to send a monitoring client info about each tunnel.
 *
 * @param cls Closure (client handle).
 * @param key Key (hashed tunnel ID, unused).
 * @param value Tunnel info.
 *
 * @return GNUNET_YES, to keep iterating.
 */
static int
monitor_all_tunnels_iterator (void *cls,
                              const struct GNUNET_HashCode * key,
                              void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct MeshTunnel *t = value;
  struct GNUNET_MESH_LocalMonitor *msg;

  msg = GNUNET_malloc (sizeof(struct GNUNET_MESH_LocalMonitor));
  GNUNET_PEER_resolve(t->id.oid, &msg->owner);
  msg->tunnel_id = htonl (t->id.tid);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);
  GNUNET_PEER_resolve (t->dest, &msg->destination);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "*  sending info about tunnel %s [%u]\n",
              GNUNET_i2s (&msg->owner), t->id.tid);

  GNUNET_SERVER_notification_context_unicast (nc, client,
                                              &msg->header, GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Handler for client's MONITOR request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_get_tunnels (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct MeshClient *c;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received get tunnels request from client %u\n",
              c->id);
  GNUNET_CONTAINER_multihashmap_iterate (tunnels,
                                         monitor_all_tunnels_iterator,
                                         client);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Get tunnels request from client %u completed\n",
              c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for client's MONITOR_TUNNEL request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_show_tunnel (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MESH_LocalMonitor *msg;
  struct GNUNET_MESH_LocalMonitor *resp;
  struct MeshClient *c;
  struct MeshTunnel *t;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_LocalMonitor *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received tunnel info request from client %u for tunnel %s[%X]\n",
              c->id,
              &msg->owner,
              ntohl (msg->tunnel_id));
  t = tunnel_get (&msg->owner, ntohl (msg->tunnel_id));
  if (NULL == t)
  {
    /* We don't know the tunnel FIXME */
    struct GNUNET_MESH_LocalMonitor warn;

    warn = *msg;
    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &warn.header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Initialize context */
  resp = GNUNET_malloc (sizeof (struct GNUNET_MESH_LocalMonitor));
  *resp = *msg;
  GNUNET_PEER_resolve (t->dest, &resp->destination);
  resp->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);
  GNUNET_free (resp);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Monitor tunnel request from client %u completed\n",
              c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  {&handle_local_data, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA, 0},
  {&handle_local_ack, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK,
   sizeof (struct GNUNET_MESH_LocalAck)},
  {&handle_local_get_tunnels, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_local_show_tunnel, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL,
     sizeof (struct GNUNET_MESH_LocalMonitor)},
  {NULL, NULL, 0, 0}
};


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *path;

  DEBUG_CONN ("Peer connected\n");
  DEBUG_CONN ("     %s\n", GNUNET_i2s (&my_full_id));
  peer_info = peer_get (peer);
  if (myid == peer_info->id)
  {
    DEBUG_CONN ("     (self)\n");
    path = path_new (1);
  }
  else
  {
    DEBUG_CONN ("     %s\n", GNUNET_i2s (peer));
    path = path_new (2);
    path->peers[1] = peer_info->id;
    GNUNET_PEER_change_rc (peer_info->id, 1);
    GNUNET_STATISTICS_update (stats, "# peers", 1, GNUNET_NO);
  }
  path->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
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
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *n;

  DEBUG_CONN ("Peer disconnected\n");
  pi = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pi)
  {
    GNUNET_break (0);
    return;
  }
  q = pi->queue_head;
  while (NULL != q)
  {
      n = q->next;
      /* TODO try to reroute this traffic instead */
      queue_destroy(q, GNUNET_YES);
      q = n;
  }
  if (NULL != pi->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel(pi->core_transmit);
    pi->core_transmit = NULL;
  }
    peer_remove_path (pi, pi->id, myid);
  if (myid == pi->id)
  {
    DEBUG_CONN ("     (self)\n");
  }
  GNUNET_STATISTICS_update (stats, "# peers", -1, GNUNET_NO);
  return;
}


/**
 * Install server (service) handlers and start listening to clients.
 */
static void
server_init (void)
{
  GNUNET_SERVER_add_handlers (server_handle, client_handlers);
  GNUNET_SERVER_connect_notify (server_handle,
                                &handle_local_client_connect, NULL);
  GNUNET_SERVER_disconnect_notify (server_handle,
                                   &handle_local_client_disconnect, NULL);
  nc = GNUNET_SERVER_notification_context_create (server_handle, 1);

  clients_head = NULL;
  clients_tail = NULL;
  next_client_id = 0;
  GNUNET_SERVER_resume (server_handle);
}


/**
 * To be called on core init/fail.
 *
 * @param cls Closure (config)
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity)
{
  const struct GNUNET_CONFIGURATION_Handle *c = cls;
  static int i = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core init\n");
  GNUNET_break (core_handle == server);
  if (0 != memcmp (identity, &my_full_id, sizeof (my_full_id)) ||
    NULL == server)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Wrong CORE service\n"));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                " core id %s\n",
                GNUNET_i2s (identity));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                " my id %s\n",
                GNUNET_i2s (&my_full_id));
    GNUNET_CORE_disconnect (core_handle);
    core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                       NULL,      /* Closure passed to MESH functions */
                                       &core_init,        /* Call core_init once connected */
                                       &core_connect,     /* Handle connects */
                                       &core_disconnect,  /* remove peers on disconnects */
                                       NULL,      /* Don't notify about all incoming messages */
                                       GNUNET_NO, /* For header only in notification */
                                       NULL,      /* Don't notify about all outbound messages */
                                       GNUNET_NO, /* For header-only out notification */
                                       core_handlers);    /* Register these handlers */
    if (10 < i++)
      GNUNET_abort();
  }
  server_init ();
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
shutdown_tunnel (void *cls, const struct GNUNET_HashCode * key, void *value)
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
shutdown_peer (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct MeshPeerInfo *p = value;
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *n;

  q = p->queue_head;
  while (NULL != q)
  {
      n = q->next;
      if (q->peer == p)
      {
        queue_destroy(q, GNUNET_YES);
      }
      q = n;
  }
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
  char *keyfile;
  struct GNUNET_CRYPTO_EccPrivateKey *pk;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting to run\n");
  server_handle = server;
  GNUNET_SERVER_suspend (server_handle);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c, "PEER", "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "peer/privatekey");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "REFRESH_PATH_TIME",
                                           &refresh_path_time))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "refresh path time");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "ID_ANNOUNCE_TIME",
                                           &id_announce_time))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "id announce time");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "CONNECT_TIMEOUT",
                                           &connect_timeout))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "connect timeout");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_MSGS_QUEUE",
                                             &max_msgs_queue))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "max msgs queue");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_TUNNELS",
                                             &max_tunnels))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "max tunnels");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DEFAULT_TTL",
                                             &default_ttl))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("%s service is lacking key configuration settings (%s). Using default (%u).\n"),
                "mesh", "default ttl", 64);
    default_ttl = 64;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_PEERS",
                                             &max_peers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("%s service is lacking key configuration settings (%s). Using default (%u).\n"),
                "mesh", "max peers", 1000);
    max_peers = 1000;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DROP_PERCENT",
                                             &drop_percent))
  {
    drop_percent = 0;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Mesh is running with drop mode enabled. "
                "This is NOT a good idea! "
                "Remove the DROP_PERCENT option from your configuration.\n");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DHT_REPLICATION_LEVEL",
                                             &dht_replication_level))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("%s service is lacking key configuration settings (%s). Using default (%u).\n"),
                "mesh", "dht replication level", 3);
    dht_replication_level = 3;
  }

  tunnels = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  incoming_tunnels = GNUNET_CONTAINER_multihashmap32_create (32);
  peers = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  ports = GNUNET_CONTAINER_multihashmap32_create (32);

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (NULL == dht_handle)
  {
    GNUNET_break (0);
  }
  stats = GNUNET_STATISTICS_create ("mesh", c);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  pk = GNUNET_CRYPTO_ecc_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  GNUNET_assert (NULL != pk);
  my_private_key = pk;
  GNUNET_CRYPTO_ecc_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_full_id.hashPubKey);
  myid = GNUNET_PEER_intern (&my_full_id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Mesh for peer [%s] starting\n",
              GNUNET_i2s(&my_full_id));

  core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                     NULL,      /* Closure passed to MESH functions */
                                     &core_init,        /* Call core_init once connected */
                                     &core_connect,     /* Handle connects */
                                     &core_disconnect,  /* remove peers on disconnects */
                                     NULL,      /* Don't notify about all incoming messages */
                                     GNUNET_NO, /* For header only in notification */
                                     NULL,      /* Don't notify about all outbound messages */
                                     GNUNET_NO, /* For header-only out notification */
                                     core_handlers);    /* Register these handlers */
  if (NULL == core_handle)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  next_tid = 0;
  next_local_tid = GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh service running\n");
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
  int r;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  r = GNUNET_SERVICE_run (argc, argv, "mesh", GNUNET_SERVICE_OPTION_NONE, &run,
                          NULL);
  ret = (GNUNET_OK == r) ? 0 : 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");

  INTERVAL_SHOW;

  return ret;
}
