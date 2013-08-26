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
 * @file mesh/gnunet-service-mesh-enc.c
 * @brief GNUnet MESH service with encryption
 * @author Bartlomiej Polot
 *
 *  FIXME in progress:
 * - when sending in-order buffered data, wait for client ACKs
 * - add signatures
 * - add encryption
 * - set connection IDs independently from tunnel, tunnel has no ID
 *
 * TODO:
 * - relay corking down to core
 * - set ttl relative to path length
 * TODO END
 * 
 * Dictionary:
 * - peer: other mesh instance. If there is direct connection it's a neighbor.
 * - tunnel: encrypted connection to a peer, neighbor or not.
 * - channel: connection between two clients, on the same or different peers.
 *            have properties like reliability.
 * - path: series of directly connected peer from one peer to another.
 * - connection: path which is being used in a tunnel.
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "mesh_enc.h"
#include "mesh_protocol_enc.h"
#include "mesh_path.h"
#include "block_mesh.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"

#define MESH_BLOOM_SIZE         128

#define MESH_DEBUG_DHT          GNUNET_NO
#define MESH_DEBUG_CONNECTION   GNUNET_YES
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

/**
 * All the states a tunnel can be in.
 */
enum MeshTunnelState
{
    /**
     * Uninitialized status, should never appear in operation.
     */
  MESH_TUNNEL_NEW,

    /**
     * Path to the peer not known yet
     */
  MESH_TUNNEL_SEARCHING,

    /**
     * Request sent, not yet answered.
     */
  MESH_TUNNEL_WAITING,

    /**
     * Peer connected and ready to accept data
     */
  MESH_TUNNEL_READY,

    /**
     * Peer connected previosly but not responding
     */
  MESH_TUNNEL_RECONNECTING
};


/**
 * All the states a connection can be in.
 */
enum MeshConnectionState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_CONNECTION_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  MESH_CONNECTION_SENT,

  /**
   * Connection ACK sent, waiting for ACK.
   */
  MESH_CONNECTION_ACK,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  MESH_CONNECTION_READY,
};


/**
 * All the states a connection can be in.
 */
enum MeshChannelState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_CHANNEL_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  MESH_CHANNEL_SENT,

  /**
   * Connection confirmed, ready to carry traffic..
   */
  MESH_CHANNEL_READY,
};


/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/** FWD declaration */
struct MeshClient;
struct MeshPeer;
struct MeshTunnel2;
struct MeshConnection;
struct MeshChannel;
struct MeshChannelReliability;


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
  struct MeshPeer *peer;

    /**
     * Connection this message belongs to.
     */
  struct MeshConnection *c;

    /**
     * Is FWD in c?
     */
  int fwd;

    /**
     * Channel this message belongs to, if known.
     */
  struct MeshChannel *ch;

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
 * Struct to encapsulate all the Flow Control information to a peer to which
 * we are directly connected (on a core level).
 */
struct MeshFlowControl
{
  /**
   * Connection this controls.
   */
  struct MeshConnection *c;

  /**
   * How many messages are in the queue on this connection.
   */
  unsigned int queue_n;

  /**
   * How many messages do we accept in the queue.
   */
  unsigned int queue_max;

  /**
   * Next ID to use.
   */
  uint32_t next_pid;

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
   * Task to poll the peer in case of a lost ACK causes stall.
   */
  GNUNET_SCHEDULER_TaskIdentifier poll_task;

  /**
   * How frequently to poll for ACKs.
   */
  struct GNUNET_TIME_Relative poll_time;
};


/**
 * Struct containing all information regarding a given peer
 */
struct MeshPeer
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
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_head;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_tail;

    /**
     * Handle to stop the DHT search for paths to this peer
     */
  struct GNUNET_DHT_GetHandle *dhtget;

    /**
     * Tunnel to this peer, if any.
     */
  struct MeshTunnel2 *tunnel;

    /**
     * Connections that go through this peer, indexed by tid;
     */
  struct GNUNET_CONTAINER_MultiHashMap *connections;

    /**
     * Handle for queued transmissions
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit;

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
};


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
     * Type of message (payload, channel management).
     */
  int16_t type;

    /**
     * Tunnel Reliability queue this message is in.
     */
  struct MeshChannelReliability  *rel;

    /**
     * ID of the message (ACK needed to free)
     */
  uint32_t                      mid;

    /**
     * When was this message issued (to calculate ACK delay)
     */
  struct GNUNET_TIME_Absolute   timestamp;

  /* struct GNUNET_MESH_Data with payload */
};


/**
 * Info about the traffic state for a client in a channel.
 */
struct MeshChannelReliability
{
    /**
     * Channel this is about.
     */
  struct MeshChannel *ch;

    /**
     * DLL of messages sent and not yet ACK'd.
     */
  struct MeshReliableMessage        *head_sent;
  struct MeshReliableMessage        *tail_sent;

    /**
     * Messages pending to send.
     */
  unsigned int                      n_sent;

    /**
     * DLL of messages received out of order.
     */
  struct MeshReliableMessage        *head_recv;
  struct MeshReliableMessage        *tail_recv;

    /**
     * Messages received.
     */
  unsigned int                      n_recv;

    /**
     * Next MID to use for outgoing traffic.
     */
  uint32_t                          mid_send;

    /**
     * Next MID expected for incoming traffic.
     */
  uint32_t                          mid_recv;

    /**
     * Can we send data to the client?
     */
  int                               client_ready;

    /**
     * Task to resend/poll in case no ACK is received.
     */
  GNUNET_SCHEDULER_TaskIdentifier   retry_task;

    /**
     * Counter for exponential backoff.
     */
  struct GNUNET_TIME_Relative       retry_timer;

    /**
     * How long does it usually take to get an ACK.
     */
  struct GNUNET_TIME_Relative       expected_delay;
};


/**
 * Struct containing all information regarding a channel to a remote client.
 */
struct MeshChannel
{
    /**
     * Tunnel this channel is in.
     */
  struct MeshTunnel2 *t;

    /**
     * Double linked list.
     */
  struct MeshChannel    *next;
  struct MeshChannel    *prev;

    /**
     * Destination port of the channel.
     */
  uint32_t port;

    /**
     * Global channel number ( < GNUNET_MESH_LOCAL_CHANNEL_ID_CLI)
     */
  MESH_ChannelNumber gid;

    /**
     * Local tunnel number for root (owner) client.
     * ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI or 0 )
     */
  MESH_ChannelNumber lid_root;

    /**
     * Local tunnel number for local destination clients (incoming number)
     * ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV or 0).
     */
  MESH_ChannelNumber lid_dest;

    /**
     * Channel state.
     */
  enum MeshChannelState state;

    /**
     * Is the tunnel bufferless (minimum latency)?
     */
  int nobuffer;

    /**
     * Is the tunnel reliable?
     */
  int reliable;

    /**
     * Last time the channel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Client owner of the tunnel, if any
     */
  struct MeshClient *root;

    /**
     * Client destination of the tunnel, if any.
     */
  struct MeshClient *dest;

    /**
     * Flag to signal the destruction of the channel.
     * If this is set GNUNET_YES the channel will be destroyed
     * when the queue is empty.
     */
  int destroy;

    /**
     * Total messages pending for this channel, payload or not.
     */
  unsigned int pending_messages;

    /**
     * Reliability data.
     * Only present (non-NULL) at the owner of a tunnel.
     */
  struct MeshChannelReliability *root_rel;

    /**
     * Reliability data.
     * Only present (non-NULL) at the destination of a tunnel.
     */
  struct MeshChannelReliability *dest_rel;

};


/**
 * Struct containing all information regarding a connection to a peer.
 */
struct MeshConnection
{
  /**
   * DLL
   */
  struct MeshConnection *next;
  struct MeshConnection *prev;

  /**
   * Tunnel this connection is part of.
   */
  struct MeshTunnel2 *t;

  /**
   * Flow control information for traffic fwd.
   */
  struct MeshFlowControl fwd_fc;

  /**
   * Flow control information for traffic bck.
   */
  struct MeshFlowControl bck_fc;

  /**
   * ID of the connection.
   */
  struct GNUNET_HashCode id;

  /**
   * State of the connection.
   */
  enum MeshConnectionState state;

  /**
   * Path being used for the tunnel.
   */
  struct MeshPeerPath *path;

  /**
   * Position of the local peer in the path.
   */
  unsigned int own_pos;

  /**
   * Task to keep the used paths alive at the owner,
   * time tunnel out on all the other peers.
   */
  GNUNET_SCHEDULER_TaskIdentifier fwd_maintenance_task;

  /**
   * Task to keep the used paths alive at the destination,
   * time tunnel out on all the other peers.
   */
  GNUNET_SCHEDULER_TaskIdentifier bck_maintenance_task;

  /**
   * Pending message count.
   */
  int pending_messages;

  /**
   * Destroy flag: if true, destroy on last message.
   */
  int destroy;
};


/**
 * Struct used to queue messages in a tunnel.
 */
struct MeshTunnelQueue
{
  /**
   * DLL
   */
  struct MeshTunnelQueue *next;
  struct MeshTunnelQueue *prev;

  /**
   * Channel.
   */
  struct MeshChannel *ch;

  /**
   * Message to send.
   */
  /* struct GNUNET_MessageHeader *msg; */
};


/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct MeshTunnel2
{
    /**
     * Endpoint of the tunnel.
     */
  struct MeshPeer *peer;

    /**
     * State of the tunnel.
     */
  enum MeshTunnelState state;

  /**
   * Local peer ephemeral private key
   */
  struct GNUNET_CRYPTO_EccPrivateKey *my_eph_key;

  /**
   * Local peer ephemeral public key
   */
  struct GNUNET_CRYPTO_EccPublicKey *my_eph;

  /**
   * Remote peer's public key.
   */
  struct GNUNET_CRYPTO_EccPublicKey *peers_eph;

  /**
   * Encryption ("our") key.
   */
  struct GNUNET_CRYPTO_AesSessionKey e_key;

  /**
   * Decryption ("their") key.
   */
  struct GNUNET_CRYPTO_AesSessionKey d_key;

  /**
   * Paths that are actively used to reach the destination peer.
   */
  struct MeshConnection *connection_head;
  struct MeshConnection *connection_tail;

  /**
   * Next connection number.
   */
  uint32_t next_cid;

  /**
   * Channels inside this tunnel.
   */
  struct MeshChannel *channel_head;
  struct MeshChannel *channel_tail;

  /**
   * Channel ID for the next created channel.
   */
  MESH_ChannelNumber next_chid;

  /**
   * Channel ID for the next incoming channel.
   */
  MESH_ChannelNumber next_local_chid;

  /**
   * Pending message count.
   */
  int pending_messages;

  /**
   * Destroy flag: if true, destroy on last message.
   */
  int destroy;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct MeshTunnelQueue *tq_head;
  struct MeshTunnelQueue *tq_tail;
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
  struct GNUNET_CONTAINER_MultiHashMap32 *own_channels;

   /**
     * Tunnels this client has accepted, indexed by incoming local id
     */
  struct GNUNET_CONTAINER_MultiHashMap32 *incoming_channels;

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
 * How often to send path keepalives. Paths timeout after 4 missed.
 */
static struct GNUNET_TIME_Relative refresh_connection_time;

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
 * How many connections are we willing to maintain.
 * Local connections are always allowed, even if there are more connections than max.
 */
static unsigned long long max_connections;

/**
 * How many messages *in total* are we willing to queue, divide by number of 
 * connections to get connection queue size.
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
 * Connections known, indexed by cid (MeshConnection).
 */
static struct GNUNET_CONTAINER_MultiHashMap *connections;

/**
 * Peers known, indexed by PeerIdentity (MeshPeer).
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/**
 * Handle to communicate with core.
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Handle to use DHT.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to server lib.
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
static struct GNUNET_CRYPTO_EccPublicKey my_public_key;

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
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
peer_get (const struct GNUNET_PeerIdentity *peer);


/**
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
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
 * Adds a path to the data structs of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
static void
path_add_to_peers (struct MeshPeerPath *p, int confirmed);


/**
 * Search for a tunnel by global ID using full PeerIdentities.
 *
 * @param t Tunnel containing the channel.
 * @param chid Public channel number.
 *
 * @return channel handler, NULL if doesn't exist
 */
static struct MeshChannel *
channel_get (struct MeshTunnel2 *t, MESH_ChannelNumber chid);


/**
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
static void
tunnel_change_state (struct MeshTunnel2 *t, enum MeshTunnelState state);


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
tunnel_notify_connection_broken (struct MeshTunnel2 *t,
                                 GNUNET_PEER_Id p1, GNUNET_PEER_Id p2);

/**
 * @brief Use the given path for the tunnel.
 * Update the next and prev hops (and RCs).
 * (Re)start the path refresh in case the tunnel is locally owned.
 * 
 * @param t Tunnel to update.
 * @param p Path to use.
 *
 * @return Connection created.
 */
static struct MeshConnection *
tunnel_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p);

/**
 * Tunnel is empty: destroy it.
 * 
 * Notifies all participants (peers, cleints) about the destruction.
 * 
 * @param t Tunnel to destroy. 
 */
static void
tunnel_destroy_empty (struct MeshTunnel2 *t);

/**
 * Destroy the tunnel.
 *
 * This function does not generate any warning traffic to clients or peers.
 *
 * Tasks:
 * Cancel messages belonging to this tunnel queued to neighbors.
 * Free any allocated resources linked to the tunnel.
 *
 * @param t The tunnel to destroy.
 */
static void
tunnel_destroy (struct MeshTunnel2 *t);

/**
 * Create a connection.
 *
 * @param cid Connection ID.
 */
static struct MeshConnection *
connection_new (const struct GNUNET_HashCode *cid);

/**
 * Connection is no longer needed: destroy it and remove from tunnel.
 *
 * @param c Connection to destroy.
 */
static void
connection_destroy (struct MeshConnection *c);

/**
 * Send FWD keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
static void
connection_fwd_keepalive (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Send BCK keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
static void
connection_bck_keepalive (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Change the tunnel state.
 *
 * @param c Connection whose state to change.
 * @param state New state.
 */
static void
connection_change_state (struct MeshConnection* c,
                         enum MeshConnectionState state);



/**
 * @brief Queue and pass message to core when possible.
 *
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
 * @param size Size of the message.
 * @param c Connection this message belongs to (cannot be NULL).
 * @param ch Channel this message belongs to, if applicable (otherwise NULL).
 * @param fwd Is this a message going root->dest? (FWD ACK are NOT FWD!)
 */
static void
queue_add (void* cls,
           uint16_t type,
           size_t size,
           struct MeshConnection* c,
           struct MeshChannel* ch,
           int fwd);


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


/**
 * Dummy function to separate declarations from definitions in function list.
 */
void
__mesh_divider______________________________________________________________();


/**
 * Get string description for tunnel state.
 *
 * @param s Tunnel state.
 *
 * @return String representation. 
 */
static const char *
GNUNET_MESH_DEBUG_TS2S (enum MeshTunnelState s)
{
  static char buf[128];

  switch (s)
  {
    case MESH_TUNNEL_NEW:
      return "MESH_TUNNEL_NEW";
    case MESH_TUNNEL_SEARCHING:
      return "MESH_TUNNEL_SEARCHING";
    case MESH_TUNNEL_WAITING:
      return "MESH_TUNNEL_WAITING";
    case MESH_TUNNEL_READY:
      return "MESH_TUNNEL_READY";
    case MESH_TUNNEL_RECONNECTING:
      return "MESH_TUNNEL_RECONNECTING";

    default:
      sprintf (buf, "%u (UNKNOWN STATE)", s);
      return buf;
  }
}


/**
 * Get string description for tunnel state.
 *
 * @param s Tunnel state.
 *
 * @return String representation. 
 */
static const char *
GNUNET_MESH_DEBUG_CS2S (enum MeshTunnelState s)
{
  switch (s) 
  {
    case MESH_CONNECTION_NEW:
      return "MESH_CONNECTION_NEW";
    case MESH_CONNECTION_SENT:
      return "MESH_CONNECTION_SENT";
    case MESH_CONNECTION_READY:
      return "MESH_CONNECTION_READY";
    default:
      return "MESH_CONNECTION_STATE_ERROR";
  }
}



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
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
static const char *
peer2s (const struct MeshPeer *peer)
{
  if (NULL == peer)
    return "(NULL)";
  return GNUNET_i2s (GNUNET_PEER_resolve2 (peer->id));
}


/**
 * Get the previous hop in a connection
 *
 * @param c Connection.
 *
 * @return Previous peer in the connection.
 */
static struct MeshPeer *
connection_get_prev_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if (0 == c->own_pos || c->path->length < 2)
    id = c->path->peers[0];
  else
    id = c->path->peers[c->own_pos - 1];

  return peer_get_short (id);
}


/**
 * Get the next hop in a connection
 *
 * @param c Connection.
 *
 * @return Next peer in the connection. 
 */
static struct MeshPeer *
connection_get_next_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if ((c->path->length - 1) == c->own_pos || c->path->length < 2)
    id = c->path->peers[c->path->length - 1];
  else
    id = c->path->peers[c->own_pos + 1];

  return peer_get_short (id);
}


/**
 * Get the hop in a connection.
 *
 * @param c Connection.
 * @param fwd Next hop?
 *
 * @return Next peer in the connection. 
 */
static struct MeshPeer *
connection_get_hop (struct MeshConnection *c, int fwd)
{
  if (fwd)
    return connection_get_next_hop (c);
  return connection_get_prev_hop (c);
}

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
 * Deletes a tunnel from a client (either owner or destination).
 *
 * @param c Client whose tunnel to delete.
 * @param ch Channel which should be deleted.
 */
static void
client_delete_channel (struct MeshClient *c, struct MeshChannel *ch)
{
  int res;

  if (c == ch->root)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                  ch->lid_root, ch);
    if (GNUNET_YES != res)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client_delete_channel owner KO\n");
  }
  if (c == ch->dest)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                  ch->lid_dest, ch);
    if (GNUNET_YES != res)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client_delete_tunnel client KO\n");
  }
}


/**
 * Notify the appropriate client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
static void
send_local_channel_create (struct MeshChannel *ch)
{
  struct GNUNET_MESH_ChannelMessage msg;
  struct MeshTunnel2 *t = ch->t;

  if (NULL == ch->dest)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
  msg.channel_id = htonl (ch->lid_dest);
  msg.port = htonl (ch->port);
  msg.opt = 0;
  msg.opt |= GNUNET_YES == ch->reliable ? GNUNET_MESH_OPTION_RELIABLE : 0;
  msg.opt |= GNUNET_YES == ch->nobuffer ? GNUNET_MESH_OPTION_NOBUFFER : 0;
  msg.opt = htonl (msg.opt);
  GNUNET_PEER_resolve (t->peer->id, &msg.peer);
  GNUNET_SERVER_notification_context_unicast (nc, ch->dest->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Notify a client that the incoming tunnel is no longer valid.
 *
 * @param ch Channel that is destroyed.
 * @param fwd Forward notification (owner->dest)?
 */
static void
send_local_channel_destroy (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_ChannelMessage msg;
  struct MeshClient *c;

  c = fwd ? ch->dest : ch->root;
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.channel_id = htonl (fwd ? ch->lid_dest : ch->lid_root);
  msg.port = htonl (0);
  memset (&msg.peer, 0, sizeof (msg.peer));
  msg.opt = htonl (0);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Build a local ACK message and send it to a local client, if needed.
 *
 * If the client was already allowed to send data, do nothing.
 *
 * @param ch Channel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param fwd Set to GNUNET_YES for FWD ACK (dest->root)
 */
static void
send_local_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_LocalAck msg;
  struct MeshChannelReliability *rel;
  struct MeshClient *c;

  c   = fwd ? ch->root     : ch->dest;
  rel = fwd ? ch->root_rel : ch->dest_rel;

  if (GNUNET_YES == rel->client_ready)
    return; /* don't send double ACKs to client */

  rel->client_ready = GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send local %s ack on %s:%X towards %p\n",
              fwd ? "FWD" : "BCK", peer2s (ch->t->peer), ch->gid, c);

  if (NULL == c
      || ( fwd && (0 == ch->lid_root || c != ch->root))
      || (!fwd && (0 == ch->lid_dest || c != ch->dest)) )
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.channel_id = htonl (fwd ? ch->lid_root : ch->lid_dest);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              c->handle,
                                              &msg.header,
                                              GNUNET_NO);

}


/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to send the message.
 *
 * @return Number of connections.
 */
static unsigned int
tunnel_count_connections (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;
  unsigned int i;

  for (c = t->connection_head, i = 0; NULL != c; c = c->next, i++);

  return i;
}


/**
 * Pick a connection on which send the next data message.
 *
 * @param t Tunnel on which to send the message.
 * @param fwd Is this a fwd message?
 *
 * @return The connection on which to send the next message.
 */
static struct MeshConnection *
tunnel_get_connection (struct MeshTunnel2 *t, int fwd)
{
  struct MeshConnection *c;
  struct MeshConnection *best;
  struct MeshFlowControl *fc;
  unsigned int lowest_q;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_get_connection %s\n",
              peer2s (t->peer));
  best = NULL;
  lowest_q = UINT_MAX;
  for (c = t->connection_head; NULL != c; c = c->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  connection %s, \n",
                GNUNET_h2s (&c->id));
    if (MESH_CONNECTION_READY == c->state)
    {
      fc = fwd ? &c->fwd_fc : &c->bck_fc;
      if (NULL == fc)
      {
        GNUNET_break (0);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    q_n %u, \n", fc->queue_n);
      if (fc->queue_n < lowest_q)
      {
        best = c;
        lowest_q = fc->queue_n;
      }
    }
  }
  return best;
}




/**
 * Is this peer the first one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return GNUNET_YES if origin, GNUNET_NO if relay/terminal.
 */
static int
connection_is_origin (struct MeshConnection *c, int fwd)
{
  if (!fwd && c->own_pos == c->path->length - 1)
    return GNUNET_YES;
  if (fwd && c->own_pos == 0)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Is this peer the last one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *            Note that the ROOT is the terminal for BCK traffic!
 *
 * @return GNUNET_YES if terminal, GNUNET_NO if relay/origin.
 */
static int
connection_is_terminal (struct MeshConnection *c, int fwd)
{
  if (fwd && c->own_pos == c->path->length - 1)
    return GNUNET_YES;
  if (!fwd && c->own_pos == 0)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Get free buffer space towards the client on a specific channel.
 *
 * @param ch Channel.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - 64]
 */
static unsigned int
channel_get_buffer (struct MeshChannel *ch, int fwd)
{
  struct MeshChannelReliability *rel;
  
  rel = fwd ? ch->dest_rel : ch->root_rel;

  /* If rel is NULL it means that the end is not yet created,
   * most probably is a loopback channel at the point of sending
   * the ChannelCreate to itself.
   */
  if (NULL == rel)
    return 64;

  return (64 - rel->n_recv);
}


/**
 * Get free buffer space in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - max_msgs_queue/max_connections]
 */
static unsigned int
connection_get_buffer (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;
  
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  
  return (fc->queue_max - fc->queue_n);
}


/**
 * Get the total buffer space for a tunnel.
 */
static unsigned int
tunnel_get_buffer (struct MeshTunnel2 *t, int fwd)
{
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  unsigned int buffer;

  c = t->connection_head;
  buffer = 0;

  if (NULL == c)
  {
    GNUNET_break (0);
    return 0;
  }

  /* If terminal, return biggest channel buffer */
  if (connection_is_terminal (c, fwd))
  {
    struct MeshChannel *ch;
    unsigned int ch_buf;

    if (NULL == t->channel_head)
      return 64;

    for (ch = t->channel_head; NULL != ch; ch = ch->next)
    {
      ch_buf = channel_get_buffer (ch, fwd);
      if (ch_buf > buffer)
        buffer = ch_buf;
    }
    return buffer;
  }

  /* If not terminal, return sum of connection buffers */
  while (NULL != c)
  {
    if (c->state != MESH_CONNECTION_READY)
      continue;

    fc = fwd ? &c->fwd_fc : &c->bck_fc;
    buffer += fc->last_ack_recv - fc->last_pid_sent;
    c = c->next;
  }

  return buffer;
}


/**
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME 
 * Encrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the encrypted data.
 * @param src Source of the plaintext.
 * @param size Size of the plaintext.
 * @param iv Initialization Vector to use.
 * @param fwd Is this a fwd message?
 */
static void
tunnel_encrypt (struct MeshTunnel2 *t,
                void *dst, const void *src,
                size_t size, uint64_t iv, int fwd)
{
  memcpy (dst, src, size);
}


/**
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME 
 * Decrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 * @param fwd Is this a fwd message?
 */
static void
tunnel_decrypt (struct MeshTunnel2 *t,
                void *dst, const void *src,
                size_t size, uint64_t iv, int fwd)
{
  memcpy (dst, src, size);
}


/**
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param c Connection on which this message is transmitted.
 * @param ch Channel on which this message is transmitted, or NULL.
 * @param fwd Is this a fwd message?
 */
static void
send_prebuilt_message_connection (const struct GNUNET_MessageHeader *message,
                                  struct MeshConnection *c,
                                  struct MeshChannel *ch,
                                  int fwd)
{
  void *data;
  size_t size;
  uint16_t type;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send %s (%u) on connection %s\n",
              GNUNET_MESH_DEBUG_M2S (type), size, GNUNET_h2s (&c->id));

  switch (type)
  {
    struct GNUNET_MESH_Encrypted *emsg;
    struct GNUNET_MESH_ACK       *amsg;
    struct GNUNET_MESH_Poll      *pmsg;
    uint32_t ttl;

    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      emsg = (struct GNUNET_MESH_Encrypted *) data;
      ttl = ntohl (emsg->ttl);
      if (0 == ttl)
      {
        GNUNET_break_op (0);
        return;
      }
      emsg->cid = c->id;
      emsg->ttl = htonl (ttl - 1);
      emsg->pid = htonl (fwd ? c->fwd_fc.next_pid++ : c->bck_fc.next_pid++);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " pid %u\n", ntohl (emsg->pid));
      break;

    case GNUNET_MESSAGE_TYPE_MESH_ACK:
      amsg = (struct GNUNET_MESH_ACK *) data;
      amsg->cid = c->id;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ack %u\n", ntohl (amsg->ack));
      break;

    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      pmsg = (struct GNUNET_MESH_Poll *) data;
      pmsg->cid = c->id;
      pmsg->pid = htonl (fwd ? c->fwd_fc.last_pid_sent : c->bck_fc.last_pid_sent);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " poll %u\n", ntohl (pmsg->pid));
      break;

    default:
      GNUNET_break (0);
  }

  queue_add (data,
             type,
             size,
             c,
             ch,
             fwd);
}


/**
 * Sends an already built message on a tunnel, choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
static void
send_prebuilt_message_tunnel (struct GNUNET_MESH_Encrypted *msg,
                              struct MeshTunnel2 *t,
                              struct MeshChannel *ch,
                              int fwd)
{
  struct MeshConnection *c;
  uint16_t type;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send on Tunnel %s\n",
              peer2s (t->peer));
  c = tunnel_get_connection (t, fwd);
  if (NULL == c)
  {
    GNUNET_break (GNUNET_YES == t->destroy);
    return;
  }
  type = ntohs (msg->header.type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      msg->cid = c->id;
      msg->ttl = htonl (default_ttl);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
                  GNUNET_MESH_DEBUG_M2S (type));
      GNUNET_break (0);
  }
  msg->reserved = 0;

  send_prebuilt_message_connection (&msg->header, c, ch, fwd);
}


/**
 * Sends an already built message on a channel, properly registering
 * all used resources and encrypting the message with the tunnel's key.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
static void
send_prebuilt_message_channel (const struct GNUNET_MessageHeader *message,
                               struct MeshChannel *ch,
                               int fwd)
{
  struct GNUNET_MESH_Encrypted *msg;
  size_t size = ntohs (message->size);
  char *cbuf[sizeof (struct GNUNET_MESH_Encrypted) + size];
  uint16_t type;
  uint64_t iv;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send on Channel %s:%X\n",
              peer2s (ch->t->peer), ch->gid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (message->type)));
  type = fwd ? GNUNET_MESSAGE_TYPE_MESH_FWD : GNUNET_MESSAGE_TYPE_MESH_BCK;
  iv = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_NONCE, UINT64_MAX);

  msg = (struct GNUNET_MESH_Encrypted *) cbuf;
  msg->header.type = htons (type);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_Encrypted) + size);
  msg->iv = GNUNET_htonll (iv);
  tunnel_encrypt (ch->t, &msg[1], message, size, iv, fwd);

  send_prebuilt_message_tunnel (msg, ch->t, ch, fwd);
}


/**
 * Sends a CREATE CONNECTION message for a path to a peer.
 * Changes the connection and tunnel states if necessary.
 *
 * @param connection Connection to create.
 */
static void
send_connection_create (struct MeshConnection *connection)
{
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection create\n");
  queue_add (NULL,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
             sizeof (struct GNUNET_MESH_ConnectionCreate) +
                (connection->path->length *
                 sizeof (struct GNUNET_PeerIdentity)),
             connection,
             NULL,
             GNUNET_YES);
  if (NULL != t &&
      (MESH_TUNNEL_SEARCHING == t->state || MESH_TUNNEL_NEW == t->state))
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
  if (MESH_CONNECTION_NEW == connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
}


/**
 * Sends a CONNECTION ACK message in reponse to a received CONNECTION_CREATE
 * directed to us.
 *
 * @param connection Connection to confirm.
 * @param fwd Is this a fwd ACK? (First is bck (SYNACK), second is fwd (ACK))
 */
static void
send_connection_ack (struct MeshConnection *connection, int fwd) 
{
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection ack\n");
  queue_add (NULL,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
             sizeof (struct GNUNET_MESH_ConnectionACK),
             connection,
             NULL,
             fwd);
  if (MESH_TUNNEL_NEW == t->state)
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
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
 * Function to send a create connection message to a peer.
 *
 * @param c Connection to create.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_create (struct MeshConnection *c, size_t size, void *buf)
{
  struct GNUNET_MESH_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct MeshPeerPath *p = c->path;
  size_t size_needed;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION CREATE...\n");
  size_needed =
      sizeof (struct GNUNET_MESH_ConnectionCreate) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  msg = (struct GNUNET_MESH_ConnectionCreate *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE);
  msg->cid = c->id;

  peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[i], peer_ptr++);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CONNECTION CREATE (%u bytes long) sent!\n", size_needed);
  return size_needed;
}


/**
 * Creates a path ack message in buf and frees all unused resources.
 *
 * @param c Connection to send an ACK on.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 *
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_ack (struct MeshConnection *c, size_t size, void *buf)
{
  struct GNUNET_MESH_ConnectionACK *msg = buf;
  struct MeshTunnel2 *t = c->t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION ACK...\n");
  GNUNET_assert (NULL != t);
  if (sizeof (struct GNUNET_MESH_ConnectionACK) > size)
  {
    GNUNET_break (0);
    return 0;
  }
  msg->header.size = htons (sizeof (struct GNUNET_MESH_ConnectionACK));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK);
  msg->cid = c->id;

  /* TODO add signature */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CONNECTION ACK sent!\n");
  return sizeof (struct GNUNET_MESH_ConnectionACK);
}


/**
 * Destroy the peer_info and free any allocated resources linked to it
 *
 * @param peer The peer_info to destroy.
 *
 * @return GNUNET_OK on success
 */
static int
peer_destroy (struct MeshPeer *peer)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPeerPath *p;
  struct MeshPeerPath *nextp;

  GNUNET_PEER_resolve (peer->id, &id);
  GNUNET_PEER_change_rc (peer->id, -1);

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_remove (peers, &id.hashPubKey, peer))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "removing peer %s, not in hashmap\n", GNUNET_i2s (&id));
  }
  if (NULL != peer->dhtget)
  {
    GNUNET_DHT_get_stop (peer->dhtget);
  }
  p = peer->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, p);
    path_destroy (p);
    p = nextp;
  }
  tunnel_destroy_empty (peer->tunnel);
  GNUNET_free (peer);
  return GNUNET_OK;
}


/**
 * Returns if peer is used (has a tunnel, is neighbor).
 *
 * @peer Peer to check.
 *
 * @return GNUNET_YES if peer is in use.
 */
static int
peer_is_used (struct MeshPeer *peer)
{
  struct MeshPeerPath *p;

  if (NULL != peer->tunnel)
    return GNUNET_YES;

  for (p = peer->path_head; NULL != p; p = p->next)
  {
    if (p->length < 3)
      return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * Iterator over all the peers to get the oldest timestamp.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_get_oldest (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct MeshPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;

  /* Don't count active peers */
  if (GNUNET_YES == peer_is_used (p))
    return GNUNET_YES;

  if (abs->abs_value_us < p->last_contact.abs_value_us)
    abs->abs_value_us = p->last_contact.abs_value_us;

  return GNUNET_YES;
}


/**
 * Iterator over all the peers to remove the oldest entry.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_timeout (void *cls,
              const struct GNUNET_HashCode *key,
              void *value)
{
  struct MeshPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;

  if (p->last_contact.abs_value_us == abs->abs_value_us &&
      GNUNET_NO == peer_is_used (p))
  {
    peer_destroy (p);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Delete oldest unused peer.
 */
static void
peer_delete_oldest (void)
{
  struct GNUNET_TIME_Absolute abs;

  abs = GNUNET_TIME_UNIT_FOREVER_ABS;

  GNUNET_CONTAINER_multihashmap_iterate (peers,
                                         &peer_get_oldest,
                                         &abs);
  GNUNET_CONTAINER_multihashmap_iterate (peers,
                                         &peer_timeout,
                                         &abs);
}


/**
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
peer_get (const struct GNUNET_PeerIdentity *peer_id)
{
  struct MeshPeer *peer;

  peer = GNUNET_CONTAINER_multihashmap_get (peers, &peer_id->hashPubKey);
  if (NULL == peer)
  {
    peer = GNUNET_new (struct MeshPeer);
    if (GNUNET_CONTAINER_multihashmap_size (peers) > max_peers)
    {
      peer_delete_oldest ();
    }
    GNUNET_CONTAINER_multihashmap_put (peers, &peer_id->hashPubKey, peer,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    peer->id = GNUNET_PEER_intern (peer_id);
  }
  peer->last_contact = GNUNET_TIME_absolute_get();

  return peer;
}


/**
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
peer_get_short (const GNUNET_PEER_Id peer)
{
  return peer_get (GNUNET_PEER_resolve2 (peer));
}


/**
 * Get a cost of a path for a peer considering existing tunnel connections.
 *
 * @param peer Peer towards which the path is considered.
 * @param path Candidate path.
 *
 * @return Cost of the path (path length + number of overlapping nodes)
 */
static unsigned int
peer_get_path_cost (const struct MeshPeer *peer,
                    const struct MeshPeerPath *path)
{
  struct MeshConnection *c;
  unsigned int overlap;
  unsigned int i;
  unsigned int j;

  if (NULL == path)
    return 0;

  overlap = 0;
  GNUNET_assert (NULL != peer->tunnel);

  for (i = 0; i < path->length; i++)
  {
    for (c = peer->tunnel->connection_head; NULL != c; c = c->next)
    {
      for (j = 0; j < c->path->length; j++)
      {
        if (path->peers[i] == c->path->peers[j])
        {
          overlap++;
          break;
        }
      }
    }
  }
  return (path->length + overlap) * (path->score * -1);
}


/**
 * Choose the best path towards a peer considering the tunnel properties.
 *
 * @param peer The destination peer.
 *
 * @return Best current known path towards the peer, if any.
 */
static struct MeshPeerPath *
peer_get_best_path (const struct MeshPeer *peer)
{
  struct MeshPeerPath *best_p;
  struct MeshPeerPath *p;
  struct MeshConnection *c;
  unsigned int best_cost;
  unsigned int cost;

  best_cost = UINT_MAX;
  best_p = NULL;
  for (p = peer->path_head; NULL != p; p = p->next)
  {
    for (c = peer->tunnel->connection_head; NULL != c; c = c->next)
      if (c->path == p)
        break;
    if (NULL != c)
      continue; /* If path is in use in a connection, skip it. */

    if ((cost = peer_get_path_cost (peer, p)) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
  }
  return best_p;
}

static int
queue_is_sendable (struct MeshPeerQueue *q)
{
  struct MeshFlowControl *fc;

  /* Is PID-independent? */
  switch (q->type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      return GNUNET_YES;
  }

  /* Is PID allowed? */
  fc = q->fwd ? &q->c->fwd_fc : &q->c->bck_fc;
  if (GMC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
    return GNUNET_YES;

  return GNUNET_NO;
}


/**
 * Get first sendable message.
 *
 * @param peer The destination peer.
 *
 * @return Best current known path towards the peer, if any.
 */
static struct MeshPeerQueue *
peer_get_first_message (const struct MeshPeer *peer)
{
  struct MeshPeerQueue *q;

  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    if (queue_is_sendable (q))
      return q;
  }

  return NULL;
}


/**
 * Try to establish a new connection to this peer in the given tunnel.
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE CONNECTION towards it.
 *
 * @param peer PeerInfo of the peer.
 */
static void
peer_connect (struct MeshPeer *peer)
{
  struct MeshTunnel2 *t;
  struct MeshPeerPath *p;
  struct MeshConnection *c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "peer_connect towards %s\n",
              peer2s (peer));
  t = peer->tunnel;
  if (NULL != peer->path_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "path exists\n");
    p = peer_get_best_path (peer);
    if (NULL != p)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %u hops\n", p->length);
      c = tunnel_use_path (t, p);
      send_connection_create (c);
    }
  }
  else if (NULL == peer->dhtget)
  {
    const struct GNUNET_PeerIdentity *id;

    id = GNUNET_PEER_resolve2 (peer->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", peer2s (peer));
    peer->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                         GNUNET_BLOCK_TYPE_MESH_PEER, /* type */
                                         &id->hashPubKey,     /* key to search */
                                         dht_replication_level, /* replication level */
                                         GNUNET_DHT_RO_RECORD_ROUTE |
                                         GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                         NULL,       /* xquery */
                                         0,     /* xquery bits */
                                         &dht_get_id_handler, peer);
    if (MESH_TUNNEL_NEW == t->state)
      tunnel_change_state (t, MESH_TUNNEL_SEARCHING);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "There is no path but the DHT GET is already started.\n");
  }
}


/**
 * Get the first transmittable message for a connection.
 *
 * @param c Connection.
 * @param fwd Is this FWD?
 *
 * @return First transmittable message.
 */
static struct MeshPeerQueue *
connection_get_first_message (struct MeshConnection *c, int fwd)
{
  struct MeshPeerQueue *q;
  struct MeshPeer *p;

  p = connection_get_hop (c, fwd);

  for (q = p->queue_head; NULL != q; q = q->next)
  {
    if (q->c != c)
      continue;
    if (queue_is_sendable (q))
      return q;
  }

  return NULL;
}


/**
 * @brief Re-initiate traffic on this connection if necessary.
 *
 * Check if there is traffic queued towards this peer
 * and the core transmit handle is NULL (traffic was stalled).
 * If so, call core tmt rdy.
 *
 * @param c Connection on which initiate traffic.
 * @param fwd Is this about fwd traffic?
 */
static void
connection_unlock_queue (struct MeshConnection *c, int fwd)
{
  struct MeshPeer *peer;
  struct MeshPeerQueue *q;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connection_unlock_queue %s on %s\n",
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

  if (connection_is_origin (c, fwd))
  {
    struct MeshTunnel2 *t = c->t;
    struct MeshChannel *ch;
    struct MeshChannelReliability *rel;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " is origin!\n");
    /* FIXME randomize channel selection, not always first channel */
    for (ch = t->channel_head; NULL != ch; ch = ch->next)
    {
      rel = fwd ? ch->root_rel : ch->dest_rel;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  channel %X - %s\n",
                  ch->gid, rel->client_ready ? "ready " : "not ready");
      if (GNUNET_NO == rel->client_ready)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    sending local ack!\n");
        send_local_ack (ch, fwd);
        return; /* FIXME authorize all channels? */
      }
    }
    return;
  }

  peer = connection_get_hop (c, fwd);

  if (NULL != peer->core_transmit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  already unlocked!\n");
    return; /* Already unlocked */
  }

  q = connection_get_first_message (c, fwd);
  if (NULL == q)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  queue empty!\n");
    return; /* Nothing to transmit */
  }

  size = q->size;
  peer->core_transmit =
      GNUNET_CORE_notify_transmit_ready (core_handle,
                                         GNUNET_NO,
                                         0,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_PEER_resolve2 (peer->id),
                                         size,
                                         &queue_send,
                                         peer);
}


/**
 * Cancel all transmissions that belong to a certain connection.
 *
 * @param c Connection which to cancel.
 * @param fwd Cancel fwd traffic?
 */
static void
connection_cancel_queues (struct MeshConnection *c, int fwd)
{
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *next;
  struct MeshFlowControl *fc;
  struct MeshPeer *peer;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  peer = connection_get_hop (c, fwd);

  for (q = peer->queue_head; NULL != q; q = next)
  {
    next = q->next;
    if (q->c == c)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connection_cancel_queue %s\n",
                  GNUNET_MESH_DEBUG_M2S (q->type));
      queue_destroy (q, GNUNET_YES);
    }
  }
  if (NULL == peer->queue_head)
  {
    if (NULL != peer->core_transmit)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
      peer->core_transmit = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    {
      GNUNET_SCHEDULER_cancel (fc->poll_task);
      fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
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
peer_remove_path (struct MeshPeer *peer, GNUNET_PEER_Id p1,
                  GNUNET_PEER_Id p2)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *next;
  struct MeshPeer *peer_d;
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


  d = tunnel_notify_connection_broken (peer->tunnel, p1, p2);

  peer_d = peer_get_short (d); // FIXME
  next = peer_get_best_path (peer_d);
  tunnel_use_path (peer->tunnel, next);
  peer_connect (peer_d);

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
peer_add_path (struct MeshPeer *peer_info, struct MeshPeerPath *path,
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "adding path [%u] to peer %s\n",
              path->length, peer2s (peer_info));

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
peer_add_path_to_origin (struct MeshPeer *peer_info,
                         struct MeshPeerPath *path, int trusted)
{
  path_invert (path);
  peer_add_path (peer_info, path, trusted);
}



/**
 * Function called if a connection has been stalled for a while,
 * possibly due to a missed ACK. Poll the neighbor about its ACK status.
 *
 * @param cls Closure (poll ctx).
 * @param tc TaskContext.
 */
static void
connection_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshFlowControl *fc = cls;
  struct GNUNET_MESH_Poll msg;
  struct MeshConnection *c;

  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  c = fc->c;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** connection %s[%X]\n", 
              peer2s (c->t->peer), c->id);

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** pid (%u)!\n", fc->last_pid_sent);
  send_prebuilt_message_connection (&msg.header, c, NULL, fc == &c->fwd_fc);
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &connection_poll, fc);
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
    struct MeshPeer *aux;
    struct MeshPeerPath *copy;

    aux = peer_get_short (p->peers[i]);
    copy = path_duplicate (p);
    copy->length = i + 1;
    peer_add_path (aux, copy, p->length < 3 ? GNUNET_NO : confirmed);
  }
}


/**
 * Search for a channel among the channels for a client
 *
 * @param c the client whose channels to search in
 * @param chid the local id of the channel
 *
 * @return channel handler, NULL if doesn't exist
 */
static struct MeshChannel *
channel_get_by_local_id (struct MeshClient *c, MESH_ChannelNumber chid)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   -- get CHID %X\n", chid);
  if (0 == (chid & GNUNET_MESH_LOCAL_CHANNEL_ID_CLI))
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CHID %X not a local chid\n", chid);
    return NULL;
  }
  if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    return GNUNET_CONTAINER_multihashmap32_get (c->incoming_channels, chid);
  return GNUNET_CONTAINER_multihashmap32_get (c->own_channels, chid);
}

/**
 * Search for a tunnel by global ID using full PeerIdentities.
 *
 * @param t Tunnel containing the channel.
 * @param chid Public channel number.
 *
 * @return channel handler, NULL if doesn't exist
 */
static struct MeshChannel *
channel_get (struct MeshTunnel2 *t, MESH_ChannelNumber chid)
{
  struct MeshChannel *ch;

  if (NULL == t)
    return NULL;

  for (ch = t->channel_head; NULL != ch; ch = ch->next)
  {
    if (ch->gid == chid)
      break;
  }

  return ch;
}


/**
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
static void
tunnel_change_state (struct MeshTunnel2* t, enum MeshTunnelState state)
{
  if (NULL == t)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state was %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (t->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state is now %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (state));
  t->state = state;
}


/**
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param ch Channel the message is about.
 * @param msg Message itself (copy will be made).
 * @param fwd Is this fwd?
 */
static void
tunnel_queue_data (struct MeshTunnel2 *t,
                   struct MeshChannel *ch,
                   struct GNUNET_MessageHeader *msg,
                   int fwd)
{
  struct MeshTunnelQueue *tq;
  uint16_t size = ntohs (msg->size);

  tq = GNUNET_malloc (sizeof (struct MeshTunnelQueue) + size);

  tq->ch = ch;
  memcpy (&tq[1], msg, size);
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head, t->tq_tail, tq);
}


/**
 * Send all cached messages that we can, tunnel is online.
 *
 * @param t Tunnel that holds the messages.
 * @param fwd Is this fwd?
 */
static void
tunnel_send_queued_data (struct MeshTunnel2 *t, int fwd)
{
  struct MeshTunnelQueue *tq;
  struct MeshTunnelQueue *next;
  unsigned int room;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "tunnel_send_queued_data on tunnel %s\n",
              peer2s (t->peer));
  room = tunnel_get_buffer (t, fwd);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  buffer space: %u\n", room);
  for (tq = t->tq_head; NULL != tq && room > 0; tq = next)
  {
    next = tq->next;
    room--;
    GNUNET_CONTAINER_DLL_remove (t->tq_head, t->tq_tail, tq);
    send_prebuilt_message_channel ((struct GNUNET_MessageHeader *) &tq[1],
                                   tq->ch, fwd);

    GNUNET_free (tq);
  }
}


static void
connection_change_state (struct MeshConnection* c,
                         enum MeshConnectionState state)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state was %s\n",
              GNUNET_h2s (&c->id), GNUNET_MESH_DEBUG_CS2S (c->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state is now %s\n",
              GNUNET_h2s (&c->id), GNUNET_MESH_DEBUG_CS2S (state));
  c->state = state;
}


/**
 * Add a client to a channel, initializing all needed data structures.
 * 
 * @param ch Channel to which add the client.
 * @param c Client which to add to the channel.
 */
static void
channel_add_client (struct MeshChannel *ch, struct MeshClient *c)
{
  struct MeshTunnel2 *t = ch->t;

  if (NULL != ch->dest)
  {
    GNUNET_break (0);
    return;
  }

  /* Assign local id as destination */
  while (NULL != channel_get_by_local_id (c, t->next_local_chid))
    t->next_local_chid = (t->next_local_chid + 1) | GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  ch->lid_dest = t->next_local_chid++;
  t->next_local_chid = t->next_local_chid | GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;

  /* Store in client's hashmap */
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap32_put (c->incoming_channels,
                                           ch->lid_dest, ch,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_break (NULL == ch->dest_rel);
  ch->dest_rel = GNUNET_new (struct MeshChannelReliability);
  ch->dest_rel->ch = ch;
  ch->dest_rel->expected_delay = MESH_RETRANSMIT_TIME;

  ch->dest = c;
}


static struct MeshConnection *
tunnel_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p)
{
  struct MeshConnection *c;
  struct GNUNET_HashCode cid;
  struct MeshPeer *peer;
  unsigned int own_pos;

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE, &cid);

  c = connection_new (&cid);
  c->t = t;
  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    connection_destroy (c);
    return NULL;
  }
  c->own_pos = own_pos;
  c->path = p;

  if (0 == own_pos)
  {
    c->fwd_maintenance_task =
        GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                      &connection_fwd_keepalive, c);
  }

  peer = connection_get_next_hop (c);
  GNUNET_CONTAINER_multihashmap_put (peer->connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  peer = connection_get_prev_hop (c);
  GNUNET_CONTAINER_multihashmap_put (peer->connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  return c;
}


/**
 * Notifies a tunnel that a connection has broken that affects at least
 * some of its peers. Sends a notification towards the root of the tree.
 * In case the peer is the owner of the tree, notifies the client that owns
 * the tunnel and tries to reconnect.
 * 
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME 
 *
 * @param t Tunnel affected.
 * @param p1 Peer that got disconnected from p2.
 * @param p2 Peer that got disconnected from p1.
 *
 * @return Short ID of the peer disconnected (either p1 or p2).
 *         0 if the tunnel remained unaffected.
 */
static GNUNET_PEER_Id
tunnel_notify_connection_broken (struct MeshTunnel2* t,
                                 GNUNET_PEER_Id p1, GNUNET_PEER_Id p2)
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
 * Send an end-to-end ACK message for the most recent in-sequence payload.
 *
 * If channel is not reliable, do nothing.
 *
 * @param ch Channel this is about.
 * @param fwd Is for FWD traffic? (ACK dest->owner)
 */
static void
channel_send_data_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_DataACK msg;
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  unsigned int delta;
  uint64_t mask;
  uint16_t type;

  if (GNUNET_NO == ch->reliable)
  {
    return;
  }
  rel = fwd ? ch->dest_rel : ch->root_rel;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send_data_ack for %u\n",
              rel->mid_recv - 1);

  type = GNUNET_MESSAGE_TYPE_MESH_DATA_ACK;
  msg.header.type = htons (type);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (ch->gid);
  msg.mid = htonl (rel->mid_recv - 1);
  msg.futures = 0;
  for (copy = rel->head_recv; NULL != copy; copy = copy->next)
  {
    if (copy->type != type)
      continue;
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

  send_prebuilt_message_channel (&msg.header, ch, fwd);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_data_ack END\n");
}


/**
 * Send an ACK informing the predecessor about the available buffer space.
 *
 * Note that for fwd ack, the FWD mean forward *traffic* (root->dest),
 * the ACK itself goes "back" (dest->root).
 *
 * @param c Connection on which to send the ACK.
 * @param buffer How much space free to advertise?
 * @param fwd Is this FWD ACK? (Going dest->owner)
 */
static void
connection_send_ack (struct MeshConnection *c, unsigned int buffer, int fwd)
{
  struct MeshFlowControl *next_fc;
  struct MeshFlowControl *prev_fc;
  struct GNUNET_MESH_ACK msg;
  uint32_t ack;
  int delta;

  next_fc = fwd ? &c->fwd_fc : &c->bck_fc;
  prev_fc = fwd ? &c->bck_fc : &c->fwd_fc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connection send %s ack on %s\n",
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

  /* Check if we need to transmit the ACK */
  if (prev_fc->last_ack_sent - prev_fc->last_pid_recv > 3)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer > 3\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  last pid recv: %u, last ack sent: %u\n",
                prev_fc->last_pid_recv, prev_fc->last_ack_sent);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  delta = next_fc->queue_max - next_fc->queue_n;
  ack = prev_fc->last_pid_recv + delta;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " last pid %u, last ack %u, qmax %u, q %u\n",
              prev_fc->last_pid_recv, prev_fc->last_ack_sent,
              next_fc->queue_max, next_fc->queue_n);
  if (ack == prev_fc->last_ack_sent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
    return;
  }

  prev_fc->last_ack_sent = ack;

  /* Build ACK message and send on connection */
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.ack = htonl (ack);
  msg.cid = c->id;

  send_prebuilt_message_connection (&msg.header, c, NULL, !fwd);
}


/**
 * Modify the mesh message TID from global to local and send to client.
 * 
 * @param ch Channel on which to send the message.
 * @param msg Message to modify and send.
 * @param c Client to send to.
 * @param tid Tunnel ID to use (c can be both owner and client).
 */
static void
channel_send_client_to_tid (struct MeshChannel *ch,
                             const struct GNUNET_MESH_Data *msg,
                             struct MeshClient *c, MESH_ChannelNumber id)
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
  copy->id = htonl (id);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &copy->header, GNUNET_NO);
}


/**
 * We have received a message out of order, or the client is not ready.
 * Buffer it until we receive an ACK from the client or the missing
 * message from the channel.
 *
 * @param msg Message to buffer (MUST be of type MESH_DATA).
 * @param rel Reliability data to the corresponding direction.
 */
static void
channel_rel_add_buffered_data (const struct GNUNET_MESH_Data *msg,
                               struct MeshChannelReliability *rel)
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
  
  rel->n_recv++;
  
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
 * Modify the data message ID from global to local and send to client.
 * 
 * @param ch Channel on which to send the message.
 * @param msg Message to modify and send.
 * @param fwd Forward?
 */
static void
channel_send_client_data (struct MeshChannel *ch,
                          const struct GNUNET_MESH_Data *msg,
                          int fwd)
{
  if (fwd)
  {
    if (ch->dest_rel->client_ready)
      channel_send_client_to_tid (ch, msg, ch->dest, ch->lid_dest);
    else
      channel_rel_add_buffered_data (msg, ch->dest_rel);
  }
  else
  {
    if (ch->root_rel->client_ready)
      channel_send_client_to_tid (ch, msg, ch->root, ch->lid_root);
    else
      channel_rel_add_buffered_data (msg, ch->root_rel);
  }
}


/**
 * Send a buffered message to the client, for in order delivery or
 * as result of client ACK.
 *
 * @param ch Channel on which to empty the message buffer.
 * @param c Client to send to.
 * @param rel Reliability structure to corresponding peer.
 *            If rel == bck_rel, this is FWD data.
 */
static void
channel_send_client_buffered_data (struct MeshChannel *ch,
                                   struct MeshClient *c,
                                   int fwd)
{
  struct MeshReliableMessage *copy;
  struct MeshChannelReliability *rel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data\n");
  rel = fwd ? ch->dest_rel : ch->root_rel;
  if (GNUNET_NO == rel->client_ready)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client not ready\n");
    return;
  }

  copy = rel->head_recv;
  /* We never buffer channel management messages */
  if (NULL != copy)
  {
    if (copy->mid == rel->mid_recv || GNUNET_NO == ch->reliable)
    {
      struct GNUNET_MESH_Data *msg = (struct GNUNET_MESH_Data *) &copy[1];

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " have %u! now expecting %u\n",
                  copy->mid, rel->mid_recv + 1);
      channel_send_client_data (ch, msg, fwd);
      rel->n_recv--;
      rel->mid_recv++;
      GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
      GNUNET_free (copy);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " reliable && don't have %u, next is %u\n",
                  rel->mid_recv,
                  copy->mid);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data END\n");
}


/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 * 
 * @param copy Message that is no longer needed: remote peer got it.
 */
static void
rel_message_free (struct MeshReliableMessage *copy)
{
  struct MeshChannelReliability *rel;
  struct GNUNET_TIME_Relative time;

  rel = copy->rel;
  time = GNUNET_TIME_absolute_get_duration (copy->timestamp);
  rel->expected_delay.rel_value_us *= 7;
  rel->expected_delay.rel_value_us += time.rel_value_us;
  rel->expected_delay.rel_value_us /= 8;
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
 * Destroy all reliable messages queued for a channel,
 * during a channel destruction.
 * Frees the reliability structure itself.
 *
 * @param rel Reliability data for a channel.
 */
static void
channel_rel_free_all (struct MeshChannelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  if (NULL == rel)
    return;

  for (copy = rel->head_recv; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
    GNUNET_free (copy);
  }
  for (copy = rel->head_sent; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
    GNUNET_free (copy);
  }
  if (GNUNET_SCHEDULER_NO_TASK != rel->retry_task)
    GNUNET_SCHEDULER_cancel (rel->retry_task);
  GNUNET_free (rel);
}


/**
 * Mark future messages as ACK'd.
 *
 * @param rel Reliability data.
 * @param msg DataACK message with a bitfield of future ACK'd messages.
 */
static void
channel_rel_free_sent (struct MeshChannelReliability *rel,
                       const struct GNUNET_MESH_DataACK *msg)
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
    rel_message_free (copy);
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
channel_retransmit_message (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshChannelReliability *rel = cls;
  struct MeshReliableMessage *copy;
  struct MeshPeerQueue *q;
  struct MeshChannel *ch;
  struct MeshConnection *c;
  struct GNUNET_MESH_Data *payload;
  struct MeshPeer *hop;
  int fwd;

  rel->retry_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  ch = rel->ch;
  copy = rel->head_sent;
  if (NULL == copy)
  {
    GNUNET_break (0);
    return;
  }

  /* Search the message to be retransmitted in the outgoing queue.
   * Check only the queue for the connection that is going to be used,
   * if the message is stuck in some other connection's queue we shouldn't
   * act upon it:
   * - cancelling it and sending the new one doesn't guarantee it's delivery,
   *   the old connection could be temporary stalled or the queue happened to
   *   be long at time of insertion.
   * - not sending the new one could cause terrible delays the old connection
   *   is stalled.
   */
  payload = (struct GNUNET_MESH_Data *) &copy[1];
  fwd = (rel == ch->root_rel);
  c = tunnel_get_connection (ch->t, fwd);
  hop = connection_get_hop (c, fwd);
  for (q = hop->queue_head; NULL != q; q = q->next)
  {
    if (ntohs (payload->header.type) == q->type && ch == q->ch)
    {
      struct GNUNET_MESH_Data *queued_data = q->cls;

      if (queued_data->mid == payload->mid)
        break;
    }
  }

  /* Message not found in the queue that we are going to use. */
  if (NULL == q)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! RETRANSMIT %u\n", copy->mid);

    send_prebuilt_message_channel (&payload->header, ch, fwd);
    GNUNET_STATISTICS_update (stats, "# data retransmitted", 1, GNUNET_NO);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! ALREADY IN QUEUE %u\n", copy->mid);
  }

  rel->retry_timer = GNUNET_TIME_STD_BACKOFF (rel->retry_timer);
  rel->retry_task = GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                                  &channel_retransmit_message,
                                                  cls);
}


/**
 * Send ACK on one or more connections due to buffer space to the client.
 *
 * Iterates all connections of the tunnel and sends ACKs appropriately.
 *
 * @param ch Channel which has some free buffer space.
 * @param fwd Is this in for FWD traffic? (ACK goes dest->root)
 */
static void
channel_send_connections_ack (struct MeshChannel *ch,
                              unsigned int buffer,
                              int fwd)
{
  struct MeshTunnel2 *t = ch->t;
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  uint32_t allowed;
  uint32_t to_allow;
  uint32_t allow_per_connection;
  unsigned int cs;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Channel send connection %s ack on %s:%X\n",
              fwd ? "FWD" : "BCK", peer2s (ch->t->peer), ch->gid);

  /* Count connections, how many messages are already allowed */
  for (cs = 0, allowed = 0, c = t->connection_head; NULL != c; c = c->next)
  {
    fc = fwd ? &c->fwd_fc : &c->bck_fc;
    if (GMC_is_pid_bigger(fc->last_pid_recv, fc->last_ack_sent))
    {
      GNUNET_break (0);
      continue;
    }
    allowed += fc->last_ack_sent - fc->last_pid_recv;
    cs++;
  }

  /* Make sure there is no overflow */
  if (allowed > buffer)
  {
    GNUNET_break (0);
    return;
  }

  /* Authorize connections to send more data */
  to_allow = buffer - allowed;

  for (c = t->connection_head; NULL != c && to_allow > 0; c = c->next)
  {
    allow_per_connection = to_allow/cs;
    to_allow -= allow_per_connection;
    cs--;
    fc = fwd ? &c->fwd_fc : &c->bck_fc;
    if (fc->last_ack_sent - fc->last_pid_recv > 64 / 3)
    {
      continue;
    }
    connection_send_ack (c, allow_per_connection, fwd);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel send connection %s ack on %s:%X\n",
                fwd ? "FWD" : "BCK", peer2s (ch->t->peer), ch->gid);
  GNUNET_break (to_allow == 0);
}


/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param ch Channel, if any.
 * @param fwd Is this a fwd ACK? (will go dest->root)
 */
static void
send_ack (struct MeshConnection *c, struct MeshChannel *ch, int fwd)
{
  unsigned int buffer;

  if (NULL == c || connection_is_terminal (c, fwd))
  {
    GNUNET_assert (NULL != ch);
    buffer = tunnel_get_buffer (ch->t, fwd);
  }
  else
  {
    GNUNET_assert (NULL != c);
    buffer = connection_get_buffer (c, fwd);
  }

  if (NULL == c)
  {
    GNUNET_assert (NULL != ch);
    channel_send_connections_ack (ch, buffer, fwd);
  }
  else if (connection_is_origin (c, fwd))
  {
    if (0 < buffer)
    {
      GNUNET_assert (NULL != ch);
      send_local_ack (ch, fwd);
    }
  }
  else
  {
    connection_send_ack (c, buffer, fwd);
  }
}


/**
 * Channel was ACK'd by remote peer, mark as ready and cancel retransmission.
 *
 * @param ch Channel to mark as ready.
 * @param fwd Was the CREATE message sent fwd?
 */
static void
channel_confirm (struct MeshChannel *ch, int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  channel confirm %s %s:%X\n",
              fwd ? "FWD" : "BCK", peer2s (ch->t->peer), ch->gid);
  ch->state = MESH_CHANNEL_READY;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  for (copy = rel->head_sent; NULL != copy; copy = next)
  {
    struct GNUNET_MessageHeader *msg;

    next = copy->next;
    msg = (struct GNUNET_MessageHeader *) &copy[1];
    if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE)
    {
      rel_message_free (copy);
      /* TODO return? */
    }
  }
  if (GNUNET_NO == rel->client_ready)
    send_local_ack (ch, fwd);
}


/**
 * Save a copy to retransmit in case it gets lost.
 *
 * Initializes all needed callbacks and timers.
 *
 * @param ch Channel this message goes on.
 * @param msg Message to copy.
 * @param fwd Is this fwd traffic?
 */
static void
channel_save_copy (struct MeshChannel *ch,
                   const struct GNUNET_MessageHeader *msg,
                   int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  uint32_t mid;
  uint16_t type;
  uint16_t size;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  mid = rel->mid_send;
  type = ntohs (msg->type);
  size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! SAVE %u\n", mid);
  copy = GNUNET_malloc (sizeof (struct MeshReliableMessage) + size);
  copy->mid = mid;
  copy->timestamp = GNUNET_TIME_absolute_get ();
  copy->rel = rel;
  copy->type = type;
  memcpy (&copy[1], msg, size);
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
                                      &channel_retransmit_message,
                                      rel);
  }
}


/**
 * Send keepalive packets for a connection.
 *
 * @param c Connection to keep alive..
 * @param fwd Is this a FWD keepalive? (owner -> dest).
 */
static void
connection_keepalive (struct MeshConnection *c, int fwd)
{
  struct GNUNET_MESH_ConnectionKeepAlive *msg;
  size_t size = sizeof (struct GNUNET_MESH_ConnectionKeepAlive);
  char cbuf[size];
  uint16_t type;

  type = fwd ? GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE :
               GNUNET_MESSAGE_TYPE_MESH_BCK_KEEPALIVE;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending %s keepalive for connection %s[%d]\n",
              fwd ? "FWD" : "BCK",
              peer2s (c->t->peer),
              c->id);

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (type);
  msg->cid = c->id;

  send_prebuilt_message_connection (&msg->header, c, NULL, fwd);
}


/**
 * Send CONNECTION_{CREATE/ACK} packets for a connection.
 *
 * @param c Connection for which to send the message.
 * @param fwd If GNUNET_YES, send CREATE, otherwise send ACK.
 */
static void
connection_recreate (struct MeshConnection *c, int fwd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending connection recreate\n");
  if (fwd)
    send_connection_create (c);
  else
    send_connection_ack (c, GNUNET_NO);
}


/**
 * Generic connection timer management.
 * Depending on the role of the peer in the connection will send the
 * appropriate message (build or keepalive)
 *
 * @param c Conncetion to maintain.
 * @param fwd Is FWD?
 */
static void
connection_maintain (struct MeshConnection *c, int fwd)
{
  if (MESH_TUNNEL_SEARCHING == c->t->state)
  {
    /* TODO DHT GET with RO_BART */
    return;
  }
  switch (c->state)
  {
    case MESH_CONNECTION_NEW:
      GNUNET_break (0);
    case MESH_CONNECTION_SENT:
      connection_recreate (c, fwd);
      break;
    case MESH_CONNECTION_READY:
      connection_keepalive (c, fwd);
      break;
    default:
      break;
  }
}


static void
connection_fwd_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->fwd_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_YES);
  c->fwd_maintenance_task = GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                                          &connection_fwd_keepalive,
                                                          c);
}


static void
connection_bck_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->bck_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_NO);
  c->bck_maintenance_task = GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                                          &connection_bck_keepalive,
                                                          c);
}


/**
 * Send a message to all peers in this connection that the connection
 * is no longer valid.
 *
 * If some peer should not receive the message, it should be zero'ed out
 * before calling this function.
 *
 * @param c The connection whose peers to notify.
 */
static void
connection_send_destroy (struct MeshConnection *c)
{
  struct GNUNET_MESH_ConnectionDestroy msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY);;
  msg.cid = c->id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending connection destroy for connection %s[%X]\n",
              peer2s (c->t->peer),
              c->id);

  send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_YES);
  send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_NO);
  c->destroy = GNUNET_YES;
}


/**
 * Confirm we got a channel create.
 *
 * @param ch The channel to confirm.
 * @param fwd Should we send the ACK fwd?
 */
static void
channel_send_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending channel ack for channel %s:%X\n",
              peer2s (ch->t->peer),
              ch->gid);

  msg.chid = htonl (ch->gid);
  send_prebuilt_message_channel (&msg.header, ch, fwd);
}


/**
 * Send a message to all clients (local and remote) of this channel
 * notifying that the channel is no longer valid.
 *
 * If some peer or client should not receive the message,
 * should be zero'ed out before calling this function.
 *
 * @param ch The channel whose clients to notify.
 */
static void
channel_send_destroy (struct MeshChannel *ch)
{
  struct GNUNET_MESH_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending channel destroy for channel %s:%X\n",
              peer2s (ch->t->peer),
              ch->gid);

  if (NULL != ch->root)
  {
    msg.chid = htonl (ch->lid_root);
    send_local_channel_destroy (ch, GNUNET_NO);
  }
  else
  {
    msg.chid = htonl (ch->gid);
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_NO);
  }

  if (NULL != ch->dest)
  {
    msg.chid = htonl (ch->lid_dest);
    send_local_channel_destroy (ch, GNUNET_YES);
  }
  else
  {
    msg.chid = htonl (ch->gid);
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_YES);
  }
}


/**
 * Create a tunnel.
 */
static struct MeshTunnel2 *
tunnel_new (void)
{
  struct MeshTunnel2 *t;

  t = GNUNET_new (struct MeshTunnel2);
  t->next_chid = 0;
  t->next_local_chid = GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
//   if (GNUNET_OK !=
//       GNUNET_CONTAINER_multihashmap_put (tunnels, tid, t,
//                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
//   {
//     GNUNET_break (0);
//     tunnel_destroy (t);
//     return NULL;
//   }

//   char salt[] = "salt";
//   GNUNET_CRYPTO_kdf (&t->e_key, sizeof (struct GNUNET_CRYPTO_AesSessionKey),
//                      salt, sizeof (salt),
//                      &t->e_key, sizeof (struct GNUNET_CRYPTO_AesSessionKey),
//                      &my_full_id, sizeof (struct GNUNET_PeerIdentity),
//                      GNUNET_PEER_resolve2 (t->peer->id), sizeof (struct GNUNET_PeerIdentity),
//                      NULL);
//   GNUNET_CRYPTO_kdf (&t->d_key, sizeof (struct GNUNET_CRYPTO_AesSessionKey),
//                      salt, sizeof (salt),
//                      &t->d_key, sizeof (struct GNUNET_CRYPTO_AesSessionKey),
//                      GNUNET_PEER_resolve2 (t->peer->id), sizeof (struct GNUNET_PeerIdentity),
//                      &my_full_id, sizeof (struct GNUNET_PeerIdentity),
//                      NULL);

  return t;
}


/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
static void
tunnel_add_connection (struct MeshTunnel2 *t, struct MeshConnection *c)
{
  c->t = t;
  GNUNET_CONTAINER_DLL_insert_tail (t->connection_head, t->connection_tail, c);
}


/**
 * Initialize a Flow Control structure to the initial state.
 * 
 * @param fc Flow Control structure to initialize.
 */
static void
fc_init (struct MeshFlowControl *fc)
{
  fc->next_pid = 0;
  fc->last_pid_sent = (uint32_t) -1; /* Next (expected) = 0 */
  fc->last_pid_recv = (uint32_t) -1;
  fc->last_ack_sent = (uint32_t) 0;
  fc->last_ack_recv = (uint32_t) 0;
  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  fc->queue_n = 0;
  fc->queue_max = (max_msgs_queue / max_connections) + 1;
}


static struct MeshConnection *
connection_new (const struct GNUNET_HashCode *cid)
{
  struct MeshConnection *c;

  c = GNUNET_new (struct MeshConnection);
  c->id = *cid;
  GNUNET_CONTAINER_multihashmap_put (connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  fc_init (&c->fwd_fc);
  fc_init (&c->bck_fc);
  c->fwd_fc.c = c;
  c->bck_fc.c = c;

  return c;
}


/**
 * Find a connection.
 *
 * @param cid Connection ID.
 */
static struct MeshConnection *
connection_get (const struct GNUNET_HashCode *cid)
{
  return GNUNET_CONTAINER_multihashmap_get (connections, cid);
}


static void
connection_destroy (struct MeshConnection *c)
{
  struct MeshPeer *peer;

  if (NULL == c)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying connection %s[%X]\n",
              peer2s (c->t->peer),
              c->id);

  /* Cancel all traffic */
  connection_cancel_queues (c, GNUNET_YES);
  connection_cancel_queues (c, GNUNET_NO);

  /* Cancel maintainance task (keepalive/timeout) */
  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);

  /* Deregister from neighbors */
  peer = connection_get_next_hop (c);
  if (NULL != peer)
    GNUNET_CONTAINER_multihashmap_remove (peer->connections, &c->id, c);
  peer = connection_get_prev_hop (c);
  if (NULL != peer)
    GNUNET_CONTAINER_multihashmap_remove (peer->connections, &c->id, c);

  /* Delete */
  GNUNET_STATISTICS_update (stats, "# connections", -1, GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (c->t->connection_head, c->t->connection_tail, c);
  GNUNET_free (c);
}


static void
tunnel_destroy (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;
  struct MeshConnection *next;

  if (NULL == t)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s\n",
              peer2s (t->peer));

//   if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &t->id, t))
//     GNUNET_break (0);

  for (c = t->connection_head; NULL != c; c = next)
  {
    next = c->next;
    connection_destroy (c);
  }

  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);

  GNUNET_free (t);
}


/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy. 
 */
static void
tunnel_destroy_empty (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;

  for (c = t->connection_head; NULL != c; c = c->next)
  {
    if (GNUNET_NO == c->destroy)
      connection_send_destroy (c);
  }

  if (0 == t->pending_messages)
    tunnel_destroy (t);
  else
    t->destroy = GNUNET_YES;
}


/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
static void
tunnel_destroy_if_empty (struct MeshTunnel2 *t)
{
  if (NULL != t->channel_head)
    return;

  tunnel_destroy_empty (t);
}


/**
 * Destroy a channel and free all resources.
 * 
 * @param ch Channel to destroy.
 */
static void
channel_destroy (struct MeshChannel *ch)
{
  struct MeshClient *c;

  if (NULL == ch)
    return;

  c = ch->root;
  if (NULL != c)
  {
    if (GNUNET_YES != GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                              ch->lid_root, ch))
    {
      GNUNET_break (0);
    }
  }

  c = ch->dest;
  if (NULL != c)
  {
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                ch->lid_dest, ch))
    {
      GNUNET_break (0);
    }
  }

  channel_rel_free_all (ch->root_rel);
  channel_rel_free_all (ch->dest_rel);

  GNUNET_CONTAINER_DLL_remove (ch->t->channel_head, ch->t->channel_tail, ch);
  GNUNET_STATISTICS_update (stats, "# channels", -1, GNUNET_NO);

  GNUNET_free (ch);
}

/**
 * Create a new channel.
 *
 * @param t Tunnel this channel is in.
 * @param owner Client that owns the channel, NULL for foreign channels.
 * @param lid_root Local ID for root client.
 *
 * @return A new initialized channel. NULL on error.
 */
static struct MeshChannel *
channel_new (struct MeshTunnel2 *t,
             struct MeshClient *owner, MESH_ChannelNumber lid_root)
{
  struct MeshChannel *ch;

  ch = GNUNET_new (struct MeshChannel);
  ch->root = owner;
  ch->lid_root = lid_root;
  ch->t = t;

  GNUNET_CONTAINER_DLL_insert (t->channel_head, t->channel_tail, ch);

  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);

  if (NULL != owner)
  {
    while (NULL != channel_get (t, t->next_chid))
      t->next_chid = (t->next_chid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
    ch->gid = t->next_chid;
    t->next_chid = (t->next_chid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;

    if(GNUNET_OK !=
       GNUNET_CONTAINER_multihashmap32_put (owner->own_channels, lid_root, ch,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break (0);
      channel_destroy (ch);
      GNUNET_SERVER_receive_done (owner->handle, GNUNET_SYSERR);
      return NULL;
    }
  }

  return ch;
}


/**
 * Set options in a channel, extracted from a bit flag field
 * 
 * @param ch Channel to set options to.
 * @param options Bit array in host byte order.
 */
static void
channel_set_options (struct MeshChannel *ch, uint32_t options)
{
  ch->nobuffer = (options & GNUNET_MESH_OPTION_NOBUFFER) != 0 ?
                 GNUNET_YES : GNUNET_NO;
  ch->reliable = (options & GNUNET_MESH_OPTION_RELIABLE) != 0 ?
                 GNUNET_YES : GNUNET_NO;
}


/**
 * Iterator for deleting each channel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local channel id (used to access the hashmap).
 * @param value The value stored at the key (channel to destroy).
 *
 * @return GNUNET_OK, keep iterating.
 */
static int
channel_destroy_iterator (void *cls,
                          uint32_t key,
                          void *value)
{
  struct MeshChannel *ch = value;
  struct MeshClient *c = cls;
  struct MeshTunnel2 *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " Channel %X (%X / %X) destroy, due to client %u shutdown.\n",
              ch->gid, ch->lid_root, ch->lid_dest, c->id);

  if (c == ch->dest)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is destination.\n", c->id);
    ch->dest = NULL;
  }
  if (c == ch->root)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is owner.\n", c->id);
    ch->root = NULL;
  }

  t = ch->t;
  channel_send_destroy (ch);
  channel_destroy (ch);
  tunnel_destroy_if_empty (t);

  return GNUNET_OK;
}


/**
 * Remove client's ports from the global hashmap on disconnect.
 *
 * @param cls Closure (unused).
 * @param key Port.
 * @param value Client structure.
 *
 * @return GNUNET_OK, keep iterating.
 */
static int
client_release_ports (void *cls,
                      uint32_t key,
                      void *value)
{
  int res;

  res = GNUNET_CONTAINER_multihashmap32_remove (ports, key, value);
  if (GNUNET_YES != res)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Port %u by client %p was not registered.\n",
                key, value);
  }
  return GNUNET_OK;
}


/**
 * Timeout function due to lack of keepalive/traffic from the owner.
 * Destroys connection if called.
 *
 * @param cls Closure (connection to destroy).
 * @param tc TaskContext.
 */
static void
connection_fwd_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->fwd_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              peer2s (c->t->peer),
              c->id);

  if (connection_is_origin (c, GNUNET_YES)) /* If local, leave. */
    return;

  connection_destroy (c);
}


/**
 * Timeout function due to lack of keepalive/traffic from the destination.
 * Destroys connection if called.
 *
 * @param cls Closure (connection to destroy).
 * @param tc TaskContext
 */
static void
connection_bck_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->bck_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              peer2s (c->t->peer),
              c->id);

  if (connection_is_origin (c, GNUNET_NO)) /* If local, leave. */
    return;

  connection_destroy (c);
}


/**
 * Resets the connection timeout task, some other message has done the
 * task's job.
 * - For the first peer on the direction this means to send
 *   a keepalive or a path confirmation message (either create or ACK).
 * - For all other peers, this means to destroy the connection,
 *   due to lack of activity.
 * Starts the tiemout if no timeout was running (connection just created).
 *
 * @param c Connection whose timeout to reset.
 * @param fwd Is this forward?
 *
 * TODO use heap to improve efficiency of scheduler.
 */
static void
connection_reset_timeout (struct MeshConnection *c, int fwd)
{
  GNUNET_SCHEDULER_TaskIdentifier *ti;
  GNUNET_SCHEDULER_Task f;

  ti = fwd ? &c->fwd_maintenance_task : &c->bck_maintenance_task;

  if (GNUNET_SCHEDULER_NO_TASK != *ti)
    GNUNET_SCHEDULER_cancel (*ti);

  if (connection_is_origin (c, fwd)) /* Endpoint */
  {
    f  = fwd ? &connection_fwd_keepalive : &connection_bck_keepalive;
    *ti = GNUNET_SCHEDULER_add_delayed (refresh_connection_time, f, c);
  }
  else /* Relay */
  {
    struct GNUNET_TIME_Relative delay;

    delay = GNUNET_TIME_relative_multiply (refresh_connection_time, 4);
    f  = fwd ? &connection_fwd_timeout : &connection_bck_timeout;
    *ti = GNUNET_SCHEDULER_add_delayed (delay, f, c);
  }
}


/**
 * Iterator to notify all connections of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param cls Closure (peer disconnected).
 * @param key Current key code (tid).
 * @param value Value in the hash map (connection).
 *
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
connection_broken (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct MeshPeer *peer = cls;
  struct MeshConnection *c = value;
  struct GNUNET_MESH_ConnectionBroken msg;
  int fwd;

  fwd = peer == connection_get_prev_hop (c);
  connection_cancel_queues (c, !fwd);

  msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectionBroken));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN);
  msg.cid = c->id;
  msg.peer1 = my_full_id;
  msg.peer2 = *GNUNET_PEER_resolve2 (peer->id);
  send_prebuilt_message_connection (&msg.header, c, NULL, fwd);
  c->destroy = GNUNET_YES;

  return GNUNET_YES;
}

/******************************************************************************/
/****************      MESH NETWORK HANDLER HELPERS     ***********************/
/******************************************************************************/

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
  struct MeshPeer *peer;
  struct MeshFlowControl *fc;
  int fwd;

  fwd = queue->fwd;
  peer = queue->peer;
  GNUNET_assert (NULL != queue->c);
  fc = fwd ? &queue->c->fwd_fc : &queue->c->bck_fc;

  if (GNUNET_YES == clear_cls)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   queue destroy type %s\n",
                GNUNET_MESH_DEBUG_M2S (queue->type));
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
      case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "destroying a DESTROY message\n");
        GNUNET_break (GNUNET_YES == queue->c->destroy);
        /* fall through */
      case GNUNET_MESSAGE_TYPE_MESH_FWD:
      case GNUNET_MESSAGE_TYPE_MESH_BCK:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   prebuilt message\n");;
        GNUNET_free_non_null (queue->cls);
        break;

      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "   type %s unknown!\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
    }

  }
  GNUNET_CONTAINER_DLL_remove (peer->queue_head, peer->queue_tail, queue);

  if (queue->type != GNUNET_MESSAGE_TYPE_MESH_ACK &&
      queue->type != GNUNET_MESSAGE_TYPE_MESH_POLL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Q_N- %p %u, \n", fc, fc->queue_n);
    fc->queue_n--;
    peer->queue_n--;
  }
  if (NULL != queue->c)
  {
    queue->c->pending_messages--;
    if (NULL != queue->c->t)
    {
      queue->c->t->pending_messages--;
    }
  }

  GNUNET_free (queue);
}


static size_t
queue_send (void *cls, size_t size, void *buf)
{
  struct MeshPeer *peer = cls;
  struct MeshFlowControl *fc;
  struct MeshConnection *c;
  struct GNUNET_MessageHeader *msg;
  struct MeshPeerQueue *queue;
  struct MeshTunnel2 *t;
  struct MeshChannel *ch;
  const struct GNUNET_PeerIdentity *dst_id;
  size_t data_size;
  uint32_t pid;
  uint16_t type;
  int fwd;

  peer->core_transmit = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Queue send (max %u)\n", size);

  if (NULL == buf || 0 == size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Buffer size 0.\n");
    return 0;
  }

  /* Initialize */
  queue = peer_get_first_message (peer);
  if (NULL == queue)
  {
    GNUNET_break (0); /* Core tmt_rdy should've been canceled */
    return 0;
  }
  c = queue->c;
  fwd = queue->fwd;
  fc = fwd ? &c->fwd_fc : &c->bck_fc;


  dst_id = GNUNET_PEER_resolve2 (peer->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   towards %s\n", GNUNET_i2s (dst_id));
  /* Check if buffer size is enough for the message */
  if (queue->size > size)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   not enough room, reissue\n");
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO,
                                             0,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             dst_id,
                                             queue->size,
                                             &queue_send,
                                             peer);
      return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   size %u ok\n", queue->size);

  t = (NULL != c) ? c->t : NULL;
  type = 0;

  /* Fill buf */
  switch (queue->type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN:
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   raw: %s\n",
                  GNUNET_MESH_DEBUG_M2S (queue->type));
      data_size = send_core_data_raw (queue->cls, size, buf);
      msg = (struct GNUNET_MessageHeader *) buf;
      type = ntohs (msg->type);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path create\n");
      if (connection_is_origin (c, GNUNET_YES))
        data_size = send_core_connection_create (queue->c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path ack\n");
      if (connection_is_origin (c, GNUNET_NO))
        data_size = send_core_connection_ack (queue->c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      /* This should be encapsulted */
      GNUNET_break (0);
      break;
    default:
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "*   type unknown: %u\n",
                  queue->type);
      data_size = 0;
  }

  if (0 < drop_percent &&
      GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Dropping message of type %s\n",
                GNUNET_MESH_DEBUG_M2S (queue->type));
    data_size = 0;
  }

  /* Free queue, but cls was freed by send_core_* */
  ch = queue->ch;
  queue_destroy (queue, GNUNET_NO);

  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      pid = ntohl ( ((struct GNUNET_MESH_Encrypted *) buf)->pid );
      fc->last_pid_sent = pid;
      send_ack (c, ch, fwd);
      break;
    default:
      break;
  }

  /* If more data in queue, send next */
  queue = peer_get_first_message (peer);
  if (NULL != queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   more data!\n");
    if (NULL == peer->core_transmit) {
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready(core_handle,
                                            0,
                                            0,
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            dst_id,
                                            queue->size,
                                            &queue_send,
                                            peer);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   tmt rdy called somewhere else\n");
    }
    if (GNUNET_SCHEDULER_NO_TASK == fc->poll_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   starting poll timeout\n");
      fc->poll_task =
          GNUNET_SCHEDULER_add_delayed (fc->poll_time, &connection_poll, fc);
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
  if (NULL != c)
  {
    c->pending_messages--;
    if (GNUNET_YES == c->destroy && 0 == c->pending_messages)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying connection!\n");
      connection_destroy (c);
    }
  }

  if (NULL != t)
  {
    t->pending_messages--;
    if (GNUNET_YES == t->destroy && 0 == t->pending_messages)
    {
//       GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying tunnel!\n");
      tunnel_destroy (t);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  Return %d\n", data_size);
  return data_size;
}


static void
queue_add (void *cls, uint16_t type, size_t size,
           struct MeshConnection *c,
           struct MeshChannel *ch,
           int fwd)
{
  struct MeshPeerQueue *queue;
  struct MeshFlowControl *fc;
  struct MeshPeer *peer;
  int priority;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "queue add %s %s (%u) on c %p, ch %p\n",
              fwd ? "FWD" : "BCK",  GNUNET_MESH_DEBUG_M2S (type), size, c, ch);
  GNUNET_assert (NULL != c);

  fc   = fwd ? &c->fwd_fc : &c->bck_fc;
  peer = fwd ? connection_get_next_hop (c) : connection_get_prev_hop (c);

  if (NULL == fc)
  {
    GNUNET_break (0);
    return;
  }

  priority = 0;

  if (GNUNET_MESSAGE_TYPE_MESH_POLL == type ||
      GNUNET_MESSAGE_TYPE_MESH_ACK == type)
  {
    priority = 100;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "priority %d\n", priority);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "fc %p\n", fc);
  if (fc->queue_n >= fc->queue_max && 0 == priority)
  {
    GNUNET_STATISTICS_update (stats, "# messages dropped (buffer full)",
                              1, GNUNET_NO);
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "queue full: %u/%u\n",
                fc->queue_n, fc->queue_max);
    return; /* Drop this message */
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pid %u\n", fc->last_pid_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ack %u\n", fc->last_ack_recv);
  if (GMC_is_pid_bigger (fc->last_pid_sent + 1, fc->last_ack_recv) &&
      GNUNET_SCHEDULER_NO_TASK == fc->poll_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "no buffer space (%u > %u): starting poll\n",
                fc->last_pid_sent + 1, fc->last_ack_recv);
    fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                  &connection_poll,
                                                  fc);
  }
  queue = GNUNET_malloc (sizeof (struct MeshPeerQueue));
  queue->cls = cls;
  queue->type = type;
  queue->size = size;
  queue->peer = peer;
  queue->c = c;
  queue->ch = ch;
  queue->fwd = fwd;
  if (100 <= priority)
  {
    GNUNET_CONTAINER_DLL_insert (peer->queue_head, peer->queue_tail, queue);
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (peer->queue_head, peer->queue_tail, queue);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Q_N+ %p %u, \n", fc, fc->queue_n);
    fc->queue_n++;
    peer->queue_n++;
  }

  if (NULL == peer->core_transmit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "calling core tmt rdy towards %s for %u bytes\n",
                peer2s (peer), size);
    peer->core_transmit =
        GNUNET_CORE_notify_transmit_ready (core_handle,
                                           0,
                                           0,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_PEER_resolve2 (peer->id),
                                           size,
                                           &queue_send,
                                           peer);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "core tmt rdy towards %s already called\n",
                peer2s (peer));

  }
  c->pending_messages++;
  c->t->pending_messages++;
}


/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/


/**
 * Generic handler for mesh network payload traffic.
 *
 * @param t Tunnel on which we got this message.
 * @param message Unencryted data message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return channel which this message was on.
 */
static struct MeshChannel *
handle_data (struct MeshTunnel2 *t, const struct GNUNET_MESH_Data *msg, int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshChannel *ch;
  struct MeshClient *c;
  uint32_t mid;
  uint16_t type;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_MESH_Data) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return NULL;
  }
  type = ntohs (msg->header.type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a %s message\n",
              GNUNET_MESH_DEBUG_M2S (type));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " payload of type %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (msg[1].header.type)));

  /* Check channel */
  ch = channel_get (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# data on unknown channel", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel unknown\n");
    return NULL;
  }

  /*  Initialize FWD/BCK data */
  c        = fwd ? ch->dest     : ch->root;
  rel      = fwd ? ch->dest_rel : ch->root_rel;

  if (NULL == c)
  {
    GNUNET_break (0);
    return NULL;
  }

  tunnel_change_state (t, MESH_TUNNEL_READY);

  GNUNET_STATISTICS_update (stats, "# data received", 1, GNUNET_NO);

  mid = ntohl (msg->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " mid %u\n", mid);

  if (GNUNET_NO == ch->reliable ||
      ( !GMC_is_pid_bigger (rel->mid_recv, mid) &&
        GMC_is_pid_bigger (rel->mid_recv + 64, mid) ) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! RECV %u\n", mid);
    if (GNUNET_YES == ch->reliable)
    {
      /* Is this the exact next expected messasge? */
      if (mid == rel->mid_recv)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "as expected\n");
        rel->mid_recv++;
        channel_send_client_data (ch, msg, fwd);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "save for later\n");
        channel_rel_add_buffered_data (msg, rel);
      }
    }
    else
    {
      /* Tunnel is unreliable: send to clients directly */
      /* FIXME: accept Out Of Order traffic */
      rel->mid_recv = mid + 1;
      channel_send_client_data (ch, msg, fwd);
    }
  }
  else
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " MID %u not expected (%u - %u), dropping!\n",
                mid, rel->mid_recv, rel->mid_recv + 64);
  }

  channel_send_data_ack (ch, fwd);
  return ch;
}

/**
 * Handler for mesh network traffic end-to-end ACKs.
 *
 * @param t Tunnel on which we got this message.
 * @param message Data message.
 * @param fwd Is this a fwd ACK? (dest->orig)
 *
 * @return channel this message was on.
 */
static struct MeshChannel *
handle_data_ack (struct MeshTunnel2 *t,
                 const struct GNUNET_MESH_DataACK *msg, int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;
  struct MeshChannel *ch;
  uint32_t ack;
  uint16_t type;
  int work;

  type = ntohs (msg->header.type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a %s message!\n",
              GNUNET_MESH_DEBUG_M2S (type));
  ch = channel_get (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# ack on unknown channel", 1, GNUNET_NO);
    return NULL;
  }
  ack = ntohl (msg->mid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! %s ACK %u\n",
              (GNUNET_YES == fwd) ? "FWD" : "BCK", ack);

  if (GNUNET_YES == fwd)
  {
    rel = ch->root_rel;
  }
  else
  {
    rel = ch->dest_rel;
  }
  if (NULL == rel)
  {
    GNUNET_break (0);
    return NULL;
  }

  for (work = GNUNET_NO, copy = rel->head_sent; copy != NULL; copy = next)
  {
    if (GMC_is_pid_bigger (copy->mid, ack))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  head %u, out!\n", copy->mid);
      channel_rel_free_sent (rel, msg);
      break;
    }
    work = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!!  id %u\n", copy->mid);
    next = copy->next;
    rel_message_free (copy);
  }
  /* ACK client if needed */
//   channel_send_ack (t, type, GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK == type);

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
                                          &channel_retransmit_message,
                                          rel);
      }
    }
    else
      GNUNET_break (0);
  }
  return ch;
}


/**
 * Core handler for connection creation.
 *
 * @param cls Closure (unused).
 * @param peer Sender (neighbor).
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_connection_create (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *id;
  struct GNUNET_HashCode *cid;
  struct MeshPeerPath *path;
  struct MeshPeer *dest_peer;
  struct MeshPeer *orig_peer;
  struct MeshConnection *c;
  unsigned int own_pos;
  uint16_t size;
  uint16_t i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received a connection create msg\n");

  /* Check size */
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ConnectionCreate))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Calculate hops */
  size -= sizeof (struct GNUNET_MESH_ConnectionCreate);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  size /= sizeof (struct GNUNET_PeerIdentity);
  if (1 > size)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    path has %u hops.\n", size);

  /* Get parameters */
  msg = (struct GNUNET_MESH_ConnectionCreate *) message;
  cid = &msg->cid;
  id = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    connection %s (%s).\n",
              GNUNET_h2s (cid), GNUNET_i2s (id));

  /* Create connection */
  c = connection_get (cid);
  if (NULL == c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating connection\n");
    c = connection_new (cid);
    if (NULL == c)
      return GNUNET_OK;
  }
  connection_reset_timeout (c, GNUNET_YES);
  tunnel_change_state (c->t,  MESH_TUNNEL_WAITING);

  /* Remember peers */
  dest_peer = peer_get (&id[size - 1]);
  orig_peer = peer_get (&id[0]);

  /* Create path */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
  path = path_new (size);
  own_pos = 0;
  for (i = 0; i < size; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ... adding %s\n",
                GNUNET_i2s (&id[i]));
    path->peers[i] = GNUNET_PEER_intern (&id[i]);
    if (path->peers[i] == myid)
      own_pos = i;
  }
  if (own_pos == 0 && path->peers[own_pos] != myid)
  {
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    connection_destroy (c);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Own position: %u\n", own_pos);
  path_add_to_peers (path, GNUNET_NO);
  c->path = path_duplicate (path);
  c->own_pos = own_pos;

  /* Is it a connection to us? */
  if (own_pos == size - 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    peer_add_path_to_origin (orig_peer, path, GNUNET_YES);

    if (NULL == orig_peer->tunnel)
      orig_peer->tunnel = tunnel_new ();
    tunnel_add_connection (orig_peer->tunnel, c);

    send_connection_ack (c, GNUNET_NO);

    /* Keep tunnel alive in direction dest->owner*/
    connection_reset_timeout (c, GNUNET_NO); 
  }
  else
  {
    /* It's for somebody else! Retransmit. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    peer_add_path (dest_peer, path_duplicate (path), GNUNET_NO);
    peer_add_path_to_origin (orig_peer, path, GNUNET_NO);
    send_prebuilt_message_connection (message, c, NULL, GNUNET_YES);
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
handle_mesh_connection_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionACK *msg;
  struct MeshPeerPath *p;
  struct MeshConnection *c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received a connection ACK msg\n");
  msg = (struct GNUNET_MESH_ConnectionACK *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on connection %s\n",
              GNUNET_h2s (&msg->cid));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# control on unknown connection",
                              1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  don't know the connection!\n");
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n",
              GNUNET_i2s (peer));

  /* Add path to peers? */
  p = c->path;
  if (NULL != p)
  {
    path_add_to_peers (p, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }
  connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, GNUNET_NO);
  if (MESH_TUNNEL_READY != c->t->state)
    tunnel_change_state (c->t, MESH_TUNNEL_READY);
  tunnel_send_queued_data (c->t, GNUNET_YES);

  /* Message for us? */
  if (connection_is_terminal (c, GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Connection ACK for us!\n");
    if (3 <= tunnel_count_connections (c->t) && NULL != c->t->peer->dhtget)
    {
      GNUNET_DHT_get_stop (c->t->peer->dhtget);
      c->t->peer->dhtget = NULL;
    }
    //connection_send_ack (c, GNUNET_NO); /* FIXME */
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  send_prebuilt_message_connection (message, c, NULL, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken paths
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_connection_broken (void *cls, const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionBroken *msg;
  struct MeshConnection *c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received a CONNECTION BROKEN msg from %s\n", GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_ConnectionBroken *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer1));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer2));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  tunnel_notify_connection_broken (c->t, GNUNET_PEER_search (&msg->peer1),
                                   GNUNET_PEER_search (&msg->peer2));
  return GNUNET_OK;

}


/**
 * Core handler for tunnel destruction
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_connection_destroy (void *cls,
                                const struct GNUNET_PeerIdentity *peer,
                                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionDestroy *msg;
  struct MeshConnection *c;
  GNUNET_PEER_Id id;
  int fwd;

  msg = (struct GNUNET_MESH_ConnectionDestroy *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a CONNECTION DESTROY message from %s\n",
              GNUNET_i2s (peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  for connection %s\n",
              GNUNET_h2s (&msg->cid));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    /* Probably already got the message from another path,
     * destroyed the tunnel and retransmitted to children.
     * Safe to ignore.
     */
    GNUNET_STATISTICS_update (stats, "# control on unknown tunnel",
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  id = GNUNET_PEER_search (peer);
  if (id == connection_get_prev_hop (c)->id)
    fwd = GNUNET_YES;
  else if (id == connection_get_next_hop (c)->id)
    fwd = GNUNET_NO;
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  send_prebuilt_message_connection (message, c, NULL, fwd);
  c->destroy = GNUNET_YES;

  return GNUNET_OK;
}


/**
 * Handler for channel create messages.
 *
 * @param t Tunnel this channel is to be created in.
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return channel this message was on.
 */
static struct MeshChannel *
handle_channel_create (struct MeshTunnel2 *t,
                       struct GNUNET_MESH_ChannelCreate *msg,
                       int fwd)
{
  MESH_ChannelNumber chid;
  struct MeshChannel *ch;
  struct MeshClient *c;
  uint32_t port;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received Channel Create\n");
  /* Check message size */
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_MESH_ChannelCreate))
  {
    GNUNET_break_op (0);
    return NULL;
  }

  /* Check if channel exists */
  chid = ntohl (msg->chid);
  ch = channel_get (t, chid);
  if (NULL != ch)
  {
    /* Probably a retransmission, safe to ignore */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   already exists...\n");
    if (NULL != ch->dest)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   duplicate CC!!\n");
      channel_send_ack (ch, !fwd);
      return NULL;
    }
  }
  else
  {
    /* Create channel */
    ch = channel_new (t, NULL, 0);
    channel_set_options (ch, ntohl (msg->opt));
  }

  /* Find a destination client */
  port = ntohl (msg->port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   port %u\n", port);
  c = GNUNET_CONTAINER_multihashmap32_get (ports, port);
  if (NULL == c)
  {
    /* TODO send reject */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  no client has port registered\n");
    /* TODO free ch */
    return NULL;
  }

  channel_add_client (ch, c);
  if (GNUNET_YES == ch->reliable)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! Reliable\n");

  send_local_channel_create (ch);
  channel_send_ack (ch, !fwd);

  return ch;
}


/**
 * Handler for channel ack messages.
 *
 * @param t Tunnel this channel is to be created in.
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return channel this message was on.
 */
static struct MeshChannel *
handle_channel_ack (struct MeshTunnel2 *t,
                    struct GNUNET_MESH_ChannelManage *msg,
                    int fwd)
{
  MESH_ChannelNumber chid;
  struct MeshChannel *ch;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received Channel ACK\n");
  /* Check message size */
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_MESH_ChannelManage))
  {
    GNUNET_break_op (0);
    return NULL;
  }

  /* Check if channel exists */
  chid = ntohl (msg->chid);
  ch = channel_get (t, chid);
  if (NULL == ch)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   channel %u unknown!!\n", chid);
    return NULL;
  }

  channel_confirm (ch, !fwd);
  return ch;
}


/**
 * Handler for channel destroy messages.
 *
 * @param t Tunnel this channel is to be destroyed of.
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return channel this message was on.
 */
static struct MeshChannel *
handle_channel_destroy (struct MeshTunnel2 *t,
                        struct GNUNET_MESH_ChannelManage *msg,
                        int fwd)
{
  MESH_ChannelNumber chid;
  struct MeshChannel *ch;

  /* Check message size */
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_MESH_ChannelManage))
  {
    GNUNET_break_op (0);
    return NULL;
  }

  /* Check if channel exists */
  chid = ntohl (msg->chid);
  ch = channel_get (t, chid);
  if (NULL == ch)
  {
    /* Probably a retransmission, safe to ignore */
    return NULL;
  }

  send_local_channel_destroy (ch, fwd);
  channel_destroy (ch);

  return ch;
}


/**
 * Generic handler for mesh network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param message Encrypted message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_encrypted (const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MESH_Encrypted *msg,
                       int fwd)
{
  struct MeshConnection *c;
  struct MeshTunnel2 *t;
  struct MeshPeer *neighbor;
  struct MeshFlowControl *fc;
  uint32_t pid;
  uint32_t ttl;
  uint16_t type;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_MESH_Encrypted) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  type = ntohs (msg->header.type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a %s message from %s\n",
              GNUNET_MESH_DEBUG_M2S (type), GNUNET_i2s (peer));

  /* Check connection */
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# unknown connection", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "WARNING connection unknown\n");
    return GNUNET_OK;
  }
  t = c->t;
  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  /* Check if origin is as expected */
  neighbor = connection_get_hop (c, fwd);
  if (peer_get (peer)->id != neighbor->id)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Check PID */
  pid = ntohl (msg->pid);
  if (GMC_is_pid_bigger (pid, fc->last_ack_sent))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited message", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "WARNING Received PID %u, (prev %u), ACK %u\n",
                pid, fc->last_pid_recv, fc->last_ack_sent);
    return GNUNET_OK;
  }
  if (GNUNET_NO == GMC_is_pid_bigger (pid, fc->last_pid_recv))
  {
    GNUNET_STATISTICS_update (stats, "# duplicate PID", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " Pid %u not expected (%u+), dropping!\n",
                pid, fc->last_pid_recv + 1);
    return GNUNET_OK;
  }
  if (MESH_CONNECTION_SENT == c->state)
    connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);
  fc->last_pid_recv = pid;

  /* Is this message for us? */
  if (connection_is_terminal (c, fwd))
  {
    size_t dsize = size - sizeof (struct GNUNET_MESH_Encrypted);
    char cbuf[dsize];
    struct GNUNET_MessageHeader *msgh;
    struct MeshChannel *ch;

    /* TODO signature verification */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  message for us!\n");
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);

    fc->last_pid_recv = pid;
    tunnel_decrypt (t, cbuf, &msg[1], dsize, msg->iv, fwd);
    msgh = (struct GNUNET_MessageHeader *) cbuf;
    switch (ntohs (msgh->type))
    {
      case GNUNET_MESSAGE_TYPE_MESH_DATA:
        /* Don't send hop ACK, wait for client to ACK */
        ch = handle_data (t, (struct GNUNET_MESH_Data *) msgh, fwd);
        break;

      case GNUNET_MESSAGE_TYPE_MESH_DATA_ACK:
        ch = handle_data_ack (t, (struct GNUNET_MESH_DataACK *) msgh, fwd);
        break;

      case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
        ch = handle_channel_create (t,
                                    (struct GNUNET_MESH_ChannelCreate *) msgh,
                                    fwd);
        break;

      case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
        ch = handle_channel_ack (t,
                                 (struct GNUNET_MESH_ChannelManage *) msgh,
                                 fwd);
        break;

      case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
        ch = handle_channel_destroy (t,
                                     (struct GNUNET_MESH_ChannelManage *) msgh,
                                     fwd);
        break;

      default:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "end-to-end message not known (%u)\n",
                    ntohs (msgh->type));
        ch = NULL;
    }

    send_ack (c, ch, fwd);
    return GNUNET_OK;
  }

  /* Message not for us: forward to next hop */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  ttl = ntohl (msg->ttl);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ttl);
  if (ttl == 0)
  {
    GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    send_ack (c, NULL, fwd);
    return GNUNET_OK;
  }
  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);

  send_prebuilt_message_connection (&msg->header, c, NULL, fwd);

  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going orig->dest.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_fwd (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_encrypted (peer,
                                (struct GNUNET_MESH_Encrypted *)message,
                                GNUNET_YES);
}

/**
 * Core handler for mesh network traffic going dest->orig.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_bck (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_encrypted (peer,
                                (struct GNUNET_MESH_Encrypted *)message,
                                GNUNET_NO);
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
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got an ACK packet from %s!\n",
              GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_ACK *) message;

  c = connection_get (&msg->cid);

  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# ack on unknown connection", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  if (connection_get_next_hop (c)->id == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    fc = &c->fwd_fc;
  }
  else if (connection_get_prev_hop (c)->id == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    fc = &c->bck_fc;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  ack = ntohl (msg->ack);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ACK %u\n", ack);

  /* Cancel polling if the ACK is bigger than before. */
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task &&
      GMC_is_pid_bigger (ack, fc->last_ack_recv))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Cancel poll\n");
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  }

  fc->last_ack_recv = ack;
  connection_unlock_queue (c, fc == &c->fwd_fc);

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
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t pid;
  int fwd;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a POLL packet from %s!\n",
              GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_Poll *) message;

  c = connection_get (&msg->cid);

  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# poll on unknown connection", 1,
                              GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK?
   * Note: a poll should never be needed in a loopback case,
   * since there is no possiblility of packet loss there, so
   * this way of discerining FWD/BCK should not be a problem.
   */
  id = GNUNET_PEER_search (peer);
  if (connection_get_next_hop (c)->id == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    fc = &c->fwd_fc;
  }
  else if (connection_get_prev_hop (c)->id == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    fc = &c->bck_fc;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  pid = ntohl (msg->pid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  PID %u, OLD %u\n",
              pid, fc->last_pid_recv);
  fc->last_pid_recv = pid;
  fwd = fc == &c->fwd_fc;
  send_ack (c, NULL, fwd);

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
  struct GNUNET_MESH_ConnectionKeepAlive *msg;
  struct MeshConnection *c;
  struct MeshPeer *neighbor;
  int fwd;

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a keepalive packet from %s\n",
              GNUNET_i2s (peer));

  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# keepalive on unknown connection", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  fwd = GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE == ntohs (message->type) ? 
        GNUNET_YES : GNUNET_NO;

  /* Check if origin is as expected */
  neighbor = connection_get_hop (c, fwd);
  if (peer_get (peer)->id != neighbor->id)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);

  if (connection_is_terminal (c, fwd))
    return GNUNET_OK;

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  send_prebuilt_message_connection (message, c, NULL, fwd);

  return GNUNET_OK;
}



/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_connection_create, GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
    0},
  {&handle_mesh_connection_ack, GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
    sizeof (struct GNUNET_MESH_ConnectionACK)},
  {&handle_mesh_connection_broken, GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN,
    sizeof (struct GNUNET_MESH_ConnectionBroken)},
  {&handle_mesh_connection_destroy, GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY,
    sizeof (struct GNUNET_MESH_ConnectionDestroy)},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE,
    sizeof (struct GNUNET_MESH_ConnectionKeepAlive)},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_BCK_KEEPALIVE,
    sizeof (struct GNUNET_MESH_ConnectionKeepAlive)},
  {&handle_mesh_ack, GNUNET_MESSAGE_TYPE_MESH_ACK,
    sizeof (struct GNUNET_MESH_ACK)},
  {&handle_mesh_poll, GNUNET_MESSAGE_TYPE_MESH_POLL,
    sizeof (struct GNUNET_MESH_Poll)},
  {&handle_mesh_fwd, GNUNET_MESSAGE_TYPE_MESH_FWD, 0},
  {&handle_mesh_bck, GNUNET_MESSAGE_TYPE_MESH_BCK, 0},
  {NULL, 0, 0}
};


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
  struct MeshPeer *peer = cls;
  struct MeshPeerPath *p;
  struct MeshConnection *c;
  struct GNUNET_PeerIdentity pi;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got results from DHT!\n");
  GNUNET_PEER_resolve (peer->id, &pi);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  for %s\n", GNUNET_i2s (&pi));

  p = path_build_from_dht (get_path, get_path_length,
                           put_path, put_path_length);
  path_add_to_peers (p, GNUNET_NO);
  path_destroy (p);

  /* Count connections */
  for (c = peer->tunnel->connection_head, i = 0; NULL != c; c = c->next, i++);

  /* If we already have 3 (or more (?!)) connections, it's enough */
  if (3 <= i)
    return;

  if (peer->tunnel->state == MESH_TUNNEL_SEARCHING)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ... connect!\n");
    peer_connect (peer);
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
  c->id = next_client_id++; /* overflow not important: just for debug */
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected: %p\n", client);
  if (client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   (SERVER DOWN)\n");
    return;
  }

  c = client_get (client);
  if (NULL != c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u, %p)\n",
                c->id, c);
    GNUNET_SERVER_client_drop (c->handle);
    c->shutting_down = GNUNET_YES;
    if (NULL != c->own_channels)
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->own_channels,
                                               &channel_destroy_iterator, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->own_channels);
    }

    if (NULL != c->incoming_channels)
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->incoming_channels,
                                               &channel_destroy_iterator, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->incoming_channels);
    }

    if (NULL != c->ports)
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->ports,
                                               &client_release_ports, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->ports);
    }
    GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
    GNUNET_STATISTICS_update (stats, "# clients", -1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  client free (%p)\n", c);
    GNUNET_free (c);
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

  c->own_channels = GNUNET_CONTAINER_multihashmap32_create (32);
  c->incoming_channels = GNUNET_CONTAINER_multihashmap32_create (32);
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
handle_local_channel_create (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ChannelMessage *msg;
  struct MeshPeer *peer;
  struct MeshTunnel2 *t;
  struct MeshChannel *ch;
  struct MeshClient *c;
  MESH_ChannelNumber chid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new channel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof (struct GNUNET_MESH_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_ChannelMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  towards %s:%u\n",
              GNUNET_i2s (&msg->peer), ntohl (msg->port));
  chid = ntohl (msg->channel_id);

  /* Sanity check for duplicate channel IDs */
  if (NULL != channel_get_by_local_id (c, chid))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  peer = peer_get (&msg->peer);
  if (NULL == peer->tunnel)
  {
    peer->tunnel = tunnel_new ();
    peer->tunnel->peer = peer;
  }
  t = peer->tunnel;

  /* Create channel */
  ch = channel_new (t, c, chid);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ch->port = ntohl (msg->port);
  channel_set_options (ch, ntohl (msg->opt));

  /* In unreliable channels, we'll use the DLL to buffer data for the root */
  ch->root_rel = GNUNET_new (struct MeshChannelReliability);
  ch->root_rel->ch = ch;
  ch->root_rel->expected_delay = MESH_RETRANSMIT_TIME;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATED CHANNEL %s[%x]:%u (%x)\n",
              peer2s (t->peer), ch->gid, ch->port, ch->lid_root);
  peer_connect (peer);

  /* Send create channel */
  {
    struct GNUNET_MESH_ChannelCreate msgcc;

    msgcc.header.size = htons (sizeof (msgcc));
    msgcc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE);
    msgcc.chid = htonl (ch->gid);
    msgcc.port = msg->port;
    msgcc.opt = msg->opt;

    tunnel_queue_data (t, ch, &msgcc.header, GNUNET_YES);
  }

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
handle_local_channel_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ChannelMessage *msg;
  struct MeshClient *c;
  struct MeshChannel *ch;
  struct MeshTunnel2 *t;
  MESH_ChannelNumber chid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a DESTROY CHANNEL from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_ChannelMessage *) message;

  /* Retrieve tunnel */
  chid = ntohl (msg->channel_id);
  ch = channel_get_by_local_id (c, chid);
  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  channel %X not found\n", chid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Cleanup after the tunnel */
  client_delete_channel (c, ch);
  if (c == ch->dest && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV <= chid)
  {
    ch->dest = NULL;
  }
  else if (c == ch->root && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV > chid)
  {
    ch->root = NULL;
  }
  else 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "  channel %X client %p (%p, %p)\n",
                chid, c, ch->root, ch->dest);
    GNUNET_break (0);
  }

  t = ch->t;
  channel_destroy (ch);
  tunnel_destroy_if_empty (t);

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
  struct GNUNET_MESH_LocalData *msg;
  struct MeshClient *c;
  struct MeshChannel *ch;
  struct MeshChannelReliability *rel;
  MESH_ChannelNumber chid;
  size_t size;
  int fwd;

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

  msg = (struct GNUNET_MESH_LocalData *) message;

  /* Sanity check for message size */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_LocalData);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Channel exists? */
  chid = ntohl (msg->id);
  fwd = chid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  ch = channel_get_by_local_id (c, chid);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Is the client in the channel? */
  if ( !( (fwd &&
           ch->root &&
           ch->root->handle == client)
         ||
          (!fwd &&
           ch->dest && 
           ch->dest->handle == client) ) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  rel = fwd ? ch->root_rel : ch->dest_rel;
  rel->client_ready = GNUNET_NO;

  /* Ok, everything is correct, send the message. */
  {
    struct GNUNET_MESH_Data *payload;
    uint16_t p2p_size = sizeof(struct GNUNET_MESH_Data) + size;
    unsigned char cbuf[p2p_size];

    payload = (struct GNUNET_MESH_Data *) cbuf;
    payload->mid = htonl (rel->mid_send);
    rel->mid_send++;
    memcpy (&payload[1], &msg[1], size);
    payload->header.size = htons (p2p_size);
    payload->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_DATA);
    payload->chid = htonl (ch->gid);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  sending on channel...\n");
    send_prebuilt_message_channel (&payload->header, ch, fwd);

    if (GNUNET_YES == ch->reliable)
      channel_save_copy (ch, &payload->header, fwd);
  }
  if (tunnel_get_buffer (ch->t, fwd) > 0)
    send_local_ack (ch, fwd);
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
  struct MeshChannelReliability *rel;
  struct MeshChannel *ch;
  struct MeshClient *c;
  MESH_ChannelNumber chid;
  int fwd;

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

  /* Channel exists? */
  chid = ntohl (msg->channel_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on channel %X\n", chid);
  ch = channel_get_by_local_id (c, chid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   -- ch %p\n", ch);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Channel %X unknown.\n", chid);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* If client is root, the ACK is going FWD, therefore this is "BCK". */
  /* If client is dest, the ACK is going BCK, therefore this is "FWD" */
  fwd = chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  rel = fwd ? ch->dest_rel : ch->root_rel;

  rel->client_ready = GNUNET_YES;
  channel_send_client_buffered_data (ch, c, fwd);
  send_ack (NULL, ch, fwd);

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
// static int
// monitor_all_tunnels_iterator (void *cls,
//                               const struct GNUNET_HashCode * key,
//                               void *value)
// {
//   struct GNUNET_SERVER_Client *client = cls;
//   struct MeshChannel *ch = value;
//   struct GNUNET_MESH_LocalMonitor *msg;
// 
//   msg = GNUNET_malloc (sizeof(struct GNUNET_MESH_LocalMonitor));
//   msg->channel_id = htonl (ch->gid);
//   msg->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
//   msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);
// 
//   GNUNET_log (GNUNET_ERROR_TYPE_INFO,
//               "*  sending info about tunnel %s\n",
//               GNUNET_i2s (&msg->owner));
// 
//   GNUNET_SERVER_notification_context_unicast (nc, client,
//                                               &msg->header, GNUNET_NO);
//   return GNUNET_YES;
// }


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
//   GNUNET_CONTAINER_multihashmap_iterate (tunnels,
//                                          monitor_all_tunnels_iterator,
//                                          client);
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
  struct MeshChannel *ch;

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
              ntohl (msg->channel_id));
//   ch = channel_get (&msg->owner, ntohl (msg->channel_id));
  ch = NULL; // FIXME
  if (NULL == ch)
  {
    /* We don't know the tunnel */
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
  {&handle_local_channel_create, NULL,
   GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE,
   sizeof (struct GNUNET_MESH_ChannelMessage)},
  {&handle_local_channel_destroy, NULL,
   GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY,
   sizeof (struct GNUNET_MESH_ChannelMessage)},
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
  struct MeshPeer *pi;
  struct MeshPeerPath *path;

  DEBUG_CONN ("Peer connected\n");
  DEBUG_CONN ("     %s\n", GNUNET_i2s (&my_full_id));
  pi = peer_get (peer);
  if (myid == pi->id)
  {
    DEBUG_CONN ("     (self)\n");
    path = path_new (1);
  }
  else
  {
    DEBUG_CONN ("     %s\n", GNUNET_i2s (peer));
    path = path_new (2);
    path->peers[1] = pi->id;
    GNUNET_PEER_change_rc (pi->id, 1);
    GNUNET_STATISTICS_update (stats, "# peers", 1, GNUNET_NO);
  }
  path->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  peer_add_path (pi, path, GNUNET_YES);

  pi->connections = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_YES);
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
  struct MeshPeer *pi;

  DEBUG_CONN ("Peer disconnected\n");
  pi = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pi)
  {
    GNUNET_break (0);
    return;
  }

  peer_remove_path (pi, myid, pi->id);

  GNUNET_CONTAINER_multihashmap_iterate (pi->connections,
                                         connection_broken,
                                         pi);
  GNUNET_CONTAINER_multihashmap_destroy (pi->connections);
  pi->connections = NULL;
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
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, 
           const struct GNUNET_PeerIdentity *identity)
{
  const struct GNUNET_CONFIGURATION_Handle *c = cls;
  static int i = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core init\n");
  if (0 != memcmp (identity, &my_full_id, sizeof (my_full_id)))
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
  struct MeshPeer *p = value;
  struct MeshTunnel2 *t = p->tunnel;

  if (NULL != t)
    tunnel_destroy (t);
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
  GNUNET_CONTAINER_multihashmap_iterate (peers, &shutdown_tunnel, NULL);
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
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "REFRESH_CONNECTION_TIME",
                                           &refresh_connection_time))
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
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_CONNECTIONS",
                                             &max_connections))
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

  connections = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_YES);
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
