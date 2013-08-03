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
   * Connection created, waiting for ACK.
   */
  MESH_CONNECTION_SENT,

  /**
   * Connection confirmed, ready to carry traffic..
   */
  MESH_CONNECTION_READY,
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
   * Peer
   */
  struct MeshPeer *peer;

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
   * How many messages do we accept in the queue.
   */
  unsigned int queue_max;

  /**
   * Handle for queued transmissions
   */
  struct GNUNET_CORE_TransmitHandle *core_transmit;

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
     * Handle to stop the DHT search for paths to this peer
     */
  struct GNUNET_DHT_GetHandle *dhtget;

    /**
     * Tunnel to this peer, if any.
     */
  struct MeshTunnel2 *tunnel;

    /**
     * Flow control information for direct traffic.
     */
  struct MeshFlowControl *fc;

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
     * Local tunnel number ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI or 0 )
     */
  MESH_ChannelNumber id;

    /**
     * Local tunnel number for local destination clients (incoming number)
     * ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV or 0). All clients share the same
     * number.
     */
  MESH_ChannelNumber id_dest;

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
  struct MeshClient *owner;

    /**
     * Client destination of the tunnel, if any.
     */
  struct MeshClient *client;

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
  struct MeshChannelReliability *fwd_rel;

    /**
     * Reliability data.
     * Only present (non-NULL) at the destination of a tunnel.
     */
  struct MeshChannelReliability *bck_rel;
};


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
   * Connection number.
   */
  uint32_t id;

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
 * Struct containing all information regarding a tunnel to a peer.
 */
struct MeshTunnel2
{
    /**
     * Endpoint of the tunnel.
     */
  struct MeshPeer *peer;

    /**
     * ID of the tunnel.
     */
  struct GNUNET_HashCode id;

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
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *my_eph;

  /**
   * Remote peer's public key.
   */
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *peers_eph;

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
   * Channel ID for the next created tunnel.
   */
  MESH_ChannelNumber next_chid;

  /**
   * Channel ID for the next incoming tunnel.
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
static struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded my_public_key;

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
 * Search for a channel by global ID using full PeerIdentities.
 *
 * @param oid owner of the tunnel.
 * @param tid global tunnel number.
 *
 * @return tunnel handler, NULL if doesn't exist.
 */
static struct MeshChannel *
channel_get (const struct GNUNET_PeerIdentity *oid, MESH_ChannelNumber tid);


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
 * @param dst Neighbor to send message to.
 * @param c Connection this message belongs to, if any.
 * @param ch Channel this message belongs to, if applicable (otherwise NULL).
 */
static void
queue_add (void *cls, uint16_t type, size_t size,
           struct MeshPeer *dst,
           struct MeshConnection *c,
           struct MeshChannel *ch);


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
queue_get_next (const struct MeshPeer *peer);


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
 * @param ch Channel which should be deleted.
 */
static void
client_delete_channel (struct MeshClient *c, struct MeshChannel *ch)
{
  int res;

  if (c == ch->owner)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                  ch->id, ch);
    if (GNUNET_YES != res)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client_delete_channel owner KO\n");
  }
  if (c == ch->client)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                  ch->id_dest, ch);
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

  if (NULL == ch->client)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
  msg.channel_id = htonl (ch->id_dest);
  msg.port = htonl (ch->port);
  msg.opt = 0;
  msg.opt |= GNUNET_YES == ch->reliable ? GNUNET_MESH_OPTION_RELIABLE : 0;
  msg.opt |= GNUNET_YES == ch->nobuffer ? GNUNET_MESH_OPTION_NOBUFFER : 0;
  msg.opt = htonl (msg.opt);
  GNUNET_PEER_resolve (t->peer->id, &msg.peer);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client->handle,
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

  c = fwd ? ch->client : ch->owner;
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.channel_id = htonl (fwd ? ch->id_dest : ch->id);
  msg.port = htonl (0);
  memset (&msg.peer, 0, sizeof (msg.peer));
  msg.opt = htonl (0);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Build a local ACK message and send it to a local client.
 * 
 * @param ch Channel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param is_fwd Set to GNUNET_YES for FWD ACK (dest->owner)
 */
static void
send_local_ack (struct MeshChannel *ch,
                struct MeshClient *c,
                int is_fwd)
{
  struct GNUNET_MESH_LocalAck msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.channel_id = htonl (is_fwd ? ch->id : ch->id_dest);
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
  struct MeshPeer *peer;
  unsigned int lowest_q;


  peer = NULL;
  best = NULL;
  lowest_q = UINT_MAX;
  for (c = t->connection_head; NULL != c; c = c->next)
  {
    if (MESH_CONNECTION_READY == c->state)
    {
      peer = fwd ? connection_get_next_hop (c) : connection_get_prev_hop (c);
      if (NULL == peer->fc)
      {
        GNUNET_break (0);
        continue;
      }
      if (peer->fc->queue_n < lowest_q)
      {
        best = c;
        lowest_q = peer->fc->queue_n;
      }
    }
  }
  return best;
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
  struct MeshPeer *neighbor;
  void *data;
  size_t size;
  uint16_t type;

  neighbor = fwd ? connection_get_next_hop (c) : connection_get_prev_hop (c);
  if (NULL == neighbor)
  {
    GNUNET_break (0);
    return;
  }

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs(message->type);

  if (GNUNET_MESSAGE_TYPE_MESH_FWD == type ||
      GNUNET_MESSAGE_TYPE_MESH_BCK == type)
  {
    struct GNUNET_MESH_Encrypted *msg;
    uint32_t ttl;

    msg = (struct GNUNET_MESH_Encrypted *) data;
    ttl = ntohl (msg->ttl);
    if (0 == ttl)
    {
      GNUNET_break_op (0);
      return;
    }
    msg->ttl = htonl (ttl - 1);
  }

  queue_add (data,
             type,
             size,
             neighbor,
             c,
             ch);
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

  c = tunnel_get_connection (t, fwd);
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  type = ntohs (msg->header.size);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      msg->cid = htonl (c->id);
      msg->tid = t->id;
      msg->ttl = default_ttl;
      break;
    default:
      GNUNET_break (0);
  }

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
  char *cbuf[size + sizeof (struct GNUNET_MESH_Encrypted)];
  uint16_t type;
  uint64_t iv;

  type = fwd ? GNUNET_MESSAGE_TYPE_MESH_FWD : GNUNET_MESSAGE_TYPE_MESH_BCK;
  iv = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);

  msg = (struct GNUNET_MESH_Encrypted *) cbuf;
  msg->header.type = htons (type);
  msg->header.size = htons (size);
  msg->iv = GNUNET_htonll (iv);
  tunnel_encrypt (ch->t, &msg[1], message, size, iv, fwd);

  send_prebuilt_message_tunnel (msg, ch->t, ch, fwd);
}


/**
 * Sends an already built message directly to a peer.
 * Message does must not belong to a connection or channel.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param peer Tunnel on which this message is transmitted.
 */
static void
send_prebuilt_message_peer (const struct GNUNET_MessageHeader *message,
                            struct MeshPeer *peer)
{
  void *data;
  size_t size;
  uint16_t type;

  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs(message->type);

  queue_add (data,
             type,
             size,
             peer,
             NULL,
             NULL);
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
  struct MeshPeer *neighbor;
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection create\n");
  neighbor = connection_get_next_hop (connection);
  queue_add (connection,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
             sizeof (struct GNUNET_MESH_ConnectionCreate) +
                (connection->path->length *
                 sizeof (struct GNUNET_PeerIdentity)),
             neighbor,
             connection,
             NULL);
  if (MESH_TUNNEL_SEARCHING == t->state)
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
  if (MESH_CONNECTION_NEW == connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
}


/**
 * Sends a CONNECTION ACK message in reponse to a received CONNECTION_CREATE
 * directed to us.
 *
 * @param connection Connection to confirm.
 */
static void
send_connection_ack (struct MeshConnection *connection) 
{
  struct MeshPeer *neighbor;
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection ack\n");
  neighbor = connection_get_prev_hop (connection);
  queue_add (connection,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
             sizeof (struct GNUNET_MESH_ConnectionACK),
             neighbor,
             connection,
             NULL);
  if (MESH_TUNNEL_NEW == t->state)
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
}


/**
 * Build an ACK message and queue it to send to the given peer.
 * 
 * @param peer Peer to whom send the ACK.
 * @param ack Value of the ACK.
 */
static void
send_ack (struct MeshPeer *peer, uint32_t ack)
{
  struct GNUNET_MESH_ACK msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.ack = htonl (ack);

  send_prebuilt_message_peer (&msg.header, peer);
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
 * Function to send a create path packet to a peer.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_create (void *cls, size_t size, void *buf)
{
  struct MeshConnection *c = cls;
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
  msg->cid = htonl (c->id);

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
 * @param cls closure (MeshTransmissionDescriptor)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_ack (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_ConnectionACK *msg = buf;
  struct MeshConnection *c = cls;
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
  GNUNET_CRYPTO_hash_xor (&GNUNET_PEER_resolve2 (t->peer->id)->hashPubKey,
                          &my_full_id.hashPubKey,
                          &msg->tid);
  msg->cid = htonl (c->id);

  /* TODO add signature */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CONNECTION ACK sent!\n");
  return sizeof (struct GNUNET_MESH_ConnectionACK);
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
peer_timeout (void *cls,
              const struct GNUNET_HashCode *key,
              void *value)
{
  return GNUNET_YES;
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
      GNUNET_CONTAINER_multihashmap_iterate (peers,
                                             &peer_timeout,
                                             NULL);
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
    if (NULL != p)
      continue; /* If path is in use in a connection, skip it. */

    if ((cost = peer_get_path_cost (peer, p)) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
  }
  return best_p;
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

  t = peer->tunnel;
  if (NULL != peer->path_head)
  {
    p = peer_get_best_path (peer);
    if (NULL != p)
    {
      c = tunnel_use_path (t, p);
      send_connection_create (c);
    }
  }
  else if (NULL == peer->dhtget)
  {
    const struct GNUNET_PeerIdentity *id;

    id = GNUNET_PEER_resolve2 (peer->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", GNUNET_i2s (id));
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
 * @brief Re-initiate traffic to this peer if necessary.
 *
 * Check if there is traffic queued towards this peer
 * and the core transmit handle is NULL (traffic was stalled).
 * If so, call core tmt rdy.
 *
 * @param peer_id Short ID of peer to which initiate traffic.
 */
static void
peer_unlock_queue (GNUNET_PEER_Id peer_id)
{
  struct MeshPeer *peer;
  struct MeshPeerQueue *q;
  size_t size;

  peer = peer_get_short (peer_id);
  if (NULL != peer->fc->core_transmit)
    return; /* Already unlocked */

  q = queue_get_next (peer);
  if (NULL == q)
    return; /* Nothing to transmit */

  size = q->size;
  peer->fc->core_transmit =
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
 * Cancel all transmissions towards a neighbor that belong to
 * a certain connection.
 *
 * @param peer Neighbor to whom cancel the transmissions.
 * @param c Connection which to cancel.
 */
static void
peer_cancel_queues (struct MeshPeer *peer, struct MeshConnection *c)
{
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *next;
  struct MeshFlowControl *fc;

  if (NULL == peer || NULL == peer->fc)
  {
    GNUNET_break (0);
    return;
  }
  fc = peer->fc;
  for (q = fc->queue_head; NULL != q; q = next)
  {
    next = q->next;
    if (q->c == c)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "peer_cancel_queue %s\n",
                  GNUNET_MESH_DEBUG_M2S (q->type));
      queue_destroy (q, GNUNET_YES);
    }
  }
  if (NULL == fc->queue_head)
  {
    if (NULL != fc->core_transmit)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (fc->core_transmit);
      fc->core_transmit = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    {
      GNUNET_SCHEDULER_cancel (fc->poll_task);
      fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
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
peer_add_path_to_origin (struct MeshPeer *peer_info,
                         struct MeshPeerPath *path, int trusted)
{
  path_invert (path);
  peer_add_path (peer_info, path, trusted);
}



/**
 * Function called if the connection to the peer has been stalled for a while,
 * possibly due to a missed ACK. Poll the peer about its ACK status.
 *
 * @param cls Closure (poll ctx).
 * @param tc TaskContext.
 */
static void
peer_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshFlowControl *fc = cls;
  struct GNUNET_MESH_Poll msg;
  struct MeshPeer *peer;

  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");
  peer = fc->peer;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** peer: %s!\n", 
                GNUNET_i2s (GNUNET_PEER_resolve2 (peer->id)));

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  msg.pid = htonl (fc->last_pid_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** pid (%u)!\n", fc->last_pid_sent);
  send_prebuilt_message_peer (&msg.header, peer);
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &peer_poll, fc);
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
 * Search for a tunnel by global ID using PEER_ID
 *
 * @param pi owner of the tunnel
 * @param tid global tunnel number
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshChannel *
channel_get_by_pi (GNUNET_PEER_Id pi, MESH_ChannelNumber tid)
{
//   struct GNUNET_HashCode hash;

//   return GNUNET_CONTAINER_multihashmap_get (tunnels, &hash); FIXME
  return NULL;
}


/**
 * Search for a tunnel by global ID using full PeerIdentities
 *
 * @param oid owner of the tunnel
 * @param tid global tunnel number
 *
 * @return tunnel handler, NULL if doesn't exist
 */
static struct MeshChannel *
channel_get (const struct GNUNET_PeerIdentity *oid, MESH_ChannelNumber tid)
{
  return channel_get_by_pi (GNUNET_PEER_search (oid), tid);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state was %s\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (t->peer->id)),
              GNUNET_MESH_DEBUG_TS2S (t->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state is now %s\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (t->peer->id)),
              GNUNET_MESH_DEBUG_TS2S (state));
  t->state = state;
}


static void
connection_change_state (struct MeshConnection* c,
                         enum MeshConnectionState state)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] state was %s\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)), c->id,
              GNUNET_MESH_DEBUG_CS2S (c->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] state is now %s\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)), c->id,
              GNUNET_MESH_DEBUG_CS2S (state));
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
  if (NULL != ch->client)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap32_put (c->incoming_channels,
                                           ch->id_dest, ch,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }
  ch->client = c;
}


static struct MeshConnection *
tunnel_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p)
{
  struct MeshConnection *c;
  unsigned int own_pos;

  c = GNUNET_new (struct MeshConnection);
  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    return NULL;
  }
  c->own_pos = own_pos;
  c->path = p;
  c->id = t->next_cid++;
  c->t = t;
  GNUNET_CONTAINER_DLL_insert_tail (t->connection_head, t->connection_tail, c);

  if (0 == own_pos)
  {
    c->fwd_maintenance_task =
        GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                      &connection_fwd_keepalive, c);
  }
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
 * Send an end-to-end FWD ACK message for the most recent in-sequence payload.
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
  uint64_t mask;
  unsigned int delta;

  if (GNUNET_NO == ch->reliable)
  {
    GNUNET_break (0);
    return;
  }
  rel = fwd ? ch->bck_rel  : ch->fwd_rel;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send_data_ack for %u\n",
              rel->mid_recv - 1);

  msg.header.type = htons (fwd ? GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK :
                                 GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (ch->id);
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

  send_prebuilt_message_channel (&msg.header, ch, fwd);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_data_ack END\n");
}


/**
 * Send an ACK informing the predecessor about the available buffer space.
 *
 * Note that although the name is fwd_ack, the FWD mean forward *traffic*,
 * the ACK itself goes "back" (towards root).
 *
 * @param c Connection on which to send the ACK.
 * @param fwd Is this FWD ACK? (Going dest->owner)
 */
static void
connection_send_ack (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *next_fc;
  struct MeshFlowControl *prev_fc;
  struct MeshPeer *next;
  struct MeshPeer *prev;
  uint32_t ack;
  int delta;

  next    = fwd ? connection_get_next_hop (c) : connection_get_prev_hop (c);
  prev    = fwd ? connection_get_prev_hop (c) : connection_get_next_hop (c);
  next_fc = next->fc;
  prev_fc = prev->fc;

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
  send_ack (prev, ack);
}


/**
 * Send an ACK informing the client about available buffer space.
 *
 * Note that although the name is fwd_ack, the FWD mean forward *traffic*,
 * the ACK itself goes "back" (towards root).
 * 
 * @param ch Channel on which to send the ACK, NULL if unknown.
 * @param fwd Is this FWD ACK? (Going dest->owner)
 */
// static void
// channel_send_ack (struct MeshChannel *ch, uint16_t type, int fwd)
// {
//   struct MeshChannelReliability *rel;
//   struct MeshFlowControl *next_fc;
//   struct MeshFlowControl *prev_fc;
//   struct MeshClient *c;
//   struct MeshClient *o;
//   GNUNET_PEER_Id hop;
//   uint32_t delta_mid;
//   uint32_t ack;
//   int delta;
// 
//   rel     = fwd ? ch->fwd_rel : ch->bck_rel;
//   c       = fwd ? ch->client  : ch->owner;
//   o       = fwd ? ch->owner   : ch->client;
//   hop     = fwd ? connection_get_prev_hop (cn) : connection_get_next_hop (cn);
//   next_fc = fwd ? &t->next_fc : &t->prev_fc;
//   prev_fc = fwd ? &t->prev_fc : &t->next_fc;
// 
//   switch (type)
//   {
//     case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
//     case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
//       GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
//                   "ACK due to %s\n",
//                   GNUNET_MESH_DEBUG_M2S (type));
//       if (GNUNET_YES == t->nobuffer && (GNUNET_NO == t->reliable || NULL == c))
//       {
//         GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, nobuffer\n");
//         return;
//       }
//       if (GNUNET_YES == t->reliable && NULL != c)
//         tunnel_send_data_ack (t, fwd);
//       break;
//     case GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK:
//     case GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK:
//     case GNUNET_MESSAGE_TYPE_MESH_ACK:
//     case GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK:
//       break;
//     case GNUNET_MESSAGE_TYPE_MESH_POLL:
//     case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
//       t->force_ack = GNUNET_YES;
//       break;
//     default:
//       GNUNET_break (0);
//   }
// 
//   /* Check if we need to transmit the ACK */
//   if (NULL == o &&
//       prev_fc->last_ack_sent - prev_fc->last_pid_recv > 3 &&
//       GNUNET_NO == t->force_ack)
//   {
//     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer free\n");
//     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
//                 "  last pid recv: %u, last ack sent: %u\n",
//                 prev_fc->last_pid_recv, prev_fc->last_ack_sent);
//     return;
//   }
// 
//   /* Ok, ACK might be necessary, what PID to ACK? */
//   delta = t->queue_max - next_fc->queue_n;
//   if (NULL != o && GNUNET_YES == t->reliable && NULL != rel->head_sent)
//     delta_mid = rel->mid_sent - rel->head_sent->mid;
//   else
//     delta_mid = 0;
//   if (0 > delta || (GNUNET_YES == t->reliable && 
//                     NULL != o &&
//                     (10 < rel->n_sent || 64 <= delta_mid)))
//     delta = 0;
//   if (NULL != o && delta > 1)
//     delta = 1;
//   ack = prev_fc->last_pid_recv + delta;
//   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
//   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
//               " last pid %u, last ack %u, qmax %u, q %u\n",
//               prev_fc->last_pid_recv, prev_fc->last_ack_sent,
//               t->queue_max, next_fc->queue_n);
//   if (ack == prev_fc->last_ack_sent && GNUNET_NO == t->force_ack)
//   {
//     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
//     return;
//   }
// 
//   prev_fc->last_ack_sent = ack;
//   if (NULL != o)
//     send_local_ack (t, o, fwd);
//   else if (0 != hop)
//     send_ack (t, hop, ack);
//   else
//     GNUNET_break (GNUNET_YES == t->destroy);
//   t->force_ack = GNUNET_NO;
// }


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
    channel_send_client_to_tid (ch, msg, ch->client, ch->id_dest);
  else
    channel_send_client_to_tid (ch, msg, ch->owner, ch->id);
}


/**
 * Send up to 64 buffered messages to the client for in order delivery.
 *
 * @param ch Channel on which to empty the message buffer.
 * @param c Client to send to.
 * @param rel Reliability structure to corresponding peer.
 *            If rel == bck_rel, this is FWD data.
 */
static void
channel_send_client_buffered_data (struct MeshChannel *ch,
                                   struct MeshClient *c,
                                   struct MeshChannelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  if (GNUNET_NO == ch->reliable)
  {
    GNUNET_break (0);
    return;
  }

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
      channel_send_client_data (ch, msg, (rel == ch->bck_rel));
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
 * @param msg Message to buffer.
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
rel_message_free (struct MeshReliableMessage *copy)
{
  struct MeshChannelReliability *rel;
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
  struct MeshPeer *pi;
  struct MeshChannel *ch;
  struct MeshConnection *c;
  struct GNUNET_MESH_Data *payload;
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
  fwd = (rel == ch->fwd_rel);
  c = tunnel_get_connection(ch->t, fwd);
  pi = connection_get_next_hop (c);
  for (q = pi->fc->queue_head; NULL != q; q = q->next)
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

    send_prebuilt_message_channel (&payload->header, ch, ch->fwd_rel == rel);
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
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)),
              c->id);

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (type);
  msg->cid = htonl (c->id);
  msg->tid = c->t->id;

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
    send_connection_ack (c);
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

  connection_keepalive (c, GNUNET_YES);
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

  connection_keepalive (c, GNUNET_NO);
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
  msg.cid = htonl (c->id);
  msg.tid = c->t->id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending tunnel destroy for connection %s[%X]\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)),
              c->id);

  send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_YES);
  send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_NO);
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
  struct GNUNET_MESH_ChannelDestroy msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY);
  msg.chid = htonl (ch->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending tunnel destroy for channel %s:%X\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (ch->t->peer->id)),
              ch->id);

  if (NULL != ch->owner)
    send_local_channel_destroy (ch, GNUNET_NO);
  else
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_NO);

  if (NULL != ch->client)
    send_local_channel_destroy (ch, GNUNET_YES);
  else
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_YES);
}


/**
 * Create a tunnel.
 *
 * @param tid Tunnel ID.
 */
static struct MeshTunnel2 *
tunnel_new (struct GNUNET_HashCode *tid)
{
  struct MeshTunnel2 *t;

  t = GNUNET_new (struct MeshTunnel2);
  t->id = *tid;
  t->next_chid = GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (tunnels, tid, t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    tunnel_destroy (t);
    return NULL;
  }

  return t;
}


/**
 * Find a tunnel.
 *
 * @param tid Tunnel ID.
 */
static struct MeshTunnel2 *
tunnel_get (struct GNUNET_HashCode *tid)
{
  return GNUNET_CONTAINER_multihashmap_get (tunnels, tid);
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
 * Create a connection.
 *
 * @param tid Tunnel ID.
 * @param cid Connection ID.
 */
static struct MeshConnection *
connection_new (struct GNUNET_HashCode *tid, uint32_t cid)
{
  struct MeshConnection *c;
  struct MeshTunnel2 *t;

  t = tunnel_get (tid);
  if (NULL == t)
  {
    t = tunnel_new (tid);
    if (NULL == t)
    {
      GNUNET_break (0);
      return NULL;
    }
  }

  c = GNUNET_new (struct MeshConnection);
  c->id = cid;
  tunnel_add_connection (t, c);

  return c;
}


/**
 * Find a connection.
 *
 * @param tid Tunnel ID.
 * @param cid Connection ID.
 */
static struct MeshConnection *
connection_get (struct GNUNET_HashCode *tid, uint32_t cid)
{
  struct MeshConnection *c;
  struct MeshTunnel2 *t;

  t = tunnel_get (tid);
  for (c = t->connection_head; NULL != c; c = c->next)
    if (c->id == cid)
      return c;

  return NULL;
}


/**
 * Connection is no longer needed: destroy it and remove from tunnel.
 *
 * @param c Connection to destroy.
 */
static void
connection_destroy (struct MeshConnection *c)
{
  struct MeshPeer *peer;

  if (NULL == c)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying connection %s[%X]\n",
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)),
              c->id);

  peer = connection_get_next_hop (c);
  if (NULL != peer)
    peer_cancel_queues (peer, c);
  peer = connection_get_prev_hop (c);
  if (NULL != peer)
    peer_cancel_queues (peer, c);

  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);

  GNUNET_CONTAINER_DLL_remove (c->t->connection_head, c->t->connection_tail, c);

  GNUNET_STATISTICS_update (stats, "# connections", -1, GNUNET_NO);
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
              GNUNET_i2s (GNUNET_PEER_resolve2 (c->t->peer->id)));

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &t->id, t))
    GNUNET_break (0);

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

  c = ch->owner;
  if (NULL != c)
  {
    if (GNUNET_YES != GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                              c->id, ch))
    {
      GNUNET_break (0);
    }
  }

  c = ch->client;
  if (NULL != c)
  {
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                ch->id_dest, ch))
    {
      GNUNET_break (0);
    }
  }

  if (GNUNET_YES == ch->reliable)
  {
    channel_rel_free_all (ch->fwd_rel);
    channel_rel_free_all (ch->bck_rel);
  }

  GNUNET_CONTAINER_DLL_remove (ch->t->channel_head, ch->t->channel_tail, ch);
  GNUNET_STATISTICS_update (stats, "# channels", -1, GNUNET_NO);

  GNUNET_free (ch);
}

/**
 * Create a new channel.
 * 
 * @param owner Clients that owns the channel, NULL for foreign channels.
 * @param id Channel Number for the channel, for the owner point of view.
 * 
 * @return A new initialized channel. NULL on error.
 */
static struct MeshChannel *
channel_new (struct MeshClient *owner,
             MESH_ChannelNumber id)
{
  struct MeshChannel *ch;

  if (NULL == owner)
    return NULL;

  ch = GNUNET_new (struct MeshChannel);
  ch->owner = owner;
  ch->id = id;

  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);

  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap32_put (owner->own_channels, id, ch,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    channel_destroy (ch);
    GNUNET_SERVER_receive_done (owner->handle, GNUNET_SYSERR);
    return NULL;
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
              " Channel %X / %X destroy, due to client %u shutdown.\n",
              ch->id, ch->id_dest, c->id);

  if (c == ch->client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is destination.\n", c->id);
    ch->client = NULL;
  }
  if (c == ch->owner)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Client %u is owner.\n", c->id);
    ch->owner = NULL;
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
              GNUNET_i2s(GNUNET_PEER_resolve2 (c->t->peer->id)),
              c->id);

  if (NULL != c->t->channel_head) /* If local, leave TODO review */
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
              GNUNET_i2s(GNUNET_PEER_resolve2 (c->t->peer->id)),
              c->id);

  if (NULL != c->t->channel_head) /* If local, leave TODO review */
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

  if (NULL != c->t->channel_head) /* Endpoint */
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
  struct MeshFlowControl *fc;

  fc = queue->peer->fc;
  if (GNUNET_YES == clear_cls)
  {
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "destroying CONNECTION_DESTROY\n");
        GNUNET_break (GNUNET_YES == queue->c->destroy);
        /* fall through */
      case GNUNET_MESSAGE_TYPE_MESH_FWD:
      case GNUNET_MESSAGE_TYPE_MESH_BCK:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   prebuilt message\n");
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type %s\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
        break;

      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type create path\n");
        break;

      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "   type %s unknown!\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
    }
    GNUNET_free_non_null (queue->cls);
  }
  GNUNET_CONTAINER_DLL_remove (fc->queue_head, fc->queue_tail, queue);

  fc->queue_n--;

  GNUNET_free (queue);
}

static size_t
queue_send (void *cls, size_t size, void *buf)
{
  struct MeshPeer *peer = cls;
  const struct GNUNET_PeerIdentity *dst_id;
  struct GNUNET_MessageHeader *msg;
  struct MeshPeerQueue *queue;
  struct MeshTunnel2 *t;
  struct MeshFlowControl *fc;
  struct MeshConnection *c;
  size_t data_size;
  uint32_t pid;
  uint16_t type;
  int fwd;

  fc = peer->fc;
  if (NULL == fc)
  {
    GNUNET_break (0);
    return 0;
  }
  fc->core_transmit = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Queue send\n");

  if (NULL == buf || 0 == size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Buffer size 0.\n");
    return 0;
  }
  queue = fc->queue_head;

  /* Queue has no traffic */
  if (NULL == queue)
  {
    GNUNET_break (0); /* Core tmt_rdy should've been canceled */
    return 0;
  }

  dst_id = GNUNET_PEER_resolve2 (peer->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   towards %s\n", GNUNET_i2s (dst_id));
  /* Check if buffer size is enough for the message */
  if (queue->size > size)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   not enough room, reissue\n");
      fc->core_transmit =
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   size ok\n");

  c = queue->c;
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
      /* Fall through */
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      data_size = send_core_data_raw (queue->cls, size, buf);
      msg = (struct GNUNET_MessageHeader *) buf;
      type = ntohs (msg->type);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path create\n");
      if (NULL != c->t->channel_head)
        data_size = send_core_connection_create (queue->cls, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path ack\n");
      if (NULL != c->t->channel_head)
        data_size = send_core_connection_ack (queue->cls, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    default:
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "*   type unknown: %u\n",
                  queue->type);
      data_size = 0;
  }

  fc->queue_n--;

  if (0 < drop_percent &&
      GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Dropping message of type %s\n",
                GNUNET_MESH_DEBUG_M2S (queue->type));
    data_size = 0;
  }
  /* Free queue, but cls was freed by send_core_* */
  queue_destroy (queue, GNUNET_NO);

  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  fwd = GNUNET_NO;
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
      fwd = GNUNET_YES;
      /* fall through */
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      pid = ntohl ( ((struct GNUNET_MESH_Encrypted *) buf)->pid );
      fc->last_pid_sent = pid;
      connection_send_ack (c, fwd);
      break;
    default:
      break;
  }

  /* If more data in queue, send next */
  queue = fc->queue_head;
  if (NULL != queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   more data!\n");
    if (NULL == fc->core_transmit) {
      peer->fc->core_transmit =
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
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "*   %s starting poll timeout\n");
      fc->poll_task =
          GNUNET_SCHEDULER_add_delayed (fc->poll_time, &peer_poll, fc);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying tunnel!\n");
      tunnel_destroy (t);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  Return %d\n", data_size);
  return data_size;
}


static void
queue_add (void *cls, uint16_t type, size_t size,
           struct MeshPeer *dst,
           struct MeshConnection *c,
           struct MeshChannel *ch)
{
  struct MeshPeerQueue *queue;
  struct MeshFlowControl *fc;
  int priority;

  fc = dst->fc;
  if (NULL == fc)
  {
    GNUNET_break (0);
    return;
  }

  priority = 0;

  if (GNUNET_MESSAGE_TYPE_MESH_POLL == type ||
      GNUNET_MESSAGE_TYPE_MESH_ACK == type)
    priority = 100;

  if (NULL != ch &&
      ( (NULL != ch->owner && GNUNET_MESSAGE_TYPE_MESH_FWD == type) ||
        (NULL != ch->client && GNUNET_MESSAGE_TYPE_MESH_BCK == type) ))
    priority = 50;

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

  fc->queue_n++;
  if (GMC_is_pid_bigger(fc->last_pid_sent + 1, fc->last_ack_recv) &&
      GNUNET_SCHEDULER_NO_TASK == fc->poll_task)
    fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                  &peer_poll,
                                                  dst);
  queue = GNUNET_malloc (sizeof (struct MeshPeerQueue));
  queue->cls = cls;
  queue->type = type;
  queue->size = size;
  queue->peer = dst;
  queue->c = c;
  queue->ch = ch;
  if (100 <= priority)
    GNUNET_CONTAINER_DLL_insert (fc->queue_head, fc->queue_tail, queue);
  else
    GNUNET_CONTAINER_DLL_insert_tail (fc->queue_head, fc->queue_tail, queue);

  if (NULL == fc->core_transmit)
  {
    fc->core_transmit =
        GNUNET_CORE_notify_transmit_ready (core_handle,
                                           0,
                                           0,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_PEER_resolve2 (dst->id),
                                           size,
                                           &queue_send,
                                           dst);
  }
  c->pending_messages++;
  c->t->pending_messages++;
}


/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/


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
  struct GNUNET_HashCode *tid;
  struct MeshPeerPath *path;
  struct MeshPeer *dest_peer;
  struct MeshPeer *orig_peer;
  struct MeshConnection *c;
  unsigned int own_pos;
  uint32_t cid;
  uint16_t size;
  uint16_t i;

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
  cid = ntohl (msg->cid);
  tid = &msg->tid;
  id = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    connection %s[%X] (%s).\n",
              GNUNET_h2s (tid), cid, GNUNET_i2s (id));

  /* Create connection */
  c = connection_get (tid, cid);
  if (NULL == c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating connection\n");
    c = connection_new (tid, cid);
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
  c->path = path;
  c->own_pos = own_pos;

  /* Is it a connection to us? */
  if (own_pos == size - 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    peer_add_path_to_origin (orig_peer, path, GNUNET_YES);

    send_connection_ack (c);

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
  uint32_t cid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received a connection ACK msg\n");
  msg = (struct GNUNET_MESH_ConnectionACK *) message;
  cid = ntohl(msg->cid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on connection %s[%X]\n",
              GNUNET_h2s (&msg->tid), cid);
  c = connection_get (&msg->tid, cid);
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

  /* Message for us? */
  if (NULL != c->t->channel_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    if (3 <= tunnel_count_connections(c->t) && NULL != c->t->peer->dhtget)
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
  c = connection_get (&msg->tid, ntohl (msg->cid));
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
  struct MeshTunnel2 *t;
  struct MeshPeer *neighbor;

  msg = (struct GNUNET_MESH_ConnectionDestroy *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a CONNECTION DESTROY message from %s\n",
              GNUNET_i2s (peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  for connection %s[%X]\n",
              GNUNET_h2s (&msg->tid), ntohl (msg->cid));
  c = connection_get (&msg->tid, ntohl (msg->cid));
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
  neighbor = peer_get (peer);
  if (neighbor == connection_get_prev_hop (c))
    neighbor = connection_get_next_hop (c);
  else if (neighbor == connection_get_next_hop (c))
    neighbor = connection_get_prev_hop (c);
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  send_prebuilt_message_peer (message, neighbor);
  t = c->t;
  connection_destroy (c);
  tunnel_destroy_if_empty (t);

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
  struct MeshChannelReliability *rel;
  struct MeshTunnel *t;
  struct MeshClient *c;
  GNUNET_PEER_Id hop;
  uint32_t pid;
  uint32_t ttl;
  uint16_t type;
  size_t size;

  /* Check size */
  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Data) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  type =ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a %s message from %s\n",
              GNUNET_MESH_DEBUG_M2S (type), GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_Data *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " payload of type %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (msg[1].header.type)));
  /* Check tunnel */
  t = channel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify back: we don't know this tunnel */
    GNUNET_STATISTICS_update (stats, "# data on unknown tunnel", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "WARNING tunnel unknown\n");
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "WARNING Received PID %u, (prev %u), ACK %u\n",
                pid, fc->last_pid_recv, fc->last_ack_sent);
    return GNUNET_OK;
  }
  if (NULL != c)
    tunnel_change_state (t, MESH_TUNNEL_READY);
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
    tunnel_send_ack (t, type, fwd);
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
  struct MeshChannelReliability *rel;
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

  t = channel_get (&msg->oid, ntohl (msg->tid));
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

  t = channel_get (&msg->oid, ntohl (msg->tid));

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
  tunnel_change_state (t, MESH_TUNNEL_READY);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a POLL packet from %s!\n",
              GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_Poll *) message;

  t = channel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_STATISTICS_update (stats, "# poll on unknown tunnel", 1, GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  pid = ntohl (msg->pid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  PID %u\n", pid);
  if (t->next_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from FWD\n");
    fc = &t->next_fc;
    old = fc->last_pid_recv;
  }
  else if (t->prev_hop == id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from BCK\n");
    fc = &t->prev_fc;
    old = fc->last_pid_recv;
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  was %u\n", fc->last_pid_recv);
  fc->last_pid_recv = pid;
  tunnel_send_ack (t, GNUNET_MESSAGE_TYPE_MESH_POLL, t->prev_hop == id);

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
  struct MeshClient *c;
  GNUNET_PEER_Id hop;
  int fwd;

  msg = (struct GNUNET_MESH_TunnelKeepAlive *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a keepalive packet from %s\n",
              GNUNET_i2s (peer));

  t = channel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify that we dont know that tunnel */
    GNUNET_STATISTICS_update (stats, "# keepalive on unknown tunnel", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  fwd = GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE == ntohs (message->type) ? 
        GNUNET_YES : GNUNET_NO;
  c   = fwd ? t->client   : t->owner;
  hop = fwd ? t->next_hop : t->prev_hop;

  if (NULL != c)
    tunnel_change_state (t, MESH_TUNNEL_READY);
  tunnel_reset_timeout (t, fwd);
  if (NULL != c || 0 == hop || myid == hop)
    return GNUNET_OK;

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  send_prebuilt_message (message, hop, t);
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
  {&handle_mesh_unicast, GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_mesh_to_orig, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
  {&handle_mesh_data_ack, GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK,
    sizeof (struct GNUNET_MESH_DataACK)},
  {&handle_mesh_data_ack, GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK,
    sizeof (struct GNUNET_MESH_DataACK)},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE,
    sizeof (struct GNUNET_MESH_TunnelKeepAlive)},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_BCK_KEEPALIVE,
    sizeof (struct GNUNET_MESH_TunnelKeepAlive)},
  {&handle_mesh_ack, GNUNET_MESSAGE_TYPE_MESH_ACK,
    sizeof (struct GNUNET_MESH_ACK)},
  {&handle_mesh_poll, GNUNET_MESSAGE_TYPE_MESH_POLL,
    sizeof (struct GNUNET_MESH_Poll)},
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u, %p)\n",
                c->id, c);
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
    {
      GNUNET_CONTAINER_multihashmap32_iterate (c->ports,
                                               &client_release_ports, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->ports);
    }
    next = c->next;
    GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  client free (%p)\n", c);
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

  /* Sanity check for duplicate tunnel IDs */
  if (NULL != channel_get_by_local_id (c, chid))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  peer = peer_get (&msg->peer);
  if (NULL == peer->tunnel)
    peer->tunnel = tunnel_new ();
  t = peer->tunnel;

  /* Create channel */
  while (NULL != channel_get_by_pi (myid, next_tid))
    next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
  t = tunnel_new (myid, next_tid, c, chid);
  next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  t->port = ntohl (msg->port);
  tunnel_set_options (t, ntohl (msg->opt));
  if (GNUNET_YES == t->reliable)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "!!! Reliable\n");
    t->fwd_rel = GNUNET_malloc (sizeof (struct MeshChannelReliability));
    t->fwd_rel->t = t;
    t->fwd_rel->expected_delay = MESH_RETRANSMIT_TIME;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATED TUNNEL %s[%x]:%u (%x)\n",
              GNUNET_i2s (&my_full_id), t->id.tid, t->port, t->local_tid);

  peer_info = peer_get (&msg->peer);
  peer_add_tunnel (peer_info, t);
  peer_connect (peer_info, t);
  tunnel_reset_timeout (t, GNUNET_YES);
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
  struct GNUNET_MESH_ChannelMessage *tunnel_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_ChannelNumber tid;

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
  if (sizeof (struct GNUNET_MESH_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  tunnel_msg = (struct GNUNET_MESH_ChannelMessage *) message;

  /* Retrieve tunnel */
  tid = ntohl (tunnel_msg->channel_id);
  t = channel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  tunnel %X not found\n", tid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Cleanup after the tunnel */
  client_delete_tunnel (c, t);
  if (c == t->client && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV <= tid)
  {
    t->client = NULL;
  }
  else if (c == t->owner && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV > tid)
  {
    peer_remove_tunnel (peer_get_short (t->dest), t);
    t->owner = NULL;
  }
  else 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "  tunnel %X client %p (%p, %p)\n",
                tid, c, t->owner, t->client);
    GNUNET_break (0);
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
  MESH_ChannelNumber tid;
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
  t = channel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Is the client in the tunnel? */
  if ( !( (tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV &&
           t->owner &&
           t->owner->handle == client)
         ||
          (tid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV &&
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

    fc = tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV ? &t->prev_fc : &t->next_fc;
    if (GNUNET_YES == t->reliable)
    {
      struct MeshChannelReliability *rel;
      struct MeshReliableMessage *copy;

      rel = (tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV) ? t->fwd_rel : t->bck_rel;
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
    payload->header.type = htons (tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV ?
                                  GNUNET_MESSAGE_TYPE_MESH_UNICAST :
                                  GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN);
    GNUNET_PEER_resolve(t->id.oid, &payload->oid);;
    payload->tid = htonl (t->id.tid);
    payload->ttl = htonl (default_ttl);
    payload->pid = htonl (fc->last_pid_recv + 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    if (tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
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
  MESH_ChannelNumber tid;

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
  tid = ntohl (msg->channel_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on tunnel %X\n", tid);
  t = channel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tunnel %X unknown.\n", tid);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Does client own tunnel? I.E: Is this an ACK for BCK traffic? */
  if (tid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
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
  struct MeshChannel *ch = value;
  struct GNUNET_MESH_LocalMonitor *msg;

  msg = GNUNET_malloc (sizeof(struct GNUNET_MESH_LocalMonitor));
  msg->channel_id = htonl (ch->id);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "*  sending info about tunnel %s\n",
              GNUNET_i2s (&msg->owner));

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
  ch = channel_get (&msg->owner, ntohl (msg->channel_id));
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
  struct MeshPeer *peer_info;
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
  peer_add_path (peer_info, path, GNUNET_YES);
  if (NULL == peer_info->fc)
  {
    peer_info->fc = GNUNET_new (struct MeshFlowControl);
    fc_init (peer_info->fc);
    peer_info->fc->peer = peer_info;
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
core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct MeshPeer *pi;
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *n;
  struct MeshFlowControl *fc;

  DEBUG_CONN ("Peer disconnected\n");
  pi = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pi)
  {
    GNUNET_break (0);
    return;
  }
  fc = pi->fc;
  if (NULL != fc)
  {
    GNUNET_break (0);
    return;
  }
  pi->fc = NULL;

  q = fc->queue_head;
  while (NULL != q)
  {
      n = q->next;
      queue_destroy (q, GNUNET_YES);
      q = n;
  }
  if (NULL != fc->core_transmit)
    GNUNET_CORE_notify_transmit_ready_cancel (fc->core_transmit);
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    GNUNET_SCHEDULER_cancel (fc->poll_task);

  peer_remove_path (pi, pi->id, myid);
  if (myid == pi->id)
  {
    DEBUG_CONN ("     (self)\n");
  }
  GNUNET_STATISTICS_update (stats, "# peers", -1, GNUNET_NO);
  GNUNET_free (fc);

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
  struct MeshTunnel2 *t = value;

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
  struct MeshPeer *p = value;
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *n;

  q = p->fc->queue_head;
  while (NULL != q)
  {
      n = q->next;
      if (q->peer == p)
      {
        queue_destroy(q, GNUNET_YES);
      }
      q = n;
  }
  peer_destroy (p);
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
