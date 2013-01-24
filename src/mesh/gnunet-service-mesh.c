/*
     This file is part of GNUnet.
     (C) 2001-2012 Christian Grothoff (and other contributing authors)

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
 * - add ping message
 * - relay corking down to core
 * - set ttl relative to tree depth
 * - Add data ACK count in path ACK
 * - Make common GNUNET_MESH_Data header for unicast, to_orig, multicast
 * TODO END
 */

#include "platform.h"
#include "mesh.h"
#include "mesh_protocol.h"
#include "mesh_tunnel_tree.h"
#include "block_mesh.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_regex_lib.h"

#define MESH_BLOOM_SIZE         128

#define MESH_DEBUG_REGEX        GNUNET_YES
#define MESH_DEBUG_DHT          GNUNET_NO
#define MESH_DEBUG_CONNECTION   GNUNET_NO
#define MESH_DEBUG_TIMING       __LINUX__ && GNUNET_NO

#define MESH_MAX_POLL_TIME      GNUNET_TIME_relative_multiply (\
                                  GNUNET_TIME_UNIT_MINUTES,\
                                  10)

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

#if MESH_DEBUG_REGEX
#define DEBUG_REGEX(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)
#else
#define DEBUG_REGEX(...)
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
 * Struct representing a piece of data being sent to other peers
 */
struct MeshData
{
  /** Tunnel it belongs to. */
  struct MeshTunnel *t;

  /** How many remaining neighbors still hav't got it. */
  unsigned int reference_counter;

  /** How many remaining neighbors we need to send this to. */
  unsigned int total_out;

  /** Size of the data. */
  size_t data_len;

  /** Data itself */
  void *data;
};


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
 * Struct to store regex information announced by clients.
 */
struct MeshRegexDescriptor
{
    /**
     * Regular expression itself.
     */
  char *regex;

    /**
     * How many characters per edge can we squeeze?
     */
  uint16_t compression;

    /**
     * Handle to announce the regex.
     */
  struct GNUNET_REGEX_announce_handle *h;
};


/**
 * Struct to keep information of searches of services described by a regex
 * using a user-provided string service description.
 */
struct MeshRegexSearchInfo
{
    /**
     * Which tunnel is this for
     */
  struct MeshTunnel *t;

    /**
     * User provided description of the searched service.
     */
  char *description;

    /**
     * Regex search handle.
     */
  struct GNUNET_REGEX_search_handle *search_handle;

    /**
     * Peer that is connecting via connect_by_string. When connected, free ctx.
     */
  GNUNET_PEER_Id peer;

    /**
     * Other peers that are found but not yet being connected to.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of elements in peers.
     */
  unsigned int n_peers;

    /**
     * Next peer to try to connect to.
     */
  unsigned int i_peer;

    /**
     * Timeout for a connect attempt.
     * When reached, try to connect to a different peer, if any. If not,
     * try the same peer again.
     */
  GNUNET_SCHEDULER_TaskIdentifier timeout;

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
     * Task handler for delayed connect task;
     */
  GNUNET_SCHEDULER_TaskIdentifier connect_task;

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
    * Handle to for queued transmissions
    */
  struct GNUNET_CORE_TransmitHandle *core_transmit;
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
     * Is the speed on the tunnel limited to the slowest peer?
     */
  int speed_min;

    /**
     * Is the tunnel bufferless (minimum latency)?
     */
  int nobuffer;

    /**
     * Packet ID of the last fwd packet seen (sent/retransmitted/received).
     */
  uint32_t fwd_pid;

    /**
     * Packet ID of the last bck packet sent (unique counter per hop).
     */
  uint32_t bck_pid;

    /**
     * SKIP value for this tunnel.
     */
  uint32_t skip;

    /**
     * Force sending ACK? Flag to allow duplicate ACK on POLL.
     */
  int force_ack;

    /**
     * MeshTunnelChildInfo of all children, indexed by GNUNET_PEER_Id.
     * Contains the Flow Control info: FWD ACK value received,
     * last BCK ACK sent, PID and SKIP values.
     */
  struct GNUNET_CONTAINER_MultiHashMap *children_fc;

    /**
     * Last ACK sent towards the origin (for traffic towards leaf node).
     */
  uint32_t last_fwd_ack;

  /**
   * BCK ACK value received from the hop towards the owner of the tunnel,
   * (previous node / owner): up to what message PID can we sent back to him.
   */
  uint32_t bck_ack;

    /**
     * How many messages are in the forward queue (towards leaves).
     */
  unsigned int fwd_queue_n;

    /**
     * How many messages do we accept in the forward queue.
     */
  unsigned int fwd_queue_max;

    /**
     * How many messages are in the backward queue (towards origin).
     */
  unsigned int bck_queue_n;

    /**
     * How many messages do we accept in the backward queue.
    */
   unsigned int bck_queue_max;

    /**
     * Task to poll peer in case of a stall.
     */
   GNUNET_SCHEDULER_TaskIdentifier fc_poll_bck;

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
     * Clients that have been informed about and want to stay in the tunnel.
     */
  struct MeshClient **clients;

    /**
     * Flow control info for each client.
     */
  struct MeshTunnelClientInfo *clients_fc;

  /**
     * Number of elements in clients/clients_fc
     */
  unsigned int nclients;

    /**
     * Clients that have been informed but requested to leave the tunnel.
     */
  struct MeshClient **ignore;

    /**
     * Number of elements in clients
     */
  unsigned int nignore;

    /**
     * Blacklisted peers
     */
  GNUNET_PEER_Id *blacklisted;

    /**
     * Number of elements in blacklisted
     */
  unsigned int nblacklisted;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[MESH_BLOOM_SIZE];

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
     * Handle for the regex search for a connect_by_string
     */
  struct MeshRegexSearchInfo *regex_search;

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
   * If the tunnel is empty, destoy it.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_destroy;
};


/**
 * Info about a child node in a tunnel, needed to perform flow control.
 */
struct MeshTunnelChildInfo
{
    /**
     * ID of the child node.
     */
  GNUNET_PEER_Id id;

    /**
     * SKIP value.
     */
  uint32_t skip;

    /**
     * Last sent PID.
     */
  uint32_t fwd_pid;

    /**
     * Last received PID.
     */
  uint32_t bck_pid;

    /**
     * Maximum PID allowed (FWD ACK received).
     */
  uint32_t fwd_ack;

    /**
     * Last ACK sent to that child (BCK ACK).
     */
  uint32_t bck_ack;

    /**
     * Circular buffer pointing to MeshPeerQueue elements for all
     * payload traffic going to this child.
     * Size determined by the tunnel queue size (@c t->fwd_queue_max).
     */
  struct MeshPeerQueue **send_buffer;

    /**
     * Index of the oldest element in the send_buffer.
     */
  unsigned int send_buffer_start;

    /**
     * How many elements are already in the buffer.
     */
  unsigned int send_buffer_n;

    /**
     * Tunnel this info is about
     */
  struct MeshTunnel *t;

    /**
     * Task to poll peer in case of a stall.
     */
  GNUNET_SCHEDULER_TaskIdentifier fc_poll;

     /**
      * Time to use for next polling call.
      */
   struct GNUNET_TIME_Relative fc_poll_time;
};


/**
 * Info about a leaf client of a tunnel, needed to perform flow control.
 */
struct MeshTunnelClientInfo
{
  /**
   * PID of the last packet sent to the client (FWD).
   */
  uint32_t fwd_pid;

  /**
   * PID of the last packet received from the client (BCK).
   */
  uint32_t bck_pid;

  /**
   * Maximum PID allowed (FWD ACK received).
   */
  uint32_t fwd_ack;
  
  /**
   * Last ACK sent to that child (BCK ACK).
   */
  uint32_t bck_ack;
};



/**
 * Info collected during iteration of child nodes in order to get the ACK value
 * for a tunnel.
 */
struct MeshTunnelChildIteratorContext
{
    /**
     * Tunnel whose info is being collected.
     */
  struct MeshTunnel *t;

    /**
     * Is this context initialized? Is the value in max_child_ack valid?
     */
  int init;

    /**
     * Maximum child ACK so far.
     */
  uint32_t max_child_ack;

    /**
     * Number of children nodes
     */
  unsigned int nchildren;
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
  
    /**
     * Regular expressions describing the services offered by this client.
     */
  struct MeshRegexDescriptor *regexes; // FIXME regex add timeout? API to remove a regex?

    /**
     * Number of regular expressions in regexes.
     */
  unsigned int n_regex;

    /**
     * Task to refresh all regular expresions in the DHT.
     */
  GNUNET_SCHEDULER_TaskIdentifier regex_announce_task;

    /**
     * Tmp store for partially retrieved regex.
     */
  char *partial_regex;

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

unsigned int debug_fwd_ack;
unsigned int debug_bck_ack;

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
 * How often to PUT local application numbers in the DHT.
 */
static struct GNUNET_TIME_Relative app_announce_time;

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


/*************************** Static global variables **************************/

/**
 * Hostkey generation context
 */
static struct GNUNET_CRYPTO_RsaKeyGenerationContext *keygen;

/**
 * DLL with all the clients, head.
 */
static struct MeshClient *clients;

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
static struct GNUNET_CONTAINER_MultiHashMap *incoming_tunnels;

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
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Own public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Tunnel ID for the next created tunnel (global tunnel number).
 */
static MESH_TunnelNumber next_tid;

/**
 * Tunnel ID for the next incoming tunnel (local tunnel number).
 */
static MESH_TunnelNumber next_local_tid;

/**
 * All application types provided by this peer.
 */
static struct GNUNET_CONTAINER_MultiHashMap *applications;

/**
 * All message types clients of this peer are interested in.
 */
static struct GNUNET_CONTAINER_MultiHashMap *types;

/**
 * Task to periodically announce provided applications.
 */
GNUNET_SCHEDULER_TaskIdentifier announce_applications_task;

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
 * and insert it in the appropiate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_info_get (const struct GNUNET_PeerIdentity *peer);


/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropiate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeerInfo *
peer_info_get_short (const GNUNET_PEER_Id peer);


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
peer_info_connect (struct MeshPeerInfo *peer, struct MeshTunnel *t);


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
 * Add a peer to a tunnel, accomodating paths accordingly and initializing all
 * needed rescources.
 * If peer already exists, reevaluate shortest path and change if different.
 *
 * @param t Tunnel we want to add a new peer to
 * @param peer PeerInfo of the peer being added
 *
 */
static void
tunnel_add_peer (struct MeshTunnel *t, struct MeshPeerInfo *peer);


/**
 * Removes an explicit path from a tunnel, freeing all intermediate nodes
 * that are no longer needed, as well as nodes of no longer reachable peers.
 * The tunnel itself is also destoyed if results in a remote empty tunnel.
 *
 * @param t Tunnel from which to remove the path.
 * @param peer Short id of the peer which should be removed.
 */
static void
tunnel_delete_peer (struct MeshTunnel *t, GNUNET_PEER_Id peer);


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
 * Get the current ack value for a tunnel, for data going from root to leaves,
 * taking in account the tunnel mode and the status of all children and clients.
 *
 * @param t Tunnel.
 *
 * @return Maximum PID allowed.
 */
static uint32_t
tunnel_get_fwd_ack (struct MeshTunnel *t);


/**
 * Add a client to a tunnel, initializing all needed data structures.
 * 
 * @param t Tunnel to which add the client.
 * @param c Client which to add to the tunnel.
 */
static void
tunnel_add_client (struct MeshTunnel *t, struct MeshClient *c);


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
/************************    REGEX INTEGRATION     ****************************/
/******************************************************************************/

/**
 * Cancel a mesh regex search and free resources.
 */
static void
regex_cancel_search (struct MeshRegexSearchInfo *regex_search)
{
  DEBUG_REGEX ("Search for %s canelled.\n", regex_search->description);
  GNUNET_REGEX_search_cancel (regex_search->search_handle);
  if (0 < regex_search->n_peers)
    GNUNET_free (regex_search->peers);
  if (GNUNET_SCHEDULER_NO_TASK != regex_search->timeout)
  {
    GNUNET_SCHEDULER_cancel(regex_search->timeout);
  }
  GNUNET_free (regex_search);
}


/**
 * Function called if the connect attempt to a peer found via
 * connect_by_string times out. Try to connect to another peer, if any.
 * Otherwise try to reconnect to the same peer.
 *
 * @param cls Closure (info about regex search).
 * @param tc TaskContext.
 */
static void
regex_connect_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshRegexSearchInfo *info = cls;
  struct MeshPeerInfo *peer_info;
  GNUNET_PEER_Id id;
  GNUNET_PEER_Id old;

  DEBUG_REGEX ("Regex connect timeout\n");
  info->timeout = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    DEBUG_REGEX (" due to shutdown\n");
    return;
  }

  old = info->peer;
  DEBUG_REGEX ("  timed out: %u\n", old);

  if (0 < info->n_peers)
  {
    // Select next peer, put current in that spot.
    id = info->peers[info->i_peer];
    info->peers[info->i_peer] = info->peer;
    info->i_peer = (info->i_peer + 1) % info->n_peers;
  }
  else
  {
    // Try to connect to same peer again.
    id = info->peer;
  }
  DEBUG_REGEX ("  trying: %u\n", id);

  peer_info = peer_info_get_short(id);
  tunnel_add_peer (info->t, peer_info);
  if (old != id)
    tunnel_delete_peer (info->t, old);
  peer_info_connect (peer_info, info->t);
  info->timeout = GNUNET_SCHEDULER_add_delayed (connect_timeout,
                                                &regex_connect_timeout,
                                                info);
  DEBUG_REGEX ("Regex connect timeout END\n");
}


/**
 * Function to process DHT string to regex matching.
 * Called on each result obtained for the DHT search.
 *
 * @param cls Closure provided in GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 */
static void
regex_found_handler (void *cls,
                     const struct GNUNET_PeerIdentity *id,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  struct MeshRegexSearchInfo *info = cls;
  struct MeshPeerPath *p;
  struct MeshPeerInfo *peer_info;

  DEBUG_REGEX ("Got regex results from DHT!\n");
  DEBUG_REGEX ("  for %s\n", info->description);

  peer_info = peer_info_get (id);
  p = path_build_from_dht (get_path, get_path_length,
                           put_path, put_path_length);
  path_add_to_peers (p, GNUNET_NO);
  path_destroy(p);

  tunnel_add_peer (info->t, peer_info);
  peer_info_connect (peer_info, info->t);
  if (0 == info->peer)
  {
    info->peer = peer_info->id;
  }
  else
  {
    GNUNET_array_append (info->peers, info->n_peers, peer_info->id);
  }

  if (GNUNET_SCHEDULER_NO_TASK != info->timeout)
    return;

  info->timeout = GNUNET_SCHEDULER_add_delayed (connect_timeout,
                                                &regex_connect_timeout,
                                                info);

  return;
}


/**
 * Store the regular expression describing a local service into the DHT.
 *
 * @param regex The regular expresion.
 */
static void
regex_put (struct MeshRegexDescriptor *regex)
{
  DEBUG_REGEX ("  regex_put (%s) start\n", regex->regex);
  if (NULL == regex->h)
  {
    DEBUG_REGEX ("  first put, creating DFA\n");
    regex->h = GNUNET_REGEX_announce (dht_handle,
                                      &my_full_id,
                                      regex->regex,
                                      regex->compression,
                                      stats);
  }
  else
  {
    DEBUG_REGEX ("  not first put, using cached data\n");
    GNUNET_REGEX_reannounce (regex->h);
  }
  DEBUG_REGEX ("  regex_put (%s) end\n", regex->regex);
}


/**
 * Periodically announce what applications are provided by local clients
 * (by regex)
 *
 * @param cls closure
 * @param tc task context
 */
static void
regex_announce (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshClient *c = cls;
  unsigned int i;

  c->regex_announce_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  DEBUG_REGEX ("Starting announce for regex\n");
  for (i = 0; i < c->n_regex; i++)
    regex_put (&c->regexes[i]);
  c->regex_announce_task = GNUNET_SCHEDULER_add_delayed (app_announce_time,
                                                         &regex_announce,
                                                         cls);
  DEBUG_REGEX ("Finished announce for regex\n");
}


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
announce_application (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct PBlock block;
  struct MeshClient *c;

  block.id = my_full_id;
  c =  GNUNET_CONTAINER_multihashmap_get (applications, key);
  GNUNET_assert(NULL != c);
  block.type = (long) GNUNET_CONTAINER_multihashmap_get (c->apps, key);
  if (0 == block.type)
  {
    GNUNET_break(0);
    return GNUNET_YES;
  }
  block.type = htonl (block.type);

  GNUNET_break (NULL != 
                GNUNET_DHT_put (dht_handle, key,
				dht_replication_level,
				GNUNET_DHT_RO_RECORD_ROUTE |
				GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
				GNUNET_BLOCK_TYPE_MESH_PEER_BY_TYPE,
				sizeof (block),
				(const char *) &block,
				GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS), /* FIXME: this should be an option */
				app_announce_time, NULL, NULL));
  return GNUNET_OK;
}


/**
 * Periodically announce what applications are provided by local clients
 * (by type)
 *
 * @param cls closure
 * @param tc task context
 */
static void
announce_applications (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
 
  DEBUG_DHT ("Starting PUT for apps\n");

  GNUNET_CONTAINER_multihashmap_iterate (applications, &announce_application,
                                         NULL);
  announce_applications_task =
      GNUNET_SCHEDULER_add_delayed (app_announce_time, &announce_applications,
                                    cls);
  DEBUG_DHT ("Finished PUT for apps\n");
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
  block.type = htonl (0);
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
 * Decrements the reference counter and frees all resources if needed
 *
 * @param mesh_data Data Descriptor used in a multicast message.
 *                  Freed no longer needed (last message).
 */
static void
data_descriptor_decrement_rc (struct MeshData *mesh_data)
{
  if (0 == --(mesh_data->reference_counter))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Last copy!\n");
    GNUNET_free (mesh_data->data);
    GNUNET_free (mesh_data);
  }
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
 * FIXME: use of crypto_hash slows it down
 *  The hash function alone takes 8-10us out of the ~55us for the whole
 * process of retransmitting the message from one local client to another.
 * Find faster implementation!
 */
static int
client_is_subscribed (uint16_t message_type, struct MeshClient *c)
{
  struct GNUNET_HashCode hc;

  if (NULL == c->types)
    return GNUNET_NO;

  GNUNET_CRYPTO_hash (&message_type, sizeof (uint16_t), &hc);
  return GNUNET_CONTAINER_multihashmap_contains (c->types, &hc);
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
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
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
  struct GNUNET_HashCode hash;

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
 * Notify the owner of a tunnel that a peer has disconnected.
 * 
 * @param c Client (owner of tunnel).
 * @param t Tunnel this message is about.
 * @param peer_id Short ID of the disconnected peer.
 */
void
client_notify_peer_disconnected (struct MeshClient *c,
                                 struct MeshTunnel *t,
                                 GNUNET_PEER_Id peer_id)
{
  struct GNUNET_MESH_PeerControl msg;

  if (NULL == t->owner || NULL == nc)
    return;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
  msg.tunnel_id = htonl (t->local_tid);
  GNUNET_PEER_resolve (peer_id, &msg.peer);
  GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Send the message to all clients that have subscribed to its type
 *
 * @param msg Pointer to the message itself
 * @param payload Pointer to the payload of the message.
 * @param t The tunnel to whose clients this message goes.
 * 
 * @return number of clients this message was sent to
 */
static unsigned int
send_subscribed_clients (const struct GNUNET_MessageHeader *msg,
                         const struct GNUNET_MessageHeader *payload,
                         struct MeshTunnel *t)
{
  struct MeshClient *c;
  MESH_TunnelNumber *tid;
  unsigned int count;
  uint16_t type;
  char cbuf[htons (msg->size)];

  type = ntohs (payload->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending to clients...\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "message of type %s\n",
              GNUNET_MESH_DEBUG_M2S (type));

  memcpy (cbuf, msg, sizeof (cbuf));
  switch (htons (msg->type))
  {
    struct GNUNET_MESH_Unicast *uc;
    struct GNUNET_MESH_Multicast *mc;
    struct GNUNET_MESH_ToOrigin *to;

    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      uc = (struct GNUNET_MESH_Unicast *) cbuf;
      tid = &uc->tid;
      break;
    case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
      mc = (struct GNUNET_MESH_Multicast *) cbuf;
      tid = &mc->tid;
      break;
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      to = (struct GNUNET_MESH_ToOrigin *) cbuf;
      tid = &to->tid;
      break;
    default:
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
          struct GNUNET_HashCode hash;

          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "     sending tunnel create\n");
          tmsg.header.size = htons (sizeof (tmsg));
          tmsg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
          GNUNET_PEER_resolve (t->id.oid, &tmsg.peer);
          tmsg.tunnel_id = htonl (t->local_tid_dest);
          tmsg.opt = 0;
          if (GNUNET_YES == t->speed_min)
            tmsg.opt |= MESH_TUNNEL_OPT_SPEED_MIN;
          if (GNUNET_YES == t->nobuffer)
            tmsg.opt |= MESH_TUNNEL_OPT_NOBUFFER;
          GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                                      &tmsg.header, GNUNET_NO);
          tunnel_add_client (t, c);
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
                                                   *) cbuf, GNUNET_NO);
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

  if (NULL == t->owner || GNUNET_YES == t->destroy)
    return;

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
peer_info_delete_tunnel (void *cls, const struct GNUNET_HashCode * key, void *value)
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
  struct MeshTransmissionDescriptor *info = cls;
  struct GNUNET_MessageHeader *msg;
  size_t total_size;

  GNUNET_assert (NULL != info);
  GNUNET_assert (NULL != info->mesh_data);
  msg = (struct GNUNET_MessageHeader *) info->mesh_data->data;
  total_size = ntohs (msg->size);

  if (total_size > size)
  {
    GNUNET_break (0);
    return 0;
  }
  memcpy (buf, msg, total_size);
  data_descriptor_decrement_rc (info->mesh_data);
  GNUNET_free (info);
  return total_size;
}


/**
 * Sends an already built non-multicast message to a peer,
 * properly registrating all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param peer Short ID of the neighbor whom to send the message.
 * @param t Tunnel on which this message is transmitted.
 */
static void
send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_PeerIdentity *peer,
                       struct MeshTunnel *t)
{
  struct MeshTransmissionDescriptor *info;
  struct MeshPeerInfo *neighbor;
  struct MeshPeerPath *p;
  size_t size;
  uint16_t type;

//   GNUNET_TRANSPORT_try_connect(); FIXME use?

  size = ntohs (message->size);
  info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));
  info->mesh_data = GNUNET_malloc (sizeof (struct MeshData));
  info->mesh_data->data = GNUNET_malloc (size);
  memcpy (info->mesh_data->data, message, size);
  type = ntohs(message->type);
  switch (type)
  {
    struct GNUNET_MESH_Unicast *m;
    struct GNUNET_MESH_ToOrigin *to;

    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      m = (struct GNUNET_MESH_Unicast *) info->mesh_data->data;
      m->ttl = htonl (ntohl (m->ttl) - 1);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      to = (struct GNUNET_MESH_ToOrigin *) info->mesh_data->data;
      t->bck_pid++;
      to->pid = htonl(t->bck_pid);
  }
  info->mesh_data->data_len = size;
  info->mesh_data->reference_counter = 1;
  info->mesh_data->total_out = 1;
  neighbor = peer_info_get (peer);
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
                GNUNET_i2s(peer));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  PATHS TO %s:\n",
                GNUNET_i2s(peer));
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    " no direct connection to %s\n",
                    GNUNET_i2s (peer));
    GNUNET_free (info->mesh_data->data);
    GNUNET_free (info->mesh_data);
    GNUNET_free (info);
    return;
  }
  info->peer = neighbor;
  if (GNUNET_MESSAGE_TYPE_MESH_PATH_ACK == type)
    type = 0;
  queue_add (info,
             type,
             size,
             neighbor,
             t);
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
  queue_add (path_info,
             GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE,
             sizeof (struct GNUNET_MESH_ManipulatePath) +
                (p->length * sizeof (struct GNUNET_PeerIdentity)),
             neighbor,
             t);
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
    send_prebuilt_message (&msg->header, tree_get_first_hop (t->tree, destination), t);
  }
  path_destroy (p);
}


/**
 * Sends a PATH ACK message in reponse to a received PATH_CREATE directed to us.
 *
 * @param t Tunnel which to confirm.
 */
static void
send_path_ack (struct MeshTunnel *t) 
{
  struct MeshTransmissionDescriptor *info;
  struct GNUNET_PeerIdentity id;
  GNUNET_PEER_Id peer;

  peer = tree_get_predecessor (t->tree);
  GNUNET_PEER_resolve (peer, &id);
  info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));
  info->origin = &t->id;
  info->peer = GNUNET_CONTAINER_multihashmap_get (peers, &id.hashPubKey);
  GNUNET_assert (NULL != info->peer);

  queue_add (info,
             GNUNET_MESSAGE_TYPE_MESH_PATH_ACK,
             sizeof (struct GNUNET_MESH_PathACK),
             info->peer,
             t);
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
      struct GNUNET_HashCode hash;

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
                                         GNUNET_BLOCK_TYPE_MESH_PEER, /* type */
                                         &id.hashPubKey,     /* key to search */
                                         dht_replication_level, /* replication level */
                                         GNUNET_DHT_RO_RECORD_ROUTE |
                                         GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                         NULL,       /* xquery */ // FIXME BLOOMFILTER
                                         0,     /* xquery bits */ // FIXME BLOOMFILTER SIZE
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

  path_info->peer->connect_task = GNUNET_SCHEDULER_NO_TASK;

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
  p = pi->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (pi->path_head, pi->path_tail, p);
    path_destroy (p);
    p = nextp;
  }
  if (GNUNET_SCHEDULER_NO_TASK != pi->connect_task)
  {
    GNUNET_free (GNUNET_SCHEDULER_cancel (pi->connect_task));
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer_info_remove_path\n");
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
 * Function called if the connection to the peer has been stalled for a while,
 * possibly due to a missed ACK. Poll the peer about its ACK status.
 *
 * @param cls Closure (cinfo).
 * @param tc TaskContext.
 */
static void
tunnel_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnelChildInfo *cinfo = cls;
  struct GNUNET_MESH_Poll msg;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnel *t;

  cinfo->fc_poll = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  t = cinfo->t;
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  msg.tid = htonl (t->id.tid);
  GNUNET_PEER_resolve (t->id.oid, &msg.oid);
  msg.last_ack = htonl (cinfo->fwd_ack);

  GNUNET_PEER_resolve (cinfo->id, &id);
  send_prebuilt_message (&msg.header, &id, cinfo->t);
  cinfo->fc_poll_time = GNUNET_TIME_relative_min (
    MESH_MAX_POLL_TIME,
    GNUNET_TIME_relative_multiply (cinfo->fc_poll_time, 2));
  cinfo->fc_poll = GNUNET_SCHEDULER_add_delayed (cinfo->fc_poll_time,
                                                 &tunnel_poll, cinfo);
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
  struct GNUNET_HashCode hash;

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
    struct GNUNET_HashCode hash;

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
      t->clients_fc[i] = t->clients_fc[t->nclients - 1];
      GNUNET_array_grow (t->clients, t->nclients, t->nclients - 1);
      t->nclients++;
      GNUNET_array_grow (t->clients_fc, t->nclients, t->nclients - 1);
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
 * @brief Iterator to destroy MeshTunnelChildInfo of tunnel children.
 * 
 * Destroys queue elements of all waiting transmissions and frees all memory
 * used by the struct and its elements.
 *
 * @param cls Closure (tunnel info).
 * @param key Hash of GNUNET_PEER_Id (unused).
 * @param value MeshTunnelChildInfo of the child.
 *
 * @return always GNUNET_YES, to keep iterating
 */
static int
tunnel_destroy_child (void *cls,
                      const struct GNUNET_HashCode * key,
                      void *value)
{
  struct MeshTunnelChildInfo *cinfo = value;
  struct MeshTunnel *t = cls;
  struct MeshPeerQueue *q;
  unsigned int c;
  unsigned int i;

  for (c = 0; c < cinfo->send_buffer_n; c++)
  {
    i = (cinfo->send_buffer_start + c) % t->fwd_queue_max;
    q = cinfo->send_buffer[i];
    cinfo->send_buffer[i] = NULL;
    if (NULL != q)
      queue_destroy (q, GNUNET_YES);
    else
      GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%u %u\n", c, cinfo->send_buffer_n);
  }
  GNUNET_free_non_null (cinfo->send_buffer);
  if (GNUNET_SCHEDULER_NO_TASK != cinfo->fc_poll)
  {
    GNUNET_SCHEDULER_cancel (cinfo->fc_poll);
    cinfo->fc_poll = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (cinfo);
  return GNUNET_YES;
}


/**
 * Callback used to notify a client owner of a tunnel that a peer has
 * disconnected, most likely because of a path change.
 *
 * @param cls Closure (tunnel this notification is about).
 * @param peer_id Short ID of disconnected peer.
 */
void
tunnel_notify_client_peer_disconnected (void *cls, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer;
  struct MeshPathInfo *path_info;

  client_notify_peer_disconnected (t->owner, t, peer_id);

  peer = peer_info_get_short (peer_id);
  path_info = GNUNET_malloc (sizeof (struct MeshPathInfo));
  path_info->peer = peer;
  path_info->t = t;
  peer->connect_task = GNUNET_SCHEDULER_add_now (&peer_info_connect_task,
                                                 path_info);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_add_peer\n");
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
    tree_add_path (t->tree, best_p, &tunnel_notify_client_peer_disconnected, t);
    if (GNUNET_SCHEDULER_NO_TASK == t->path_refresh_task)
      t->path_refresh_task =
          GNUNET_SCHEDULER_add_delayed (refresh_path_time, &path_refresh, t);
  }
  else
  {
    /* Start a DHT get */
    peer_info_connect (peer, t);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_add_peer END\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_add_path\n");
  GNUNET_assert (0 != own_pos);
  tree_add_path (t->tree, p, NULL, NULL);
  if (own_pos < p->length - 1)
  {
    GNUNET_PEER_resolve (p->peers[own_pos + 1], &id);
    tree_update_first_hops (t->tree, myid, &id);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_add_path END\n");
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
  struct MeshTunnelClientInfo clinfo;

  GNUNET_array_append (t->clients, t->nclients, c);
  clinfo.fwd_ack = t->fwd_pid + 1;
  clinfo.bck_ack = t->nobuffer ? 1 : INITIAL_WINDOW_SIZE - 1;
  clinfo.fwd_pid = t->fwd_pid;
  clinfo.bck_pid = (uint32_t) -1; // Expected next: 0
  t->nclients--;
  GNUNET_array_append (t->clients_fc, t->nclients, clinfo);
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
      tree_notify_connection_broken (t->tree, p1, p2,
                                     &tunnel_notify_client_peer_disconnected,
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
      send_prebuilt_message (&msg.header, &neighbor, t);
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
  struct GNUNET_MessageHeader *msg;

  info = GNUNET_malloc (sizeof (struct MeshTransmissionDescriptor));

  info->mesh_data = mdata;
  (mdata->reference_counter) ++;
  info->destination = neighbor_id;
  GNUNET_PEER_resolve (neighbor_id, &neighbor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   sending to %s...\n",
              GNUNET_i2s (&neighbor));
  info->peer = peer_info_get (&neighbor);
  GNUNET_assert (NULL != info->peer);
  msg = (struct GNUNET_MessageHeader *) mdata->data;
  queue_add(info,
            ntohs (msg->type),
            info->mesh_data->data_len,
            info->peer,
            mdata->t);
}


/**
 * Queue a message in a tunnel in multicast, sending a copy to each child node
 * down the local one in the tunnel tree.
 *
 * @param t Tunnel in which to send the data.
 * @param msg Message to be sent.
 */
static void
tunnel_send_multicast (struct MeshTunnel *t,
                       const struct GNUNET_MessageHeader *msg)
{
  struct MeshData *mdata;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " sending a multicast packet...\n");

  mdata = GNUNET_malloc (sizeof (struct MeshData));
  mdata->data_len = ntohs (msg->size);
  mdata->t = t;
  mdata->data = GNUNET_malloc (mdata->data_len);
  memcpy (mdata->data, msg, mdata->data_len);
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_MESH_MULTICAST)
  {
    struct GNUNET_MESH_Multicast *mcast;

    mcast = (struct GNUNET_MESH_Multicast *) mdata->data;
    if (t->fwd_queue_n >= t->fwd_queue_max)
    {
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  queue full!\n");
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "  message from %s!\n",
                  GNUNET_i2s(&mcast->oid));
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "  message at %s!\n",
                  GNUNET_i2s(&my_full_id));
      GNUNET_free (mdata->data);
      GNUNET_free (mdata);
      return;
    }
    t->fwd_queue_n++;
    mcast->ttl = htonl (ntohl (mcast->ttl) - 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  data packet, ttl: %u\n",
                ntohl (mcast->ttl));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  not a data packet, no ttl\n");
  }

  tree_iterate_children (t->tree, &tunnel_send_multicast_iterator, mdata);
  if (mdata->reference_counter == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  no one to send data to\n");
    GNUNET_free (mdata->data);
    GNUNET_free (mdata);
    if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_MESH_MULTICAST)
      t->fwd_queue_n--;
  }
  else
  {
    mdata->total_out = mdata->reference_counter;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " sending a multicast packet done\n");
  return;
}


/**
 * Increase the SKIP value of all peers that
 * have not received a unicast message.
 *
 * @param cls Closure (ID of the peer that HAS received the message).
 * @param key ID of the neighbor.
 * @param value Information about the neighbor.
 *
 * @return GNUNET_YES to keep iterating.
 */
static int
tunnel_add_skip (void *cls,
                 const struct GNUNET_HashCode * key,
                 void *value)
{
  struct GNUNET_PeerIdentity *neighbor = cls;
  struct MeshTunnelChildInfo *cinfo = value;

  /* TODO compare only pointers? key == neighbor? */
  if (0 == memcmp (&neighbor->hashPubKey, key, sizeof (struct GNUNET_HashCode)))
  {
    return GNUNET_YES;
  }
  cinfo->skip++;
  return GNUNET_YES;
}


/**
 * @brief Get neighbor's Flow Control information.
 *
 * Retrieves the MeshTunnelChildInfo containing Flow Control data about a direct
 * descendant of the local node in a certain tunnel.
 * If the info is not yet there (recently created path), creates the data struct
 * and inserts it into the tunnel info, initialized to the current tunnel ACK
 * values.
 *
 * @param t Tunnel related.
 * @param peer Neighbor whose Flow Control info is needed.
 *
 * @return Neighbor's Flow Control info.
 */
static struct MeshTunnelChildInfo *
tunnel_get_neighbor_fc (struct MeshTunnel *t,
                        const struct GNUNET_PeerIdentity *peer)
{
  struct MeshTunnelChildInfo *cinfo;

  if (NULL == t->children_fc)
    return NULL;

  cinfo = GNUNET_CONTAINER_multihashmap_get (t->children_fc,
                                             &peer->hashPubKey);
  if (NULL == cinfo)
  {
    uint32_t delta;

    cinfo = GNUNET_malloc (sizeof (struct MeshTunnelChildInfo));
    cinfo->id = GNUNET_PEER_intern (peer);
    cinfo->skip = t->fwd_pid;
    cinfo->t = t;

    delta = t->nobuffer ? 1 : INITIAL_WINDOW_SIZE;
    cinfo->fwd_ack = t->fwd_pid + delta;
    cinfo->bck_ack = delta;
    cinfo->bck_pid = -1;

    cinfo->fc_poll = GNUNET_SCHEDULER_NO_TASK;
    cinfo->fc_poll_time = GNUNET_TIME_UNIT_SECONDS;

    cinfo->send_buffer =
        GNUNET_malloc (sizeof(struct MeshPeerQueue *) * t->fwd_queue_max);

    GNUNET_assert (GNUNET_OK ==
      GNUNET_CONTAINER_multihashmap_put (t->children_fc,
                                         &peer->hashPubKey,
                                         cinfo,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  }
  return cinfo;
}


/**
 * Get the Flow Control info of a client.
 * 
 * @param t Tunnel on which to look.
 * @param c Client whose ACK to get.
 * 
 * @return ACK value.
 */
static struct MeshTunnelClientInfo *
tunnel_get_client_fc (struct MeshTunnel *t,
                      struct MeshClient *c)
{
  unsigned int i;

  for (i = 0; i < t->nclients; i++)
  {
    if (t->clients[i] != c)
      continue;
    return &t->clients_fc[i];
  }
  GNUNET_assert (0);
  return NULL; // avoid compiler / coverity complaints
}


/**
 * Iterator to get the appropiate ACK value from all children nodes.
 *
 * @param cls Closue (tunnel).
 * @param id Id of the child node.
 */
static void
tunnel_get_child_fwd_ack (void *cls,
                          GNUNET_PEER_Id id)
{
  struct GNUNET_PeerIdentity peer_id;
  struct MeshTunnelChildInfo *cinfo;
  struct MeshTunnelChildIteratorContext *ctx = cls;
  struct MeshTunnel *t = ctx->t;
  uint32_t ack;

  GNUNET_PEER_resolve (id, &peer_id);
  cinfo = tunnel_get_neighbor_fc (t, &peer_id);
  ack = cinfo->fwd_ack;

  ctx->nchildren++;
  if (GNUNET_NO == ctx->init)
  {
    ctx->max_child_ack = ack;
    ctx->init = GNUNET_YES;
  }

  if (GNUNET_YES == t->speed_min)
  {
    ctx->max_child_ack = ctx->max_child_ack > ack ? ack : ctx->max_child_ack;
  }
  else
  {
    ctx->max_child_ack = ctx->max_child_ack > ack ? ctx->max_child_ack : ack;
  }

}


/**
 * Get the maximum PID allowed to transmit to any
 * tunnel child of the local peer, depending on the tunnel
 * buffering/speed settings.
 *
 * @param t Tunnel.
 *
 * @return Maximum PID allowed (uint32 MAX), -1LL if node has no children.
 */
static int64_t
tunnel_get_children_fwd_ack (struct MeshTunnel *t)
{
  struct MeshTunnelChildIteratorContext ctx;
  ctx.t = t;
  ctx.max_child_ack = 0;
  ctx.nchildren = 0;
  ctx.init = GNUNET_NO;
  tree_iterate_children (t->tree, tunnel_get_child_fwd_ack, &ctx);

  if (0 == ctx.nchildren)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "  tunnel has no children, no FWD ACK\n");
    return -1LL;
  }

  if (GNUNET_YES == t->nobuffer && GMC_is_pid_bigger(ctx.max_child_ack, t->fwd_pid))
    ctx.max_child_ack = t->fwd_pid + 1; // Might overflow, it's ok.

  return (int64_t) ctx.max_child_ack;
}


/**
 * Set the FWD ACK value of a client in a particular tunnel.
 * 
 * @param t Tunnel affected.
 * @param c Client whose ACK to set.
 * @param ack ACK value.
 */
static void
tunnel_set_client_fwd_ack (struct MeshTunnel *t,
                           struct MeshClient *c, 
                           uint32_t ack)
{
  unsigned int i;

  for (i = 0; i < t->nclients; i++)
  {
    if (t->clients[i] != c)
      continue;
    t->clients_fc[i].fwd_ack = ack;
    return;
  }
  GNUNET_break (0);
}


/**
 * Get the highest ACK value of all clients in a particular tunnel,
 * according to the buffering/speed settings.
 * 
 * @param t Tunnel on which to look.
 * 
 * @return Corresponding ACK value (max uint32_t).
 *         If no clients are suscribed, -1LL.
 */
static int64_t
tunnel_get_clients_fwd_ack (struct MeshTunnel *t)
{
  unsigned int i;
  int64_t ack;

  if (0 == t->nclients)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  tunnel has no clients, no FWD ACK\n");
    return -1LL;
  }

  for (ack = -1LL, i = 0; i < t->nclients; i++)
  {
    if (-1LL == ack ||
        (GNUNET_YES == t->speed_min &&
         GNUNET_YES == GMC_is_pid_bigger (ack, t->clients_fc[i].fwd_ack)) ||
        (GNUNET_NO == t->speed_min &&
         GNUNET_YES == GMC_is_pid_bigger (t->clients_fc[i].fwd_ack, ack)))
    {
      ack = t->clients_fc[i].fwd_ack;
    }
  }

  if (GNUNET_YES == t->nobuffer && GMC_is_pid_bigger(ack, t->fwd_pid))
    ack = (uint32_t) t->fwd_pid + 1; // Might overflow, it's ok.

  return (uint32_t) ack;
}


/**
 * Get the current fwd ack value for a tunnel, taking in account the tunnel
 * mode and the status of all children nodes.
 *
 * @param t Tunnel.
 *
 * @return Maximum PID allowed.
 */
static uint32_t
tunnel_get_fwd_ack (struct MeshTunnel *t)
{
  uint32_t ack;
  uint32_t count;
  uint32_t buffer_free;
  int64_t child_ack;
  int64_t client_ack;

  count = t->fwd_pid - t->skip;
  buffer_free = t->fwd_queue_max - t->fwd_queue_n;
  child_ack = tunnel_get_children_fwd_ack (t);
  client_ack = tunnel_get_clients_fwd_ack (t);
  if (GNUNET_YES == t->nobuffer)
  {
    ack = count;
    if (-1LL == child_ack)
      child_ack = client_ack;
    if (-1LL == child_ack)
    {
      GNUNET_break (0);
      client_ack = child_ack = ack;
    }
  }
  else
  {
    ack = count + buffer_free; // Overflow? OK!
  }
  if (-1LL == child_ack)
  {
    // Node has no children, child_ack AND core buffer are irrelevant.
    if (-1LL == client_ack) // No children AND no clients? Not good!
    {
      GNUNET_STATISTICS_update (stats, "# mesh acks with no target",
                                1, GNUNET_NO);

    }
    return (uint32_t) client_ack;
  }
  if (-1LL == client_ack)
  {
    client_ack = ack;
  }
  if (GNUNET_YES == t->speed_min)
  {
    ack = GMC_min_pid ((uint32_t) child_ack, ack);
    ack = GMC_min_pid ((uint32_t) client_ack, ack);
  }
  else
  {
    ack = GMC_max_pid ((uint32_t) child_ack, ack);
    ack = GMC_max_pid ((uint32_t) client_ack, ack);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "c %u, bf %u, ch %lld, cl %lld, ACK: %u\n",
              count, buffer_free, child_ack, client_ack, ack);
  return ack;
}


/**
 * Build a local ACK message and send it to a local client.
 * 
 * @param t Tunnel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param ack Value of the ACK.
 */
static void
send_local_ack (struct MeshTunnel *t, struct MeshClient *c, uint32_t ack)
{
  struct GNUNET_MESH_LocalAck msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.tunnel_id = htonl (t->owner == c ? t->local_tid : t->local_tid_dest);
  msg.max_pid = htonl (ack); 
  GNUNET_SERVER_notification_context_unicast(nc,
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
send_ack (struct MeshTunnel *t, struct GNUNET_PeerIdentity *peer,  uint32_t ack)
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
 * Notify a the owner of a tunnel about how many more
 * payload packages will we accept on a given tunnel.
 *
 * @param t Tunnel on which to send the ACK.
 */
static void
tunnel_send_client_fwd_ack (struct MeshTunnel *t)
{
  uint32_t ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending client FWD ACK on tunnel %X\n",
              t->local_tid);

  ack = tunnel_get_fwd_ack (t);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ack %u\n", ack);
  if (t->last_fwd_ack == ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " same as last, not sending!\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " sending!\n");
  t->last_fwd_ack = ack;
  send_local_ack (t, t->owner, ack);
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
 */
static void
tunnel_send_fwd_ack (struct MeshTunnel *t, uint16_t type)
{
  struct GNUNET_PeerIdentity id;
  uint32_t ack;

  if (NULL != t->owner)
  {
    tunnel_send_client_fwd_ack (t);
    return;
  }
  /* Is it after unicast / multicast retransmission? */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ACK due to FWD DATA retransmission\n");
      if (GNUNET_YES == t->nobuffer)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, nobuffer\n");
        return;
      }
      break;
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK:
      break;
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      t->force_ack = GNUNET_YES;
      break;
    default:
      GNUNET_break (0);
  }

  /* Check if we need to transmit the ACK */
  if (t->fwd_queue_max > t->fwd_queue_n * 4 &&
      GMC_is_pid_bigger(t->last_fwd_ack, t->fwd_pid) &&
      GNUNET_NO == t->force_ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer free\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  t->qmax: %u, t->qn: %u\n",
                t->fwd_queue_max, t->fwd_queue_n);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  t->pid: %u, t->ack: %u\n",
                t->fwd_pid, t->last_fwd_ack);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  ack = tunnel_get_fwd_ack (t);

  /* If speed_min and not all children have ack'd, dont send yet */
  if (ack == t->last_fwd_ack && GNUNET_NO == t->force_ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not ready\n");
    return;
  }

  t->last_fwd_ack = ack;
  GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &id);
  send_ack (t, &id, ack);
  debug_fwd_ack++;
  t->force_ack = GNUNET_NO;
}


/**
 * Iterator to send a child node a BCK ACK to allow him to send more
 * to_origin data.
 *
 * @param cls Closure (tunnel).
 * @param id Id of the child node.
 */
static void
tunnel_send_child_bck_ack (void *cls,
                           GNUNET_PEER_Id id)
{
  struct MeshTunnel *t = cls;
  struct MeshTunnelChildInfo *cinfo;
  struct GNUNET_PeerIdentity peer;
  uint32_t ack;

  GNUNET_PEER_resolve (id, &peer);
  cinfo = tunnel_get_neighbor_fc (t, &peer);
  ack = cinfo->bck_pid + t->bck_queue_max - t->bck_queue_n;

  if (cinfo->bck_ack == ack && GNUNET_NO == t->force_ack)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "    Not sending ACK, not needed\n");
    return;
  }
  cinfo->bck_ack = ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "    Sending BCK ACK %u (last sent: %u)\n",
              ack, cinfo->bck_ack);
  send_ack (t, &peer, ack);
}


/**
 * @brief Send BCK ACKs to clients to allow them more to_origin traffic
 * 
 * Iterates over all clients and sends BCK ACKs to the ones that need it.
 *
 * FIXME fc: what happens if we have 2 clients but q_size is 1?
 *           - implement a size 1 buffer in each client_fc AND children_fc
 *           to hold at least 1 message per "child".
 *             problem: violates no buffer policy
 *           - ack 0 and make "children" poll for transmission slots
 *             problem: big overhead, extra latency even in low traffic
 *                      settings
 * 
 * @param t Tunnel on which to send the BCK ACKs.
 */
static void
tunnel_send_clients_bck_ack (struct MeshTunnel *t)
{
  unsigned int i;
  unsigned int tunnel_delta;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Sending BCK ACK to clients\n");

  tunnel_delta = t->bck_queue_max - t->bck_queue_n;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   tunnel delta: %u\n", tunnel_delta);

  /* Find client whom to allow to send to origin (with lowest buffer space) */
  for (i = 0; i < t->nclients; i++)
  {
    struct MeshTunnelClientInfo *clinfo;
    unsigned int delta;

    clinfo = &t->clients_fc[i];
    delta = clinfo->bck_ack - clinfo->bck_pid;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    client %u delta: %u\n",
         t->clients[i]->id, delta);

    if ((GNUNET_NO == t->nobuffer && tunnel_delta > delta) ||
        (GNUNET_YES == t->nobuffer && 0 == delta))
    {
      uint32_t ack;

      ack = clinfo->bck_pid;
      ack += t->nobuffer ? 1 : tunnel_delta;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "    sending ack to client %u: %u\n",
                  t->clients[i]->id, ack);
      send_local_ack (t, t->clients[i], ack);
      clinfo->bck_ack = ack;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "    not sending ack to client %u (td %u, d %u)\n",
                  t->clients[i]->id, tunnel_delta, delta);
    }
  }
}


/**
 * Send an ACK informing the children nodes and destination clients about
 * the available buffer space.
 * If buffering is off, send only on behalf of root (can be self).
 * If buffering is on, send when sent to predecessor and buffer space is free.
 * Note that although the name is bck_ack, the BCK mean backwards *traffic*,
 * the ACK itself goes "forward" (towards children/clients).
 * 
 * @param t Tunnel on which to send the ACK.
 * @param type Type of message that triggered the ACK transmission.
 */
static void
tunnel_send_bck_ack (struct MeshTunnel *t, uint16_t type)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending BCK ACK on tunnel %u [%u] due to %s\n",
              t->id.oid, t->id.tid, GNUNET_MESH_DEBUG_M2S(type));
  /* Is it after data to_origin retransmission? */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      if (GNUNET_YES == t->nobuffer)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "    Not sending ACK, nobuffer\n");
        return;
      }
      break;
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK:
      break;
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      t->force_ack = GNUNET_YES;
      break;
    default:
      GNUNET_break (0);
  }

  tunnel_send_clients_bck_ack (t);
  tree_iterate_children (t->tree, &tunnel_send_child_bck_ack, t);
  t->force_ack = GNUNET_NO;
}


/**
 * @brief Re-initiate traffic to this peer if necessary.
 *
 * Check if there is traffic queued towards this peer
 * and the core transmit handle is NULL (traffic was stalled).
 * If so, call core tmt rdy.
 *
 * @param cls Closure (unused)
 * @param peer_id Short ID of peer to which initiate traffic.
 */
static void
peer_unlock_queue(void *cls, GNUNET_PEER_Id peer_id)
{
  struct MeshPeerInfo *peer;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerQueue *q;
  size_t size;

  peer = peer_info_get_short(peer_id);
  if (NULL != peer->core_transmit)
    return;

  q = queue_get_next(peer);
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
 * @brief Allow transmission of FWD traffic on this tunnel
 *
 * Check if there is traffic queued towards any children
 * and the core transmit handle is NULL, and if so, call core tmt rdy.
 *
 * @param t Tunnel on which to unlock FWD traffic.
 */
static void
tunnel_unlock_fwd_queues (struct MeshTunnel *t)
{
  if (0 == t->fwd_queue_n)
    return;

  tree_iterate_children (t->tree, &peer_unlock_queue, NULL);
}


/**
 * @brief Allow transmission of BCK traffic on this tunnel
 *
 * Check if there is traffic queued towards the root of the tree
 * and the core transmit handle is NULL, and if so, call core tmt rdy.
 *
 * @param t Tunnel on which to unlock BCK traffic.
 */
static void
tunnel_unlock_bck_queue (struct MeshTunnel *t)
{
  if (0 == t->bck_queue_n)
    return;

  peer_unlock_queue(NULL, tree_get_predecessor(t->tree));
}


/**
 * Send a message to all peers in this tunnel that the tunnel is no longer
 * valid.
 *
 * @param t The tunnel whose peers to notify.
 * @param parent ID of the parent, in case the tree is already destroyed.
 */
static void
tunnel_send_destroy (struct MeshTunnel *t, GNUNET_PEER_Id parent)
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
  if (tree_count_children(t->tree) > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  sending multicast to children\n");
    tunnel_send_multicast (t, &msg.header);
  }
  if (0 == parent)
    parent = tree_get_predecessor (t->tree);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  parent: %u\n", parent);
  if (0 == parent)
    return;

  GNUNET_PEER_resolve (parent, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending back to %s\n",
              GNUNET_i2s (&id));
  send_prebuilt_message (&msg.header, &id, t);
}


/**
 * Cancel all transmissions towards a neighbor that belong to a certain tunnel.
 *
 * @param cls Closure (Tunnel which to cancel).
 * @param neighbor_id Short ID of the neighbor to whom cancel the transmissions.
 */
static void
tunnel_cancel_queues (void *cls, GNUNET_PEER_Id neighbor_id)
{
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerQueue *pq;
  struct MeshPeerQueue *next;

  peer_info = peer_info_get_short (neighbor_id);
  for (pq = peer_info->queue_head; NULL != pq; pq = next)
  {
    next = pq->next;
    if (pq->tunnel == t)
    {
      if (GNUNET_MESSAGE_TYPE_MESH_MULTICAST == pq->type ||
          GNUNET_MESSAGE_TYPE_MESH_UNICAST == pq->type ||
          GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == pq->type)
      {
        // Should have been removed on destroy children
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
  struct GNUNET_HashCode hash;
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
    GNUNET_break (0);
    r = GNUNET_SYSERR;
  }

  if (NULL != c)
  {
    GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multihashmap_remove (c->own_tunnels, &hash, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
  }

  GNUNET_CRYPTO_hash (&t->local_tid_dest, sizeof (MESH_TunnelNumber), &hash);
  for (i = 0; i < t->nclients; i++)
  {
    c = t->clients[i];
    if (GNUNET_YES !=
          GNUNET_CONTAINER_multihashmap_remove (c->incoming_tunnels, &hash, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
  }
  for (i = 0; i < t->nignore; i++)
  {
    c = t->ignore[i];
    if (GNUNET_YES !=
          GNUNET_CONTAINER_multihashmap_remove (c->ignore_tunnels, &hash, t))
    {
      GNUNET_break (0);
      r = GNUNET_SYSERR;
    }
  }

  (void) GNUNET_CONTAINER_multihashmap_remove (incoming_tunnels, &hash, t);
  GNUNET_free_non_null (t->clients);
  GNUNET_free_non_null (t->ignore);
  GNUNET_free_non_null (t->clients_fc);

  if (NULL != t->peers)
  {
    GNUNET_CONTAINER_multihashmap_iterate (t->peers, &peer_info_delete_tunnel,
                                           t);
    GNUNET_CONTAINER_multihashmap_destroy (t->peers);
  }

  GNUNET_CONTAINER_multihashmap_iterate (t->children_fc,
                                         &tunnel_destroy_child,
                                         t);
  GNUNET_CONTAINER_multihashmap_destroy (t->children_fc);
  t->children_fc = NULL;

  tree_iterate_children (t->tree, &tunnel_cancel_queues, t);
  tree_destroy (t->tree);

  if (NULL != t->regex_search)
    GNUNET_REGEX_search_cancel (t->regex_search->search_handle);
  if (NULL != t->dht_get_type)
    GNUNET_DHT_get_stop (t->dht_get_type);
  if (GNUNET_SCHEDULER_NO_TASK != t->timeout_task)
    GNUNET_SCHEDULER_cancel (t->timeout_task);
  if (GNUNET_SCHEDULER_NO_TASK != t->path_refresh_task)
    GNUNET_SCHEDULER_cancel (t->path_refresh_task);

  n_tunnels--;
  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  GNUNET_free (t);
  return r;
}

#define TUNNEL_DESTROY_EMPTY_TIME GNUNET_TIME_UNIT_MILLISECONDS

/**
 * Tunnel is empty: destroy it.
 * 
 * @param cls Closure (Tunnel).
 * @param tc TaskContext. 
 */
static void
tunnel_destroy_empty_delayed (void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;

  t->delayed_destroy = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (0 != t->nclients ||
      0 != tree_count_children (t->tree))
    return;

  #if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (t->id.oid, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "executing destruction of empty tunnel %s [%X]\n",
                GNUNET_i2s (&id), t->id.tid);
  }
  #endif

  tunnel_send_destroy (t, 0);
  if (0 == t->pending_messages)
    tunnel_destroy (t);
  else
    t->destroy = GNUNET_YES;
}


/**
 * Schedule tunnel destruction if is empty and no new traffic comes in a time.
 * 
 * @param t Tunnel to destroy if empty.
 */
static void
tunnel_destroy_empty (struct MeshTunnel *t)
{
  if (GNUNET_SCHEDULER_NO_TASK != t->delayed_destroy || 
      0 != t->nclients ||
      0 != tree_count_children (t->tree))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u %u %u\n",
                t->delayed_destroy, t->nclients, tree_count_children(t->tree));
    return;
  }

  #if MESH_DEBUG
  {
    struct GNUNET_PeerIdentity id;

    GNUNET_PEER_resolve (t->id.oid, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "scheduling destruction of empty tunnel %s [%X]\n",
                GNUNET_i2s (&id), t->id.tid);
  }
  #endif

  t->delayed_destroy =
      GNUNET_SCHEDULER_add_delayed (TUNNEL_DESTROY_EMPTY_TIME,
                                    &tunnel_destroy_empty_delayed,
                                    t);
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
  t->fwd_queue_max = (max_msgs_queue / max_tunnels) + 1;
  t->bck_queue_max = t->fwd_queue_max;
  t->tree = tree_new (owner);
  t->owner = client;
  t->fwd_pid = (uint32_t) -1; // Next (expected) = 0
  t->bck_pid = (uint32_t) -1; // Next (expected) = 0
  t->bck_ack = INITIAL_WINDOW_SIZE - 1;
  t->last_fwd_ack = INITIAL_WINDOW_SIZE - 1;
  t->local_tid = local;
  t->children_fc = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
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
    GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (client->own_tunnels, &hash, t,
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
 * Callback when removing children from a tunnel tree. Notify owner.
 *
 * @param cls Closure (tunnel).
 * @param peer_id Short ID of the peer deleted.
 */
void
tunnel_child_removed (void *cls, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnel *t = cls;

  client_notify_peer_disconnected (t->owner, t, peer_id);
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
  int r;

  r = tree_del_peer (t->tree, peer, &tunnel_child_removed, t);
  if (GNUNET_NO == r)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Tunnel %u [%u] has no more nodes\n",
                t->id.oid, t->id.tid);
  }
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
 * @return GNUNET_OK, keep iterating.
 */
static int
tunnel_destroy_iterator (void *cls,
                         const struct GNUNET_HashCode * key,
                         void *value)
{
  struct MeshTunnel *t = value;
  struct MeshClient *c = cls;

  send_client_tunnel_disconnect (t, c);
  if (c != t->owner)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %u is destination.\n", c->id);
    tunnel_delete_client (t, c);
    client_delete_tunnel (c, t);
    tunnel_destroy_empty (t);
    return GNUNET_OK;
  }
  tunnel_send_destroy (t, 0);
  t->owner = NULL;
  t->destroy = GNUNET_YES;

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

  t->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_PEER_resolve(t->id.oid, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Tunnel %s [%X] timed out. Destroying.\n",
              GNUNET_i2s(&id), t->id.tid);
  send_clients_tunnel_destroy (t);
  tunnel_destroy (t);
}

/**
 * Resets the tunnel timeout. Starts it if no timeout was running.
 *
 * @param t Tunnel whose timeout to reset.
 *
 * TODO use heap to improve efficiency of scheduler.
 */
static void
tunnel_reset_timeout (struct MeshTunnel *t)
{
  if (GNUNET_SCHEDULER_NO_TASK != t->timeout_task)
    GNUNET_SCHEDULER_cancel (t->timeout_task);
  t->timeout_task =
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
  struct MeshPathInfo *info = cls;
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct MeshTunnel *t = info->t;
  struct MeshPeerPath *p = info->path;
  size_t size_needed;
  uint32_t opt;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATE PATH sending...\n");
  size_needed =
      sizeof (struct GNUNET_MESH_ManipulatePath) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  msg = (struct GNUNET_MESH_ManipulatePath *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE);
  msg->tid = ntohl (t->id.tid);

  opt = 0;
  if (GNUNET_YES == t->speed_min)
    opt |= MESH_TUNNEL_OPT_SPEED_MIN;
  if (GNUNET_YES == t->nobuffer)
    opt |= MESH_TUNNEL_OPT_NOBUFFER;
  msg->opt = htonl(opt);
  msg->reserved = 0;

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
 * Fill the core buffer 
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
    GNUNET_break (0);
    return 0;
  }
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
                  " multicast, payload type %s\n",
                  GNUNET_MESH_DEBUG_M2S (ntohs (mh->type)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  " multicast, payload size %u\n", ntohs (mh->size));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " type %s\n",
                  GNUNET_MESH_DEBUG_M2S (ntohs (mh->type)));
    }
  }
#endif
  data_descriptor_decrement_rc (info->mesh_data);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "freeing info...\n");
  GNUNET_free (info);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "return %u\n", total_size);
  return total_size;
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
  struct MeshTransmissionDescriptor *info = cls;
  struct GNUNET_MESH_PathACK *msg = buf;

  GNUNET_assert (NULL != info);
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
  struct MeshTransmissionDescriptor *dd;
  struct MeshPathInfo *path_info;
  struct MeshTunnelChildInfo *cinfo;
  struct GNUNET_PeerIdentity id;
  unsigned int i;
  unsigned int max;

  if (GNUNET_YES == clear_cls)
  {
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "   cancelling TUNNEL_DESTROY\n");
        GNUNET_break (GNUNET_YES == queue->tunnel->destroy);
        /* fall through */
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "   prebuilt message\n");
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "   type %s\n",
                    GNUNET_MESH_DEBUG_M2S(queue->type));
        dd = queue->cls;
        data_descriptor_decrement_rc (dd->mesh_data);
        break;
      case GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   type create path\n");
        path_info = queue->cls;
        path_destroy (path_info->path);
        break;
      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "   type %s unknown!\n",
                    GNUNET_MESH_DEBUG_M2S(queue->type));
    }
    GNUNET_free_non_null (queue->cls);
  }
  GNUNET_CONTAINER_DLL_remove (queue->peer->queue_head,
                               queue->peer->queue_tail,
                               queue);

  /* Delete from child_fc in the appropiate tunnel */
  max = queue->tunnel->fwd_queue_max;
  GNUNET_PEER_resolve (queue->peer->id, &id);
  cinfo = tunnel_get_neighbor_fc (queue->tunnel, &id);
  if (NULL != cinfo)
  {
    for (i = 0; i < cinfo->send_buffer_n; i++)
    {
      unsigned int i2;
      i2 = (cinfo->send_buffer_start + i) % max;
      if (cinfo->send_buffer[i2] == queue)
      {
        /* Found corresponding entry in the send_buffer. Move all others back. */
        unsigned int j;
        unsigned int j2;
        unsigned int j3;

        for (j = i, j2 = 0, j3 = 0; j < cinfo->send_buffer_n - 1; j++)
        {
          j2 = (cinfo->send_buffer_start + j) % max;
          j3 = (cinfo->send_buffer_start + j + 1) % max;
          cinfo->send_buffer[j2] = cinfo->send_buffer[j3];
        }

        cinfo->send_buffer[j3] = NULL;
        cinfo->send_buffer_n--;
      }
    }
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
  struct MeshTunnel *t;
  struct MeshTransmissionDescriptor *info;
  struct MeshTunnelChildInfo *cinfo;
  struct GNUNET_MESH_Unicast *ucast;
  struct GNUNET_MESH_ToOrigin *to_orig;
  struct GNUNET_MESH_Multicast *mcast;
  struct GNUNET_PeerIdentity id;
  uint32_t pid;
  uint32_t ack;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   selecting message\n");
  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    t = q->tunnel;
    info = q->cls;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*********     %s\n",
                GNUNET_MESH_DEBUG_M2S(q->type));
    switch (q->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
        ucast = (struct GNUNET_MESH_Unicast *) info->mesh_data->data;
        pid = ntohl (ucast->pid);
        GNUNET_PEER_resolve (info->peer->id, &id);
        cinfo = tunnel_get_neighbor_fc(t, &id);
        ack = cinfo->fwd_ack;
        break;
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
        to_orig = (struct GNUNET_MESH_ToOrigin *) info->mesh_data->data;
        pid = ntohl (to_orig->pid);
        ack = t->bck_ack;
        break;
      case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
        mcast = (struct GNUNET_MESH_Multicast *) info->mesh_data->data;
        if (GNUNET_MESSAGE_TYPE_MESH_MULTICAST != ntohs(mcast->header.type)) 
        {
          // Not a multicast payload: multicast control traffic (destroy, etc)
          return q;
        }
        pid = ntohl (mcast->pid);
        GNUNET_PEER_resolve (info->peer->id, &id);
        cinfo = tunnel_get_neighbor_fc(t, &id);
        ack = cinfo->fwd_ack;
        break;
      default:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "*********   OK!\n");
        return q;
    }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "*********     ACK: %u, PID: %u\n",
                    ack, pid);
    if (GNUNET_NO == GMC_is_pid_bigger(pid, ack))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*********   OK!\n");
      return q;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*********     NEXT!\n");
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*********   nothing found\n");
  return NULL;
}


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
queue_send (void *cls, size_t size, void *buf)
{
    struct MeshPeerInfo *peer = cls;
    struct GNUNET_MessageHeader *msg;
    struct MeshPeerQueue *queue;
    struct MeshTunnel *t;
    struct MeshTunnelChildInfo *cinfo;
    struct GNUNET_PeerIdentity dst_id;
    size_t data_size;

    peer->core_transmit = NULL;
    cinfo = NULL;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "********* Queue send\n");
    queue = queue_get_next (peer);

    /* Queue has no internal mesh traffic nor sendable payload */
    if (NULL == queue)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   not ready, return\n");
      if (NULL == peer->queue_head)
        GNUNET_break (0); // Should've been canceled
      return 0;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   not empty\n");

    GNUNET_PEER_resolve (peer->id, &dst_id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "*********   towards %s\n",
                GNUNET_i2s(&dst_id));
    /* Check if buffer size is enough for the message */
    if (queue->size > size)
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "*********   not enough room, reissue\n");
        peer->core_transmit =
            GNUNET_CORE_notify_transmit_ready (core_handle,
                                               0,
                                               0,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &dst_id,
                                               queue->size,
                                               &queue_send,
                                               peer);
        return 0;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   size ok\n");

    t = queue->tunnel;
    GNUNET_assert (0 < t->pending_messages);
    t->pending_messages--;
    if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == queue->type)
    {
      t->fwd_queue_n--;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*********   unicast: t->q (%u/%u)\n",
                  t->fwd_queue_n, t->fwd_queue_max);
    }
    else if (GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == queue->type)
    {
      t->bck_queue_n--;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   to origin\n");
    }

    /* Fill buf */
    switch (queue->type)
    {
      case 0:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN:
      case GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY:
      case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "*********   raw: %s\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
        /* Fall through */
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
        data_size = send_core_data_raw (queue->cls, size, buf);
        msg = (struct GNUNET_MessageHeader *) buf;
        switch (ntohs (msg->type)) // Type of preconstructed message
        {
          case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
            tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_UNICAST);
            break;
          case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
            tunnel_send_bck_ack (t, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN);
            break;
          default:
              break;
        }
        break;
      case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   multicast\n");
        {
          struct MeshTransmissionDescriptor *info = queue->cls;

          if ((1 == info->mesh_data->reference_counter
              && GNUNET_YES == t->speed_min)
              ||
              (info->mesh_data->total_out == info->mesh_data->reference_counter
              && GNUNET_NO == t->speed_min))
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "*********   considered sent\n");
            t->fwd_queue_n--;
          }
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "*********   NOT considered sent yet\n");
            t->pending_messages++;
          }
        }
        data_size = send_core_data_multicast(queue->cls, size, buf);
        tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_MULTICAST);
        break;
      case GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   path create\n");
        data_size = send_core_path_create (queue->cls, size, buf);
        break;
      case GNUNET_MESSAGE_TYPE_MESH_PATH_ACK:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   path ack\n");
        data_size = send_core_path_ack (queue->cls, size, buf);
        break;
      case GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   path keepalive\n");
        data_size = send_core_data_multicast (queue->cls, size, buf);
        break;
      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "*********   type unknown: %u\n",
                    queue->type);
        data_size = 0;
    }
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
      case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
      case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
        cinfo = tunnel_get_neighbor_fc (t, &dst_id);
        if (cinfo->send_buffer[cinfo->send_buffer_start] != queue)
        {
          GNUNET_break (0);
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "at pos %u (%p) != %p\n",
                      cinfo->send_buffer_start,
                      cinfo->send_buffer[cinfo->send_buffer_start],
                      queue);
        }
        if (cinfo->send_buffer_n > 0)
        {
          cinfo->send_buffer[cinfo->send_buffer_start] = NULL;
          cinfo->send_buffer_n--;
          cinfo->send_buffer_start++;
          cinfo->send_buffer_start %= t->fwd_queue_max;
        }
        else
        {
          GNUNET_break (0);
        }
        break;
      default:
        break;
    }

    /* Free queue, but cls was freed by send_core_* */
    queue_destroy (queue, GNUNET_NO);

    if (GNUNET_YES == t->destroy && 0 == t->pending_messages)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********  destroying tunnel!\n");
      tunnel_destroy (t);
    }

    /* If more data in queue, send next */
    queue = queue_get_next(peer);
    if (NULL != queue)
    {
        struct GNUNET_PeerIdentity id;

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   more data!\n");
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
    else
    {
      if (NULL != peer->queue_head)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "*********   %s stalled\n",
                    GNUNET_i2s(&my_full_id));
        if (NULL == cinfo)
          cinfo = tunnel_get_neighbor_fc (t, &dst_id);
        // FIXME unify bck/fwd structures, bck does not have cinfo right now
        if (NULL != cinfo && GNUNET_SCHEDULER_NO_TASK == cinfo->fc_poll)
        {
          cinfo->fc_poll = GNUNET_SCHEDULER_add_delayed (cinfo->fc_poll_time,
                                                         &tunnel_poll, cinfo);
        }
      }
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*********   return %d\n", data_size);
    return data_size;
}


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
           struct MeshPeerInfo *dst, struct MeshTunnel *t)
{
  struct MeshPeerQueue *queue;
  struct MeshTunnelChildInfo *cinfo;
  struct GNUNET_PeerIdentity id;
  unsigned int *max;
  unsigned int *n;
  unsigned int i;

  n = NULL;
  if (GNUNET_MESSAGE_TYPE_MESH_UNICAST == type ||
      GNUNET_MESSAGE_TYPE_MESH_MULTICAST == type)
  {
    n = &t->fwd_queue_n;
    max = &t->fwd_queue_max;
  }
  else if (GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN == type)
  {
    n = &t->bck_queue_n;
    max = &t->bck_queue_max;
  }
  if (NULL != n)
  {
    if (*n >= *max)
    {
      GNUNET_break(0);
      GNUNET_STATISTICS_update(stats,
                               "# messages dropped (buffer full)",
                               1, GNUNET_NO);
      return; // Drop message
    }
    (*n)++;
  }
  queue = GNUNET_malloc (sizeof (struct MeshPeerQueue));
  queue->cls = cls;
  queue->type = type;
  queue->size = size;
  queue->peer = dst;
  queue->tunnel = t;
  GNUNET_CONTAINER_DLL_insert_tail (dst->queue_head, dst->queue_tail, queue);
  GNUNET_PEER_resolve (dst->id, &id);
  if (NULL == dst->core_transmit)
  {
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
  if (NULL == n) // Is this internal mesh traffic?
    return;

  // It's payload, keep track of buffer per peer.
  cinfo = tunnel_get_neighbor_fc(t, &id);
  i = (cinfo->send_buffer_start + cinfo->send_buffer_n) % t->fwd_queue_max;
  if (NULL != cinfo->send_buffer[i])
  {
    GNUNET_break (cinfo->send_buffer_n == t->fwd_queue_max); // aka i == start
    queue_destroy (cinfo->send_buffer[cinfo->send_buffer_start], GNUNET_YES);
    cinfo->send_buffer_start++;
    cinfo->send_buffer_start %= t->fwd_queue_max;
  }
  else
  {
    cinfo->send_buffer_n++;
  }
  cinfo->send_buffer[i] = queue;
  if (cinfo->send_buffer_n > t->fwd_queue_max)
  {
    GNUNET_break (0);
    cinfo->send_buffer_n = t->fwd_queue_max;
  }
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
  struct GNUNET_HashCode hash;
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
  if (NULL == t) // FIXME only for INCOMING tunnels?
  {
    uint32_t opt;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Creating tunnel\n");
    t = tunnel_new (GNUNET_PEER_intern (pi), tid, NULL, 0);
    if (NULL == t)
    {
      // FIXME notify failure
      return GNUNET_OK;
    }
    opt = ntohl (msg->opt);
    t->speed_min = (0 != (opt & MESH_TUNNEL_OPT_SPEED_MIN)) ?
                   GNUNET_YES : GNUNET_NO;
    if (0 != (opt & MESH_TUNNEL_OPT_NOBUFFER))
    {
      t->nobuffer = GNUNET_YES;
      t->last_fwd_ack = t->fwd_pid + 1;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  speed_min: %d, nobuffer:%d\n",
                t->speed_min, t->nobuffer);

    if (GNUNET_YES == t->nobuffer)
    {
      t->bck_queue_max = 1;
      t->fwd_queue_max = 1;
    }

    // FIXME only assign a local tid if a local client is interested (on demand)
    while (NULL != tunnel_get_incoming (next_local_tid))
      next_local_tid = (next_local_tid + 1) | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
    t->local_tid_dest = next_local_tid++;
    next_local_tid = next_local_tid | GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
    // FIXME end

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
    tunnel_destroy (t);
    return GNUNET_OK;
  }
  path_add_to_peers (path, GNUNET_NO);
  tunnel_add_path (t, path, own_pos);
  if (own_pos == size - 1)
  {
    /* It is for us! Send ack. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    peer_info_add_path_to_origin (orig_peer_info, path, GNUNET_NO);
    if (NULL == t->peers)
    {
      /* New tunnel! Notify clients on first payload message. */
      t->peers = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
    }
    GNUNET_break (GNUNET_SYSERR !=
                  GNUNET_CONTAINER_multihashmap_put (t->peers,
                                                     &my_full_id.hashPubKey,
                                                     peer_info_get
                                                     (&my_full_id),
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
    send_path_ack (t);
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
    send_prebuilt_message (message, &pi[own_pos + 1], t);
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
  GNUNET_PEER_Id parent;
  GNUNET_PEER_Id pid;

  msg = (struct GNUNET_MESH_TunnelDestroy *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a TUNNEL DESTROY packet from %s\n",
              GNUNET_i2s (peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  for tunnel %s [%u]\n",
              GNUNET_i2s (&msg->oid), ntohl (msg->tid));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  /* Check signature */
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
  parent = tree_get_predecessor (t->tree);
  pid = GNUNET_PEER_search (peer);
  if (pid != parent)
  {
    unsigned int nc;

    tree_del_peer (t->tree, pid, &tunnel_child_removed, t);
    nc = tree_count_children (t->tree);
    if (nc > 0 || NULL != t->owner || t->nclients > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "still in use: %u cl, %u ch\n",
                  t->nclients, nc);
      return GNUNET_OK;
    }
  }
  if (t->local_tid_dest >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    /* Tunnel was incoming, notify clients */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "INCOMING TUNNEL %X %X\n",
                t->local_tid, t->local_tid_dest);
    send_clients_tunnel_destroy (t);
  }
  tunnel_send_destroy (t, parent);
  t->destroy = GNUNET_YES;
  // TODO: add timeout to destroy the tunnel anyway
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
  struct GNUNET_PeerIdentity *neighbor;
  struct MeshTunnelChildInfo *cinfo;
  struct MeshTunnel *t;
  GNUNET_PEER_Id dest_id;
  uint32_t pid;
  uint32_t ttl;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got a unicast packet from %s\n",
              GNUNET_i2s (peer));
  /* Check size */
  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Unicast) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Unicast *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " of type %s\n",
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
  pid = ntohl (msg->pid);
  if (t->fwd_pid == pid)
  {
    GNUNET_STATISTICS_update (stats, "# duplicate PID drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                " Already seen pid %u, DROPPING!\n", pid);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " pid %u not seen yet, forwarding\n", pid);
  }

  t->skip += (pid - t->fwd_pid) - 1;
  t->fwd_pid = pid;

  if (GMC_is_pid_bigger (pid, t->last_fwd_ack))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited unicast", 1, GNUNET_NO);
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received PID %u, ACK %u\n",
                pid, t->last_fwd_ack);
    return GNUNET_OK;
  }

  tunnel_reset_timeout (t);
  dest_id = GNUNET_PEER_search (&msg->destination);
  if (dest_id == myid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  it's for us! sending to clients...\n");
    GNUNET_STATISTICS_update (stats, "# unicast received", 1, GNUNET_NO);
    send_subscribed_clients (message, &msg[1].header, t);
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_UNICAST);
    return GNUNET_OK;
  }
  ttl = ntohl (msg->ttl);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ttl);
  if (ttl == 0)
  {
    GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  not for us, retransmitting...\n");

  neighbor = tree_get_first_hop (t->tree, dest_id);
  cinfo = tunnel_get_neighbor_fc (t, neighbor);
  cinfo->fwd_pid = pid;
  GNUNET_CONTAINER_multihashmap_iterate (t->children_fc,
                                         &tunnel_add_skip,
                                         &neighbor);
  if (GNUNET_YES == t->nobuffer &&
      GNUNET_YES == GMC_is_pid_bigger (pid, cinfo->fwd_ack))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited unicast", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "  %u > %u\n", pid, cinfo->fwd_ack);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  send_prebuilt_message (message, neighbor, t);
  GNUNET_STATISTICS_update (stats, "# unicast forwarded", 1, GNUNET_NO);
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
  uint32_t pid;

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
    GNUNET_STATISTICS_update (stats, "# data on unknown tunnel", 1, GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  pid = ntohl (msg->pid);
  if (t->fwd_pid == pid)
  {
    /* already seen this packet, drop */
    GNUNET_STATISTICS_update (stats, "# duplicate PID drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " Already seen pid %u, DROPPING!\n", pid);
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " pid %u not seen yet, forwarding\n", pid);
  }
  t->skip += (pid - t->fwd_pid) - 1;
  t->fwd_pid = pid;
  tunnel_reset_timeout (t);

  /* Transmit to locally interested clients */
  if (NULL != t->peers &&
      GNUNET_CONTAINER_multihashmap_contains (t->peers, &my_full_id.hashPubKey))
  {
    GNUNET_STATISTICS_update (stats, "# multicast received", 1, GNUNET_NO);
    send_subscribed_clients (message, &msg[1].header, t);
    tunnel_send_fwd_ack(t, GNUNET_MESSAGE_TYPE_MESH_MULTICAST);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ntohl (msg->ttl));
  if (ntohl (msg->ttl) == 0)
  {
    GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    return GNUNET_OK;
  }
  GNUNET_STATISTICS_update (stats, "# multicast forwarded", 1, GNUNET_NO);
  tunnel_send_multicast (t, message);
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
  struct MeshTunnelChildInfo *cinfo;
  GNUNET_PEER_Id predecessor;
  size_t size;
  uint32_t pid;

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " of type %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (msg[1].header.type)));
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  pid = ntohl (msg->pid);

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    GNUNET_STATISTICS_update (stats, "# data on unknown tunnel", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received to_origin with PID %u on unknown tunnel %s [%u]\n",
                pid, GNUNET_i2s (&msg->oid), ntohl (msg->tid));
    return GNUNET_OK;
  }

  cinfo = tunnel_get_neighbor_fc(t, peer);
  if (NULL == cinfo)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }

  if (cinfo->bck_pid == pid)
  {
    /* already seen this packet, drop */
    GNUNET_STATISTICS_update (stats, "# duplicate PID drops BCK", 1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " Already seen pid %u, DROPPING!\n", pid);
    tunnel_send_bck_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    return GNUNET_OK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " pid %u not seen yet, forwarding\n", pid);
  cinfo->bck_pid = pid;

  if (NULL != t->owner)
  {
    char cbuf[size];
    struct GNUNET_MESH_ToOrigin *copy;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  it's for us! sending to clients...\n");
    /* TODO signature verification */
    memcpy (cbuf, message, size);
    copy = (struct GNUNET_MESH_ToOrigin *) cbuf;
    copy->tid = htonl (t->local_tid);
    t->bck_pid++;
    copy->pid = htonl (t->bck_pid);
    GNUNET_STATISTICS_update (stats, "# to origin received", 1, GNUNET_NO);
    GNUNET_SERVER_notification_context_unicast (nc, t->owner->handle,
                                                &copy->header, GNUNET_NO);
    tunnel_send_bck_ack (t, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN);
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
  predecessor = tree_get_predecessor (t->tree);
  if (0 == predecessor)
  {
    if (GNUNET_YES == t->destroy)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "to orig received on a dying tunnel %s [%X]\n",
                  GNUNET_i2s (&msg->oid), ntohl(msg->tid));
      return GNUNET_OK;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "unknown to origin at %s\n",
                GNUNET_i2s (&my_full_id));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "from peer %s\n",
                GNUNET_i2s (peer));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "for tunnel %s [%X]\n",
                GNUNET_i2s (&msg->oid), ntohl(msg->tid));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "current tree:\n");
    tree_debug (t->tree);
    return GNUNET_OK;
  }
  GNUNET_PEER_resolve (predecessor, &id);
  send_prebuilt_message (message, &id, t);
  GNUNET_STATISTICS_update (stats, "# to origin forwarded", 1, GNUNET_NO);

  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic point-to-point acks.
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
handle_mesh_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message,
                 const struct GNUNET_ATS_Information *atsi,
                 unsigned int atsi_count)
{
  struct GNUNET_MESH_ACK *msg;
  struct MeshTunnel *t;
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
  if (tree_get_predecessor(t->tree) != GNUNET_PEER_search(peer))
  {
    struct MeshTunnelChildInfo *cinfo;

    debug_bck_ack++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    cinfo = tunnel_get_neighbor_fc (t, peer);
    cinfo->fwd_ack = ack;
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    tunnel_unlock_fwd_queues (t);
    if (GNUNET_SCHEDULER_NO_TASK != cinfo->fc_poll)
    {
      GNUNET_SCHEDULER_cancel (cinfo->fc_poll);
      cinfo->fc_poll = GNUNET_SCHEDULER_NO_TASK;
      cinfo->fc_poll_time = GNUNET_TIME_UNIT_SECONDS;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    t->bck_ack = ack;
    tunnel_send_bck_ack (t, GNUNET_MESSAGE_TYPE_MESH_ACK);
    tunnel_unlock_bck_queue (t);
  }
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic point-to-point ack polls.
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
handle_mesh_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi,
                  unsigned int atsi_count)
{
  struct GNUNET_MESH_Poll *msg;
  struct MeshTunnel *t;

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
  if (tree_get_predecessor(t->tree) != GNUNET_PEER_search(peer))
  {
    struct MeshTunnelChildInfo *cinfo;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from FWD\n");
    cinfo = tunnel_get_neighbor_fc (t, peer);
    cinfo->bck_ack = cinfo->fwd_pid; // mark as ready to send
    tunnel_send_bck_ack (t, GNUNET_MESSAGE_TYPE_MESH_POLL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  from BCK\n");
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_POLL);
  }

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

  peer_info = peer_info_get (&msg->peer_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by peer %s\n",
              GNUNET_i2s (&msg->peer_id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n",
              GNUNET_i2s (peer));

  if (NULL != t->regex_search && t->regex_search->peer == peer_info->id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connect_by_string completed, stopping search\n");
    regex_cancel_search (t->regex_search);
    t->regex_search = NULL;
  }

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
  send_prebuilt_message (message, &id, t);
  return GNUNET_OK;
}


/**
 * Core handler for mesh keepalives.
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
handle_mesh_keepalive (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_ATS_Information *atsi,
                       unsigned int atsi_count)
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

  tunnel_reset_timeout (t);

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  tunnel_send_multicast (t, message);
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
  {&handle_mesh_tunnel_destroy, GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY,
   sizeof (struct GNUNET_MESH_TunnelDestroy)},
  {&handle_mesh_data_unicast, GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_mesh_data_multicast, GNUNET_MESSAGE_TYPE_MESH_MULTICAST, 0},
  {&handle_mesh_keepalive, GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE,
    sizeof (struct GNUNET_MESH_TunnelKeepAlive)},
  {&handle_mesh_data_to_orig, GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
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
deregister_app (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap *h = cls;
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (h, key, value));
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
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;
  struct GNUNET_MESH_TunnelKeepAlive *msg;
  size_t size = sizeof (struct GNUNET_MESH_TunnelKeepAlive);
  char cbuf[size];

  t->path_refresh_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
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
  tunnel_send_multicast (t, &msg->header);

  t->path_refresh_task =
      GNUNET_SCHEDULER_add_delayed (refresh_path_time, &path_refresh, t);
  tunnel_reset_timeout(t);
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
                    const struct GNUNET_HashCode * key,
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
                      const struct GNUNET_HashCode * key,
                      const struct GNUNET_PeerIdentity *get_path,
                      unsigned int get_path_length,
                      const struct GNUNET_PeerIdentity *put_path,
                      unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                      size_t size, const void *data)
{
  const struct PBlock *pb = data;
  const struct GNUNET_PeerIdentity *pi = &pb->id;
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *p;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got type DHT result!\n");
  if (size != sizeof (struct PBlock))
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohl(pb->type) != t->type)
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
  unsigned int i;

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
      GNUNET_CONTAINER_multihashmap_iterate (c->apps, &deregister_app, c->apps);
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
    for (i = 0; i < c->n_regex; i++)
    {
      GNUNET_free (c->regexes[i].regex);
      if (NULL != c->regexes[i].h)
	GNUNET_REGEX_announce_cancel (c->regexes[i].h);
    }
    GNUNET_free_non_null (c->regexes);
    if (GNUNET_SCHEDULER_NO_TASK != c->regex_announce_task)
      GNUNET_SCHEDULER_cancel (c->regex_announce_task);
    next = c->next;
    GNUNET_CONTAINER_DLL_remove (clients, clients_tail, c);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  CLIENT FREE at %p\n", c);
    GNUNET_free (c);
    GNUNET_STATISTICS_update (stats, "# clients", -1, GNUNET_NO);
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
    struct GNUNET_HashCode hc;

    c->apps = GNUNET_CONTAINER_multihashmap_create (napps, GNUNET_NO);
    for (i = 0; i < napps; i++)
    {
      at = ntohl (a[i]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  app type: %u\n", at);
      GNUNET_CRYPTO_hash (&at, sizeof (at), &hc);
      /* store in clients hashmap */
      GNUNET_CONTAINER_multihashmap_put (c->apps, &hc, (void *) (long) at,
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
    struct GNUNET_HashCode hc;

    t = (uint16_t *) & a[napps];
    c->types = GNUNET_CONTAINER_multihashmap_create (ntypes, GNUNET_NO);
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
  c->own_tunnels = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  c->incoming_tunnels = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  c->ignore_tunnels = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_STATISTICS_update (stats, "# clients", 1, GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new client processed\n");
}


/**
 * Handler for clients announcing available services by a regular expression.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, which includes messages the client wants
 */
static void
handle_local_announce_regex (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MESH_RegexAnnounce *msg;
  struct MeshRegexDescriptor rd;
  struct MeshClient *c;
  char *regex;
  size_t len;
  size_t offset;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "announce regex started\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  msg = (const struct GNUNET_MESH_RegexAnnounce *) message;

  len = ntohs (message->size) - sizeof(struct GNUNET_MESH_RegexAnnounce);
  if (NULL != c->partial_regex)
  {
    regex = c->partial_regex;
    offset = strlen (c->partial_regex);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  continuation, already have %u bytes\n",
                offset);
  }
  else
  {
    regex = NULL;
    offset = 0;
  }

  regex = GNUNET_realloc (regex, offset + len + 1);
  memcpy (&regex[offset], &msg[1], len);
  regex[offset + len] = '\0';
  if (0 == ntohs (msg->last))
  {
    c->partial_regex = regex;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  not ended, stored %u bytes for later\n",
                len);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  rd.regex = regex;
  rd.compression = ntohs (msg->compression_characters);
  rd.h = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  length %u\n", len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  regex %s\n", regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  compr %u\n", ntohs (rd.compression));
  GNUNET_array_append (c->regexes, c->n_regex, rd);
  c->partial_regex = NULL;
  if (GNUNET_SCHEDULER_NO_TASK == c->regex_announce_task)
  {
    c->regex_announce_task = GNUNET_SCHEDULER_add_now (&regex_announce, c);
  }
  else
  {
    regex_put (&rd);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "announce regex processed\n");
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

  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_TunnelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  t_msg = (struct GNUNET_MESH_TunnelMessage *) message;
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

  while (NULL != tunnel_get_by_pi (myid, next_tid))
    next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  t = tunnel_new (myid, next_tid++, c, tid);
  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Tunnel creation failed.\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  next_tid = next_tid & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CREATED TUNNEL %s [%x] (%x)\n",
              GNUNET_i2s (&my_full_id), t->id.tid, t->local_tid);
  t->peers = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);

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
  if (c != t->owner || tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    client_ignore_tunnel (c, t);
    tunnel_destroy_empty (t);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  send_client_tunnel_disconnect (t, c);
  client_delete_tunnel (c, t);

  /* Don't try to ACK the client about the tunnel_destroy multicast packet */
  t->owner = NULL;
  tunnel_send_destroy (t, 0);
  t->destroy = GNUNET_YES;
  /* The tunnel will be destroyed when the last message is transmitted. */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}


/**
 * Handler for requests of seeting tunnel's speed.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_tunnel_speed (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelMessage *tunnel_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a SPEED request from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
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
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  tunnel %X not found\n", tid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  switch (ntohs(message->type))
  {
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MIN:
          t->speed_min = GNUNET_YES;
          break;
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MAX:
          t->speed_min = GNUNET_NO;
          break;
      default:
          GNUNET_break (0);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for requests of seeting tunnel's buffering policy.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_local_tunnel_buffer (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_TunnelMessage *tunnel_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a BUFFER request from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  tunnel %X not found\n", tid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  switch (ntohs(message->type))
  {
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_BUFFER:
          t->nobuffer = GNUNET_NO;
          break;
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_NOBUFFER:
          t->nobuffer = GNUNET_YES;
          break;
      default:
          GNUNET_break (0);
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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
 * Handler for blacklist requests of peers in a tunnel
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 * 
 * FIXME implement DHT block bloomfilter
 */
static void
handle_local_blacklist (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PeerControl *peer_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a PEER BLACKLIST request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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

  GNUNET_array_append(t->blacklisted, t->nblacklisted,
                      GNUNET_PEER_intern(&peer_msg->peer));
}


/**
 * Handler for unblacklist requests of peers in a tunnel
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 */
static void
handle_local_unblacklist (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PeerControl *peer_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;
  GNUNET_PEER_Id pid;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a PEER UNBLACKLIST request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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

  /* if peer is not known, complain */
  pid = GNUNET_PEER_search (&peer_msg->peer);
  if (0 == pid)
  {
    GNUNET_break (0);
    return;
  }

  /* search and remove from list */
  for (i = 0; i < t->nblacklisted; i++)
  {
    if (t->blacklisted[i] == pid)
    {
      t->blacklisted[i] = t->blacklisted[t->nblacklisted - 1];
      GNUNET_array_grow (t->blacklisted, t->nblacklisted, t->nblacklisted - 1);
      return;
    }
  }

  /* if peer hasn't been blacklisted, complain */
  GNUNET_break (0);
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
  struct GNUNET_HashCode hash;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got connect by type request\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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
      GNUNET_DHT_get_start (dht_handle, 
                            GNUNET_BLOCK_TYPE_MESH_PEER_BY_TYPE,
                            &hash,
                            dht_replication_level,
                            GNUNET_DHT_RO_RECORD_ROUTE |
                            GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                            NULL, 0,
                            &dht_get_type_handler, t);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}


/**
 * Handler for connection requests to new peers by a string service description.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, which includes messages the client wants
 */
static void
handle_local_connect_by_string (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectPeerByString *msg;
  struct MeshRegexSearchInfo *info;
  struct MeshTunnel *t;
  struct MeshClient *c;
  MESH_TunnelNumber tid;
  const char *string;
  size_t size;
  size_t len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connect by string started\n");
  msg = (struct GNUNET_MESH_ConnectPeerByString *) message;
  size = htons (message->size);

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof(struct GNUNET_MESH_ConnectPeerByString) >= size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Tunnel exists? */
  tid = ntohl (msg->tunnel_id);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  on tunnel %s [%u]\n",
              GNUNET_i2s(&my_full_id),
              t->id.tid);

  /* Only one connect_by_string allowed at the same time! */
  /* FIXME: allow more, return handle at api level to cancel, document */
  if (NULL != t->regex_search)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Find string itself */
  len = size - sizeof(struct GNUNET_MESH_ConnectPeerByString);
  string = (const char *) &msg[1];

  info = GNUNET_malloc (sizeof (struct MeshRegexSearchInfo));
  info->t = t;
  info->description = GNUNET_strndup (string, len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   string: %s\n", info->description);

  t->regex_search = info;

  info->search_handle = GNUNET_REGEX_search (dht_handle,
                                             info->description,
                                             &regex_found_handler, info,
                                             stats);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connect by string processed\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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

  /* PID should be as expected */
  if (ntohl (data_msg->pid) != t->fwd_pid + 1)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Unicast PID, expected %u, got %u\n",
              t->fwd_pid + 1, ntohl (data_msg->pid));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Ok, everything is correct, send the message
   * (pretend we got it from a mesh peer)
   */
  {
    /* Work around const limitation */
    char buf[ntohs (message->size)] GNUNET_ALIGN;
    struct GNUNET_MESH_Unicast *copy;

    copy = (struct GNUNET_MESH_Unicast *) buf;
    memcpy (buf, data_msg, size);
    copy->oid = my_full_id;
    copy->tid = htonl (t->id.tid);
    copy->ttl = htonl (default_ttl);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    handle_mesh_data_unicast (NULL, &my_full_id, &copy->header, NULL, 0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "receive done OK\n");
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
  struct MeshTunnelClientInfo *clinfo;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a ToOrigin request from a client!\n");
  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  on tunnel %X\n", tid);
  if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  t = tunnel_get_by_local_id (c, tid);
  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tunnel %X unknown.\n", tid);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /*  It should be sent by someone who has this as incoming tunnel. */
  if (GNUNET_NO == client_knows_tunnel (c, t))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* PID should be as expected */
  clinfo = tunnel_get_client_fc (t, c);
  if (ntohl (data_msg->pid) != clinfo->bck_pid + 1)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "To Origin PID, expected %u, got %u\n",
                clinfo->bck_pid + 1,
                ntohl (data_msg->pid));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  clinfo->bck_pid++;

  /* Ok, everything is correct, send the message
   * (pretend we got it from a mesh peer)
   */
  {
    char buf[ntohs (message->size)] GNUNET_ALIGN;
    struct GNUNET_MESH_ToOrigin *copy;

    /* Work around const limitation */
    copy = (struct GNUNET_MESH_ToOrigin *) buf;
    memcpy (buf, data_msg, size);
    GNUNET_PEER_resolve (t->id.oid, &copy->oid);
    copy->tid = htonl (t->id.tid);
    copy->ttl = htonl (default_ttl);
    copy->pid = htonl (t->bck_pid + 1);

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

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
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tunnel %X unknown.\n", tid);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
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

  /* PID should be as expected */
  if (ntohl (data_msg->pid) != t->fwd_pid + 1)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Multicast PID, expected %u, got %u\n",
              t->fwd_pid + 1, ntohl (data_msg->pid));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  {
    char buf[ntohs (message->size)] GNUNET_ALIGN;
    struct GNUNET_MESH_Multicast *copy;

    copy = (struct GNUNET_MESH_Multicast *) buf;
    memcpy (buf, message, ntohs (message->size));
    copy->oid = my_full_id;
    copy->tid = htonl (t->id.tid);
    copy->ttl = htonl (default_ttl);
    GNUNET_assert (ntohl (copy->pid) == (t->fwd_pid + 1));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  calling generic handler...\n");
    handle_mesh_data_multicast (client, &my_full_id, &copy->header, NULL, 0);
  }

  GNUNET_SERVER_receive_done (t->owner->handle, GNUNET_OK);
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
  uint32_t ack;

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

  ack = ntohl (msg->max_pid);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ack %u\n", ack);

  /* Does client own tunnel? I.E: Is this an ACK for BCK traffic? */
  if (NULL != t->owner && t->owner->handle == client)
  {
    /* The client owns the tunnel, ACK is for data to_origin, send BCK ACK. */
    t->bck_ack = ack;
    tunnel_send_bck_ack(t, GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  }
  else
  {
    /* The client doesn't own the tunnel, this ACK is for FWD traffic. */
    tunnel_set_client_fwd_ack (t, c, ack);
    tunnel_send_fwd_ack (t, GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
}


/**
 * Iterator over all peers to send a monitoring client info about a tunnel.
 *
 * @param cls Closure (message being built).
 * @param key Key (hashed tunnel ID, unused).
 * @param value Peer info.
 *
 * @return GNUNET_YES, to keep iterating.
 */
static int
monitor_peers_iterator (void *cls,
                        const struct GNUNET_HashCode * key,
                        void *value)
{
  struct GNUNET_MESH_LocalMonitor *msg = cls;
  struct GNUNET_PeerIdentity *id;
  struct MeshPeerInfo *info = value;

  id = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_PEER_resolve (info->id, &id[msg->npeers]);
  msg->npeers++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "*    sending info about peer %s [%u]\n",
              GNUNET_i2s (&id[msg->npeers - 1]), msg->npeers);

  return GNUNET_YES;
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
  uint32_t npeers;
  
  npeers = GNUNET_CONTAINER_multihashmap_size (t->peers);
  msg = GNUNET_malloc (sizeof(struct GNUNET_MESH_LocalMonitor) +
  npeers * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_PEER_resolve(t->id.oid, &msg->owner);
  msg->tunnel_id = htonl (t->id.tid);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor) +
  npeers * sizeof (struct GNUNET_PeerIdentity));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);
  msg->npeers = 0;
  (void) GNUNET_CONTAINER_multihashmap_iterate (t->peers,
                                                monitor_peers_iterator,
                                                msg);
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "*  sending info about tunnel %s [%u] (%u peers)\n",
              GNUNET_i2s (&msg->owner), t->id.tid, npeers);
  
  if (msg->npeers != npeers)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Get tunnels fail: size %u - iter %u\n",
                npeers, msg->npeers);
  }
  
    msg->npeers = htonl (npeers);
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
 * Data needed to build a Monitor_Tunnel message.
 */
struct MeshMonitorTunnelContext
{
  /**
   * Partial message, including peer count.
   */
  struct GNUNET_MESH_LocalMonitor *msg;

  /**
   * Hashmap with positions: peer->position.
   */
  struct GNUNET_CONTAINER_MultiHashMap *lookup;

  /**
   * Index of the parent of each peer in the message, realtive to the absolute
   * order in the array (can be in a previous message).
   */
  uint32_t parents[1024];

  /**
   * Peers visited so far in the tree, aka position of the current peer.
   */
  unsigned int npeers;

  /**
   * Client requesting the info.
   */
  struct MeshClient *c;
};


/**
 * Send a client a message about the structure of a tunnel.
 *
 * @param ctx Context of the tunnel iteration, with info regarding the state
 *            of the execution and the number of peers visited for this message.
 */
static void
send_client_tunnel_info (struct MeshMonitorTunnelContext *ctx)
{
  struct GNUNET_MESH_LocalMonitor *resp = ctx->msg;
  struct GNUNET_PeerIdentity *pid;
  unsigned int *parent;
  size_t size;

  size = sizeof (struct GNUNET_MESH_LocalMonitor);
  size += (sizeof (struct GNUNET_PeerIdentity) + sizeof (int)) * resp->npeers;
  resp->header.size = htons (size);
  pid = (struct GNUNET_PeerIdentity *) &resp[1];
  parent = (unsigned int *) &pid[resp->npeers];
  memcpy (parent, ctx->parents, sizeof(uint32_t) * resp->npeers);
  GNUNET_SERVER_notification_context_unicast (nc, ctx->c->handle,
                                              &resp->header, GNUNET_NO);
}

/**
 * Iterator over a tunnel tree to build a message containing all peers
 * the in the tunnel, including relay nodes.
 *
 * @param cls Closure (pointer to pointer of message being built).
 * @param peer Short ID of a peer.
 * @param parent Short ID of the @c peer 's parent.
 */
static void
tunnel_tree_iterator (void *cls,
                      GNUNET_PEER_Id peer,
                      GNUNET_PEER_Id parent)
{
  struct MeshMonitorTunnelContext *ctx = cls;
  struct GNUNET_MESH_LocalMonitor *msg;
  struct GNUNET_PeerIdentity *pid;
  struct GNUNET_PeerIdentity ppid;

  msg = ctx->msg;
  pid = (struct GNUNET_PeerIdentity *) &msg[1];
  GNUNET_PEER_resolve (peer, &pid[msg->npeers]);
  GNUNET_CONTAINER_multihashmap_put (ctx->lookup,
                                     &pid[msg->npeers].hashPubKey,
                                     (void *) (long) ctx->npeers,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  GNUNET_PEER_resolve (parent, &ppid);
  ctx->parents[msg->npeers] =
      htonl ((long) GNUNET_CONTAINER_multihashmap_get (ctx->lookup,
                                                       &ppid.hashPubKey));

  ctx->npeers++;
  msg->npeers++;

  if (sizeof (struct GNUNET_MESH_LocalMonitor) +
      (msg->npeers + 1) *
      (sizeof (struct GNUNET_PeerIdentity) + sizeof (uint32_t))
      > USHRT_MAX)
  {
    send_client_tunnel_info (ctx);
    msg->npeers = 0;
  }
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
  struct MeshMonitorTunnelContext ctx;
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
    /* We don't know the tunnel */
    struct GNUNET_MESH_LocalMonitor warn;

    warn = *msg;
    warn.npeers = htonl (UINT_MAX);
    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &warn.header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Initialize context */
  resp = GNUNET_malloc (USHRT_MAX); /* avoid realloc'ing on each step */
  *resp = *msg;
  resp->npeers = 0;
  ctx.msg = resp;
  ctx.lookup = GNUNET_CONTAINER_multihashmap_create (4 * t->peers_total,
                                                     GNUNET_YES);
  ctx.c = c;

  /* Collect and send information */
  tree_iterate_all (t->tree, &tunnel_tree_iterator, &ctx);
  send_client_tunnel_info (&ctx);

  /* Free context */
  GNUNET_CONTAINER_multihashmap_destroy (ctx.lookup);
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
  {&handle_local_announce_regex, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_ANNOUNCE_REGEX, 0},
  {&handle_local_tunnel_create, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_destroy, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_speed, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MIN,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_speed, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MAX,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_buffer, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_BUFFER,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_tunnel_buffer, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_NOBUFFER,
   sizeof (struct GNUNET_MESH_TunnelMessage)},
  {&handle_local_connect_add, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_del, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_blacklist, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_BLACKLIST,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_unblacklist, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_UNBLACKLIST,
   sizeof (struct GNUNET_MESH_PeerControl)},
  {&handle_local_connect_by_type, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE,
   sizeof (struct GNUNET_MESH_ConnectPeerByType)},
  {&handle_local_connect_by_string, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_STRING, 0},
  {&handle_local_unicast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_UNICAST, 0},
  {&handle_local_to_origin, NULL,
   GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN, 0},
  {&handle_local_multicast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_MULTICAST, 0},
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
  static int i = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core init\n");
  core_handle = server;
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
    GNUNET_SCHEDULER_shutdown (); // Try gracefully
    if (10 < i++)
      GNUNET_abort(); // Try harder
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
  GNUNET_STATISTICS_update (stats, "# peers", 1, GNUNET_NO);
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
  peer_info_remove_path (pi, pi->id, myid);
  if (myid == pi->id)
  {
    DEBUG_CONN ("     (self)\n");
  }
  GNUNET_STATISTICS_update (stats, "# peers", -1, GNUNET_NO);
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
  if (NULL != keygen)
  {
    GNUNET_CRYPTO_rsa_key_create_stop (keygen);
    keygen = NULL;
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
  if (GNUNET_SCHEDULER_NO_TASK != announce_applications_task)
  {
    GNUNET_SCHEDULER_cancel (announce_applications_task);
    announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shut down\n");
}


/**
 * Callback for hostkey read/generation
 *
 * @param cls Closure (Configuration handle).
 * @param pk the private key
 * @param emsg error message
 */
static void
key_generation_cb (void *cls,
                   struct GNUNET_CRYPTO_RsaPrivateKey *pk,
                   const char *emsg)
{
  const struct GNUNET_CONFIGURATION_Handle *c = cls;
  struct MeshPeerInfo *peer;
  struct MeshPeerPath *p;

  keygen = NULL;  
  if (NULL == pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Mesh service could not access hostkey: %s. Exiting.\n"),
                emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_private_key = pk;
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
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
  
  if (core_handle == NULL)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  next_tid = 0;
  next_local_tid = GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;


  GNUNET_SERVER_add_handlers (server_handle, client_handlers);
  nc = GNUNET_SERVER_notification_context_create (server_handle, 1);
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
  GNUNET_SERVER_resume (server_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh service running\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting to run\n");
  server_handle = server;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c, "GNUNETD", "HOSTKEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "hostkey");
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
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "APP_ANNOUNCE_TIME",
                                           &app_announce_time))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "mesh", "app announce time");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "APP_ANNOUNCE_TIME %llu ms\n", 
	      app_announce_time.rel_value);
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
  incoming_tunnels = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  peers = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  applications = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  types = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (NULL == dht_handle)
  {
    GNUNET_break (0);
  }
  stats = GNUNET_STATISTICS_create ("mesh", c);

  GNUNET_SERVER_suspend (server_handle);
  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  keygen = GNUNET_CRYPTO_rsa_key_create_start (keyfile,
                                               &key_generation_cb,
                                               (void *) c);
  GNUNET_free (keyfile);
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Mesh for peer [%s] FWD ACKs %u, BCK ACKs %u\n",
              GNUNET_i2s(&my_full_id), debug_fwd_ack, debug_bck_ack);

  return ret;
}
