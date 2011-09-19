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
 * - add connection confirmation message
 * - handle trnsmt_rdy return values
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

#define MESH_DEBUG              GNUNET_YES

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

  if (GNUNET_SCHEDULER_REASON_SHUTDOWN == tc->reason)
  {
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: %s\n", s);
}
#endif

/* TODO: move into configuration file */
#define CORE_QUEUE_SIZE         10
#define LOCAL_QUEUE_SIZE        100
#define REFRESH_PATH_TIME       GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    300)
#define APP_ANNOUNCE_TIME       GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    5)

#define ID_ANNOUNCE_TIME        GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_SECONDS,\
                                    5)

/******************************************************************************/
/************************        ENUMERATIONS      ****************************/
/******************************************************************************/

/**
 * All the states a peer participating in a tunnel can be in.
 */
enum MeshPeerState
{
    /**
     * Peer only retransmits traffic, is not a final destination
     */
  MESH_PEER_RELAY,

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


/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a possible path to reach a single peer
 */
struct MeshPeerPath
{

    /**
     * Linked list
     */
  struct MeshPeerPath *next;
  struct MeshPeerPath *prev;

    /**
     * List of all the peers that form the path from origin to target.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of peers (hops) in the path
     */
  unsigned int length;

};


/**
 * Node of path tree for a tunnel
 */
struct MeshTunnelPathNode
{
  /**
   * Tunnel this node belongs to (and therefore tree)
   */
  struct MeshTunnel *t;

  /**
   * Peer this node describes
   */
  struct MeshPeerInfo *peer;

  /**
   * Parent node in the tree
   */
  struct MeshTunnelPathNode *parent;

  /**
   * Array of children
   */
  struct MeshTunnelPathNode *children;

  /**
   * Number of children
   */
  unsigned int nchildren;

    /**
     * Status of the peer in the tunnel
     */
  enum MeshPeerState status;
};


/**
 * Tree to reach all peers in the tunnel
 */
struct MeshTunnelPath
{
  /**
   * Tunnel this path belongs to
   */
  struct MeshTunnel *t;

  /**
   * Root node of peer tree
   */
  struct MeshTunnelPathNode *root;

  /**
   * Node that represents our position in the tree (for non local tunnels)
   */
  struct MeshTunnelPathNode *me;

  /**
   * Cache of all peers and the first hop to them.
   * Indexed by Peer_Identity, contains a pointer to the PeerInfo of 1st hop.
   */
  struct GNUNET_CONTAINER_MultiHashMap *first_hops;

};


/** FWD declaration */
struct MeshPeerInfo;

/**
 * Struct containing all info possibly needed to build a package when called
 * back by core.
 */
struct MeshDataDescriptor
{
    /** ID of the tunnel this packet travels in */
  struct MESH_TunnelID *origin;

    /** Ultimate destination of the packet */
  GNUNET_PEER_Id destination;

    /** Number of identical messages sent to different hops (multicast) */
  unsigned int copies;

    /** Size of the data */
  size_t size;

    /** Client that asked for the transmission, if any */
  struct GNUNET_SERVER_Client *client;

    /** Who was is message being sent to */
  struct MeshPeerInfo *peer;

    /** Which handler was used to request the transmission */
  unsigned int handler_n;

  /* Data at the end */
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
     * Handles to stop queued transmissions for this peer
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit[CORE_QUEUE_SIZE];

    /**
     * Pointer to info stuctures used as cls for queued transmissions
     */
  struct MeshDataDescriptor *infos[CORE_QUEUE_SIZE];

    /**
     * Array of tunnels this peer participates in
     * (most probably a small amount, therefore not a hashmap)
     * When the path to the peer changes, notify these tunnels to let them
     * re-adjust their path trees.
     */
  struct MeshTunnel **tunnels;

    /**
     * Number of tunnels above
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
     * Last time the tunnel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnel, indexed by PeerIdentity -> (MeshPeerInfo)
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
  struct MeshClient *client;

    /**
     * Messages ready to transmit
     */
  struct MeshQueue *queue_head;
  struct MeshQueue *queue_tail;

  /**
   * Tunnel paths
   */
  struct MeshTunnelPath *paths;

  /**
   * Task to keep the used paths alive
   */
  GNUNET_SCHEDULER_TaskIdentifier path_refresh_task;
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
   * Destination peer
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
     * Linked list
     */
  struct MeshClient *next;
  struct MeshClient *prev;

    /**
     * Tunnels that belong to this client, indexed by local id
     */
  struct GNUNET_CONTAINER_MultiHashMap *tunnels;

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
     * Used to search peers offering a service
     */
  struct GNUNET_DHT_GetHandle *dht_get_type;

#if MESH_DEBUG
    /**
     * ID of the client, for debug messages
     */
  unsigned int id;
#endif

};

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
 * Peers known, indexed by PeerIdentity (MeshPeerInfo)
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/**
 * Handle to communicate with core
 */
static struct GNUNET_CORE_Handle *core_handle;

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
static struct GNUNET_CRYPTO_RsaPrivateKey* my_private_key;

/**
 * Own public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Tunnel ID for the next created tunnel (global tunnel number)
 */
static MESH_TunnelNumber next_tid;

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

#if MESH_DEBUG
unsigned int next_client_id;
#endif


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
  GNUNET_DHT_put (dht_handle, key, 10U, GNUNET_DHT_RO_RECORD_ROUTE,
                  GNUNET_BLOCK_TYPE_TEST, sizeof (struct GNUNET_PeerIdentity),
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Starting PUT for apps\n");
  GNUNET_CONTAINER_multihashmap_iterate (applications, &announce_application,
                                         NULL);
  announce_applications_task =
      GNUNET_SCHEDULER_add_delayed (APP_ANNOUNCE_TIME, &announce_applications,
                                    cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Finished PUT for apps\n");
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
  GNUNET_DHT_put (dht_handle,   /* DHT handle */
                  &my_full_id.hashPubKey,       /* Key to use */
                  10U,          /* Replication level */
                  GNUNET_DHT_RO_RECORD_ROUTE,   /* DHT options */
                  GNUNET_BLOCK_TYPE_TEST,       /* Block type */
                  0,            /* Size of the data */
                  NULL,         /* Data itself */
                  GNUNET_TIME_absolute_get_forever (),  /* Data expiration */
                  GNUNET_TIME_UNIT_FOREVER_REL, /* Retry time */
#if MESH_DEBUG
                  &mesh_debug, "DHT_put for id completed");
#else
                  NULL,         /* Continuation */
                  NULL);        /* Continuation closure */
#endif
  announce_id_task =
      GNUNET_SCHEDULER_add_delayed (ID_ANNOUNCE_TIME, &announce_id, cls);
}


/**
 * Send keepalive packets for a peer
 *
 * @param cls unused
 * @param tc unused
 *
 * FIXME path
 */
static void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;

//   struct GNUNET_PeerIdentity id;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  /* FIXME implement multicast keepalive. Just an empty multicast packet? */
//   GNUNET_PEER_resolve (path_get_first_hop (path->t, path->peer)->id, &id);
//   GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
//                                      GNUNET_TIME_UNIT_FOREVER_REL, &id,
//                                      sizeof (struct GNUNET_MESH_ManipulatePath)
//                                      +
//                                      (path->path->length *
//                                       sizeof (struct GNUNET_PeerIdentity)),
//                                      &send_core_create_path,
//                                      t);
  t->path_refresh_task =
      GNUNET_SCHEDULER_add_delayed (REFRESH_PATH_TIME, &path_refresh, t);
  return;
}


/******************************************************************************/
/******************      GENERAL HELPER FUNCTIONS      ************************/
/******************************************************************************/

/**
 * Retrieve the MeshPeerInfo stucture associated with the peer, create one
 * and insert it in the appropiate structures if the peer is not known yet.
 *
 * @param peer Identity of the peer
 *
 * @return Existing or newly created peer info
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


#if LATER
/**
 * Destroy the peer_info and free any allocated resources linked to it
 * @param t tunnel the path belongs to
 * @param pi the peer_info to destroy
 * @return GNUNET_OK on success
 */
static int
peer_info_destroy (struct MeshPeerInfo *pi)
{
  GNUNET_HashCode hash;
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (pi->id, &id);
  GNUNET_PEER_change_rc (pi->id, -1);
  GNUNET_CRYPTO_hash (&id, sizeof (struct GNUNET_PeerIdentity), &hash);

  GNUNET_CONTAINER_multihashmap_remove (peers, &hash, pi);
  GNUNET_SCHEDULER_cancel (pi->path_refresh_task);
  GNUNET_free (pi);
  return GNUNET_OK;
}
#endif


/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
static int
path_destroy (struct MeshPeerPath *p)
{
  GNUNET_PEER_decrement_rcs (p->peers, p->length);
  GNUNET_free (p->peers);
  GNUNET_free (p);
  return GNUNET_OK;
}


/**
 * Invert the path
 *
 * @param p the path to invert
 */
static void
path_invert (struct MeshPeerPath *path)
{
  GNUNET_PEER_Id aux;
  unsigned int i;

  for (i = 0; i < path->length / 2; i++)
  {
    aux = path->peers[i];
    path->peers[i] = path->peers[path->length - i - 1];
    path->peers[path->length - i - 1] = aux;
  }
}


/**
 * Find the first peer whom to send a packet to go down this path
 *
 * @param t The tunnel to use
 * @param peer The peerinfo of the peer we are trying to reach
 *
 * @return peerinfo of the peer who is the first hop in the tunnel
 *         NULL on error
 */
static struct MeshPeerInfo *
path_get_first_hop (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer->id, &id);
  return GNUNET_CONTAINER_multihashmap_get (t->paths->first_hops,
                                            &id.hashPubKey);
}


/**
 * Get the length of a path
 *
 * @param path The path to measure, with the local peer at any point of it
 *
 * @return Number of hops to reach destination
 *         UINT_MAX in case the peer is not in the path
 */
static unsigned int
path_get_length (struct MeshPeerPath *path)
{
  unsigned int i;

  if (NULL == path)
    return UINT_MAX;
  for (i = 0; i < path->length; i++)
  {
    if (path->peers[i] == myid)
    {
      return path->length - i;
    }
  }
  return UINT_MAX;
}


/**
 * Get the cost of the path relative to the already built tunnel tree
 *
 * @param t The tunnel to which compare
 * @param path The individual path to reach a peer
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 *
 * TODO: remove dummy implementation, look into the tunnel tree
 */
static unsigned int
path_get_cost (struct MeshTunnel *t, struct MeshPeerPath *path)
{
  return path_get_length (path);
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *
 * TODO: trim the part from origin to us? Add it as path to origin?
 */
static void
path_add_to_peer (struct MeshPeerInfo *peer_info, struct MeshPeerPath *path)
{
  unsigned int l;
  struct MeshPeerPath *aux;

  if (NULL == peer_info || NULL == path)
  {
    GNUNET_break (0);
    return;
  }

  l = path_get_length (path);

  for (aux = peer_info->path_head; aux != NULL; aux = aux->next)
  {
    if (path_get_length (aux) > l)
    {
      GNUNET_CONTAINER_DLL_insert_before (peer_info->path_head,
                                          peer_info->path_tail, aux, path);
    }
  }
  GNUNET_CONTAINER_DLL_insert_tail (peer_info->path_head, peer_info->path_tail,
                                    path);
  return;
}


/**
 * Notify a tunnel that a connection has broken that affects at least
 * some of its peers.
 *
 * @param t Tunnel affected
 * @param peer Peer that (at least) has been affected by the disconnection
 * @param p1 Peer that got disconnected from p2
 * @param p2 Peer that got disconnected from p1
 */
static void
tunnel_notify_connection_broken (struct MeshTunnel *t,
                                 struct MeshPeerInfo *peer, GNUNET_PEER_Id p1,
                                 GNUNET_PEER_Id p2);


/**
 * Remove all paths that rely on a direct connection between p1 and p2
 * from the peer itself and notify all tunnels about it.
 *
 * @param pi PeerInfo of affected peer
 * @param p1 GNUNET_PEER_Id of one peer.
 * @param p2 GNUNET_PEER_Id of another peer that was connected to the first and
 *           no longer is.
 */
static void
path_remove_from_peer (struct MeshPeerInfo *peer, GNUNET_PEER_Id p1,
                       GNUNET_PEER_Id p2)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *aux;
  unsigned int destroyed;
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
    tunnel_notify_connection_broken (peer->tunnels[i], peer, p1, p2);
  }
}


/**
 * Add the path to the origin peer and update the path used to reach it in case
 * this is the shortest.
 * The path is given in peer_info -> destination, therefore we turn the path
 * upside down first.
 *
 * @param peer_info Peer to add the path to, being the origin of the path.
 * @param path New path to add after being inversed.
 */
static void
path_add_to_origin (struct MeshPeerInfo *peer_info, struct MeshPeerPath *path)
{
  path_invert(path);
  path_add_to_peer (peer_info, path);
}


/**
 * Build a PeerPath from the paths returned from the DHT, reversing the paths
 * to obtain a local peer -> destination path and interning the peer ids.
 *
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 *
 * @return Newly allocated and created path
 */
static struct MeshPeerPath *
path_build_from_dht (const struct GNUNET_PeerIdentity *const *get_path,
                     const struct GNUNET_PeerIdentity *const *put_path)
{
  struct MeshPeerPath *p;
  int i;

  p = GNUNET_malloc (sizeof (struct MeshPeerPath));
  for (i = 0; get_path[i] != NULL; i++) ;
  for (i--; i >= 0; i--)
  {
    p->peers =
        GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * (p->length + 1));
    p->peers[p->length] = GNUNET_PEER_intern (get_path[i]);
    p->length++;
  }
  for (i = 0; put_path[i] != NULL; i++) ;
  for (i--; i >= 0; i--)
  {
    p->peers =
        GNUNET_realloc (p->peers, sizeof (GNUNET_PEER_Id) * (p->length + 1));
    p->peers[p->length] = GNUNET_PEER_intern (put_path[i]);
    p->length++;
  }
  return p;
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
  GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash (&tid, sizeof (MESH_TunnelNumber), &hash);
  return GNUNET_CONTAINER_multihashmap_get (c->tunnels, &hash);
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
 * Recursively find the given peer in the tree.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to look for.
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
static struct MeshTunnelPathNode *
tunnel_find_peer (struct MeshTunnelPathNode *root, struct MeshPeerInfo *peer)
{
  struct MeshTunnelPathNode *n;
  unsigned int i;

  if (root->peer == peer)
    return root;
  for (i = 0; i < root->nchildren; i++)
  {
    n = tunnel_find_peer (&root->children[i], peer);
    if (NULL != n)
      return n;
  }
  return NULL;
}


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param parent Node to be clean, potentially with children
 */
static void
tunnel_mark_peers_disconnected (struct MeshTunnelPathNode *parent)
{
  struct GNUNET_MESH_PeerControl msg;
  unsigned int i;

  parent->status = MESH_PEER_RECONNECTING;
  for (i = 0; i < parent->nchildren; i++)
  {
    tunnel_mark_peers_disconnected (&parent->children[i]);
  }
  if (NULL == parent->t->client)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
  msg.tunnel_id = htonl (parent->t->local_tid);
  GNUNET_PEER_resolve (parent->peer->id, &msg.peer);
  GNUNET_SERVER_notification_context_unicast (nc, parent->t->client->handle,
                                              &msg.header, GNUNET_NO);
}

/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel where to delete the path from.
 * @param peer Destination peer whose path we want to remove.
 *
 * @return pointer to the pathless node, NULL on error
 *
 * TODO: notify peers of deletion
 */
static struct MeshTunnelPathNode *
tunnel_del_path (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct MeshTunnelPathNode *parent;
  struct MeshTunnelPathNode *node;
  struct MeshTunnelPathNode *n;

  node = n = tunnel_find_peer (t->paths->me, peer);
  if (NULL == n)
    return NULL;
  parent = n->parent;
  n->parent = NULL;
  while (NULL != parent && MESH_PEER_RELAY == parent->status &&
         1 == parent->nchildren)
  {
    n = parent;
    GNUNET_free (parent->children);
    parent = parent->parent;
  }
  if (NULL == parent)
    return node;
  *n = parent->children[parent->nchildren - 1];
  parent->nchildren--;
  parent->children = GNUNET_realloc (parent->children, parent->nchildren);

  tunnel_mark_peers_disconnected (node);

  return node;
}


/**
 * Return a newly allocated individual path to reach a peer from the local peer,
 * according to the path tree of some tunnel.
 * 
 * @param t Tunnel from which to read the path tree
 * @param peer_info Destination peer to whom we want a path
 * 
 * @return A newly allocated individual path to reach the destination peer.
 *         Path must be destroyed afterwards.
 */
static struct MeshPeerPath *
tunnel_get_path_to_peer(struct MeshTunnel *t, struct MeshPeerInfo *peer_info)
{
  struct MeshTunnelPathNode *n;
  struct MeshPeerPath *p;

  n = tunnel_find_peer(t->paths->me, peer_info);
  p = GNUNET_malloc(sizeof(struct MeshPeerPath));

  /* Building the path (inverted!) */
  while (n->peer->id != myid)
  {
    GNUNET_array_append(p->peers, p->length, n->peer->id);
    GNUNET_PEER_change_rc(n->peer->id, 1);
    n = n->parent;
    GNUNET_assert(NULL != n);
  }
  GNUNET_array_append(p->peers, p->length, myid);
  GNUNET_PEER_change_rc(myid, 1);

  path_invert(p);

  return p;
}


/**
 * Integrate a stand alone path into the tunnel tree.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to be integrated.
 *
 * @return GNUNET_OK in case of success.
 *         GNUNET_SYSERR in case of error.
 *
 * TODO: optimize
 * - go backwards on path looking for each peer in the present tree
 */
static int
tunnel_add_path (struct MeshTunnel *t, struct MeshPeerPath *p)
{
  struct MeshTunnelPathNode *parent;
  struct MeshTunnelPathNode *oldnode;
  struct MeshTunnelPathNode *n;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_PeerIdentity hop;
  int me;
  unsigned int i;
  unsigned int j;

  n = t->paths->root;
  if (n->peer->id != p->peers[0])
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
               "local id's: %u %s\n",
               myid,
               GNUNET_h2s_full(&my_full_id.hashPubKey));
    GNUNET_PEER_resolve(n->peer->id, &id);
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
               "root:  %s\n",
               GNUNET_h2s_full(&id.hashPubKey));
    GNUNET_PEER_resolve (p->peers[0], &id);
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
               "first: %s\n",
               GNUNET_h2s_full(&id.hashPubKey));

    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* Ignore return value, if not found it's ok. */
  GNUNET_PEER_resolve (p->peers[p->length - 1], &id);
  oldnode = tunnel_del_path (t, peer_info_get (&id));
  /* Look for the first node that is not already present in the tree
   *
   * Assuming that the tree is somewhat balanced, O(log n * log N).
   * - Length of the path is expected to be log N (size of whole network).
   * - Each level of the tree is expected to have log n children (size of tree).
   */
  for (i = 1, me = -1; i < p->length; i++)
  {
    parent = n;
    if (p->peers[i] == myid)
      me = i;
    for (j = 0; j < n->nchildren; j++)
    {
      if (n->children[j].peer->id == p->peers[i])
      {
        n = &n->children[j];
        break;
      }
    }
    /*  If we couldn't find a child equal to path[i], we have reached the end
     * of the common path. */
    if (parent == n)
      break;
  }
  if (-1 == me)
  {
    /* New path deviates from tree before reaching us. What happened? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* Add the rest of the path as a branch from parent. */
  while (i < p->length)
  {
    parent->nchildren++;
    parent->children = GNUNET_realloc (parent->children,
                                       parent->nchildren *
                                       sizeof(struct MeshTunnelPathNode));
    n = &parent->children[parent->nchildren - 1];
    if (i == p->length - 1 && NULL != oldnode)
    {
      /* Assignation and free can be misleading, using explicit mempcy */
      memcpy (n, oldnode, sizeof (struct MeshTunnelPathNode));
      GNUNET_free (oldnode);
    }
    else
    {
      n->t = t;
      n->status = MESH_PEER_RELAY;
      GNUNET_PEER_resolve (p->peers[i], &id);
      n->peer = peer_info_get (&id);
    }
    n->parent = parent;
    i++;
    parent = n;
  }

  /* Add info about first hop into hashmap. */
  if (me < p->length - 1)
  {
    GNUNET_PEER_resolve (p->peers[p->length - 1], &id);
    GNUNET_PEER_resolve (p->peers[me + 1], &hop);
    GNUNET_CONTAINER_multihashmap_put (t->paths->first_hops, &id.hashPubKey,
                                       peer_info_get (&hop),
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  return GNUNET_OK;
}


/**
 * Add a peer to a tunnel, accomodating paths accordingly and initializing all
 * needed rescources.
 *
 * @param t Tunnel we want to add a new peer to
 * @param peer PeerInfo of the peer being added
 *
 */
static void
tunnel_add_peer (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *best_p;
  unsigned int best_cost;
  unsigned int cost;

  GNUNET_array_append (peer->tunnels, peer->ntunnels, t);
  if (NULL == (p = peer->path_head))
    return;

  best_p = p;
  best_cost = UINT_MAX;
  while (NULL != p)
  {
    if ((cost = path_get_cost (t, p)) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
    p = p->next;
  }
  tunnel_add_path (t, best_p);
  if (GNUNET_SCHEDULER_NO_TASK == t->path_refresh_task)
    t->path_refresh_task =
        GNUNET_SCHEDULER_add_delayed (REFRESH_PATH_TIME, &path_refresh, t);
}


/**
 * Notify a tunnel that a connection has broken that affects at least
 * some of its peers.
 *
 * @param t Tunnel affected
 * @param peer Peer that (at least) has been affected by the disconnection
 * @param p1 Peer that got disconnected from p2
 * @param p2 Peer that got disconnected from p1
 * 
 * FIXME path
 */
static void
tunnel_notify_connection_broken (struct MeshTunnel *t,
                                 struct MeshPeerInfo *peer, GNUNET_PEER_Id p1,
                                 GNUNET_PEER_Id p2)
{
}


/**
 * Recursively destory the path tree of a tunnel.
 * Note: it does not liberate memory for itself, parent must do it!
 *
 * @param n The node to destroy, along with children.
 *
 * @return GNUNET_OK on success
 */
static void
tunnel_destroy_tree_node (struct MeshTunnelPathNode *n)
{
  unsigned int i;

  for (i = 0; i < n->nchildren; i++)
  {
    tunnel_destroy_tree_node(&n->children[i]);
  }
  if (NULL != n->children)
    GNUNET_free (n->children);
}


/**
 * Destroy the tunnel and free any allocated resources linked to it
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
  int r;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: DESTROYING TUNNEL at %p\n", t);
  if (NULL == t)
    return GNUNET_OK;

  c = t->client;
#if MESH_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:   by client %u\n", c->id);
#endif

  GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &hash, t))
  {
    r = GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (c->tunnels, &hash, t))
  {
    r = GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_multihashmap_destroy (t->peers);
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

  GNUNET_CONTAINER_multihashmap_destroy(t->paths->first_hops);
  tunnel_destroy_tree_node(t->paths->root);
  GNUNET_free(t->paths->root);
  GNUNET_free (t->paths);
  GNUNET_free (t);
  return r;
}


/**
 * tunnel_destroy_iterator: iterator for deleting each tunnel that belongs to a
 * client when the client disconnects.
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
  int r;

  r = tunnel_destroy ((struct MeshTunnel *) value);
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
send_core_create_path (void *cls, size_t size, void *buf)
{
  struct MeshPathInfo *info = cls;
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerInfo *peer = info->peer;
  struct MeshTunnel *t = info->t;
  struct MeshPeerPath *p = info->path;
  size_t size_needed;
  int i;

  size_needed =
      sizeof (struct GNUNET_MESH_ManipulatePath) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Retransmitting create path\n");
    GNUNET_PEER_resolve (path_get_first_hop (t, peer)->id, &id);
    GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                       GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                       size_needed, &send_core_create_path,
                                       info);
    return 0;
  }

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

  return size_needed;
}


#if LATER
/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (MeshDataDescriptor with all info to build packet)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_data_to_origin (void *cls, size_t size, void *buf)
{
  struct MeshDataDescriptor *info = cls;
  struct GNUNET_MESH_ToOrigin *msg = buf;
  size_t total_size;

  GNUNET_assert (NULL != info);
  total_size = sizeof (struct GNUNET_MESH_ToOrigin) + info->size;
  GNUNET_assert (total_size < 65536);   /* UNIT16_MAX */

  if (total_size > size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "not enough buffer to send data to origin\n");
    return 0;
  }
  msg->header.size = htons (total_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN);
  GNUNET_PEER_resolve (info->origin->oid, &msg->oid);
  msg->tid = htonl (info->origin->tid);
  if (0 != info->size)
  {
    memcpy (&msg[1], &info[1], info->size);
  }
  if (NULL != info->client)
  {
    GNUNET_SERVER_receive_done (info->client, GNUNET_OK);
  }
  GNUNET_free (info);
  return total_size;
}
#endif

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
send_core_data_unicast (void *cls, size_t size, void *buf)
{
  struct MeshDataDescriptor *info = cls;
  struct GNUNET_MESH_Unicast *msg = buf;
  size_t total_size;

  GNUNET_assert (NULL != info);
  total_size = sizeof (struct GNUNET_MESH_Unicast) + info->size;
  GNUNET_assert (total_size < 65536);   /* UNIT16_MAX */

  if (total_size > size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "not enough buffer to send data to peer\n");
    return 0;
  }
  msg->header.size = htons (total_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_UNICAST);
  GNUNET_PEER_resolve (info->origin->oid, &msg->oid);
  GNUNET_PEER_resolve (info->destination, &msg->destination);
  msg->tid = htonl (info->origin->tid);
  if (0 != info->size)
  {
    memcpy (&msg[1], &info[1], info->size);
  }
  if (NULL != info->client)
  {
    GNUNET_SERVER_receive_done (info->client, GNUNET_OK);
  }
  GNUNET_free (info);
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
send_core_data_multicast (void *cls, size_t size, void *buf)
{
  struct MeshDataDescriptor *info = cls;
  struct GNUNET_MESH_Multicast *msg = buf;
  size_t total_size;

  GNUNET_assert (NULL != info);
  total_size = info->size + sizeof (struct GNUNET_MESH_Multicast);
  GNUNET_assert (total_size < GNUNET_SERVER_MAX_MESSAGE_SIZE);

  if (info->peer)
  {
    info->peer->core_transmit[info->handler_n] = NULL;
  }
  if (total_size > size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "not enough buffer to send data futher\n");
    return 0;
  }
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_MULTICAST);
  msg->header.size = htons (total_size);
  GNUNET_PEER_resolve (info->origin->oid, &msg->oid);
  msg->tid = htonl (info->origin->tid);
  memcpy (&msg[1], &info[1], total_size);
  if (0 == --info->copies)
  {
    if (NULL != info->client)
    {
      GNUNET_SERVER_receive_done (info->client, GNUNET_OK);
    }
    GNUNET_free (info);
  }
  return total_size;
}


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure (MeshDataDescriptor)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_path_ack (void *cls, size_t size, void *buf)
{
  struct MeshDataDescriptor *info = cls;
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

  return sizeof (struct GNUNET_MESH_PathACK);
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


#if LATER
/**
 * Send another peer a notification to destroy a tunnel
 * @param cls The tunnel to destroy
 * @param size Size in the buffer
 * @param buf Memory where to put the data to transmit
 * @return Size of data put in buffer
 */
static size_t
send_p2p_tunnel_destroy (void *cls, size_t size, void *buf)
{
  struct MeshTunnel *t = cls;
  struct MeshClient *c;
  struct GNUNET_MESH_TunnelMessage *msg;

  c = t->client;
  msg = buf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
   /*FIXME*/ msg->header.size =
      htons (sizeof (struct GNUNET_MESH_TunnelMessage));
  msg->tunnel_id = htonl (t->id.tid);

  tunnel_destroy (c, t);
  return sizeof (struct GNUNET_MESH_TunnelMessage);
}
#endif


/**
 * Send the message to all clients that have subscribed to its type
 *
 * @param msg Pointer to the message itself
 * @return number of clients this message was sent to
 */
static unsigned int
send_subscribed_clients (struct GNUNET_MessageHeader *msg)
{
  struct MeshClient *c;
  unsigned int count;
  uint16_t type;

  type = ntohs (msg->type);
  for (count = 0, c = clients; c != NULL; c = c->next)
  {
    if (client_is_subscribed (type, c))
    {
      count++;
      GNUNET_SERVER_notification_context_unicast (nc, c->handle, msg,
                                                  GNUNET_YES);
    }
  }
  return count;
}


/**
 * Iterator over hash map peer entries collect all neighbors who to resend the
 * data to.
 *
 * @param cls closure (**GNUNET_PEER_Id to store hops to send packet)
 * @param key current key code (peer id hash)
 * @param value value in the hash map (peer_info)
 * @return GNUNET_YES if we should continue to iterate, GNUNET_NO if not.
 */
static int
iterate_collect_neighbors (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MeshPeerInfo *peer_info = value;
  struct MeshPathInfo *neighbors = cls;
  unsigned int i;

  if (peer_info->id == myid)
  {
    return GNUNET_YES;
  }
  peer_info = path_get_first_hop (neighbors->t, peer_info);
  for (i = 0; i < neighbors->path->length; i++)
  {
    if (neighbors->path->peers[i] == peer_info->id)
      return GNUNET_YES;
  }
  GNUNET_array_append (neighbors->path->peers, neighbors->path->length,
                       peer_info->id);

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
handle_mesh_path_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  unsigned int own_pos;
  uint16_t size;
  uint16_t i;
  MESH_TunnelNumber tid;
  struct GNUNET_MESH_ManipulatePath *msg;
  struct GNUNET_PeerIdentity *pi;
  struct GNUNET_PeerIdentity id;
  GNUNET_HashCode hash;
  struct MeshPeerPath *path;
  struct MeshPeerInfo *dest_peer_info;
  struct MeshPeerInfo *orig_peer_info;
  struct MeshTunnel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MESH: Received a MESH path create msg\n");
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
  msg = (struct GNUNET_MESH_ManipulatePath *) message;

  tid = ntohl (msg->tid);
  pi = (struct GNUNET_PeerIdentity *) &msg[1];
  t = tunnel_get (pi, tid);

  if (NULL == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Creating tunnel\n");
    t = GNUNET_malloc (sizeof (struct MeshTunnel));
    t->id.oid = GNUNET_PEER_intern (pi);
    t->id.tid = tid;
    t->peers = GNUNET_CONTAINER_multihashmap_create (32);

    GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (tunnels, &hash, t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }

  }
  dest_peer_info =
      GNUNET_CONTAINER_multihashmap_get (peers, &pi[size - 1].hashPubKey);
  if (NULL == dest_peer_info)
  {
    dest_peer_info = GNUNET_malloc (sizeof (struct MeshPeerInfo));
    dest_peer_info->id = GNUNET_PEER_intern (&pi[size - 1]);
    GNUNET_CONTAINER_multihashmap_put (peers, &pi[size - 1].hashPubKey,
                                       dest_peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  orig_peer_info = GNUNET_CONTAINER_multihashmap_get (peers, &pi->hashPubKey);
  if (NULL == orig_peer_info)
  {
    orig_peer_info = GNUNET_malloc (sizeof (struct MeshPeerInfo));
    orig_peer_info->id = GNUNET_PEER_intern (pi);
    GNUNET_CONTAINER_multihashmap_put (peers, &pi->hashPubKey, orig_peer_info,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  path = GNUNET_malloc (sizeof (struct MeshPeerPath));
  path->length = size;
  path->peers = GNUNET_malloc (size * sizeof (GNUNET_PEER_Id));
  own_pos = 0;
  for (i = 0; i < size; i++)
  {
    path->peers[i] = GNUNET_PEER_intern (&pi[i]);
    if (path->peers[i] == myid)
      own_pos = i;
  }
  if (own_pos == 0)
  {                             /* cannot be self, must be 'not found' */
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    /* FIXME error. destroy tunnel? leave for timeout? */
    return 0;
  }
  if (own_pos == size - 1)
  {
    /* It is for us! Send ack. */
    struct MeshDataDescriptor *info;
    unsigned int j;

    path_add_to_origin (orig_peer_info, path);  /* inverts path!  */
    info = GNUNET_malloc (sizeof (struct MeshDataDescriptor));
    info->origin = &t->id;
    info->peer = GNUNET_CONTAINER_multihashmap_get (peers, &id.hashPubKey);
    GNUNET_assert (info->peer);
    for (j = 0; info->peer->core_transmit[j]; j++)
    {
      if (j == 9)
      {
        GNUNET_break (0);
        return GNUNET_OK;
      }
    }
    info->handler_n = j;
    info->peer->core_transmit[j] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 100,
                                           GNUNET_TIME_UNIT_FOREVER_REL, peer,
                                           sizeof (struct GNUNET_MessageHeader),
                                           &send_core_path_ack, info);
  }
  else
  {
    /* It's for somebody else! Retransmit. */
    struct MeshPathInfo *path_info;

    path_info = GNUNET_malloc (sizeof (struct MeshPathInfo));
    path_info->t = t;
    path_info->path = path;
    path_info->peer = dest_peer_info;

    path_add_to_peer (dest_peer_info, path);
    GNUNET_PEER_resolve (path->peers[own_pos + 1], &id);
    GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                       GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                       sizeof (struct GNUNET_MessageHeader),
                                       &send_core_create_path, path_info);
  }
  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going from the origin to a peer
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param message message
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_unicast (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_Unicast *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnel *t;
  struct MeshPeerInfo *pi;
  size_t size;

  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Unicast) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Unicast *) message;
  t = tunnel_get (&msg->oid, ntohl (msg->tid));
  if (NULL == t)
  {
    /* TODO notify back: we don't know this tunnel */
    return GNUNET_OK;
  }
  pi = GNUNET_CONTAINER_multihashmap_get (t->peers,
                                          &msg->destination.hashPubKey);
  if (NULL == pi)
  {
    /* TODO maybe feedback, log to statistics */
    return GNUNET_OK;
  }
  if (pi->id == myid)
  {
    send_subscribed_clients ((struct GNUNET_MessageHeader *) &msg[1]);
    return GNUNET_OK;
  }
  GNUNET_PEER_resolve (path_get_first_hop (t, pi)->id, &id);
  msg = GNUNET_malloc (size);
  memcpy (msg, message, size);
  GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                     GNUNET_TIME_UNIT_FOREVER_REL, &id, size,
                                     &send_core_data_raw, msg);
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
handle_mesh_data_multicast (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message,
                            const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_Multicast *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshDataDescriptor *info;
  struct MeshPathInfo neighbors;
  struct MeshTunnel *t;
  size_t size;
  uint16_t i;
  uint16_t j;


  size = ntohs (message->size);
  if (size <
      sizeof (struct GNUNET_MESH_Multicast) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_Multicast *) message;
  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know that tunnel */
    return GNUNET_OK;
  }

  /* Transmit to locally interested clients */
  if (GNUNET_CONTAINER_multihashmap_contains (t->peers, &my_full_id.hashPubKey))
  {
    send_subscribed_clients ((struct GNUNET_MessageHeader *) &msg[1]);
  }

  /* Retransmit to other peers.
   * Using path here as just a collection of peers, not a path per se.
   */
  neighbors.t = t;
  neighbors.path = GNUNET_malloc (sizeof (struct MeshPeerPath));
  GNUNET_CONTAINER_multihashmap_iterate (t->peers, &iterate_collect_neighbors,
                                         &neighbors);
  if (0 == neighbors.path->length)
  {
    GNUNET_free (neighbors.path);
    return GNUNET_OK;
  }
  size -= sizeof (struct GNUNET_MESH_Multicast);
  info = GNUNET_malloc (sizeof (struct MeshDataDescriptor) + size);
  info->origin = &t->id;
  info->copies = neighbors.path->length;
  for (i = 0; i < info->copies; i++)
  {
    GNUNET_PEER_resolve (neighbors.path->peers[i], &id);
    info->peer = GNUNET_CONTAINER_multihashmap_get (peers, &id.hashPubKey);
    GNUNET_assert (NULL != info->peer);
    for (j = 0; 0 != info->peer->core_transmit[j]; j++)
    {
      if (j == (CORE_QUEUE_SIZE - 1))
      {
        GNUNET_break (0);
        return GNUNET_OK;
      }
    }
    info->handler_n = j;
    info->peer->infos[j] = info;
    info->peer->core_transmit[j] =
        GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                           GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                           ntohs (msg->header.size),
                                           &send_core_data_multicast, info);
  }
  GNUNET_free (neighbors.path->peers);
  GNUNET_free (neighbors.path);
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
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_data_to_orig (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_ToOrigin *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshPeerInfo *peer_info;
  struct MeshTunnel *t;
  size_t size;

  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ToOrigin) +     /* Payload must be */
      sizeof (struct GNUNET_MessageHeader))     /* at least a header */
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  msg = (struct GNUNET_MESH_ToOrigin *) message;
  t = tunnel_get (&msg->oid, ntohl (msg->tid));

  if (NULL == t)
  {
    /* TODO notify that we dont know this tunnel (whom)? */
    return GNUNET_OK;
  }

  if (t->id.oid == myid)
  {
    if (NULL == t->client)
    {
      /* got data packet for ownerless tunnel */
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    /* TODO signature verification */
    GNUNET_SERVER_notification_context_unicast (nc, t->client->handle, message,
                                                GNUNET_YES);
    return GNUNET_OK;
  }
  peer_info = peer_info_get (&msg->oid);
  if (NULL == peer_info)
  {
    /* unknown origin of tunnel */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_PEER_resolve (t->paths->me->parent->peer->id, &id);
  msg = GNUNET_malloc (size);
  memcpy (msg, message, size);
  GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                     GNUNET_TIME_UNIT_FOREVER_REL, &id, size,
                                     &send_core_data_raw, msg);

  return GNUNET_OK;
}


/**
 * Core handler for path ACKs
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 * FIXME path change state
 */
static int
handle_mesh_path_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message,
                      const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_PathACK *msg;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnel *t;
  struct MeshPeerInfo *peer_info;

  msg = (struct GNUNET_MESH_PathACK *) message;
  t = tunnel_get (&msg->oid, msg->tid);
  if (NULL == t)
  {
    /* TODO notify that we don't know the tunnel */
    return GNUNET_OK;
  }

  /* Message for us? */
  if (0 == memcmp (&msg->oid, &my_full_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    struct GNUNET_MESH_PeerControl pc;

    if (NULL == t->client)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
    peer_info = peer_info_get (&msg->peer_id);
    if (NULL == peer_info)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    /* FIXME change state of peer */
    pc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD);
    pc.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
    pc.tunnel_id = htonl (t->local_tid);
    GNUNET_PEER_resolve (peer_info->id, &pc.peer);
    GNUNET_SERVER_notification_context_unicast (nc, t->client->handle,
                                                &pc.header, GNUNET_NO);
    return GNUNET_OK;
  }

  peer_info = peer_info_get (&msg->oid);
  if (NULL == peer_info)
  {
    /* If we know the tunnel, we should DEFINITELY know the peer */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_PEER_resolve (path_get_first_hop (t, peer_info)->id, &id);
  msg = GNUNET_malloc (sizeof (struct GNUNET_MESH_PathACK));
  memcpy (msg, message, sizeof (struct GNUNET_MESH_PathACK));
  GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                     GNUNET_TIME_UNIT_FOREVER_REL, &id,
                                     sizeof (struct GNUNET_MESH_PathACK),
                                     &send_core_data_raw, msg);
  return GNUNET_OK;
}


/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
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
  GNUNET_CONTAINER_multihashmap_remove (applications, key, value);
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
 *
 * FIXME path
 */
static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *const *get_path,
                    const struct GNUNET_PeerIdentity *const *put_path,
                    enum GNUNET_BLOCK_Type type, size_t size, const void *data)
{
  struct MeshPathInfo *path_info = cls;
  struct MeshPeerPath *p;
  struct GNUNET_PeerIdentity pi;
  int i;

  if (NULL == get_path || NULL == put_path)
  {
    if (NULL == path_info->peer->path_head)
    {
      // Find ourselves some alternate initial path to the destination: retry
      GNUNET_DHT_get_stop (path_info->peer->dhtget);
      GNUNET_PEER_resolve (path_info->peer->id, &pi);
      path_info->peer->dhtget = GNUNET_DHT_get_start (dht_handle,       /* handle */
                                                      GNUNET_TIME_UNIT_FOREVER_REL,     /* timeout */
                                                      GNUNET_BLOCK_TYPE_TEST,   /* type */
                                                      &pi.hashPubKey,   /*key to search */
                                                      4,        /* replication level */
                                                      GNUNET_DHT_RO_RECORD_ROUTE, NULL, /* bloom filter */
                                                      0,        /* mutator */
                                                      NULL,     /* xquery */
                                                      0,        /* xquery bits */
                                                      dht_get_id_handler,
                                                      (void *) path_info);
      return;
    }
  }

  p = path_build_from_dht (get_path, put_path);
  path_add_to_peer (path_info->peer, p);
  for (i = 0; i < path_info->peer->ntunnels; i++)
  {
    tunnel_add_peer (path_info->peer->tunnels[i], path_info->peer);
  }
  GNUNET_free (path_info);

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
dht_get_type_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                      const GNUNET_HashCode * key,
                      const struct GNUNET_PeerIdentity *const *get_path,
                      const struct GNUNET_PeerIdentity *const *put_path,
                      enum GNUNET_BLOCK_Type type, size_t size,
                      const void *data)
{
  const struct GNUNET_PeerIdentity *pi = data;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnel *t = cls;
  struct MeshPeerInfo *peer_info;
  struct MeshPathInfo *path_info;
  struct MeshPeerPath *p;
  int i;

  if (size != sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_assert (NULL != t->client);
  GNUNET_DHT_get_stop (t->client->dht_get_type);
  t->client->dht_get_type = NULL;
  peer_info = peer_info_get (pi);
  GNUNET_CONTAINER_multihashmap_put (t->peers, &pi->hashPubKey, peer_info,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  if ((NULL == get_path || NULL == put_path) && NULL == peer_info->path_head &&
      NULL == peer_info->dhtget)
  {
    /* we don't have a route to the peer, let's try a direct lookup */
    peer_info->dhtget = GNUNET_DHT_get_start (dht_handle,
                                              /* handle */
                                              GNUNET_TIME_UNIT_FOREVER_REL,
                                              /* timeout */
                                              GNUNET_BLOCK_TYPE_TEST,
                                              /* block type */
                                              &pi->hashPubKey,
                                              /* key to look up */
                                              10U,
                                              /* replication level */
                                              GNUNET_DHT_RO_RECORD_ROUTE,
                                              /* option to dht: record route */
                                              NULL,     /* bloom filter */
                                              0,        /* mutator */
                                              NULL,     /* xquery */
                                              0,        /* xquery bits */
                                              dht_get_id_handler,
                                              /* callback */
                                              peer_info);       /* closure */
  }

  p = path_build_from_dht (get_path, put_path);
  path_add_to_peer (peer_info, p);
  tunnel_add_peer(t, peer_info);
  p = tunnel_get_path_to_peer(t, peer_info);
  path_info = GNUNET_malloc(sizeof(struct MeshPathInfo));
  path_info->t = t;
  path_info->peer = peer_info;
  path_info->path = p;
#if MESH_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MESH: new route for tunnel 0x%x found, has %u hops\n",
              t->local_tid, p->length);
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[0], &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:\t%d\t%s\n", i,
                GNUNET_h2s_full (&id.hashPubKey));
  }
#endif

  GNUNET_PEER_resolve (p->peers[1], &id);
  GNUNET_CORE_notify_transmit_ready (core_handle,
                                     /* handle */
                                     0,
                                     /* cork */
                                     0,
                                     /* priority */
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     /* timeout */
                                     &id,
                                     /* target */
                                     sizeof (struct GNUNET_MESH_ManipulatePath)
                                     +
                                     (p->length *
                                      sizeof (struct GNUNET_PeerIdentity)),
                                     /*size */
                                     &send_core_create_path,
                                     /* callback */
                                     path_info);        /* cls */
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: client disconnected\n");
  if (client == NULL)
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:    (SERVER DOWN)\n");
  c = clients;
  while (NULL != c)
  {
    if (c->handle != client && NULL != client)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:    ... searching\n");
      c = c->next;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: matching client found\n");
    if (NULL != c->tunnels)
    {
      GNUNET_CONTAINER_multihashmap_iterate (c->tunnels,
                                             &tunnel_destroy_iterator,
                                             c);
      GNUNET_CONTAINER_multihashmap_destroy (c->tunnels);
    }

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
    if (NULL != c->dht_get_type)
      GNUNET_DHT_get_stop (c->dht_get_type);
    GNUNET_CONTAINER_DLL_remove (clients, clients_tail, c);
    next = c->next;
    GNUNET_free (c);
    c = next;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:    done!\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: new client connected\n");
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
#if MESH_DEBUG
  c->id = next_client_id++;
#endif
  c->handle = client;
  a = (GNUNET_MESH_ApplicationType *) &cc_msg[1];
  if (napps > 0)
  {
    GNUNET_MESH_ApplicationType at;
    GNUNET_HashCode hc;

    c->apps = GNUNET_CONTAINER_multihashmap_create (napps);
    for (i = 0; i < napps; i++)
    {
      at = ntohl (a[i]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:   app type: %u\n", at);
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
              "MESH:  client has %u+%u subscriptions\n", napps, ntypes);

  GNUNET_CONTAINER_DLL_insert (clients, clients_tail, c);
  c->tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  GNUNET_SERVER_notification_context_add (nc, client);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
#if MESH_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: new client processed\n");
#endif
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: new tunnel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
#if MESH_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:   by client %u\n", c->id);
#endif

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: CREATED TUNNEL at %p\n", t);
  while (NULL != tunnel_get_by_pi (myid, next_tid))
    next_tid = (next_tid + 1) & ~GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  t->id.tid = next_tid++;
  t->id.oid = myid;
  t->local_tid = ntohl (t_msg->tunnel_id);
  t->client = c;
  t->peers = GNUNET_CONTAINER_multihashmap_create (32);

  GNUNET_CRYPTO_hash (&t->local_tid, sizeof (MESH_TunnelNumber), &hash);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (c->tunnels, &hash, t,
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
  t->paths = GNUNET_malloc (sizeof(struct MeshTunnelPath));
  t->paths->first_hops = GNUNET_CONTAINER_multihashmap_create(32);
  t->paths->t = t;
  t->paths->root = GNUNET_malloc(sizeof(struct MeshTunnelPathNode));
  t->paths->root->status = MESH_PEER_READY;
  t->paths->root->t = t;
  t->paths->root->peer = peer_info_get(&my_full_id);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MESH:  adding root node id %u\n",
             t->paths->root->peer->id);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MESH:  own id is %s\n",
             GNUNET_h2s_full(&my_full_id.hashPubKey));
  struct GNUNET_PeerIdentity id;
  GNUNET_PEER_resolve(t->paths->root->peer->id, &id);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MESH:  id of peer is %s\n",
             GNUNET_h2s_full(&id.hashPubKey));
  t->paths->me = t->paths->root;

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
  GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: destroying tunnel\n");

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
#if MESH_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:   by client %u\n", c->id);
#endif
  tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;

  /* Retrieve tunnel */
  tid = ntohl (tunnel_msg->tunnel_id);

  /* Remove from local id hashmap */
  GNUNET_CRYPTO_hash (&tid, sizeof (MESH_TunnelNumber), &hash);
  t = GNUNET_CONTAINER_multihashmap_get (c->tunnels, &hash);
  GNUNET_CONTAINER_multihashmap_remove (c->tunnels, &hash, t);

  /* Remove from global id hashmap */
  GNUNET_CRYPTO_hash (&t->id, sizeof (struct MESH_TunnelID), &hash);
  GNUNET_CONTAINER_multihashmap_remove (tunnels, &hash, t);

//     notify_tunnel_destroy(t); FIXME
  tunnel_destroy(t);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}


/**
 * Handler for connection requests to new peers
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 *
 * FIXME path
 */
static void
handle_local_connect_add (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_PeerControl *peer_msg;
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;
  struct MeshPeerInfo *peer_info;


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
  if (t->client->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  t->peers_total++;
  peer_info = peer_info_get (&peer_msg->peer);

  /* Start DHT search if needed FIXME: if not already connected */
  if (NULL == peer_info->dhtget)
  {
    peer_info->dhtget = GNUNET_DHT_get_start (dht_handle, GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_BLOCK_TYPE_TEST, &peer_msg->peer.hashPubKey, 4,  /* replication level */
                                              GNUNET_DHT_RO_RECORD_ROUTE, NULL, /* bloom filter */
                                              0,        /* mutator */
                                              NULL,     /* xquery */
                                              0,        /* xquery bits */
                                              dht_get_id_handler,
                                              (void *) peer_info);
  }

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
  struct MeshClient *c;
  struct MeshTunnel *t;
  MESH_TunnelNumber tid;

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
  if (t->client->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Ok, delete peer from tunnel */
  GNUNET_CONTAINER_multihashmap_remove_all (t->peers,
                                            &peer_msg->peer.hashPubKey);

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
  GNUNET_MESH_ApplicationType type;
  MESH_TunnelNumber tid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: got connect by type request\n");
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
  if (t->client->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Do WE have the service? */
  type = ntohl (connect_msg->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:  type requested: %u\n", type);
  GNUNET_CRYPTO_hash (&type, sizeof (GNUNET_MESH_ApplicationType), &hash);
  if (GNUNET_CONTAINER_multihashmap_contains (applications, &hash) ==
      GNUNET_YES)
  {
    /* Yes! Fast forward, add ourselves to the tunnel and send the
     * good news to the client
     */
    struct GNUNET_MESH_PeerControl pc;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:  available locally\n");
    pc.peer = my_full_id;
    GNUNET_CONTAINER_multihashmap_put (t->peers, &pc.peer.hashPubKey,
                                       peer_info_get (&pc.peer),
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    pc.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
    pc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD);
    pc.tunnel_id = htonl (t->local_tid);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:  notifying client\n");
    GNUNET_SERVER_notification_context_unicast (nc,     /* context */
                                                client, /* dest */
                                                &pc.header,     /* msg */
                                                GNUNET_NO);     /* can drop? */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:  Done\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  /* Ok, lets find a peer offering the service */
  if (c->dht_get_type)
  {
    GNUNET_DHT_get_stop (c->dht_get_type);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:  looking in DHT for %s\n",
              GNUNET_h2s_full (&hash));
  c->dht_get_type =
      GNUNET_DHT_get_start (dht_handle, GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_BLOCK_TYPE_TEST, &hash, 10U,
                            GNUNET_DHT_RO_RECORD_ROUTE, NULL, 0, NULL, 0,
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
  struct GNUNET_PeerIdentity next_hop;
  struct MeshDataDescriptor *info;
  MESH_TunnelNumber tid;
  size_t data_size;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  data_msg = (struct GNUNET_MESH_Unicast *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_Unicast) +
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

  /*  Is it a local tunnel? Then, does client own the tunnel? */
  if (t->client->handle != NULL && t->client->handle != client)
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
  if (pi->id == myid)
  {
    struct GNUNET_MESH_Unicast copy;

    /* Work around const limitation */
    memcpy (&copy, data_msg, sizeof (struct GNUNET_MESH_Unicast));
    copy.oid = my_full_id;
    copy.tid = htonl (t->id.tid);
    handle_mesh_data_unicast (NULL, &my_full_id, &copy.header, NULL);
    return;
  }
  GNUNET_PEER_resolve (path_get_first_hop (t, pi)->id, &next_hop);
  data_size = ntohs (message->size) - sizeof (struct GNUNET_MESH_Unicast);
  info = GNUNET_malloc (sizeof (struct MeshDataDescriptor) + data_size);
  memcpy (&info[1], &data_msg[1], data_size);
  info->destination = pi->id;
  info->origin = &t->id;
  info->size = data_size;
  info->client = client;
  GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
                                     GNUNET_TIME_UNIT_FOREVER_REL, &next_hop,
                                     /* FIXME re-check types */
                                     data_size +
                                     sizeof (struct GNUNET_MESH_Unicast),
                                     &send_core_data_unicast, info);
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

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  data_msg = (struct GNUNET_MESH_Multicast *) message;
  /* Sanity check for message size */
  if (sizeof (struct GNUNET_MESH_PeerControl) != ntohs (data_msg->header.size))
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
  if (t->client->handle != client)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /*  TODO */

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}

/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler client_handlers[] = {
  {&handle_local_new_client, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
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
  {&handle_local_unicast, NULL,
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
 * @param publicKey the public key of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Core init\n");
  core_handle = server;
  if (0 != memcmp(identity, &my_full_id, sizeof(my_full_id)) || NULL == server)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("MESH: Wrong CORE service\n"));
    GNUNET_SCHEDULER_shutdown();   
  }
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
core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
//     GNUNET_PEER_Id              pid;
  struct MeshPeerInfo *peer_info;
  struct MeshPeerPath *path;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Peer connected\n");
  peer_info = peer_info_get (peer);
  if (myid == peer_info->id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:      (self)\n");
  }
  path = GNUNET_malloc (sizeof (struct MeshPeerPath));
  path->length = 2;
  path->peers = GNUNET_malloc (sizeof (GNUNET_PEER_Id) * 2);
  path->peers[0] = myid;
  path->peers[1] = peer_info->id;
  path_add_to_peer (peer_info, path);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: Peer disconnected\n");
  pi = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (!pi)
  {
    GNUNET_break (0);
    return;
  }
  for (i = 0; i < CORE_QUEUE_SIZE; i++)
  {
    if (pi->core_transmit[i])
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pi->core_transmit[i]);
      /* TODO: notify that tranmission has failed */
      GNUNET_free (pi->infos[i]);
    }
  }
  path_remove_from_peer (pi, pi->id, myid);
  if (myid == pi->id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH:      (self)\n");
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
  struct MeshClient *c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: shutting down\n");
  if (core_handle != NULL)
  {
    GNUNET_CORE_disconnect (core_handle);
    core_handle = NULL;
  }
  if (dht_handle != NULL)
  {
    for (c = clients; NULL != c; c = c->next)
      if (NULL != c->dht_get_type)
        GNUNET_DHT_get_stop (c->dht_get_type);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: shut down\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: starting to run\n");
  server_handle = server;
  core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                     CORE_QUEUE_SIZE,   /* queue size */
                                     NULL,      /* Closure passed to MESH functions */
                                     &core_init,        /* Call core_init once connected */
                                     &core_connect,     /* Handle connects */
                                     &core_disconnect,  /* remove peers on disconnects */
                                     NULL,      /* Do we care about "status" updates? */
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

  dht_handle = GNUNET_DHT_connect (c, 64);
  if (dht_handle == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error connecting to DHT.\
                   Running without DHT has a severe\
                   impact in MESH capabilities.\n\
                   Plase check your configuretion and enable DHT.\n");
    GNUNET_break (0);
  }

  next_tid = 0;

  tunnels = GNUNET_CONTAINER_multihashmap_create (32);
  peers = GNUNET_CONTAINER_multihashmap_create (32);
  applications = GNUNET_CONTAINER_multihashmap_create (32);
  types = GNUNET_CONTAINER_multihashmap_create (32);

  GNUNET_SERVER_add_handlers (server_handle, client_handlers);
  nc = GNUNET_SERVER_notification_context_create (server_handle,
                                                  LOCAL_QUEUE_SIZE);
  GNUNET_SERVER_disconnect_notify (server_handle,
                                   &handle_local_client_disconnect,
                                   NULL);


  clients = NULL;
  clients_tail = NULL;
#if MESH_DEBUG
  next_client_id = 0;
#endif

  announce_applications_task = GNUNET_SCHEDULER_NO_TASK;
  announce_id_task = GNUNET_SCHEDULER_add_now (&announce_id, cls);

  /* Create a peer_info for the local peer */
  peer_info_get(&my_full_id);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: end of run()\n");
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

#if MESH_DEBUG
  fprintf (stderr, "main ()\n");
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: main()\n");
  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "mesh", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MESH: main() END\n");
#if MESH_DEBUG
  fprintf (stderr, "main () END\n");
#endif
  return ret;
}
