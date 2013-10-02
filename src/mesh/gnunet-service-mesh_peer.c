/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet-service-mesh_peer.h"

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

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


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Peers known, indexed by PeerIdentity (MeshPeer).
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * How many peers do we want to remember?
 */
static unsigned long long max_peers;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

/**
 * Iterator over tunnel hash map entries to destroy the tunnel during shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
shutdown_tunnel (void *cls, 
                 const struct GNUNET_PeerIdentity *key, 
                 void *value)
{
  struct MeshPeer *p = value;
  struct MeshTunnel2 *t = p->tunnel;

  if (NULL != t)
    GMT_destroy (t);
  return GNUNET_YES;
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize the peer subsystem.
 *
 * @param c Configuration.
 */
void
GMP_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  peers = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_PEERS",
                                             &max_peers))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "MAX_PEERS", "USING DEFAULT");
    max_peers = 1000;
  }
}

/**
 * Shut down the peer subsystem.
 */
void
GMP_shutdown (void)
{
  GNUNET_CONTAINER_multipeermap_iterate (peers, &shutdown_tunnel, NULL);
}

