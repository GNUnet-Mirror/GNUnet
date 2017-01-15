
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet-new_peer.c
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "cadet_protocol.h"
#include "cadet_path.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_dht.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_tunnels.h"

/**
 * How long do we wait until tearing down an idle peer?
 */
#define IDLE_PEER_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)


/**
 * Struct containing all information regarding a given peer
 */
struct CadetPeer
{
  /**
   * ID of the peer
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Last time we heard from this peer
   */
  struct GNUNET_TIME_Absolute last_contact;

  /**
   * Paths to reach the peer, ordered by ascending hop count
   */
  struct CadetPeerPath *path_head;

  /**
   * Paths to reach the peer, ordered by ascending hop count
   */
  struct CadetPeerPath *path_tail;

  /**
   * Handle to stop the DHT search for paths to this peer
   */
  struct GCD_search_handle *search_h;

  /**
   * Task to stop the DHT search for paths to this peer
   */
  struct GNUNET_SCHEDULER_Task *search_delayed;

  /**
   * Task to destroy this entry.
   */
  struct GNUNET_SCHEDULER_Task *destroy_task;

  /**
   * Tunnel to this peer, if any.
   */
  struct CadetTunnel *t;

  /**
   * Connections that go through this peer; indexed by tid.
   */
  struct GNUNET_CONTAINER_MultiHashMap *connections;

  /**
   * Handle for core transmissions.
   */
  struct GNUNET_MQ_Handle *core_mq;

  /**
   * Hello message of the peer.
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Handle to us offering the HELLO to the transport.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *hello_offer;

  /**
   * Handle to our ATS request asking ATS to suggest an address
   * to TRANSPORT for this peer (to establish a direct link).
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *connectivity_suggestion;

  /**
   * How many messages are in the queue to this peer.
   */
  unsigned int queue_n;

  /**
   * How many paths do we have to this peer (in the @e path_head DLL).
   */
  unsigned int num_paths;

};


/**
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
const char *
GCP_2s (const struct CadetPeer *peer)
{
  if (NULL == peer)
    return "PEER(NULL)";
  return GNUNET_i2s (&peer->pid);
}


/**
 * This peer is no longer be needed, clean it up now.
 *
 * @param cls peer to clean up
 */
static void
destroy_peer (void *cls)
{
  struct CadetPeer *cp = cls;

  cp->destroy_task = NULL;
  GNUNET_assert (NULL == cp->t);
  GNUNET_assert (NULL == cp->core_mq);
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (cp->connections));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (peers,
                                                       &cp->pid,
                                                       cp));
  /* FIXME: clean up paths! */
  /* FIXME: clean up search_h! */
  /* FIXME: clean up search_delayed! */

  GNUNET_CONTAINER_multihashmap_destroy (cp->connections);
  GNUNET_free_non_null (cp->hello);
  if (NULL != cp->hello_offer)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (cp->hello_offer);
    cp->hello_offer = NULL;
  }
  if (NULL != cp->connectivity_suggestion)
  {
    GNUNET_ATS_connectivity_suggest_cancel (cp->connectivity_suggestion);
    cp->connectivity_suggestion = NULL;
  }
  GNUNET_free (cp);
}


/**
 * Function called to destroy a peer now.
 *
 * @param cls NULL
 * @param pid identity of the peer (unused)
 * @param value the `struct CadetPeer` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_iterator_cb (void *cls,
                     const struct GNUNET_PeerIdentity *pid,
                     void *value)
{
  struct CadetPeer *cp = value;

  if (NULL != cp->destroy_task)
    GNUNET_SCHEDULER_cancel (cp->destroy_task);
  destroy_peer (cp);
  return GNUNET_OK;
}


/**
 * Clean up all entries about all peers.
 * Must only be called after all tunnels, CORE-connections and
 * connections are down.
 */
void
GCP_destroy_all_peers ()
{
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &destroy_iterator_cb,
                                         NULL);
}


/**
 * This peer may no longer be needed, consider cleaning it up.
 *
 * @param peer peer to clean up
 */
static void
consider_peer_destroy (struct CadetPeer *peer)
{
  struct GNUNET_TIME_Relative exp;

  if (NULL != peer->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (peer->destroy_task);
    peer->destroy_task = NULL;
  }
  if (NULL != peer->t)
    return; /* still relevant! */
  if (NULL != peer->core_mq)
    return; /* still relevant! */
  if (0 != GNUNET_CONTAINER_multihashmap_size (peer->connections))
    return; /* still relevant! */
  if (NULL != peer->hello)
  {
    /* relevant only until HELLO expires */
    exp = GNUNET_TIME_absolute_get_remaining (GNUNET_HELLO_get_last_expiration (peer->hello));
    peer->destroy_task = GNUNET_SCHEDULER_add_delayed (exp,
                                                       &destroy_peer,
                                                       peer);
    return;
  }
  peer->destroy_task = GNUNET_SCHEDULER_add_delayed (IDLE_PEER_TIMEOUT,
                                                     &destroy_peer,
                                                     peer);
}


/**
 * Function called when the DHT finds a @a path to the peer (@a cls).
 *
 * @param cls the `struct CadetPeer`
 * @param path the path that was found
 */
static void
dht_result_cb (void *cls,
               const struct CadetPeerPath *path)
{
  struct CadetPeer *peer = cls;

  // FIXME: handle path!
}


/**
 * This peer is now on more "active" duty, activate processes related to it.
 *
 * @param peer the more-active peer
 */
static void
consider_peer_activate (struct CadetPeer *peer)
{
  uint32_t strength;

  if (NULL != peer->destroy_task)
  {
    /* It's active, do not destory! */
    GNUNET_SCHEDULER_cancel (peer->destroy_task);
    peer->destroy_task = NULL;
  }
  if (NULL == peer->core_mq)
  {
    /* Lacks direct connection, try to create one by querying the DHT */
    if ( (NULL == peer->search_h) &&
         (DESIRED_CONNECTIONS_PER_TUNNEL < peer->num_paths) )
      peer->search_h
        = GCD_search (&peer->pid,
                      &dht_result_cb,
                      peer);
  }
  else
  {
    /* Have direct connection, stop DHT search if active */
    if (NULL != peer->search_h)
    {
      GCD_search_stop (peer->search_h);
      peer->search_h = NULL;
    }
  }

  /* If we have a tunnel, our urge for connections is much bigger */
  strength = (NULL != peer->t) ? 32 : 1;
  if (NULL != peer->connectivity_suggestion)
    GNUNET_ATS_connectivity_suggest_cancel (peer->connectivity_suggestion);
  peer->connectivity_suggestion
    = GNUNET_ATS_connectivity_suggest (ats_ch,
                                       &peer->pid,
                                       strength);
}


/**
 * Retrieve the CadetPeer stucture associated with the
 * peer. Optionally create one and insert it in the appropriate
 * structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO to return NULL if peer is unknown.
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id,
         int create)
{
  struct CadetPeer *cp;

  cp = GNUNET_CONTAINER_multipeermap_get (peers,
                                          peer_id);
  if (NULL != cp)
    return cp;
  if (GNUNET_NO == create)
    return NULL;
  cp = GNUNET_new (struct CadetPeer);
  cp->pid = *peer_id;
  cp->connections = GNUNET_CONTAINER_multihashmap_create (32,
                                                          GNUNET_YES);
  cp->search_h = NULL; // FIXME: start search immediately!?
  cp->connectivity_suggestion = NULL; // FIXME: request with ATS!?

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (peers,
                                                    &cp->pid,
                                                    cp,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return cp;
}


/**
 * Obtain the peer identity for a `struct CadetPeer`.
 *
 * @param cp our peer handle
 * @param[out] peer_id where to write the peer identity
 */
void
GCP_id (struct CadetPeer *cp,
        struct GNUNET_PeerIdentity *peer_id)
{
  *peer_id = cp->pid;
}


/**
 * Create a peer path based on the result of a DHT lookup.
 *
 * @param get_path path of the get request
 * @param get_path_length lenght of @a get_path
 * @param put_path path of the put request
 * @param put_path_length length of the @a put_path
 * @return a path through the network
 */
struct CadetPeerPath *
GCP_path_from_dht (const struct GNUNET_PeerIdentity *get_path,
                   unsigned int get_path_length,
                   const struct GNUNET_PeerIdentity *put_path,
                   unsigned int put_path_length)
{
  GNUNET_assert (0); // FIXME: implement!
  return NULL;
}


/**
 * Iterate over all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter,
                 void *cls)
{
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         iter,
                                         cls);
}


/**
 * Count the number of known paths toward the peer.
 *
 * @param peer Peer to get path info.
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *peer)
{
  return peer->num_paths;
}


/**
 * Iterate over the paths to a peer.
 *
 * @param peer Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *peer,
                   GCP_PathIterator callback,
                   void *callback_cls)
{
  unsigned int ret = 0;

  for (struct CadetPeerPath *path = peer->path_head;
       NULL != path;
       path = path->next)
  {
    if (GNUNET_NO ==
        callback (callback_cls,
                  peer,
                  path))
      return ret;
    ret++;
  }
  return ret;
}


/**
 * Get the tunnel towards a peer.
 *
 * @param peer Peer to get from.
 * @param create #GNUNET_YES to create a tunnel if we do not have one
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (struct CadetPeer *peer,
                int create)
{
  if (NULL == peer)
    return NULL;
  if ( (NULL != peer->t) ||
       (GNUNET_NO == create) )
    return peer->t;
  peer->t = GCT_create_tunnel (peer);
  consider_peer_activate (peer);
  return peer->t;
}


/**
 * We got a HELLO for a @a peer, remember it, and possibly
 * trigger adequate actions (like trying to connect).
 *
 * @param peer the peer we got a HELLO for
 * @param hello the HELLO to remember
 */
void
GCP_set_hello (struct CadetPeer *peer,
               const struct GNUNET_HELLO_Message *hello)
{
  /* FIXME! */

  consider_peer_destroy (peer);
}


/**
 * The tunnel to the given peer no longer exists, remove it from our
 * data structures, and possibly clean up the peer itself.
 *
 * @param peer the peer affected
 * @param t the dead tunnel
 */
void
GCP_drop_tunnel (struct CadetPeer *peer,
                 struct CadetTunnel *t)
{
  GNUNET_assert (peer->t == t);
  peer->t = NULL;
  consider_peer_destroy (peer);
}


/* end of gnunet-service-cadet-new_peer.c */
