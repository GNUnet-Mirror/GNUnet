/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file cadet/gnunet-service-cadet_peer.c
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * TODO:
 * - optimize stopping/restarting DHT search to situations
 *   where we actually need it (i.e. not if we have a direct connection,
 *   or if we already have plenty of good short ones, or maybe even
 *   to take a break if we have some connections and have searched a lot (?))
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_dht.h"
#include "gnunet-service-cadet_paths.h"
#include "gnunet-service-cadet_tunnels.h"


#define LOG(level, ...) GNUNET_log_from (level, "cadet-per", __VA_ARGS__)


/**
 * How long do we wait until tearing down an idle peer?
 */
#define IDLE_PEER_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How long do we keep paths around if we no longer care about the peer?
 */
#define IDLE_PATH_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Queue size when we start dropping OOO messages.
 */
#define MAX_OOO_QUEUE_SIZE  100

/**
 * Data structure used to track whom we have to notify about changes
 * to our message queue.
 */
struct GCP_MessageQueueManager
{
  /**
   * Kept in a DLL.
   */
  struct GCP_MessageQueueManager *next;

  /**
   * Kept in a DLL.
   */
  struct GCP_MessageQueueManager *prev;

  /**
   * Function to call with updated message queue object.
   */
  GCP_MessageQueueNotificationCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * The peer this is for.
   */
  struct CadetPeer *cp;

  /**
   * Envelope this manager would like to transmit once it is its turn.
   */
  struct GNUNET_MQ_Envelope *env;
};


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
   * Last time we heard from this peer (currently not used!)
   */
  struct GNUNET_TIME_Absolute last_connection_create;

  /**
   * Array of DLLs of paths traversing the peer, organized by the
   * offset of the peer on the larger path.
   */
  struct CadetPeerPathEntry **path_heads;

  /**
   * Array of DLL of paths traversing the peer, organized by the
   * offset of the peer on the larger path.
   */
  struct CadetPeerPathEntry **path_tails;

  /**
   * Notifications to call when @e core_mq changes.
   */
  struct GCP_MessageQueueManager *mqm_head;

  /**
   * Notifications to call when @e core_mq changes.
   */
  struct GCP_MessageQueueManager *mqm_tail;

  /**
   * Pointer to first "ready" entry in @e mqm_head.
   */
  struct GCP_MessageQueueManager *mqm_ready_ptr;

  /**
   * MIN-heap of paths owned by this peer (they also end at this
   * peer).  Ordered by desirability.
   */
  struct GNUNET_CONTAINER_Heap *path_heap;

  /**
   * Handle to stop the DHT search for paths to this peer
   */
  struct GCD_search_handle *search_h;

  /**
   * Task to clean up @e path_heap asynchronously.
   */
  struct GNUNET_SCHEDULER_Task *heap_cleanup_task;

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
  struct GNUNET_CONTAINER_MultiShortmap *connections;

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
   * How many paths do we have to this peer (in all @e path_heads DLLs combined).
   */
  unsigned int num_paths;

  /**
   * Sum over all of the offsets of all of the paths in the @a path_heads DLLs.
   * Used to speed-up @GCP_get_desirability_of_path() calculation.
   */
  unsigned int off_sum;

  /**
   * Number of message queue managers of this peer that have a message in waiting.
   *
   * Used to quickly see if we need to bother scanning the @e msm_head DLL.
   * TODO: could be replaced by another DLL that would then allow us to avoid
   * the O(n)-scan of the DLL for ready entries!
   */
  unsigned int mqm_ready_counter;

  /**
   * Current length of the @e path_heads and @path_tails arrays.
   * The arrays should be grown as needed.
   */
  unsigned int path_dll_length;
};


/**
 * Get the static string for a peer ID.
 *
 * @param cp Peer.
 * @return Static string for it's ID.
 */
const char *
GCP_2s (const struct CadetPeer *cp)
{
  static char buf[5];
  char *ret;

  if ((NULL == cp) ||
      (0 == GNUNET_is_zero (&cp->pid.public_key)))
    return "NULL";

  ret = GNUNET_CRYPTO_eddsa_public_key_to_string (&cp->pid.public_key);
  if (NULL == ret)
    return "NULL";

  GNUNET_strlcpy (buf,
                  ret,
                  sizeof(buf));
  GNUNET_free (ret);
  return buf;
}


/**
 * Calculate how desirable a path is for @a cp if @a cp
 * is at offset @a off.
 *
 * The 'desirability_table.c' program can be used to compute a list of
 * sample outputs for different scenarios.  Basically, we score paths
 * lower if there are many alternatives, and higher if they are
 * shorter than average, and very high if they are much shorter than
 * average and without many alternatives.
 *
 * @param cp a peer reachable via a path
 * @param off offset of @a cp in the path
 * @return score how useful a path is to reach @a cp,
 *         positive scores mean path is more desirable
 */
double
GCP_get_desirability_of_path (struct CadetPeer *cp,
                              unsigned int off)
{
  unsigned int num_alts = cp->num_paths;
  unsigned int off_sum;
  double avg_sum;
  double path_delta;
  double weight_alts;

  GNUNET_assert (num_alts >= 1);  /* 'path' should be in there! */
  GNUNET_assert (0 != cp->path_dll_length);

  /* We maintain 'off_sum' in 'peer' and thereby
     avoid the SLOW recalculation each time. Kept here
     just to document what is going on. */
#if SLOW
  off_sum = 0;
  for (unsigned int j = 0; j < cp->path_dll_length; j++)
    for (struct CadetPeerPathEntry *pe = cp->path_heads[j];
         NULL != pe;
         pe = pe->next)
      off_sum += j;
  GNUNET_assert (off_sum == cp->off_sum);
#else
  off_sum = cp->off_sum;
#endif
  avg_sum = off_sum * 1.0 / cp->path_dll_length;
  path_delta = off - avg_sum;
  /* path_delta positiv: path off of peer above average (bad path for peer),
     path_delta negativ: path off of peer below average (good path for peer) */
  if (path_delta <= -1.0)
    weight_alts = -num_alts / path_delta;  /* discount alternative paths */
  else if (path_delta >= 1.0)
    weight_alts = num_alts * path_delta; /* overcount alternative paths */
  else
    weight_alts = num_alts; /* count alternative paths normally */


  /* off+1: long paths are generally harder to find and thus count
     a bit more as they get longer.  However, above-average paths
     still need to count less, hence the squaring of that factor. */
  return (off + 1.0) / (weight_alts * weight_alts);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying state about peer %s\n",
       GCP_2s (cp));
  cp->destroy_task = NULL;
  GNUNET_assert (NULL == cp->t);
  GNUNET_assert (NULL == cp->core_mq);
  GNUNET_assert (0 == cp->num_paths);
  for (unsigned int i = 0; i < cp->path_dll_length; i++)
    GNUNET_assert (NULL == cp->path_heads[i]);
  GNUNET_assert (0 == GNUNET_CONTAINER_multishortmap_size (cp->connections));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (peers,
                                                       &cp->pid,
                                                       cp));
  GNUNET_free_non_null (cp->path_heads);
  GNUNET_free_non_null (cp->path_tails);
  cp->path_dll_length = 0;
  if (NULL != cp->search_h)
  {
    GCD_search_stop (cp->search_h);
    cp->search_h = NULL;
  }
  /* FIXME: clean up search_delayedXXX! */

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
  GNUNET_CONTAINER_multishortmap_destroy (cp->connections);
  if (NULL != cp->path_heap)
  {
    GNUNET_CONTAINER_heap_destroy (cp->path_heap);
    cp->path_heap = NULL;
  }
  if (NULL != cp->heap_cleanup_task)
  {
    GNUNET_SCHEDULER_cancel (cp->heap_cleanup_task);
    cp->heap_cleanup_task = NULL;
  }
  GNUNET_free_non_null (cp->hello);
  /* Peer should not be freed if paths exist; if there are no paths,
     there ought to be no connections, and without connections, no
     notifications. Thus we can assert that mqm_head is empty at this
     point. */
  GNUNET_assert (NULL == cp->mqm_head);
  GNUNET_assert (NULL == cp->mqm_ready_ptr);
  GNUNET_free (cp);
}


/**
 * This peer is now on more "active" duty, activate processes related to it.
 *
 * @param cp the more-active peer
 */
static void
consider_peer_activate (struct CadetPeer *cp)
{
  uint32_t strength;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating peer %s activation state (%u connections)%s%s\n",
       GCP_2s (cp),
       GNUNET_CONTAINER_multishortmap_size (cp->connections),
       (NULL == cp->t) ? "" : " with tunnel",
       (NULL == cp->core_mq) ? "" : " with CORE link");
  if (NULL != cp->destroy_task)
  {
    /* It's active, do not destory! */
    GNUNET_SCHEDULER_cancel (cp->destroy_task);
    cp->destroy_task = NULL;
  }
  if ((0 == GNUNET_CONTAINER_multishortmap_size (cp->connections)) &&
      (NULL == cp->t))
  {
    /* We're just on a path or directly connected; don't bother too much */
    if (NULL != cp->connectivity_suggestion)
    {
      GNUNET_ATS_connectivity_suggest_cancel (cp->connectivity_suggestion);
      cp->connectivity_suggestion = NULL;
    }
    if (NULL != cp->search_h)
    {
      GCD_search_stop (cp->search_h);
      cp->search_h = NULL;
    }
    return;
  }
  if (NULL == cp->core_mq)
  {
    /* Lacks direct connection, try to create one by querying the DHT */
    if ((NULL == cp->search_h) &&
        (DESIRED_CONNECTIONS_PER_TUNNEL > cp->num_paths))
      cp->search_h
        = GCD_search (&cp->pid);
  }
  else
  {
    /* Have direct connection, stop DHT search if active */
    if (NULL != cp->search_h)
    {
      GCD_search_stop (cp->search_h);
      cp->search_h = NULL;
    }
  }

  /* If we have a tunnel, our urge for connections is much bigger */
  strength = (NULL != cp->t) ? 32 : 1;
  if (NULL != cp->connectivity_suggestion)
    GNUNET_ATS_connectivity_suggest_cancel (cp->connectivity_suggestion);
  cp->connectivity_suggestion
    = GNUNET_ATS_connectivity_suggest (ats_ch,
                                       &cp->pid,
                                       strength);
}


/**
 * This peer may no longer be needed, consider cleaning it up.
 *
 * @param cp peer to clean up
 */
static void
consider_peer_destroy (struct CadetPeer *cp);


/**
 * We really no longere care about a peer, stop hogging memory with paths to it.
 * Afterwards, see if there is more to be cleaned up about this peer.
 *
 * @param cls a `struct CadetPeer`.
 */
static void
drop_paths (void *cls)
{
  struct CadetPeer *cp = cls;
  struct CadetPeerPath *path;

  cp->destroy_task = NULL;
  while (NULL != (path = GNUNET_CONTAINER_heap_remove_root (cp->path_heap)))
    GCPP_release (path);
  consider_peer_destroy (cp);
}


/**
 * This peer may no longer be needed, consider cleaning it up.
 *
 * @param cp peer to clean up
 */
static void
consider_peer_destroy (struct CadetPeer *cp)
{
  struct GNUNET_TIME_Relative exp;

  if (NULL != cp->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (cp->destroy_task);
    cp->destroy_task = NULL;
  }
  if (NULL != cp->t)
    return; /* still relevant! */
  if (NULL != cp->core_mq)
    return; /* still relevant! */
  if (0 != GNUNET_CONTAINER_multishortmap_size (cp->connections))
    return; /* still relevant! */
  if ((NULL != cp->path_heap) &&
      (0 < GNUNET_CONTAINER_heap_get_size (cp->path_heap)))
  {
    cp->destroy_task = GNUNET_SCHEDULER_add_delayed (IDLE_PATH_TIMEOUT,
                                                     &drop_paths,
                                                     cp);
    return;
  }
  if (0 != cp->num_paths)
    return; /* still relevant! */
  if (NULL != cp->hello)
  {
    /* relevant only until HELLO expires */
    exp = GNUNET_TIME_absolute_get_remaining (GNUNET_HELLO_get_last_expiration (
                                                cp->hello));
    cp->destroy_task = GNUNET_SCHEDULER_add_delayed (exp,
                                                     &destroy_peer,
                                                     cp);
    return;
  }
  cp->destroy_task = GNUNET_SCHEDULER_add_delayed (IDLE_PEER_TIMEOUT,
                                                   &destroy_peer,
                                                   cp);
}


/**
 * Set the message queue to @a mq for peer @a cp and notify watchers.
 *
 * @param cp peer to modify
 * @param mq message queue to set (can be NULL)
 */
void
GCP_set_mq (struct CadetPeer *cp,
            struct GNUNET_MQ_Handle *mq)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message queue for peer %s is now %p\n",
       GCP_2s (cp),
       mq);
  cp->core_mq = mq;
  for (struct GCP_MessageQueueManager *mqm = cp->mqm_head, *next;
       NULL != mqm;
       mqm = next)
  {
    /* Save next pointer in case mqm gets freed by the callback */
    next = mqm->next;
    if (NULL == mq)
    {
      if (NULL != mqm->env)
      {
        GNUNET_MQ_discard (mqm->env);
        mqm->env = NULL;
        mqm->cb (mqm->cb_cls,
                 GNUNET_SYSERR);
      }
      else
      {
        mqm->cb (mqm->cb_cls,
                 GNUNET_NO);
      }
    }
    else
    {
      GNUNET_assert (NULL == mqm->env);
      mqm->cb (mqm->cb_cls,
               GNUNET_YES);
    }
  }
  if ((NULL != mq) ||
      (NULL != cp->t))
    consider_peer_activate (cp);
  else
    consider_peer_destroy (cp);

  if ((NULL != mq) &&
      (NULL != cp->t))
  {
    /* have a new, direct path to the target, notify tunnel */
    struct CadetPeerPath *path;

    path = GCPP_get_path_from_route (1,
                                     &cp->pid);
    GCT_consider_path (cp->t,
                       path,
                       0);
  }
}


/**
 * Debug function should NEVER return true in production code, useful to
 * simulate losses for testcases.
 *
 * @return #GNUNET_YES or #GNUNET_NO with the decision to drop.
 */
static int
should_I_drop (void)
{
  if (0 == drop_percent)
    return GNUNET_NO;
  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                101) < drop_percent)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Function called when CORE took one of the messages from
 * a message queue manager and transmitted it.
 *
 * @param cls the `struct CadetPeeer` where we made progress
 */
static void
mqm_send_done (void *cls);


/**
 * Transmit current envelope from this @a mqm.
 *
 * @param mqm mqm to transmit message for now
 */
static void
mqm_execute (struct GCP_MessageQueueManager *mqm)
{
  struct CadetPeer *cp = mqm->cp;

  /* Move ready pointer to the next entry that might be ready. */
  if ((mqm == cp->mqm_ready_ptr) &&
      (NULL != mqm->next))
    cp->mqm_ready_ptr = mqm->next;
  /* Move entry to the end of the DLL, to be fair. */
  if (mqm != cp->mqm_tail)
  {
    GNUNET_CONTAINER_DLL_remove (cp->mqm_head,
                                 cp->mqm_tail,
                                 mqm);
    GNUNET_CONTAINER_DLL_insert_tail (cp->mqm_head,
                                      cp->mqm_tail,
                                      mqm);
  }
  cp->mqm_ready_counter--;
  if (GNUNET_YES == should_I_drop ())
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "DROPPING message to peer %s from MQM %p\n",
         GCP_2s (cp),
         mqm);
    GNUNET_MQ_discard (mqm->env);
    mqm->env = NULL;
    mqm_send_done (cp);
  }
  else
  {
    {
      const struct GNUNET_MessageHeader *mh;

      mh = GNUNET_MQ_env_get_msg (mqm->env);
      switch (ntohs (mh->type))
      {
      case GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX:
        {
          const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg
            = (const struct GNUNET_CADET_TunnelKeyExchangeMessage *) mh;
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "P2P forwarding KX with ephemeral %s to %s on CID %s\n",
               GNUNET_e2s (&msg->ephemeral_key),
               GCP_2s (cp),
               GNUNET_sh2s (&msg->cid.connection_of_tunnel));
        }
        break;

      default:
        break;
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending to peer %s from MQM %p\n",
         GCP_2s (cp),
         mqm);
    GNUNET_MQ_send (cp->core_mq,
                    mqm->env);
    mqm->env = NULL;
  }
  mqm->cb (mqm->cb_cls,
           GNUNET_YES);
}


/**
 * Find the next ready message in the queue (starting
 * the search from the `cp->mqm_ready_ptr`) and if possible
 * execute the transmission.
 *
 * @param cp peer to try to send the next ready message to
 */
static void
send_next_ready (struct CadetPeer *cp)
{
  struct GCP_MessageQueueManager *mqm;

  if (0 == cp->mqm_ready_counter)
    return;
  while ((NULL != (mqm = cp->mqm_ready_ptr)) &&
         (NULL == mqm->env))
    cp->mqm_ready_ptr = mqm->next;
  if (NULL == mqm)
    return; /* nothing to do */
  mqm_execute (mqm);
}


/**
 * Function called when CORE took one of the messages from
 * a message queue manager and transmitted it.
 *
 * @param cls the `struct CadetPeeer` where we made progress
 */
static void
mqm_send_done (void *cls)
{
  struct CadetPeer *cp = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending to peer %s completed\n",
       GCP_2s (cp));
  send_next_ready (cp);
}


/**
 * Send the message in @a env to @a cp.
 *
 * @param mqm the message queue manager to use for transmission
 * @param env envelope with the message to send; must NOT
 *            yet have a #GNUNET_MQ_notify_sent() callback attached to it
 */
void
GCP_send (struct GCP_MessageQueueManager *mqm,
          struct GNUNET_MQ_Envelope *env)
{
  struct CadetPeer *cp = mqm->cp;

  GNUNET_assert (NULL != env);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing message to peer %s in MQM %p\n",
       GCP_2s (cp),
       mqm);
  GNUNET_assert (NULL != cp->core_mq);
  GNUNET_assert (NULL == mqm->env);
  GNUNET_MQ_notify_sent (env,
                         &mqm_send_done,
                         cp);
  mqm->env = env;
  cp->mqm_ready_counter++;
  if (mqm != cp->mqm_ready_ptr)
    cp->mqm_ready_ptr = cp->mqm_head;
  if (1 == cp->mqm_ready_counter)
    cp->mqm_ready_ptr = mqm;
  if (0 != GNUNET_MQ_get_length (cp->core_mq))
    return;
  send_next_ready (cp);
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
  {
    GNUNET_SCHEDULER_cancel (cp->destroy_task);
    cp->destroy_task = NULL;
  }
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying all peers now\n");
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &destroy_iterator_cb,
                                         NULL);
}


/**
 * Drop all paths owned by this peer, and do not
 * allow new ones to be added: We are shutting down.
 *
 * @param cp peer to drop paths to
 */
void
GCP_drop_owned_paths (struct CadetPeer *cp)
{
  struct CadetPeerPath *path;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying all paths to %s\n",
       GCP_2s (cp));
  while (NULL != (path =
                    GNUNET_CONTAINER_heap_remove_root (cp->path_heap)))
    GCPP_release (path);
  GNUNET_CONTAINER_heap_destroy (cp->path_heap);
  cp->path_heap = NULL;
}


/**
 * Add an entry to the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_add (struct CadetPeer *cp,
                    struct CadetPeerPathEntry *entry,
                    unsigned int off)
{
  GNUNET_assert (cp == GCPP_get_peer_at_offset (entry->path,
                                                off));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Discovered that peer %s is on path %s at offset %u\n",
       GCP_2s (cp),
       GCPP_2s (entry->path),
       off);
  if (off >= cp->path_dll_length)
  {
    unsigned int len = cp->path_dll_length;

    GNUNET_array_grow (cp->path_heads,
                       len,
                       off + 4);
    GNUNET_array_grow (cp->path_tails,
                       cp->path_dll_length,
                       off + 4);
  }
  GNUNET_CONTAINER_DLL_insert (cp->path_heads[off],
                               cp->path_tails[off],
                               entry);
  cp->off_sum += off;
  cp->num_paths++;

  /* If we have a tunnel to this peer, tell the tunnel that there is a
     new path available. */
  if (NULL != cp->t)
    GCT_consider_path (cp->t,
                       entry->path,
                       off);

  if ((NULL != cp->search_h) &&
      (DESIRED_CONNECTIONS_PER_TUNNEL <= cp->num_paths))
  {
    /* Now I have enough paths, stop search */
    GCD_search_stop (cp->search_h);
    cp->search_h = NULL;
  }
  if (NULL != cp->destroy_task)
  {
    /* paths changed, this resets the destroy timeout counter
       and aborts a destroy task that may no longer be valid
       to have (as we now have more paths via this peer). */
    consider_peer_destroy (cp);
  }
}


/**
 * Remove an entry from the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_remove (struct CadetPeer *cp,
                       struct CadetPeerPathEntry *entry,
                       unsigned int off)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing knowledge about peer %s beging on path %s at offset %u\n",
       GCP_2s (cp),
       GCPP_2s (entry->path),
       off);
  GNUNET_CONTAINER_DLL_remove (cp->path_heads[off],
                               cp->path_tails[off],
                               entry);
  GNUNET_assert (0 < cp->num_paths);
  cp->off_sum -= off;
  cp->num_paths--;
  if ((NULL == cp->core_mq) &&
      (NULL != cp->t) &&
      (NULL == cp->search_h) &&
      (DESIRED_CONNECTIONS_PER_TUNNEL > cp->num_paths))
    cp->search_h
      = GCD_search (&cp->pid);
  if (NULL == cp->destroy_task)
  {
    /* paths changed, we might now be ready for destruction, check again */
    consider_peer_destroy (cp);
  }
}


/**
 * Prune down the number of paths to this peer, we seem to
 * have way too many.
 *
 * @param cls the `struct CadetPeer` to maintain the path heap for
 */
static void
path_heap_cleanup (void *cls)
{
  struct CadetPeer *cp = cls;
  struct CadetPeerPath *root;

  cp->heap_cleanup_task = NULL;
  while (GNUNET_CONTAINER_heap_get_size (cp->path_heap) >=
         2 * DESIRED_CONNECTIONS_PER_TUNNEL)
  {
    /* Now we have way too many, drop least desirable UNLESS it is in use!
       (Note that this intentionally keeps highly desireable, but currently
       unused paths around in the hope that we might be able to switch, even
       if the number of paths exceeds the threshold.) */
    root = GNUNET_CONTAINER_heap_peek (cp->path_heap);
    GNUNET_assert (NULL != root);
    if (NULL !=
        GCPP_get_connection (root,
                             cp,
                             GCPP_get_length (root) - 1))
      break;   /* can't fix */
    /* Got plenty of paths to this destination, and this is a low-quality
       one that we don't care about. Allow it to die. */
    GNUNET_assert (root ==
                   GNUNET_CONTAINER_heap_remove_root (cp->path_heap));
    GCPP_release (root);
  }
}


/**
 * Try adding a @a path to this @a peer.  If the peer already
 * has plenty of paths, return NULL.
 *
 * @param cp peer to which the @a path leads to
 * @param path a path looking for an owner; may not be fully initialized yet!
 * @param off offset of @a cp in @a path
 * @param force force attaching the path
 * @return NULL if this peer does not care to become a new owner,
 *         otherwise the node in the peer's path heap for the @a path.
 */
struct GNUNET_CONTAINER_HeapNode *
GCP_attach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 unsigned int off,
                 int force)
{
  GNUNET_CONTAINER_HeapCostType desirability;
  struct CadetPeerPath *root;
  GNUNET_CONTAINER_HeapCostType root_desirability;
  struct GNUNET_CONTAINER_HeapNode *hn;

  GNUNET_assert (off == GCPP_get_length (path) - 1);
  GNUNET_assert (cp == GCPP_get_peer_at_offset (path,
                                                off));
  if (NULL == cp->path_heap)
  {
    /* #GCP_drop_owned_paths() was already called, we cannot take new ones! */
    GNUNET_assert (GNUNET_NO == force);
    return NULL;
  }
  desirability = GCPP_get_desirability (path);
  if (GNUNET_NO == force)
  {
    /* FIXME: desirability is not yet initialized; tricky! */
    if (GNUNET_NO ==
        GNUNET_CONTAINER_heap_peek2 (cp->path_heap,
                                     (void **) &root,
                                     &root_desirability))
    {
      root = NULL;
      root_desirability = 0;
    }

    if ((DESIRED_CONNECTIONS_PER_TUNNEL > cp->num_paths) &&
        (desirability < root_desirability))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Decided to not attach path %s to peer %s due to undesirability\n",
           GCPP_2s (path),
           GCP_2s (cp));
      return NULL;
    }
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Attaching path %s to peer %s (%s)\n",
       GCPP_2s (path),
       GCP_2s (cp),
       (GNUNET_NO == force) ? "desirable" : "forced");

  /* Yes, we'd like to add this path, add to our heap */
  hn = GNUNET_CONTAINER_heap_insert (cp->path_heap,
                                     path,
                                     desirability);

  /* Consider maybe dropping other paths because of the new one */
  if ((GNUNET_CONTAINER_heap_get_size (cp->path_heap) >=
       2 * DESIRED_CONNECTIONS_PER_TUNNEL) &&
      (NULL != cp->heap_cleanup_task))
    cp->heap_cleanup_task = GNUNET_SCHEDULER_add_now (&path_heap_cleanup,
                                                      cp);
  return hn;
}


/**
 * This peer can no longer own @a path as the path
 * has been extended and a peer further down the line
 * is now the new owner.
 *
 * @param cp old owner of the @a path
 * @param path path where the ownership is lost
 * @param hn note in @a cp's path heap that must be deleted
 */
void
GCP_detach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 struct GNUNET_CONTAINER_HeapNode *hn)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Detatching path %s from peer %s\n",
       GCPP_2s (path),
       GCP_2s (cp));
  GNUNET_assert (path ==
                 GNUNET_CONTAINER_heap_remove_node (hn));
}


/**
 * Add a @a connection to this @a cp.
 *
 * @param cp peer via which the @a connection goes
 * @param cc the connection to add
 */
void
GCP_add_connection (struct CadetPeer *cp,
                    struct CadetConnection *cc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding %s to peer %s\n",
       GCC_2s (cc),
       GCP_2s (cp));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (cp->connections,
                                                     &GCC_get_id (
                                                       cc)->connection_of_tunnel,
                                                     cc,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (NULL != cp->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (cp->destroy_task);
    cp->destroy_task = NULL;
  }
}


/**
 * Remove a @a connection that went via this @a cp.
 *
 * @param cp peer via which the @a connection went
 * @param cc the connection to remove
 */
void
GCP_remove_connection (struct CadetPeer *cp,
                       struct CadetConnection *cc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing connection %s from peer %s\n",
       GCC_2s (cc),
       GCP_2s (cp));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multishortmap_remove (cp->connections,
                                                        &GCC_get_id (
                                                          cc)->
                                                        connection_of_tunnel,
                                                        cc));
  consider_peer_destroy (cp);
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
  cp->connections = GNUNET_CONTAINER_multishortmap_create (32,
                                                           GNUNET_YES);
  cp->path_heap = GNUNET_CONTAINER_heap_create (
    GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (peers,
                                                    &cp->pid,
                                                    cp,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating peer %s\n",
       GCP_2s (cp));
  return cp;
}


/**
 * Obtain the peer identity for a `struct CadetPeer`.
 *
 * @param cp our peer handle
 * @return the peer identity
 */
const struct GNUNET_PeerIdentity *
GCP_get_id (struct CadetPeer *cp)
{
  return &cp->pid;
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
 * @param cp Peer to get path info.
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *cp)
{
  return cp->num_paths;
}


/**
 * Iterate over the paths to a peer.
 *
 * @param cp Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *cp,
                   GCP_PathIterator callback,
                   void *callback_cls)
{
  unsigned int ret = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Iterating over paths to peer %s%s\n",
       GCP_2s (cp),
       (NULL == cp->core_mq) ? "" : " including direct link");
  if (NULL != cp->core_mq)
  {
    /* FIXME: this branch seems to duplicate the
       i=0 case below (direct link). Leave out!??? -CG */
    struct CadetPeerPath *path;

    path = GCPP_get_path_from_route (1,
                                     &cp->pid);
    ret++;
    if (GNUNET_NO ==
        callback (callback_cls,
                  path,
                  0))
      return ret;
  }
  for (unsigned int i = 0; i < cp->path_dll_length; i++)
  {
    for (struct CadetPeerPathEntry *pe = cp->path_heads[i];
         NULL != pe;
         pe = pe->next)
    {
      ret++;
      if (GNUNET_NO ==
          callback (callback_cls,
                    pe->path,
                    i))
        return ret;
    }
  }
  return ret;
}


/**
 * Iterate over the paths to a peer without direct link.
 *
 * @param cp Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_indirect_paths (struct CadetPeer *cp,
                            GCP_PathIterator callback,
                            void *callback_cls)
{
  unsigned int ret = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Iterating over paths to peer %s without direct link\n",
       GCP_2s (cp));
  for (unsigned int i = 1; i < cp->path_dll_length; i++)
  {
    for (struct CadetPeerPathEntry *pe = cp->path_heads[i];
         NULL != pe;
         pe = pe->next)
    {
      ret++;
      if (GNUNET_NO ==
          callback (callback_cls,
                    pe->path,
                    i))
        return ret;
    }
  }
  return ret;
}


/**
 * Iterate over the paths to @a cp where
 * @a cp is at distance @a dist from us.
 *
 * @param cp Peer to get path info.
 * @param dist desired distance of @a cp to us on the path
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths_at (struct CadetPeer *cp,
                      unsigned int dist,
                      GCP_PathIterator callback,
                      void *callback_cls)
{
  unsigned int ret = 0;

  if (dist >= cp->path_dll_length)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Asked to look for paths at distance %u, but maximum for me is < %u\n",
         dist,
         cp->path_dll_length);
    return 0;
  }
  for (struct CadetPeerPathEntry *pe = cp->path_heads[dist];
       NULL != pe;
       pe = pe->next)
  {
    if (GNUNET_NO ==
        callback (callback_cls,
                  pe->path,
                  dist))
      return ret;
    ret++;
  }
  return ret;
}


/**
 * Get the tunnel towards a peer.
 *
 * @param cp Peer to get from.
 * @param create #GNUNET_YES to create a tunnel if we do not have one
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (struct CadetPeer *cp,
                int create)
{
  if (NULL == cp)
    return NULL;
  if ((NULL != cp->t) ||
      (GNUNET_NO == create))
    return cp->t;
  cp->t = GCT_create_tunnel (cp);
  consider_peer_activate (cp);
  return cp->t;
}


/**
 * Hello offer was passed to the transport service. Mark it
 * as done.
 *
 * @param cls the `struct CadetPeer` where the offer completed
 */
static void
hello_offer_done (void *cls)
{
  struct CadetPeer *cp = cls;

  cp->hello_offer = NULL;
}


/**
 * We got a HELLO for a @a peer, remember it, and possibly
 * trigger adequate actions (like trying to connect).
 *
 * @param cp the peer we got a HELLO for
 * @param hello the HELLO to remember
 */
void
GCP_set_hello (struct CadetPeer *cp,
               const struct GNUNET_HELLO_Message *hello)
{
  struct GNUNET_HELLO_Message *mrg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got %u byte HELLO for peer %s\n",
       (unsigned int) GNUNET_HELLO_size (hello),
       GCP_2s (cp));
  if (NULL != cp->hello_offer)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (cp->hello_offer);
    cp->hello_offer = NULL;
  }
  if (NULL != cp->hello)
  {
    mrg = GNUNET_HELLO_merge (hello,
                              cp->hello);
    GNUNET_free (cp->hello);
    cp->hello = mrg;
  }
  else
  {
    cp->hello = GNUNET_memdup (hello,
                               GNUNET_HELLO_size (hello));
  }
  cp->hello_offer
    = GNUNET_TRANSPORT_offer_hello (cfg,
                                    GNUNET_HELLO_get_header (cp->hello),
                                    &hello_offer_done,
                                    cp);
  /* New HELLO means cp's destruction time may change... */
  consider_peer_destroy (cp);
}


/**
 * The tunnel to the given peer no longer exists, remove it from our
 * data structures, and possibly clean up the peer itself.
 *
 * @param cp the peer affected
 * @param t the dead tunnel
 */
void
GCP_drop_tunnel (struct CadetPeer *cp,
                 struct CadetTunnel *t)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dropping tunnel %s to peer %s\n",
       GCT_2s (t),
       GCP_2s (cp));
  GNUNET_assert (cp->t == t);
  cp->t = NULL;
  consider_peer_destroy (cp);
}


/**
 * Test if @a cp has a core-level connection
 *
 * @param cp peer to test
 * @return #GNUNET_YES if @a cp has a core-level connection
 */
int
GCP_has_core_connection (struct CadetPeer *cp)
{
  return (NULL != cp->core_mq) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Start message queue change notifications.
 *
 * @param cp peer to notify for
 * @param cb function to call if mq becomes available or unavailable
 * @param cb_cls closure for @a cb
 * @return handle to cancel request
 */
struct GCP_MessageQueueManager *
GCP_request_mq (struct CadetPeer *cp,
                GCP_MessageQueueNotificationCallback cb,
                void *cb_cls)
{
  struct GCP_MessageQueueManager *mqm;

  mqm = GNUNET_new (struct GCP_MessageQueueManager);
  mqm->cb = cb;
  mqm->cb_cls = cb_cls;
  mqm->cp = cp;
  GNUNET_CONTAINER_DLL_insert (cp->mqm_head,
                               cp->mqm_tail,
                               mqm);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating MQM %p for peer %s\n",
       mqm,
       GCP_2s (cp));
  if (NULL != cp->core_mq)
    cb (cb_cls,
        GNUNET_YES);
  return mqm;
}


/**
 * Stops message queue change notifications.
 *
 * @param mqm handle matching request to cancel
 * @param last_env final message to transmit, or NULL
 */
void
GCP_request_mq_cancel (struct GCP_MessageQueueManager *mqm,
                       struct GNUNET_MQ_Envelope *last_env)
{
  struct CadetPeer *cp = mqm->cp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying MQM %p for peer %s%s\n",
       mqm,
       GCP_2s (cp),
       (NULL == last_env) ? "" : " with last ditch transmission");
  if (NULL != mqm->env)
    GNUNET_MQ_discard (mqm->env);
  if (NULL != last_env)
  {
    if (NULL != cp->core_mq)
    {
      GNUNET_MQ_notify_sent (last_env,
                             &mqm_send_done,
                             cp);
      GNUNET_MQ_send (cp->core_mq,
                      last_env);
    }
    else
    {
      GNUNET_MQ_discard (last_env);
    }
  }
  if (cp->mqm_ready_ptr == mqm)
    cp->mqm_ready_ptr = mqm->next;
  GNUNET_CONTAINER_DLL_remove (cp->mqm_head,
                               cp->mqm_tail,
                               mqm);
  GNUNET_free (mqm);
}


/**
 * Send the message in @a env to @a cp, overriding queueing logic.
 * This function should only be used to send error messages outside
 * of flow and congestion control, similar to ICMP.  Note that
 * the envelope may be silently discarded as well.
 *
 * @param cp peer to send the message to
 * @param env envelope with the message to send
 */
void
GCP_send_ooo (struct CadetPeer *cp,
              struct GNUNET_MQ_Envelope *env)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending message to %s out of management\n",
       GCP_2s (cp));
  if (NULL == cp->core_mq)
  {
    GNUNET_MQ_discard (env);
    return;
  }
  if (GNUNET_MQ_get_length (cp->core_mq) > MAX_OOO_QUEUE_SIZE)
  {
    GNUNET_MQ_discard (env);
    return;
  }
  GNUNET_MQ_notify_sent (env,
                         &mqm_send_done,
                         cp);
  GNUNET_MQ_send (cp->core_mq,
                  env);
}

/**
 * Checking if a monotime value is newer than the last monotime value received from a peer. If the time value is newer it will be stored at the peer.
 *
 * @param peer The peer we received a new time value from.
 * @param monotime Time value we check against the last time value we received from a peer.
 * @return GNUNET_YES if monotime is newer than the last received time value, GNUNET_NO if monotime is not newer.
 */
int
GCP_check_and_update_monotime (struct CadetPeer *peer,
                               struct GNUNET_TIME_AbsoluteNBO monotime)
{

  struct GNUNET_TIME_Absolute mt = GNUNET_TIME_absolute_ntoh (monotime);

  if (mt.abs_value_us > *(&peer->last_connection_create.abs_value_us))
  {
    peer->last_connection_create = mt;
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * Checking the signature for a monotime of a GNUNET_CADET_ConnectionCreateMessage.
 *
 * @param peer The peer that signed the monotime value.
 * @param msg The GNUNET_CADET_ConnectionCreateMessage with the monotime value.
 * @return GNUNET_OK if the signature is good, GNUNET_SYSERR if not.
 */
int
GCP_check_monotime_sig (struct CadetPeer *peer,
                        const struct GNUNET_CADET_ConnectionCreateMessage *msg)
{
  struct CadetConnectionCreatePS cp = { .purpose.purpose = htonl (
                                          GNUNET_SIGNATURE_PURPOSE_CADET_CONNECTION_INITIATOR),
                                        .purpose.size = htonl (sizeof(cp)),
                                        .monotonic_time = msg->monotime};

  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (
        GNUNET_SIGNATURE_PURPOSE_CADET_CONNECTION_INITIATOR,
        &cp,
        &msg->monotime_sig,
        &peer->pid.public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/* end of gnunet-service-cadet-new_peer.c */
