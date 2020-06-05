/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_core.c
 * @brief cadet service; interaction with CORE service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCO (Gnunet Cadet cOre (bottom))
 *
 * TODO:
 * - Optimization: given BROKEN messages, destroy paths (?)
 */
#include "platform.h"
#include "gnunet-service-cadet_core.h"
#include "gnunet-service-cadet_paths.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_tunnels.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "cadet_protocol.h"

#define LOG(level, ...) GNUNET_log_from (level, "cadet-cor", __VA_ARGS__)

/**
 * Information we keep per direction for a route.
 */
struct RouteDirection;

/**
 * Set of CadetRoutes that have exactly the same number of messages
 * in their buffer.  Used so we can efficiently find all of those
 * routes that have the current maximum of messages in the buffer (in
 * case we have to purge).
 */
struct Rung
{
  /**
   * Rung of RouteDirections with one more buffer entry each.
   */
  struct Rung *next;

  /**
   * Rung of RouteDirections with one less buffer entry each.
   */
  struct Rung *prev;

  /**
   * DLL of route directions with a number of buffer entries matching this rung.
   */
  struct RouteDirection *rd_head;

  /**
   * DLL of route directions with a number of buffer entries matching this rung.
   */
  struct RouteDirection *rd_tail;

  /**
   * Total number of route directions in this rung.
   */
  unsigned int num_routes;

  /**
   * Number of messages route directions at this rung have
   * in their buffer.
   */
  unsigned int rung_off;
};


/**
 * Information we keep per direction for a route.
 */
struct RouteDirection
{
  /**
   * DLL of other route directions within the same `struct Rung`.
   */
  struct RouteDirection *prev;

  /**
   * DLL of other route directions within the same `struct Rung`.
   */
  struct RouteDirection *next;

  /**
   * Rung of this route direction (matches length of the buffer DLL).
   */
  struct Rung *rung;

  /**
   * Head of DLL of envelopes we have in the buffer for this direction.
   */
  struct GNUNET_MQ_Envelope *env_head;

  /**
   * Tail of DLL of envelopes we have in the buffer for this direction.
   */
  struct GNUNET_MQ_Envelope *env_tail;

  /**
   * Target peer.
   */
  struct CadetPeer *hop;

  /**
   * Route this direction is part of.
   */
  struct CadetRoute *my_route;

  /**
   * Message queue manager for @e hop.
   */
  struct GCP_MessageQueueManager *mqm;

  /**
   * Is @e mqm currently ready for transmission?
   */
  int is_ready;
};


/**
 * Description of a segment of a `struct CadetConnection` at the
 * intermediate peers.  Routes are basically entries in a peer's
 * routing table for forwarding traffic.  At both endpoints, the
 * routes are terminated by a `struct CadetConnection`, which knows
 * the complete `struct CadetPath` that is formed by the individual
 * routes.
 */
struct CadetRoute
{
  /**
   * Information about the next hop on this route.
   */
  struct RouteDirection next;

  /**
   * Information about the previous hop on this route.
   */
  struct RouteDirection prev;

  /**
   * Unique identifier for the connection that uses this route.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * When was this route last in use?
   */
  struct GNUNET_TIME_Absolute last_use;

  /**
   * Position of this route in the #route_heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;
};


/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Routes on which this peer is an intermediate.
 */
static struct GNUNET_CONTAINER_MultiShortmap *routes;

/**
 * Heap of routes, MIN-sorted by last activity.
 */
static struct GNUNET_CONTAINER_Heap *route_heap;

/**
 * Rung zero (always pointed to by #rung_head).
 */
static struct Rung rung_zero;

/**
 * DLL of rungs, with the head always point to a rung of
 * route directions with no messages in the queue.
 */
static struct Rung *rung_head = &rung_zero;

/**
 * Tail of the #rung_head DLL.
 */
static struct Rung *rung_tail = &rung_zero;

/**
 * Maximum number of concurrent routes this peer will support.
 */
static unsigned long long max_routes;

/**
 * Maximum number of envelopes we will buffer at this peer.
 */
static unsigned long long max_buffers;

/**
 * Current number of envelopes we have buffered at this peer.
 */
static unsigned long long cur_buffers;

/**
 * Task to timeout routes.
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * Get the route corresponding to a hash.
 *
 * @param cid hash generated from the connection identifier
 */
static struct CadetRoute *
get_route (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  return GNUNET_CONTAINER_multishortmap_get (routes,
                                             &cid->connection_of_tunnel);
}


/**
 * Lower the rung in which @a dir is by 1.
 *
 * @param dir direction to lower in rung.
 */
static void
lower_rung (struct RouteDirection *dir)
{
  struct Rung *rung = dir->rung;
  struct Rung *prev;

  GNUNET_CONTAINER_DLL_remove (rung->rd_head, rung->rd_tail, dir);
  prev = rung->prev;
  GNUNET_assert (NULL != prev);
  if (prev->rung_off != rung->rung_off - 1)
  {
    prev = GNUNET_new (struct Rung);
    prev->rung_off = rung->rung_off - 1;
    GNUNET_CONTAINER_DLL_insert_after (rung_head, rung_tail, rung->prev, prev);
  }
  GNUNET_assert (NULL != prev);
  GNUNET_CONTAINER_DLL_insert (prev->rd_head, prev->rd_tail, dir);
  dir->rung = prev;
}


/**
 * Discard the buffer @a env from the route direction @a dir and
 * move @a dir down a rung.
 *
 * @param dir direction that contains the @a env in the buffer
 * @param env envelope to discard
 */
static void
discard_buffer (struct RouteDirection *dir, struct GNUNET_MQ_Envelope *env)
{
  GNUNET_MQ_dll_remove (&dir->env_head, &dir->env_tail, env);
  cur_buffers--;
  GNUNET_MQ_discard (env);
  lower_rung (dir);
  GNUNET_STATISTICS_set (stats, "# buffer use", cur_buffers, GNUNET_NO);
}


/**
 * Discard all messages from the highest rung, to make space.
 */
static void
discard_all_from_rung_tail ()
{
  struct Rung *tail = rung_tail;
  struct RouteDirection *dir;

  while (NULL != (dir = tail->rd_head))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue full due new message %s on connection %s, dropping old message\n",
         GNUNET_sh2s (&dir->my_route->cid.connection_of_tunnel));
    GNUNET_STATISTICS_update (stats,
                              "# messages dropped due to full buffer",
                              1,
                              GNUNET_NO);
    discard_buffer (dir, dir->env_head);
  }
  GNUNET_CONTAINER_DLL_remove (rung_head, rung_tail, tail);
  GNUNET_free (tail);
}


/**
 * We message @a msg from @a prev.  Find its route by @a cid and
 * forward to the next hop.  Drop and signal broken route if we do not
 * have a route.
 *
 * @param prev previous hop (sender)
 * @param cid connection identifier, tells us which route to use
 * @param msg the message to forward
 */
static void
route_message (struct CadetPeer *prev,
               const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
               const struct GNUNET_MessageHeader *msg,
               const enum GNUNET_MQ_PriorityPreferences priority)
{
  struct CadetRoute *route;
  struct RouteDirection *dir;
  struct Rung *rung;
  struct Rung *nxt;
  struct GNUNET_MQ_Envelope *env;

  route = get_route (cid);
  if (NULL == route)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionBrokenMessage *bm;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to route message of type %u from %s on connection %s: no route\n",
         ntohs (msg->type),
         GCP_2s (prev),
         GNUNET_sh2s (&cid->connection_of_tunnel));
    switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      /* No need to respond to these! */
      return;
    }
    env = GNUNET_MQ_msg (bm, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
    bm->cid = *cid;
    bm->peer1 = my_full_id;
    GCP_send_ooo (prev, env);
    return;
  }
  route->last_use = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_heap_update_cost (route->hn, route->last_use.abs_value_us);
  dir = (prev == route->prev.hop) ? &route->next : &route->prev;
  if (GNUNET_YES == dir->is_ready)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Routing message of type %u from %s to %s on connection %s\n",
         ntohs (msg->type),
         GCP_2s (prev),
         GNUNET_i2s (GCP_get_id (dir->hop)),
         GNUNET_sh2s (&cid->connection_of_tunnel));
    dir->is_ready = GNUNET_NO;
    GCP_send (dir->mqm, GNUNET_MQ_msg_copy (msg));
    return;
  }
  /* Check if low latency is required and if the previous message was
     unreliable; if so, make sure we only queue one message per
     direction (no buffering). */
  if ((0 != (priority & GNUNET_MQ_PREF_LOW_LATENCY)) &&
      (NULL != dir->env_head) &&
      (0 ==
       (GNUNET_MQ_env_get_options (dir->env_head) & GNUNET_MQ_PREF_UNRELIABLE)))
    discard_buffer (dir, dir->env_head);
  /* Check for duplicates */
  for (const struct GNUNET_MQ_Envelope *env = dir->env_head; NULL != env;
       env = GNUNET_MQ_env_next (env))
  {
    const struct GNUNET_MessageHeader *hdr = GNUNET_MQ_env_get_msg (env);

    if ((hdr->size == msg->size) && (0 == memcmp (hdr, msg, ntohs (msg->size))))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received duplicate of message already in buffer, dropping\n");
      GNUNET_STATISTICS_update (stats,
                                "# messages dropped due to duplicate in buffer",
                                1,
                                GNUNET_NO);
      return;
    }
  }

  rung = dir->rung;
  if (cur_buffers == max_buffers)
  {
    /* Need to make room. */
    if (NULL != rung->next)
    {
      /* Easy case, drop messages from route directions in highest rung */
      discard_all_from_rung_tail ();
    }
    else
    {
      /* We are in the highest rung, drop our own! */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Queue full due new message %s on connection %s, dropping old message\n",
           GNUNET_sh2s (&dir->my_route->cid.connection_of_tunnel));
      GNUNET_STATISTICS_update (stats,
                                "# messages dropped due to full buffer",
                                1,
                                GNUNET_NO);
      discard_buffer (dir, dir->env_head);
      rung = dir->rung;
    }
  }
  /* remove 'dir' from current rung */
  GNUNET_CONTAINER_DLL_remove (rung->rd_head, rung->rd_tail, dir);
  /* make 'nxt' point to the next higher rung, create if necessary */
  nxt = rung->next;
  if ((NULL == nxt) || (rung->rung_off + 1 != nxt->rung_off))
  {
    nxt = GNUNET_new (struct Rung);
    nxt->rung_off = rung->rung_off + 1;
    GNUNET_CONTAINER_DLL_insert_after (rung_head, rung_tail, rung, nxt);
  }
  /* insert 'dir' into next higher rung */
  GNUNET_CONTAINER_DLL_insert (nxt->rd_head, nxt->rd_tail, dir);
  dir->rung = nxt;

  /* add message into 'dir' buffer */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing new message of type %u from %s to %s on connection %s\n",
       ntohs (msg->type),
       GCP_2s (prev),
       GNUNET_i2s (GCP_get_id (dir->hop)),
       GNUNET_sh2s (&cid->connection_of_tunnel));
  env = GNUNET_MQ_msg_copy (msg);
  GNUNET_MQ_env_set_options (env, priority);
  if ((0 != (priority & GNUNET_MQ_PREF_LOW_LATENCY)) &&
      (0 != (priority & GNUNET_MQ_PREF_OUT_OF_ORDER)) &&
      (NULL != dir->env_head) &&
      (0 == (GNUNET_MQ_env_get_options (dir->env_head)
             & GNUNET_MQ_PREF_LOW_LATENCY)))
    GNUNET_MQ_dll_insert_head (&dir->env_head, &dir->env_tail, env);
  else
    GNUNET_MQ_dll_insert_tail (&dir->env_head, &dir->env_tail, env);
  cur_buffers++;
  GNUNET_STATISTICS_set (stats, "# buffer use", cur_buffers, GNUNET_NO);
  /* Clean up 'rung' if now empty (and not head) */
  if ((NULL == rung->rd_head) && (rung != rung_head))
  {
    GNUNET_CONTAINER_DLL_remove (rung_head, rung_tail, rung);
    GNUNET_free (rung);
  }
}


/**
 * Check if the create_connection message has the appropriate size.
 *
 * @param cls Closure (unused).
 * @param msg Message to check.
 *
 * @return #GNUNET_YES if size is correct, #GNUNET_NO otherwise.
 */
static int
check_connection_create (void *cls,
                         const struct GNUNET_CADET_ConnectionCreateMessage *msg)
{
  uint16_t size = ntohs (msg->header.size) - sizeof(*msg);

  if (0 != (size % sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Free internal data of a route direction.
 *
 * @param dir direction to destroy (do NOT free memory of 'dir' itself)
 */
static void
destroy_direction (struct RouteDirection *dir)
{
  struct GNUNET_MQ_Envelope *env;

  while (NULL != (env = dir->env_head))
  {
    GNUNET_STATISTICS_update (stats,
                              "# messages dropped due to route destruction",
                              1,
                              GNUNET_NO);
    discard_buffer (dir, env);
  }
  if (NULL != dir->mqm)
  {
    GCP_request_mq_cancel (dir->mqm, NULL);
    dir->mqm = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (rung_head->rd_head, rung_head->rd_tail, dir);
}


/**
 * Destroy our state for @a route.
 *
 * @param route route to destroy
 */
static void
destroy_route (struct CadetRoute *route)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying route from %s to %s of connection %s\n",
       GNUNET_i2s (GCP_get_id (route->prev.hop)),
       GNUNET_i2s2 (GCP_get_id (route->next.hop)),
       GNUNET_sh2s (&route->cid.connection_of_tunnel));
  GNUNET_assert (route == GNUNET_CONTAINER_heap_remove_node (route->hn));
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multishortmap_remove (routes,
                                           &route->cid.connection_of_tunnel,
                                           route));
  GNUNET_STATISTICS_set (stats,
                         "# routes",
                         GNUNET_CONTAINER_multishortmap_size (routes),
                         GNUNET_NO);
  destroy_direction (&route->prev);
  destroy_direction (&route->next);
  GNUNET_free (route);
}


/**
 * Send message that a route is broken between @a peer1 and @a peer2.
 *
 * @param target where to send the message
 * @param cid connection identifier to use
 * @param peer1 one of the peers where a link is broken
 * @param peer2 another one of the peers where a link is broken
 */
static void
send_broken (struct RouteDirection *target,
             const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
             const struct GNUNET_PeerIdentity *peer1,
             const struct GNUNET_PeerIdentity *peer2)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_ConnectionBrokenMessage *bm;

  if (NULL == target->mqm)
    return; /* Can't send notification, connection is down! */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying %s about BROKEN route at %s-%s of connection %s\n",
       GCP_2s (target->hop),
       GNUNET_i2s (peer1),
       GNUNET_i2s2 (peer2),
       GNUNET_sh2s (&cid->connection_of_tunnel));

  env = GNUNET_MQ_msg (bm, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
  bm->cid = *cid;
  if (NULL != peer1)
    bm->peer1 = *peer1;
  if (NULL != peer2)
    bm->peer2 = *peer2;
  GCP_request_mq_cancel (target->mqm, env);
  target->mqm = NULL;
}


/**
 * Function called to check if any routes have timed out, and if
 * so, to clean them up.  Finally, schedules itself again at the
 * earliest time where there might be more work.
 *
 * @param cls NULL
 */
static void
timeout_cb (void *cls)
{
  struct CadetRoute *r;
  struct GNUNET_TIME_Relative linger;
  struct GNUNET_TIME_Absolute exp;

  timeout_task = NULL;
  linger = GNUNET_TIME_relative_multiply (keepalive_period, 3);
  while (NULL != (r = GNUNET_CONTAINER_heap_peek (route_heap)))
  {
    exp = GNUNET_TIME_absolute_add (r->last_use, linger);
    if (0 != GNUNET_TIME_absolute_get_remaining (exp).rel_value_us)
    {
      /* Route not yet timed out, wait until it does. */
      timeout_task = GNUNET_SCHEDULER_add_at (exp, &timeout_cb, NULL);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Sending BROKEN due to timeout (%s was last use, %s linger)\n",
                GNUNET_STRINGS_absolute_time_to_string (r->last_use),
                GNUNET_STRINGS_relative_time_to_string (linger, GNUNET_YES));
    send_broken (&r->prev, &r->cid, NULL, NULL);
    send_broken (&r->next, &r->cid, NULL, NULL);
    destroy_route (r);
  }
  /* No more routes left, so no need for a #timeout_task */
}


/**
 * Function called when the message queue to the previous hop
 * becomes available/unavailable.  We expect this function to
 * be called immediately when we register, and then again
 * later if the connection ever goes down.
 *
 * @param cls the `struct RouteDirection`
 * @param available #GNUNET_YES if sending is now possible,
 *                  #GNUNET_NO if sending is no longer possible
 *                  #GNUNET_SYSERR if sending is no longer possible
 *                                 and the last envelope was discarded
 */
static void
dir_ready_cb (void *cls, int ready)
{
  struct RouteDirection *dir = cls;
  struct CadetRoute *route = dir->my_route;
  struct RouteDirection *odir;

  if (GNUNET_YES == ready)
  {
    struct GNUNET_MQ_Envelope *env;

    dir->is_ready = GNUNET_YES;
    if (NULL != (env = dir->env_head))
    {
      GNUNET_MQ_dll_remove (&dir->env_head, &dir->env_tail, env);
      cur_buffers--;
      GNUNET_STATISTICS_set (stats, "# buffer use", cur_buffers, GNUNET_NO);
      lower_rung (dir);
      dir->is_ready = GNUNET_NO;
      GCP_send (dir->mqm, env);
    }
    return;
  }
  odir = (dir == &route->next) ? &route->prev : &route->next;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending BROKEN due to MQ going down\n");
  send_broken (&route->next, &route->cid, GCP_get_id (odir->hop), &my_full_id);
  destroy_route (route);
}


/**
 * Initialize one of the directions of a route.
 *
 * @param route route the direction belongs to
 * @param dir direction to initialize
 * @param hop next hop on in the @a dir
 */
static void
dir_init (struct RouteDirection *dir,
          struct CadetRoute *route,
          struct CadetPeer *hop)
{
  dir->hop = hop;
  dir->my_route = route;
  dir->mqm = GCP_request_mq (hop, &dir_ready_cb, dir);
  GNUNET_CONTAINER_DLL_insert (rung_head->rd_head, rung_head->rd_tail, dir);
  dir->rung = rung_head;
  GNUNET_assert (GNUNET_YES == dir->is_ready);
}


/**
 * We could not create the desired route.  Send a
 * #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN
 * message to @a target.
 *
 * @param target who should receive the message
 * @param cid identifier of the connection/route that failed
 * @param failure_at neighbour with which we failed to route,
 *        or NULL.
 */
static void
send_broken_without_mqm (
  struct CadetPeer *target,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
  const struct GNUNET_PeerIdentity *failure_at)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_ConnectionBrokenMessage *bm;

  env = GNUNET_MQ_msg (bm, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
  bm->cid = *cid;
  bm->peer1 = my_full_id;
  if (NULL != failure_at)
    bm->peer2 = *failure_at;
  GCP_send_ooo (target, env);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_create (
  void *cls,
  const struct GNUNET_CADET_ConnectionCreateMessage *msg)
{
  struct CadetPeer *sender = cls;
  struct CadetPeer *next;
  const struct GNUNET_PeerIdentity *pids =
    (const struct GNUNET_PeerIdentity *) &msg[1];
  struct CadetRoute *route;
  uint16_t size = ntohs (msg->header.size) - sizeof(*msg);
  unsigned int path_length;
  unsigned int off;
  struct CadetTunnel *t;

  path_length = size / sizeof(struct GNUNET_PeerIdentity);
  if (0 == path_length)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping CADET_CONNECTION_CREATE with empty path\n");
    GNUNET_break_op (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling CADET_CONNECTION_CREATE from %s for CID %s with %u hops\n",
       GCP_2s (sender),
       GNUNET_sh2s (&msg->cid.connection_of_tunnel),
       path_length);
  /* Check for loops */
  {
    struct GNUNET_CONTAINER_MultiPeerMap *map;

    map = GNUNET_CONTAINER_multipeermap_create (path_length * 2, GNUNET_YES);
    GNUNET_assert (NULL != map);
    for (unsigned int i = 0; i < path_length; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "CADET_CONNECTION_CREATE has peer %s at offset %u\n",
           GNUNET_i2s (&pids[i]),
           i);
      if (GNUNET_SYSERR == GNUNET_CONTAINER_multipeermap_put (
            map,
            &pids[i],
            NULL,
            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
      {
        /* bogus request */
        GNUNET_CONTAINER_multipeermap_destroy (map);
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Dropping CADET_CONNECTION_CREATE with cyclic path\n");
        GNUNET_break_op (0);
        return;
      }
    }
    GNUNET_CONTAINER_multipeermap_destroy (map);
  }
  /* Initiator is at offset 0, find us */
  for (off = 1; off < path_length; off++)
    if (0 == GNUNET_memcmp (&my_full_id, &pids[off]))
      break;
  if (off == path_length)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping CADET_CONNECTION_CREATE without us in the path\n");
    GNUNET_break_op (0);
    return;
  }
  /* Check previous hop */
  if (sender != GCP_get (&pids[off - 1], GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping CADET_CONNECTION_CREATE without sender at previous hop in the path\n");
    GNUNET_break_op (0);
    return;
  }
  if (NULL != (route = get_route (&msg->cid)))
  {
    /* Duplicate CREATE, pass it on, previous one might have been lost! */

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Passing on duplicate CADET_CONNECTION_CREATE message on connection %s\n",
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));
    route_message (sender,
                   &msg->cid,
                   &msg->header,
                   GNUNET_MQ_PRIO_CRITICAL_CONTROL
                   | GNUNET_MQ_PREF_LOW_LATENCY);
    return;
  }
  if (off == path_length - 1)
  {
    /* We are the destination, create connection */
    struct CadetConnection *cc;
    struct CadetPeerPath *path;
    struct CadetPeer *origin;

    cc = GCC_lookup (&msg->cid);
    if (NULL != cc)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received duplicate CADET_CONNECTION_CREATE message on connection %s\n",
           GNUNET_sh2s (&msg->cid.connection_of_tunnel));
      GCC_handle_duplicate_create (cc);
      return;
    }

    origin = GCP_get (&pids[0], GNUNET_YES);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "I am destination for CADET_CONNECTION_CREATE message from %s for connection %s, building inverse path\n",
         GCP_2s (origin),
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));
    path = GCPP_get_path_from_route (path_length - 1, pids);
    t = GCP_get_tunnel (sender, GNUNET_YES);

    // Check for CADET state in case the other side has lost the tunnel (xrs,t3ss)
    if ((GNUNET_YES == msg->has_monotime) &&
        (GNUNET_YES == GCP_check_and_update_monotime(origin, msg->monotime)) &&
        ( GNUNET_OK == GCP_check_monotime_sig(origin, msg)) &&
         (CADET_TUNNEL_KEY_OK == GCT_get_estate(t)))
    {
      GCT_change_estate (t, CADET_TUNNEL_KEY_UNINITIALIZED);
    }

    if (GNUNET_OK !=
        GCT_add_inbound_connection (t,
                                    &msg->cid,
                                    path))
    {
      /* Send back BROKEN: duplicate connection on the same path,
         we will use the other one. */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received CADET_CONNECTION_CREATE from %s for %s, but %s already has a connection. Sending BROKEN\n",
           GCP_2s (sender),
           GNUNET_sh2s (&msg->cid.connection_of_tunnel),
           GCPP_2s (path));
      send_broken_without_mqm (sender, &msg->cid, NULL);
      return;
    }
    return;
  }
  /* We are merely a hop on the way, check if we can support the route */
  next = GCP_get (&pids[off + 1], GNUNET_NO);
  if ((NULL == next) || (GNUNET_NO == GCP_has_core_connection (next)))
  {
    /* unworkable, send back BROKEN notification */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CADET_CONNECTION_CREATE from %s for %s. Next hop %s:%u is down. Sending BROKEN\n",
         GCP_2s (sender),
         GNUNET_sh2s (&msg->cid.connection_of_tunnel),
         GNUNET_i2s (&pids[off + 1]),
         off + 1);
    send_broken_without_mqm (sender, &msg->cid, &pids[off + 1]);
    return;
  }
  if (max_routes <= GNUNET_CONTAINER_multishortmap_size (routes))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CADET_CONNECTION_CREATE from %s for %s. We have reached our route limit. Sending BROKEN\n",
         GCP_2s (sender),
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));
    send_broken_without_mqm (sender, &msg->cid, &pids[off - 1]);
    return;
  }

  /* Workable route, create routing entry */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received CADET_CONNECTION_CREATE from %s for %s. Next hop %s:%u is up. Creating route\n",
       GCP_2s (sender),
       GNUNET_sh2s (&msg->cid.connection_of_tunnel),
       GNUNET_i2s (&pids[off + 1]),
       off + 1);
  route = GNUNET_new (struct CadetRoute);
  route->cid = msg->cid;
  route->last_use = GNUNET_TIME_absolute_get ();
  dir_init (&route->prev, route, sender);
  dir_init (&route->next, route, next);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (
                   routes,
                   &route->cid.connection_of_tunnel,
                   route,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (stats,
                         "# routes",
                         GNUNET_CONTAINER_multishortmap_size (routes),
                         GNUNET_NO);
  route->hn = GNUNET_CONTAINER_heap_insert (route_heap,
                                            route,
                                            route->last_use.abs_value_us);
  if (NULL == timeout_task)
    timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (
                                      keepalive_period,
                                      3),
                                    &timeout_cb,
                                    NULL);
  /* also pass CREATE message along to next hop */
  route_message (sender,
                 &msg->cid,
                 &msg->header,
                 GNUNET_MQ_PRIO_CRITICAL_CONTROL | GNUNET_MQ_PREF_LOW_LATENCY);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_create_ack (
  void *cls,
  const struct GNUNET_CADET_ConnectionCreateAckMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if ACK belongs to a connection that ends here. */
  cc = GCC_lookup (&msg->cid);
  if (NULL != cc)
  {
    /* verify ACK came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received ACK from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CONNECTION_CREATE_ACK for connection %s.\n",
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));
    GCC_handle_connection_create_ack (cc);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header,
                 GNUNET_MQ_PRIO_CRITICAL_CONTROL | GNUNET_MQ_PREF_LOW_LATENCY);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 * @deprecated duplicate logic with #handle_destroy(); dedup!
 */
static void
handle_connection_broken (
  void *cls,
  const struct GNUNET_CADET_ConnectionBrokenMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;
  struct CadetRoute *route;

  /* First, check if message belongs to a connection that ends here. */
  cc = GCC_lookup (&msg->cid);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CONNECTION_BROKEN for connection %s. Destroying it.\n",
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));
    GCC_destroy_without_core (cc);

    /* FIXME: also destroy the path up to the specified link! */
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header,
                 GNUNET_MQ_PREF_LOW_LATENCY | GNUNET_MQ_PRIO_CRITICAL_CONTROL);
  route = get_route (&msg->cid);
  if (NULL != route)
    destroy_route (route);
  /* FIXME: also destroy paths we MAY have up to the specified link! */
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_destroy (
  void *cls,
  const struct GNUNET_CADET_ConnectionDestroyMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;
  struct CadetRoute *route;

  /* First, check if message belongs to a connection that ends here. */
  cc = GCC_lookup (&msg->cid);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CONNECTION_DESTROY for connection %s. Destroying connection.\n",
         GNUNET_sh2s (&msg->cid.connection_of_tunnel));

    GCC_destroy_without_core (cc);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received CONNECTION_DESTROY for connection %s. Destroying route.\n",
       GNUNET_sh2s (&msg->cid.connection_of_tunnel));
  route_message (peer,
                 &msg->cid,
                 &msg->header,
                 GNUNET_MQ_PREF_LOW_LATENCY | GNUNET_MQ_PRIO_CRITICAL_CONTROL);
  route = get_route (&msg->cid);
  if (NULL != route)
    destroy_route (route);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_tunnel_kx (void *cls,
                  const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if message belongs to a connection that ends here. */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Routing KX with ephemeral %s on CID %s\n",
       GNUNET_e2s (&msg->ephemeral_key),
       GNUNET_sh2s (&msg->cid.connection_of_tunnel));


  cc = GCC_lookup (&msg->cid);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_kx (cc, msg);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header,
                 GNUNET_MQ_PRIO_CRITICAL_CONTROL | GNUNET_MQ_PREF_LOW_LATENCY);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_tunnel_kx_auth (
  void *cls,
  const struct GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if message belongs to a connection that ends here. */
  cc = GCC_lookup (&msg->kx.cid);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_kx_auth (cc, msg);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->kx.cid,
                 &msg->kx.header,
                 GNUNET_MQ_PRIO_CRITICAL_CONTROL | GNUNET_MQ_PREF_LOW_LATENCY);
}


/**
 * Check if the encrypted message has the appropriate size.
 *
 * @param cls Closure (unused).
 * @param msg Message to check.
 *
 * @return #GNUNET_YES if size is correct, #GNUNET_NO otherwise.
 */
static int
check_tunnel_encrypted (void *cls,
                        const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  return GNUNET_YES;
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED.
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_tunnel_encrypted (void *cls,
                         const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if message belongs to a connection that ends here. */
  cc = GCC_lookup (&msg->cid);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    unsigned int len;
    struct CadetPeerPath *path = GCC_get_path (cc, &len);

    if (peer != GCPP_get_peer_at_offset (path, 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_encrypted (cc, msg);
    return;
  }
  /* We're just an intermediary peer, route the message along its path */
  route_message (peer, &msg->cid, &msg->header, GNUNET_MQ_PRIO_BEST_EFFORT);
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_init_cb (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (0 == GNUNET_memcmp (my_identity, &my_full_id));
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void *
core_connect_cb (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  struct CadetPeer *cp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "CORE connection to peer %s was established.\n",
       GNUNET_i2s (peer));
  cp = GCP_get (peer, GNUNET_YES);
  GCP_set_mq (cp, mq);
  return cp;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *peer_cls)
{
  struct CadetPeer *cp = peer_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "CORE connection to peer %s went down.\n",
       GNUNET_i2s (peer));
  GCP_set_mq (cp, NULL);
}


/**
 * Initialize the CORE subsystem.
 *
 * @param c Configuration.
 */
void
GCO_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_var_size (connection_create,
                           GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE,
                           struct GNUNET_CADET_ConnectionCreateMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (connection_create_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK,
                             struct GNUNET_CADET_ConnectionCreateAckMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_broken,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN,
                             struct GNUNET_CADET_ConnectionBrokenMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY,
                             struct GNUNET_CADET_ConnectionDestroyMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (tunnel_kx,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX,
                             struct GNUNET_CADET_TunnelKeyExchangeMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (tunnel_kx_auth,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH,
                             struct GNUNET_CADET_TunnelKeyExchangeAuthMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (tunnel_encrypted,
                           GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED,
                           struct GNUNET_CADET_TunnelEncryptedMessage,
                           NULL),
    GNUNET_MQ_handler_end () };

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (c,
                                                          "CADET",
                                                          "MAX_ROUTES",
                                                          &max_routes))
    max_routes = 5000;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (c,
                                                          "CADET",
                                                          "MAX_MSGS_QUEUE",
                                                          &max_buffers))
    max_buffers = 10000;
  routes = GNUNET_CONTAINER_multishortmap_create (1024, GNUNET_NO);
  route_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  core = GNUNET_CORE_connect (c,
                              NULL,
                              &core_init_cb,
                              &core_connect_cb,
                              &core_disconnect_cb,
                              handlers);
}


/**
 * Shut down the CORE subsystem.
 */
void
GCO_shutdown ()
{
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  GNUNET_assert (0 == GNUNET_CONTAINER_multishortmap_size (routes));
  GNUNET_CONTAINER_multishortmap_destroy (routes);
  routes = NULL;
  GNUNET_CONTAINER_heap_destroy (route_heap);
  route_heap = NULL;
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
}


/* end of gnunet-cadet-service_core.c */
