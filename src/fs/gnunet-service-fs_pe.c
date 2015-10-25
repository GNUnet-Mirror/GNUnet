/*
     This file is part of GNUnet.
     Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_pe.c
 * @brief API to manage query plan
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_pe.h"
#include "gnunet-service-fs_pr.h"

/**
 * Collect an instane number of statistics?  May cause excessive IPC.
 */
#define INSANE_STATISTICS GNUNET_NO

/**
 * List of GSF_PendingRequests this request plan
 * participates with.
 */
struct PendingRequestList;

/**
 * Transmission plan for a peer.
 */
struct PeerPlan;


/**
 * M:N binding of plans to pending requests.
 * Each pending request can be in a number of plans,
 * and each plan can have a number of pending requests.
 * Objects of this type indicate a mapping of a plan to
 * a particular pending request.
 *
 * The corresponding head and tail of the "PE" MDLL
 * are stored in a `struct GSF_RequestPlan`. (We need
 * to be able to lookup all pending requests corresponding
 * to a given plan entry.)
 *
 * Similarly head and tail of the "PR" MDLL are stored
 * with the 'struct GSF_PendingRequest'.  (We need
 * to be able to lookup all plan entries corresponding
 * to a given pending request.)
 */
struct GSF_PendingRequestPlanBijection
{

  /**
   * This is a doubly-linked list.
   */
  struct GSF_PendingRequestPlanBijection *next_PR;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_PendingRequestPlanBijection *prev_PR;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_PendingRequestPlanBijection *next_PE;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_PendingRequestPlanBijection *prev_PE;

  /**
   * Associated request plan.
   */
  struct GSF_RequestPlan *rp;

  /**
   * Associated pending request.
   */
  struct GSF_PendingRequest *pr;

};


/**
 * Information we keep per request per peer.  This is a doubly-linked
 * list (with head and tail in the 'struct GSF_PendingRequestData')
 * with one entry in each heap of each 'struct PeerPlan'.  Each
 * entry tracks information relevant for this request and this peer.
 */
struct GSF_RequestPlan
{

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlan *next;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlan *prev;

  /**
   * Heap node associated with this request and this peer.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * The transmission plan for a peer that this request is associated with.
   */
  struct PeerPlan *pp;

  /**
   * Head of list of associated pending requests.
   */
  struct GSF_PendingRequestPlanBijection *pe_head;

  /**
   * Tail of list of associated pending requests.
   */
  struct GSF_PendingRequestPlanBijection *pe_tail;

  /**
   * Earliest time we'd be happy to (re)transmit this request.
   */
  struct GNUNET_TIME_Absolute earliest_transmission;

  /**
   * When was the last time we transmitted this request to this peer? 0 for never.
   */
  struct GNUNET_TIME_Absolute last_transmission;

  /**
   * Current priority for this request for this target.
   */
  uint64_t priority;

  /**
   * How often did we transmit this request to this peer?
   */
  unsigned int transmission_counter;

};


/**
 * Transmission plan for a peer.
 */
struct PeerPlan
{
  /**
   * Heap with pending queries (struct GSF_RequestPlan), higher weights mean higher priority.
   */
  struct GNUNET_CONTAINER_Heap *priority_heap;

  /**
   * Heap with pending queries (struct GSF_RequestPlan), by transmission time, lowest first.
   */
  struct GNUNET_CONTAINER_Heap *delay_heap;

  /**
   * Map of queries to plan entries.  All entries in the priority_heap or delay_heap
   * should be in the plan map.  Note that it IS possible for the plan map to have
   * multiple entries for the same query.
   */
  struct GNUNET_CONTAINER_MultiHashMap *plan_map;

  /**
   * Current transmission request handle.
   */
  struct GSF_PeerTransmitHandle *pth;

  /**
   * Peer for which this is the plan.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Current task for executing the plan.
   */
  struct GNUNET_SCHEDULER_Task * task;
};


/**
 * Hash map from peer identities to PeerPlans.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *plans;

/**
 * Sum of all transmission counters (equals total delay for all plan entries).
 */
static unsigned long long total_delay;

/**
 * Number of plan entries.
 */
static unsigned long long plan_count;


/**
 * Return the query (key in the plan_map) for the given request plan.
 * Note that this key may change as there can be multiple pending
 * requests for the same key and we just return _one_ of them; this
 * particular one might complete while another one might still be
 * active, hence the lifetime of the returned hash code is NOT
 * necessarily identical to that of the 'struct GSF_RequestPlan'
 * given.
 *
 * @param rp a request plan
 * @return the associated query
 */
static const struct GNUNET_HashCode *
get_rp_key (struct GSF_RequestPlan *rp)
{
  return &GSF_pending_request_get_data_ (rp->pe_head->pr)->query;
}


/**
 * Figure out when and how to transmit to the given peer.
 *
 * @param cls the `struct GSF_ConnectedPeer` for transmission
 * @param tc scheduler context
 */
static void
schedule_peer_transmission (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Insert the given request plan into the heap with the appropriate weight.
 *
 * @param pp associated peer's plan
 * @param rp request to plan
 */
static void
plan (struct PeerPlan *pp, struct GSF_RequestPlan *rp)
{
#define N ((double)128.0)
  /**
   * Running average delay we currently impose.
   */
  static double avg_delay;

  struct GSF_PendingRequestData *prd;
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert (rp->pp == pp);
  GNUNET_STATISTICS_set (GSF_stats,
                         gettext_noop ("# average retransmission delay (ms)"),
                         total_delay * 1000LL / plan_count, GNUNET_NO);
  prd = GSF_pending_request_get_data_ (rp->pe_head->pr);

  if (rp->transmission_counter < 8)
    delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       rp->transmission_counter);
  else if (rp->transmission_counter < 32)
    delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       8 +
                                       (1LL << (rp->transmission_counter - 8)));
  else
    delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       8 + (1LL << 24));
  delay.rel_value_us =
    GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
			      delay.rel_value_us + 1);
  /* Add 0.01 to avg_delay to avoid division-by-zero later */
  avg_delay = (((avg_delay * (N - 1.0)) + delay.rel_value_us) / N) + 0.01;

  /*
   * For the priority, we need to consider a few basic rules:
   * 1) if we just started requesting (delay is small), we should
   * virtually always have a priority of zero.
   * 2) for requests with average latency, our priority should match
   * the average priority observed on the network
   * 3) even the longest-running requests should not be WAY out of
   * the observed average (thus we bound by a factor of 2)
   * 4) we add +1 to the observed average priority to avoid everyone
   * staying put at zero (2 * 0 = 0...).
   *
   * Using the specific calculation below, we get:
   *
   * delay = 0 => priority = 0;
   * delay = avg delay => priority = running-average-observed-priority;
   * delay >> avg_delay => priority = 2 * running-average-observed-priority;
   *
   * which satisfies all of the rules above.
   *
   * Note: M_PI_4 = PI/4 = arctan(1)
   */
  rp->priority =
      round ((GSF_current_priorities +
              1.0) * atan (delay.rel_value_us / avg_delay)) / M_PI_4;
  /* Note: usage of 'round' and 'atan' requires -lm */

  if (rp->transmission_counter != 0)
    delay.rel_value_us += TTL_DECREMENT * 1000;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Considering (re)transmission number %u in %s\n",
              (unsigned int) rp->transmission_counter,
              GNUNET_STRINGS_relative_time_to_string (delay,
						      GNUNET_YES));
  rp->earliest_transmission = GNUNET_TIME_relative_to_absolute (delay);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Earliest (re)transmission for `%s' in %us\n",
              GNUNET_h2s (&prd->query), rp->transmission_counter);
  GNUNET_assert (rp->hn == NULL);
  if (0 == GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission).rel_value_us)
    rp->hn = GNUNET_CONTAINER_heap_insert (pp->priority_heap, rp, rp->priority);
  else
    rp->hn =
        GNUNET_CONTAINER_heap_insert (pp->delay_heap, rp,
                                      rp->earliest_transmission.abs_value_us);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_contains_value (pp->plan_map,
                                                               get_rp_key (rp),
                                                               rp));
  if (NULL != pp->task)
    GNUNET_SCHEDULER_cancel (pp->task);
  pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
#undef N
}


/**
 * Get the pending request with the highest TTL from the given plan.
 *
 * @param rp plan to investigate
 * @return pending request with highest TTL
 */
struct GSF_PendingRequest *
get_latest (const struct GSF_RequestPlan *rp)
{
  struct GSF_PendingRequest *ret;
  struct GSF_PendingRequestPlanBijection *bi;
  const struct GSF_PendingRequestData *rprd;
  const struct GSF_PendingRequestData *prd;

  bi = rp->pe_head;
  if (NULL == bi)
    return NULL; /* should never happen */
  ret = bi->pr;
  rprd = GSF_pending_request_get_data_ (ret);
  for (bi = bi->next_PE; NULL != bi; bi = bi->next_PE)
  {
    prd = GSF_pending_request_get_data_ (bi->pr);
    if (prd->ttl.abs_value_us >
        rprd->ttl.abs_value_us)
    {
      ret = bi->pr;
      rprd = prd;
    }
  }
  return ret;
}


/**
 * Function called to get a message for transmission.
 *
 * @param cls closure
 * @param buf_size number of bytes available in @a buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
static size_t
transmit_message_callback (void *cls, size_t buf_size, void *buf)
{
  struct PeerPlan *pp = cls;
  struct GSF_RequestPlan *rp;
  size_t msize;

  pp->pth = NULL;
  if (NULL == buf)
  {
    /* failed, try again... */
    if (NULL != pp->task)
      GNUNET_SCHEDULER_cancel (pp->task);

    pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# transmission failed (core has no bandwidth)"),
                              1, GNUNET_NO);
    return 0;
  }
  rp = GNUNET_CONTAINER_heap_peek (pp->priority_heap);
  if (NULL == rp)
  {
    if (NULL != pp->task)
      GNUNET_SCHEDULER_cancel (pp->task);
    pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
    return 0;
  }
  msize = GSF_pending_request_get_message_ (get_latest (rp), buf_size, buf);
  if (msize > buf_size)
  {
    if (NULL != pp->task)
      GNUNET_SCHEDULER_cancel (pp->task);
    /* buffer to small (message changed), try again */
    pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
    return 0;
  }
  /* remove from root, add again elsewhere... */
  GNUNET_assert (rp == GNUNET_CONTAINER_heap_remove_root (pp->priority_heap));
  rp->hn = NULL;
  rp->last_transmission = GNUNET_TIME_absolute_get ();
  rp->transmission_counter++;
  total_delay++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Executing plan %p executed %u times, planning retransmission\n",
              rp, rp->transmission_counter);
  plan (pp, rp);
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# query messages sent to other peers"), 1,
                            GNUNET_NO);
  return msize;
}


/**
 * Figure out when and how to transmit to the given peer.
 *
 * @param cls the `struct PeerPlan`
 * @param tc scheduler context
 */
static void
schedule_peer_transmission (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerPlan *pp = cls;
  struct GSF_RequestPlan *rp;
  size_t msize;
  struct GNUNET_TIME_Relative delay;

  pp->task = NULL;
  if (NULL != pp->pth)
  {
    GSF_peer_transmit_cancel_ (pp->pth);
    pp->pth = NULL;
  }
  /* move ready requests to priority queue */
  while ((NULL != (rp = GNUNET_CONTAINER_heap_peek (pp->delay_heap))) &&
         (0 == GNUNET_TIME_absolute_get_remaining
          (rp->earliest_transmission).rel_value_us))
  {
    GNUNET_assert (rp == GNUNET_CONTAINER_heap_remove_root (pp->delay_heap));
    rp->hn = GNUNET_CONTAINER_heap_insert (pp->priority_heap, rp, rp->priority);
  }
  if (0 == GNUNET_CONTAINER_heap_get_size (pp->priority_heap))
  {
    /* priority heap (still) empty, check for delay... */
    rp = GNUNET_CONTAINER_heap_peek (pp->delay_heap);
    if (NULL == rp)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No active requests for plan %p.\n",
                  pp);
      return;                   /* both queues empty */
    }
    delay = GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sleeping for %s before retrying requests on plan %p.\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
							GNUNET_YES),
		pp);
    GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# delay heap timeout (ms)"),
                           delay.rel_value_us / 1000LL, GNUNET_NO);

    pp->task =
        GNUNET_SCHEDULER_add_delayed (delay, &schedule_peer_transmission, pp);
    return;
  }
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# query plans executed"),
                            1, GNUNET_NO);
#endif
  /* process from priority heap */
  rp = GNUNET_CONTAINER_heap_peek (pp->priority_heap);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing query plan %p\n", rp);
  GNUNET_assert (NULL != rp);
  msize = GSF_pending_request_get_message_ (get_latest (rp), 0, NULL);
  pp->pth =
      GSF_peer_transmit_ (pp->cp, GNUNET_YES, rp->priority,
                          GNUNET_TIME_UNIT_FOREVER_REL, msize,
                          &transmit_message_callback, pp);
  GNUNET_assert (NULL != pp->pth);
}


/**
 * Closure for merge_pr().
 */
struct MergeContext
{

  struct GSF_PendingRequest *pr;

  int merged;

};


/**
 * Iterator that checks if an equivalent request is already
 * present for this peer.
 *
 * @param cls closure
 * @param query the query
 * @param element request plan stored at the node
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not (merge success)
 */
static int
merge_pr (void *cls,
          const struct GNUNET_HashCode *query,
          void *element)
{
  struct MergeContext *mpr = cls;
  struct GSF_RequestPlan *rp = element;
  struct GSF_PendingRequestData *prd;
  struct GSF_PendingRequestPlanBijection *bi;
  struct GSF_PendingRequest *latest;

  if (GNUNET_OK !=
      GSF_pending_request_is_compatible_ (mpr->pr,
                                          rp->pe_head->pr))
    return GNUNET_YES;
  /* merge new request with existing request plan */
  bi = GNUNET_new (struct GSF_PendingRequestPlanBijection);
  bi->rp = rp;
  bi->pr = mpr->pr;
  prd = GSF_pending_request_get_data_ (mpr->pr);
  GNUNET_CONTAINER_MDLL_insert (PR,
                                prd->pr_head,
                                prd->pr_tail,
                                bi);
  GNUNET_CONTAINER_MDLL_insert (PE,
                                rp->pe_head,
                                rp->pe_tail,
                                bi);
  mpr->merged = GNUNET_YES;
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# requests merged"), 1,
                            GNUNET_NO);
#endif
  latest = get_latest (rp);
  if (GSF_pending_request_get_data_ (latest)->ttl.abs_value_us <
      prd->ttl.abs_value_us)
  {
#if INSANE_STATISTICS
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# requests refreshed"),
                              1, GNUNET_NO);
#endif
    rp->transmission_counter = 0;       /* reset */
  }
  return GNUNET_NO;
}


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 */
void
GSF_plan_add_ (struct GSF_ConnectedPeer *cp,
               struct GSF_PendingRequest *pr)
{
  const struct GNUNET_PeerIdentity *id;
  struct PeerPlan *pp;
  struct GSF_PendingRequestData *prd;
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestPlanBijection *bi;
  struct MergeContext mpc;

  GNUNET_assert (NULL != cp);
  id = GSF_connected_peer_get_identity2_ (cp);
  pp = GNUNET_CONTAINER_multipeermap_get (plans, id);
  if (NULL == pp)
  {
    pp = GNUNET_new (struct PeerPlan);
    pp->plan_map = GNUNET_CONTAINER_multihashmap_create (128, GNUNET_NO);
    pp->priority_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
    pp->delay_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
    pp->cp = cp;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (plans,
                                                      id,
                                                      pp,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  mpc.merged = GNUNET_NO;
  mpc.pr = pr;
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_CONTAINER_multihashmap_get_multiple (pp->plan_map,
                                              &prd->query,
                                              &merge_pr,
                                              &mpc);
  if (GNUNET_NO != mpc.merged)
    return;
  plan_count++;
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# query plan entries"),
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Planning transmission of query `%s' to peer `%s'\n",
              GNUNET_h2s (&prd->query),
              GNUNET_i2s (id));
  rp = GNUNET_new (struct GSF_RequestPlan);
  bi = GNUNET_new (struct GSF_PendingRequestPlanBijection);
  bi->rp = rp;
  bi->pr = pr;
  GNUNET_CONTAINER_MDLL_insert (PR,
                                prd->pr_head,
                                prd->pr_tail,
                                bi);
  GNUNET_CONTAINER_MDLL_insert (PE,
                                rp->pe_head,
                                rp->pe_tail,
                                bi);
  rp->pp = pp;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_put (pp->plan_map,
                                                    get_rp_key (rp),
                                                    rp,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  plan (pp,
        rp);
}


/**
 * Notify the plan about a peer being no longer available;
 * destroy all entries associated with this peer.
 *
 * @param cp connected peer
 */
void
GSF_plan_notify_peer_disconnect_ (const struct GSF_ConnectedPeer *cp)
{
  const struct GNUNET_PeerIdentity *id;
  struct PeerPlan *pp;
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;
  struct GSF_PendingRequestPlanBijection *bi;

  id = GSF_connected_peer_get_identity2_ (cp);
  pp = GNUNET_CONTAINER_multipeermap_get (plans, id);
  if (NULL == pp)
    return;                     /* nothing was ever planned for this peer */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (plans, id,
                                                       pp));
  if (NULL != pp->pth)
  {
    GSF_peer_transmit_cancel_ (pp->pth);
    pp->pth = NULL;
  }
  if (NULL != pp->task)
  {
    GNUNET_SCHEDULER_cancel (pp->task);
    pp->task = NULL;
  }
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->priority_heap)))
  {
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_remove (pp->plan_map,
                                                        get_rp_key (rp), rp));
    while (NULL != (bi = rp->pe_head))
    {
      GNUNET_CONTAINER_MDLL_remove (PE, rp->pe_head, rp->pe_tail, bi);
      prd = GSF_pending_request_get_data_ (bi->pr);
      GNUNET_CONTAINER_MDLL_remove (PR, prd->pr_head, prd->pr_tail, bi);
      GNUNET_free (bi);
    }
    plan_count--;
    GNUNET_free (rp);
  }
  GNUNET_CONTAINER_heap_destroy (pp->priority_heap);
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->delay_heap)))
  {
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_remove (pp->plan_map,
                                                        get_rp_key (rp), rp));
    while (NULL != (bi = rp->pe_head))
    {
      prd = GSF_pending_request_get_data_ (bi->pr);
      GNUNET_CONTAINER_MDLL_remove (PE, rp->pe_head, rp->pe_tail, bi);
      GNUNET_CONTAINER_MDLL_remove (PR, prd->pr_head, prd->pr_tail, bi);
      GNUNET_free (bi);
    }
    plan_count--;
    GNUNET_free (rp);
  }
  GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# query plan entries"),
                         plan_count, GNUNET_NO);
  GNUNET_CONTAINER_heap_destroy (pp->delay_heap);
  GNUNET_CONTAINER_multihashmap_destroy (pp->plan_map);
  GNUNET_free (pp);
}


/**
 * Get the last transmission attempt time for the request plan list
 * referenced by @a pr_head, that was sent to @a sender
 *
 * @param pr_head request plan reference list to check.
 * @param sender the peer that we've sent the request to.
 * @param result the timestamp to fill, set to #GNUNET_TIME_UNIT_FOREVER_ABS if never transmitted
 * @return #GNUNET_YES if @a result was changed, #GNUNET_NO otherwise.
 */
int
GSF_request_plan_reference_get_last_transmission_ (struct GSF_PendingRequestPlanBijection *pr_head,
                                                   struct GSF_ConnectedPeer *sender,
                                                   struct GNUNET_TIME_Absolute *result)
{
  struct GSF_PendingRequestPlanBijection *bi;

  for (bi = pr_head; NULL != bi; bi = bi->next_PR)
  {
    if (bi->rp->pp->cp == sender)
    {
      if (0 == bi->rp->last_transmission.abs_value_us)
	*result = GNUNET_TIME_UNIT_FOREVER_ABS;
      else
	*result = bi->rp->last_transmission;
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * Notify the plan about a request being done; destroy all entries
 * associated with this request.
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (struct GSF_PendingRequest *pr)
{
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;
  struct GSF_PendingRequestPlanBijection *bi;

  prd = GSF_pending_request_get_data_ (pr);
  while (NULL != (bi = prd->pr_head))
  {
    rp = bi->rp;
    GNUNET_CONTAINER_MDLL_remove (PR, prd->pr_head, prd->pr_tail, bi);
    GNUNET_CONTAINER_MDLL_remove (PE, rp->pe_head, rp->pe_tail, bi);
    if (NULL == rp->pe_head)
    {
      GNUNET_CONTAINER_heap_remove_node (rp->hn);
      plan_count--;
      GNUNET_break (GNUNET_YES ==
                    GNUNET_CONTAINER_multihashmap_remove (rp->pp->plan_map,
							  &GSF_pending_request_get_data_
							  (bi->pr)->query,
                                                          rp));
      GNUNET_free (rp);
    }
    GNUNET_free (bi);
  }
  GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# query plan entries"),
                         plan_count, GNUNET_NO);
}


/**
 * Initialize plan subsystem.
 */
void
GSF_plan_init ()
{
  plans = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_YES);
}


/**
 * Shutdown plan subsystem.
 */
void
GSF_plan_done ()
{
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (plans));
  GNUNET_CONTAINER_multipeermap_destroy (plans);
}



/* end of gnunet-service-fs_pe.h */
