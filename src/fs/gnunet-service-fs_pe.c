/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * List of GSF_PendingRequests this request plan
 * participates with.
 */
struct PendingRequestList;

/**
 * Transmission plan for a peer.
 */
struct PeerPlan;


/**
 * DLL of request plans a particular pending request is
 * involved with.
 */
struct GSF_RequestPlanReference
{

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlanReference *next;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlanReference *prev;

  /**
   * Associated request plan.
   */
  struct GSF_RequestPlan *rp;

  /**
   * Corresponding PendingRequestList.
   */
  struct PendingRequestList *prl;
};


/**
 * List of GSF_PendingRequests this request plan
 * participates with.
 */
struct PendingRequestList
{

  /**
   * This is a doubly-linked list.
   */
  struct PendingRequestList *next;

  /**
   * This is a doubly-linked list.
   */
  struct PendingRequestList *prev;

  /**
   * Associated pending request.
   */
  struct GSF_PendingRequest *pr;

  /**
   * Corresponding GSF_RequestPlanReference.
   */
  struct GSF_RequestPlanReference *rpr;

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
  struct PendingRequestList *prl_head;

  /**
   * Tail of list of associated pending requests.
   */
  struct PendingRequestList *prl_tail;

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
  GNUNET_SCHEDULER_TaskIdentifier task;
};


/**
 * Hash map from peer identities to PeerPlans.
 */
static struct GNUNET_CONTAINER_MultiHashMap *plans;

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
 *
 * @param rp a request plan
 * @return the associated query
 */
static const GNUNET_HashCode *
get_rp_key (struct GSF_RequestPlan *rp)
{
  return &GSF_pending_request_get_data_ (rp->prl_head->pr)->query;
}


/**
 * Figure out when and how to transmit to the given peer.
 *
 * @param cls the 'struct GSF_ConnectedPeer' for transmission
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
  prd = GSF_pending_request_get_data_ (rp->prl_head->pr);

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
  delay.rel_value =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                delay.rel_value + 1);
  /* Add 0.01 to avg_delay to avoid division-by-zero later */
  avg_delay = (((avg_delay * (N - 1.0)) + delay.rel_value) / N) + 0.01;

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
              1.0) * atan (delay.rel_value / avg_delay)) / M_PI_4;
  /* Note: usage of 'round' and 'atan' requires -lm */

  if (rp->transmission_counter != 0)
    delay.rel_value += TTL_DECREMENT;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Considering (re)transmission number %u in %llu ms\n",
              (unsigned int) rp->transmission_counter,
              (unsigned long long) delay.rel_value);
  rp->earliest_transmission = GNUNET_TIME_relative_to_absolute (delay);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Earliest (re)transmission for `%s' in %us\n",
              GNUNET_h2s (&prd->query), rp->transmission_counter);
  GNUNET_assert (rp->hn == NULL);
  if (GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission).rel_value
      == 0)
    rp->hn = GNUNET_CONTAINER_heap_insert (pp->priority_heap, rp, rp->priority);
  else
    rp->hn =
        GNUNET_CONTAINER_heap_insert (pp->delay_heap, rp,
                                      rp->earliest_transmission.abs_value);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_contains_value (pp->plan_map,
                                                               get_rp_key (rp),
                                                               rp));
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
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
  struct PendingRequestList *prl;

  prl = rp->prl_head;
  ret = prl->pr;
  prl = prl->next;
  while (NULL != prl)
  {
    if (GSF_pending_request_get_data_ (prl->pr)->ttl.abs_value >
        GSF_pending_request_get_data_ (ret)->ttl.abs_value)
      ret = prl->pr;
    prl = prl->next;
  }
  return ret;
}


/**
 * Function called to get a message for transmission.
 *
 * @param cls closure
 * @param buf_size number of bytes available in buf
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
    pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
    return 0;
  }
  msize = GSF_pending_request_get_message_ (get_latest (rp), buf_size, buf);
  if (msize > buf_size)
  {
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
 * @param cls the 'struct PeerPlan'
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

  pp->task = GNUNET_SCHEDULER_NO_TASK;
  if (pp->pth != NULL)
  {
    GSF_peer_transmit_cancel_ (pp->pth);
    pp->pth = NULL;
  }
  /* move ready requests to priority queue */
  while ((NULL != (rp = GNUNET_CONTAINER_heap_peek (pp->delay_heap))) &&
         (GNUNET_TIME_absolute_get_remaining
          (rp->earliest_transmission).rel_value == 0))
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
                "Sleeping for %llu ms before retrying requests on plan %p.\n",
                (unsigned long long) delay.rel_value, pp);
    GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# delay heap timeout"),
                           delay.rel_value, GNUNET_NO);

    pp->task =
        GNUNET_SCHEDULER_add_delayed (delay, &schedule_peer_transmission, pp);
    return;
  }
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# query plans executed"),
                            1, GNUNET_NO);
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
 * Closure for 'merge_pr'.
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
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not (merge success)
 */
static int
merge_pr (void *cls, const GNUNET_HashCode * query, void *element)
{
  struct MergeContext *mpr = cls;
  struct GSF_RequestPlan *rp = element;
  struct GSF_PendingRequestData *prd;
  struct GSF_RequestPlanReference *rpr;
  struct PendingRequestList *prl;
  struct GSF_PendingRequest *latest;

  if (GNUNET_OK !=
      GSF_pending_request_is_compatible_ (mpr->pr, rp->prl_head->pr))
    return GNUNET_YES;
  /* merge new request with existing request plan */
  rpr = GNUNET_malloc (sizeof (struct GSF_RequestPlanReference));
  prl = GNUNET_malloc (sizeof (struct PendingRequestList));
  rpr->rp = rp;
  rpr->prl = prl;
  prl->rpr = rpr;
  prl->pr = mpr->pr;
  prd = GSF_pending_request_get_data_ (mpr->pr);
  GNUNET_CONTAINER_DLL_insert (prd->rpr_head, prd->rpr_tail, rpr);
  GNUNET_CONTAINER_DLL_insert (rp->prl_head, rp->prl_tail, prl);
  mpr->merged = GNUNET_YES;
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# requests merged"), 1,
                            GNUNET_NO);
  latest = get_latest (rp);
  if (GSF_pending_request_get_data_ (latest)->ttl.abs_value <
      prd->ttl.abs_value)
  {
    GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# requests refreshed"),
                              1, GNUNET_NO);
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
GSF_plan_add_ (struct GSF_ConnectedPeer *cp, struct GSF_PendingRequest *pr)
{
  struct GNUNET_PeerIdentity id;
  struct PeerPlan *pp;
  struct GSF_PendingRequestData *prd;
  struct GSF_RequestPlan *rp;
  struct GSF_RequestPlanReference *rpr;
  struct PendingRequestList *prl;
  struct MergeContext mpc;

  GNUNET_assert (NULL != cp);
  GSF_connected_peer_get_identity_ (cp, &id);
  pp = GNUNET_CONTAINER_multihashmap_get (plans, &id.hashPubKey);
  if (NULL == pp)
  {
    pp = GNUNET_malloc (sizeof (struct PeerPlan));
    pp->plan_map = GNUNET_CONTAINER_multihashmap_create (128);
    pp->priority_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
    pp->delay_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
    pp->cp = cp;
    GNUNET_CONTAINER_multihashmap_put (plans, &id.hashPubKey, pp,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  mpc.merged = GNUNET_NO;
  mpc.pr = pr;
  GNUNET_CONTAINER_multihashmap_get_multiple (pp->plan_map,
                                              &GSF_pending_request_get_data_
                                              (pr)->query, &merge_pr, &mpc);
  if (mpc.merged != GNUNET_NO)
    return;
  GNUNET_CONTAINER_multihashmap_get_multiple (pp->plan_map,
                                              &GSF_pending_request_get_data_
                                              (pr)->query, &merge_pr, &mpc);
  if (mpc.merged != GNUNET_NO)
    return;
  plan_count++;
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# query plan entries"), 1,
                            GNUNET_NO);
  prd = GSF_pending_request_get_data_ (pr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Planning transmission of query `%s' to peer `%s'\n",
              GNUNET_h2s (&prd->query), GNUNET_i2s (&id));
  rp = GNUNET_malloc (sizeof (struct GSF_RequestPlan));
  rpr = GNUNET_malloc (sizeof (struct GSF_RequestPlanReference));
  prl = GNUNET_malloc (sizeof (struct PendingRequestList));
  rpr->rp = rp;
  rpr->prl = prl;
  prl->rpr = rpr;
  prl->pr = pr;
  GNUNET_CONTAINER_DLL_insert (prd->rpr_head, prd->rpr_tail, rpr);
  GNUNET_CONTAINER_DLL_insert (rp->prl_head, rp->prl_tail, prl);
  rp->pp = pp;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_put (pp->plan_map,
                                                    get_rp_key (rp), rp,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  plan (pp, rp);
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
  struct GNUNET_PeerIdentity id;
  struct PeerPlan *pp;
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;
  struct PendingRequestList *prl;

  GSF_connected_peer_get_identity_ (cp, &id);
  pp = GNUNET_CONTAINER_multihashmap_get (plans, &id.hashPubKey);
  if (NULL == pp)
    return;                     /* nothing was ever planned for this peer */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (plans, &id.hashPubKey,
                                                       pp));
  if (NULL != pp->pth)
    GSF_peer_transmit_cancel_ (pp->pth);
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
  {
    GNUNET_SCHEDULER_cancel (pp->task);
    pp->task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->priority_heap)))
  {
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_remove (pp->plan_map,
                                                        get_rp_key (rp), rp));
    while (NULL != (prl = rp->prl_head))
    {
      GNUNET_CONTAINER_DLL_remove (rp->prl_head, rp->prl_tail, prl);
      prd = GSF_pending_request_get_data_ (prl->pr);
      GNUNET_CONTAINER_DLL_remove (prd->rpr_head, prd->rpr_tail, prl->rpr);
      GNUNET_free (prl->rpr);
      GNUNET_free (prl);
    }
    GNUNET_free (rp);
  }
  GNUNET_CONTAINER_heap_destroy (pp->priority_heap);
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->delay_heap)))
  {
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_remove (pp->plan_map,
                                                        get_rp_key (rp), rp));
    while (NULL != (prl = rp->prl_head))
    {
      GNUNET_CONTAINER_DLL_remove (rp->prl_head, rp->prl_tail, prl);
      prd = GSF_pending_request_get_data_ (prl->pr);
      GNUNET_CONTAINER_DLL_remove (prd->rpr_head, prd->rpr_tail, prl->rpr);
      GNUNET_free (prl->rpr);
      GNUNET_free (prl);
    }
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
 * referenced by 'rpr_head', that was sent to 'sender'
 *
 * @param rpr_head request plan reference list to check.
 * @param sender the peer that we've sent the request to.
 * @param result the timestamp to fill.
 * @return GNUNET_YES if 'result' was changed, GNUNET_NO otherwise.
 */
int
GSF_request_plan_reference_get_last_transmission_ (
    struct GSF_RequestPlanReference *rpr_head, struct GSF_ConnectedPeer *sender,
    struct GNUNET_TIME_Absolute *result)
{
  struct GSF_RequestPlanReference *rpr;
  for (rpr = rpr_head; rpr; rpr = rpr->next)
  {
    if (rpr->rp->pp->cp == sender)
    {
      *result = rpr->rp->last_transmission;
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
  struct GSF_RequestPlanReference *rpr;

  prd = GSF_pending_request_get_data_ (pr);
  while (NULL != (rpr = prd->rpr_head))
  {
    GNUNET_CONTAINER_DLL_remove (prd->rpr_head, prd->rpr_tail, rpr);
    rp = rpr->rp;
    GNUNET_CONTAINER_DLL_remove (rp->prl_head, rp->prl_tail, rpr->prl);
    if (NULL == rp->prl_head)
    {
      GNUNET_CONTAINER_heap_remove_node (rp->hn);
      plan_count--;
      GNUNET_break (GNUNET_YES ==
                    GNUNET_CONTAINER_multihashmap_remove (rp->pp->plan_map,
                                                          &GSF_pending_request_get_data_
                                                          (rpr->prl->pr)->query,
                                                          rp));
      GNUNET_free (rp);
    }
    GNUNET_free (rpr->prl);
    GNUNET_free (rpr);
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
  plans = GNUNET_CONTAINER_multihashmap_create (256);
}


/**
 * Shutdown plan subsystem.
 */
void
GSF_plan_done ()
{
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (plans));
  GNUNET_CONTAINER_multihashmap_destroy (plans);
}



/* end of gnunet-service-fs_pe.h */
