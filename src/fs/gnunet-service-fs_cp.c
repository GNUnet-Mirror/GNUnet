/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file fs/gnunet-service-fs_cp.c
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_load_lib.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_pe.h"
#include "gnunet-service-fs_pr.h"
#include "gnunet-service-fs_push.h"
#include "gnunet_peerstore_service.h"


/**
 * Ratio for moving average delay calculation.  The previous
 * average goes in with a factor of (n-1) into the calculation.
 * Must be > 0.
 */
#define RUNAVG_DELAY_N 16

/**
 * How often do we flush respect values to disk?
 */
#define RESPECT_FLUSH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After how long do we discard a reply?
 */
#define REPLY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Collect an instane number of statistics?  May cause excessive IPC.
 */
#define INSANE_STATISTICS GNUNET_NO


/**
 * Handle to cancel a transmission request.
 */
struct GSF_PeerTransmitHandle
{

  /**
   * Kept in a doubly-linked list.
   */
  struct GSF_PeerTransmitHandle *next;

  /**
   * Kept in a doubly-linked list.
   */
  struct GSF_PeerTransmitHandle *prev;

  /**
   * Time when this transmission request was issued.
   */
  struct GNUNET_TIME_Absolute transmission_request_start_time;

  /**
   * Envelope with the actual message.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Peer this request targets.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * #GNUNET_YES if this is a query, #GNUNET_NO for content.
   */
  int is_query;

  /**
   * Did we get a reservation already?
   */
  int was_reserved;

  /**
   * Priority of this request.
   */
  uint32_t priority;

};


/**
 * Handle for an entry in our delay list.
 */
struct GSF_DelayedHandle
{

  /**
   * Kept in a doubly-linked list.
   */
  struct GSF_DelayedHandle *next;

  /**
   * Kept in a doubly-linked list.
   */
  struct GSF_DelayedHandle *prev;

  /**
   * Peer this transmission belongs to.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Envelope of the message that was delayed.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Task for the delay.
   */
  struct GNUNET_SCHEDULER_Task *delay_task;

  /**
   * Size of the message.
   */
  size_t msize;

};


/**
 * Information per peer and request.
 */
struct PeerRequest
{

  /**
   * Handle to generic request (generic: from peer or local client).
   */
  struct GSF_PendingRequest *pr;

  /**
   * Which specific peer issued this request?
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Task for asynchronous stopping of this request.
   */
  struct GNUNET_SCHEDULER_Task *kill_task;

};


/**
 * A connected peer.
 */
struct GSF_ConnectedPeer
{

  /**
   * Performance data for this peer.
   */
  struct GSF_PeerPerformanceData ppd;

  /**
   * Time until when we blocked this peer from migrating
   * data to us.
   */
  struct GNUNET_TIME_Absolute last_migration_block;

  /**
   * Task scheduled to revive migration to this peer.
   */
  struct GNUNET_SCHEDULER_Task *mig_revive_task;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct GSF_PeerTransmitHandle *pth_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct GSF_PeerTransmitHandle *pth_tail;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct GSF_DelayedHandle *delayed_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct GSF_DelayedHandle *delayed_tail;

  /**
   * Context of our GNUNET_ATS_reserve_bandwidth call (or NULL).
   */
  struct GNUNET_ATS_ReservationContext *rc;

  /**
   * Task scheduled if we need to retry bandwidth reservation later.
   */
  struct GNUNET_SCHEDULER_Task *rc_delay_task;

  /**
   * Active requests from this neighbour, map of query to `struct PeerRequest`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *request_map;

  /**
   * Handle for an active request for transmission to this
   * peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Number of entries in @e delayed_head DLL.
   */
  unsigned int delay_queue_size;

  /**
   * Respect rating for this peer on disk.
   */
  uint32_t disk_respect;

  /**
   * Which offset in @e last_p2p_replies will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in @e last_client_replies will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into @e last_request_times ring buffer.
   */
  unsigned int last_request_times_off;

  /**
   * #GNUNET_YES if we did successfully reserve 32k bandwidth,
   * #GNUNET_NO if not.
   */
  int did_reserve;

  /**
   * Handle to the PEERSTORE iterate request for peer respect value
   */
  struct GNUNET_PEERSTORE_IterateContext *respect_iterate_req;

};


/**
 * Map from peer identities to `struct GSF_ConnectPeer` entries.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *cp_map;

/**
 * Handle to peerstore service.
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Task used to flush respect values to disk.
 */
static struct GNUNET_SCHEDULER_Task *fr_task;


/**
 * Update the latency information kept for the given peer.
 *
 * @param id peer record to update
 * @param latency current latency value
 */
void
GSF_update_peer_latency_ (const struct GNUNET_PeerIdentity *id,
			  struct GNUNET_TIME_Relative latency)
{
  struct GSF_ConnectedPeer *cp;

  cp = GSF_peer_get_ (id);
  if (NULL == cp)
    return; /* we're not yet connected at the core level, ignore */
  GNUNET_LOAD_value_set_decline (cp->ppd.transmission_delay,
                                 latency);
}


/**
 * Return the performance data record for the given peer
 *
 * @param cp peer to query
 * @return performance data record for the peer
 */
struct GSF_PeerPerformanceData *
GSF_get_peer_performance_data_ (struct GSF_ConnectedPeer *cp)
{
  return &cp->ppd;
}


/**
 * Core is ready to transmit to a peer, get the message.
 *
 * @param cp which peer to send a message to
 */
static void
peer_transmit (struct GSF_ConnectedPeer *cp);


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the `struct GSF_ConnectedPeer` of the peer for which we made the request
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
static void
ats_reserve_callback (void *cls,
                      const struct GNUNET_PeerIdentity *peer,
                      int32_t amount,
                      struct GNUNET_TIME_Relative res_delay);


/**
 * If ready (bandwidth reserved), try to schedule transmission via
 * core for the given handle.
 *
 * @param pth transmission handle to schedule
 */
static void
schedule_transmission (struct GSF_PeerTransmitHandle *pth)
{
  struct GSF_ConnectedPeer *cp;
  struct GNUNET_PeerIdentity target;

  cp = pth->cp;
  GNUNET_assert (0 != cp->ppd.pid);
  GNUNET_PEER_resolve (cp->ppd.pid, &target);

  if (0 != cp->inc_preference)
  {
    GNUNET_ATS_performance_change_preference (GSF_ats,
                                              &target,
                                              GNUNET_ATS_PREFERENCE_BANDWIDTH,
                                              (double) cp->inc_preference,
                                              GNUNET_ATS_PREFERENCE_END);
    cp->inc_preference = 0;
  }

  if ( (GNUNET_YES == pth->is_query) &&
       (GNUNET_YES != pth->was_reserved) )
  {
    /* query, need reservation */
    if (GNUNET_YES != cp->did_reserve)
      return;                   /* not ready */
    cp->did_reserve = GNUNET_NO;
    /* reservation already done! */
    pth->was_reserved = GNUNET_YES;
    cp->rc = GNUNET_ATS_reserve_bandwidth (GSF_ats,
                                           &target,
                                           DBLOCK_SIZE,
                                           &ats_reserve_callback,
                                           cp);
    return;
  }
  peer_transmit (cp);
}


/**
 * Core is ready to transmit to a peer, get the message.
 *
 * @param cp which peer to send a message to
 */
static void
peer_transmit (struct GSF_ConnectedPeer *cp)
{
  struct GSF_PeerTransmitHandle *pth = cp->pth_head;
  struct GSF_PeerTransmitHandle *pos;

  if (NULL == pth)
    return;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
                               cp->pth_tail,
                               pth);
  if (GNUNET_YES == pth->is_query)
  {
    cp->ppd.last_request_times[(cp->last_request_times_off++) %
                               MAX_QUEUE_PER_PEER] =
      GNUNET_TIME_absolute_get ();
    GNUNET_assert (0 < cp->ppd.pending_queries--);
  }
  else if (GNUNET_NO == pth->is_query)
  {
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  }
  GNUNET_LOAD_update (cp->ppd.transmission_delay,
                      GNUNET_TIME_absolute_get_duration
                      (pth->transmission_request_start_time).rel_value_us);
  GNUNET_MQ_send (cp->mq,
		  pth->env);
  GNUNET_free (pth);
  if (NULL != (pos = cp->pth_head))
  {
    GNUNET_assert (pos != pth);
    schedule_transmission (pos);
  }
}


/**
 * (re)try to reserve bandwidth from the given peer.
 *
 * @param cls the `struct GSF_ConnectedPeer` to reserve from
 */
static void
retry_reservation (void *cls)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_PeerIdentity target;

  GNUNET_PEER_resolve (cp->ppd.pid, &target);
  cp->rc_delay_task = NULL;
  cp->rc =
    GNUNET_ATS_reserve_bandwidth (GSF_ats,
                                  &target,
                                  DBLOCK_SIZE,
				  &ats_reserve_callback, cp);
}


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the `struct GSF_ConnectedPeer` of the peer for which we made the request
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
static void
ats_reserve_callback (void *cls,
                      const struct GNUNET_PeerIdentity *peer,
                      int32_t amount,
                      struct GNUNET_TIME_Relative res_delay)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GSF_PeerTransmitHandle *pth;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Reserved %d bytes / need to wait %s for reservation\n",
              (int) amount,
	      GNUNET_STRINGS_relative_time_to_string (res_delay, GNUNET_YES));
  cp->rc = NULL;
  if (0 == amount)
  {
    cp->rc_delay_task =
        GNUNET_SCHEDULER_add_delayed (res_delay,
                                      &retry_reservation,
                                      cp);
    return;
  }
  cp->did_reserve = GNUNET_YES;
  pth = cp->pth_head;
  if (NULL != pth)
  {
    /* reservation success, try transmission now! */
    peer_transmit (cp);
  }
}


/**
 * Function called by PEERSTORE with peer respect record
 *
 * @param cls handle to connected peer entry
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 */
static void
peer_respect_cb (void *cls,
                 const struct GNUNET_PEERSTORE_Record *record,
                 const char *emsg)
{
  struct GSF_ConnectedPeer *cp = cls;

  GNUNET_assert (NULL != cp->respect_iterate_req);
  if ( (NULL != record) &&
       (sizeof (cp->disk_respect) == record->value_size))
  {
    cp->disk_respect = *((uint32_t *)record->value);
    cp->ppd.respect += *((uint32_t *)record->value);
  }
  GSF_push_start_ (cp);
  if (NULL != record)
    GNUNET_PEERSTORE_iterate_cancel (cp->respect_iterate_req);
  cp->respect_iterate_req = NULL;
}


/**
 * Function called for each pending request whenever a new
 * peer connects, giving us a chance to decide about submitting
 * the existing request to the new peer.
 *
 * @param cls the `struct GSF_ConnectedPeer` of the new peer
 * @param key query for the request
 * @param pr handle to the pending request
 * @return #GNUNET_YES to continue to iterate
 */
static int
consider_peer_for_forwarding (void *cls,
                              const struct GNUNET_HashCode *key,
                              struct GSF_PendingRequest *pr)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_YES !=
      GSF_pending_request_test_active_ (pr))
    return GNUNET_YES; /* request is not actually active, skip! */
  GSF_connected_peer_get_identity_ (cp, &pid);
  if (GNUNET_YES !=
      GSF_pending_request_test_target_ (pr, &pid))
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# Loopback routes suppressed"),
                              1,
                              GNUNET_NO);
    return GNUNET_YES;
  }
  GSF_plan_add_ (cp, pr);
  return GNUNET_YES;
}


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param cls NULL
 * @param peer identity of peer that connected
 * @param mq message queue for talking to @a peer
 * @return our internal handle for the peer
 */
void *
GSF_peer_connect_handler (void *cls,
			  const struct GNUNET_PeerIdentity *peer,
			  struct GNUNET_MQ_Handle *mq)
{
  struct GSF_ConnectedPeer *cp;

  if (0 ==
      GNUNET_CRYPTO_cmp_peer_identity (&GSF_my_id,
                                       peer))
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to peer %s\n",
              GNUNET_i2s (peer));
  cp = GNUNET_new (struct GSF_ConnectedPeer);
  cp->ppd.pid = GNUNET_PEER_intern (peer);
  cp->ppd.peer = peer;
  cp->mq = mq;
  cp->ppd.transmission_delay = GNUNET_LOAD_value_init (GNUNET_TIME_UNIT_ZERO);
  cp->rc =
      GNUNET_ATS_reserve_bandwidth (GSF_ats,
                                    peer,
                                    DBLOCK_SIZE,
                                    &ats_reserve_callback, cp);
  cp->request_map = GNUNET_CONTAINER_multihashmap_create (128,
                                                          GNUNET_YES);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (cp_map,
               GSF_connected_peer_get_identity2_ (cp),
                                                   cp,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (GSF_stats,
                         gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multipeermap_size (cp_map),
                         GNUNET_NO);
  cp->respect_iterate_req 
    = GNUNET_PEERSTORE_iterate (peerstore,
				"fs",
                                peer,
				"respect",
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &peer_respect_cb,
                                cp);
  GSF_iterate_pending_requests_ (&consider_peer_for_forwarding,
                                 cp);
  return cp;
}


/**
 * It may be time to re-start migrating content to this
 * peer.  Check, and if so, restart migration.
 *
 * @param cls the `struct GSF_ConnectedPeer`
 */
static void
revive_migration (void *cls)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_TIME_Relative bt;

  cp->mig_revive_task = NULL;
  bt = GNUNET_TIME_absolute_get_remaining (cp->ppd.migration_blocked_until);
  if (0 != bt.rel_value_us)
  {
    /* still time left... */
    cp->mig_revive_task =
        GNUNET_SCHEDULER_add_delayed (bt, &revive_migration, cp);
    return;
  }
  GSF_push_start_ (cp);
}


/**
 * Get a handle for a connected peer.
 *
 * @param peer peer's identity
 * @return NULL if the peer is not currently connected
 */
struct GSF_ConnectedPeer *
GSF_peer_get_ (const struct GNUNET_PeerIdentity *peer)
{
  if (NULL == cp_map)
    return NULL;
  return GNUNET_CONTAINER_multipeermap_get (cp_map, peer);
}


/**
 * Handle P2P #GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP message. 
 *
 * @param cls closure, the `struct GSF_ConnectedPeer`
 * @param msm the actual message
 */
void
handle_p2p_migration_stop (void *cls,
			   const struct MigrationStopMessage *msm)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_TIME_Relative bt;

  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# migration stop messages received"),
                            1, GNUNET_NO);
  bt = GNUNET_TIME_relative_ntoh (msm->duration);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Migration of content to peer `%s' blocked for %s\n"),
              GNUNET_i2s (cp->ppd.peer),
	      GNUNET_STRINGS_relative_time_to_string (bt, GNUNET_YES));
  cp->ppd.migration_blocked_until = GNUNET_TIME_relative_to_absolute (bt);
  if ( (NULL == cp->mig_revive_task) &&
       (NULL == cp->respect_iterate_req) )
  {
    GSF_push_stop_ (cp);
    cp->mig_revive_task =
        GNUNET_SCHEDULER_add_delayed (bt,
                                      &revive_migration, cp);
  }
}


/**
 * Free resources associated with the given peer request.
 *
 * @param peerreq request to free
 */
static void
free_pending_request (struct PeerRequest *peerreq)
{
  struct GSF_ConnectedPeer *cp = peerreq->cp;
  struct GSF_PendingRequestData *prd;

  prd = GSF_pending_request_get_data_ (peerreq->pr);
  if (NULL != peerreq->kill_task)
  {
    GNUNET_SCHEDULER_cancel (peerreq->kill_task);
    peerreq->kill_task = NULL;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# P2P searches active"),
                            -1,
                            GNUNET_NO);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (cp->request_map,
                                                      &prd->query,
                                                      peerreq));
  GNUNET_free (peerreq);
}


/**
 * Cancel all requests associated with the peer.
 *
 * @param cls unused
 * @param query hash code of the request
 * @param value the `struct GSF_PendingRequest`
 * @return #GNUNET_YES (continue to iterate)
 */
static int
cancel_pending_request (void *cls,
                        const struct GNUNET_HashCode *query,
                        void *value)
{
  struct PeerRequest *peerreq = value;
  struct GSF_PendingRequest *pr = peerreq->pr;

  free_pending_request (peerreq);
  GSF_pending_request_cancel_ (pr,
                               GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Free the given request.
 *
 * @param cls the request to free
 */
static void
peer_request_destroy (void *cls)
{
  struct PeerRequest *peerreq = cls;
  struct GSF_PendingRequest *pr = peerreq->pr;
  struct GSF_PendingRequestData *prd;

  peerreq->kill_task = NULL;
  prd = GSF_pending_request_get_data_ (pr);
  cancel_pending_request (NULL,
                          &prd->query,
                          peerreq);
}


/**
 * The artificial delay is over, transmit the message now.
 *
 * @param cls the `struct GSF_DelayedHandle` with the message
 */
static void
transmit_delayed_now (void *cls)
{
  struct GSF_DelayedHandle *dh = cls;
  struct GSF_ConnectedPeer *cp = dh->cp;

  GNUNET_CONTAINER_DLL_remove (cp->delayed_head,
                               cp->delayed_tail,
                               dh);
  cp->delay_queue_size--;
  GSF_peer_transmit_ (cp,
		      GNUNET_NO,
		      UINT32_MAX,
		      dh->env);
  GNUNET_free (dh);
}


/**
 * Get the randomized delay a response should be subjected to.
 *
 * @return desired delay
 */
static struct GNUNET_TIME_Relative
get_randomized_delay ()
{
  struct GNUNET_TIME_Relative ret;

  ret =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                     GNUNET_CRYPTO_random_u32
                                     (GNUNET_CRYPTO_QUALITY_WEAK,
                                      2 * GSF_avg_latency.rel_value_us + 1));
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# artificial delays introduced (ms)"),
                            ret.rel_value_us / 1000LL, GNUNET_NO);
#endif
  return ret;
}


/**
 * Handle a reply to a pending request.  Also called if a request
 * expires (then with data == NULL).  The handler may be called
 * many times (depending on the request type), but will not be
 * called during or after a call to GSF_pending_request_cancel
 * and will also not be called anymore after a call signalling
 * expiration.
 *
 * @param cls `struct PeerRequest` this is an answer for
 * @param eval evaluation of the result
 * @param pr handle to the original pending request
 * @param reply_anonymity_level anonymity level for the reply, UINT32_MAX for "unknown"
 * @param expiration when does @a data expire?
 * @param last_transmission when did we last transmit a request for this block
 * @param type type of the block
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in @a data
 */
static void
handle_p2p_reply (void *cls,
                  enum GNUNET_BLOCK_EvaluationResult eval,
                  struct GSF_PendingRequest *pr,
                  uint32_t reply_anonymity_level,
                  struct GNUNET_TIME_Absolute expiration,
                  struct GNUNET_TIME_Absolute last_transmission,
                  enum GNUNET_BLOCK_Type type,
                  const void *data,
                  size_t data_len)
{
  struct PeerRequest *peerreq = cls;
  struct GSF_ConnectedPeer *cp = peerreq->cp;
  struct GSF_PendingRequestData *prd;
  struct GNUNET_MQ_Envelope *env;
  struct PutMessage *pm;
  size_t msize;

  GNUNET_assert (data_len + sizeof (struct PutMessage) <
                 GNUNET_MAX_MESSAGE_SIZE);
  GNUNET_assert (peerreq->pr == pr);
  prd = GSF_pending_request_get_data_ (pr);
  if (NULL == data)
  {
    free_pending_request (peerreq);
    return;
  }
  GNUNET_break (GNUNET_BLOCK_TYPE_ANY != type);
  if ((prd->type != type) && (GNUNET_BLOCK_TYPE_ANY != prd->type))
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop
			      ("# replies dropped due to type mismatch"),
                                1, GNUNET_NO);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting result for query `%s' to peer\n",
              GNUNET_h2s (&prd->query));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# replies received for other peers"),
                            1, GNUNET_NO);
  msize = sizeof (struct PutMessage) + data_len;
  if (msize >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  if ((UINT32_MAX != reply_anonymity_level) && (reply_anonymity_level > 1))
  {
    if (reply_anonymity_level - 1 > GSF_cover_content_count)
    {
      GNUNET_STATISTICS_update (GSF_stats,
                                gettext_noop
                                ("# replies dropped due to insufficient cover traffic"),
                                1, GNUNET_NO);
      return;
    }
    GSF_cover_content_count -= (reply_anonymity_level - 1);
  }

  env = GNUNET_MQ_msg_extra (pm,
			     data_len,
			     GNUNET_MESSAGE_TYPE_FS_PUT);
  pm->type = htonl (type);
  pm->expiration = GNUNET_TIME_absolute_hton (expiration);
  GNUNET_memcpy (&pm[1],
		 data,
		 data_len);
  if ( (UINT32_MAX != reply_anonymity_level) &&
       (0 != reply_anonymity_level) &&
       (GNUNET_YES == GSF_enable_randomized_delays) )
  {
    struct GSF_DelayedHandle *dh;

    dh = GNUNET_new (struct GSF_DelayedHandle);
    dh->cp = cp;
    dh->env = env;
    dh->msize = msize;
    GNUNET_CONTAINER_DLL_insert (cp->delayed_head,
                                 cp->delayed_tail,
                                 dh);
    cp->delay_queue_size++;
    dh->delay_task =
        GNUNET_SCHEDULER_add_delayed (get_randomized_delay (),
                                      &transmit_delayed_now,
                                      dh);
  }
  else
  {
    GSF_peer_transmit_ (cp,
			GNUNET_NO,
			UINT32_MAX,
			env);
  }
  if (GNUNET_BLOCK_EVALUATION_OK_LAST != eval)
    return;
  if (NULL == peerreq->kill_task)
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# P2P searches destroyed due to ultimate reply"),
                              1,
                              GNUNET_NO);
    peerreq->kill_task =
        GNUNET_SCHEDULER_add_now (&peer_request_destroy,
                                  peerreq);
  }
}


/**
 * Increase the peer's respect by a value.
 *
 * @param cp which peer to change the respect value on
 * @param value is the int value by which the
 *  peer's credit is to be increased or decreased
 * @returns the actual change in respect (positive or negative)
 */
static int
change_peer_respect (struct GSF_ConnectedPeer *cp, int value)
{
  if (0 == value)
    return 0;
  GNUNET_assert (NULL != cp);
  if (value > 0)
  {
    if (cp->ppd.respect + value < cp->ppd.respect)
    {
      value = UINT32_MAX - cp->ppd.respect;
      cp->ppd.respect = UINT32_MAX;
    }
    else
      cp->ppd.respect += value;
  }
  else
  {
    if (cp->ppd.respect < -value)
    {
      value = -cp->ppd.respect;
      cp->ppd.respect = 0;
    }
    else
      cp->ppd.respect += value;
  }
  return value;
}


/**
 * We've received a request with the specified priority.  Bound it
 * according to how much we respect the given peer.
 *
 * @param prio_in requested priority
 * @param cp the peer making the request
 * @return effective priority
 */
static int32_t
bound_priority (uint32_t prio_in,
                struct GSF_ConnectedPeer *cp)
{
#define N ((double)128.0)
  uint32_t ret;
  double rret;
  int ld;

  ld = GSF_test_get_load_too_high_ (0);
  if (GNUNET_SYSERR == ld)
  {
#if INSANE_STATISTICS
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests done for free (low load)"), 1,
                              GNUNET_NO);
#endif
    return 0;                   /* excess resources */
  }
  if (prio_in > INT32_MAX)
    prio_in = INT32_MAX;
  ret = -change_peer_respect (cp, -(int) prio_in);
  if (ret > 0)
  {
    if (ret > GSF_current_priorities + N)
      rret = GSF_current_priorities + N;
    else
      rret = ret;
    GSF_current_priorities = (GSF_current_priorities * (N - 1) + rret) / N;
  }
  if ((GNUNET_YES == ld) && (ret > 0))
  {
    /* try with charging */
    ld = GSF_test_get_load_too_high_ (ret);
  }
  if (GNUNET_YES == ld)
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# request dropped, priority insufficient"), 1,
                              GNUNET_NO);
    /* undo charge */
    change_peer_respect (cp, (int) ret);
    return -1;                  /* not enough resources */
  }
  else
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests done for a price (normal load)"), 1,
                              GNUNET_NO);
  }
#undef N
  return ret;
}


/**
 * The priority level imposes a bound on the maximum
 * value for the ttl that can be requested.
 *
 * @param ttl_in requested ttl
 * @param prio given priority
 * @return @a ttl_in if @a ttl_in is below the limit,
 *         otherwise the ttl-limit for the given @a prio
 */
static int32_t
bound_ttl (int32_t ttl_in,
           uint32_t prio)
{
  unsigned long long allowed;

  if (ttl_in <= 0)
    return ttl_in;
  allowed = ((unsigned long long) prio) * TTL_DECREMENT / 1000;
  if (ttl_in > allowed)
  {
    if (allowed >= (1 << 30))
      return 1 << 30;
    return allowed;
  }
  return ttl_in;
}


/**
 * Closure for #test_exist_cb().
 */
struct TestExistClosure
{

  /**
   * Priority of the incoming request.
   */
  int32_t priority;

  /**
   * Relative TTL of the incoming request.
   */
  int32_t ttl;

  /**
   * Type of the incoming request.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Set to #GNUNET_YES if we are done handling the query.
   */
  int finished;

};


/**
 * Test if the query already exists.  If so, merge it, otherwise
 * keep `finished` at #GNUNET_NO.
 *
 * @param cls our `struct TestExistClosure`
 * @param hc the key of the query
 * @param value the existing `struct PeerRequest`.
 * @return #GNUNET_YES to continue to iterate,
 *         #GNUNET_NO if we successfully merged
 */
static int
test_exist_cb (void *cls,
               const struct GNUNET_HashCode *hc,
               void *value)
{
  struct TestExistClosure *tec = cls;
  struct PeerRequest *peerreq = value;
  struct GSF_PendingRequest *pr;
  struct GSF_PendingRequestData *prd;

  pr = peerreq->pr;
  prd = GSF_pending_request_get_data_ (pr);
  if (prd->type != tec->type)
    return GNUNET_YES;
  if (prd->ttl.abs_value_us >=
      GNUNET_TIME_absolute_get ().abs_value_us + tec->ttl * 1000LL)
  {
    /* existing request has higher TTL, drop new one! */
    prd->priority += tec->priority;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have existing request with higher TTL, dropping new request.\n");
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due to higher-TTL request"),
                              1, GNUNET_NO);
    tec->finished = GNUNET_YES;
    return GNUNET_NO;
  }
  /* existing request has lower TTL, drop old one! */
  tec->priority += prd->priority;
  free_pending_request (peerreq);
  GSF_pending_request_cancel_ (pr,
                               GNUNET_YES);
  return GNUNET_NO;
}


/**
 * Handle P2P "QUERY" message.  Creates the pending request entry
 * and sets up all of the data structures to that we will
 * process replies properly.  Does not initiate forwarding or
 * local database lookups.
 *
 * @param cls the other peer involved (sender of the message)
 * @param gm the GET message
 */
void
handle_p2p_get (void *cls,
		const struct GetMessage *gm)
{
  struct GSF_ConnectedPeer *cps = cls;
  struct PeerRequest *peerreq;
  struct GSF_PendingRequest *pr;
  struct GSF_ConnectedPeer *cp;
  const struct GNUNET_PeerIdentity *target;
  enum GSF_PendingRequestOptions options;
  uint16_t msize;
  unsigned int bits;
  const struct GNUNET_PeerIdentity *opt;
  uint32_t bm;
  size_t bfsize;
  uint32_t ttl_decrement;
  struct TestExistClosure tec;
  GNUNET_PEER_Id spid;
  const struct GSF_PendingRequestData *prd;

  msize = ntohs (gm->header.size);
  tec.type = ntohl (gm->type);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  while (bm > 0)
  {
    if (1 == (bm & 1))
      bits++;
    bm >>= 1;
  }
  opt = (const struct GNUNET_PeerIdentity *) &gm[1];
  bfsize = msize - sizeof (struct GetMessage) - bits * sizeof (struct GNUNET_PeerIdentity);
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# GET requests received (from other peers)"),
                            1,
                            GNUNET_NO);
  GSF_cover_query_count++;
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
    cp = GSF_peer_get_ (&opt[bits++]);
  else
    cp = cps;
  if (NULL == cp)
  {
    if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to find RETURN-TO peer `%s' in connection set. Dropping query.\n",
                  GNUNET_i2s (&opt[bits - 1]));

    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to find peer `%s' in connection set. Dropping query.\n",
                  GNUNET_i2s (cps->ppd.peer));
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due to missing reverse route"),
                              1,
                              GNUNET_NO);
    return;
  }
  unsigned int queue_size = GNUNET_MQ_get_length (cp->mq);
  queue_size += cp->ppd.pending_replies + cp->delay_queue_size;
  if (queue_size > MAX_QUEUE_PER_PEER)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer `%s' has too many replies queued already. Dropping query.\n",
                GNUNET_i2s (cps->ppd.peer));
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# requests dropped due to full reply queue"),
                              1,
                              GNUNET_NO);
    return;
  }
  /* note that we can really only check load here since otherwise
   * peers could find out that we are overloaded by not being
   * disconnected after sending us a malformed query... */
  tec.priority = bound_priority (ntohl (gm->priority),
                                 cps);
  if (tec.priority < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping query from `%s', this peer is too busy.\n",
                GNUNET_i2s (cps->ppd.peer));
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for `%s' of type %u from peer `%s' with flags %u\n",
              GNUNET_h2s (&gm->query),
              (unsigned int) tec.type,
              GNUNET_i2s (cps->ppd.peer),
              (unsigned int) bm);
  target =
      (0 !=
       (bm & GET_MESSAGE_BIT_TRANSMIT_TO)) ? (&opt[bits++]) : NULL;
  options = GSF_PRO_DEFAULTS;
  spid = 0;
  if ((GNUNET_LOAD_get_load (cp->ppd.transmission_delay) > 3 * (1 + tec.priority))
      || (GNUNET_LOAD_get_average (cp->ppd.transmission_delay) >
          GNUNET_CONSTANTS_MAX_CORK_DELAY.rel_value_us * 2 +
          GNUNET_LOAD_get_average (GSF_rt_entry_lifetime)))
  {
    /* don't have BW to send to peer, or would likely take longer than we have for it,
     * so at best indirect the query */
    tec.priority = 0;
    options |= GSF_PRO_FORWARD_ONLY;
    spid = GNUNET_PEER_intern (cps->ppd.peer);
    GNUNET_assert (0 != spid);
  }
  tec.ttl = bound_ttl (ntohl (gm->ttl),
                       tec.priority);
  /* decrement ttl (always) */
  ttl_decrement =
      2 * TTL_DECREMENT + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                    TTL_DECREMENT);
  if ( (tec.ttl < 0) &&
       (((int32_t) (tec.ttl - ttl_decrement)) > 0) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping query from `%s' due to TTL underflow (%d - %u).\n",
                GNUNET_i2s (cps->ppd.peer),
                tec.ttl,
                ttl_decrement);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due TTL underflow"), 1,
                              GNUNET_NO);
    /* integer underflow => drop (should be very rare)! */
    return;
  }
  tec.ttl -= ttl_decrement;

  /* test if the request already exists */
  tec.finished = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_get_multiple (cp->request_map,
                                              &gm->query,
                                              &test_exist_cb,
                                              &tec);
  if (GNUNET_YES == tec.finished)
    return; /* merged into existing request, we're done */

  peerreq = GNUNET_new (struct PeerRequest);
  peerreq->cp = cp;
  pr = GSF_pending_request_create_ (options,
                                    tec.type,
                                    &gm->query,
                                    target,
                                    (bfsize > 0)
                                    ? (const char *) &opt[bits]
                                    : NULL,
                                    bfsize,
                                    ntohl (gm->filter_mutator),
                                    1 /* anonymity */,
                                    (uint32_t) tec.priority,
                                    tec.ttl,
                                    spid,
                                    GNUNET_PEER_intern (cps->ppd.peer),
                                    NULL, 0,        /* replies_seen */
                                    &handle_p2p_reply,
                                    peerreq);
  GNUNET_assert (NULL != pr);
  prd = GSF_pending_request_get_data_ (pr);
  peerreq->pr = pr;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (cp->request_map,
                                                   &prd->query,
                                                   peerreq,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# P2P query messages received and processed"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# P2P searches active"),
                            1,
                            GNUNET_NO);
  GSF_pending_request_get_data_ (pr)->has_started = GNUNET_YES;
  GSF_local_lookup_ (pr,
                     &GSF_consider_forwarding,
                     NULL);
}


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a `NULL` @a buffer.
 *
 * @param cp target peer
 * @param is_query is this a query (#GNUNET_YES) or content (#GNUNET_NO) or neither (#GNUNET_SYSERR)
 * @param priority how important is this request?
 * @param timeout when does this request timeout 
 * @param size number of bytes we would like to send to the peer
 * @param env message to send
 */
void
GSF_peer_transmit_ (struct GSF_ConnectedPeer *cp,
                    int is_query,
                    uint32_t priority,
                    struct GNUNET_MQ_Envelope *env)
{
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_PeerTransmitHandle *pos;
  struct GSF_PeerTransmitHandle *prev;

  pth = GNUNET_new (struct GSF_PeerTransmitHandle);
  pth->transmission_request_start_time = GNUNET_TIME_absolute_get ();
  pth->env = env;
  pth->is_query = is_query;
  pth->priority = priority;
  pth->cp = cp;
  /* insertion sort (by priority, descending) */
  prev = NULL;
  pos = cp->pth_head;
  while ((NULL != pos) && (pos->priority > priority))
  {
    prev = pos;
    pos = pos->next;
  }
  GNUNET_CONTAINER_DLL_insert_after (cp->pth_head,
                                     cp->pth_tail,
                                     prev,
                                     pth);
  if (GNUNET_YES == is_query)
    cp->ppd.pending_queries++;
  else if (GNUNET_NO == is_query)
    cp->ppd.pending_replies++;
  schedule_transmission (pth);
}


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param cp responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *cp,
                              struct GNUNET_TIME_Absolute request_time,
                              uint32_t request_priority)
{
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (request_time);
  cp->ppd.avg_reply_delay.rel_value_us =
      (cp->ppd.avg_reply_delay.rel_value_us * (RUNAVG_DELAY_N - 1) +
       delay.rel_value_us) / RUNAVG_DELAY_N;
  cp->ppd.avg_priority =
      (cp->ppd.avg_priority * (RUNAVG_DELAY_N - 1) +
       request_priority) / RUNAVG_DELAY_N;
}


/**
 * Report on receiving a reply in response to an initiating client.
 * Remember that this peer is good for this client.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_client local client on responsible for query
 */
void
GSF_peer_update_responder_client_ (struct GSF_ConnectedPeer *cp,
                                   struct GSF_LocalClient *initiator_client)
{
  cp->ppd.last_client_replies[cp->last_client_replies_woff++ %
                              CS2P_SUCCESS_LIST_SIZE] = initiator_client;
}


/**
 * Report on receiving a reply in response to an initiating peer.
 * Remember that this peer is good for this initiating peer.
 *
 * @param cp responding peer (will be updated)
 * @param initiator_peer other peer responsible for query
 */
void
GSF_peer_update_responder_peer_ (struct GSF_ConnectedPeer *cp,
                                 const struct GSF_ConnectedPeer *initiator_peer)
{
  unsigned int woff;

  woff = cp->last_p2p_replies_woff % P2P_SUCCESS_LIST_SIZE;
  GNUNET_PEER_change_rc (cp->ppd.last_p2p_replies[woff], -1);
  cp->ppd.last_p2p_replies[woff] = initiator_peer->ppd.pid;
  GNUNET_PEER_change_rc (initiator_peer->ppd.pid, 1);
  cp->last_p2p_replies_woff = (woff + 1) % P2P_SUCCESS_LIST_SIZE;
}


/**
 * Write peer-respect information to a file - flush the buffer entry!
 *
 * @param cls unused
 * @param key peer identity
 * @param value the `struct GSF_ConnectedPeer` to flush
 * @return #GNUNET_OK to continue iteration
 */
static int
flush_respect (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct GSF_ConnectedPeer *cp = value;
  struct GNUNET_PeerIdentity pid;

  if (cp->ppd.respect == cp->disk_respect)
    return GNUNET_OK;           /* unchanged */
  GNUNET_assert (0 != cp->ppd.pid);
  GNUNET_PEER_resolve (cp->ppd.pid, &pid);
  GNUNET_PEERSTORE_store (peerstore, "fs", &pid, "respect", &cp->ppd.respect,
                          sizeof (cp->ppd.respect),
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE,
			  NULL,
			  NULL);
  return GNUNET_OK;
}


/**
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that disconnected
 * @param internal_cls the corresponding `struct GSF_ConnectedPeer`
 */
void
GSF_peer_disconnect_handler (void *cls,
			     const struct GNUNET_PeerIdentity *peer,
			     void *internal_cls)
{
  struct GSF_ConnectedPeer *cp = internal_cls;
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_DelayedHandle *dh;

  if (NULL == cp)
    return;  /* must have been disconnect from core with
	      * 'peer' == my_id, ignore */
  flush_respect (NULL,
		 peer,
		 cp);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (cp_map,
                                                       peer,
						       cp));
  GNUNET_STATISTICS_set (GSF_stats,
			 gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multipeermap_size (cp_map),
                         GNUNET_NO);
  if (NULL != cp->respect_iterate_req)
  {
    GNUNET_PEERSTORE_iterate_cancel (cp->respect_iterate_req);
    cp->respect_iterate_req = NULL;
  }
  if (NULL != cp->rc)
  {
    GNUNET_ATS_reserve_bandwidth_cancel (cp->rc);
    cp->rc = NULL;
  }
  if (NULL != cp->rc_delay_task)
  {
    GNUNET_SCHEDULER_cancel (cp->rc_delay_task);
    cp->rc_delay_task = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (cp->request_map,
                                         &cancel_pending_request,
                                         cp);
  GNUNET_CONTAINER_multihashmap_destroy (cp->request_map);
  cp->request_map = NULL;
  GSF_plan_notify_peer_disconnect_ (cp);
  GNUNET_LOAD_value_free (cp->ppd.transmission_delay);
  GNUNET_PEER_decrement_rcs (cp->ppd.last_p2p_replies,
                             P2P_SUCCESS_LIST_SIZE);
  memset (cp->ppd.last_p2p_replies,
          0,
          sizeof (cp->ppd.last_p2p_replies));
  GSF_push_stop_ (cp);
  while (NULL != (pth = cp->pth_head))
  {
    GNUNET_CONTAINER_DLL_remove (cp->pth_head,
                                 cp->pth_tail,
                                 pth);
    if (GNUNET_YES == pth->is_query)
      GNUNET_assert (0 < cp->ppd.pending_queries--);
    else if (GNUNET_NO == pth->is_query)
      GNUNET_assert (0 < cp->ppd.pending_replies--);
    GNUNET_free (pth);
  }
  while (NULL != (dh = cp->delayed_head))
  {
    GNUNET_CONTAINER_DLL_remove (cp->delayed_head,
                                 cp->delayed_tail,
                                 dh);
    GNUNET_MQ_discard (dh->env);
    cp->delay_queue_size--;
    GNUNET_SCHEDULER_cancel (dh->delay_task);
    GNUNET_free (dh);
  }
  GNUNET_PEER_change_rc (cp->ppd.pid, -1);
  if (NULL != cp->mig_revive_task)
  {
    GNUNET_SCHEDULER_cancel (cp->mig_revive_task);
    cp->mig_revive_task = NULL;
  }
  GNUNET_break (0 == cp->ppd.pending_queries);
  GNUNET_break (0 == cp->ppd.pending_replies);
  GNUNET_free (cp);
}


/**
 * Closure for #call_iterator().
 */
struct IterationContext
{
  /**
   * Function to call on each entry.
   */
  GSF_ConnectedPeerIterator it;

  /**
   * Closure for @e it.
   */
  void *it_cls;
};


/**
 * Function that calls the callback for each peer.
 *
 * @param cls the `struct IterationContext *`
 * @param key identity of the peer
 * @param value the `struct GSF_ConnectedPeer *`
 * @return #GNUNET_YES to continue iteration
 */
static int
call_iterator (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct IterationContext *ic = cls;
  struct GSF_ConnectedPeer *cp = value;

  ic->it (ic->it_cls,
          key, cp,
          &cp->ppd);
  return GNUNET_YES;
}


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for @a it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it,
                              void *it_cls)
{
  struct IterationContext ic;

  ic.it = it;
  ic.it_cls = it_cls;
  GNUNET_CONTAINER_multipeermap_iterate (cp_map,
                                         &call_iterator,
                                         &ic);
}


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to get identity of
 * @param id identity to set (written to)
 */
void
GSF_connected_peer_get_identity_ (const struct GSF_ConnectedPeer *cp,
                                  struct GNUNET_PeerIdentity *id)
{
  GNUNET_assert (0 != cp->ppd.pid);
  GNUNET_PEER_resolve (cp->ppd.pid, id);
}


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to get identity of
 * @return reference to peer identity, valid until peer disconnects (!)
 */
const struct GNUNET_PeerIdentity *
GSF_connected_peer_get_identity2_ (const struct GSF_ConnectedPeer *cp)
{
  GNUNET_assert (0 != cp->ppd.pid);
  return GNUNET_PEER_resolve2 (cp->ppd.pid);
}


/**
 * Ask a peer to stop migrating data to us until the given point
 * in time.
 *
 * @param cp peer to ask
 * @param block_time until when to block
 */
void
GSF_block_peer_migration_ (struct GSF_ConnectedPeer *cp,
                           struct GNUNET_TIME_Absolute block_time)
{
  struct GNUNET_MQ_Envelope *env;
  struct MigrationStopMessage *msm;
  
  if (cp->last_migration_block.abs_value_us > block_time.abs_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Migration already blocked for another %s\n",
                GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining
							(cp->last_migration_block), GNUNET_YES));
    return;                     /* already blocked */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking to stop migration for %s\n",
              GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (block_time),
						      GNUNET_YES));
  cp->last_migration_block = block_time;
  env = GNUNET_MQ_msg (msm,
		       GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP);
  msm->reserved = htonl (0);
  msm->duration
    = GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining
				 (cp->last_migration_block));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# migration stop messages sent"),
                            1,
			    GNUNET_NO);
  GSF_peer_transmit_ (cp,
		      GNUNET_SYSERR,
		      UINT32_MAX,
		      env);
}


/**
 * Notify core about a preference we have for the given peer
 * (to allocate more resources towards it).  The change will
 * be communicated the next time we reserve bandwidth with
 * core (not instantly).
 *
 * @param cp peer to reserve bandwidth from
 * @param pref preference change
 */
void
GSF_connected_peer_change_preference_ (struct GSF_ConnectedPeer *cp,
                                       uint64_t pref)
{
  cp->inc_preference += pref;
}


/**
 * Call this method periodically to flush respect information to disk.
 *
 * @param cls closure, not used
 */
static void
cron_flush_respect (void *cls)
{
  fr_task = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (cp_map,
                                         &flush_respect,
					 NULL);
  fr_task = GNUNET_SCHEDULER_add_delayed_with_priority (RESPECT_FLUSH_FREQ,
							GNUNET_SCHEDULER_PRIORITY_HIGH,
							&cron_flush_respect, NULL);
}


/**
 * Initialize peer management subsystem.
 */
void
GSF_connected_peer_init_ ()
{
  cp_map = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_YES);
  peerstore = GNUNET_PEERSTORE_connect (GSF_cfg);
  fr_task = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_HIGH,
						&cron_flush_respect, NULL);
}


/**
 * Shutdown peer management subsystem.
 */
void
GSF_connected_peer_done_ ()
{
  GNUNET_CONTAINER_multipeermap_iterate (cp_map,
                                         &flush_respect,
                                         NULL);
  GNUNET_SCHEDULER_cancel (fr_task);
  fr_task = NULL;
  GNUNET_CONTAINER_multipeermap_destroy (cp_map);
  cp_map = NULL;
  GNUNET_PEERSTORE_disconnect (peerstore,
			       GNUNET_YES);
  
}


/**
 * Iterator to remove references to LC entry.
 *
 * @param cls the `struct GSF_LocalClient *` to look for
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
clean_local_client (void *cls,
		    const struct GNUNET_PeerIdentity *key,
		    void *value)
{
  const struct GSF_LocalClient *lc = cls;
  struct GSF_ConnectedPeer *cp = value;
  unsigned int i;

  for (i = 0; i < CS2P_SUCCESS_LIST_SIZE; i++)
    if (cp->ppd.last_client_replies[i] == lc)
      cp->ppd.last_client_replies[i] = NULL;
  return GNUNET_YES;
}


/**
 * Notification that a local client disconnected.  Clean up all of our
 * references to the given handle.
 *
 * @param lc handle to the local client (henceforth invalid)
 */
void
GSF_handle_local_client_disconnect_ (const struct GSF_LocalClient *lc)
{
  if (NULL == cp_map)
    return;                     /* already cleaned up */
  GNUNET_CONTAINER_multipeermap_iterate (cp_map,
					 &clean_local_client,
                                         (void *) lc);
}


/* end of gnunet-service-fs_cp.c */
