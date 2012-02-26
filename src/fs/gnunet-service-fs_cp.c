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
 * @file fs/gnunet-service-fs_cp.c
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_load_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_pe.h"
#include "gnunet-service-fs_pr.h"
#include "gnunet-service-fs_push.h"


/**
 * Ratio for moving average delay calculation.  The previous
 * average goes in with a factor of (n-1) into the calculation.
 * Must be > 0.
 */
#define RUNAVG_DELAY_N 16

/**
 * How often do we flush trust values to disk?
 */
#define TRUST_FLUSH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After how long do we discard a reply?
 */
#define REPLY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


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
   * Handle for an active request for transmission to this
   * peer, or NULL (if core queue was full).
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Time when this transmission request was issued.
   */
  struct GNUNET_TIME_Absolute transmission_request_start_time;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task called on timeout, or 0 for none.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Function to call to get the actual message.
   */
  GSF_GetMessageCallback gmc;

  /**
   * Peer this request targets.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Closure for 'gmc'.
   */
  void *gmc_cls;

  /**
   * Size of the message to be transmitted.
   */
  size_t size;

  /**
   * Set to 1 if we're currently in the process of calling
   * 'GNUNET_CORE_notify_transmit_ready' (so while cth is
   * NULL, we should not call notify_transmit_ready for this
   * handle right now).
   */
  unsigned int cth_in_progress;

  /**
   * GNUNET_YES if this is a query, GNUNET_NO for content.
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
   * The PUT that was delayed.
   */
  struct PutMessage *pm;

  /**
   * Task for the delay.
   */
  GNUNET_SCHEDULER_TaskIdentifier delay_task;

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
   * Handle to generic request.
   */
  struct GSF_PendingRequest *pr;

  /**
   * Handle to specific peer.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Task for asynchronous stopping of this request.
   */
  GNUNET_SCHEDULER_TaskIdentifier kill_task;

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
  GNUNET_SCHEDULER_TaskIdentifier mig_revive_task;

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
   * Migration stop message in our queue, or NULL if we have none pending.
   */
  struct GSF_PeerTransmitHandle *migration_pth;

  /**
   * Context of our GNUNET_ATS_reserve_bandwidth call (or NULL).
   */
  struct GNUNET_ATS_ReservationContext *rc;

  /**
   * Task scheduled if we need to retry bandwidth reservation later.
   */
  GNUNET_SCHEDULER_TaskIdentifier rc_delay_task;

  /**
   * Active requests from this neighbour, map of query to 'struct PeerRequest'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *request_map;

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Trust rating for this peer on disk.
   */
  uint32_t disk_trust;

  /**
   * Which offset in "last_p2p_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in "last_client_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into 'last_request_times' ring buffer.
   */
  unsigned int last_request_times_off;

  /**
   * GNUNET_YES if we did successfully reserve 32k bandwidth,
   * GNUNET_NO if not.
   */
  int did_reserve;

};


/**
 * Map from peer identities to 'struct GSF_ConnectPeer' entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *cp_map;

/**
 * Where do we store trust information?
 */
static char *trustDirectory;

/**
 * Handle to ATS service.
 */
static struct GNUNET_ATS_PerformanceHandle *ats;

/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_trust_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  GNUNET_CRYPTO_hash_to_enc (&id->hashPubKey, &fil);
  GNUNET_asprintf (&fn, "%s%s%s", trustDirectory, DIR_SEPARATOR_STR, &fil);
  return fn;
}


/**
 * Find latency information in 'atsi'.
 *
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return connection latency
 */
static struct GNUNET_TIME_Relative
get_latency (const struct GNUNET_ATS_Information *atsi, unsigned int atsi_count)
{
  unsigned int i;

  for (i = 0; i < atsi_count; i++)
    if (ntohl (atsi->type) == GNUNET_ATS_QUALITY_NET_DELAY)
      return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                            ntohl (atsi->value));
  return GNUNET_TIME_UNIT_SECONDS;
}


/**
 * Update the performance information kept for the given peer.
 *
 * @param cp peer record to update
 * @param atsi transport performance data
 * @param atsi_count number of records in 'atsi'
 */
static void
update_atsi (struct GSF_ConnectedPeer *cp,
             const struct GNUNET_ATS_Information *atsi, unsigned int atsi_count)
{
  struct GNUNET_TIME_Relative latency;

  latency = get_latency (atsi, atsi_count);
  GNUNET_LOAD_value_set_decline (cp->ppd.transmission_delay, latency);
  /* LATER: merge atsi into cp's performance data (if we ever care...) */
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
 * @param cls the 'struct GSF_PeerTransmitHandle' of the message
 * @param size number of bytes core is willing to take
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
peer_transmit_ready_cb (void *cls, size_t size, void *buf);


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the 'struct GSF_ConnectedPeer' of the peer for which we made the request
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
static void
ats_reserve_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                      int32_t amount, struct GNUNET_TIME_Relative res_delay);


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

  if ((NULL != pth->cth) || (0 != pth->cth_in_progress))
    return;                     /* already done */
  cp = pth->cp;
  GNUNET_assert (0 != cp->ppd.pid);
  GNUNET_PEER_resolve (cp->ppd.pid, &target);

  if (0 != cp->inc_preference)
  {
    GNUNET_ATS_change_preference (ats, &target, GNUNET_ATS_PREFERENCE_BANDWIDTH,
                                  (double) cp->inc_preference,
                                  GNUNET_ATS_PREFERENCE_END);
    cp->inc_preference = 0;
  }

  if ((GNUNET_YES == pth->is_query) && (GNUNET_YES != pth->was_reserved))
  {
    /* query, need reservation */
    if (GNUNET_YES != cp->did_reserve)
      return;                   /* not ready */
    cp->did_reserve = GNUNET_NO;
    /* reservation already done! */
    pth->was_reserved = GNUNET_YES;
    cp->rc =
        GNUNET_ATS_reserve_bandwidth (ats, &target, DBLOCK_SIZE,
                                      &ats_reserve_callback, cp);
  }
  GNUNET_assert (pth->cth == NULL);
  pth->cth_in_progress++;
  pth->cth =
      GNUNET_CORE_notify_transmit_ready (GSF_core, GNUNET_YES, pth->priority,
                                         GNUNET_TIME_absolute_get_remaining
                                         (pth->timeout), &target, pth->size,
                                         &peer_transmit_ready_cb, pth);
  GNUNET_assert (0 < pth->cth_in_progress--);
}


/**
 * Core is ready to transmit to a peer, get the message.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the message
 * @param size number of bytes core is willing to take
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
peer_transmit_ready_cb (void *cls, size_t size, void *buf)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_PeerTransmitHandle *pos;
  struct GSF_ConnectedPeer *cp;
  size_t ret;

  GNUNET_assert ((NULL == buf) || (pth->size <= size));
  pth->cth = NULL;
  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (pth->timeout_task);
    pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head, cp->pth_tail, pth);
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
                      (pth->transmission_request_start_time).rel_value);
  ret = pth->gmc (pth->gmc_cls, size, buf);
  GNUNET_assert (NULL == pth->cth);
  for (pos = cp->pth_head; pos != NULL; pos = pos->next)
  {
    GNUNET_assert (pos != pth);
    schedule_transmission (pos);
  }
  GNUNET_assert (pth->cth == NULL);
  GNUNET_assert (pth->cth_in_progress == 0);
  GNUNET_free (pth);
  return ret;
}


/**
 * (re)try to reserve bandwidth from the given peer.
 *
 * @param cls the 'struct GSF_ConnectedPeer' to reserve from
 * @param tc scheduler context
 */
static void
retry_reservation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_PeerIdentity target;

  GNUNET_PEER_resolve (cp->ppd.pid, &target);
  cp->rc_delay_task = GNUNET_SCHEDULER_NO_TASK;
  cp->rc =
      GNUNET_ATS_reserve_bandwidth (ats, &target, DBLOCK_SIZE,
                                    &ats_reserve_callback, cp);
}


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the 'struct GSF_ConnectedPeer' of the peer for which we made the request
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
static void
ats_reserve_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                      int32_t amount, struct GNUNET_TIME_Relative res_delay)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GSF_PeerTransmitHandle *pth;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Reserved %d bytes / need to wait %llu ms for reservation\n",
              (int) amount, (unsigned long long) res_delay.rel_value);
  cp->rc = NULL;
  if (0 == amount)
  {
    cp->rc_delay_task =
        GNUNET_SCHEDULER_add_delayed (res_delay, &retry_reservation, cp);
    return;
  }
  cp->did_reserve = GNUNET_YES;
  pth = cp->pth_head;
  if ((NULL != pth) && (NULL == pth->cth))
  {
    /* reservation success, try transmission now! */
    pth->cth_in_progress++;
    pth->cth =
        GNUNET_CORE_notify_transmit_ready (GSF_core, GNUNET_YES, pth->priority,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pth->timeout), peer, pth->size,
                                           &peer_transmit_ready_cb, pth);
    GNUNET_assert (0 < pth->cth_in_progress--);
  }
}


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param peer identity of peer that connected
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 * @return handle to connected peer entry
 */
struct GSF_ConnectedPeer *
GSF_peer_connect_handler_ (const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_ATS_Information *atsi,
                           unsigned int atsi_count)
{
  struct GSF_ConnectedPeer *cp;
  char *fn;
  uint32_t trust;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s\n",
              GNUNET_i2s (peer));
  cp = GNUNET_malloc (sizeof (struct GSF_ConnectedPeer));
  cp->ppd.pid = GNUNET_PEER_intern (peer);
  cp->ppd.transmission_delay = GNUNET_LOAD_value_init (GNUNET_TIME_UNIT_ZERO);
  cp->rc =
      GNUNET_ATS_reserve_bandwidth (ats, peer, DBLOCK_SIZE,
                                    &ats_reserve_callback, cp);
  fn = get_trust_filename (peer);
  if ((GNUNET_DISK_file_test (fn) == GNUNET_YES) &&
      (sizeof (trust) == GNUNET_DISK_fn_read (fn, &trust, sizeof (trust))))
    cp->disk_trust = cp->ppd.trust = ntohl (trust);
  GNUNET_free (fn);
  cp->request_map = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (cp_map, &peer->hashPubKey,
                                                   cp,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multihashmap_size (cp_map),
                         GNUNET_NO);
  update_atsi (cp, atsi, atsi_count);
  GSF_push_start_ (cp);
  return cp;
}


/**
 * It may be time to re-start migrating content to this
 * peer.  Check, and if so, restart migration.
 *
 * @param cls the 'struct GSF_ConnectedPeer'
 * @param tc scheduler context
 */
static void
revive_migration (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct GNUNET_TIME_Relative bt;

  cp->mig_revive_task = GNUNET_SCHEDULER_NO_TASK;
  bt = GNUNET_TIME_absolute_get_remaining (cp->ppd.migration_blocked_until);
  if (0 != bt.rel_value)
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
  return GNUNET_CONTAINER_multihashmap_get (cp_map, &peer->hashPubKey);
}


/**
 * Handle P2P "MIGRATION_STOP" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GSF_handle_p2p_migration_stop_ (void *cls,
                                const struct GNUNET_PeerIdentity *other,
                                const struct GNUNET_MessageHeader *message,
                                const struct GNUNET_ATS_Information *atsi,
                                unsigned int atsi_count)
{
  struct GSF_ConnectedPeer *cp;
  const struct MigrationStopMessage *msm;
  struct GNUNET_TIME_Relative bt;

  msm = (const struct MigrationStopMessage *) message;
  cp = GSF_peer_get_ (other);
  if (cp == NULL)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# migration stop messages received"),
                            1, GNUNET_NO);
  bt = GNUNET_TIME_relative_ntoh (msm->duration);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Migration of content to peer `%s' blocked for %llu ms\n"),
              GNUNET_i2s (other), (unsigned long long) bt.rel_value);
  cp->ppd.migration_blocked_until = GNUNET_TIME_relative_to_absolute (bt);
  if (cp->mig_revive_task == GNUNET_SCHEDULER_NO_TASK)
  {
    GSF_push_stop_ (cp);
    cp->mig_revive_task =
        GNUNET_SCHEDULER_add_delayed (bt, &revive_migration, cp);
  }
  update_atsi (cp, atsi, atsi_count);
  return GNUNET_OK;
}


/**
 * Copy reply and free put message.
 *
 * @param cls the 'struct PutMessage'
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
static size_t
copy_reply (void *cls, size_t buf_size, void *buf)
{
  struct PutMessage *pm = cls;
  size_t size;

  if (buf != NULL)
  {
    GNUNET_assert (buf_size >= ntohs (pm->header.size));
    size = ntohs (pm->header.size);
    memcpy (buf, pm, size);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# replies transmitted to other peers"), 1,
                              GNUNET_NO);
  }
  else
  {
    size = 0;
    GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# replies dropped"), 1,
                              GNUNET_NO);
  }
  GNUNET_free (pm);
  return size;
}


/**
 * Free resources associated with the given peer request.
 *
 * @param peerreq request to free
 * @param query associated key for the request
 */
static void
free_pending_request (struct PeerRequest *peerreq,
		      const GNUNET_HashCode *query)
{
  struct GSF_ConnectedPeer *cp = peerreq->cp;

  if (peerreq->kill_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (peerreq->kill_task);
    peerreq->kill_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# P2P searches active"),
                            -1, GNUNET_NO);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (cp->request_map,
                                                      query, peerreq));
  GNUNET_free (peerreq);
}


/**
 * Cancel all requests associated with the peer.
 *
 * @param cls unused
 * @param query hash code of the request
 * @param value the 'struct GSF_PendingRequest'
 * @return GNUNET_YES (continue to iterate)
 */
static int
cancel_pending_request (void *cls, const GNUNET_HashCode * query, void *value)
{
  struct PeerRequest *peerreq = value;
  struct GSF_PendingRequest *pr = peerreq->pr;
  struct GSF_PendingRequestData *prd;

  prd = GSF_pending_request_get_data_ (pr);
  GSF_pending_request_cancel_ (pr, GNUNET_NO);
  free_pending_request (peerreq, &prd->query);
  return GNUNET_OK;
}


/**
 * Free the given request.
 *
 * @param cls the request to free
 * @param tc task context
 */
static void
peer_request_destroy (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerRequest *peerreq = cls;
  struct GSF_PendingRequest *pr = peerreq->pr;
  struct GSF_PendingRequestData *prd;

  peerreq->kill_task = GNUNET_SCHEDULER_NO_TASK;
  prd = GSF_pending_request_get_data_ (pr);
  cancel_pending_request (NULL, &prd->query, peerreq);
}


/**
 * The artificial delay is over, transmit the message now.
 *
 * @param cls the 'struct GSF_DelayedHandle' with the message
 * @param tc scheduler context
 */
static void
transmit_delayed_now (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_DelayedHandle *dh = cls;
  struct GSF_ConnectedPeer *cp = dh->cp;

  GNUNET_CONTAINER_DLL_remove (cp->delayed_head, cp->delayed_tail, dh);
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free (dh->pm);
    GNUNET_free (dh);
    return;
  }
  (void) GSF_peer_transmit_ (cp, GNUNET_NO, UINT32_MAX, REPLY_TIMEOUT,
                             dh->msize, &copy_reply, dh->pm);
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
                                      2 * GSF_avg_latency.rel_value + 1));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# artificial delays introduced (ms)"),
                            ret.rel_value, GNUNET_NO);

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
 * @param cls 'struct PeerRequest' this is an answer for
 * @param eval evaluation of the result
 * @param pr handle to the original pending request
 * @param reply_anonymity_level anonymity level for the reply, UINT32_MAX for "unknown"
 * @param expiration when does 'data' expire?
 * @param last_transmission when did we last transmit a request for this block
 * @param type type of the block
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in data
 */
static void
handle_p2p_reply (void *cls, enum GNUNET_BLOCK_EvaluationResult eval,
                  struct GSF_PendingRequest *pr, uint32_t reply_anonymity_level,
                  struct GNUNET_TIME_Absolute expiration,
                  struct GNUNET_TIME_Absolute last_transmission,
                  enum GNUNET_BLOCK_Type type, const void *data,
                  size_t data_len)
{
  struct PeerRequest *peerreq = cls;
  struct GSF_ConnectedPeer *cp = peerreq->cp;
  struct GSF_PendingRequestData *prd;
  struct PutMessage *pm;
  size_t msize;

  GNUNET_assert (data_len + sizeof (struct PutMessage) <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (peerreq->pr == pr);
  prd = GSF_pending_request_get_data_ (pr);
  if (NULL == data)
  {
    free_pending_request (peerreq, &prd->query);
    return;
  }
  GNUNET_break (type != GNUNET_BLOCK_TYPE_ANY);
  if ((prd->type != type) && (prd->type != GNUNET_BLOCK_TYPE_ANY))
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
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  if ((reply_anonymity_level != UINT32_MAX) && (reply_anonymity_level > 1))
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

  pm = GNUNET_malloc (msize);
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
  pm->header.size = htons (msize);
  pm->type = htonl (type);
  pm->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&pm[1], data, data_len);
  if ((reply_anonymity_level != UINT32_MAX) && (reply_anonymity_level != 0) &&
      (GSF_enable_randomized_delays == GNUNET_YES))
  {
    struct GSF_DelayedHandle *dh;

    dh = GNUNET_malloc (sizeof (struct GSF_DelayedHandle));
    dh->cp = cp;
    dh->pm = pm;
    dh->msize = msize;
    GNUNET_CONTAINER_DLL_insert (cp->delayed_head, cp->delayed_tail, dh);
    dh->delay_task =
        GNUNET_SCHEDULER_add_delayed (get_randomized_delay (),
                                      &transmit_delayed_now, dh);
  }
  else
  {
    (void) GSF_peer_transmit_ (cp, GNUNET_NO, UINT32_MAX, REPLY_TIMEOUT, msize,
                               &copy_reply, pm);
  }
  if (eval != GNUNET_BLOCK_EVALUATION_OK_LAST)
    return;
  if (GNUNET_SCHEDULER_NO_TASK == peerreq->kill_task)
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# P2P searches destroyed due to ultimate reply"),
                              1, GNUNET_NO);
    peerreq->kill_task =
        GNUNET_SCHEDULER_add_now (&peer_request_destroy, peerreq);
  }
}


/**
 * Increase the host credit by a value.
 *
 * @param cp which peer to change the trust value on
 * @param value is the int value by which the
 *  host credit is to be increased or decreased
 * @returns the actual change in trust (positive or negative)
 */
static int
change_host_trust (struct GSF_ConnectedPeer *cp, int value)
{
  if (value == 0)
    return 0;
  GNUNET_assert (cp != NULL);
  if (value > 0)
  {
    if (cp->ppd.trust + value < cp->ppd.trust)
    {
      value = UINT32_MAX - cp->ppd.trust;
      cp->ppd.trust = UINT32_MAX;
    }
    else
      cp->ppd.trust += value;
  }
  else
  {
    if (cp->ppd.trust < -value)
    {
      value = -cp->ppd.trust;
      cp->ppd.trust = 0;
    }
    else
      cp->ppd.trust += value;
  }
  return value;
}


/**
 * We've received a request with the specified priority.  Bound it
 * according to how much we trust the given peer.
 *
 * @param prio_in requested priority
 * @param cp the peer making the request
 * @return effective priority
 */
static int32_t
bound_priority (uint32_t prio_in, struct GSF_ConnectedPeer *cp)
{
#define N ((double)128.0)
  uint32_t ret;
  double rret;
  int ld;

  ld = GSF_test_get_load_too_high_ (0);
  if (ld == GNUNET_SYSERR)
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests done for free (low load)"), 1,
                              GNUNET_NO);
    return 0;                   /* excess resources */
  }
  if (prio_in > INT32_MAX)
    prio_in = INT32_MAX;
  ret = -change_host_trust (cp, -(int) prio_in);
  if (ret > 0)
  {
    if (ret > GSF_current_priorities + N)
      rret = GSF_current_priorities + N;
    else
      rret = ret;
    GSF_current_priorities = (GSF_current_priorities * (N - 1) + rret) / N;
  }
  if ((ld == GNUNET_YES) && (ret > 0))
  {
    /* try with charging */
    ld = GSF_test_get_load_too_high_ (ret);
  }
  if (ld == GNUNET_YES)
  {
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# request dropped, priority insufficient"), 1,
                              GNUNET_NO);
    /* undo charge */
    change_host_trust (cp, (int) ret);
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
 * @return ttl_in if ttl_in is below the limit,
 *         otherwise the ttl-limit for the given priority
 */
static int32_t
bound_ttl (int32_t ttl_in, uint32_t prio)
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
 * Handle P2P "QUERY" message.  Creates the pending request entry
 * and sets up all of the data structures to that we will
 * process replies properly.  Does not initiate forwarding or
 * local database lookups.
 *
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return pending request handle, NULL on error
 */
struct GSF_PendingRequest *
GSF_handle_p2p_query_ (const struct GNUNET_PeerIdentity *other,
                       const struct GNUNET_MessageHeader *message)
{
  struct PeerRequest *peerreq;
  struct GSF_PendingRequest *pr;
  struct GSF_PendingRequestData *prd;
  struct GSF_ConnectedPeer *cp;
  struct GSF_ConnectedPeer *cps;
  const GNUNET_HashCode *namespace;
  const struct GNUNET_PeerIdentity *target;
  enum GSF_PendingRequestOptions options;
  uint16_t msize;
  const struct GetMessage *gm;
  unsigned int bits;
  const GNUNET_HashCode *opt;
  uint32_t bm;
  size_t bfsize;
  uint32_t ttl_decrement;
  int32_t priority;
  int32_t ttl;
  enum GNUNET_BLOCK_Type type;
  GNUNET_PEER_Id spid;

  GNUNET_assert (other != NULL);
  msize = ntohs (message->size);
  if (msize < sizeof (struct GetMessage))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# GET requests received (from other peers)"), 1,
                            GNUNET_NO);
  gm = (const struct GetMessage *) message;
  type = ntohl (gm->type);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  while (bm > 0)
  {
    if (1 == (bm & 1))
      bits++;
    bm >>= 1;
  }
  if (msize < sizeof (struct GetMessage) + bits * sizeof (GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  opt = (const GNUNET_HashCode *) &gm[1];
  bfsize = msize - sizeof (struct GetMessage) - bits * sizeof (GNUNET_HashCode);
  /* bfsize must be power of 2, check! */
  if (0 != ((bfsize - 1) & bfsize))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  GSF_cover_query_count++;
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  cps = GSF_peer_get_ (other);
  if (NULL == cps)
  {
    /* peer must have just disconnected */
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due to initiator not being connected"),
                              1, GNUNET_NO);
    return NULL;
  }
  if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
    cp = GSF_peer_get_ ((const struct GNUNET_PeerIdentity *) &opt[bits++]);
  else
    cp = cps;
  if (cp == NULL)
  {
    if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to find RETURN-TO peer `%4s' in connection set. Dropping query.\n",
                  GNUNET_i2s ((const struct GNUNET_PeerIdentity *)
                              &opt[bits - 1]));

    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to find peer `%4s' in connection set. Dropping query.\n",
                  GNUNET_i2s (other));
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due to missing reverse route"),
                              1, GNUNET_NO);
    return NULL;
  }
  /* note that we can really only check load here since otherwise
   * peers could find out that we are overloaded by not being
   * disconnected after sending us a malformed query... */
  priority = bound_priority (ntohl (gm->priority), cps);
  if (priority < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping query from `%s', this peer is too busy.\n",
                GNUNET_i2s (other));
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for `%s' of type %u from peer `%4s' with flags %u\n",
              GNUNET_h2s (&gm->query), (unsigned int) type, GNUNET_i2s (other),
              (unsigned int) bm);
  namespace = (0 != (bm & GET_MESSAGE_BIT_SKS_NAMESPACE)) ? &opt[bits++] : NULL;
  if ((type == GNUNET_BLOCK_TYPE_FS_SBLOCK) && (namespace == NULL))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if ((type != GNUNET_BLOCK_TYPE_FS_SBLOCK) && (namespace != NULL))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  target =
      (0 !=
       (bm & GET_MESSAGE_BIT_TRANSMIT_TO)) ? ((const struct GNUNET_PeerIdentity
                                               *) &opt[bits++]) : NULL;
  options = GSF_PRO_DEFAULTS;
  spid = 0;
  if ((GNUNET_LOAD_get_load (cp->ppd.transmission_delay) > 3 * (1 + priority))
      || (GNUNET_LOAD_get_average (cp->ppd.transmission_delay) >
          GNUNET_CONSTANTS_MAX_CORK_DELAY.rel_value * 2 +
          GNUNET_LOAD_get_average (GSF_rt_entry_lifetime)))
  {
    /* don't have BW to send to peer, or would likely take longer than we have for it,
     * so at best indirect the query */
    priority = 0;
    options |= GSF_PRO_FORWARD_ONLY;
    spid = GNUNET_PEER_intern (other);
    GNUNET_assert (0 != spid);
  }
  ttl = bound_ttl (ntohl (gm->ttl), priority);
  /* decrement ttl (always) */
  ttl_decrement =
      2 * TTL_DECREMENT + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                    TTL_DECREMENT);
  if ((ttl < 0) && (((int32_t) (ttl - ttl_decrement)) > 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping query from `%s' due to TTL underflow (%d - %u).\n",
                GNUNET_i2s (other), ttl, ttl_decrement);
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop
                              ("# requests dropped due TTL underflow"), 1,
                              GNUNET_NO);
    /* integer underflow => drop (should be very rare)! */
    return NULL;
  }
  ttl -= ttl_decrement;

  /* test if the request already exists */
  peerreq = GNUNET_CONTAINER_multihashmap_get (cp->request_map, &gm->query);
  if (peerreq != NULL)
  {
    pr = peerreq->pr;
    prd = GSF_pending_request_get_data_ (pr);
    if ((prd->type == type) &&
        ((type != GNUNET_BLOCK_TYPE_FS_SBLOCK) ||
         (0 == memcmp (&prd->namespace, namespace, sizeof (GNUNET_HashCode)))))
    {
      if (prd->ttl.abs_value >= GNUNET_TIME_absolute_get ().abs_value + ttl)
      {
        /* existing request has higher TTL, drop new one! */
        prd->priority += priority;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Have existing request with higher TTL, dropping new request.\n",
                    GNUNET_i2s (other));
        GNUNET_STATISTICS_update (GSF_stats,
                                  gettext_noop
                                  ("# requests dropped due to higher-TTL request"),
                                  1, GNUNET_NO);
        return NULL;
      }
      /* existing request has lower TTL, drop old one! */
      priority += prd->priority;
      GSF_pending_request_cancel_ (pr, GNUNET_YES);
      free_pending_request (peerreq, &gm->query);
    }
  }

  peerreq = GNUNET_malloc (sizeof (struct PeerRequest));
  peerreq->cp = cp;
  pr = GSF_pending_request_create_ (options, type, &gm->query, namespace,
                                    target,
                                    (bfsize >
                                     0) ? (const char *) &opt[bits] : NULL,
                                    bfsize, ntohl (gm->filter_mutator),
                                    1 /* anonymity */ ,
                                    (uint32_t) priority, ttl, spid, GNUNET_PEER_intern (other), NULL, 0,        /* replies_seen */
                                    &handle_p2p_reply, peerreq);
  GNUNET_assert (NULL != pr);
  peerreq->pr = pr;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (cp->request_map, &gm->query,
                                                   peerreq,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop
                            ("# P2P query messages received and processed"), 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GSF_stats, gettext_noop ("# P2P searches active"),
                            1, GNUNET_NO);
  return pr;
}


/**
 * Function called if there has been a timeout trying to satisfy
 * a transmission request.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the request
 * @param tc scheduler context
 */
static void
peer_transmit_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Timeout trying to transmit to other peer\n");
  pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head, cp->pth_tail, pth);
  if (GNUNET_YES == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);
  else if (GNUNET_NO == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_LOAD_update (cp->ppd.transmission_delay, UINT64_MAX);
  if (NULL != pth->cth)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pth->cth);
    pth->cth = NULL;
  }
  pth->gmc (pth->gmc_cls, 0, NULL);
  GNUNET_assert (0 == pth->cth_in_progress);
  GNUNET_free (pth);
}


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param cp target peer
 * @param is_query is this a query (GNUNET_YES) or content (GNUNET_NO) or neither (GNUNET_SYSERR)
 * @param priority how important is this request?
 * @param timeout when does this request timeout (call gmc with error)
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 * @return handle to cancel request
 */
struct GSF_PeerTransmitHandle *
GSF_peer_transmit_ (struct GSF_ConnectedPeer *cp, int is_query,
                    uint32_t priority, struct GNUNET_TIME_Relative timeout,
                    size_t size, GSF_GetMessageCallback gmc, void *gmc_cls)
{
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_PeerTransmitHandle *pos;
  struct GSF_PeerTransmitHandle *prev;

  pth = GNUNET_malloc (sizeof (struct GSF_PeerTransmitHandle));
  pth->transmission_request_start_time = GNUNET_TIME_absolute_get ();
  pth->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pth->gmc = gmc;
  pth->gmc_cls = gmc_cls;
  pth->size = size;
  pth->is_query = is_query;
  pth->priority = priority;
  pth->cp = cp;
  /* insertion sort (by priority, descending) */
  prev = NULL;
  pos = cp->pth_head;
  while ((pos != NULL) && (pos->priority > priority))
  {
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL)
    GNUNET_CONTAINER_DLL_insert (cp->pth_head, cp->pth_tail, pth);
  else
    GNUNET_CONTAINER_DLL_insert_after (cp->pth_head, cp->pth_tail, prev, pth);
  if (GNUNET_YES == is_query)
    cp->ppd.pending_queries++;
  else if (GNUNET_NO == is_query)
    cp->ppd.pending_replies++;
  pth->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &peer_transmit_timeout, pth);
  schedule_transmission (pth);
  return pth;
}


/**
 * Cancel an earlier request for transmission.
 *
 * @param pth request to cancel
 */
void
GSF_peer_transmit_cancel_ (struct GSF_PeerTransmitHandle *pth)
{
  struct GSF_ConnectedPeer *cp;

  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (pth->timeout_task);
    pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != pth->cth)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pth->cth);
    pth->cth = NULL;
  }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head, cp->pth_tail, pth);
  if (GNUNET_YES == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);
  else if (GNUNET_NO == pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_assert (0 == pth->cth_in_progress);
  GNUNET_free (pth);
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
  cp->ppd.avg_reply_delay.rel_value =
      (cp->ppd.avg_reply_delay.rel_value * (RUNAVG_DELAY_N - 1) +
       delay.rel_value) / RUNAVG_DELAY_N;
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
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that connected
 */
void
GSF_peer_disconnect_handler_ (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct GSF_ConnectedPeer *cp;
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_DelayedHandle *dh;

  cp = GSF_peer_get_ (peer);
  if (NULL == cp)
    return;                     /* must have been disconnect from core with
                                 * 'peer' == my_id, ignore */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (cp_map,
                                                       &peer->hashPubKey, cp));
  GNUNET_STATISTICS_set (GSF_stats, gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multihashmap_size (cp_map),
                         GNUNET_NO);
  if (NULL != cp->migration_pth)
  {
    GSF_peer_transmit_cancel_ (cp->migration_pth);
    cp->migration_pth = NULL;
  }
  if (NULL != cp->rc)
  {
    GNUNET_ATS_reserve_bandwidth_cancel (cp->rc);
    cp->rc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != cp->rc_delay_task)
  {
    GNUNET_SCHEDULER_cancel (cp->rc_delay_task);
    cp->rc_delay_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_multihashmap_iterate (cp->request_map,
                                         &cancel_pending_request, cp);
  GNUNET_CONTAINER_multihashmap_destroy (cp->request_map);
  cp->request_map = NULL;
  GSF_plan_notify_peer_disconnect_ (cp);
  GNUNET_LOAD_value_free (cp->ppd.transmission_delay);
  GNUNET_PEER_decrement_rcs (cp->ppd.last_p2p_replies, P2P_SUCCESS_LIST_SIZE);
  memset (cp->ppd.last_p2p_replies, 0, sizeof (cp->ppd.last_p2p_replies));
  GSF_push_stop_ (cp);
  while (NULL != (pth = cp->pth_head))
  {
    if (NULL != pth->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pth->cth);
      pth->cth = NULL;
    }
    if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pth->timeout_task);
      pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    GNUNET_CONTAINER_DLL_remove (cp->pth_head, cp->pth_tail, pth);
    GNUNET_assert (0 == pth->cth_in_progress);
    pth->gmc (pth->gmc_cls, 0, NULL);
    GNUNET_free (pth);
  }
  while (NULL != (dh = cp->delayed_head))
  {
    GNUNET_CONTAINER_DLL_remove (cp->delayed_head, cp->delayed_tail, dh);
    GNUNET_SCHEDULER_cancel (dh->delay_task);
    GNUNET_free (dh->pm);
    GNUNET_free (dh);
  }
  GNUNET_PEER_change_rc (cp->ppd.pid, -1);
  if (GNUNET_SCHEDULER_NO_TASK != cp->mig_revive_task)
  {
    GNUNET_SCHEDULER_cancel (cp->mig_revive_task);
    cp->mig_revive_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (cp);
}


/**
 * Closure for 'call_iterator'.
 */
struct IterationContext
{
  /**
   * Function to call on each entry.
   */
  GSF_ConnectedPeerIterator it;

  /**
   * Closure for 'it'.
   */
  void *it_cls;
};


/**
 * Function that calls the callback for each peer.
 *
 * @param cls the 'struct IterationContext*'
 * @param key identity of the peer
 * @param value the 'struct GSF_ConnectedPeer*'
 * @return GNUNET_YES to continue iteration
 */
static int
call_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct IterationContext *ic = cls;
  struct GSF_ConnectedPeer *cp = value;

  ic->it (ic->it_cls, (const struct GNUNET_PeerIdentity *) key, cp, &cp->ppd);
  return GNUNET_YES;
}


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it, void *it_cls)
{
  struct IterationContext ic;

  ic.it = it;
  ic.it_cls = it_cls;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map, &call_iterator, &ic);
}


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to reserve bandwidth from
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
 * Assemble a migration stop message for transmission.
 *
 * @param cls the 'struct GSF_ConnectedPeer' to use
 * @param size number of bytes we're allowed to write to buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
create_migration_stop_message (void *cls, size_t size, void *buf)
{
  struct GSF_ConnectedPeer *cp = cls;
  struct MigrationStopMessage msm;

  cp->migration_pth = NULL;
  if (NULL == buf)
    return 0;
  GNUNET_assert (size >= sizeof (struct MigrationStopMessage));
  msm.header.size = htons (sizeof (struct MigrationStopMessage));
  msm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP);
  msm.reserved = htonl (0);
  msm.duration =
      GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining
                                 (cp->last_migration_block));
  memcpy (buf, &msm, sizeof (struct MigrationStopMessage));
  GNUNET_STATISTICS_update (GSF_stats,
                            gettext_noop ("# migration stop messages sent"),
                            1, GNUNET_NO);
  return sizeof (struct MigrationStopMessage);
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
  if (cp->last_migration_block.abs_value > block_time.abs_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Migration already blocked for another %llu ms\n",
                (unsigned long long)
                GNUNET_TIME_absolute_get_remaining
                (cp->last_migration_block).rel_value);
    return;                     /* already blocked */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking to stop migration for %llu ms\n",
              (unsigned long long) GNUNET_TIME_absolute_get_remaining (block_time).rel_value);
  cp->last_migration_block = block_time;
  if (cp->migration_pth != NULL)
    GSF_peer_transmit_cancel_ (cp->migration_pth);
  cp->migration_pth =
      GSF_peer_transmit_ (cp, GNUNET_SYSERR, UINT32_MAX,
                          GNUNET_TIME_UNIT_FOREVER_REL,
                          sizeof (struct MigrationStopMessage),
                          &create_migration_stop_message, cp);
}


/**
 * Write host-trust information to a file - flush the buffer entry!
 *
 * @param cls closure, not used
 * @param key host identity
 * @param value the 'struct GSF_ConnectedPeer' to flush
 * @return GNUNET_OK to continue iteration
 */
static int
flush_trust (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GSF_ConnectedPeer *cp = value;
  char *fn;
  uint32_t trust;
  struct GNUNET_PeerIdentity pid;

  if (cp->ppd.trust == cp->disk_trust)
    return GNUNET_OK;           /* unchanged */
  GNUNET_assert (0 != cp->ppd.pid);
  GNUNET_PEER_resolve (cp->ppd.pid, &pid);
  fn = get_trust_filename (&pid);
  if (cp->ppd.trust == 0)
  {
    if ((0 != UNLINK (fn)) && (errno != ENOENT))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                GNUNET_ERROR_TYPE_BULK, "unlink", fn);
  }
  else
  {
    trust = htonl (cp->ppd.trust);
    if (sizeof (uint32_t) ==
        GNUNET_DISK_fn_write (fn, &trust, sizeof (uint32_t),
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE |
                              GNUNET_DISK_PERM_GROUP_READ |
                              GNUNET_DISK_PERM_OTHER_READ))
      cp->disk_trust = cp->ppd.trust;
  }
  GNUNET_free (fn);
  return GNUNET_OK;
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
 * Call this method periodically to flush trust information to disk.
 *
 * @param cls closure, not used
 * @param tc task context, not used
 */
static void
cron_flush_trust (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (NULL == cp_map)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map, &flush_trust, NULL);
  if (NULL == tc)
    return;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_SCHEDULER_add_delayed_with_priority (TRUST_FLUSH_FREQ,
					      GNUNET_SCHEDULER_PRIORITY_HIGH,
					      &cron_flush_trust, NULL);
}


/**
 * Initialize peer management subsystem.
 */
void
GSF_connected_peer_init_ ()
{
  cp_map = GNUNET_CONTAINER_multihashmap_create (128);
  ats = GNUNET_ATS_performance_init (GSF_cfg, NULL, NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (GSF_cfg, "fs",
                                                          "TRUST",
                                                          &trustDirectory));
  GNUNET_DISK_directory_create (trustDirectory);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                      &cron_flush_trust, NULL);
}


/**
 * Iterator to free peer entries.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
clean_peer (void *cls, const GNUNET_HashCode * key, void *value)
{
  GSF_peer_disconnect_handler_ (NULL, (const struct GNUNET_PeerIdentity *) key);
  return GNUNET_YES;
}


/**
 * Shutdown peer management subsystem.
 */
void
GSF_connected_peer_done_ ()
{
  cron_flush_trust (NULL, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (cp_map, &clean_peer, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (cp_map);
  cp_map = NULL;
  GNUNET_free (trustDirectory);
  trustDirectory = NULL;
  GNUNET_ATS_performance_done (ats);
  ats = NULL;
}


/**
 * Iterator to remove references to LC entry.
 *
 * @param cls the 'struct GSF_LocalClient*' to look for
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
clean_local_client (void *cls, const GNUNET_HashCode * key, void *value)
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
  GNUNET_CONTAINER_multihashmap_iterate (cp_map, &clean_local_client,
                                         (void *) lc);
}


/* end of gnunet-service-fs_cp.c */
