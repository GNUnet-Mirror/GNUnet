/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api.c
 * @brief automatic transport selection API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - write test case
 * - extend API to get performance data
 * - implement simplistic strategy based on say 'lowest latency' or strict ordering
 * - extend API to get peer preferences, implement proportional bandwidth assignment
 * - re-implement API against a real ATS service (!)
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats_api.h"

#define DEBUG_ATS GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "ats-api", __VA_ARGS__)

/**
 * Receive and send buffer windows grow over time.  For
 * how long can 'unused' bandwidth accumulate before we
 * need to cap it?  (specified in seconds).
 */
#define MAX_WINDOW_TIME_S (5 * 60)

// NOTE: this implementation is simply supposed
// to implement a simplistic strategy in-process;
// in the future, we plan to replace it with a real
// service implementation


/**
 * Opaque handle to obtain address suggestions.
 */
struct GNUNET_ATS_SuggestionContext
{

  /**
   * Function to call with our final suggestion.
   */
  GNUNET_ATS_AddressSuggestionCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Global ATS handle.
   */
  struct GNUNET_ATS_SchedulingHandle *atc;

  /**
   * Which peer are we monitoring?
   */
  struct GNUNET_PeerIdentity target;

};


/**
 * Count number of connected records.
 *
 * @param cls pointer to counter
 * @param key identity of the peer associated with the records
 * @param value a 'struct AllocationRecord'
 * @return GNUNET_YES (continue iteration)
 */
static int
count_connections (void *cls, const GNUNET_HashCode * key, void *value)
{
  unsigned int *ac = cls;
  struct AllocationRecord *ar = value;

  if (GNUNET_YES == ar->connected)
    (*ac)++;
  return GNUNET_YES;
}


/**
 * Closure for 'set_bw_connections'.
 */
struct SetBandwidthContext
{
  /**
   * ATS handle.
   */
  struct GNUNET_ATS_SchedulingHandle *atc;

  /**
   * Inbound bandwidth to assign.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_in;

  /**
   * Outbound bandwidth to assign.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out;
};


/**
 * Set bandwidth based on record.
 *
 * @param cls 'struct SetBandwidthContext'
 * @param key identity of the peer associated with the records
 * @param value a 'struct AllocationRecord'
 * @return GNUNET_YES (continue iteration)
 */
static int
set_bw_connections (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct SetBandwidthContext *sbc = cls;
  struct AllocationRecord *ar = value;

  GNUNET_assert (GNUNET_SYSERR != ar->connected);
  /* FIXME: ||1 because we currently NEVER get 'connected' events... */
  if ((GNUNET_YES == ar->connected) || 1)
  {
    ar->bandwidth_in = sbc->bw_in;
    ar->bandwidth_out = sbc->bw_out;
    GNUNET_BANDWIDTH_tracker_update_quota (&ar->available_recv_window,
                                           ar->bandwidth_in);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Bandwidth assigned to peer %s is i:%u/o:%u bytes/s\n",
         GNUNET_i2s ((const struct GNUNET_PeerIdentity *) key),
         ntohl (ar->bandwidth_in.value__), ntohl (ar->bandwidth_out.value__));
    if (NULL != sbc->atc->alloc_cb)
      sbc->atc->alloc_cb (sbc->atc->alloc_cb_cls,
                          (const struct GNUNET_PeerIdentity *) key,
                          ar->plugin_name, ar->plugin_addr, ar->plugin_addr_len,
                          ar->session, ar->bandwidth_out, ar->bandwidth_in,
                          NULL, 0);
  }
  else if (ntohl (ar->bandwidth_out.value__) > 0)
  {
    ar->bandwidth_in = GNUNET_BANDWIDTH_value_init (0);
    ar->bandwidth_out = GNUNET_BANDWIDTH_value_init (0);
    if (NULL != sbc->atc->alloc_cb)
      sbc->atc->alloc_cb (sbc->atc->alloc_cb_cls,
                          (const struct GNUNET_PeerIdentity *) key,
                          ar->plugin_name, ar->plugin_addr, ar->plugin_addr_len,
                          ar->session, ar->bandwidth_out, ar->bandwidth_in,
                          NULL, 0);
  }
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not communicating bandwidth assigned to peer %s: not connected and bw is: i:%u/o:%u bytes/s\n",
         GNUNET_i2s ((const struct GNUNET_PeerIdentity *) key),
         ntohl (ar->bandwidth_in.value__), ntohl (ar->bandwidth_out.value__));

  return GNUNET_YES;
}


/**
 * Task run to update bandwidth assignments.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param tc scheduler context
 */
static void
update_bandwidth_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_SchedulingHandle *atc = cls;
  unsigned int ac = 0;
  struct SetBandwidthContext bwc;

  atc->ba_task = GNUNET_SCHEDULER_NO_TASK;
  /* FIXME: update calculations NICELY; what follows is a naive version */
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &count_connections, &ac);
  bwc.atc = atc;
  if (ac == 0)
    ac++;
  GNUNET_assert (ac > 0);
  bwc.bw_in = GNUNET_BANDWIDTH_value_init (atc->total_bps_in / ac);
  bwc.bw_out = GNUNET_BANDWIDTH_value_init (atc->total_bps_out / ac);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trivial implementation: bandwidth assigned to each peer is i:%u/o:%u bytes/s\n",
       ntohl (bwc.bw_in.value__), ntohl (bwc.bw_out.value__));
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &set_bw_connections, &bwc);
}


/**
 * Calculate an updated bandwidth assignment and notify.
 *
 * @param atc handle
 * @param change which allocation record changed?
 */
static void
update_bandwidth_assignment (struct GNUNET_ATS_SchedulingHandle *atc,
                             struct AllocationRecord *change)
{
  /* FIXME: based on the 'change', update the LP-problem... */
  if (atc->ba_task == GNUNET_SCHEDULER_NO_TASK)
    atc->ba_task = GNUNET_SCHEDULER_add_now (&update_bandwidth_task, atc);
}


/**
 * Function called with feasbile addresses we might want to suggest.
 *
 * @param cls the 'struct GNUNET_ATS_SuggestionContext'
 * @param key identity of the peer
 * @param value a 'struct AllocationRecord' for the peer
 * @return GNUNET_NO if we're done, GNUNET_YES if we did not suggest an address yet
 */
static int
suggest_address (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_ATS_SuggestionContext *asc = cls;
  struct AllocationRecord *ar = value;

#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Suggesting address for peer `%s', starting with i:%u/o:%u bytes/s\n",
       GNUNET_h2s (key), asc->atc->total_bps_in / 32,
       asc->atc->total_bps_out / 32);
#endif

  /* trivial strategy: pick first available address... */
  asc->cb (asc->cb_cls, &asc->target, ar->plugin_name, ar->plugin_addr,
           ar->plugin_addr_len, ar->session,
           GNUNET_BANDWIDTH_value_init (asc->atc->total_bps_out / 32),
           GNUNET_BANDWIDTH_value_init (asc->atc->total_bps_in / 32), ar->ats,
           ar->ats_count);
  asc->cb = NULL;
  return GNUNET_NO;
}


int
map_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Found entry for %s\n", GNUNET_h2s (key));
  return GNUNET_YES;
}

/**
 * We would like to establish a new connection with a peer.
 * ATS should suggest a good address to begin with.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param cb function to call with the address
 * @param cb_cls closure for cb
 */
struct GNUNET_ATS_SuggestionContext *
GNUNET_ATS_suggest_address (struct GNUNET_ATS_SchedulingHandle *atc,
                            const struct GNUNET_PeerIdentity *peer,
                            GNUNET_ATS_AddressSuggestionCallback cb,
                            void *cb_cls)
{
  struct GNUNET_ATS_SuggestionContext *asc;

#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Looking up suggested address for peer `%s'\n",
       GNUNET_i2s (peer));
#endif
  asc = GNUNET_malloc (sizeof (struct GNUNET_ATS_SuggestionContext));
  asc->cb = cb;
  asc->cb_cls = cb_cls;
  asc->atc = atc;
  asc->target = *peer;
  (void) GNUNET_CONTAINER_multihashmap_get_multiple (atc->peers,
                                                     &peer->hashPubKey,
                                                     &suggest_address, asc);

  if (NULL == asc->cb)
  {
    GNUNET_free (asc);
    return NULL;
  }
  GNUNET_CONTAINER_multihashmap_put (atc->notify_map, &peer->hashPubKey, asc,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return asc;
}


/**
 * Cancel suggestion request.
 *
 * @param asc handle of the request to cancel
 */
void
GNUNET_ATS_suggest_address_cancel (struct GNUNET_ATS_SuggestionContext *asc)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (asc->atc->notify_map,
                                                       &asc->target.hashPubKey,
                                                       asc));
  GNUNET_free (asc);
}


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for 'alloc_cb'
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 GNUNET_ATS_AddressSuggestionCallback alloc_cb,
                 void *alloc_cb_cls)
{
  struct GNUNET_ATS_SchedulingHandle *atc;

#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "ATS init\n");
#endif
  atc = GNUNET_malloc (sizeof (struct GNUNET_ATS_SchedulingHandle));
  atc->cfg = cfg;
  atc->alloc_cb = alloc_cb;
  atc->alloc_cb_cls = alloc_cb_cls;
  atc->peers = GNUNET_CONTAINER_multihashmap_create (256);
  atc->notify_map = GNUNET_CONTAINER_multihashmap_create (256);
  GNUNET_CONFIGURATION_get_value_size (cfg, "core", "TOTAL_QUOTA_OUT",
                                         &atc->total_bps_out);
  GNUNET_CONFIGURATION_get_value_size (cfg, "core", "TOTAL_QUOTA_IN",
				       &atc->total_bps_in);
  return atc;
}


/**
 * Free an allocation record.
 *
 * @param cls unused
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_allocation_record (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct AllocationRecord *ar = value;

  GNUNET_array_grow (ar->ats, ar->ats_count, 0);
  GNUNET_free (ar->plugin_name);
  GNUNET_free (ar);
  return GNUNET_OK;
}


/**
 * Shutdown the ATS subsystem.
 *
 * @param atc handle
 */
void
GNUNET_ATS_shutdown (struct GNUNET_ATS_SchedulingHandle *atc)
{
#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "ATS shutdown\n");
#endif
  if (GNUNET_SCHEDULER_NO_TASK != atc->ba_task)
  {
    GNUNET_SCHEDULER_cancel (atc->ba_task);
    atc->ba_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &destroy_allocation_record,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (atc->peers);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_size (atc->notify_map) == 0);
  GNUNET_CONTAINER_multihashmap_destroy (atc->notify_map);
  atc->notify_map = NULL;
  GNUNET_free (atc);
}


/**
 * Closure for 'update_session'
 */
struct UpdateSessionContext
{
  /**
   * Ats handle.
   */
  struct GNUNET_ATS_SchedulingHandle *atc;

  /**
   * Allocation record with new information.
   */
  struct AllocationRecord *arnew;
};


/**
 * Update an allocation record, merging with the new information
 *
 * @param cls a new 'struct AllocationRecord'
 * @param key identity of the peer associated with the records
 * @param value the old 'struct AllocationRecord'
 * @return GNUNET_YES if the records do not match,
 *         GNUNET_NO if the record do match and 'old' was updated
 */
static int
update_session (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct UpdateSessionContext *usc = cls;
  struct AllocationRecord *arnew = usc->arnew;
  struct AllocationRecord *arold = value;
  int c_old;
  int c_new;
  int found;


  if (0 != strcmp (arnew->plugin_name, arold->plugin_name))
    return GNUNET_YES;
  if (!
      (((arnew->session == arold->session) && (arnew->session != NULL)) ||
       ((arold->session == NULL) &&
        (arold->plugin_addr_len == arnew->plugin_addr_len) &&
        (0 ==
         memcmp (arold->plugin_addr, arnew->plugin_addr,
                 arnew->plugin_addr_len)))))
    return GNUNET_YES;          /* no match */
  /* records match */
#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating session for peer `%s' plugin `%s'\n",
       GNUNET_h2s (key), arold->plugin_name);
#endif
  if (arnew->session != arold->session)
  {
    arold->session = arnew->session;
  }
  if ((arnew->connected == GNUNET_YES) && (arold->connected == GNUNET_NO))
  {
    arold->connected = GNUNET_YES;
  }

  /* Update existing value */
  c_new = 0;
  while (c_new < arnew->ats_count)
  {
    c_old = 0;
    found = GNUNET_NO;
    while (c_old < arold->ats_count)
    {
      if (arold->ats[c_old].type == arnew->ats[c_new].type)
      {
#if DEBUG_ATS
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Found type %i, old value=%i new value=%i\n",
             ntohl (arold->ats[c_old].type), ntohl (arold->ats[c_old].value),
             ntohl (arnew->ats[c_new].value));
#endif
        arold->ats[c_old].value = arnew->ats[c_new].value;
        found = GNUNET_YES;
      }
      c_old++;
    }
    /* Add new value */
    if (found == GNUNET_NO)
    {
#if DEBUG_ATS
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Added new type %i new value=%i\n",
           ntohl (arnew->ats[c_new].type), ntohl (arnew->ats[c_new].value));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Old array size: %u\n", arold->ats_count);
#endif
      GNUNET_array_grow (arold->ats, arold->ats_count, arold->ats_count + 1);
      GNUNET_assert (arold->ats_count >= 2);
      arold->ats[arold->ats_count - 2].type = arnew->ats[c_new].type;
      arold->ats[arold->ats_count - 2].value = arnew->ats[c_new].value;
      arold->ats[arold->ats_count - 1].type = htonl (0);
      arold->ats[arold->ats_count - 1].value = htonl (0);
#if DEBUG_ATS
      LOG (GNUNET_ERROR_TYPE_DEBUG, "New array size: %i\n", arold->ats_count);
#endif
    }
    c_new++;
  }

  update_bandwidth_assignment (usc->atc, arold);
  return GNUNET_NO;
}


/**
 * Create an allocation record with the given properties.
 *
 * @param plugin_name name of the currently used transport plugin
 * @param session session in use (if available)
 * @param plugin_addr address in use (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
static struct AllocationRecord *
create_allocation_record (const char *plugin_name, struct Session *session,
                          const void *plugin_addr, size_t plugin_addr_len,
                          const struct GNUNET_ATS_Information *ats,
                          uint32_t ats_count)
{
  struct AllocationRecord *ar;

  ar = GNUNET_malloc (sizeof (struct AllocationRecord) + plugin_addr_len);
  ar->plugin_name = GNUNET_strdup (plugin_name);
  ar->plugin_addr = &ar[1];
  memcpy (&ar[1], plugin_addr, plugin_addr_len);
  ar->session = session;
  ar->plugin_addr_len = plugin_addr_len;
  GNUNET_BANDWIDTH_tracker_init (&ar->available_recv_window, ar->bandwidth_in,
                                 MAX_WINDOW_TIME_S);
  GNUNET_assert (ats_count > 0);
  GNUNET_array_grow (ar->ats, ar->ats_count, ats_count);
  memcpy (ar->ats, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
  ar->connected = GNUNET_SYSERR;        /* aka: not known / no change */
  return ar;
}


/**
 * Mark all matching allocation records as not connected.
 *
 * @param cls 'struct GTS_AtsHandle'
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to clear the 'connected' flag
 * @return GNUNET_OK (continue to iterate)
 */
static int
disconnect_peer (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_ATS_SchedulingHandle *atc = cls;
  struct AllocationRecord *ar = value;

  if (GNUNET_YES == ar->connected)
  {
    ar->connected = GNUNET_NO;
    update_bandwidth_assignment (atc, ar);
  }
  return GNUNET_OK;
}


/**
 * We established a new connection with a peer (for example, because
 * core asked for it or because the other peer connected to us).
 * Calculate bandwidth assignments including the new peer.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param plugin_name name of the currently used transport plugin
 * @param session session in use (if available)
 * @param plugin_addr address in use (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_peer_connect (struct GNUNET_ATS_SchedulingHandle *atc,
                         const struct GNUNET_PeerIdentity *peer,
                         const char *plugin_name, struct Session *session,
                         const void *plugin_addr, size_t plugin_addr_len,
                         const struct GNUNET_ATS_Information *ats,
                         uint32_t ats_count)
{
  struct AllocationRecord *ar;
  struct UpdateSessionContext usc;

#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s\n", GNUNET_i2s (peer));
#endif

  (void) GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &disconnect_peer,
                                                atc);
  ar = create_allocation_record (plugin_name, session, plugin_addr,
                                 plugin_addr_len, ats, ats_count);
  ar->connected = GNUNET_YES;
  usc.atc = atc;
  usc.arnew = ar;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &update_session, &usc))
  {
    destroy_allocation_record (NULL, &peer->hashPubKey, ar);
    return;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (atc->peers,
                                                    &peer->hashPubKey, ar,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * We disconnected from the given peer (for example, because ats, core
 * or blacklist asked for it or because the other peer disconnected).
 * Calculate bandwidth assignments without the peer.
 *
 * @param atc handle
 * @param peer identity of the new peer
 */
void
GNUNET_ATS_peer_disconnect (struct GNUNET_ATS_SchedulingHandle *atc,
                            const struct GNUNET_PeerIdentity *peer)
{
#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnected from peer %s\n",
       GNUNET_i2s (peer));
#endif
  (void) GNUNET_CONTAINER_multihashmap_get_multiple (atc->peers,
                                                     &peer->hashPubKey,
                                                     &disconnect_peer, atc);
}


/**
 * Closure for 'destroy_allocation_record'
 */
struct SessionDestroyContext
{
  /**
   * Ats handle.
   */
  struct GNUNET_ATS_SchedulingHandle *atc;

  /**
   * Session being destroyed.
   */
  const struct Session *session;
};


/**
 * Free an allocation record matching the given session.
 *
 * @param cls the 'struct SessionDestroyContext'
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_session (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct SessionDestroyContext *sdc = cls;
  struct AllocationRecord *ar = value;

  if (ar->session != sdc->session)
    return GNUNET_OK;
  ar->session = NULL;
  if (ar->plugin_addr != NULL)
    return GNUNET_OK;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (sdc->atc->peers, key,
                                                       ar));
  if (GNUNET_YES == ar->connected) ;
  {
    /* FIXME: is this supposed to be allowed? What to do then? */
    GNUNET_break (0);
  }
  destroy_allocation_record (NULL, key, ar);
  return GNUNET_OK;
}


/**
 * A session got destroyed, stop including it as a valid address.
 *
 * @param atc handle
 * @param peer identity of the peer
 * @param session session handle that is no longer valid
 */
void
GNUNET_ATS_session_destroyed (struct GNUNET_ATS_SchedulingHandle *atc,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct Session *session)
{
  struct SessionDestroyContext sdc;

  sdc.atc = atc;
  sdc.session = session;
  (void) GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &destroy_session,
                                                &sdc);
}


/**
 * Notify validation watcher that an entry is now valid
 *
 * @param cls 'struct ValidationEntry' that is now valid
 * @param key peer identity (unused)
 * @param value a 'GST_ValidationIteratorContext' to notify
 * @return GNUNET_YES (continue to iterate)
 */
static int
notify_valid (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct AllocationRecord *ar = cls;
  struct GNUNET_ATS_SuggestionContext *asc = value;

  asc->cb (asc->cb_cls, &asc->target, ar->plugin_name, ar->plugin_addr,
           ar->plugin_addr_len, ar->session,
           GNUNET_BANDWIDTH_value_init (asc->atc->total_bps_out / 32),
           GNUNET_BANDWIDTH_value_init (asc->atc->total_bps_in / 32), ar->ats,
           ar->ats_count);
  GNUNET_ATS_suggest_address_cancel (asc);
  asc = NULL;
  return GNUNET_OK;
}


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param atc handle
 * @param peer identity of the peer
 * @param valid_until how long is the address valid?
 * @param plugin_name name of the transport plugin
 * @param session session handle (if available)
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_SchedulingHandle *atc,
                           const struct GNUNET_PeerIdentity *peer,
                           struct GNUNET_TIME_Absolute valid_until,
                           const char *plugin_name, struct Session *session,
                           const void *plugin_addr, size_t plugin_addr_len,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct AllocationRecord *ar;
  struct UpdateSessionContext usc;

#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s', plugin `%s'\n",
       GNUNET_i2s (peer), plugin_name);
#endif
  ar = create_allocation_record (plugin_name, session, plugin_addr,
                                 plugin_addr_len, ats, ats_count);
  usc.atc = atc;
  usc.arnew = ar;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers, &update_session, &usc))
  {
    destroy_allocation_record (NULL, &peer->hashPubKey, ar);
    return;
  }
#if DEBUG_ATS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding new address for peer `%s', plugin `%s'\n", GNUNET_i2s (peer),
       plugin_name);
#endif
  ar->connected = GNUNET_NO;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (atc->peers,
                                                    &peer->hashPubKey, ar,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_CONTAINER_multihashmap_get_multiple (atc->notify_map,
                                              &peer->hashPubKey, &notify_valid,
                                              ar);
}

/* end of file gnunet-service-transport_ats.c */
