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
 * @file ats/gnunet-service-ats_addresses.c
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"
#if HAVE_LIBGLPK
#include "gnunet-service-ats_addresses_mlp.h"
#endif
#include "gnunet-service-ats_addresses_simplistic.h"

#define ATS_BLOCKING_DELTA GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100)


/**
 * Available ressource assignment modes
 */
enum ATS_Mode
{
  /*
   * Simplistic mode:
   *
   * Assign each peer an equal amount of bandwidth (bw)
   *
   * bw_per_peer = bw_total / #active addresses
   */
  MODE_SIMPLISTIC,

  /*
   * MLP mode:
   *
   * Solve ressource assignment as an optimization problem
   * Uses an mixed integer programming solver
   */
  MODE_MLP
};






struct GAS_Addresses_Handle
{
  struct GNUNET_CONTAINER_MultiHashMap *addresses;

  unsigned long long wan_quota_in;

  unsigned long long wan_quota_out;

  unsigned int active_addr_count;

  int running;


  int ats_mode;
  /* Solver handle */
  void *solver;

  /* Solver functions */
  GAS_solver_init s_init;
  GAS_solver_done s_done;
  GAS_solver_address_delete s_del;
  GAS_solver_address_change_preference s_pref;
};

struct GAS_Addresses_Handle *handle;

static unsigned int
assemble_ats_information (struct ATS_Address *aa,  struct GNUNET_ATS_Information **dest)
{
  unsigned int ats_count = GNUNET_ATS_PropertyCount - 1;
  struct GNUNET_ATS_Information *ats = GNUNET_malloc (ats_count * sizeof (struct GNUNET_ATS_Information));
  (*dest) = ats;

  ats[0].type = ntohl(GNUNET_ATS_UTILIZATION_UP);
  ats[0].value = aa->atsp_utilization_out.value__;
  ats[1].type = ntohl(GNUNET_ATS_UTILIZATION_DOWN);
  ats[1].value = aa->atsp_utilization_in.value__;
  ats[2].type = ntohl(GNUNET_ATS_NETWORK_TYPE);
  ats[2].value = ntohl(aa->atsp_network_type);
  ats[3].type = ntohl(GNUNET_ATS_QUALITY_NET_DELAY);
  ats[3].value = ntohl(aa->atsp_latency.rel_value);
  ats[4].type = ntohl(GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats[4].value = ntohl(aa->atsp_distance);
  ats[5].type = ntohl(GNUNET_ATS_COST_WAN);
  ats[5].value = ntohl (aa->atsp_cost_wan);
  ats[6].type = ntohl(GNUNET_ATS_COST_LAN);
  ats[6].value = ntohl (aa->atsp_cost_lan);
  ats[7].type = ntohl(GNUNET_ATS_COST_WLAN);
  ats[7].value = ntohl (aa->atsp_cost_wlan);
  return ats_count;
}

static void
send_bw_notification (struct ATS_Address *aa)
{
  struct GNUNET_ATS_Information *ats;
  uint32_t ats_count;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New bandwidth for peer %s is %u/%u\n",
              GNUNET_i2s (&aa->peer), ntohl (aa->assigned_bw_in.value__),
              ntohl (aa->assigned_bw_out.value__));
  ats_count = assemble_ats_information (aa, &ats);

  GAS_scheduling_transmit_address_suggestion (&aa->peer, aa->plugin, aa->addr,
                                              aa->addr_len, aa->session_id,
                                              ats, ats_count,
                                              aa->assigned_bw_out,
                                              aa->assigned_bw_in);
  GAS_reservations_set_bandwidth (&aa->peer, aa->assigned_bw_in);
  GAS_performance_notify_all_clients (&aa->peer, aa->plugin, aa->addr, aa->addr_len,
                                  aa->active,
                                  ats, ats_count, aa->assigned_bw_out,
                                  aa->assigned_bw_in);
  GNUNET_free (ats);
}

/**
 * Update a bandwidth assignment for a peer.  This trivial method currently
 * simply assigns the same share to all active connections.
 *
 * @param cls unused
 * @param key unused
 * @param value the 'struct ATS_Address'
 * @return GNUNET_OK (continue to iterate)
 */
static int
update_bw_simple_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  if (GNUNET_YES != aa->active)
    return GNUNET_OK;
  GNUNET_assert (handle->active_addr_count > 0);


  /* Simple method */
  aa->assigned_bw_in.value__ = htonl (handle->wan_quota_in / handle->active_addr_count);
  aa->assigned_bw_out.value__ = htonl (handle->wan_quota_out / handle->active_addr_count);

  send_bw_notification (aa);

  return GNUNET_OK;
}


/**
 * Some (significant) input changed, recalculate bandwidth assignment
 * for all peers.
 */
static void
recalculate_assigned_bw ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Recalculating bandwidth for all active connections\n");
  GNUNET_STATISTICS_update (GSA_stats, "# bandwidth recalculations performed",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_set (GSA_stats, "# active addresses", handle->active_addr_count,
                         GNUNET_NO);

  GNUNET_CONTAINER_multihashmap_iterate (handle->addresses, &update_bw_simple_it, NULL);
}

/**
 * Free the given address
 * @param addr address to destroy
 */
static void
free_address (struct ATS_Address *addr)
{
  GNUNET_free_non_null (addr->ats);
  GNUNET_free (addr->plugin);
  GNUNET_free (addr);
}

/**
 * Create a ATS_address with the given information
 * @param peer peer
 * @param plugin_name plugin
 * @param plugin_addr address
 * @param plugin_addr_len address length
 * @param session_id session
 * @return the ATS_Address
 */
static struct ATS_Address *
create_address (const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name,
                const void *plugin_addr, size_t plugin_addr_len,
                uint32_t session_id)
{
  struct ATS_Address *aa = NULL;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  memcpy (&aa[1], plugin_addr, plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_id = session_id;
  return aa;
}


/**
 * Destroy the given address.
 *
 * @param addr address to destroy
 * @return GNUNET_YES if bandwidth allocations should be recalcualted
 */
static int
destroy_address (struct ATS_Address *addr)
{
  int ret;

  ret = GNUNET_NO;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (handle->addresses,
                                                       &addr->peer.hashPubKey,
                                                       addr));

#if HAVE_LIBGLPK
  if (handle->ats_mode == MODE_MLP)
    GAS_mlp_address_delete (handle->solver, handle->addresses, addr);
#endif

  if (GNUNET_YES == addr->active)
  {
    handle->active_addr_count--;
    addr->active = GNUNET_NO;
    ret = GNUNET_YES;
  }
  free_address (addr);
  return ret;
}


struct CompareAddressContext
{
  const struct ATS_Address *search;

  /* exact_address != NULL if address and session is equal */
  struct ATS_Address *exact_address;
  /* exact_address != NULL if address and session is 0 */
  struct ATS_Address *base_address;
};


static int
compare_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct CompareAddressContext *cac = cls;
  struct ATS_Address *aa = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Comparing peer %4s: address length %u session %u <-> address length %u session %u\n",
      GNUNET_h2s (key),
      aa->addr_len, aa->session_id,
      cac->search->addr_len, cac->search->session_id);

  /* Find an matching exact address:
   *
   * Compare by:
   * aa->addr_len == cac->search->addr_len
   * aa->plugin == cac->search->plugin
   * aa->addr == cac->search->addr
   * aa->session == cac->search->session
   *
   * return as exact address
   */
  if ((aa->addr_len == cac->search->addr_len) && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
      if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)) && (aa->session_id == cac->search->session_id))
        cac->exact_address = aa;
  }

  /* Find an matching base address:
   *
   * Properties:
   *
   * aa->session_id == 0
   *
   * Compare by:
   * aa->addr_len == cac->search->addr_len
   * aa->plugin == cac->search->plugin
   * aa->addr == cac->search->addr
   *
   * return as base address
   */
  if ((aa->addr_len == cac->search->addr_len) && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
      if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)) && (aa->session_id == 0))
        cac->base_address = aa;
  }

  /* Find an matching exact address based on session:
   *
   * Properties:
   *
   * cac->search->addr_len == 0
   *
   * Compare by:
   * aa->plugin == cac->search->plugin
   * aa->session_id == cac->search->session_id
   *
   * return as exact address
   */
  if (0 == cac->search->addr_len)
  {
      if ((0 == strcmp (aa->plugin, cac->search->plugin)) && (aa->session_id == cac->search->session_id))
        cac->exact_address = aa;
  }

  if (cac->exact_address == NULL)
    return GNUNET_YES; /* Continue iteration to find exact address */
  else
    return GNUNET_NO; /* Stop iteration since we have an exact address */
}


/**
 * Find an existing equivalent address record.
 * Compares by peer identity and network address OR by session ID
 * (one of the two must match).
 *
 * @param peer peer to lookup addresses for
 * @param addr existing address record
 * @return existing address record, NULL for none
 */
struct ATS_Address *
find_address (const struct GNUNET_PeerIdentity *peer,
              const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.exact_address = NULL;
  cac.base_address = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &compare_address_it, &cac);

#if 0
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found exact address: %s           base address: %s\n",
              (cac.exact_address != NULL) ? "YES" : "NO",
              (cac.base_address != NULL) ? "YES" : "NO");
#endif
  if (cac.exact_address == NULL)
    return cac.base_address;
  return cac.exact_address;
}


static struct ATS_Address *
lookup_address (const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name, const void *plugin_addr,
                size_t plugin_addr_len, uint32_t session_id,
                const struct GNUNET_ATS_Information *atsi,
                uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *old;

  aa = create_address (peer,
                       plugin_name,
                       plugin_addr, plugin_addr_len,
                       session_id);

  aa->mlp_information = NULL;
  aa->ats = GNUNET_malloc (atsi_count * sizeof (struct GNUNET_ATS_Information));
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_ATS_Information));

  /* Get existing address or address with session == 0 */
  old = find_address (peer, aa);
  free_address (aa);
  if (old == NULL)
  {
    return NULL;
  }
  else if (old->session_id != session_id)
  {
    return NULL;
  }
  return old;
}


static int
compare_address_session_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct CompareAddressContext *cac = cls;
  struct ATS_Address *aa = value;

  if ((aa->addr_len == cac->search->addr_len) && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
      if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)) && (aa->session_id == cac->search->session_id))
      {
       cac->exact_address = aa;
        return GNUNET_NO;
      }
  }
  return GNUNET_YES;
}


/**
 * Find an existing equivalent address record.
 * Compares by peer identity and network address AND by session ID
 * (one of the two must match).
 *
 * @param peer peer to lookup addresses for
 * @param addr existing address record
 * @return existing address record, NULL for none
 */
static struct ATS_Address *
find_exact_address (const struct GNUNET_PeerIdentity *peer,
              const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.exact_address = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &compare_address_session_it, &cac);
  return cac.exact_address;
}


void
GAS_addresses_add (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *old;

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert (NULL != handle->addresses);

  aa = create_address (peer,
                       plugin_name,
                       plugin_addr, plugin_addr_len,
                       session_id);

  aa->mlp_information = NULL;
  aa->ats = GNUNET_malloc (atsi_count * sizeof (struct GNUNET_ATS_Information));
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_ATS_Information));

  /* Get existing address or address with session == 0 */
  old = find_address (peer, aa);
  if (old == NULL)
  {
    /* We have a new address */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (handle->addresses,
                                                      &peer->hashPubKey, aa,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added new address for peer `%s' session id %u, %p\n",
                GNUNET_i2s (peer), session_id, aa);
    return;
  }

  if (old->session_id == 0)
  {
    /* We have a base address with out an session, update this address */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updated existing address for peer `%s' %p with new session %u\n",
              GNUNET_i2s (peer), old, session_id);
    GNUNET_free_non_null (old->ats);
    old->session_id = session_id;
    old->ats = NULL;
    old->ats_count = 0;
    old->ats = aa->ats;
    old->ats_count = aa->ats_count;
    GNUNET_free (aa->plugin);
    GNUNET_free (aa);
    return;
  }

  /* This address and session is already existing */
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Added already existing address for peer `%s' `%s' %p with new session %u\n",
            GNUNET_i2s (peer), plugin_name, session_id);
  GNUNET_break (0);
}


void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *old;
  uint32_t i;

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert (NULL != handle->addresses);

  /* Get existing address */
  old = lookup_address (peer, plugin_name, plugin_addr, plugin_addr_len,
                       session_id, atsi, atsi_count);
  if (old == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Tried to update unknown address for peer `%s' `%s' session id %u\n",
                GNUNET_i2s (peer), plugin_name, session_id);
    GNUNET_break (0);
    return;
  }

  for (i = 0; i < atsi_count; i++)
    switch (ntohl (atsi[i].type))
    {
    case GNUNET_ATS_UTILIZATION_UP:
      old->atsp_utilization_out.value__ = atsi[i].value;
      break;
    case GNUNET_ATS_UTILIZATION_DOWN:
      old->atsp_utilization_in.value__ = atsi[i].value;
      break;
    case GNUNET_ATS_QUALITY_NET_DELAY:
      old->atsp_latency.rel_value = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      old->atsp_distance = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_WAN:
      old->atsp_cost_wan = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_LAN:
      old->atsp_cost_lan = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_COST_WLAN:
      old->atsp_cost_wlan = ntohl (atsi[i].value);
      break;
    case GNUNET_ATS_NETWORK_TYPE:
      old->atsp_network_type = ntohl (atsi[i].value);
      break;

    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received unsupported ATS type %u\n", ntohl (atsi[i].type));
      GNUNET_break (0);
      break;
    }

  /* Tell solver about update */
  switch (handle->ats_mode)
  {
    case MODE_MLP:
      GAS_mlp_address_update (handle->solver, handle->addresses, old);
      break;
    case MODE_SIMPLISTIC:
      GAS_simplistic_address_update (handle->solver, handle->addresses, old);
      break;
    default:
      GNUNET_break (0);
      break;
  }
}


/**
 * Delete an address
 *
 * If session != 0, just the session is deleted, the address itself still exists
 * If session == 0, remove full address
 * If session == 0 and addrlen == 0, destroy inbound address
 *
 * @param cls unused
 * @param key unused
 * @param value the 'struct ATS_Address'
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_by_session_id (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  const struct ATS_Address *info = cls;
  struct ATS_Address *aa = value;

  GNUNET_assert (0 ==
                 memcmp (&aa->peer, &info->peer,
                         sizeof (struct GNUNET_PeerIdentity)));
  /* session == 0, remove full address  */
  if ((info->session_id == 0) && (0 == strcmp (info->plugin, aa->plugin)) &&
      (aa->addr_len == info->addr_len) &&
      (0 == memcmp (info->addr, aa->addr, aa->addr_len)))
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deleting address for peer `%s': `%s' %u\n",
                GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);

    if (GNUNET_YES == destroy_address (aa))
      recalculate_assigned_bw ();
    return GNUNET_OK;
  }
  /* session != 0, just remove session */
  if (aa->session_id != info->session_id)
    return GNUNET_OK;           /* irrelevant */
  if (aa->session_id != 0)
    GNUNET_break (0 == strcmp (info->plugin, aa->plugin));
  /* session died */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting session for peer `%s': `%s' %u\n",
              GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
  aa->session_id = 0;

  if (GNUNET_YES == aa->active)
  {
    aa->active = GNUNET_NO;
    handle->active_addr_count--;
    recalculate_assigned_bw ();
  }

  /* session == 0 and addrlen == 0 : destroy address */
  if (aa->addr_len == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deleting session and address for peer `%s': `%s' %u\n",
                GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
    (void) destroy_address (aa);
  }
  else
  {
    /* session was set to 0, update address */
#if HAVE_LIBGLPK
  if (handle->ats_mode == MODE_MLP)
    GAS_mlp_address_update (handle->solver, handle->addresses, aa);
#endif
  }

  return GNUNET_OK;
}


void
GAS_addresses_destroy (const struct GNUNET_PeerIdentity *peer,
                       const char *plugin_name, const void *plugin_addr,
                       size_t plugin_addr_len, uint32_t session_id)
{
  struct ATS_Address *aa;
  struct ATS_Address *old;

  if (GNUNET_NO == handle->running)
    return;

  /* Get existing address */
  old = lookup_address (peer, plugin_name, plugin_addr, plugin_addr_len,
                       session_id, NULL, 0);
  if (old == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tried to destroy unknown address for peer `%s' `%s' session id %u\n",
                GNUNET_i2s (peer), plugin_name, session_id);
    return;
  }


  GNUNET_break (0 < strlen (plugin_name));
  aa = create_address (peer, plugin_name, plugin_addr, plugin_addr_len, session_id);

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &destroy_by_session_id, aa);

  free_address (aa);
}


/**
 * Find a "good" address to use for a peer.  If we already have an existing
 * address, we stick to it.  Otherwise, we pick by lowest distance and then
 * by lowest latency.
 *
 * @param cls the 'struct ATS_Address**' where we store the result
 * @param key unused
 * @param value another 'struct ATS_Address*' to consider using
 * @return GNUNET_OK (continue to iterate)
 */
static int
find_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ATS_Address **ap = cls;
  struct ATS_Address *aa = (struct ATS_Address *) value;
  struct ATS_Address *ab = *ap;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get();

  if (aa->blocked_until.abs_value == GNUNET_TIME_absolute_max (now, aa->blocked_until).abs_value)
  {
    /* This address is blocked for suggestion */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Address %p blocked for suggestion for %llu ms \n",
                aa,
                GNUNET_TIME_absolute_get_difference(now, aa->blocked_until).rel_value);
    return GNUNET_OK;
  }

  aa->block_interval = GNUNET_TIME_relative_add (aa->block_interval, ATS_BLOCKING_DELTA);
  aa->blocked_until = GNUNET_TIME_absolute_add (now, aa->block_interval);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address %p ready for suggestion, block interval now %llu \n", aa, aa->block_interval);

  /* FIXME this is a hack */


  if (NULL != ab)
  {
    if ((0 == strcmp (ab->plugin, "tcp")) &&
        (0 == strcmp (aa->plugin, "tcp")))
    {
      if ((0 != ab->addr_len) &&
          (0 == aa->addr_len))
      {
        /* saved address was an outbound address, but we have an inbound address */
        *ap = aa;
        return GNUNET_OK;
      }
      if (0 == ab->addr_len)
      {
        /* saved address was an inbound address, so do not overwrite */
        return GNUNET_OK;
      }
    }
  }
  /* FIXME end of hack */

  if (NULL == ab)
  {
    *ap = aa;
    return GNUNET_OK;
  }
  if ((ntohl (ab->assigned_bw_in.value__) == 0) &&
      (ntohl (aa->assigned_bw_in.value__) > 0))
  {
    /* stick to existing connection */
    *ap = aa;
    return GNUNET_OK;
  }
  if (ab->atsp_distance > aa->atsp_distance)
  {
    /* user shorter distance */
    *ap = aa;
    return GNUNET_OK;
  }
  if (ab->atsp_latency.rel_value > aa->atsp_latency.rel_value)
  {
    /* user lower latency */
    *ap = aa;
    return GNUNET_OK;
  }
  /* don't care */
  return GNUNET_OK;
}


int
GAS_addresses_in_use (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id, int in_use)
{
#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message for peer `%s': %i\n", "ADDRESS_IN_USE",
              GNUNET_i2s (peer), in_use);
#endif

  struct ATS_Address *old;

  if (GNUNET_NO == handle->running)
    return GNUNET_SYSERR;

  old = lookup_address (peer, plugin_name, plugin_addr, plugin_addr_len, session_id, NULL, 0);
  if (NULL == old)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Trying to set unknown address `%s', %s %u %s \n",
                GNUNET_i2s (peer),
                plugin_name, session_id,
                (GNUNET_NO == in_use) ? "NO" : "YES");
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (old->used == in_use)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Address in use called multiple times for peer `%s': %s -> %s \n",
                GNUNET_i2s (peer),
                (GNUNET_NO == old->used) ? "NO" : "YES",
                (GNUNET_NO == in_use) ? "NO" : "YES");
    return GNUNET_SYSERR;
  }
  old->used = in_use;

  /* Tell solver about update */
  switch (handle->ats_mode)
  {
    case MODE_MLP:
      GAS_mlp_address_update (handle->solver, handle->addresses, old);
      break;
    case MODE_SIMPLISTIC:
      GAS_simplistic_address_update (handle->solver, handle->addresses, old);
      break;
    default:
      GNUNET_break (0);
      break;
  }
  return GNUNET_OK;
}


static void 
request_address_mlp (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *aa;
  aa = NULL;

#if HAVE_GLPK
  /* Get preferred address from MODE_MLP */
  struct ATS_PreferedAddress * paddr = NULL;
  paddr = GAS_mlp_get_preferred_address (mlp, addresses, peer);
  aa = paddr->address;
  aa->assigned_bw_out = GNUNET_BANDWIDTH_value_init(paddr->bandwidth_out);
  /* FIXME use bw in value */
  paddr->bandwidth_in = paddr->bandwidth_out;
  aa->assigned_bw_in = GNUNET_BANDWIDTH_value_init (paddr->bandwidth_in);
  GNUNET_free (paddr);
#endif

  if (aa == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }
  if (aa->active == GNUNET_NO)
  {
    aa->active = GNUNET_YES;
    handle->active_addr_count++;
    send_bw_notification (aa);
  }
  else
  {
    /* just to be sure... */
    GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr,
                                                aa->addr_len, aa->session_id,
                                                aa->ats, aa->ats_count,
                                                aa->assigned_bw_out,
                                                aa->assigned_bw_in);
  }

}


static void 
request_address_simple (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *aa;
  aa = NULL;

  /* Get address with: stick to current address, lower distance, lower latency */
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &find_address_it, &aa);
  if (aa == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Suggesting address %p for peer `%s'\n", aa, GNUNET_i2s (peer));

  if (aa->active == GNUNET_NO)
  {
    aa->active = GNUNET_YES;
    handle->active_addr_count++;
    if (handle->ats_mode == MODE_SIMPLISTIC)
    {
      recalculate_assigned_bw ();
    }
  }
  else
  {
    /* just to be sure... */
    GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr,
                                                aa->addr_len, aa->session_id,
                                                aa->ats, aa->ats_count,
                                                aa->assigned_bw_out,
                                                aa->assigned_bw_in);
  }
}


void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == handle->running)
    return;

  if (handle->ats_mode == MODE_SIMPLISTIC)
  {
    request_address_simple (peer);
  }
  if (handle->ats_mode == MODE_MLP)
  {
    request_address_mlp(peer);
  }
}


static int
reset_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Resetting interval for peer `%s' address %p from %llu to 0\n", GNUNET_i2s (&aa->peer), aa, aa->block_interval);

  aa->blocked_until = GNUNET_TIME_UNIT_ZERO_ABS;
  aa->block_interval = GNUNET_TIME_UNIT_ZERO;
  return GNUNET_OK;
}


void
GAS_addresses_handle_backoff_reset (const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_break (GNUNET_SYSERR != GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses,
                                              &peer->hashPubKey,
                                              &reset_address_it,
                                              NULL));
}



// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
void
GAS_addresses_change_preference (const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score)
{
  if (GNUNET_NO == handle->running)
    return;


  /* Tell solver about update */
  switch (handle->ats_mode)
  {
    case MODE_MLP:
      GAS_mlp_address_change_preference (handle->solver, peer, kind, score);
      break;
    case MODE_SIMPLISTIC:
      GAS_simplistic_address_change_preference (handle->solver, peer, kind, score);
      break;
    default:
      GNUNET_break (0);
      break;
  }
}



/**
 * Initialize address subsystem.
 *
 * @param cfg configuration to use
 * @param stats the statistics handle to use
 */
struct GAS_Addresses_Handle *
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_STATISTICS_Handle *stats)
{
  struct GAS_Addresses_Handle *ah;
  char *quota_wan_in_str;
  char *quota_wan_out_str;
  char *mode_str;
  int c;

  ah = GNUNET_malloc (sizeof (struct GAS_Addresses_Handle));
  handle = ah;
  handle->running = GNUNET_NO;

  /* Initialize the system with configuration values */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", "WAN_QUOTA_IN", &quota_wan_in_str))
  {
    if (0 == strcmp(quota_wan_in_str, "unlimited") ||
        (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_wan_in_str, &ah->wan_quota_in)))
      ah->wan_quota_in = (UINT32_MAX) /10;

    GNUNET_free (quota_wan_in_str);
    quota_wan_in_str = NULL;
  }
  else
      ah->wan_quota_in = (UINT32_MAX) /10;

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", "WAN_QUOTA_OUT", &quota_wan_out_str))
  {
    if (0 == strcmp(quota_wan_out_str, "unlimited") ||
        (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_wan_out_str, &ah->wan_quota_out)))
      ah->wan_quota_out = (UINT32_MAX) /10;

    GNUNET_free (quota_wan_out_str);
    quota_wan_out_str = NULL;
  }
  else
    ah->wan_quota_out = (UINT32_MAX) /10;

  /* Initialize the addresses database */
  ah->addresses = GNUNET_CONTAINER_multihashmap_create (128, GNUNET_NO);
  GNUNET_assert (NULL != ah->addresses);

  /* Figure out configured solution method */
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", "MODE", &mode_str))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "No ressource assignment method configured, using simplistic approch\n");
      ah->ats_mode = MODE_SIMPLISTIC;
  }
  else
  {
      for (c = 0; c < strlen (mode_str); c++)
        mode_str[c] = toupper (mode_str[c]);
      if (0 == strcmp (mode_str, "SIMPLISTIC"))
      {
          ah->ats_mode = MODE_SIMPLISTIC;
      }
      else if (0 == strcmp (mode_str, "MLP"))
      {
          ah->ats_mode = MODE_MLP;
#if !HAVE_LIBGLPK
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Assignment method `%s' configured, but GLPK is not availabe, please install \n", mode_str);
          ah->ats_mode = MODE_SIMPLISTIC;
#endif
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid ressource assignment method `%s' configured, using simplistic approch\n", mode_str);
          ah->ats_mode = MODE_SIMPLISTIC;
      }
      GNUNET_free (mode_str);
  }
  /* Start configured solution method */
  switch (ah->ats_mode)
  {
    case MODE_MLP:
      /* Init the MLP solver with default values */
#if HAVE_LIBGLPK
      ah->ats_mode = MODE_MLP;
      ah->s_init = &GAS_mlp_init;
      ah->s_pref = &GAS_mlp_address_change_preference;
      ah->s_del =  &GAS_mlp_address_delete;
      ah->s_done = &GAS_mlp_done;
#else
      GNUNET_free (ah);
      return NULL;
#endif
      break;
    case MODE_SIMPLISTIC:
      /* Init the simplistic solver with default values */
      ah->ats_mode = MODE_SIMPLISTIC;
      ah->s_init = &GAS_simplistic_init;
      ah->s_pref = &GAS_simplistic_address_change_preference;
      ah->s_del  = &GAS_simplistic_address_delete;
      ah->s_done = &GAS_simplistic_done;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS started in %s mode\n", "SIMPLISTIC");
      break;
    default:
      return NULL;
      break;
  }

  GNUNET_assert (NULL != ah->s_init);
  GNUNET_assert (NULL != ah->s_pref);
  GNUNET_assert (NULL != ah->s_del);
  GNUNET_assert (NULL != ah->s_done);

  ah->solver = ah->s_init (cfg, stats);
  if (NULL == ah->solver)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to initialize MLP solver!\n");
    GNUNET_free (ah);
    return NULL;
  }

  /* up and running */
  ah->running = GNUNET_YES;
  return ah;
}


/**
 * Free memory of address.
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the 'struct ATS_Address' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  destroy_address (aa);
  return GNUNET_OK;
}


void
GAS_addresses_destroy_all ()
{
  if (GNUNET_NO == handle->running)
    return;

  if (handle->addresses != NULL)
    GNUNET_CONTAINER_multihashmap_iterate (handle->addresses, &free_address_it, NULL);
  GNUNET_assert (handle->active_addr_count == 0);
}


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done (struct GAS_Addresses_Handle *handle)
{
  GNUNET_assert (NULL != handle);

  GAS_addresses_destroy_all ();
  handle->running = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_destroy (handle->addresses);
  handle->addresses = NULL;
  GNUNET_free (handle);
  /* Stop configured solution method */

}

struct PeerIteratorContext
{
  GNUNET_ATS_Peer_Iterator it;
  void *it_cls;
  struct GNUNET_CONTAINER_MultiHashMap *peers_returned;
};

static int
peer_it (void *cls,
         const struct GNUNET_HashCode * key,
         void *value)
{
  struct PeerIteratorContext *ip_ctx = cls;
  struct GNUNET_PeerIdentity tmp;

  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(ip_ctx->peers_returned, key))
  {
      GNUNET_CONTAINER_multihashmap_put(ip_ctx->peers_returned, key, NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
      tmp.hashPubKey = (*key);
      ip_ctx->it (ip_ctx->it_cls, &tmp);
  }

  return GNUNET_OK;
}

/**
 * Return all peers currently known to ATS
 *
 * @param p_it the iterator to call for every peer, callbach with id == NULL
 *        when done
 * @param p_it_cls the closure for the iterator
 */
void
GAS_addresses_iterate_peers (GNUNET_ATS_Peer_Iterator p_it, void *p_it_cls)
{
  struct PeerIteratorContext ip_ctx;
  unsigned int size;

  if (NULL == p_it)
      return;
  GNUNET_assert (NULL != handle->addresses);

  size = GNUNET_CONTAINER_multihashmap_size(handle->addresses);
  if (0 != size)
  {
    ip_ctx.it = p_it;
    ip_ctx.it_cls = p_it_cls;
    ip_ctx.peers_returned = GNUNET_CONTAINER_multihashmap_create (size, GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_iterate (handle->addresses, &peer_it, &ip_ctx);
    GNUNET_CONTAINER_multihashmap_destroy (ip_ctx.peers_returned);
  }
  p_it (p_it_cls, NULL);
}

struct PeerInfoIteratorContext
{
  GNUNET_ATS_PeerInfo_Iterator it;
  void *it_cls;
};


static int 
peerinfo_it (void *cls,
	     const struct GNUNET_HashCode * key,
	     void *value)
{
  struct PeerInfoIteratorContext *pi_ctx = cls;
  struct ATS_Address *addr = (struct ATS_Address *)  value;
  struct GNUNET_ATS_Information *ats;
  uint32_t ats_count;

  if (NULL != pi_ctx->it)
  {
    ats_count = assemble_ats_information (addr, &ats);

    pi_ctx->it (pi_ctx->it_cls,
                &addr->peer,
                addr->plugin,
                addr->addr, addr->addr_len,
                addr->active,
                ats, ats_count,
                addr->assigned_bw_out,
                addr->assigned_bw_in);
    GNUNET_free (ats);
  }
  return GNUNET_YES;
}


/**
 * Return all peers currently known to ATS
 *
 * @param peer the respective peer
 * @param pi_it the iterator to call for every peer
 * @param pi_it_cls the closure for the iterator
 */
void
GAS_addresses_get_peer_info (const struct GNUNET_PeerIdentity *peer, GNUNET_ATS_PeerInfo_Iterator pi_it, void *pi_it_cls)
{
  struct PeerInfoIteratorContext pi_ctx;
  struct GNUNET_BANDWIDTH_Value32NBO zero_bw;
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL != handle->addresses);
  if (NULL == pi_it)
    return; /* does not make sense without callback */

  zero_bw = GNUNET_BANDWIDTH_value_init (0);
  pi_ctx.it = pi_it;
  pi_ctx.it_cls = pi_it_cls;

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey, &peerinfo_it, &pi_ctx);

  if (NULL != pi_it)
    pi_it (pi_it_cls, NULL, NULL, NULL, 0, GNUNET_NO, NULL, 0, zero_bw, zero_bw);

}


/* end of gnunet-service-ats_addresses.c */
