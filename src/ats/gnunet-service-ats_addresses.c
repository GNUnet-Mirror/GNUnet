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

#define VERBOSE GNUNET_NO

enum ATS_Mode
{
  /*
   * Assign each peer an equal amount of bandwidth (bw)
   *
   * bw_per_peer = bw_total / #active addresses
   */
  SIMPLE,

  /*
   * Use MLP solver to assign bandwidth
   */
  MLP
};

static struct GNUNET_CONTAINER_MultiHashMap *addresses;

#if HAVE_LIBGLPK
static struct GAS_MLP_Handle *mlp;
#endif

static unsigned long long wan_quota_in;

static unsigned long long wan_quota_out;

static unsigned int active_addr_count;

static int ats_mode;


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
update_bw_simple_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  if (GNUNET_YES != aa->active)
    return GNUNET_OK;
  GNUNET_assert (active_addr_count > 0);


  /* Simple method */
  aa->assigned_bw_in.value__ = htonl (wan_quota_in / active_addr_count);
  aa->assigned_bw_out.value__ = htonl (wan_quota_out / active_addr_count);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New bandwidth for peer %s is %u/%u\n",
              GNUNET_i2s (&aa->peer), ntohl (aa->assigned_bw_in.value__),
              ntohl (aa->assigned_bw_out.value__));
  GAS_scheduling_transmit_address_suggestion (&aa->peer, aa->plugin, aa->addr,
                                              aa->addr_len, aa->session_id,
                                              aa->ats, aa->ats_count,
                                              aa->assigned_bw_out,
                                              aa->assigned_bw_in);
  GAS_reservations_set_bandwidth (&aa->peer, aa->assigned_bw_in);
  GAS_performance_notify_clients (&aa->peer, aa->plugin, aa->addr, aa->addr_len,
                                  aa->ats, aa->ats_count, aa->assigned_bw_out,
                                  aa->assigned_bw_in);
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
  GNUNET_STATISTICS_set (GSA_stats, "# active addresses", active_addr_count,
                         GNUNET_NO);

  GNUNET_CONTAINER_multihashmap_iterate (addresses, &update_bw_simple_it, NULL);
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
  aa->mlp_information = NULL;
  aa->next = NULL;
  aa->prev = NULL;
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
                 GNUNET_CONTAINER_multihashmap_remove (addresses,
                                                       &addr->peer.hashPubKey,
                                                       addr));

#if HAVE_LIBGLPK
  if (ats_mode == MLP)
    GAS_mlp_address_delete (mlp, addresses, addr);
#endif

  if (GNUNET_YES == addr->active)
  {
    active_addr_count--;
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
compare_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct CompareAddressContext *cac = cls;
  struct ATS_Address *aa = value;
/*
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Comparing to: %s %s %u session %u\n",
              GNUNET_i2s (&aa->peer), aa->plugin, aa->addr_len, aa->session_id);

*/
  /* find an exact matching address: aa->addr == cac->search->addr && aa->session == cac->search->session */
  if ((aa->addr_len == cac->search->addr_len) && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
      if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)) && (aa->session_id == cac->search->session_id))
      {
        cac->exact_address = aa;
      }
  }

  /* find an matching address: aa->addr == cac->search->addr && aa->session == 0 */
  /* this address can be used to be updated */
  if ((aa->addr_len == cac->search->addr_len) && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
      if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)) && (aa->session_id == 0))
      {
        cac->base_address = aa;
      }
  }

  if (cac->exact_address == NULL)
    return GNUNET_YES;
  else
    return GNUNET_NO;
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
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &compare_address_it, &cac);

/*
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "exact address: %s           base address: %s\n",
              (cac.exact_address != NULL) ? "YES" : "NO",
              (cac.base_address != NULL) ? "YES" : "NO");
*/
  if (cac.exact_address == NULL)
    return cac.base_address;
  return cac.exact_address;
}


static int
compare_address_session_it (void *cls, const GNUNET_HashCode * key, void *value)
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
struct ATS_Address *
find_exact_address (const struct GNUNET_PeerIdentity *peer,
              const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.exact_address = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &compare_address_session_it, &cac);
  return cac.exact_address;
}


void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *old;
  uint32_t i;

  aa = create_address (peer,
                       plugin_name,
                       plugin_addr, plugin_addr_len,
                       session_id);

  aa->mlp_information = NULL;
  aa->ats = GNUNET_malloc (atsi_count * sizeof (struct GNUNET_ATS_Information));
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_ATS_Information));

#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' %u\n",
              GNUNET_i2s (peer),
              session_id);
#endif
  /* Get existing address or address with session == 0 */
  old = find_address (peer, aa);
  if (old == NULL)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (addresses,
                                                      &peer->hashPubKey, aa,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
#if DEBUG_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added new address for peer `%s' %X\n",
                GNUNET_i2s (peer), aa);
#endif
    old = aa;
  }
  else
  {
#if DEBUG_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Updated existing address for peer `%s' %p old session %u new session %u\n",
                GNUNET_i2s (peer), old,
                old->session_id, session_id);
#endif
    GNUNET_free_non_null (old->ats);
    old->session_id = session_id;
    old->ats = NULL;
    old->ats_count = 0;
    old->ats = aa->ats;
    old->ats_count = aa->ats_count;
    GNUNET_free (aa->plugin);
    GNUNET_free (aa);
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
#if HAVE_LIBGLPK
  if (ats_mode == MLP)
    GAS_mlp_address_update (mlp, addresses, old);
#endif
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
destroy_by_session_id (void *cls, const GNUNET_HashCode * key, void *value)
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
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deleting address for peer `%s': `%s' %u\n",
                GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
#endif
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
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting session for peer `%s': `%s' %u\n",
              GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
#endif
  aa->session_id = 0;

  if (GNUNET_YES == aa->active)
  {
    aa->active = GNUNET_NO;
    active_addr_count--;
    recalculate_assigned_bw ();
  }

  /* session == 0 and addrlen == 0 : destroy address */
  if (aa->addr_len == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deleting session and address for peer `%s': `%s' %u\n",
                GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
#endif
    (void) destroy_address (aa);
  }
  else
  {
    /* session was set to 0, update address */
#if HAVE_LIBGLPK
  if (ats_mode == MLP)
    GAS_mlp_address_update (mlp, addresses, aa);
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

  GNUNET_break (0 < strlen (plugin_name));
  aa = create_address (peer, plugin_name, plugin_addr, plugin_addr_len, session_id);

  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
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
find_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address **ap = cls;
  struct ATS_Address *aa = (struct ATS_Address *) value;
  struct ATS_Address *ab = *ap;

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


void
GAS_addresses_in_use (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id, int in_use)
{
#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message for peer `%s': %i\n", "ADDRESS_IN_USE",
              GNUNET_i2s (peer), in_use);
#endif

  struct ATS_Address *aa;
  struct ATS_Address *old;


  aa = create_address(peer, plugin_name, plugin_addr, plugin_addr_len, session_id);
  old = find_exact_address (peer, aa);
  free_address (aa);

  GNUNET_assert (old != NULL);
  GNUNET_assert (old->used != in_use);
  old->used = in_use;

#if HAVE_LIBGLPK
  if (ats_mode == MLP)
     GAS_mlp_address_update (mlp, addresses, old);
#endif
}


void request_address_mlp (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *aa;
  aa = NULL;

#if HAVE_GLPK
  /* Get preferred address from MLP */
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }
  if (aa->active == GNUNET_NO)
  {
    aa->active = GNUNET_YES;
    active_addr_count++;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New bandwidth for peer %s is %u/%u\n",
                GNUNET_i2s (&aa->peer), ntohl (aa->assigned_bw_in.value__),
                ntohl (aa->assigned_bw_out.value__));
    GAS_scheduling_transmit_address_suggestion (&aa->peer, aa->plugin, aa->addr,
                                                aa->addr_len, aa->session_id,
                                                aa->ats, aa->ats_count,
                                                aa->assigned_bw_out,
                                                aa->assigned_bw_in);
    GAS_reservations_set_bandwidth (&aa->peer, aa->assigned_bw_in);
    GAS_performance_notify_clients (&aa->peer, aa->plugin, aa->addr, aa->addr_len,
                                    aa->ats, aa->ats_count, aa->assigned_bw_out,
                                    aa->assigned_bw_in);
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

void request_address_simple (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *aa;
  aa = NULL;

  /* Get address with: stick to current address, lower distance, lower latency */
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &find_address_it, &aa);
  if (aa == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }

  if (aa->active == GNUNET_NO)
  {
    aa->active = GNUNET_YES;
    active_addr_count++;
    if (ats_mode == SIMPLE)
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
  if (ats_mode == SIMPLE)
  {
    request_address_simple (peer);
  }
  if (ats_mode == MLP)
  {
    request_address_mlp(peer);
  }
}


// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
void
GAS_addresses_change_preference (const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score)
{
#if HAVE_LIBGLPK
  if (ats_mode == MLP)
    GAS_mlp_address_change_preference (mlp, peer, kind, score);
#endif
}



/**
 * Initialize address subsystem.
 *
 * @param cfg configuration to use
 * @param stats the statistics handle to use
 */
void
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_STATISTICS_Handle *stats)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "WAN_QUOTA_IN",
                                                      &wan_quota_in));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "WAN_QUOTA_OUT",
                                                      &wan_quota_out));

  switch (GNUNET_CONFIGURATION_get_value_yesno (cfg, "ats", "MLP"))
  {
	/* MLP = YES */
	case GNUNET_YES:
#if HAVE_LIBGLPK
          ats_mode = MLP;
          /* Init the MLP solver with default values */
          mlp = GAS_mlp_init (cfg, stats, MLP_MAX_EXEC_DURATION, MLP_MAX_ITERATIONS);
          break;
#else
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MLP mode was configured, but libglpk is not installed, switching to simple mode");
          ats_mode = SIMPLE;
          break;
#endif
	/* MLP = NO */
	case GNUNET_NO:
		ats_mode = SIMPLE;
		break;
	/* No configuration value */
	case GNUNET_SYSERR:
		ats_mode = SIMPLE;
		break;
	default:
		break;
  }

  addresses = GNUNET_CONTAINER_multihashmap_create (128);
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
free_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ATS_Address *aa = value;

  destroy_address (aa);
  return GNUNET_OK;
}


void
GAS_addresses_destroy_all ()
{
  if (addresses != NULL)
    GNUNET_CONTAINER_multihashmap_iterate (addresses, &free_address_it, NULL);
  GNUNET_assert (active_addr_count == 0);
}


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done ()
{
  GAS_addresses_destroy_all ();
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
  addresses = NULL;
#if HAVE_LIBGLPK
  if (ats_mode == MLP)
  {
    GAS_mlp_done (mlp);
  }
#endif

}


/* end of gnunet-service-ats_addresses.c */
