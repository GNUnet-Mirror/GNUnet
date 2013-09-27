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
 * @file ats/gnunet-service-ats-solver_proportional.c
 * @brief ATS proportional solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-proportional",__VA_ARGS__)

/**
 *
 * NOTE: Do not change this documentation. This documentation is based
 * on gnunet.org:/vcs/fsnsg/ats-paper.git/tech-doku/ats-tech-guide.tex
 * use build_txt.sh to generate plaintext output
 *
 * ATS addresses : proportional solver
 *
 *    The proportional solver ("proportional") distributes the available
 *    bandwidth fair over all the addresses influenced by the
 *    preference values. For each available network type an in- and
 *    outbound quota is configured and the bandwidth available in
 *    these networks is distributed over the addresses.  The solver
 *    first assigns every addresses the minimum amount of bandwidth
 *    GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT and then distributes the
 *    remaining bandwidth available according to the preference
 *    values. For each peer only a single address gets bandwidth
 *    assigned and only one address marked as active.  The most
 *    important functionality for the solver is implemented in: *
 *    find_address_it is an hashmap iterator returning the prefered
 *    address for an peer * update_quota_per_network distributes
 *    available bandwidth for a network over active addresses
 *
 *    Changes to addresses automatically have an impact on the the
 *    bandwidth assigned to other addresses in the same network since
 *    the solver distributes the remaining bandwidth over the
 *    addresses in the network.  When changes to the addresses occur,
 *    the solver first performs the changes, like adding or deleting
 *    addresses, and then updates bandwidth assignment for the
 *    affected network. Bandwidth assignment is only recalculated on
 *    demand when an address is requested by a client for a peer or
 *    when the addresses available have changed or an address changed
 *    the network it is located in. When the bandwidth assignment has
 *    changed the callback is called with the new bandwidth
 *    assignments. The bandwidth distribution for a network is
 *    recalculated due to: * address suggestion requests * address
 *    deletions * address switching networks during address update *
 *    preference changes
 *
 *     3.1 Data structures used
 *
 *    For each ATS network (e.g. WAN, LAN, loopback) a struct Network
 *    is used to specify network related information as total adresses
 *    and active addresses in this network and the configured in- and
 *    outbound quota. Each network also contains a list of addresses
 *    added to the solver located in this network. The proportional
 *    solver uses the addresses' solver_information field to store the
 *    proportional network it belongs to for each address.
 *
 *     3.2 Initializing
 *
 *    When the proportional solver is initialized the solver creates a
 *    new solver handle and initializes the network structures with
 *    the quotas passed from addresses and returns the handle solver.
 *
 *     3.3 Adding an address
 *
 *    When a new address is added to the solver using s_add, a lookup
 *    for the network for this address is done and the address is
 *    enqueued in in the linked list of the network.
 *
 *     3.4 Updating an address
 *
 *    The main purpose of address updates is to update the ATS
 *    information for addresse selection. Important for the proportional
 *    solver is when an address switches network it is located
 *    in. This is common because addresses added by transport's
 *    validation mechanism are commonly located in
 *    GNUNET_ATS_NET_UNSPECIFIED. Addresses in validation are located
 *    in this network type and only if a connection is successful on
 *    return of payload data transport switches to the real network
 *    the address is located in.  When an address changes networks it
 *    is first of all removed from the old network using the solver
 *    API function GAS_proportional_address_delete and the network in
 *    the address struct is updated. A lookup for the respective new
 *    proportional network is done and stored in the addresse's
 *    solver_information field. Next the address is re-added to the
 *    solver using the solver API function
 *    GAS_proportional_address_add. If the address was marked as in
 *    active, the solver checks if bandwidth is available in the
 *    network and if yes sets the address to active and updates the
 *    bandwidth distribution in this network. If no bandwidth is
 *    available it sets the bandwidth for this address to 0 and tries
 *    to suggest an alternative address. If an alternative address was
 *    found, addresses' callback is called for this address.
 *
 *     3.5 Deleting an address
 *
 *    When an address is removed from the solver, it removes the
 *    respective address from the network and if the address was
 *    marked as active, it updates the bandwidth distribution for this
 *    network.
 *
 *     3.6 Requesting addresses
 *
 *    When an address is requested for a peer the solver performs a
 *    lookup for the peer entry in addresses address hashmap and
 *    selects the best address.  The selection of the most suitable
 *    address is done in the find_address_it hashmap iterator
 *    described in detail in section 3.7. If no address is returned,
 *    no address can be suggested at the moment. If the address
 *    returned is marked as active, the solver can return this
 *    address. If the address is not marked as active, the solver
 *    checks if another address belongign to this peer is marked as
 *    active and marks the address as inactive, updates the bandwidth
 *    for this address to 0, call the bandwidth changed callback for
 *    this address due to the change and updates quota assignment for
 *    the addresse's network. the now in-active address is belonging
 *    to. The solver marks the new address as active and updates the
 *    bandwidth assignment for this network.
 *
 *     3.7 Choosing addresses
 *
 *    Choosing the best possible address for suggestion is done by
 *    iterating over all addresses of a peer stored in addresses'
 *    hashmap and using the hashmap iterator find_address_it to select
 *    the best available address.  Several checks are done when an
 *    address is selected. First if this address is currently blocked
 *    by addresses from being suggested. An address is blocked for the
 *    duration of ATS_BLOCKING_DELTA when it is suggested to
 *    transport. Next it is checked if at least
 *    GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT bytes bandwidth is available
 *    in the addresse's network, because suggesting an address without
 *    bandwidth does not make sense. This also ensures that all active
 *    addresses in this network get at least the minimum amount of
 *    bandwidth assigned. In the next step the solver ensures that for
 *    tcp connections inbound connections are prefered over outbound
 *    connections. In the next stet the solver ensures that
 *    connections are prefered in the following order: * connections
 *    are already established and have bandwidth assigned *
 *    connections with a shorter distance * connectes have a shorter
 *    latency
 *
 *     3.8 Changing preferences
 *
 *     3.9 Shutdown
 *
 *    During shutdown all network entries and aging processes are
 *    destroyed and freed.
 *
 *
 * OLD DOCUMENTATION
 *
 * This solver assigns in and outbound bandwidth equally for all
 * addresses in specific network type (WAN, LAN) based on configured
 * in and outbound quota for this network.
 *
 * The solver is notified by addresses about changes to the addresses
 * and recalculates the bandwith assigned if required. The solver
 * notifies addresses by calling the GAS_bandwidth_changed_cb
 * callback.
 *
 * - Initialization
 *
 *
 *
 *
 * For each peer only a single is selected and marked as "active" in the address
 * struct.
 *
 * E.g.:
 *
 * You have the networks WAN and LAN and quotas
 * WAN_TOTAL_IN, WAN_TOTAL_OUT
 * LAN_TOTAL_IN, LAN_TOTAL_OUT
 *
 * If you have x addresses in the network segment LAN, the quotas are
 * QUOTA_PER_ADDRESS = LAN_TOTAL_OUT / x
 *
 * Quotas are automatically recalculated and reported back when addresses are
 * - requested
 *
 */

#define PREF_AGING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define PREF_AGING_FACTOR 0.95

#define DEFAULT_REL_PREFERENCE 1.0
#define DEFAULT_ABS_PREFERENCE 0.0
#define MIN_UPDATE_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * A handle for the proportional solver
 */
struct GAS_PROPORTIONAL_Handle
{
  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Hashmap containing all valid addresses
   */
  const struct GNUNET_CONTAINER_MultiHashMap *addresses;

  /**
   * Pending address requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *requests;

  /**
   * Bandwidth changed callback
   */
  GAS_bandwidth_changed_cb bw_changed;

  /**
   * Bandwidth changed callback cls
   */
  void *bw_changed_cls;

  /**
   * ATS function to get preferences
   */
  GAS_get_preferences get_preferences;

  /**
   * Closure for ATS function to get preferences
   */
  void *get_preferences_cls;

  /**
   * ATS function to get properties
   */
  GAS_get_properties get_properties;

  /**
   * Closure for ATS function to get properties
   */
  void *get_properties_cls;

  /**
   * Bulk lock
   */
  int bulk_lock;

  /**
   * Number of changes while solver was locked
   */
  int bulk_requests;

  /**
   * Total number of addresses for solver
   */
  unsigned int total_addresses;

  /**
   * Number of active addresses for solver
   */
  unsigned int active_addresses;

  /**
   * Networks array
   */
  struct Network *network_entries;

  /**
   * Number of networks
   */
  unsigned int networks;

};

/**
 * Representation of a network
 */
struct Network
{
  /**
   * ATS network type
   */
  unsigned int type;

  /**
   * Network description
   */
  char *desc;

  /**
   * Total inbound quota
   *
   */
  unsigned long long total_quota_in;

  /**
   * Total outbound quota
   *
   */
  unsigned long long total_quota_out;

  /**
   * Number of active addresses for this network
   */
  unsigned int active_addresses;

  /**
   * Number of total addresses for this network
   */
  unsigned int total_addresses;

  /**
   * String for statistics total addresses
   */
  char *stat_total;

  /**
   * String for statistics active addresses
   */
  char *stat_active;

  struct AddressWrapper *head;
  struct AddressWrapper *tail;
};

/**
 * Wrapper for addresses to store them in network's linked list
 */
struct AddressWrapper
{
  /**
   * Next in DLL
   */
  struct AddressWrapper *next;

  /**
   * Previous in DLL
   */
  struct AddressWrapper *prev;

  /**
   * The address
   */
  struct ATS_Address *addr;
};

/**
 *  Important solver functions
 *  ---------------------------
 */

/**
 * Test if bandwidth is available in this network to add an additional address
 *
 * @param net the network type to update
 * @return GNUNET_YES or GNUNET_NO
 */
static int
is_bandwidth_available_in_network (struct Network *net)
{
  GNUNET_assert(NULL != net);
  unsigned int na = net->active_addresses + 1;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  if (((net->total_quota_in / na) > min_bw)
      && ((net->total_quota_out / na) > min_bw))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "Enough bandwidth available for %u active addresses in network `%s'\n",
        na, net->desc);

    return GNUNET_YES;
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Not enough bandwidth available for %u active addresses in network `%s'\n",
      na, net->desc);
  return GNUNET_NO;
}

/**
 * Update bandwidth assigned to peers in this network
 *
 * @param s the solver handle
 * @param net the network type to update
 * @param address_except address excluded from notification, since we suggest
 * this address
 */
static void
distribute_bandwidth_in_network (struct GAS_PROPORTIONAL_Handle *s,
    struct Network *net, struct ATS_Address *address_except)
{
  unsigned long long remaining_quota_in = 0;
  unsigned long long quota_out_used = 0;

  unsigned long long remaining_quota_out = 0;
  unsigned long long quota_in_used = 0;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  double peer_prefs;
  double total_prefs; /* Important: has to be double not float due to precision */
  double cur_pref; /* Important: has to be double not float due to precision */
  const double *t = NULL; /* Important: has to be double not float due to precision */
  int c;

  unsigned long long assigned_quota_in = 0;
  unsigned long long assigned_quota_out = 0;
  struct AddressWrapper *cur;

  if (GNUNET_YES == s->bulk_lock)
  {
    s->bulk_requests++;
    return;
  }

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Recalculate quota for network type `%s' for %u addresses (in/out): %llu/%llu \n",
      net->desc, net->active_addresses, net->total_quota_in,
      net->total_quota_in);

  if (net->active_addresses == 0)
    return; /* no addresses to update */

  /* Idea
   * Assign every peer in network minimum Bandwidth
   * Distribute bandwidth left according to preference
   */

  if ((net->active_addresses * min_bw) > net->total_quota_in)
  {
    GNUNET_break(0);
    return;
  }
  if ((net->active_addresses * min_bw) > net->total_quota_out)
  {
    GNUNET_break(0);
    return;
  }

  remaining_quota_in = net->total_quota_in - (net->active_addresses * min_bw);
  remaining_quota_out = net->total_quota_out - (net->active_addresses * min_bw);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Remaining bandwidth : (in/out): %llu/%llu \n",
      remaining_quota_in, remaining_quota_out);
  total_prefs = 0.0;
  for (cur = net->head; NULL != cur; cur = cur->next)
  {
    if (GNUNET_YES == cur->addr->active)
    {
      GNUNET_assert(
          NULL != (t = s->get_preferences (s->get_preferences_cls, &cur->addr->peer)));

      peer_prefs = 0.0;
      for (c = 0; c < GNUNET_ATS_PreferenceCount; c++)
      {
        if (c != GNUNET_ATS_PREFERENCE_END)
        {
          //fprintf (stderr, "VALUE[%u] %s %.3f \n", c, GNUNET_i2s (&cur->addr->peer), t[c]);
          peer_prefs += t[c];
        }
      }
      total_prefs += (peer_prefs / (GNUNET_ATS_PreferenceCount - 1));
    }
  }
  for (cur = net->head; NULL != cur; cur = cur->next)
  {
    if (GNUNET_YES == cur->addr->active)
    {
      cur_pref = 0.0;
      GNUNET_assert(
          NULL != (t = s->get_preferences (s->get_preferences_cls, &cur->addr->peer)));

      for (c = 0; c < GNUNET_ATS_PreferenceCount; c++)
      {
        if (c != GNUNET_ATS_PREFERENCE_END)
          cur_pref += t[c];
      }
      cur_pref /= 2;

      assigned_quota_in = min_bw
          + ((cur_pref / total_prefs) * remaining_quota_in);
      assigned_quota_out = min_bw
          + ((cur_pref / total_prefs) * remaining_quota_out);

      LOG(GNUNET_ERROR_TYPE_DEBUG,
          "New quota for peer `%s' with preference (cur/total) %.3f/%.3f (in/out): %llu / %llu\n",
          GNUNET_i2s (&cur->addr->peer), cur_pref, total_prefs,
          assigned_quota_in, assigned_quota_out);
    }
    else
    {
      assigned_quota_in = 0;
      assigned_quota_out = 0;
    }

    quota_in_used += assigned_quota_in;
    quota_out_used += assigned_quota_out;
    /* Prevent overflow due to rounding errors */
    if (assigned_quota_in > UINT32_MAX)
      assigned_quota_in = UINT32_MAX;
    if (assigned_quota_out > UINT32_MAX)
      assigned_quota_out = UINT32_MAX;

    /* Compare to current bandwidth assigned */
    if ((assigned_quota_in != ntohl (cur->addr->assigned_bw_in.value__))
        || (assigned_quota_out != ntohl (cur->addr->assigned_bw_out.value__)))
    {
      cur->addr->assigned_bw_in.value__ = htonl (assigned_quota_in);
      cur->addr->assigned_bw_out.value__ = htonl (assigned_quota_out);
      /* Notify on change */
      if ((GNUNET_YES == cur->addr->active) && (cur->addr != address_except))
        s->bw_changed (s->bw_changed_cls, cur->addr);
    }

  }
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Total bandwidth assigned is (in/out): %llu /%llu\n", quota_in_used,
      quota_out_used);
  if (quota_out_used > net->total_quota_out + 1) /* +1 is required due to rounding errors */
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Total outbound bandwidth assigned is larger than allowed (used/allowed) for %u active addresses: %llu / %llu\n",
        net->active_addresses, quota_out_used, net->total_quota_out);
  }
  if (quota_in_used > net->total_quota_in + 1) /* +1 is required due to rounding errors */
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Total inbound bandwidth assigned is larger than allowed (used/allowed) for %u active addresses: %llu / %llu\n",
        net->active_addresses, quota_in_used, net->total_quota_in);
  }
}

struct FindBestAddressCtx
{
  struct GAS_PROPORTIONAL_Handle *s;
  struct ATS_Address *best;
};

static int
find_property_index (uint32_t type)
{
  int existing_types[] = GNUNET_ATS_QualityProperties;
  int c;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
    if (existing_types[c] == type)
      return c;
  return GNUNET_SYSERR;
}

/**
 * Find a "good" address to use for a peer by iterating over the addresses for this peer.
 * If we already have an existing address, we stick to it.
 * Otherwise, we pick by lowest distance and then by lowest latency.
 *
 * @param cls the 'struct ATS_Address**' where we store the result
 * @param key unused
 * @param value another 'struct ATS_Address*' to consider using
 * @return GNUNET_OK (continue to iterate)
 */
static int
find_best_address_it (void *cls, const struct GNUNET_HashCode * key,
    void *value)
{
  struct FindBestAddressCtx *fba_ctx = (struct FindBestAddressCtx *) cls;
  struct ATS_Address *current = (struct ATS_Address *) value;
  struct GNUNET_TIME_Absolute now;
  struct Network *net = (struct Network *) current->solver_information;
  const double *norm_prop_cur;
  const double *norm_prop_prev;
  int index;

  now = GNUNET_TIME_absolute_get ();

  if (current->blocked_until.abs_value_us
      == GNUNET_TIME_absolute_max (now, current->blocked_until).abs_value_us)
  {
    /* This address is blocked for suggestion */
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Address %p blocked for suggestion for %s \n",
        current,
        GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (now, current->blocked_until), GNUNET_YES));
    return GNUNET_OK;
  }
  if (GNUNET_NO == is_bandwidth_available_in_network (net))
    return GNUNET_OK; /* There's no bandwidth available in this network */
  if (NULL != fba_ctx->best)
  {
    GNUNET_assert(NULL != fba_ctx->best->plugin);
    GNUNET_assert(NULL != current->plugin);
    if (0 == strcmp (fba_ctx->best->plugin, current->plugin))
    {
      if ((0 != fba_ctx->best->addr_len) && (0 == current->addr_len))
      {
        /* saved address was an outbound address, but we have an inbound address */
        fba_ctx->best = current;
        return GNUNET_OK;
      }
      if (0 == fba_ctx->best->addr_len)
      {
        /* saved address was an inbound address, so do not overwrite */
        return GNUNET_OK;
      }
    }
  }
  if (NULL == fba_ctx->best)
  {
    fba_ctx->best = current;
    return GNUNET_OK;
  }
  if ((ntohl (fba_ctx->best->assigned_bw_in.value__) == 0)
      && (ntohl (current->assigned_bw_in.value__) > 0))
  {
    /* stick to existing connection */
    fba_ctx->best = current;
    return GNUNET_OK;
  }

  norm_prop_cur = fba_ctx->s->get_properties (fba_ctx->s->get_properties_cls,
      (const struct ATS_Address *) current);
  norm_prop_prev = fba_ctx->s->get_properties (fba_ctx->s->get_properties_cls,
      (const struct ATS_Address *) fba_ctx->best);
  /*
   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s previous %.2f current %.2f\n",
   "DISTANCE", norm_prop_cur[1], norm_prop_cur[1]);
   */
  index = find_property_index (GNUNET_ATS_QUALITY_NET_DISTANCE);
  if (GNUNET_SYSERR == index)
  {
    GNUNET_break(0);
    return GNUNET_OK;
  }
  if (norm_prop_cur[index] < norm_prop_prev[index])
  {
    /* user shorter distance */
    fba_ctx->best = current;
    return GNUNET_OK;
  }
  /*
   GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s previous %.2f current %.2f\n",
   "DELAY", norm_prop_cur[1], norm_prop_cur[1]);
   */
  index = find_property_index (GNUNET_ATS_QUALITY_NET_DELAY);
  if (GNUNET_SYSERR == index)
  {
    GNUNET_break(0);
    return GNUNET_OK;
  }
  if (norm_prop_cur[index] < norm_prop_prev[index])
  {
    /* user shorter delay */
    fba_ctx->best = current;
    return GNUNET_OK;
  }

  /* don't care */
  return GNUNET_OK;
}

/**
 *  Helper functions
 *  ---------------------------
 */

/**
 * Update bandwidth assignment for all networks
 *
 * @param s the solver handle
 */
static void
distribute_bandwidth_in_all_networks (struct GAS_PROPORTIONAL_Handle *s)
{
  int i;
  for (i = 0; i < s->networks; i++)
    distribute_bandwidth_in_network (s, &s->network_entries[i], NULL );
}

/**
 * Lookup network struct by type
 *
 * @param s the solver handle
 * @param type the network type
 * @return the network struct
 */
static struct Network *
get_network (struct GAS_PROPORTIONAL_Handle *s, uint32_t type)
{
  int c;
  for (c = 0; c < s->networks; c++)
  {
    if (s->network_entries[c].type == type)
      return &s->network_entries[c];

  }
  return NULL ;
}

/**
 * Hashmap Iterator to find current active address for peer
 *
 * @param cls last active address
 * @param key peer's key
 * @param value address to check
 * @return GNUNET_NO on double active address else GNUNET_YES;
 */
static int
get_active_address_it (void *cls, const struct GNUNET_HashCode * key,
    void *value)
{
  struct ATS_Address **dest = cls;
  struct ATS_Address *aa = (struct ATS_Address *) value;

  if (GNUNET_YES == aa->active)
  {

    if (NULL != (*dest))
    {
      /* should never happen */
      LOG(GNUNET_ERROR_TYPE_ERROR, "Multiple active addresses for peer `%s'\n",
          GNUNET_i2s (&aa->peer));
      GNUNET_break(0);
      return GNUNET_NO;
    }
    (*dest) = aa;
  }
  return GNUNET_OK;
}

/**
 * Find current active address for peer
 *
 * @param solver the solver handle
 * @param addresses the address set
 * @param peer the peer
 * @return active address or NULL
 */
static struct ATS_Address *
get_active_address (void *solver,
    struct GNUNET_CONTAINER_MultiHashMap * addresses,
    const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address * dest = NULL;

  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
      &get_active_address_it, &dest);
  return dest;
}

static void
addresse_increment (struct GAS_PROPORTIONAL_Handle *s, struct Network *net,
    int total, int active)
{
  if (GNUNET_YES == total)
  {
    s->total_addresses++;
    net->total_addresses++;
    GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", 1, GNUNET_NO);
    GNUNET_STATISTICS_update (s->stats, net->stat_total, 1, GNUNET_NO);
  }
  if (GNUNET_YES == active)
  {
    net->active_addresses++;
    s->active_addresses++;
    GNUNET_STATISTICS_update (s->stats, "# ATS active addresses total", 1,
        GNUNET_NO);
    GNUNET_STATISTICS_update (s->stats, net->stat_active, 1, GNUNET_NO);
  }

}

static int
addresse_decrement (struct GAS_PROPORTIONAL_Handle *s, struct Network *net,
    int total, int active)
{
  int res = GNUNET_OK;
  if (GNUNET_YES == total)
  {
    if (s->total_addresses < 1)
    {
      GNUNET_break(0);
      res = GNUNET_SYSERR;
    }
    else
    {
      s->total_addresses--;
      GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", -1,
          GNUNET_NO);
    }
    if (net->total_addresses < 1)
    {
      GNUNET_break(0);
      res = GNUNET_SYSERR;
    }
    else
    {
      net->total_addresses--;
      GNUNET_STATISTICS_update (s->stats, net->stat_total, -1, GNUNET_NO);
    }
  }

  if (GNUNET_YES == active)
  {
    if (net->active_addresses < 1)
    {
      GNUNET_break(0);
      res = GNUNET_SYSERR;
    }
    else
    {
      net->active_addresses--;
      GNUNET_STATISTICS_update (s->stats, net->stat_active, -1, GNUNET_NO);
    }
    if (s->active_addresses < 1)
    {
      GNUNET_break(0);
      res = GNUNET_SYSERR;
    }
    else
    {
      s->active_addresses--;
      GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", -1,
          GNUNET_NO);
    }
  }
  return res;
}

/**
 *  Solver API functions
 *  ---------------------------
 */

/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param pref_rel the normalized preference value for this kind over all clients
 */
void
GAS_proportional_address_change_preference (void *solver,
    const struct GNUNET_PeerIdentity *peer, enum GNUNET_ATS_PreferenceKind kind,
    double pref_rel)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  GNUNET_assert(NULL != solver);
  GNUNET_assert(NULL != peer);

  distribute_bandwidth_in_all_networks (s);
}

/**
 * Get application feedback for a peer
 *
 * @param solver the solver handle
 * @param application the application
 * @param peer the peer to change the preference for
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_proportional_address_preference_feedback (void *solver, void *application,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_TIME_Relative scope,
    enum GNUNET_ATS_PreferenceKind kind, double score)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  GNUNET_assert(NULL != solver);
  GNUNET_assert(NULL != peer);

  GNUNET_assert(NULL != s);
  GNUNET_break(0);
}

/**
 * Get the preferred address for a specific peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_proportional_get_preferred_address (void *solver,
    const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct Network *net_prev;
  struct Network *net_cur;
  struct ATS_Address *prev;
  struct FindBestAddressCtx fba_ctx;

  GNUNET_assert(s != NULL);
  GNUNET_assert(peer != NULL);

  /* Add to list of pending requests */
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (s->requests,
          &peer->hashPubKey))
  {
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (s->requests, &peer->hashPubKey, NULL,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  /* Get address with: stick to current address, lower distance, lower latency */
  fba_ctx.s = s;
  fba_ctx.best = NULL;

  GNUNET_CONTAINER_multihashmap_get_multiple (s->addresses, &peer->hashPubKey,
      &find_best_address_it, &fba_ctx);
  if (NULL == fba_ctx.best)
  {
    LOG(GNUNET_ERROR_TYPE_INFO, "Cannot suggest address for peer `%s'\n",
        GNUNET_i2s (peer));
    return NULL ;
  }

  LOG(GNUNET_ERROR_TYPE_INFO, "Suggesting %s address %p for peer `%s'\n",
      (GNUNET_NO == fba_ctx.best->active) ? "inactive" : "active", fba_ctx.best,
      GNUNET_i2s (peer));
  net_cur = (struct Network *) fba_ctx.best->solver_information;
  if (NULL == fba_ctx.best)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Trying to suggesting unknown address peer `%s'\n", GNUNET_i2s (peer));
    GNUNET_break(0);
    return NULL ;
  }
  if (GNUNET_YES == fba_ctx.best->active)
  {
    /* This address was selected previously, so no need to update quotas */
    return fba_ctx.best;
  }

  /* This address was not active, so we have to:
   *
   * - mark previous active address as not active
   * - update quota for previous address network
   * - update quota for this address network
   */
  prev = get_active_address (s,
      (struct GNUNET_CONTAINER_MultiHashMap *) s->addresses, peer);
  if (NULL != prev)
  {
    net_prev = (struct Network *) prev->solver_information;
    prev->active = GNUNET_NO; /* No active any longer */
    prev->assigned_bw_in = BANDWIDTH_ZERO; /* no bandwidth assigned */
    prev->assigned_bw_out = BANDWIDTH_ZERO; /* no bandwidth assigned */
    if (GNUNET_SYSERR == addresse_decrement (s, net_prev, GNUNET_NO, GNUNET_YES))
      GNUNET_break(0);
    distribute_bandwidth_in_network (s, net_prev, NULL );
  }

  if (GNUNET_NO == (is_bandwidth_available_in_network (fba_ctx.best->solver_information)))
  {
    GNUNET_break(0); /* This should never happen*/
    return NULL ;
  }

  fba_ctx.best->active = GNUNET_YES;
  addresse_increment (s, net_cur, GNUNET_NO, GNUNET_YES);
  distribute_bandwidth_in_network (s, net_cur, fba_ctx.best );
  return fba_ctx.best;
}

/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the solver handle
 * @param peer the peer
 */
void
GAS_proportional_stop_get_preferred_address (void *solver,
    const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct ATS_Address *cur;
  struct Network *cur_net;

  if (GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (s->requests,
          &peer->hashPubKey))
    GNUNET_CONTAINER_multihashmap_remove (s->requests, &peer->hashPubKey,
        NULL );

  cur = get_active_address (s,
      (struct GNUNET_CONTAINER_MultiHashMap *) s->addresses, peer);
  if (NULL != cur)
  {
    /* Disabling current address */
    cur_net = (struct Network *) cur->solver_information;
    cur->active = GNUNET_NO; /* No active any longer */
    cur->assigned_bw_in = BANDWIDTH_ZERO; /* no bandwidth assigned */
    cur->assigned_bw_out = BANDWIDTH_ZERO; /* no bandwidth assigned */
    if (GNUNET_SYSERR == addresse_decrement (s, cur_net, GNUNET_NO, GNUNET_YES))
      GNUNET_break(0);
    distribute_bandwidth_in_network (s, cur_net, NULL );
  }
  return;
}

/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_proportional_address_delete (void *solver, struct ATS_Address *address,
    int session_only)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct Network *net;
  struct AddressWrapper *aw;
  const struct ATS_Address *new_address;


  /* Remove an adress completely, we have to:
   * - Remove from specific network
   * - Decrease number of total addresses
   * - If active:
   *   - decrease number of active addreses
   *   - update quotas
   */

  net = (struct Network *) address->solver_information;

  if (GNUNET_NO == session_only)
  {
    LOG(GNUNET_ERROR_TYPE_INFO,
        "Deleting %s address %p for peer `%s' from network `%s' (total: %u/ active: %u)\n",
        (GNUNET_NO == address->active) ? "inactive" : "active", address,
        GNUNET_i2s (&address->peer), net->desc, net->total_addresses,
        net->active_addresses);

    /* Remove address */
    addresse_decrement (s, net, GNUNET_YES, GNUNET_NO);
    for (aw = net->head; NULL != aw; aw = aw->next)
    {
      if (aw->addr == address)
        break;
    }
    if (NULL == aw)
    {
      GNUNET_break(0);
      return;
    }
    GNUNET_CONTAINER_DLL_remove(net->head, net->tail, aw);
    GNUNET_free(aw);
  }
  else
  {
    /* Remove session only: remove if active and update */
    LOG(GNUNET_ERROR_TYPE_INFO,
        "Deleting %s session %p for peer `%s' from network `%s' (total: %u/ active: %u)\n",
        (GNUNET_NO == address->active) ? "inactive" : "active", address,
        GNUNET_i2s (&address->peer), net->desc, net->total_addresses,
        net->active_addresses);
  }

  if (GNUNET_YES == address->active)
  {
    /* Address was active, remove from network and update quotas*/
    address->active = GNUNET_NO;
    address->assigned_bw_in = BANDWIDTH_ZERO;
    address->assigned_bw_out = BANDWIDTH_ZERO;

    if (GNUNET_SYSERR == addresse_decrement (s, net, GNUNET_NO, GNUNET_YES))
      GNUNET_break(0);
    distribute_bandwidth_in_network (s, net, NULL );
    if (NULL == (new_address = GAS_proportional_get_preferred_address (s, &address->peer)))
    {
      /* No alternative address found, disconnect peer */
      s->bw_changed (s->bw_changed_cls, address);
    }
    else
    {
      s->bw_changed (s->bw_changed_cls, (struct ATS_Address *) new_address);
    }
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "After deleting address now total %u and active %u addresses in network `%s'\n",
      net->total_addresses, net->active_addresses, net->desc);

}

/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
void
GAS_proportional_bulk_start (void *solver)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Locking solver for bulk operation ...\n");
  struct GAS_PROPORTIONAL_Handle *s = (struct GAS_PROPORTIONAL_Handle *) solver;

  GNUNET_assert(NULL != solver);
  s->bulk_lock++;
}

/**
 * Bulk operation done
 */
void
GAS_proportional_bulk_stop (void *solver)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Unlocking solver from bulk operation ...\n");

  struct GAS_PROPORTIONAL_Handle *s = (struct GAS_PROPORTIONAL_Handle *) solver;
  GNUNET_assert(NULL != solver);

  if (s->bulk_lock < 1)
  {
    GNUNET_break(0);
    return;
  }
  s->bulk_lock--;
  if ((0 == s->bulk_lock) && (0 < s->bulk_requests))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "No lock pending, recalculating\n");
    distribute_bandwidth_in_all_networks (s);
    s->bulk_requests = 0;
  }
}

/**
 * Add a new single address to a network
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_proportional_address_add (void *solver, struct ATS_Address *address,
    uint32_t network);

/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
void
GAS_proportional_address_property_changed (void *solver,
    struct ATS_Address *address, uint32_t type, uint32_t abs_value,
    double rel_value)
{
  struct GAS_PROPORTIONAL_Handle *s;
  struct Network *n;

  GNUNET_assert(NULL != solver);
  GNUNET_assert(NULL != address);

  s = (struct GAS_PROPORTIONAL_Handle *) solver;
  n = (struct Network *) address->solver_information;

  if (NULL == n)
  {
    GNUNET_break(0);
    return;
  }

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Property `%s' for peer `%s' address %p changed to %.2f \n",
      GNUNET_ATS_print_property_type (type), GNUNET_i2s (&address->peer),
      address, rel_value);
  switch (type)
  {
  case GNUNET_ATS_UTILIZATION_UP:
  case GNUNET_ATS_UTILIZATION_DOWN:
  case GNUNET_ATS_QUALITY_NET_DELAY:
  case GNUNET_ATS_QUALITY_NET_DISTANCE:
  case GNUNET_ATS_COST_WAN:
  case GNUNET_ATS_COST_LAN:
  case GNUNET_ATS_COST_WLAN:
    distribute_bandwidth_in_network (s, n, GNUNET_NO);
    break;
  }
}

/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param cur_session the current session
 * @param new_session the new session
 */
void
GAS_proportional_address_session_changed (void *solver,
    struct ATS_Address *address, uint32_t cur_session, uint32_t new_session)
{
  if (cur_session != new_session)
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Session changed from %u to %u\n", cur_session,
        new_session);
  }
}

/**
 * Usage for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
void
GAS_proportional_address_inuse_changed (void *solver,
    struct ATS_Address *address, int in_use)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Usage changed to %s\n",
      (GNUNET_YES == in_use) ? "USED" : "UNUSED");
}

/**
 * Network scope for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param current_network the current network
 * @param new_network the new network
 */
void
GAS_proportional_address_change_network (void *solver,
    struct ATS_Address *address, uint32_t current_network, uint32_t new_network)
{
  struct ATS_Address *new;
  struct GAS_PROPORTIONAL_Handle *s = (struct GAS_PROPORTIONAL_Handle *) solver;
  int save_active = GNUNET_NO;
  struct Network *new_net = NULL;

  if (current_network == new_network)
  {
    GNUNET_break(0);
    return;
  }

  /* Network changed */
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Network type changed, moving %s address from `%s' to `%s'\n",
      (GNUNET_YES == address->active) ? "active" : "inactive",
      GNUNET_ATS_print_network_type (current_network),
      GNUNET_ATS_print_network_type (new_network));

  save_active = address->active;

  /* Disable and assign no bandwidth */
  address->active = GNUNET_NO;
  address->assigned_bw_in = BANDWIDTH_ZERO; /* no bandwidth assigned */
  address->assigned_bw_out = BANDWIDTH_ZERO; /* no bandwidth assigned */

  /* Remove from old network */
  GAS_proportional_address_delete (solver, address, GNUNET_NO);

  /* Set new network type */
  if (NULL == (new_net = get_network (solver, new_network)))
  {
    /* Address changed to invalid network... */
    LOG(GNUNET_ERROR_TYPE_ERROR,
        _("Invalid network type `%u' `%s': Disconnect!\n"), new_network,
        GNUNET_ATS_print_network_type (new_network));

    /* Find new address to suggest since no bandwidth in network*/
    if (NULL == (new = (struct ATS_Address *) GAS_proportional_get_preferred_address (s, &address->peer)))
    {
      /* No alternative address found, disconnect peer */
      s->bw_changed (s->bw_changed_cls, address);
    }
    return;
  }

  /* Add to new network and update*/
  address->solver_information = new_net;
  GAS_proportional_address_add (solver, address, new_network);
  if (GNUNET_YES == save_active)
  {
    /* check if bandwidth available in new network */
    if (GNUNET_YES == (is_bandwidth_available_in_network (new_net)))
    {
      /* Assign bandwidth to updated address */
      address->active = GNUNET_YES;
      addresse_increment (s, new_net, GNUNET_NO, GNUNET_YES);
      distribute_bandwidth_in_network (solver, new_net, NULL );
    }
    else
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG,
          "Not enough bandwidth in new network, suggesting alternative address ..\n");
      /* Find new address to suggest since no bandwidth in network*/
      if (NULL
          == (new =
              (struct ATS_Address *) GAS_proportional_get_preferred_address (s,
                  &address->peer)))
      {
        /* No alternative address found, disconnect peer */
        s->bw_changed (s->bw_changed_cls, address);
      }
    }
  }
}

/**
 * Add a new single address to a network
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_proportional_address_add (void *solver, struct ATS_Address *address,
    uint32_t network)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct Network *net = NULL;
  struct AddressWrapper *aw = NULL;
  const struct ATS_Address *new_address;

  GNUNET_assert(NULL != s);


  net = get_network (s, network);
  if (NULL == net)
  {
    GNUNET_break(0);
    return;
  }

  aw = GNUNET_malloc (sizeof (struct AddressWrapper));
  aw->addr = address;
  GNUNET_CONTAINER_DLL_insert(net->head, net->tail, aw);
  addresse_increment (s, net, GNUNET_YES, GNUNET_NO);
  aw->addr->solver_information = net;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (s->requests, &address->peer.hashPubKey))
  {
    if (NULL == get_active_address (s, (struct GNUNET_CONTAINER_MultiHashMap *) s->addresses, &address->peer))
    {
      if (NULL != (new_address = GAS_proportional_get_preferred_address (s, &address->peer)))
          s->bw_changed (s->bw_changed_cls, (struct ATS_Address *) address);
    }
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "After adding address now total %u and active %u addresses in network `%s'\n",
      net->total_addresses, net->active_addresses, net->desc);
}

/**
 * Init the proportional problem solver
 *
 * Quotas:
 * network[i] contains the network type as type GNUNET_ATS_NetworkType[i]
 * out_quota[i] contains outbound quota for network type i
 * in_quota[i] contains inbound quota for network type i
 *
 * Example
 * network = {GNUNET_ATS_NET_UNSPECIFIED, GNUNET_ATS_NET_LOOPBACK, GNUNET_ATS_NET_LAN, GNUNET_ATS_NET_WAN, GNUNET_ATS_NET_WLAN}
 * network[2]   == GNUNET_ATS_NET_LAN
 * out_quota[2] == 65353
 * in_quota[2]  == 65353
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @param addresses hashmap containing all addresses
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param out_quota array of outbound quotas
 * @param in_quota array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @param get_preference callback to get relative preferences for a peer
 * @param get_preference_cls cls for callback to get relative preferences
 * @param get_properties for callback to get relative properties
 * @param get_properties_cls cls for callback to get relative properties
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_proportional_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const struct GNUNET_STATISTICS_Handle *stats,
    const struct GNUNET_CONTAINER_MultiHashMap *addresses, int *network,
    unsigned long long *out_quota, unsigned long long *in_quota,
    int dest_length, GAS_bandwidth_changed_cb bw_changed_cb,
    void *bw_changed_cb_cls, GAS_get_preferences get_preference,
    void *get_preference_cls, GAS_get_properties get_properties,
    void *get_properties_cls)
{
  int c;
  struct GAS_PROPORTIONAL_Handle *s =
      GNUNET_malloc (sizeof (struct GAS_PROPORTIONAL_Handle));
  struct Network * cur;
  char * net_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;

  GNUNET_assert(NULL != cfg);
  GNUNET_assert(NULL != stats);
  GNUNET_assert(NULL != network);
  GNUNET_assert(NULL != bw_changed_cb);
  GNUNET_assert(NULL != get_preference);
  GNUNET_assert(NULL != get_properties);

  s->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  s->bw_changed = bw_changed_cb;
  s->bw_changed_cls = bw_changed_cb_cls;
  s->get_preferences = get_preference;
  s->get_preferences_cls = get_preference_cls;
  s->get_properties = get_properties;
  s->get_properties_cls = get_properties_cls;
  s->networks = dest_length;
  s->network_entries = GNUNET_malloc (dest_length * sizeof (struct Network));
  s->active_addresses = 0;
  s->total_addresses = 0;
  s->bulk_lock = GNUNET_NO;
  s->addresses = addresses;

  s->requests = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);

  for (c = 0; c < dest_length; c++)
  {
    cur = &s->network_entries[c];
    cur->total_addresses = 0;
    cur->active_addresses = 0;
    cur->type = network[c];
    cur->total_quota_in = in_quota[c];
    cur->total_quota_out = out_quota[c];
    cur->desc = net_str[c];
    GNUNET_asprintf (&cur->stat_total, "# ATS addresses %s total", cur->desc);
    GNUNET_asprintf (&cur->stat_active, "# ATS active addresses %s total",
        cur->desc);
  }
  return s;
}

/**
 * Shutdown the proportional problem solver
 *
 * @param solver the respective handle to shutdown
 */
void
GAS_proportional_done (void *solver)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct AddressWrapper *cur;
  struct AddressWrapper *next;
  int c;
  GNUNET_assert(s != NULL);

  for (c = 0; c < s->networks; c++)
  {
    if (s->network_entries[c].total_addresses > 0)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR,
          "Had %u addresses for network `%s' not deleted during shutdown\n",
          s->network_entries[c].total_addresses, s->network_entries[c].desc);
      GNUNET_break(0);
    }

    if (s->network_entries[c].active_addresses > 0)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR,
          "Had %u active addresses for network `%s' not deleted during shutdown\n",
          s->network_entries[c].active_addresses, s->network_entries[c].desc);
      GNUNET_break(0);
    }

    next = s->network_entries[c].head;
    while (NULL != (cur = next))
    {
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove(s->network_entries[c].head,
          s->network_entries[c].tail, cur);
      GNUNET_free(cur);
    }
    GNUNET_free(s->network_entries[c].stat_total);
    GNUNET_free(s->network_entries[c].stat_active);
  }
  if (s->total_addresses > 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Had %u addresses not deleted during shutdown\n", s->total_addresses);
    GNUNET_break(0);
  }
  if (s->active_addresses > 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Had %u active addresses not deleted during shutdown\n",
        s->active_addresses);
    GNUNET_break(0);
  }
  GNUNET_free(s->network_entries);
  GNUNET_CONTAINER_multihashmap_destroy (s->requests);
  GNUNET_free(s);
}

/* end of gnunet-service-ats-solver_proportional.c */
