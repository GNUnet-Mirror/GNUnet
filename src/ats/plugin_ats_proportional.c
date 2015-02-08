/*
 This file is part of GNUnet.
 Copyright (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/plugin_ats_proportional.c
 * @brief ATS proportional solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_plugin.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_addresses.h"

#define PROP_STABILITY_FACTOR 1.25


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
 *    #GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT and then distributes the
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
 *    #GNUNET_ATS_NET_UNSPECIFIED. Addresses in validation are located
 *    in this network type and only if a connection is successful on
 *    return of payload data transport switches to the real network
 *    the address is located in.  When an address changes networks it
 *    is first of all removed from the old network using the solver
 *    API function #GAS_proportional_address_delete() and the network in
 *    the address struct is updated. A lookup for the respective new
 *    proportional network is done and stored in the addresse's
 *    solver_information field. Next the address is re-added to the
 *    solver using the solver API function
 *    #GAS_proportional_address_add(). If the address was marked as in
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
 *    duration of #ATS_BLOCKING_DELTA when it is suggested to
 *    transport. Next it is checked if at least
 *    #GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT bytes bandwidth is available
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

/**
 * Default value to assume for the proportionality factor,
 * if none is given in the configuration.
 */
#define PROPORTIONALITY_FACTOR 2.0


/**
 * Address information stored for the proportional solver in the
 * `solver_information` member of `struct GNUNET_ATS_Address`.
 *
 * They are also stored in the respective `struct Network`'s linked
 * list.
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

    /**
   * Network scope this address is in
   */
  struct Network *network;

  /**
   * Inbound quota
   */
  uint32_t calculated_quota_in;

  /**
   * Outbound quota
   */
  uint32_t calculated_quota_out;

  /**
   * When was this address activated
   */
  struct GNUNET_TIME_Absolute activated;

};


/**
 * Representation of a network
 */
struct Network
{
  /**
   * Network description
   */
  const char *desc;

  /**
   * String for statistics total addresses
   */
  char *stat_total;

  /**
   * String for statistics active addresses
   */
  char *stat_active;

  /**
   * Linked list of addresses in this network: head
   */
  struct AddressWrapper *head;

  /**
   * Linked list of addresses in this network: tail
   */
  struct AddressWrapper *tail;

  /**
   * Total inbound quota
   */
  unsigned long long total_quota_in;

  /**
   * Total outbound quota
   */
  unsigned long long total_quota_out;

  /**
   * ATS network type
   */
  enum GNUNET_ATS_Network_Type type;

  /**
   * Number of active addresses for this network
   */
  unsigned int active_addresses;

  /**
   * Number of total addresses for this network
   */
  unsigned int total_addresses;

};


/**
 * A handle for the proportional solver
 */
struct GAS_PROPORTIONAL_Handle
{

  /**
   * Our execution environment.
   */
  struct GNUNET_ATS_PluginEnvironment *env;

  /**
   * Networks array
   */
  struct Network *network_entries;

  /**
   * Proportionality factor
   */
  double prop_factor;

  /**
   * Stability factor
   */
  double stability_factor;

  /**
   * Bulk lock counter. If zero, we are not locked.
   */
  unsigned int bulk_lock;

  /**
   * Number of changes made while solver was locked.  We really only
   * use 0/non-zero to check on unlock if we have to run the update.
   */
  unsigned int bulk_requests;

  /**
   * Number of active addresses for solver
   */
  unsigned int active_addresses;

  /**
   * Number of networks in @a network_entries
   */
  unsigned int network_count;
};


/**
 * Test if bandwidth is available in this network to add an additional address
 *
 * @param net the network type to update
 * @return #GNUNET_YES or #GNUNET_NO
 */
static int
is_bandwidth_available_in_network (struct Network *net)
{
  unsigned int na = net->active_addresses + 1;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  if ( ((net->total_quota_in / na) > min_bw) &&
       ((net->total_quota_out / na) > min_bw) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Enough bandwidth available for %u active addresses in network `%s'\n",
         na,
         net->desc);

    return GNUNET_YES;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Not enough bandwidth available for %u active addresses in network `%s'\n",
       na,
       net->desc);
  return GNUNET_NO;
}


/**
 * Update bandwidth assigned to peers in this network
 *
 * @param s the solver handle
 * @param net the network type to update
 * this address
 */
static void
distribute_bandwidth (struct GAS_PROPORTIONAL_Handle *s,
                      struct Network *net)
{
  struct AddressWrapper *aw;
  unsigned long long remaining_quota_in = 0;
  unsigned long long quota_out_used = 0;
  unsigned long long remaining_quota_out = 0;
  unsigned long long quota_in_used = 0;
  int count_addresses;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  double relative_peer_prefence;
  double sum_relative_peer_prefences; /* Important: has to be double not float due to precision */
  double cur_pref; /* Important: has to be double not float due to precision */
  double peer_weight;
  double total_weight;
  const double *peer_relative_prefs = NULL; /* Important: has to be double not float due to precision */

  uint32_t assigned_quota_in = 0;
  uint32_t assigned_quota_out = 0;


  LOG (GNUNET_ERROR_TYPE_INFO,
       "Recalculate quota for network type `%s' for %u addresses (in/out): %llu/%llu \n",
       net->desc,
       net->active_addresses,
       net->total_quota_in,
       net->total_quota_in);

  if (net->active_addresses == 0)
  {
    return; /* no addresses to update */
  }

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
  sum_relative_peer_prefences = 0.0;

  /* Calculate sum of relative preference for active addresses in this network */
  count_addresses = 0;
  for (aw = net->head; NULL != aw; aw = aw->next)
  {
    if (GNUNET_YES != aw->addr->active)
      continue;

    peer_relative_prefs = s->env->get_preferences (s->env->cls,
                                                   &aw->addr->peer);
    relative_peer_prefence = 0.0;
    relative_peer_prefence += peer_relative_prefs[GNUNET_ATS_PREFERENCE_BANDWIDTH];
    sum_relative_peer_prefences += relative_peer_prefence;
    count_addresses ++;
  }

  if (count_addresses != net->active_addresses)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "%s: Counted %u active addresses, but network says to have %u active addresses\n",
         net->desc,
         count_addresses,
         net->active_addresses);
    for (aw = net->head; NULL != aw; aw = aw->next)
    {
      if (GNUNET_YES != aw->addr->active)
        continue;

      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Active: `%s' `%s' length %u\n",
           GNUNET_i2s (&aw->addr->peer),
           aw->addr->plugin,
           aw->addr->addr_len);
    }
  }

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Total relative preference %.3f for %u addresses in network %s\n",
       sum_relative_peer_prefences,
       net->active_addresses,
       net->desc);

  for (aw = net->head; NULL != aw; aw = aw->next)
  {
    if (GNUNET_YES == aw->addr->active)
    {
      peer_relative_prefs = s->env->get_preferences (s->env->cls,
                                                     &aw->addr->peer);

      cur_pref = peer_relative_prefs[GNUNET_ATS_PREFERENCE_BANDWIDTH];
      total_weight = net->active_addresses +
          s->prop_factor * sum_relative_peer_prefences;
      peer_weight = (1.0 + (s->prop_factor * cur_pref));

      assigned_quota_in = min_bw
          + ((peer_weight / total_weight) * remaining_quota_in);
      assigned_quota_out = min_bw
          + ((peer_weight / total_weight) * remaining_quota_out);

      LOG (GNUNET_ERROR_TYPE_INFO,
          "New quota for peer `%s' with weight (cur/total) %.3f/%.3f (in/out): %llu / %llu\n",
          GNUNET_i2s (&aw->addr->peer),
           peer_weight,
           total_weight,
          assigned_quota_in,
           assigned_quota_out);
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

    /* Store for later propagation */
    aw->calculated_quota_in = assigned_quota_in;
    aw->calculated_quota_out = assigned_quota_out;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Total bandwidth assigned is (in/out): %llu /%llu\n",
       quota_in_used,
       quota_out_used);
  if (quota_out_used > net->total_quota_out + 1) /* +1 is required due to rounding errors */
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Total outbound bandwidth assigned is larger than allowed (used/allowed) for %u active addresses: %llu / %llu\n",
         net->active_addresses,
         quota_out_used,
         net->total_quota_out);
  }
  if (quota_in_used > net->total_quota_in + 1) /* +1 is required due to rounding errors */
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Total inbound bandwidth assigned is larger than allowed (used/allowed) for %u active addresses: %llu / %llu\n",
         net->active_addresses,
         quota_in_used,
         net->total_quota_in);
  }
}


/**
 * Notify ATS service of bandwidth changes to addresses.
 *
 * @param s solver handle
 * @param net the network to propagate changes in
 */
static void
propagate_bandwidth (struct GAS_PROPORTIONAL_Handle *s,
                     struct Network *net)
{
  struct AddressWrapper *cur;

  for (cur = net->head; NULL != cur; cur = cur->next)
  {
    if ( (cur->addr->assigned_bw_in == cur->calculated_quota_in) &&
         (cur->addr->assigned_bw_out == cur->calculated_quota_out) )
      continue;
    cur->addr->assigned_bw_in = cur->calculated_quota_in;
    cur->addr->assigned_bw_out = cur->calculated_quota_out;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Bandwidth for %s address %p for peer `%s' changed to %u/%u\n",
         (GNUNET_NO == cur->addr->active) ? "inactive" : "active",
         cur->addr,
         GNUNET_i2s (&cur->addr->peer),
         cur->addr->assigned_bw_in,
         cur->addr->assigned_bw_out);

    /* Notify on change */
    if (GNUNET_YES == cur->addr->active)
      s->env->bandwidth_changed_cb (s->env->cls,
                                    cur->addr);
  }
}


/**
 * Distribute bandwidth.  The addresses have already been selected,
 * this is merely distributed the bandwidth among the addresses.
 *
 * @param s the solver handle
 * @param n the network, can be NULL for all networks
 */
static void
distribute_bandwidth_in_network (struct GAS_PROPORTIONAL_Handle *s,
                                 struct Network *n)
{
  unsigned int i;

  if (GNUNET_YES == s->bulk_lock)
  {
    s->bulk_requests++;
    return;
  }
  if (NULL != n)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Redistributing bandwidth in network %s with %u active and %u total addresses\n",
         GNUNET_ATS_print_network_type(n->type),
         n->active_addresses,
         n->total_addresses);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_START,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_SINGLE);
    distribute_bandwidth(s,
                         n);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_STOP,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_SINGLE);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_UPDATE_NOTIFICATION_START,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_SINGLE);
    propagate_bandwidth (s,
                         n);

    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_SINGLE);
  }
  else
  {
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_START,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_ALL);
    for (i = 0; i < s->network_count; i++)
      distribute_bandwidth (s,
                            &s->network_entries[i]);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_STOP,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_ALL);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_UPDATE_NOTIFICATION_START,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_ALL);
    for (i = 0; i < s->network_count; i++)
      propagate_bandwidth (s,
                           &s->network_entries[i]);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_ALL);
  }
}


/**
 * Context for finding the best address* Linked list of addresses in this network: head
 */
struct FindBestAddressCtx
{
  /**
   * The solver handle
   */
  struct GAS_PROPORTIONAL_Handle *s;

  /**
   * The currently best address
   */
  struct ATS_Address *best;
};


/**
 * Find index of a ATS property type in the quality properties array.
 *
 * @param type ATS property type
 * @return index in the quality array, #GNUNET_SYSERR if the type
 *         was not a quality property
 */
static int
find_quality_property_index (enum GNUNET_ATS_Property type)
{
  enum GNUNET_ATS_Property existing_types[] = GNUNET_ATS_QualityProperties;
  unsigned int c;

  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
    if (existing_types[c] == type)
      return c;
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Find a "good" address to use for a peer by iterating over the
 * addresses for this peer.  If we already have an existing address,
 * we stick to it.  Otherwise, we pick by lowest distance and then by
 * lowest latency.
 *
 * @param cls the `struct FindBestAddressCtx *' where we store the result
 * @param key the peer we are trying to find the best address for
 * @param value another `struct ATS_Address*` to consider using
 * @return #GNUNET_OK (continue to iterate)
 */
static int
find_best_address_it (void *cls,
		      const struct GNUNET_PeerIdentity *key,
		      void *value)
{
  struct FindBestAddressCtx *ctx = cls;
  struct ATS_Address *current = value;
  struct AddressWrapper *asi = current->solver_information;
  struct GNUNET_TIME_Relative active_time;
  double best_delay;
  double best_distance;
  double cur_delay;
  double cur_distance;
  int index;

  if (GNUNET_NO ==
      is_bandwidth_available_in_network (asi->network))
  {
    /* There's no bandwidth available in this network,
       so we cannot use this address. */
    return GNUNET_OK;
  }
  if (GNUNET_YES == current->active)
  {
    active_time = GNUNET_TIME_absolute_get_duration (asi->activated);
    if (active_time.rel_value_us <=
        ((double) GNUNET_TIME_UNIT_SECONDS.rel_value_us) * ctx->s->stability_factor)
    {
      /* Keep active address for stability reasons */
      ctx->best = current;
      return GNUNET_NO;
    }
  }
  if (NULL == ctx->best)
  {
    /* We so far have nothing else, so go with it! */
    ctx->best = current;
    return GNUNET_OK;
  }

  /* Now compare ATS information */
  index = find_quality_property_index (GNUNET_ATS_QUALITY_NET_DISTANCE);
  cur_distance = current->atsin[index].norm;
  best_distance = ctx->best->atsin[index].norm;
  index = find_quality_property_index (GNUNET_ATS_QUALITY_NET_DELAY);
  cur_delay = current->atsin[index].norm;
  best_delay = ctx->best->atsin[index].norm;

  /* user shorter distance */
  if (cur_distance < best_distance)
  {
    if (GNUNET_NO == ctx->best->active)
    {
      /* Activity doesn't influence the equation, use current */
      ctx->best = current;
    }
    else if ((best_distance / cur_distance) > ctx->s->stability_factor)
    {
      /* Distance change is significant, switch active address! */
      ctx->best = current;
    }
  }

  /* User connection with less delay */
  if (cur_delay < best_delay)
  {
    if (GNUNET_NO == ctx->best->active)
    {
      /* Activity doesn't influence the equation, use current */
      ctx->best = current;
    }
    else if ((best_delay / cur_delay) > ctx->s->stability_factor)
    {
      /* Latency change is significant, switch active address! */
      ctx->best = current;
    }
  }
  return GNUNET_OK;
}


/**
 * Find the currently best address for a peer from the set of
 * addresses available or return NULL of no address is available.
 *
 * @param s the proportional handle
 * @param addresses the address hashmap
 * @param id the peer id
 * @return the address or NULL
 */
struct ATS_Address *
get_best_address (struct GAS_PROPORTIONAL_Handle *s,
                  struct GNUNET_CONTAINER_MultiPeerMap *addresses,
                  const struct GNUNET_PeerIdentity *id)
{
  struct FindBestAddressCtx fba_ctx;

  fba_ctx.best = NULL;
  fba_ctx.s = s;
  GNUNET_CONTAINER_multipeermap_get_multiple (addresses,
                                              id,
                                              &find_best_address_it,
                                              &fba_ctx);
  return fba_ctx.best;
}


/**
 * Decrease number of active addresses in network.
 *
 * @param s the solver handle
 * @param net the network type
 */
static void
address_decrement_active (struct GAS_PROPORTIONAL_Handle *s,
                          struct Network *net)
{
  GNUNET_assert (net->active_addresses > 0);
  net->active_addresses--;
  GNUNET_STATISTICS_update (s->env->stats,
                            net->stat_active,
                            -1,
                            GNUNET_NO);
  GNUNET_assert (s->active_addresses > 0);
  s->active_addresses--;
  GNUNET_STATISTICS_update (s->env->stats,
                            "# ATS addresses total",
                            -1,
                            GNUNET_NO);
}


/**
 * Address map iterator to find current active address for peer.
 * Asserts that only one address is active per peer.
 *
 * @param cls last active address
 * @param key peer's key
 * @param value address to check
 * @return #GNUNET_NO on double active address else #GNUNET_YES;
 */
static int
get_active_address_it (void *cls,
                       const struct GNUNET_PeerIdentity *key,
                       void *value)
{
  struct ATS_Address **dest = cls;
  struct ATS_Address *aa = value;

  if (GNUNET_YES != aa->active)
    return GNUNET_OK;
  GNUNET_assert (NULL == (*dest));
  (*dest) = aa;
  return GNUNET_OK;
}


/**
 * Find current active address for peer
 *
 * @param s the solver handle
 * @param peer the peer
 * @return active address or NULL
 */
static struct ATS_Address *
get_active_address (struct GAS_PROPORTIONAL_Handle *s,
                    const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *dest;

  dest = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (s->env->addresses,
                                              peer,
                                              &get_active_address_it,
                                              &dest);
  return dest;
}


/**
 * Update active address for a peer:
 * Check if active address exists and what the best address is, if addresses
 * are different switch
 *
 * @param s solver handle
 * @param peer the peer to check
 * return the new address or NULL if no update was performed
  */
static struct ATS_Address *
update_active_address (struct GAS_PROPORTIONAL_Handle *s,
                       const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *best_address;
  struct ATS_Address *current_address;
  struct AddressWrapper *asi;
  struct Network *net;

  current_address = get_active_address (s,
                                        peer);
  best_address = get_best_address (s,
                                   s->env->addresses,
                                   peer);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Peer `%s' has active address %p and best address %p\n",
       GNUNET_i2s (peer),
       current_address,
       best_address);

  if (NULL != current_address)
  {
    GNUNET_assert (GNUNET_YES == current_address->active);
    if ( (NULL == best_address) ||
         ( (NULL != best_address) &&
           (current_address != best_address) ) )
    {
      /* We switch to a new address (or to none),
         mark old address as inactive */
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Disabling previous %s address %p for peer `%s'\n",
           (GNUNET_NO == current_address->active) ? "inactive" : "active",
           current_address,
           GNUNET_i2s (peer));

      asi = current_address->solver_information;
      net = asi->network;
      asi->activated = GNUNET_TIME_UNIT_ZERO_ABS;
      current_address->active = GNUNET_NO; /* No active any longer */
      current_address->assigned_bw_in = 0; /* no bandwidth assigned */
      current_address->assigned_bw_out = 0; /* no bandwidth assigned */
      address_decrement_active (s, net);
      distribute_bandwidth_in_network (s, net);
    }
    if (NULL == best_address)
    {
      /* We previously had an active address, but now we cannot suggest one
       * Therefore we have to disconnect the peer */
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Disconnecting peer `%s' with previous address %p\n",
           GNUNET_i2s (peer),
           current_address);
      s->env->bandwidth_changed_cb (s->env->cls,
                                    current_address);
    }
  }
  if (NULL == best_address)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Cannot suggest address for peer `%s'\n",
         GNUNET_i2s (peer));
    return NULL;
  }

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Suggesting new address %p for peer `%s'\n",
       best_address,
       GNUNET_i2s (peer));

  if ( (NULL != current_address) &&
       (best_address == current_address) )
  {
    GNUNET_break (GNUNET_NO != current_address->active);
    return best_address; /* Same same */
  }

  asi = best_address->solver_information;
  GNUNET_assert (NULL != asi);
  net = asi->network;

  /* Mark address as active */
  asi->activated = GNUNET_TIME_absolute_get ();
  best_address->active = GNUNET_YES;

  net->active_addresses++;
  s->active_addresses++;
  GNUNET_STATISTICS_update (s->env->stats,
                            "# ATS active addresses total",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (s->env->stats,
                            net->stat_active,
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Address %p for peer `%s' is now active\n",
       best_address,
       GNUNET_i2s (peer));
  /* Distribute bandwidth */
  distribute_bandwidth_in_network (s, net);
  return best_address;
}


/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param pref_rel the normalized preference value for this kind over all clients
 */
static void
GAS_proportional_address_change_preference (void *solver,
					    const struct GNUNET_PeerIdentity *peer,
					    enum GNUNET_ATS_PreferenceKind kind,
					    double pref_rel)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct ATS_Address *best_address;
  struct ATS_Address *active_address;
  struct AddressWrapper *asi;

  if (0 ==
      s->env->get_connectivity (s->env->cls,
                                peer))
    return; /* Peer is not requested */

  /* This peer is requested, find best address */
  active_address = get_active_address (s,
                                       peer);
  best_address = update_active_address (s, peer);

  if ( (NULL != best_address) &&
       (active_address == best_address) )
  {
    asi = best_address->solver_information;
    GNUNET_assert (NULL != asi);

    /* We sticked to the same address, therefore redistribute  */
    distribute_bandwidth_in_network (s, asi->network);
  }
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
static void
GAS_proportional_address_preference_feedback (void *solver,
                                              struct GNUNET_SERVER_Client *application,
                                              const struct GNUNET_PeerIdentity *peer,
                                              const struct GNUNET_TIME_Relative scope,
                                              enum GNUNET_ATS_PreferenceKind kind,
                                              double score)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;

  GNUNET_assert(NULL != peer);
  GNUNET_assert(NULL != s);
}


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
static void
GAS_proportional_get_preferred_address (void *solver,
                                        const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct ATS_Address *best_address;

  best_address = update_active_address (s, peer);
  if (NULL == best_address)
    return;
  if (s->bulk_lock > 0)
    return;
  s->env->bandwidth_changed_cb (s->env->cls,
                                best_address);
}


/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the solver handle
 * @param peer the peer
 */
static void
GAS_proportional_stop_get_preferred_address (void *solver,
                                             const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct ATS_Address *cur;
  struct AddressWrapper *asi;
  struct Network *cur_net;

  cur = get_active_address (s,
                            peer);
  if (NULL != cur)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Disabling %s address %p for peer `%s'\n",
         (GNUNET_NO == cur->active) ? "inactive" : "active",
         cur,
         GNUNET_i2s (&cur->peer));

    /* Disabling current address */
    asi = cur->solver_information;
    cur_net = asi->network;
    asi->activated = GNUNET_TIME_UNIT_ZERO_ABS;
    cur->active = GNUNET_NO; /* No active any longer */
    cur->assigned_bw_in = 0; /* no bandwidth assigned */
    cur->assigned_bw_out = 0; /* no bandwidth assigned */

    address_decrement_active (s, cur_net);

    distribute_bandwidth_in_network (s, cur_net);
  }
}


/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
static void
GAS_proportional_bulk_start (void *solver)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Locking solver for bulk operation ...\n");
  GNUNET_assert (NULL != solver);
  s->bulk_lock++;
}


/**
 * Bulk operation done.
 *
 * @param solver our `struct GAS_PROPORTIONAL_Handle *`
 */
static void
GAS_proportional_bulk_stop (void *solver)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Unlocking solver from bulk operation ...\n");
  if (s->bulk_lock < 1)
  {
    GNUNET_break(0);
    return;
  }
  s->bulk_lock--;
  if ((0 == s->bulk_lock) && (0 < s->bulk_requests))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No lock pending, recalculating\n");
    distribute_bandwidth_in_network (s, NULL);
    s->bulk_requests = 0;
  }
}


/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
static void
GAS_proportional_address_property_changed (void *solver,
                                           struct ATS_Address *address,
                                           enum GNUNET_ATS_Property type,
                                           uint32_t abs_value,
                                           double rel_value)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct AddressWrapper *asi;
  struct ATS_Address *best_address;
  struct ATS_Address *active_address;

  asi = address->solver_information;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Property `%s' for peer `%s' address %p changed to %.2f\n",
       GNUNET_ATS_print_property_type (type),
       GNUNET_i2s (&address->peer),
       address,
       rel_value);

  if (0 ==
      s->env->get_connectivity (s->env->cls,
                                &address->peer))
    return; /* Peer is not requested */

  /* This peer is requested, find active and best address */
  active_address = get_active_address (s,
                                       &address->peer);
  best_address = update_active_address (s,
                                        &address->peer);
  if (active_address == best_address)
  {
    /* We stuck to the same address, therefore redistribute
       (NOTE: because otherwise update_active_address() already
       calls distribute_bandwidth_in_network() )*/
    distribute_bandwidth_in_network (s, asi->network);
  }
}


/**
 * Add a new single address to a network
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
static void
GAS_proportional_address_add (void *solver,
                              struct ATS_Address *address,
                              enum GNUNET_ATS_Network_Type network)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct Network *net;
  struct AddressWrapper *aw;

  GNUNET_assert (network < s->env->network_count);
  net = &s->network_entries[network];
  net->total_addresses++;

  aw = GNUNET_new (struct AddressWrapper);
  aw->addr = address;
  aw->network = net;
  address->solver_information = aw;
  GNUNET_CONTAINER_DLL_insert (net->head,
                               net->tail,
                               aw);
  GNUNET_STATISTICS_update (s->env->stats,
                            "# ATS addresses total",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (s->env->stats,
                            net->stat_total,
                            1,
                            GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Adding new address %p for peer `%s', now total %u and active %u addresses in network `%s'\n",
       address,
       GNUNET_i2s (&address->peer),
       net->total_addresses,
       net->active_addresses,
       net->desc);

  if (0 ==
      s->env->get_connectivity (s->env->cls,
                                &address->peer))
    return; /* Peer is not requested */

  /* This peer is requested, find best address */
  update_active_address (s,
                         &address->peer);
}


/**
 * Remove an address from the solver. To do so, we:
 * - Removed it from specific network
 * - Decrease the number of total addresses
 * - If active:
 *   - decrease number of active addreses
 *   - update quotas
 *
 * @param solver the solver handle
 * @param address the address to remove
 */
static void
GAS_proportional_address_delete (void *solver,
                                 struct ATS_Address *address)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct AddressWrapper *aw = address->solver_information;
  struct Network *net = aw->network;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Deleting %s address for peer `%s' from network `%s' (total: %u/active: %u)\n",
       (GNUNET_NO == address->active) ? "inactive" : "active",
       GNUNET_i2s (&address->peer),
       net->desc,
       net->total_addresses,
       net->active_addresses);

  GNUNET_CONTAINER_DLL_remove (net->head,
                               net->tail,
                               aw);
  GNUNET_assert (net->total_addresses > 0);
  net->total_addresses--;
  GNUNET_STATISTICS_update (s->env->stats,
                            net->stat_total,
                            -1,
                            GNUNET_NO);
  if (GNUNET_YES == address->active)
  {
    /* Address was active, remove from network and update quotas*/
    address->active = GNUNET_NO;
    address->assigned_bw_in = 0;
    address->assigned_bw_out = 0;
    address_decrement_active (s, net);
    /* FIXME: this may trigger the solver unnecessarily,
       especially if update_active_address() succeeds! */
    distribute_bandwidth_in_network (s, net);

    if (NULL ==
        update_active_address (s,
                               &address->peer))
    {
      /* No alternative address found, disconnect peer */
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Disconnecting peer `%s' after deleting previous address %p\n",
           GNUNET_i2s (&address->peer),
           address);
      s->env->bandwidth_changed_cb (s->env->cls,
                                    address);
    }
  }
  GNUNET_free (aw);
  address->solver_information = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "After deleting address now total %u and active %u addresses in network `%s'\n",
       net->total_addresses,
       net->active_addresses,
       net->desc);
}


/**
 * Function invoked when the plugin is loaded.
 *
 * @param[in,out] cls the `struct GNUNET_ATS_PluginEnvironment *` to use;
 *            modified to return the API functions (ugh).
 * @return the `struct GAS_PROPORTIONAL_Handle` to pass as a closure
 */
void *
libgnunet_plugin_ats_proportional_init (void *cls)
{
  static struct GNUNET_ATS_SolverFunctions sf;
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct GAS_PROPORTIONAL_Handle *s;
  struct Network * cur;
  float f_tmp;
  unsigned int c;

  s = GNUNET_new (struct GAS_PROPORTIONAL_Handle);
  s->env = env;
  sf.cls = s;
  sf.s_add = &GAS_proportional_address_add;
  sf.s_address_update_property = &GAS_proportional_address_property_changed;
  sf.s_get = &GAS_proportional_get_preferred_address;
  sf.s_get_stop = &GAS_proportional_stop_get_preferred_address;
  sf.s_pref = &GAS_proportional_address_change_preference;
  sf.s_feedback = &GAS_proportional_address_preference_feedback;
  sf.s_del = &GAS_proportional_address_delete;
  sf.s_bulk_start = &GAS_proportional_bulk_start;
  sf.s_bulk_stop = &GAS_proportional_bulk_stop;
  s->stability_factor = PROP_STABILITY_FACTOR;
  if (GNUNET_SYSERR !=
      GNUNET_CONFIGURATION_get_value_float (env->cfg,
                                            "ats",
                                            "PROP_STABILITY_FACTOR",
                                            &f_tmp))
  {
    if ((f_tmp < 1.0) || (f_tmp > 2.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Invalid %s configuration %f \n"),
           "PROP_STABILITY_FACTOR",
           f_tmp);
    }
    else
    {
      s->stability_factor = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Using %s of %.3f\n",
           "PROP_STABILITY_FACTOR",
           f_tmp);
    }
  }
  s->prop_factor = PROPORTIONALITY_FACTOR;
  if (GNUNET_SYSERR !=
      GNUNET_CONFIGURATION_get_value_float (env->cfg,
                                            "ats",
                                            "PROP_PROPORTIONALITY_FACTOR",
                                            &f_tmp))
  {
    if (f_tmp < 1.0)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Invalid %s configuration %f\n"),
           "PROP_PROPORTIONALITY_FACTOR",
           f_tmp);
    }
    else
    {
      s->prop_factor = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO,
           "Using %s of %.3f\n",
           "PROP_PROPORTIONALITY_FACTOR",
           f_tmp);
    }
  }

  s->network_entries = GNUNET_malloc (env->network_count *
                                      sizeof (struct Network));
  for (c = 0; c < env->network_count; c++)
  {
    cur = &s->network_entries[c];
    cur->type = c;
    cur->total_quota_in = env->in_quota[c];
    cur->total_quota_out = env->out_quota[c];
    cur->desc = GNUNET_ATS_print_network_type (c);
    GNUNET_asprintf (&cur->stat_total,
                     "# ATS addresses %s total",
                     cur->desc);
    GNUNET_asprintf (&cur->stat_active,
                     "# ATS active addresses %s total",
                     cur->desc);
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Added network %u `%s' (%llu/%llu)\n",
         c,
         cur->desc,
         cur->total_quota_in,
         cur->total_quota_out);
  }
  return &sf;
}


/**
 * Function used to unload the plugin.
 *
 * @param cls return value from #libgnunet_plugin_ats_proportional_init()
 */
void *
libgnunet_plugin_ats_proportional_done (void *cls)
{
  struct GNUNET_ATS_SolverFunctions *sf = cls;
  struct GAS_PROPORTIONAL_Handle *s = sf->cls;
  struct AddressWrapper *cur;
  struct AddressWrapper *next;
  unsigned int c;

  for (c = 0; c < s->network_count; c++)
  {
    GNUNET_break (0 == s->network_entries[c].total_addresses);
    GNUNET_break (0 == s->network_entries[c].active_addresses);
    next = s->network_entries[c].head;
    while (NULL != (cur = next))
    {
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove (s->network_entries[c].head,
                                   s->network_entries[c].tail,
                                   cur);
      GNUNET_free_non_null (cur->addr->solver_information);
      GNUNET_free(cur);
    }
    GNUNET_free (s->network_entries[c].stat_total);
    GNUNET_free (s->network_entries[c].stat_active);
  }
  GNUNET_break (0 == s->active_addresses);
  GNUNET_free (s->network_entries);
  GNUNET_free (s);
  return NULL;
}


/* end of plugin_ats_proportional.c */
