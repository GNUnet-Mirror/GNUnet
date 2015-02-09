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

#define LOG(kind,...) GNUNET_log_from (kind, "ats-proportional",__VA_ARGS__)

/**
 * How much do we value stability over adaptation by default.  A low
 * value (close to 1.0) means we adapt as soon as possible, a larger
 * value means that we have to have the respective factor of an
 * advantage (or delay) before we adapt and sacrifice stability.
 */
#define PROP_STABILITY_FACTOR 1.25


/**
 * Default value to assume for the proportionality factor, if none is
 * given in the configuration.  This factor determines how strong the
 * bandwidth allocation will orient itself on the application
 * preferences.  A lower factor means a more balanced bandwidth
 * distribution while a larger number means a distribution more in
 * line with application (bandwidth) preferences.
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

};


/**
 * Test if bandwidth is available in this network to add an additional address.
 *
 * @param net the network type to check
 * @param extra for how many extra addresses do we check?
 * @return #GNUNET_YES or #GNUNET_NO
 */
static int
is_bandwidth_available_in_network (struct Network *net,
                                   int extra)
{
  unsigned int na;
  uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

  GNUNET_assert (net->active_addresses + extra >= 0);
  na = net->active_addresses + extra;
  if (0 == na)
    return GNUNET_YES;
  if ( ((net->total_quota_in / na) > min_bw) &&
       ((net->total_quota_out / na) > min_bw) )
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Test if all peers in this network require connectivity at level at
 * least @a con.
 *
 * @param s the solver handle
 * @param net the network type to check
 * @param con connection return value threshold to check
 * @return #GNUNET_YES or #GNUNET_NO
 */
static int
all_require_connectivity (struct GAS_PROPORTIONAL_Handle *s,
                          struct Network *net,
                          unsigned int con)
{
  struct AddressWrapper *aw;

  for (aw = net->head; NULL != aw; aw = aw->next)
    if (con >
        s->env->get_connectivity (s->env->cls,
                                  &aw->addr->peer))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Update bandwidth assigned to peers in this network.  The basic idea
 * is to assign every peer in the network the minimum bandwidth, and
 * then distribute the remaining bandwidth proportional to application
 * preferences.
 *
 * @param s the solver handle
 * @param net the network type to update
 */
static void
distribute_bandwidth (struct GAS_PROPORTIONAL_Handle *s,
                      struct Network *net)
{
  const uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  struct AddressWrapper *aw;
  unsigned long long remaining_quota_in;
  unsigned long long quota_out_used;
  unsigned long long remaining_quota_out;
  unsigned long long quota_in_used;
  unsigned int count_addresses;
  double sum_relative_peer_prefences;
  double peer_weight;
  double total_weight;
  const double *peer_relative_prefs;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Recalculate quota for network type `%s' for %u addresses (in/out): %llu/%llu \n",
       net->desc,
       net->active_addresses,
       net->total_quota_in,
       net->total_quota_in);

  if (0 == net->active_addresses)
    return; /* no addresses to update */

  /* sanity checks */
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

  /* Calculate sum of relative preference for active addresses in this
     network */
  sum_relative_peer_prefences = 0.0;
  count_addresses = 0;
  for (aw = net->head; NULL != aw; aw = aw->next)
  {
    if (GNUNET_YES != aw->addr->active)
      continue;
    peer_relative_prefs = s->env->get_preferences (s->env->cls,
                                                   &aw->addr->peer);
    sum_relative_peer_prefences += peer_relative_prefs[GNUNET_ATS_PREFERENCE_BANDWIDTH];
    count_addresses++;
  }
  if (count_addresses != net->active_addresses)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "%s: Counted %u active addresses, expected %u active addresses\n",
         net->desc,
         count_addresses,
         net->active_addresses);
    /* try to fix... */
    net->active_addresses = count_addresses;
  }
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Total relative preference %.3f for %u addresses in network %s\n",
       sum_relative_peer_prefences,
       net->active_addresses,
       net->desc);

  /* check how much we have to distribute */
  remaining_quota_in = net->total_quota_in - (net->active_addresses * min_bw);
  remaining_quota_out = net->total_quota_out - (net->active_addresses * min_bw);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Proportionally distributable bandwidth (in/out): %llu/%llu\n",
       remaining_quota_in,
       remaining_quota_out);

  /* distribute remaining quota; we do not do it exactly proportional,
     but balance "even" distribution ("net->active_addresses") with
     the preference sum using the "prop_factor". */
  total_weight = net->active_addresses +
    s->prop_factor * sum_relative_peer_prefences;
  quota_out_used = 0;
  quota_in_used = 0;
  for (aw = net->head; NULL != aw; aw = aw->next)
  {
    if (GNUNET_YES != aw->addr->active)
    {
      /* set to 0, just to be sure */
      aw->calculated_quota_in = 0;
      aw->calculated_quota_out = 0;
      continue;
    }
    peer_relative_prefs = s->env->get_preferences (s->env->cls,
                                                   &aw->addr->peer);
    peer_weight = 1.0
      + s->prop_factor * peer_relative_prefs[GNUNET_ATS_PREFERENCE_BANDWIDTH];

    aw->calculated_quota_in = min_bw
      + (peer_weight / total_weight) * remaining_quota_in;
    aw->calculated_quota_out = min_bw
      + (peer_weight / total_weight) * remaining_quota_out;

    LOG (GNUNET_ERROR_TYPE_INFO,
         "New quotas for peer `%s' with weight (cur/total) %.3f/%.3f (in/out) are: %u/%u\n",
         GNUNET_i2s (&aw->addr->peer),
         peer_weight,
         total_weight,
         (unsigned int) aw->calculated_quota_in,
         (unsigned int) aw->calculated_quota_out);
    quota_in_used += aw->calculated_quota_in;
    quota_out_used += aw->calculated_quota_out;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Total bandwidth assigned is (in/out): %llu /%llu\n",
       quota_in_used,
       quota_out_used);
  /* +1 due to possible rounding errors */
  GNUNET_break (quota_out_used <= net->total_quota_out + 1);
  GNUNET_break (quota_in_used <= net->total_quota_in + 1);
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

  if (0 != s->bulk_lock)
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Redistributing bandwidth in all %u networks\n",
         s->env->network_count);
    s->env->info_cb (s->env->cls,
                     GAS_OP_SOLVE_START,
                     GAS_STAT_SUCCESS,
                     GAS_INFO_PROP_ALL);
    for (i = 0; i < s->env->network_count; i++)
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
    for (i = 0; i < s->env->network_count; i++)
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
  unsigned int con;
  int bw_available;
  int need;

  /* we need +1 slot if 'current' is not yet active */
  need = (GNUNET_YES == current->active) ? 0 : 1;
  /* we save -1 slot if 'best' is active and belongs
     to the same network (as we would replace it) */
  if ( (NULL != ctx->best) &&
       (GNUNET_YES == ctx->best->active) &&
       (((struct AddressWrapper *) ctx->best->solver_information)->network ==
        asi->network) )
    need--;
  /* we can gain -1 slot if this peers connectivity
     requirement is higher than that of another peer
     in that network scope */
  con = ctx->s->env->get_connectivity (ctx->s->env->cls,
                                       key);
  if (GNUNET_YES !=
      all_require_connectivity (ctx->s,
                                asi->network,
                                con))
    need--;
  /* test if minimum bandwidth for 'current' would be available */
  bw_available
    = is_bandwidth_available_in_network (asi->network,
                                         need);
  if (! bw_available)
  {
    /* Bandwidth for this address is unavailable, so we cannot use
       it. */
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
 * Update active address for a peer.  Check if active address exists
 * and what the best address is, if addresses are different switch.
 * Then reallocate bandwidth within the affected network scopes.
 *
 * @param s solver handle
 * @param current_address the address currently active for the peer,
 *        NULL for none
 * @param peer the peer to check
 */
static void
update_active_address (struct GAS_PROPORTIONAL_Handle *s,
                       struct ATS_Address *current_address,
                       const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address *best_address;
  struct AddressWrapper *asi_cur;
  struct AddressWrapper *asi_best;
  struct AddressWrapper *aw;
  struct AddressWrapper *aw_min;
  unsigned int a_con;
  unsigned int con_min;

  best_address = get_best_address (s,
                                   s->env->addresses,
                                   peer);
  if (NULL != best_address)
    asi_best = best_address->solver_information;
  else
    asi_best = NULL;
  if (current_address == best_address)
    return; /* no changes */
  if (NULL != current_address)
  {
    /* We switch to a new address (or to none);
       mark old address as inactive. */
    asi_cur = current_address->solver_information;
    GNUNET_assert (GNUNET_YES == current_address->active);
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Disabling previous active address for peer `%s'\n",
         GNUNET_i2s (peer));
    asi_cur->activated = GNUNET_TIME_UNIT_ZERO_ABS;
    current_address->active = GNUNET_NO;
    current_address->assigned_bw_in = 0;
    current_address->assigned_bw_out = 0;
    address_decrement_active (s,
                              asi_cur->network);
    if ( (NULL == best_address) ||
         (asi_best->network != asi_cur->network) )
      distribute_bandwidth_in_network (s,
                                       asi_cur->network);
    if (NULL == best_address)
    {
      /* We previously had an active address, but now we cannot
       * suggest one.  Therefore we have to disconnect the peer.
       * The above call to "distribute_bandwidth_in_network()
       * does not see 'current_address' so we need to trigger
       * the update here. */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Disconnecting peer `%s'.\n",
           GNUNET_i2s (peer));
      s->env->bandwidth_changed_cb (s->env->cls,
                                    current_address);
      return;
    }
  }
  if (NULL == best_address)
  {
    /* We do not have a new address, so we are done. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Cannot suggest address for peer `%s'\n",
         GNUNET_i2s (peer));
    return;
  }
  /* We do have a new address, activate it */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Selecting new address %p for peer `%s'\n",
       best_address,
       GNUNET_i2s (peer));
  /* Mark address as active */
  best_address->active = GNUNET_YES;
  asi_best->activated = GNUNET_TIME_absolute_get ();
  asi_best->network->active_addresses++;
  s->active_addresses++;
  GNUNET_STATISTICS_update (s->env->stats,
                            "# ATS active addresses total",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (s->env->stats,
                            asi_best->network->stat_active,
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Address %p for peer `%s' is now active\n",
       best_address,
       GNUNET_i2s (peer));

  if (GNUNET_NO ==
      is_bandwidth_available_in_network (asi_best->network,
                                         0))
  {
    /* we went over the maximum number of addresses for
       this scope; remove the address with the smallest
       connectivity requirement */
    con_min = UINT32_MAX;
    aw_min = NULL;
    for (aw = asi_best->network->head; NULL != aw; aw = aw->next)
    {
      if (con_min >
          (a_con = s->env->get_connectivity (s->env->cls,
                                             &aw->addr->peer)))
      {
        aw_min = aw;
        con_min = a_con;
        if (0 == con_min)
          break;
      }
    }
    update_active_address (s,
                           aw_min->addr,
                           &aw->addr->peer);
  }
  distribute_bandwidth_in_network (s,
                                   asi_best->network);
}


/**
 * The preferences for a peer in the problem changed.
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param pref_rel the normalized preference value for this kind over all clients
 */
static void
GAS_proportional_change_preference (void *solver,
                                    const struct GNUNET_PeerIdentity *peer,
                                    enum GNUNET_ATS_PreferenceKind kind,
                                    double pref_rel)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;

  if (GNUNET_ATS_PREFERENCE_BANDWIDTH != kind)
    return; /* we do not care */
  distribute_bandwidth_in_network (s,
                                   NULL);
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
GAS_proportional_feedback (void *solver,
                           struct GNUNET_SERVER_Client *application,
                           const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_TIME_Relative scope,
                           enum GNUNET_ATS_PreferenceKind kind,
                           double score)
{
  /* Proportional does not care about feedback */
}


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
static void
GAS_proportional_start_get_address (void *solver,
                                    const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;

  update_active_address (s,
                         get_active_address (s,
                                             peer),
                         peer);
}


/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the solver handle
 * @param peer the peer
 */
static void
GAS_proportional_stop_get_address (void *solver,
                                   const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  struct ATS_Address *cur;
  struct AddressWrapper *asi;

  cur = get_active_address (s,
                            peer);
  if (NULL == cur)
    return;
  asi = cur->solver_information;
  distribute_bandwidth_in_network (s,
                                   asi->network);
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
  if ( (0 == s->bulk_lock) &&
       (0 < s->bulk_requests) )
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No lock pending, recalculating\n");
    distribute_bandwidth_in_network (s,
                                     NULL);
    s->bulk_requests = 0;
  }
}


/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type
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
  struct AddressWrapper *asi = address->solver_information;

  distribute_bandwidth_in_network (s,
                                   asi->network);
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
  update_active_address (s,
                         get_active_address (s,
                                             &address->peer),
                         &address->peer);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Added new address for `%s', now total %u and active %u addresses in network `%s'\n",
       GNUNET_i2s (&address->peer),
       net->total_addresses,
       net->active_addresses,
       net->desc);
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
    /* Address was active, remove from network and update quotas */
    update_active_address (s,
                           address,
                           &address->peer);
    distribute_bandwidth_in_network (s, net);
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
  sf.s_get = &GAS_proportional_start_get_address;
  sf.s_get_stop = &GAS_proportional_stop_get_address;
  sf.s_pref = &GAS_proportional_change_preference;
  sf.s_feedback = &GAS_proportional_feedback;
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

  for (c = 0; c < s->env->network_count; c++)
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
