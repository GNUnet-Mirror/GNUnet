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
 * @file ats/gnunet-service-ats_addresses_simplistic.h
 * @brief ats simplistic ressource assignment
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-simplistic",__VA_ARGS__)

/**
 * ATS simplistic solver
 *
 * Assigns in and outbound bandwidth equally for all addresses in specific
 * network type (WAN, LAN) based on configured in and outbound quota for this
 * network.
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
 * A handle for the simplistic solver
 */
struct GAS_SIMPLISTIC_Handle
{
  /**
   * Statistics handle
   */

  struct GNUNET_STATISTICS_Handle *stats;

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

  /**
   * Callback
   */
  GAS_bandwidth_changed_cb bw_changed;

  /**
   * Callback cls
   */
  void *bw_changed_cls;
};

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

struct AddressWrapper
{
  struct AddressWrapper *next;
  struct AddressWrapper *prev;

  struct ATS_Address *addr;
};

/**
 * Init the simplistic problem solving component
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
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param out_quota array of outbound quotas
 * @param in_quota array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_simplistic_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     const struct GNUNET_STATISTICS_Handle *stats,
                     int *network,
                     unsigned long long *out_quota,
                     unsigned long long *in_quota,
                     int dest_length,
                     GAS_bandwidth_changed_cb bw_changed_cb,
                     void *bw_changed_cb_cls)
{
  int c;
  struct GAS_SIMPLISTIC_Handle *s = GNUNET_malloc (sizeof (struct GAS_SIMPLISTIC_Handle));
  struct Network * cur;
  char * net_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;


  s->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  s->bw_changed = bw_changed_cb;
  s->bw_changed_cls = bw_changed_cb_cls;
  s->networks = dest_length;
  s->network_entries = GNUNET_malloc (dest_length * sizeof (struct Network));
  s->active_addresses = 0;
  s->total_addresses = 0;

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
      GNUNET_asprintf (&cur->stat_active, "# ATS active addresses %s total", cur->desc);
  }
  return s;
}


/**
 * Shutdown the simplistic problem solving component
 *
 * @param solver the respective handle to shutdown
 */
void
GAS_simplistic_done (void *solver)
{
  struct GAS_SIMPLISTIC_Handle *s = solver;
  struct AddressWrapper *cur;
  struct AddressWrapper *next;
  int c;
  GNUNET_assert (s != NULL);

  for (c = 0; c < s->networks; c++)
  {
      if (s->network_entries[c].total_addresses > 0)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
                    "Had %u addresses for network `%s' not deleted during shutdown\n",
                    s->network_entries[c].total_addresses,
                    s->network_entries[c].desc);
        GNUNET_break (0);
      }

      if (s->network_entries[c].active_addresses > 0)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
                    "Had %u active addresses for network `%s' not deleted during shutdown\n",
                    s->network_entries[c].active_addresses,
                    s->network_entries[c].desc);
        GNUNET_break (0);
      }

      next = s->network_entries[c].head;
      while (NULL != (cur = next))
      {
          next = cur->next;
          GNUNET_CONTAINER_DLL_remove (s->network_entries[c].head,
                                       s->network_entries[c].tail,
                                       cur);
          GNUNET_free (cur);
      }
      GNUNET_free (s->network_entries[c].stat_total);
      GNUNET_free (s->network_entries[c].stat_active);
  }
  if (s->total_addresses > 0)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
                "Had %u addresses not deleted during shutdown\n",
                s->total_addresses);
    GNUNET_break (0);
  }
  if (s->active_addresses > 0)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
                "Had %u active addresses not deleted during shutdown\n",
                s->active_addresses);
    GNUNET_break (0);
  }

  GNUNET_free (s->network_entries);
  GNUNET_free (s);
}

/**
 * Update the quotas for a network type
 *
 * @param s the solver handle
 * @param net the network type to update
 * @param address_except address excluded from notifcation, since we suggest
 * this address
 */

static void
update_quota_per_network (struct GAS_SIMPLISTIC_Handle *s,
                          struct Network *net,
                          struct ATS_Address *address_except)
{
  unsigned long long quota_in = 0;
  unsigned long long quota_out = 0;
  struct AddressWrapper *cur;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Recalculate quota for network type `%s' for %u addresses (in/out): %llu/%llu \n",
              net->desc, net->active_addresses, quota_in, quota_out);

  if (net->active_addresses == 0)
    return; /* no addresses to update */

  quota_in = net->total_quota_in / net->active_addresses;
  quota_out = net->total_quota_out / net->active_addresses;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "New per address quota for network type `%s' for %u addresses (in/out): %llu/%llu \n",
              net->desc, net->active_addresses, quota_in, quota_out);

  cur = net->head;
  while (NULL != cur)
  {
      /* Compare to current bandwidth assigned */
      if ((quota_in != ntohl(cur->addr->assigned_bw_in.value__)) ||
          (quota_out != ntohl(cur->addr->assigned_bw_out.value__)))
      {
        cur->addr->assigned_bw_in.value__ = htonl (quota_in);
        cur->addr->assigned_bw_out.value__ = htonl (quota_out);
        /* Notify on change */
        if ((GNUNET_YES == cur->addr->active) && (cur->addr != address_except))
          s->bw_changed (s->bw_changed_cls, cur->addr);
      }
      cur = cur->next;
  }
}

static void
addresse_increment (struct GAS_SIMPLISTIC_Handle *s,
                                struct Network *net,
                                int total,
                                int active)
{
  if (GNUNET_YES == total)
  {
      s->total_addresses ++;
      net->total_addresses ++;
      GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", 1, GNUNET_NO);
      GNUNET_STATISTICS_update (s->stats, net->stat_total, 1, GNUNET_NO);
  }
  if (GNUNET_YES == active)
  {
    net->active_addresses ++;
    s->active_addresses ++;
    GNUNET_STATISTICS_update (s->stats, "# ATS active addresses total", 1, GNUNET_NO);
    GNUNET_STATISTICS_update (s->stats, net->stat_active, 1, GNUNET_NO);
  }

}

static int
addresse_decrement (struct GAS_SIMPLISTIC_Handle *s,
                    struct Network *net,
                    int total,
                    int active)
{
  int res = GNUNET_OK;
  if (GNUNET_YES == total)
  {
    if (s->total_addresses < 1)
    {
      GNUNET_break (0);
      res = GNUNET_SYSERR;
    }
    else
    {
      s->total_addresses --;
      GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", -1, GNUNET_NO);
    }
    if (net->total_addresses < 1)
    {
      GNUNET_break (0);
      res = GNUNET_SYSERR;
    }
    else
    {
      net->total_addresses --;
      GNUNET_STATISTICS_update (s->stats, net->stat_total, -1, GNUNET_NO);
    }
  }

  if (GNUNET_YES == active)
  {
    if (net->active_addresses < 1)
    {
      GNUNET_break (0);
      res = GNUNET_SYSERR;
    }
    else
    {
      net->active_addresses --;
      GNUNET_STATISTICS_update (s->stats, net->stat_active, -1, GNUNET_NO);
    }
    if (s->active_addresses < 1)
    {
      GNUNET_break (0);
      res = GNUNET_SYSERR;
    }
    else
    {
      s->active_addresses --;
      GNUNET_STATISTICS_update (s->stats, "# ATS addresses total", -1, GNUNET_NO);
    }
  }
  return res;
}


/**
 * Add a single address to the solve
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to add
 */
void
GAS_simplistic_address_add (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  struct GAS_SIMPLISTIC_Handle *s = solver;
  struct Network *net = NULL;
  struct AddressWrapper *aw = NULL;
  GNUNET_assert (NULL != s);
  int c;
  for (c = 0; c < s->networks; c++)
  {
      net = &s->network_entries[c];
      if (address->atsp_network_type == net->type)
          break;
  }
  if (NULL == net)
  {
    GNUNET_break (0);
    return;
  }

  aw = GNUNET_malloc (sizeof (struct AddressWrapper));
  aw->addr = address;
  GNUNET_CONTAINER_DLL_insert (net->head, net->tail, aw);
  addresse_increment (s, net, GNUNET_YES, GNUNET_NO);
  aw->addr->solver_information = net;


  LOG (GNUNET_ERROR_TYPE_DEBUG, "After adding address now total %u and active %u addresses in network `%s'\n",
      net->total_addresses,
      net->active_addresses,
      net->desc);
}

/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_simplistic_address_delete (void *solver,
    struct GNUNET_CONTAINER_MultiHashMap * addresses,
    struct ATS_Address *address, int session_only)
{
  struct GAS_SIMPLISTIC_Handle *s = solver;
  struct Network *net;
  struct AddressWrapper *aw;

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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Deleting %s address %p for peer `%s' from network `%s' (total: %u/ active: %u)\n",
        (GNUNET_NO == address->active) ? "inactive" : "active",
        address, GNUNET_i2s (&address->peer),
        net->desc, net->total_addresses, net->active_addresses);

    /* Remove address */
    addresse_decrement (s, net, GNUNET_YES, GNUNET_NO);
    for (aw = net->head; NULL != aw; aw = aw->next)
    {
        if (aw->addr == address)
          break;
    }
    if (NULL == aw )
    {
        GNUNET_break (0);
        return;
    }
    GNUNET_CONTAINER_DLL_remove (net->head, net->tail, aw);
    GNUNET_free (aw);
  }
  else
  {
      /* Remove session only: remove if active and update */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Deleting %s session %p for peer `%s' from network `%s' (total: %u/ active: %u)\n",
          (GNUNET_NO == address->active) ? "inactive" : "active",
          address, GNUNET_i2s (&address->peer),
          net->desc, net->total_addresses, net->active_addresses);
  }


  if (GNUNET_YES == address->active)
  {
      /* Address was active, remove from network and update quotas*/
      address->active = GNUNET_NO;
      if (GNUNET_SYSERR == addresse_decrement (s, net, GNUNET_NO, GNUNET_YES))
        GNUNET_break (0);
      update_quota_per_network (s, net, NULL);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "After deleting address now total %u and active %u addresses in network `%s'\n",
      net->total_addresses,
      net->active_addresses,
      net->desc);

}

static struct Network *
find_network (struct GAS_SIMPLISTIC_Handle *s, uint32_t type)
{
  int c;
  for (c = 0 ; c < s->networks; c++)
  {
      if (s->network_entries[c].type == type)
        return &s->network_entries[c];
  }
  return NULL;
}

/**
 * Updates a single address in the solve
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the update address
 * @param session the new session (if changed otherwise current)
 * @param in_use the new address in use state (if changed otherwise current)
 * @param atsi the latest ATS information
 * @param atsi_count the atsi count
 */
void
GAS_simplistic_address_update (void *solver,
                              struct GNUNET_CONTAINER_MultiHashMap *addresses,
                              struct ATS_Address *address,
                              uint32_t session,
                              int in_use,
                              const struct GNUNET_ATS_Information *atsi,
                              uint32_t atsi_count)
{
  struct GAS_SIMPLISTIC_Handle *s = (struct GAS_SIMPLISTIC_Handle *) solver;
  int i;
  uint32_t value;
  uint32_t type;
  int save_active = GNUNET_NO;
  struct Network *new_net = NULL;
  for (i = 0; i < atsi_count; i++)
  {
    type = ntohl (atsi[i].type);
    value = ntohl (atsi[i].value);
    switch (type)
    {
    case GNUNET_ATS_UTILIZATION_UP:
      //if (address->atsp_utilization_out.value__ != atsi[i].value)

      break;
    case GNUNET_ATS_UTILIZATION_DOWN:
      //if (address->atsp_utilization_in.value__ != atsi[i].value)

      break;
    case GNUNET_ATS_QUALITY_NET_DELAY:
      //if (address->atsp_latency.rel_value != value)

      break;
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      //if (address->atsp_distance != value)

      break;
    case GNUNET_ATS_COST_WAN:
      //if (address->atsp_cost_wan != value)

      break;
    case GNUNET_ATS_COST_LAN:
      //if (address->atsp_cost_lan != value)

      break;
    case GNUNET_ATS_COST_WLAN:
      //if (address->atsp_cost_wlan != value)

      break;
    case GNUNET_ATS_NETWORK_TYPE:
      if (address->atsp_network_type != value)
      {

        LOG (GNUNET_ERROR_TYPE_DEBUG, "Network type changed, moving %s address from `%s' to `%s'\n",
            (GNUNET_YES == address->active) ? "active" : "inactive",
            GNUNET_ATS_print_network_type(address->atsp_network_type),
            GNUNET_ATS_print_network_type(value));

        save_active = address->active;
        /* remove from old network */
        GAS_simplistic_address_delete (solver, addresses, address, GNUNET_NO);

        /* set new network type */
        address->atsp_network_type = value;
        new_net = find_network (solver, value);
        address->solver_information = new_net;
        if (address->solver_information == NULL)
        {
            GNUNET_break (0);
            address->atsp_network_type = GNUNET_ATS_NET_UNSPECIFIED;
            return;
        }

        /* restore active state, add to new network and update*/
        address->active = save_active;
        GAS_simplistic_address_add (solver, addresses, address);
        if (GNUNET_YES == save_active)
        {
          addresse_increment (s, new_net, GNUNET_NO, GNUNET_YES);
          update_quota_per_network (solver, new_net, NULL);
        }
      }
      break;
    case GNUNET_ATS_ARRAY_TERMINATOR:
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Received unsupported ATS type %u\n", type);
      GNUNET_break (0);
      break;

    }

  }
  if (address->session_id != session)
  {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
                  "Session changed from %u to %u\n", address->session_id, session);
      address->session_id = session;
  }
  if (address->used != in_use)
  {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
                  "Usage changed from %u to %u\n", address->used, in_use);
      address->used = in_use;
  }

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
  struct ATS_Address **previous_p = cls;
  struct ATS_Address *current = (struct ATS_Address *) value;
  struct ATS_Address *previous = *previous_p;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get();

  if (current->blocked_until.abs_value == GNUNET_TIME_absolute_max (now, current->blocked_until).abs_value)
  {
    /* This address is blocked for suggestion */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "Address %p blocked for suggestion for %llu ms \n",
                current,
                GNUNET_TIME_absolute_get_difference(now, current->blocked_until).rel_value);
    return GNUNET_OK;
  }

  if (NULL != previous)
  {
    if ((0 == strcmp (previous->plugin, "tcp")) &&
        (0 == strcmp (current->plugin, "tcp")))
    {
      if ((0 != previous->addr_len) &&
          (0 == current->addr_len))
      {
        /* saved address was an outbound address, but we have an inbound address */
        *previous_p = current;
        return GNUNET_OK;
      }
      if (0 == previous->addr_len)
      {
        /* saved address was an inbound address, so do not overwrite */
        return GNUNET_OK;
      }
    }
  }

  if (NULL == previous)
  {
    *previous_p = current;
    return GNUNET_OK;
  }
  if ((ntohl (previous->assigned_bw_in.value__) == 0) &&
      (ntohl (current->assigned_bw_in.value__) > 0))
  {
    /* stick to existing connection */
    *previous_p = current;
    return GNUNET_OK;
  }
  if (previous->atsp_distance > current->atsp_distance)
  {
    /* user shorter distance */
    *previous_p = current;
    return GNUNET_OK;
  }
  if (previous->atsp_latency.rel_value > current->atsp_latency.rel_value)
  {
    /* user lower latency */
    *previous_p = current;
    return GNUNET_OK;
  }
  /* don't care */
  return GNUNET_OK;
}

static int
find_active_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ATS_Address * dest = (struct ATS_Address *) (*(struct ATS_Address **)cls);
  struct ATS_Address * aa = (struct ATS_Address *) value;

  if (GNUNET_YES == aa->active)
  {
      if (dest != NULL)
      {
          /* should never happen */
          LOG (GNUNET_ERROR_TYPE_ERROR, "Multiple active addresses for peer `%s'\n", GNUNET_i2s (&aa->peer));
          GNUNET_break (0);
          return GNUNET_NO;
      }
      dest = aa;
  }
  return GNUNET_OK;
}

static struct ATS_Address *
find_active_address (void *solver,
                     struct GNUNET_CONTAINER_MultiHashMap * addresses,
                     const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address * dest = NULL;

  GNUNET_CONTAINER_multihashmap_get_multiple(addresses,
       &peer->hashPubKey,
       &find_active_address_it, &dest);
  return dest;
}

/**
 * Get the prefered address for a specific peer
 *
 * @param solver the solver handle
 * @param addresses the address hashmap containing all addresses
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_simplistic_get_preferred_address (void *solver,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_SIMPLISTIC_Handle *s = solver;
  struct Network *net_prev;
  struct Network *net_cur;
  struct ATS_Address *cur;
  struct ATS_Address *prev;

  GNUNET_assert (s != NULL);
  cur = NULL;
  /* Get address with: stick to current address, lower distance, lower latency */
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &find_address_it, &cur);
  if (NULL == cur)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return NULL;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Suggesting %s address %p for peer `%s'\n",
      (GNUNET_NO == cur->active) ? "inactive" : "active",
      cur, GNUNET_i2s (peer));
  net_cur = (struct Network *) cur->solver_information;
  if (GNUNET_YES == cur->active)
  {
      /* This address was selected previously, so no need to update quotas */
      return cur;
  }

  /* This address was not active, so we have to:
   *
   * - mark previous active address as not active
   * - update quota for previous address network
   * - update quota for this address network
   */

  prev = find_active_address (s, addresses, peer);
  if (NULL != prev)
  {
      net_prev = (struct Network *) prev->solver_information;
      prev->active = GNUNET_NO; /* No active any longer */
      prev->assigned_bw_in = GNUNET_BANDWIDTH_value_init (0); /* no bw assigned */
      prev->assigned_bw_out = GNUNET_BANDWIDTH_value_init (0); /* no bw assigned */
      s->bw_changed (s->bw_changed_cls, prev); /* notify about bw change, REQUIRED? */
      if (GNUNET_SYSERR == addresse_decrement (s, net_prev, GNUNET_NO, GNUNET_YES))
        GNUNET_break (0);
      update_quota_per_network (s, net_prev, NULL);
  }

  cur->active = GNUNET_YES;
  addresse_increment(s, net_cur, GNUNET_NO, GNUNET_YES);
  update_quota_per_network (s, net_cur, cur);

  return cur;
}


/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param client the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_simplistic_address_change_preference (void *solver,
                                   void *client,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score)
{

}

/* end of gnunet-service-ats_addresses_simplistic.c */
