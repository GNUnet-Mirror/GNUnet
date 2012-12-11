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
  unsigned int active_addresses;

  struct Network *network_entries;

  unsigned int networks;
  GAS_bandwidth_changed_cb bw_changed;
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
 * param in_quota array of outbound quota
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_simplistic_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     const struct GNUNET_STATISTICS_Handle *stats,
                     int *network,
                     unsigned long long *out_quota,
                     unsigned long long *in_quota,
                     int dest_length,
                     GAS_bandwidth_changed_cb bw_changed_cb)
{
  int c;
  struct GAS_SIMPLISTIC_Handle *s = GNUNET_malloc (sizeof (struct GAS_SIMPLISTIC_Handle));
  struct Network * cur;
  char * net_str[GNUNET_ATS_NetworkTypeCount] = {"UNSPECIFIED", "LOOPBACK", "LAN", "WAN", "WLAN"};

  s->bw_changed = bw_changed_cb;
  s->networks = dest_length;
  s->network_entries = GNUNET_malloc (dest_length * sizeof (struct Network));

  for (c = 0; c < dest_length; c++)
  {
      cur = &s->network_entries[c];
      cur->total_addresses = 0;
      cur->active_addresses = 0;
      cur->type = network[c];
      cur->total_quota_in = in_quota[c];
      cur->total_quota_out = out_quota[c];
      cur->desc = net_str[c];
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
      next = s->network_entries[c].head;
      while (NULL != (cur = next))
      {
          next = cur->next;
          GNUNET_CONTAINER_DLL_remove (s->network_entries[c].head,
                                       s->network_entries[c].tail,
                                       cur);
          GNUNET_free (cur);

      }
  }
  GNUNET_free (s->network_entries);
  GNUNET_free (s);
}

/**
 * Update the quotas for a network type
 *
 * @param network the network type to update
 * @param address_except address excluded from notifcation, since we suggest
 * this address
 */

static void
update_quota_per_network (struct GAS_SIMPLISTIC_Handle *s,
                          struct Network *net,
                          struct ATS_Address *address_except)
{
  unsigned long long quota_in;
  unsigned long long quota_out;
  struct AddressWrapper *cur;

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
          s->bw_changed (cur->addr);
      }
      cur = cur->next;
  }
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
  struct Network *cur = NULL;
  struct AddressWrapper *aw = NULL;
  GNUNET_assert (NULL != s);
  int c;
  for (c = 0; c < s->networks; c++)
  {
      cur = &s->network_entries[c];
      if (address->atsp_network_type == cur->type)
          break;
  }
  if (NULL == cur)
  {
    GNUNET_break (0);
    return;
  }

  aw = GNUNET_malloc (sizeof (struct AddressWrapper));
  aw->addr = address;
  GNUNET_CONTAINER_DLL_insert (cur->head, cur->tail, aw);
  cur->total_addresses ++;
  aw->addr->solver_information = cur;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Adding new address for network type `%s' (now %u total)\n",
              cur->desc,
              cur->active_addresses);
}



/**
 * Updates a single address in the solve
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the update address
 */
void
GAS_simplistic_address_update (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
#if 0
  struct GAS_SIMPLISTIC_Handle *s = solver;
  GNUNET_assert (NULL != s);
  int c;
  for (c = 0; c < s->networks; c++)
  {
      if (address->atsp_network_type == s->quota_net[c])
      {
          LOG (GNUNET_ERROR_TYPE_DEBUG,
                      "Updating address for network type %u (%u total)\n",
                      address->atsp_network_type,
                      s->active_addresses_per_net[c]);
          break;
      }
  }

  /* Update quota for this network type */
  update_quota_per_network (s, c);
#endif
}


/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to remove
 */
void
GAS_simplistic_address_delete (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
#if 0
  struct GAS_SIMPLISTIC_Handle *s = solver;
  GNUNET_assert (NULL != s);
  int c;
  for (c = 0; c < s->networks; c++)
  {
      if (address->atsp_network_type == s->quota_net[c])
      {
          GNUNET_assert (s->active_addresses_per_net[c] > 0);
          s->active_addresses_per_net[c] --;
          LOG (GNUNET_ERROR_TYPE_DEBUG,
                      "Deleting address for network type %u (now %u total)\n",
                      address->atsp_network_type,
                      s->active_addresses_per_net[c]);
          break;
      }
  }

  /* Update quota for this network type */
  update_quota_per_network (s, c);
#endif
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

static struct ATS_Address *
find_active_address (void *solver,
                     struct GNUNET_CONTAINER_MultiHashMap * addresses,
                     const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address * aa = NULL;

  return aa;
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Suggesting address %p for peer `%s'\n", cur, GNUNET_i2s (peer));
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
      s->bw_changed (prev); /* notify about bw change, REQUIERED? */
      net_cur->active_addresses --;
      update_quota_per_network (s, net_prev, NULL);
  }

  cur->active = GNUNET_YES;
  net_cur->active_addresses ++;
  update_quota_per_network (s, net_cur, cur);

  return cur;
}


/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_simplistic_address_change_preference (void *solver,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score)
{
  /* FIXME : implement this */
}

/* end of gnunet-service-ats_addresses_simplistic.c */
