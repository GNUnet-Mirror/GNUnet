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
 * A handle for the simplistic solver
 */
struct GAS_SIMPLISTIC_Handle
{
  unsigned int active_addresses;

  struct Network *network_entries;

  unsigned int networks;
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
                     int dest_length)
{
  int c;
  struct GAS_SIMPLISTIC_Handle *s = GNUNET_malloc (sizeof (struct GAS_SIMPLISTIC_Handle));
  struct Network * cur;
  char * net_str[GNUNET_ATS_NetworkTypeCount] = {"UNSPECIFIED", "LOOPBACK", "LAN", "WAN", "WLAN"};

  s->networks = dest_length;
  s->network_entries = GNUNET_malloc (dest_length * sizeof (struct Network));

  for (c = 0; c < dest_length; c++)
  {
      cur = &s->network_entries[c];
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
  GNUNET_assert (s != NULL);
  GNUNET_free (s->network_entries);
  GNUNET_free (s);
}

static void
update_quota (struct GAS_SIMPLISTIC_Handle *s, struct Network *net)
{
  unsigned long long quota_in;
  unsigned long long quota_out;

  quota_in = net->total_quota_in / net->active_addresses;
  quota_out = net->total_quota_out / net->active_addresses;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "New quota for network type `%s' (in/out): %llu/%llu \n",
              net->desc, quota_in, quota_out);
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
  GNUNET_assert (NULL != s);
  int c;
  for (c = 0; c < s->networks; c++)
  {
      cur = &s->network_entries[c];
      if (address->atsp_network_type == cur->type)
      {
          cur->active_addresses ++;
          LOG (GNUNET_ERROR_TYPE_DEBUG,
                      "Adding new address for network type `%s' (now %u total)\n",
                      cur->desc,
                      cur->active_addresses);
          break;
      }
  }
  if (NULL == cur)
  {
    GNUNET_break (0);
    return;
  }

  /* Update quota for this network type */
  update_quota (s, cur);


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
  update_quota (s, c);
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
  update_quota (s, c);
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

static int
update_bw_simple_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct GAS_SIMPLISTIC_Handle *s = cls;
  struct ATS_Address *aa = value;

  if (GNUNET_YES != aa->active)
    return GNUNET_OK;
  GNUNET_assert (s->active_addresses > 0);


  /* Simple method */

  aa->assigned_bw_in.value__ = htonl (UINT32_MAX / s->active_addresses);
  aa->assigned_bw_out.value__ = htonl (UINT32_MAX / s->active_addresses);

  return GNUNET_OK;
}

/**
 * Some (significant) input changed, recalculate bandwidth assignment
 * for all peers.
 */
static void
recalculate_assigned_bw (void *solver,
                         struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Recalculating bandwidth for all active connections\n");
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &update_bw_simple_it, solver);
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
  struct ATS_Address *aa;

  GNUNET_assert (s != NULL);
  aa = NULL;
  /* Get address with: stick to current address, lower distance, lower latency */
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
                                              &find_address_it, &aa);
  if (NULL == aa)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Suggesting address %p for peer `%s'\n", aa, GNUNET_i2s (peer));

    if (GNUNET_NO == aa->active)
    {
      aa->active = GNUNET_YES;
      s->active_addresses++;
      recalculate_assigned_bw (s, addresses);
    }
  }

  return aa;
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
