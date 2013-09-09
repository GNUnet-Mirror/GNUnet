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
 * @file ats/gnunet-service-ats-solver_ril.h
 * @brief ATS reinforcement learning solver
 * @author Fabian Oehlmann
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-ats_addresses.h"

/**
 * ATS reinforcement learning solver
 *
 * General description
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
GAS_ril_address_change_preference (void *solver,
								 	 	 	const struct GNUNET_PeerIdentity *peer,
								 	 	 	enum GNUNET_ATS_PreferenceKind kind,
								 	 	 	double pref_rel);


/**
 * Init the reinforcement learning problem solver
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
 * @param addresses hashmap containing all addresses
 * @param out_quota array of outbound quotas
 * @param in_quota array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @param get_preference callback to get relative preferences for a peer
 * @param get_preference_cls cls for callback to get relative preferences
 * @param get_properties_cls for callback to get relative properties
 * @param get_properties_cls cls for callback to get relative properties
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_ril_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     const struct GNUNET_STATISTICS_Handle *stats,
                     const struct GNUNET_CONTAINER_MultiHashMap *addresses,
                     int *network,
                     unsigned long long *out_quota,
                     unsigned long long *in_quota,
                     int dest_length,
                     GAS_bandwidth_changed_cb bw_changed_cb,
                     void *bw_changed_cb_cls,
                     GAS_get_preferences get_preference,
                     void *get_preference_cls,
                     GAS_get_properties get_properties,
                     void *get_properties_cls);

/**
 * Shutdown the reinforcement learning problem solver
 *
 * @param solver the respective handle to shutdown
 */
void
GAS_ril_done (void * solver);


/**
 * Add a single address within a network to the solver
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_ril_address_add (void *solver,
							struct ATS_Address *address,
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
GAS_ril_address_property_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t type,
    															uint32_t abs_value,
    															double rel_value);


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
GAS_ril_address_session_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t cur_session,
    															uint32_t new_session);


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
GAS_ril_address_inuse_changed (void *solver,
    															struct ATS_Address *address,
    															int in_use);

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
GAS_ril_address_change_network (void *solver,
																	   struct ATS_Address *address,
																	   uint32_t current_network,
																	   uint32_t new_network);

/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_ril_address_delete (void *solver,
    struct ATS_Address *address, int session_only);


/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
void
GAS_ril_bulk_start (void *solver);


/**
 * Bulk operation done
 */
void
GAS_ril_bulk_stop (void *solver);

/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the solver handle
 * @param peer the peer
 */
void
GAS_ril_stop_get_preferred_address (void *solver,
                                     const struct GNUNET_PeerIdentity *peer);


/**
 * Get the prefered address for a specific peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_ril_get_preferred_address (void *solver,
                               const struct GNUNET_PeerIdentity *peer);

/* end of gnunet-service-ats-solver_reinf.h */
