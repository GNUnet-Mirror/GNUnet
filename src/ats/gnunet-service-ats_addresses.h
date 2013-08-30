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
 * @file ats/gnunet-service-ats_addresses.h
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_ADDRESSES_H
#define GNUNET_SERVICE_ATS_ADDRESSES_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats.h"
#include "gnunet_statistics_service.h"
#include "ats.h"

/**
 * NOTE: Do not change this documentation. This documentation is based on
 * gnunet.org:/vcs/fsnsg/ats-paper.git/tech-doku/ats-tech-guide.tex
 * use build_txt.sh to generate plaintext output
 *
 *   1 ATS addresses : ATS address management
 *
 *    This ATS addresses ("addresses") component manages the addresses known to
 *    ATS service and suggests addresses to transport service when it is
 *    interested in address suggestion for a peer. ATS addresses also
 *    instantiates the bandwidth assignment mechanism (solver), notifies it
 *    about changes to addresses and forwards changes to bandwidth assignments
 *    to transport, depending if transport is interested in this change.
 *
 *     1.1 Input data
 *
 *       1.1.1 Addresses
 *
 *    Addresses are added by specifying peer ID, plugin, address, address length
 *    and session, if available. ATS information can be specified if available.
 *
 *       1.1.2 Networks
 *
 *    ATS specifies a fix set of networks an address can belong to. For each
 *    network an inbound and outbound quota will be specified. The available
 *    networks and addtional helper varaibles are defined in
 *    gnunet_ats_service.h. At the moment 5 networks are defined:
 *      * GNUNET_ATS_NET_UNSPECIFIED
 *      * GNUNET_ATS_NET_LOOPBACK
 *      * GNUNET_ATS_NET_LAN
 *      * GNUNET_ATS_NET_WAN
 *      * GNUNET_ATS_NET_WLAN
 *
 *    The total number of networks defined is stored in
 *    GNUNET_ATS_NetworkTypeCount GNUNET_ATS_NetworkType can be used array
 *    initializer for an int array, while GNUNET_ATS_NetworkType is an
 *    initializer for a char array containing a string description of all
 *    networks
 *
 *       1.1.3 Quotas
 *
 *    An inbound and outbound quota for each of the networks mentioned in 1.1.2
 *    is loaded from ats configuration during initialization. This quota defines
 *    to total amount of inbound and outbound traffic allowed for a specific
 *    network. The configuration values used are in section ats:
 *      * "NETWORK"_QUOTA_IN = <value>
 *      * "NETWORK"_QUOTA_IN = <value>
 *
 *    You can specify quotas by setting the <value> to a:
 *      * unrestricted: unlimited
 *      * number of bytes: e.g. 10240
 *      * fancy value: e.g. 64 Kib
 *
 *    unlimited is defined as GNUNET_ATS_MaxBandwidthString and equivalent to
 *    the value GNUNET_ATS_MaxBandwidth Important predefined values for quotas
 *    are:
 *      * GNUNET_ATS_DefaultBandwidth: 65536
 *      * GNUNET_ATS_MaxBandwidth: UINT32_MAX
 *      * GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT: 1024
 *
 *    Details of loading quotas and default values will be described on
 *
 *       1.1.4 Preference values
 *
 *     1.2 Data structures used
 *
 *    Addresse uses struct ATS_Address for each address. The structs are stored
 *    in a linked list and provides a pointer void *solver_information for the
 *    solver to store address specific information. It provides the int values
 *    active which is set to GNUNET_YES if the address is select for transport
 *    use and used, representing that transport service is actively using this
 *    address. Address information are stored in peer, addr, addr_len, plugin.
 *
 *     1.3 Initialization
 *
 *    During initialization a hashmap to store addresses is created. The quotas
 *    for all networks defined for ATS are loaded from configuration. For each
 *    network first the logic will check if the string
 *    GNUNET_ATS_MaxBandwidthString is configured, if not it will try to convert
 *    the configured value as a fancy size and if this fails it will try to use
 *    it as a value_number. If no configuration value is found it will assign
 *    GNUNET_ATS_DefaultBandwidth. The most important step is to load the
 *    configured solver using configuration "[ats]:MODE". Current solvers are
 *    MODE_SIMPLISTIC, MODE_MLP. Interaction is done using a solver API
 *
 *     1.4 Solver API
 *
 *    Solver functions:
 *      * s_init: init the solver with required information
 *      * s_add: add a new address
 *      * s_update: update ATS values or session for an address
 *      * s_get: get prefered address for a peer
 *      * s_del: delete an address
 *      * s_pref: change preference value for a peer
 *      * s_done: shutdown solver
 *
 *    Callbacks: addresses provides a bandwidth_changed_cb callback to the
 *    solver which is called when bandwidth assigned to peer has changed
 *
 *     1.5 Shutdown
 *
 *    During shutdown all addresses are freed and the solver told to shutdown
 *
 *     1.6 Addresses and sessions
 *
 *    Addresses consist of the address itself and a numerical session. When a
 *    new address without a session is added it has no session, so it gets
 *    session 0 assigned. When an address with a session is added and an address
 *    object with session 0 is found, this object is updated with the session
 *    otherwise a new address object with this session assigned is created.
 *
 *       1.6.1 Terminology
 *
 *    Addresses a1,a2 with session s1, s2 are "exact" if:
 *    (a1 == a2)&&(s1 == s2)
 *    Addresses a1,a2 with session s1, s2 are "equivalent" if:
 *    (a1 == a2)&&((s1 == s2)||(s1 == 0)||(s2 == 0)
 *
 *     1.7 Address management
 *
 *    Transport service notifies ATS about changes to the addresses known to
 *    him.
 *
 *       1.7.1 Adding an address
 *
 *    When transport learns a new address it tells ATS and ATS is telling
 *    addresses about it using GAS_address_add. If not known to addresses it
 *    creates a new address object and calls solver's s_add. ATS information are
 *    deserialized and solver is notified about the session and ATS information
 *    using s_update.
 *
 *       1.7.2 Updating an address
 *
 *    Addresses does an lookup up for the existing address with the given
 *    session. If disassembles included ATS information and notifies the solver
 *    using s_update about the update.
 *
 *       1.7.3 Deleting an address
 *
 *    Addresses does an lookup for the exact address and session and if removes
 *    this address. If session != 0 the session is set to 0 and the address is
 *    kept. If session == 0, the addresses is removed.
 *
 *       1.7.4 Requesting an address suggestion
 *
 *    The address client issues a request address message to be notified about
 *    address suggestions for a specific peer. Addresses asks the solver with
 *    s_get. If no address is available, it will not send a response, otherwise
 *    it will respond with the choosen address.
 *
 *       1.7.5 Address suggestions
 *
 *    Addresses will notify the client automatically on any bandwidth_changed_cb
 *    by the solver if a address suggestion request is pending. If no address is
 *    available it will not respond at all If the client is not interested
 *    anymore, it has to cancel the address suggestion request.
 *
 *       1.7.6 Suggestions blocks and reset
 *
 *    After suggesting an address it is blocked for ATS_BLOCKING_DELTA sec. to
 *    prevent the client from being thrashed. If the client requires immediately
 *    it can reset this block using GAS_addresses_handle_backoff_reset.
 *
 *       1.7.7 Marking address in use
 *
 *    The client can notify addresses that it successfully uses an address and
 *    wants this address to be kept by calling GSA_address_in_use. Adresses will
 *    mark the address as used an notify the solver about the use.
 *
 *       1.7.8 Address lifecycle
 *
 *      * (add address)
 *      * (updated address) || (address in use)
 *      * (delete address)
 *
 *     1.8 Bandwidth assignment
 *
 *    The addresses are used to perform resource allocation operations. ATS
 *    addresses takes care of instantiating the solver configured and notifies
 *    the respective solver about address changes and receives changes to the
 *    bandwidth assignment from the solver. The current bandwidth assignment is
 *    sent to transport. The specific solvers will be described in the specific
 *    section.
 *
 *     1.9 Changing peer preferences
 *
 *    The bandwidth assigned to a peer can be influenced by setting a preference
 *    for a peer. The prefernce will be given to to the solver with s_pref which
 *    has to take care of the preference value

 */


/*
 * How long will address suggestions blocked after a suggestion
 */
#define ATS_BLOCKING_DELTA GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100)


/**
 * Information provided by ATS normalization
 */
struct GAS_NormalizationInfo
{
		/**
		 * Next index to use in averaging queue
		 */
		unsigned int avg_queue_index;

		/**
		 * Averaging queue
		 */
	  uint32_t atsi_abs[GAS_normalization_queue_length];

		/**
		 * Averaged ATSI values from queue
		 */
		uint32_t avg;

		/**
		 * Normalized values from queue to a range of values [1.0...2.0]
		 */
		double norm;
};


/**
 * Address with additional information
 */
struct ATS_Address
{
  /**
   * Next element in DLL
   */
  struct ATS_Address *next;

  /**
   * Previous element in DLL
   */
  struct ATS_Address *prev;

  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Session ID, 0 if no session is given
   */
  uint32_t session_id;

  /**
   * Address
   */
  const void *addr;

  /**
   * Address length
   */
  size_t addr_len;

  /**
   * Plugin name
   */
  char *plugin;

  /**
   * Solver specific information for this address
   */
  void *solver_information;

  /**
   * ATS performance information for this address
   */
  struct GNUNET_ATS_Information *atsi;

  /**
   * ATS performance information for this address
   */
  uint32_t atsi_count;

  /**
   * Inbound bandwidth assigned by solver in NBO
   */
  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_in;

  /**
   * Outbound bandwidth assigned by solver in NBO
   */
  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_out;

  /**
   * Blocking interval
   */
  struct GNUNET_TIME_Relative block_interval;

  /**
   * Time when address can be suggested again
   */
  struct GNUNET_TIME_Absolute blocked_until;

  /**
   * Is this the active address for this peer?
   */
  int active;

  /**
   * Is this the address for this peer in use?
   */
  int used;

  /**
   * Normalized ATS performance information for this address
   * Each entry can be accessed using the GNUNET_ATS_QualityProperties avg_queue_index
   */
  struct GAS_NormalizationInfo atsin[GNUNET_ATS_QualityPropertiesCount];
};


/**
 * Callback to call from solver when bandwidth for address has changed
 *
 * @param address the with changed bandwidth assigned
 */
typedef void
 (*GAS_bandwidth_changed_cb) (void *cls, struct ATS_Address *address);


/**
 * Callback to call from solver to obtain application preference values for a
 * peer
 *
 * @param cls the cls
 * @param id the peer id
 * @return carry of double values containing the preferences with
 * 	GNUNET_ATS_PreferenceCount elements
 */
typedef const double *
 (*GAS_get_preferences) (void *cls, const struct GNUNET_PeerIdentity *id);


/**
 * Callback to call from solver to obtain transport properties for an
 * address
 *
 * @param cls the cls
 * @param address the address
 * @return carry of double values containing the preferences with
 * 	GNUNET_ATS_PreferenceCount elements
 */
typedef const double *
 (*GAS_get_properties) (void *cls, const struct ATS_Address *address);



/*
 * Solver API
 * ----------
 */

/**
 * Init the problem solving component
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
 * @param bw_changed_cb callback to call when assigned changes
 * @return handle for the solver on success, NULL on fail
 */
typedef void *
 (*GAS_solver_init) (const struct GNUNET_CONFIGURATION_Handle *cfg,
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
 * Change the preference for a peer
 *
 * @param handle the solver handle
 * @param client the client sending this request
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score the new preference score
 * @param pref_rel the normalized preference value for this kind over all clients
 */
typedef void
(*GAS_solver_address_change_preference) (void *solver,
																				 const struct GNUNET_PeerIdentity *peer,
																				 enum GNUNET_ATS_PreferenceKind kind,
																				 double pref_rel);


/**
 * Give feedback about the current assignment
 *
 * @param handle the solver handle
 * @param application the application sending this request
 * @param peer the peer id
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the preference kind for this feedback
 * @param score the feedback score
 */
typedef void
(*GAS_solver_address_feedback_preference) (void *solver,
																				 void *application,
																				 const struct GNUNET_PeerIdentity *peer,
																				 const struct GNUNET_TIME_Relative scope,
																				 enum GNUNET_ATS_PreferenceKind kind,
																				 double score);

/**
 * Notify the solver about a bulk operation changing possibly a lot of values
 * Solver will not resolve until all bulk operations are marked as done
 *
 * @param solver the solver
 */
typedef void
(*GAS_solver_bulk_start) (void *solver);


/**
 * Mark a bulk operation as done
 * Solver will resolve if values have changed
 *
 * @param solver the solver
 */
typedef void
(*GAS_solver_bulk_stop) (void *solver);


/**
 * Add a single address within a network to the solver
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to add
 * @param network network type of this address
 */
typedef void
(*GAS_solver_address_add) (void *solver,
													 struct ATS_Address *address,
													 uint32_t network);


/**
 * Delete an address or just the session from the solver
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to delete
 * @param session_only remove address or just session
 */
typedef void
 (*GAS_solver_address_delete) (void *solver,
                               struct ATS_Address *address,
                               int session_only);


/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
typedef void
(*GAS_solver_address_property_changed) (void *solver,
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
typedef void
(*GAS_solver_address_session_changed) (void *solver,
 																			struct ATS_Address *address,
																			uint32_t cur_session,
																			uint32_t new_session);

/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
typedef void
(*GAS_solver_address_inuse_changed) (void *solver,
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
typedef void
(*GAS_solver_address_network_changed) (void *solver,
																	   struct ATS_Address *address,
																	   uint32_t current_network,
																	   uint32_t new_network);


/**
 * Get the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param addresses the address hashmap containing all addresses
 * @param peer the peer
 */
typedef const struct ATS_Address *
(*GAS_solver_get_preferred_address) (void *solver,
                                     const struct GNUNET_PeerIdentity *peer);


/**
 * Stop getting the prefered address for a peer from solver
 *
 * @param solver the solver to use
 * @param addresses the address hashmap containing all addresses
 * @param peer the peer
 */
typedef void
(*GAS_solver_stop_get_preferred_address) (void *solver,
                                     const struct GNUNET_PeerIdentity *peer);

/**
 * Shutdown solver
 *
 * @param solver the solver to shutdown
 */

typedef void
 (*GAS_solver_done) (void *solver);


/**
 * Initialize address subsystem. The addresses subsystem manages the addresses
 * known and current performance information. It has a solver component
 * responsible for the resource allocation. It tells the solver about changes
 * and receives updates when the solver changes the ressource allocation.
 *
 * @param cfg configuration to use
 * @param stats the statistics handle to use
 * @return an address handle
 */
struct GAS_Addresses_Handle *
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_STATISTICS_Handle *stats);


/**
 * Shutdown address subsystem.
 *
 * @param handle the address handle to shutdown
 */
void
GAS_addresses_done (struct GAS_Addresses_Handle *handle);


/**
 * Add a new address for a peer.
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param session_id session id, can be 0
 * @param atsi performance information for this address
 * @param atsi_count number of performance information contained
 */
void
GAS_addresses_add (struct GAS_Addresses_Handle *handle,
                   const struct GNUNET_PeerIdentity *peer,
                   const char *plugin_name,
                   const void *plugin_addr,
                   size_t plugin_addr_len,
                   uint32_t session_id,
                   const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count);


/**
 * Notification about active use of an address.
 * in_use == GNUNET_YES:
 * 	This address is used to maintain an active connection with a peer.
 * in_use == GNUNET_NO:
 * 	This address is no longer used to maintain an active connection with a peer.
 *
 * Note: can only be called with in_use == GNUNET_NO if called with GNUNET_YES
 * before
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param session_id session id, can be 0
 * @param in_use GNUNET_YES if GNUNET_NO
 * @return GNUNET_SYSERR on failure (address unknown ...)
 */
int
GAS_addresses_in_use (struct GAS_Addresses_Handle *handle,
                      const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name,
                      const void *plugin_addr,
                      size_t plugin_addr_len,
                      uint32_t session_id,
                      int in_use);


/**
 * Update an address with a session or performance information for a peer.
 *
 * If an address was added without a session it will be updated with the
 * session
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param session_id session id, can be 0
 * @param atsi performance information for this address
 * @param atsi_count number of performance information contained
 */
void
GAS_addresses_update (struct GAS_Addresses_Handle *handle,
                      const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name,
                      const void *plugin_addr,
                      size_t plugin_addr_len,
                      uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count);


/**
 * Remove an address or just a session for a peer.
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param session_id session id, can be 0
 */
void
GAS_addresses_destroy (struct GAS_Addresses_Handle *handle,
                       const struct GNUNET_PeerIdentity *peer,
                       const char *plugin_name,
                       const void *plugin_addr,
                       size_t plugin_addr_len,
                       uint32_t session_id);


/**
 * Remove all addresses
 *
 * @param handle the address handle to use
 */
void
GAS_addresses_destroy_all (struct GAS_Addresses_Handle *handle);


/**
 * Request address suggestions for a peer
 *
 * @param handle the address handle
 * @param peer the peer id
 */
void
GAS_addresses_request_address (struct GAS_Addresses_Handle *handle,
                               const struct GNUNET_PeerIdentity *peer);

/**
 * Cancel address suggestions for a peer
 *
 * @param handle the address handle
 * @param peer the peer id
 */
void
GAS_addresses_request_address_cancel (struct GAS_Addresses_Handle *handle,
                                      const struct GNUNET_PeerIdentity *peer);


/**
 * Reset suggestion backoff for a peer
 *
 * Suggesting addresses is blocked for ATS_BLOCKING_DELTA. Blocking can be
 * reset using this function
 *
 * @param handle the address handle
 * @param peer the peer id
 */
void
GAS_addresses_handle_backoff_reset (struct GAS_Addresses_Handle *handle,
                                    const struct GNUNET_PeerIdentity *peer);


/**
 * Change the preference for a peer
 *
 * @param handle the address handle
 * @param client the client sending this request
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
void
GAS_addresses_change_preference (struct GAS_Addresses_Handle *handle,
                                 void *client,
                                 const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score_abs);


/**
 * Change the preference for a peer
 *
 * @param handle the address handle
 * @param application the client sending this request
 * @param peer the peer id
 * @param scope the time interval this valid for: [now - scope .. now]
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
void
GAS_addresses_preference_feedback (struct GAS_Addresses_Handle *handle,
																		void *application,
																		const struct GNUNET_PeerIdentity *peer,
																		const struct GNUNET_TIME_Relative scope,
																		enum GNUNET_ATS_PreferenceKind kind,
																		float score_abs);


/**
 * Iterator for GAS_addresses_iterate_peers
 *
 * @param p_it_cls closure
 * @param id the peer id
 */
typedef void (*GNUNET_ATS_Peer_Iterator) (void *p_it_cls,
                                          const struct GNUNET_PeerIdentity *id);


/**
 * Return all peers currently known to ATS
 *
 * @param handle the address handle to use
 * @param p_it the iterator to call for every peer
 * @param p_it_cls the closure for the iterator
 */
void
GAS_addresses_iterate_peers (struct GAS_Addresses_Handle *handle,
                             GNUNET_ATS_Peer_Iterator p_it,
                             void *p_it_cls);


/**
 * Iterator for GAS_addresses_get_peer_info
 *
 * @param p_it_cls closure closure
 * @param id the peer id
 * @param plugin_name plugin name
 * @param plugin_addr address
 * @param plugin_addr_len address length
 * @param address_active is address actively used
 * @param atsi ats performance information
 * @param atsi_count number of ats performance elements
 * @param bandwidth_out current outbound bandwidth assigned to address
 * @param bandwidth_in current inbound bandwidth assigned to address
 */
typedef void (*GNUNET_ATS_PeerInfo_Iterator) (void *p_it_cls,
    const struct GNUNET_PeerIdentity *id,
    const char *plugin_name,
    const void *plugin_addr,
    size_t plugin_addr_len,
    const int address_active,
    const struct GNUNET_ATS_Information *atsi,
    uint32_t atsi_count,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in);


/**
 * Return information all peers currently known to ATS
 *
 * @param handle the address handle to use
 * @param peer the respective peer
 * @param pi_it the iterator to call for every peer
 * @param pi_it_cls the closure for the iterator
 */
void
GAS_addresses_get_peer_info (struct GAS_Addresses_Handle *handle,
                             const struct GNUNET_PeerIdentity *peer,
                             GNUNET_ATS_PeerInfo_Iterator pi_it,
                             void *pi_it_cls);

#endif

/* end of gnunet-service-ats_addresses.h */
