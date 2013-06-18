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
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"
#if HAVE_LIBGLPK
#include "gnunet-service-ats_addresses_mlp.h"
#endif
#include "gnunet-service-ats-solver_proportional.h"

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


/**
 * Pending Address suggestion requests
 */
struct GAS_Addresses_Suggestion_Requests
{
  /**
   * Next in DLL
   */
  struct GAS_Addresses_Suggestion_Requests *next;

  /**
   * Previous in DLL
   */
  struct GAS_Addresses_Suggestion_Requests *prev;

  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity id;
};


/**
 * Handle for ATS address component
 */
struct GAS_Addresses_Handle
{
  /**
   *
   */
  struct GNUNET_STATISTICS_Handle *stat;

  /**
   * A multihashmap to store all addresses
   */
  struct GNUNET_CONTAINER_MultiHashMap *addresses;

  /**
   * Configure WAN quota in
   */
  unsigned long long wan_quota_in;

  /**
   * Configure WAN quota out
   */
  unsigned long long wan_quota_out;

  /**
   * Is ATS addresses running
   */
  int running;

  /**
   * Configured ATS solver
   */
  int ats_mode;

  /**
   *  Solver handle
   */
  void *solver;

  /**
   * Address suggestion requests DLL head
   */
  struct GAS_Addresses_Suggestion_Requests *r_head;

  /**
   * Address suggestion requests DLL tail
   */
  struct GAS_Addresses_Suggestion_Requests *r_tail;

  /* Solver functions */

  /**
   * Initialize solver
   */
  GAS_solver_init s_init;

  /**
   * Add an address to the solver
   */
  GAS_solver_address_add s_add;

  /**
   * Update address in solver
   */
  GAS_solver_address_update s_update;

  /**
   * Get address from solver
   */
  GAS_solver_get_preferred_address s_get;

  /**
   * Get address from solver
   */
  GAS_solver_stop_get_preferred_address s_get_stop;

  /**
   * Delete address in solver
   */
  GAS_solver_address_delete s_del;

  /**
   * Change relative preference for quality in solver
   */
  GAS_solver_address_change_preference s_pref;

  /**
   * Shutdown solver
   */
  GAS_solver_done s_done;
};


/**
 * Disassemble ATS information and update performance information in address
 *
 * Updates existing information and adds new information
 *
 * @param dest destination address
 * @param update source ATS information
 * @param update_count number of ATS information
 * @param delta_dest ats performance information which were updated
 * 				including previous value
 * @param delta_count number of ATS information in the delta
 * @return GNUNET_YES if address was address updated, GNUNET_NO otherwise
 */
static unsigned int
disassemble_ats_information (struct ATS_Address *dest,
														 const struct GNUNET_ATS_Information *update,
                             uint32_t update_count,
                             struct GNUNET_ATS_Information **delta_dest,
                             uint32_t *delta_count)
{

  int c1;
  int c2;
  int found;
  int change;

  struct GNUNET_ATS_Information add_atsi[update_count];
  struct GNUNET_ATS_Information delta_atsi[update_count];
  struct GNUNET_ATS_Information *tmp_atsi;
  uint32_t add_atsi_count;
  uint32_t delta_atsi_count;

  change = GNUNET_NO;
  add_atsi_count = 0;
  delta_atsi_count = 0;

  if (0 == update_count)
  	return GNUNET_NO;

  if (NULL == dest->atsi)
  {
  		/* Create performance information */
  		dest->atsi = GNUNET_malloc (update_count * sizeof (struct GNUNET_ATS_Information));
  		dest->atsi_count = update_count;
  		memcpy (dest->atsi, update, update_count * sizeof (struct GNUNET_ATS_Information));
  		delta_atsi_count = update_count;
  		(*delta_dest) = GNUNET_malloc (update_count * sizeof (struct GNUNET_ATS_Information));
  		for (c1 = 0; c1 < update_count; c1 ++)
  		{
  			(*delta_dest)[c1].type = update[c1].type;
  			(*delta_dest)[c1].value = htonl(GNUNET_ATS_VALUE_UNDEFINED);
  		}
  		(*delta_count) = update_count;
  		return GNUNET_YES;
  }

  for (c1 = 0; c1 < update_count; c1++)
  {
  	/* Update existing performance information */
  	found = GNUNET_NO;
  	for (c2 = 0; c2 < dest->atsi_count; c2++)
  	{
			if (update[c1].type == dest->atsi[c2].type)
			{
				if (update[c1].value != dest->atsi[c2].value)
				{
						/* Save previous value in delta */
						delta_atsi[delta_atsi_count] = dest->atsi[c2];
						delta_atsi_count ++;
						/* Set new value */
						dest->atsi[c2].value = update[c1].value;
						change = GNUNET_YES;
				}
				found = GNUNET_YES;
				break;
			}
  	}
		if (GNUNET_NO == found)
		{
				add_atsi[add_atsi_count] = update[c1];
				add_atsi_count ++;
				delta_atsi[delta_atsi_count].type = update[c1].type;
				delta_atsi[delta_atsi_count].value = htonl (GNUNET_ATS_VALUE_UNDEFINED);
				delta_atsi_count ++;
		}
  }

  if (add_atsi_count > 0)
  {
  		/* Extend ats performance information */

  		tmp_atsi = GNUNET_malloc ((dest->atsi_count + add_atsi_count) *
  															(sizeof (struct GNUNET_ATS_Information)));
  		memcpy (tmp_atsi, dest->atsi, dest->atsi_count * sizeof (struct GNUNET_ATS_Information));
  		memcpy (&tmp_atsi[dest->atsi_count], add_atsi, add_atsi_count * sizeof (struct GNUNET_ATS_Information));
  		GNUNET_free (dest->atsi);
  		dest->atsi = tmp_atsi;
  		dest->atsi_count = dest->atsi_count + add_atsi_count;
			change = GNUNET_YES;
  }

  if (delta_atsi_count > 0)
  {
  		/* Copy delta */
  		(*delta_dest) = GNUNET_malloc (delta_atsi_count * sizeof (struct GNUNET_ATS_Information));
  		memcpy ((*delta_dest), delta_atsi, delta_atsi_count * sizeof (struct GNUNET_ATS_Information));
  		(*delta_count) = delta_atsi_count;
  }

  return change;
}

/**
 * Free the given address
 *
 * @param addr address to destroy
 */
static void
free_address (struct ATS_Address *addr)
{
  GNUNET_free (addr->plugin);
  GNUNET_free_non_null (addr->atsi);
  GNUNET_free (addr);
}

/**
 * Create a ATS_address with the given information
 *
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
  aa->active = GNUNET_NO;
  aa->used = GNUNET_NO;
  aa->solver_information = NULL;
  aa->atsi = NULL;
  aa->atsi_count = 0;
  aa->assigned_bw_in = GNUNET_BANDWIDTH_value_init(0);
  aa->assigned_bw_out = GNUNET_BANDWIDTH_value_init(0);
  return aa;
}


/**
 * Destroy the given address.
 *
 * @param handle the address handle
 * @param addr address to destroy
 * @return GNUNET_YES if bandwidth allocations should be recalcualted
 */
static int
destroy_address (struct GAS_Addresses_Handle *handle, struct ATS_Address *addr)
{
  int ret;

  ret = GNUNET_NO;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (handle->addresses,
                                                       &addr->peer.hashPubKey,
                                                       addr));
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

/**
 * Comapre addresses
 *
 * @param cls a CompareAddressContext containin the source address
 * @param key peer id
 * @param value the address to compare with
 * @return GNUNET_YES to continue, GNUNET_NO if address is founce
 */

static int
compare_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct CompareAddressContext *cac = cls;
  struct ATS_Address *aa = value;

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
 * @param handle the address handle
 * @param peer peer to lookup addresses for
 * @param addr existing address record
 * @return existing address record, NULL for none
 */
struct ATS_Address *
find_equivalent_address (struct GAS_Addresses_Handle *handle,
                         const struct GNUNET_PeerIdentity *peer,
                         const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.exact_address = NULL;
  cac.base_address = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &compare_address_it, &cac);

  if (cac.exact_address == NULL)
    return cac.base_address;
  return cac.exact_address;
}


/**
 * Lookup an ATS address by the address properties and session or return an
 * equivalent address with a session == 0
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param session_id session id, can be 0
 * @param atsi performance information for this address
 * @param atsi_count number of performance information contained
 * @return an ATS_address or NULL
 */

static struct ATS_Address *
lookup_address (struct GAS_Addresses_Handle *handle,
                const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name,
                const void *plugin_addr,
                size_t plugin_addr_len,
                uint32_t session_id,
                const struct GNUNET_ATS_Information *atsi,
                uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *ea;

  aa = create_address (peer,
                       plugin_name,
                       plugin_addr, plugin_addr_len,
                       session_id);

  /* Get existing address or address with session == 0 */
  ea = find_equivalent_address (handle, peer, aa);
  free_address (aa);
  if (ea == NULL)
  {
    return NULL;
  }
  else if (ea->session_id != session_id)
  {
    return NULL;
  }
  return ea;
}

/**
 * Extract an ATS performance info from an address
 *
 * @param address the address
 * @param type the type to extract in HBO
 * @return the value in HBO or GNUNET_ATS_VALUE_UNDEFINED in HBO if value does not exist
 */
static int
get_performance_info (struct ATS_Address *address, uint32_t type)
{
	int c1;
	GNUNET_assert (NULL != address);

	if ((NULL == address->atsi) || (0 == address->atsi_count))
			return GNUNET_ATS_VALUE_UNDEFINED;

	for (c1 = 0; c1 < address->atsi_count; c1++)
	{
			if (ntohl(address->atsi[c1].type) == type)
				return ntohl(address->atsi[c1].value);
	}
	return GNUNET_ATS_VALUE_UNDEFINED;
}


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
                   const char *plugin_name, const void *plugin_addr,
                   size_t plugin_addr_len, uint32_t session_id,
                   const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct ATS_Address *ea;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;
  uint32_t addr_net;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s'\n",
              "ADDRESS ADD",
              GNUNET_i2s (peer));

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert (NULL != handle->addresses);

  aa = create_address (peer, plugin_name, plugin_addr, plugin_addr_len,
                       session_id);
  atsi_delta = NULL;
  disassemble_ats_information (aa, atsi, atsi_count, &atsi_delta, &atsi_delta_count);
  GNUNET_free_non_null (atsi_delta);
  addr_net = get_performance_info (aa, GNUNET_ATS_NETWORK_TYPE);
  if (GNUNET_ATS_VALUE_UNDEFINED == addr_net)
  		addr_net = GNUNET_ATS_NET_UNSPECIFIED;

  /* Get existing address or address with session == 0 */
  ea = find_equivalent_address (handle, peer, aa);
  if (ea == NULL)
  {
    /* We have a new address */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (handle->addresses,
                                                      &peer->hashPubKey, aa,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added new address for peer `%s' session id %u, %p\n",
                GNUNET_i2s (peer), session_id, aa);
    /* Tell solver about new address */
    handle->s_add (handle->solver, handle->addresses, aa, addr_net);
    /* Notify performance clients about new address */
    GAS_performance_notify_all_clients (&aa->peer,
        aa->plugin,
        aa->addr, aa->addr_len,
        aa->session_id,
        aa->atsi, aa->atsi_count,
        aa->assigned_bw_out,
        aa->assigned_bw_in);
    return;
  }

  GNUNET_free (aa->plugin);
  GNUNET_free_non_null (aa->atsi);
  GNUNET_free (aa);
  aa = NULL;

  if (ea->session_id != 0)
  {
      /* This address with the same session is already existing
       * Should not happen */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Added already existing address for peer `%s' `%s' %p with new session %u\n",
                GNUNET_i2s (peer), plugin_name, session_id);
      GNUNET_break (0);
      return;
  }

  /* We have an address without an session, update this address */
  atsi_delta = NULL;
  atsi_delta_count = 0;
  if (GNUNET_YES == disassemble_ats_information (ea, atsi, atsi_count, &atsi_delta, &atsi_delta_count))
  {
		GAS_performance_notify_all_clients (&ea->peer,
				ea->plugin,
				ea->addr, ea->addr_len,
				ea->session_id,
				ea->atsi, ea->atsi_count,
				ea->assigned_bw_out,
				ea->assigned_bw_in);
  }

  /* Notify solver about update with atsi information and session */
  handle->s_update (handle->solver, handle->addresses, ea, session_id, ea->used, atsi_delta, atsi_delta_count);
  GNUNET_free_non_null (atsi_delta);

  /* Do the update */
  ea->session_id = session_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
           "Updated existing address for peer `%s' %p with new session %u\n",
           GNUNET_i2s (peer), ea, session_id);
}


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
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;
  uint32_t prev_session;

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert (NULL != handle->addresses);

  /* Get existing address */
  aa = lookup_address (handle, peer, plugin_name, plugin_addr, plugin_addr_len,
                       session_id, atsi, atsi_count);
  if (aa == NULL)
  {
    /* GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Tried to update unknown address for peer `%s' `%s' session id %u\n", */
    /*             GNUNET_i2s (peer), plugin_name, session_id); */
    /* GNUNET_break (0); */
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received `%s' for peer `%s' address \n",
                "ADDRESS UPDATE",
                GNUNET_i2s (peer), aa);

  /* Update address */
  atsi_delta = NULL;
  atsi_delta_count = 0;
  if (GNUNET_YES == disassemble_ats_information (aa, atsi, atsi_count, &atsi_delta, &atsi_delta_count))
  {
  		/* Notify performance clients about updated address */
  		GAS_performance_notify_all_clients (&aa->peer,
  				aa->plugin,
  				aa->addr, aa->addr_len,
  				aa->session_id,
  				aa->atsi, aa->atsi_count,
  				aa->assigned_bw_out,
  				aa->assigned_bw_in);
  }
  prev_session = aa->session_id;
  aa->session_id = session_id;


  /* Tell solver about update */
  handle->s_update (handle->solver, handle->addresses, aa, prev_session, aa->used, atsi_delta, atsi_delta_count);
  GNUNET_free_non_null (atsi_delta);
}


struct DestroyContext
{
  struct ATS_Address *aa;

  struct GAS_Addresses_Handle *handle;

  /**
   * GNUNET_NO  : full address
   * GNUNET_YES : just session
   */
  int result;
};


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
  struct DestroyContext *dc = cls;
  struct GAS_Addresses_Handle *handle = dc->handle;
  const struct ATS_Address *des = dc->aa;
  struct ATS_Address *aa = value;

  GNUNET_assert (0 == memcmp (&aa->peer, &des->peer,
                              sizeof (struct GNUNET_PeerIdentity)));


  if (des->session_id == 0)
  {
    /* Session == 0, remove full address  */
    if ((0 == strcmp (des->plugin, aa->plugin)) &&
        (aa->addr_len == des->addr_len) &&
        (0 == memcmp (des->addr, aa->addr, aa->addr_len)))
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Deleting full address for peer `%s' session %u %p\n",
                  GNUNET_i2s (&aa->peer), aa->session_id, aa);

      /* Notify solver about deletion */
      handle->s_del (handle->solver, handle->addresses, aa, GNUNET_NO);
      destroy_address (handle, aa);
      dc->result = GNUNET_NO;
      return GNUNET_OK; /* Continue iteration */
    }
  }
  else
  {
    /* Session != 0, just remove session */
    if (aa->session_id != des->session_id)
      return GNUNET_OK; /* irrelevant */

    if ((aa->session_id != 0) &&
        (0 != strcmp (des->plugin, aa->plugin)))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Different plugins during removal: `%s' vs `%s' \n",
                    des->plugin, aa->plugin);
        GNUNET_break (0);
        return GNUNET_OK;
    }

    if (aa->addr_len == 0)
    {
        /* Inbound connection died, delete full address */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Deleting inbound address for peer `%s': `%s' session %u\n",
                    GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);

        /* Notify solver about deletion */
        handle->s_del (handle->solver, handle->addresses, aa, GNUNET_NO);
        destroy_address (handle, aa);
        dc->result = GNUNET_NO;
        return GNUNET_OK; /* Continue iteration */
    }
    else
    {
        /* Session died */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Deleting session for peer `%s': `%s' %u\n",
                    GNUNET_i2s (&aa->peer), aa->plugin, aa->session_id);
        /* Notify solver to delete session */
        handle->s_del (handle->solver, handle->addresses, aa, GNUNET_YES);
        aa->session_id = 0;
        return GNUNET_OK;
    }
  }
  return GNUNET_OK;
}


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
                       uint32_t session_id)
{
  struct ATS_Address *ea;
  struct DestroyContext dc;

  if (GNUNET_NO == handle->running)
    return;

  /* Get existing address */
  ea = lookup_address (handle, peer, plugin_name, plugin_addr, plugin_addr_len,
                       session_id, NULL, 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s' address %p session %u\n",
              "ADDRESS DESTROY",
              GNUNET_i2s (peer), ea, session_id);

  if (ea == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Tried to destroy unknown address for peer `%s' `%s' session id %u\n",
                GNUNET_i2s (peer), plugin_name, session_id);
    return;
  }

  GNUNET_break (0 < strlen (plugin_name));
  dc.handle = handle;
  dc.aa = create_address (peer, plugin_name, plugin_addr, plugin_addr_len, session_id);

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses, &peer->hashPubKey,
                                              &destroy_by_session_id, &dc);
  free_address (dc.aa);
}


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
                      int in_use)
{
  struct ATS_Address *ea;
  int prev_inuse;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received `%s' for peer `%s'\n",
                "ADDRESS IN USE",
                GNUNET_i2s (peer));

  if (GNUNET_NO == handle->running)
    return GNUNET_SYSERR;

  ea = lookup_address (handle, peer, plugin_name,
                        plugin_addr, plugin_addr_len,
                        session_id, NULL, 0);
  if (NULL == ea)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Trying to set unknown address `%s', %s %u %s \n",
                GNUNET_i2s (peer),
                plugin_name, session_id,
                (GNUNET_NO == in_use) ? "NO" : "YES");
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ea->used == in_use)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Address in use called multiple times for peer `%s': %s -> %s \n",
                GNUNET_i2s (peer),
                (GNUNET_NO == ea->used) ? "NO" : "YES",
                (GNUNET_NO == in_use) ? "NO" : "YES");
    return GNUNET_SYSERR;
  }

  /* Tell solver about update */
  prev_inuse = ea->used;
  ea->used = in_use;
  handle->s_update (handle->solver, handle->addresses, ea, session_id, prev_inuse, NULL, 0);


  return GNUNET_OK;
}


/**
 * Cancel address suggestions for a peer
 *
 * @param handle the address handle
 * @param peer the peer id
 */
void
GAS_addresses_request_address_cancel (struct GAS_Addresses_Handle *handle,
                                      const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_Addresses_Suggestion_Requests *cur = handle->r_head;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request: `%s' for peer %s\n", "request_address_cancel", GNUNET_i2s (peer));

  while (NULL != cur)
  {
      if (0 == memcmp (peer, &cur->id, sizeof (cur->id)))
        break; /* found */
      cur = cur->next;
  }

  if (NULL == cur)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "No address requests pending for peer `%s', cannot remove!\n", GNUNET_i2s (peer));
      return;
  }
  handle->s_get_stop (handle->solver, handle->addresses, peer);
  GAS_addresses_handle_backoff_reset (handle, peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removed request pending for peer `%s\n", GNUNET_i2s (peer));
  GNUNET_CONTAINER_DLL_remove (handle->r_head, handle->r_tail, cur);
  GNUNET_free (cur);
}


/**
 * Request address suggestions for a peer
 *
 * @param handle the address handle
 * @param peer the peer id
 */
void
GAS_addresses_request_address (struct GAS_Addresses_Handle *handle,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_Addresses_Suggestion_Requests *cur = handle->r_head;
  struct ATS_Address *aa;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s'\n",
              "REQUEST ADDRESS",
              GNUNET_i2s (peer));

  if (GNUNET_NO == handle->running)
    return;
  while (NULL != cur)
  {
      if (0 == memcmp (peer, &cur->id, sizeof (cur->id)))
        break; /* already suggesting */
      cur = cur->next;
  }
  if (NULL == cur)
  {
      cur = GNUNET_malloc (sizeof (struct GAS_Addresses_Suggestion_Requests));
      cur->id = (*peer);
      GNUNET_CONTAINER_DLL_insert (handle->r_head, handle->r_tail, cur);
  }

  /* Get prefered address from solver */
  aa = (struct ATS_Address *) handle->s_get (handle->solver, handle->addresses, peer);
  if (NULL == aa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cannot suggest address for peer `%s'\n", GNUNET_i2s (peer));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Suggesting address %p for peer `%s'\n", aa, GNUNET_i2s (peer));

  GAS_scheduling_transmit_address_suggestion (peer,
                                              aa->plugin,
                                              aa->addr, aa->addr_len,
                                              aa->session_id,
                                              aa->atsi, aa->atsi_count,
                                              aa->assigned_bw_out,
                                              aa->assigned_bw_in);

  aa->block_interval = GNUNET_TIME_relative_add (aa->block_interval, ATS_BLOCKING_DELTA);
  aa->blocked_until = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(), aa->block_interval);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
       "Address %p ready for suggestion, block interval now %llu \n",
       aa, aa->block_interval);
}


/**
 * Iterator to reset address blocking
 *
 * @param cls not used
 * @param key the peer
 * @param value the address to reset
 * @return GNUNET_OK to continue
 */
static int
reset_address_it (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct ATS_Address *aa = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Resetting interval for peer `%s' address %p from %llu to 0\n",
              GNUNET_i2s (&aa->peer), aa, aa->block_interval);

  aa->blocked_until = GNUNET_TIME_UNIT_ZERO_ABS;
  aa->block_interval = GNUNET_TIME_UNIT_ZERO;
  return GNUNET_OK;
}


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
                                    const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s'\n",
              "RESET BACKOFF",
              GNUNET_i2s (peer));

  GNUNET_break (GNUNET_SYSERR != GNUNET_CONTAINER_multihashmap_get_multiple (handle->addresses,
                                              &peer->hashPubKey,
                                              &reset_address_it,
                                              NULL));
}

static void
normalized_preference_changed_cb (void *cls,
																	const struct GNUNET_PeerIdentity *peer,
	  															enum GNUNET_ATS_PreferenceKind kind,
	  															double pref_rel)
{
	GNUNET_assert (NULL != cls);
	struct GAS_Addresses_Handle *handle = cls;
  /* Tell solver about update */
  handle->s_pref (handle->solver, handle->addresses, peer, kind, pref_rel);
}


/**
 * Change the preference for a peer
 *
 * @param handle the address handle
 * @param client the client sending this request
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score the new preference score
 */
void
GAS_addresses_change_preference (struct GAS_Addresses_Handle *handle,
                                 void *client,
                                 const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score_abs)
{
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s' for client %p\n",
              "CHANGE PREFERENCE",
              GNUNET_i2s (peer), client);

  if (GNUNET_NO == handle->running)
    return;

  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->addresses,
                                                          &peer->hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received `%s' for unknown peer `%s' from client %p\n",
                  "CHANGE PREFERENCE",
                  GNUNET_i2s (peer), client);
      return;
  }
  /* Tell normalization about change, normalization will call callback if preference changed */
  GAS_normalization_change_preference (client, peer, kind, score_abs);
}


/**
 * Load quotas for networks from configuration
 *
 * @param cfg configuration handle
 * @param out_dest where to write outbound quotas
 * @param in_dest where to write inbound quotas
 * @param dest_length length of inbound and outbound arrays
 * @return number of networks loaded
 */
static unsigned int
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg, unsigned long long *out_dest, unsigned long long *in_dest, int dest_length)
{
  char *network_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;
  char * entry_in = NULL;
  char * entry_out = NULL;
  char * quota_out_str;
  char * quota_in_str;
  int c;
  int res;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    GNUNET_asprintf (&entry_out, "%s_QUOTA_OUT", network_str[c]);
    GNUNET_asprintf (&entry_in, "%s_QUOTA_IN", network_str[c]);

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_out_str, GNUNET_ATS_MaxBandwidthString))
      {
        out_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &out_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_out,  &out_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
              network_str[c], quota_out_str, GNUNET_ATS_DefaultBandwidth);
          out_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Outbound quota configure for network `%s' is %llu\n"),
              network_str[c], out_dest[c]);
      }
      GNUNET_free (quota_out_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("No outbound quota configured for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_in_str, GNUNET_ATS_MaxBandwidthString))
      {
        in_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_in,  &in_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
              network_str[c], quota_in_str, GNUNET_ATS_DefaultBandwidth);
          in_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Inbound quota configured for network `%s' is %llu\n"),
              network_str[c], in_dest[c]);
      }
      GNUNET_free (quota_in_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("No outbound quota configure for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded quota for network `%s' (in/out): %llu %llu\n", network_str[c], in_dest[c], out_dest[c]);
    GNUNET_free (entry_out);
    GNUNET_free (entry_in);
  }
  return GNUNET_ATS_NetworkTypeCount;
}


/**
 * Callback for solver to notify about assignment changes
 *
 * @param cls the GAS_Addresses_Handle
 * @param address the address with changes
 */
static void
bandwidth_changed_cb (void *cls, struct ATS_Address *address)
{
  struct GAS_Addresses_Handle *handle = cls;
  struct GAS_Addresses_Suggestion_Requests *cur;

  GNUNET_assert (handle != NULL);
  GNUNET_assert (address != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Bandwidth assignment changed for peer %s \n", GNUNET_i2s(&address->peer));

  /* Notify performance clients about changes to address */
  GAS_performance_notify_all_clients (&address->peer,
      address->plugin,
      address->addr, address->addr_len,
      address->session_id,
      address->atsi, address->atsi_count,
      address->assigned_bw_out,
      address->assigned_bw_in);
  cur = handle->r_head;
  while (NULL != cur)
  {
      if (0 == memcmp (&address->peer, &cur->id, sizeof (cur->id)))
        break; /* we have an address request pending*/
      cur = cur->next;
  }
  if (NULL == cur)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Nobody is interested in peer `%s' :(\n",GNUNET_i2s (&address->peer));
      return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending bandwidth update for peer `%s'\n",GNUNET_i2s (&address->peer));

  /* *Notify scheduling clients about suggestion */
  GAS_scheduling_transmit_address_suggestion (&address->peer,
                                              address->plugin,
                                              address->addr, address->addr_len,
                                              address->session_id,
                                              address->atsi, address->atsi_count,
                                              address->assigned_bw_out,
                                              address->assigned_bw_in);
}


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
                    const struct GNUNET_STATISTICS_Handle *stats)
{
  struct GAS_Addresses_Handle *ah;
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  unsigned long long  quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long  quotas_out[GNUNET_ATS_NetworkTypeCount];
  int quota_count;
  char *mode_str;
  int c;

  ah = GNUNET_malloc (sizeof (struct GAS_Addresses_Handle));
  ah->running = GNUNET_NO;

  ah->stat = (struct GNUNET_STATISTICS_Handle *) stats;
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
      ah->s_add = &GAS_mlp_address_add;
      ah->s_update = &GAS_mlp_address_update;
      ah->s_get = &GAS_mlp_get_preferred_address;
      ah->s_get_stop = &GAS_mlp_stop_get_preferred_address;
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
      ah->s_init = &GAS_proportional_init;
      ah->s_add = &GAS_proportional_address_add;
      ah->s_update = &GAS_proportional_address_update;
      ah->s_get = &GAS_proportional_get_preferred_address;
      ah->s_get_stop = &GAS_proportional_stop_get_preferred_address;
      ah->s_pref = &GAS_proportional_address_change_preference;
      ah->s_del  = &GAS_proportional_address_delete;
      ah->s_done = &GAS_proportional_done;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS started in %s mode\n", "SIMPLISTIC");
      break;
    default:
      return NULL;
      break;
  }

  GNUNET_assert (NULL != ah->s_init);
  GNUNET_assert (NULL != ah->s_add);
  GNUNET_assert (NULL != ah->s_update);
  GNUNET_assert (NULL != ah->s_get);
  GNUNET_assert (NULL != ah->s_get_stop);
  GNUNET_assert (NULL != ah->s_pref);
  GNUNET_assert (NULL != ah->s_del);
  GNUNET_assert (NULL != ah->s_done);

  GAS_normalization_start (&normalized_preference_changed_cb, ah);
  quota_count = load_quotas(cfg, quotas_in, quotas_out, GNUNET_ATS_NetworkTypeCount);

  ah->solver = ah->s_init (cfg, stats, quotas, quotas_in, quotas_out, quota_count, &bandwidth_changed_cb, ah);
  if (NULL == ah->solver)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to initialize solver!\n");
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
  struct GAS_Addresses_Handle *handle = cls;
  struct ATS_Address *aa = value;
  handle->s_del (handle->solver, handle->addresses, aa, GNUNET_NO);
  destroy_address (handle, aa);
  return GNUNET_OK;
}


/**
 * Remove all addresses
 *
 * @param handle the address handle to use
 */
void
GAS_addresses_destroy_all (struct GAS_Addresses_Handle *handle)
{
  if (GNUNET_NO == handle->running)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s'\n",
              "DESTROY ALL");

  if (handle->addresses != NULL)
    GNUNET_CONTAINER_multihashmap_iterate (handle->addresses, &free_address_it, handle);
}


/**
 * Shutdown address subsystem.
 *
 * @param handle the address handle to shutdown
 */
void
GAS_addresses_done (struct GAS_Addresses_Handle *handle)
{
  struct GAS_Addresses_Suggestion_Requests *cur;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down addresses\n");
  GNUNET_assert (NULL != handle);
  GAS_addresses_destroy_all (handle);
  handle->running = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_destroy (handle->addresses);
  handle->addresses = NULL;
  while (NULL != (cur = handle->r_head))
  {
      GNUNET_CONTAINER_DLL_remove (handle->r_head, handle->r_tail, cur);
      GNUNET_free (cur);
  }
  handle->s_done (handle->solver);
  GNUNET_free (handle);
  /* Stop configured solution method */
  GAS_normalization_stop ();
}


struct PeerIteratorContext
{
  GNUNET_ATS_Peer_Iterator it;
  void *it_cls;
  struct GNUNET_CONTAINER_MultiHashMap *peers_returned;
};


/**
 * Iterator to iterate over all peers
 *
 * @param cls a PeerIteratorContext
 * @param key the peer id
 * @param value the ATS_address
 * @return GNUNET_OK to continue
 */
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
 * Return information all peers currently known to ATS
 *
 * @param handle the address handle to use
 * @param p_it the iterator to call for every peer
 * @param p_it_cls the closure for the iterator
 */
void
GAS_addresses_iterate_peers (struct GAS_Addresses_Handle *handle,
														 GNUNET_ATS_Peer_Iterator p_it,
														 void *p_it_cls)
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


/**
 * Iterator to iterate over a peer's addresses
 *
 * @param cls a PeerInfoIteratorContext
 * @param key the peer id
 * @param value the ATS_address
 * @return GNUNET_OK to continue
 */
static int 
peerinfo_it (void *cls,
	     const struct GNUNET_HashCode * key,
	     void *value)
{
  struct PeerInfoIteratorContext *pi_ctx = cls;
  struct ATS_Address *addr = (struct ATS_Address *)  value;

  if (NULL != pi_ctx->it)
  {
    pi_ctx->it (pi_ctx->it_cls,
                &addr->peer,
                addr->plugin,
                addr->addr, addr->addr_len,
                addr->active,
                addr->atsi, addr->atsi_count,
                addr->assigned_bw_out,
                addr->assigned_bw_in);
  }
  return GNUNET_YES;
}


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
                             void *pi_it_cls)
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
