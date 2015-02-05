/*
 This file is part of GNUnet.
 (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-ats_plugins.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"


/**
 * NOTE: Do not change this documentation. This documentation is based on
 * gnunet.org:/vcs/fsnsg/2014-p2p-ats.git/tech-doku/ats-tech-guide.tex
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
 *    MODE_PROPORTIONAL, MODE_MLP. Interaction is done using a solver API
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
 *       1.7.6 Address lifecycle
 *
 *      * (add address)
 *      * (updated address)
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
 * A multihashmap to store all addresses
 */
struct GNUNET_CONTAINER_MultiPeerMap *GSA_addresses;

/**
 * Context for sending messages to performance clients without PIC.
 */
static struct GNUNET_SERVER_NotificationContext *nc;


/**
 * Update statistic on number of addresses.
 */
static void
update_addresses_stat ()
{
  GNUNET_STATISTICS_set (GSA_stats,
                         "# addresses",
                         GNUNET_CONTAINER_multipeermap_size (GSA_addresses),
                         GNUNET_NO);
}


/**
 * Disassemble ATS information and update performance information in address
 *
 * Updates existing information and adds new information
 *
 * @param dest destination address
 * @param update source ATS information
 * @param update_count number of ATS information in @a update
 * @param delta_dest ats performance information which were updated
 * 				including previous value
 * @param delta_count number of ATS information in the @a delta_dest
 * @return #GNUNET_YES if address was address updated, GNUNET_NO otherwise
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
    dest->atsi =
        GNUNET_malloc (update_count * sizeof (struct GNUNET_ATS_Information));
    dest->atsi_count = update_count;
    memcpy (dest->atsi,
            update,
            update_count * sizeof(struct GNUNET_ATS_Information));
    *delta_dest =
        GNUNET_malloc (update_count * sizeof (struct GNUNET_ATS_Information));
    for (c1 = 0; c1 < update_count; c1++)
    {
      (*delta_dest)[c1].type = update[c1].type;
      (*delta_dest)[c1].value = htonl (GNUNET_ATS_VALUE_UNDEFINED);
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
          delta_atsi_count++;
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
      add_atsi_count++;
      delta_atsi[delta_atsi_count].type = update[c1].type;
      delta_atsi[delta_atsi_count].value = htonl (GNUNET_ATS_VALUE_UNDEFINED);
      delta_atsi_count++;
    }
  }

  if (add_atsi_count > 0)
  {
    /* Extend ats performance information */

    tmp_atsi = GNUNET_malloc ((dest->atsi_count + add_atsi_count) *
        (sizeof (struct GNUNET_ATS_Information)));
    memcpy (tmp_atsi, dest->atsi,
        dest->atsi_count * sizeof(struct GNUNET_ATS_Information));
    memcpy (&tmp_atsi[dest->atsi_count], add_atsi,
        add_atsi_count * sizeof(struct GNUNET_ATS_Information));
    GNUNET_free (dest->atsi);
    dest->atsi = tmp_atsi;
    dest->atsi_count = dest->atsi_count + add_atsi_count;
    change = GNUNET_YES;
  }

  if (delta_atsi_count > 0)
  {
    /* Copy delta */
    (*delta_dest) =
        GNUNET_malloc (delta_atsi_count * sizeof (struct GNUNET_ATS_Information));
    memcpy ((*delta_dest), delta_atsi,
        delta_atsi_count * sizeof(struct GNUNET_ATS_Information));
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
  GNUNET_CONTAINER_multipeermap_remove (GSA_addresses,
                                        &addr->peer,
                                        addr);
  update_addresses_stat ();
  GAS_plugin_delete_address (addr);
  GAS_performance_notify_all_clients (&addr->peer,
                                      addr->plugin,
                                      addr->addr,
                                      addr->addr_len,
                                      GNUNET_NO,
                                      NULL, 0,
                                      GNUNET_BANDWIDTH_ZERO,
                                      GNUNET_BANDWIDTH_ZERO);
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
 * @param local_address_info additional local info for the address
 * @param session_id session identifier, can never be 0
 * @return the ATS_Address
 */
static struct ATS_Address *
create_address (const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name,
                const void *plugin_addr,
                size_t plugin_addr_len,
                uint32_t local_address_info,
                uint32_t session_id)
{
  struct ATS_Address *aa;
  unsigned int c1;
  unsigned int c2;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  memcpy (&aa[1],
          plugin_addr,
          plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_id = session_id;
  aa->local_address_info = local_address_info;

  for (c1 = 0; c1 < GNUNET_ATS_QualityPropertiesCount; c1++)
  {
    aa->atsin[c1].avg_queue_index = 0;
    for (c2 = 0; c2 < GAS_normalization_queue_length; c2++)
      aa->atsin[c1].atsi_abs[c2] = GNUNET_ATS_VALUE_UNDEFINED;
  }
  return aa;
}


/**
 * Closure for #find_address_cb()
 */
struct FindAddressContext
{
  /**
   * Session Id to look for.
   */
  uint32_t session_id;

  /**
   * Where to store matching address result.
   */
  struct ATS_Address *exact_address;

};


/**
 * Find session matching given session ID.
 *
 * @param cls a `struct FindAddressContext`
 * @param key peer id
 * @param value the address to compare with
 * @return #GNUNET_YES to continue, #GNUNET_NO if address is found
 */
static int
find_address_cb (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct FindAddressContext *fac = cls;
  struct ATS_Address *aa = value;

  if (aa->session_id == fac->session_id)
  {
    fac->exact_address = aa;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Find the exact address
 *
 * @param peer peer
 * @param session_id session id, can never be 0
 * @return an ATS_address or NULL
 */
static struct ATS_Address *
find_exact_address (const struct GNUNET_PeerIdentity *peer,
                    uint32_t session_id)
{
  struct FindAddressContext fac;

  fac.exact_address = NULL;
  fac.session_id = session_id;
  GNUNET_CONTAINER_multipeermap_get_multiple (GSA_addresses,
					      peer,
					      &find_address_cb, &fac);
  return fac.exact_address;
}


/**
 * Extract an ATS performance info from an address
 *
 * @param address the address
 * @param type the type to extract in HBO
 * @return the value in HBO or #GNUNET_ATS_VALUE_UNDEFINED in HBO if value does not exist
 */
static int
get_performance_info (struct ATS_Address *address, uint32_t type)
{
  int c1;
  GNUNET_assert(NULL != address);

  if ((NULL == address->atsi) || (0 == address->atsi_count))
    return GNUNET_ATS_VALUE_UNDEFINED;

  for (c1 = 0; c1 < address->atsi_count; c1++)
  {
    if (ntohl (address->atsi[c1].type) == type)
      return ntohl (address->atsi[c1].value);
  }
  return GNUNET_ATS_VALUE_UNDEFINED;
}


/**
 * Add a new address for a peer.
 *
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address in @a plugin_addr
 * @param local_address_info the local address for the address
 * @param session_id session id, can be 0
 * @param atsi performance information for this address
 * @param atsi_count number of performance information contained in @a atsi
 */
void
GAS_addresses_add (const struct GNUNET_PeerIdentity *peer,
                   const char *plugin_name,
                   const void *plugin_addr,
                   size_t plugin_addr_len,
                   uint32_t local_address_info,
                   uint32_t session_id,
                   const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count)
{
  struct ATS_Address *new_address;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;
  uint32_t addr_net;

  if (NULL != find_exact_address (peer, session_id))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s'\n",
              "ADDRESS ADD",
              GNUNET_i2s (peer));
  new_address = create_address (peer,
                                plugin_name,
                                plugin_addr,
                                plugin_addr_len,
                                local_address_info,
                                session_id);
  atsi_delta = NULL;
  disassemble_ats_information (new_address,
                               atsi, atsi_count,
                               &atsi_delta,
                               &atsi_delta_count);
  GNUNET_free_non_null (atsi_delta);
  addr_net = get_performance_info (new_address, GNUNET_ATS_NETWORK_TYPE);
  if (GNUNET_ATS_VALUE_UNDEFINED == addr_net)
    addr_net = GNUNET_ATS_NET_UNSPECIFIED;

  /* Add a new address */
  new_address->t_added = GNUNET_TIME_absolute_get();
  new_address->t_last_activity = GNUNET_TIME_absolute_get();
  GNUNET_assert(GNUNET_OK ==
		GNUNET_CONTAINER_multipeermap_put (GSA_addresses,
						   peer,
						   new_address,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  update_addresses_stat ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Adding new address %p for peer `%s', length %u, session id %u, %s\n",
	      new_address,
	      GNUNET_i2s (peer),
	      plugin_addr_len,
	      session_id,
	      GNUNET_ATS_print_network_type (addr_net));

  /* Tell solver about new address */
  GAS_plugin_new_address (new_address,
			  addr_net,
			  atsi,
			  atsi_count);
  /* Notify performance clients about new address */
  GAS_performance_notify_all_clients (&new_address->peer,
				      new_address->plugin,
				      new_address->addr,
				      new_address->addr_len,
				      new_address->active,
				      new_address->atsi,
				      new_address->atsi_count,
				      GNUNET_BANDWIDTH_value_init (new_address->assigned_bw_out),
				      GNUNET_BANDWIDTH_value_init (new_address->assigned_bw_in));
}


/**
 * Update an address with new performance information for a peer.
 *
 * @param peer peer
 * @param session_id session id, never 0
 * @param atsi performance information for this address
 * @param atsi_count number of performance information contained in @a atsi
 */
void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;

  /* Get existing address */
  aa = find_exact_address (peer,
                           session_id);
  if (NULL == aa)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == aa->solver_information)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for peer `%s' address \n",
              "ADDRESS UPDATE",
              GNUNET_i2s (peer),
              aa);

  /* Update address */
  aa->t_last_activity = GNUNET_TIME_absolute_get();
  atsi_delta = NULL;
  atsi_delta_count = 0;
  if (GNUNET_YES ==
      disassemble_ats_information (aa, atsi,
                                   atsi_count,
                                   &atsi_delta,
                                   &atsi_delta_count))
  {
    /* Notify performance clients about updated address */
    GAS_performance_notify_all_clients (&aa->peer,
					aa->plugin,
					aa->addr,
					aa->addr_len,
					aa->active,
					aa->atsi,
					aa->atsi_count,
					GNUNET_BANDWIDTH_value_init (aa->assigned_bw_out),
					GNUNET_BANDWIDTH_value_init (aa->assigned_bw_in));

    GAS_plugin_update_address (aa,
			       atsi,
			       atsi_count);
  }
  GNUNET_free_non_null (atsi_delta);
}


/**
 * Remove an address or just a session for a peer.
 *
 * @param peer peer
 * @param session_id session id, can never be 0
 */
void
GAS_addresses_destroy (const struct GNUNET_PeerIdentity *peer,
                       uint32_t session_id)
{
  struct ATS_Address *ea;

  /* Get existing address */
  ea = find_exact_address (peer,
                           session_id);
  if (NULL == ea)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ADDRESS_DESTROYED for peer `%s' address %p session %u\n",
              GNUNET_i2s (peer),
              ea,
              session_id);
  free_address (ea);
}


/**
 * Initialize address subsystem. The addresses subsystem manages the addresses
 * known and current performance information. It has a solver component
 * responsible for the resource allocation. It tells the solver about changes
 * and receives updates when the solver changes the resource allocation.
 *
 * @param server handle to our server
 */
void
GAS_addresses_init (struct GNUNET_SERVER_Handle *server)
{
  GSA_addresses = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  update_addresses_stat ();
  nc = GNUNET_SERVER_notification_context_create (server, 32);
}


/**
 * Destroy all addresses iterator
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the 'struct ATS_Address' to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_all_address_it (void *cls,
			const struct GNUNET_PeerIdentity *key,
			void *value)
{
  struct ATS_Address *aa = value;

  free_address (aa);
  return GNUNET_OK;
}


/**
 * Remove all addresses
 */
void
GAS_addresses_destroy_all ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Destroying all addresses\n");
  GAS_plugin_solver_lock ();
  GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                         &destroy_all_address_it,
                                         NULL);
  GAS_plugin_solver_unlock ();
}


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done ()
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "Shutting down addresses\n");
  GAS_addresses_destroy_all ();
  GNUNET_CONTAINER_multipeermap_destroy (GSA_addresses);
  GSA_addresses = NULL;
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
}


/**
 * Closure for #peerinfo_it().
 */
struct PeerInfoIteratorContext
{
  /**
   * Function to call for each address.
   */
  GNUNET_ATS_PeerInfo_Iterator it;

  /**
   * Closure for @e it.
   */
  void *it_cls;
};


/**
 * Iterator to iterate over a peer's addresses
 *
 * @param cls a `struct PeerInfoIteratorContext`
 * @param key the peer id
 * @param value the `struct ATS_address`
 * @return #GNUNET_OK to continue
 */
static int
peerinfo_it (void *cls,
	     const struct GNUNET_PeerIdentity *key,
	     void *value)
{
  struct PeerInfoIteratorContext *pi_ctx = cls;
  struct ATS_Address *addr = value;

  pi_ctx->it (pi_ctx->it_cls,
              &addr->peer,
              addr->plugin,
              addr->addr,
              addr->addr_len,
              addr->active,
              addr->atsi, addr->atsi_count,
              GNUNET_BANDWIDTH_value_init (addr->assigned_bw_out),
              GNUNET_BANDWIDTH_value_init (addr->assigned_bw_in));
  return GNUNET_OK;
}


/**
 * Return information all peers currently known to ATS
 *
 * @param peer the respective peer, NULL for 'all' peers
 * @param pi_it the iterator to call for every peer
 * @param pi_it_cls the closure for @a pi_it
 */
void
GAS_addresses_get_peer_info (const struct GNUNET_PeerIdentity *peer,
                             GNUNET_ATS_PeerInfo_Iterator pi_it,
                             void *pi_it_cls)
{
  struct PeerInfoIteratorContext pi_ctx;

  if (NULL == pi_it)
  {
    /* does not make sense without callback */
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Returning information for %s from a total of %u known addresses\n",
              (NULL == peer)
              ? "all peers"
              : GNUNET_i2s (peer),
              (unsigned int) GNUNET_CONTAINER_multipeermap_size (GSA_addresses));
  pi_ctx.it = pi_it;
  pi_ctx.it_cls = pi_it_cls;
  if (NULL == peer)
    GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                           &peerinfo_it,
                                           &pi_ctx);
  else
    GNUNET_CONTAINER_multipeermap_get_multiple (GSA_addresses,
                                                peer,
                                                &peerinfo_it, &pi_ctx);
  pi_it (pi_it_cls,
         NULL, NULL, NULL, 0,
         GNUNET_NO,
         NULL, 0,
         GNUNET_BANDWIDTH_ZERO,
         GNUNET_BANDWIDTH_ZERO);
}


/**
 * Information we need for the callbacks to return a list of addresses
 * back to the client.
 */
struct AddressIteration
{
  /**
   * Actual handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Are we sending all addresses, or only those that are active?
   */
  int all;

  /**
   * Which ID should be included in the response?
   */
  uint32_t id;

};


/**
 * Send a #GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE with the
 * given address details to the client identified in @a ai.
 *
 * @param ai our address information context (identifies the client)
 * @param id the peer id this address is for
 * @param plugin_name name of the plugin that supports this address
 * @param plugin_addr address
 * @param plugin_addr_len length of @a plugin_addr
 * @param active #GNUNET_YES if this address is actively used
 * @param atsi ats performance information
 * @param atsi_count number of ats performance elements in @a atsi
 * @param bandwidth_out current outbound bandwidth assigned to address
 * @param bandwidth_in current inbound bandwidth assigned to address
 */
static void
transmit_req_addr (struct AddressIteration *ai,
                   const struct GNUNET_PeerIdentity *id,
                   const char *plugin_name,
                   const void *plugin_addr,
                   size_t plugin_addr_len,
                   int active,
                   const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)

{
  struct GNUNET_ATS_Information *atsp;
  struct PeerInformationMessage *msg;
  char *addrp;
  size_t plugin_name_length;
  size_t msize;

  if (NULL != plugin_name)
    plugin_name_length = strlen (plugin_name) + 1;
  else
    plugin_name_length = 0;
  msize = sizeof (struct PeerInformationMessage) +
          atsi_count * sizeof (struct GNUNET_ATS_Information) +
          plugin_addr_len + plugin_name_length;
  char buf[msize] GNUNET_ALIGN;

  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (atsi_count <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE /
                 sizeof (struct GNUNET_ATS_Information));
  msg = (struct PeerInformationMessage *) buf;
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE);
  msg->ats_count = htonl (atsi_count);
  msg->id = htonl (ai->id);
  if (NULL != id)
    msg->peer = *id;
  else
    memset (&msg->peer, '\0', sizeof (struct GNUNET_PeerIdentity));
  msg->address_length = htons (plugin_addr_len);
  msg->address_active = ntohl (active);
  msg->plugin_name_length = htons (plugin_name_length);
  msg->bandwidth_out = bandwidth_out;
  msg->bandwidth_in = bandwidth_in;
  atsp = (struct GNUNET_ATS_Information *) &msg[1];
  memcpy (atsp, atsi, sizeof (struct GNUNET_ATS_Information) * atsi_count);
  addrp = (char *) &atsp[atsi_count];
  if (NULL != plugin_addr)
    memcpy (addrp, plugin_addr, plugin_addr_len);
  if (NULL != plugin_name)
    strcpy (&addrp[plugin_addr_len], plugin_name);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              ai->client,
                                              &msg->header,
                                              GNUNET_NO);
}


/**
 * Iterator for #GAS_addresses_get_peer_info(), called with peer-specific
 * information to be passed back to the client.
 *
 * @param cls closure with our `struct AddressIteration *`
 * @param id the peer id
 * @param plugin_name plugin name
 * @param plugin_addr address
 * @param plugin_addr_len length of @a plugin_addr
 * @param active is address actively used
 * @param atsi ats performance information
 * @param atsi_count number of ats performance elements in @a atsi
 * @param bandwidth_out current outbound bandwidth assigned to address
 * @param bandwidth_in current inbound bandwidth assigned to address
 */
static void
req_addr_peerinfo_it (void *cls,
                      const struct GNUNET_PeerIdentity *id,
                      const char *plugin_name,
                      const void *plugin_addr,
                      size_t plugin_addr_len,
                      int active,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count,
                      struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                      struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct AddressIteration *ai = cls;

  if ( (NULL == id) &&
       (NULL == plugin_name) &&
       (NULL == plugin_addr) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Address iteration done for one peer\n");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Callback for %s peer `%s' plugin `%s' BW out %u, BW in %u\n",
              (active == GNUNET_YES) ? "ACTIVE" : "INACTIVE",
              GNUNET_i2s (id),
              plugin_name,
              (unsigned int) ntohl (bandwidth_out.value__),
              (unsigned int) ntohl (bandwidth_in.value__));
  /* Transmit result (either if address is active, or if
     client wanted all addresses) */
  if ( (GNUNET_YES != ai->all) &&
       (GNUNET_YES != active))
    return;
  transmit_req_addr (ai,
                     id,
                     plugin_name,
                     plugin_addr, plugin_addr_len,
                     active,
                     atsi,
                     atsi_count,
                     bandwidth_out,
                     bandwidth_in);
}


/**
 * Handle 'address list request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address_list (void *cls,
                                 struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  struct AddressIteration ai;
  const struct AddressListRequestMessage *alrm;
  struct GNUNET_PeerIdentity allzeros;

  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ADDRESSLIST_REQUEST message\n");
  alrm = (const struct AddressListRequestMessage *) message;
  ai.all = ntohl (alrm->all);
  ai.id = ntohl (alrm->id);
  ai.client = client;

  memset (&allzeros,
          '\0',
          sizeof (struct GNUNET_PeerIdentity));
  if (0 == memcmp (&alrm->peer,
                   &allzeros,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* Return addresses for all peers */
    GAS_addresses_get_peer_info (NULL,
                                 &req_addr_peerinfo_it,
                                 &ai);
  }
  else
  {
    /* Return addresses for a specific peer */
    GAS_addresses_get_peer_info (&alrm->peer,
                                 &req_addr_peerinfo_it,
                                 &ai);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished handling `%s' message\n",
              "ADDRESSLIST_REQUEST");
  transmit_req_addr (&ai,
                     NULL, NULL, NULL,
                     0, GNUNET_NO,
                     NULL, 0,
                     GNUNET_BANDWIDTH_ZERO,
                     GNUNET_BANDWIDTH_ZERO);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}



/* end of gnunet-service-ats_addresses.c */
