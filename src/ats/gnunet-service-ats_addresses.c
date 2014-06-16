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
#include "gnunet_ats_plugin.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_scheduling.h"
#include "gnunet-service-ats_reservations.h"


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
  * Pending Address suggestion requests
  */
 struct GAS_Addresses_Preference_Clients
 {
   /**
    * Next in DLL
    */
   struct GAS_Addresses_Preference_Clients *next;

   /**
    * Previous in DLL
    */
   struct GAS_Addresses_Preference_Clients *prev;

   /**
    * Peer ID
    */
   void *client;
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
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /**
   * Is ATS addresses running
   */
  int running;

  /**
   * Preferences clients
   */
  int pref_clients;

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
  struct GAS_Addresses_Suggestion_Requests *pending_requests_head;

  /**
   * Address suggestion requests DLL tail
   */
  struct GAS_Addresses_Suggestion_Requests *pending_requests_tail;

  /**
   * Address suggestion requests DLL head
   */
  struct GAS_Addresses_Preference_Clients *preference_clients_head;

  /**
   * Address suggestion requests DLL head
   */
  struct GAS_Addresses_Preference_Clients *preference_clients_tail;

  /**
   * Solver functions
   */
  struct GNUNET_ATS_PluginEnvironment env;

  /**
   * Solver plugin name as string
   */
  char *plugin;
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
    const struct GNUNET_ATS_Information *update, uint32_t update_count,
    struct GNUNET_ATS_Information **delta_dest, uint32_t *delta_count)
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
    memcpy (dest->atsi, update,
        update_count * sizeof(struct GNUNET_ATS_Information));
    (*delta_dest) =
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
    GNUNET_free(dest->atsi);
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
  GNUNET_free(addr->plugin);
  GNUNET_free_non_null(addr->atsi);
  GNUNET_free(addr);
}


/**
 * Create a ATS_address with the given information
 *
 * @param peer peer
 * @param plugin_name plugin
 * @param plugin_addr address
 * @param plugin_addr_len address length
 * @param local_address_info additional local info for the address
 * @param session_id session identifier, can be 0
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
  struct ATS_Address *aa = NULL;
  int c1;
  int c2;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  memcpy (&aa[1], plugin_addr, plugin_addr_len);
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
 * @return #GNUNET_YES to continue, #GNUNET_NO if address is founce
 */
static int
compare_address_it (void *cls,
		    const struct GNUNET_PeerIdentity *key,
		    void *value)
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
  if ((aa->addr_len == cac->search->addr_len)
      && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
    if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len))
        && (aa->session_id == cac->search->session_id))
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
  if ((aa->addr_len == cac->search->addr_len)
      && (0 == strcmp (aa->plugin, cac->search->plugin)))
  {
    if ((0 == memcmp (aa->addr, cac->search->addr, aa->addr_len))
        && (aa->session_id == 0))
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
    if ((0 == strcmp (aa->plugin, cac->search->plugin))
        && (aa->session_id == cac->search->session_id))
      cac->exact_address = aa;
  }

  if (cac->exact_address == NULL )
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
    const struct GNUNET_PeerIdentity *peer, const struct ATS_Address *addr)
{
  struct CompareAddressContext cac;

  cac.exact_address = NULL;
  cac.base_address = NULL;
  cac.search = addr;
  GNUNET_CONTAINER_multipeermap_get_multiple (handle->addresses,
					      peer,
					      &compare_address_it, &cac);

  if (cac.exact_address == NULL)
    return cac.base_address;
  return cac.exact_address;
}


/**
 * Find the exact address
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param local_address_info the local address for the address
 * @param session_id session id, can be 0
 * @return an ATS_address or NULL
 */

static struct ATS_Address *
find_exact_address (struct GAS_Addresses_Handle *handle,
    const struct GNUNET_PeerIdentity *peer,
    const char *plugin_name,
    const void *plugin_addr,
    size_t plugin_addr_len,
    uint32_t local_address_info,
    uint32_t session_id)
{
  struct ATS_Address *aa;
  struct ATS_Address *ea;

  aa = create_address (peer, plugin_name, plugin_addr, plugin_addr_len,
      local_address_info, session_id);

  /* Get existing address or address with session == 0 */
  ea = find_equivalent_address (handle, peer, aa);
  free_address (aa);
  if (ea == NULL )
    return NULL ;
  else if (ea->session_id != session_id)
    return NULL ;
  return ea;
}

/**
 * Function allowing the solver to obtain normalized preference
 * values from solver
 *
 * @param cls unused
 * @param id the peer to return the normalized properties for
 * @return array of double values with |GNUNET_ATS_PreferenceCount| elements
 */
const double *
get_preferences_cb (void *cls, const struct GNUNET_PeerIdentity *id)
{
  return GAS_normalization_get_preferences_by_peer (id);
}

/**
 * Function allowing the solver to obtain normalized property
 * values for an address from solver
 *
 * @param cls unused
 * @param address the address
 * @return array of double values with |GNUNET_ATS_QualityPropertiesCount| elements
 */
const double *
get_property_cb (void *cls, const struct ATS_Address *address)
{
  return GAS_normalization_get_properties ((struct ATS_Address *) address);
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
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param local_address_info the local address for the address
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
    uint32_t local_address_info,
    uint32_t session_id,
    const struct GNUNET_ATS_Information *atsi,
    uint32_t atsi_count)
{
  struct ATS_Address *new_address;
  struct ATS_Address *existing_address;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;
  uint32_t addr_net;
  uint32_t previous_session;
  int c1;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received `%s' for peer `%s'\n",
      "ADDRESS ADD", GNUNET_i2s (peer));

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert(NULL != handle->addresses);

  new_address = create_address (peer, plugin_name, plugin_addr, plugin_addr_len,
      local_address_info, session_id);
  atsi_delta = NULL;
  disassemble_ats_information (new_address, atsi, atsi_count, &atsi_delta,
      &atsi_delta_count);
  GNUNET_free_non_null(atsi_delta);
  addr_net = get_performance_info (new_address, GNUNET_ATS_NETWORK_TYPE);
  if (GNUNET_ATS_VALUE_UNDEFINED == addr_net)
    addr_net = GNUNET_ATS_NET_UNSPECIFIED;

  /* Get existing address or address with session == 0 */
  existing_address = find_equivalent_address (handle, peer, new_address);
  if (existing_address == NULL )
  {
    /* Add a new address */
    new_address->t_added = GNUNET_TIME_absolute_get();
    new_address->t_last_activity = GNUNET_TIME_absolute_get();
    GNUNET_assert(
        GNUNET_OK == GNUNET_CONTAINER_multipeermap_put (handle->addresses,
							peer,
							new_address,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));

    GNUNET_STATISTICS_set (handle->stat,
                           "# addresses",
                           GNUNET_CONTAINER_multipeermap_size (handle->addresses),
                           GNUNET_NO);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Adding new address %p for peer `%s', length %u, session id %u, %s\n",
                new_address,
                GNUNET_i2s (peer),
                plugin_addr_len,
                session_id,
                GNUNET_ATS_print_network_type (addr_net));

    /* Tell solver about new address */
    handle->env.sf.s_add (handle->solver, new_address, addr_net);

    handle->env.sf.s_bulk_start (handle->solver);
    GAS_normalization_normalize_property (handle->addresses,
                                          new_address,
                                          atsi,
                                          atsi_count);
    handle->env.sf.s_bulk_stop (handle->solver);

    /* Notify performance clients about new address */
    GAS_performance_notify_all_clients (&new_address->peer,
                                        new_address->plugin,
                                        new_address->addr,
                                        new_address->addr_len,
                                        new_address->active,
                                        new_address->atsi,
                                        new_address->atsi_count,
                                        new_address->assigned_bw_out,
                                        new_address->assigned_bw_in);
    return;
  }

  /* We have an existing address we can use, clean up new */
  GNUNET_free(new_address->plugin);
  GNUNET_free_non_null(new_address->atsi);
  GNUNET_free(new_address);
  new_address = NULL;

  if (0 != existing_address->session_id)
  {
    /* Should not happen */
    GNUNET_break(0);
    return;
  }

  addr_net = get_performance_info (existing_address, GNUNET_ATS_NETWORK_TYPE);
  if (GNUNET_ATS_VALUE_UNDEFINED == addr_net)
    addr_net = GNUNET_ATS_NET_UNSPECIFIED;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Found existing address for peer `%s' %p with new session %u in network %s\n",
      GNUNET_i2s (peer), existing_address, session_id,
      GNUNET_ATS_print_network_type (addr_net));
  /* We have an address without an session, update this address */
  existing_address->t_added = GNUNET_TIME_absolute_get();
  existing_address->t_last_activity = GNUNET_TIME_absolute_get();
  atsi_delta = NULL;
  atsi_delta_count = 0;
  if (GNUNET_YES
      == disassemble_ats_information (existing_address, atsi, atsi_count,
          &atsi_delta, &atsi_delta_count))
  {
    /* Notify performance clients about properties */
    GAS_performance_notify_all_clients (&existing_address->peer,
                                        existing_address->plugin,
                                        existing_address->addr,
                                        existing_address->addr_len,
                                        existing_address->active,
                                        existing_address->atsi,
                                        existing_address->atsi_count,
                                        existing_address->assigned_bw_out,
                                        existing_address->assigned_bw_in);

    for (c1 = 0; c1 < atsi_delta_count; c1++)
    {
      if ((GNUNET_ATS_NETWORK_TYPE == ntohl (atsi_delta[c1].type))
          && (addr_net != ntohl (atsi_delta[c1].value)))
      {
        /* Network type changed */
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Address for peer `%s' %p changed from network %s to %s\n",
            GNUNET_i2s (peer), existing_address,
            GNUNET_ATS_print_network_type (addr_net),
            GNUNET_ATS_print_network_type (ntohl (atsi_delta[c1].value)));
        handle->env.sf.s_address_update_network (handle->solver, existing_address,
            ntohl (atsi_delta[c1].value),
            get_performance_info (existing_address, GNUNET_ATS_NETWORK_TYPE));
        addr_net = get_performance_info (existing_address,
            GNUNET_ATS_NETWORK_TYPE);
      }
    }
    /* Notify solver about update with atsi information and session */
    handle->env.sf.s_bulk_start (handle->solver);
    GAS_normalization_normalize_property (handle->addresses, existing_address,
        atsi, atsi_count);
    handle->env.sf.s_bulk_stop (handle->solver);
  }
  GNUNET_free_non_null(atsi_delta);

  /* Notify solver about new session */
  if (existing_address->session_id == session_id)
    return; /* possible, can both be 0 since address is revalidated */

  previous_session = existing_address->session_id;
  existing_address->session_id = session_id;
  handle->env.sf.s_address_update_session (handle->solver, existing_address,
      previous_session, session_id);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Updated existing address for peer `%s' %p length %u with new session %u in network %s\n",
      GNUNET_i2s (peer), existing_address, existing_address->addr_len,
      session_id, GNUNET_ATS_print_network_type (addr_net));
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
 * @param local_address_info the local address for the address
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
                      uint32_t local_address_info,
                      uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count)
{
  struct ATS_Address *aa;
  struct GNUNET_ATS_Information *atsi_delta;
  uint32_t atsi_delta_count;
  uint32_t prev_session;
  int c1;

  if (GNUNET_NO == handle->running)
    return;

  GNUNET_assert(NULL != handle->addresses);

  /* Get existing address */
  aa = find_exact_address (handle, peer, plugin_name, plugin_addr,
      plugin_addr_len, local_address_info, session_id);
  if (aa == NULL )
    return;
  if (NULL == aa->solver_information)
    return;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received `%s' for peer `%s' address \n",
             "ADDRESS UPDATE",
             GNUNET_i2s (peer), aa);

  /* Update address */
  aa->t_last_activity = GNUNET_TIME_absolute_get();
  if (session_id != aa->session_id)
  {
    /* Session changed */
    prev_session = aa->session_id;
    aa->session_id = session_id;
    handle->env.sf.s_address_update_session (handle->solver,
                                             aa,
                                             prev_session,
                                             aa->session_id);
  }

  atsi_delta = NULL;
  atsi_delta_count = 0;
  if (GNUNET_YES ==
      disassemble_ats_information (aa, atsi,
                                   atsi_count,
                                   &atsi_delta,
                                   &atsi_delta_count))
  {
    /* ATS properties changed */
    for (c1 = 0; c1 < atsi_delta_count; c1++)
    {
      if (GNUNET_ATS_NETWORK_TYPE == ntohl (atsi_delta[c1].type))
      {
        /* Network type changed */
        handle->env.sf.s_address_update_network (handle->solver, aa,
            ntohl (atsi_delta[c1].value),
            get_performance_info (aa, GNUNET_ATS_NETWORK_TYPE));
      }
    }

    /* Notify performance clients about updated address */
    GAS_performance_notify_all_clients (&aa->peer,
                                        aa->plugin,
                                        aa->addr,
                                        aa->addr_len,
                                        aa->active,
                                        aa->atsi,
                                        aa->atsi_count,
                                        aa->assigned_bw_out,
                                        aa->assigned_bw_in);
    handle->env.sf.s_bulk_start (handle->solver);
    GAS_normalization_normalize_property (handle->addresses,
                                          aa,
                                          atsi,
                                          atsi_count);
    handle->env.sf.s_bulk_stop (handle->solver);
  }
  GNUNET_free_non_null (atsi_delta);
}


/**
 * Closure for #destroy_by_session_id().
 */
struct DestroyContext
{
  /**
   * FIXME.
   */
  struct ATS_Address *aa;

  /**
   * FIXME.
   */
  struct GAS_Addresses_Handle *handle;

  /**
   * #GNUNET_NO  : full address
   * #GNUNET_YES : just session
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
 * @param value the `struct ATS_Address *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_by_session_id (void *cls,
		       const struct GNUNET_PeerIdentity *key,
		       void *value)
{
  struct DestroyContext *dc = cls;
  struct GAS_Addresses_Handle *handle = dc->handle;
  const struct ATS_Address *des = dc->aa;
  struct ATS_Address *aa = value;

  GNUNET_assert(
      0 == memcmp (&aa->peer, &des->peer, sizeof(struct GNUNET_PeerIdentity)));

  if (des->session_id == 0)
  {
    /* Session == 0, remove full address  */
    if ((0 == strcmp (des->plugin, aa->plugin))
        && (aa->addr_len == des->addr_len)
        && (0 == memcmp (des->addr, aa->addr, aa->addr_len)))
    {

      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Deleting full address for peer `%s' session %u %p\n",
                  GNUNET_i2s (&aa->peer),
                  aa->session_id,
                  aa);

      /* Notify solver about deletion */
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multipeermap_remove (handle->addresses,
                                                           &aa->peer,
                                                           aa));
      handle->env.sf.s_del (handle->solver, aa, GNUNET_NO);
      free_address (aa);
      dc->result = GNUNET_NO;
      return GNUNET_OK; /* Continue iteration */
    }
  }
  else
  {
    /* Session != 0, just remove session */
    if (aa->session_id != des->session_id)
      return GNUNET_OK; /* irrelevant */

    if ((aa->session_id != 0) && (0 != strcmp (des->plugin, aa->plugin)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Different plugins during removal: `%s' vs `%s' \n",
                  des->plugin,
                  aa->plugin);
      GNUNET_break (0);
      return GNUNET_OK;
    }
    if (GNUNET_HELLO_ADDRESS_INFO_INBOUND ==
        (aa->local_address_info && GNUNET_HELLO_ADDRESS_INFO_INBOUND))
    {
      /* Inbound connection died, delete full address */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Deleting inbound address for peer `%s': `%s' session %u\n",
                  GNUNET_i2s (&aa->peer),
                  aa->plugin,
                  aa->session_id);

      /* Notify solver about deletion */
      GNUNET_assert(GNUNET_YES ==
                    GNUNET_CONTAINER_multipeermap_remove (handle->addresses,
                                                          &aa->peer, aa));
      handle->env.sf.s_del (handle->solver, aa, GNUNET_NO);
      free_address (aa);
      dc->result = GNUNET_NO;
      return GNUNET_OK; /* Continue iteration */
    }
    else
    {
      /* Session died */
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                 "Deleting session for peer `%s': `%s' %u\n",
                 GNUNET_i2s (&aa->peer),
                 aa->plugin, aa->session_id);
      /* Notify solver to delete session */
      handle->env.sf.s_del (handle->solver, aa, GNUNET_YES);
      aa->session_id = 0;
      aa->active = GNUNET_NO;
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
 * @param local_address_info the local address for the address
 * @param session_id session id, can be 0
 */
void
GAS_addresses_destroy (struct GAS_Addresses_Handle *handle,
                       const struct GNUNET_PeerIdentity *peer,
                       const char *plugin_name,
                       const void *plugin_addr,
                       size_t plugin_addr_len,
                       uint32_t local_address_info,
                       uint32_t session_id)
{
  struct ATS_Address *ea;
  struct DestroyContext dc;

  if (GNUNET_NO == handle->running)
    return;

  /* Get existing address */
  ea = find_exact_address (handle, peer, plugin_name, plugin_addr,
      plugin_addr_len, local_address_info, session_id);
  if (ea == NULL )
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Tried to destroy unknown address for peer `%s' `%s' session id %u\n",
               GNUNET_i2s (peer),
               plugin_name,
               session_id);
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received `%s' for peer `%s' address %p session %u\n", "ADDRESS DESTROY",
             GNUNET_i2s (peer),
             ea,
             session_id);

  GNUNET_break(0 < strlen (plugin_name));
  dc.handle = handle;
  dc.aa = create_address (peer,
                          plugin_name,
                          plugin_addr,
                          plugin_addr_len,
                          local_address_info, session_id);
  GNUNET_CONTAINER_multipeermap_get_multiple (handle->addresses,
					      peer,
					      &destroy_by_session_id, &dc);
  GNUNET_STATISTICS_set (handle->stat,
                         "# addresses",
                         GNUNET_CONTAINER_multipeermap_size (handle->addresses),
                         GNUNET_NO);
  free_address (dc.aa);
}


/**
 * Notification about active use of an address.
 * in_use == #GNUNET_YES:
 * 	This address is used to maintain an active connection with a peer.
 * in_use == #GNUNET_NO:
 * 	This address is no longer used to maintain an active connection with a peer.
 *
 * Note: can only be called with in_use == #GNUNET_NO if called with #GNUNET_YES
 * before
 *
 * @param handle the address handle to use
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address
 * @param local_address_info the local address for the address
 * @param session_id session id, can be 0
 * @param in_use #GNUNET_YES if #GNUNET_NO FIXME
 * @return #GNUNET_SYSERR on failure (address unknown ...)
 */
int
GAS_addresses_in_use (struct GAS_Addresses_Handle *handle,
                      const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name,
                      const void *plugin_addr,
                      size_t plugin_addr_len,
                      uint32_t local_address_info,
                      uint32_t session_id,
                      int in_use)
{
  struct ATS_Address *ea;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received `%s' for peer `%s'\n",
             "ADDRESS IN USE",
             GNUNET_i2s (peer));
  if (GNUNET_NO == handle->running)
    return GNUNET_SYSERR;
  ea = find_exact_address (handle,
                           peer, plugin_name,
                           plugin_addr,
                           plugin_addr_len,
                           local_address_info,
                           session_id);
  if (NULL == ea)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Trying to set unknown address `%s' `%s' `%u' to %s \n",
                GNUNET_i2s (peer),
                plugin_name,
                session_id,
                (GNUNET_NO == in_use) ? "NO" : "YES");
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ea->used == in_use)
  {
    GNUNET_break (0);
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
               "Address in use called multiple times for peer `%s': %s -> %s \n",
               GNUNET_i2s (peer),
               (GNUNET_NO == ea->used) ? "NO" : "YES",
               (GNUNET_NO == in_use) ? "NO" : "YES");
    return GNUNET_SYSERR;
  }
  /* Tell solver about update */
  ea->used = in_use;
  ea->t_last_activity = GNUNET_TIME_absolute_get();
  handle->env.sf.s_address_update_inuse (handle->solver,
                                         ea,
                                         ea->used);
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
  struct GAS_Addresses_Suggestion_Requests *cur = handle->pending_requests_head;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received request: `%s' for peer %s\n",
      "request_address_cancel", GNUNET_i2s (peer));

  while (NULL != cur)
  {
    if (0 == memcmp (peer, &cur->id, sizeof(cur->id)))
      break; /* found */
    cur = cur->next;
  }

  if (NULL == cur)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "No address requests pending for peer `%s', cannot remove!\n",
        GNUNET_i2s (peer));
    return;
  }
  handle->env.sf.s_get_stop (handle->solver, peer);
  GAS_addresses_handle_backoff_reset (handle, peer);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Removed request pending for peer `%s\n",
      GNUNET_i2s (peer));
  GNUNET_CONTAINER_DLL_remove(handle->pending_requests_head, handle->pending_requests_tail, cur);
  GNUNET_free(cur);
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
  struct GAS_Addresses_Suggestion_Requests *cur = handle->pending_requests_head;
  struct ATS_Address *aa;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received `%s' for peer `%s'\n",
      "REQUEST ADDRESS", GNUNET_i2s (peer));

  if (GNUNET_NO == handle->running)
    return;
  while (NULL != cur)
  {
    if (0 == memcmp (peer, &cur->id, sizeof(cur->id)))
      break; /* already suggesting */
    cur = cur->next;
  }
  if (NULL == cur)
  {
    cur = GNUNET_new (struct GAS_Addresses_Suggestion_Requests);
    cur->id = (*peer);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Adding new address suggestion request for `%s'\n",
         GNUNET_i2s (peer));
    GNUNET_CONTAINER_DLL_insert(handle->pending_requests_head, handle->pending_requests_tail, cur);
  }

  /* Get prefered address from solver */
  aa = (struct ATS_Address *) handle->env.sf.s_get (handle->solver, peer);
  if (NULL == aa)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Cannot suggest address for peer `%s'\n",
        GNUNET_i2s (peer));
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Suggesting address %p for peer `%s'\n",
      aa, GNUNET_i2s (peer));

  GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr,
      aa->addr_len, aa->local_address_info, aa->session_id,
      aa->atsi, aa->atsi_count,
      aa->assigned_bw_out, aa->assigned_bw_in);

  aa->block_interval = GNUNET_TIME_relative_add (aa->block_interval,
      ATS_BLOCKING_DELTA);
  aa->blocked_until = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
      aa->block_interval);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Address %p ready for suggestion, block interval now %llu \n", aa,
      aa->block_interval);
}

/**
 * Iterator to reset address blocking
 *
 * @param cls not used
 * @param key the peer
 * @param value the address to reset
 * @return #GNUNET_OK to continue
 */
static int
reset_address_it (void *cls,
		  const struct GNUNET_PeerIdentity *key,
		  void *value)
{
  struct ATS_Address *aa = value;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	     "Resetting interval for peer `%s' address %p from %llu to 0\n",
	     GNUNET_i2s (&aa->peer),
	     aa,
	     aa->block_interval);
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
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received `%s' for peer `%s'\n",
      "RESET BACKOFF", GNUNET_i2s (peer));

  GNUNET_break(
      GNUNET_SYSERR != GNUNET_CONTAINER_multipeermap_get_multiple (handle->addresses,
								   peer,
								   &reset_address_it, NULL));
}


/**
 * Solver information callback
 *
 * @param cls the closure
 * @param op the operation
 * @param stat operation status
 * @param add additional information
 */

static void
solver_info_cb (void *cls,
    enum GAS_Solver_Operation op,
    enum GAS_Solver_Status stat,
    enum GAS_Solver_Additional_Information add)
{
  char *add_info;

  switch (add) {
    case GAS_INFO_NONE:
      add_info = "GAS_INFO_NONE";
      break;
    case GAS_INFO_FULL:
      add_info = "GAS_INFO_MLP_FULL";
      break;
    case GAS_INFO_UPDATED:
      add_info = "GAS_INFO_MLP_UPDATED";
      break;
    case GAS_INFO_PROP_ALL:
      add_info = "GAS_INFO_PROP_ALL";
      break;
    case GAS_INFO_PROP_SINGLE:
      add_info = "GAS_INFO_PROP_SINGLE";
      break;
    default:
      add_info = "INVALID";
      break;
  }
  switch (op)
  {
    case GAS_OP_SOLVE_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s' `%s'\n", "GAS_OP_SOLVE_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      return;
    case GAS_OP_SOLVE_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL", add_info);
      return;

    case GAS_OP_SOLVE_SETUP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_SETUP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_LP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_LP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;

    case GAS_OP_SOLVE_MLP_MLP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_MLP_MLP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_START:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    case GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      return;
    default:
      break;
    }
}


/**
 * The preference changed for a peer
 *
 * @param cls the address handle
 * @param peer the peer
 * @param kind the ATS kind
 * @param pref_rel the new relative preference value
 */
static void
normalized_preference_changed_cb (void *cls,
    const struct GNUNET_PeerIdentity *peer, enum GNUNET_ATS_PreferenceKind kind,
    double pref_rel)
{
  GNUNET_assert(NULL != cls);
  struct GAS_Addresses_Handle *handle = cls;

  /* Tell solver about update */
  handle->env.sf.s_pref (handle->solver, peer, kind, pref_rel);
}

/**
 * The relative value for a property changed
 *
 * @param cls the address handle
 * @param address the peer
 * @param type the ATS type
 * @param prop_rel the new relative preference value
 */
static void
normalized_property_changed_cb (void *cls, struct ATS_Address *address,
    uint32_t type, double prop_rel)
{
  struct GAS_Addresses_Handle *ah = (struct GAS_Addresses_Handle *) cls;
  GNUNET_assert(NULL != ah);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Normalized property %s for peer `%s' changed to %.3f \n",
      GNUNET_ATS_print_property_type (type), GNUNET_i2s (&address->peer),
      prop_rel);

  ah->env.sf.s_address_update_property (ah->solver, address, type, 0, prop_rel);
}

static struct GAS_Addresses_Preference_Clients *
find_preference_client (struct GAS_Addresses_Handle *handle, void *client)
{
  struct GAS_Addresses_Preference_Clients *cur;

  for (cur = handle->preference_clients_head; NULL != cur; cur = cur->next)
  {
    if (cur->client == client)
      return cur;
  }
  return NULL;
}

/**
 * A performance client disconnected
 *
 * @param handle address handle
 * @param client the client
 */

void
GAS_addresses_preference_client_disconnect (struct GAS_Addresses_Handle *handle,
    void *client)
{
  struct GAS_Addresses_Preference_Clients * pc;
  if (NULL != (pc = find_preference_client (handle, client)))
  {
    GNUNET_CONTAINER_DLL_remove (handle->preference_clients_head,
        handle->preference_clients_tail, pc);
    GNUNET_free (pc);
    GNUNET_assert (handle->pref_clients > 0);
    handle->pref_clients --;
    GNUNET_STATISTICS_set (handle->stat, "# active performance clients", handle->pref_clients, GNUNET_NO);
  }
  GAS_normalization_preference_client_disconnect (client);
}

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
GAS_addresses_preference_change (struct GAS_Addresses_Handle *handle,
    void *client, const struct GNUNET_PeerIdentity *peer,
    enum GNUNET_ATS_PreferenceKind kind, float score_abs)
{
  struct GAS_Addresses_Preference_Clients * pc;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Received `%s' for peer `%s' for client %p\n", "CHANGE PREFERENCE",
      GNUNET_i2s (peer), client);

  if (GNUNET_NO == handle->running)
    return;

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (handle->addresses,
					      peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Received `%s' for unknown peer `%s' from client %p\n",
        "CHANGE PREFERENCE", GNUNET_i2s (peer), client);
    return;
  }

  if (NULL == find_preference_client (handle, client))
  {
    pc = GNUNET_new (struct GAS_Addresses_Preference_Clients);
    pc->client = client;
    GNUNET_CONTAINER_DLL_insert (handle->preference_clients_head,
        handle->preference_clients_tail, pc);
    handle->pref_clients ++;
    GNUNET_STATISTICS_set (handle->stat, "# active performance clients", handle->pref_clients, GNUNET_NO);
  }

  handle->env.sf.s_bulk_start (handle->solver);
  /* Tell normalization about change, normalization will call callback if preference changed */
  GAS_normalization_normalize_preference (client, peer, kind, score_abs);
  handle->env.sf.s_bulk_stop (handle->solver);
}

/**
 * Change the preference for a peer
 *
 * @param handle the address handle
 * @param application the client sending this request
 * @param peer the peer id
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
void
GAS_addresses_preference_feedback (struct GAS_Addresses_Handle *handle,
    void *application, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_TIME_Relative scope,
    enum GNUNET_ATS_PreferenceKind kind, float score_abs)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Received `%s' for peer `%s' for client %p\n", "PREFERENCE FEEDBACK",
      GNUNET_i2s (peer), application);

  if (GNUNET_NO == handle->running)
    return;

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (handle->addresses,
					      peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Received `%s' for unknown peer `%s' from client %p\n",
        "PREFERENCE FEEDBACK", GNUNET_i2s (peer), application);
    return;
  }

  handle->env.sf.s_feedback (handle->solver, application, peer, scope, kind,
      score_abs);
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
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg,
    unsigned long long *out_dest, unsigned long long *in_dest, int dest_length)
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
    if (GNUNET_OK
        == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", entry_out,
            &quota_out_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp (quota_out_str, GNUNET_ATS_MaxBandwidthString))
      {
        out_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str,
                  &out_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_out,
                  &out_dest[c])))
        res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
            network_str[c], quota_out_str, GNUNET_ATS_DefaultBandwidth);
        out_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            _("Outbound quota configure for network `%s' is %llu\n"),
            network_str[c], out_dest[c]);
      }
      GNUNET_free(quota_out_str);
    }
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("No outbound quota configured for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }

    /* quota in */
    if (GNUNET_OK
        == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", entry_in,
            &quota_in_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp (quota_in_str, GNUNET_ATS_MaxBandwidthString))
      {
        in_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res)
          && (GNUNET_OK
              == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_in,
                  &in_dest[c])))
        res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
            network_str[c], quota_in_str, GNUNET_ATS_DefaultBandwidth);
        in_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            _("Inbound quota configured for network `%s' is %llu\n"),
            network_str[c], in_dest[c]);
      }
      GNUNET_free(quota_in_str);
    }
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("No outbound quota configure for network `%s', assigning default bandwidth %llu\n"),
          network_str[c], GNUNET_ATS_DefaultBandwidth);
      in_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Loaded quota for network `%s' (in/out): %llu %llu\n", network_str[c],
        in_dest[c], out_dest[c]);
    GNUNET_free(entry_out);
    GNUNET_free(entry_in);
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
bandwidth_changed_cb (void *cls,
                      struct ATS_Address *address)
{
  struct GAS_Addresses_Handle *handle = cls;
  struct GAS_Addresses_Suggestion_Requests *cur;

  GNUNET_assert(handle != NULL);
  GNUNET_assert(address != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bandwidth assignment changed for peer %s \n",
              GNUNET_i2s (&address->peer));

  /* Notify performance clients about changes to address */
  GAS_performance_notify_all_clients (&address->peer,
                                      address->plugin,
                                      address->addr,
                                      address->addr_len,
                                      address->active,
                                      address->atsi,
                                      address->atsi_count,
                                      address->assigned_bw_out,
                                      address->assigned_bw_in);
  cur = handle->pending_requests_head;
  while (NULL != cur)
  {
    if (0 == memcmp (&address->peer, &cur->id, sizeof(cur->id)))
      break; /* we have an address request pending*/
    cur = cur->next;
  }
  if (NULL == cur)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Nobody is interested in peer `%s' :(\n",
               GNUNET_i2s (&address->peer));
    return;
  }

  if ((0 == ntohl (address->assigned_bw_in.value__))
      && (0 == ntohl (address->assigned_bw_out.value__)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
               "Telling transport to disconnect peer `%s'\n",
                GNUNET_i2s (&address->peer));
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Sending bandwidth update for peer `%s': %u %u\n",
               GNUNET_i2s (&address->peer),
               (unsigned int) ntohl (address->assigned_bw_out.value__),
               (unsigned int) ntohl (address->assigned_bw_out.value__));
  }

  /* *Notify scheduling clients about suggestion */
  GAS_scheduling_transmit_address_suggestion (&address->peer, address->plugin,
      address->addr, address->addr_len, address->local_address_info,
      address->session_id, address->atsi,
      address->atsi_count, address->assigned_bw_out, address->assigned_bw_in);
}


/**
 * Initialize address subsystem. The addresses subsystem manages the addresses
 * known and current performance information. It has a solver component
 * responsible for the resource allocation. It tells the solver about changes
 * and receives updates when the solver changes the resource allocation.
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
  unsigned long long quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long quotas_out[GNUNET_ATS_NetworkTypeCount];
  char *mode_str;
  char *plugin_short;
  int c;

  ah = GNUNET_new (struct GAS_Addresses_Handle);
  ah->running = GNUNET_NO;

  ah->stat = (struct GNUNET_STATISTICS_Handle *) stats;
  /* Initialize the addresses database */
  ah->addresses = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  ah->pref_clients = 0;
  GNUNET_assert(NULL != ah->addresses);

  /* Figure out configured solution method */
  if (GNUNET_SYSERR
      == GNUNET_CONFIGURATION_get_value_string (cfg, "ats", "MODE", &mode_str))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
        "No resource assignment method configured, using proportional approach\n");
    ah->ats_mode = MODE_PROPORTIONAL;
  }
  else
  {
    for (c = 0; c < strlen (mode_str); c++)
      mode_str[c] = toupper (mode_str[c]);
    if (0 == strcmp (mode_str, "PROPORTIONAL"))
      ah->ats_mode = MODE_PROPORTIONAL;
    else if (0 == strcmp (mode_str, "MLP"))
    {
      ah->ats_mode = MODE_MLP;
#if !HAVE_LIBGLPK
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          "Assignment method `%s' configured, but GLPK is not available, please install \n",
          mode_str);
      ah->ats_mode = MODE_PROPORTIONAL;
#endif
    }
    else if (0 == strcmp (mode_str, "RIL"))
      ah->ats_mode = MODE_RIL;
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          "Invalid resource assignment method `%s' configured, using proportional approach\n",
          mode_str);
      ah->ats_mode = MODE_PROPORTIONAL;
    }
    GNUNET_free(mode_str);
  }

  load_quotas (cfg, quotas_out, quotas_in, GNUNET_ATS_NetworkTypeCount);
  ah->env.info_cb = &solver_info_cb;
  ah->env.info_cb_cls = ah;
  ah->env.bandwidth_changed_cb = &bandwidth_changed_cb;
  ah->env.bw_changed_cb_cls = ah;
  ah->env.get_preferences = &get_preferences_cb;
  ah->env.get_preference_cls = ah;
  ah->env.get_property = &get_property_cb;
  ah->env.get_property_cls = ah;
  ah->env.cfg = cfg;
  ah->env.stats = stats;
  ah->env.addresses = ah->addresses;

  ah->env.network_count = GNUNET_ATS_NetworkTypeCount;
  int networks[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    ah->env.networks[c] = networks[c];
    ah->env.out_quota[c] = quotas_out[c];
    ah->env.in_quota[c] = quotas_in[c];
  }

  switch (ah->ats_mode) {
    case MODE_PROPORTIONAL:
      plugin_short = "proportional";
      break;
    case MODE_MLP:
      plugin_short = "mlp";
      break;
    case MODE_RIL:
      plugin_short = "ril";
      break;
    default:
      plugin_short = NULL;
      break;
  }
  GNUNET_asprintf (&ah->plugin, "libgnunet_plugin_ats_%s", plugin_short);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initializing solver `%s '`%s'\n"), plugin_short, ah->plugin);
  if  (NULL == (ah->solver = GNUNET_PLUGIN_load (ah->plugin, &ah->env)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to initialize solver `%s'!\n"), ah->plugin);
    return NULL;
  }

  GNUNET_assert (NULL != ah->env.sf.s_add);
  GNUNET_assert (NULL != ah->env.sf.s_address_update_inuse);
  GNUNET_assert (NULL != ah->env.sf.s_address_update_property);
  GNUNET_assert (NULL != ah->env.sf.s_address_update_session);
  GNUNET_assert (NULL != ah->env.sf.s_address_update_network);
  GNUNET_assert (NULL != ah->env.sf.s_get);
  GNUNET_assert (NULL != ah->env.sf.s_get_stop);
  GNUNET_assert (NULL != ah->env.sf.s_pref);
  GNUNET_assert (NULL != ah->env.sf.s_feedback);
  GNUNET_assert (NULL != ah->env.sf.s_del);
  GNUNET_assert (NULL != ah->env.sf.s_bulk_start);
  GNUNET_assert (NULL != ah->env.sf.s_bulk_stop);


  GAS_normalization_start (&normalized_preference_changed_cb, ah,
      &normalized_property_changed_cb, ah);

  if (NULL == ah->solver)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to initialize solver!\n"));
    GNUNET_free(ah);
    return NULL ;
  }
  /* up and running */
  ah->running = GNUNET_YES;

  GNUNET_STATISTICS_set (ah->stat, "# addresses",
      GNUNET_CONTAINER_multipeermap_size (ah->addresses), GNUNET_NO);

  return ah;
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
  struct GAS_Addresses_Handle *handle = cls;
  struct ATS_Address *aa = value;

  /* Remove */
  GNUNET_assert(GNUNET_YES ==
		GNUNET_CONTAINER_multipeermap_remove (handle->addresses, key, value));
  /* Notify */
  handle->env.sf.s_del (handle->solver, aa, GNUNET_NO);
  /* Destroy */
  free_address (aa);

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

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Destroying all addresses\n");
  handle->env.sf.s_bulk_start (handle->solver);
  if (handle->addresses != NULL )
    GNUNET_CONTAINER_multipeermap_iterate (handle->addresses,
					   &destroy_all_address_it,
					   handle);
  handle->env.sf.s_bulk_start (handle->solver);
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
  struct GAS_Addresses_Preference_Clients *pcur;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Shutting down addresses\n");
  GNUNET_assert(NULL != handle);
  GAS_addresses_destroy_all (handle);
  handle->running = GNUNET_NO;
  GNUNET_CONTAINER_multipeermap_destroy (handle->addresses);
  handle->addresses = NULL;
  while (NULL != (cur = handle->pending_requests_head))
  {
    GNUNET_CONTAINER_DLL_remove(handle->pending_requests_head, handle->pending_requests_tail, cur);
    GNUNET_free(cur);
  }

  while (NULL != (pcur = handle->preference_clients_head))
  {
    GNUNET_CONTAINER_DLL_remove (handle->preference_clients_head,
        handle->preference_clients_tail, pcur);
    GNUNET_assert (handle->pref_clients > 0);
    handle->pref_clients --;
    GNUNET_STATISTICS_set (handle->stat, "# active performance clients", handle->pref_clients, GNUNET_NO);
    GNUNET_free (pcur);
  }

  GNUNET_PLUGIN_unload (handle->plugin, handle->solver);
  GNUNET_free (handle->plugin);
  GNUNET_free(handle);
  /* Stop configured solution method */
  GAS_normalization_stop ();
}


struct PeerIteratorContext
{
  GNUNET_ATS_Peer_Iterator it;
  void *it_cls;
  struct GNUNET_CONTAINER_MultiPeerMap *peers_returned;
};


/**
 * Iterator to iterate over all peers
 *
 * @param cls a PeerIteratorContext
 * @param key the peer id
 * @param value the ATS_address
 * @return #GNUNET_OK to continue
 */
static int
peer_it (void *cls,
	 const struct GNUNET_PeerIdentity *key,
	 void *value)
{
  struct PeerIteratorContext *ip_ctx = cls;

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (ip_ctx->peers_returned, key))
  {
    GNUNET_CONTAINER_multipeermap_put (ip_ctx->peers_returned, key, NULL,
				       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    ip_ctx->it (ip_ctx->it_cls, key);
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
    GNUNET_ATS_Peer_Iterator p_it, void *p_it_cls)
{
  struct PeerIteratorContext ip_ctx;
  unsigned int size;

  if (NULL == p_it)
    return;
  GNUNET_assert(NULL != handle->addresses);

  size = GNUNET_CONTAINER_multipeermap_size (handle->addresses);
  if (0 != size)
  {
    ip_ctx.it = p_it;
    ip_ctx.it_cls = p_it_cls;
    ip_ctx.peers_returned = GNUNET_CONTAINER_multipeermap_create (size,
								  GNUNET_NO);
    GNUNET_CONTAINER_multipeermap_iterate (handle->addresses,
					   &peer_it,
					   &ip_ctx);
    GNUNET_CONTAINER_multipeermap_destroy (ip_ctx.peers_returned);
  }
  p_it (p_it_cls, NULL );
}

struct PeerInfoIteratorContext
{
  GNUNET_ATS_PeerInfo_Iterator it;
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

  if (NULL != pi_ctx->it)
  {
    pi_ctx->it (pi_ctx->it_cls, &addr->peer, addr->plugin, addr->addr,
        addr->addr_len, addr->active, addr->atsi, addr->atsi_count,
        addr->assigned_bw_out, addr->assigned_bw_in);
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
    const struct GNUNET_PeerIdentity *peer, GNUNET_ATS_PeerInfo_Iterator pi_it,
    void *pi_it_cls)
{
  struct PeerInfoIteratorContext pi_ctx;
  struct GNUNET_BANDWIDTH_Value32NBO zero_bw;

  GNUNET_assert(NULL != peer);
  GNUNET_assert(NULL != handle->addresses);
  if (NULL == pi_it)
    return; /* does not make sense without callback */

  zero_bw = GNUNET_BANDWIDTH_value_init (0);
  pi_ctx.it = pi_it;
  pi_ctx.it_cls = pi_it_cls;

  GNUNET_CONTAINER_multipeermap_get_multiple (handle->addresses,
					      peer,
					      &peerinfo_it, &pi_ctx);

  if (NULL != pi_it)
    pi_it (pi_it_cls, NULL, NULL, NULL, 0, GNUNET_NO, NULL, 0, zero_bw,
        zero_bw);

}

/* end of gnunet-service-ats_addresses.c */
