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
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */

/**
 * @file ats/gnunet-service-ats_addresses.c
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_plugins.h"


/**
 * A multihashmap to store all addresses
 */
struct GNUNET_CONTAINER_MultiPeerMap *GSA_addresses;


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
 * Free the given address
 *
 * @param addr address to destroy
 */
static void
free_address (struct ATS_Address *addr)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (GSA_addresses,
                                                       &addr->peer,
                                                       addr));
  update_addresses_stat ();
  GAS_plugin_delete_address (addr);
  GAS_performance_notify_all_clients (&addr->peer,
                                      addr->plugin,
                                      addr->addr,
                                      addr->addr_len,
                                      GNUNET_NO,
                                      NULL,
                                      addr->local_address_info,
                                      GNUNET_BANDWIDTH_ZERO,
                                      GNUNET_BANDWIDTH_ZERO);
  GNUNET_free (addr->plugin);
  GNUNET_free (addr);
}


/**
 * Initialize @a norm.  Sets all historic values to undefined.
 *
 * @param norm normalization data to initialize
 */
static void
init_norm (struct GAS_NormalizationInfo *norm)
{
  unsigned int c;

  for (c = 0; c < GAS_normalization_queue_length; c++)
    norm->atsi_abs[c] = UINT64_MAX;
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
  init_norm (&aa->norm_delay);
  init_norm (&aa->norm_distance);
  init_norm (&aa->norm_utilization_in);
  init_norm (&aa->norm_utilization_out);
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
 * Add a new address for a peer.
 *
 * @param peer peer
 * @param plugin_name transport plugin name
 * @param plugin_addr plugin address
 * @param plugin_addr_len length of the plugin address in @a plugin_addr
 * @param local_address_info the local address for the address
 * @param session_id session id, can be 0
 * @param prop performance information for this address
 */
void
GAS_addresses_add (const struct GNUNET_PeerIdentity *peer,
                   const char *plugin_name,
                   const void *plugin_addr,
                   size_t plugin_addr_len,
                   uint32_t local_address_info,
                   uint32_t session_id,
                   const struct GNUNET_ATS_Properties *prop)
{
  struct ATS_Address *new_address;

  if (NULL != find_exact_address (peer,
                                  session_id))
  {
    GNUNET_break (0);
    return;
  }
  new_address = create_address (peer,
                                plugin_name,
                                plugin_addr,
                                plugin_addr_len,
                                local_address_info,
                                session_id);
  /* Add a new address */
  new_address->properties = *prop;
  new_address->t_added = GNUNET_TIME_absolute_get();
  new_address->t_last_activity = GNUNET_TIME_absolute_get();
  GNUNET_assert(GNUNET_OK ==
		GNUNET_CONTAINER_multipeermap_put (GSA_addresses,
						   peer,
						   new_address,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  update_addresses_stat ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Adding new address for peer `%s' slot %u\n",
	      GNUNET_i2s (peer),
	      session_id);
  /* Tell solver about new address */
  GAS_plugin_solver_lock ();
  GAS_plugin_new_address (new_address);
  GAS_normalization_update_property (new_address); // FIXME: needed?
  GAS_plugin_solver_unlock ();
  /* Notify performance clients about new address */
  GAS_performance_notify_all_clients (&new_address->peer,
				      new_address->plugin,
				      new_address->addr,
				      new_address->addr_len,
				      new_address->active,
				      &new_address->properties,
                                      new_address->local_address_info,
				      GNUNET_BANDWIDTH_value_init (new_address->assigned_bw_out),
				      GNUNET_BANDWIDTH_value_init (new_address->assigned_bw_in));
}


/**
 * Update an address with new performance information for a peer.
 *
 * @param peer peer
 * @param session_id session id, never 0
 * @param prop performance information for this address
 */
void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      uint32_t session_id,
                      const struct GNUNET_ATS_Properties *prop)
{
  struct ATS_Address *aa;

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
              "Received ADDRESS_UPDATE for peer `%s' slot %u\n",
              GNUNET_i2s (peer),
              (unsigned int) session_id);

  /* Update address */
  aa->t_last_activity = GNUNET_TIME_absolute_get();
  aa->properties = *prop;
  /* Notify performance clients about updated address */
  GAS_performance_notify_all_clients (&aa->peer,
                                      aa->plugin,
                                      aa->addr,
                                      aa->addr_len,
                                      aa->active,
                                      prop,
                                      aa->local_address_info,
                                      GNUNET_BANDWIDTH_value_init (aa->assigned_bw_out),
                                      GNUNET_BANDWIDTH_value_init (aa->assigned_bw_in));

  GAS_normalization_update_property (aa);
}


/**
 * Remove an address for a peer.
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
              "Received ADDRESS_DESTROYED for peer `%s' session %u\n",
              GNUNET_i2s (peer),
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
  if (0 ==
      GNUNET_CONTAINER_multipeermap_size (GSA_addresses))
    return;
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
              &addr->properties,
              addr->local_address_info,
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
         NULL,
         GNUNET_HELLO_ADDRESS_INFO_NONE,
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
 * @param prop performance information
 * @param local_address_info flags for the address
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
                   const struct GNUNET_ATS_Properties *prop,
                   enum GNUNET_HELLO_AddressInfo local_address_info,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)

{
  struct PeerInformationMessage *msg;
  char *addrp;
  size_t plugin_name_length;
  size_t msize;
  struct GNUNET_SERVER_NotificationContext **uc;
  struct GNUNET_SERVER_NotificationContext *nc;

  if (NULL != plugin_name)
    plugin_name_length = strlen (plugin_name) + 1;
  else
    plugin_name_length = 0;
  msize = sizeof (struct PeerInformationMessage) +
          plugin_addr_len + plugin_name_length;
  char buf[msize] GNUNET_ALIGN;

  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  msg = (struct PeerInformationMessage *) buf;
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE);
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
  if (NULL != prop)
    GNUNET_ATS_properties_hton (&msg->properties,
                                prop);
  else
    memset (&msg->properties,
            0,
            sizeof (struct GNUNET_ATS_Properties));
  msg->address_local_info = htonl ((uint32_t) local_address_info);
  addrp = (char *) &msg[1];
  if (NULL != plugin_addr)
    memcpy (addrp, plugin_addr, plugin_addr_len);
  if (NULL != plugin_name)
    strcpy (&addrp[plugin_addr_len], plugin_name);
  uc = GNUNET_SERVER_client_get_user_context (ai->client,
                                              struct GNUNET_SERVER_NotificationContext *);
  if (NULL == uc)
  {
    GNUNET_break (0);
    return;
  }
  nc = *uc;
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
 * @param prop performance information
 * @param local_address_info additional local info for the address
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
                      const struct GNUNET_ATS_Properties *prop,
                      enum GNUNET_HELLO_AddressInfo local_address_info,
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
                     prop,
                     local_address_info,
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
                     NULL,
                     GNUNET_HELLO_ADDRESS_INFO_NONE,
                     GNUNET_BANDWIDTH_ZERO,
                     GNUNET_BANDWIDTH_ZERO);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}



/* end of gnunet-service-ats_addresses.c */
