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
 * @file ats/gnunet-service-ats_scheduling.c
 * @brief ats service, interaction with 'scheduling' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_scheduling.h"
#include "ats.h"


/**
 * We keep clients that are interested in scheduling in a linked list.
 * This list typically has only one entry (for the
 * gnunet-service-transport process); however, it is possible that
 * there is more than one (at least briefly) because after a crash a
 * new one may connect before we've been notified to clean up the old
 * process.
 */
struct SchedulingClient
{
  /**
   * Next in doubly-linked list.
   */
  struct SchedulingClient * next;

  /**
   * Previous in doubly-linked list.
   */
  struct SchedulingClient * prev;

  /**
   * Actual handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

};


/**
 * Head of linked list of all clients to this service.
 */
static struct SchedulingClient *sc_head;

/**
 * Tail of linked list of all clients to this service.
 */
static struct SchedulingClient *sc_tail;

/**
 * Context for sending messages to clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

static unsigned long long total_quota_in;

static unsigned long long total_quota_out;


/**
 * Find the scheduling client associated with the given
 * handle.
 *
 * @param client server handle
 * @return internal handle
 */
static struct SchedulingClient * 
find_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient * sc;

  for (sc = sc_head; sc != NULL; sc = sc->next)
    if (sc->client == client)
      return sc;
  return NULL;
}


/**
 * Register a new scheduling client.
 *
 * @param client handle of the new client
 */
void
GAS_scheduling_add_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient *sc;

  GNUNET_break (NULL == find_client (client));
  sc = GNUNET_malloc (sizeof (struct SchedulingClient));
  sc->client = client;
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert(sc_head, sc_tail, sc);
}



/**
 * Unregister a client (which may have been a scheduling client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_scheduling_remove_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient * sc;

  sc = find_client (client);
  if (NULL == sc)
    return;
  GNUNET_CONTAINER_DLL_remove (sc_head, sc_tail, sc);
  GAS_address_client_disconnected (client);
  GNUNET_SERVER_client_drop (client);
  GNUNET_free (sc);
}


/**
 * Transmit the given address suggestion and bandwidth update to all scheduling
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session_client which client gave us this session_id?
 * @param session_id session ID to use for the given client (other clients will see 0)
 * @param atsi performance data for the address
 * @param atsi_count number of performance records in 'ats'
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_scheduling_transmit_address_suggestion (const struct GNUNET_PeerIdentity *peer,
					    const char *plugin_name,
					    const void *plugin_addr, size_t plugin_addr_len,
					    struct GNUNET_SERVER_Client *session_client,
					    uint32_t session_id,
					    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
					    uint32_t atsi_count,				
					    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
					    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct SchedulingClient *sc;
  struct AddressSuggestionMessage *msg;
  size_t plugin_name_length = strlen (plugin_name) + 1;
  size_t msize = sizeof (struct AddressSuggestionMessage) + atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) 
    + plugin_addr_len + plugin_name_length;
  char buf[msize];
  struct GNUNET_TRANSPORT_ATS_Information *atsp;
  char *addrp;

  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (atsi_count < GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  msg = (struct AddressSuggestionMessage*) buf;
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION);
  msg->ats_count = htonl (atsi_count);
  msg->peer = *peer;
  msg->address_length = htons (plugin_addr_len);
  msg->plugin_name_length = htons (plugin_name_length);
  /* session ID is set only if 'client' is the same... */
  msg->bandwidth_out = bandwidth_out;
  msg->bandwidth_in = bandwidth_in;
  atsp = (struct GNUNET_TRANSPORT_ATS_Information* ) &msg[1];
  memcpy (atsp, atsi, sizeof (struct GNUNET_TRANSPORT_ATS_Information) * atsi_count);
  addrp = (char*) &atsp[atsi_count];
  memcpy (addrp, plugin_addr, plugin_addr_len);
  strcpy (&addrp[plugin_addr_len], plugin_name);
  for (sc = sc_head; sc != NULL; sc = sc->next)
  {
    if (sc->client == session_client)
      msg->session_id = htonl (session_id);
    else
      msg->session_id = htonl (0);
    GNUNET_SERVER_notification_context_unicast (nc,
						sc->client,
						&msg->header,
						GNUNET_YES);
  } 
}


/**
 * Handle 'request address' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address (void *cls, struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)

{
  const struct RequestAddressMessage * msg = (const struct RequestAddressMessage *) message;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "REQUEST_ADDRESS");
  GNUNET_break (0 == ntohl (msg->reserved));
  GAS_addresses_request_address (&msg->peer);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle 'address update' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_update (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  const struct AddressUpdateMessage * m;
  const struct GNUNET_TRANSPORT_ATS_Information *atsi;
  const char *address;
  const char *plugin_name;
  uint16_t address_length;
  uint16_t plugin_name_length;
  uint32_t ats_count;
  uint16_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "ADDRESS_UPDATE");
  size = ntohs (message->size);
  if (size <= sizeof (struct AddressUpdateMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  m = (const struct AddressUpdateMessage*) message;
  ats_count = ntohl (m->ats_count);
  address_length = ntohs (m->address_length);
  plugin_name_length = ntohs (m->plugin_name_length);  
  atsi = (const struct GNUNET_TRANSPORT_ATS_Information*) &m[1];
  address = (const char*) &atsi[ats_count];
  if (plugin_name_length != 0)
    plugin_name = &address[address_length];
  else
    plugin_name = "";
  if ( (address_length +
	plugin_name_length +
	ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) +
	sizeof (struct AddressUpdateMessage) != ntohs (message->size))  ||
       (ats_count > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_TRANSPORT_ATS_Information)) ||
       (plugin_name[plugin_name_length - 1] != '\0') )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GAS_address_update (&m->peer,
		      plugin_name,
		      address,
		      address_length,
		      client,
		      ntohl (m->session_id),
		      atsi,
		      ats_count);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle 'address destroyed' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_destroyed (void *cls, struct GNUNET_SERVER_Client *client,
			      const struct GNUNET_MessageHeader *message)

{
  const struct AddressDestroyedMessage * m;
  const char *address;
  const char *plugin_name;
  uint16_t address_length;
  uint16_t plugin_name_length;
  uint16_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message of size %u %u\n",
	      "ADDRESS_DESTROYED", ntohs (message->size), sizeof (struct AddressDestroyedMessage));
  size = ntohs (message->size);
  if (size < sizeof (struct AddressDestroyedMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  m = (const struct AddressDestroyedMessage*) message;
  GNUNET_break (0 == ntohl (m->reserved));
  address_length = ntohs (m->address_length);
  plugin_name_length = ntohs (m->plugin_name_length);  
  address = (const char*) &m[1];
  if (plugin_name_length != 0)
    plugin_name = &address[address_length];
  else
    plugin_name = "";

  if ( (address_length +
	plugin_name_length +
	sizeof (struct AddressDestroyedMessage) != ntohs (message->size)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  if (plugin_name_length != 0)
    if (plugin_name[plugin_name_length - 1] != '\0')
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }

  GAS_address_destroyed (&m->peer,
			 plugin_name,
			 address,
			 address_length,
			 client,
			 ntohl (m->session_id));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Initialize scheduling subsystem.
 *
 * @param server handle to our server
 * @param cfg configuration to use
 */
void
GAS_scheduling_init (struct GNUNET_SERVER_Handle *server,
		     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_get_value_number (cfg,
							"core",
							"TOTAL_QUOTA_IN",
							&total_quota_in));
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_get_value_number (cfg,
							"core",
							"TOTAL_QUOTA_OUT",
							&total_quota_out));
  nc = GNUNET_SERVER_notification_context_create (server, 128);
}


/**
 * Shutdown scheduling subsystem.
 */
void
GAS_scheduling_done ()
{
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
}


/* end of gnunet-service-ats_scheduling.c */
