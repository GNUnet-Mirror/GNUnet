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
 */
#include "platform.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_scheduling.h"
#include "ats.h"


struct SchedulingClient
{
  struct SchedulingClient * next;

  struct SchedulingClient * prev;

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


static struct SchedulingClient * 
find_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient * sc;

  for (sc = sc_head; sc != NULL; sc = sc->next)
    if (sc->client == client)
      return sc;
  return NULL;
}


void
GAS_add_scheduling_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient *sc;

  GNUNET_break (NULL == find_client (client));
  sc = GNUNET_malloc (sizeof (struct SchedulingClient));
  sc->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert(sc_head, sc_tail, sc);
}


void
GAS_remove_scheduling_client (struct GNUNET_SERVER_Client *client)
{
  struct SchedulingClient * sc;

  sc = find_client (client);
  if (NULL == sc)
    return;
  GNUNET_CONTAINER_DLL_remove (sc_head, sc_tail, sc);
  GNUNET_SERVER_client_drop (client);
  GNUNET_free (sc);
}


void
GAS_handle_request_address (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct RequestAddressMessage * msg = (struct RequestAddressMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "REQUEST_ADDRESS");

}


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
  plugin_name = &address[address_length];
  if ( (address_length +
	plugin_name_length +
	ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) +
	sizeof (struct AddressSuggestionMessage) != ntohs (message->size))  ||
       (ats_count > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_TRANSPORT_ATS_Information)) ||
       (plugin_name[plugin_name_length - 1] != '\0') )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GAS_address_update (client,
		      &m->peer,
		      plugin_name,
		      address,
		      address_length,
		      ntohl (m->session_id),
		      atsi,
		      ats_count);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


void
GAS_handle_address_destroyed (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ADDRESS_DESTROYED");
}

/* end of gnunet-service-ats_scheduling.c */
