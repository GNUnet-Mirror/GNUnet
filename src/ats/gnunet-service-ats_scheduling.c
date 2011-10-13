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
#if 0
  struct AddressUpdateMessage * msg = (struct AddressUpdateMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ADDRESS_UPDATE");

  struct GNUNET_TRANSPORT_ATS_Information *am;
  char *pm;

  size_t size = ntohs (msg->header.size);
  if ((size <= sizeof (struct AddressUpdateMessage)) || (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }

  size_t ats_count = ntohs (msg->ats_count);
  size_t addr_len = ntohs (msg->address_length);
  size_t plugin_len = ntohs (msg->plugin_name_length) + 1 ;

  if (
       (plugin_len  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (addr_len  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (addr_len >= GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_TRANSPORT_ATS_Information)) )
  {
    GNUNET_break (0);
    return;
  }

  struct ATS_Address * aa = GNUNET_malloc (sizeof (struct ATS_Address) +
                                           ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) +
                                           addr_len +
                                           plugin_len);



  memcpy (&aa->peer, &msg->peer, sizeof (struct GNUNET_PeerIdentity));
  aa->addr_len = addr_len;
  aa->ats_count = ats_count;
  aa->ats = (struct GNUNET_TRANSPORT_ATS_Information *) &aa[1];

  am = (struct GNUNET_TRANSPORT_ATS_Information*) &msg[1];
  memcpy (&aa->ats, am, ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  pm = (char *) &am[ats_count];
  memcpy (aa->addr, pm, addr_len);
  memcpy (aa->plugin, &pm[plugin_len], plugin_len);
  aa->session_id = ntohl(msg->session_id);

  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(addresses, &aa->peer.hashPubKey, aa, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
#endif
}


void
GAS_handle_address_destroyed (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
#if 0
  // struct AddressDestroyedMessage * msg = (struct AddressDestroyedMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ADDRESS_DESTROYED");
/*
  struct GNUNET_PeerIdentity *peer = &msg->peer;
  struct ATS_Address * aa = find_address_by_addr (peer);
  GNUNET_CONTAINER_multihashmap_remove(addresses, peer, aa);
  GNUNET_free (aa);*/
#endif
}

/* end of gnunet-service-ats_scheduling.c */
