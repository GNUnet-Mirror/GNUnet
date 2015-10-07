/*
     This file is part of GNUnet.
     Copyright (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * Context for sending messages to clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Actual handle to the client.
 */
static struct GNUNET_SERVER_Client *my_client;


/**
 * Register a new scheduling client.
 *
 * @param client handle of the new client
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GAS_scheduling_add_client (struct GNUNET_SERVER_Client *client)
{
  if (NULL != my_client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "This ATS already has a scheduling client, refusing new scheduling client for now.\n");
    return GNUNET_SYSERR;
  }
  my_client = client;
  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  GNUNET_SERVER_client_set_user_context (client,
                                         &nc);
  return GNUNET_OK;
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
  if (my_client != client)
    return;
  GAS_addresses_destroy_all ();
  my_client = NULL;
}


/**
 * Transmit the given address suggestion and bandwidth update to all scheduling
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param session_id session ID to use for the given client
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_scheduling_transmit_address_suggestion (const struct GNUNET_PeerIdentity *peer,
                                            uint32_t session_id,
                                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct AddressSuggestionMessage msg;

  if (NULL == my_client)
    return;
  GNUNET_STATISTICS_update (GSA_stats,
                            "# address suggestions made",
			    1,
                            GNUNET_NO);
  msg.header.size = htons (sizeof (struct AddressSuggestionMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION);
  msg.peer = *peer;
  msg.session_id = htonl (session_id);
  msg.bandwidth_out = bandwidth_out;
  msg.bandwidth_in = bandwidth_in;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS sends quota for peer `%s': (in/out) %u/%u\n",
              GNUNET_i2s (peer),
              (unsigned int) ntohl (bandwidth_in.value__),
              (unsigned int) ntohl (bandwidth_out.value__));
  GNUNET_SERVER_notification_context_unicast (nc,
                                              my_client,
                                              &msg.header,
                                              GNUNET_YES);
}


/**
 * Handle 'address add' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_add (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct AddressAddMessage *m;
  const char *address;
  const char *plugin_name;
  uint16_t address_length;
  uint16_t plugin_name_length;
  uint16_t size;
  struct GNUNET_ATS_Properties prop;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ADDRESS_ADD");
  size = ntohs (message->size);
  if (size < sizeof (struct AddressAddMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  m = (const struct AddressAddMessage *) message;
  address_length = ntohs (m->address_length);
  plugin_name_length = ntohs (m->plugin_name_length);
  address = (const char *) &m[1];
  if (plugin_name_length != 0)
    plugin_name = &address[address_length];
  else
    plugin_name = "";

  if ((address_length + plugin_name_length +
       sizeof (struct AddressAddMessage) != ntohs (message->size)) ||
       ( (plugin_name_length > 0) &&
         (plugin_name[plugin_name_length - 1] != '\0') ) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_STATISTICS_update (GSA_stats,
                            "# addresses created",
                            1,
                            GNUNET_NO);
  GNUNET_ATS_properties_ntoh (&prop,
                              &m->properties);
  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != prop.scope);
  GAS_addresses_add (&m->peer,
                     plugin_name,
                     address,
                     address_length,
                     ntohl (m->address_local_info),
                     ntohl (m->session_id),
                     &prop);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Handle 'address update' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_update (void *cls,
                           struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
  const struct AddressUpdateMessage *m;
  struct GNUNET_ATS_Properties prop;

  m = (const struct AddressUpdateMessage *) message;
  GNUNET_STATISTICS_update (GSA_stats,
                            "# address updates received",
                            1,
                            GNUNET_NO);
  GNUNET_ATS_properties_ntoh (&prop,
                              &m->properties);
  GAS_addresses_update (&m->peer,
                        ntohl (m->session_id),
                        &prop);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Handle 'address destroyed' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_destroyed (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct AddressDestroyedMessage *m;
  struct SessionReleaseMessage srm;

  m = (const struct AddressDestroyedMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ADDRESS_DESTROYED");
  GNUNET_STATISTICS_update (GSA_stats,
                            "# addresses destroyed",
                            1,
                            GNUNET_NO);
  GAS_addresses_destroy (&m->peer,
                         ntohl (m->session_id));
  srm.header.type = ntohs (GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE);
  srm.header.size = ntohs (sizeof (struct SessionReleaseMessage));
  srm.session_id = m->session_id;
  srm.peer = m->peer;
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &srm.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Initialize scheduling subsystem.
 *
 * @param server handle to our server
 * @param ah the address handle to use
 */
void
GAS_scheduling_init (struct GNUNET_SERVER_Handle *server)
{
  nc = GNUNET_SERVER_notification_context_create (server, 128);
}


/**
 * Shutdown scheduling subsystem.
 */
void
GAS_scheduling_done ()
{
  if (NULL != my_client)
  {
    my_client = NULL;
  }
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
}


/* end of gnunet-service-ats_scheduling.c */
