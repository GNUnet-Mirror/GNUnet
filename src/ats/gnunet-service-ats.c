/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats.c
 * @brief ats service
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_ats_service.h"
#include "ats.h"

struct ATS_Clients
{
  struct ATS_Clients * next;

  struct ATS_Clients * prev;

  struct GNUNET_SERVER_Client *client;

  uint32_t flags;
};

struct ATS_Address
{
  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  uint32_t session_id;

  uint32_t ats_count;

  void * addr;

  char * plugin;

  struct GNUNET_TRANSPORT_ATS_Information * ats;
};

/**
 * Head of linked list of all clients to this service.
 */
static struct ATS_Clients *ac_head;

/**
 * Tail of linked list of all clients to this service.
 */
static struct ATS_Clients *ac_tail;

static struct GNUNET_CONTAINER_MultiHashMap * addresses;

int free_address_it (void *cls,
               const GNUNET_HashCode * key,
               void *value)
{
  struct ATS_Address * aa = cls;
  GNUNET_free (aa);
  return GNUNET_OK;
}

struct CompareAddressContext
{
  struct ATS_Address * search;
  struct ATS_Address * result;
};

int compare_address_it (void *cls,
               const GNUNET_HashCode * key,
               void *value)
{
  struct CompareAddressContext * cac = cls;
  struct ATS_Address * aa = (struct ATS_Address *) value;
  if (0 == strcmp(aa->plugin, cac->search->plugin))
  {
    if ((aa->addr_len == cac->search->addr_len) &&
        (0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)))
      cac->result = aa;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ATS_Clients * t;

  while (ac_head != NULL)
  {
    t = ac_head;
    GNUNET_CONTAINER_DLL_remove(ac_head,ac_tail, t);
    GNUNET_free (t);
  }

  GNUNET_CONTAINER_multihashmap_iterate (addresses, free_address_it, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (addresses);
}

static struct ATS_Clients * find_client (struct GNUNET_SERVER_Client *client)
{
  struct ATS_Clients * ac = ac_head;
  while (ac != NULL)
  {
  if (ac->client == client)
    break;
  ac = ac->next;
  }
  return ac;
}

static void
handle_ats_start (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  struct ClientStartMessage * msg = (struct ClientStartMessage *) message;
  struct ATS_Clients * ac = NULL;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ATS_START");

  GNUNET_assert (find_client(client) == NULL);

  ac = GNUNET_malloc (sizeof (struct ATS_Clients));
  ac->client = client;
  ac->flags = ntohl (msg->start_flag);

  GNUNET_CONTAINER_DLL_insert(ac_head, ac_tail, ac);
}

static void
handle_request_address (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct RequestAddressMessage * msg = (struct RequestAddressMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "REQUEST_ADDRESS");

}

static void
handle_address_update (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
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
}

static void
handle_address_destroyed (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct AddressDestroyedMessage * msg = (struct AddressDestroyedMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ADDRESS_DESTROYED");
/*
  struct GNUNET_PeerIdentity *peer = &msg->peer;
  struct ATS_Address * aa = find_address_by_addr (peer);
  GNUNET_CONTAINER_multihashmap_remove(addresses, peer, aa);
  GNUNET_free (aa);*/
}

static void
handle_reservation_request (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct AddressUpdateMessage * msg = (struct AddressUpdateMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "RESERVATION_REQUEST");
}

static void
handle_preference_change (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct ChangePreferenceMessage * msg = (struct ChangePreferenceMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "PREFERENCE_CHANGE");
}

/**
 * Process template requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
      {&handle_ats_start, NULL, GNUNET_MESSAGE_TYPE_ATS_START, sizeof (struct ClientStartMessage)},
      {&handle_request_address, NULL, GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS, sizeof (struct RequestAddressMessage)},
      {&handle_address_update, NULL, GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE, 0},
      {&handle_address_destroyed, NULL, GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED, 0},
      {&handle_reservation_request, NULL, GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST, sizeof (struct ReservationRequestMessage)},
      {&handle_preference_change, NULL, GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE, 0},
    {NULL, NULL, 0, 0}
  };

  addresses = GNUNET_CONTAINER_multihashmap_create(100);

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the ats service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "ats",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-ats.c */
