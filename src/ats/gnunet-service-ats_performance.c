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
 * @file ats/gnunet-service-ats_performance.c
 * @brief ats service, interaction with 'performance' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_reservations.h"
#include "ats.h"


/**
 * We keep clients that are interested in performance in a linked list.
 */
struct PerformanceClient
{
  /**
   * Next in doubly-linked list.
   */
  struct PerformanceClient *next;

  /**
   * Previous in doubly-linked list.
   */
  struct PerformanceClient *prev;

  /**
   * Actual handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Options for the client.
   */
  enum StartFlag flag;

};


/**
 * Head of linked list of all clients to this service.
 */
static struct PerformanceClient *pc_head;

/**
 * Tail of linked list of all clients to this service.
 */
static struct PerformanceClient *pc_tail;

/**
 * Context for sending messages to performance clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;


/**
 * Find the performance client associated with the given handle.
 *
 * @param client server handle
 * @return internal handle
 */
static struct PerformanceClient *
find_client (struct GNUNET_SERVER_Client *client)
{
  struct PerformanceClient *pc;

  for (pc = pc_head; pc != NULL; pc = pc->next)
    if (pc->client == client)
      return pc;
  return NULL;
}


/**
 * Register a new performance client.
 *
 * @param client handle of the new client
 * @param flag flag specifying the type of the client
 */
void
GAS_performance_add_client (struct GNUNET_SERVER_Client *client,
                            enum StartFlag flag)
{
  struct PerformanceClient *pc;

  GNUNET_break (NULL == find_client (client));
  pc = GNUNET_malloc (sizeof (struct PerformanceClient));
  pc->client = client;
  pc->flag = flag;
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (pc_head, pc_tail, pc);
}


/**
 * Unregister a client (which may have been a performance client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_performance_remove_client (struct GNUNET_SERVER_Client *client)
{
  struct PerformanceClient *pc;

  pc = find_client (client);
  if (NULL == pc)
    return;
  GNUNET_CONTAINER_DLL_remove (pc_head, pc_tail, pc);
  GNUNET_SERVER_client_drop (client);
  GNUNET_free (pc);
}


/**
 * Transmit the given performance information to all performance
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param atsi performance data for the address
 * @param atsi_count number of performance records in 'ats'
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_performance_notify_clients (const struct GNUNET_PeerIdentity *peer,
                                const char *plugin_name,
                                const void *plugin_addr, size_t plugin_addr_len,
                                const struct GNUNET_ATS_Information *atsi,
                                uint32_t atsi_count,
                                struct GNUNET_BANDWIDTH_Value32NBO
                                bandwidth_out,
                                struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct PerformanceClient *pc;
  struct PeerInformationMessage *msg;
  size_t plugin_name_length = strlen (plugin_name) + 1;
  size_t msize =
      sizeof (struct PeerInformationMessage) +
      atsi_count * sizeof (struct GNUNET_ATS_Information) + plugin_addr_len +
      plugin_name_length;
  char buf[msize] GNUNET_ALIGN;
  struct GNUNET_ATS_Information *atsp;
  char *addrp;

  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (atsi_count <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE /
                 sizeof (struct GNUNET_ATS_Information));
  msg = (struct PeerInformationMessage *) buf;
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION);
  msg->ats_count = htonl (atsi_count);
  msg->peer = *peer;
  msg->address_length = htons (plugin_addr_len);
  msg->plugin_name_length = htons (plugin_name_length);
  msg->bandwidth_out = bandwidth_out;
  msg->bandwidth_in = bandwidth_in;
  atsp = (struct GNUNET_ATS_Information *) &msg[1];
  memcpy (atsp, atsi, sizeof (struct GNUNET_ATS_Information) * atsi_count);
  addrp = (char *) &atsp[atsi_count];
  memcpy (addrp, plugin_addr, plugin_addr_len);
  strcpy (&addrp[plugin_addr_len], plugin_name);
  for (pc = pc_head; pc != NULL; pc = pc->next)
    if (pc->flag == START_FLAG_PERFORMANCE_WITH_PIC)
    {
      GNUNET_SERVER_notification_context_unicast (nc, pc->client, &msg->header,
                                                  GNUNET_YES);
      GNUNET_STATISTICS_update (GSA_stats,
                                "# performance updates given to clients", 1,
                                GNUNET_NO);
    }
}


/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_reservation_request (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct ReservationRequestMessage *msg =
      (const struct ReservationRequestMessage *) message;
  struct ReservationResultMessage result;
  int32_t amount;
  struct GNUNET_TIME_Relative res_delay;

  if (NULL == find_client (client))
  {
    /* missing start message! */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n",
              "RESERVATION_REQUEST");
  amount = (int32_t) ntohl (msg->amount);
  res_delay = GAS_reservations_reserve (&msg->peer, amount);
  if (res_delay.rel_value > 0)
    amount = 0;
  result.header.size = htons (sizeof (struct ReservationResultMessage));
  result.header.type = htons (GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT);
  result.amount = htonl (amount);
  result.peer = msg->peer;
  result.res_delay = GNUNET_TIME_relative_hton (res_delay);
  GNUNET_STATISTICS_update (GSA_stats, "# reservation requests processed", 1,
                            GNUNET_NO);
  GNUNET_SERVER_notification_context_unicast (nc, client, &result.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle 'preference change' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_preference_change (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct ChangePreferenceMessage *msg;
  const struct PreferenceInformation *pi;
  uint16_t msize;
  uint32_t nump;
  uint32_t i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n",
              "PREFERENCE_CHANGE");
  msize = ntohs (message->size);
  if (msize < sizeof (struct ChangePreferenceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct ChangePreferenceMessage *) message;
  nump = ntohl (msg->num_preferences);
  if (msize !=
      sizeof (struct ChangePreferenceMessage) +
      nump * sizeof (struct PreferenceInformation))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_STATISTICS_update (GSA_stats, "# preference change requests processed",
                            1, GNUNET_NO);
  pi = (const struct PreferenceInformation *) &msg[1];
  for (i = 0; i < nump; i++)
    GAS_addresses_change_preference (&msg->peer,
                                     (enum GNUNET_ATS_PreferenceKind)
                                     ntohl (pi[i].preference_kind),
                                     pi[i].preference_value);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Initialize performance subsystem.
 *
 * @param server handle to our server
 */
void
GAS_performance_init (struct GNUNET_SERVER_Handle *server)
{
  nc = GNUNET_SERVER_notification_context_create (server, 128);
}


/**
 * Shutdown performance subsystem.
 */
void
GAS_performance_done ()
{
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
}

/* end of gnunet-service-ats_performance.c */
