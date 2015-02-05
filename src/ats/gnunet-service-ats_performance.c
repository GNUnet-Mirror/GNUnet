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
  GNUNET_free (pc);
}


/**
 * Transmit the given performance information to all performance
 * clients.
 *
 * @param pc performance client to send to
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param atsi performance data for the address
 * @param atsi_count number of performance records in @a atsi
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_performance_notify_client (struct PerformanceClient *pc,
                               const struct GNUNET_PeerIdentity *peer,
                               const char *plugin_name,
                               const void *plugin_addr,
                               size_t plugin_addr_len,
                               int active,
                               const struct GNUNET_ATS_Information *atsi,
                               uint32_t atsi_count,
                               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{

  struct PeerInformationMessage *msg;
  size_t plugin_name_length = strlen (plugin_name) + 1;
  size_t msize =
      sizeof (struct PeerInformationMessage) +
      atsi_count * sizeof (struct GNUNET_ATS_Information) + plugin_addr_len +
      plugin_name_length;
  char buf[msize] GNUNET_ALIGN;
  struct GNUNET_ATS_Information *atsp;
  char *addrp;

  GNUNET_assert (NULL != pc);
  if (NULL == find_client (pc->client))
    return; /* Client disconnected */

  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (atsi_count <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE /
                 sizeof (struct GNUNET_ATS_Information));
  msg = (struct PeerInformationMessage *) buf;
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION);
  msg->id = htonl (0);
  msg->ats_count = htonl (atsi_count);
  msg->peer = *peer;
  msg->address_length = htons (plugin_addr_len);
  msg->address_active = ntohl ((uint32_t) active);
  msg->plugin_name_length = htons (plugin_name_length);
  msg->bandwidth_out = bandwidth_out;
  msg->bandwidth_in = bandwidth_in;
  atsp = (struct GNUNET_ATS_Information *) &msg[1];
  memcpy (atsp, atsi, sizeof (struct GNUNET_ATS_Information) * atsi_count);
  addrp = (char *) &atsp[atsi_count];
  memcpy (addrp, plugin_addr, plugin_addr_len);
  strcpy (&addrp[plugin_addr_len], plugin_name);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              pc->client,
                                              &msg->header,
                                              GNUNET_YES);
}


/**
 * Transmit the given performance information to all performance
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in @a plugin_addr
 * @param active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param atsi performance data for the address
 * @param atsi_count number of performance records in @a atsi
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_performance_notify_all_clients (const struct GNUNET_PeerIdentity *peer,
                                    const char *plugin_name,
                                    const void *plugin_addr,
                                    size_t plugin_addr_len,
                                    int active,
                                    const struct GNUNET_ATS_Information *atsi,
                                    uint32_t atsi_count,
                                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct PerformanceClient *pc;

  for (pc = pc_head; pc != NULL; pc = pc->next)
    if (pc->flag == START_FLAG_PERFORMANCE_WITH_PIC)
    {
        GAS_performance_notify_client (pc,
                                       peer,
                                       plugin_name,
                                       plugin_addr,
                                       plugin_addr_len,
                                       active,
                                       atsi, atsi_count,
                                       bandwidth_out, bandwidth_in);
    }
  GNUNET_STATISTICS_update (GSA_stats,
                            "# performance updates given to clients", 1,
                            GNUNET_NO);
}



/**
 * Iterator for called from #GAS_addresses_get_peer_info()
 *
 * @param cls closure with the `struct PerformanceClient *`
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
peerinfo_it (void *cls,
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
  struct PerformanceClient *pc = cls;

  GNUNET_assert (NULL != pc);
  if (NULL == id)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Callback for peer `%s' plugin `%s' BW out %u, BW in %u \n",
              GNUNET_i2s (id),
              plugin_name,
              (unsigned int) ntohl (bandwidth_out.value__),
              (unsigned int) ntohl (bandwidth_in.value__));
  GAS_performance_notify_client (pc,
                                 id,
                                 plugin_name,
                                 plugin_addr,
                                 plugin_addr_len,
                                 active,
                                 atsi, atsi_count,
                                 bandwidth_out,
                                 bandwidth_in);
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
  pc = GNUNET_new (struct PerformanceClient);
  pc->client = client;
  pc->flag = flag;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding performance client %s PIC\n",
              (flag == START_FLAG_PERFORMANCE_WITH_PIC) ? "with" : "without");

  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  GNUNET_CONTAINER_DLL_insert (pc_head,
                               pc_tail,
                               pc);
  GAS_addresses_get_peer_info (NULL,
                               &peerinfo_it,
                               pc);
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
  struct PerformanceClient *pc;

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
                                              ai->pc->client,
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
  if ( (GNUNET_YES == ai->all) ||
       (GNUNET_YES == active))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending result for %s peer `%s' plugin `%s' BW out %u, BW in %u\n",
                (active == GNUNET_YES) ? "ACTIVE" : "INACTIVE",
                GNUNET_i2s (id),
                plugin_name,
                (unsigned int) ntohl (bandwidth_out.value__),
                (unsigned int) ntohl (bandwidth_in.value__));
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
  struct PerformanceClient *pc;
  struct AddressIteration ai;
  const struct AddressListRequestMessage *alrm;
  struct GNUNET_PeerIdentity allzeros;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_zero;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ADDRESSLIST_REQUEST");
  if (NULL == (pc = find_client(client)))
  {
    GNUNET_break (0);
    return;
  }
  alrm = (const struct AddressListRequestMessage *) message;
  ai.all = ntohl (alrm->all);
  ai.id = ntohl (alrm->id);
  ai.pc = pc;

  memset (&allzeros, '\0', sizeof (struct GNUNET_PeerIdentity));
  bandwidth_zero.value__ = htonl (0);
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
                     bandwidth_zero,
                     bandwidth_zero);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_reservation_request (void *cls,
                                struct GNUNET_SERVER_Client *client,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "RESERVATION_REQUEST");
  amount = (int32_t) ntohl (msg->amount);
  res_delay = GAS_reservations_reserve (&msg->peer, amount);
  if (res_delay.rel_value_us > 0)
    amount = 0;
  result.header.size = htons (sizeof (struct ReservationResultMessage));
  result.header.type = htons (GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT);
  result.amount = htonl (amount);
  result.peer = msg->peer;
  result.res_delay = GNUNET_TIME_relative_hton (res_delay);
  GNUNET_STATISTICS_update (GSA_stats,
                            "# reservation requests processed", 1,
                            GNUNET_NO);
  GNUNET_SERVER_notification_context_unicast (nc, client, &result.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}




/**
 * Initialize performance subsystem.
 *
 * @param server handle to our server
 * @param addresses the address handle to use
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
