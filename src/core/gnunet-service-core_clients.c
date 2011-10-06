/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_clients.c
 * @brief code for managing interactions with clients of core service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_service_core.h"
#include "gnunet_service_core_clients.h"
#include "gnunet_service_core_sessions.h"
#include "gnunet_service_core_typemap.h"



/**
 * Data structure for each client connected to the core service.
 */
struct Client
{
  /**
   * Clients are kept in a linked list.
   */
  struct Client *next;

  /**
   * Clients are kept in a linked list.
   */
  struct Client *prev;

  /**
   * Handle for the client with the server API.
   */
  struct GNUNET_SERVER_Client *client_handle;

  /**
   * Array of the types of messages this peer cares
   * about (with "tcnt" entries).  Allocated as part
   * of this client struct, do not free!
   */
  const uint16_t *types;

  /**
   * Map of peer identities to active transmission requests of this
   * client to the peer (of type 'struct ClientActiveRequest').
   */
  struct GNUNET_CONTAINER_MultiHashMap *requests;

  /**
   * Options for messages this client cares about,
   * see GNUNET_CORE_OPTION_ values.
   */
  uint32_t options;

  /**
   * Number of types of incoming messages this client
   * specifically cares about.  Size of the "types" array.
   */
  unsigned int tcnt;

};


/**
 * Head of linked list of our clients.
 */
static struct Client *client_head;

/**
 * Tail of linked list of our clients.
 */
static struct Client *client_tail;

/**
 * Context for notifications we need to send to our clients.
 */
static struct GNUNET_SERVER_NotificationContext *notifier;

/**
 * Tokenizer for messages received from clients.
 */
static struct GNUNET_SERVER_MessageStreamTokenizer *client_mst;


/**
 * Lookup our client struct given the server's client handle.
 *
 * @param client server client handle to look up
 * @return our client handle for the client
 */
static struct Client *
find_client (struct GNUNET_SERVER_Client *client)
{
  struct Client *c;

  c = client_head;
  while ((c != NULL) && (c->client_handle != client))
    c = c->next;
  return c;
}


/**
 * Send a message to one of our clients.
 *
 * @param client target for the message
 * @param msg message to transmit
 * @param can_drop could this message be dropped if the
 *        client's queue is getting too large?
 */
static void
send_to_client (struct Client *client, 
		const struct GNUNET_MessageHeader *msg,
                int can_drop)
{
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Preparing to send %u bytes of message of type %u to client.\n",
              (unsigned int) ntohs (msg->size),
              (unsigned int) ntohs (msg->type));
#endif
  GNUNET_SERVER_notification_context_unicast (notifier, client->client_handle,
                                              msg, can_drop);
}


/**
 * Test if the client is interested in messages of the given type.
 *
 * @param type message type
 * @param c client to test
 * @return GNUNET_YES if 'c' is interested, GNUNET_NO if not.
 */
static int
type_match (uint16_t type,
	    struct Client *c)
{
  unsigned int i;

  for (i=0;i<c->tcnt;i++)
    if (type == c->types[i])
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Send a message to all of our current clients that have the right
 * options set.
 *
 * @param msg message to multicast
 * @param can_drop can this message be discarded if the queue is too long
 * @param options mask to use
 * @param type type of the embedded message, 0 for none
 */
static void
send_to_all_clients (const struct GNUNET_MessageHeader *msg, 
		     int can_drop,
                     int options,
		     uint16_t type)
{
  struct Client *c;

  for (c = client_head; c != NULL; c = c->next)
  {
    if ( (0 == (c->options & options)) &&
	 (GNUNET_YES != type_match (type, c)) )
      continue;
#if DEBUG_CORE_CLIENT > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Sending message of type %u to client.\n",
		(unsigned int) ntohs (msg->type));
#endif
    send_to_client (c, msg, can_drop);
  }
}


/**
 * Handle CORE_INIT request.
 *
 * @param cls unused
 * @param client new client that sent INIT
 * @param message the 'struct InitMessage' (presumably)
 */
static void
handle_client_init (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct InitMessage *im;
  struct InitReplyMessage irm;
  struct Client *c;
  uint16_t msize;
  const uint16_t *types;
  uint16_t *wtypes;
  unsigned int i;

  /* check that we don't have an entry already */
  c = find_client (client);
  if (NULL != c)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (msize < sizeof (struct InitMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_notification_context_add (notifier, client);
  im = (const struct InitMessage *) message;
  types = (const uint16_t *) &im[1];
  msize -= sizeof (struct InitMessage);
  c = GNUNET_malloc (sizeof (struct Client) + msize);
  c->client_handle = client;
  c->tcnt = msize / sizeof (uint16_t);
  c->options = ntohl (im->options);
  c->types = (const uint16_t *) &c[1];
  wtypes = (uint16_t *) & c[1];
  for (i = 0; i < c->tcnt; i++)
    wtypes[i] = ntohs (types[i]);
  GSC_TYPEMAP_add (wtypes, c->tcnt);
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       c);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting to core service is interested in %u message types\n", 
              (unsigned int) c->tcnt);
#endif
  /* send init reply message */
  irm.header.size = htons (sizeof (struct InitReplyMessage));
  irm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY);
  irm.reserved = htonl (0);
  irm.publicKey = GSC_my_public_key;
  send_to_client (c, &irm.header, GNUNET_NO);
  if (0 != (c->options & GNUNET_CORE_OPTION_SEND_CONNECT))
    GSC_SESSIONS_notify_client_about_sessions (c);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle CORE_SEND_REQUEST message.
 *
 * @param cls unused
 * @param client new client that sent CORE_SEND_REQUEST
 * @param message the 'struct InitMessage' (presumably)
 */
static void
handle_client_send_request (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct SendMessageRequest *req;
  struct Client *c;
  struct ClientActiveRequest *car;

  req = (const struct SendMessageRequest *) message;
  c = find_client (client);
  if (c == NULL)
  {
    /* client did not send INIT first! */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (c->requests == NULL)
    c->requests = GNUNET_CONTAINER_multihashmap_create (16);
  car = GNUNET_CONTAINER_multihashmap_get (c->requests, &req->peer.hashPubKey);
  if (car == NULL)
  {
    /* create new entry */
    car = GNUNET_malloc (sizeof (struct ClientActiveRequest));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (c->requests,
                                                      &req->peer.hashPubKey,
                                                      car,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
    car->client = c;
  }
  car->target = req->peer;
  GNUNET_SERVER_client_keep (client);
  car->client_handle = client;
  car->deadline = GNUNET_TIME_absolute_ntoh (req->deadline);
  car->priority = ntohl (req->priority);
  car->msize = ntohs (req->size);
  car->smr_id = req->smr_id;
  if (0 ==
      memcmp (&req->peer, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))
    GSC_CLIENTS_solicit_request (car);
  else
    GSC_SESSIONS_queue_request (car);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle CORE_SEND request.
 *
 * @param cls unused
 * @param client the client issuing the request
 * @param message the "struct SendMessage"
 */
static void
handle_client_send (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct SendMessage *sm;
  struct Client *c;
  struct ClientActiveRequest *car;
  uint16_t msize;

  msize = ntohs (message->size);
  if (msize <
      sizeof (struct SendMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sm = (const struct SendMessage *) message;
  msize -= sizeof (struct SendMessage);
  GNUNET_break (0 == ntohl (sm->reserved));
  c = find_client (client);
  if (c == NULL)
  {
    /* client did not send INIT first! */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  car = GNUNET_CONTAINER_multihashmap_get (c->requests, &sm->peer.hashPubKey);
  if (NULL == car)
  {
    /* client did not request transmission first! */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (c->requests, 
						       &sm->peer.hashPubKey,
						       car));
  GNUNET_SERVER_mst_receive (client_mst,
			     car, 
			     &sm[1], msize,
			     GNUNET_YES,
			     GNUNET_NO);
  if (0 !=
      memcmp (&car->peer, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))  
    GSC_SESSIONS_dequeue_request (car);
  GNUNET_free (car);  
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions with this signature are called whenever a complete
 * message is received by the tokenizer.  Used by the 'client_mst' for
 * dispatching messages from clients to either the SESSION subsystem
 * or other CLIENT (for loopback).
 *
 * @param cls closure
 * @param client reservation request ('struct ClientActiveRequest')
 * @param message the actual message
 */
static void
client_tokenizer_callback (void *cls, void *client,
			   const struct GNUNET_MessageHeader *message)
{
  struct ClientActiveRequest *car = client;

  if (0 ==
      memcmp (&car->peer, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))  
    GDS_CLIENTS_deliver_message (&GSC_my_identity, &payload->header);  
  else
    GSC_SESSIONS_transmit (car, &payload->header);
}


/**
 * Free client request records.
 *
 * @param cls NULL
 * @param key identity of peer for which this is an active request
 * @param value the 'struct ClientActiveRequest' to free
 * @return GNUNET_YES (continue iteration)
 */
static int
destroy_active_client_request (void *cls, const GNUNET_HashCode * key,
                               void *value)
{
  struct ClientActiveRequest *car = value;

  GSC_SESSIONS_dequeue_request (car);
  GNUNET_free (car);
  return GNUNET_YES;
}


/**
 * A client disconnected, clean up.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client *client)
{
  struct Client *c;

  if (client == NULL)
    return;
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p has disconnected from core service.\n", client);
#endif
  c = find_client (client);
  if (c == NULL)
    return; /* client never sent INIT */
  GNUNET_CONTAINER_DLL_remove (client_head,
			       client_tail,
			       c);
  if (c->requests != NULL)
  {
    GNUNET_CONTAINER_multihashmap_iterate (c->requests,
                                           &destroy_active_client_request,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (c->requests);
  }
  GSC_TYPEMAP_remove (c->types, c->tcnt);
  GNUNET_free (c);
}






// FIXME from here.......................................



/**
 * Tell a client that we are ready to receive the message.
 *
 * @param car request that is now ready; the responsibility
 *        for the handle remains shared between CLIENTS
 *        and SESSIONS after this call.
 */
void
GSC_CLIENTS_solicit_request (struct GSC_ClientActiveRequest *car)
{
}


/**
 * Tell a client that we will never be ready to receive the
 * given message in time (disconnect or timeout).
 *
 * @param car request that now permanently failed; the
 *        responsibility for the handle is now returned
 *        to CLIENTS (SESSIONS is done with it).
 */
void
GSC_CLIENTS_reject_request (struct GSC_ClientActiveRequest *car)
{
}




/**
 * Notify client about an existing connection to one of our neighbours.
 */
static int
notify_client_about_neighbour (void *cls, const GNUNET_HashCode * key,
                               void *value)
{
  struct Client *c = cls;
  struct Neighbour *n = value;
  size_t size;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  struct ConnectNotifyMessage *cnm;

  size =
      sizeof (struct ConnectNotifyMessage) +
      (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw away performance data */
    GNUNET_array_grow (n->ats, n->ats_count, 0);
    size =
        sizeof (struct ConnectNotifyMessage) +
        (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
  cnm = (struct ConnectNotifyMessage *) buf;
  cnm->header.size = htons (size);
  cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  cnm->ats_count = htonl (n->ats_count);
  ats = &cnm->ats;
  memcpy (ats, n->ats,
          sizeof (struct GNUNET_TRANSPORT_ATS_Information) * n->ats_count);
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
  {
#if DEBUG_CORE_CLIENT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
                "NOTIFY_CONNECT");
#endif
    cnm->peer = n->peer;
    send_to_client (c, &cnm->header, GNUNET_NO);
  }
  return GNUNET_OK;
}



/**
 * Helper function for handle_client_iterate_peers.
 *
 * @param cls the 'struct GNUNET_SERVER_TransmitContext' to queue replies
 * @param key identity of the connected peer
 * @param value the 'struct Neighbour' for the peer
 * @return GNUNET_OK (continue to iterate)
 */
static int
queue_connect_message (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct Neighbour *n = value;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  size_t size;
  struct ConnectNotifyMessage *cnm;

  cnm = (struct ConnectNotifyMessage *) buf;
  if (n->status != PEER_STATE_KEY_CONFIRMED)
    return GNUNET_OK;
  size =
      sizeof (struct ConnectNotifyMessage) +
      (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw away performance data */
    GNUNET_array_grow (n->ats, n->ats_count, 0);
    size =
        sizeof (struct PeerStatusNotifyMessage) +
        n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
  cnm = (struct ConnectNotifyMessage *) buf;
  cnm->header.size = htons (size);
  cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  cnm->ats_count = htonl (n->ats_count);
  ats = &cnm->ats;
  memcpy (ats, n->ats,
          n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
              "NOTIFY_CONNECT");
#endif
  cnm->peer = n->peer;
  GNUNET_SERVER_transmit_context_append_message (tc, &cnm->header);
  return GNUNET_OK;
}


/**
 * Handle CORE_ITERATE_PEERS request.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_iterate_peers (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  int msize;

  /* notify new client about existing neighbours */

  msize = ntohs (message->size);
  tc = GNUNET_SERVER_transmit_context_create (client);
  if (msize == sizeof (struct GNUNET_MessageHeader))
    GNUNET_CONTAINER_multihashmap_iterate (neighbours, &queue_connect_message,
                                           tc);
  else
    GNUNET_break (0);

  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle CORE_PEER_CONNECTED request.  Notify client about existing neighbours.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_have_peer (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct GNUNET_PeerIdentity *peer;

  tc = GNUNET_SERVER_transmit_context_create (client);
  peer = (struct GNUNET_PeerIdentity *) &message[1];
  GNUNET_CONTAINER_multihashmap_get_multiple (neighbours, &peer->hashPubKey,
                                              &queue_connect_message, tc);
  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle REQUEST_INFO request.
 *
 * @param cls unused
 * @param client client sending the request
 * @param message iteration request message
 */
static void
handle_client_request_info (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct RequestInfoMessage *rcm;
  struct Client *pos;
  struct Neighbour *n;
  struct ConfigurationInfoMessage cim;
  int32_t want_reserv;
  int32_t got_reserv;
  unsigned long long old_preference;
  struct GNUNET_TIME_Relative rdelay;

  rdelay = GNUNET_TIME_relative_get_zero ();
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core service receives `%s' request.\n",
              "REQUEST_INFO");
#endif
  pos = clients;
  while (pos != NULL)
  {
    if (client == pos->client_handle)
      break;
    pos = pos->next;
  }
  if (pos == NULL)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  rcm = (const struct RequestInfoMessage *) message;
  n = find_neighbour (&rcm->peer);
  memset (&cim, 0, sizeof (cim));
  if ((n != NULL) && (GNUNET_YES == n->is_connected))
  {
    want_reserv = ntohl (rcm->reserve_inbound);
    if (n->bw_out_internal_limit.value__ != rcm->limit_outbound.value__)
    {
      n->bw_out_internal_limit = rcm->limit_outbound;
      if (n->bw_out.value__ !=
          GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
                                      n->bw_out_external_limit).value__)
      {
        n->bw_out =
            GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
                                        n->bw_out_external_limit);
        GNUNET_BANDWIDTH_tracker_update_quota (&n->available_recv_window,
                                               n->bw_out);
        GNUNET_TRANSPORT_set_quota (transport, &n->peer, n->bw_in, n->bw_out);
        handle_peer_status_change (n);
      }
    }
    if (want_reserv < 0)
    {
      got_reserv = want_reserv;
    }
    else if (want_reserv > 0)
    {
      rdelay =
          GNUNET_BANDWIDTH_tracker_get_delay (&n->available_recv_window,
                                              want_reserv);
      if (rdelay.rel_value == 0)
        got_reserv = want_reserv;
      else
        got_reserv = 0;         /* all or nothing */
    }
    else
      got_reserv = 0;
    GNUNET_BANDWIDTH_tracker_consume (&n->available_recv_window, got_reserv);
    old_preference = n->current_preference;
    n->current_preference += GNUNET_ntohll (rcm->preference_change);
    if (old_preference > n->current_preference)
    {
      /* overflow; cap at maximum value */
      n->current_preference = ULLONG_MAX;
    }
    update_preference_sum (n->current_preference - old_preference);
#if DEBUG_CORE_QUOTA
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received reservation request for %d bytes for peer `%4s', reserved %d bytes, suggesting delay of %llu ms\n",
                (int) want_reserv, GNUNET_i2s (&rcm->peer), (int) got_reserv,
                (unsigned long long) rdelay.rel_value);
#endif
    cim.reserved_amount = htonl (got_reserv);
    cim.reserve_delay = GNUNET_TIME_relative_hton (rdelay);
    cim.bw_out = n->bw_out;
    cim.preference = n->current_preference;
  }
  else
  {
    /* Technically, this COULD happen (due to asynchronous behavior),
     * but it should be rare, so we should generate an info event
     * to help diagnosis of serious errors that might be masked by this */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Client asked for preference change with peer `%s', which is not connected!\n"),
                GNUNET_i2s (&rcm->peer));
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  cim.header.size = htons (sizeof (struct ConfigurationInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO);
  cim.peer = rcm->peer;
  cim.rim_id = rcm->rim_id;
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
              "CONFIGURATION_INFO");
#endif
  send_to_client (pos, &cim.header, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}




/**
 * Send a P2P message to a client.
 *
 * @param sender who sent us the message?
 * @param client who should we give the message to?
 * @param m contains the message to transmit
 * @param msize number of bytes in buf to transmit
 */
static void
send_p2p_message_to_client (struct Neighbour *sender, struct Client *client,
                            const void *m, size_t msize)
{
  size_t size =
      msize + sizeof (struct NotifyTrafficMessage) +
      (sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  char buf[size];
  struct NotifyTrafficMessage *ntm;
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  GNUNET_assert (GNUNET_YES == sender->is_connected);
  GNUNET_break (sender->status == PEER_STATE_KEY_CONFIRMED);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw performance data away... */
    GNUNET_array_grow (sender->ats, sender->ats_count, 0);
    size =
        msize + sizeof (struct NotifyTrafficMessage) +
        (sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%4s' of type %u to client.\n",
              GNUNET_i2s (&sender->peer),
              (unsigned int)
              ntohs (((const struct GNUNET_MessageHeader *) m)->type));
#endif
  ntm = (struct NotifyTrafficMessage *) buf;
  ntm->header.size = htons (size);
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND);
  ntm->ats_count = htonl (sender->ats_count);
  ntm->peer = sender->peer;
  ats = &ntm->ats;
  memcpy (ats, sender->ats,
          sizeof (struct GNUNET_TRANSPORT_ATS_Information) * sender->ats_count);
  ats[sender->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[sender->ats_count].value = htonl (0);
  memcpy (&ats[sender->ats_count + 1], m, msize);
  send_to_client (client, &ntm->header, GNUNET_YES);
}



/**
 * Notify a particular client about a change to existing connection to
 * one of our neighbours (check if the client is interested).  Called
 * from 'GSC_SESSIONS_notify_client_about_sessions'.
 *
 * @param client client to notify
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_client_about_neighbour (struct GSC_Client *client,
					   const struct GNUNET_PeerIdentity *neighbour,
					   const struct GSC_TypeMap *tmap_old,
					   const struct GSC_TypeMap *tmap_new)
{
}


/**
 * Notify client about a change to existing connection to one of our neighbours.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
					    const struct GSC_TypeMap *tmap_old,
					    const struct GSC_TypeMap *tmap_new)
{
}


/**
 * Deliver P2P message to interested clients.
 *
 * @param sender peer who sent us the message 
 * @param m the message
 */
void
GSC_CLIENTS_deliver_message (const struct GNUNET_PeerIdentity *sender,
			     const struct GNUNET_MessageHeader *m)
{
  struct Neighbour *sender = client;
  size_t msize = ntohs (m->size);
  char buf[256];
  struct Client *cpos;
  uint16_t type;
  unsigned int tpos;
  int deliver_full;
  int dropped;

  GNUNET_break (sender->status == PEER_STATE_KEY_CONFIRMED);
  type = ntohs (m->type);
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received encapsulated message of type %u and size %u from `%4s'\n",
              (unsigned int) type, ntohs (m->size), GNUNET_i2s (&sender->peer));
#endif
  GNUNET_snprintf (buf, sizeof (buf),
                   gettext_noop ("# bytes of messages of type %u received"),
                   (unsigned int) type);
  GNUNET_STATISTICS_update (stats, buf, msize, GNUNET_NO);
  if ((GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP == type) ||
      (GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP == type))
  {
    /* FIXME: update message type map for 'Neighbour' */
    return;
  }
  dropped = GNUNET_YES;
  cpos = clients;
  while (cpos != NULL)
  {
    deliver_full = GNUNET_NO;
    if (0 != (cpos->options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND))
      deliver_full = GNUNET_YES;
    else
    {
      for (tpos = 0; tpos < cpos->tcnt; tpos++)
      {
        if (type != cpos->types[tpos])
          continue;
        deliver_full = GNUNET_YES;
        break;
      }
    }
    if (GNUNET_YES == deliver_full)
    {
      send_p2p_message_to_client (sender, cpos, m, msize);
      dropped = GNUNET_NO;
    }
    else if (cpos->options & GNUNET_CORE_OPTION_SEND_HDR_INBOUND)
    {
      send_p2p_message_to_client (sender, cpos, m,
                                  sizeof (struct GNUNET_MessageHeader));
    }
    cpos = cpos->next;
  }
  if (dropped == GNUNET_YES)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Message of type %u from `%4s' not delivered to any client.\n",
                (unsigned int) type, GNUNET_i2s (&sender->peer));
#endif
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# messages not delivered to any client"), 1,
                              GNUNET_NO);
  }
}


/**
 * Initialize clients subsystem.
 *
 * @param server handle to server clients connect to
 */
void
GSC_CLIENTS_init (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_init, NULL,
     GNUNET_MESSAGE_TYPE_CORE_INIT, 0},
    {&handle_client_iterate_peers, NULL,
     GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_client_have_peer, NULL,
     GNUNET_MESSAGE_TYPE_CORE_PEER_CONNECTED,
     sizeof (struct GNUNET_MessageHeader) +
     sizeof (struct GNUNET_PeerIdentity)},
    {&handle_client_request_info, NULL,
     GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO,
     sizeof (struct RequestInfoMessage)},
    {&handle_client_send_request, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST,
     sizeof (struct SendMessageRequest)},
    {&handle_client_send, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND, 0},
    {NULL, NULL, 0, 0}
  };

  /* setup notification */
  client_mst = GNUNET_SERVER_mst_create (&client_tokenizer_callback, NULL);
  notifier =
      GNUNET_SERVER_notification_context_create (server, MAX_NOTIFY_QUEUE);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * Shutdown clients subsystem.
 */
void
GSC_CLIENTS_done ()
{
  struct Client *c;

  while (NULL != (c = client_head))  
    handle_client_disconnect (NULL, c->client_handle);
  GNUNET_SERVER_notification_context_destroy (notifier);
  notifier = NULL;
  GNUNET_SERVER_MST_destroy (client_mst);
  client_mst = NULL;
}

/* end of gnunet-service-core_clients.c */
