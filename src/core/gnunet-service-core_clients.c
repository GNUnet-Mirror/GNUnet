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
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_clients.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core_typemap.h"
#include "core.h"

/**
 * How many messages do we queue up at most for optional
 * notifications to a client?  (this can cause notifications
 * about outgoing messages to be dropped).
 */
#define MAX_NOTIFY_QUEUE 1024


/**
 * Data structure for each client connected to the core service.
 */
struct GSC_Client
{
  /**
   * Clients are kept in a linked list.
   */
  struct GSC_Client *next;

  /**
   * Clients are kept in a linked list.
   */
  struct GSC_Client *prev;

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
   * client to the peer (of type 'struct GSC_ClientActiveRequest').
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
static struct GSC_Client *client_head;

/**
 * Tail of linked list of our clients.
 */
static struct GSC_Client *client_tail;

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
static struct GSC_Client *
find_client (struct GNUNET_SERVER_Client *client)
{
  struct GSC_Client *c;

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
send_to_client (struct GSC_Client *client, 
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
 * Send a message to one of our clients.
 *
 * @param client target for the message
 * @param msg message to transmit
 * @param can_drop could this message be dropped if the
 *        client's queue is getting too large?
 */
void
GSC_CLIENTS_send_to_client (struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *msg,
			    int can_drop)
{
  struct GSC_Client *c;

  c = find_client (client);
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  send_to_client (c, msg, can_drop);
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
	    struct GSC_Client *c)
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
  struct GSC_Client *c;

  for (c = client_head; c != NULL; c = c->next)
  {
    if (! ( (0 != (c->options & options)) ||
	    ( (0 != (options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND)) &&
	      (GNUNET_YES == type_match (type, c)) ) ) )
      continue; /* skip */
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
  struct GSC_Client *c;
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
  c = GNUNET_malloc (sizeof (struct GSC_Client) + msize);
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
  irm.my_identity = GSC_my_identity;
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
  struct GSC_Client *c;
  struct GSC_ClientActiveRequest *car;

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
    car = GNUNET_malloc (sizeof (struct GSC_ClientActiveRequest));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (c->requests,
                                                      &req->peer.hashPubKey,
                                                      car,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
    car->client_handle = c;
  }
  car->target = req->peer;
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
  struct GSC_Client *c;
  struct GSC_ClientActiveRequest *car;
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
			     (const char*) &sm[1], msize,
			     GNUNET_YES,
			     GNUNET_NO);
  if (0 !=
      memcmp (&car->target, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))  
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
 * @param client reservation request ('struct GSC_ClientActiveRequest')
 * @param message the actual message
 */
static void
client_tokenizer_callback (void *cls, void *client,
			   const struct GNUNET_MessageHeader *message)
{
  struct GSC_ClientActiveRequest *car = client;

  if (0 ==
      memcmp (&car->target, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))  
  {
    GSC_CLIENTS_deliver_message (&GSC_my_identity, 
				 NULL, 0,
				 message,
				 ntohs (message->size),
				 GNUNET_CORE_OPTION_SEND_FULL_INBOUND | GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND);  
    GSC_CLIENTS_deliver_message (&GSC_my_identity, 
				 NULL, 0,
				 message,
				 sizeof (struct GNUNET_MessageHeader),
				 GNUNET_CORE_OPTION_SEND_HDR_INBOUND | GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND);  
  }
  else
    GSC_SESSIONS_transmit (car, message);
}


/**
 * Free client request records.
 *
 * @param cls NULL
 * @param key identity of peer for which this is an active request
 * @param value the 'struct GSC_ClientActiveRequest' to free
 * @return GNUNET_YES (continue iteration)
 */
static int
destroy_active_client_request (void *cls, const GNUNET_HashCode * key,
                               void *value)
{
  struct GSC_ClientActiveRequest *car = value;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (car->client_handle->requests,
						       &car->target.hashPubKey,
						       car));
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
  struct GSC_Client *c;

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
  struct GSC_Client *c;
  struct SendMessageReady smr;

  c = car->client_handle;
  smr.header.size = htons (sizeof (struct SendMessageReady));
  smr.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND_READY);
  smr.size = htons (car->msize);
  smr.smr_id = car->smr_id;
  smr.peer = car->target;
  send_to_client (c, &smr.header, GNUNET_NO);
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
  GNUNET_assert (GNUNET_YES ==
		 destroy_active_client_request (NULL, &car->target.hashPubKey, car));  
}


/**
 * Notify a particular client about a change to existing connection to
 * one of our neighbours (check if the client is interested).  Called
 * from 'GSC_SESSIONS_notify_client_about_sessions'.
 *
 * @param client client to notify
 * @param neighbour identity of the neighbour that changed status
 * @param atsi performance information about neighbour
 * @param atsi_count number of entries in 'ats' array
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_client_about_neighbour (struct GSC_Client *client,
					   const struct GNUNET_PeerIdentity *neighbour,
					   const struct GNUNET_TRANSPORT_ATS_Information *atsi,
					   unsigned int atsi_count,
					   const struct GSC_TypeMap *tmap_old,
					   const struct GSC_TypeMap *tmap_new)
{
  struct ConnectNotifyMessage *cnm;
  size_t size;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *a;
  struct DisconnectNotifyMessage dcm;
  int old_match;
  int new_match;

  old_match = GSC_TYPEMAP_test_match (tmap_old, client->types, client->tcnt);
  new_match = GSC_TYPEMAP_test_match (tmap_new, client->types, client->tcnt);
  if (old_match == new_match)
    return; /* no change */
  if (old_match == GNUNET_NO)
  {
    /* send connect */  
    size =
      sizeof (struct ConnectNotifyMessage) +
      (atsi_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
      {
	GNUNET_break (0);
	/* recovery strategy: throw away performance data */
	atsi_count = 0;
	size = sizeof (struct ConnectNotifyMessage);
      }
    cnm = (struct ConnectNotifyMessage *) buf;
    cnm->header.size = htons (size);
    cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
    cnm->ats_count = htonl (atsi_count);
    a = &cnm->ats;
    memcpy (a, atsi,
	    sizeof (struct GNUNET_TRANSPORT_ATS_Information) * atsi_count);
    a[atsi_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
    a[atsi_count].value = htonl (0);
#if DEBUG_CORE_CLIENT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Sending `%s' message to client.\n",
                "NOTIFY_CONNECT");
#endif
    cnm->peer = *neighbour;
    send_to_client (client, &cnm->header, GNUNET_NO);
  }
  else
  {
    /* send disconnect */
    dcm.header.size = htons (sizeof (struct DisconnectNotifyMessage));
    dcm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT);
    dcm.reserved = htonl (0);
    dcm.peer = *neighbour;
    send_to_client (client, &dcm.header, GNUNET_NO);
  }
}


/**
 * Notify all clients about a change to existing session.
 * Called from SESSIONS whenever there is a change in sessions
 * or types processed by the respective peer.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param atsi performance information about neighbour
 * @param atsi_count number of entries in 'ats' array
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
					    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
					    unsigned int atsi_count,
					    const struct GSC_TypeMap *tmap_old,
					    const struct GSC_TypeMap *tmap_new)
{
  struct GSC_Client *c;

  for (c = client_head; c != NULL; c = c->next)
    GDS_CLIENTS_notify_client_about_neighbour (c, neighbour, atsi,
					       atsi_count, 
					       tmap_old, tmap_new);
}


/**
 * Deliver P2P message to interested clients.  Caller must have checked
 * that the sending peer actually lists the given message type as one 
 * of its types.
 *
 * @param sender peer who sent us the message 
 * @param atsi performance information about neighbour
 * @param atsi_count number of entries in 'ats' array
 * @param msg the message
 * @param msize number of bytes to transmit
 * @param options options for checking which clients should
 *        receive the message
 */
void
GSC_CLIENTS_deliver_message (const struct GNUNET_PeerIdentity *sender,
			     const struct GNUNET_TRANSPORT_ATS_Information *atsi,
			     unsigned int atsi_count,
			     const struct GNUNET_MessageHeader *msg,
			     uint16_t msize,
			     int options)
{
  size_t size = msize + sizeof (struct NotifyTrafficMessage) +
      atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  char buf[size];
  struct NotifyTrafficMessage *ntm;
  struct GNUNET_TRANSPORT_ATS_Information *a;

  if (0 == options)
  {
    GNUNET_snprintf (buf, sizeof (buf),
		     gettext_noop ("# bytes of messages of type %u received"),
		     (unsigned int) ntohs (msg->type));
    GNUNET_STATISTICS_update (GSC_stats, buf, msize, GNUNET_NO);
  }
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw performance data away... */
    atsi_count = 0;
    size = msize + sizeof (struct NotifyTrafficMessage);
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%4s' of type %u to client.\n",
              GNUNET_i2s (sender),
              (unsigned int) ntohs (msg->type));
#endif
  ntm = (struct NotifyTrafficMessage *) buf;
  ntm->header.size = htons (size);
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND);
  ntm->ats_count = htonl (atsi_count);
  ntm->peer = *sender;
  a = &ntm->ats;
  memcpy (a, atsi,
          sizeof (struct GNUNET_TRANSPORT_ATS_Information) * atsi_count);
  a[atsi_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  a[atsi_count].value = htonl (0);
  memcpy (&a[atsi_count + 1], msg, msize);
  send_to_all_clients (&ntm->header, GNUNET_YES, 
		       options, ntohs (msg->type));
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
    {&GSC_SESSIONS_handle_client_iterate_peers, NULL,
     GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS,
     sizeof (struct GNUNET_MessageHeader)},
    {&GSC_SESSIONS_handle_client_have_peer, NULL,
     GNUNET_MESSAGE_TYPE_CORE_PEER_CONNECTED,
     sizeof (struct GNUNET_MessageHeader) +
     sizeof (struct GNUNET_PeerIdentity)},
    {&GSC_SESSIONS_handle_client_request_info, NULL,
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
  struct GSC_Client *c;

  while (NULL != (c = client_head))  
    handle_client_disconnect (NULL, c->client_handle);
  GNUNET_SERVER_notification_context_destroy (notifier);
  notifier = NULL;
  GNUNET_SERVER_mst_destroy (client_mst);
  client_mst = NULL;
}

/* end of gnunet-service-core_clients.c */
