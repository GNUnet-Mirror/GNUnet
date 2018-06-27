/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file core/gnunet-service-core.c
 * @brief high-level P2P messaging
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_kx.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core_typemap.h"

/**
 * How many messages do we queue up at most for any client? This can
 * cause messages to be dropped if clients do not process them fast
 * enough!  Note that this is a soft limit; we try
 * to keep a few larger messages above the limit.
 */
#define SOFT_MAX_QUEUE 128

/**
 * How many messages do we queue up at most for any client? This can
 * cause messages to be dropped if clients do not process them fast
 * enough!  Note that this is the hard limit.
 */
#define HARD_MAX_QUEUE 256


/**
 * Data structure for each client connected to the CORE service.
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
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue to talk to @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Array of the types of messages this peer cares
   * about (with @e tcnt entries).  Allocated as part
   * of this client struct, do not free!
   */
  uint16_t *types;

  /**
   * Map of peer identities to active transmission requests of this
   * client to the peer (of type `struct GSC_ClientActiveRequest`).
   */
  struct GNUNET_CONTAINER_MultiPeerMap *requests;

  /**
   * Map containing all peers that this client knows we're connected to.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *connectmap;

  /**
   * Options for messages this client cares about,
   * see GNUNET_CORE_OPTION_ values.
   */
  uint32_t options;

  /**
   * Have we gotten the #GNUNET_MESSAGE_TYPE_CORE_INIT message
   * from this client already?
   */
  int got_init;

  /**
   * Number of types of incoming messages this client
   * specifically cares about.  Size of the @e types array.
   */
  unsigned int tcnt;

};


/**
 * Our identity.
 */
struct GNUNET_PeerIdentity GSC_my_identity;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *GSC_cfg;

/**
 * For creating statistics.
 */
struct GNUNET_STATISTICS_Handle *GSC_stats;

/**
 * Big "or" of all client options.
 */
static uint32_t all_client_options;

/**
 * Head of linked list of our clients.
 */
static struct GSC_Client *client_head;

/**
 * Tail of linked list of our clients.
 */
static struct GSC_Client *client_tail;


/**
 * Test if the client is interested in messages of the given type.
 *
 * @param type message type
 * @param c client to test
 * @return #GNUNET_YES if @a c is interested, #GNUNET_NO if not.
 */
static int
type_match (uint16_t type,
	    struct GSC_Client *c)
{
  if ( (0 == c->tcnt) &&
       (0 != c->options) )
    return GNUNET_YES;          /* peer without handlers and inbound/outbond
				   callbacks matches ALL */
  if (NULL == c->types)
    return GNUNET_NO;
  for (unsigned int i = 0; i < c->tcnt; i++)
    if (type == c->types[i])
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Check #GNUNET_MESSAGE_TYPE_CORE_INIT request.
 *
 * @param cls client that sent #GNUNET_MESSAGE_TYPE_CORE_INIT
 * @param im the `struct InitMessage`
 * @return #GNUNET_OK if @a im is well-formed
 */
static int
check_client_init (void *cls,
		   const struct InitMessage *im)
{
  return GNUNET_OK;
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_INIT request.
 *
 * @param cls client that sent #GNUNET_MESSAGE_TYPE_CORE_INIT
 * @param im the `struct InitMessage`
 */
static void
handle_client_init (void *cls,
                    const struct InitMessage *im)
{
  struct GSC_Client *c = cls;
  struct GNUNET_MQ_Envelope *env;
  struct InitReplyMessage *irm;
  uint16_t msize;
  const uint16_t *types;

  /* check that we don't have an entry already */
  msize = ntohs (im->header.size) - sizeof (struct InitMessage);
  types = (const uint16_t *) &im[1];
  c->tcnt = msize / sizeof (uint16_t);
  c->options = ntohl (im->options);
  c->got_init = GNUNET_YES;
  all_client_options |= c->options;
  c->types = GNUNET_malloc (msize);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (c->connectmap,
                                                    &GSC_my_identity,
                                                    NULL,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  for (unsigned int i = 0; i < c->tcnt; i++)
    c->types[i] = ntohs (types[i]);
  GSC_TYPEMAP_add (c->types,
		   c->tcnt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting to core service is interested in %u message types\n",
              (unsigned int) c->tcnt);
  /* send init reply message */
  env = GNUNET_MQ_msg (irm,
		       GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY);
  irm->reserved = htonl (0);
  irm->my_identity = GSC_my_identity;
  GNUNET_MQ_send (c->mq,
		  env);
  GSC_SESSIONS_notify_client_about_sessions (c);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * We will never be ready to transmit the given message in (disconnect
 * or invalid request).  Frees resources associated with @a car.  We
 * don't explicitly tell the client, it'll learn with the disconnect
 * (or violated the protocol).
 *
 * @param car request that now permanently failed; the
 *        responsibility for the handle is now returned
 *        to CLIENTS (SESSIONS is done with it).
 * @param drop_client #GNUNET_YES if the client violated the protocol
 *        and we should thus drop the connection
 */
void
GSC_CLIENTS_reject_request (struct GSC_ClientActiveRequest *car,
                            int drop_client)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (car->
                                                       client_handle->requests,
                                                       &car->target,
                                                       car));
  if (GNUNET_YES == drop_client)
    GNUNET_SERVICE_client_drop (car->client_handle->client);
  GNUNET_free (car);
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
  struct GNUNET_MQ_Envelope *env;
  struct SendMessageReady *smr;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_TIME_Relative left;

  c = car->client_handle;
  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_contains (c->connectmap,
                                              &car->target))
  {
    /* connection has gone down since, drop request */
    GNUNET_assert (0 !=
                   memcmp (&car->target,
                           &GSC_my_identity,
                           sizeof (struct GNUNET_PeerIdentity)));
    GSC_SESSIONS_dequeue_request (car);
    GSC_CLIENTS_reject_request (car,
                                GNUNET_NO);
    return;
  }
  delay = GNUNET_TIME_absolute_get_duration (car->received_time);
  left = GNUNET_TIME_absolute_get_duration (car->deadline);
  if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Client waited %s for permission to transmit to `%s'%s (priority %u)\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES),
                GNUNET_i2s (&car->target),
                (0 == left.rel_value_us)
                ? " (past deadline)"
                : "",
                car->priority);
  env = GNUNET_MQ_msg (smr,
		       GNUNET_MESSAGE_TYPE_CORE_SEND_READY);
  smr->size = htons (car->msize);
  smr->smr_id = car->smr_id;
  smr->peer = car->target;
  GNUNET_MQ_send (c->mq,
		  env);
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST message.
 *
 * @param cls client that sent a #GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST
 * @param req the `struct SendMessageRequest`
 */
static void
handle_client_send_request (void *cls,
                            const struct SendMessageRequest *req)
{
  struct GSC_Client *c = cls;
  struct GSC_ClientActiveRequest *car;
  int is_loopback;

  if (NULL == c->requests)
    c->requests = GNUNET_CONTAINER_multipeermap_create (16,
                                                        GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client asked for transmission to `%s'\n",
              GNUNET_i2s (&req->peer));
  is_loopback =
      (0 ==
       memcmp (&req->peer,
               &GSC_my_identity,
               sizeof (struct GNUNET_PeerIdentity)));
  if ((! is_loopback) &&
      (GNUNET_YES !=
       GNUNET_CONTAINER_multipeermap_contains (c->connectmap,
                                               &req->peer)))
  {
    /* neighbour must have disconnected since request was issued,
     * ignore (client will realize it once it processes the
     * disconnect notification) */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# send requests dropped (disconnected)"), 1,
                              GNUNET_NO);
    GNUNET_SERVICE_client_continue (c->client);
    return;
  }

  car = GNUNET_CONTAINER_multipeermap_get (c->requests,
                                           &req->peer);
  if (NULL == car)
  {
    /* create new entry */
    car = GNUNET_new (struct GSC_ClientActiveRequest);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (c->requests,
                                                      &req->peer,
                                                      car,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
    car->client_handle = c;
  }
  else
  {
    /* dequeue and recycle memory from pending request, there can only
       be at most one per client and peer */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# dequeuing CAR (duplicate request)"),
			      1,
                              GNUNET_NO);
    GSC_SESSIONS_dequeue_request (car);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmission request to `%s' was a duplicate!\n",
                GNUNET_i2s (&req->peer));
  }
  car->target = req->peer;
  car->received_time = GNUNET_TIME_absolute_get ();
  car->deadline = GNUNET_TIME_absolute_ntoh (req->deadline);
  car->priority = (enum GNUNET_CORE_Priority) ntohl (req->priority);
  car->msize = ntohs (req->size);
  car->smr_id = req->smr_id;
  car->was_solicited = GNUNET_NO;
  GNUNET_SERVICE_client_continue (c->client);
  if (is_loopback)
  {
    /* loopback, satisfy immediately */
    GSC_CLIENTS_solicit_request (car);
    return;
  }
  GSC_SESSIONS_queue_request (car);
}


/**
 * Closure for the #client_tokenizer_callback().
 */
struct TokenizerContext
{

  /**
   * Active request handle for the message.
   */
  struct GSC_ClientActiveRequest *car;

  /**
   * How important is this message.
   */
  enum GNUNET_CORE_Priority priority;

  /**
   * Is corking allowed (set only once we have the real message).
   */
  int cork;

};


/**
 * Functions with this signature are called whenever a complete
 * message is received by the tokenizer.  Used by
 * #handle_client_send() for dispatching messages from clients to
 * either the SESSION subsystem or other CLIENT (for loopback).
 *
 * @param cls reservation request (`struct TokenizerContext`)
 * @param message the actual message
 * @return #GNUNET_OK on success,
 *    #GNUNET_NO to stop further processing (no error)
 *    #GNUNET_SYSERR to stop further processing with error
 */
static int
tokenized_cb (void *cls,
	      const struct GNUNET_MessageHeader *message)
{
  struct TokenizerContext *tc = cls;
  struct GSC_ClientActiveRequest *car = tc->car;
  char buf[92];

  GNUNET_snprintf (buf,
		   sizeof (buf),
		   gettext_noop ("# bytes of messages of type %u received"),
		   (unsigned int) ntohs (message->type));
  GNUNET_STATISTICS_update (GSC_stats,
                            buf,
                            ntohs (message->size),
                            GNUNET_NO);
  if (0 ==
      memcmp (&car->target,
              &GSC_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delivering message of type %u to myself\n",
                ntohs (message->type));
    GSC_CLIENTS_deliver_message (&GSC_my_identity,
				 message,
				 ntohs (message->size),
				 GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND);
    GSC_CLIENTS_deliver_message (&GSC_my_identity,
				 message,
				 sizeof (struct GNUNET_MessageHeader),
				 GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND);
    GSC_CLIENTS_deliver_message (&GSC_my_identity,
				 message,
				 ntohs (message->size),
				 GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
    GSC_CLIENTS_deliver_message (&GSC_my_identity,
				 message,
				 sizeof (struct GNUNET_MessageHeader),
				 GNUNET_CORE_OPTION_SEND_HDR_INBOUND);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delivering message of type %u and size %u to %s\n",
                ntohs (message->type),
		ntohs (message->size),
                GNUNET_i2s (&car->target));
    GSC_CLIENTS_deliver_message (&car->target,
				 message,
				 ntohs (message->size),
				 GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND);
    GSC_CLIENTS_deliver_message (&car->target,
				 message,
				 sizeof (struct GNUNET_MessageHeader),
				 GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND);
    GSC_SESSIONS_transmit (car,
                           message,
                           tc->cork,
                           tc->priority);
  }
  return GNUNET_OK;
}


/**
 * Check #GNUNET_MESSAGE_TYPE_CORE_SEND request.
 *
 * @param cls the `struct GSC_Client`
 * @param sm the `struct SendMessage`
 * @return #GNUNET_OK if @a sm is well-formed
 */
static int
check_client_send (void *cls,
		   const struct SendMessage *sm)
{
  return GNUNET_OK;
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_SEND request.
 *
 * @param cls the `struct GSC_Client`
 * @param sm the `struct SendMessage`
 */
static void
handle_client_send (void *cls,
		    const struct SendMessage *sm)
{
  struct GSC_Client *c = cls;
  struct TokenizerContext tc;
  uint16_t msize;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_MessageStreamTokenizer *mst;

  msize = ntohs (sm->header.size) - sizeof (struct SendMessage);
  GNUNET_break (0 == ntohl (sm->reserved));
  tc.car = GNUNET_CONTAINER_multipeermap_get (c->requests,
					      &sm->peer);
  if (NULL == tc.car)
  {
    /* Must have been that we first approved the request, then got disconnected
     * (which triggered removal of the 'car') and now the client gives us a message
     * just *before* the client learns about the disconnect.  Theoretically, we
     * might also now be *again* connected.  So this can happen (but should be
     * rare).  If it does happen, the message is discarded. */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# messages discarded (session disconnected)"),
                              1,
			      GNUNET_NO);
    GNUNET_SERVICE_client_continue (c->client);
    return;
  }
  delay = GNUNET_TIME_absolute_get_duration (tc.car->received_time);
  tc.cork = ntohl (sm->cork);
  tc.priority = (enum GNUNET_CORE_Priority) ntohl (sm->priority);
  if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Client waited %s for transmission of %u bytes to `%s'%s\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES),
                msize,
                GNUNET_i2s (&sm->peer),
                tc.cork ? " (cork)" : " (uncorked)");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client waited %s for transmission of %u bytes to `%s'%s\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES),
                msize,
                GNUNET_i2s (&sm->peer),
                tc.cork ? " (cork)" : " (uncorked)");

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (c->requests,
                                                       &sm->peer,
                                                       tc.car));
  mst = GNUNET_MST_create (&tokenized_cb,
			   &tc);
  GNUNET_MST_from_buffer (mst,
			  (const char *) &sm[1],
			  msize,
			  GNUNET_YES,
			  GNUNET_NO);
  GNUNET_MST_destroy (mst);
  GSC_SESSIONS_dequeue_request (tc.car);
  GNUNET_free (tc.car);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Free client request records.
 *
 * @param cls NULL
 * @param key identity of peer for which this is an active request
 * @param value the `struct GSC_ClientActiveRequest` to free
 * @return #GNUNET_YES (continue iteration)
 */
static int
destroy_active_client_request (void *cls,
			       const struct GNUNET_PeerIdentity *key,
                               void *value)
{
  struct GSC_ClientActiveRequest *car = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (car->
                                                       client_handle->requests,
                                                       &car->target,
                                                       car));
  GSC_SESSIONS_dequeue_request (car);
  GNUNET_free (car);
  return GNUNET_YES;
}


/**
 * A client connected, set up.
 *
 * @param cls closure
 * @param client identification of the client
 * @param mq message queue to talk to @a client
 * @return our client handle
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct GSC_Client *c;

  c = GNUNET_new (struct GSC_Client);
  c->client = client;
  c->mq = mq;
  c->connectmap = GNUNET_CONTAINER_multipeermap_create (16,
							GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       c);
  return c;
}


/**
 * A client disconnected, clean up.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx our `struct GST_Client` for @a client
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct GSC_Client *c = app_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p has disconnected from core service.\n",
              client);
  GNUNET_CONTAINER_DLL_remove (client_head,
			       client_tail,
			       c);
  if (NULL != c->requests)
  {
    GNUNET_CONTAINER_multipeermap_iterate (c->requests,
                                           &destroy_active_client_request,
                                           NULL);
    GNUNET_CONTAINER_multipeermap_destroy (c->requests);
  }
  GNUNET_CONTAINER_multipeermap_destroy (c->connectmap);
  c->connectmap = NULL;
  if (NULL != c->types)
  {
    GSC_TYPEMAP_remove (c->types,
			c->tcnt);
    GNUNET_free (c->types);
  }
  GNUNET_free (c);

  /* recalculate 'all_client_options' */
  all_client_options = 0;
  for (c = client_head; NULL != c ; c = c->next)
    all_client_options |= c->options;
}


/**
 * Notify a particular client about a change to existing connection to
 * one of our neighbours (check if the client is interested).  Called
 * from #GSC_SESSIONS_notify_client_about_sessions().
 *
 * @param client client to notify
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for connect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GSC_CLIENTS_notify_client_about_neighbour (struct GSC_Client *client,
                                           const struct GNUNET_PeerIdentity *neighbour,
                                           const struct GSC_TypeMap *tmap_old,
                                           const struct GSC_TypeMap *tmap_new)
{
  struct GNUNET_MQ_Envelope *env;
  int old_match;
  int new_match;

  if (GNUNET_YES != client->got_init)
    return;
  old_match = GSC_TYPEMAP_test_match (tmap_old,
				      client->types,
				      client->tcnt);
  new_match = GSC_TYPEMAP_test_match (tmap_new,
				      client->types,
				      client->tcnt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying client about neighbour %s (%d/%d)\n",
              GNUNET_i2s (neighbour),
              old_match,
              new_match);
  if (old_match == new_match)
  {
    GNUNET_assert (old_match ==
                   GNUNET_CONTAINER_multipeermap_contains (client->connectmap,
                                                           neighbour));
    return;                     /* no change */
  }
  if (GNUNET_NO == old_match)
  {
    struct ConnectNotifyMessage *cnm;

    /* send connect */
    GNUNET_assert (GNUNET_NO ==
                   GNUNET_CONTAINER_multipeermap_contains (client->connectmap,
                                                           neighbour));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (client->connectmap,
                                                      neighbour,
                                                      NULL,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    env = GNUNET_MQ_msg (cnm,
			 GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
    cnm->reserved = htonl (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending NOTIFY_CONNECT message about peer %s to client.\n",
                GNUNET_i2s (neighbour));
    cnm->peer = *neighbour;
    GNUNET_MQ_send (client->mq,
		    env);
  }
  else
  {
    struct DisconnectNotifyMessage *dcm;

    /* send disconnect */
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_contains (client->connectmap,
                                                           neighbour));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (client->connectmap,
                                                         neighbour,
                                                         NULL));
    env = GNUNET_MQ_msg (dcm,
			 GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT);
    dcm->reserved = htonl (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending NOTIFY_DISCONNECT message about peer %s to client.\n",
                GNUNET_i2s (neighbour));
    dcm->peer = *neighbour;
    GNUNET_MQ_send (client->mq,
		    env);
  }
}


/**
 * Notify all clients about a change to existing session.
 * Called from SESSIONS whenever there is a change in sessions
 * or types processed by the respective peer.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for connect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GSC_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
                                            const struct GSC_TypeMap *tmap_old,
                                            const struct GSC_TypeMap *tmap_new)
{
  struct GSC_Client *c;

  for (c = client_head; NULL != c; c = c->next)
    GSC_CLIENTS_notify_client_about_neighbour (c,
					       neighbour,
                                               tmap_old,
					       tmap_new);
}


/**
 * Deliver P2P message to interested clients.  Caller must have checked
 * that the sending peer actually lists the given message type as one
 * of its types.
 *
 * @param sender peer who sent us the message
 * @param msg the message
 * @param msize number of bytes to transmit
 * @param options options for checking which clients should
 *        receive the message
 */
void
GSC_CLIENTS_deliver_message (const struct GNUNET_PeerIdentity *sender,
                             const struct GNUNET_MessageHeader *msg,
                             uint16_t msize,
                             uint32_t options)
{
  size_t size = msize + sizeof (struct NotifyTrafficMessage);

  if (size >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  if (! ( (0 != (all_client_options & options)) ||
	  (0 != (options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND)) ))
    return; /* no client cares about this message notification */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%s' of type %u to client.\n",
              GNUNET_i2s (sender),
              (unsigned int) ntohs (msg->type));
  GSC_SESSIONS_add_to_typemap (sender,
			       ntohs (msg->type));

  for (struct GSC_Client *c = client_head; NULL != c; c = c->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct NotifyTrafficMessage *ntm;
    uint16_t mtype;
    unsigned int qlen;
    int tm;

    tm = type_match (ntohs (msg->type),
		     c);
    if (! ( (0 != (c->options & options)) ||
	    ( (0 != (options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND)) &&
	      (GNUNET_YES == tm) ) ) )
      continue;  /* neither options nor type match permit the message */
    if ( (0 != (options & GNUNET_CORE_OPTION_SEND_HDR_INBOUND)) &&
	 ( (0 != (c->options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND)) ||
	   (GNUNET_YES == tm) ) )
      continue;
    if ( (0 != (options & GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND)) &&
	 (0 != (c->options & GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND)) )
      continue;

    /* Drop messages if:
       1) We are above the hard limit, or
       2) We are above the soft limit, and a coin toss limited
          to the message size (giving larger messages a
          proportionally higher chance of being queued) falls
          below the threshold. The threshold is based on where
          we are between the soft and the hard limit, scaled
          to match the range of message sizes we usually encounter
          (i.e. up to 32k); so a 64k message has a 50% chance of
          being kept if we are just barely below the hard max,
          and a 99% chance of being kept if we are at the soft max.
       The reason is to make it more likely to drop control traffic
       (ACK, queries) which may be cummulative or highly redundant,
       and cheap to drop than data traffic.  */
    qlen = GNUNET_MQ_get_length (c->mq);
    if ( (qlen >= HARD_MAX_QUEUE) ||
         ( (qlen > SOFT_MAX_QUEUE) &&
           ( (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                        ntohs (msg->size)) ) <
             (qlen - SOFT_MAX_QUEUE) * 0x8000 /
             (HARD_MAX_QUEUE - SOFT_MAX_QUEUE) ) ) )
    {
      char buf[1024];

      GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
                  "Dropping decrypted message of type %u as client is too busy (queue full)\n",
                  (unsigned int) ntohs (msg->type));
      GNUNET_snprintf (buf,
                       sizeof (buf),
                       gettext_noop ("# messages of type %u discarded (client busy)"),
                       (unsigned int) ntohs (msg->type));
      GNUNET_STATISTICS_update (GSC_stats,
                                buf,
                                1,
                                GNUNET_NO);
      continue;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending %u message with %u bytes to client interested in messages of type %u.\n",
		options,
		ntohs (msg->size),
                (unsigned int) ntohs (msg->type));

    if (0 != (options & (GNUNET_CORE_OPTION_SEND_FULL_INBOUND | GNUNET_CORE_OPTION_SEND_HDR_INBOUND)))
      mtype = GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND;
    else
      mtype = GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND;
    env = GNUNET_MQ_msg_extra (ntm,
			       msize,
			       mtype);
    ntm->peer = *sender;
    GNUNET_memcpy (&ntm[1],
		   msg,
		   msize);

    GNUNET_assert ( (0 == (c->options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND)) ||
		    (GNUNET_YES != tm) ||
		    (GNUNET_YES ==
		     GNUNET_CONTAINER_multipeermap_contains (c->connectmap,
							     sender)) );
    GNUNET_MQ_send (c->mq,
		    env);
  }
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport.
 *
 * @param cls NULL, unused
 */
static void
shutdown_task (void *cls)
{
  struct GSC_Client *c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service shutting down.\n");
  while (NULL != (c = client_head))
    GNUNET_SERVICE_client_drop (c->client);
  GSC_SESSIONS_done ();
  GSC_KX_done ();
  GSC_TYPEMAP_done ();
  if (NULL != GSC_stats)
  {
    GNUNET_STATISTICS_destroy (GSC_stats,
			       GNUNET_NO);
    GSC_stats = NULL;
  }
  GSC_cfg = NULL;
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS request.  For this
 * request type, the client does not have to have transmitted an INIT
 * request.  All current peers are returned, regardless of which
 * message types they accept.
 *
 * @param cls client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_monitor_peers (void *cls,
			     const struct GNUNET_MessageHeader *message)
{
  struct GSC_Client *c = cls;

  GNUNET_SERVICE_client_continue (c->client);
  GSC_KX_handle_client_monitor_peers (c->mq);
}


/**
 * Initiate core service.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;
  char *keyfile;

  GSC_cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (GSC_cfg,
					       "PEER",
					       "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Core service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GSC_stats = GNUNET_STATISTICS_create ("core",
					GSC_cfg);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  GNUNET_SERVICE_suspend (service);
  GSC_TYPEMAP_init ();
  pk = GNUNET_CRYPTO_eddsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  GNUNET_assert (NULL != pk);
  if (GNUNET_OK != GSC_KX_init (pk))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GSC_SESSIONS_init ();
  GNUNET_SERVICE_resume (service);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Core service of `%s' ready.\n"),
              GNUNET_i2s (&GSC_my_identity));
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("core",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (client_init,
			GNUNET_MESSAGE_TYPE_CORE_INIT,
			struct InitMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (client_monitor_peers,
			  GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_send_request,
			  GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST,
			  struct SendMessageRequest,
			  NULL),
 GNUNET_MQ_hd_var_size (client_send,
			GNUNET_MESSAGE_TYPE_CORE_SEND,
			struct SendMessage,
			NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-core.c */
