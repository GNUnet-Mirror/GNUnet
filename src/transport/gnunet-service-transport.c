/*
 This file is part of GNUnet.
 Copyright (C) 2010-2016 GNUnet e.V.

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
 * @file transport/gnunet-service-transport.c
 * @brief main for gnunet-service-transport
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_ats.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport_manipulation.h"
#include "transport.h"

/**
 * Size of the blacklist hash map.
 */
#define TRANSPORT_BLACKLIST_HT_SIZE 64

/**
 * How many messages can we have pending for a given client process
 * before we start to drop incoming messages?  We typically should
 * have only one client and so this would be the primary buffer for
  * messages, so the number should be chosen rather generously.
 *
 * The expectation here is that most of the time the queue is large
 * enough so that a drop is virtually never required.  Note that
 * this value must be about as large as 'TOTAL_MSGS' in the
 * 'test_transport_api_reliability.c', otherwise that testcase may
 * fail.
 */
#define MAX_PENDING (128 * 1024)


/**
 * Information we need for an asynchronous session kill.
 */
struct GNUNET_ATS_SessionKiller
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_SessionKiller *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_SessionKiller *prev;

  /**
   * Session to kill.
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Plugin for the session.
   */
  struct GNUNET_TRANSPORT_PluginFunctions *plugin;

  /**
   * The kill task.
   */
  struct GNUNET_SCHEDULER_Task *task;
};


/**
 * What type of client is the `struct TransportClient` about?
 */
enum ClientType
{
  /**
   * We do not know yet (client is fresh).
   */
  CT_NONE = 0,

  /**
   * Is the CORE service, we need to forward traffic to it.
   */
  CT_CORE = 1,

  /**
   * It is a monitor, forward monitor data.
   */
  CT_MONITOR = 2,

  /**
   * It is a blacklist, query about allowed connections.
   */
  CT_BLACKLIST = 3
};


/**
 * Context we use when performing a blacklist check.
 */
struct GST_BlacklistCheck;

/**
 * Client connected to the transport service.
 */
struct TransportClient
{

  /**
   * This is a doubly-linked list.
   */
  struct TransportClient *next;

  /**
   * This is a doubly-linked list.
   */
  struct TransportClient *prev;

  /**
   * Handle to the client.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue to the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * What type of client is this?
   */
  enum ClientType type;

  union {

    /**
     * Peer identity to monitor the addresses of.
     * Zero to monitor all neighbours.  Valid if
     * @e type is CT_MONITOR.
     */
    struct GNUNET_PeerIdentity monitor_peer;

    /**
     * Additional details if @e type is CT_BLACKLIST.
     */
    struct {

      /**
       * Blacklist check that we're currently performing (or NULL
       * if we're performing one that has been cancelled).
       */
      struct GST_BlacklistCheck *bc;

      /**
       * Set to #GNUNET_YES if we're currently waiting for a reply.
       */
      int waiting_for_reply;

      /**
       * #GNUNET_YES if we have to call receive_done for this client
       */
      int call_receive_done;

    } blacklist;

  } details;

};



/**
 * Context we use when performing a blacklist check.
 */
struct GST_BlacklistCheck
{

  /**
   * This is a linked list.
   */
  struct GST_BlacklistCheck *next;

  /**
   * This is a linked list.
   */
  struct GST_BlacklistCheck *prev;

  /**
   * Peer being checked.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Continuation to call with the result.
   */
  GST_BlacklistTestContinuation cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Address for #GST_blacklist_abort_matching(), can be NULL.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Session for #GST_blacklist_abort_matching(), can be NULL.
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Our current position in the blacklisters list.
   */
  struct TransportClient *bl_pos;

  /**
   * Current task performing the check.
   */
  struct GNUNET_SCHEDULER_Task *task;

};


/**
 * Context for address to string operations
 */
struct AddressToStringContext
{
  /**
   * This is a doubly-linked list.
   */
  struct AddressToStringContext *next;

  /**
   * This is a doubly-linked list.
   */
  struct AddressToStringContext *prev;

  /**
   * Client that made the request.
   */
  struct TransportClient* tc;
};


/**
 * Closure for #handle_send_transmit_continuation()
 */
struct SendTransmitContinuationContext
{

  /**
   * Client that made the request.
   */
  struct TransportClient *tc;

  /**
   * Peer that was the target.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * At what time did we receive the message?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * Unique ID, for logging.
   */
  unsigned long long uuid;

  /**
   * Set to #GNUNET_YES if the connection for @e target goes
   * down and we thus must no longer send the
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK message.
   */
  int down;
};


/**
 * Head of linked list of all clients to this service.
 */
static struct TransportClient *clients_head;

/**
 * Tail of linked list of all clients to this service.
 */
static struct TransportClient *clients_tail;

/**
 * Map of peer identities to active send transmit continuation
 * contexts. Used to flag contexts as 'dead' when a connection goes
 * down. Values are of type `struct SendTransmitContinuationContext
 * *`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *active_stccs;

/**
 * Head of linked list of all pending address iterations
 */
static struct AddressToStringContext *a2s_head;

/**
 * Tail of linked list of all pending address iterations
 */
static struct AddressToStringContext *a2s_tail;

/**
 * Head of DLL of active blacklisting queries.
 */
static struct GST_BlacklistCheck *bc_head;

/**
 * Tail of DLL of active blacklisting queries.
 */
static struct GST_BlacklistCheck *bc_tail;

/**
 * Hashmap of blacklisted peers.  Values are of type 'char *' (transport names),
 * can be NULL if we have no static blacklist.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *blacklist;

/**
 * Notification context, to send updates on changes to active plugin
 * connections.
 */
static struct GNUNET_NotificationContext *plugin_nc;

/**
 * Plugin monitoring client we are currently syncing, NULL if all
 * monitoring clients are in sync.
 */
static struct TransportClient *sync_client;

/**
 * Peer identity that is all zeros, used as a way to indicate
 * "all peers".  Used for comparissons.
 */
static struct GNUNET_PeerIdentity all_zeros;

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Our private key.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *GST_my_private_key;

/**
 * ATS scheduling handle.
 */
struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * ATS connectivity handle.
 */
struct GNUNET_ATS_ConnectivityHandle *GST_ats_connect;

/**
 * Hello address expiration
 */
struct GNUNET_TIME_Relative hello_expiration;

/**
 * Head of DLL of asynchronous tasks to kill sessions.
 */
static struct GNUNET_ATS_SessionKiller *sk_head;

/**
 * Tail of DLL of asynchronous tasks to kill sessions.
 */
static struct GNUNET_ATS_SessionKiller *sk_tail;

/**
 * Interface scanner determines our LAN address range(s).
 */
struct GNUNET_ATS_InterfaceScanner *GST_is;


/**
 * Queue the given message for transmission to the given client
 *
 * @param tc target of the message
 * @param msg message to transmit
 * @param may_drop #GNUNET_YES if the message can be dropped
 */
static void
unicast (struct TransportClient *tc,
         const struct GNUNET_MessageHeader *msg,
         int may_drop)
{
  struct GNUNET_MQ_Envelope *env;

  if ( (GNUNET_MQ_get_length (tc->mq) >= MAX_PENDING) &&
       (GNUNET_YES == may_drop) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping message of type %u and size %u, have %u/%u messages pending\n",
                ntohs (msg->type),
                ntohs (msg->size),
                GNUNET_MQ_get_length (tc->mq),
                MAX_PENDING);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# messages dropped due to slow client"), 1,
                              GNUNET_NO);
    return;
  }
  env = GNUNET_MQ_msg_copy (msg);
  GNUNET_MQ_send (tc->mq,
		  env);
}


/**
 * Called whenever a client connects.  Allocates our
 * data structures associated with that client.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param mq message queue for the client
 * @return our `struct TransportClient`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct TransportClient *tc;

  tc = GNUNET_new (struct TransportClient);
  tc->client = client;
  tc->mq = mq;
  GNUNET_CONTAINER_DLL_insert (clients_head,
                               clients_tail,
                               tc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              tc);
  return tc;
}


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the `struct BlacklistCheck*`
 */
static void
do_blacklist_check (void *cls);


/**
 * Mark the peer as down so we don't call the continuation
 * context in the future.
 *
 * @param cls a `struct TransportClient`
 * @param peer a peer we are sending to
 * @param value a `struct SendTransmitContinuationContext` to mark
 * @return #GNUNET_OK (continue to iterate)
 */
static int
mark_match_down (void *cls,
		 const struct GNUNET_PeerIdentity *peer,
		 void *value)
{
  struct TransportClient *tc = cls;
  struct SendTransmitContinuationContext *stcc = value;

  if (tc == stcc->tc)
  {
    stcc->down = GNUNET_YES;
    stcc->tc = NULL;
  }
  return GNUNET_OK;
}


/**
 * Called whenever a client is disconnected.  Frees our
 * resources associated with that client.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param app_ctx our `struct TransportClient`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct TransportClient *tc = app_ctx;
  struct GST_BlacklistCheck *bc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected, cleaning up.\n",
              tc);
  GNUNET_CONTAINER_multipeermap_iterate (active_stccs,
					 &mark_match_down,
					 tc);
  for (struct AddressToStringContext *cur = a2s_head;
       NULL != cur;
       cur = cur->next)
  {
    if (cur->tc == tc)
      cur->tc = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (clients_head,
                               clients_tail,
                               tc);
  switch (tc->type)
  {
  case CT_NONE:
    break;
  case CT_CORE:
    break;
  case CT_MONITOR:
    break;
  case CT_BLACKLIST:
    for (bc = bc_head; NULL != bc; bc = bc->next)
    {
      if (bc->bl_pos != tc)
        continue;
      bc->bl_pos = tc->next;
      if (NULL == bc->task)
        bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					     bc);
    }
    break;
  }
  GNUNET_free (tc);
}


/**
 * Function called for each of our connected neighbours.  Notify the
 * client about the existing neighbour.
 *
 * @param cls the `struct TransportClient *` to notify
 * @param peer identity of the neighbour
 * @param address the address
 * @param state the current state of the peer
 * @param state_timeout the time out for the state
 * @param bandwidth_in inbound bandwidth in NBO
 * @param bandwidth_out outbound bandwidth in NBO
 */
static void
notify_client_about_neighbour (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_HELLO_Address *address,
                               enum GNUNET_TRANSPORT_PeerState state,
                               struct GNUNET_TIME_Absolute state_timeout,
                               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct TransportClient *tc = cls;
  struct ConnectInfoMessage cim;

  if (GNUNET_NO == GST_neighbours_test_connected (peer))
    return;
  cim.header.size = htons (sizeof (struct ConnectInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim.id = *peer;
  cim.quota_in = bandwidth_in;
  cim.quota_out = bandwidth_out;
  unicast (tc,
	   &cim.header,
	   GNUNET_NO);
}


/**
 * Initialize a normal client.  We got a start message from this
 * client, add it to the list of clients for broadcasting of inbound
 * messages.
 *
 * @param cls the client
 * @param start the start message that was sent
 */
static void
handle_client_start (void *cls,
		     const struct StartMessage *start)
{
  struct TransportClient *tc = cls;
  const struct GNUNET_MessageHeader *hello;
  uint32_t options;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p sent START\n",
              tc);
  options = ntohl (start->options);
  if ((0 != (1 & options)) &&
      (0 !=
       memcmp (&start->self,
               &GST_my_identity,
               sizeof (struct GNUNET_PeerIdentity))))
  {
    /* client thinks this is a different peer, reject */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  if (CT_NONE != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  if (0 != (2 & options))
    tc->type = CT_CORE;
  hello = GST_hello_get ();
  if (NULL != hello)
    unicast (tc,
             hello,
             GNUNET_NO);
  GST_neighbours_iterate (&notify_client_about_neighbour,
                          tc);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Client sent us a HELLO.  Check the request.
 *
 * @param cls the client
 * @param message the HELLO message
 */
static int
check_client_hello (void *cls,
		    const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK; /* FIXME: check here? */
}


/**
 * Client sent us a HELLO.  Process the request.
 *
 * @param cls the client
 * @param message the HELLO message
 */
static void
handle_client_hello (void *cls,
		     const struct GNUNET_MessageHeader *message)
{
  struct TransportClient *tc = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Received HELLO message\n");
  GST_validation_handle_hello (message);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Function called after the transmission is done.  Notify the client that it is
 * OK to send the next message.
 *
 * @param cls closure
 * @param success #GNUNET_OK on success, #GNUNET_NO on failure, #GNUNET_SYSERR if we're not connected
 * @param bytes_payload bytes payload sent
 * @param bytes_on_wire bytes sent on wire
 */
static void
handle_send_transmit_continuation (void *cls,
                                   int success,
                                   size_t bytes_payload,
                                   size_t bytes_on_wire)
{
  struct SendTransmitContinuationContext *stcc = cls;
  struct SendOkMessage send_ok_msg;
  struct GNUNET_TIME_Relative delay;
  const struct GNUNET_HELLO_Address *addr;

  delay = GNUNET_TIME_absolute_get_duration (stcc->send_time);
  addr = GST_neighbour_get_current_address (&stcc->target);
  if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "It took us %s to send %u/%u bytes to %s (%d, %s)\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES),
                (unsigned int) bytes_payload,
                (unsigned int) bytes_on_wire,
                GNUNET_i2s (&stcc->target),
                success,
                (NULL != addr) ? addr->transport_name : "%");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "It took us %s to send %u/%u bytes to %s (%d, %s)\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
							GNUNET_YES),
                (unsigned int) bytes_payload,
                (unsigned int) bytes_on_wire,
                GNUNET_i2s (&stcc->target),
                success,
                (NULL != addr) ? addr->transport_name : "%");

  if (GNUNET_NO == stcc->down)
  {
    /* Only send confirmation if we are still connected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending SEND_OK for transmission request %llu\n",
                stcc->uuid);
    send_ok_msg.header.size = htons (sizeof (send_ok_msg));
    send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
    send_ok_msg.bytes_msg = htonl (bytes_payload);
    send_ok_msg.bytes_physical = htonl (bytes_on_wire);
    send_ok_msg.success = htonl (success);
    send_ok_msg.peer = stcc->target;
    unicast (stcc->tc,
	     &send_ok_msg.header,
	     GNUNET_NO);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (active_stccs,
                                                       &stcc->target,
                                                       stcc));
  GNUNET_free (stcc);
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls the client
 * @param obm the send message that was sent
 */
static int
check_client_send (void *cls,
		   const struct OutboundMessage *obm)
{
  uint16_t size;
  const struct GNUNET_MessageHeader *obmm;

  size = ntohs (obm->header.size) - sizeof (struct OutboundMessage);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  if (size != ntohs (obmm->size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls the client
 * @param obm the send message that was sent
 */
static void
handle_client_send (void *cls,
		    const struct OutboundMessage *obm)
{
  static unsigned long long uuid_gen;
  struct TransportClient *tc = cls;
  const struct GNUNET_MessageHeader *obmm;
  struct SendTransmitContinuationContext *stcc;

  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  if (GNUNET_NO == GST_neighbours_test_connected (&obm->peer))
  {
    /* not connected, not allowed to send; can happen due to asynchronous operations */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Could not send message to peer `%s': not connected\n",
                GNUNET_i2s (&obm->peer));
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bytes payload dropped (other peer was not connected)"),
                              ntohs (obmm->size),
			      GNUNET_NO);
    GNUNET_SERVICE_client_continue (tc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received SEND request %llu for `%s' and first message of type %u and total size %u\n",
              uuid_gen,
              GNUNET_i2s (&obm->peer),
              ntohs (obmm->type),
              ntohs (obmm->size));
  GNUNET_SERVICE_client_continue (tc->client);

  stcc = GNUNET_new (struct SendTransmitContinuationContext);
  stcc->target = obm->peer;
  stcc->tc = tc;
  stcc->send_time = GNUNET_TIME_absolute_get ();
  stcc->uuid = uuid_gen++;
  (void) GNUNET_CONTAINER_multipeermap_put (active_stccs,
                                            &stcc->target,
                                            stcc,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GST_manipulation_send (&obm->peer,
                         obmm,
                         ntohs (obmm->size),
                         GNUNET_TIME_relative_ntoh (obm->timeout),
                         &handle_send_transmit_continuation,
                         stcc);
}


/**
 * Take the given address and append it to the set of results sent back to
 * the client.  This function may be called serveral times for a single
 * conversion.   The last invocation will be with a @a address of
 * NULL and a @a res of #GNUNET_OK.  Thus, to indicate conversion
 * errors, the callback might be called first with @a address NULL and
 * @a res being #GNUNET_SYSERR.  In that case, there will still be a
 * subsequent call later with @a address NULL and @a res #GNUNET_OK.
 *
 * @param cls the `struct AddressToStringContext`
 * @param buf text to transmit (contains the human-readable address, or NULL)
 * @param res #GNUNET_OK if conversion was successful, #GNUNET_SYSERR on error,
 *            never #GNUNET_NO
 */
static void
transmit_address_to_client (void *cls,
                            const char *buf,
                            int res)
{
  struct AddressToStringContext *actx = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AddressToStringResultMessage *atsm;
  size_t slen;

  GNUNET_assert ( (GNUNET_OK == res) ||
                  (GNUNET_SYSERR == res) );
  if (NULL == actx->tc)
    return;
  if (NULL == buf)
  {
    env = GNUNET_MQ_msg (atsm,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    if (GNUNET_OK == res)
    {
      /* this was the last call, transmit */
      atsm->res = htonl (GNUNET_OK);
      atsm->addr_len = htonl (0);
      GNUNET_MQ_send (actx->tc->mq,
		      env);
      GNUNET_CONTAINER_DLL_remove (a2s_head,
                                   a2s_tail,
                                   actx);
      GNUNET_free (actx);
      return;
    }
    if (GNUNET_SYSERR == res)
    {
      /* address conversion failed, but there will be more callbacks */
      atsm->res = htonl (GNUNET_SYSERR);
      atsm->addr_len = htonl (0);
      GNUNET_MQ_send (actx->tc->mq,
		      env);
      return;
    }
  }
  GNUNET_assert (GNUNET_OK == res);
  /* succesful conversion, append*/
  slen = strlen (buf) + 1;
  env = GNUNET_MQ_msg_extra (atsm,
			     slen,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
  atsm->res = htonl (GNUNET_YES);
  atsm->addr_len = htonl (slen);
  GNUNET_memcpy (&atsm[1],
		 buf,
		 slen);
  GNUNET_MQ_send (actx->tc->mq,
		  env);
}


/**
 * Client asked to resolve an address.  Check the request.
 *
 * @param cls the client
 * @param alum the resolution request
 * @return #GNUNET_OK if @a alum is well-formed
 */
static int
check_client_address_to_string (void *cls,
				const struct AddressLookupMessage *alum)
{
  const char *plugin_name;
  const char *address;
  uint32_t address_len;
  uint16_t size;

  size = ntohs (alum->header.size);
  address_len = ntohs (alum->addrlen);
  if (size <= sizeof (struct AddressLookupMessage) + address_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  address = (const char *) &alum[1];
  plugin_name = (const char *) &address[address_len];
  if ('\0' != plugin_name[size - sizeof (struct AddressLookupMessage) - address_len - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Client asked to resolve an address.  Process the request.
 *
 * @param cls the client
 * @param alum the resolution request
 */
static void
handle_client_address_to_string (void *cls,
				 const struct AddressLookupMessage *alum)
{
  struct TransportClient *tc = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  const char *plugin_name;
  const char *address;
  uint32_t address_len;
  struct AddressToStringContext *actx;
  struct GNUNET_MQ_Envelope *env;
  struct AddressToStringResultMessage *atsm;
  struct GNUNET_TIME_Relative rtimeout;
  int32_t numeric;

  address_len = ntohs (alum->addrlen);
  address = (const char *) &alum[1];
  plugin_name = (const char *) &address[address_len];
  rtimeout = GNUNET_TIME_relative_ntoh (alum->timeout);
  numeric = ntohs (alum->numeric_only);
  papi = GST_plugins_printer_find (plugin_name);
  if (NULL == papi)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to find plugin `%s'\n",
                plugin_name);
    env = GNUNET_MQ_msg (atsm,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    atsm->res = htonl (GNUNET_SYSERR);
    atsm->addr_len = htonl (0);
    GNUNET_MQ_send (tc->mq,
		    env);
    env = GNUNET_MQ_msg (atsm,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    atsm->res = htonl (GNUNET_OK);
    atsm->addr_len = htonl (0);
    GNUNET_MQ_send (tc->mq,
		    env);
    return;
  }
  actx = GNUNET_new (struct AddressToStringContext);
  actx->tc = tc;
  GNUNET_CONTAINER_DLL_insert (a2s_head,
			       a2s_tail,
			       actx);
  GNUNET_SERVICE_client_disable_continue_warning (tc->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Pretty-printing address of %u bytes using plugin `%s'\n",
              address_len,
              plugin_name);
  papi->address_pretty_printer (papi->cls,
                                plugin_name,
                                address,
				address_len,
                                numeric,
                                rtimeout,
                                &transmit_address_to_client,
                                actx);
}


/**
 * Compose #PeerIterateResponseMessage using the given peer and address.
 *
 * @param peer identity of the peer
 * @param address the address, NULL on disconnect
 * @return composed message
 */
static struct PeerIterateResponseMessage *
compose_address_iterate_response_message (const struct GNUNET_PeerIdentity *peer,
                                          const struct GNUNET_HELLO_Address *address)
{
  struct PeerIterateResponseMessage *msg;
  size_t size;
  size_t tlen;
  size_t alen;
  char *addr;

  GNUNET_assert (NULL != peer);
  if (NULL != address)
  {
    tlen = strlen (address->transport_name) + 1;
    alen = address->address_length;
  }
  else
  {
    tlen = 0;
    alen = 0;
  }
  size = (sizeof (struct PeerIterateResponseMessage) + alen + tlen);
  msg = GNUNET_malloc (size);
  msg->header.size = htons (size);
  msg->header.type
    = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  msg->addrlen = htonl (alen);
  msg->pluginlen = htonl (tlen);

  if (NULL != address)
  {
    msg->local_address_info = htonl((uint32_t) address->local_info);
    addr = (char *) &msg[1];
    GNUNET_memcpy (addr,
		   address->address,
		   alen);
    GNUNET_memcpy (&addr[alen],
		   address->transport_name,
		   tlen);
  }
  return msg;
}


/**
 * Context for #send_validation_information() and
 * #send_peer_information().
 */
struct IterationContext
{
  /**
   * Context to use for the transmission.
   */
  struct TransportClient *tc;

  /**
   * Which peers do we care about?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * #GNUNET_YES if @e id should be ignored because we want all peers.
   */
  int all;
};


/**
 * Output information of neighbours to the given client.
 *
 * @param cls the `struct PeerIterationContext *`
 * @param peer identity of the neighbour
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in inbound quota in NBO
 * @param bandwidth_out outbound quota in NBO
 */
static void
send_peer_information (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_HELLO_Address *address,
                       enum GNUNET_TRANSPORT_PeerState state,
                       struct GNUNET_TIME_Absolute state_timeout,
                       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct IterationContext *pc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct PeerIterateResponseMessage *msg;

  if ( (GNUNET_YES != pc->all) &&
       (0 != memcmp (peer,
		     &pc->id,
		     sizeof (pc->id))) )
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending information about `%s' using address `%s' in state `%s'\n",
              GNUNET_i2s(peer),
              (NULL != address) ? GST_plugins_a2s (address) : "<none>",
              GNUNET_TRANSPORT_ps2s (state));
  msg = compose_address_iterate_response_message (peer,
						  address);
  msg->state = htonl (state);
  msg->state_timeout = GNUNET_TIME_absolute_hton(state_timeout);
  env = GNUNET_MQ_msg_copy (&msg->header);
  GNUNET_free (msg);
  GNUNET_MQ_send (pc->tc->mq,
		  env);
}


/**
 * Client asked to obtain information about a specific or all peers
 * Process the request.
 *
 * @param cls the client
 * @param msg the peer address information request
 */
static void
handle_client_monitor_peers (void *cls,
			     const struct PeerMonitorMessage *msg)
{
  struct TransportClient *tc = cls;
  struct IterationContext pc;

  if (CT_NONE != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_SERVICE_client_disable_continue_warning (tc->client);
  GNUNET_SERVICE_client_mark_monitor (tc->client);

  /* Send initial list */
  pc.tc = tc;
  if (0 == memcmp (&msg->peer,
                   &all_zeros,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* iterate over all neighbours */
    pc.all = GNUNET_YES;
    pc.id = msg->peer;
  }
  else
  {
    /* just return one neighbour */
    pc.all = GNUNET_NO;
    pc.id = msg->peer;
  }
  GST_neighbours_iterate (&send_peer_information,
                          &pc);

  if (GNUNET_YES != ntohl (msg->one_shot))
  {
    tc->details.monitor_peer = msg->peer;
    tc->type = CT_MONITOR;
    if (0 != memcmp (&msg->peer,
		     &all_zeros,
		     sizeof (struct GNUNET_PeerIdentity)))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Client %p started monitoring of the peer `%s'\n",
		  tc,
		  GNUNET_i2s (&msg->peer));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Client %p started monitoring all peers\n",
		  tc);
  }
  else
  {
    struct GNUNET_MessageHeader *msg;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (msg,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE_END);
    GNUNET_MQ_send (tc->mq,
		    env);
  }
}


/**
 * Function called by the plugin with information about the
 * current sessions managed by the plugin (for monitoring).
 *
 * @param cls closure
 * @param session session handle this information is about,
 *        NULL to indicate that we are "in sync" (initial
 *        iteration complete)
 * @param info information about the state of the session,
 *        NULL if @a session is also NULL and we are
 *        merely signalling that the initial iteration is over
 */
static void
plugin_session_info_cb (void *cls,
			struct GNUNET_ATS_Session *session,
			const struct GNUNET_TRANSPORT_SessionInfo *info)
{
  struct GNUNET_MQ_Envelope *env;
  struct TransportPluginMonitorMessage *msg;
  struct GNUNET_MessageHeader *sync;
  size_t size;
  size_t slen;
  uint16_t alen;
  char *name;
  char *addr;

  if (0 == GNUNET_notification_context_get_size (plugin_nc))
  {
    GST_plugins_monitor_subscribe (NULL,
                                   NULL);
    return;
  }
  if ( (NULL == info) &&
       (NULL == session) )
  {
    /* end of initial iteration */
    if (NULL != sync_client)
    {
      env = GNUNET_MQ_msg (sync,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_SYNC);
      GNUNET_MQ_send (sync_client->mq,
		      env);
      sync_client = NULL;
    }
    return;
  }
  GNUNET_assert (NULL != info);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Plugin event for peer %s on transport %s\n",
              GNUNET_i2s (&info->address->peer),
              info->address->transport_name);
  slen = strlen (info->address->transport_name) + 1;
  alen = info->address->address_length;
  size = sizeof (struct TransportPluginMonitorMessage) + slen + alen;
  if (size > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }
  msg = GNUNET_malloc (size);
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT);
  msg->session_state = htons ((uint16_t) info->state);
  msg->is_inbound = htons ((int16_t) info->is_inbound);
  msg->msgs_pending = htonl (info->num_msg_pending);
  msg->bytes_pending = htonl (info->num_bytes_pending);
  msg->timeout = GNUNET_TIME_absolute_hton (info->session_timeout);
  msg->delay = GNUNET_TIME_absolute_hton (info->receive_delay);
  msg->peer = info->address->peer;
  msg->session_id = (uint64_t) (intptr_t) session;
  msg->plugin_name_len = htons (slen);
  msg->plugin_address_len = htons (alen);
  name = (char *) &msg[1];
  GNUNET_memcpy (name,
		 info->address->transport_name,
		 slen);
  addr = &name[slen];
  GNUNET_memcpy (addr,
          info->address->address,
          alen);
  if (NULL != sync_client)
  {
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg_copy (&msg->header);
    GNUNET_MQ_send (sync_client->mq,
		    env);
  }
  else
  {
    GNUNET_notification_context_broadcast (plugin_nc,
					   &msg->header,
					   GNUNET_NO);
  }
  GNUNET_free (msg);
}


/**
 * Client asked to obtain information about all plugin connections.
 *
 * @param cls the client
 * @param message the peer address information request
 */
static void
handle_client_monitor_plugins (void *cls,
			       const struct GNUNET_MessageHeader *message)
{
  struct TransportClient *tc = cls;

  GNUNET_SERVICE_client_mark_monitor (tc->client);
  GNUNET_SERVICE_client_disable_continue_warning (tc->client);
  GNUNET_notification_context_add (plugin_nc,
				   tc->mq);
  GNUNET_assert (NULL == sync_client);
  sync_client = tc;
  GST_plugins_monitor_subscribe (&plugin_session_info_cb,
                                 NULL);
}


/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 * @param may_drop #GNUNET_YES if the message can be dropped / is payload
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg,
                       int may_drop)
{
  struct TransportClient *tc;
  int done;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to broadcast message of type %u with %u bytes\n",
              (unsigned int) ntohs (msg->type),
              (unsigned int) ntohs (msg->size));
  done = GNUNET_NO;
  for (tc = clients_head; NULL != tc; tc = tc->next)
  {
    if ( (GNUNET_YES == may_drop) &&
         (CT_CORE != tc->type) )
      continue; /* skip, this client does not care about payload */
    unicast (tc,
	     msg,
	     may_drop);
    done = GNUNET_YES;
  }
  if (GNUNET_NO == done)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Message of type %u not delivered, is CORE service up?\n",
		ntohs (msg->type));
}


/**
 * Broadcast the new active address to all clients monitoring the peer.
 *
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL on disconnect
 * @param state the current state of the peer
 * @param state_timeout the time out for the state
 */
void
GST_clients_broadcast_peer_notification (const struct GNUNET_PeerIdentity *peer,
                                         const struct GNUNET_HELLO_Address *address,
                                         enum GNUNET_TRANSPORT_PeerState state,
                                         struct GNUNET_TIME_Absolute state_timeout)
{
  struct GNUNET_MQ_Envelope *env;
  struct PeerIterateResponseMessage *msg;
  struct TransportClient *tc;

  msg = compose_address_iterate_response_message (peer,
						  address);
  msg->state = htonl (state);
  msg->state_timeout = GNUNET_TIME_absolute_hton (state_timeout);
  for (tc = clients_head; NULL != tc; tc = tc->next)
  {
    if (CT_MONITOR != tc->type)
      continue;
    if ((0 == memcmp (&tc->details.monitor_peer,
		      &all_zeros,
                      sizeof (struct GNUNET_PeerIdentity))) ||
        (0 == memcmp (&tc->details.monitor_peer,
		      peer,
                      sizeof (struct GNUNET_PeerIdentity))))
    {
      env = GNUNET_MQ_msg_copy (&msg->header);
      GNUNET_MQ_send (tc->mq,
		      env);
    }
  }
  GNUNET_free (msg);
}


/**
 * Mark the peer as down so we don't call the continuation
 * context in the future.
 *
 * @param cls NULL
 * @param peer peer that got disconnected
 * @param value a `struct SendTransmitContinuationContext` to mark
 * @return #GNUNET_OK (continue to iterate)
 */
static int
mark_peer_down (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                void *value)
{
  struct SendTransmitContinuationContext *stcc = value;

  stcc->down = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Notify all clients about a disconnect, and cancel
 * pending SEND_OK messages for this peer.
 *
 * @param peer peer that disconnected
 */
void
GST_clients_broadcast_disconnect (const struct GNUNET_PeerIdentity *peer)
{
  struct DisconnectInfoMessage disconnect_msg;

  GNUNET_CONTAINER_multipeermap_get_multiple (active_stccs,
                                              peer,
                                              &mark_peer_down,
                                              NULL);
  disconnect_msg.header.size = htons (sizeof(struct DisconnectInfoMessage));
  disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.peer = *peer;
  GST_clients_broadcast (&disconnect_msg.header,
                         GNUNET_NO);

}


/**
 * Transmit our HELLO message to the given (connected) neighbour.
 *
 * @param cls the 'HELLO' message
 * @param peer identity of the peer
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in inbound quota in NBO
 * @param bandwidth_out outbound quota in NBO
 */
static void
transmit_our_hello (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_HELLO_Address *address,
		    enum GNUNET_TRANSPORT_PeerState state,
		    struct GNUNET_TIME_Absolute state_timeout,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  const struct GNUNET_MessageHeader *hello = cls;

  if (0 ==
      memcmp (peer,
              &GST_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return; /* not to ourselves */
  if (GNUNET_NO == GST_neighbours_test_connected (peer))
    return;

  GST_neighbours_send (peer,
		       hello,
		       ntohs (hello->size),
		       hello_expiration,
                       NULL,
		       NULL);
}


/**
 * My HELLO has changed. Tell everyone who should know.
 *
 * @param cls unused
 * @param hello new HELLO
 */
static void
process_hello_update (void *cls,
                      const struct GNUNET_MessageHeader *hello)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting HELLO to clients\n");
  GST_clients_broadcast (hello, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting HELLO to neighbours\n");
  GST_neighbours_iterate (&transmit_our_hello,
                          (void *) hello);
}


/**
 * We received some payload.  Prepare to pass it on to our clients.
 *
 * @param address address and (claimed) identity of the other peer
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param message the message to process
 * @return how long the plugin should wait until receiving more data
 */
static struct GNUNET_TIME_Relative
process_payload (const struct GNUNET_HELLO_Address *address,
                 struct GNUNET_ATS_Session *session,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TIME_Relative ret;
  int do_forward;
  struct InboundMessage *im;
  size_t msg_size = ntohs (message->size);
  size_t size = sizeof(struct InboundMessage) + msg_size;
  char buf[size] GNUNET_ALIGN;

  do_forward = GNUNET_SYSERR;
  ret = GST_neighbours_calculate_receive_delay (&address->peer,
						msg_size,
						&do_forward);
  if (! GST_neighbours_test_connected (&address->peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Discarded %u bytes type %u payload from peer `%s'\n",
                (unsigned int) msg_size,
                ntohs (message->type),
                GNUNET_i2s (&address->peer));
    GNUNET_STATISTICS_update (GST_stats, gettext_noop
                              ("# bytes payload discarded due to not connected peer"),
                              msg_size,
                              GNUNET_NO);
    return ret;
  }

  if (GNUNET_YES != do_forward)
    return ret;
  im = (struct InboundMessage *) buf;
  im->header.size = htons (size);
  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
  im->peer = address->peer;
  GNUNET_memcpy (&im[1],
		 message,
		 ntohs (message->size));
  GST_clients_broadcast (&im->header,
			 GNUNET_YES);
  return ret;
}


/**
 * Task to asynchronously terminate a session.
 *
 * @param cls the `struct GNUNET_ATS_SessionKiller` with the information for the kill
 */
static void
kill_session_task (void *cls)
{
  struct GNUNET_ATS_SessionKiller *sk = cls;

  sk->task = NULL;
  GNUNET_CONTAINER_DLL_remove (sk_head,
			       sk_tail,
			       sk);
  sk->plugin->disconnect_session (sk->plugin->cls,
				  sk->session);
  GNUNET_free(sk);
}


/**
 * Force plugin to terminate session due to communication
 * issue.
 *
 * @param plugin_name name of the plugin
 * @param session session to termiante
 */
static void
kill_session (const char *plugin_name,
              struct GNUNET_ATS_Session *session)
{
  struct GNUNET_TRANSPORT_PluginFunctions *plugin;
  struct GNUNET_ATS_SessionKiller *sk;

  for (sk = sk_head; NULL != sk; sk = sk->next)
    if (sk->session == session)
      return;
  plugin = GST_plugins_find (plugin_name);
  if (NULL == plugin)
  {
    GNUNET_break(0);
    return;
  }
  /* need to issue disconnect asynchronously */
  sk = GNUNET_new (struct GNUNET_ATS_SessionKiller);
  sk->session = session;
  sk->plugin = plugin;
  sk->task = GNUNET_SCHEDULER_add_now (&kill_session_task,
				       sk);
  GNUNET_CONTAINER_DLL_insert (sk_head,
                               sk_tail,
                               sk);
}


/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and ???
 *
 * @param cls the message
 * @param peer the peer
 * @param address the address
 * @param session the session
 * @param result the result
 */
static void
connect_bl_check_cont (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
		       const struct GNUNET_HELLO_Address *address,
		       struct GNUNET_ATS_Session *session,
                       int result)
{
  struct GNUNET_MessageHeader *msg = cls;

  if (GNUNET_OK == result)
  {
    /* Blacklist allows to speak to this peer, forward SYN to neighbours  */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received SYN message from peer `%s' at `%s'\n",
                GNUNET_i2s (peer),
                GST_plugins_a2s (address));
    if (GNUNET_OK !=
        GST_neighbours_handle_session_syn (msg,
                                           peer))
    {
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (address->transport_name,
                    session);
    }
    GNUNET_free (msg);
    return;
  }
  GNUNET_free (msg);
  if (GNUNET_SYSERR == result)
    return; /* check was aborted, session destroyed */
  /* Blacklist denies to speak to this peer */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Discarding SYN message from `%s' due to denied blacklist check\n",
	      GNUNET_i2s (peer));
  kill_session (address->transport_name,
		session);
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param address address and (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
struct GNUNET_TIME_Relative
GST_receive_callback (void *cls,
                      const struct GNUNET_HELLO_Address *address,
                      struct GNUNET_ATS_Session *session,
                      const struct GNUNET_MessageHeader *message)
{
  const char *plugin_name = cls;
  struct GNUNET_TIME_Relative ret;
  uint16_t type;

  ret = GNUNET_TIME_UNIT_ZERO;
  if (NULL == message)
    goto end;
  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message with type %u from peer `%s' at %s\n",
              type,
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));

  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# bytes total received"),
                            ntohs (message->size),
                            GNUNET_NO);
  GST_neighbours_notify_data_recv (address,
                                   message);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_HELLO_LEGACY:
    /* Legacy HELLO message, discard  */
    return ret;
  case GNUNET_MESSAGE_TYPE_HELLO:
    if (GNUNET_OK != GST_validation_handle_hello (message))
    {
      GNUNET_break_op (0);
      GST_blacklist_abort_matching (address,
				    session);
    }
    return ret;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processing PING from `%s'\n",
                GST_plugins_a2s (address));
    if (GNUNET_OK !=
        GST_validation_handle_ping (&address->peer,
                                    message,
                                    address,
                                    session))
    {
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (plugin_name,
                    session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Processing PONG from `%s'\n",
               GST_plugins_a2s (address));
    if (GNUNET_OK !=
	GST_validation_handle_pong (&address->peer,
				    message))
    {
      GNUNET_break_op (0);
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN:
    /* Do blacklist check if communication with this peer is allowed */
    (void) GST_blacklist_test_allowed (&address->peer,
				       NULL,
				       &connect_bl_check_cont,
				       GNUNET_copy_message (message),
				       address,
				       session);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK:
    if (GNUNET_OK !=
        GST_neighbours_handle_session_syn_ack (message,
                                               address,
                                               session))
    {
      GST_blacklist_abort_matching (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK:
    if (GNUNET_OK !=
        GST_neighbours_handle_session_ack (message,
                                           address,
                                           session))
    {
      GNUNET_break_op(0);
      GST_blacklist_abort_matching (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT:
    GST_neighbours_handle_disconnect_message (&address->peer,
                                              message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_QUOTA:
    GST_neighbours_handle_quota_message (&address->peer,
                                         message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE:
    GST_neighbours_keepalive (&address->peer,
                              message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE:
    GST_neighbours_keepalive_response (&address->peer,
                                       message);
    break;
  default:
    /* should be payload */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# bytes payload received"),
                              ntohs (message->size),
                              GNUNET_NO);
    ret = process_payload (address,
                           session,
                           message);
    break;
  }
 end:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Allowing receive from peer %s to continue in %s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_STRINGS_relative_time_to_string (ret,
                                                      GNUNET_YES));
  return ret;
}


/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.  Update our HELLO.
 *
 * @param cls name of the plugin (const char*)
 * @param add_remove should the address added (YES) or removed (NO) from the
 *                   set of valid addresses?
 * @param address the address to add or remove
 */
static void
plugin_env_address_change_notification (void *cls,
                                        int add_remove,
                                        const struct GNUNET_HELLO_Address *address)
{
  static int addresses = 0;

  if (GNUNET_YES == add_remove)
  {
    addresses ++;
    GNUNET_STATISTICS_update (GST_stats,
                              "# transport addresses",
                              1,
                              GNUNET_NO);
  }
  else if (GNUNET_NO == add_remove)
  {
    if (0 == addresses)
    {
      GNUNET_break (0);
    }
    else
    {
      addresses --;
      GNUNET_STATISTICS_update (GST_stats,
                                "# transport addresses",
                                -1,
                                GNUNET_NO);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Transport now has %u addresses to communicate\n",
              addresses);
  GST_hello_modify_addresses (add_remove,
                              address);
}


/**
 * Function that will be called whenever the plugin internally
 * cleans up a session pointer and hence the service needs to
 * discard all of those sessions as well.  Plugins that do not
 * use sessions can simply omit calling this function and always
 * use NULL wherever a session pointer is needed.  This function
 * should be called BEFORE a potential "TransmitContinuation"
 * from the "TransmitFunction".
 *
 * @param cls closure
 * @param address which address was the session for
 * @param session which session is being destoyed
 */
static void
plugin_env_session_end (void *cls,
                        const struct GNUNET_HELLO_Address *address,
                        struct GNUNET_ATS_Session *session)
{
  struct GNUNET_ATS_SessionKiller *sk;

  if (NULL == address)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (strlen (address->transport_name) > 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notification from plugin about terminated session %p from peer `%s' address `%s'\n",
              session,
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));

  GST_neighbours_session_terminated (&address->peer,
				     session);
  GST_ats_del_session (address,
                       session);
  GST_blacklist_abort_matching (address,
				session);

  for (sk = sk_head; NULL != sk; sk = sk->next)
  {
    if (sk->session == session)
    {
      GNUNET_CONTAINER_DLL_remove (sk_head,
				   sk_tail,
				   sk);
      GNUNET_SCHEDULER_cancel (sk->task);
      GNUNET_free(sk);
      break;
    }
  }
}


/**
 * Black list check result from blacklist check triggered when a
 * plugin gave us a new session in #plugin_env_session_start().  If
 * connection to the peer is disallowed, kill the session.
 *
 * @param cls NULL
 * @param peer the peer
 * @param address address associated with the request
 * @param session session associated with the request
 * @param result the result
 */
static void
plugin_env_session_start_bl_check_cont (void *cls,
                                        const struct GNUNET_PeerIdentity *peer,
					const struct GNUNET_HELLO_Address *address,
					struct GNUNET_ATS_Session *session,
                                        int result)
{
  if (GNUNET_OK != result)
  {
    kill_session (address->transport_name,
                  session);
    return;
  }
  if (GNUNET_YES !=
      GNUNET_HELLO_address_check_option (address,
					 GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Informing verifier about inbound session's address `%s'\n",
                GST_plugins_a2s (address));
    GST_validation_handle_address (address);
  }
}


/**
 * Plugin tells transport service about a new inbound session
 *
 * @param cls unused
 * @param address the address
 * @param session the new session
 * @param scope network scope information
 */
static void
plugin_env_session_start (void *cls,
                          const struct GNUNET_HELLO_Address *address,
                          struct GNUNET_ATS_Session *session,
                          enum GNUNET_ATS_Network_Type scope)
{
  struct GNUNET_ATS_Properties prop;

  if (NULL == address)
  {
    GNUNET_break(0);
    return;
  }
  if (NULL == session)
  {
    GNUNET_break(0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Notification from plugin `%s' about new session from peer `%s' address `%s'\n",
              address->transport_name,
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));
  if (GNUNET_YES ==
      GNUNET_HELLO_address_check_option (address,
                                         GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    /* inbound is always new, but outbound MAY already be known, but
       for example for UNIX, we have symmetric connections and thus we
       may not know the address yet; add if necessary! */
    /* FIXME: maybe change API here so we just pass scope? */
    memset (&prop,
	    0,
	    sizeof (prop));
    GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != scope);
    prop.scope = scope;
    GST_ats_add_inbound_address (address,
                                 session,
                                 &prop);
  }
  /* Do blacklist check if communication with this peer is allowed */
  (void) GST_blacklist_test_allowed (&address->peer,
				     address->transport_name,
				     &plugin_env_session_start_bl_check_cont,
				     NULL,
				     address,
				     session);
}


/**
 * Function called by ATS to notify the callee that the
 * assigned bandwidth or address for a given peer was changed.  If the
 * callback is called with address/bandwidth assignments of zero, the
 * ATS disconnect function will still be called once the disconnect
 * actually happened.
 *
 * @param cls closure
 * @param peer the peer this address is intended for
 * @param address address to use (for peer given in address)
 * @param session session to use (if available)
 * @param bandwidth_out assigned outbound bandwidth for the connection in NBO,
 * 	0 to disconnect from peer
 * @param bandwidth_in assigned inbound bandwidth for the connection in NBO,
 * 	0 to disconnect from peer
 * @param ats ATS information
 * @param ats_count number of @a ats elements
 */
static void
ats_request_address_change (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_HELLO_Address *address,
                            struct GNUNET_ATS_Session *session,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  uint32_t bw_in = ntohl (bandwidth_in.value__);
  uint32_t bw_out = ntohl (bandwidth_out.value__);

  if (NULL == peer)
  {
    /* ATS service died, all suggestions become invalid!
       (but we'll keep using the allocations for a little
       while, to keep going while ATS restarts) */
    /* FIXME: We should drop all
       connections now, as ATS won't explicitly tell
       us and be unaware of ongoing resource allocations! */
    return;
  }
  /* ATS tells me to disconnect from peer */
  if ((0 == bw_in) && (0 == bw_out))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "ATS tells me to disconnect from peer `%s'\n",
                GNUNET_i2s (peer));
    GST_neighbours_force_disconnect (peer);
    return;
  }
  GNUNET_assert (NULL != address);
  GNUNET_STATISTICS_update (GST_stats,
                            "# ATS suggestions received",
                            1,
                            GNUNET_NO);
  GST_neighbours_switch_to_address (address,
                                    session,
                                    bandwidth_in,
                                    bandwidth_out);
}


/**
 * Closure for #test_connection_ok().
 */
struct TestConnectionContext
{
  /**
   * Is this the first neighbour we're checking?
   */
  int first;

  /**
   * Handle to the blacklisting client we need to ask.
   */
  struct TransportClient *tc;
};


/**
 * Got the result about an existing connection from a new blacklister.
 * Shutdown the neighbour if necessary.
 *
 * @param cls unused
 * @param peer the neighbour that was investigated
 * @param address address associated with the request
 * @param session session associated with the request
 * @param allowed #GNUNET_OK if we can keep it,
 *                #GNUNET_NO if we must shutdown the connection
 */
static void
confirm_or_drop_neighbour (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_HELLO_Address *address,
			   struct GNUNET_ATS_Session *session,
                           int allowed)
{
  if (GNUNET_OK == allowed)
    return;                     /* we're done */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# disconnects due to blacklist"),
			    1,
                            GNUNET_NO);
  GST_neighbours_force_disconnect (peer);
}


/**
 * Test if an existing connection is still acceptable given a new
 * blacklisting client.
 *
 * @param cls the `struct TestConnectionContext *`
 * @param peer identity of the peer
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in bandwidth assigned inbound
 * @param bandwidth_out bandwidth assigned outbound
 */
static void
test_connection_ok (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_HELLO_Address *address,
		    enum GNUNET_TRANSPORT_PeerState state,
		    struct GNUNET_TIME_Absolute state_timeout,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct TestConnectionContext *tcc = cls;
  struct GST_BlacklistCheck *bc;

  bc = GNUNET_new (struct GST_BlacklistCheck);
  GNUNET_CONTAINER_DLL_insert (bc_head,
			       bc_tail,
			       bc);
  bc->peer = *peer;
  bc->address = GNUNET_HELLO_address_copy (address);
  bc->cont = &confirm_or_drop_neighbour;
  bc->cont_cls = NULL;
  bc->bl_pos = tcc->tc;
  if (GNUNET_YES == tcc->first)
  {
    /* all would wait for the same client, no need to
     * create more than just the first task right now */
    bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					 bc);
    tcc->first = GNUNET_NO;
  }
}


/**
 * Initialize a blacklisting client.  We got a blacklist-init
 * message from this client, add it to the list of clients
 * to query for blacklisting.
 *
 * @param cls the client
 * @param message the blacklist-init message that was sent
 */
static void
handle_client_blacklist_init (void *cls,
			      const struct GNUNET_MessageHeader *message)
{
  struct TransportClient *tc = cls;
  struct TestConnectionContext tcc;

  if (CT_NONE != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_SERVICE_client_mark_monitor (tc->client);
  tc->type = CT_BLACKLIST;
  tc->details.blacklist.call_receive_done = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New blacklist client %p\n",
              tc);
  /* confirm that all existing connections are OK! */
  tcc.tc = tc;
  tcc.first = GNUNET_YES;
  GST_neighbours_iterate (&test_connection_ok,
			  &tcc);
}


/**
 * Free the given entry in the blacklist.
 *
 * @param cls unused
 * @param key host identity (unused)
 * @param value the blacklist entry
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_blacklist_entry (void *cls,
		      const struct GNUNET_PeerIdentity *key,
		      void *value)
{
  char *be = value;

  GNUNET_free_non_null (be);
  return GNUNET_OK;
}


/**
 * Set traffic metric to manipulate
 *
 * @param cls closure
 * @param message containing information
 */
static void
handle_client_set_metric (void *cls,
			  const struct TrafficMetricMessage *tm)
{
  struct TransportClient *tc = cls;

  GST_manipulation_set_metric (tm);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 */
static void
shutdown_task (void *cls)
{
  struct AddressToStringContext *cur;

  GST_neighbours_stop ();
  GST_plugins_unload ();
  GST_validation_stop ();
  GST_ats_done ();
  GNUNET_ATS_scheduling_done (GST_ats);
  GST_ats = NULL;
  GNUNET_ATS_connectivity_done (GST_ats_connect);
  GST_ats_connect = NULL;
  GNUNET_ATS_scanner_done (GST_is);
  GST_is = NULL;
  while (NULL != (cur = a2s_head))
  {
    GNUNET_CONTAINER_DLL_remove (a2s_head,
				 a2s_tail,
				 cur);
    GNUNET_free (cur);
  }
  if (NULL != plugin_nc)
  {
    GNUNET_notification_context_destroy (plugin_nc);
    plugin_nc = NULL;
  }
  GNUNET_CONTAINER_multipeermap_destroy (active_stccs);
  active_stccs = NULL;
  if (NULL != blacklist)
  {
    GNUNET_CONTAINER_multipeermap_iterate (blacklist,
					   &free_blacklist_entry,
					   NULL);
    GNUNET_CONTAINER_multipeermap_destroy (blacklist);
    blacklist = NULL;
  }
  GST_hello_stop ();
  GST_manipulation_stop ();

  if (NULL != GST_peerinfo)
  {
    GNUNET_PEERINFO_disconnect (GST_peerinfo);
    GST_peerinfo = NULL;
  }
  if (NULL != GST_stats)
  {
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    GST_stats = NULL;
  }
  if (NULL != GST_my_private_key)
  {
    GNUNET_free (GST_my_private_key);
    GST_my_private_key = NULL;
  }
}


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the `struct GST_BlacklistCheck *`
 */
static void
do_blacklist_check (void *cls)
{
  struct GST_BlacklistCheck *bc = cls;
  struct TransportClient *tc;
  struct GNUNET_MQ_Envelope *env;
  struct BlacklistMessage *bm;

  bc->task = NULL;
  while (NULL != (tc = bc->bl_pos))
  {
    if (CT_BLACKLIST == tc->type)
      break;
    bc->bl_pos = tc->next;
  }
  if (NULL == tc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No other blacklist clients active, will allow neighbour `%s'\n",
                GNUNET_i2s (&bc->peer));

    bc->cont (bc->cont_cls,
	      &bc->peer,
	      bc->address,
	      bc->session,
	      GNUNET_OK);
    GST_blacklist_test_cancel (bc);
    return;
  }
  if ( (NULL != tc->details.blacklist.bc) ||
       (GNUNET_NO != tc->details.blacklist.waiting_for_reply) )
    return;                     /* someone else busy with this client */
  tc->details.blacklist.bc = bc;
  env = GNUNET_MQ_msg (bm,
		       GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY);
  bm->is_allowed = htonl (0);
  bm->peer = bc->peer;
  GNUNET_MQ_send (tc->mq,
		  env);
  if (GNUNET_YES == tc->details.blacklist.call_receive_done)
  {
    tc->details.blacklist.call_receive_done = GNUNET_NO;
    GNUNET_SERVICE_client_continue (tc->client);
  }
  tc->details.blacklist.waiting_for_reply = GNUNET_YES;
}


/**
 * A blacklisting client has sent us reply. Process it.
 *
 * @param cls the client
 * @param msg the blacklist-reply message that was sent
 */
static void
handle_client_blacklist_reply (void *cls,
			       const struct BlacklistMessage *msg)
{
  struct TransportClient *tc = cls;
  struct GST_BlacklistCheck *bc;

  if (CT_BLACKLIST != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Blacklist client %p sent reply for `%s'\n",
              tc,
              GNUNET_i2s (&msg->peer));
  bc = tc->details.blacklist.bc;
  tc->details.blacklist.bc = NULL;
  tc->details.blacklist.waiting_for_reply = GNUNET_NO;
  tc->details.blacklist.call_receive_done = GNUNET_YES;
  if (NULL != bc)
  {
    /* only run this if the blacklist check has not been
     * cancelled in the meantime... */
    GNUNET_assert (bc->bl_pos == tc);
    if (ntohl (msg->is_allowed) == GNUNET_SYSERR)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist check failed, peer not allowed\n");
      /* For the duration of the continuation, make the ongoing
	 check invisible (to avoid double-cancellation); then
	 add it back again so we can re-use GST_blacklist_test_cancel() */
      GNUNET_CONTAINER_DLL_remove (bc_head,
				   bc_tail,
				   bc);
      bc->cont (bc->cont_cls,
		&bc->peer,
		bc->address,
		bc->session,
		GNUNET_NO);
      GNUNET_CONTAINER_DLL_insert (bc_head,
				   bc_tail,
				   bc);
      GST_blacklist_test_cancel (bc);
      tc->details.blacklist.call_receive_done = GNUNET_NO;
      GNUNET_SERVICE_client_continue (tc->client);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist check succeeded, continuing with checks\n");
      tc->details.blacklist.call_receive_done = GNUNET_NO;
      GNUNET_SERVICE_client_continue (tc->client);
      bc->bl_pos = tc->next;
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					   bc);
    }
  }
  /* check if any other blacklist checks are waiting for this blacklister */
  for (bc = bc_head; bc != NULL; bc = bc->next)
    if ( (bc->bl_pos == tc) &&
	 (NULL == bc->task) )
    {
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					   bc);
      break;
    }
}


/**
 * Add the given peer to the blacklist (for the given transport).
 *
 * @param peer peer to blacklist
 * @param transport_name transport to blacklist for this peer, NULL for all
 */
void
GST_blacklist_add_peer (const struct GNUNET_PeerIdentity *peer,
                        const char *transport_name)
{
  char *transport = NULL;

  if (NULL != transport_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Adding peer `%s' with plugin `%s' to blacklist\n",
		GNUNET_i2s (peer),
		transport_name);
    transport = GNUNET_strdup (transport_name);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Adding peer `%s' with all plugins to blacklist\n",
		GNUNET_i2s (peer));
  if (NULL == blacklist)
    blacklist =
      GNUNET_CONTAINER_multipeermap_create (TRANSPORT_BLACKLIST_HT_SIZE,
					    GNUNET_NO);

  GNUNET_CONTAINER_multipeermap_put (blacklist,
				     peer,
                                     transport,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Abort blacklist if @a address and @a session match.
 *
 * @param address address used to abort matching checks
 * @param session session used to abort matching checks
 */
void
GST_blacklist_abort_matching (const struct GNUNET_HELLO_Address *address,
			      struct GNUNET_ATS_Session *session)
{
  struct GST_BlacklistCheck *bc;
  struct GST_BlacklistCheck *n;

  n = bc_head;
  while (NULL != (bc = n))
  {
    n = bc->next;
    if ( (bc->session == session) &&
	 (0 == GNUNET_HELLO_address_cmp (bc->address,
					 address)) )
    {
      bc->cont (bc->cont_cls,
		&bc->peer,
		bc->address,
		bc->session,
		GNUNET_SYSERR);
      GST_blacklist_test_cancel (bc);
    }
  }
}


/**
 * Test if the given blacklist entry matches.  If so,
 * abort the iteration.
 *
 * @param cls the transport name to match (const char*)
 * @param key the key (unused)
 * @param value the 'char *' (name of a blacklisted transport)
 * @return #GNUNET_OK if the entry does not match, #GNUNET_NO if it matches
 */
static int
test_blacklisted (void *cls,
		  const struct GNUNET_PeerIdentity *key,
		  void *value)
{
  const char *transport_name = cls;
  char *be = value;

  /* Blacklist entry be:
   *  (NULL == be): peer is blacklisted with all plugins
   *  (NULL != be): peer is blacklisted for a specific plugin
   *
   * If (NULL != transport_name) we look for a transport specific entry:
   *  if (transport_name == be) forbidden
   *
   */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Comparing BL request for peer `%4s':`%s' with BL entry: `%s'\n",
	      GNUNET_i2s (key),
	      (NULL == transport_name) ? "unspecified" : transport_name,
	      (NULL == be) ? "all plugins" : be);
  /* all plugins for this peer were blacklisted: disallow */
  if (NULL == value)
    return GNUNET_NO;

  /* blacklist check for specific transport */
  if ( (NULL != transport_name) &&
       (NULL != value) )
  {
    if (0 == strcmp (transport_name,
		     be))
      return GNUNET_NO;           /* plugin is blacklisted! */
  }
  return GNUNET_OK;
}


/**
 * Test if a peer/transport combination is blacklisted.
 *
 * @param peer the identity of the peer to test
 * @param transport_name name of the transport to test, never NULL
 * @param cont function to call with result
 * @param cont_cls closure for @a cont
 * @param address address to pass back to @a cont, can be NULL
 * @param session session to pass back to @a cont, can be NULL
 * @return handle to the blacklist check, NULL if the decision
 *        was made instantly and @a cont was already called
 */
struct GST_BlacklistCheck *
GST_blacklist_test_allowed (const struct GNUNET_PeerIdentity *peer,
                            const char *transport_name,
                            GST_BlacklistTestContinuation cont,
                            void *cont_cls,
			    const struct GNUNET_HELLO_Address *address,
			    struct GNUNET_ATS_Session *session)
{
  struct GST_BlacklistCheck *bc;
  struct TransportClient *tc;

  GNUNET_assert (NULL != peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Blacklist check for peer `%s':%s\n",
              GNUNET_i2s (peer),
              (NULL != transport_name) ? transport_name : "unspecified");

  /* Check local blacklist by iterating over hashmap
   * If iteration is aborted, we found a matching blacklist entry */
  if ((NULL != blacklist) &&
      (GNUNET_SYSERR ==
       GNUNET_CONTAINER_multipeermap_get_multiple (blacklist, peer,
                                                   &test_blacklisted,
                                                   (void *) transport_name)))
  {
    /* Disallowed by config, disapprove instantly */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to blacklist"),
                              1,
			      GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Disallowing connection to peer `%s' on transport %s\n"),
    		GNUNET_i2s (peer),
                (NULL != transport_name) ? transport_name : "unspecified");
    if (NULL != cont)
      cont (cont_cls,
	    peer,
	    address,
	    session,
	    GNUNET_NO);
    return NULL;
  }

  for (tc = clients_head; NULL != tc; tc = tc->next)
    if (CT_BLACKLIST == tc->type)
      break;
  if (NULL == tc)
  {
    /* no blacklist clients, approve instantly */
    if (NULL != cont)
      cont (cont_cls,
	    peer,
	    address,
	    session,
	    GNUNET_OK);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Allowing connection to peer `%s' %s\n",
    		GNUNET_i2s (peer),
                (NULL != transport_name) ? transport_name : "");
    return NULL;
  }

  /* need to query blacklist clients */
  bc = GNUNET_new (struct GST_BlacklistCheck);
  GNUNET_CONTAINER_DLL_insert (bc_head,
			       bc_tail,
			       bc);
  bc->peer = *peer;
  bc->address = GNUNET_HELLO_address_copy (address);
  bc->session = session;
  bc->cont = cont;
  bc->cont_cls = cont_cls;
  bc->bl_pos = tc;
  bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
				       bc);
  return bc;
}


/**
 * Cancel a blacklist check.
 *
 * @param bc check to cancel
 */
void
GST_blacklist_test_cancel (struct GST_BlacklistCheck *bc)
{
  GNUNET_CONTAINER_DLL_remove (bc_head,
                               bc_tail,
                               bc);
  if (NULL != bc->bl_pos)
  {
    if ( (CT_BLACKLIST == bc->bl_pos->type) &&
	 (bc->bl_pos->details.blacklist.bc == bc) )
    {
      /* we're at the head of the queue, remove us! */
      bc->bl_pos->details.blacklist.bc = NULL;
    }
  }
  if (NULL != bc->task)
  {
    GNUNET_SCHEDULER_cancel (bc->task);
    bc->task = NULL;
  }
  GNUNET_free_non_null (bc->address);
  GNUNET_free (bc);
}


/**
 * Function to iterate over options in the blacklisting section for a peer.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
blacklist_cfg_iter (void *cls,
                    const char *section,
		    const char *option,
		    const char *value)
{
  unsigned int *res = cls;
  struct GNUNET_PeerIdentity peer;
  char *plugs;
  char *pos;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (option,
                                                  strlen (option),
                                                  &peer.public_key))
    return;

  if ((NULL == value) || (0 == strcmp(value, "")))
  {
    /* Blacklist whole peer */
    GST_blacklist_add_peer (&peer, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Adding blacklisting entry for peer `%s'\n"),
                GNUNET_i2s (&peer));
  }
  else
  {
    plugs = GNUNET_strdup (value);
    for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Adding blacklisting entry for peer `%s':`%s'\n"),
		    GNUNET_i2s (&peer), pos);
	GST_blacklist_add_peer (&peer, pos);
      }
    GNUNET_free (plugs);
  }
  (*res)++;
}


/**
 * Read blacklist configuration
 *
 * @param cfg the configuration handle
 * @param my_id my peer identity
 */
static void
read_blacklist_configuration (const struct GNUNET_CONFIGURATION_Handle *cfg,
			      const struct GNUNET_PeerIdentity *my_id)
{
  char cfg_sect[512];
  unsigned int res = 0;

  GNUNET_snprintf (cfg_sect,
		   sizeof (cfg_sect),
		   "transport-blacklist-%s",
		   GNUNET_i2s_full (my_id));
  GNUNET_CONFIGURATION_iterate_section_values (cfg,
                                               cfg_sect,
                                               &blacklist_cfg_iter,
                                               &res);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loaded %u blacklisting entries from configuration\n",
              res);
}


/**
 * Initiate transport service.
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
  char *keyfile;
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;
  long long unsigned int max_fd_cfg;
  int max_fd_rlimit;
  int max_fd;
  int friend_only;

  /* setup globals */
  GST_cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c,
                                               "PEER",
                                               "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "transport",
                                           "HELLO_EXPIRATION",
                                           &hello_expiration))
  {
    hello_expiration = GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION;
  }
  pk = GNUNET_CRYPTO_eddsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  GNUNET_assert (NULL != pk);
  GST_my_private_key = pk;

  GST_stats = GNUNET_STATISTICS_create ("transport", GST_cfg);
  GST_peerinfo = GNUNET_PEERINFO_connect (GST_cfg);
  GNUNET_CRYPTO_eddsa_key_get_public (GST_my_private_key,
                                      &GST_my_identity.public_key);
  GNUNET_assert (NULL != GST_my_private_key);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "My identity is `%s'\n",
             GNUNET_i2s_full (&GST_my_identity));

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  if (NULL == GST_peerinfo)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not access PEERINFO service.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  max_fd_rlimit = 0;
#if HAVE_GETRLIMIT
  {
    struct rlimit r_file;

    if (0 == getrlimit (RLIMIT_NOFILE,
			&r_file))
    {
      max_fd_rlimit = r_file.rlim_cur;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Maximum number of open files was: %u/%u\n",
		  (unsigned int) r_file.rlim_cur,
		  (unsigned int) r_file.rlim_max);
    }
    max_fd_rlimit = (9 * max_fd_rlimit) / 10; /* Keep 10% for rest of transport */
  }
#endif
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (GST_cfg,
                                             "transport",
                                             "MAX_FD",
                                             &max_fd_cfg))
    max_fd_cfg = max_fd_rlimit;

  if (max_fd_cfg > max_fd_rlimit)
    max_fd = max_fd_cfg;
  else
    max_fd = max_fd_rlimit;
  if (max_fd < DEFAULT_MAX_FDS)
    max_fd = DEFAULT_MAX_FDS;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Limiting number of sockets to %u: validation %u, neighbors: %u\n",
              max_fd,
              (max_fd / 3),
              (max_fd / 3) * 2);

  friend_only = GNUNET_CONFIGURATION_get_value_yesno (GST_cfg,
                                                      "topology",
                                                      "FRIENDS-ONLY");
  if (GNUNET_SYSERR == friend_only)
    friend_only = GNUNET_NO; /* According to topology defaults */
  /* start subsystems */
  read_blacklist_configuration (GST_cfg,
				&GST_my_identity);
  GST_is = GNUNET_ATS_scanner_init ();
  GST_ats_connect = GNUNET_ATS_connectivity_init (GST_cfg);
  GST_ats = GNUNET_ATS_scheduling_init (GST_cfg,
                                        &ats_request_address_change,
                                        NULL);
  GST_ats_init ();
  GST_manipulation_init ();
  GST_plugins_load (&GST_manipulation_recv,
                    &plugin_env_address_change_notification,
                    &plugin_env_session_start,
                    &plugin_env_session_end);
  GST_hello_start (friend_only,
                   &process_hello_update,
                   NULL);
  GST_neighbours_start ((max_fd / 3) * 2);
  active_stccs = GNUNET_CONTAINER_multipeermap_create (128,
						       GNUNET_YES);
  plugin_nc = GNUNET_notification_context_create (0);
  GST_validation_start ((max_fd / 3));
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("transport",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_start,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_START,
			  struct StartMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (client_hello,
			GNUNET_MESSAGE_TYPE_HELLO,
			struct GNUNET_MessageHeader,
			NULL),
 GNUNET_MQ_hd_var_size (client_send,
			GNUNET_MESSAGE_TYPE_TRANSPORT_SEND,
			struct OutboundMessage,
			NULL),
 GNUNET_MQ_hd_var_size (client_address_to_string,
			GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING,
			struct AddressLookupMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (client_monitor_peers,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST,
			  struct PeerMonitorMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_blacklist_init,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_blacklist_reply,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY,
			  struct BlacklistMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_set_metric,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC,
			  struct TrafficMetricMessage,
			  NULL),
 GNUNET_MQ_hd_fixed_size (client_monitor_plugins,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START,
			  struct GNUNET_MessageHeader,
			  NULL),
 GNUNET_MQ_handler_end ());


/* end of file gnunet-service-transport.c */
