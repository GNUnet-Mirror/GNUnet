/*
     This file is part of GNUnet.
     (C) 2010-2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_clients.c
 * @brief plugin management API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport_manipulation.h"
#include "gnunet-service-transport.h"
#include "transport.h"


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
 * Linked list of messages to be transmitted to the client.  Each
 * entry is followed by the actual message.
 */
struct ClientMessageQueueEntry
{
  /**
   * This is a doubly-linked list.
   */
  struct ClientMessageQueueEntry *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientMessageQueueEntry *prev;
};


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
  struct GNUNET_SERVER_Client *client;

  /**
   * Linked list of messages yet to be transmitted to
   * the client.
   */
  struct ClientMessageQueueEntry *message_queue_head;

  /**
   * Tail of linked list of messages yet to be transmitted to the
   * client.
   */
  struct ClientMessageQueueEntry *message_queue_tail;

  /**
   * Current transmit request handle.
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Length of the list of messages pending for this client.
   */
  unsigned int message_count;

  /**
   * Is this client interested in payload messages?
   */
  int send_payload;
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
   * Transmission context
   */
  struct GNUNET_SERVER_TransmitContext* tc;
};

/**
 * Client monitoring changes of active addresses of our neighbours.
 */
struct MonitoringClient
{
  /**
   * This is a doubly-linked list.
   */
  struct MonitoringClient *next;

  /**
   * This is a doubly-linked list.
   */
  struct MonitoringClient *prev;

  /**
   * Handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Peer identity to monitor the addresses of.
   * Zero to monitor all neighrours.
   */
  struct GNUNET_PeerIdentity peer;

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
 * Head of linked list of all pending address iterations
 */
struct AddressToStringContext *a2s_head;

/**
 * Tail of linked list of all pending address iterations
 */
struct AddressToStringContext *a2s_tail;

/**
 * Head of linked list of monitoring clients.
 */
static struct MonitoringClient *peer_monitoring_clients_head;

/**
 * Tail of linked list of monitoring clients.
 */
static struct MonitoringClient *peer_monitoring_clients_tail;

/**
 * Head of linked list of validation monitoring clients.
 */
static struct MonitoringClient *val_monitoring_clients_head;

/**
 * Tail of linked list of validation monitoring clients.
 */
static struct MonitoringClient *val_monitoring_clients_tail;

/**
 * Notification context, to send updates on changes to active addresses
 * of our neighbours.
 */
static struct GNUNET_SERVER_NotificationContext *peer_nc;

/**
 * Notification context, to send updates on changes to active addresses
 * of our neighbours.
 */
static struct GNUNET_SERVER_NotificationContext *val_nc;

/**
 * Find the internal handle associated with the given client handle
 *
 * @param client server's client handle to look up
 * @return internal client handle
 */
static struct TransportClient *
lookup_client (struct GNUNET_SERVER_Client *client)
{
  struct TransportClient *tc;

  for (tc = clients_head; NULL != tc; tc = tc->next)
    if (tc->client == client)
      return tc;
  return NULL;
}


/**
 * Create the internal handle for the given server client handle
 *
 * @param client server's client handle to create our internal handle for
 * @return fresh internal client handle
 */
static struct TransportClient *
setup_client (struct GNUNET_SERVER_Client *client)
{
  struct TransportClient *tc;

  GNUNET_assert (NULL == lookup_client (client));
  tc = GNUNET_new (struct TransportClient);
  tc->client = client;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              tc);
  return tc;
}


/**
 * Find the handle to the monitoring client associated with the given
 * client handle
 *
 * @param head the head of the client queue to look in
 * @param client server's client handle to look up
 * @return handle to the monitoring client
 */
static struct MonitoringClient *
lookup_monitoring_client (struct MonitoringClient *head,
                          struct GNUNET_SERVER_Client *client)
{
  struct MonitoringClient *mc;

  for (mc = head; NULL != mc; mc = mc->next)
    if (mc->client == client)
      return mc;
  return NULL;
}


/**
 * Setup a new monitoring client using the given server client handle and
 * the peer identity.
 *
 * @param client server's client handle to create our internal handle for
 * @param peer identity of the peer to monitor the addresses of,
 *             zero to monitor all neighrours.
 * @return handle to the new monitoring client
 */
static struct MonitoringClient *
setup_peer_monitoring_client (struct GNUNET_SERVER_Client *client,
                              struct GNUNET_PeerIdentity *peer)
{
  struct MonitoringClient *mc;
  static struct GNUNET_PeerIdentity all_zeros;

  GNUNET_assert (lookup_monitoring_client (peer_monitoring_clients_head, client) == NULL);
  mc = GNUNET_new (struct MonitoringClient);
  mc->client = client;
  mc->peer = *peer;
  GNUNET_CONTAINER_DLL_insert (peer_monitoring_clients_head, peer_monitoring_clients_tail, mc);
  GNUNET_SERVER_notification_context_add (peer_nc, client);

  if (0 != memcmp (peer, &all_zeros, sizeof (struct GNUNET_PeerIdentity)))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client %p started monitoring of the peer `%s'\n",
                mc, GNUNET_i2s (peer));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Client %p started monitoring all peers\n", mc);
  return mc;
}


/**
 * Setup a new monitoring client using the given server client handle and
 * the peer identity.
 *
 * @param client server's client handle to create our internal handle for
 * @param peer identity of the peer to monitor the addresses of,
 *             zero to monitor all neighrours.
 * @return handle to the new monitoring client
 */
static struct MonitoringClient *
setup_val_monitoring_client (struct GNUNET_SERVER_Client *client,
                             struct GNUNET_PeerIdentity *peer)
{
  struct MonitoringClient *mc;
  static struct GNUNET_PeerIdentity all_zeros;

  GNUNET_assert (lookup_monitoring_client (val_monitoring_clients_head, client) == NULL);
  mc = GNUNET_new (struct MonitoringClient);
  mc->client = client;
  mc->peer = *peer;
  GNUNET_CONTAINER_DLL_insert (val_monitoring_clients_head, val_monitoring_clients_tail, mc);
  GNUNET_SERVER_notification_context_add (val_nc, client);

  if (0 != memcmp (peer, &all_zeros, sizeof (struct GNUNET_PeerIdentity)))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client %p started monitoring of the peer `%s'\n",
                mc, GNUNET_i2s (peer));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Client %p started monitoring all peers\n", mc);
  return mc;
}


/**
 * Function called to notify a client about the socket being ready to
 * queue more data.  "buf" will be NULL and "size" zero if the socket
 * was closed for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_to_client_callback (void *cls,
                             size_t size,
                             void *buf)
{
  struct TransportClient *tc = cls;
  struct ClientMessageQueueEntry *q;
  const struct GNUNET_MessageHeader *msg;
  char *cbuf;
  uint16_t msize;
  size_t tsize;

  tc->th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmission to client failed, closing connection.\n");
    return 0;
  }
  cbuf = buf;
  tsize = 0;
  while (NULL != (q = tc->message_queue_head))
  {
    msg = (const struct GNUNET_MessageHeader *) &q[1];
    msize = ntohs (msg->size);
    if (msize + tsize > size)
      break;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting message of type %u to client %p.\n",
                ntohs (msg->type), tc);
    GNUNET_CONTAINER_DLL_remove (tc->message_queue_head,
                                 tc->message_queue_tail,
                                 q);
    tc->message_count--;
    memcpy (&cbuf[tsize], msg, msize);
    GNUNET_free (q);
    tsize += msize;
  }
  if (NULL != q)
  {
    GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
    tc->th =
        GNUNET_SERVER_notify_transmit_ready (tc->client, msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_to_client_callback, tc);
    GNUNET_assert (NULL != tc->th);
  }
  return tsize;
}


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
  struct ClientMessageQueueEntry *q;
  uint16_t msize;

  if (NULL == msg)
  {
    GNUNET_break (0);
    return;
  }

  if ((tc->message_count >= MAX_PENDING) && (GNUNET_YES == may_drop))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Dropping message of type %u and size %u, have %u/%u messages pending\n"),
                ntohs (msg->type),
                ntohs (msg->size),
                tc->message_count,
                MAX_PENDING);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# messages dropped due to slow client"), 1,
                              GNUNET_NO);
    return;
  }
  msize = ntohs (msg->size);
  GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
  q = GNUNET_malloc (sizeof (struct ClientMessageQueueEntry) + msize);
  memcpy (&q[1], msg, msize);
  GNUNET_CONTAINER_DLL_insert_tail (tc->message_queue_head,
                                    tc->message_queue_tail, q);
  tc->message_count++;
  if (NULL != tc->th)
    return;
  tc->th =
      GNUNET_SERVER_notify_transmit_ready (tc->client, msize,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &transmit_to_client_callback, tc);
  GNUNET_assert (NULL != tc->th);
}


/**
 * Called whenever a client is disconnected.  Frees our
 * resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls,
                                struct GNUNET_SERVER_Client *client)
{
  struct TransportClient *tc;
  struct MonitoringClient *mc;
  struct ClientMessageQueueEntry *mqe;

  if (client == NULL)
    return;
  mc = lookup_monitoring_client (peer_monitoring_clients_head, client);
  if (mc != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (peer_monitoring_clients_head,
                                 peer_monitoring_clients_tail,
                                 mc);
    GNUNET_free (mc);
  }
  mc = lookup_monitoring_client (val_monitoring_clients_head, client);
  if (mc != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (val_monitoring_clients_head,
                                 val_monitoring_clients_tail,
                                 mc);
    GNUNET_free (mc);
  }
  tc = lookup_client (client);
  if (tc == NULL)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Client %p disconnected, cleaning up.\n", tc);
  while (NULL != (mqe = tc->message_queue_head))
  {
    GNUNET_CONTAINER_DLL_remove (tc->message_queue_head, tc->message_queue_tail,
                                 mqe);
    tc->message_count--;
    GNUNET_free (mqe);
  }
  GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, tc);
  if (tc->th != NULL)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (tc->th);
    tc->th = NULL;
  }
  GNUNET_break (0 == tc->message_count);
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
  struct ConnectInfoMessage *cim;
  size_t size = sizeof (struct ConnectInfoMessage);
  char buf[size] GNUNET_ALIGN;

  if (GNUNET_NO == GST_neighbours_test_connected (peer))
    return;

  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  cim = (struct ConnectInfoMessage *) buf;
  cim->header.size = htons (size);
  cim->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim->id = *peer;
  cim->quota_in = bandwidth_in;
  cim->quota_out = bandwidth_out;
  unicast (tc, &cim->header, GNUNET_NO);
}


/**
 * Initialize a normal client.  We got a start message from this
 * client, add him to the list of clients for broadcasting of inbound
 * messages.
 *
 * @param cls unused
 * @param client the client
 * @param message the start message that was sent
 */
static void
clients_handle_start (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  const struct StartMessage *start;
  struct TransportClient *tc;
  uint32_t options;

  tc = lookup_client (client);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
              "Client %p sent START\n", tc);
  if (tc != NULL)
  {
    /* got 'start' twice from the same client, not allowed */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "TransportClient %p ServerClient %p sent multiple START messages\n",
                tc, tc->client);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  start = (const struct StartMessage *) message;
  options = ntohl (start->options);
  if ((0 != (1 & options)) &&
      (0 !=
       memcmp (&start->self, &GST_my_identity,
               sizeof (struct GNUNET_PeerIdentity))))
  {
    /* client thinks this is a different peer, reject */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Rejecting control connection from peer `%s', which is not me!\n"),
                GNUNET_i2s (&start->self));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  tc = setup_client (client);
  tc->send_payload = (0 != (2 & options));
  unicast (tc, GST_hello_get (), GNUNET_NO);
  GST_neighbours_iterate (&notify_client_about_neighbour, tc);
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, tc);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Client sent us a HELLO.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the HELLO message
 */
static void
clients_handle_hello (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  GST_validation_handle_hello (message);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Closure for 'handle_send_transmit_continuation'
 */
struct SendTransmitContinuationContext
{
  /**
   * Client that made the request.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Peer that was the target.
   */
  struct GNUNET_PeerIdentity target;
};


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
handle_send_transmit_continuation (void *cls, int success,
                                   size_t bytes_payload,
                                   size_t bytes_on_wire)
{
  struct SendTransmitContinuationContext *stcc = cls;
  struct SendOkMessage send_ok_msg;

  if (GNUNET_OK == success)
    GST_neighbours_notify_payload_sent (&stcc->target, bytes_payload);

  send_ok_msg.header.size = htons (sizeof (send_ok_msg));
  send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
  send_ok_msg.bytes_msg = htonl (bytes_payload);
  send_ok_msg.bytes_physical = htonl (bytes_on_wire);
  send_ok_msg.success = htonl (success);
  send_ok_msg.latency =
      GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_FOREVER_REL);
  send_ok_msg.peer = stcc->target;
  GST_clients_unicast (stcc->client, &send_ok_msg.header, GNUNET_NO);
  GNUNET_SERVER_client_drop (stcc->client);
  GNUNET_free (stcc);
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the send message that was sent
 */
static void
clients_handle_send (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  const struct OutboundMessage *obm;
  const struct GNUNET_MessageHeader *obmm;
  struct SendTransmitContinuationContext *stcc;
  uint16_t size;
  uint16_t msize;
  struct TransportClient *tc;

  tc = lookup_client (client);
  if (NULL == tc)
  {
    /* client asked for transmission before 'START' */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  size = ntohs (message->size);
  if (size <
      sizeof (struct OutboundMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  obm = (const struct OutboundMessage *) message;
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  msize = size - sizeof (struct OutboundMessage);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client with target `%4s' and first message of type %u and total size %u\n",
              "SEND",
              GNUNET_i2s (&obm->peer),
              ntohs (obmm->type),
              msize);
  if (GNUNET_NO == GST_neighbours_test_connected (&obm->peer))
  {
    /* not connected, not allowed to send; can happen due to asynchronous operations */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Could not send message to peer `%s': not connected\n",
                GNUNET_i2s (&obm->peer));
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bytes payload dropped (other peer was not connected)"),
                              msize, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  stcc = GNUNET_new (struct SendTransmitContinuationContext);
  stcc->target = obm->peer;
  stcc->client = client;
  GNUNET_SERVER_client_keep (client);
  GST_manipulation_send (&obm->peer, obmm, msize,
                       GNUNET_TIME_relative_ntoh (obm->timeout),
                       &handle_send_transmit_continuation, stcc);
}


/**
 * Try to initiate a connection to the given peer if the blacklist
 * allowed it.
 *
 * @param cls closure (unused, NULL)
 * @param peer identity of peer that was tested
 * @param result #GNUNET_OK if the connection is allowed,
 *               #GNUNET_NO if not
 */
static void
try_connect_if_allowed (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        int result)
{
  if (GNUNET_OK != result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Blacklist refuses connection attempt to peer `%s'\n"),
                GNUNET_i2s (peer));
    return;                     /* not allowed */
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Blacklist allows connection attempt to peer `%s'\n"),
              GNUNET_i2s (peer));

  GST_neighbours_try_connect (peer);
}


/**
 * Handle request connect message
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
clients_handle_request_connect (void *cls,
                                struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct TransportRequestConnectMessage *trcm =
      (const struct TransportRequestConnectMessage *) message;

  if (GNUNET_YES == ntohl (trcm->connect))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# REQUEST CONNECT messages received"), 1,
                              GNUNET_NO);

    if (0 == memcmp (&trcm->peer, &GST_my_identity,
                  sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received a request connect message myself `%s'\n",
                  GNUNET_i2s (&trcm->peer));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Received a request connect message for peer `%s'\n"),
                  GNUNET_i2s (&trcm->peer));

      (void) GST_blacklist_test_allowed (&trcm->peer, NULL, &try_connect_if_allowed,
                                       NULL);
    }
  }
  else if (GNUNET_NO == ntohl (trcm->connect))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# REQUEST DISCONNECT messages received"), 1,
                              GNUNET_NO);

    if (0 == memcmp (&trcm->peer, &GST_my_identity,
                  sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received a request disconnect message myself `%s'\n",
                  GNUNET_i2s (&trcm->peer));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Received a request disconnect message for peer `%s'\n"),
                  GNUNET_i2s (&trcm->peer));
      (void) GST_neighbours_force_disconnect (&trcm->peer);
    }
  }
  else
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
 * @param cls the transmission context used (`struct GNUNET_SERVER_TransmitContext *`)
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
  struct AddressToStringResultMessage *atsm;
  size_t len;
  size_t slen;

  GNUNET_assert ( (GNUNET_OK == res) ||
                  (GNUNET_SYSERR == res) );
  if (NULL == buf)
  {
    len = sizeof (struct AddressToStringResultMessage);
    atsm = GNUNET_malloc (len);
    atsm->header.size = ntohs (len);
    atsm->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    if (GNUNET_OK == res)
    {
      /* this was the last call, transmit */
      atsm->res = htonl (GNUNET_OK);
      atsm->addr_len = htonl (0);
      GNUNET_SERVER_transmit_context_append_message (actx->tc,
                                                     (const struct GNUNET_MessageHeader *) atsm);
      GNUNET_SERVER_transmit_context_run (actx->tc,
                                          GNUNET_TIME_UNIT_FOREVER_REL);
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
      GNUNET_SERVER_transmit_context_append_message (actx->tc,
                                                     (const struct GNUNET_MessageHeader *) atsm);
      GNUNET_free (atsm);
      return;
    }
  }
  GNUNET_assert (GNUNET_OK == res);
  /* succesful conversion, append*/
  slen = strlen (buf) + 1;
  len = sizeof (struct AddressToStringResultMessage) + slen;
  atsm = GNUNET_malloc (len);
  atsm->header.size = ntohs (len);
  atsm->header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
  atsm->res = htonl (GNUNET_YES);
  atsm->addr_len = htonl (slen);
  memcpy (&atsm[1],
          buf,
          slen);
  GNUNET_SERVER_transmit_context_append_message (actx->tc,
                                                 (const struct GNUNET_MessageHeader *) atsm);
  GNUNET_free (atsm);
}


/**
 * Client asked to resolve an address.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the resolution request
 */
static void
clients_handle_address_to_string (void *cls,
                                  struct GNUNET_SERVER_Client *client,
                                  const struct GNUNET_MessageHeader *message)
{
  const struct AddressLookupMessage *alum;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  const char *plugin_name;
  const char *address;
  uint32_t address_len;
  uint16_t size;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct AddressToStringContext *actx;
  struct AddressToStringResultMessage atsm;
  struct GNUNET_TIME_Relative rtimeout;
  int32_t numeric;

  size = ntohs (message->size);
  if (size < sizeof (struct AddressLookupMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  alum = (const struct AddressLookupMessage *) message;
  address_len = ntohs (alum->addrlen);
  if (size <= sizeof (struct AddressLookupMessage) + address_len)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  address = (const char *) &alum[1];
  plugin_name = (const char *) &address[address_len];
  if ('\0' != plugin_name[size - sizeof (struct AddressLookupMessage) - address_len - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rtimeout = GNUNET_TIME_relative_ntoh (alum->timeout);
  numeric = ntohs (alum->numeric_only);
  tc = GNUNET_SERVER_transmit_context_create (client);
  papi = GST_plugins_printer_find (plugin_name);
  if (NULL == papi)
  {
    fprintf (stderr,
             "DEAD: %s\n",
             plugin_name);
    atsm.header.size = ntohs (sizeof (struct AddressToStringResultMessage));
    atsm.header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    atsm.res = htonl (GNUNET_SYSERR);
    atsm.addr_len = htonl (0);
    GNUNET_SERVER_transmit_context_append_message (tc,
                                                   &atsm.header);
    atsm.header.size = ntohs (sizeof (struct AddressToStringResultMessage));
    atsm.header.type = ntohs (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY);
    atsm.res = htonl (GNUNET_OK);
    atsm.addr_len = htonl (0);
    GNUNET_SERVER_transmit_context_append_message (tc,
                                                   &atsm.header);
    GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  actx = GNUNET_new (struct AddressToStringContext);
  actx->tc = tc;
  GNUNET_CONTAINER_DLL_insert (a2s_head, a2s_tail, actx);
  GNUNET_SERVER_disable_receive_done_warning (client);
  papi->address_pretty_printer (papi->cls,
                                plugin_name,
                                address, address_len,
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
    tlen = alen = 0;
  size = (sizeof (struct PeerIterateResponseMessage) + alen + tlen);
  msg = GNUNET_malloc (size);
  msg->header.size = htons (size);
  msg->header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  msg->addrlen = htonl (alen);
  msg->pluginlen = htonl (tlen);

  if (NULL != address)
  {
    msg->local_address_info = htonl((uint32_t) address->local_info);
    addr = (char *) &msg[1];
    memcpy (addr, address->address, alen);
    memcpy (&addr[alen], address->transport_name, tlen);
  }
  return msg;
}

/**
 * Compose #PeerIterateResponseMessage using the given peer and address.
 *
 * @param peer identity of the peer
 * @param address the address, NULL on disconnect
 * @return composed message
 */
static struct ValidationIterateResponseMessage *
compose_validation_iterate_response_message (const struct GNUNET_PeerIdentity *peer,
                                          const struct GNUNET_HELLO_Address *address)
{
  struct ValidationIterateResponseMessage *msg;
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
    tlen = alen = 0;
  size = (sizeof (struct ValidationIterateResponseMessage) + alen + tlen);
  msg = GNUNET_malloc (size);
  msg->header.size = htons (size);
  msg->header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_RESPONSE);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  msg->addrlen = htonl (alen);
  msg->pluginlen = htonl (tlen);

  if (NULL != address)
  {
    msg->local_address_info = htonl((uint32_t) address->local_info);
    addr = (char *) &msg[1];
    memcpy (addr, address->address, alen);
    memcpy (&addr[alen], address->transport_name, tlen);
  }
  return msg;
}

struct IterationContext
{
  struct GNUNET_SERVER_TransmitContext *tc;

  struct GNUNET_PeerIdentity id;

  int all;
};

/**
 * Output information of validation entries to the given client.
 *
 * @param cls the 'struct IterationContext'
 * @param peer identity of the neighbour
 * @param address the address
 * @param last_validation point in time when last validation was performed
 * @param valid_until point in time how long address is valid
 * @param next_validation point in time when next validation will be performed
 * @param state state of validation notification
 */
static void
send_validation_information (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address,
    struct GNUNET_TIME_Absolute last_validation,
    struct GNUNET_TIME_Absolute valid_until,
    struct GNUNET_TIME_Absolute next_validation,
    enum GNUNET_TRANSPORT_ValidationState state)
{
  struct IterationContext *pc = cls;
  struct ValidationIterateResponseMessage *msg;

  if ( (GNUNET_YES == pc->all) ||
       (0 == memcmp (peer, &pc->id, sizeof (pc->id))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Sending information about for validation entry for peer `%s' using address `%s'\n",
        GNUNET_i2s(peer), (address != NULL) ? GST_plugins_a2s (address) : "<none>");
    msg = compose_validation_iterate_response_message (peer, address);
    msg->last_validation = GNUNET_TIME_absolute_hton(last_validation);
    msg->valid_until = GNUNET_TIME_absolute_hton(valid_until);
    msg->next_validation = GNUNET_TIME_absolute_hton(next_validation);
    msg->state = htonl ((uint32_t) state);
    GNUNET_SERVER_transmit_context_append_message (pc->tc, &msg->header);
    GNUNET_free (msg);
  }
}


/**
 * Output information of neighbours to the given client.
 *
 * @param cls the 'struct PeerIterationContext'
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
  struct PeerIterateResponseMessage *msg;

  if ( (GNUNET_YES == pc->all) ||
       (0 == memcmp (peer, &pc->id, sizeof (pc->id))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Sending information about `%s' using address `%s' in state `%s'\n",
        GNUNET_i2s(peer),
        (address != NULL) ? GST_plugins_a2s (address) : "<none>",
        GNUNET_TRANSPORT_ps2s (state));
    msg = compose_address_iterate_response_message (peer, address);
    msg->state = htonl (state);
    msg->state_timeout = GNUNET_TIME_absolute_hton(state_timeout);
    GNUNET_SERVER_transmit_context_append_message (pc->tc, &msg->header);
    GNUNET_free (msg);
  }
}



/**
 * Client asked to obtain information about a specific or all peers
 * Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the peer address information request
 */
static void
clients_handle_monitor_peers (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  static struct GNUNET_PeerIdentity all_zeros;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct PeerMonitorMessage *msg;
  struct IterationContext pc;

  if (ntohs (message->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (ntohs (message->size) != sizeof (struct PeerMonitorMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (struct PeerMonitorMessage *) message;
  if ( (GNUNET_YES != ntohl (msg->one_shot)) &&
       (NULL != lookup_monitoring_client (peer_monitoring_clients_head, client)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
		"ServerClient %p tried to start monitoring twice\n",
		client);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_disable_receive_done_warning (client);
  pc.tc = tc = GNUNET_SERVER_transmit_context_create (client);

  /* Send initial list */
  if (0 == memcmp (&msg->peer, &all_zeros, sizeof (struct GNUNET_PeerIdentity)))
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
  GST_neighbours_iterate (&send_peer_information, &pc);

  if (GNUNET_YES != ntohl (msg->one_shot))
  {
    setup_peer_monitoring_client (client, &msg->peer);
  }
  else
  {
    GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
        GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE);
  }

  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Client asked to obtain information about a specific or all validation
 * processes
 *
 * @param cls unused
 * @param client the client
 * @param message the peer address information request
 */
static void
clients_handle_monitor_validation (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  static struct GNUNET_PeerIdentity all_zeros;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct PeerMonitorMessage *msg;
  struct IterationContext pc;

  if (ntohs (message->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_REQUEST)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (ntohs (message->size) != sizeof (struct ValidationMonitorMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (struct PeerMonitorMessage *) message;
  if ( (GNUNET_YES != ntohl (msg->one_shot)) &&
       (NULL != lookup_monitoring_client (val_monitoring_clients_head, client)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "ServerClient %p tried to start monitoring twice\n",
                client);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_disable_receive_done_warning (client);
  pc.tc = tc = GNUNET_SERVER_transmit_context_create (client);

  /* Send initial list */
  if (0 == memcmp (&msg->peer, &all_zeros, sizeof (struct GNUNET_PeerIdentity)))
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

  GST_validation_iterate (&send_validation_information, &pc);

  if (GNUNET_YES != ntohl (msg->one_shot))
  {
    setup_val_monitoring_client (client, &msg->peer);
  }
  else
  {
    GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
        GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_RESPONSE);
  }
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Start handling requests from clients.
 *
 * @param server server used to accept clients from.
 */
void
GST_clients_start (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&clients_handle_start, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_START, sizeof (struct StartMessage)},
    {&clients_handle_hello, NULL,
     GNUNET_MESSAGE_TYPE_HELLO, 0},
    {&clients_handle_send, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_SEND, 0},
    {&clients_handle_request_connect, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT,
     sizeof (struct TransportRequestConnectMessage)},
    {&clients_handle_address_to_string, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING, 0},
    {&clients_handle_monitor_peers, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST,
     sizeof (struct PeerMonitorMessage)},
    {&clients_handle_monitor_validation, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_REQUEST,
     sizeof (struct ValidationMonitorMessage)},
    {&GST_blacklist_handle_init, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT,
     sizeof (struct GNUNET_MessageHeader)},
    {&GST_blacklist_handle_reply, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY,
     sizeof (struct BlacklistMessage)},
    {&GST_manipulation_set_metric, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC, 0},
    {NULL, NULL, 0, 0}
  };
  peer_nc = GNUNET_SERVER_notification_context_create (server, 0);
  val_nc = GNUNET_SERVER_notification_context_create (server, 0);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect_notification,
                                   NULL);
}


/**
 * Stop processing clients.
 */
void
GST_clients_stop ()
{
  struct AddressToStringContext *cur;

  while (NULL != (cur = a2s_head))
  {
    GNUNET_SERVER_transmit_context_destroy (cur->tc, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (a2s_head, a2s_tail, cur);
    GNUNET_free (cur);
  }
  if (NULL != peer_nc)
  {
    GNUNET_SERVER_notification_context_destroy (peer_nc);
    peer_nc = NULL;
  }
  if (NULL != val_nc)
  {
    GNUNET_SERVER_notification_context_destroy (val_nc);
    val_nc = NULL;
  }
}


/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 * @param may_drop #GNUNET_YES if the message can be dropped / is payload
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg, int may_drop)
{
  struct TransportClient *tc;

  for (tc = clients_head; NULL != tc; tc = tc->next)
  {
    if ((GNUNET_YES == may_drop) && (GNUNET_YES != tc->send_payload))
      continue;                 /* skip, this client does not care about payload */
    unicast (tc, msg, may_drop);
  }
}


/**
 * Send the given message to a particular client
 *
 * @param client target of the message
 * @param msg message to transmit
 * @param may_drop #GNUNET_YES if the message can be dropped
 */
void
GST_clients_unicast (struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg, int may_drop)
{
  struct TransportClient *tc;

  tc = lookup_client (client);
  if (NULL == tc)
    return;                     /* client got disconnected in the meantime, drop message */
  unicast (tc, msg, may_drop);
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
  struct PeerIterateResponseMessage *msg;
  struct MonitoringClient *mc;
  static struct GNUNET_PeerIdentity all_zeros;
  msg = compose_address_iterate_response_message (peer, address);
  msg->state = htonl (state);
  msg->state_timeout = GNUNET_TIME_absolute_hton (state_timeout);
  mc = peer_monitoring_clients_head;
  while (mc != NULL)
  {
    if ((0 == memcmp (&mc->peer, &all_zeros,
                      sizeof (struct GNUNET_PeerIdentity))) ||
        (0 == memcmp (&mc->peer, peer,
                      sizeof (struct GNUNET_PeerIdentity))))
    {
      GNUNET_SERVER_notification_context_unicast (peer_nc, mc->client,
                                                  &msg->header, GNUNET_NO);
    }

    mc = mc->next;
  }
  GNUNET_free (msg);
}

/**
 * Broadcast the new validation changes to all clients monitoring the peer.
 *
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL on disconnect
 * @param last_validation point in time when last validation was performed
 * @param valid_until point in time how long address is valid
 * @param next_validation point in time when next validation will be performed
 * @param state state of validation notification
 */
void
GST_clients_broadcast_validation_notification (
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address,
    struct GNUNET_TIME_Absolute last_validation,
    struct GNUNET_TIME_Absolute valid_until,
    struct GNUNET_TIME_Absolute next_validation,
    enum GNUNET_TRANSPORT_ValidationState state)
{
  struct ValidationIterateResponseMessage *msg;
  struct MonitoringClient *mc;
  static struct GNUNET_PeerIdentity all_zeros;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Sending information about for validation entry for peer `%s' using address `%s'\n",
      GNUNET_i2s(peer), (address != NULL) ? GST_plugins_a2s (address) : "<none>");

  msg = compose_validation_iterate_response_message (peer, address);
  msg->last_validation = GNUNET_TIME_absolute_hton(last_validation);
  msg->valid_until = GNUNET_TIME_absolute_hton(valid_until);
  msg->next_validation = GNUNET_TIME_absolute_hton(next_validation);
  msg->state = htonl ((uint32_t) state);
  mc = val_monitoring_clients_head;
  while (mc != NULL)
  {
    if ((0 == memcmp (&mc->peer, &all_zeros,
                      sizeof (struct GNUNET_PeerIdentity))) ||
        (0 == memcmp (&mc->peer, peer,
                      sizeof (struct GNUNET_PeerIdentity))))
    {
      GNUNET_SERVER_notification_context_unicast (val_nc, mc->client,
                                                  &msg->header, GNUNET_NO);

    }
    mc = mc->next;
  }
  GNUNET_free (msg);
}


/* end of file gnunet-service-transport_clients.c */
