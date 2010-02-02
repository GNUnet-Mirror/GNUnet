/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/gnunet-service-transport.c
 * @brief low-level P2P messaging
 * @author Christian Grothoff
 *
 * TODO:
 * - remove AddressValidations, incorporate them into the PeerAddressLists
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_plugin_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "plugin_transport.h"
#include "transport.h"

/**
 * How many messages can we have pending for a given client process
 * before we start to drop incoming messages?  We typically should
 * have only one client and so this would be the primary buffer for
 * messages, so the number should be chosen rather generously.
 *
 * The expectation here is that most of the time the queue is large
 * enough so that a drop is virtually never required.
 */
#define MAX_PENDING 128

/**
 * How often should we try to reconnect to a peer using a particular
 * transport plugin before giving up?  Note that the plugin may be
 * added back to the list after PLUGIN_RETRY_FREQUENCY expires.
 */
#define MAX_CONNECT_RETRY 3

/**
 * How often must a peer violate bandwidth quotas before we start
 * to simply drop its messages?
 */
#define QUOTA_VIOLATION_DROP_THRESHOLD 100

/**
 * How long until a HELLO verification attempt should time out?
 * Must be rather small, otherwise a partially successful HELLO
 * validation (some addresses working) might not be available
 * before a client's request for a connection fails for good.
 * Besides, if a single request to an address takes a long time,
 * then the peer is unlikely worthwhile anyway.
 */
#define HELLO_VERIFICATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long will we allow sending of a ping to be delayed?
 */
#define TRANSPORT_DEFAULT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define TRANSPORT_DEFAULT_PRIORITY 4 /* Tired of remembering arbitrary priority names */

/**
 * How often do we re-add (cheaper) plugins to our list of plugins
 * to try for a given connected peer?
 */
#define PLUGIN_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * After how long do we expire an address in a HELLO
 * that we just validated?  This value is also used
 * for our own addresses when we create a HELLO.
 */
#define HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)


/**
 * List of addresses of other peers
 */
struct PeerAddressList
{
  /**
   * This is a linked list.
   */
  struct PeerAddressList *next;

  /*
   * Pointer to the validation associated with this
   * address.  May be NULL if already validated!
   */
  struct ValidationAddress *validation;

  /**
   * Which of our transport plugins does this entry
   * belong to?
   */
  struct TransportPlugin *plugin;

  /**
   * Neighbor this entry belongs to.
   */
  struct NeighborList *neighbor;

  /*
   * Ready list (transport) that this peer belongs to
   */
  struct ReadyList *ready_list;
  /**
   * How long until we auto-expire this address (unless it is
   * re-confirmed by the transport)?
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * Length of addr.
   */
  size_t addrlen;

  /**
   * The address
   */
  char *addr;

  /**
   * Is this plugin ready to transmit to the specific target?
   * GNUNET_NO if not.  Initially, all plugins are marked ready.  If a
   * transmission is in progress, "transmit_ready" is set to
   * GNUNET_NO.
   */
  int transmit_ready;

  /**
   * What was the last latency observed for this plugin
   * and peer?  Invalid if connected is GNUNET_NO.
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * If we did not successfully transmit a message to the given peer
   * via this connection during the specified time, we should consider
   * the connection to be dead.  This is used in the case that a TCP
   * transport simply stalls writing to the stream but does not
   * formerly get a signal that the other peer died.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Is this plugin currently connected?  The first time
   * we transmit or send data to a peer via a particular
   * plugin, we set this to GNUNET_YES.  If we later get
   * an error (disconnect notification or transmission
   * failure), we set it back to GNUNET_NO.  Each time the
   * value is set to GNUNET_YES, we increment the
   * "connect_attempts" counter.  If that one reaches a
   * particular threshold, we consider the plugin to not
   * be working properly at this time for the given peer
   * and remove it from the eligible list.
   */
  int connected;

  /**
   * How often have we tried to connect using this plugin?
   */
  unsigned int connect_attempts;

};


/**
 * Entry in linked list of network addresses.
 */
struct AddressList
{
  /**
   * This is a linked list.
   */
  struct AddressList *next;

  /**
   * The address, actually a pointer to the end
   * of this struct.  Do not free!
   */
  void *addr;

  /**
   * How long until we auto-expire this address (unless it is
   * re-confirmed by the transport)?
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * Length of addr.
   */
  size_t addrlen;

};


/**
 * Entry in linked list of all of our plugins.
 */
struct TransportPlugin
{

  /**
   * This is a linked list.
   */
  struct TransportPlugin *next;

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_TRANSPORT_PluginFunctions *api;

  /**
   * Short name for the plugin (i.e. "tcp").
   */
  char *short_name;

  /**
   * Name of the library (i.e. "gnunet_plugin_transport_tcp").
   */
  char *lib_name;

  /**
   * List of our known addresses for this transport.
   */
  struct AddressList *addresses;

  /**
   * Environment this transport service is using
   * for this plugin.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment env;

  /**
   * ID of task that is used to clean up expired addresses.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;


  /**
   * Set to GNUNET_YES if we need to scrap the existing
   * list of "addresses" and start fresh when we receive
   * the next address update from a transport.  Set to
   * GNUNET_NO if we should just add the new address
   * to the list and wait for the commit call.
   */
  int rebuild;
};

struct NeighborList;

/**
 * For each neighbor we keep a list of messages
 * that we still want to transmit to the neighbor.
 */
struct MessageQueue
{

  /**
   * This is a linked list.
   */
  struct MessageQueue *next;

  /**
   * The message(s) we want to transmit, GNUNET_MessageHeader(s)
   * stuck together in memory.
   */
  char *message_buf;

  /*
   * Size of the message buf
   */
  size_t message_buf_size;

  /**
   * Client responsible for queueing the message;
   * used to check that a client has no two messages
   * pending for the same target.  Can be NULL.
   */
  struct TransportClient *client;

  /**
   * Neighbor this entry belongs to.
   */
  /*struct NeighborList *neighbor;*/

  /**
   * Peer ID of the Neighbor this entry belongs to.
   */
  struct GNUNET_PeerIdentity *neighbor_id;

  /**
   * Plugin that we used for the transmission.
   * NULL until we scheduled a transmission.
   */
  struct TransportPlugin *plugin;

  /**
   * Internal message of the transport system that should not be
   * included in the usual SEND-SEND_OK transmission confirmation
   * traffic management scheme.  Typically, "internal_msg" will
   * be set whenever "client" is NULL (but it is not strictly
   * required).
   */
  int internal_msg;

  /**
   * How important is the message?
   */
  unsigned int priority;

  /*
   * Using which specific address should we send this message?
   */
  struct PeerAddressList *specific_peer;

};


/**
 * For a given Neighbor, which plugins are available
 * to talk to this peer and what are their costs?
 */
struct ReadyList
{
  /**
   * This is a linked list.
   */
  struct ReadyList *next;

  /**
   * Which of our transport plugins does this entry
   * represent?
   */
  struct TransportPlugin *plugin;

  /**
   * Neighbor this entry belongs to.
   */
  struct NeighborList *neighbor;

  /*
   * Transport addresses, latency, and readiness for
   * this particular plugin.
   */
  struct PeerAddressList *addresses;

  /**
   * Is this plugin ready to transmit to the specific target?
   * GNUNET_NO if not.  Initially, all plugins are marked ready.  If a
   * transmission is in progress, "transmit_ready" is set to
   * GNUNET_NO.
   */
  int plugin_transmit_ready;

  /*
   * Are any of our PeerAddressList addresses still connected?
   */
  int connected; /* FIXME: dynamically check PeerAddressList addresses when asked to! */
};


/**
 * Entry in linked list of all of our current neighbors.
 */
struct NeighborList
{

  /**
   * This is a linked list.
   */
  struct NeighborList *next;

  /**
   * Which of our transports is connected to this peer
   * and what is their status?
   */
  struct ReadyList *plugins;

  /**
   * List of messages we would like to send to this peer;
   * must contain at most one message per client.
   */
  struct MessageQueue *messages;

  /**
   * Identity of this neighbor.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * ID of task scheduled to run when this peer is about to
   * time out (will free resources associated with the peer).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * How long until we should consider this peer dead
   * (if we don't receive another message in the
   * meantime)?
   */
  struct GNUNET_TIME_Absolute peer_timeout;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * At what time should we try to again add plugins to
   * our ready list?
   */
  struct GNUNET_TIME_Absolute retry_plugins_time;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Global quota for inbound traffic for the neighbor in bytes/ms.
   */
  uint32_t quota_in;

  /**
   * How often has the other peer (recently) violated the
   * inbound traffic limit?  Incremented by 10 per violation,
   * decremented by 1 per non-violation (for each
   * time interval).
   */
  unsigned int quota_violation_count;

  /**
   * Have we seen an ACK from this neighbor in the past?
   * (used to make up a fake ACK for clients connecting after
   * the neighbor connected to us).
   */
  int received_pong;

  /* The latency we have seen for this particular address for
   * this particular peer.  This latency may have been calculated
   * over multiple transports.  This value reflects how long it took
   * us to receive a response when SENDING via this particular
   * transport/neighbor/address combination!
   */
  struct GNUNET_TIME_RelativeNBO latency;

};

/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address used.  Note that the
 * recipients response does not affirm that he has this address,
 * only that he got the challenge message.
 */
struct TransportPingMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who is the intended recipient?
   */
  struct GNUNET_PeerIdentity target;

};


/**
 * Message used to validate a HELLO.  The challenge is included in the
 * confirmation to make matching of replies to requests possible.  The
 * signature signs the original challenge number, our public key, the
 * sender's address (so that the sender can check that the address we
 * saw is plausible for him and possibly detect a MiM attack) and a
 * timestamp (to limit replay).<p>
 *
 * This message is followed by the address of the
 * client that we are observing (which is part of what
 * is being signed).
 */
struct TransportPongMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * For padding, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What are we signing and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who signed this message?
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded signer;

  /*
   * Size of address appended to this message
   */
  size_t addrlen;

};

/**
 * Linked list of messages to be transmitted to
 * the client.  Each entry is followed by the
 * actual message.
 */
struct ClientMessageQueueEntry
{
  /**
   * This is a linked list.
   */
  struct ClientMessageQueueEntry *next;
};


/**
 * Client connected to the transport service.
 */
struct TransportClient
{

  /**
   * This is a linked list.
   */
  struct TransportClient *next;

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
   * Is a call to "transmit_send_continuation" pending?  If so, we
   * must not free this struct (even if the corresponding client
   * disconnects) and instead only remove it from the linked list and
   * set the "client" field to NULL.
   */
  int tcs_pending;

  /**
   * Length of the list of messages pending for this client.
   */
  unsigned int message_count;

};


/**
 * For each HELLO, we may have to validate multiple addresses;
 * each address gets its own request entry.
 */
struct ValidationAddress
{
  /**
   * This is a linked list.
   */
  struct ValidationAddress *next;

  /*
   * What peer_address does this validation belong to?
   */
  struct PeerAddressList *peer_address;

  /**
   * Name of the transport.
   */
  char *transport_name;

  /**
   * When should this validated address expire?
   */
  struct GNUNET_TIME_Absolute expiration;

  /*
   * At what time did we send this validation?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * Challenge number we used.
   */
  uint32_t challenge;

  /**
   * Set to GNUNET_YES if the challenge was met,
   * GNUNET_SYSERR if we know it failed, GNUNET_NO
   * if we are waiting on a response.
   */
  int ok;
};


/**
 * Entry in linked list of all HELLOs awaiting validation.
 */
struct ValidationList
{

  /**
   * This is a linked list.
   */
  struct ValidationList *next;

  /**
   * Linked list with one entry per address from the HELLO
   * that needs to be validated.
   */
  struct ValidationAddress *addresses;

  /**
   * The public key of the peer.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

  /**
   * When does this record time-out? (assuming the
   * challenge goes unanswered)
   */
  struct GNUNET_TIME_Absolute timeout;

};


struct CheckHelloValidatedContext
{
  /**
   * Plugin for which we are validating.
   */
  struct TransportPlugin *plugin;

  /**
   * Hello that we are validating.
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Validation list being built.
   */
  struct ValidationList *e;

  /**
   * Context for peerinfo iteration.
   * NULL after we are done processing peerinfo's information.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;

};



/**
 * HELLOs awaiting validation.
 */
static struct ValidationList *pending_validations;

/**
 * Our HELLO message.
 */
static struct GNUNET_HELLO_Message *our_hello;

/**
 * "version" of "our_hello".  Used to see if a given
 * neighbor has already been sent the latest version
 * of our HELLO message.
 */
static unsigned int our_hello_version;

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Our identity.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Our scheduler.
 */
struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Linked list of all clients to this service.
 */
static struct TransportClient *clients;

/**
 * All loaded plugins.
 */
static struct TransportPlugin *plugins;

/**
 * Our server.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * All known neighbors and their HELLOs.
 */
static struct NeighborList *neighbors;

/**
 * Number of neighbors we'd like to have.
 */
static uint32_t max_connect_per_transport;

/**
 * The peer specified by the given neighbor has timed-out or a plugin
 * has disconnected.  We may either need to do nothing (other plugins
 * still up), or trigger a full disconnect and clean up.  This
 * function updates our state and do the necessary notifications.
 * Also notifies our clients that the neighbor is now officially
 * gone.
 *
 * @param n the neighbor list entry for the peer
 * @param check should we just check if all plugins
 *        disconnected or must we ask all plugins to
 *        disconnect?
 */
static void disconnect_neighbor (struct NeighborList *n, int check);


/**
 * Check the ready list for the given neighbor and
 * if a plugin is ready for transmission (and if we
 * have a message), do so!
 *
 * @param neighbor target peer for which to check the plugins
 */
static ssize_t try_transmission_to_peer (struct NeighborList *neighbor);


/**
 * Find an entry in the neighbor list for a particular peer.
 * if sender_address is not specified (NULL) then return the
 * first matching entry.  If sender_address is specified, then
 * make sure that the address and address_len also matches.
 *
 * @return NULL if not found.
 */
static struct NeighborList *
find_neighbor (const struct GNUNET_PeerIdentity *key)
{
  struct NeighborList *head = neighbors;

  while ((head != NULL) &&
        (0 != memcmp (key, &head->id, sizeof (struct GNUNET_PeerIdentity))))
    head = head->next;

  return head;
}


/**
 * Find an entry in the transport list for a particular transport.
 *
 * @return NULL if not found.
 */
static struct TransportPlugin *
find_transport (const char *short_name)
{
  struct TransportPlugin *head = plugins;
  while ((head != NULL) && (0 != strcmp (short_name, head->short_name)))
    head = head->next;
  return head;
}


/**
 * Update the quota values for the given neighbor now.
 */
static void
update_quota (struct NeighborList *n)
{
  struct GNUNET_TIME_Relative delta;
  uint64_t allowed;
  uint64_t remaining;

  delta = GNUNET_TIME_absolute_get_duration (n->last_quota_update);
  if (delta.value < MIN_QUOTA_REFRESH_TIME)
    return;                     /* not enough time passed for doing quota update */
  allowed = delta.value * n->quota_in;
  if (n->last_received < allowed)
    {
      remaining = allowed - n->last_received;
      if (n->quota_in > 0)
        remaining /= n->quota_in;
      else
        remaining = 0;
      if (remaining > MAX_BANDWIDTH_CARRY)
        remaining = MAX_BANDWIDTH_CARRY;
      n->last_received = 0;
      n->last_quota_update = GNUNET_TIME_absolute_get ();
      n->last_quota_update.value -= remaining;
      if (n->quota_violation_count > 0)
        n->quota_violation_count--;
    }
  else
    {
      n->last_received -= allowed;
      n->last_quota_update = GNUNET_TIME_absolute_get ();
      if (n->last_received > allowed)
        {
          /* more than twice the allowed rate! */
          n->quota_violation_count += 10;
        }
    }
}


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_client_callback (void *cls, size_t size, void *buf)
{
  struct TransportClient *client = cls;
  struct ClientMessageQueueEntry *q;
  uint16_t msize;
  size_t tsize;
  const struct GNUNET_MessageHeader *msg;
  struct GNUNET_CONNECTION_TransmitHandle *th;
  char *cbuf;

  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission to client failed, closing connection.\n");
      /* fatal error with client, free message queue! */
      while (NULL != (q = client->message_queue_head))
        {
          client->message_queue_head = q->next;
          GNUNET_free (q);
        }
      client->message_queue_tail = NULL;
      client->message_count = 0;
      return 0;
    }
  cbuf = buf;
  tsize = 0;
  while (NULL != (q = client->message_queue_head))
    {
      msg = (const struct GNUNET_MessageHeader *) &q[1];
      msize = ntohs (msg->size);
      if (msize + tsize > size)
        break;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmitting message of type %u to client.\n",
                  ntohs (msg->type));
#endif
      client->message_queue_head = q->next;
      if (q->next == NULL)
        client->message_queue_tail = NULL;
      memcpy (&cbuf[tsize], msg, msize);
      tsize += msize;
      GNUNET_free (q);
      client->message_count--;
    }
  if (NULL != q)
    {
      GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
      th = GNUNET_SERVER_notify_transmit_ready (client->client,
                                                msize,
                                                GNUNET_TIME_UNIT_FOREVER_REL,
                                                &transmit_to_client_callback,
                                                client);
      GNUNET_assert (th != NULL);
    }
  return tsize;
}


/**
 * Send the specified message to the specified client.  Since multiple
 * messages may be pending for the same client at a time, this code
 * makes sure that no message is lost.
 *
 * @param client client to transmit the message to
 * @param msg the message to send
 * @param may_drop can this message be dropped if the
 *        message queue for this client is getting far too large?
 */
static void
transmit_to_client (struct TransportClient *client,
                    const struct GNUNET_MessageHeader *msg, int may_drop)
{
  struct ClientMessageQueueEntry *q;
  uint16_t msize;
  struct GNUNET_CONNECTION_TransmitHandle *th;

  if ((client->message_count >= MAX_PENDING) && (GNUNET_YES == may_drop))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Dropping message, have %u messages pending (%u is the soft limit)\n"),
                  client->message_count, MAX_PENDING);
      /* TODO: call to statistics... */
      return;
    }
  client->message_count++;
  msize = ntohs (msg->size);
  GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
  q = GNUNET_malloc (sizeof (struct ClientMessageQueueEntry) + msize);
  memcpy (&q[1], msg, msize);
  /* append to message queue */
  if (client->message_queue_tail == NULL)
    {
      client->message_queue_tail = q;
    }
  else
    {
      client->message_queue_tail->next = q;
      client->message_queue_tail = q;
    }
  if (client->message_queue_head == NULL)
    {
      client->message_queue_head = q;
      th = GNUNET_SERVER_notify_transmit_ready (client->client,
                                                msize,
                                                GNUNET_TIME_UNIT_FOREVER_REL,
                                                &transmit_to_client_callback,
                                                client);
      GNUNET_assert (th != NULL);
    }
}


/**
 * Find alternative plugins for communication.
 *
 * @param neighbor for which neighbor should we try to find
 *        more plugins?
 */
static void
try_alternative_plugins (struct NeighborList *neighbor)
{
  struct ReadyList *rl;

  if ((neighbor->plugins != NULL) &&
      (neighbor->retry_plugins_time.value >
       GNUNET_TIME_absolute_get ().value))
    return;                     /* don't try right now */
  neighbor->retry_plugins_time
    = GNUNET_TIME_relative_to_absolute (PLUGIN_RETRY_FREQUENCY);

  rl = neighbor->plugins;
#if WTF /* FIXME: What is this supposed to do? */
  while (rl != NULL)
    {
      if (rl->connect_attempts > 0)
        rl->connect_attempts--; /* amnesty */
      rl = rl->next;
    }
#endif
}


/**
 * Function called by the GNUNET_TRANSPORT_TransmitFunction
 * upon "completion" of a send request.  This tells the API
 * that it is now legal to send another message to the given
 * peer.
 *
 * @param cls closure, identifies the entry on the
 *            message queue that was transmitted and the
 *            client responsible for queueing the message
 * @param target the peer receiving the message
 * @param result GNUNET_OK on success, if the transmission
 *           failed, we should not tell the client to transmit
 *           more messages
 */
static void
transmit_send_continuation (void *cls,
                            const struct GNUNET_PeerIdentity *target,
                            int result)
{
  struct MessageQueue *mq = cls;
  /*struct ReadyList *rl;*/ /* We no longer use the ReadyList for anything here, safe to remove? */
  struct SendOkMessage send_ok_msg;
  struct NeighborList *n;

  GNUNET_assert (mq != NULL);
  n = find_neighbor(mq->neighbor_id);
  if (n == NULL) /* Neighbor must have been removed asynchronously! */
    return;

  /* Otherwise, let's make sure we've got the right peer */
  GNUNET_assert (0 ==
                 memcmp (&n->id, target,
                         sizeof (struct GNUNET_PeerIdentity)));

  if (result == GNUNET_OK)
    {
      mq->specific_peer->timeout =
        GNUNET_TIME_relative_to_absolute
        (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission to peer `%s' failed, marking connection as down.\n",
                  GNUNET_i2s (target));
      mq->specific_peer->connected = GNUNET_NO;
    }
  if (!mq->internal_msg)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Setting transmit_ready on transport!\n");
#endif
      mq->specific_peer->transmit_ready = GNUNET_YES;
    }

  if (mq->client != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Notifying client %p about transmission to peer `%4s'.\n",
                  mq->client, GNUNET_i2s (target));
      send_ok_msg.header.size = htons (sizeof (send_ok_msg));
      send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
      send_ok_msg.success = htonl (result);
      send_ok_msg.peer = n->id;
      transmit_to_client (mq->client, &send_ok_msg.header, GNUNET_NO);
    }
  GNUNET_free (mq->message_buf);
  GNUNET_free (mq);
  /* one plugin just became ready again, try transmitting
     another message (if available) */
  if (result == GNUNET_OK)
    try_transmission_to_peer (n);
  else
    disconnect_neighbor (n, GNUNET_YES);
}




struct PeerAddressList *
find_ready_address(struct NeighborList *neighbor)
{
  struct ReadyList *head = neighbor->plugins;
  struct PeerAddressList *addresses;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Relative min_latency = GNUNET_TIME_relative_get_forever();
  struct PeerAddressList *best_address;

  best_address = NULL;
  while (head != NULL)
    {
      addresses = head->addresses;

      while (addresses != NULL)
        {
          if ((addresses->timeout.value < now.value) && (addresses->connected == GNUNET_YES))
            {
#if DEBUG_TRANSPORT
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Marking long-time inactive connection to `%4s' as down.\n",
                          GNUNET_i2s (&addresses->ready_list->neighbor->id));
#endif
              addresses->connected = GNUNET_NO;
            }
          addresses = addresses->next;
        }

      addresses = head->addresses;
      while (addresses != NULL)
        {
          if ((addresses->connected == GNUNET_YES) &&
              (addresses->transmit_ready == GNUNET_YES) &&
              ((addresses->latency.value < min_latency.value) || (best_address == NULL)))
            {
#if DEBUG_TRANSPORT
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Found address with latency %llu, setting as best found yet!\n",
                          addresses->latency.value);
#endif
              best_address = addresses;
            }
          addresses = addresses->next;
        }
      head = head->next;
    }
#if DEBUG_TRANSPORT
  if (best_address != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Best address found has latency of %llu!\n",
                  best_address->latency.value);
    }
#endif
  return best_address;

}

/**
 * Check the ready list for the given neighbor and
 * if a plugin is ready for transmission (and if we
 * have a message), do so!
 */
static ssize_t
try_transmission_to_peer (struct NeighborList *neighbor)
{
  struct GNUNET_TIME_Relative min_latency;
  struct ReadyList *rl;
  struct MessageQueue *mq;
  struct GNUNET_TIME_Absolute now;

  if (neighbor->messages == NULL)
    return 0;                     /* nothing to do */
  try_alternative_plugins (neighbor);
  min_latency = GNUNET_TIME_UNIT_FOREVER_REL;
  rl = NULL;
  mq = neighbor->messages;
  now = GNUNET_TIME_absolute_get ();

  if (mq->specific_peer == NULL)
    mq->specific_peer = find_ready_address(neighbor); /* Find first available (or best!) address to transmit to */

  if (mq->specific_peer == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No plugin ready to transmit message\n");
#endif
      return 0;                   /* nobody ready */
    }

  rl = mq->specific_peer->ready_list;
  neighbor->messages = mq->next;
  mq->plugin = rl->plugin;
  if (!mq->internal_msg)
    mq->specific_peer->transmit_ready = GNUNET_NO;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Giving message of size `%u' for `%4s' to plugin `%s'\n",
              mq->message_buf_size,
              GNUNET_i2s (&neighbor->id), rl->plugin->short_name);
#endif

  return rl->plugin->api->send (rl->plugin->api->cls,
                         mq->neighbor_id,
                         mq->message_buf,
                         mq->message_buf_size,
                         mq->priority,
                         GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                         mq->specific_peer->addr,
                         mq->specific_peer->addrlen,
                         GNUNET_YES,
                         &transmit_send_continuation, mq);

}


/**
 * Send the specified message to the specified peer.
 *
 * @param client source of the transmission request (can be NULL)
 * @param peer_address PeerAddressList where we should send this message
 * @param priority how important is the message
 * @param message_buf message(s) to send GNUNET_MessageHeader(s)
 * @param message_buf_size total size of all messages in message_buf
 * @param is_internal is this an internal message
 * @param neighbor handle to the neighbor for transmission
 */
static ssize_t
transmit_to_peer (struct TransportClient *client,
                  struct PeerAddressList *peer_address,
                  unsigned int priority,
                  const char *message_buf,
                  size_t message_buf_size,
                  int is_internal, struct NeighborList *neighbor)
{
  struct MessageQueue *mq;
  struct MessageQueue *mqe;
  char *m;

  if (client != NULL)
    {
      /* check for duplicate submission */
      mq = neighbor->messages;
      while (NULL != mq)
        {
          if (mq->client == client)
            {
              /* client transmitted to same peer twice
                 before getting SendOk! */
              GNUNET_break (0);
              return 0;
            }
          mq = mq->next;
        }
    }
  mq = GNUNET_malloc (sizeof (struct MessageQueue));
  mq->specific_peer = peer_address;
  mq->client = client;
  m = GNUNET_malloc (message_buf_size);
  memcpy (m, message_buf, message_buf_size);
  mq->message_buf = m;
  mq->message_buf_size = message_buf_size;
  mq->neighbor_id = GNUNET_malloc(sizeof (struct GNUNET_PeerIdentity));

  memcpy(mq->neighbor_id, &neighbor->id, sizeof(struct GNUNET_PeerIdentity));
  mq->internal_msg = is_internal;
  mq->priority = priority;

  /* find tail */
  mqe = neighbor->messages;
  if (mqe != NULL)
    while (mqe->next != NULL)
      mqe = mqe->next;
  if (mqe == NULL)
    {
      /* new head */
      neighbor->messages = mq;
    }
  else
    {
      /* append */
      mqe->next = mq;
    }
  return try_transmission_to_peer (neighbor);
}


/**
 * FIXME: document.
 */
struct GeneratorContext
{
  struct TransportPlugin *plug_pos;
  struct AddressList *addr_pos;
  struct GNUNET_TIME_Absolute expiration;
};


/**
 * FIXME: document.
 */
static size_t
address_generator (void *cls, size_t max, void *buf)
{
  struct GeneratorContext *gc = cls;
  size_t ret;

  while ((gc->addr_pos == NULL) && (gc->plug_pos != NULL))
    {
      gc->plug_pos = gc->plug_pos->next;
      gc->addr_pos = (gc->plug_pos != NULL) ? gc->plug_pos->addresses : NULL;
    }
  if (NULL == gc->plug_pos)
    {

      return 0;
    }
  ret = GNUNET_HELLO_add_address (gc->plug_pos->short_name,
                                  gc->expiration,
                                  gc->addr_pos->addr,
                                  gc->addr_pos->addrlen, buf, max);
  gc->addr_pos = gc->addr_pos->next;
  return ret;
}


/**
 * Construct our HELLO message from all of the addresses of
 * all of the transports.
 */
static void
refresh_hello ()
{
  struct GNUNET_HELLO_Message *hello;
  struct TransportClient *cpos;
  struct NeighborList *npos;
  struct GeneratorContext gc;

  gc.plug_pos = plugins;
  gc.addr_pos = plugins != NULL ? plugins->addresses : NULL;
  gc.expiration = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
  hello = GNUNET_HELLO_create (&my_public_key, &address_generator, &gc);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Refreshed my `%s', new size is %d\n", "HELLO", GNUNET_HELLO_size(hello));
#endif
  cpos = clients;
  while (cpos != NULL)
    {
      transmit_to_client (cpos,
                          (const struct GNUNET_MessageHeader *) hello,
                          GNUNET_NO);
      cpos = cpos->next;
    }

  GNUNET_free_non_null (our_hello);
  our_hello = hello;
  our_hello_version++;
  GNUNET_PEERINFO_add_peer (cfg, sched, &my_identity, our_hello);
  npos = neighbors;
  while (npos != NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Transmitting updated `%s' to neighbor `%4s'\n",
                  "HELLO", GNUNET_i2s (&npos->id));
#endif // FIXME: just testing
      //transmit_to_peer (NULL, NULL, 0,
      //                  (const char *) our_hello, GNUNET_HELLO_size(our_hello),
      //                  GNUNET_YES, npos);
      npos = npos->next;
    }
}


/**
 * Task used to clean up expired addresses for a plugin.
 *
 * @param cls closure
 * @param tc context
 */
static void
expire_address_task (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Update the list of addresses for this plugin,
 * expiring those that are past their expiration date.
 *
 * @param plugin addresses of which plugin should be recomputed?
 * @param fresh set to GNUNET_YES if a new address was added
 *        and we need to regenerate the HELLO even if nobody
 *        expired
 */
static void
update_addresses (struct TransportPlugin *plugin, int fresh)
{
  struct GNUNET_TIME_Relative min_remaining;
  struct GNUNET_TIME_Relative remaining;
  struct GNUNET_TIME_Absolute now;
  struct AddressList *pos;
  struct AddressList *prev;
  struct AddressList *next;
  int expired;

  if (plugin->address_update_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (plugin->env.sched, plugin->address_update_task);
  plugin->address_update_task = GNUNET_SCHEDULER_NO_TASK;
  now = GNUNET_TIME_absolute_get ();
  min_remaining = GNUNET_TIME_UNIT_FOREVER_REL;
  expired = GNUNET_NO;
  prev = NULL;
  pos = plugin->addresses;
  while (pos != NULL)
    {
      next = pos->next;
      if (pos->expires.value < now.value)
        {
          expired = GNUNET_YES;
          if (prev == NULL)
            plugin->addresses = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
        }
      else
        {
          remaining = GNUNET_TIME_absolute_get_remaining (pos->expires);
          if (remaining.value < min_remaining.value)
            min_remaining = remaining;
          prev = pos;
        }
      pos = next;
    }

  if (expired || fresh)
    refresh_hello ();
  if (min_remaining.value < GNUNET_TIME_UNIT_FOREVER_REL.value)
    plugin->address_update_task
      = GNUNET_SCHEDULER_add_delayed (plugin->env.sched,
                                      min_remaining,
                                      &expire_address_task, plugin);

}


/**
 * Task used to clean up expired addresses for a plugin.
 *
 * @param cls closure
 * @param tc context
 */
static void
expire_address_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TransportPlugin *plugin = cls;
  plugin->address_update_task = GNUNET_SCHEDULER_NO_TASK;
  update_addresses (plugin, GNUNET_NO);
}


/**
 * Function that must be called by each plugin to notify the
 * transport service about the addresses under which the transport
 * provided by the plugin can be reached.
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param expires when should this address automatically expire?
 */
static void
plugin_env_notify_address (void *cls,
                           const char *name,
                           const void *addr,
                           size_t addrlen,
                           struct GNUNET_TIME_Relative expires)
{
  struct TransportPlugin *p = cls;
  struct AddressList *al;
  struct GNUNET_TIME_Absolute abex;

  abex = GNUNET_TIME_relative_to_absolute (expires);
  GNUNET_assert (p == find_transport (name));

  al = p->addresses;
  while (al != NULL)
    {
      if ((addrlen == al->addrlen) && (0 == memcmp (addr, &al[1], addrlen)))
        {
          if (al->expires.value < abex.value)
            al->expires = abex;
          return;
        }
      al = al->next;
    }

  al = GNUNET_malloc (sizeof (struct AddressList) + addrlen);
  al->addr = &al[1];
  al->next = p->addresses;
  p->addresses = al;
  al->expires = abex;
  al->addrlen = addrlen;
  memcpy (&al[1], addr, addrlen);
  update_addresses (p, GNUNET_YES);
}


/**
 * Notify all of our clients about a peer connecting.
 */
static void
notify_clients_connect (const struct GNUNET_PeerIdentity *peer,
                        struct GNUNET_TIME_Relative latency)
{
  struct ConnectInfoMessage cim;
  struct TransportClient *cpos;

  cim.header.size = htons (sizeof (struct ConnectInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim.quota_out = htonl (GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT / (60 * 1000));
  cim.latency = GNUNET_TIME_relative_hton (latency);
  memcpy (&cim.id, peer, sizeof (struct GNUNET_PeerIdentity));
  cpos = clients;
  while (cpos != NULL)
    {
      transmit_to_client (cpos, &cim.header, GNUNET_NO);
      cpos = cpos->next;
    }
}


/**
 * Notify all of our clients about a peer disconnecting.
 */
static void
notify_clients_disconnect (const struct GNUNET_PeerIdentity *peer)
{
  struct DisconnectInfoMessage dim;
  struct TransportClient *cpos;

  dim.header.size = htons (sizeof (struct DisconnectInfoMessage));
  dim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  dim.reserved = htonl (0);
  memcpy (&dim.peer, peer, sizeof (struct GNUNET_PeerIdentity));
  cpos = clients;
  while (cpos != NULL)
    {
      transmit_to_client (cpos, &dim.header, GNUNET_NO);
      cpos = cpos->next;
    }
}


/**
 * Copy any validated addresses to buf.
 *
 * @return 0 once all addresses have been
 *         returned
 */
static size_t
list_validated_addresses (void *cls, size_t max, void *buf)
{
  struct ValidationAddress **va = cls;
  size_t ret;

  while ((NULL != *va) && ((*va)->ok != GNUNET_YES))
    *va = (*va)->next;
  if (NULL == *va)
    return 0;
  ret = GNUNET_HELLO_add_address ((*va)->transport_name,
                                  (*va)->expiration,
                                  (*va)->peer_address->addr, (*va)->peer_address->addrlen, buf, max);
  *va = (*va)->next;
  return ret;
}


/**
 * HELLO validation cleanup task.
 */
static void
cleanup_validation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationAddress *va;
  struct ValidationList *pos;
  struct ValidationList *prev;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute first;
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity pid;
  struct NeighborList *n;

  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  pos = pending_validations;
  while (pos != NULL)
    {
      if (pos->timeout.value < now.value)
        {
          if (prev == NULL)
            pending_validations = pos->next;
          else
            prev->next = pos->next;
          va = pos->addresses;
          hello = GNUNET_HELLO_create (&pos->publicKey,
                                       &list_validated_addresses, &va);
          GNUNET_CRYPTO_hash (&pos->publicKey,
                              sizeof (struct
                                      GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                              &pid.hashPubKey);
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Creating persistent `%s' message for peer `%4s' based on confirmed addresses.\n",
                      "HELLO", GNUNET_i2s (&pid));
#endif
          GNUNET_PEERINFO_add_peer (cfg, sched, &pid, hello);
          n = find_neighbor (&pid);
          if (NULL != n)
            {
              try_transmission_to_peer (n);
            }
          GNUNET_free (hello);
          while (NULL != (va = pos->addresses))
            {
              pos->addresses = va->next;
              GNUNET_free (va->transport_name);
              GNUNET_free (va);
            }
          GNUNET_free (pos);
          if (prev == NULL)
            pos = pending_validations;
          else
            pos = prev->next;
          continue;
        }
      prev = pos;
      pos = pos->next;
    }

  /* finally, reschedule cleanup if needed; list is
     ordered by timeout, so we need the last element... */
  if (NULL != pending_validations)
    {
      first = pending_validations->timeout;
      pos = pending_validations;
      while (pos != NULL)
        {
          first = GNUNET_TIME_absolute_min (first, pos->timeout);
          pos = pos->next;
        }
      if (tc->reason != GNUNET_SCHEDULER_REASON_SHUTDOWN)
        {
          GNUNET_SCHEDULER_add_delayed (sched,
                                        GNUNET_TIME_absolute_get_remaining
                                        (first), &cleanup_validation, NULL);
        }
    }
}


/**
 * Function that will be called if we receive a validation
 * of an address challenge that we transmitted to another
 * peer.  Note that the validation should only be considered
 * acceptable if the challenge matches AND if the sender
 * address is at least a plausible address for this peer
 * (otherwise we may be seeing a MiM attack).
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param peer who responded to our challenge
 * @param challenge the challenge number we presumably used
 * @param sender_addr string describing our sender address (as observed
 *         by the other peer in human-readable format)
 */
static void
handle_pong (void *cls, const struct GNUNET_MessageHeader *message,
             const struct GNUNET_PeerIdentity *peer,
             const char *sender_address,
             size_t sender_address_len)
{
  unsigned int not_done;
  int matched;
  struct ValidationList *pos;
  struct ValidationAddress *va;
  struct GNUNET_PeerIdentity id;
  const struct TransportPongMessage *pong = (const struct TransportPongMessage *)message;
  int count = 0;
  unsigned int challenge = ntohl(pong->challenge);
  pos = pending_validations;

  while (pos != NULL)
    {
      GNUNET_CRYPTO_hash (&pos->publicKey,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &id.hashPubKey);
      if (0 == memcmp (peer, &id, sizeof (struct GNUNET_PeerIdentity)))
        break;
      pos = pos->next;
      count++;
    }
  if (pos == NULL)
    {
      /* TODO: call statistics (unmatched PONG) */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Received validation response but have no record of any validation request for `%4s' (out of %d). Ignoring.\n"),
                  GNUNET_i2s (peer), count);
      return;
    }
  not_done = 0;
  matched = GNUNET_NO;
  va = pos->addresses;
  while (va != NULL)
    {
      if (va->challenge == challenge)
        {
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Confirmed validity of address, peer `%4s' has address `%s'.\n",
                      GNUNET_i2s (peer),
                      GNUNET_a2s ((const struct sockaddr *) sender_address,
                                  sender_address_len));
#endif
          GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
                      _
                      ("Another peer saw us using the address `%s' via `%s'. If this is not plausible, this address should be listed in the configuration as implausible to avoid MiM attacks.\n"),
                      GNUNET_a2s ((const struct sockaddr *) &pong[1],
                                                           ntohs(pong->addrlen)), va->transport_name);
          va->ok = GNUNET_YES;
          va->expiration =
            GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
          matched = GNUNET_YES;
          va->peer_address->connected = GNUNET_YES;
          va->peer_address->latency = GNUNET_TIME_absolute_get_difference(va->peer_address->validation->send_time, GNUNET_TIME_absolute_get());
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Confirmed validity of address, peer `%4s' has address `%s', latency of %llu\n",
                      GNUNET_i2s (peer),
                      GNUNET_a2s ((const struct sockaddr *) sender_address,
                                  sender_address_len), (unsigned long long)va->peer_address->latency.value);
#endif
          va->peer_address->transmit_ready = GNUNET_YES;
          va->peer_address->expires = GNUNET_TIME_relative_to_absolute
              (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
        }
      if (va->ok != GNUNET_YES)
        not_done++;
      va = va->next;
    }
  if (GNUNET_NO == matched)
    {
      /* TODO: call statistics (unmatched PONG) */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Received `%s' message but have no record of a matching `%s' message. Ignoring.\n"),
                  "PONG", "PING");
    }
  if (0 == not_done)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All addresses validated, will now construct `%s' for `%4s'.\n",
                  "HELLO", GNUNET_i2s (peer));
#endif
      pos->timeout.value = 0;
      GNUNET_SCHEDULER_add_with_priority (sched,
                                          GNUNET_SCHEDULER_PRIORITY_IDLE,
                                          &cleanup_validation, NULL);
    }

}

/**
 * Add an entry for each of our transport plugins
 * (that are able to send) to the list of plugins
 * for this neighbor.
 *
 * @param neighbor to initialize
 */
static void
add_plugins (struct NeighborList *neighbor)
{
  struct TransportPlugin *tp;
  struct ReadyList *rl;

  neighbor->retry_plugins_time
    = GNUNET_TIME_relative_to_absolute (PLUGIN_RETRY_FREQUENCY);
  tp = plugins;
  while (tp != NULL)
    {
      if (tp->api->send != NULL)
        {
          rl = GNUNET_malloc (sizeof (struct ReadyList));
          rl->next = neighbor->plugins;
          neighbor->plugins = rl;
          rl->plugin = tp;
          rl->neighbor = neighbor;
          rl->addresses = NULL;
        }
      tp = tp->next;
    }
}

static void
neighbor_timeout_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighborList *n = cls;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Neighbor `%4s' has timed out!\n", GNUNET_i2s (&n->id));
#endif
  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  disconnect_neighbor (n, GNUNET_NO);
}

/**
 * Create a fresh entry in our neighbor list for the given peer.
 * Will try to transmit our current HELLO to the new neighbor.  Also
 * notifies our clients about the new "connection".
 *
 * @param peer the peer for which we create the entry
 * @return the new neighbor list entry
 */
static struct NeighborList *
setup_new_neighbor (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighborList *n;

  GNUNET_assert (our_hello != NULL);
  n = GNUNET_malloc (sizeof (struct NeighborList));
  n->next = neighbors;
  neighbors = n;
  n->id = *peer;
  n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  n->quota_in = (GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT + 59999) / (60 * 1000);
  add_plugins (n);
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                  GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                  &neighbor_timeout_task, n);
  transmit_to_peer (NULL, NULL, 0,
                    (const char *) our_hello, GNUNET_HELLO_size(our_hello),
                    GNUNET_YES, n);
  notify_clients_connect (peer, GNUNET_TIME_UNIT_FOREVER_REL);
  return n;
}

static struct PeerAddressList *
add_peer_address(struct NeighborList *neighbor, const char *addr, size_t addrlen)
{
  /* FIXME: should return a list of PeerAddressLists, support for multiple transports! */
  struct ReadyList *head = neighbor->plugins;
  struct PeerAddressList * new_address;

  GNUNET_assert(addr != NULL);

  new_address = NULL;
  while (head != NULL)
    {
      new_address = GNUNET_malloc(sizeof(struct PeerAddressList));
      new_address->addr = GNUNET_malloc(addrlen);
      memcpy(new_address->addr, addr, addrlen);
      new_address->addrlen = addrlen;
      new_address->connect_attempts = 0;
      new_address->connected = GNUNET_YES; /* Set connected to GNUNET_YES, assuming that we're good */
      new_address->expires = GNUNET_TIME_relative_to_absolute
          (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
      new_address->latency = GNUNET_TIME_relative_get_forever();
      new_address->neighbor = neighbor;
      new_address->plugin = head->plugin;
      new_address->transmit_ready = GNUNET_YES;
      new_address->timeout = GNUNET_TIME_relative_to_absolute
          (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT); /* FIXME: Do we need this? */
      new_address->ready_list = head;
      new_address->next = head->addresses;
      head->addresses = new_address;
      head = head->next;
    }

  return new_address;
}

static struct PeerAddressList *
find_peer_address(struct NeighborList *neighbor, const char *addr, size_t addrlen)
{
  struct ReadyList *head = neighbor->plugins;
  struct PeerAddressList *address_head;
  while (head != NULL)
    {
      address_head = head->addresses;
      while ((address_head != NULL) &&
              (address_head->addrlen != addrlen) &&
              (memcmp(address_head->addr, addr, addrlen) != 0))
        {
          address_head = address_head->next;
        }
      if (address_head != NULL)
        return address_head;

      head = head->next;
    }
  return NULL;
}

/**
 * Append the given address to the list of entries
 * that need to be validated.
 */
static int
run_validation (void *cls,
                const char *tname,
                struct GNUNET_TIME_Absolute expiration,
                const void *addr, size_t addrlen)
{
  struct ValidationList *e = cls;
  struct TransportPlugin *tp;
  struct ValidationAddress *va;
  struct GNUNET_PeerIdentity id;
  struct NeighborList *neighbor;
  struct PeerAddressList *peer_address;
  int sent;
  struct TransportPingMessage *ping;
  char * message_buf;
  int hello_size;
  int tsize;

  tp = find_transport (tname);
  if (tp == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO |
                  GNUNET_ERROR_TYPE_BULK,
                  _
                  ("Transport `%s' not loaded, will not try to validate peer address using this transport.\n"),
                  tname);
      return GNUNET_OK;
    }
  GNUNET_CRYPTO_hash (&e->publicKey,
                      sizeof (struct
                              GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id.hashPubKey);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling validation of address `%s' via `%s' for `%4s'\n",
              GNUNET_a2s (addr, addrlen), tname, GNUNET_i2s (&id));
#endif
  va = GNUNET_malloc (sizeof (struct ValidationAddress));
  va->next = e->addresses;
  e->addresses = va;
  va->transport_name = GNUNET_strdup (tname);
  va->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                            (unsigned int) -1);
  va->send_time = GNUNET_TIME_absolute_get();

  neighbor = find_neighbor(&id);

  if (neighbor == NULL)
    neighbor = setup_new_neighbor(&id);

  peer_address = find_peer_address(neighbor, addr, addrlen);
  if (peer_address == NULL)
    {
      peer_address = add_peer_address(neighbor, addr, addrlen);
    }

  GNUNET_assert(peer_address != NULL);

  va->peer_address = peer_address; /* Back pointer FIXME: remove this nonsense! */
  peer_address->validation = va;

  hello_size = GNUNET_HELLO_size(our_hello);
  tsize = sizeof(struct TransportPingMessage) + hello_size;

  message_buf = GNUNET_malloc(tsize);

  ping = GNUNET_malloc(sizeof(struct TransportPingMessage));
  ping->challenge = htonl(va->challenge);
  ping->header.size = htons(sizeof(struct TransportPingMessage));
  ping->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  memcpy(&ping->target, &id, sizeof(struct GNUNET_PeerIdentity));

#if DEBUG_TRANSPORT
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "hello size is %d, ping size is %d, total size is %d", hello_size, sizeof(struct TransportPingMessage), tsize);
#endif
  memcpy(message_buf, our_hello, hello_size);
  memcpy(&message_buf[hello_size], ping, sizeof(struct TransportPingMessage));

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending ping message of size %d to address `%s' via `%s' for `%4s'\n",
                tsize, GNUNET_a2s (addr, addrlen), tname, GNUNET_i2s (&id));
#endif
  sent = transmit_to_peer(NULL, peer_address, GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                   message_buf, tsize, GNUNET_NO, neighbor);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transport returned %d from send!\n", sent);
#endif

  GNUNET_free(ping);
  GNUNET_free(message_buf);
  return GNUNET_OK;
}

#if WHY
/*
 * @param cls handle to the plugin (for sending)
 * @param target the peer identity of the peer we are sending to
 * @param challenge the challenge number
 * @param timeout how long to await validation?
 * @param addr the address to validate
 * @param addrlen the length of the address
 *
 * Perform address validation, which means sending a PING PONG to
 * the address via the transport plugin.  If not validated, then
 * do not count this as a good peer/address...
 *
 * Currently this function is not used, ping/pongs get sent from the
 * run_validation function.  Haven't decided yet how to do this.
 */
static void
validate_address (void *cls, struct ValidationAddress *va,
                  const struct GNUNET_PeerIdentity *target,
                  struct GNUNET_TIME_Relative timeout,
                  const void *addr, size_t addrlen)
{
  /* struct Plugin *plugin = cls;
  int challenge = va->challenge; */


  return;
}
#endif

/**
 * Check if addresses in validated hello "h" overlap with
 * those in "chvc->hello" and update "chvc->hello" accordingly,
 * removing those addresses that have already been validated.
 */
static void
check_hello_validated (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_HELLO_Message *h, uint32_t trust)
{
  struct CheckHelloValidatedContext *chvc = cls;
  struct ValidationAddress *va;
  struct TransportPlugin *tp;
  int first_call;
  int count;
  struct GNUNET_PeerIdentity apeer;

  first_call = GNUNET_NO;
  if (chvc->e == NULL)
    {
      chvc->piter = NULL;
      first_call = GNUNET_YES;
      chvc->e = GNUNET_malloc (sizeof (struct ValidationList));
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_HELLO_get_key (h != NULL ? h : chvc->hello,
                                           &chvc->e->publicKey));
      chvc->e->timeout =
        GNUNET_TIME_relative_to_absolute (HELLO_VERIFICATION_TIMEOUT);
      chvc->e->next = pending_validations;
      pending_validations = chvc->e;
    }

  if (h != NULL)
    {
      GNUNET_HELLO_iterate_new_addresses (chvc->hello,
                                          h,
                                          GNUNET_TIME_absolute_get (),
                                          &run_validation, chvc->e);
    }
  else if (GNUNET_YES == first_call)
    {
      /* no existing HELLO, all addresses are new */
      GNUNET_HELLO_iterate_addresses (chvc->hello,
                                      GNUNET_NO, &run_validation, chvc->e);
    }

  if (h != NULL)
    return;                     /* wait for next call */
  /* finally, transmit validation attempts */
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_id (chvc->hello, &apeer));

  va = chvc->e->addresses;
  count = 0;
  while (va != NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Establishing `%s' connection to validate `%s' address `%s' of `%4s'\n",
                  va->transport_name,
                  "HELLO",
                  GNUNET_a2s ((const struct sockaddr *) va->peer_address->addr,
                              va->peer_address->addrlen), GNUNET_i2s (&apeer));
#endif
      tp = find_transport (va->transport_name);
      GNUNET_assert (tp != NULL);
      /* This validation should happen inside the transport, not from the plugin! */
      va->ok = GNUNET_SYSERR;
      va = va->next;
      count++;
    }

  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_absolute_get_remaining (chvc->
                                                                    e->timeout),
                                &cleanup_validation, NULL);
  GNUNET_free (chvc);
}


/**
 * Process HELLO-message.
 *
 * @param plugin transport involved, may be NULL
 * @param message the actual message
 * @return GNUNET_OK if the HELLO was well-formed, GNUNET_SYSERR otherwise
 */
static int
process_hello (struct TransportPlugin *plugin,
               const struct GNUNET_MessageHeader *message)
{
  struct ValidationList *e;
  uint16_t hsize;
  struct GNUNET_PeerIdentity target;
  const struct GNUNET_HELLO_Message *hello;
  struct CheckHelloValidatedContext *chvc;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

  hsize = ntohs (message->size);
  if ((ntohs (message->type) != GNUNET_MESSAGE_TYPE_HELLO) ||
      (hsize < sizeof (struct GNUNET_MessageHeader)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  /* first, check if load is too high */
  if (GNUNET_OS_load_cpu_get (cfg) > 100)
    {
      /* TODO: call to stats? */
      return GNUNET_OK;
    }
  hello = (const struct GNUNET_HELLO_Message *) message;
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, &publicKey))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  GNUNET_CRYPTO_hash (&publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &target.hashPubKey);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing `%s' message for `%4s' of size %d (hsize is %d)\n",
              "HELLO", GNUNET_i2s (&target), GNUNET_HELLO_size(hello), hsize);
#endif
  /* check if a HELLO for this peer is already on the validation list */
  e = pending_validations;
  while (e != NULL)
    {
      if (0 == memcmp (&e->publicKey,
                       &publicKey,
                       sizeof (struct
                               GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
        {
          /* TODO: call to stats? */
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "`%s' message for peer `%4s' is already pending; ignoring new message\n",
                      "HELLO", GNUNET_i2s (&target));
#endif
          return GNUNET_OK;
        }
      e = e->next;
    }
  chvc = GNUNET_malloc (sizeof (struct CheckHelloValidatedContext) + hsize);
  chvc->plugin = plugin;
  chvc->hello = (struct GNUNET_HELLO_Message *) &chvc[1];
  chvc->e = NULL;
  memcpy (chvc->hello, hello, hsize);
  /* finally, check if HELLO was previously validated
     (continuation will then schedule actual validation) */
  chvc->piter = GNUNET_PEERINFO_iterate (cfg,
                                         sched,
                                         &target,
                                         0,
                                         HELLO_VERIFICATION_TIMEOUT,
                                         &check_hello_validated, chvc);
  return GNUNET_OK;
}


/**
 * The peer specified by the given neighbor has timed-out or a plugin
 * has disconnected.  We may either need to do nothing (other plugins
 * still up), or trigger a full disconnect and clean up.  This
 * function updates our state and does the necessary notifications.
 * Also notifies our clients that the neighbor is now officially
 * gone.
 *
 * @param n the neighbor list entry for the peer
 * @param check should we just check if all plugins
 *        disconnected or must we ask all plugins to
 *        disconnect?
 */
static void
disconnect_neighbor (struct NeighborList *current_handle, int check)
{
  struct ReadyList *rpos;
  struct NeighborList *npos;
  struct NeighborList *nprev;
  struct NeighborList *n;
  struct MessageQueue *mq;
  struct PeerAddressList *peer_addresses;

  if (neighbors == NULL)
    return; /* We don't have any neighbors, so client has an already removed handle! */

  npos = neighbors;
  while ((npos != NULL) && (current_handle != npos))
    npos = npos->next;

  if (npos == NULL)
    return; /* Couldn't find neighbor in existing list, must have been already removed! */
  else
    n = npos;

  if (GNUNET_YES == check)
    {
      rpos = n->plugins;
      while (NULL != rpos)
        {
          peer_addresses = rpos->addresses;
          while (peer_addresses != NULL)
            {
              if (GNUNET_YES == peer_addresses->connected)
                return;             /* still connected */
              peer_addresses = peer_addresses->next;
            }
          rpos = rpos->next;
        }
    }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Disconnecting from `%4s'\n", GNUNET_i2s (&n->id));
#endif
  /* remove n from neighbors list */
  nprev = NULL;
  npos = neighbors;
  while ((npos != NULL) && (npos != n))
    {
      nprev = npos;
      npos = npos->next;
    }
  GNUNET_assert (npos != NULL);
  if (nprev == NULL)
    neighbors = n->next;
  else
    nprev->next = n->next;

  /* notify all clients about disconnect */
  notify_clients_disconnect (&n->id);

  /* clean up all plugins, cancel connections and pending transmissions */
  while (NULL != (rpos = n->plugins))
    {
      n->plugins = rpos->next;
      GNUNET_assert (rpos->neighbor == n);
      if (GNUNET_YES == rpos->connected)
        rpos->plugin->api->disconnect (rpos->plugin->api->cls, &n->id);
      GNUNET_free (rpos);
    }

  /* free all messages on the queue */
  while (NULL != (mq = n->messages))
    {
      n->messages = mq->next;
      GNUNET_assert (0 == memcmp(mq->neighbor_id, &n->id, sizeof(struct GNUNET_PeerIdentity)));
      GNUNET_free (mq);
    }
  if (n->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->timeout_task);
  /* finally, free n itself */
  GNUNET_free (n);
}


/*
 * We have received a PING message from someone.  Need to send a PONG message
 * in response to the peer by any means necessary.  Of course, with something
 * like TCP where a connection exists, we may want to send it that way.  But
 * we may not be able to make that distinction...
 */
static int handle_ping(void *cls, const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_PeerIdentity *peer,
                       const char *sender_address,
                       size_t sender_address_len)
{
  struct TransportPlugin *plugin = cls;
  struct TransportPingMessage *ping;
  struct TransportPongMessage *pong;
  struct PeerAddressList *peer_address;
  uint16_t msize;
  struct NeighborList *n;

#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Processing `%s' from `%s'\n",
               "PING", GNUNET_a2s ((const struct sockaddr *)sender_address, sender_address_len));
#endif

  msize = ntohs (message->size);
  if (msize < sizeof (struct TransportPingMessage))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  ping = (struct TransportPingMessage *) message;
  if (0 != memcmp (&ping->target,
                   plugin->env.my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Received `%s' message not destined for me!\n"), "PING");
      return GNUNET_SYSERR;
    }

  msize -= sizeof (struct TransportPingMessage);

  pong = GNUNET_malloc (sizeof (struct TransportPongMessage) + sender_address_len);
  pong->header.size = htons (sizeof (struct TransportPongMessage) + sender_address_len);
  pong->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
  pong->purpose.size =
    htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
           sizeof (uint32_t) +
           sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) + sender_address_len);
  pong->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_TCP_PING);
  pong->challenge = ping->challenge;
  pong->addrlen = htons(sender_address_len);

  memcpy(&pong->signer, &my_public_key, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  memcpy (&pong[1], sender_address, sender_address_len);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key,
                                         &pong->purpose, &pong->signature));

  n = find_neighbor(peer);
  if (n == NULL)
    n = setup_new_neighbor(peer);

  peer_address = find_peer_address(n, sender_address, sender_address_len);
  if (peer_address == NULL)
    peer_address = add_peer_address(n, sender_address, sender_address_len);

  transmit_to_peer(NULL, NULL, TRANSPORT_DEFAULT_PRIORITY, (char *)pong, ntohs(pong->header.size), GNUNET_NO, n);

  GNUNET_free(pong);
  return GNUNET_OK;
}

/**
 * Function called by the plugin for each received message.
 * Update data volumes, possibly notify plugins about
 * reducing the rate at which they read from the socket
 * and generally forward to our receive callback.
 *
 * @param cls the "struct TransportPlugin *" we gave to the plugin
 * @param message the message, NULL if peer was disconnected
 * @param distance the transport cost to this peer (not latency!)
 * @param sender_address the address that the sender reported
 *        (opaque to transport service)
 * @param sender_address_len the length of the sender address
 * @param peer (claimed) identity of the other peer
 * @return the new service_context that the plugin should use
 *         for future receive calls for messages from this
 *         particular peer
 *
 */
static void
plugin_env_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    unsigned int distance, const char *sender_address,
                    size_t sender_address_len)
{
  struct ReadyList *service_context;
  struct TransportPlugin *plugin = cls;
  struct TransportClient *cpos;
  struct InboundMessage *im;
  struct PeerAddressList *peer_address;
  uint16_t msize;
  struct NeighborList *n;

  n = find_neighbor (peer);
  if (n == NULL)
    {
      if (message == NULL)
        return;                 /* disconnect of peer already marked down */
      n = setup_new_neighbor (peer);

    }

  peer_address = find_peer_address(n, sender_address, sender_address_len);
  if (peer_address == NULL)
    peer_address = add_peer_address(n, sender_address, sender_address_len);

  service_context = n->plugins;
  while ((service_context != NULL) && (plugin != service_context->plugin))
    service_context = service_context->next;
  GNUNET_assert ((plugin->api->send == NULL) || (service_context != NULL));
  if (message == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Receive failed from `%4s', triggering disconnect\n",
                  GNUNET_i2s (&n->id));
#endif
      /* TODO: call stats */
      if (service_context != NULL)
        service_context->connected = GNUNET_NO;
      disconnect_neighbor (n, GNUNET_YES);
      return;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Processing message of type `%u' received by plugin...\n",
              ntohs (message->type));
#endif
  if (service_context != NULL)
    {
      if (service_context->connected == GNUNET_NO)
        {
          /*service_context->connected = GNUNET_YES;*/
          /* FIXME: What to do here?  Should we use these as well, to specify some Address
           * in the AddressList should be available?
           */
          peer_address->transmit_ready = GNUNET_YES;
          peer_address->connect_attempts++;
        }
      peer_address->timeout
        =
        GNUNET_TIME_relative_to_absolute
        (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    }
  /* update traffic received amount ... */
  msize = ntohs (message->size);
  n->last_received += msize;
  GNUNET_SCHEDULER_cancel (sched, n->timeout_task);
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  n->timeout_task =
    GNUNET_SCHEDULER_add_delayed (sched,
                                  GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                  &neighbor_timeout_task, n);
  update_quota (n);
  if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
    {
      /* dropping message due to frequent inbound volume violations! */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING |
                  GNUNET_ERROR_TYPE_BULK,
                  _
                  ("Dropping incoming message due to repeated bandwidth quota violations.\n"));
      /* TODO: call stats */
      GNUNET_assert ((service_context == NULL) ||
                     (NULL != service_context->neighbor));
      return;
    }
  switch (ntohs (message->type))
    {
    case GNUNET_MESSAGE_TYPE_HELLO:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message from `%4s'.\n", "HELLO",
                  GNUNET_i2s (peer));
#endif
      process_hello (plugin, message);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
      handle_ping(plugin, message, peer, sender_address, sender_address_len);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
      handle_pong(plugin, message, peer, sender_address, sender_address_len);
      break;
    default:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received REAL MESSAGE type %u from `%4s', sending to all clients.\n",
                  ntohs (message->type), GNUNET_i2s (peer));
#endif
      /* transmit message to all clients */
      im = GNUNET_malloc (sizeof (struct InboundMessage) + msize);
      im->header.size = htons (sizeof (struct InboundMessage) + msize);
      im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
      im->latency = n->latency;
      im->peer = *peer;
      memcpy (&im[1], message, msize);

      cpos = clients;
      while (cpos != NULL)
        {
          transmit_to_client (cpos, &im->header, GNUNET_YES);
          cpos = cpos->next;
        }
      GNUNET_free (im);
    }
  GNUNET_assert ((service_context == NULL) ||
                 (NULL != service_context->neighbor));
}


/**
 * Handle START-message.  This is the first message sent to us
 * by any client which causes us to add it to our list.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start (void *cls,
              struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  struct TransportClient *c;
  struct ConnectInfoMessage cim;
  struct NeighborList *n;
  struct InboundMessage *im;
  struct GNUNET_MessageHeader *ack;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client\n", "START");
#endif
  c = clients;
  while (c != NULL)
    {
      if (c->client == client)
        {
          /* client already on our list! */
          GNUNET_break (0);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
      c = c->next;
    }
  c = GNUNET_malloc (sizeof (struct TransportClient));
  c->next = clients;
  clients = c;
  c->client = client;
  if (our_hello != NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending our own `%s' to new client\n", "HELLO");
#endif
      transmit_to_client (c,
                          (const struct GNUNET_MessageHeader *) our_hello,
                          GNUNET_NO);
      /* tell new client about all existing connections */
      cim.header.size = htons (sizeof (struct ConnectInfoMessage));
      cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
      cim.quota_out =
        htonl (GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT / (60 * 1000));
      cim.latency = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_ZERO);  /* FIXME? */
      im = GNUNET_malloc (sizeof (struct InboundMessage) +
                          sizeof (struct GNUNET_MessageHeader));
      im->header.size = htons (sizeof (struct InboundMessage) +
                               sizeof (struct GNUNET_MessageHeader));
      im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
      im->latency = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_ZERO);  /* FIXME? */
      ack = (struct GNUNET_MessageHeader *) &im[1];
      ack->size = htons (sizeof (struct GNUNET_MessageHeader));
      ack->type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ACK);
      for (n = neighbors; n != NULL; n = n->next)
        {
          cim.id = n->id;
          transmit_to_client (c, &cim.header, GNUNET_NO);
          if (n->received_pong)
            {
              im->peer = n->id;
              transmit_to_client (c, &im->header, GNUNET_NO);
            }
        }
      GNUNET_free (im);
    }
  else
    {
      fprintf(stderr, "Our hello is NULL!\n");
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle HELLO-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_hello (void *cls,
              struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  int ret;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client\n", "HELLO");
#endif
  ret = process_hello (NULL, message);
  GNUNET_SERVER_receive_done (client, ret);
}


/**
 * Handle SEND-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_send (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct TransportClient *tc;
  struct NeighborList *n;
  const struct OutboundMessage *obm;
  const struct GNUNET_MessageHeader *obmm;
  uint16_t size;
  uint16_t msize;

  size = ntohs (message->size);
  if (size <
      sizeof (struct OutboundMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  obm = (const struct OutboundMessage *) message;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client with target `%4s'\n",
              "SEND", GNUNET_i2s (&obm->peer));
#endif
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  msize = ntohs (obmm->size);
  if (size != msize + sizeof (struct OutboundMessage))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  n = find_neighbor (&obm->peer);
  if (n == NULL)
    n = setup_new_neighbor (&obm->peer); /* But won't ever add address, we have none! */
  tc = clients;
  while ((tc != NULL) && (tc->client != client))
    tc = tc->next;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client asked to transmit %u-byte message of type %u to `%4s'\n",
              ntohs (obmm->size),
              ntohs (obmm->type), GNUNET_i2s (&obm->peer));
#endif
  transmit_to_peer (tc, NULL, ntohl (obm->priority), (char *)obmm, ntohs (obmm->size), GNUNET_NO, n);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle SET_QUOTA-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_set_quota (void *cls,
                  struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  const struct QuotaSetMessage *qsm =
    (const struct QuotaSetMessage *) message;
  struct NeighborList *n;
  struct TransportPlugin *p;
  struct ReadyList *rl;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client for peer `%4s'\n",
              "SET_QUOTA", GNUNET_i2s (&qsm->peer));
#endif
  n = find_neighbor (&qsm->peer);
  if (n == NULL)
    {
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  update_quota (n);
  if (n->quota_in < ntohl (qsm->quota_in))
    n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->quota_in = ntohl (qsm->quota_in);
  rl = n->plugins;
  while (rl != NULL)
    {
      p = rl->plugin;
      p->api->set_receive_quota (p->api->cls,
                                 &qsm->peer, ntohl (qsm->quota_in));
      rl = rl->next;
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle TRY_CONNECT-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_try_connect (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct TryConnectMessage *tcm;
  struct NeighborList *neighbor;
  tcm = (const struct TryConnectMessage *) message;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client %p asking to connect to `%4s'\n",
              "TRY_CONNECT", client, GNUNET_i2s (&tcm->peer));
#endif
  neighbor = find_neighbor(&tcm->peer);

  if (neighbor == NULL)
    setup_new_neighbor (&tcm->peer);
  else
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Client asked to connect to `%4s', but connection already exists\n",
                  "TRY_CONNECT", GNUNET_i2s (&tcm->peer));
#endif
      transmit_to_peer (NULL, NULL, 0,
                        (const char *) our_hello, GNUNET_HELLO_size(our_hello),
                        GNUNET_YES, neighbor);
      notify_clients_connect (&tcm->peer, GNUNET_TIME_UNIT_FOREVER_REL);
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void
transmit_address_to_client (void *cls, const char *address)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  size_t slen;

  if (NULL == address)
    slen = 0;
  else
    slen = strlen (address) + 1;
  GNUNET_SERVER_transmit_context_append_data (tc, address, slen,
					      GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_REPLY);
  if (NULL == address)
    GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Handle AddressLookup-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_address_lookup (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  const struct AddressLookupMessage *alum;
  struct TransportPlugin *lsPlugin;
  const char *nameTransport;
  const char *address;
  uint16_t size;
  struct GNUNET_SERVER_TransmitContext *tc;

  size = ntohs (message->size);
  if (size < sizeof (struct AddressLookupMessage))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  alum = (const struct AddressLookupMessage *) message;
  uint32_t addressLen = ntohl (alum->addrlen);
  if (size <= sizeof (struct AddressLookupMessage) + addressLen)
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  address = (const char *) &alum[1];
  nameTransport = (const char *) &address[addressLen];
  if (nameTransport
      [size - sizeof (struct AddressLookupMessage) - addressLen - 1] != '\0')
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  struct GNUNET_TIME_Absolute timeout =
    GNUNET_TIME_absolute_ntoh (alum->timeout);
  struct GNUNET_TIME_Relative rtimeout =
    GNUNET_TIME_absolute_get_remaining (timeout);
  lsPlugin = find_transport (nameTransport);
  if (NULL == lsPlugin)
    {
      tc = GNUNET_SERVER_transmit_context_create (client);
      GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
						  GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_REPLY);
      GNUNET_SERVER_transmit_context_run (tc, rtimeout);
      return;
    }
  tc = GNUNET_SERVER_transmit_context_create (client);
  lsPlugin->api->address_pretty_printer (cls, nameTransport,
                                         address, addressLen, GNUNET_YES,
                                         rtimeout,
                                         &transmit_address_to_client, tc);
}

/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_start, NULL,
   GNUNET_MESSAGE_TYPE_TRANSPORT_START, 0},
  {&handle_hello, NULL,
   GNUNET_MESSAGE_TYPE_HELLO, 0},
  {&handle_send, NULL,
   GNUNET_MESSAGE_TYPE_TRANSPORT_SEND, 0},
  {&handle_set_quota, NULL,
   GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA, sizeof (struct QuotaSetMessage)},
  {&handle_try_connect, NULL,
   GNUNET_MESSAGE_TYPE_TRANSPORT_TRY_CONNECT,
   sizeof (struct TryConnectMessage)},
  {&handle_address_lookup, NULL,
   GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP,
   0},
  {NULL, NULL, 0, 0}
};


/**
 * Setup the environment for this plugin.
 */
static void
create_environment (struct TransportPlugin *plug)
{
  plug->env.cfg = cfg;
  plug->env.sched = sched;
  plug->env.my_identity = &my_identity;
  plug->env.cls = plug;
  plug->env.receive = &plugin_env_receive;
  plug->env.notify_address = &plugin_env_notify_address;
  plug->env.default_quota_in =
    (GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT + 59999) / (60 * 1000);
  plug->env.max_connections = max_connect_per_transport;
}


/**
 * Start the specified transport (load the plugin).
 */
static void
start_transport (struct GNUNET_SERVER_Handle *server, const char *name)
{
  struct TransportPlugin *plug;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' transport plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", name);
  plug = GNUNET_malloc (sizeof (struct TransportPlugin));
  create_environment (plug);
  plug->short_name = GNUNET_strdup (name);
  plug->lib_name = libname;
  plug->next = plugins;
  plugins = plug;
  plug->api = GNUNET_PLUGIN_load (libname, &plug->env);
  if (plug->api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load transport plugin for `%s'\n"), name);
      GNUNET_free (plug->short_name);
      plugins = plug->next;
      GNUNET_free (libname);
      GNUNET_free (plug);
    }
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
  struct TransportClient *pos;
  struct TransportClient *prev;
  struct ClientMessageQueueEntry *mqe;

  if (client == NULL)
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Client disconnected, cleaning up.\n");
#endif
  prev = NULL;
  pos = clients;
  while ((pos != NULL) && (pos->client != client))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    return;
  while (NULL != (mqe = pos->message_queue_head))
    {
      pos->message_queue_head = mqe->next;
      GNUNET_free (mqe);
    }
  pos->message_queue_head = NULL;
  if (prev == NULL)
    clients = pos->next;
  else
    prev->next = pos->next;
  if (GNUNET_YES == pos->tcs_pending)
    {
      pos->client = NULL;
      return;
    }
  GNUNET_free (pos);
}


/**
 * Function called when the service shuts down.  Unloads our plugins.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
unload_plugins (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TransportPlugin *plug;
  struct AddressList *al;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transport service is unloading plugins...\n");
#endif
  while (NULL != (plug = plugins))
    {
      plugins = plug->next;
      GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug->short_name);
      while (NULL != (al = plug->addresses))
        {
          plug->addresses = al->next;
          GNUNET_free (al);
        }
      GNUNET_free (plug);
    }
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  GNUNET_free_non_null (our_hello);
}


/**
 * Initiate transport service.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param serv the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     struct GNUNET_SERVER_Handle *serv,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *plugs;
  char *pos;
  int no_transports;
  unsigned long long tneigh;
  char *keyfile;

  sched = s;
  cfg = c;
  /* parse configuration */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c,
                                              "TRANSPORT",
                                              "NEIGHBOUR_LIMIT",
                                              &tneigh)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (c,
                                                "GNUNETD",
                                                "HOSTKEY", &keyfile)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);
  /* setup notification */
  server = serv;
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification, NULL);
  /* load plugins... */
  no_transports = 1;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (c,
                                             "TRANSPORT", "PLUGINS", &plugs))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Starting transport plugins `%s'\n"), plugs);
      pos = strtok (plugs, " ");
      while (pos != NULL)
        {
          start_transport (server, pos);
          no_transports = 0;
          pos = strtok (NULL, " ");
        }
      GNUNET_free (plugs);
    }
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &unload_plugins, NULL);
  if (no_transports)
    refresh_hello ();

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transport service ready.\n"));
#endif
  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "transport",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-transport.c */
