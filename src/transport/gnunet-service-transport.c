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
 * - if we do not receive an ACK in response to our
 *   HELLO, retransmit HELLO!
 */
#include "platform.h"
#include "gnunet_client_lib.h"
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
 */
#define HELLO_VERIFICATION_TIMEOUT GNUNET_TIME_UNIT_MINUTES

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
 * After how long do we consider a connection to a peer dead
 * if we don't receive messages from the peer?
 */
#define IDLE_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


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

struct NeighbourList;

/**
 * For each neighbour we keep a list of messages
 * that we still want to transmit to the neighbour.
 */
struct MessageQueue
{

  /**
   * This is a linked list.
   */
  struct MessageQueue *next;

  /**
   * The message we want to transmit.
   */
  struct GNUNET_MessageHeader *message;

  /**
   * Client responsible for queueing the message;
   * used to check that a client has not two messages
   * pending for the same target.  Can be NULL.
   */
  struct TransportClient *client;

  /**
   * Neighbour this entry belongs to.
   */
  struct NeighbourList *neighbour;

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

};


/**
 * For a given Neighbour, which plugins are available
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
   * Neighbour this entry belongs to.
   */
  struct NeighbourList *neighbour;

  /**
   * Opaque handle (specific to the plugin) for the
   * connection to our target; can be NULL.
   */
  void *plugin_handle;

  /**
   * What was the last latency observed for this plugin
   * and peer?  Invalid if connected is GNUNET_NO.
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * If we did not successfully transmit a message to the
   * given peer via this connection during the specified
   * time, we should consider the connection to be dead.
   * This is used in the case that a TCP transport simply
   * stalls writing to the stream but does not formerly
   * get a signal that the other peer died.
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

  /**
   * Is this plugin ready to transmit to the specific
   * target?  GNUNET_NO if not.  Initially, all plugins
   * are marked ready.  If a transmission is in progress,
   * "transmit_ready" is set to GNUNET_NO.
   */
  int transmit_ready;

};


/**
 * Entry in linked list of all of our current neighbours.
 */
struct NeighbourList
{

  /**
   * This is a linked list.
   */
  struct NeighbourList *next;

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
   * Identity of this neighbour.
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
   * Global quota for outbound traffic for the neighbour in bytes/ms.
   */
  uint32_t quota_in;

  /**
   * What is the latest version of our HELLO that we have
   * sent to this neighbour?
   */
  unsigned int hello_version_sent;

  /**
   * How often has the other peer (recently) violated the
   * inbound traffic limit?  Incremented by 10 per violation,
   * decremented by 1 per non-violation (for each
   * time interval).
   */
  unsigned int quota_violation_count;

  /**
   * Have we seen an ACK from this neighbour in the past?
   * (used to make up a fake ACK for clients connecting after
   * the neighbour connected to us).
   */
  int saw_ack;

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
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address used.  Note that the
 * recipients response does not affirm that he has this address,
 * only that he got the challenge message.
 */
struct ValidationChallengeMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * What are we signing and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

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
 * Message used to validate a HELLO.  If this was
 * the right recipient, the response is a signature
 * of the original validation request.  The
 * challenge is included in the confirmation to make
 * matching of replies to requests possible.
 */
struct ValidationChallengeResponse
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random challenge number (in network byte order).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who signed this message?
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

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

  /**
   * Our challenge message.  Points to after this
   * struct, so this field should not be freed.
   */
  struct ValidationChallengeMessage *msg;

  /**
   * Name of the transport.
   */
  char *transport_name;

  /**
   * When should this validated address expire?
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Length of the address we are validating.
   */
  size_t addr_len;

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
 * neighbour has already been sent the latest version
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
struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * All known neighbours and their HELLOs.
 */
static struct NeighbourList *neighbours;

/**
 * Default bandwidth quota for receiving for new peers in bytes/ms.
 */
static uint32_t default_quota_in;

/**
 * Default bandwidth quota for sending for new peers in bytes/ms.
 */
static uint32_t default_quota_out;

/**
 * Number of neighbours we'd like to have.
 */
static uint32_t max_connect_per_transport;


/**
 * Find an entry in the neighbour list for a particular peer.
 *
 * @return NULL if not found.
 */
static struct NeighbourList *
find_neighbour (const struct GNUNET_PeerIdentity *key)
{
  struct NeighbourList *head = neighbours;
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
 * Update the quota values for the given neighbour now.
 */
static void
update_quota (struct NeighbourList *n)
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
  struct GNUNET_NETWORK_TransmitHandle *th;
  char *cbuf;

  if (buf == NULL)
    {
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
      client->message_queue_head = q->next;
      if (q->next == NULL)
        client->message_queue_tail = NULL;
      memcpy (&cbuf[tsize], msg, msize);
      tsize += msize;
      GNUNET_free (q);
      client->message_count--;
    }
  GNUNET_assert (tsize > 0);
  if (NULL != q)
    {
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
  struct GNUNET_NETWORK_TransmitHandle *th;

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
 * @param neighbour for which neighbour should we try to find
 *        more plugins?
 */
static void
try_alternative_plugins (struct NeighbourList *neighbour)
{
  struct ReadyList *rl;

  if ((neighbour->plugins != NULL) &&
      (neighbour->retry_plugins_time.value >
       GNUNET_TIME_absolute_get ().value))
    return;                     /* don't try right now */
  neighbour->retry_plugins_time
    = GNUNET_TIME_relative_to_absolute (PLUGIN_RETRY_FREQUENCY);

  rl = neighbour->plugins;
  while (rl != NULL)
    {
      if (rl->connect_attempts > 0)
        rl->connect_attempts--; /* amnesty */
      rl = rl->next;
    }

}


/**
 * Check the ready list for the given neighbour and
 * if a plugin is ready for transmission (and if we
 * have a message), do so!
 *
 * @param neighbour target peer for which to check the plugins
 */
static void try_transmission_to_peer (struct NeighbourList *neighbour);


/**
 * Function called by the GNUNET_TRANSPORT_TransmitFunction
 * upon "completion" of a send request.  This tells the API
 * that it is now legal to send another message to the given
 * peer.
 *
 * @param cls closure, identifies the entry on the
 *            message queue that was transmitted and the
 *            client responsible for queueing the message
 * @param rl identifies plugin used for the transmission for
 *           this neighbour; needs to be re-enabled for
 *           future transmissions
 * @param target the peer receiving the message
 * @param result GNUNET_OK on success, if the transmission
 *           failed, we should not tell the client to transmit
 *           more messages
 */
static void
transmit_send_continuation (void *cls,
                            struct ReadyList *rl,
                            const struct GNUNET_PeerIdentity *target,
                            int result)
{
  struct MessageQueue *mq = cls;
  struct SendOkMessage send_ok_msg;
  struct NeighbourList *n;

  GNUNET_assert (mq != NULL);
  n = mq->neighbour;
  GNUNET_assert (0 ==
                 memcmp (&n->id, target,
                         sizeof (struct GNUNET_PeerIdentity)));
  if (rl == NULL)
    {
      rl = n->plugins;
      while ((rl != NULL) && (rl->plugin != mq->plugin))
        rl = rl->next;
      GNUNET_assert (rl != NULL);
    }
  if (result == GNUNET_OK)
    rl->timeout = GNUNET_TIME_relative_to_absolute (IDLE_CONNECTION_TIMEOUT);
  else
    rl->connected = GNUNET_NO;
  if (!mq->internal_msg)
    rl->transmit_ready = GNUNET_YES;
  if (mq->client != NULL)
    {
      send_ok_msg.header.size = htons (sizeof (send_ok_msg));
      send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
      send_ok_msg.success = htonl (result);
      send_ok_msg.peer = n->id;
      transmit_to_client (mq->client, &send_ok_msg.header, GNUNET_NO);
    }
  GNUNET_free (mq->message);
  GNUNET_free (mq);
  /* one plugin just became ready again, try transmitting
     another message (if available) */
  try_transmission_to_peer (n);
}




/**
 * We could not use an existing (or validated) connection to
 * talk to a peer.  Try addresses that have not yet been
 * validated.
 *
 * @param n neighbour we want to communicate with
 * @return plugin ready to talk, or NULL if none is available
 */
static struct ReadyList *
try_unvalidated_addresses (struct NeighbourList *n)
{
  struct ValidationList *vl;
  struct ValidationAddress *va;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TIME_Absolute now;
  unsigned int total;
  unsigned int cnt;
  struct ReadyList *rl;
  struct TransportPlugin *plugin;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to connect to `%4s' using unvalidated addresses\n",
              GNUNET_i2s (&n->id));
#endif
  /* NOTE: this function needs to not only identify the
     plugin but also setup "plugin_handle", binding it to the
     right address using the plugin's "send_to" API */
  now = GNUNET_TIME_absolute_get ();
  vl = pending_validations;
  while (vl != NULL)
    {
      GNUNET_CRYPTO_hash (&vl->publicKey,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &id.hashPubKey);
      if (0 == memcmp (&id, &n->id, sizeof (struct GNUNET_PeerIdentity)))
        break;
      vl = vl->next;
    }
  if (vl == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No unvalidated address found for peer `%4s'\n",
                  GNUNET_i2s (&n->id));
#endif
      return NULL;
    }
  total = 0;
  cnt = 0;
  va = vl->addresses;
  while (va != NULL)
    {
      cnt++;
      if (va->expiration.value > now.value)
        total++;
      va = va->next;
    }
  if (total == 0)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All %u unvalidated addresses for peer have expired\n",
                  cnt);
#endif
      return NULL;
    }
  total = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  for (va = vl->addresses; va != NULL; va = va->next)
    {
      if (va->expiration.value <= now.value)
        continue;
      if (total > 0)
        {
          total--;
          continue;
        }
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Trying unvalidated address of `%s' transport\n",
                  va->transport_name);
#endif
      plugin = find_transport (va->transport_name);
      if (plugin == NULL)
        {
          GNUNET_break (0);
          break;
        }
      rl = GNUNET_malloc (sizeof (struct ReadyList));
      rl->next = n->plugins;
      n->plugins = rl;
      rl->plugin = plugin;
      rl->plugin_handle = plugin->api->send_to (plugin->api->cls,
                                                &n->id,
                                                NULL,
                                                NULL,
                                                GNUNET_TIME_UNIT_ZERO,
                                                &va->msg[1], va->addr_len);
      rl->transmit_ready = GNUNET_YES;
      return rl;
    }
  return NULL;
}


/**
 * Check the ready list for the given neighbour and
 * if a plugin is ready for transmission (and if we
 * have a message), do so!
 */
static void
try_transmission_to_peer (struct NeighbourList *neighbour)
{
  struct ReadyList *pos;
  struct GNUNET_TIME_Relative min_latency;
  struct ReadyList *rl;
  struct MessageQueue *mq;
  struct GNUNET_TIME_Absolute now;

  if (neighbour->messages == NULL)
    return;                     /* nothing to do */
  try_alternative_plugins (neighbour);
  min_latency = GNUNET_TIME_UNIT_FOREVER_REL;
  rl = NULL;
  mq = neighbour->messages;
  now = GNUNET_TIME_absolute_get ();
  pos = neighbour->plugins;
  while (pos != NULL)
    {
      /* set plugins that are inactive for a long time back to disconnected */
      if ((pos->timeout.value < now.value) && (pos->connected == GNUNET_YES))
        {
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Marking long-time inactive connection to `%4s' as down.\n",
                      GNUNET_i2s (&neighbour->id));
#endif
          pos->connected = GNUNET_NO;
        }
      if (((GNUNET_YES == pos->transmit_ready) ||
           (mq->internal_msg)) &&
          (pos->connect_attempts < MAX_CONNECT_RETRY) &&
          ((rl == NULL) || (min_latency.value > pos->latency.value)))
        {
          rl = pos;
          min_latency = pos->latency;
        }
      pos = pos->next;
    }
  if (rl == NULL)
    rl = try_unvalidated_addresses (neighbour);
  if (rl == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No plugin ready to transmit message\n");
#endif
      return;                   /* nobody ready */
    }
  if (GNUNET_NO == rl->connected)
    {
      rl->connect_attempts++;
      rl->connected = GNUNET_YES;
    }
  neighbour->messages = mq->next;
  mq->plugin = rl->plugin;
  if (!mq->internal_msg)
    rl->transmit_ready = GNUNET_NO;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Giving message of type `%u' for `%4s' to plugin `%s'\n",
              ntohs (mq->message->type),
              GNUNET_i2s (&neighbour->id), rl->plugin->short_name);
#endif
  rl->plugin_handle
    = rl->plugin->api->send (rl->plugin->api->cls,
                             rl->plugin_handle,
                             rl,
                             &neighbour->id,
                             mq->message,
                             IDLE_CONNECTION_TIMEOUT,
                             &transmit_send_continuation, mq);
}


/**
 * Send the specified message to the specified peer.
 *
 * @param client source of the transmission request (can be NULL)
 * @param msg message to send
 * @param is_internal is this an internal message
 * @param neighbour handle to the neighbour for transmission
 */
static void
transmit_to_peer (struct TransportClient *client,
                  const struct GNUNET_MessageHeader *msg,
                  int is_internal, struct NeighbourList *neighbour)
{
  struct MessageQueue *mq;
  struct MessageQueue *mqe;
  struct GNUNET_MessageHeader *m;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Sending message of type %u to peer `%4s'\n"),
              ntohs (msg->type), GNUNET_i2s (&neighbour->id));
#endif
  if (client != NULL)
    {
      /* check for duplicate submission */
      mq = neighbour->messages;
      while (NULL != mq)
        {
          if (mq->client == client)
            {
              /* client transmitted to same peer twice
                 before getting SendOk! */
              GNUNET_break (0);
              return;
            }
          mq = mq->next;
        }
    }
  mq = GNUNET_malloc (sizeof (struct MessageQueue));
  mq->client = client;
  m = GNUNET_malloc (ntohs (msg->size));
  memcpy (m, msg, ntohs (msg->size));
  mq->message = m;
  mq->neighbour = neighbour;
  mq->internal_msg = is_internal;

  /* find tail */
  mqe = neighbour->messages;
  if (mqe != NULL)
    while (mqe->next != NULL)
      mqe = mqe->next;
  if (mqe == NULL)
    {
      /* new head */
      neighbour->messages = mq;
      try_transmission_to_peer (neighbour);
    }
  else
    {
      /* append */
      mqe->next = mq;
    }
}


struct GeneratorContext
{
  struct TransportPlugin *plug_pos;
  struct AddressList *addr_pos;
  struct GNUNET_TIME_Absolute expiration;
};


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
    return 0;
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
  struct NeighbourList *npos;
  struct GeneratorContext gc;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Refreshing my HELLO\n");
#endif
  gc.plug_pos = plugins;
  gc.addr_pos = plugins != NULL ? plugins->addresses : NULL;
  gc.expiration = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
  hello = GNUNET_HELLO_create (&my_public_key, &address_generator, &gc);
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
  npos = neighbours;
  while (npos != NULL)
    {
      transmit_to_peer (NULL,
                        (const struct GNUNET_MessageHeader *) our_hello,
                        GNUNET_YES, npos);
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

  if (plugin->address_update_task != GNUNET_SCHEDULER_NO_PREREQUISITE_TASK)
    GNUNET_SCHEDULER_cancel (plugin->env.sched, plugin->address_update_task);
  plugin->address_update_task = GNUNET_SCHEDULER_NO_PREREQUISITE_TASK;
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
                                      GNUNET_NO,
                                      GNUNET_SCHEDULER_PRIORITY_IDLE,
                                      GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
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
  plugin->address_update_task = GNUNET_SCHEDULER_NO_PREREQUISITE_TASK;
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

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Plugin `%s' informs us about a new address\n", name);
#endif
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


struct LookupHelloContext
{
  GNUNET_TRANSPORT_AddressCallback iterator;

  void *iterator_cls;
};


static int
lookup_address_callback (void *cls,
                         const char *tname,
                         struct GNUNET_TIME_Absolute expiration,
                         const void *addr, size_t addrlen)
{
  struct LookupHelloContext *lhc = cls;
  lhc->iterator (lhc->iterator_cls, tname, addr, addrlen);
  return GNUNET_OK;
}


static void
lookup_hello_callback (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_HELLO_Message *h, uint32_t trust)
{
  struct LookupHelloContext *lhc = cls;

  if (peer == NULL)
    {
      lhc->iterator (lhc->iterator_cls, NULL, NULL, 0);
      GNUNET_free (lhc);
      return;
    }
  if (h == NULL)
    return;
  GNUNET_HELLO_iterate_addresses (h,
                                  GNUNET_NO, &lookup_address_callback, lhc);
}


/**
 * Function that allows a transport to query the known
 * network addresses for a given peer.
 *
 * @param cls closure
 * @param timeout after how long should we time out?
 * @param target which peer are we looking for?
 * @param iter function to call for each known address
 * @param iter_cls closure for iter
 */
static void
plugin_env_lookup_address (void *cls,
                           struct GNUNET_TIME_Relative timeout,
                           const struct GNUNET_PeerIdentity *target,
                           GNUNET_TRANSPORT_AddressCallback iter,
                           void *iter_cls)
{
  struct LookupHelloContext *lhc;

  lhc = GNUNET_malloc (sizeof (struct LookupHelloContext));
  lhc->iterator = iter;
  lhc->iterator_cls = iter_cls;
  GNUNET_PEERINFO_for_all (cfg,
                           sched,
                           target, 0, timeout, &lookup_hello_callback, &lhc);
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

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Informing clients about peer `%4s' connecting to us\n",
              GNUNET_i2s (peer));
#endif
  cim.header.size = htons (sizeof (struct ConnectInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim.quota_out = htonl (default_quota_out);
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

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Informing clients about peer `%4s' disconnecting\n",
              GNUNET_i2s (peer));
#endif
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
                                  &(*va)->msg[1], (*va)->addr_len, buf, max);
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
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity pid;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "HELLO validation cleanup background task running...\n");
#endif
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
  pos = pending_validations;
  while ((pos != NULL) && (pos->next != NULL))
    pos = pos->next;
  if (NULL != pos)
    GNUNET_SCHEDULER_add_delayed (sched,
                                  GNUNET_NO,
                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                  GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                  GNUNET_TIME_absolute_get_remaining
                                  (pos->timeout), &cleanup_validation, NULL);
}


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
   * Validation list being build.
   */
  struct ValidationList *e;
};


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
  struct ValidationChallengeMessage *vcm;

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
  va = GNUNET_malloc (sizeof (struct ValidationAddress) +
                      sizeof (struct ValidationChallengeMessage) + addrlen);
  va->next = e->addresses;
  e->addresses = va;
  vcm = (struct ValidationChallengeMessage *) &va[1];
  va->msg = vcm;
  va->transport_name = GNUNET_strdup (tname);
  va->addr_len = addrlen;
  vcm->header.size =
    htons (sizeof (struct ValidationChallengeMessage) + addrlen);
  vcm->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  vcm->purpose.size =
    htonl (sizeof (struct ValidationChallengeMessage) + addrlen -
           sizeof (struct GNUNET_MessageHeader));
  vcm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_HELLO);
  vcm->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                             (unsigned int) -1);
  /* Note: vcm->target is set in check_hello_validated */
  memcpy (&vcm[1], addr, addrlen);
  return GNUNET_OK;
}


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

  first_call = GNUNET_NO;
  if (chvc->e == NULL)
    {
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
  va = chvc->e->addresses;
  while (va != NULL)
    {
      GNUNET_CRYPTO_hash (&chvc->e->publicKey,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &va->msg->target.hashPubKey);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Establishing `%s' connection to validate `%s' of `%4s' (sending our `%s')\n",
                  va->transport_name,
                  "HELLO", GNUNET_i2s (&va->msg->target), "HELLO");
#endif
      tp = find_transport (va->transport_name);
      GNUNET_assert (tp != NULL);
      if (NULL ==
          tp->api->send_to (tp->api->cls,
                            &va->msg->target,
                            (const struct GNUNET_MessageHeader *) our_hello,
                            &va->msg->header,
                            HELLO_VERIFICATION_TIMEOUT,
                            &va->msg[1], va->addr_len))
        va->ok = GNUNET_SYSERR;
      va = va->next;
    }
  if (chvc->e->next == NULL)
    GNUNET_SCHEDULER_add_delayed (sched,
                                  GNUNET_NO,
                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                  GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                  GNUNET_TIME_absolute_get_remaining
                                  (chvc->e->timeout), &cleanup_validation,
                                  NULL);
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
              "Processing `%s' message for `%4s'\n",
              "HELLO", GNUNET_i2s (&target));
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
          return GNUNET_OK;
        }
      e = e->next;
    }
  chvc = GNUNET_malloc (sizeof (struct CheckHelloValidatedContext) + hsize);
  chvc->plugin = plugin;
  chvc->hello = (struct GNUNET_HELLO_Message *) &chvc[1];
  memcpy (chvc->hello, hello, hsize);
  /* finally, check if HELLO was previously validated
     (continuation will then schedule actual validation) */
  GNUNET_PEERINFO_for_all (cfg,
                           sched,
                           &target,
                           0,
                           HELLO_VERIFICATION_TIMEOUT,
                           &check_hello_validated, chvc);
  return GNUNET_OK;
}


/**
 * Handle PING-message.  If the plugin that gave us the message is
 * able to queue the PONG immediately, we only queue one PONG.
 * Otherwise we send at most TWO PONG messages, one via an unconfirmed
 * transport and one via a confirmed transport.  Both addresses are
 * selected randomly among those available.
 *
 * @param plugin plugin that gave us the message
 * @param sender claimed sender of the PING
 * @param plugin_context context that might be used to send response
 * @param message the actual message
 */
static void
process_ping (struct TransportPlugin *plugin,
              const struct GNUNET_PeerIdentity *sender,
              void *plugin_context,
              const struct GNUNET_MessageHeader *message)
{
  const struct ValidationChallengeMessage *vcm;
  struct ValidationChallengeResponse vcr;
  uint16_t msize;
  struct NeighbourList *n;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Processing PING\n");
#endif
  msize = ntohs (message->size);
  if (msize < sizeof (struct ValidationChallengeMessage))
    {
      GNUNET_break_op (0);
      return;
    }
  vcm = (const struct ValidationChallengeMessage *) message;
  if (0 != memcmp (&vcm->target,
                   &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Received `%s' message not destined for me!\n"), "PING");
      /* TODO: call statistics */
      return;
    }
  if ((ntohl (vcm->purpose.size) !=
       msize - sizeof (struct GNUNET_MessageHeader))
      || (ntohl (vcm->purpose.purpose) !=
          GNUNET_SIGNATURE_PURPOSE_TRANSPORT_HELLO))
    {
      GNUNET_break_op (0);
      return;
    }
  msize -= sizeof (struct ValidationChallengeMessage);
  if (GNUNET_OK !=
      plugin->api->address_suggested (plugin->api->cls, &vcm[1], msize))
    {
      GNUNET_break_op (0);
      return;
    }
  vcr.header.size = htons (sizeof (struct ValidationChallengeResponse));
  vcr.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
  vcr.challenge = vcm->challenge;
  vcr.sender = my_identity;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key,
                                         &vcm->purpose, &vcr.signature));
#if EXTRA_CHECKS
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_verify
                 (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_HELLO, &vcm->purpose,
                  &vcr.signature, &my_public_key));
#endif
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Trying to transmit PONG using inbound connection\n");
#endif
  n = find_neighbour (sender);
  if (n == NULL)
    {
      GNUNET_break (0);
      return;
    }
  transmit_to_peer (NULL, &vcr.header, GNUNET_YES, n);
}


/**
 * Handle PONG-message.
 *
 * @param message the actual message
 */
static void
process_pong (struct TransportPlugin *plugin,
              const struct GNUNET_MessageHeader *message)
{
  const struct ValidationChallengeResponse *vcr;
  struct ValidationList *pos;
  struct GNUNET_PeerIdentity peer;
  struct ValidationAddress *va;
  int all_done;
  int matched;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Processing PONG\n");
#endif
  vcr = (const struct ValidationChallengeResponse *) message;
  pos = pending_validations;
  while (pos != NULL)
    {
      GNUNET_CRYPTO_hash (&pos->publicKey,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          &peer.hashPubKey);
      if (0 ==
          memcmp (&peer, &vcr->sender, sizeof (struct GNUNET_PeerIdentity)))
        break;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      /* TODO: call statistics (unmatched PONG) */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Received `%s' message but have no record of a matching `%s' message. Ignoring.\n"),
                  "PONG", "PING");
      return;
    }
  all_done = GNUNET_YES;
  matched = GNUNET_NO;
  va = pos->addresses;
  while (va != NULL)
    {
      if (va->msg->challenge == vcr->challenge)
        {
          if (GNUNET_OK !=
              GNUNET_CRYPTO_rsa_verify
              (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_HELLO, &va->msg->purpose,
               &vcr->signature, &pos->publicKey))
            {
              /* this could rarely happen if we used the same
                 challenge number for the peer for two different
                 transports / addresses, but the likelihood is
                 very small... */
              GNUNET_break_op (0);
            }
          else
            {
#if DEBUG_TRANSPORT
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Confirmed validity of peer address.\n");
#endif
              va->ok = GNUNET_YES;
              va->expiration =
                GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
              matched = GNUNET_YES;
            }
        }
      if (va->ok != GNUNET_YES)
        all_done = GNUNET_NO;
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
  if (GNUNET_YES == all_done)
    {
      pos->timeout.value = 0;
      GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_NO,
                                    GNUNET_SCHEDULER_PRIORITY_IDLE,
                                    GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                    GNUNET_TIME_UNIT_ZERO,
                                    &cleanup_validation, NULL);
    }
}


/**
 * The peer specified by the given neighbour has timed-out.  Update
 * our state and do the necessary notifications.  Also notifies
 * our clients that the neighbour is now officially gone.
 *
 * @param n the neighbour list entry for the peer
 */
static void
disconnect_neighbour (struct NeighbourList *n)
{
  struct ReadyList *rpos;
  struct NeighbourList *npos;
  struct NeighbourList *nprev;
  struct MessageQueue *mq;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Disconnecting from neighbour\n");
#endif
  /* remove n from neighbours list */
  nprev = NULL;
  npos = neighbours;
  while ((npos != NULL) && (npos != n))
    {
      nprev = npos;
      npos = npos->next;
    }
  GNUNET_assert (npos != NULL);
  if (nprev == NULL)
    neighbours = n->next;
  else
    nprev->next = n->next;

  /* notify all clients about disconnect */
  notify_clients_disconnect (&n->id);

  /* clean up all plugins, cancel connections & pending transmissions */
  while (NULL != (rpos = n->plugins))
    {
      n->plugins = rpos->next;
      GNUNET_assert (rpos->neighbour == n);
      rpos->plugin->api->cancel (rpos->plugin->api->cls,
                                 rpos->plugin_handle, rpos, &n->id);
      GNUNET_free (rpos);
    }

  /* free all messages on the queue */
  while (NULL != (mq = n->messages))
    {
      n->messages = mq->next;
      GNUNET_assert (mq->neighbour == n);
      GNUNET_free (mq);
    }

  /* finally, free n itself */
  GNUNET_free (n);
}


/**
 * Add an entry for each of our transport plugins
 * (that are able to send) to the list of plugins
 * for this neighbour.
 *
 * @param neighbour to initialize
 */
static void
add_plugins (struct NeighbourList *neighbour)
{
  struct TransportPlugin *tp;
  struct ReadyList *rl;

  neighbour->retry_plugins_time
    = GNUNET_TIME_relative_to_absolute (PLUGIN_RETRY_FREQUENCY);
  tp = plugins;
  while (tp != NULL)
    {
      if (tp->api->send != NULL)
        {
          rl = GNUNET_malloc (sizeof (struct ReadyList));
          rl->next = neighbour->plugins;
          neighbour->plugins = rl;
          rl->plugin = tp;
          rl->neighbour = neighbour;
          rl->transmit_ready = GNUNET_YES;
        }
      tp = tp->next;
    }
}


static void
neighbour_timeout_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourList *n = cls;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Neighbour has timed out!\n");
#endif
  n->timeout_task = GNUNET_SCHEDULER_NO_PREREQUISITE_TASK;
  disconnect_neighbour (n);
}



/**
 * Create a fresh entry in our neighbour list for the given peer.
 * Will try to transmit our current HELLO to the new neighbour.  Also
 * notifies our clients about the new "connection".
 *
 * @param peer the peer for which we create the entry
 * @return the new neighbour list entry
 */
static struct NeighbourList *
setup_new_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourList *n;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Setting up new neighbour `%4s', sending our HELLO to introduce ourselves\n",
              GNUNET_i2s (peer));
#endif
  GNUNET_assert (our_hello != NULL);
  n = GNUNET_malloc (sizeof (struct NeighbourList));
  n->next = neighbours;
  neighbours = n;
  n->id = *peer;
  n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute (IDLE_CONNECTION_TIMEOUT);
  n->quota_in = default_quota_in;
  add_plugins (n);
  n->hello_version_sent = our_hello_version;
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                  GNUNET_NO,
                                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                                  GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                                  IDLE_CONNECTION_TIMEOUT,
                                                  &neighbour_timeout_task, n);
  transmit_to_peer (NULL,
                    (const struct GNUNET_MessageHeader *) our_hello,
                    GNUNET_YES, n);
  notify_clients_connect (peer, GNUNET_TIME_UNIT_FOREVER_REL);
  return n;
}


/**
 * Function called by the plugin for each received message.
 * Update data volumes, possibly notify plugins about
 * reducing the rate at which they read from the socket
 * and generally forward to our receive callback.
 *
 * @param plugin_context value to pass to this plugin
 *        to respond to the given peer (use is optional,
 *        but may speed up processing)
 * @param service_context value passed to the transport-service
 *        to identify the neighbour; will be NULL on the first
 *        call for a given peer
 * @param latency estimated latency for communicating with the
 *             given peer
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if peer was disconnected
 * @return the new service_context that the plugin should use
 *         for future receive calls for messages from this
 *         particular peer
 */
static struct ReadyList *
plugin_env_receive (void *cls,
                    void *plugin_context,
                    struct ReadyList *service_context,
                    struct GNUNET_TIME_Relative latency,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MessageHeader ack = {
    htons (sizeof (struct GNUNET_MessageHeader)),
    htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ACK)
  };
  struct TransportPlugin *plugin = cls;
  struct TransportClient *cpos;
  struct InboundMessage *im;
  uint16_t msize;
  struct NeighbourList *n;

  if (service_context != NULL)
    {
      n = service_context->neighbour;
      GNUNET_assert (n != NULL);
    }
  else
    {
      n = find_neighbour (peer);
      if (n == NULL)
        {
          if (message == NULL)
            return NULL;        /* disconnect of peer already marked down */
          n = setup_new_neighbour (peer);
        }
      service_context = n->plugins;
      while ((service_context != NULL) && (plugin != service_context->plugin))
        service_context = service_context->next;
      GNUNET_assert ((plugin->api->send == NULL) ||
                     (service_context != NULL));
    }
  if (message == NULL)
    {
      if ((service_context != NULL) &&
          (service_context->plugin_handle == plugin_context))
        {
          service_context->connected = GNUNET_NO;
          service_context->plugin_handle = NULL;
        }
      /* TODO: call stats */
      return NULL;
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
          service_context->connected = GNUNET_YES;
          service_context->transmit_ready = GNUNET_YES;
          service_context->connect_attempts++;
        }
      service_context->timeout
        = GNUNET_TIME_relative_to_absolute (IDLE_CONNECTION_TIMEOUT);
      service_context->plugin_handle = plugin_context;
      service_context->latency = latency;
    }
  /* update traffic received amount ... */
  msize = ntohs (message->size);
  n->last_received += msize;
  GNUNET_SCHEDULER_cancel (sched, n->timeout_task);
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute (IDLE_CONNECTION_TIMEOUT);
  n->timeout_task =
    GNUNET_SCHEDULER_add_delayed (sched, GNUNET_NO,
                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                  GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                  IDLE_CONNECTION_TIMEOUT,
                                  &neighbour_timeout_task, n);
  update_quota (n);
  if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
    {
      /* dropping message due to frequent inbound volume violations! */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING |
                  GNUNET_ERROR_TYPE_BULK,
                  _
                  ("Dropping incoming message due to repeated bandwidth quota violations.\n"));
      /* TODO: call stats */
      return service_context;
    }
  switch (ntohs (message->type))
    {
    case GNUNET_MESSAGE_TYPE_HELLO:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message from other peer.\n", "HELLO");
#endif
      process_hello (plugin, message);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending `%s' message to connecting peer.\n", "ACK");
#endif
      transmit_to_peer (NULL, &ack, GNUNET_YES, n);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
      process_ping (plugin, peer, plugin_context, message);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
      process_pong (plugin, message);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_ACK:
      n->saw_ack = GNUNET_YES;
      /* intentional fall-through! */
    default:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received message of type %u from other peer, sending to all clients.\n",
                  ntohs (message->type));
#endif
      /* transmit message to all clients */
      im = GNUNET_malloc (sizeof (struct InboundMessage) + msize);
      im->header.size = htons (sizeof (struct InboundMessage) + msize);
      im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
      im->latency = GNUNET_TIME_relative_hton (latency);
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
  return service_context;
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
  struct NeighbourList *n;
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
                  "Sending our own HELLO to new client\n");
#endif
      transmit_to_client (c,
                          (const struct GNUNET_MessageHeader *) our_hello,
                          GNUNET_NO);
      /* tell new client about all existing connections */
      cim.header.size = htons (sizeof (struct ConnectInfoMessage));
      cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
      cim.quota_out = htonl (default_quota_out);
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
      for (n = neighbours; n != NULL; n = n->next)
        {
          cim.id = n->id;
          transmit_to_client (c, &cim.header, GNUNET_NO);
          if (n->saw_ack)
            {
              im->peer = n->id;
              transmit_to_client (c, &im->header, GNUNET_NO);
            }
        }
      GNUNET_free (im);
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
  struct NeighbourList *n;
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
  n = find_neighbour (&obm->peer);
  if (n == NULL)
    n = setup_new_neighbour (&obm->peer);
  tc = clients;
  while ((tc != NULL) && (tc->client != client))
    tc = tc->next;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client asked to transmit %u-byte message of type %u to `%4s'\n",
              ntohs (obmm->size),
              ntohs (obmm->type), GNUNET_i2s (&obm->peer));
#endif
  transmit_to_peer (tc, obmm, GNUNET_NO, n);
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
  struct NeighbourList *n;
  struct TransportPlugin *p;
  struct ReadyList *rl;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client for peer `%4s'\n",
              "SET_QUOTA", GNUNET_i2s (&qsm->peer));
#endif
  n = find_neighbour (&qsm->peer);
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

  tcm = (const struct TryConnectMessage *) message;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client asking to connect to `%4s'\n",
              "TRY_CONNECT", GNUNET_i2s (&tcm->peer));
#endif
  if (NULL == find_neighbour (&tcm->peer))
    setup_new_neighbour (&tcm->peer);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  plug->env.my_public_key = &my_public_key;
  plug->env.cls = plug;
  plug->env.receive = &plugin_env_receive;
  plug->env.lookup = &plugin_env_lookup_address;
  plug->env.notify_address = &plugin_env_notify_address;
  plug->env.default_quota_in = default_quota_in;
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
     struct GNUNET_SERVER_Handle *serv, struct GNUNET_CONFIGURATION_Handle *c)
{
  char *plugs;
  char *pos;
  int no_transports;
  unsigned long long qin;
  unsigned long long qout;
  unsigned long long tneigh;
  char *keyfile;

  sched = s;
  cfg = c;
  /* parse configuration */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c,
                                              "TRANSPORT",
                                              "DEFAULT_QUOTA_IN",
                                              &qin)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c,
                                              "TRANSPORT",
                                              "DEFAULT_QUOTA_OUT",
                                              &qout)) ||
      (GNUNET_OK !=
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
  default_quota_in = (uint32_t) qin;
  default_quota_out = (uint32_t) qout;
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
  if (no_transports)
    refresh_hello ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transport service ready.\n"));
  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * Function called when the service shuts
 * down.  Unloads our plugins.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
unload_plugins (void *cls, struct GNUNET_CONFIGURATION_Handle *cfg)
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
                              &run, NULL, &unload_plugins, NULL)) ? 0 : 1;
}

/* end of gnunet-service-transport.c */
