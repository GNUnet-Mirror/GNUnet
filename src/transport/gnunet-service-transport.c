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
 * NOTE:
 * - This code uses 'GNUNET_a2s' for debug printing in many places,
 *   which is technically wrong since it assumes we have IP+Port 
 *   (v4/v6) addresses.  Once we add transports like http or smtp
 *   this will have to be changed!
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
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
 * Should we do some additional checks (to validate behavior
 * of clients)?
 */
#define EXTRA_CHECKS GNUNET_YES

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
 * Limit on the number of ready-to-run tasks when validating 
 * HELLOs.  If more tasks are ready to run, we will drop 
 * HELLOs instead of validating them.
 */
#define MAX_HELLO_LOAD 4

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

/**
 * Priority to use for PONG messages.
 */
#define TRANSPORT_PONG_PRIORITY 4

/**
 * How often do we re-add (cheaper) plugins to our list of plugins
 * to try for a given connected peer?
 */
#define PLUGIN_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * After how long do we expire an address in a HELLO that we just
 * validated?  This value is also used for our own addresses when we
 * create a HELLO.
 */
#define HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)


/**
 * How long before an existing address expires should we again try to
 * validate it?  Must be (significantly) smaller than
 * HELLO_ADDRESS_EXPIRATION.
 */
#define HELLO_REVALIDATION_START_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)


/**
 * List of addresses of other peers
 */
struct ForeignAddressList
{
  /**
   * This is a linked list.
   */
  struct ForeignAddressList *next;

  /**
   * Which ready list does this entry belong to.
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
   * The address.
   */
  const void *addr;

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
   * Are we currently connected via this address?  The first time we
   * successfully transmit or receive data to a peer via a particular
   * address, we set this to GNUNET_YES.  If we later get an error
   * (disconnect notification, transmission failure, timeout), we set
   * it back to GNUNET_NO.  
   */
  int connected;

  /**
   * Is this plugin currently busy transmitting to the specific target?
   * GNUNET_NO if not (initial, default state is GNUNET_NO).   Internal
   * messages do not count as 'in transmit'.
   */
  int in_transmit;

  /**
   * Has this address been validated yet?
   */
  int validated;

  /**
   * How often have we tried to connect using this plugin?  Used to
   * discriminate against addresses that do not work well.
   * FIXME: not yet used, but should be!
   */
  unsigned int connect_attempts;

  /**
   * DV distance to this peer (1 if no DV is used). 
   * FIXME: need to set this from transport plugins!
   */
  uint32_t distance;

};


/**
 * Entry in linked list of network addresses for ourselves.
 */
struct OwnAddressList
{
  /**
   * This is a linked list.
   */
  struct OwnAddressList *next;

  /**
   * The address, actually a pointer to the end
   * of this struct.  Do not free!
   */
  const void *addr;
  
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
  struct OwnAddressList *addresses;

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
   * This is a doubly linked list.
   */
  struct MessageQueue *next;

  /**
   * This is a doubly linked list.
   */
  struct MessageQueue *prev;

  /**
   * The message(s) we want to transmit, GNUNET_MessageHeader(s)
   * stuck together in memory.  Allocated at the end of this struct.
   */
  const char *message_buf;

  /**
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
   * Using which specific address should we send this message?
   */
  struct ForeignAddressList *specific_address;

  /**
   * Peer ID of the Neighbour this entry belongs to.
   */
  struct GNUNET_PeerIdentity neighbour_id;

  /**
   * Plugin that we used for the transmission.
   * NULL until we scheduled a transmission.
   */
  struct TransportPlugin *plugin;

  /**
   * At what time should we fail?
   */
  struct GNUNET_TIME_Absolute timeout;

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
   * Transport addresses, latency, and readiness for
   * this particular plugin.
   */
  struct ForeignAddressList *addresses;

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
   * Head of list of messages we would like to send to this peer;
   * must contain at most one message per client.
   */
  struct MessageQueue *messages_head;

  /**
   * Tail of list of messages we would like to send to this peer; must
   * contain at most one message per client.
   */
  struct MessageQueue *messages_tail;

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
   * ID of task scheduled to run when we should retry transmitting
   * the head of the message queue.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

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
   * The latency we have seen for this particular address for
   * this particular peer.  This latency may have been calculated
   * over multiple transports.  This value reflects how long it took
   * us to receive a response when SENDING via this particular
   * transport/neighbour/address combination!
   *
   * FIXME: we need to periodically send PINGs to update this
   * latency (at least more often than the current "huge" (11h?)
   * update interval).
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * DV distance to this peer (1 if no DV is used). 
   */
  uint32_t distance;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Global quota for inbound traffic for the neighbour in bytes/ms.
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
   * Have we seen an PONG from this neighbour in the past (and
   * not had a disconnect since)?
   */
  int received_pong;

};

/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  
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

  /**
   * Size of address appended to this message
   */
  size_t addrlen;

};


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
   * Current transmit request handle.
   */ 
  struct GNUNET_CONNECTION_TransmitHandle *th;

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
 * Entry in map of all HELLOs awaiting validation.
 */
struct ValidationEntry
{

  /**
   * The address, actually a pointer to the end
   * of this struct.  Do not free!
   */
  const void *addr;

  /**
   * Name of the transport.
   */
  char *transport_name;

  /**
   * The public key of the peer.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

  /**
   * ID of task that will clean up this entry if we don't succeed
   * with the validation first.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * At what time did we send this validation?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * Length of addr.
   */
  size_t addrlen;

  /**
   * Challenge number we used.
   */
  uint32_t challenge;

};


/**
 * Context of currently active requests to peerinfo
 * for validation of HELLOs.
 */
struct CheckHelloValidatedContext
{

  /**
   * This is a doubly-linked list.
   */
  struct CheckHelloValidatedContext *next;

  /**
   * This is a doubly-linked list.
   */
  struct CheckHelloValidatedContext *prev;

  /**
   * Hello that we are validating.
   */
  const struct GNUNET_HELLO_Message *hello;

  /**
   * Context for peerinfo iteration.
   * NULL after we are done processing peerinfo's information.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;
  
  /**
   * Was a HELLO known for this peer to peerinfo?
   */
  int hello_known;

};


/**
 * Our HELLO message.
 */
static struct GNUNET_HELLO_Message *our_hello;

/**
 * "version" of "our_hello".  Used to see if a given neighbour has
 * already been sent the latest version of our HELLO message.
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
 * All known neighbours and their HELLOs.
 */
static struct NeighbourList *neighbours;

/**
 * Number of neighbours we'd like to have.
 */
static uint32_t max_connect_per_transport;

/**
 * Head of linked list.
 */
static struct CheckHelloValidatedContext *chvc_head;

/**
 * Tail of linked list.
 */
static struct CheckHelloValidatedContext *chvc_tail;


/**
 * Map of PeerIdentities to 'struct ValidationEntry*'s (addresses
 * of the given peer that we are currently validating).
 */
static struct GNUNET_CONTAINER_MultiHashMap *validation_map;


/**
 * The peer specified by the given neighbour has timed-out or a plugin
 * has disconnected.  We may either need to do nothing (other plugins
 * still up), or trigger a full disconnect and clean up.  This
 * function updates our state and do the necessary notifications.
 * Also notifies our clients that the neighbour is now officially
 * gone.
 *
 * @param n the neighbour list entry for the peer
 * @param check should we just check if all plugins
 *        disconnected or must we ask all plugins to
 *        disconnect?
 */
static void disconnect_neighbour (struct NeighbourList *n, int check);

/**
 * Check the ready list for the given neighbour and if a plugin is
 * ready for transmission (and if we have a message), do so!
 *
 * @param neighbour target peer for which to transmit
 */
static void try_transmission_to_peer (struct NeighbourList *neighbour);


/**
 * Find an entry in the neighbour list for a particular peer.
 * if sender_address is not specified (NULL) then return the
 * first matching entry.  If sender_address is specified, then
 * make sure that the address and address_len also matches.
 * 
 * FIXME: This description does not fit the function.
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
 *
 * @param n neighbour to update
 * @param force GNUNET_YES to force recalculation now
 */
static void
update_quota (struct NeighbourList *n,
	      int force)
{
  struct GNUNET_TIME_Absolute now;
  unsigned long long delta;
  uint64_t allowed;
  uint64_t remaining;

  now = GNUNET_TIME_absolute_get ();
  delta = now.value - n->last_quota_update.value;
  allowed = n->quota_in * delta;
  if ( (delta < MIN_QUOTA_REFRESH_TIME) &&
       (!force) &&
       (allowed < 32 * 1024) )
    return;                     /* too early, not enough data */
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
      n->last_quota_update = now;
      n->last_quota_update.value -= remaining;
      if (n->quota_violation_count > 0)
        n->quota_violation_count--;
    }
  else
    {
      n->last_received -= allowed;
      n->last_quota_update = now;
      if (n->last_received > allowed)
        {
          /* much more than the allowed rate! */
          n->quota_violation_count += 10;
        }
    }
}


/**
 * Function called to notify a client about the socket being ready to
 * queue more data.  "buf" will be NULL and "size" zero if the socket
 * was closed for writing in the meantime.
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
  char *cbuf;

  client->th = NULL;
  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission to client failed, closing connection.\n");
      /* fatal error with client, free message queue! */
      while (NULL != (q = client->message_queue_head))
        {
	  GNUNET_CONTAINER_DLL_remove (client->message_queue_head,
				       client->message_queue_tail,
				       q);
          GNUNET_free (q);
        }
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
      GNUNET_CONTAINER_DLL_remove (client->message_queue_head,
				   client->message_queue_tail,
				   q);
      memcpy (&cbuf[tsize], msg, msize);
      tsize += msize;
      GNUNET_free (q);
      client->message_count--;
    }
  if (NULL != q)
    {
      GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
      client->th = GNUNET_SERVER_notify_transmit_ready (client->client,
							msize,
							GNUNET_TIME_UNIT_FOREVER_REL,
							&transmit_to_client_callback,
							client);
      GNUNET_assert (client->th != NULL);
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

  if ((client->message_count >= MAX_PENDING) && (GNUNET_YES == may_drop))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Dropping message, have %u messages pending (%u is the soft limit)\n"),
                  client->message_count, MAX_PENDING);
      /* TODO: call to statistics... */
      return;
    }
  msize = ntohs (msg->size);
  GNUNET_assert (msize >= sizeof (struct GNUNET_MessageHeader));
  q = GNUNET_malloc (sizeof (struct ClientMessageQueueEntry) + msize);
  memcpy (&q[1], msg, msize);
  GNUNET_CONTAINER_DLL_insert_after (client->message_queue_head,
				     client->message_queue_tail,
				     client->message_queue_tail,
				     q);				     
  client->message_count++;
  if (client->th == NULL)
    {
      client->th = GNUNET_SERVER_notify_transmit_ready (client->client,
							msize,
							GNUNET_TIME_UNIT_FOREVER_REL,
							&transmit_to_client_callback,
							client);
      GNUNET_assert (client->th != NULL);
    }
}


/**
 * Transmit a 'SEND_OK' notification to the given client for the
 * given neighbour.
 *
 * @param client who to notify
 * @param n neighbour to notify about
 * @param result status code for the transmission request
 */
static void
transmit_send_ok (struct TransportClient *client,
		  struct NeighbourList *n,
		  int result)
{
  struct SendOkMessage send_ok_msg;

  send_ok_msg.header.size = htons (sizeof (send_ok_msg));
  send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
  send_ok_msg.success = htonl (result);
  send_ok_msg.latency = GNUNET_TIME_relative_hton (n->latency);
  send_ok_msg.peer = n->id;
  transmit_to_client (client, &send_ok_msg.header, GNUNET_NO); 
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
  struct NeighbourList *n;

  n = find_neighbour(&mq->neighbour_id);
  GNUNET_assert (n != NULL);
  if (mq->specific_address != NULL)
    {
      if (result == GNUNET_OK)    
	{
	  mq->specific_address->timeout =
	    GNUNET_TIME_relative_to_absolute
	    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
	  mq->specific_address->connected = GNUNET_YES;
	}    
      else
	{
	  mq->specific_address->connected = GNUNET_NO;
	}    
      if (! mq->internal_msg) 
	mq->specific_address->in_transmit = GNUNET_NO;
    }
  if (mq->client != NULL)
    transmit_send_ok (mq->client, n, result);
  GNUNET_free (mq);
  try_transmission_to_peer (n);
  /** Never disconnect a neighbor here... 
  if (result != GNUNET_OK)
    disconnect_neighbour (n, GNUNET_YES);
  */    
}


/**
 * Find an address in any of the available transports for
 * the given neighbour that would be good for message
 * transmission.  This is essentially the transport selection
 * routine.
 *
 * @param neighbour for whom to select an address
 * @return selected address, NULL if we have none
 */
struct ForeignAddressList *
find_ready_address(struct NeighbourList *neighbour)
{
  struct ReadyList *head = neighbour->plugins;
  struct ForeignAddressList *addresses;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct ForeignAddressList *best_address;

  best_address = NULL;
  while (head != NULL)
    {
      addresses = head->addresses;
      while (addresses != NULL)
        {
          if ( (addresses->timeout.value < now.value) && 
	       (addresses->connected == GNUNET_YES) )
            {
#if DEBUG_TRANSPORT
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Marking long-time inactive connection to `%4s' as down.\n",
                          GNUNET_i2s (&neighbour->id));
#endif
              addresses->connected = GNUNET_NO;
            }
          addresses = addresses->next;
        }

      addresses = head->addresses;
      while (addresses != NULL)
        {
          if ( ( (best_address == NULL) || 
		 (addresses->connected == GNUNET_YES) ||
		 (best_address->connected == GNUNET_NO) ) &&
	       (addresses->in_transmit == GNUNET_NO) &&
	       ( (best_address == NULL) || 
		 (addresses->latency.value < best_address->latency.value)) )
	    best_address = addresses;            
	  /* FIXME: also give lower-latency addresses that are not
	     connected a chance some times... */
          addresses = addresses->next;
        }
      head = head->next;
    }
#if DEBUG_TRANSPORT
  if (best_address != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Best address found has latency of %llu ms.\n",
                  best_address->latency.value);
    }
#endif
  return best_address;

}


/**
 * We should re-try transmitting to the given peer,
 * hopefully we've learned something in the meantime.
 */
static void
retry_transmission_task (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourList *n = cls;

  n->retry_task = GNUNET_SCHEDULER_NO_TASK;
  try_transmission_to_peer (n);
}


/**
 * Check the ready list for the given neighbour and if a plugin is
 * ready for transmission (and if we have a message), do so!
 *
 * @param neighbour target peer for which to transmit
 */
static void
try_transmission_to_peer (struct NeighbourList *neighbour)
{
  struct ReadyList *rl;
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;

  if (neighbour->messages_head == NULL)
    return;                     /* nothing to do */
  rl = NULL;
  mq = neighbour->messages_head;
  /* FIXME: support bi-directional use of TCP */
  if (mq->specific_address == NULL)
    mq->specific_address = find_ready_address(neighbour); 
  if (mq->specific_address == NULL)
    {
      timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
      if (timeout.value == 0)
	{
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "No destination address available to transmit message of size %u to peer `%4s'\n",
		      mq->message_buf_size,
		      GNUNET_i2s (&mq->neighbour_id));
#endif
	  if (mq->client != NULL)
	    transmit_send_ok (mq->client, neighbour, GNUNET_NO);
	  GNUNET_CONTAINER_DLL_remove (neighbour->messages_head,
				       neighbour->messages_tail,
				       mq);
	  GNUNET_free (mq);
	  return;               /* nobody ready */ 
	}
      if (neighbour->retry_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched,
				 neighbour->retry_task);
      neighbour->retry_task = GNUNET_SCHEDULER_add_delayed (sched,
							    timeout,
							    &retry_transmission_task,
							    neighbour);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No validated destination address available to transmit message of size %u to peer `%4s', will wait %llums to find an address.\n",
		  mq->message_buf_size,
		  GNUNET_i2s (&mq->neighbour_id),
		  timeout.value);
#endif
      return;    
    }
  GNUNET_CONTAINER_DLL_remove (neighbour->messages_head,
			       neighbour->messages_tail,
			       mq);
  if (mq->specific_address->connected == GNUNET_NO)
    mq->specific_address->connect_attempts++;
  rl = mq->specific_address->ready_list;
  mq->plugin = rl->plugin;
  if (!mq->internal_msg)
    mq->specific_address->in_transmit = GNUNET_YES;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message of size %u for `%4s' to `%s' via plugin `%s'\n",
              mq->message_buf_size,
              GNUNET_i2s (&neighbour->id), 
	      GNUNET_a2s (mq->specific_address->addr,
			  mq->specific_address->addrlen),
	      rl->plugin->short_name);
#endif
  rl->plugin->api->send (rl->plugin->api->cls,
			 &mq->neighbour_id,
			 mq->message_buf,
			 mq->message_buf_size,
			 mq->priority,
			 GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
			 mq->specific_address->addr,
			 mq->specific_address->addrlen,
			 GNUNET_YES /* FIXME: sometimes, we want to be more tolerant here! */,
			 &transmit_send_continuation, mq);
}


/**
 * Send the specified message to the specified peer.
 *
 * @param client source of the transmission request (can be NULL)
 * @param peer_address ForeignAddressList where we should send this message
 * @param priority how important is the message
 * @param timeout how long do we have to transmit?
 * @param message_buf message(s) to send GNUNET_MessageHeader(s)
 * @param message_buf_size total size of all messages in message_buf
 * @param is_internal is this an internal message; these are pre-pended and
 *                    also do not count for plugins being "ready" to transmit
 * @param neighbour handle to the neighbour for transmission
 */
static void
transmit_to_peer (struct TransportClient *client,
                  struct ForeignAddressList *peer_address,
                  unsigned int priority,
		  struct GNUNET_TIME_Relative timeout,
                  const char *message_buf,
                  size_t message_buf_size,
                  int is_internal, struct NeighbourList *neighbour)
{
  struct MessageQueue *mq;

#if EXTRA_CHECKS
  if (client != NULL)
    {
      /* check for duplicate submission */
      mq = neighbour->messages_head;
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
#endif
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + message_buf_size);
  mq->specific_address = peer_address;
  mq->client = client;
  memcpy (&mq[1], message_buf, message_buf_size);
  mq->message_buf = (const char*) &mq[1];
  mq->message_buf_size = message_buf_size;
  memcpy(&mq->neighbour_id, &neighbour->id, sizeof(struct GNUNET_PeerIdentity));
  mq->internal_msg = is_internal;
  mq->priority = priority;
  mq->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (is_internal)    
    GNUNET_CONTAINER_DLL_insert (neighbour->messages_head,
				 neighbour->messages_tail,
				 mq);
  else
    GNUNET_CONTAINER_DLL_insert_after (neighbour->messages_head,
				       neighbour->messages_tail,
				       neighbour->messages_tail,
				       mq);
  try_transmission_to_peer (neighbour);
}


/**
 * FIXME: document.
 */
struct GeneratorContext
{
  struct TransportPlugin *plug_pos;
  struct OwnAddressList *addr_pos;
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
  struct NeighbourList *npos;
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
  npos = neighbours;
  while (npos != NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Transmitting updated `%s' to neighbour `%4s'\n",
                  "HELLO", GNUNET_i2s (&npos->id));
#endif
      transmit_to_peer (NULL, NULL, 0,
			HELLO_ADDRESS_EXPIRATION,
                        (const char *) our_hello, 
			GNUNET_HELLO_size(our_hello),
                        GNUNET_NO, npos);
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
  struct OwnAddressList *pos;
  struct OwnAddressList *prev;
  struct OwnAddressList *next;
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
  struct OwnAddressList *al;
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

  al = GNUNET_malloc (sizeof (struct OwnAddressList) + addrlen);
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
                        struct GNUNET_TIME_Relative latency,
			uint32_t distance)
{
  struct ConnectInfoMessage cim;
  struct TransportClient *cpos;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Notifying clients about connection from `%s'\n",
	      GNUNET_i2s (peer));
#endif
  cim.header.size = htons (sizeof (struct ConnectInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim.distance = htonl (distance);
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
	      "Notifying clients about lost connection to `%s'\n",
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
 * Find a ForeignAddressList entry for the given neighbour
 * that matches the given address and transport.
 *
 * @param neighbour which peer we care about
 * @param tname name of the transport plugin
 * @param addr binary address
 * @param addrlen length of addr
 * @return NULL if no such entry exists
 */
static struct ForeignAddressList *
find_peer_address(struct NeighbourList *neighbour,
		  const char *tname,
		  const char *addr,
		  size_t addrlen)
{
  struct ReadyList *head;
  struct ForeignAddressList *address_head;

  head = neighbour->plugins;
  while (head != NULL)
    {
      if (0 == strcmp (tname, head->plugin->short_name))
	break;
      head = head->next;
    }
  if (head == NULL)
    return NULL;

  address_head = head->addresses;
  while ( (address_head != NULL) &&
	  ( (address_head->addrlen != addrlen) ||
	    (memcmp(address_head->addr, addr, addrlen) != 0) ) )
    address_head = address_head->next;
  return address_head;
}


/**
 * Get the peer address struct for the given neighbour and
 * address.  If it doesn't yet exist, create it.
 *
 * @param neighbour which peer we care about
 * @param tname name of the transport plugin
 * @param addr binary address
 * @param addrlen length of addr
 * @return NULL if we do not have a transport plugin for 'tname'
 */
static struct ForeignAddressList *
add_peer_address(struct NeighbourList *neighbour,
		 const char *tname,
		 const char *addr, 
		 size_t addrlen)
{
  struct ReadyList *head;
  struct ForeignAddressList *ret;

  ret = find_peer_address (neighbour, tname, addr, addrlen);
  if (ret != NULL)
    return ret;
  head = neighbour->plugins;
  while (head != NULL)
    {
      if (0 == strcmp (tname, head->plugin->short_name))
	break;
      head = head->next;
    }
  if (head == NULL)
    return NULL;
  ret = GNUNET_malloc(sizeof(struct ForeignAddressList) + addrlen);
  ret->addr = (const char*) &ret[1];
  memcpy (&ret[1], addr, addrlen);
  ret->addrlen = addrlen;
  ret->expires = GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  ret->latency = GNUNET_TIME_relative_get_forever();
  ret->distance = -1;
  ret->timeout = GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT); 
  ret->ready_list = head;
  ret->next = head->addresses;
  head->addresses = ret;
  return ret;
}


/**
 * Closure for 'add_validated_address'.
 */
struct AddValidatedAddressContext
{
  /**
   * Entry that has been validated.
   */
  const struct ValidationEntry *ve;

  /**
   * Flag set after we have added the address so
   * that we terminate the iteration next time.
   */
  int done;
};


/**
 * Callback function used to fill a buffer of max bytes with a list of
 * addresses in the format used by HELLOs.  Should use
 * "GNUNET_HELLO_add_address" as a helper function.
 *
 * @param cls the 'struct AddValidatedAddressContext' with the validated address
 * @param max maximum number of bytes that can be written to buf
 * @param buf where to write the address information
 * @return number of bytes written, 0 to signal the
 *         end of the iteration.
 */
static size_t
add_validated_address (void *cls,
		       size_t max, void *buf)
{
  struct AddValidatedAddressContext *avac = cls;
  const struct ValidationEntry *ve = avac->ve;

  if (GNUNET_YES == avac->done)
    return 0;
  avac->done = GNUNET_YES;
  return GNUNET_HELLO_add_address (ve->transport_name,
				   GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION),
				   ve->addr,
				   ve->addrlen,
				   buf,
				   max);
}


/**
 * Iterator over hash map entries.  Checks if the given
 * validation entry is for the same challenge as what
 * is given in the PONG.
 *
 * @param cls the 'struct TransportPongMessage*'
 * @param key peer identity 
 * @param value value in the hash map ('struct ValidationEntry')
 * @return GNUNET_YES if we should continue to
 *         iterate (mismatch), GNUNET_NO if not (entry matched)
 */
static int
check_pending_validation (void *cls,
			  const GNUNET_HashCode * key,
			  void *value)
{
  const struct TransportPongMessage *pong = cls;
  struct ValidationEntry *ve = value;
  struct AddValidatedAddressContext avac;
  unsigned int challenge = ntohl(pong->challenge);
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity target;
  struct NeighbourList *n;
  struct ForeignAddressList *fal;

  if (ve->challenge != challenge)
    return GNUNET_YES;
  
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Confirmed validity of address, peer `%4s' has address `%s' (%s).\n",
	      GNUNET_h2s (key),
	      GNUNET_a2s ((const struct sockaddr *) ve->addr,
			  ve->addrlen),
	      ve->transport_name);
#endif
  /* create the updated HELLO */
  GNUNET_CRYPTO_hash (&ve->publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &target.hashPubKey);
  avac.done = GNUNET_NO;
  avac.ve = ve;
  hello = GNUNET_HELLO_create (&ve->publicKey,
			       &add_validated_address,
			       &avac);
  GNUNET_PEERINFO_add_peer (cfg, sched,
			    &target, 
			    hello);
  GNUNET_free (hello);
  n = find_neighbour (&target);
  if (n != NULL)
    {
      fal = add_peer_address (n, ve->transport_name, 
			      ve->addr,
			      ve->addrlen);
      fal->expires = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
      fal->validated = GNUNET_YES;
      fal->latency = GNUNET_TIME_absolute_get_duration (ve->send_time);
      if (n->latency.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
	n->latency = fal->latency;
      else
	n->latency.value = (fal->latency.value + n->latency.value) / 2;
      n->distance = fal->distance;
      if (GNUNET_NO == n->received_pong)
	{
	  notify_clients_connect (&target, n->latency, n->distance);
	  n->received_pong = GNUNET_YES;
	}
      if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (sched,
				   n->retry_task);
	  n->retry_task = GNUNET_SCHEDULER_NO_TASK;	
	  try_transmission_to_peer (n);
	}
    }

  /* clean up validation entry */
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (validation_map,
						       key,
						       ve));
  GNUNET_SCHEDULER_cancel (sched,
			   ve->timeout_task);
  GNUNET_free (ve->transport_name);
  GNUNET_free (ve);
  return GNUNET_NO;
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
 * @param message the pong message
 * @param peer who responded to our challenge
 * @param sender_address string describing our sender address (as observed
 *         by the other peer in binary format)
 * @param sender_address_len number of bytes in 'sender_address'
 */
static void
handle_pong (void *cls, const struct GNUNET_MessageHeader *message,
             const struct GNUNET_PeerIdentity *peer,
             const char *sender_address,
             size_t sender_address_len)
{
#if DEBUG_TRANSPORT > 1
  /* we get tons of these that just get discarded, only log
     if we are quite verbose */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Receiving `%s' message from `%4s'.\n", "PONG",
	      GNUNET_i2s (peer));
#endif
  if (GNUNET_SYSERR != 
      GNUNET_CONTAINER_multihashmap_get_multiple (validation_map,
						  &peer->hashPubKey,
						  &check_pending_validation,
						  (void*) message))
    {
      /* This is *expected* to happen a lot since we send
	 PONGs to *all* known addresses of the sender of
	 the PING, so most likely we get multiple PONGs
	 per PING, and all but the first PONG will end up
	 here. So really we should not print anything here
	 unless we want to be very, very verbose... */
#if DEBUG_TRANSPORT > 2
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received `%s' message from `%4s' but have no record of a matching `%s' message. Ignoring.\n",
                  "PONG",
		  GNUNET_i2s (peer),
		  "PING");
#endif
      return;
    }
  
#if 0
  /* FIXME: add given address to potential pool of our addresses
     (for voting) */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
	      _("Another peer saw us using the address `%s' via `%s'.\n"),
	      GNUNET_a2s ((const struct sockaddr *) &pong[1],
			  ntohs(pong->addrlen)), 
	      va->transport_name);  
#endif
}


static void
neighbour_timeout_task (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourList *n = cls;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Neighbour `%4s' has timed out!\n", GNUNET_i2s (&n->id));
#endif
  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  disconnect_neighbour (n, GNUNET_NO);
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
  struct TransportPlugin *tp;
  struct ReadyList *rl;

  GNUNET_assert (our_hello != NULL);
  n = GNUNET_malloc (sizeof (struct NeighbourList));
  n->next = neighbours;
  neighbours = n;
  n->id = *peer;
  n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  n->quota_in = (GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT + 59999) / (60 * 1000);
  tp = plugins;
  while (tp != NULL)
    {
      if (tp->api->send != NULL)
        {
          rl = GNUNET_malloc (sizeof (struct ReadyList));
          rl->next = n->plugins;
          n->plugins = rl;
          rl->plugin = tp;
          rl->addresses = NULL;
        }
      tp = tp->next;
    }
  n->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  n->distance = -1;
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                  GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                  &neighbour_timeout_task, n);
  transmit_to_peer (NULL, NULL, 0,
		    HELLO_ADDRESS_EXPIRATION,
                    (const char *) our_hello, GNUNET_HELLO_size(our_hello),
                    GNUNET_NO, n);
  return n;
}


/**
 * Closure for 'check_address_exists'.
 */
struct CheckAddressExistsClosure
{
  /**
   * Address to check for.
   */
  const void *addr;

  /**
   * Name of the transport.
   */
  const char *tname;

  /**
   * Length of addr.
   */
  size_t addrlen;

  /**
   * Set to GNUNET_YES if the address exists.
   */
  int exists;
};


/**
 * Iterator over hash map entries.  Checks if the given
 * validation entry is for the same address as what is given
 * in the closure.
 *
 * @param cls the 'struct CheckAddressExistsClosure*'
 * @param key current key code (ignored)
 * @param value value in the hash map ('struct ValidationEntry')
 * @return GNUNET_YES if we should continue to
 *         iterate (mismatch), GNUNET_NO if not (entry matched)
 */
static int
check_address_exists (void *cls,
		      const GNUNET_HashCode * key,
		      void *value)
{
  struct CheckAddressExistsClosure *caec = cls;
  struct ValidationEntry *ve = value;
  if ( (0 == strcmp (caec->tname,
		     ve->transport_name)) &&
       (caec->addrlen == ve->addrlen) &&
       (0 == memcmp (caec->addr,
		     ve->addr,
		     caec->addrlen)) )
    {
      caec->exists = GNUNET_YES;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * HELLO validation cleanup task (validation failed).
 *
 * @param cls the 'struct ValidationEntry' that failed
 * @param tc scheduler context (unused)
 */
static void
timeout_hello_validation (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *va = cls;
  struct GNUNET_PeerIdentity pid;

  GNUNET_CRYPTO_hash (&va->publicKey,
		      sizeof (struct
			      GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &pid.hashPubKey);
  GNUNET_CONTAINER_multihashmap_remove (validation_map,
					&pid.hashPubKey,
					va);
  GNUNET_free (va->transport_name);
  GNUNET_free (va);
}


/**
 * Check if the given address is already being validated; if not,
 * append the given address to the list of entries that are being be
 * validated and initiate validation.
 *
 * @param cls closure ('struct CheckHelloValidatedContext *')
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK (always)
 */
static int
run_validation (void *cls,
                const char *tname,
                struct GNUNET_TIME_Absolute expiration,
                const void *addr, size_t addrlen)
{
  struct CheckHelloValidatedContext *chvc = cls;
  struct GNUNET_PeerIdentity id;
  struct TransportPlugin *tp;
  struct ValidationEntry *va;
  struct NeighbourList *neighbour;
  struct ForeignAddressList *peer_address;
  struct TransportPingMessage ping;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct CheckAddressExistsClosure caec;
  char * message_buf;
  uint16_t hello_size;
  size_t tsize;

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
  GNUNET_HELLO_get_key (chvc->hello, &pk);
  GNUNET_CRYPTO_hash (&pk,
                      sizeof (struct
                              GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id.hashPubKey);
  caec.addr = addr;
  caec.addrlen = addrlen;
  caec.tname = tname;
  caec.exists = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
					 &check_address_exists,
					 &caec);
  if (caec.exists == GNUNET_YES)
    {
      /* During validation attempts we will likely trigger the other
	 peer trying to validate our address which in turn will cause
	 it to send us its HELLO, so we expect to hit this case rather
	 frequently.  Only print something if we are very verbose. */
#if DEBUG_TRANSPORT > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Validation of address `%s' via `%s' for peer `%4s' already in progress.\n",
		  GNUNET_a2s (addr, addrlen), 
		  tname, 
		  GNUNET_i2s (&id));
#endif
      return GNUNET_OK;
    } 
  va = GNUNET_malloc (sizeof (struct ValidationEntry) + addrlen);
  va->transport_name = GNUNET_strdup (tname);
  va->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                            (unsigned int) -1);
  va->send_time = GNUNET_TIME_absolute_get();
  va->addr = (const void*) &va[1];
  memcpy (&va[1], addr, addrlen);
  va->addrlen = addrlen;
  GNUNET_HELLO_get_key (chvc->hello,
			&va->publicKey);
  va->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
						   HELLO_VERIFICATION_TIMEOUT,
						   &timeout_hello_validation,
						   va);  
  GNUNET_CONTAINER_multihashmap_put (validation_map,
				     &id.hashPubKey,
				     va,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  neighbour = find_neighbour(&id);  
  if (neighbour == NULL)
    neighbour = setup_new_neighbour(&id);
  peer_address = add_peer_address(neighbour, tname, addr, addrlen);    
  GNUNET_assert(peer_address != NULL);
  hello_size = GNUNET_HELLO_size(our_hello);
  tsize = sizeof(struct TransportPingMessage) + hello_size;
  message_buf = GNUNET_malloc(tsize);
  ping.challenge = htonl(va->challenge);
  ping.header.size = htons(sizeof(struct TransportPingMessage));
  ping.header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  memcpy(&ping.target, &id, sizeof(struct GNUNET_PeerIdentity));
  memcpy(message_buf, our_hello, hello_size);
  memcpy(&message_buf[hello_size], 
	 &ping, 
	 sizeof(struct TransportPingMessage));
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing validation of address `%s' via `%s' for peer `%4s' sending `%s' (%u bytes) and `%s' (%u bytes)\n",
              GNUNET_a2s (addr, addrlen), 
	      tname, 
	      GNUNET_i2s (&id),
	      "HELLO", hello_size,
	      "PING", sizeof (struct TransportPingMessage));
#endif
  transmit_to_peer (NULL, peer_address, 
		    GNUNET_SCHEDULER_PRIORITY_DEFAULT,
		    HELLO_VERIFICATION_TIMEOUT,
		    message_buf, tsize, 
		    GNUNET_YES, neighbour);
  GNUNET_free(message_buf);
  return GNUNET_OK;
}


/**
 * Add the given address to the list of foreign addresses
 * available for the given peer (check for duplicates).
 *
 * @param cls the respective 'struct NeighbourList' to update
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK (always)
 */
static int
add_to_foreign_address_list (void *cls,
			     const char *tname,
			     struct GNUNET_TIME_Absolute expiration,
			     const void *addr, size_t addrlen)
{
  struct NeighbourList *n = cls;
  struct ForeignAddressList *fal;

  fal = find_peer_address (n, tname, addr, addrlen);
  if (fal == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Adding address `%s' (%s) for peer `%4s' due to peerinfo data for %llums.\n",
		  GNUNET_a2s (addr, addrlen),
		  tname,
		  GNUNET_i2s (&n->id),
		  expiration.value);
#endif
      fal = add_peer_address (n, tname, addr, addrlen);
    }
  if (fal == NULL)
    return GNUNET_OK;
  fal->expires = GNUNET_TIME_absolute_max (expiration,
					   fal->expires);
  fal->validated = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Check if addresses in validated hello "h" overlap with
 * those in "chvc->hello" and validate the rest.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param h hello message for the peer (can be NULL)
 * @param trust amount of trust we have in the peer (not used)
 */
static void
check_hello_validated (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_HELLO_Message *h, 
		       uint32_t trust)
{
  struct CheckHelloValidatedContext *chvc = cls;
  struct GNUNET_HELLO_Message *plain_hello;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct GNUNET_PeerIdentity target;
  struct NeighbourList *n;

  if (peer == NULL)
    {
      chvc->piter = NULL;
      GNUNET_CONTAINER_DLL_remove (chvc_head,
				   chvc_tail,
				   chvc);
      if (GNUNET_NO == chvc->hello_known)
	{
	  /* notify PEERINFO about the peer now, so that we at least
	     have the public key if some other component needs it */
	  GNUNET_HELLO_get_key (chvc->hello, &pk);
	  GNUNET_CRYPTO_hash (&pk,
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			      &target.hashPubKey);
	  plain_hello = GNUNET_HELLO_create (&pk,
					     NULL, 
					     NULL);
	  GNUNET_PEERINFO_add_peer (cfg, sched, &target, plain_hello);
	  GNUNET_free (plain_hello);
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Peerinfo had no `%s' message for peer `%4s', full validation needed.\n",
		      "HELLO",
		      GNUNET_i2s (&target));
#endif
	  GNUNET_HELLO_iterate_addresses (chvc->hello,
					  GNUNET_NO, 
					  &run_validation, 
					  chvc);
	}
      GNUNET_free (chvc);
      return;
    }
  if (h == NULL)
    return;
  chvc->hello_known = GNUNET_YES;
  n = find_neighbour (peer);
  if (n != NULL)
    {
      GNUNET_HELLO_iterate_addresses (h,
				      GNUNET_NO,
				      &add_to_foreign_address_list,
				      n);
      try_transmission_to_peer (n);
    }
  GNUNET_HELLO_iterate_new_addresses (chvc->hello,
				      h,
				      GNUNET_TIME_relative_to_absolute (HELLO_REVALIDATION_START_TIME),
				      &run_validation, 
				      chvc);
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
  if (GNUNET_SCHEDULER_get_load (sched,
				 GNUNET_SCHEDULER_PRIORITY_BACKGROUND) > MAX_HELLO_LOAD)
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
              "Processing `%s' message for `%4s' of size %u\n",
              "HELLO", 
	      GNUNET_i2s (&target), 
	      GNUNET_HELLO_size(hello));
#endif

  chvc = GNUNET_malloc (sizeof (struct CheckHelloValidatedContext) + hsize);
  chvc->hello = (const struct GNUNET_HELLO_Message *) &chvc[1];
  memcpy (&chvc[1], hello, hsize);
  GNUNET_CONTAINER_DLL_insert (chvc_head,
			       chvc_tail,
			       chvc);
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
 * The peer specified by the given neighbour has timed-out or a plugin
 * has disconnected.  We may either need to do nothing (other plugins
 * still up), or trigger a full disconnect and clean up.  This
 * function updates our state and does the necessary notifications.
 * Also notifies our clients that the neighbour is now officially
 * gone.
 *
 * @param n the neighbour list entry for the peer
 * @param check should we just check if all plugins
 *        disconnected or must we ask all plugins to
 *        disconnect?
 */
static void
disconnect_neighbour (struct NeighbourList *n, int check)
{
  struct ReadyList *rpos;
  struct NeighbourList *npos;
  struct NeighbourList *nprev;
  struct MessageQueue *mq;
  struct ForeignAddressList *peer_addresses;
  struct ForeignAddressList *peer_pos;

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
              "Disconnecting from `%4s'\n",
	      GNUNET_i2s (&n->id));
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
  if (GNUNET_YES == n->received_pong)
    notify_clients_disconnect (&n->id);

  /* clean up all plugins, cancel connections and pending transmissions */
  while (NULL != (rpos = n->plugins))
    {
      n->plugins = rpos->next;
      rpos->plugin->api->disconnect (rpos->plugin->api->cls, &n->id);

      while (rpos->addresses != NULL)
        {
          peer_pos = rpos->addresses;
          rpos->addresses = peer_pos->next;
          GNUNET_free(peer_pos);
        }
      GNUNET_free (rpos);
    }

  /* free all messages on the queue */
  while (NULL != (mq = n->messages_head))
    {
      GNUNET_CONTAINER_DLL_remove (n->messages_head,
				   n->messages_tail,
				   mq);
      GNUNET_assert (0 == memcmp(&mq->neighbour_id, 
				 &n->id,
				 sizeof(struct GNUNET_PeerIdentity)));
      GNUNET_free (mq);
    }
  if (n->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, n->timeout_task);
      n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, n->retry_task);
      n->retry_task = GNUNET_SCHEDULER_NO_TASK;
    }
  /* finally, free n itself */
  GNUNET_free (n);
}


/**
 * We have received a PING message from someone.  Need to send a PONG message
 * in response to the peer by any means necessary. 
 *
 * FIXME: With something like TCP where a connection exists, we may
 * want to send it that way.  But the current API does not seem to
 * allow us to do so (can't tell this to the transport!)
 */
static int 
handle_ping(void *cls, const struct GNUNET_MessageHeader *message,
	    const struct GNUNET_PeerIdentity *peer,
	    const char *sender_address,
	    size_t sender_address_len)
{
  struct TransportPlugin *plugin = cls;
  struct TransportPingMessage *ping;
  struct TransportPongMessage *pong;
  struct NeighbourList *n;
  struct ReadyList *rl;
  struct ForeignAddressList *fal;

  if (ntohs (message->size) != sizeof (struct TransportPingMessage))
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
                  _("Received `%s' message not destined for me!\n"), 
		  "PING");
      return GNUNET_SYSERR;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
	      "Processing `%s' from `%s'\n",
	      "PING", 
	      GNUNET_a2s ((const struct sockaddr *)sender_address, 
			  sender_address_len));
#endif
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
  memcpy(&pong->signer, 
	 &my_public_key, 
	 sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  memcpy (&pong[1], sender_address, sender_address_len);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key,
                                         &pong->purpose, &pong->signature));

  n = find_neighbour(peer);
  if (n == NULL)
    n = setup_new_neighbour(peer);
  /* broadcast 'PONG' to all available addresses */
  rl = n->plugins;
  while (rl != NULL)
    {
      fal = rl->addresses;
      while (fal != NULL)
	{
	  transmit_to_peer(NULL, fal,
			   TRANSPORT_PONG_PRIORITY, 
			   HELLO_VERIFICATION_TIMEOUT,
			   (const char *)pong, 
			   ntohs(pong->header.size), 
			   GNUNET_YES, 
			   n);
	  fal = fal->next;
	}
      rl = rl->next;
    }
  GNUNET_free(pong);
  return GNUNET_OK;
}


/**
 * Calculate how long we should delay reading from the TCP socket to
 * ensure that we stay within our bandwidth limits (push back).
 *
 * @param n for which neighbour should this be calculated
 * @return how long to delay receiving more data
 */
static struct GNUNET_TIME_Relative
calculate_throttle_delay (struct NeighbourList *n)
{
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_TIME_Absolute now;
  uint64_t del;
  uint64_t avail;
  uint64_t excess;

  now = GNUNET_TIME_absolute_get ();
  del = now.value - n->last_quota_update.value;
  if (del > MAX_BANDWIDTH_CARRY)
    {
      update_quota (n, GNUNET_YES);
      del = now.value - n->last_quota_update.value;
      GNUNET_assert (del <= MAX_BANDWIDTH_CARRY);
    }
  if (n->quota_in == 0)
    n->quota_in = 1;      /* avoid divison by zero */
  avail = del * n->quota_in;
  if (avail > n->last_received)
    return GNUNET_TIME_UNIT_ZERO;       /* can receive right now */
  excess = n->last_received - avail;
  ret.value = excess / n->quota_in;
  if (ret.value > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Throttling read (%llu bytes excess at %llu b/ms), waiting %llums before reading more.\n",
		(unsigned long long) excess,
		(unsigned long long) n->quota_in,
		(unsigned long long) ret.value);
  return ret;
}


/**
 * Function called by the plugin for each received message.
 * Update data volumes, possibly notify plugins about
 * reducing the rate at which they read from the socket
 * and generally forward to our receive callback.
 *
 * @param cls the "struct TransportPlugin *" we gave to the plugin
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @param distance in overlay hops; use 1 unless DV (or 0 if message == NULL)
 * @param sender_address binary address of the sender (if observed)
 * @param sender_address_len number of bytes in sender_address
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
static struct GNUNET_TIME_Relative
plugin_env_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    unsigned int distance, const char *sender_address,
                    size_t sender_address_len)
{
  struct ReadyList *service_context;
  struct TransportPlugin *plugin = cls;
  struct TransportClient *cpos;
  struct InboundMessage *im;
  struct ForeignAddressList *peer_address;
  uint16_t msize;
  struct NeighbourList *n;

  n = find_neighbour (peer);
  if (n == NULL)
    n = setup_new_neighbour (peer);    
  update_quota (n, GNUNET_NO);
  service_context = n->plugins;
  while ((service_context != NULL) && (plugin != service_context->plugin))
    service_context = service_context->next;
  GNUNET_assert ((plugin->api->send == NULL) || (service_context != NULL));
  if (message != NULL)
    {
      peer_address = add_peer_address(n, 
				      plugin->short_name,
				      sender_address, 
				      sender_address_len);  
      if (peer_address != NULL)
	{
	  peer_address->distance = distance;
	  if (peer_address->connected == GNUNET_NO)
	    {
	      peer_address->connected = GNUNET_YES;
	      peer_address->connect_attempts++;
	    }
	  peer_address->timeout
	    =
	    GNUNET_TIME_relative_to_absolute
	    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
	}
      /* update traffic received amount ... */
      msize = ntohs (message->size);
      n->distance = distance;
      n->peer_timeout =
	GNUNET_TIME_relative_to_absolute
	(GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
      GNUNET_SCHEDULER_cancel (sched,
			       n->timeout_task);
      n->timeout_task =
	GNUNET_SCHEDULER_add_delayed (sched,
				      GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
				      &neighbour_timeout_task, n);
      if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
	{
	  /* dropping message due to frequent inbound volume violations! */
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING |
		      GNUNET_ERROR_TYPE_BULK,
		      _
		      ("Dropping incoming message due to repeated bandwidth quota violations (total of %u).\n"), 
		      n->quota_violation_count);
	  return GNUNET_TIME_UNIT_MINUTES; /* minimum penalty, likely ignored (UDP...) */
	}
      switch (ntohs (message->type))
	{
	case GNUNET_MESSAGE_TYPE_HELLO:
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
		      "Received message of type %u from `%4s', sending to all clients.\n",
		      ntohs (message->type), GNUNET_i2s (peer));
#endif
	  /* transmit message to all clients */
	  im = GNUNET_malloc (sizeof (struct InboundMessage) + msize);
	  im->header.size = htons (sizeof (struct InboundMessage) + msize);
	  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
	  im->latency = GNUNET_TIME_relative_hton (n->latency);
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
    }  
  return calculate_throttle_delay (n);
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
      n = neighbours; 
      while (n != NULL)
	{
	  if (GNUNET_YES == n->received_pong)
	    {
	      cim.id = n->id;
	      cim.latency = GNUNET_TIME_relative_hton (n->latency);
	      cim.distance = htonl (n->distance);
	      transmit_to_client (c, &cim.header, GNUNET_NO);
            }
	    n = n->next;
        }
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
  transmit_to_peer (tc, NULL, ntohl (obm->priority), 
		    GNUNET_TIME_relative_ntoh (obm->timeout),
		    (char *)obmm, 
		    ntohs (obmm->size), GNUNET_NO, n);
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
  uint32_t qin;

  n = find_neighbour (&qsm->peer);
  if (n == NULL)
    {
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  qin = ntohl (qsm->quota_in);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request (new quota %u, old quota %u) from client for peer `%4s'\n",
              "SET_QUOTA", qin, n->quota_in, GNUNET_i2s (&qsm->peer));
#endif
  update_quota (n, GNUNET_YES);
  if (n->quota_in < qin)
    n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->quota_in = qin;
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
      GNUNET_CONTAINER_DLL_remove (pos->message_queue_head,
				   pos->message_queue_tail,
				   mqe);
      pos->message_count--;
      GNUNET_free (mqe);
    }
  if (prev == NULL)
    clients = pos->next;
  else
    prev->next = pos->next;
  if (GNUNET_YES == pos->tcs_pending)
    {
      pos->client = NULL;
      return;
    }
  if (pos->th != NULL)
    {
      GNUNET_CONNECTION_notify_transmit_ready_cancel (pos->th);
      pos->th = NULL;
    }
  GNUNET_break (0 == pos->message_count);
  GNUNET_free (pos);
}


/**
 * Iterator to free entries in the validation_map.
 *
 * @param cls closure (unused)
 * @param key current key code
 * @param value value in the hash map (validation to abort)
 * @return GNUNET_YES (always)
 */
static int 
abort_validation (void *cls,
		  const GNUNET_HashCode * key,
		  void *value)
{
  struct ValidationEntry *va = value;

  GNUNET_SCHEDULER_cancel (sched, va->timeout_task);
  GNUNET_free (va->transport_name);
  GNUNET_free (va);
  return GNUNET_YES;
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TransportPlugin *plug;
  struct OwnAddressList *al;
  struct CheckHelloValidatedContext *chvc;

  while (neighbours != NULL)
    disconnect_neighbour (neighbours, GNUNET_NO);
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

  /* free 'chvc' data structure */
  while (NULL != (chvc = chvc_head))
    {
      chvc_head = chvc->next;
      GNUNET_PEERINFO_iterate_cancel (chvc->piter);
      GNUNET_free (chvc);
    }
  chvc_tail = NULL;

  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
					 &abort_validation,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (validation_map);
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
  validation_map = GNUNET_CONTAINER_multihashmap_create (64);
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
                                &shutdown_task, NULL);
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
