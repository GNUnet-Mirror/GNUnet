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
 * @file core/gnunet-service-core.c
 * @brief high-level P2P messaging
 * @author Christian Grothoff
 *
 * Considerations for later:
 * - check that hostkey used by transport (for HELLOs) is the
 *   same as the hostkey that we are using!
 * - add code to send PINGs if we are about to time-out otherwise
 * - optimize lookup (many O(n) list traversals
 *   could ideally be changed to O(1) hash map lookups)
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "core.h"


#define DEBUG_HANDSHAKE GNUNET_NO

#define DEBUG_CORE_QUOTA GNUNET_YES

/**
 * Receive and send buffer windows grow over time.  For
 * how long can 'unused' bandwidth accumulate before we
 * need to cap it?  (specified in seconds).
 */
#define MAX_WINDOW_TIME_S (5 * 60)

/**
 * How many messages do we queue up at most for optional
 * notifications to a client?  (this can cause notifications
 * about outgoing messages to be dropped).
 */
#define MAX_NOTIFY_QUEUE 16

/**
 * Minimum bandwidth (out) to assign to any connected peer.
 * Should be rather low; values larger than DEFAULT_BW_IN_OUT make no
 * sense.
 */
#define MIN_BANDWIDTH_PER_PEER GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT

/**
 * After how much time past the "official" expiration time do
 * we discard messages?  Should not be zero since we may 
 * intentionally defer transmission until close to the deadline
 * and then may be slightly past the deadline due to inaccuracy
 * in sleep and our own CPU consumption.
 */
#define PAST_EXPIRATION_DISCARD_TIME GNUNET_TIME_UNIT_SECONDS

/**
 * How long do we delay messages to get larger packet sizes (CORKing)?
 */
#define MAX_CORK_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * What is the maximum delay for a SET_KEY message?
 */
#define MAX_SET_KEY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * What how long do we wait for SET_KEY confirmation initially?
 */
#define INITIAL_SET_KEY_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 3)

/**
 * What is the maximum delay for a PING message?
 */
#define MAX_PING_DELAY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 2)

/**
 * What is the maximum delay for a PONG message?
 */
#define MAX_PONG_DELAY GNUNET_TIME_relative_multiply (MAX_PING_DELAY, 2)

/**
 * What is the minimum frequency for a PING message?
 */
#define MIN_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we recalculate bandwidth quotas?
 */
#define QUOTA_UPDATE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * What is the priority for a SET_KEY message?
 */
#define SET_KEY_PRIORITY 0xFFFFFF

/**
 * What is the priority for a PING message?
 */
#define PING_PRIORITY 0xFFFFFF

/**
 * What is the priority for a PONG message?
 */
#define PONG_PRIORITY 0xFFFFFF

/**
 * How many messages do we queue per peer at most?  Must be at
 * least two.
 */
#define MAX_PEER_QUEUE_SIZE 16

/**
 * How many non-mandatory messages do we queue per client at most?
 */
#define MAX_CLIENT_QUEUE_SIZE 32

/**
 * What is the maximum age of a message for us to consider
 * processing it?  Note that this looks at the timestamp used
 * by the other peer, so clock skew between machines does
 * come into play here.  So this should be picked high enough
 * so that a little bit of clock skew does not prevent peers
 * from connecting to us.
 */
#define MAX_MESSAGE_AGE GNUNET_TIME_UNIT_DAYS

/**
 * What is the maximum size for encrypted messages?  Note that this
 * number imposes a clear limit on the maximum size of any message.
 * Set to a value close to 64k but not so close that transports will
 * have trouble with their headers.
 */
#define MAX_ENCRYPTED_MESSAGE_SIZE (63 * 1024)


/**
 * State machine for our P2P encryption handshake.  Everyone starts in
 * "DOWN", if we receive the other peer's key (other peer initiated)
 * we start in state RECEIVED (since we will immediately send our
 * own); otherwise we start in SENT.  If we get back a PONG from
 * within either state, we move up to CONFIRMED (the PONG will always
 * be sent back encrypted with the key we sent to the other peer).
 */
enum PeerStateMachine
{
  PEER_STATE_DOWN,
  PEER_STATE_KEY_SENT,
  PEER_STATE_KEY_RECEIVED,
  PEER_STATE_KEY_CONFIRMED
};


/**
 * Number of bytes (at the beginning) of "struct EncryptedMessage"
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE (sizeof(struct GNUNET_MessageHeader) + sizeof(uint32_t))


/**
 * Encapsulation for encrypted messages exchanged between
 * peers.  Followed by the actual encrypted data.
 */
struct EncryptedMessage
{
  /**
   * Message type is either CORE_ENCRYPTED_MESSAGE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random value used for IV generation.  ENCRYPTED_HEADER_SIZE must
   * be set to the offset of the *next* field.
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * Hash of the plaintext (starting at 'sequence_number'), used to
   * verify message integrity.  Everything after this hash (including
   * this hash itself) will be encrypted.  
   */
  GNUNET_HashCode plaintext_hash;

  /**
   * Sequence number, in network byte order.  This field
   * must be the first encrypted/decrypted field and the
   * first byte that is hashed for the plaintext hash.
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Desired bandwidth (how much we should send to this peer / how
   * much is the sender willing to receive)?
   */
  struct GNUNET_BANDWIDTH_Value32NBO inbound_bw_limit;

  /**
   * Timestamp.  Used to prevent reply of ancient messages
   * (recent messages are caught with the sequence number).
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

};


/**
 * We're sending an (encrypted) PING to the other peer to check if he
 * can decrypt.  The other peer should respond with a PONG with the
 * same content, except this time encrypted with the receiver's key.
 */
struct PingMessage
{
  /**
   * Message type is CORE_PING.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random number chosen to make reply harder.
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;
};



/**
 * Response to a PING.  Includes data from the original PING
 * plus initial bandwidth quota information.
 */
struct PongMessage
{
  /**
   * Message type is CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random number proochosen to make reply harder.  Must be
   * first field after header (this is where we start to encrypt!).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Must be zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Desired bandwidth (how much we should send to this
   * peer / how much is the sender willing to receive).
   */
  struct GNUNET_BANDWIDTH_Value32NBO inbound_bw_limit;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;
};


/**
 * Message transmitted to set (or update) a session key.
 */
struct SetKeyMessage
{

  /**
   * Message type is either CORE_SET_KEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status of the sender (should be in "enum PeerStateMachine"), nbo.
   */
  int32_t sender_status GNUNET_PACKED;

  /**
   * Purpose of the signature, will be
   * GNUNET_SIGNATURE_PURPOSE_SET_KEY.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * At what time was this key created?
   */
  struct GNUNET_TIME_AbsoluteNBO creation_time;

  /**
   * The encrypted session key.
   */
  struct GNUNET_CRYPTO_RsaEncryptedData encrypted_key;

  /**
   * Who is the intended recipient?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Signature of the stuff above (starting at purpose).
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

};


/**
 * Message waiting for transmission. This struct
 * is followed by the actual content of the message.
 */
struct MessageEntry
{

  /**
   * We keep messages in a doubly linked list.
   */
  struct MessageEntry *next;

  /**
   * We keep messages in a doubly linked list.
   */
  struct MessageEntry *prev;

  /**
   * By when are we supposed to transmit this message?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * By when are we supposed to transmit this message (after
   * giving slack)?
   */
  struct GNUNET_TIME_Absolute slack_deadline;

  /**
   * How important is this message to us?
   */
  unsigned int priority;

  /**
   * How long is the message? (number of bytes following
   * the "struct MessageEntry", but not including the
   * size of "struct MessageEntry" itself!)
   */
  uint16_t size;

  /**
   * Was this message selected for transmission in the
   * current round? GNUNET_YES or GNUNET_NO.
   */
  int8_t do_transmit;

  /**
   * Did we give this message some slack (delayed sending) previously
   * (and hence should not give it any more slack)? GNUNET_YES or
   * GNUNET_NO.
   */
  int8_t got_slack;

};


struct Neighbour
{
  /**
   * We keep neighbours in a linked list (for now).
   */
  struct Neighbour *next;

  /**
   * Unencrypted messages destined for this peer.
   */
  struct MessageEntry *messages;

  /**
   * Head of the batched, encrypted message queue (already ordered,
   * transmit starting with the head).
   */
  struct MessageEntry *encrypted_head;

  /**
   * Tail of the batched, encrypted message queue (already ordered,
   * append new messages to tail)
   */
  struct MessageEntry *encrypted_tail;

  /**
   * Handle for pending requests for transmission to this peer
   * with the transport service.  NULL if no request is pending.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  /**
   * Public key of the neighbour, NULL if we don't have it yet.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key;

  /**
   * We received a PING message before we got the "public_key"
   * (or the SET_KEY).  We keep it here until we have a key
   * to decrypt it.  NULL if no PING is pending.
   */
  struct PingMessage *pending_ping;

  /**
   * We received a PONG message before we got the "public_key"
   * (or the SET_KEY).  We keep it here until we have a key
   * to decrypt it.  NULL if no PONG is pending.
   */
  struct PongMessage *pending_pong;

  /**
   * Non-NULL if we are currently looking up HELLOs for this peer.
   * for this peer.
   */
  struct GNUNET_PEERINFO_IteratorContext *pitr;

  /**
   * SetKeyMessage to transmit, NULL if we are not currently trying
   * to send one.
   */
  struct SetKeyMessage *skm;

  /**
   * Identity of the neighbour.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Key we use to encrypt our messages for the other peer
   * (initialized by us when we do the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey encrypt_key;

  /**
   * Key we use to decrypt messages from the other peer
   * (given to us by the other peer during the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey decrypt_key;

  /**
   * ID of task used for re-trying plaintext scheduling.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_plaintext_task;

  /**
   * ID of task used for re-trying SET_KEY and PING message.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_set_key_task;

  /**
   * ID of task used for updating bandwidth quota for this neighbour.
   */
  GNUNET_SCHEDULER_TaskIdentifier quota_update_task;

  /**
   * ID of task used for sending keep-alive pings.
   */
  GNUNET_SCHEDULER_TaskIdentifier keep_alive_task;

  /**
   * ID of task used for cleaning up dead neighbour entries.
   */
  GNUNET_SCHEDULER_TaskIdentifier dead_clean_task;

  /**
   * At what time did we generate our encryption key?
   */
  struct GNUNET_TIME_Absolute encrypt_key_created;

  /**
   * At what time did the other peer generate the decryption key?
   */
  struct GNUNET_TIME_Absolute decrypt_key_created;

  /**
   * At what time did we initially establish (as in, complete session
   * key handshake) this connection?  Should be zero if status != KEY_CONFIRMED.
   */
  struct GNUNET_TIME_Absolute time_established;

  /**
   * At what time did we last receive an encrypted message from the
   * other peer?  Should be zero if status != KEY_CONFIRMED.
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Last latency observed from this peer.
   */
  struct GNUNET_TIME_Relative last_latency;

  /**
   * At what frequency are we currently re-trying SET_KEY messages?
   */
  struct GNUNET_TIME_Relative set_key_retry_frequency;

  /**
   * Tracking bandwidth for sending to this peer.
   */
  struct GNUNET_BANDWIDTH_Tracker available_send_window;

  /**
   * Tracking bandwidth for receiving from this peer.
   */
  struct GNUNET_BANDWIDTH_Tracker available_recv_window;

  /**
   * How valueable were the messages of this peer recently?
   */
  unsigned long long current_preference;

  /**
   * Bit map indicating which of the 32 sequence numbers before the last
   * were received (good for accepting out-of-order packets and
   * estimating reliability of the connection)
   */
  unsigned int last_packets_bitmap;

  /**
   * last sequence number received on this connection (highest)
   */
  uint32_t last_sequence_number_received;

  /**
   * last sequence number transmitted
   */
  uint32_t last_sequence_number_sent;

  /**
   * Available bandwidth in for this peer (current target).
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_in;    

  /**
   * Available bandwidth out for this peer (current target).
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out;  

  /**
   * Internal bandwidth limit set for this peer (initially typically
   * set to "-1").  Actual "bw_out" is MIN of
   * "bpm_out_internal_limit" and "bw_out_external_limit".
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out_internal_limit;

  /**
   * External bandwidth limit set for this peer by the
   * peer that we are communicating with.  "bw_out" is MIN of
   * "bw_out_internal_limit" and "bw_out_external_limit".
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out_external_limit;

  /**
   * What was our PING challenge number (for this peer)?
   */
  uint32_t ping_challenge;

  /**
   * What was the last distance to this peer as reported by the transports?
   */
  uint32_t last_distance;

  /**
   * What is our connection status?
   */
  enum PeerStateMachine status;

  /**
   * Are we currently connected to this neighbour?
   */ 
  int is_connected;

};


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
 * Our server.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * Transport service.
 */
static struct GNUNET_TRANSPORT_Handle *transport;

/**
 * Linked list of our clients.
 */
static struct Client *clients;

/**
 * Context for notifications we need to send to our clients.
 */
static struct GNUNET_SERVER_NotificationContext *notifier;

/**
 * We keep neighbours in a linked list (for now).
 */
static struct Neighbour *neighbours;

/**
 * For creating statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Sum of all preferences among all neighbours.
 */
static unsigned long long preference_sum;

/**
 * Total number of neighbours we have.
 */
static unsigned int neighbour_count;

/**
 * How much inbound bandwidth are we supposed to be using per second?
 * FIXME: this value is not used!
 */
static unsigned long long bandwidth_target_in_bps;

/**
 * How much outbound bandwidth are we supposed to be using per second?
 */
static unsigned long long bandwidth_target_out_bps;



/**
 * A preference value for a neighbour was update.  Update
 * the preference sum accordingly.
 *
 * @param inc how much was a preference value increased?
 */
static void
update_preference_sum (unsigned long long inc)
{
  struct Neighbour *n;
  unsigned long long os;

  os = preference_sum;
  preference_sum += inc;
  if (preference_sum >= os)
    return; /* done! */
  /* overflow! compensate by cutting all values in half! */
  preference_sum = 0;
  n = neighbours;
  while (n != NULL)
    {
      n->current_preference /= 2;
      preference_sum += n->current_preference;
      n = n->next;
    }    
  GNUNET_STATISTICS_set (stats, gettext_noop ("# total peer preference"), preference_sum, GNUNET_NO);
}


/**
 * Find the entry for the given neighbour.
 *
 * @param peer identity of the neighbour
 * @return NULL if we are not connected, otherwise the
 *         neighbour's entry.
 */
static struct Neighbour *
find_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  struct Neighbour *ret;

  ret = neighbours;
  while ((ret != NULL) &&
         (0 != memcmp (&ret->peer,
                       peer, sizeof (struct GNUNET_PeerIdentity))))
    ret = ret->next;
  return ret;
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
              "Preparing to send message of type %u to client.\n",
              ntohs (msg->type));
#endif  
  GNUNET_SERVER_notification_context_unicast (notifier,
					      client->client_handle,
					      msg,
					      can_drop);
}


/**
 * Send a message to all of our current clients that have
 * the right options set.
 * 
 * @param msg message to multicast
 * @param can_drop can this message be discarded if the queue is too long
 * @param options mask to use 
 */
static void
send_to_all_clients (const struct GNUNET_MessageHeader *msg, 
		     int can_drop,
		     int options)
{
  struct Client *c;

  c = clients;
  while (c != NULL)
    {
      if (0 != (c->options & options))
	{
#if DEBUG_CORE_CLIENT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Sending message of type %u to client.\n",
		      ntohs (msg->type));
#endif
	  send_to_client (c, msg, can_drop);
	}
      c = c->next;
    }
}


/**
 * Handle CORE_INIT request.
 */
static void
handle_client_init (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct InitMessage *im;
  struct InitReplyMessage irm;
  struct Client *c;
  uint16_t msize;
  const uint16_t *types;
  uint16_t *wtypes;
  struct Neighbour *n;
  struct ConnectNotifyMessage cnm;
  unsigned int i;

#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting to core service with `%s' message\n",
              "INIT");
#endif
  /* check that we don't have an entry already */
  c = clients;
  while (c != NULL)
    {
      if (client == c->client_handle)
        {
          GNUNET_break (0);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
      c = c->next;
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
  c->next = clients;
  clients = c;
  c->tcnt = msize / sizeof (uint16_t);
  c->types = (const uint16_t *) &c[1];
  wtypes = (uint16_t *) &c[1];
  for (i=0;i<c->tcnt;i++)
    wtypes[i] = ntohs (types[i]);
  c->options = ntohl (im->options);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p is interested in %u message types\n",
	      c,
	      c->tcnt);
#endif
  /* send init reply message */
  irm.header.size = htons (sizeof (struct InitReplyMessage));
  irm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY);
  irm.reserved = htonl (0);
  memcpy (&irm.publicKey,
          &my_public_key,
          sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending `%s' message to client.\n", "INIT_REPLY");
#endif
  send_to_client (c, &irm.header, GNUNET_NO);
  if (0 != (c->options & GNUNET_CORE_OPTION_SEND_CONNECT))
    {
      /* notify new client about existing neighbours */
      cnm.header.size = htons (sizeof (struct ConnectNotifyMessage));
      cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
      n = neighbours;
      while (n != NULL)
	{
	  if (n->status == PEER_STATE_KEY_CONFIRMED)
	    {
#if DEBUG_CORE_CLIENT
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Sending `%s' message to client.\n", "NOTIFY_CONNECT");
#endif
	      cnm.distance = htonl (n->last_distance);
	      cnm.latency = GNUNET_TIME_relative_hton (n->last_latency);
	      cnm.peer = n->peer;
	      send_to_client (c, &cnm.header, GNUNET_NO);
	    }
	  n = n->next;
	}
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * A client disconnected, clean up.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Client *pos;
  struct Client *prev;

  if (client == NULL)
    return;
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p has disconnected from core service.\n",
	      client);
#endif
  prev = NULL;
  pos = clients;
  while (pos != NULL)
    {
      if (client == pos->client_handle)
        {
          if (prev == NULL)
            clients = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos);
          return;
        }
      prev = pos;
      pos = pos->next;
    }
  /* client never sent INIT */
}


/**
 * Handle REQUEST_INFO request.
 */
static void
handle_client_request_info (void *cls,
			    struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  const struct RequestInfoMessage *rcm;
  struct Neighbour *n;
  struct ConfigurationInfoMessage cim;
  int32_t want_reserv;
  int32_t got_reserv;
  unsigned long long old_preference;
  struct GNUNET_SERVER_TransmitContext *tc;

#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request.\n", "REQUEST_INFO");
#endif
  rcm = (const struct RequestInfoMessage *) message;
  n = find_neighbour (&rcm->peer);
  memset (&cim, 0, sizeof (cim));
  if (n != NULL) 
    {
      want_reserv = ntohl (rcm->reserve_inbound);
      if (n->bw_out_internal_limit.value__ != rcm->limit_outbound.value__)
	{
	  n->bw_out_internal_limit = rcm->limit_outbound;
	  n->bw_out = GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
						  n->bw_out_external_limit);
	  GNUNET_BANDWIDTH_tracker_update_quota (&n->available_recv_window,
						 n->bw_out);
	  GNUNET_TRANSPORT_set_quota (transport,
				      &n->peer,
				      n->bw_in,
				      n->bw_out,
				      GNUNET_TIME_UNIT_FOREVER_REL,
				      NULL, NULL); 
	}
      if (want_reserv < 0)
        {
	  got_reserv = want_reserv;
        }
      else if (want_reserv > 0)
        {
	  if (GNUNET_BANDWIDTH_tracker_get_delay (&n->available_recv_window,
						  want_reserv).value == 0)
	    got_reserv = want_reserv;
	  else
            got_reserv = 0; /* all or nothing */
        }
      else
	got_reserv = 0;
      GNUNET_BANDWIDTH_tracker_consume (&n->available_recv_window,
					got_reserv);
      old_preference = n->current_preference;
      n->current_preference += GNUNET_ntohll(rcm->preference_change);
      if (old_preference > n->current_preference) 
	{
	  /* overflow; cap at maximum value */
	  n->current_preference = (unsigned long long) -1;
	}
      update_preference_sum (n->current_preference - old_preference);
#if DEBUG_CORE_QUOTA
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received reservation request for %d bytes for peer `%4s', reserved %d bytes\n",
		  (int) want_reserv,
		  GNUNET_i2s (&rcm->peer),
		  (int) got_reserv);
#endif
      cim.reserved_amount = htonl (got_reserv);
      cim.bw_in = n->bw_in;
      cim.bw_out = n->bw_out;
      cim.preference = n->current_preference;
    }
  cim.header.size = htons (sizeof (struct ConfigurationInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO);
  cim.peer = rcm->peer;

#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending `%s' message to client.\n", "CONFIGURATION_INFO");
#endif
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_SERVER_transmit_context_append_message (tc, &cim.header);
  GNUNET_SERVER_transmit_context_run (tc,
				      GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Free the given entry for the neighbour (it has
 * already been removed from the list at this point).
 *
 * @param n neighbour to free
 */
static void
free_neighbour (struct Neighbour *n)
{
  struct MessageEntry *m;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Destroying neighbour entry for peer `%4s'\n",
	      GNUNET_i2s (&n->peer));
  if (n->pitr != NULL)
    {
      GNUNET_PEERINFO_iterate_cancel (n->pitr);
      n->pitr = NULL;
    }
  if (n->skm != NULL)
    {
      GNUNET_free (n->skm);
      n->skm = NULL;
    }
  while (NULL != (m = n->messages))
    {
      n->messages = m->next;
      GNUNET_free (m);
    }
  while (NULL != (m = n->encrypted_head))
    {
      GNUNET_CONTAINER_DLL_remove (n->encrypted_head,
				   n->encrypted_tail,
				   m);
      GNUNET_free (m);
    }
  if (NULL != n->th)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (n->th);
      n->th = NULL;
    }
  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->retry_plaintext_task);
  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->retry_set_key_task);
  if (n->quota_update_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->quota_update_task);
  if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->dead_clean_task);
  if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)    
      GNUNET_SCHEDULER_cancel (sched, n->keep_alive_task);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    GNUNET_STATISTICS_update (stats, gettext_noop ("# established sessions"), -1, GNUNET_NO);
  GNUNET_free_non_null (n->public_key);
  GNUNET_free_non_null (n->pending_ping);
  GNUNET_free_non_null (n->pending_pong);
  GNUNET_free (n);
}


/**
 * Check if we have encrypted messages for the specified neighbour
 * pending, and if so, check with the transport about sending them
 * out.
 *
 * @param n neighbour to check.
 */
static void process_encrypted_neighbour_queue (struct Neighbour *n);


/**
 * Encrypt size bytes from in and write the result to out.  Use the
 * key for outbound traffic of the given neighbour.
 *
 * @param n neighbour we are sending to
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_encrypt (struct Neighbour *n,
            const GNUNET_HashCode * iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  GNUNET_assert (size ==
                 GNUNET_CRYPTO_aes_encrypt (in,
                                            (uint16_t) size,
                                            &n->encrypt_key,
                                            (const struct
                                             GNUNET_CRYPTO_AesInitializationVector
                                             *) iv, out));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes encrypted"), size, GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted %u bytes for `%4s' using key %u\n", size,
              GNUNET_i2s (&n->peer), n->encrypt_key.crc32);
#endif
  return GNUNET_OK;
}


/**
 * Consider freeing the given neighbour since we may not need
 * to keep it around anymore.
 *
 * @param n neighbour to consider discarding
 */
static void
consider_free_neighbour (struct Neighbour *n);


/**
 * Task triggered when a neighbour entry is about to time out 
 * (and we should prevent this by sending a PING).
 *
 * @param cls the 'struct Neighbour'
 * @param tc scheduler context (not used)
 */
static void
send_keep_alive (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_Relative retry;
  struct GNUNET_TIME_Relative left;
  struct MessageEntry *me;
  struct PingMessage pp;
  struct PingMessage *pm;

  n->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
  /* send PING */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PingMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PING_DELAY);
  me->priority = PING_PRIORITY;
  me->size = sizeof (struct PingMessage);
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  pm = (struct PingMessage *) &me[1];
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pp.challenge = htonl (n->ping_challenge);
  pp.target = n->peer;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' and `%s' messages for `%4s'.\n",
              "SET_KEY", "PING", GNUNET_i2s (&n->peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending `%s' to `%4s' with challenge %u encrypted using key %u\n",
              "PING",
              GNUNET_i2s (&n->peer), n->ping_challenge, n->encrypt_key.crc32);
#endif
  do_encrypt (n,
              &n->peer.hashPubKey,
              &pp.challenge,
              &pm->challenge,
              sizeof (struct PingMessage) -
              sizeof (struct GNUNET_MessageHeader));
  process_encrypted_neighbour_queue (n);
  /* reschedule PING job */
  left = GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_add (n->last_activity,
								       GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));
  retry = GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
				    MIN_PING_FREQUENCY);
  n->keep_alive_task 
    = GNUNET_SCHEDULER_add_delayed (sched, 
				    retry,
				    &send_keep_alive,
				    n);

}


/**
 * Task triggered when a neighbour entry might have gotten stale.
 *
 * @param cls the 'struct Neighbour'
 * @param tc scheduler context (not used)
 */
static void
consider_free_task (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

  n->dead_clean_task = GNUNET_SCHEDULER_NO_TASK;
  consider_free_neighbour (n);
}


/**
 * Consider freeing the given neighbour since we may not need
 * to keep it around anymore.
 *
 * @param n neighbour to consider discarding
 */
static void
consider_free_neighbour (struct Neighbour *n)
{ 
  struct Neighbour *pos;
  struct Neighbour *prev;
  struct GNUNET_TIME_Relative left;

  if ( (n->th != NULL) ||
       (n->pitr != NULL) ||
       (n->status == PEER_STATE_KEY_CONFIRMED) ||
       (GNUNET_YES == n->is_connected) )
    return; /* no chance */
  
  left = GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_add (n->last_activity,
								       GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));
  if (left.value > 0)
    {
      if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched, n->dead_clean_task);
      n->dead_clean_task = GNUNET_SCHEDULER_add_delayed (sched,
							 left,
							 &consider_free_task,
							 n);
      return;
    }
  /* actually free the neighbour... */
  prev = NULL;
  pos = neighbours;
  while (pos != n)
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    neighbours = n->next;
  else
    prev->next = n->next;
  GNUNET_assert (neighbour_count > 0);
  neighbour_count--;
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# active neighbours"), 
			 neighbour_count,
			 GNUNET_NO);
  free_neighbour (n);
}


/**
 * Function called when the transport service is ready to
 * receive an encrypted message for the respective peer
 *
 * @param cls neighbour to use message from
 * @param size number of bytes we can transmit
 * @param buf where to copy the message
 * @return number of bytes transmitted
 */
static size_t
notify_encrypted_transmit_ready (void *cls, size_t size, void *buf)
{
  struct Neighbour *n = cls;
  struct MessageEntry *m;
  size_t ret;
  char *cbuf;

  n->th = NULL;
  m = n->encrypted_head;
  if (m == NULL)
    return 0;
  GNUNET_CONTAINER_DLL_remove (n->encrypted_head,
			       n->encrypted_tail,
			       m);
  ret = 0;
  cbuf = buf;
  if (buf != NULL)
    {
      GNUNET_assert (size >= m->size);
      memcpy (cbuf, &m[1], m->size);
      ret = m->size;
      GNUNET_BANDWIDTH_tracker_consume (&n->available_send_window,
					m->size);
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copied message of type %u and size %u into transport buffer for `%4s'\n",
                  ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                  ret, GNUNET_i2s (&n->peer));
#endif
      process_encrypted_neighbour_queue (n);
    }
  else
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission of message of type %u and size %u failed\n",
                  ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                  m->size);
#endif
    }
  GNUNET_free (m);
  consider_free_neighbour (n);
  return ret;
}


/**
 * Check if we have plaintext messages for the specified neighbour
 * pending, and if so, consider batching and encrypting them (and
 * then trigger processing of the encrypted queue if needed).
 *
 * @param n neighbour to check.
 */
static void process_plaintext_neighbour_queue (struct Neighbour *n);


/**
 * Check if we have encrypted messages for the specified neighbour
 * pending, and if so, check with the transport about sending them
 * out.
 *
 * @param n neighbour to check.
 */
static void
process_encrypted_neighbour_queue (struct Neighbour *n)
{
  struct MessageEntry *m;
 
  if (n->th != NULL)
    return;  /* request already pending */
  m = n->encrypted_head;
  if (m == NULL)
    {
      /* encrypted queue empty, try plaintext instead */
      process_plaintext_neighbour_queue (n);
      return;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport for transmission of %u bytes to `%4s' in next %llu ms\n",
              m->size,
              GNUNET_i2s (&n->peer),
              GNUNET_TIME_absolute_get_remaining (m->deadline).
              value);
#endif
  n->th =
    GNUNET_TRANSPORT_notify_transmit_ready (transport, &n->peer,
                                            m->size,
					    m->priority,
                                            GNUNET_TIME_absolute_get_remaining
                                            (m->deadline),
                                            &notify_encrypted_transmit_ready,
                                            n);
  if (n->th == NULL)
    {
      /* message request too large or duplicate request */
      GNUNET_break (0);
      /* discard encrypted message */
      GNUNET_CONTAINER_DLL_remove (n->encrypted_head,
				   n->encrypted_tail,
				   m);
      GNUNET_free (m);
      process_encrypted_neighbour_queue (n);
    }
}


/**
 * Decrypt size bytes from in and write the result to out.  Use the
 * key for inbound traffic of the given neighbour.  This function does
 * NOT do any integrity-checks on the result.
 *
 * @param n neighbour we are receiving from
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_decrypt (struct Neighbour *n,
            const GNUNET_HashCode * iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  if ((n->status != PEER_STATE_KEY_RECEIVED) &&
      (n->status != PEER_STATE_KEY_CONFIRMED))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (size !=
      GNUNET_CRYPTO_aes_decrypt (in,
                                 (uint16_t) size,
                                 &n->decrypt_key,
				 (const struct
                                  GNUNET_CRYPTO_AesInitializationVector *) iv,
                                 out))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes decrypted"), size, GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted %u bytes from `%4s' using key %u\n",
              size, GNUNET_i2s (&n->peer), n->decrypt_key.crc32);
#endif
  return GNUNET_OK;
}


/**
 * Select messages for transmission.  This heuristic uses a combination
 * of earliest deadline first (EDF) scheduling (with bounded horizon)
 * and priority-based discard (in case no feasible schedule exist) and
 * speculative optimization (defer any kind of transmission until
 * we either create a batch of significant size, 25% of max, or until
 * we are close to a deadline).  Furthermore, when scheduling the
 * heuristic also packs as many messages into the batch as possible,
 * starting with those with the earliest deadline.  Yes, this is fun.
 *
 * @param n neighbour to select messages from
 * @param size number of bytes to select for transmission
 * @param retry_time set to the time when we should try again
 *        (only valid if this function returns zero)
 * @return number of bytes selected, or 0 if we decided to
 *         defer scheduling overall; in that case, retry_time is set.
 */
static size_t
select_messages (struct Neighbour *n,
                 size_t size, struct GNUNET_TIME_Relative *retry_time)
{
  struct MessageEntry *pos;
  struct MessageEntry *min;
  struct MessageEntry *last;
  unsigned int min_prio;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delta;
  uint64_t avail;
  struct GNUNET_TIME_Relative slack;     /* how long could we wait before missing deadlines? */
  size_t off;
  uint64_t tsize;
  unsigned int queue_size;
  int discard_low_prio;

  GNUNET_assert (NULL != n->messages);
  now = GNUNET_TIME_absolute_get ();
  /* last entry in linked list of messages processed */
  last = NULL;
  /* should we remove the entry with the lowest
     priority from consideration for scheduling at the
     end of the loop? */
  queue_size = 0;
  tsize = 0;
  pos = n->messages;
  while (pos != NULL)
    {
      queue_size++;
      tsize += pos->size;
      pos = pos->next;
    }
  discard_low_prio = GNUNET_YES;
  while (GNUNET_YES == discard_low_prio)
    {
      min = NULL;
      min_prio = -1;
      discard_low_prio = GNUNET_NO;
      /* calculate number of bytes available for transmission at time "t" */
      avail = GNUNET_BANDWIDTH_tracker_get_available (&n->available_send_window);
      t = now;
      /* how many bytes have we (hypothetically) scheduled so far */
      off = 0;
      /* maximum time we can wait before transmitting anything
         and still make all of our deadlines */
      slack = MAX_CORK_DELAY;
      pos = n->messages;
      /* note that we use "*2" here because we want to look
         a bit further into the future; much more makes no
         sense since new message might be scheduled in the
         meantime... */
      while ((pos != NULL) && (off < size * 2))
        {         
          if (pos->do_transmit == GNUNET_YES)
            {
              /* already removed from consideration */
              pos = pos->next;
              continue;
            }
          if (discard_low_prio == GNUNET_NO)
            {
	      delta = GNUNET_TIME_absolute_get_difference (t, pos->deadline);
	      if (delta.value > 0)
		{
		  // FIXME: HUH? Check!
		  t = pos->deadline;
		  avail += GNUNET_BANDWIDTH_value_get_available_until (n->bw_out,
								       delta);
		}
              if (avail < pos->size)
                {
		  // FIXME: HUH? Check!
                  discard_low_prio = GNUNET_YES;        /* we could not schedule this one! */
                }
              else
                {
                  avail -= pos->size;
                  /* update slack, considering both its absolute deadline
                     and relative deadlines caused by other messages
                     with their respective load */
                  slack = GNUNET_TIME_relative_min (slack,
						    GNUNET_BANDWIDTH_value_get_delay_for (n->bw_out,
											  avail));
                  if (pos->deadline.value <= now.value) 
		    {
		      /* now or never */
		      slack = GNUNET_TIME_UNIT_ZERO;
		    }
		  else if (GNUNET_YES == pos->got_slack)
		    {
		      /* should be soon now! */
		      slack = GNUNET_TIME_relative_min (slack,
							GNUNET_TIME_absolute_get_remaining (pos->slack_deadline));
		    }
                  else
		    {
		      slack =
			GNUNET_TIME_relative_min (slack, 
						  GNUNET_TIME_absolute_get_difference (now, pos->deadline));
		      pos->got_slack = GNUNET_YES;
		      pos->slack_deadline = GNUNET_TIME_absolute_min (pos->deadline,
								      GNUNET_TIME_relative_to_absolute (MAX_CORK_DELAY));
		    }
                }
            }
          off += pos->size;
          t = GNUNET_TIME_absolute_max (pos->deadline, t); // HUH? Check!
          if (pos->priority <= min_prio)
            {
              /* update min for discard */
              min_prio = pos->priority;
              min = pos;
            }
          pos = pos->next;
        }
      if (discard_low_prio)
        {
          GNUNET_assert (min != NULL);
          /* remove lowest-priority entry from consideration */
          min->do_transmit = GNUNET_YES;        /* means: discard (for now) */
        }
      last = pos;
    }
  /* guard against sending "tiny" messages with large headers without
     urgent deadlines */
  if ( (slack.value > 0) && 
       (size > 4 * off) &&
       (queue_size <= MAX_PEER_QUEUE_SIZE - 2) )
    {
      /* less than 25% of message would be filled with deadlines still
         being met if we delay by one second or more; so just wait for
         more data; but do not wait longer than 1s (since we don't want
	 to delay messages for a really long time either). */
      *retry_time = MAX_CORK_DELAY;
      /* reset do_transmit values for next time */
      while (pos != last)
        {
          pos->do_transmit = GNUNET_NO;	  
          pos = pos->next;
        }
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Deferring transmission for %llums due to underfull message buffer size (%u/%u)\n",
		  (unsigned long long) slack.value,
		  (unsigned int) off,
		  (unsigned int) size);
#endif
      return 0;
    }
  /* select marked messages (up to size) for transmission */
  off = 0;
  pos = n->messages;
  while (pos != last)
    {
      if ((pos->size <= size) && (pos->do_transmit == GNUNET_NO))
        {
          pos->do_transmit = GNUNET_YES;        /* mark for transmission */
          off += pos->size;
          size -= pos->size;
        }
      else
        pos->do_transmit = GNUNET_NO;   /* mark for not transmitting! */
      pos = pos->next;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %u/%u bytes of %u/%u plaintext messages for transmission to `%4s'.\n",
              off, tsize,
	      queue_size, MAX_PEER_QUEUE_SIZE,
	      GNUNET_i2s (&n->peer));
#endif
  return off;
}


/**
 * Batch multiple messages into a larger buffer.
 *
 * @param n neighbour to take messages from
 * @param buf target buffer
 * @param size size of buf
 * @param deadline set to transmission deadline for the result
 * @param retry_time set to the time when we should try again
 *        (only valid if this function returns zero)
 * @param priority set to the priority of the batch
 * @return number of bytes written to buf (can be zero)
 */
static size_t
batch_message (struct Neighbour *n,
               char *buf,
               size_t size,
               struct GNUNET_TIME_Absolute *deadline,
               struct GNUNET_TIME_Relative *retry_time,
               unsigned int *priority)
{
  char ntmb[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  struct NotifyTrafficMessage *ntm = (struct NotifyTrafficMessage*) ntmb;
  struct MessageEntry *pos;
  struct MessageEntry *prev;
  struct MessageEntry *next;
  size_t ret;
  
  ret = 0;
  *priority = 0;
  *deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  *retry_time = GNUNET_TIME_UNIT_FOREVER_REL;
  if (0 == select_messages (n, size, retry_time))
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No messages selected, will try again in %llu ms\n",
                  retry_time->value);
#endif
      return 0;
    }
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND);
  ntm->distance = htonl (n->last_distance);
  ntm->latency = GNUNET_TIME_relative_hton (n->last_latency);
  ntm->peer = n->peer;
  
  pos = n->messages;
  prev = NULL;
  while ((pos != NULL) && (size >= sizeof (struct GNUNET_MessageHeader)))
    {
      next = pos->next;
      if (GNUNET_YES == pos->do_transmit)
        {
          GNUNET_assert (pos->size <= size);
	  /* do notifications */
	  /* FIXME: track if we have *any* client that wants
	     full notifications and only do this if that is
	     actually true */
	  if (pos->size < GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct NotifyTrafficMessage))
	    {
	      memcpy (&ntm[1], &pos[1], pos->size);
	      ntm->header.size = htons (sizeof (struct NotifyTrafficMessage) + 
					sizeof (struct GNUNET_MessageHeader));
	      send_to_all_clients (&ntm->header,
				   GNUNET_YES,
				   GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND);
	    }
	  else
	    {
	      /* message too large for 'full' notifications, we do at
		 least the 'hdr' type */
	      memcpy (&ntm[1],
		      &pos[1],
		      sizeof (struct GNUNET_MessageHeader));
	    }
	  ntm->header.size = htons (sizeof (struct NotifyTrafficMessage) + 
				    pos->size);
	  send_to_all_clients (&ntm->header,
			       GNUNET_YES,
			       GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND); 	 
#if DEBUG_HANDSHAKE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Encrypting message of type %u\n",
		      ntohs(((struct GNUNET_MessageHeader*)&pos[1])->type));
#endif
	  /* copy for encrypted transmission */
          memcpy (&buf[ret], &pos[1], pos->size);
          ret += pos->size;
          size -= pos->size;
          *priority += pos->priority;
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Adding plaintext message of size %u with deadline %llu ms to batch\n",
		      pos->size,
		      GNUNET_TIME_absolute_get_remaining (pos->deadline).value);
#endif
          deadline->value = GNUNET_MIN (deadline->value, pos->deadline.value);
          GNUNET_free (pos);
          if (prev == NULL)
            n->messages = next;
          else
            prev->next = next;
        }
      else
        {
          prev = pos;
        }
      pos = next;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Deadline for message batch is %llu ms\n",
	      GNUNET_TIME_absolute_get_remaining (*deadline).value);
#endif
  return ret;
}


/**
 * Remove messages with deadlines that have long expired from
 * the queue.
 *
 * @param n neighbour to inspect
 */
static void
discard_expired_messages (struct Neighbour *n)
{
  struct MessageEntry *prev;
  struct MessageEntry *next;
  struct MessageEntry *pos;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delta;

  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  pos = n->messages;
  while (pos != NULL) 
    {
      next = pos->next;
      delta = GNUNET_TIME_absolute_get_difference (pos->deadline, now);
      if (delta.value > PAST_EXPIRATION_DISCARD_TIME.value)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      "Message is %llu ms past due, discarding.\n",
		      delta.value);
#endif
	  if (prev == NULL)
	    n->messages = next;
	  else
	    prev->next = next;
	  GNUNET_free (pos);
	}
      else
	prev = pos;
      pos = next;
    }
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
retry_plaintext_processing (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

  n->retry_plaintext_task = GNUNET_SCHEDULER_NO_TASK;
  process_plaintext_neighbour_queue (n);
}


/**
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param n the other peer
 */
static void send_key (struct Neighbour *n);

/**
 * Task that will retry "send_key" if our previous attempt failed
 * to yield a PONG.
 */
static void
set_key_retry_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Retrying key transmission to `%4s'\n",
	      GNUNET_i2s (&n->peer));
#endif
  n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  n->set_key_retry_frequency =
    GNUNET_TIME_relative_multiply (n->set_key_retry_frequency, 2);
  send_key (n);
}


/**
 * Check if we have plaintext messages for the specified neighbour
 * pending, and if so, consider batching and encrypting them (and
 * then trigger processing of the encrypted queue if needed).
 *
 * @param n neighbour to check.
 */
static void
process_plaintext_neighbour_queue (struct Neighbour *n)
{
  char pbuf[MAX_ENCRYPTED_MESSAGE_SIZE];        /* plaintext */
  size_t used;
  size_t esize;
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct MessageEntry *me;
  unsigned int priority;
  struct GNUNET_TIME_Absolute deadline;
  struct GNUNET_TIME_Relative retry_time;
  GNUNET_HashCode iv;

  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, n->retry_plaintext_task);
      n->retry_plaintext_task = GNUNET_SCHEDULER_NO_TASK;
    }
  switch (n->status)
    {
    case PEER_STATE_DOWN:
      send_key (n);
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
		  GNUNET_i2s(&n->peer));
#endif
      return;
    case PEER_STATE_KEY_SENT:
      if (n->retry_set_key_task == GNUNET_SCHEDULER_NO_TASK)
	n->retry_set_key_task
	  = GNUNET_SCHEDULER_add_delayed (sched,
					  n->set_key_retry_frequency,
					  &set_key_retry_task, n);    
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
		  GNUNET_i2s(&n->peer));
#endif
      return;
    case PEER_STATE_KEY_RECEIVED:
      if (n->retry_set_key_task == GNUNET_SCHEDULER_NO_TASK)        
	n->retry_set_key_task
	  = GNUNET_SCHEDULER_add_delayed (sched,
					  n->set_key_retry_frequency,
					  &set_key_retry_task, n);        
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
		  GNUNET_i2s(&n->peer));
#endif
      return;
    case PEER_STATE_KEY_CONFIRMED:
      /* ready to continue */
      break;
    }
  discard_expired_messages (n);
  if (n->messages == NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Plaintext message queue for `%4s' is empty.\n",
		  GNUNET_i2s(&n->peer));
#endif
      return;                   /* no pending messages */
    }
  if (n->encrypted_head != NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Encrypted message queue for `%4s' is still full, delaying plaintext processing.\n",
		  GNUNET_i2s(&n->peer));
#endif
      return;                   /* wait for messages already encrypted to be
                                   processed first! */
    }
  ph = (struct EncryptedMessage *) pbuf;
  deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  priority = 0;
  used = sizeof (struct EncryptedMessage);
  used += batch_message (n,
                         &pbuf[used],
                         MAX_ENCRYPTED_MESSAGE_SIZE - used,
                         &deadline, &retry_time, &priority);
  if (used == sizeof (struct EncryptedMessage))
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No messages selected for transmission to `%4s' at this time, will try again later.\n",
		  GNUNET_i2s(&n->peer));
#endif
      /* no messages selected for sending, try again later... */
      n->retry_plaintext_task =
        GNUNET_SCHEDULER_add_delayed (sched,
                                      retry_time,
                                      &retry_plaintext_processing, n);
      return;
    }
#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending %u b/s as new limit to peer `%4s'\n",
	      (unsigned int) ntohl (n->bw_in.value__),
	      GNUNET_i2s (&n->peer));
#endif
  ph->iv_seed = htonl (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, -1));
  ph->sequence_number = htonl (++n->last_sequence_number_sent);
  ph->inbound_bw_limit = n->bw_in;
  ph->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

  /* setup encryption message header */
  me = GNUNET_malloc (sizeof (struct MessageEntry) + used);
  me->deadline = deadline;
  me->priority = priority;
  me->size = used;
  em = (struct EncryptedMessage *) &me[1];
  em->header.size = htons (used);
  em->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE);
  em->iv_seed = ph->iv_seed;
  esize = used - ENCRYPTED_HEADER_SIZE;
  GNUNET_CRYPTO_hash (&ph->sequence_number,
		      esize - sizeof (GNUNET_HashCode), 
		      &ph->plaintext_hash);
  GNUNET_CRYPTO_hash (&ph->iv_seed, sizeof (uint32_t), &iv);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hashed %u bytes of plaintext (`%s') using IV `%d'\n",
	      esize - sizeof (GNUNET_HashCode),
	      GNUNET_h2s (&ph->plaintext_hash),
	      (int) ph->iv_seed);
#endif
  /* encrypt */
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting %u bytes of plaintext messages for `%4s' for transmission in %llums.\n",
	      esize,
	      GNUNET_i2s(&n->peer),
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (deadline).value);
#endif
  GNUNET_assert (GNUNET_OK ==
                 do_encrypt (n,
                             &iv,
                             &ph->plaintext_hash,
                             &em->plaintext_hash, esize));
  /* append to transmission list */
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  process_encrypted_neighbour_queue (n);
}


/**
 * Function that recalculates the bandwidth quota for the
 * given neighbour and transmits it to the transport service.
 * 
 * @param cls neighbour for the quota update
 * @param tc context
 */
static void
neighbour_quota_update (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Schedule the task that will recalculate the bandwidth
 * quota for this peer (and possibly force a disconnect of
 * idle peers by calculating a bandwidth of zero).
 */
static void
schedule_quota_update (struct Neighbour *n)
{
  GNUNET_assert (n->quota_update_task ==
		 GNUNET_SCHEDULER_NO_TASK);
  n->quota_update_task
    = GNUNET_SCHEDULER_add_delayed (sched,
				    QUOTA_UPDATE_FREQUENCY,
				    &neighbour_quota_update,
				    n);
}


/**
 * Initialize a new 'struct Neighbour'.
 *
 * @param pid ID of the new neighbour
 * @return handle for the new neighbour
 */
static struct Neighbour *
create_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  struct Neighbour *n;
  struct GNUNET_TIME_Absolute now;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating neighbour entry for peer `%4s'\n",
	      GNUNET_i2s (pid));
  n = GNUNET_malloc (sizeof (struct Neighbour));
  n->next = neighbours;
  neighbours = n;
  neighbour_count++;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# active neighbours"), neighbour_count, GNUNET_NO);
  n->peer = *pid;
  GNUNET_CRYPTO_aes_create_session_key (&n->encrypt_key);
  now = GNUNET_TIME_absolute_get ();
  n->encrypt_key_created = now;
  n->last_activity = now;
  n->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  n->bw_in = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out_internal_limit = GNUNET_BANDWIDTH_value_init ((uint32_t) - 1);
  n->bw_out_external_limit = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->ping_challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                (uint32_t) - 1);
  neighbour_quota_update (n, NULL);
  return n;
}


/**
 * Handle CORE_SEND request.
 *
 * @param cls unused
 * @param client the client issuing the request
 * @param message the "struct SendMessage"
 */
static void
handle_client_send (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct SendMessage *sm;
  struct Neighbour *n;
  struct MessageEntry *prev;
  struct MessageEntry *pos;
  struct MessageEntry *e; 
  struct MessageEntry *min_prio_entry;
  struct MessageEntry *min_prio_prev;
  unsigned int min_prio;
  unsigned int queue_size;
  uint16_t msize;

  msize = ntohs (message->size);
  if (msize <
      sizeof (struct SendMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break (0);
      if (client != NULL)
        GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  sm = (const struct SendMessage *) message;
  msize -= sizeof (struct SendMessage);
  if (0 == memcmp (&sm->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      /* FIXME: should we not allow loopback-injection here? */
      GNUNET_break (0);
      if (client != NULL)
        GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  n = find_neighbour (&sm->peer);
  if (n == NULL)
    n = create_neighbour (&sm->peer);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core received `%s' request, queueing %u bytes of plaintext data for transmission to `%4s'.\n",
	      "SEND",
              msize, 
	      GNUNET_i2s (&sm->peer));
#endif
  /* bound queue size */
  discard_expired_messages (n);
  min_prio = (unsigned int) -1;
  min_prio_entry = NULL;
  min_prio_prev = NULL;
  queue_size = 0;
  prev = NULL;
  pos = n->messages;
  while (pos != NULL) 
    {
      if (pos->priority < min_prio)
	{
	  min_prio_entry = pos;
	  min_prio_prev = prev;
	  min_prio = pos->priority;
	}
      queue_size++;
      prev = pos;
      pos = pos->next;
    }
  if (queue_size >= MAX_PEER_QUEUE_SIZE)
    {
      /* queue full */
      if (ntohl(sm->priority) <= min_prio)
	{
	  /* discard new entry */
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Queue full (%u/%u), discarding new request (%u bytes of type %u)\n",
		      queue_size,
		      MAX_PEER_QUEUE_SIZE,
		      msize,
		      ntohs (message->type));
#endif
	  if (client != NULL)
	    GNUNET_SERVER_receive_done (client, GNUNET_OK);
	  return;
	}
      /* discard "min_prio_entry" */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Queue full, discarding existing older request\n");
#endif
      if (min_prio_prev == NULL)
	n->messages = min_prio_entry->next;
      else
	min_prio_prev->next = min_prio_entry->next;      
      GNUNET_free (min_prio_entry);	
    }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding transmission request for `%4s' of size %u to queue\n",
	      GNUNET_i2s (&sm->peer),
	      msize);
#endif  
  e = GNUNET_malloc (sizeof (struct MessageEntry) + msize);
  e->deadline = GNUNET_TIME_absolute_ntoh (sm->deadline);
  e->priority = ntohl (sm->priority);
  e->size = msize;
  memcpy (&e[1], &sm[1], msize);

  /* insert, keep list sorted by deadline */
  prev = NULL;
  pos = n->messages;
  while ((pos != NULL) && (pos->deadline.value < e->deadline.value))
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    n->messages = e;
  else
    prev->next = e;
  e->next = pos;

  /* consider scheduling now */
  process_plaintext_neighbour_queue (n);
  if (client != NULL)
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function called when the transport service is ready to
 * receive a message.  Only resets 'n->th' to NULL.
 *
 * @param cls neighbour to use message from
 * @param size number of bytes we can transmit
 * @param buf where to copy the message
 * @return number of bytes transmitted
 */
static size_t
notify_transport_connect_done (void *cls, size_t size, void *buf)
{
  struct Neighbour *n = cls;

  n->th = NULL;
  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Failed to connect to `%4s': transport failed to connect\n"),
		  GNUNET_i2s (&n->peer));
      return 0;
    }
  send_key (n);
  return 0;
}


/**
 * Handle CORE_REQUEST_CONNECT request.
 *
 * @param cls unused
 * @param client the client issuing the request
 * @param message the "struct ConnectMessage"
 */
static void
handle_client_request_connect (void *cls,
			       struct GNUNET_SERVER_Client *client,
			       const struct GNUNET_MessageHeader *message)
{
  const struct ConnectMessage *cm = (const struct ConnectMessage*) message;
  struct Neighbour *n;
  struct GNUNET_TIME_Relative timeout;

  if (0 == memcmp (&cm->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  n = find_neighbour (&cm->peer);
  if (n == NULL)
    n = create_neighbour (&cm->peer);
  if ( (n->is_connected) ||
       (n->th != NULL) )
    return; /* already connected, or at least trying */
  GNUNET_STATISTICS_update (stats, gettext_noop ("# connection requests received"), 1, GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core received `%s' request for `%4s', will try to establish connection\n",
	      "REQUEST_CONNECT",
	      GNUNET_i2s (&cm->peer));
#endif
  timeout = GNUNET_TIME_relative_ntoh (cm->timeout);
  /* ask transport to connect to the peer */
  n->th = GNUNET_TRANSPORT_notify_transmit_ready (transport,
						  &cm->peer,
						  sizeof (struct GNUNET_MessageHeader), 0,
						  timeout,
						  &notify_transport_connect_done,
						  n);
  GNUNET_break (NULL != n->th);
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_client_init, NULL,
   GNUNET_MESSAGE_TYPE_CORE_INIT, 0},
  {&handle_client_request_info, NULL,
   GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO,
   sizeof (struct RequestInfoMessage)},
  {&handle_client_send, NULL,
   GNUNET_MESSAGE_TYPE_CORE_SEND, 0},
  {&handle_client_request_connect, NULL,
   GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT,
   sizeof (struct ConnectMessage)},
  {NULL, NULL, 0, 0}
};


/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry send_key.  Or, if we did not get a
 * HELLO, just do nothing.
 *
 * @param cls the 'struct Neighbour' to retry sending the key for
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param trust amount of trust we currently have in that peer
 */
static void
process_hello_retry_send_key (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_HELLO_Message *hello,
                              uint32_t trust)
{
  struct Neighbour *n = cls;

  if (peer == NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Entered `process_hello_retry_send_key' and `peer' is NULL!\n");
#endif
      n->pitr = NULL;
      if (n->public_key != NULL)
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# SETKEY messages deferred (need public key)"), 
				    -1, 
				    GNUNET_NO);
	  send_key (n);
	}
      else
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# Delayed connecting due to lack of public key"),
				    1,
				    GNUNET_NO);      
	  if (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task)
	    n->retry_set_key_task
	      = GNUNET_SCHEDULER_add_delayed (sched,
					      n->set_key_retry_frequency,
					      &set_key_retry_task, n);
	}
      return;
    }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Entered `process_hello_retry_send_key' for peer `%4s'\n",
              GNUNET_i2s (peer));
#endif
  if (n->public_key != NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "already have public key for peer %s!! (so why are we here?)\n",
              GNUNET_i2s (peer));
#endif
      return;
    }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received new `%s' message for `%4s', initiating key exchange.\n",
	      "HELLO",
              GNUNET_i2s (peer));
#endif
  n->public_key =
    GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, n->public_key))
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# Error extracting public key from HELLO"),
				1,
				GNUNET_NO);      
      GNUNET_free (n->public_key);
      n->public_key = NULL;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNUNET_HELLO_get_key returned awfully\n");
#endif
      return;
    }
}


/**
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param n the other peer
 */
static void
send_key (struct Neighbour *n)
{
  struct SetKeyMessage *sm;
  struct MessageEntry *me;
  struct PingMessage pp;
  struct PingMessage *pm;

  if ( (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK) ||
       (n->pitr != NULL) )
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Key exchange in progress with `%4s'.\n",
                  GNUNET_i2s (&n->peer));
#endif
      return; /* already in progress */
    }
  if (! n->is_connected)
    {
      if (NULL == n->th)
	{
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# Asking transport to connect (for SETKEY)"), 
				    1, 
				    GNUNET_NO);
	  n->th = GNUNET_TRANSPORT_notify_transmit_ready (transport,
							  &n->peer,
							  sizeof (struct SetKeyMessage) + sizeof (struct PingMessage),
							  0,
							  GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
							  &notify_encrypted_transmit_ready,
							  n);
	}
      return; 
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to perform key exchange with `%4s'.\n",
              GNUNET_i2s (&n->peer));
#endif
  if (n->public_key == NULL)
    {
      /* lookup n's public key, then try again */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Lacking public key for `%4s', trying to obtain one (send_key).\n",
                  GNUNET_i2s (&n->peer));
#endif
      GNUNET_assert (n->pitr == NULL);
      n->pitr = GNUNET_PEERINFO_iterate (cfg,
					 sched,
					 &n->peer,
					 0,
					 GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20),
					 &process_hello_retry_send_key, n);
      return;
    }
  /* first, set key message */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct SetKeyMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_SET_KEY_DELAY);
  me->priority = SET_KEY_PRIORITY;
  me->size = sizeof (struct SetKeyMessage);
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  sm = (struct SetKeyMessage *) &me[1];
  sm->header.size = htons (sizeof (struct SetKeyMessage));
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SET_KEY);
  sm->sender_status = htonl ((int32_t) ((n->status == PEER_STATE_DOWN) ?
                                        PEER_STATE_KEY_SENT : n->status));
  sm->purpose.size =
    htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
           sizeof (struct GNUNET_TIME_AbsoluteNBO) +
           sizeof (struct GNUNET_CRYPTO_RsaEncryptedData) +
           sizeof (struct GNUNET_PeerIdentity));
  sm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SET_KEY);
  sm->creation_time = GNUNET_TIME_absolute_hton (n->encrypt_key_created);
  sm->target = n->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_encrypt (&n->encrypt_key,
                                            sizeof (struct
                                                    GNUNET_CRYPTO_AesSessionKey),
                                            n->public_key,
                                            &sm->encrypted_key));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key, &sm->purpose,
                                         &sm->signature));

  /* second, encrypted PING message */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PingMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PING_DELAY);
  me->priority = PING_PRIORITY;
  me->size = sizeof (struct PingMessage);
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  pm = (struct PingMessage *) &me[1];
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pp.challenge = htonl (n->ping_challenge);
  pp.target = n->peer;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' and `%s' messages for `%4s'.\n",
              "SET_KEY", "PING", GNUNET_i2s (&n->peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending `%s' to `%4s' with challenge %u encrypted using key %u\n",
              "PING",
              GNUNET_i2s (&n->peer), n->ping_challenge, n->encrypt_key.crc32);
#endif
  do_encrypt (n,
              &n->peer.hashPubKey,
              &pp.challenge,
              &pm->challenge,
              sizeof (struct PingMessage) -
              sizeof (struct GNUNET_MessageHeader));
  /* update status */
  switch (n->status)
    {
    case PEER_STATE_DOWN:
      n->status = PEER_STATE_KEY_SENT;
      break;
    case PEER_STATE_KEY_SENT:
      break;
    case PEER_STATE_KEY_RECEIVED:
      break;
    case PEER_STATE_KEY_CONFIRMED:
      break;
    default:
      GNUNET_break (0);
      break;
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# SETKEY and PING messages created"), 
			    1, 
			    GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Have %llu ms left for `%s' transmission.\n",
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (me->deadline).value,
	      "SET_KEY");
#endif
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
  if ( (n->status != PEER_STATE_KEY_CONFIRMED) &&
       (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task) )
    n->retry_set_key_task
      = GNUNET_SCHEDULER_add_delayed (sched,
				      n->set_key_retry_frequency,
				      &set_key_retry_task, n);    
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param n the neighbour from which we received message m
 * @param m the set key message we received
 */
static void
handle_set_key (struct Neighbour *n, const struct SetKeyMessage *m);


/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry handling the set_key message.  Or,
 * if we did not get a HELLO, just free the set key message.
 *
 * @param cls pointer to the set key message
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param trust amount of trust we currently have in that peer
 */
static void
process_hello_retry_handle_set_key (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_HELLO_Message *hello,
                                    uint32_t trust)
{
  struct Neighbour *n = cls;
  struct SetKeyMessage *sm = n->skm;

  if (peer == NULL)
    {
      GNUNET_free (sm);
      n->skm = NULL;
      n->pitr = NULL;
      return;
    }
  if (n->public_key != NULL)
    return;                     /* multiple HELLOs match!? */
  n->public_key =
    GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, n->public_key))
    {
      GNUNET_break_op (0);
      GNUNET_free (n->public_key);
      n->public_key = NULL;
      return;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' for `%4s', continuing processing of `%s' message.\n",
              "HELLO", GNUNET_i2s (peer), "SET_KEY");
#endif
  handle_set_key (n, sm);
}


/**
 * We received a PING message.  Validate and transmit
 * PONG.
 *
 * @param n sender of the PING
 * @param m the encrypted PING message itself
 */
static void
handle_ping (struct Neighbour *n, const struct PingMessage *m)
{
  struct PingMessage t;
  struct PongMessage tx;
  struct PongMessage *tp;
  struct MessageEntry *me;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "PING", GNUNET_i2s (&n->peer));
#endif
  if (GNUNET_OK !=
      do_decrypt (n,
                  &my_identity.hashPubKey,
                  &m->challenge,
                  &t.challenge,
                  sizeof (struct PingMessage) -
                  sizeof (struct GNUNET_MessageHeader)))
    return;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' to `%4s' with challenge %u decrypted using key %u\n",
              "PING",
              GNUNET_i2s (&t.target),
              ntohl (t.challenge), n->decrypt_key.crc32);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Target of `%s' request is `%4s'.\n",
              "PING", GNUNET_i2s (&t.target));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PING messages decrypted"), 
			    1,
			    GNUNET_NO);
  if (0 != memcmp (&t.target,
                   &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      return;
    }
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PongMessage));
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PONG_DELAY);
  me->priority = PONG_PRIORITY;
  me->size = sizeof (struct PongMessage);
  tx.reserved = htonl (0);
  tx.inbound_bw_limit = n->bw_in;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp = (struct PongMessage *) &me[1];
  tp->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp->header.size = htons (sizeof (struct PongMessage));
  do_encrypt (n,
              &my_identity.hashPubKey,
              &tx.challenge,
              &tp->challenge,
              sizeof (struct PongMessage) -
              sizeof (struct GNUNET_MessageHeader));
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# PONG messages created"), 
			    1, 
			    GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' with challenge %u using key %u\n", "PONG",
              ntohl (t.challenge), n->encrypt_key.crc32);
#endif
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
}


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param n sender of the PONG
 * @param m the encrypted PONG message itself
 */
static void
handle_pong (struct Neighbour *n, 
	     const struct PongMessage *m)
{
  struct PongMessage t;
  struct ConnectNotifyMessage cnm;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "PONG", GNUNET_i2s (&n->peer));
#endif
  if (GNUNET_OK !=
      do_decrypt (n,
                  &n->peer.hashPubKey,
                  &m->challenge,
                  &t.challenge,
                  sizeof (struct PongMessage) -
                  sizeof (struct GNUNET_MessageHeader)))
    {
      GNUNET_break_op (0);
      return;
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# PONG messages decrypted"), 
			    1, 
			    GNUNET_NO);
  if (0 != ntohl (t.reserved))
    {
      GNUNET_break_op (0);
      return;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' from `%4s' with challenge %u using key %u\n",
              "PONG",
              GNUNET_i2s (&t.target),
              ntohl (t.challenge), n->decrypt_key.crc32);
#endif
  if ((0 != memcmp (&t.target,
                    &n->peer,
                    sizeof (struct GNUNET_PeerIdentity))) ||
      (n->ping_challenge != ntohl (t.challenge)))
    {
      /* PONG malformed */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received malformed `%s' wanted sender `%4s' with challenge %u\n",
                  "PONG", GNUNET_i2s (&n->peer), n->ping_challenge);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received malformed `%s' received from `%4s' with challenge %u\n",
                  "PONG", GNUNET_i2s (&t.target), ntohl (t.challenge));
#endif
      GNUNET_break_op (0);
      return;
    }
  switch (n->status)
    {
    case PEER_STATE_DOWN:
      GNUNET_break (0);         /* should be impossible */
      return;
    case PEER_STATE_KEY_SENT:
      GNUNET_break (0);         /* should be impossible, how did we decrypt? */
      return;
    case PEER_STATE_KEY_RECEIVED:
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# Session keys confirmed via PONG"), 
				1, 
				GNUNET_NO);
      n->status = PEER_STATE_KEY_CONFIRMED;
      if (n->bw_out_external_limit.value__ != t.inbound_bw_limit.value__)
	{
	  n->bw_out_external_limit = t.inbound_bw_limit;
	  n->bw_out = GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit,
						  n->bw_out_internal_limit);
	  GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window,
						 n->bw_out);       
	  GNUNET_TRANSPORT_set_quota (transport,
				      &n->peer,
				      n->bw_in,
				      n->bw_out,
				      GNUNET_TIME_UNIT_FOREVER_REL,
				      NULL, NULL); 
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Confirmed key via `%s' message for peer `%4s'\n",
                  "PONG", GNUNET_i2s (&n->peer));
#endif      
      if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (sched, n->retry_set_key_task);
          n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
        }      
      cnm.header.size = htons (sizeof (struct ConnectNotifyMessage));
      cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
      cnm.distance = htonl (n->last_distance);
      cnm.latency = GNUNET_TIME_relative_hton (n->last_latency);
      cnm.peer = n->peer;
      send_to_all_clients (&cnm.header, GNUNET_YES, GNUNET_CORE_OPTION_SEND_CONNECT);
      process_encrypted_neighbour_queue (n);
      /* fall-through! */
    case PEER_STATE_KEY_CONFIRMED:
      n->last_activity = GNUNET_TIME_absolute_get ();
      if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched, n->keep_alive_task);
      n->keep_alive_task 
	= GNUNET_SCHEDULER_add_delayed (sched, 
					GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
					&send_keep_alive,
					n);
      break;
    default:
      GNUNET_break (0);
      break;
    }
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param n the neighbour from which we received message m
 * @param m the set key message we received
 */
static void
handle_set_key (struct Neighbour *n, const struct SetKeyMessage *m)
{
  struct SetKeyMessage *m_cpy;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesSessionKey k;
  struct PingMessage *ping;
  struct PongMessage *pong;
  enum PeerStateMachine sender_status;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "SET_KEY", GNUNET_i2s (&n->peer));
#endif
  if (n->public_key == NULL)
    {
      if (n->pitr != NULL)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Ignoring `%s' message due to lack of public key for peer (still trying to obtain one).\n",
		      "SET_KEY");
#endif
	  return;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Lacking public key for peer, trying to obtain one (handle_set_key).\n");
#endif
      m_cpy = GNUNET_malloc (sizeof (struct SetKeyMessage));
      memcpy (m_cpy, m, sizeof (struct SetKeyMessage));
      /* lookup n's public key, then try again */
      GNUNET_assert (n->skm == NULL);
      n->skm = m_cpy;
      n->pitr = GNUNET_PEERINFO_iterate (cfg,
					 sched,
					 &n->peer,
					 0,
					 GNUNET_TIME_UNIT_MINUTES,
					 &process_hello_retry_handle_set_key, n);
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# SETKEY messages deferred (need public key)"), 
				1, 
				GNUNET_NO);
      return;
    }
  if (0 != memcmp (&m->target,
		   &my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Received `%s' message that was for `%s', not for me.  Ignoring.\n"),
		  "SET_KEY",
		  GNUNET_i2s (&m->target));
      return;
    }
  if ((ntohl (m->purpose.size) !=
       sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
       sizeof (struct GNUNET_CRYPTO_RsaEncryptedData) +
       sizeof (struct GNUNET_PeerIdentity)) ||
      (GNUNET_OK !=
       GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_SET_KEY,
                                 &m->purpose, &m->signature, n->public_key)))
    {
      /* invalid signature */
      GNUNET_break_op (0);
      return;
    }
  t = GNUNET_TIME_absolute_ntoh (m->creation_time);
  if (((n->status == PEER_STATE_KEY_RECEIVED) ||
       (n->status == PEER_STATE_KEY_CONFIRMED)) &&
      (t.value < n->decrypt_key_created.value))
    {
      /* this could rarely happen due to massive re-ordering of
         messages on the network level, but is most likely either
         a bug or some adversary messing with us.  Report. */
      GNUNET_break_op (0);
      return;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Decrypting key material.\n");
#endif  
  if ((GNUNET_CRYPTO_rsa_decrypt (my_private_key,
                                  &m->encrypted_key,
                                  &k,
                                  sizeof (struct GNUNET_CRYPTO_AesSessionKey))
       != sizeof (struct GNUNET_CRYPTO_AesSessionKey)) ||
      (GNUNET_OK != GNUNET_CRYPTO_aes_check_session_key (&k)))
    {
      /* failed to decrypt !? */
      GNUNET_break_op (0);
      return;
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# SETKEY messages decrypted"), 
			    1, 
			    GNUNET_NO);
  n->decrypt_key = k;
  if (n->decrypt_key_created.value != t.value)
    {
      /* fresh key, reset sequence numbers */
      n->last_sequence_number_received = 0;
      n->last_packets_bitmap = 0;
      n->decrypt_key_created = t;
    }
  sender_status = (enum PeerStateMachine) ntohl (m->sender_status);
  switch (n->status)
    {
    case PEER_STATE_DOWN:
      n->status = PEER_STATE_KEY_RECEIVED;
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Responding to `%s' with my own key.\n", "SET_KEY");
#endif
      send_key (n);
      break;
    case PEER_STATE_KEY_SENT:
    case PEER_STATE_KEY_RECEIVED:
      n->status = PEER_STATE_KEY_RECEIVED;
      if ((sender_status != PEER_STATE_KEY_RECEIVED) &&
          (sender_status != PEER_STATE_KEY_CONFIRMED))
        {
#if DEBUG_CORE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Responding to `%s' with my own key (other peer has status %u).\n",
                      "SET_KEY", sender_status);
#endif
          send_key (n);
        }
      break;
    case PEER_STATE_KEY_CONFIRMED:
      if ((sender_status != PEER_STATE_KEY_RECEIVED) &&
          (sender_status != PEER_STATE_KEY_CONFIRMED))
        {	  
#if DEBUG_CORE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Responding to `%s' with my own key (other peer has status %u), I was already fully up.\n",
                      "SET_KEY", sender_status);
#endif
          send_key (n);
        }
      break;
    default:
      GNUNET_break (0);
      break;
    }
  if (n->pending_ping != NULL)
    {
      ping = n->pending_ping;
      n->pending_ping = NULL;
      handle_ping (n, ping);
      GNUNET_free (ping);
    }
  if (n->pending_pong != NULL)
    {
      pong = n->pending_pong;
      n->pending_pong = NULL;
      handle_pong (n, pong);
      GNUNET_free (pong);
    }
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
send_p2p_message_to_client (struct Neighbour *sender,
                            struct Client *client,
                            const void *m, size_t msize)
{
  char buf[msize + sizeof (struct NotifyTrafficMessage)];
  struct NotifyTrafficMessage *ntm;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%4s' of type %u to client.\n",
	      GNUNET_i2s(&sender->peer),
              ntohs (((const struct GNUNET_MessageHeader *) m)->type));
#endif
  ntm = (struct NotifyTrafficMessage *) buf;
  ntm->header.size = htons (msize + sizeof (struct NotifyTrafficMessage));
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND);
  ntm->distance = htonl (sender->last_distance);
  ntm->latency = GNUNET_TIME_relative_hton (sender->last_latency);
  ntm->peer = sender->peer;
  memcpy (&ntm[1], m, msize);
  send_to_client (client, &ntm->header, GNUNET_YES);
}


/**
 * Deliver P2P message to interested clients.
 *
 * @param sender who sent us the message?
 * @param m the message
 * @param msize size of the message (including header)
 */
static void
deliver_message (struct Neighbour *sender,
                 const struct GNUNET_MessageHeader *m, size_t msize)
{
  char buf[256];
  struct Client *cpos;
  uint16_t type;
  unsigned int tpos;
  int deliver_full;
  int dropped;

  type = ntohs (m->type);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received encapsulated message of type %u from `%4s'\n",
	      type,
	      GNUNET_i2s (&sender->peer));
#endif
  GNUNET_snprintf (buf,
		   sizeof(buf),
		   gettext_noop ("# bytes of messages of type %u received"),
		   type);
  GNUNET_STATISTICS_set (stats,
			 buf,
			 msize,
			 GNUNET_NO);     
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
		  type,
		  GNUNET_i2s (&sender->peer));
#endif
      /* FIXME: stats... */
    }
}


/**
 * Align P2P message and then deliver to interested clients.
 *
 * @param sender who sent us the message?
 * @param buffer unaligned (!) buffer containing message
 * @param msize size of the message (including header)
 */
static void
align_and_deliver (struct Neighbour *sender, const char *buffer, size_t msize)
{
  char abuf[msize];

  /* TODO: call to statistics? */
  memcpy (abuf, buffer, msize);
  deliver_message (sender, (const struct GNUNET_MessageHeader *) abuf, msize);
}


/**
 * Deliver P2P messages to interested clients.
 *
 * @param sender who sent us the message?
 * @param buffer buffer containing messages, can be modified
 * @param buffer_size size of the buffer (overall)
 * @param offset offset where messages in the buffer start
 */
static void
deliver_messages (struct Neighbour *sender,
                  const char *buffer, size_t buffer_size, size_t offset)
{
  struct GNUNET_MessageHeader *mhp;
  struct GNUNET_MessageHeader mh;
  uint16_t msize;
  int need_align;

  while (offset + sizeof (struct GNUNET_MessageHeader) <= buffer_size)
    {
      if (0 != offset % sizeof (uint16_t))
        {
          /* outch, need to copy to access header */
          memcpy (&mh, &buffer[offset], sizeof (struct GNUNET_MessageHeader));
          mhp = &mh;
        }
      else
        {
          /* can access header directly */
          mhp = (struct GNUNET_MessageHeader *) &buffer[offset];
        }
      msize = ntohs (mhp->size);
      if (msize + offset > buffer_size)
        {
          /* malformed message, header says it is larger than what
             would fit into the overall buffer */
          GNUNET_break_op (0);
          break;
        }
#if HAVE_UNALIGNED_64_ACCESS
      need_align = (0 != offset % 4) ? GNUNET_YES : GNUNET_NO;
#else
      need_align = (0 != offset % 8) ? GNUNET_YES : GNUNET_NO;
#endif
      if (GNUNET_YES == need_align)
        align_and_deliver (sender, &buffer[offset], msize);
      else
        deliver_message (sender,
                         (const struct GNUNET_MessageHeader *)
                         &buffer[offset], msize);
      offset += msize;
    }
}


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 */
static void
handle_encrypted_message (struct Neighbour *n,
                          const struct EncryptedMessage *m)
{
  size_t size = ntohs (m->header.size);
  char buf[size];
  struct EncryptedMessage *pt;  /* plaintext */
  GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  GNUNET_HashCode iv;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "ENCRYPTED_MESSAGE", GNUNET_i2s (&n->peer));
#endif  
  GNUNET_CRYPTO_hash (&m->iv_seed, sizeof (uint32_t), &iv);
  /* decrypt */
  if (GNUNET_OK !=
      do_decrypt (n,
                  &iv,
                  &m->plaintext_hash,
                  &buf[ENCRYPTED_HEADER_SIZE], 
		  size - ENCRYPTED_HEADER_SIZE))
    return;
  pt = (struct EncryptedMessage *) buf;
  /* validate hash */
  GNUNET_CRYPTO_hash (&pt->sequence_number,
                      size - ENCRYPTED_HEADER_SIZE - sizeof (GNUNET_HashCode), &ph);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "V-Hashed %u bytes of plaintext (`%s') using IV `%d'\n",
	      size - ENCRYPTED_HEADER_SIZE - sizeof (GNUNET_HashCode),
	      GNUNET_h2s (&ph),
	      (int) m->iv_seed);
#endif
  if (0 != memcmp (&ph, 
		   &pt->plaintext_hash, 
		   sizeof (GNUNET_HashCode)))
    {
      /* checksum failed */
      GNUNET_break_op (0);
      return;
    }

  /* validate sequence number */
  snum = ntohl (pt->sequence_number);
  if (n->last_sequence_number_received == snum)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Received duplicate message, ignoring.\n");
      /* duplicate, ignore */
      GNUNET_STATISTICS_set (stats,
			     gettext_noop ("# bytes dropped (duplicates)"),
			     size,
			     GNUNET_NO);      
      return;
    }
  if ((n->last_sequence_number_received > snum) &&
      (n->last_sequence_number_received - snum > 32))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Received ancient out of sequence message, ignoring.\n");
      /* ancient out of sequence, ignore */
      GNUNET_STATISTICS_set (stats,
			     gettext_noop ("# bytes dropped (out of sequence)"),
			     size,
			     GNUNET_NO);      
      return;
    }
  if (n->last_sequence_number_received > snum)
    {
      unsigned int rotbit =
        1 << (n->last_sequence_number_received - snum - 1);
      if ((n->last_packets_bitmap & rotbit) != 0)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Received duplicate message, ignoring.\n");
	  GNUNET_STATISTICS_set (stats,
				 gettext_noop ("# bytes dropped (duplicates)"),
				 size,
				 GNUNET_NO);      
          /* duplicate, ignore */
          return;
        }
      n->last_packets_bitmap |= rotbit;
    }
  if (n->last_sequence_number_received < snum)
    {
      n->last_packets_bitmap <<= (snum - n->last_sequence_number_received);
      n->last_sequence_number_received = snum;
    }

  /* check timestamp */
  t = GNUNET_TIME_absolute_ntoh (pt->timestamp);
  if (GNUNET_TIME_absolute_get_duration (t).value > MAX_MESSAGE_AGE.value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Message received far too old (%llu ms). Content ignored.\n"),
                  GNUNET_TIME_absolute_get_duration (t).value);
      GNUNET_STATISTICS_set (stats,
			     gettext_noop ("# bytes dropped (ancient message)"),
			     size,
			     GNUNET_NO);      
      return;
    }

  /* process decrypted message(s) */
  if (n->bw_out_external_limit.value__ != pt->inbound_bw_limit.value__)
    {
#if DEBUG_CORE_SET_QUOTA
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received %u b/s as new inbound limit for peer `%4s'\n",
		  (unsigned int) ntohl (pt->inbound_bw_limit.value__),
		  GNUNET_i2s (&n->peer));
#endif
      n->bw_out_external_limit = pt->inbound_bw_limit;
      n->bw_out = GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit,
					      n->bw_out_internal_limit);
      GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window,
					     n->bw_out);
      GNUNET_TRANSPORT_set_quota (transport,
				  &n->peer,
				  n->bw_in,
				  n->bw_out,
				  GNUNET_TIME_UNIT_FOREVER_REL,
				  NULL, NULL); 
    }
  n->last_activity = GNUNET_TIME_absolute_get ();
  if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, n->keep_alive_task);
  n->keep_alive_task 
    = GNUNET_SCHEDULER_add_delayed (sched, 
				    GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
				    &send_keep_alive,
				    n);
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# bytes of payload decrypted"),
			 size - sizeof (struct EncryptedMessage),
			 GNUNET_NO);      
  deliver_messages (n, buf, size, sizeof (struct EncryptedMessage));
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 * @param latency estimated latency for communicating with the
 *             given peer (round-trip)
 * @param distance in overlay hops, as given by transport plugin
 */
static void
handle_transport_receive (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          struct GNUNET_TIME_Relative latency,
			  unsigned int distance)
{
  struct Neighbour *n;
  struct GNUNET_TIME_Absolute now;
  int up;
  uint16_t type;
  uint16_t size;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %u from `%4s', demultiplexing.\n",
              ntohs (message->type), GNUNET_i2s (peer));
#endif
  if (0 == memcmp (peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      return;
    }
  n = find_neighbour (peer);
  if (n == NULL)
    n = create_neighbour (peer);
  n->last_latency = latency;
  n->last_distance = distance;
  up = (n->status == PEER_STATE_KEY_CONFIRMED);
  type = ntohs (message->type);
  size = ntohs (message->size);
#if DEBUG_HANDSHAKE
  fprintf (stderr,
	   "Received message of type %u from `%4s'\n",
	   type,
	   GNUNET_i2s (peer));
#endif
  switch (type)
    {
    case GNUNET_MESSAGE_TYPE_CORE_SET_KEY:
      if (size != sizeof (struct SetKeyMessage))
        {
          GNUNET_break_op (0);
          return;
        }
      GNUNET_STATISTICS_update (stats, gettext_noop ("# session keys received"), 1, GNUNET_NO);
      handle_set_key (n, (const struct SetKeyMessage *) message);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE:
      if (size < sizeof (struct EncryptedMessage) +
          sizeof (struct GNUNET_MessageHeader))
        {
          GNUNET_break_op (0);
          return;
        }
      if ((n->status != PEER_STATE_KEY_RECEIVED) &&
          (n->status != PEER_STATE_KEY_CONFIRMED))
        {
          GNUNET_break_op (0);
	  /* blacklist briefly (?); might help recover (?) */
	  GNUNET_TRANSPORT_blacklist (sched, cfg,
				      &n->peer, 
				      GNUNET_TIME_UNIT_SECONDS,
				      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
								     5),
				      NULL, NULL);
          return;
        }
      handle_encrypted_message (n, (const struct EncryptedMessage *) message);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_PING:
      if (size != sizeof (struct PingMessage))
        {
          GNUNET_break_op (0);
          return;
        }
      GNUNET_STATISTICS_update (stats, gettext_noop ("# PING messages received"), 1, GNUNET_NO);
      if ((n->status != PEER_STATE_KEY_RECEIVED) &&
          (n->status != PEER_STATE_KEY_CONFIRMED))
        {
#if DEBUG_CORE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Core service receives `%s' request from `%4s' but have not processed key; marking as pending.\n",
                      "PING", GNUNET_i2s (&n->peer));
#endif
          GNUNET_free_non_null (n->pending_ping);
          n->pending_ping = GNUNET_malloc (sizeof (struct PingMessage));
          memcpy (n->pending_ping, message, sizeof (struct PingMessage));
          return;
        }
      handle_ping (n, (const struct PingMessage *) message);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_PONG:
      if (size != sizeof (struct PongMessage))
        {
          GNUNET_break_op (0);
          return;
        }
      GNUNET_STATISTICS_update (stats, gettext_noop ("# PONG messages received"), 1, GNUNET_NO);
      if ( (n->status != PEER_STATE_KEY_RECEIVED) &&
	   (n->status != PEER_STATE_KEY_CONFIRMED) )
        {
#if DEBUG_CORE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Core service receives `%s' request from `%4s' but have not processed key; marking as pending.\n",
                      "PONG", GNUNET_i2s (&n->peer));
#endif
          GNUNET_free_non_null (n->pending_pong);
          n->pending_pong = GNUNET_malloc (sizeof (struct PongMessage));
          memcpy (n->pending_pong, message, sizeof (struct PongMessage));
          return;
        }
      handle_pong (n, (const struct PongMessage *) message);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Unsupported message of type %u received.\n"), type);
      return;
    }
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    {
      now = GNUNET_TIME_absolute_get ();
      n->last_activity = now;
      if (!up)
	{
	  GNUNET_STATISTICS_update (stats, gettext_noop ("# established sessions"), 1, GNUNET_NO);
	  n->time_established = now;
	}
      if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched, n->keep_alive_task);
      n->keep_alive_task 
	= GNUNET_SCHEDULER_add_delayed (sched, 
					GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
					&send_keep_alive,
					n);
    }
}


/**
 * Function that recalculates the bandwidth quota for the
 * given neighbour and transmits it to the transport service.
 * 
 * @param cls neighbour for the quota update
 * @param tc context
 */
static void
neighbour_quota_update (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;
  struct GNUNET_BANDWIDTH_Value32NBO q_in;
  double pref_rel;
  double share;
  unsigned long long distributable;
  uint64_t need_per_peer;
  uint64_t need_per_second;
  
  n->quota_update_task = GNUNET_SCHEDULER_NO_TASK;
  /* calculate relative preference among all neighbours;
     divides by a bit more to avoid division by zero AND to
     account for possibility of new neighbours joining any time 
     AND to convert to double... */
  if (preference_sum == 0)
    {
      pref_rel = 1.0 / (double) neighbour_count;
    }
  else
    {
      pref_rel = n->current_preference / preference_sum;
    }
  need_per_peer = GNUNET_BANDWIDTH_value_get_available_until (MIN_BANDWIDTH_PER_PEER,
							      GNUNET_TIME_UNIT_SECONDS);  
  need_per_second = need_per_peer * neighbour_count;
  distributable = 0;
  if (bandwidth_target_out_bps > need_per_second)
    distributable = bandwidth_target_out_bps - need_per_second;
  share = distributable * pref_rel;
  if (share + need_per_peer > ( (uint32_t)-1))
    q_in = GNUNET_BANDWIDTH_value_init ((uint32_t) -1);
  else
    q_in = GNUNET_BANDWIDTH_value_init (need_per_peer + (uint32_t) share);
  /* check if we want to disconnect for good due to inactivity */
  if ( (GNUNET_TIME_absolute_get_duration (n->last_activity).value > GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.value) &&
       (GNUNET_TIME_absolute_get_duration (n->time_established).value > GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.value) )
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Forcing disconnect of `%4s' due to inactivity (?).\n",
		  GNUNET_i2s (&n->peer));
#endif
      q_in = GNUNET_BANDWIDTH_value_init (0); /* force disconnect */
    }
#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Current quota for `%4s' is %u/%llu b/s in (old: %u b/s) / %u out (%u internal)\n",
	      GNUNET_i2s (&n->peer),
	      (unsigned int) ntohl (q_in.value__),
	      bandwidth_target_out_bps,
	      (unsigned int) ntohl (n->bw_in.value__),
	      (unsigned int) ntohl (n->bw_out.value__),
	      (unsigned int) ntohl (n->bw_out_internal_limit.value__));
#endif
  if (n->bw_in.value__ != q_in.value__) 
    {
      n->bw_in = q_in;
      GNUNET_TRANSPORT_set_quota (transport,
				  &n->peer,
				  n->bw_in,
				  n->bw_out,
				  GNUNET_TIME_UNIT_FOREVER_REL,
				  NULL, NULL);
    }
  schedule_quota_update (n);
}


/**
 * Function called by transport to notify us that
 * a peer connected to us (on the network level).
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param latency current latency of the connection
 * @param distance in overlay hops, as given by transport plugin
 */
static void
handle_transport_notify_connect (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 struct GNUNET_TIME_Relative latency,
				 unsigned int distance)
{
  struct Neighbour *n;
  struct ConnectNotifyMessage cnm;

  if (0 == memcmp (peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      return;
    }
  n = find_neighbour (peer);
  if (n != NULL)
    {
      if (n->is_connected)
	{
	  /* duplicate connect notification!? */
	  GNUNET_break (0);
	  return;
	}
    }
  else
    {
      n = create_neighbour (peer);
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# peers connected"), 
			    1, 
			    GNUNET_NO);
  n->is_connected = GNUNET_YES;      
  n->last_latency = latency;
  n->last_distance = distance;
  GNUNET_BANDWIDTH_tracker_init (&n->available_send_window,
				 n->bw_out,
				 MAX_WINDOW_TIME_S);
  GNUNET_BANDWIDTH_tracker_init (&n->available_recv_window,
				 n->bw_in,
				 MAX_WINDOW_TIME_S);  
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received connection from `%4s'.\n",
              GNUNET_i2s (&n->peer));
#endif
  cnm.header.size = htons (sizeof (struct ConnectNotifyMessage));
  cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_PRE_CONNECT);
  cnm.distance = htonl (n->last_distance);
  cnm.latency = GNUNET_TIME_relative_hton (n->last_latency);
  cnm.peer = *peer;
  send_to_all_clients (&cnm.header, GNUNET_YES, GNUNET_CORE_OPTION_SEND_PRE_CONNECT);
  GNUNET_TRANSPORT_set_quota (transport,
			      &n->peer,
			      n->bw_in,
			      n->bw_out,
			      GNUNET_TIME_UNIT_FOREVER_REL,
			      NULL, NULL);
  send_key (n); 
}


/**
 * Function called by transport telling us that a peer
 * disconnected.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
handle_transport_notify_disconnect (void *cls,
                                    const struct GNUNET_PeerIdentity *peer)
{
  struct DisconnectNotifyMessage cnm;
  struct Neighbour *n;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected from us.\n", GNUNET_i2s (peer));
#endif
  n = find_neighbour (peer);
  if (n == NULL)
    {
      GNUNET_break (0);
      return;
    }
  GNUNET_break (n->is_connected);
  cnm.header.size = htons (sizeof (struct DisconnectNotifyMessage));
  cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT);
  cnm.peer = *peer;
  send_to_all_clients (&cnm.header, GNUNET_YES, GNUNET_CORE_OPTION_SEND_DISCONNECT);
  n->is_connected = GNUNET_NO;
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# peers connected"), 
			    -1, 
			    GNUNET_NO);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n;
  struct Client *c;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core service shutting down.\n");
#endif
  GNUNET_assert (transport != NULL);
  GNUNET_TRANSPORT_disconnect (transport);
  transport = NULL;
  while (NULL != (n = neighbours))
    {
      neighbours = n->next;
      GNUNET_assert (neighbour_count > 0);
      neighbour_count--;
      free_neighbour (n);
    }
  GNUNET_STATISTICS_set (stats, gettext_noop ("# active neighbours"), neighbour_count, GNUNET_NO);
  GNUNET_SERVER_notification_context_destroy (notifier);
  notifier = NULL;
  while (NULL != (c = clients))
    handle_client_disconnect (NULL, c->client_handle);
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  if (stats != NULL)
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
}


/**
 * Initiate core service.
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
  char *keyfile;

  sched = s;
  cfg = c;  
  /* parse configuration */
  if (
       (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_number (c,
                                               "CORE",
                                               "TOTAL_QUOTA_IN",
                                               &bandwidth_target_in_bps)) ||
       (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_number (c,
                                               "CORE",
                                               "TOTAL_QUOTA_OUT",
                                               &bandwidth_target_out_bps)) ||
       (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (c,
                                                 "GNUNETD",
                                                 "HOSTKEY", &keyfile)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Core service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Core service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);
  /* setup notification */
  server = serv;
  notifier = GNUNET_SERVER_notification_context_create (server, 
							MAX_NOTIFY_QUEUE);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  /* setup transport connection */
  transport = GNUNET_TRANSPORT_connect (sched,
                                        cfg,
                                        NULL,
                                        &handle_transport_receive,
                                        &handle_transport_notify_connect,
                                        &handle_transport_notify_disconnect);
  GNUNET_assert (NULL != transport);
  stats = GNUNET_STATISTICS_create (sched, "core", cfg);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Core service of `%4s' ready.\n"), GNUNET_i2s (&my_identity));
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
                              "core",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-core.c */
