/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

#define DEBUG_CORE_QUOTA GNUNET_NO

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
#define MAX_NOTIFY_QUEUE 1024

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
 * What is the maximum delay for a SET_KEY message?
 */
#define MAX_SET_KEY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * How long do we wait for SET_KEY confirmation initially?
 */
#define INITIAL_SET_KEY_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 1)

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
 * State machine for our P2P encryption handshake.  Everyone starts in
 * "DOWN", if we receive the other peer's key (other peer initiated)
 * we start in state RECEIVED (since we will immediately send our
 * own); otherwise we start in SENT.  If we get back a PONG from
 * within either state, we move up to CONFIRMED (the PONG will always
 * be sent back encrypted with the key we sent to the other peer).
 */
enum PeerStateMachine
{
  /**
   * No handshake yet.
   */
  PEER_STATE_DOWN,

  /**
   * We've sent our session key.
   */
  PEER_STATE_KEY_SENT,
  
  /**
   * We've received the other peers session key.
   */
  PEER_STATE_KEY_RECEIVED,

  /**
   * The other peer has confirmed our session key with a message
   * encrypted with his session key (which we got).  Session is now fully up.
   */
  PEER_STATE_KEY_CONFIRMED
};


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
   * Random value used for IV generation.
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * MAC of the encrypted message (starting at 'sequence_number'),
   * used to verify message integrity. Everything after this value
   * (excluding this value itself) will be encrypted and authenticated.
   * ENCRYPTED_HEADER_SIZE must be set to the offset of the *next* field.
   */
  GNUNET_HashCode hmac;

  /**
   * Sequence number, in network byte order.  This field
   * must be the first encrypted/decrypted field
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
 * Number of bytes (at the beginning) of "struct EncryptedMessage"
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE (offsetof(struct EncryptedMessage, sequence_number))


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
   * Seed for the IV
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Random number chosen to make reply harder.
   */
  uint32_t challenge GNUNET_PACKED;
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
   * Seed for the IV
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * Random number to make faking the reply harder.  Must be
   * first field after header (this is where we start to encrypt!).
   */
  uint32_t challenge GNUNET_PACKED;

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
   * If this is a SET_KEY message, what was our connection status when this
   * message was queued?
   */
  enum PeerStateMachine sender_status;

  /**
   * Is this a SET_KEY message?
   */
  int is_setkey;

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


/**
 * Record kept for each request for transmission issued by a 
 * client that is still pending.
 */
struct ClientActiveRequest;

/**
 * Data kept per neighbouring peer.
 */
struct Neighbour
{

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
   * Head of list of requests from clients for transmission to 
   * this peer.
   */
  struct ClientActiveRequest *active_client_request_head;

  /**
   * Tail of list of requests from clients for transmission to 
   * this peer.
   */
  struct ClientActiveRequest *active_client_request_tail;

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
   * Performance data for the peer.
   */ 
  struct GNUNET_TRANSPORT_ATS_Information *ats;

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
   * Number of entries in 'ats'.
   */ 
  unsigned int ats_count;

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
 * Record kept for each request for transmission issued by a 
 * client that is still pending.
 */
struct ClientActiveRequest
{

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct ClientActiveRequest *next;

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct ClientActiveRequest *prev;

  /**
   * Handle to the client.
   */
  struct Client *client;

  /**
   * By what time would the client want to see this message out?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How important is this request.
   */
  uint32_t priority;

  /**
   * How many more requests does this client have?
   */
  uint32_t queue_size;

  /**
   * How many bytes does the client intend to send?
   */
  uint16_t msize;

  /**
   * Unique request ID (in big endian).
   */
  uint16_t smr_id;
  
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
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Our message stream tokenizer (for encrypted payload).
 */
static struct GNUNET_SERVER_MessageStreamTokenizer *mst;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * Map of peer identities to 'struct Neighbour'.
 */
static struct GNUNET_CONTAINER_MultiHashMap *neighbours;

/**
 * Neighbour entry for "this" peer.
 */
static struct Neighbour self;

/**
 * For creating statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Sum of all preferences among all neighbours.
 */
static unsigned long long preference_sum;

/**
 * How much inbound bandwidth are we supposed to be using per second?
 */
static unsigned long long bandwidth_target_in_bps;

/**
 * How much outbound bandwidth are we supposed to be using per second?
 */
static unsigned long long bandwidth_target_out_bps;

/**
 * Derive an authentication key from "set key" information
 */
static void
derive_auth_key (struct GNUNET_CRYPTO_AuthKey *akey,
    const struct GNUNET_CRYPTO_AesSessionKey *skey,
    uint32_t seed,
    struct GNUNET_TIME_Absolute creation_time)
{
  static const char ctx[] = "authentication key";
  struct GNUNET_TIME_AbsoluteNBO ctbe;


  ctbe = GNUNET_TIME_absolute_hton (creation_time);
  GNUNET_CRYPTO_hmac_derive_key (akey,
                                 skey,
                                 &seed,
                                 sizeof(seed),
                                 &skey->key,
                                 sizeof(skey->key),
                                 &ctbe,
                                 sizeof(ctbe),
                                 ctx,
                                 sizeof(ctx), NULL);
}


/**
 * Derive an IV from packet information
 */
static void
derive_iv (struct GNUNET_CRYPTO_AesInitializationVector *iv,
    const struct GNUNET_CRYPTO_AesSessionKey *skey, uint32_t seed,
    const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "initialization vector";

  GNUNET_CRYPTO_aes_derive_iv (iv,
                               skey,
                               &seed,
                               sizeof(seed),
                               &identity->hashPubKey.bits,
                               sizeof(identity->hashPubKey.bits),
                               ctx,
                               sizeof(ctx), NULL);
}

/**
 * Derive an IV from pong packet information
 */
static void
derive_pong_iv (struct GNUNET_CRYPTO_AesInitializationVector *iv,
    const struct GNUNET_CRYPTO_AesSessionKey *skey, uint32_t seed,
    uint32_t challenge, const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "pong initialization vector";

  GNUNET_CRYPTO_aes_derive_iv (iv,
                               skey,
                               &seed,
                               sizeof(seed),
                               &identity->hashPubKey.bits,
                               sizeof(identity->hashPubKey.bits),
                               &challenge,
                               sizeof(challenge),
                               ctx,
                               sizeof(ctx), NULL);
}


/**
 * At what time should the connection to the given neighbour
 * time out (given no further activity?)
 *
 * @param n neighbour in question
 * @return absolute timeout
 */
static struct GNUNET_TIME_Absolute 
get_neighbour_timeout (struct Neighbour *n)
{
  return GNUNET_TIME_absolute_add (n->last_activity,
				   GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Helper function for update_preference_sum.
 */
static int
update_preference (void *cls,
		   const GNUNET_HashCode *key,
		   void *value)
{
  unsigned long long *ps = cls;
  struct Neighbour *n = value;

  n->current_preference /= 2;
  *ps += n->current_preference;
  return GNUNET_OK;
}    


/**
 * A preference value for a neighbour was update.  Update
 * the preference sum accordingly.
 *
 * @param inc how much was a preference value increased?
 */
static void
update_preference_sum (unsigned long long inc)
{
  unsigned long long os;

  os = preference_sum;
  preference_sum += inc;
  if (preference_sum >= os)
    return; /* done! */
  /* overflow! compensate by cutting all values in half! */
  preference_sum = 0;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &update_preference,
					 &preference_sum);
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
  return GNUNET_CONTAINER_multihashmap_get (neighbours, &peer->hashPubKey);
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
		      (unsigned int) ntohs (msg->type));
#endif
	  send_to_client (c, msg, can_drop);
	}
      c = c->next;
    }
}


/**
 * Function called by transport telling us that a peer
 * changed status.
 *
 * @param n the peer that changed status
 */
static void
handle_peer_status_change (struct Neighbour *n)
{
  struct PeerStatusNotifyMessage *psnm;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  size_t size;

  if ( (! n->is_connected) ||
       (n->status != PEER_STATE_KEY_CONFIRMED) )
    return;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' changed status\n",
	      GNUNET_i2s (&n->peer));
#endif
  size = sizeof (struct PeerStatusNotifyMessage) +
    n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      /* recovery strategy: throw away performance data */
      GNUNET_array_grow (n->ats,
			 n->ats_count,
			 0);
      size = sizeof (struct PeerStatusNotifyMessage) +
	n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    }
  psnm = (struct PeerStatusNotifyMessage*) buf;
  psnm->header.size = htons (size);
  psnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_STATUS_CHANGE);
  psnm->timeout = GNUNET_TIME_absolute_hton (get_neighbour_timeout (n));
  psnm->bandwidth_in = n->bw_in;
  psnm->bandwidth_out = n->bw_out;
  psnm->peer = n->peer;
  psnm->ats_count = htonl (n->ats_count);
  ats = &psnm->ats;
  memcpy (ats,
	  n->ats,
	  n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  ats[n->ats_count].type = htonl (0);
  ats[n->ats_count].value = htonl (0);
  send_to_all_clients (&psnm->header, 
		       GNUNET_YES, 
		       GNUNET_CORE_OPTION_SEND_STATUS_CHANGE);
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# peer status changes"), 
			    1, 
			    GNUNET_NO);
}


/**
 * Go over our message queue and if it is not too long, go
 * over the pending requests from clients for this
 * neighbour and send some clients a 'READY' notification.
 *
 * @param n which peer to process
 */
static void
schedule_peer_messages (struct Neighbour *n)
{
  struct SendMessageReady smr;
  struct ClientActiveRequest *car;
  struct ClientActiveRequest *pos;
  struct Client *c;
  struct MessageEntry *mqe;
  unsigned int queue_size;
  
  /* check if neighbour queue is empty enough! */
  if (n != &self)
    {
      queue_size = 0;
      mqe = n->messages;
      while (mqe != NULL) 
	{
	  queue_size++;
	  mqe = mqe->next;
	}
      if (queue_size >= MAX_PEER_QUEUE_SIZE)
	{
#if DEBUG_CORE_CLIENT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Not considering client transmission requests: queue full\n");
#endif
	  return; /* queue still full */
	}
      /* find highest priority request */
      pos = n->active_client_request_head;
      car = NULL;
      while (pos != NULL)
	{
	  if ( (car == NULL) ||
	       (pos->priority > car->priority) )
	    car = pos;
	  pos = pos->next;
	}
    }
  else
    {
      car = n->active_client_request_head;
    }
  if (car == NULL)
    return; /* no pending requests */
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Permitting client transmission request to `%s'\n",
	      GNUNET_i2s (&n->peer));
#endif
  c = car->client;
  GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
			       n->active_client_request_tail,
			       car);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (c->requests,
						       &n->peer.hashPubKey,
						       car));  
  smr.header.size = htons (sizeof (struct SendMessageReady));
  smr.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND_READY);
  smr.size = htons (car->msize);
  smr.smr_id = car->smr_id;
  smr.peer = n->peer;
  send_to_client (c, &smr.header, GNUNET_NO);
  GNUNET_free (car);
}


/**
 * Handle CORE_SEND_REQUEST message.
 */
static void
handle_client_send_request (void *cls,
			    struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  const struct SendMessageRequest *req;
  struct Neighbour *n;
  struct Client *c;
  struct ClientActiveRequest *car;

  req = (const struct SendMessageRequest*) message;
  if (0 == memcmp (&req->peer,
		   &my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
    n = &self;
  else
    n = find_neighbour (&req->peer);
  if ( (n == NULL) ||
       (GNUNET_YES != n->is_connected) ||
       (n->status != PEER_STATE_KEY_CONFIRMED) )
    { 
      /* neighbour must have disconnected since request was issued,
	 ignore (client will realize it once it processes the 
	 disconnect notification) */
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Dropped client request for transmission (am disconnected)\n");
#endif
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# send requests dropped (disconnected)"), 
				1, 
				GNUNET_NO);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  c = clients;
  while ( (c != NULL) &&
	  (c->client_handle != client) )
    c = c->next;
  if (c == NULL)
    {
      /* client did not send INIT first! */
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  if (c->requests == NULL)
    c->requests = GNUNET_CONTAINER_multihashmap_create (16);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received client transmission request. queueing\n");
#endif
  car = GNUNET_CONTAINER_multihashmap_get (c->requests,
					   &req->peer.hashPubKey);
  if (car == NULL)
    {
      /* create new entry */
      car = GNUNET_malloc (sizeof (struct ClientActiveRequest));
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_put (c->requests,
							&req->peer.hashPubKey,
							car,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
      GNUNET_CONTAINER_DLL_insert (n->active_client_request_head,
				   n->active_client_request_tail,
				   car);
      car->client = c;
    }
  car->deadline = GNUNET_TIME_absolute_ntoh (req->deadline);
  car->priority = ntohl (req->priority);
  car->queue_size = ntohl (req->queue_size);
  car->msize = ntohs (req->size);
  car->smr_id = req->smr_id;
  schedule_peer_messages (n);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Notify client about an existing connection to one of our neighbours.
 */
static int
notify_client_about_neighbour (void *cls,
			       const GNUNET_HashCode *key,
			       void *value)
{
  struct Client *c = cls;
  struct Neighbour *n = value;
  size_t size;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  struct ConnectNotifyMessage *cnm;

  size = sizeof (struct ConnectNotifyMessage) +
    (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      /* recovery strategy: throw away performance data */
      GNUNET_array_grow (n->ats,
			 n->ats_count,
			 0);
      size = sizeof (struct ConnectNotifyMessage) +
	(n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    }
  cnm = (struct ConnectNotifyMessage*) buf;	  
  cnm->header.size = htons (size);
  cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  cnm->ats_count = htonl (n->ats_count);
  ats = &cnm->ats;
  memcpy (ats,
	  n->ats,
	  sizeof (struct GNUNET_TRANSPORT_ATS_Information) * n->ats_count);
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    {
#if DEBUG_CORE_CLIENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Sending `%s' message to client.\n", "NOTIFY_CONNECT");
#endif
      cnm->peer = n->peer;
      send_to_client (c, &cnm->header, GNUNET_NO);
    }
  return GNUNET_OK;
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
	      (unsigned int) c->tcnt);
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
      GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					     &notify_client_about_neighbour,
					     c);
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
destroy_active_client_request (void *cls,
			       const GNUNET_HashCode *key,
			       void *value)
{
  struct ClientActiveRequest *car = value;
  struct Neighbour *n;
  struct GNUNET_PeerIdentity peer;

  peer.hashPubKey = *key;
  n = find_neighbour (&peer);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
			       n->active_client_request_tail,
			       car);
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
        break;
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      /* client never sent INIT */
      return;
    }
  if (prev == NULL)
    clients = pos->next;
  else
    prev->next = pos->next;
  if (pos->requests != NULL)
    {
      GNUNET_CONTAINER_multihashmap_iterate (pos->requests,
					     &destroy_active_client_request,
					     NULL);
      GNUNET_CONTAINER_multihashmap_destroy (pos->requests);
    }
  GNUNET_free (pos);
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
queue_connect_message (void *cls,
		       const GNUNET_HashCode *key,
		       void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct Neighbour *n = value;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  size_t size;
  struct ConnectNotifyMessage *cnm;

  cnm = (struct ConnectNotifyMessage*) buf;
  if (n->status != PEER_STATE_KEY_CONFIRMED)
    return GNUNET_OK;
  size = sizeof (struct ConnectNotifyMessage) +
    (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      /* recovery strategy: throw away performance data */
      GNUNET_array_grow (n->ats,
			 n->ats_count,
			 0);
      size = sizeof (struct PeerStatusNotifyMessage) +
	n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    }
  cnm = (struct ConnectNotifyMessage*) buf;
  cnm->header.size = htons (size);
  cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  cnm->ats_count = htonl (n->ats_count);
  ats = &cnm->ats;
  memcpy (ats,
	  n->ats,
	  n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);	  
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending `%s' message to client.\n",
	      "NOTIFY_CONNECT");
#endif
  cnm->peer = n->peer;
  GNUNET_SERVER_transmit_context_append_message (tc, 
						 &cnm->header);
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
handle_client_iterate_peers (void *cls,
			     struct GNUNET_SERVER_Client *client,
			     const struct GNUNET_MessageHeader *message)

{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  int msize;
  /* notify new client about existing neighbours */

  msize = ntohs(message->size);
  tc = GNUNET_SERVER_transmit_context_create (client);
  if (msize == sizeof(struct GNUNET_MessageHeader))
    GNUNET_CONTAINER_multihashmap_iterate (neighbours, &queue_connect_message, tc);
  else
    GNUNET_break(0);

  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc,
                                      GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Handle CORE_ITERATE_PEERS request.  Notify client about existing neighbours.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_have_peer (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)

{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct GNUNET_PeerIdentity *peer;

  tc = GNUNET_SERVER_transmit_context_create (client);
  peer = (struct GNUNET_PeerIdentity *) &message[1];
  GNUNET_CONTAINER_multihashmap_get_multiple(neighbours,
					     &peer->hashPubKey, 
					     &queue_connect_message, 
					     tc);
  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc,
                                      GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle REQUEST_INFO request.
 *
 * @param cls unused
 * @param client client sending the request
 * @param message iteration request message
 */
static void
handle_client_request_info (void *cls,
			    struct GNUNET_SERVER_Client *client,
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

  rdelay = GNUNET_TIME_relative_get_zero();
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request.\n", "REQUEST_INFO");
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
  if (n != NULL) 
    {
      want_reserv = ntohl (rcm->reserve_inbound);
      if (n->bw_out_internal_limit.value__ != rcm->limit_outbound.value__)
	{
	  n->bw_out_internal_limit = rcm->limit_outbound;
	  if (n->bw_out.value__ != GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
							       n->bw_out_external_limit).value__)
	    {
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
	      handle_peer_status_change (n);
	    }
	}
      if (want_reserv < 0)
        {
	  got_reserv = want_reserv;
        }
      else if (want_reserv > 0)
        {
	  rdelay = GNUNET_BANDWIDTH_tracker_get_delay (&n->available_recv_window,
						       want_reserv);
	  if (rdelay.rel_value == 0)
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
	  n->current_preference = ULLONG_MAX;
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
      cim.reserve_delay = GNUNET_TIME_relative_hton (rdelay);
      cim.rim_id = rcm->rim_id;
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
  send_to_client (pos, &cim.header, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  struct ClientActiveRequest *car;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Destroying neighbour entry for peer `%4s'\n",
	      GNUNET_i2s (&n->peer));
#endif
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
  while (NULL != (car = n->active_client_request_head))
    {
      GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
				   n->active_client_request_tail,
				   car);
      GNUNET_CONTAINER_multihashmap_remove (car->client->requests,
					    &n->peer.hashPubKey,
					    car);
      GNUNET_free (car);
    }
  if (NULL != n->th)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (n->th);
      n->th = NULL;
    }
  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->retry_plaintext_task);
  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
  if (n->quota_update_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->quota_update_task);
  if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->dead_clean_task);
  if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)    
      GNUNET_SCHEDULER_cancel (n->keep_alive_task);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    GNUNET_STATISTICS_update (stats, 
			      gettext_noop ("# established sessions"), 
			      -1, 
			      GNUNET_NO);
  GNUNET_array_grow (n->ats, n->ats_count, 0);
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
            const struct GNUNET_CRYPTO_AesInitializationVector * iv,
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
                                            iv, out));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes encrypted"), size, GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted %u bytes for `%4s' using key %u, IV %u\n",
	      (unsigned int) size,
              GNUNET_i2s (&n->peer),
	      (unsigned int) n->encrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (iv, sizeof(iv)));
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
  struct GNUNET_CRYPTO_AesInitializationVector iv;

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
  pm->iv_seed = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
      UINT32_MAX);
  derive_iv (&iv, &n->encrypt_key, pm->iv_seed, &n->peer);
  pp.challenge = n->ping_challenge;
  pp.target = n->peer;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' message with challenge %u for `%4s' using key %u, IV %u (salt %u).\n",
              "PING", 
	      (unsigned int) n->ping_challenge,
	      GNUNET_i2s (&n->peer),
	      (unsigned int) n->encrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (&iv, sizeof(iv)),
	      pm->iv_seed);
#endif
  do_encrypt (n,
              &iv,
              &pp.target,
              &pm->target,
              sizeof (struct PingMessage) -
              ((void *) &pm->target - (void *) pm));
  process_encrypted_neighbour_queue (n);
  /* reschedule PING job */
  left = GNUNET_TIME_absolute_get_remaining (get_neighbour_timeout (n));
  retry = GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
				    MIN_PING_FREQUENCY);
  n->keep_alive_task 
    = GNUNET_SCHEDULER_add_delayed (retry,
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
  struct GNUNET_TIME_Relative left;

  if ( (n->th != NULL) ||
       (n->pitr != NULL) ||
       (GNUNET_YES == n->is_connected) )
    return; /* no chance */
    
  left = GNUNET_TIME_absolute_get_remaining (get_neighbour_timeout (n));
  if (left.rel_value > 0)
    {
      if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (n->dead_clean_task);
      n->dead_clean_task = GNUNET_SCHEDULER_add_delayed (left,
							 &consider_free_task,
							 n);
      return;
    }
  /* actually free the neighbour... */
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (neighbours,
						       &n->peer.hashPubKey,
						       n));
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# neighbour entries allocated"), 
			 GNUNET_CONTAINER_multihashmap_size (neighbours),
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
notify_encrypted_transmit_ready (void *cls, 
				 size_t size, 
				 void *buf)
{
  struct Neighbour *n = cls;
  struct MessageEntry *m;
  size_t ret;
  char *cbuf;

  n->th = NULL;
  m = n->encrypted_head;
  if (m == NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Encrypted message queue empty, no messages added to buffer for `%4s'\n",
		  GNUNET_i2s (&n->peer));
#endif
      return 0;
    }
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
                  (unsigned int) ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                  (unsigned int) ret, 
		  GNUNET_i2s (&n->peer));
#endif
      process_encrypted_neighbour_queue (n);
    }
  else
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission of message of type %u and size %u failed\n",
                  (unsigned int) ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                  (unsigned int) m->size);
#endif
    }
  GNUNET_free (m);
  consider_free_neighbour (n);
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# encrypted bytes given to transport"), 
			    ret, 
			    GNUNET_NO);
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
              (unsigned int) m->size,
              GNUNET_i2s (&n->peer),
              (unsigned long long) GNUNET_TIME_absolute_get_remaining (m->deadline).rel_value);
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
            const struct GNUNET_CRYPTO_AesInitializationVector * iv,
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
				 iv,
                                 out))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# bytes decrypted"), 
			    size, 
			    GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted %u bytes from `%4s' using key %u, IV %u\n",
              (unsigned int) size, 
	      GNUNET_i2s (&n->peer),
	      (unsigned int) n->decrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (iv, sizeof(*iv)));
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
      min_prio = UINT_MAX;
      discard_low_prio = GNUNET_NO;
      /* calculate number of bytes available for transmission at time "t" */
      avail = GNUNET_BANDWIDTH_tracker_get_available (&n->available_send_window);
      t = now;
      /* how many bytes have we (hypothetically) scheduled so far */
      off = 0;
      /* maximum time we can wait before transmitting anything
         and still make all of our deadlines */
      slack = GNUNET_TIME_UNIT_FOREVER_REL;
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
	      if (delta.rel_value > 0)
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
                  if (pos->deadline.abs_value <= now.abs_value) 
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
								      GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_MAX_CORK_DELAY));
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
  if ( (slack.rel_value > GNUNET_CONSTANTS_MAX_CORK_DELAY.rel_value) && 
       (size > 4 * off) &&
       (queue_size <= MAX_PEER_QUEUE_SIZE - 2) )
    {
      /* less than 25% of message would be filled with deadlines still
         being met if we delay by one second or more; so just wait for
         more data; but do not wait longer than 1s (since we don't want
	 to delay messages for a really long time either). */
      *retry_time = GNUNET_CONSTANTS_MAX_CORK_DELAY;
      /* reset do_transmit values for next time */
      while (pos != last)
        {
          pos->do_transmit = GNUNET_NO;	  
          pos = pos->next;
        }
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# transmissions delayed due to corking"), 
				1, GNUNET_NO);
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Deferring transmission for %llums due to underfull message buffer size (%u/%u)\n",
		  (unsigned long long) retry_time->rel_value,
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
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Selecting message of size %u for transmission\n",
		      (unsigned int) pos->size);
#endif
        }
      else
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Not selecting message of size %u for transmission at this time (maximum is %u)\n",
		      (unsigned int) pos->size,
		      size);
#endif
	  pos->do_transmit = GNUNET_NO;   /* mark for not transmitting! */
	}
      pos = pos->next;
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %llu/%llu bytes of %u/%u plaintext messages for transmission to `%4s'.\n",
              (unsigned long long) off, (unsigned long long) tsize,
	      queue_size, (unsigned int) MAX_PEER_QUEUE_SIZE,
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
  char ntmb[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
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
                  retry_time->rel_value);
#endif
      return 0;
    }
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND);
  ntm->ats_count = htonl (0);
  ntm->ats.type = htonl (0);
  ntm->ats.value = htonl (0);
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
		      "Encrypting %u bytes with message of type %u and size %u\n",
		      pos->size,
		      (unsigned int) ntohs(((const struct GNUNET_MessageHeader*)&pos[1])->type),
		      (unsigned int) ntohs(((const struct GNUNET_MessageHeader*)&pos[1])->size));
#endif
	  /* copy for encrypted transmission */
          memcpy (&buf[ret], &pos[1], pos->size);
          ret += pos->size;
          size -= pos->size;
          *priority += pos->priority;
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Adding plaintext message of size %u with deadline %llu ms to batch\n",
		      (unsigned int) pos->size,
		      (unsigned long long) GNUNET_TIME_absolute_get_remaining (pos->deadline).rel_value);
#endif
          deadline->abs_value = GNUNET_MIN (deadline->abs_value, pos->deadline.abs_value);
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
	      GNUNET_TIME_absolute_get_remaining (*deadline).rel_value);
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
  int disc;

  disc = GNUNET_NO;
  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  pos = n->messages;
  while (pos != NULL) 
    {
      next = pos->next;
      delta = GNUNET_TIME_absolute_get_difference (pos->deadline, now);
      if (delta.rel_value > PAST_EXPIRATION_DISCARD_TIME.rel_value)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      "Message is %llu ms past due, discarding.\n",
		      delta.rel_value);
#endif
	  if (prev == NULL)
	    n->messages = next;
	  else
	    prev->next = next;
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# messages discarded (expired prior to transmission)"), 
				    1, 
				    GNUNET_NO);
	  disc = GNUNET_YES;
	  GNUNET_free (pos);
	}
      else
	prev = pos;
      pos = next;
    }
  if (GNUNET_YES == disc)
    schedule_peer_messages (n);
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
  char pbuf[GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE + sizeof (struct EncryptedMessage)];        /* plaintext */
  size_t used;
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct MessageEntry *me;
  unsigned int priority;
  struct GNUNET_TIME_Absolute deadline;
  struct GNUNET_TIME_Relative retry_time;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (n->retry_plaintext_task);
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
	  = GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
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
	  = GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
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
                         GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE,
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
        GNUNET_SCHEDULER_add_delayed (retry_time,
                                      &retry_plaintext_processing, n);
      return;
    }
#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending %u b/s as new limit to peer `%4s'\n",
	      (unsigned int) ntohl (n->bw_in.value__),
	      GNUNET_i2s (&n->peer));
#endif
  ph->iv_seed = htonl (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX));
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
  derive_iv (&iv, &n->encrypt_key, ph->iv_seed, &n->peer);
  /* encrypt */
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting %u bytes of plaintext messages for `%4s' for transmission in %llums.\n",
	      (unsigned int) used - ENCRYPTED_HEADER_SIZE,
	      GNUNET_i2s(&n->peer),
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (deadline).rel_value);
#endif
  GNUNET_assert (GNUNET_OK ==
                 do_encrypt (n,
                             &iv,
                             &ph->sequence_number,
                             &em->sequence_number, used - ENCRYPTED_HEADER_SIZE));
  derive_auth_key (&auth_key,
                   &n->encrypt_key,
                   ph->iv_seed,
                   n->encrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key,
                      &em->sequence_number,
                      used - ENCRYPTED_HEADER_SIZE,
                      &em->hmac);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Authenticated %u bytes of ciphertext %u: `%s'\n",
              used - ENCRYPTED_HEADER_SIZE,
              GNUNET_CRYPTO_crc32_n (&em->sequence_number,
                  used - ENCRYPTED_HEADER_SIZE),
              GNUNET_h2s (&em->hmac));
#endif
  /* append to transmission list */
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  process_encrypted_neighbour_queue (n);
  schedule_peer_messages (n);
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
    = GNUNET_SCHEDULER_add_delayed (QUOTA_UPDATE_FREQUENCY,
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

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating neighbour entry for peer `%4s'\n",
	      GNUNET_i2s (pid));
#endif
  n = GNUNET_malloc (sizeof (struct Neighbour));
  n->peer = *pid;
  GNUNET_CRYPTO_aes_create_session_key (&n->encrypt_key);
  now = GNUNET_TIME_absolute_get ();
  n->encrypt_key_created = now;
  n->last_activity = now;
  n->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  n->bw_in = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out_internal_limit = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  n->bw_out_external_limit = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->ping_challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                UINT32_MAX);
  GNUNET_assert (GNUNET_OK == 
		 GNUNET_CONTAINER_multihashmap_put (neighbours,
						    &n->peer.hashPubKey,
						    n,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (stats, gettext_noop ("# neighbour entries allocated"), 
			 GNUNET_CONTAINER_multihashmap_size (neighbours), GNUNET_NO);
  neighbour_quota_update (n, NULL);
  consider_free_neighbour (n);
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
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "about to assert fail, msize is %d, should be at least %d\n", msize, sizeof (struct SendMessage) + sizeof (struct GNUNET_MessageHeader));
      GNUNET_break (0);
      if (client != NULL)
        GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  sm = (const struct SendMessage *) message;
  msize -= sizeof (struct SendMessage);
  if (0 == memcmp (&sm->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      /* loopback */
      GNUNET_SERVER_mst_receive (mst,
				 &self,
				 (const char*) &sm[1],
				 msize,
				 GNUNET_YES,
				 GNUNET_NO);
      if (client != NULL)
        GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  n = find_neighbour (&sm->peer);
  if (n == NULL)
    n = create_neighbour (&sm->peer);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core received `%s' request, queueing %u bytes of plaintext data for transmission to `%4s'.\n",
	      "SEND",
              (unsigned int) msize, 
	      GNUNET_i2s (&sm->peer));
#endif
  discard_expired_messages (n);
  /* bound queue size */
  /* NOTE: this entire block to bound the queue size should be
     obsolete with the new client-request code and the
     'schedule_peer_messages' mechanism; we still have this code in
     here for now as a sanity check for the new mechanmism;
     ultimately, we should probably simply reject SEND messages that
     are not 'approved' (or provide a new core API for very unreliable
     delivery that always sends with priority 0).  Food for thought. */
  min_prio = UINT32_MAX;
  min_prio_entry = NULL;
  min_prio_prev = NULL;
  queue_size = 0;
  prev = NULL;
  pos = n->messages;
  while (pos != NULL) 
    {
      if (pos->priority <= min_prio)
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
	  /* discard new entry; this should no longer happen! */
	  GNUNET_break (0);
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Queue full (%u/%u), discarding new request (%u bytes of type %u)\n",
		      queue_size,
		      (unsigned int) MAX_PEER_QUEUE_SIZE,
		      (unsigned int) msize,
		      (unsigned int) ntohs (message->type));
#endif
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# discarded CORE_SEND requests"), 
				    1, GNUNET_NO);

	  if (client != NULL)
	    GNUNET_SERVER_receive_done (client, GNUNET_OK);
	  return;
	}
      GNUNET_assert (min_prio_entry != NULL);
      /* discard "min_prio_entry" */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Queue full, discarding existing older request\n");
#endif
	  GNUNET_STATISTICS_update (stats, gettext_noop ("# discarded lower priority CORE_SEND requests"), 1, GNUNET_NO);
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
	      (unsigned int) msize);
#endif  
  GNUNET_break (0 == ntohl (sm->reserved));
  e = GNUNET_malloc (sizeof (struct MessageEntry) + msize);
  e->deadline = GNUNET_TIME_absolute_ntoh (sm->deadline);
  e->priority = ntohl (sm->priority);
  e->size = msize;
  if (GNUNET_YES != (int) ntohl (sm->cork))
    e->got_slack = GNUNET_YES;
  memcpy (&e[1], &sm[1], msize);

  /* insert, keep list sorted by deadline */
  prev = NULL;
  pos = n->messages;
  while ((pos != NULL) && (pos->deadline.abs_value < e->deadline.abs_value))
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
notify_transport_connect_done (void *cls,
			       size_t size,
			       void *buf)
{
  struct Neighbour *n = cls;

  n->th = NULL;
  if (GNUNET_YES != n->is_connected)
    {
      /* transport should only call us to transmit a message after
       * telling us about a successful connection to the respective peer */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Timeout on notify connect!\n");
#endif
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# connection requests timed out in transport"), 
				1,
				GNUNET_NO);
      return 0;
    }
  if (buf == NULL)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# connection requests timed out in transport"),
                                1,
                                GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Failed to connect to `%4s': transport failed to connect\n"),
		  GNUNET_i2s (&n->peer));
      return 0;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("TRANSPORT connection to peer `%4s' is up, trying to establish CORE connection\n"),
	      GNUNET_i2s (&n->peer));
  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
  n->retry_set_key_task = GNUNET_SCHEDULER_add_now (&set_key_retry_task,
						    n);
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

  if (0 == memcmp (&cm->peer, 
		   &my_identity, 
		   sizeof (struct GNUNET_PeerIdentity)))
    {
      /* In this case a client has asked us to connect to ourselves, not really an error! */
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  timeout = GNUNET_TIME_relative_ntoh (cm->timeout);
  GNUNET_break (ntohl (cm->reserved) == 0);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  n = find_neighbour (&cm->peer);
  if (n == NULL)
    n = create_neighbour (&cm->peer);
  if ( (GNUNET_YES == n->is_connected) ||
       (n->th != NULL) )
    {
      if (GNUNET_YES == n->is_connected) 
	GNUNET_STATISTICS_update (stats, 
				  gettext_noop ("# connection requests ignored (already connected)"), 
				  1,
				  GNUNET_NO);
      else
        {
          GNUNET_TRANSPORT_notify_transmit_ready_cancel(n->th);
          n->th = GNUNET_TRANSPORT_notify_transmit_ready (transport,
                                                          &cm->peer,
                                                          sizeof (struct GNUNET_MessageHeader), 0,
                                                          timeout,
                                                          &notify_transport_connect_done,
                                                          n);
          GNUNET_break (NULL != n->th);
          GNUNET_STATISTICS_update (stats,
                                    gettext_noop ("# connection requests retried (due to repeat request connect)"),
                                    1,
                                    GNUNET_NO);
        }
      return; /* already connected, or at least trying */
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# connection requests received"), 
			    1,
			    GNUNET_NO);

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core received `%s' request for `%4s', will try to establish connection\n",
	      "REQUEST_CONNECT",
	      GNUNET_i2s (&cm->peer));
#endif

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
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry send_key.  Or, if we did not get a
 * HELLO, just do nothing.
 *
 * @param cls the 'struct Neighbour' to retry sending the key for
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_hello_retry_send_key (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_HELLO_Message *hello,
                              const char *err_msg)
{
  struct Neighbour *n = cls;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    /* return; */
  }

  if (peer == NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Entered `%s' and `%s' is NULL!\n",
		  "process_hello_retry_send_key",
		  "peer");
#endif
      n->pitr = NULL;
      if (n->public_key != NULL)
	{
	  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
	    {
	      GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
	      n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
	    }      
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# SET_KEY messages deferred (need public key)"), 
				    -1, 
				    GNUNET_NO);
	  send_key (n);
	}
      else
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Failed to obtain public key for peer `%4s', delaying processing of SET_KEY\n",
		      GNUNET_i2s (&n->peer));
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# Delayed connecting due to lack of public key"),
				    1,
				    GNUNET_NO);      
	  if (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task)
	    n->retry_set_key_task
	      = GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
					      &set_key_retry_task, n);
	}
      return;
    }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Entered `%s' for peer `%4s'\n",
	      "process_hello_retry_send_key",
              GNUNET_i2s (peer));
#endif
  if (n->public_key != NULL)
    {
      /* already have public key, why are we here? */
      GNUNET_break (0);
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
  struct MessageEntry *pos;
  struct SetKeyMessage *sm;
  struct MessageEntry *me;
  struct PingMessage pp;
  struct PingMessage *pm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
      n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
    }        
  if (n->pitr != NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Key exchange in progress with `%4s'.\n",
                  GNUNET_i2s (&n->peer));
#endif
      return; /* already in progress */
    }
  if (GNUNET_YES != n->is_connected)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not yet connected to peer `%4s'!\n",
                  GNUNET_i2s (&n->peer));
#endif
      if (NULL == n->th)
	{
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# Asking transport to connect (for SET_KEY)"), 
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
      n->pitr = GNUNET_PEERINFO_iterate (peerinfo,
					 &n->peer,
					 GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20),
					 &process_hello_retry_send_key, n);
      return;
    }
  pos = n->encrypted_head;
  while (pos != NULL)
    {
      if (GNUNET_YES == pos->is_setkey)
	{
	  if (pos->sender_status == n->status)
	    {
#if DEBUG_CORE
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "`%s' message for `%4s' queued already\n",
			  "SET_KEY",
			  GNUNET_i2s (&n->peer));
#endif
	      goto trigger_processing;
	    }
	  GNUNET_CONTAINER_DLL_remove (n->encrypted_head,
				       n->encrypted_tail,
				       pos);
	  GNUNET_free (pos);
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Removing queued `%s' message for `%4s', will create a new one\n",
		      "SET_KEY",
		      GNUNET_i2s (&n->peer));
#endif
	  break;
	}
      pos = pos->next;
    }

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
  

  /* first, set key message */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct SetKeyMessage) +
		      sizeof (struct PingMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_SET_KEY_DELAY);
  me->priority = SET_KEY_PRIORITY;
  me->size = sizeof (struct SetKeyMessage) + sizeof (struct PingMessage);
  me->is_setkey = GNUNET_YES;
  me->got_slack = GNUNET_YES; /* do not defer this one! */
  me->sender_status = n->status;
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
  pm = (struct PingMessage *) &sm[1];
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pm->iv_seed = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_iv (&iv, &n->encrypt_key, pm->iv_seed, &n->peer);
  pp.challenge = n->ping_challenge;
  pp.target = n->peer;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' and `%s' messages with challenge %u for `%4s' using key %u, IV %u (salt %u).\n",
              "SET_KEY", "PING",
	      (unsigned int) n->ping_challenge,
	      GNUNET_i2s (&n->peer),
	      (unsigned int) n->encrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (&iv, sizeof(iv)),
	      pm->iv_seed);
#endif
  do_encrypt (n,
              &iv,
              &pp.target,
              &pm->target,
              sizeof (struct PingMessage) -
              ((void *) &pm->target - (void *) pm));
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# SET_KEY and PING messages created"), 
			    1, 
			    GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Have %llu ms left for `%s' transmission.\n",
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (me->deadline).rel_value,
	      "SET_KEY");
#endif
 trigger_processing:
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
  if ( (n->status != PEER_STATE_KEY_CONFIRMED) &&
       (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task) )
    n->retry_set_key_task
      = GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
				      &set_key_retry_task, n);    
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param n the neighbour from which we received message m
 * @param m the set key message we received
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_set_key (struct Neighbour *n,
		const struct SetKeyMessage *m,
		const struct GNUNET_TRANSPORT_ATS_Information *ats, 
		uint32_t ats_count);



/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry handling the set_key message.  Or,
 * if we did not get a HELLO, just free the set key message.
 *
 * @param cls pointer to the set key message
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_hello_retry_handle_set_key (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_HELLO_Message *hello,
                                    const char *err_msg)
{
  struct Neighbour *n = cls;
  struct SetKeyMessage *sm = n->skm;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    /* return; */
  }

  if (peer == NULL)
    {
      n->skm = NULL;
      n->pitr = NULL;
      if (n->public_key != NULL)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Received `%s' for `%4s', continuing processing of `%s' message.\n",
		      "HELLO",
		      GNUNET_i2s (&n->peer),
		      "SET_KEY");
#endif
	  handle_set_key (n, sm, NULL, 0);
	}
      else
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      _("Ignoring `%s' message due to lack of public key for peer `%4s' (failed to obtain one).\n"),
		      "SET_KEY",
		      GNUNET_i2s (&n->peer));
	}
      GNUNET_free (sm);
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
    }
}


/**
 * Merge the given performance data with the data we currently
 * track for the given neighbour.
 *
 * @param n neighbour
 * @param ats new performance data
 * @param ats_count number of records in ats
 */
static void
update_neighbour_performance (struct Neighbour *n,
			      const struct GNUNET_TRANSPORT_ATS_Information *ats, 
			      uint32_t ats_count)
{
  uint32_t i;
  unsigned int j;

  if (ats_count == 0)
    return;
  for (i = 0; i < ats_count; i++)
    {
      for (j=0;j < n->ats_count; j++)
	{
	  if (n->ats[j].type == ats[i].type)
	    {
	      n->ats[j].value = ats[i].value;
	      break;
	    }
	}
      if (j == n->ats_count)
        {
          GNUNET_array_append (n->ats,
                               n->ats_count,
                               ats[i]);
        }
    }
}


/**
 * We received a PING message.  Validate and transmit
 * PONG.
 *
 * @param n sender of the PING
 * @param m the encrypted PING message itself
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_ping (struct Neighbour *n,
	     const struct PingMessage *m,
	     const struct GNUNET_TRANSPORT_ATS_Information *ats, 
	     uint32_t ats_count)
{
  struct PingMessage t;
  struct PongMessage tx;
  struct PongMessage *tp;
  struct MessageEntry *me;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "PING", GNUNET_i2s (&n->peer));
#endif
  derive_iv (&iv, &n->decrypt_key, m->iv_seed, &my_identity);
  if (GNUNET_OK !=
      do_decrypt (n,
                  &iv,
                  &m->target,
                  &t.target,
                  sizeof (struct PingMessage) -
                  ((void *) &m->target - (void *) m)))
    return;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' to `%4s' with challenge %u decrypted using key %u, IV %u (salt %u)\n",
              "PING",
              GNUNET_i2s (&t.target),
              (unsigned int) t.challenge,
	      (unsigned int) n->decrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (&iv, sizeof(iv)),
	      m->iv_seed);
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PING messages decrypted"), 
			    1,
			    GNUNET_NO);
  if (0 != memcmp (&t.target,
                   &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      char * peer;
    	  GNUNET_asprintf(&peer, "%s",GNUNET_i2s (&t.target));
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Received PING for different identity : I am %s, PONG identity: %s\n",GNUNET_i2s (&my_identity), peer );
	  GNUNET_free (peer);
      GNUNET_break_op (0);
      return;
    }
  update_neighbour_performance (n, ats, ats_count);
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PongMessage));
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head,
				     n->encrypted_tail,
				     n->encrypted_tail,
				     me);
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PONG_DELAY);
  me->priority = PONG_PRIORITY;
  me->size = sizeof (struct PongMessage);
  tx.inbound_bw_limit = n->bw_in;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp = (struct PongMessage *) &me[1];
  tp->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp->header.size = htons (sizeof (struct PongMessage));
  tp->iv_seed = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_pong_iv (&iv, &n->encrypt_key, tp->iv_seed, t.challenge, &n->peer);
  do_encrypt (n,
              &iv,
              &tx.challenge,
              &tp->challenge,
              sizeof (struct PongMessage) -
              ((void *) &tp->challenge - (void *) tp));
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# PONG messages created"), 
			    1, 
			    GNUNET_NO);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' with challenge %u using key %u, IV %u (salt %u)\n",
	      "PONG",
              (unsigned int) t.challenge,
	      (unsigned int) n->encrypt_key.crc32,
	      GNUNET_CRYPTO_crc32_n (&iv, sizeof(iv)),
	      tp->iv_seed);
#endif
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
}


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param n sender of the PONG
 * @param m the encrypted PONG message itself
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_pong (struct Neighbour *n, 
	     const struct PongMessage *m,
	     const struct GNUNET_TRANSPORT_ATS_Information *ats, 
	     uint32_t ats_count)
{
  struct PongMessage t;
  struct ConnectNotifyMessage *cnm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *mats;
  size_t size;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' response from `%4s'.\n",
              "PONG", GNUNET_i2s (&n->peer));
#endif
  /* mark as garbage, just to be sure */
  memset (&t, 255, sizeof (t));
  derive_pong_iv (&iv, &n->decrypt_key, m->iv_seed, n->ping_challenge,
      &my_identity);
  if (GNUNET_OK !=
      do_decrypt (n,
                  &iv,
                  &m->challenge,
                  &t.challenge,
                  sizeof (struct PongMessage) -
                  ((void *) &m->challenge - (void *) m)))
    {
      GNUNET_break_op (0);
      return;
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# PONG messages decrypted"), 
			    1, 
			    GNUNET_NO);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' from `%4s' with challenge %u using key %u, IV %u (salt %u)\n",
              "PONG",
              GNUNET_i2s (&t.target),
              (unsigned int) t.challenge,
              (unsigned int) n->decrypt_key.crc32,
              GNUNET_CRYPTO_crc32_n (&iv, sizeof(iv)),
              m->iv_seed);
#endif
  if ((0 != memcmp (&t.target,
                    &n->peer,
                    sizeof (struct GNUNET_PeerIdentity))) ||
      (n->ping_challenge != t.challenge))
    {
      /* PONG malformed */
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received malformed `%s' wanted sender `%4s' with challenge %u\n",
                  "PONG", 
		  GNUNET_i2s (&n->peer),
		  (unsigned int) n->ping_challenge);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received malformed `%s' received from `%4s' with challenge %u\n",
                  "PONG", GNUNET_i2s (&t.target), 
		  (unsigned int) t.challenge);
#endif
      GNUNET_break_op (n->ping_challenge != t.challenge);
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
          GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
          n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
        }      
      update_neighbour_performance (n, ats, ats_count);      
      size = sizeof (struct ConnectNotifyMessage) +
	(n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
      if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  /* recovery strategy: throw away performance data */
	  GNUNET_array_grow (n->ats,
			     n->ats_count,
			     0);
	  size = sizeof (struct PeerStatusNotifyMessage) +
	    n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
	}
      cnm = (struct ConnectNotifyMessage*) buf;
      cnm->header.size = htons (size);
      cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
      cnm->ats_count = htonl (n->ats_count);
      cnm->peer = n->peer;
      mats = &cnm->ats;
      memcpy (mats,
	      n->ats,
	      n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
      mats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
      mats[n->ats_count].value = htonl (0);      
      send_to_all_clients (&cnm->header, 
			   GNUNET_NO, 
			   GNUNET_CORE_OPTION_SEND_CONNECT);
      process_encrypted_neighbour_queue (n);
      /* fall-through! */
    case PEER_STATE_KEY_CONFIRMED:
      n->last_activity = GNUNET_TIME_absolute_get ();
      if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (n->keep_alive_task);
      n->keep_alive_task 
	= GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
					&send_keep_alive,
					n);
      handle_peer_status_change (n);
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
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_set_key (struct Neighbour *n, 
		const struct SetKeyMessage *m,
		const struct GNUNET_TRANSPORT_ATS_Information *ats, 
		uint32_t ats_count)
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
      n->pitr = GNUNET_PEERINFO_iterate (peerinfo,
					 &n->peer,
					 GNUNET_TIME_UNIT_MINUTES,
					 &process_hello_retry_handle_set_key, n);
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# SET_KEY messages deferred (need public key)"), 
				1, 
				GNUNET_NO);
      return;
    }
  if (0 != memcmp (&m->target,
		   &my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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
      (t.abs_value < n->decrypt_key_created.abs_value))
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
			    gettext_noop ("# SET_KEY messages decrypted"), 
			    1, 
			    GNUNET_NO);
  n->decrypt_key = k;
  if (n->decrypt_key_created.abs_value != t.abs_value)
    {
      /* fresh key, reset sequence numbers */
      n->last_sequence_number_received = 0;
      n->last_packets_bitmap = 0;
      n->decrypt_key_created = t;
    }
  update_neighbour_performance (n, ats, ats_count);
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
                      "SET_KEY",
		      (unsigned int) sender_status);
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
                      "SET_KEY", 
		      (unsigned int) sender_status);
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
      handle_ping (n, ping, NULL, 0);
      GNUNET_free (ping);
    }
  if (n->pending_pong != NULL)
    {
      pong = n->pending_pong;
      n->pending_pong = NULL;
      handle_pong (n, pong, NULL, 0);
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
  size_t size = msize + sizeof (struct NotifyTrafficMessage) +
    (sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  char buf[size];
  struct NotifyTrafficMessage *ntm;
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      /* recovery strategy: throw performance data away... */
      GNUNET_array_grow (sender->ats,
			 sender->ats_count,
			 0);
      size = msize + sizeof (struct NotifyTrafficMessage) +
	(sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%4s' of type %u to client.\n",
	      GNUNET_i2s(&sender->peer),
              (unsigned int) ntohs (((const struct GNUNET_MessageHeader *) m)->type));
#endif
  ntm = (struct NotifyTrafficMessage *) buf;
  ntm->header.size = htons (size);
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND);
  ntm->ats_count = htonl (sender->ats_count);
  ntm->peer = sender->peer;
  ats = &ntm->ats;
  memcpy (ats,
	  sender->ats,
	  sizeof (struct GNUNET_TRANSPORT_ATS_Information) * sender->ats_count);
  ats[sender->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[sender->ats_count].value = htonl (0);  
  memcpy (&ats[sender->ats_count+1],
	  m, 
	  msize);
  send_to_client (client, &ntm->header, GNUNET_YES);
}


/**
 * Deliver P2P message to interested clients.
 *
 * @param cls always NULL
 * @param client who sent us the message (struct Neighbour)
 * @param m the message
 */
static void
deliver_message (void *cls,
		 void *client,
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

  type = ntohs (m->type);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received encapsulated message of type %u and size %u from `%4s'\n",
	      (unsigned int) type,
	      ntohs (m->size),
	      GNUNET_i2s (&sender->peer));
#endif
  GNUNET_snprintf (buf,
		   sizeof(buf),
		   gettext_noop ("# bytes of messages of type %u received"),
		   (unsigned int) type);
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
		  (unsigned int) type,
		  GNUNET_i2s (&sender->peer));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# messages not delivered to any client"), 
				1, GNUNET_NO);
    }
}


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param n target of the message
 * @param m encrypted message
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_encrypted_message (struct Neighbour *n,
                          const struct EncryptedMessage *m,
                          const struct GNUNET_TRANSPORT_ATS_Information *ats, 
			  uint32_t ats_count)
{
  size_t size = ntohs (m->header.size);
  char buf[size];
  struct EncryptedMessage *pt;  /* plaintext */
  GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "ENCRYPTED_MESSAGE", GNUNET_i2s (&n->peer));
#endif  
  /* validate hash */
  derive_auth_key (&auth_key,
                   &n->decrypt_key,
                   m->iv_seed,
                   n->decrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key,
                      &m->sequence_number,
                      size - ENCRYPTED_HEADER_SIZE, &ph);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Re-Authenticated %u bytes of ciphertext (`%u'): `%s'\n",
	      (unsigned int) size - ENCRYPTED_HEADER_SIZE,
              GNUNET_CRYPTO_crc32_n (&m->sequence_number,
                  size - ENCRYPTED_HEADER_SIZE),
	      GNUNET_h2s (&ph));
#endif

  if (0 != memcmp (&ph,
		   &m->hmac,
		   sizeof (GNUNET_HashCode)))
    {
      /* checksum failed */
      GNUNET_break_op (0);
      return;
    }
  derive_iv (&iv, &n->decrypt_key, m->iv_seed, &my_identity);
  /* decrypt */
  if (GNUNET_OK !=
      do_decrypt (n,
                  &iv,
                  &m->sequence_number,
                  &buf[ENCRYPTED_HEADER_SIZE],
                  size - ENCRYPTED_HEADER_SIZE))
    return;
  pt = (struct EncryptedMessage *) buf;

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
      int shift = (snum - n->last_sequence_number_received);
      if (shift >= 8 * sizeof(n->last_packets_bitmap))
        n->last_packets_bitmap = 0;
      else
        n->last_packets_bitmap <<= shift;
      n->last_sequence_number_received = snum;
    }

  /* check timestamp */
  t = GNUNET_TIME_absolute_ntoh (pt->timestamp);
  if (GNUNET_TIME_absolute_get_duration (t).rel_value > MAX_MESSAGE_AGE.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Message received far too old (%llu ms). Content ignored.\n"),
                  GNUNET_TIME_absolute_get_duration (t).rel_value);
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
    GNUNET_SCHEDULER_cancel (n->keep_alive_task);
  n->keep_alive_task 
    = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
				    &send_keep_alive,
				    n);
  GNUNET_STATISTICS_set (stats,
			 gettext_noop ("# bytes of payload decrypted"),
			 size - sizeof (struct EncryptedMessage),
			 GNUNET_NO);
  handle_peer_status_change (n);
  update_neighbour_performance (n, ats, ats_count);
  if (GNUNET_OK != GNUNET_SERVER_mst_receive (mst, 
					      n,
					      &buf[sizeof (struct EncryptedMessage)], 
					      size - sizeof (struct EncryptedMessage),
					      GNUNET_YES, GNUNET_NO))
    GNUNET_break_op (0);
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_transport_receive (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_TRANSPORT_ATS_Information *ats, 
			  uint32_t ats_count)
{
  struct Neighbour *n;
  struct GNUNET_TIME_Absolute now;
  int up;
  uint16_t type;
  uint16_t size;
  int changed;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %u from `%4s', demultiplexing.\n",
              (unsigned int) ntohs (message->type), 
	      GNUNET_i2s (peer));
#endif
  if (0 == memcmp (peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      return;
    }
  n = find_neighbour (peer);
  if (n == NULL)
    n = create_neighbour (peer);
  changed = GNUNET_NO;
  up = (n->status == PEER_STATE_KEY_CONFIRMED);
  type = ntohs (message->type);
  size = ntohs (message->size);
  switch (type)
    {
    case GNUNET_MESSAGE_TYPE_CORE_SET_KEY:
      if (size != sizeof (struct SetKeyMessage))
        {
          GNUNET_break_op (0);
          return;
        }
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# session keys received"), 
				1, 
				GNUNET_NO);
      handle_set_key (n,
		      (const struct SetKeyMessage *) message,
		      ats, ats_count);
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
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# failed to decrypt message (no session key)"), 
				    1, 
				    GNUNET_NO);
          send_key (n);
          return;
        }
      handle_encrypted_message (n, 
				(const struct EncryptedMessage *) message,
				ats, ats_count);
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
      handle_ping (n, (const struct PingMessage *) message,
		   ats, ats_count);
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
      handle_pong (n, (const struct PongMessage *) message,
		   ats, ats_count);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Unsupported message of type %u received.\n"),
		  (unsigned int) type);
      return;
    }
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    {
      now = GNUNET_TIME_absolute_get ();
      n->last_activity = now;
      changed = GNUNET_YES;
      if (!up)
	{
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# established sessions"), 
				    1, 
				    GNUNET_NO);
	  n->time_established = now;
	}
      if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (n->keep_alive_task);
      n->keep_alive_task 
	= GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
					&send_keep_alive,
					n);
    }
  if (changed)
    handle_peer_status_change (n);
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
  struct GNUNET_BANDWIDTH_Value32NBO q_out;
  struct GNUNET_BANDWIDTH_Value32NBO q_out_min;
  double pref_rel;
  double share;
  unsigned long long distributable;
  uint64_t need_per_peer;
  uint64_t need_per_second;
  unsigned int neighbour_count;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Neighbour quota update calculation running for peer `%4s'\n",
	      GNUNET_i2s (&n->peer));  
#endif
  n->quota_update_task = GNUNET_SCHEDULER_NO_TASK;
  /* calculate relative preference among all neighbours;
     divides by a bit more to avoid division by zero AND to
     account for possibility of new neighbours joining any time 
     AND to convert to double... */
  neighbour_count = GNUNET_CONTAINER_multihashmap_size (neighbours);
  if (neighbour_count == 0)
    return;
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

  /* calculate inbound bandwidth per peer */
  distributable = 0;
  if (bandwidth_target_in_bps > need_per_second)
    distributable = bandwidth_target_in_bps - need_per_second;
  share = distributable * pref_rel;
  if (share + need_per_peer > UINT32_MAX)
    q_in = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  else
    q_in = GNUNET_BANDWIDTH_value_init (need_per_peer + (uint32_t) share);

  /* calculate outbound bandwidth per peer */
  distributable = 0;
  if (bandwidth_target_out_bps > need_per_second)
    distributable = bandwidth_target_out_bps - need_per_second;
  share = distributable * pref_rel;
  if (share + need_per_peer > UINT32_MAX)
    q_out = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  else
    q_out = GNUNET_BANDWIDTH_value_init (need_per_peer + (uint32_t) share);
  n->bw_out_internal_limit = q_out;

  q_out_min = GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit, n->bw_out_internal_limit);
  GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window, n->bw_out);

  /* check if we want to disconnect for good due to inactivity */
  if ( (GNUNET_TIME_absolute_get_duration (get_neighbour_timeout (n)).rel_value > 0) &&
       (GNUNET_TIME_absolute_get_duration (n->time_established).rel_value > GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value) )
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Forcing disconnect of `%4s' due to inactivity\n",
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
  if ((n->bw_in.value__ != q_in.value__) || (n->bw_out.value__ != q_out_min.value__))
    {
	  if (n->bw_in.value__ != q_in.value__)
		  n->bw_in = q_in;
	  if (n->bw_out.value__ != q_out_min.value__)
		  n->bw_out = q_out_min;
      if (GNUNET_YES == n->is_connected)
	GNUNET_TRANSPORT_set_quota (transport,
				    &n->peer,
				    n->bw_in,
				    n->bw_out,
				    GNUNET_TIME_UNIT_FOREVER_REL,
				    NULL, NULL);
      handle_peer_status_change (n);
    }
  schedule_quota_update (n);
}


/**
 * Function called by transport to notify us that
 * a peer connected to us (on the network level).
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_transport_notify_connect (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_TRANSPORT_ATS_Information *ats,
				 uint32_t ats_count)
{
  struct Neighbour *n;

  if (0 == memcmp (peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      return;
    }
  n = find_neighbour (peer);
  if (n != NULL)
    {
      if (GNUNET_YES == n->is_connected)
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
			    gettext_noop ("# peers connected (transport)"), 
			    1, 
			    GNUNET_NO);
  n->is_connected = GNUNET_YES;      
  update_neighbour_performance (n, ats, ats_count);
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
  struct ClientActiveRequest *car;
  struct GNUNET_TIME_Relative left;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected from us; received notification from transport.\n", 
	      GNUNET_i2s (peer));
#endif
  n = find_neighbour (peer);
  if (n == NULL)
    {
      GNUNET_break (0);
      return;
    }
  GNUNET_break (n->is_connected == GNUNET_YES);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    {
      cnm.header.size = htons (sizeof (struct DisconnectNotifyMessage));
      cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT);
      cnm.reserved = htonl (0);
      cnm.peer = *peer;
      send_to_all_clients (&cnm.header, GNUNET_NO, GNUNET_CORE_OPTION_SEND_DISCONNECT);
      GNUNET_STATISTICS_update (stats, 
				gettext_noop ("# established sessions"), 
				-1, 
				GNUNET_NO);
    }

  /* On transport disconnect transport doesn't cancel requests, so must do so here. */
  if (n->th != NULL)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (n->th);
      n->th = NULL;
    }
  n->is_connected = GNUNET_NO;
  n->status = PEER_STATE_DOWN;
  while (NULL != (car = n->active_client_request_head))
    {
      GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
				   n->active_client_request_tail,
				   car);
      GNUNET_CONTAINER_multihashmap_remove (car->client->requests,
					    &n->peer.hashPubKey,
					    car);
      GNUNET_free (car);
    }

  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# peers connected (transport)"), 
			    -1, 
			    GNUNET_NO);
  if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->dead_clean_task);
  left = GNUNET_TIME_relative_subtract (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
					GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT);
  n->last_activity = GNUNET_TIME_absolute_subtract (GNUNET_TIME_absolute_get (), 
						    left);
  n->dead_clean_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT,
						     &consider_free_task,
						     n);
}


/**
 * Wrapper around 'free_neighbour'; helper for 'cleaning_task'.
 */
static int
free_neighbour_helper (void *cls,
		       const GNUNET_HashCode *key,
		       void *value)
{
  struct Neighbour *n = value;

  free_neighbour (n);
  return GNUNET_OK;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Client *c;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core service shutting down.\n");
#endif
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &free_neighbour_helper,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  neighbours = NULL;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# neighbour entries allocated"), 0, GNUNET_NO);
  GNUNET_assert (transport != NULL);
  GNUNET_TRANSPORT_disconnect (transport);
  transport = NULL;
  GNUNET_SERVER_notification_context_destroy (notifier);
  notifier = NULL;
  while (NULL != (c = clients))
    handle_client_disconnect (NULL, c->client_handle);
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  if (stats != NULL)
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  if (peerinfo != NULL)
    GNUNET_PEERINFO_disconnect (peerinfo);
  if (mst != NULL)
    GNUNET_SERVER_mst_destroy (mst);
}


/**
 * Initiate core service.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_init, NULL,
     GNUNET_MESSAGE_TYPE_CORE_INIT, 0},
    {&handle_client_iterate_peers, NULL,
     GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_client_have_peer, NULL,
     GNUNET_MESSAGE_TYPE_CORE_PEER_CONNECTED,
     sizeof (struct GNUNET_MessageHeader) + sizeof(struct GNUNET_PeerIdentity)},
    {&handle_client_request_info, NULL,
     GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO,
     sizeof (struct RequestInfoMessage)},
    {&handle_client_send_request, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST,
     sizeof (struct SendMessageRequest)},
    {&handle_client_send, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND, 0},
    {&handle_client_request_connect, NULL,
     GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT,
     sizeof (struct ConnectMessage)},
    {NULL, NULL, 0, 0}
  };
  char *keyfile;

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
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  peerinfo = GNUNET_PEERINFO_connect (cfg);
  if (NULL == peerinfo)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not access PEERINFO service.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free (keyfile);
      return;
    }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Core service could not access hostkey.  Exiting.\n"));
      GNUNET_PEERINFO_disconnect (peerinfo);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  neighbours = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);
  self.public_key = &my_public_key;
  self.peer = my_identity;
  self.last_activity = GNUNET_TIME_UNIT_FOREVER_ABS;
  self.status = PEER_STATE_KEY_CONFIRMED;
  self.is_connected = GNUNET_YES;
  /* setup notification */
  notifier = GNUNET_SERVER_notification_context_create (server, 
							MAX_NOTIFY_QUEUE);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  /* setup transport connection */
  transport = GNUNET_TRANSPORT_connect (cfg,
					&my_identity,
                                        NULL,
                                        &handle_transport_receive,
                                        &handle_transport_notify_connect,
                                        &handle_transport_notify_disconnect);
  GNUNET_assert (NULL != transport);
  stats = GNUNET_STATISTICS_create ("core", cfg);

  GNUNET_STATISTICS_set (stats, gettext_noop ("# discarded CORE_SEND requests"), 0, GNUNET_NO);
  GNUNET_STATISTICS_set (stats, gettext_noop ("# discarded lower priority CORE_SEND requests"), 0, GNUNET_NO);

  mst = GNUNET_SERVER_mst_create (&deliver_message,
				  NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
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
