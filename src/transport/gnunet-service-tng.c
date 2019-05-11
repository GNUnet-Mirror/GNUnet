/*
 This file is part of GNUnet.
 Copyright (C) 2010-2016, 2018, 2019 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file transport/gnunet-service-tng.c
 * @brief main for gnunet-service-tng
 * @author Christian Grothoff
 *
 * TODO:
 * Implement next:
 * - FIXME-NEXT: logic to decide which pm to pick for a given queue (sorting!)
 * - FIXME-FC: realize transport-to-transport flow control (needed in case
 *   communicators do not offer flow control).  Note that we may not
 *   want to simply delay the ACKs as that may cause unnecessary
 *   re-transmissions. => Introduce proper flow and congestion window(s)!
 * - review retransmission logic, right now there is no smartness there!
 *   => congestion control, flow control, etc [PERFORMANCE-BASICS]
 *
 * Optimizations:
 * - When forwarding DV learn messages, if a peer is reached that
 *   has a *bidirectional* link to the origin beyond 1st hop,
 *   do NOT forward it to peers _other_ than the origin, as
 *   there is clearly a better path directly from the origin to
 *   whatever else we could reach.
 * - AcknowledgementUUIDPs are overkill with 256 bits (128 would do)
 *   => Need 128 bit hash map though! [BANDWIDTH, MEMORY]
 * - queue_send_msg and route_message both by API design have to make copies
 *   of the payload, and route_message on top of that requires a malloc/free.
 *   Change design to approximate "zero" copy better... [CPU]
 * - could avoid copying body of message into each fragment and keep
 *   fragments as just pointers into the original message and only
 *   fully build fragments just before transmission (optimization, should
 *   reduce CPU and memory use) [CPU, MEMORY]
 * - if messages are below MTU, consider adding ACKs and other stuff
 *   to the same transmission to avoid tiny messages (requires planning at
 *   receiver, and additional MST-style demultiplex at receiver!) [PACKET COUNT]
 * - When we passively learned DV (with unconfirmed freshness), we
 *   right now add the path to our list but with a zero path_valid_until
 *   time and only use it for unconfirmed routes.  However, we could consider
 *   triggering an explicit validation mechansim ourselves, specifically routing
 *   a challenge-response message over the path [ROUTING]
 * - Track ACK losses based on ACK-counter [ROUTING]
 *
 * Design realizations / discussion:
 * - communicators do flow control by calling MQ "notify sent"
 *   when 'ready'. They determine flow implicitly (i.e. TCP blocking)
 *   or explicitly via backchannel FC ACKs.  As long as the
 *   channel is not full, they may 'notify sent' even if the other
 *   peer has not yet confirmed receipt. The other peer confirming
 *   is _only_ for FC, not for more reliable transmission; reliable
 *   transmission (i.e. of fragments) is left to _transport_.
 * - ACKs sent back in uni-directional communicators are done via
 *   the background channel API; here transport _may_ initially
 *   broadcast (with bounded # hops) if no path is known;
 * - transport should _integrate_ DV-routing and build a view of
 *   the network; then background channel traffic can be
 *   routed via DV as well as explicit "DV" traffic.
 * - background channel is also used for ACKs and NAT traversal support
 * - transport service is responsible for AEAD'ing the background
 *   channel, timestamps and monotonic time are used against replay
 *   of old messages -> peerstore needs to be supplied with
 *   "latest timestamps seen" data
 * - if transport implements DV, we likely need a 3rd peermap
 *   in addition to ephemerals and (direct) neighbours
 *   ==> check if stuff needs to be moved out of "Neighbour"
 * - transport should encapsualte core-level messages and do its
 *   own ACKing for RTT/goodput/loss measurements _and_ fragment
 *   for retransmission
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_monitor_service.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_signatures.h"
#include "transport.h"

/**
 * Maximum number of messages we acknowledge together in one
 * cummulative ACK.  Larger values may save a bit of bandwidth.
 */
#define MAX_CUMMULATIVE_ACKS 64

/**
 * What is the size we assume for a read operation in the
 * absence of an MTU for the purpose of flow control?
 */
#define IN_PACKET_SIZE_WITHOUT_MTU 128

/**
 * Number of slots we keep of historic data for computation of
 * goodput / message loss ratio.
 */
#define GOODPUT_AGING_SLOTS 4

/**
 * Maximum number of peers we select for forwarding DVInit
 * messages at the same time (excluding initiator).
 */
#define MAX_DV_DISCOVERY_SELECTION 16

/**
 * Window size. How many messages to the same target do we pass
 * to CORE without a RECV_OK in between? Small values limit
 * thoughput, large values will increase latency.
 *
 * FIXME-OPTIMIZE: find out what good values are experimentally,
 * maybe set adaptively (i.e. to observed available bandwidth).
 */
#define RECV_WINDOW_SIZE 4

/**
 * Minimum number of hops we should forward DV learn messages
 * even if they are NOT useful for us in hope of looping
 * back to the initiator?
 *
 * FIXME: allow initiator some control here instead?
 */
#define MIN_DV_PATH_LENGTH_FOR_INITIATOR 3

/**
 * Maximum DV distance allowed ever.
 */
#define MAX_DV_HOPS_ALLOWED 16

/**
 * Maximum number of DV learning activities we may
 * have pending at the same time.
 */
#define MAX_DV_LEARN_PENDING 64

/**
 * Maximum number of DV paths we keep simultaneously to the same target.
 */
#define MAX_DV_PATHS_TO_TARGET 3

/**
 * If a queue delays the next message by more than this number
 * of seconds we log a warning. Note: this is for testing,
 * the value chosen here might be too aggressively low!
 */
#define DELAY_WARN_THRESHOLD \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * We only consider queues as "quality" connections when
 * suppressing the generation of DV initiation messages if
 * the latency of the queue is below this threshold.
 */
#define DV_QUALITY_RTT_THRESHOLD \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * How long do we consider a DV path valid if we see no
 * further updates on it? Note: the value chosen here might be too low!
 */
#define DV_PATH_VALIDITY_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How long do we cache backchannel (struct Backtalker) information
 * after a backchannel goes inactive?
 */
#define BACKCHANNEL_INACTIVITY_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How long before paths expire would we like to (re)discover DV paths? Should
 * be below #DV_PATH_VALIDITY_TIMEOUT.
 */
#define DV_PATH_DISCOVERY_FREQUENCY \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 4)

/**
 * How long are ephemeral keys valid?
 */
#define EPHEMERAL_VALIDITY \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * How long do we keep partially reassembled messages around before giving up?
 */
#define REASSEMBLY_EXPIRATION \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 4)

/**
 * What is the fastest rate at which we send challenges *if* we keep learning
 * an address (gossip, DHT, etc.)?
 */
#define FAST_VALIDATION_CHALLENGE_FREQ \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * What is the slowest rate at which we send challenges?
 */
#define MAX_VALIDATION_CHALLENGE_FREQ \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_DAYS, 1)

/**
 * How long until we forget about historic accumulators and thus
 * reset the ACK counter? Should exceed the maximum time an
 * active connection experiences without an ACK.
 */
#define ACK_CUMMULATOR_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * What is the non-randomized base frequency at which we
 * would initiate DV learn messages?
 */
#define DV_LEARN_BASE_FREQUENCY GNUNET_TIME_UNIT_MINUTES

/**
 * How many good connections (confirmed, bi-directional, not DV)
 * do we need to have to suppress initiating DV learn messages?
 */
#define DV_LEARN_QUALITY_THRESHOLD 100

/**
 * When do we forget an invalid address for sure?
 */
#define MAX_ADDRESS_VALID_UNTIL \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MONTHS, 1)

/**
 * How long do we consider an address valid if we just checked?
 */
#define ADDRESS_VALIDATION_LIFETIME \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * What is the maximum frequency at which we do address validation?
 * A random value between 0 and this value is added when scheduling
 * the #validation_task (both to ensure we do not validate too often,
 * and to randomize a bit).
 */
#define MIN_DELAY_ADDRESS_VALIDATION GNUNET_TIME_UNIT_MILLISECONDS

/**
 * How many network RTTs before an address validation expires should we begin
 * trying to revalidate? (Note that the RTT used here is the one that we
 * experienced during the last validation, not necessarily the latest RTT
 * observed).
 */
#define VALIDATION_RTT_BUFFER_FACTOR 3

/**
 * How many messages can we have pending for a given communicator
 * process before we start to throttle that communicator?
 *
 * Used if a communicator might be CPU-bound and cannot handle the traffic.
 */
#define COMMUNICATOR_TOTAL_QUEUE_LIMIT 512

/**
 * How many messages can we have pending for a given queue (queue to
 * a particular peer via a communicator) process before we start to
 * throttle that queue?
 */
#define QUEUE_LENGTH_LIMIT 32


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Unique identifier we attach to a message.
 */
struct MessageUUIDP
{
  /**
   * Unique value, generated by incrementing the
   * `message_uuid_ctr` of `struct Neighbour`.
   */
  uint64_t uuid GNUNET_PACKED;
};


/**
 * Unique identifier to map an acknowledgement to a transmission.
 */
struct AcknowledgementUUIDP
{
  /**
   * The UUID value.  Not actually a hash, but a random value.
   */
  struct GNUNET_ShortHashCode value;
};


/**
 * Type of a nonce used for challenges.
 */
struct ChallengeNonceP
{
  /**
   * The value of the nonce.  Note that this is NOT a hash.
   */
  struct GNUNET_ShortHashCode value;
};


/**
 * Outer layer of an encapsulated backchannel message.
 */
struct TransportBackchannelEncapsulationMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION.
   */
  struct GNUNET_MessageHeader header;

  /* Followed by *another* message header which is the message to
     the communicator */

  /* Followed by a 0-terminated name of the communicator */
};


/**
 * Body by which a peer confirms that it is using an ephemeral key.
 */
struct EphemeralConfirmationPS
{

  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * How long is this signature over the ephemeral key valid?
   *
   * Note that the receiver MUST IGNORE the absolute time, and only interpret
   * the value as a mononic time and reject "older" values than the last one
   * observed.  This is necessary as we do not want to require synchronized
   * clocks and may not have a bidirectional communication channel.
   *
   * Even with this, there is no real guarantee against replay achieved here,
   * unless the latest timestamp is persisted.  While persistence should be
   * provided via PEERSTORE, we do not consider the mechanism reliable!  Thus,
   * communicators must protect against replay attacks when using backchannel
   * communication!
   */
  struct GNUNET_TIME_AbsoluteNBO sender_monotonic_time;

  /**
   * Target's peer identity.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Ephemeral key setup by the sender for @e target, used
   * to encrypt the payload.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;
};


/**
 * Plaintext of the variable-size payload that is encrypted
 * within a `struct TransportBackchannelEncapsulationMessage`
 */
struct TransportDVBoxPayloadP
{

  /**
   * Sender's peer identity.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Signature of the sender over an
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL.
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Current monotonic time of the sending transport service.  Used to
   * detect replayed messages.  Note that the receiver should remember
   * a list of the recently seen timestamps and only reject messages
   * if the timestamp is in the list, or the list is "full" and the
   * timestamp is smaller than the lowest in the list.
   *
   * Like the @e ephemeral_validity, the list of timestamps per peer should be
   * persisted to guard against replays after restarts.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /* Followed by a `struct GNUNET_MessageHeader` with a message
     for the target peer */
};


/**
 * Outer layer of an encapsulated unfragmented application message sent
 * over an unreliable channel.
 */
struct TransportReliabilityBoxMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of messages still to be sent before a commulative
   * ACK is requested.  Zero if an ACK is requested immediately.
   * In NBO.  Note that the receiver may send the ACK faster
   * if it believes that is reasonable.
   */
  uint32_t ack_countdown GNUNET_PACKED;

  /**
   * Unique ID of the message used for signalling receipt of
   * messages sent over possibly unreliable channels.  Should
   * be a random.
   */
  struct AcknowledgementUUIDP ack_uuid;
};


/**
 * Acknowledgement payload.
 */
struct TransportCummulativeAckPayloadP
{
  /**
   * How long was the ACK delayed for generating cummulative ACKs?
   * Used to calculate the correct network RTT by taking the receipt
   * time of the ack minus the transmission time of the sender minus
   * this value.
   */
  struct GNUNET_TIME_RelativeNBO ack_delay;

  /**
   * UUID of a message being acknowledged.
   */
  struct AcknowledgementUUIDP ack_uuid;
};


/**
 * Confirmation that the receiver got a
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX. Note that the
 * confirmation may be transmitted over a completely different queue,
 * so ACKs are identified by a combination of PID of sender and
 * message UUID, without the queue playing any role!
 */
struct TransportReliabilityAckMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Counter of ACKs transmitted by the sender to us. Incremented
   * by one for each ACK, used to detect how many ACKs were lost.
   */
  uint32_t ack_counter GNUNET_PACKED;

  /* followed by any number of `struct TransportCummulativeAckPayloadP`
     messages providing ACKs */
};


/**
 * Outer layer of an encapsulated fragmented application message.
 */
struct TransportFragmentBoxMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Offset of this fragment in the overall message.
   */
  uint16_t frag_off GNUNET_PACKED;

  /**
   * Total size of the message that is being fragmented.
   */
  uint16_t msg_size GNUNET_PACKED;

  /**
   * Unique ID of this fragment (and fragment transmission!). Will
   * change even if a fragement is retransmitted to make each
   * transmission attempt unique! If a client receives a duplicate
   * fragment (same @e frag_off for same @a msg_uuid, it must send
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK immediately.
   */
  struct AcknowledgementUUIDP ack_uuid;

  /**
   * Original message ID for of the message that all the fragments
   * belong to.  Must be the same for all fragments.
   */
  struct MessageUUIDP msg_uuid;
};


/**
 * Content signed by the initator during DV learning.
 *
 * The signature is required to prevent DDoS attacks. A peer sending out this
 * message is potentially generating a lot of traffic that will go back to the
 * initator, as peers receiving this message will try to let the initiator
 * know that they got the message.
 *
 * Without this signature, an attacker could abuse this mechanism for traffic
 * amplification, sending a lot of traffic to a peer by putting out this type
 * of message with the victim's peer identity.
 *
 * Even with just a signature, traffic amplification would be possible via
 * replay attacks. The @e monotonic_time limits such replay attacks, as every
 * potential amplificator will check the @e monotonic_time and only respond
 * (at most) once per message.
 */
struct DvInitPS
{
  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Time at the initiator when generating the signature.
   *
   * Note that the receiver MUST IGNORE the absolute time, and only interpret
   * the value as a mononic time and reject "older" values than the last one
   * observed.  This is necessary as we do not want to require synchronized
   * clocks and may not have a bidirectional communication channel.
   *
   * Even with this, there is no real guarantee against replay achieved here,
   * unless the latest timestamp is persisted.  Persistence should be
   * provided via PEERSTORE if possible.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /**
   * Challenge value used by the initiator to re-identify the path.
   */
  struct ChallengeNonceP challenge;
};


/**
 * Content signed by each peer during DV learning.
 *
 * This assues the initiator of the DV learning operation that the hop from @e
 * pred via the signing peer to @e succ actually exists.  This makes it
 * impossible for an adversary to supply the network with bogus routes.
 *
 * The @e challenge is included to provide replay protection for the
 * initiator. This way, the initiator knows that the hop existed after the
 * original @e challenge was first transmitted, providing a freshness metric.
 *
 * Peers other than the initiator that passively learn paths by observing
 * these messages do NOT benefit from this. Here, an adversary may indeed
 * replay old messages.  Thus, passively learned paths should always be
 * immediately marked as "potentially stale".
 */
struct DvHopPS
{
  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Identity of the previous peer on the path.
   */
  struct GNUNET_PeerIdentity pred;

  /**
   * Identity of the next peer on the path.
   */
  struct GNUNET_PeerIdentity succ;

  /**
   * Challenge value used by the initiator to re-identify the path.
   */
  struct ChallengeNonceP challenge;
};


/**
 * An entry describing a peer on a path in a
 * `struct TransportDVLearnMessage` message.
 */
struct DVPathEntryP
{
  /**
   * Identity of a peer on the path.
   */
  struct GNUNET_PeerIdentity hop;

  /**
   * Signature of this hop over the path, of purpose
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP
   */
  struct GNUNET_CRYPTO_EddsaSignature hop_sig;
};


/**
 * Internal message used by transport for distance vector learning.
 * If @e num_hops does not exceed the threshold, peers should append
 * themselves to the peer list and flood the message (possibly only
 * to a subset of their neighbours to limit discoverability of the
 * network topology).  To the extend that the @e bidirectional bits
 * are set, peers may learn the inverse paths even if they did not
 * initiate.
 *
 * Unless received on a bidirectional queue and @e num_hops just
 * zero, peers that can forward to the initator should always try to
 * forward to the initiator.
 */
struct TransportDVLearnMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of hops this messages has travelled, in NBO. Zero if
   * sent by initiator.
   */
  uint16_t num_hops GNUNET_PACKED;

  /**
   * Bitmask of the last 16 hops indicating whether they are confirmed
   * available (without DV) in both directions or not, in NBO.  Used
   * to possibly instantly learn a path in both directions.  Each peer
   * should shift this value by one to the left, and then set the
   * lowest bit IF the current sender can be reached from it (without
   * DV routing).
   */
  uint16_t bidirectional GNUNET_PACKED;

  /**
   * Peers receiving this message and delaying forwarding to other
   * peers for any reason should increment this value by the non-network
   * delay created by the peer.
   */
  struct GNUNET_TIME_RelativeNBO non_network_delay;

  /**
   * Time at the initiator when generating the signature.
   *
   * Note that the receiver MUST IGNORE the absolute time, and only interpret
   * the value as a mononic time and reject "older" values than the last one
   * observed.  This is necessary as we do not want to require synchronized
   * clocks and may not have a bidirectional communication channel.
   *
   * Even with this, there is no real guarantee against replay achieved here,
   * unless the latest timestamp is persisted.  Persistence should be
   * provided via PEERSTORE if possible.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /**
   * Signature of this hop over the path, of purpose
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR
   */
  struct GNUNET_CRYPTO_EddsaSignature init_sig;

  /**
   * Identity of the peer that started this learning activity.
   */
  struct GNUNET_PeerIdentity initiator;

  /**
   * Challenge value used by the initiator to re-identify the path.
   */
  struct ChallengeNonceP challenge;

  /* Followed by @e num_hops `struct DVPathEntryP` values,
     excluding the initiator of the DV trace; the last entry is the
     current sender; the current peer must not be included. */
};


/**
 * Outer layer of an encapsulated message send over multiple hops.
 * The path given only includes the identities of the subsequent
 * peers, i.e. it will be empty if we are the receiver. Each
 * forwarding peer should scan the list from the end, and if it can,
 * forward to the respective peer. The list should then be shortened
 * by all the entries up to and including that peer.  Each hop should
 * also increment @e total_hops to allow the receiver to get a precise
 * estimate on the number of hops the message travelled.  Senders must
 * provide a learned path that thus should work, but intermediaries
 * know of a shortcut, they are allowed to send the message via that
 * shortcut.
 *
 * If a peer finds itself still on the list, it must drop the message.
 *
 * The payload of the box can only be decrypted and verified by the
 * ultimate receiver. Intermediaries do not learn the sender's
 * identity and the path the message has taken.  However, the first
 * hop does learn the sender as @e total_hops would be zero and thus
 * the predecessor must be the origin (so this is not really useful
 * for anonymization).
 */
struct TransportDVBoxMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of total hops this messages travelled. In NBO.
   * @e origin sets this to zero, to be incremented at
   * each hop.  Peers should limit the @e total_hops value
   * they accept from other peers.
   */
  uint16_t total_hops GNUNET_PACKED;

  /**
   * Number of hops this messages includes. In NBO.  Reduced by one
   * or more at each hop.  Peers should limit the @e num_hops value
   * they accept from other peers.
   */
  uint16_t num_hops GNUNET_PACKED;

  /**
   * Ephemeral key setup by the sender for target, used to encrypt the
   * payload.  Intermediaries must not change this value.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  /**
   * We use an IV here as the @e ephemeral_key is re-used for
   * #EPHEMERAL_VALIDITY time to avoid re-signing it all the time.
   * Intermediaries must not change this value.
   */
  struct GNUNET_ShortHashCode iv;

  /**
   * HMAC over the ciphertext of the encrypted, variable-size body
   * that follows.  Verified via DH of target and @e ephemeral_key.
   * Intermediaries must not change this value.
   */
  struct GNUNET_HashCode hmac;

  /* Followed by @e num_hops `struct GNUNET_PeerIdentity` values;
     excluding the @e origin and the current peer, the last must be
     the ultimate target; if @e num_hops is zero, the receiver of this
     message is the ultimate target. */

  /* Followed by encrypted, variable-size payload, which
     must begin with a `struct TransportDVBoxPayloadP` */

  /* Followed by the actual message, which itself must not be a
     a DV_LEARN or DV_BOX message! */
};


/**
 * Message send to another peer to validate that it can indeed
 * receive messages at a particular address.
 */
struct TransportValidationChallengeMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_CHALLENGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Challenge to be signed by the receiving peer.
   */
  struct ChallengeNonceP challenge;

  /**
   * Timestamp of the sender, to be copied into the reply
   * to allow sender to calculate RTT.
   */
  struct GNUNET_TIME_AbsoluteNBO sender_time;
};


/**
 * Message signed by a peer to confirm that it can indeed
 * receive messages at a particular address.
 */
struct TransportValidationPS
{

  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * How long does the sender believe the address on
   * which the challenge was received to remain valid?
   */
  struct GNUNET_TIME_RelativeNBO validity_duration;

  /**
   * Challenge signed by the receiving peer.
   */
  struct ChallengeNonceP challenge;
};


/**
 * Message send to a peer to respond to a
 * #GNUNET_MESSAGE_TYPE_ADDRESS_VALIDATION_CHALLENGE
 */
struct TransportValidationResponseMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The peer's signature matching the
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE purpose.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * The challenge that was signed by the receiving peer.
   */
  struct ChallengeNonceP challenge;

  /**
   * Original timestamp of the sender (was @code{sender_time}),
   * copied into the reply to allow sender to calculate RTT.
   */
  struct GNUNET_TIME_AbsoluteNBO origin_time;

  /**
   * How long does the sender believe this address to remain
   * valid?
   */
  struct GNUNET_TIME_RelativeNBO validity_duration;
};


GNUNET_NETWORK_STRUCT_END


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
   * It is a communicator, use for communication.
   */
  CT_COMMUNICATOR = 3,

  /**
   * "Application" telling us where to connect (i.e. TOPOLOGY, DHT or CADET).
   */
  CT_APPLICATION = 4
};


/**
 * Which transmission options are allowable for transmission?
 * Interpreted bit-wise!
 */
enum RouteMessageOptions
{
  /**
   * Only confirmed, non-DV direct neighbours.
   */
  RMO_NONE = 0,

  /**
   * We are allowed to use DV routing for this @a hdr
   */
  RMO_DV_ALLOWED = 1,

  /**
   * We are allowed to use unconfirmed queues or DV routes for this message
   */
  RMO_UNCONFIRMED_ALLOWED = 2,

  /**
   * Reliable and unreliable, DV and non-DV are all acceptable.
   */
  RMO_ANYTHING_GOES = (RMO_DV_ALLOWED | RMO_UNCONFIRMED_ALLOWED),

  /**
   * If we have multiple choices, it is OK to send this message
   * over multiple channels at the same time to improve loss tolerance.
   * (We do at most 2 transmissions.)
   */
  RMO_REDUNDANT = 4
};


/**
 * When did we launch this DV learning activity?
 */
struct LearnLaunchEntry
{

  /**
   * Kept (also) in a DLL sorted by launch time.
   */
  struct LearnLaunchEntry *prev;

  /**
   * Kept (also) in a DLL sorted by launch time.
   */
  struct LearnLaunchEntry *next;

  /**
   * Challenge that uniquely identifies this activity.
   */
  struct ChallengeNonceP challenge;

  /**
   * When did we transmit the DV learn message (used to calculate RTT) and
   * determine freshness of paths learned via this operation.
   */
  struct GNUNET_TIME_Absolute launch_time;
};


/**
 * Information we keep per #GOODPUT_AGING_SLOTS about historic
 * (or current) transmission performance.
 */
struct TransmissionHistoryEntry
{
  /**
   * Number of bytes actually sent in the interval.
   */
  uint64_t bytes_sent;

  /**
   * Number of bytes received and acknowledged by the other peer in
   * the interval.
   */
  uint64_t bytes_received;
};


/**
 * Performance data for a transmission possibility.
 */
struct PerformanceData
{
  /**
   * Weighted average for the RTT.
   */
  struct GNUNET_TIME_Relative aged_rtt;

  /**
   * Historic performance data, using a ring buffer of#GOODPUT_AGING_SLOTS
   * entries.
   */
  struct TransmissionHistoryEntry the[GOODPUT_AGING_SLOTS];

  /**
   * What was the last age when we wrote to @e the? Used to clear
   * old entries when the age advances.
   */
  unsigned int last_age;
};


/**
 * Client connected to the transport service.
 */
struct TransportClient;

/**
 * A neighbour that at least one communicator is connected to.
 */
struct Neighbour;

/**
 * Entry in our #dv_routes table, representing a (set of) distance
 * vector routes to a particular peer.
 */
struct DistanceVector;

/**
 * A queue is a message queue provided by a communicator
 * via which we can reach a particular neighbour.
 */
struct Queue;

/**
 * Message awaiting transmission. See detailed comments below.
 */
struct PendingMessage;

/**
 * One possible hop towards a DV target.
 */
struct DistanceVectorHop;


/**
 * Context from #handle_incoming_msg().  Closure for many
 * message handlers below.
 */
struct CommunicatorMessageContext
{

  /**
   * Kept in a DLL of `struct VirtualLink` if waiting for CORE
   * flow control to unchoke.
   */
  struct CommunicatorMessageContext *next;

  /**
   * Kept in a DLL of `struct VirtualLink` if waiting for CORE
   * flow control to unchoke.
   */
  struct CommunicatorMessageContext *prev;

  /**
   * Which communicator provided us with the message.
   */
  struct TransportClient *tc;

  /**
   * Additional information for flow control and about the sender.
   */
  struct GNUNET_TRANSPORT_IncomingMessage im;

  /**
   * Number of hops the message has travelled (if DV-routed).
   * FIXME: make use of this in ACK handling!
   */
  uint16_t total_hops;
};


/**
 * A virtual link is another reachable peer that is known to CORE.  It
 * can be either a `struct Neighbour` with at least one confirmed
 * `struct Queue`, or a `struct DistanceVector` with at least one
 * confirmed `struct DistanceVectorHop`.  With a virtual link we track
 * data that is per neighbour that is not specific to how the
 * connectivity is established.
 */
struct VirtualLink
{
  /**
   * Identity of the peer at the other end of the link.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Communicators blocked for receiving on @e target as we are waiting
   * on the @e core_recv_window to increase.
   */
  struct CommunicatorMessageContext *cmc_head;

  /**
   * Communicators blocked for receiving on @e target as we are waiting
   * on the @e core_recv_window to increase.
   */
  struct CommunicatorMessageContext *cmc_tail;

  /**
   * Head of list of messages pending for this VL.
   */
  struct PendingMessage *pending_msg_head;

  /**
   * Tail of list of messages pending for this VL.
   */
  struct PendingMessage *pending_msg_tail;

  /**
   * Task scheduled to possibly notfiy core that this peer is no
   * longer counting as confirmed.  Runs the #core_visibility_check(),
   * which checks that some DV-path or a queue exists that is still
   * considered confirmed.
   */
  struct GNUNET_SCHEDULER_Task *visibility_task;

  /**
   * Neighbour used by this virtual link, NULL if @e dv is used.
   */
  struct Neighbour *n;

  /**
   * Distance vector used by this virtual link, NULL if @e n is used.
   */
  struct DistanceVector *dv;

  /**
   * Used to generate unique UUIDs for messages that are being
   * fragmented.
   */
  uint64_t message_uuid_ctr;

  /**
   * How many more messages can we send to core before we exhaust
   * the receive window of CORE for this peer? If this hits zero,
   * we must tell communicators to stop providing us more messages
   * for this peer.  In fact, the window can go negative as we
   * have multiple communicators, so per communicator we can go
   * down by one into the negative range.
   */
  int core_recv_window;
};


/**
 * Data structure kept when we are waiting for an acknowledgement.
 */
struct PendingAcknowledgement
{

  /**
   * If @e pm is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to its pending message.
   */
  struct PendingAcknowledgement *next_pm;

  /**
   * If @e pm is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to its pending message.
   */
  struct PendingAcknowledgement *prev_pm;

  /**
   * If @e queue is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to the queue that was used to transmit the
   * @a pm.
   */
  struct PendingAcknowledgement *next_queue;

  /**
   * If @e queue is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to the queue that was used to transmit the
   * @a pm.
   */
  struct PendingAcknowledgement *prev_queue;

  /**
   * If @e dvh is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to the DVH that was used to transmit the
   * @a pm.
   */
  struct PendingAcknowledgement *next_dvh;

  /**
   * If @e dvh is non-NULL, this is the DLL in which this acknowledgement
   * is kept in relation to the DVH that was used to transmit the
   * @a pm.
   */
  struct PendingAcknowledgement *prev_dvh;

  /**
   * Pointers for the DLL of all pending acknowledgements.
   * This list is sorted by @e transmission time.  If the list gets too
   * long, the oldest entries are discarded.
   */
  struct PendingAcknowledgement *next_pa;

  /**
   * Pointers for the DLL of all pending acknowledgements.
   * This list is sorted by @e transmission time.  If the list gets too
   * long, the oldest entries are discarded.
   */
  struct PendingAcknowledgement *prev_pa;

  /**
   * Unique identifier for this transmission operation.
   */
  struct AcknowledgementUUIDP ack_uuid;

  /**
   * Message that was transmitted, may be NULL if the message was ACKed
   * via another channel.
   */
  struct PendingMessage *pm;

  /**
   * Distance vector path chosen for this transmission, NULL if transmission
   * was to a direct neighbour OR if the path was forgotten in the meantime.
   */
  struct DistanceVectorHop *dvh;

  /**
   * Queue used for transmission, NULL if the queue has been destroyed
   * (which may happen before we get an acknowledgement).
   */
  struct Queue *queue;

  /**
   * Time of the transmission, for RTT calculation.
   */
  struct GNUNET_TIME_Absolute transmission_time;

  /**
   * Number of bytes of the original message (to calculate bandwidth).
   */
  uint16_t message_size;
};


/**
 * One possible hop towards a DV target.
 */
struct DistanceVectorHop
{

  /**
   * Kept in a MDLL, sorted by @e timeout.
   */
  struct DistanceVectorHop *next_dv;

  /**
   * Kept in a MDLL, sorted by @e timeout.
   */
  struct DistanceVectorHop *prev_dv;

  /**
   * Kept in a MDLL.
   */
  struct DistanceVectorHop *next_neighbour;

  /**
   * Kept in a MDLL.
   */
  struct DistanceVectorHop *prev_neighbour;

  /**
   * Head of DLL of PAs that used our @a path.
   */
  struct PendingAcknowledgement *pa_head;

  /**
   * Tail of DLL of PAs that used our @a path.
   */
  struct PendingAcknowledgement *pa_tail;

  /**
   * What would be the next hop to @e target?
   */
  struct Neighbour *next_hop;

  /**
   * Distance vector entry this hop belongs with.
   */
  struct DistanceVector *dv;

  /**
   * Array of @e distance hops to the target, excluding @e next_hop.
   * NULL if the entire path is us to @e next_hop to `target`. Allocated
   * at the end of this struct. Excludes the target itself!
   */
  const struct GNUNET_PeerIdentity *path;

  /**
   * At what time do we forget about this path unless we see it again
   * while learning?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * For how long is the validation of this path considered
   * valid?
   * Set to ZERO if the path is learned by snooping on DV learn messages
   * initiated by other peers, and to the time at which we generated the
   * challenge for DV learn operations this peer initiated.
   */
  struct GNUNET_TIME_Absolute path_valid_until;

  /**
   * Performance data for this transmission possibility.
   */
  struct PerformanceData pd;

  /**
   * Number of hops in total to the `target` (excluding @e next_hop and `target`
   * itself). Thus 0 still means a distance of 2 hops (to @e next_hop and then
   * to `target`).
   */
  unsigned int distance;
};


/**
 * Entry in our #dv_routes table, representing a (set of) distance
 * vector routes to a particular peer.
 */
struct DistanceVector
{

  /**
   * To which peer is this a route?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Known paths to @e target.
   */
  struct DistanceVectorHop *dv_head;

  /**
   * Known paths to @e target.
   */
  struct DistanceVectorHop *dv_tail;

  /**
   * Task scheduled to purge expired paths from @e dv_head MDLL.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Do we have a confirmed working queue and are thus visible to
   * CORE?  If so, this is the virtual link, otherwise NULL.
   */
  struct VirtualLink *vl;

  /**
   * Signature affirming @e ephemeral_key of type
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * How long is @e sender_sig valid
   */
  struct GNUNET_TIME_Absolute ephemeral_validity;

  /**
   * What time was @e sender_sig created
   */
  struct GNUNET_TIME_Absolute monotime;

  /**
   * Our ephemeral key.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  /**
   * Our private ephemeral key.
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey private_key;
};


/**
 * Entry identifying transmission in one of our `struct
 * Queue` which still awaits an ACK.  This is used to
 * ensure we do not overwhelm a communicator and limit the number of
 * messages outstanding per communicator (say in case communicator is
 * CPU bound) and per queue (in case bandwidth allocation exceeds
 * what the communicator can actually provide towards a particular
 * peer/target).
 */
struct QueueEntry
{

  /**
   * Kept as a DLL.
   */
  struct QueueEntry *next;

  /**
   * Kept as a DLL.
   */
  struct QueueEntry *prev;

  /**
   * Queue this entry is queued with.
   */
  struct Queue *queue;

  /**
   * Pending message this entry is for, or NULL for none.
   */
  struct PendingMessage *pm;

  /**
   * Message ID used for this message with the queue used for transmission.
   */
  uint64_t mid;
};


/**
 * A queue is a message queue provided by a communicator
 * via which we can reach a particular neighbour.
 */
struct Queue
{
  /**
   * Kept in a MDLL.
   */
  struct Queue *next_neighbour;

  /**
   * Kept in a MDLL.
   */
  struct Queue *prev_neighbour;

  /**
   * Kept in a MDLL.
   */
  struct Queue *prev_client;

  /**
   * Kept in a MDLL.
   */
  struct Queue *next_client;

  /**
   * Head of DLL of PAs that used this queue.
   */
  struct PendingAcknowledgement *pa_head;

  /**
   * Tail of DLL of PAs that used this queue.
   */
  struct PendingAcknowledgement *pa_tail;

  /**
   * Head of DLL of unacked transmission requests.
   */
  struct QueueEntry *queue_head;

  /**
   * End of DLL of unacked transmission requests.
   */
  struct QueueEntry *queue_tail;

  /**
   * Which neighbour is this queue for?
   */
  struct Neighbour *neighbour;

  /**
   * Which communicator offers this queue?
   */
  struct TransportClient *tc;

  /**
   * Address served by the queue.
   */
  const char *address;

  /**
   * Task scheduled for the time when this queue can (likely) transmit the
   * next message.
   */
  struct GNUNET_SCHEDULER_Task *transmit_task;

  /**
   * How long do *we* consider this @e address to be valid?  In the past or
   * zero if we have not yet validated it.  Can be updated based on
   * challenge-response validations (via address validation logic), or when we
   * receive ACKs that we can definitively map to transmissions via this
   * queue.
   */
  struct GNUNET_TIME_Absolute validated_until;

  /**
   * Performance data for this queue.
   */
  struct PerformanceData pd;

  /**
   * Message ID generator for transmissions on this queue to the
   * communicator.
   */
  uint64_t mid_gen;

  /**
   * Unique identifier of this queue with the communicator.
   */
  uint32_t qid;

  /**
   * Maximum transmission unit supported by this queue.
   */
  uint32_t mtu;

  /**
   * Messages pending.
   */
  uint32_t num_msg_pending;

  /**
   * Bytes pending.
   */
  uint32_t num_bytes_pending;

  /**
   * Length of the DLL starting at @e queue_head.
   */
  unsigned int queue_length;

  /**
   * Network type offered by this queue.
   */
  enum GNUNET_NetworkType nt;

  /**
   * Connection status for this queue.
   */
  enum GNUNET_TRANSPORT_ConnectionStatus cs;

  /**
   * Set to #GNUNET_YES if this queue is idle waiting for some
   * virtual link to give it a pending message.
   */
  int idle;
};


/**
 * Information we keep for a message that we are reassembling.
 */
struct ReassemblyContext
{

  /**
   * Original message ID for of the message that all the fragments
   * belong to.
   */
  struct MessageUUIDP msg_uuid;

  /**
   * Which neighbour is this context for?
   */
  struct Neighbour *neighbour;

  /**
   * Entry in the reassembly heap (sorted by expiration).
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Bitfield with @e msg_size bits representing the positions
   * where we have received fragments.  When we receive a fragment,
   * we check the bits in @e bitfield before incrementing @e msg_missing.
   *
   * Allocated after the reassembled message.
   */
  uint8_t *bitfield;

  /**
   * At what time will we give up reassembly of this message?
   */
  struct GNUNET_TIME_Absolute reassembly_timeout;

  /**
   * Time we received the last fragment.  @e avg_ack_delay must be
   * incremented by now - @e last_frag multiplied by @e num_acks.
   */
  struct GNUNET_TIME_Absolute last_frag;

  /**
   * How big is the message we are reassembling in total?
   */
  uint16_t msg_size;

  /**
   * How many bytes of the message are still missing?  Defragmentation
   * is complete when @e msg_missing == 0.
   */
  uint16_t msg_missing;

  /* Followed by @e msg_size bytes of the (partially) defragmented original
   * message */

  /* Followed by @e bitfield data */
};


/**
 * A neighbour that at least one communicator is connected to.
 */
struct Neighbour
{

  /**
   * Which peer is this about?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Map with `struct ReassemblyContext` structs for fragments under
   * reassembly. May be NULL if we currently have no fragments from
   * this @e pid (lazy initialization).
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *reassembly_map;

  /**
   * Heap with `struct ReassemblyContext` structs for fragments under
   * reassembly. May be NULL if we currently have no fragments from
   * this @e pid (lazy initialization).
   */
  struct GNUNET_CONTAINER_Heap *reassembly_heap;

  /**
   * Task to free old entries from the @e reassembly_heap and @e reassembly_map.
   */
  struct GNUNET_SCHEDULER_Task *reassembly_timeout_task;

  /**
   * Head of MDLL of DV hops that have this neighbour as next hop. Must be
   * purged if this neighbour goes down.
   */
  struct DistanceVectorHop *dv_head;

  /**
   * Tail of MDLL of DV hops that have this neighbour as next hop. Must be
   * purged if this neighbour goes down.
   */
  struct DistanceVectorHop *dv_tail;

  /**
   * Head of DLL of queues to this peer.
   */
  struct Queue *queue_head;

  /**
   * Tail of DLL of queues to this peer.
   */
  struct Queue *queue_tail;

  /**
   * Handle for an operation to fetch @e last_dv_learn_monotime information from
   * the PEERSTORE, or NULL.
   */
  struct GNUNET_PEERSTORE_IterateContext *get;

  /**
   * Handle to a PEERSTORE store operation to store this @e pid's @e
   * @e last_dv_learn_monotime.  NULL if no PEERSTORE operation is pending.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * Do we have a confirmed working queue and are thus visible to
   * CORE?  If so, this is the virtual link, otherwise NULL.
   */
  struct VirtualLink *vl;

  /**
   * Latest DVLearn monotonic time seen from this peer.  Initialized only
   * if @e dl_monotime_available is #GNUNET_YES.
   */
  struct GNUNET_TIME_Absolute last_dv_learn_monotime;

  /**
   * Do we have the lastest value for @e last_dv_learn_monotime from
   * PEERSTORE yet, or are we still waiting for a reply of PEERSTORE?
   */
  int dv_monotime_available;
};


/**
 * A peer that an application (client) would like us to talk to directly.
 */
struct PeerRequest
{

  /**
   * Which peer is this about?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Client responsible for the request.
   */
  struct TransportClient *tc;

  /**
   * Handle for watching the peerstore for HELLOs for this peer.
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * What kind of performance preference does this @e tc have?
   *
   * TODO: use this!
   */
  enum GNUNET_MQ_PriorityPreferences pk;

  /**
   * How much bandwidth would this @e tc like to see?
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;
};


/**
 * Types of different pending messages.
 */
enum PendingMessageType
{

  /**
   * Ordinary message received from the CORE service.
   */
  PMT_CORE = 0,

  /**
   * Fragment box.
   */
  PMT_FRAGMENT_BOX = 1,

  /**
   * Reliability box.
   */
  PMT_RELIABILITY_BOX = 2

};


/**
 * Transmission request that is awaiting delivery.  The original
 * transmission requests from CORE may be too big for some queues.
 * In this case, a *tree* of fragments is created.  At each
 * level of the tree, fragments are kept in a DLL ordered by which
 * fragment should be sent next (at the head).  The tree is searched
 * top-down, with the original message at the root.
 *
 * To select a node for transmission, first it is checked if the
 * current node's message fits with the MTU.  If it does not, we
 * either calculate the next fragment (based on @e frag_off) from the
 * current node, or, if all fragments have already been created,
 * descend to the @e head_frag.  Even though the node was already
 * fragmented, the fragment may be too big if the fragment was
 * generated for a queue with a larger MTU. In this case, the node
 * may be fragmented again, thus creating a tree.
 *
 * When acknowledgements for fragments are received, the tree
 * must be pruned, removing those parts that were already
 * acknowledged.  When fragments are sent over a reliable
 * channel, they can be immediately removed.
 *
 * If a message is ever fragmented, then the original "full" message
 * is never again transmitted (even if it fits below the MTU), and
 * only (remaining) fragments are sent.
 */
struct PendingMessage
{
  /**
   * Kept in a MDLL of messages for this @a vl.
   */
  struct PendingMessage *next_vl;

  /**
   * Kept in a MDLL of messages for this @a vl.
   */
  struct PendingMessage *prev_vl;

  /**
   * Kept in a MDLL of messages from this @a client (if @e pmt is #PMT_CORE)
   */
  struct PendingMessage *next_client;

  /**
   * Kept in a MDLL of messages from this @a client  (if @e pmt is #PMT_CORE)
   */
  struct PendingMessage *prev_client;

  /**
   * Kept in a MDLL of messages from this @a cpm (if @e pmt is
   * #PMT_FRAGMENT_BOx)
   */
  struct PendingMessage *next_frag;

  /**
   * Kept in a MDLL of messages from this @a cpm  (if @e pmt is
   * #PMT_FRAGMENT_BOX)
   */
  struct PendingMessage *prev_frag;

  /**
   * Head of DLL of PAs for this pending message.
   */
  struct PendingAcknowledgement *pa_head;

  /**
   * Tail of DLL of PAs for this pending message.
   */
  struct PendingAcknowledgement *pa_tail;

  /**
   * This message, reliability boxed. Only possibly available if @e pmt is
   * #PMT_CORE.
   */
  struct PendingMessage *bpm;

  /**
   * Target of the request (always the ultimate destination!).
   */
  struct VirtualLink *vl;

  /**
   * Set to non-NULL value if this message is currently being given to a
   * communicator and we are awaiting that communicator's acknowledgement.
   * Note that we must not retransmit a pending message while we're still
   * in the process of giving it to a communicator. If a pending message
   * is free'd while this entry is non-NULL, the @e qe reference to us
   * should simply be set to NULL.
   */
  struct QueueEntry *qe;

  /**
   * Client that issued the transmission request, if @e pmt is #PMT_CORE.
   */
  struct TransportClient *client;

  /**
   * Head of a MDLL of fragments created for this core message.
   */
  struct PendingMessage *head_frag;

  /**
   * Tail of a MDLL of fragments created for this core message.
   */
  struct PendingMessage *tail_frag;

  /**
   * Our parent in the fragmentation tree.
   */
  struct PendingMessage *frag_parent;

  /**
   * At what time should we give up on the transmission (and no longer retry)?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * What is the earliest time for us to retry transmission of this message?
   */
  struct GNUNET_TIME_Absolute next_attempt;

  /**
   * UUID to use for this message (used for reassembly of fragments, only
   * initialized if @e msg_uuid_set is #GNUNET_YES).
   */
  struct MessageUUIDP msg_uuid;

  /**
   * UUID we use to identify this message in our logs.
   * Generated by incrementing the "logging_uuid_gen".
   */
  unsigned long long logging_uuid;

  /**
   * Type of the pending message.
   */
  enum PendingMessageType pmt;

  /**
   * Preferences for this message.
   * TODO: actually use this!
   */
  enum GNUNET_MQ_PriorityPreferences prefs;

  /**
   * Size of the original message.
   */
  uint16_t bytes_msg;

  /**
   * Offset at which we should generate the next fragment.
   */
  uint16_t frag_off;

  /**
   * #GNUNET_YES once @e msg_uuid was initialized
   */
  int16_t msg_uuid_set;

  /* Followed by @e bytes_msg to transmit */
};


/**
 * Acknowledgement payload.
 */
struct TransportCummulativeAckPayload
{
  /**
   * When did we receive the message we are ACKing?  Used to calculate
   * the delay we introduced by cummulating ACKs.
   */
  struct GNUNET_TIME_Absolute receive_time;

  /**
   * UUID of a message being acknowledged.
   */
  struct AcknowledgementUUIDP ack_uuid;
};


/**
 * Data structure in which we track acknowledgements still to
 * be sent to the
 */
struct AcknowledgementCummulator
{
  /**
   * Target peer for which we are accumulating ACKs here.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * ACK data being accumulated.  Only @e num_acks slots are valid.
   */
  struct TransportCummulativeAckPayload ack_uuids[MAX_CUMMULATIVE_ACKS];

  /**
   * Task scheduled either to transmit the cummulative ACK message,
   * or to clean up this data structure after extended periods of
   * inactivity (if @e num_acks is zero).
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * When is @e task run (only used if @e num_acks is non-zero)?
   */
  struct GNUNET_TIME_Absolute min_transmission_time;

  /**
   * Counter to produce the `ack_counter` in the `struct
   * TransportReliabilityAckMessage`.  Allows the receiver to detect
   * lost ACK messages.  Incremented by @e num_acks upon transmission.
   */
  uint32_t ack_counter;

  /**
   * Number of entries used in @e ack_uuids.  Reset to 0 upon transmission.
   */
  unsigned int num_acks;
};


/**
 * One of the addresses of this peer.
 */
struct AddressListEntry
{

  /**
   * Kept in a DLL.
   */
  struct AddressListEntry *next;

  /**
   * Kept in a DLL.
   */
  struct AddressListEntry *prev;

  /**
   * Which communicator provides this address?
   */
  struct TransportClient *tc;

  /**
   * The actual address.
   */
  const char *address;

  /**
   * Current context for storing this address in the peerstore.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * Task to periodically do @e st operation.
   */
  struct GNUNET_SCHEDULER_Task *st;

  /**
   * What is a typical lifetime the communicator expects this
   * address to have? (Always from now.)
   */
  struct GNUNET_TIME_Relative expiration;

  /**
   * Address identifier used by the communicator.
   */
  uint32_t aid;

  /**
   * Network type offered by this address.
   */
  enum GNUNET_NetworkType nt;
};


/**
 * Client connected to the transport service.
 */
struct TransportClient
{

  /**
   * Kept in a DLL.
   */
  struct TransportClient *next;

  /**
   * Kept in a DLL.
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

  union
  {

    /**
     * Information for @e type #CT_CORE.
     */
    struct
    {

      /**
       * Head of list of messages pending for this client, sorted by
       * transmission time ("next_attempt" + possibly internal prioritization).
       */
      struct PendingMessage *pending_msg_head;

      /**
       * Tail of list of messages pending for this client.
       */
      struct PendingMessage *pending_msg_tail;

    } core;

    /**
     * Information for @e type #CT_MONITOR.
     */
    struct
    {

      /**
       * Peer identity to monitor the addresses of.
       * Zero to monitor all neighbours.  Valid if
       * @e type is #CT_MONITOR.
       */
      struct GNUNET_PeerIdentity peer;

      /**
       * Is this a one-shot monitor?
       */
      int one_shot;

    } monitor;


    /**
     * Information for @e type #CT_COMMUNICATOR.
     */
    struct
    {
      /**
       * If @e type is #CT_COMMUNICATOR, this communicator
       * supports communicating using these addresses.
       */
      char *address_prefix;

      /**
       * Head of DLL of queues offered by this communicator.
       */
      struct Queue *queue_head;

      /**
       * Tail of DLL of queues offered by this communicator.
       */
      struct Queue *queue_tail;

      /**
       * Head of list of the addresses of this peer offered by this
       * communicator.
       */
      struct AddressListEntry *addr_head;

      /**
       * Tail of list of the addresses of this peer offered by this
       * communicator.
       */
      struct AddressListEntry *addr_tail;

      /**
       * Number of queue entries in all queues to this communicator. Used
       * throttle sending to a communicator if we see that the communicator
       * is globally unable to keep up.
       */
      unsigned int total_queue_length;

      /**
       * Characteristics of this communicator.
       */
      enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc;

    } communicator;

    /**
     * Information for @e type #CT_APPLICATION
     */
    struct
    {

      /**
       * Map of requests for peers the given client application would like to
       * see connections for.  Maps from PIDs to `struct PeerRequest`.
       */
      struct GNUNET_CONTAINER_MultiPeerMap *requests;

    } application;

  } details;
};


/**
 * State we keep for validation activities.  Each of these
 * is both in the #validation_heap and the #validation_map.
 */
struct ValidationState
{

  /**
   * For which peer is @a address to be validated (or possibly valid)?
   * Serves as key in the #validation_map.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * How long did the peer claim this @e address to be valid? Capped at
   * minimum of #MAX_ADDRESS_VALID_UNTIL relative to the time where we last
   * were told about the address and the value claimed by the other peer at
   * that time.  May be updated similarly when validation succeeds.
   */
  struct GNUNET_TIME_Absolute valid_until;

  /**
   * How long do *we* consider this @e address to be valid?
   * In the past or zero if we have not yet validated it.
   */
  struct GNUNET_TIME_Absolute validated_until;

  /**
   * When did we FIRST use the current @e challenge in a message?
   * Used to sanity-check @code{origin_time} in the response when
   * calculating the RTT. If the @code{origin_time} is not in
   * the expected range, the response is discarded as malicious.
   */
  struct GNUNET_TIME_Absolute first_challenge_use;

  /**
   * When did we LAST use the current @e challenge in a message?
   * Used to sanity-check @code{origin_time} in the response when
   * calculating the RTT.  If the @code{origin_time} is not in
   * the expected range, the response is discarded as malicious.
   */
  struct GNUNET_TIME_Absolute last_challenge_use;

  /**
   * Next time we will send the @e challenge to the peer, if this time is past
   * @e valid_until, this validation state is released at this time.  If the
   * address is valid, @e next_challenge is set to @e validated_until MINUS @e
   * validation_delay * #VALIDATION_RTT_BUFFER_FACTOR, such that we will try
   * to re-validate before the validity actually expires.
   */
  struct GNUNET_TIME_Absolute next_challenge;

  /**
   * Current backoff factor we're applying for sending the @a challenge.
   * Reset to 0 if the @a challenge is confirmed upon validation.
   * Reduced to minimum of #FAST_VALIDATION_CHALLENGE_FREQ and half of the
   * existing value if we receive an unvalidated address again over
   * another channel (and thus should consider the information "fresh").
   * Maximum is #MAX_VALIDATION_CHALLENGE_FREQ.
   */
  struct GNUNET_TIME_Relative challenge_backoff;

  /**
   * Initially set to "forever". Once @e validated_until is set, this value is
   * set to the RTT that tells us how long it took to receive the validation.
   */
  struct GNUNET_TIME_Relative validation_rtt;

  /**
   * The challenge we sent to the peer to get it to validate the address. Note
   * that we rotate the challenge whenever we update @e validated_until to
   * avoid attacks where a peer simply replays an old challenge in the future.
   * (We must not rotate more often as otherwise we may discard valid answers
   * due to packet losses, latency and reorderings on the network).
   */
  struct ChallengeNonceP challenge;

  /**
   * Claimed address of the peer.
   */
  char *address;

  /**
   * Entry in the #validation_heap, which is sorted by @e next_challenge. The
   * heap is used to figure out when the next validation activity should be
   * run.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Handle to a PEERSTORE store operation for this @e address.  NULL if
   * no PEERSTORE operation is pending.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * We are technically ready to send the challenge, but we are waiting for
   * the respective queue to become available for transmission.
   */
  int awaiting_queue;
};


/**
 * A Backtalker is a peer sending us backchannel messages. We use this
 * struct to detect monotonic time violations, cache ephemeral key
 * material (to avoid repeatedly checking signatures), and to synchronize
 * monotonic time with the PEERSTORE.
 */
struct Backtalker
{
  /**
   * Peer this is about.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Last (valid) monotonic time received from this sender.
   */
  struct GNUNET_TIME_Absolute monotonic_time;

  /**
   * When will this entry time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Last (valid) ephemeral key received from this sender.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey last_ephemeral;

  /**
   * Task associated with this backtalker. Can be for timeout,
   * or other asynchronous operations.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Communicator context waiting on this backchannel's @e get, or NULL.
   */
  struct CommunicatorMessageContext *cmc;

  /**
   * Handle for an operation to fetch @e monotonic_time information from the
   * PEERSTORE, or NULL.
   */
  struct GNUNET_PEERSTORE_IterateContext *get;

  /**
   * Handle to a PEERSTORE store operation for this @e pid's @e
   * monotonic_time.  NULL if no PEERSTORE operation is pending.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * Number of bytes of the original message body that follows after this
   * struct.
   */
  size_t body_size;
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
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Our public key.
 */
static struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *GST_my_private_key;

/**
 * Map from PIDs to `struct Neighbour` entries.  A peer is
 * a neighbour if we have an MQ to it from some communicator.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *neighbours;

/**
 * Map from PIDs to `struct Backtalker` entries.  A peer is
 * a backtalker if it recently send us backchannel messages.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *backtalkers;

/**
 * Map from PIDs to `struct AcknowledgementCummulator`s.
 * Here we track the cummulative ACKs for transmission.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *ack_cummulators;

/**
 * Map of pending acknowledgements, mapping `struct AcknowledgementUUID` to
 * a `struct PendingAcknowledgement`.
 */
static struct GNUNET_CONTAINER_MultiShortmap *pending_acks;

/**
 * Map from PIDs to `struct DistanceVector` entries describing
 * known paths to the peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *dv_routes;

/**
 * Map from PIDs to `struct ValidationState` entries describing
 * addresses we are aware of and their validity state.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *validation_map;

/**
 * Map from PIDs to `struct VirtualLink` entries describing
 * links CORE knows to exist.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *links;

/**
 * Map from challenges to `struct LearnLaunchEntry` values.
 */
static struct GNUNET_CONTAINER_MultiShortmap *dvlearn_map;

/**
 * Head of a DLL sorted by launch time.
 */
static struct LearnLaunchEntry *lle_head;

/**
 * Tail of a DLL sorted by launch time.
 */
static struct LearnLaunchEntry *lle_tail;

/**
 * MIN Heap sorted by "next_challenge" to `struct ValidationState` entries
 * sorting addresses we are aware of by when we should next try to (re)validate
 * (or expire) them.
 */
static struct GNUNET_CONTAINER_Heap *validation_heap;

/**
 * Database for peer's HELLOs.
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Task run to initiate DV learning.
 */
static struct GNUNET_SCHEDULER_Task *dvlearn_task;

/**
 * Task to run address validation.
 */
static struct GNUNET_SCHEDULER_Task *validation_task;

/**
 * The most recent PA we have created, head of DLL.
 * The length of the DLL is kept in #pa_count.
 */
static struct PendingAcknowledgement *pa_head;

/**
 * The oldest PA we have created, tail of DLL.
 * The length of the DLL is kept in #pa_count.
 */
static struct PendingAcknowledgement *pa_tail;

/**
 * Generator of `logging_uuid` in `struct PendingMessage`.
 */
static unsigned long long logging_uuid_gen;

/**
 * Number of entries in the #pa_head/#pa_tail DLL.  Used to
 * limit the size of the data structure.
 */
static unsigned int pa_count;

/**
 * Monotonic time we use for HELLOs generated at this time.  TODO: we
 * should increase this value from time to time (i.e. whenever a
 * `struct AddressListEntry` actually expires), but IF we do this, we
 * must also update *all* (remaining) addresses in the PEERSTORE at
 * that time! (So for now only increased when the peer is restarted,
 * which hopefully roughly matches whenever our addresses change.)
 */
static struct GNUNET_TIME_Absolute hello_mono_time;


/**
 * Get an offset into the transmission history buffer for `struct
 * PerformanceData`.  Note that the caller must perform the required
 * modulo #GOODPUT_AGING_SLOTS operation before indexing into the
 * array!
 *
 * An 'age' lasts 15 minute slots.
 *
 * @return current age of the world
 */
static unsigned int
get_age ()
{
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  return now.abs_value_us / GNUNET_TIME_UNIT_MINUTES.rel_value_us / 15;
}


/**
 * Release @a pa data structure.
 *
 * @param pa data structure to release
 */
static void
free_pending_acknowledgement (struct PendingAcknowledgement *pa)
{
  struct Queue *q = pa->queue;
  struct PendingMessage *pm = pa->pm;
  struct DistanceVectorHop *dvh = pa->dvh;

  GNUNET_CONTAINER_MDLL_remove (pa, pa_head, pa_tail, pa);
  pa_count--;
  if (NULL != q)
  {
    GNUNET_CONTAINER_MDLL_remove (queue, q->pa_head, q->pa_tail, pa);
    pa->queue = NULL;
  }
  if (NULL != pm)
  {
    GNUNET_CONTAINER_MDLL_remove (pm, pm->pa_head, pm->pa_tail, pa);
    pa->pm = NULL;
  }
  if (NULL != dvh)
  {
    GNUNET_CONTAINER_MDLL_remove (dvh, dvh->pa_head, dvh->pa_tail, pa);
    pa->queue = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multishortmap_remove (pending_acks,
                                                        &pa->ack_uuid.value,
                                                        pa));
  GNUNET_free (pa);
}


/**
 * Free fragment tree below @e root, excluding @e root itself.
 * FIXME: this does NOT seem to have the intended semantics
 * based on how this is called. Seems we generally DO expect
 * @a root to be free'ed itself as well!
 *
 * @param root root of the tree to free
 */
static void
free_fragment_tree (struct PendingMessage *root)
{
  struct PendingMessage *frag;

  while (NULL != (frag = root->head_frag))
  {
    struct PendingAcknowledgement *pa;

    free_fragment_tree (frag);
    while (NULL != (pa = frag->pa_head))
    {
      GNUNET_CONTAINER_MDLL_remove (pm, frag->pa_head, frag->pa_tail, pa);
      pa->pm = NULL;
    }
    GNUNET_CONTAINER_MDLL_remove (frag, root->head_frag, root->tail_frag, frag);
    GNUNET_free (frag);
  }
}


/**
 * Release memory associated with @a pm and remove @a pm from associated
 * data structures.  @a pm must be a top-level pending message and not
 * a fragment in the tree.  The entire tree is freed (if applicable).
 *
 * @param pm the pending message to free
 */
static void
free_pending_message (struct PendingMessage *pm)
{
  struct TransportClient *tc = pm->client;
  struct VirtualLink *vl = pm->vl;
  struct PendingAcknowledgement *pa;

  if (NULL != tc)
  {
    GNUNET_CONTAINER_MDLL_remove (client,
                                  tc->details.core.pending_msg_head,
                                  tc->details.core.pending_msg_tail,
                                  pm);
  }
  if (NULL != vl)
  {
    GNUNET_CONTAINER_MDLL_remove (vl,
                                  vl->pending_msg_head,
                                  vl->pending_msg_tail,
                                  pm);
  }
  while (NULL != (pa = pm->pa_head))
  {
    GNUNET_CONTAINER_MDLL_remove (pm, pm->pa_head, pm->pa_tail, pa);
    pa->pm = NULL;
  }

  free_fragment_tree (pm);
  if (NULL != pm->qe)
  {
    GNUNET_assert (pm == pm->qe->pm);
    pm->qe->pm = NULL;
  }
  GNUNET_free_non_null (pm->bpm);
  GNUNET_free (pm);
}


/**
 * Free virtual link.
 *
 * @param vl link data to free
 */
static void
free_virtual_link (struct VirtualLink *vl)
{
  struct PendingMessage *pm;

  while (NULL != (pm = vl->pending_msg_head))
    free_pending_message (pm);
  GNUNET_CONTAINER_multipeermap_remove (links, &vl->target, vl);
  if (NULL != vl->visibility_task)
  {
    GNUNET_SCHEDULER_cancel (vl->visibility_task);
    vl->visibility_task = NULL;
  }
  GNUNET_break (NULL == vl->n);
  GNUNET_break (NULL == vl->dv);
  GNUNET_free (vl);
}


/**
 * Free validation state.
 *
 * @param vs validation state to free
 */
static void
free_validation_state (struct ValidationState *vs)
{
  GNUNET_CONTAINER_multipeermap_remove (validation_map, &vs->pid, vs);
  GNUNET_CONTAINER_heap_remove_node (vs->hn);
  vs->hn = NULL;
  if (NULL != vs->sc)
  {
    GNUNET_PEERSTORE_store_cancel (vs->sc);
    vs->sc = NULL;
  }
  GNUNET_free (vs->address);
  GNUNET_free (vs);
}


/**
 * Lookup neighbour record for peer @a pid.
 *
 * @param pid neighbour to look for
 * @return NULL if we do not have this peer as a neighbour
 */
static struct Neighbour *
lookup_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multipeermap_get (neighbours, pid);
}


/**
 * Details about what to notify monitors about.
 */
struct MonitorEvent
{
  /**
   * @deprecated To be discussed if we keep these...
   */
  struct GNUNET_TIME_Absolute last_validation;
  struct GNUNET_TIME_Absolute valid_until;
  struct GNUNET_TIME_Absolute next_validation;

  /**
   * Current round-trip time estimate.
   */
  struct GNUNET_TIME_Relative rtt;

  /**
   * Connection status.
   */
  enum GNUNET_TRANSPORT_ConnectionStatus cs;

  /**
   * Messages pending.
   */
  uint32_t num_msg_pending;

  /**
   * Bytes pending.
   */
  uint32_t num_bytes_pending;
};


/**
 * Free a @dvh. Callers MAY want to check if this was the last path to the
 * `target`, and if so call #free_dv_route to also free the associated DV
 * entry in #dv_routes (if not, the associated scheduler job should eventually
 * take care of it).
 *
 * @param dvh hop to free
 */
static void
free_distance_vector_hop (struct DistanceVectorHop *dvh)
{
  struct Neighbour *n = dvh->next_hop;
  struct DistanceVector *dv = dvh->dv;
  struct PendingAcknowledgement *pa;

  while (NULL != (pa = dvh->pa_head))
  {
    GNUNET_CONTAINER_MDLL_remove (dvh, dvh->pa_head, dvh->pa_tail, pa);
    pa->dvh = NULL;
  }
  GNUNET_CONTAINER_MDLL_remove (neighbour, n->dv_head, n->dv_tail, dvh);
  GNUNET_CONTAINER_MDLL_remove (dv, dv->dv_head, dv->dv_tail, dvh);
  GNUNET_free (dvh);
}


/**
 * Task run to check whether the hops of the @a cls still
 * are validated, or if we need to core about disconnection.
 *
 * @param cls a `struct VirtualLink`
 */
static void
check_link_down (void *cls);


/**
 * Send message to CORE clients that we lost a connection.
 *
 * @param pid peer the connection was for
 */
static void
cores_send_disconnect_info (const struct GNUNET_PeerIdentity *pid)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Informing CORE clients about disconnect from %s\n",
              GNUNET_i2s (pid));
  for (struct TransportClient *tc = clients_head; NULL != tc; tc = tc->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct DisconnectInfoMessage *dim;

    if (CT_CORE != tc->type)
      continue;
    env = GNUNET_MQ_msg (dim, GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
    dim->peer = *pid;
    GNUNET_MQ_send (tc->mq, env);
  }
}


/**
 * Free entry in #dv_routes.  First frees all hops to the target, and
 * if there are no entries left, frees @a dv as well.
 *
 * @param dv route to free
 */
static void
free_dv_route (struct DistanceVector *dv)
{
  struct DistanceVectorHop *dvh;

  while (NULL != (dvh = dv->dv_head))
    free_distance_vector_hop (dvh);
  if (NULL == dv->dv_head)
  {
    struct VirtualLink *vl;

    GNUNET_assert (
      GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_remove (dv_routes, &dv->target, dv));
    if (NULL != (vl = dv->vl))
    {
      GNUNET_assert (dv == vl->dv);
      vl->dv = NULL;
      if (NULL == vl->n)
      {
        cores_send_disconnect_info (&dv->target);
        free_virtual_link (vl);
      }
      else
      {
        GNUNET_SCHEDULER_cancel (vl->visibility_task);
        vl->visibility_task = GNUNET_SCHEDULER_add_now (&check_link_down, vl);
      }
      dv->vl = NULL;
    }

    if (NULL != dv->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (dv->timeout_task);
      dv->timeout_task = NULL;
    }
    GNUNET_free (dv);
  }
}


/**
 * Notify monitor @a tc about an event.  That @a tc
 * cares about the event has already been checked.
 *
 * Send @a tc information in @a me about a @a peer's status with
 * respect to some @a address to all monitors that care.
 *
 * @param tc monitor to inform
 * @param peer peer the information is about
 * @param address address the information is about
 * @param nt network type associated with @a address
 * @param me detailed information to transmit
 */
static void
notify_monitor (struct TransportClient *tc,
                const struct GNUNET_PeerIdentity *peer,
                const char *address,
                enum GNUNET_NetworkType nt,
                const struct MonitorEvent *me)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_MonitorData *md;
  size_t addr_len = strlen (address) + 1;

  env = GNUNET_MQ_msg_extra (md,
                             addr_len,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_DATA);
  md->nt = htonl ((uint32_t) nt);
  md->peer = *peer;
  md->last_validation = GNUNET_TIME_absolute_hton (me->last_validation);
  md->valid_until = GNUNET_TIME_absolute_hton (me->valid_until);
  md->next_validation = GNUNET_TIME_absolute_hton (me->next_validation);
  md->rtt = GNUNET_TIME_relative_hton (me->rtt);
  md->cs = htonl ((uint32_t) me->cs);
  md->num_msg_pending = htonl (me->num_msg_pending);
  md->num_bytes_pending = htonl (me->num_bytes_pending);
  memcpy (&md[1], address, addr_len);
  GNUNET_MQ_send (tc->mq, env);
}


/**
 * Send information in @a me about a @a peer's status with respect
 * to some @a address to all monitors that care.
 *
 * @param peer peer the information is about
 * @param address address the information is about
 * @param nt network type associated with @a address
 * @param me detailed information to transmit
 */
static void
notify_monitors (const struct GNUNET_PeerIdentity *peer,
                 const char *address,
                 enum GNUNET_NetworkType nt,
                 const struct MonitorEvent *me)
{
  for (struct TransportClient *tc = clients_head; NULL != tc; tc = tc->next)
  {
    if (CT_MONITOR != tc->type)
      continue;
    if (tc->details.monitor.one_shot)
      continue;
    if ((0 != GNUNET_is_zero (&tc->details.monitor.peer)) &&
        (0 != GNUNET_memcmp (&tc->details.monitor.peer, peer)))
      continue;
    notify_monitor (tc, peer, address, nt, me);
  }
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

  (void) cls;
  tc = GNUNET_new (struct TransportClient);
  tc->client = client;
  tc->mq = mq;
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, tc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", tc);
  return tc;
}


/**
 * Free @a rc
 *
 * @param rc data structure to free
 */
static void
free_reassembly_context (struct ReassemblyContext *rc)
{
  struct Neighbour *n = rc->neighbour;

  GNUNET_assert (rc == GNUNET_CONTAINER_heap_remove_node (rc->hn));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_remove (n->reassembly_map,
                                                         rc->msg_uuid.uuid,
                                                         rc));
  GNUNET_free (rc);
}


/**
 * Task run to clean up reassembly context of a neighbour that have expired.
 *
 * @param cls a `struct Neighbour`
 */
static void
reassembly_cleanup_task (void *cls)
{
  struct Neighbour *n = cls;
  struct ReassemblyContext *rc;

  n->reassembly_timeout_task = NULL;
  while (NULL != (rc = GNUNET_CONTAINER_heap_peek (n->reassembly_heap)))
  {
    if (0 == GNUNET_TIME_absolute_get_remaining (rc->reassembly_timeout)
               .rel_value_us)
    {
      free_reassembly_context (rc);
      continue;
    }
    GNUNET_assert (NULL == n->reassembly_timeout_task);
    n->reassembly_timeout_task =
      GNUNET_SCHEDULER_add_at (rc->reassembly_timeout,
                               &reassembly_cleanup_task,
                               n);
    return;
  }
}


/**
 * function called to #free_reassembly_context().
 *
 * @param cls NULL
 * @param key unused
 * @param value a `struct ReassemblyContext` to free
 * @return #GNUNET_OK (continue iteration)
 */
static int
free_reassembly_cb (void *cls, uint32_t key, void *value)
{
  struct ReassemblyContext *rc = value;

  (void) cls;
  (void) key;
  free_reassembly_context (rc);
  return GNUNET_OK;
}


/**
 * Release memory used by @a neighbour.
 *
 * @param neighbour neighbour entry to free
 */
static void
free_neighbour (struct Neighbour *neighbour)
{
  struct DistanceVectorHop *dvh;
  struct VirtualLink *vl;

  GNUNET_assert (NULL == neighbour->queue_head);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (neighbours,
                                                       &neighbour->pid,
                                                       neighbour));
  if (NULL != neighbour->reassembly_map)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (neighbour->reassembly_map,
                                             &free_reassembly_cb,
                                             NULL);
    GNUNET_CONTAINER_multihashmap32_destroy (neighbour->reassembly_map);
    neighbour->reassembly_map = NULL;
    GNUNET_CONTAINER_heap_destroy (neighbour->reassembly_heap);
    neighbour->reassembly_heap = NULL;
  }
  while (NULL != (dvh = neighbour->dv_head))
  {
    struct DistanceVector *dv = dvh->dv;

    free_distance_vector_hop (dvh);
    if (NULL == dv->dv_head)
      free_dv_route (dv);
  }
  if (NULL != neighbour->reassembly_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (neighbour->reassembly_timeout_task);
    neighbour->reassembly_timeout_task = NULL;
  }
  if (NULL != neighbour->get)
  {
    GNUNET_PEERSTORE_iterate_cancel (neighbour->get);
    neighbour->get = NULL;
  }
  if (NULL != neighbour->sc)
  {
    GNUNET_PEERSTORE_store_cancel (neighbour->sc);
    neighbour->sc = NULL;
  }
  if (NULL != (vl = neighbour->vl))
  {
    GNUNET_assert (neighbour == vl->n);
    vl->n = NULL;
    if (NULL == vl->dv)
    {
      cores_send_disconnect_info (&vl->target);
      free_virtual_link (vl);
    }
    else
    {
      GNUNET_SCHEDULER_cancel (vl->visibility_task);
      vl->visibility_task = GNUNET_SCHEDULER_add_now (&check_link_down, vl);
    }
    neighbour->vl = NULL;
  }
  GNUNET_free (neighbour);
}


/**
 * Send message to CORE clients that we lost a connection.
 *
 * @param tc client to inform (must be CORE client)
 * @param pid peer the connection is for
 */
static void
core_send_connect_info (struct TransportClient *tc,
                        const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_MQ_Envelope *env;
  struct ConnectInfoMessage *cim;

  GNUNET_assert (CT_CORE == tc->type);
  env = GNUNET_MQ_msg (cim, GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim->id = *pid;
  GNUNET_MQ_send (tc->mq, env);
}


/**
 * Send message to CORE clients that we gained a connection
 *
 * @param pid peer the queue was for
 */
static void
cores_send_connect_info (const struct GNUNET_PeerIdentity *pid)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Informing CORE clients about connection to %s\n",
              GNUNET_i2s (pid));
  for (struct TransportClient *tc = clients_head; NULL != tc; tc = tc->next)
  {
    if (CT_CORE != tc->type)
      continue;
    core_send_connect_info (tc, pid);
  }
}


/**
 * We believe we are ready to transmit a message on a queue. Gives the
 * message to the communicator for transmission (updating the tracker,
 * and re-scheduling itself if applicable).
 *
 * @param cls the `struct Queue` to process transmissions for
 */
static void
transmit_on_queue (void *cls);


/**
 * Called whenever something changed that might effect when we
 * try to do the next transmission on @a queue using #transmit_on_queue().
 *
 * @param queue the queue to do scheduling for
 * @param p task priority to use, if @a queue is scheduled
 */
static void
schedule_transmit_on_queue (struct Queue *queue,
                            enum GNUNET_SCHEDULER_Priority p)
{
  if (queue->tc->details.communicator.total_queue_length >=
      COMMUNICATOR_TOTAL_QUEUE_LIMIT)
  {
    GNUNET_STATISTICS_update (
      GST_stats,
      "# Transmission throttled due to communicator queue limit",
      1,
      GNUNET_NO);
    queue->idle = GNUNET_NO;
    return;
  }
  if (queue->queue_length >= QUEUE_LENGTH_LIMIT)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              "# Transmission throttled due to queue queue limit",
                              1,
                              GNUNET_NO);
    queue->idle = GNUNET_NO;
    return;
  }
  /* queue might indeed be ready, schedule it */
  if (NULL != queue->transmit_task)
    GNUNET_SCHEDULER_cancel (queue->transmit_task);
  queue->transmit_task =
    GNUNET_SCHEDULER_add_with_priority (p, &transmit_on_queue, queue);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Considering transmission on queue `%s' to %s\n",
              queue->address,
              GNUNET_i2s (&queue->neighbour->pid));
}


/**
 * Task run to check whether the hops of the @a cls still
 * are validated, or if we need to core about disconnection.
 *
 * @param cls a `struct VirtualLink`
 */
static void
check_link_down (void *cls)
{
  struct VirtualLink *vl = cls;
  struct DistanceVector *dv = vl->dv;
  struct Neighbour *n = vl->n;
  struct GNUNET_TIME_Absolute dvh_timeout;
  struct GNUNET_TIME_Absolute q_timeout;

  vl->visibility_task = NULL;
  dvh_timeout = GNUNET_TIME_UNIT_ZERO_ABS;
  for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
       pos = pos->next_dv)
    dvh_timeout = GNUNET_TIME_absolute_max (dvh_timeout, pos->path_valid_until);
  if (0 == GNUNET_TIME_absolute_get_remaining (dvh_timeout).rel_value_us)
  {
    vl->dv->vl = NULL;
    vl->dv = NULL;
  }
  q_timeout = GNUNET_TIME_UNIT_ZERO_ABS;
  for (struct Queue *q = n->queue_head; NULL != q; q = q->next_neighbour)
    q_timeout = GNUNET_TIME_absolute_max (q_timeout, q->validated_until);
  if (0 == GNUNET_TIME_absolute_get_remaining (q_timeout).rel_value_us)
  {
    vl->n->vl = NULL;
    vl->n = NULL;
  }
  if ((NULL == vl->n) && (NULL == vl->dv))
  {
    cores_send_disconnect_info (&vl->target);
    free_virtual_link (vl);
    return;
  }
  vl->visibility_task =
    GNUNET_SCHEDULER_add_at (GNUNET_TIME_absolute_max (q_timeout, dvh_timeout),
                             &check_link_down,
                             vl);
}


/**
 * Free @a queue.
 *
 * @param queue the queue to free
 */
static void
free_queue (struct Queue *queue)
{
  struct Neighbour *neighbour = queue->neighbour;
  struct TransportClient *tc = queue->tc;
  struct MonitorEvent me = {.cs = GNUNET_TRANSPORT_CS_DOWN,
                            .rtt = GNUNET_TIME_UNIT_FOREVER_REL};
  struct QueueEntry *qe;
  int maxxed;
  struct PendingAcknowledgement *pa;
  struct VirtualLink *vl;

  if (NULL != queue->transmit_task)
  {
    GNUNET_SCHEDULER_cancel (queue->transmit_task);
    queue->transmit_task = NULL;
  }
  while (NULL != (pa = queue->pa_head))
  {
    GNUNET_CONTAINER_MDLL_remove (queue, queue->pa_head, queue->pa_tail, pa);
    pa->queue = NULL;
  }

  GNUNET_CONTAINER_MDLL_remove (neighbour,
                                neighbour->queue_head,
                                neighbour->queue_tail,
                                queue);
  GNUNET_CONTAINER_MDLL_remove (client,
                                tc->details.communicator.queue_head,
                                tc->details.communicator.queue_tail,
                                queue);
  maxxed = (COMMUNICATOR_TOTAL_QUEUE_LIMIT >=
            tc->details.communicator.total_queue_length);
  while (NULL != (qe = queue->queue_head))
  {
    GNUNET_CONTAINER_DLL_remove (queue->queue_head, queue->queue_tail, qe);
    queue->queue_length--;
    tc->details.communicator.total_queue_length--;
    if (NULL != qe->pm)
    {
      GNUNET_assert (qe == qe->pm->qe);
      qe->pm->qe = NULL;
    }
    GNUNET_free (qe);
  }
  GNUNET_assert (0 == queue->queue_length);
  if ((maxxed) && (COMMUNICATOR_TOTAL_QUEUE_LIMIT <
                   tc->details.communicator.total_queue_length))
  {
    /* Communicator dropped below threshold, resume all _other_ queues */
    GNUNET_STATISTICS_update (
      GST_stats,
      "# Transmission throttled due to communicator queue limit",
      -1,
      GNUNET_NO);
    for (struct Queue *s = tc->details.communicator.queue_head; NULL != s;
         s = s->next_client)
      schedule_transmit_on_queue (s, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  }
  notify_monitors (&neighbour->pid, queue->address, queue->nt, &me);
  GNUNET_free (queue);

  vl = GNUNET_CONTAINER_multipeermap_get (links, &neighbour->pid);
  if ((NULL != vl) && (neighbour == vl->n))
  {
    GNUNET_SCHEDULER_cancel (vl->visibility_task);
    check_link_down (vl);
  }
  if (NULL == neighbour->queue_head)
  {
    free_neighbour (neighbour);
  }
}


/**
 * Free @a ale
 *
 * @param ale address list entry to free
 */
static void
free_address_list_entry (struct AddressListEntry *ale)
{
  struct TransportClient *tc = ale->tc;

  GNUNET_CONTAINER_DLL_remove (tc->details.communicator.addr_head,
                               tc->details.communicator.addr_tail,
                               ale);
  if (NULL != ale->sc)
  {
    GNUNET_PEERSTORE_store_cancel (ale->sc);
    ale->sc = NULL;
  }
  if (NULL != ale->st)
  {
    GNUNET_SCHEDULER_cancel (ale->st);
    ale->st = NULL;
  }
  GNUNET_free (ale);
}


/**
 * Stop the peer request in @a value.
 *
 * @param cls a `struct TransportClient` that no longer makes the request
 * @param pid the peer's identity
 * @param value a `struct PeerRequest`
 * @return #GNUNET_YES (always)
 */
static int
stop_peer_request (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct TransportClient *tc = cls;
  struct PeerRequest *pr = value;

  GNUNET_PEERSTORE_watch_cancel (pr->wc);
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (tc->details.application.requests,
                                          pid,
                                          pr));
  GNUNET_free (pr);

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

  (void) cls;
  (void) client;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected, cleaning up.\n",
              tc);
  GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, tc);
  switch (tc->type)
  {
  case CT_NONE:
    break;
  case CT_CORE: {
    struct PendingMessage *pm;

    while (NULL != (pm = tc->details.core.pending_msg_head))
    {
      GNUNET_CONTAINER_MDLL_remove (client,
                                    tc->details.core.pending_msg_head,
                                    tc->details.core.pending_msg_tail,
                                    pm);
      pm->client = NULL;
    }
  }
  break;
  case CT_MONITOR:
    break;
  case CT_COMMUNICATOR: {
    struct Queue *q;
    struct AddressListEntry *ale;

    while (NULL != (q = tc->details.communicator.queue_head))
      free_queue (q);
    while (NULL != (ale = tc->details.communicator.addr_head))
      free_address_list_entry (ale);
    GNUNET_free (tc->details.communicator.address_prefix);
  }
  break;
  case CT_APPLICATION:
    GNUNET_CONTAINER_multipeermap_iterate (tc->details.application.requests,
                                           &stop_peer_request,
                                           tc);
    GNUNET_CONTAINER_multipeermap_destroy (tc->details.application.requests);
    break;
  }
  GNUNET_free (tc);
}


/**
 * Iterator telling new CORE client about all existing
 * connections to peers.
 *
 * @param cls the new `struct TransportClient`
 * @param pid a connected peer
 * @param value the `struct Neighbour` with more information
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_client_connect_info (void *cls,
                            const struct GNUNET_PeerIdentity *pid,
                            void *value)
{
  struct TransportClient *tc = cls;

  (void) value;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Telling new CORE client about existing connection to %s\n",
              GNUNET_i2s (pid));
  core_send_connect_info (tc, pid);
  return GNUNET_OK;
}


/**
 * Initialize a "CORE" client.  We got a start message from this
 * client, so add it to the list of clients for broadcasting of
 * inbound messages.
 *
 * @param cls the client
 * @param start the start message that was sent
 */
static void
handle_client_start (void *cls, const struct StartMessage *start)
{
  struct TransportClient *tc = cls;
  uint32_t options;

  options = ntohl (start->options);
  if ((0 != (1 & options)) &&
      (0 != GNUNET_memcmp (&start->self, &GST_my_identity)))
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
  tc->type = CT_CORE;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New CORE client with PID %s registered\n",
              GNUNET_i2s (&start->self));
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &notify_client_connect_info,
                                         tc);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls the client
 * @param obm the send message that was sent
 */
static int
check_client_send (void *cls, const struct OutboundMessage *obm)
{
  struct TransportClient *tc = cls;
  uint16_t size;
  const struct GNUNET_MessageHeader *obmm;

  if (CT_CORE != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
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
 * Send a response to the @a pm that we have processed a "send"
 * request.  Sends a confirmation to the "core" client responsible for
 * the original request and free's @a pm.
 *
 * @param pm handle to the original pending message
 */
static void
client_send_response (struct PendingMessage *pm)
{
  struct TransportClient *tc = pm->client;
  struct VirtualLink *vl = pm->vl;
  struct GNUNET_MQ_Envelope *env;
  struct SendOkMessage *som;

  if (NULL != tc)
  {
    env = GNUNET_MQ_msg (som, GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
    som->peer = vl->target;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Confirming transmission of <%llu> to %s\n",
                pm->logging_uuid,
                GNUNET_i2s (&vl->target));
    GNUNET_MQ_send (tc->mq, env);
  }
  free_pending_message (pm);
}


/**
 * Pick @a hops_array_length random DV paths satisfying @a options
 *
 * @param dv data structure to pick paths from
 * @param options constraints to satisfy
 * @param hops_array[out] set to the result
 * @param hops_array_length length of the @a hops_array
 * @return number of entries set in @a hops_array
 */
static unsigned int
pick_random_dv_hops (const struct DistanceVector *dv,
                     enum RouteMessageOptions options,
                     struct DistanceVectorHop **hops_array,
                     unsigned int hops_array_length)
{
  uint64_t choices[hops_array_length];
  uint64_t num_dv;
  unsigned int dv_count;

  /* Pick random vectors, but weighted by distance, giving more weight
     to shorter vectors */
  num_dv = 0;
  dv_count = 0;
  for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
       pos = pos->next_dv)
  {
    if ((0 == (options & RMO_UNCONFIRMED_ALLOWED)) &&
        (GNUNET_TIME_absolute_get_remaining (pos->path_valid_until)
           .rel_value_us == 0))
      continue; /* pos unconfirmed and confirmed required */
    num_dv += MAX_DV_HOPS_ALLOWED - pos->distance;
    dv_count++;
  }
  if (0 == dv_count)
    return 0;
  if (dv_count <= hops_array_length)
  {
    dv_count = 0;
    for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
         pos = pos->next_dv)
      hops_array[dv_count++] = pos;
    return dv_count;
  }
  for (unsigned int i = 0; i < hops_array_length; i++)
  {
    int ok = GNUNET_NO;
    while (GNUNET_NO == ok)
    {
      choices[i] =
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, num_dv);
      ok = GNUNET_YES;
      for (unsigned int j = 0; j < i; j++)
        if (choices[i] == choices[j])
        {
          ok = GNUNET_NO;
          break;
        }
    }
  }
  dv_count = 0;
  num_dv = 0;
  for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
       pos = pos->next_dv)
  {
    uint32_t delta = MAX_DV_HOPS_ALLOWED - pos->distance;

    if ((0 == (options & RMO_UNCONFIRMED_ALLOWED)) &&
        (GNUNET_TIME_absolute_get_remaining (pos->path_valid_until)
           .rel_value_us == 0))
      continue; /* pos unconfirmed and confirmed required */
    for (unsigned int i = 0; i < hops_array_length; i++)
      if ((num_dv <= choices[i]) && (num_dv + delta > choices[i]))
        hops_array[dv_count++] = pos;
    num_dv += delta;
  }
  return dv_count;
}


/**
 * There is a message at the head of the pending messages for @a vl
 * which may be ready for transmission. Check if a queue is ready to
 * take it.
 *
 * This function must (1) check for flow control to ensure that we can
 * right now send to @a vl, (2) check that the pending message in the
 * queue is actually eligible, (3) determine if any applicable queue
 * (direct neighbour or DVH path) is ready to accept messages, and
 * (4) prioritize based on the preferences associated with the
 * pending message.
 *
 * So yeah, easy.
 *
 * @param vl virtual link where we should check for transmission
 */
static void
check_vl_transmission (struct VirtualLink *vl)
{
  struct Neighbour *n = vl->n;
  struct DistanceVector *dv = vl->dv;
  struct GNUNET_TIME_Absolute now;
  int elig;

  /* FIXME-FC: need to implement virtual link flow control! */

  /* Check that we have an eligible pending message!
     (cheaper than having #transmit_on_queue() find out!) */
  elig = GNUNET_NO;
  for (struct PendingMessage *pm = vl->pending_msg_head; NULL != pm;
       pm = pm->next_vl)
  {
    if (NULL != pm->qe)
      continue; /* not eligible, is in a queue! */
    elig = GNUNET_YES;
    break;
  }
  if (GNUNET_NO == elig)
    return;

  /* Notify queues at direct neighbours that we are interested */
  now = GNUNET_TIME_absolute_get ();
  if (NULL != n)
  {
    for (struct Queue *queue = n->queue_head; NULL != queue;
         queue = queue->next_neighbour)
      if ((GNUNET_YES == queue->idle) &&
          (queue->validated_until.abs_value_us > now.abs_value_us))
        schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  }
  /* Notify queues via DV that we are interested */
  if (NULL != dv)
  {
    /* Do DV with lower scheduler priority, which effectively means that
       IF a neighbour exists and is available, we prefer it. */
    for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
         pos = pos->next_dv)
    {
      struct Neighbour *nh = pos->next_hop;

      if (pos->path_valid_until.abs_value_us <= now.abs_value_us)
        continue; /* skip this one: path not validated */
      for (struct Queue *queue = nh->queue_head; NULL != queue;
           queue = queue->next_neighbour)
        if ((GNUNET_YES == queue->idle) &&
            (queue->validated_until.abs_value_us > now.abs_value_us))
          schedule_transmit_on_queue (queue,
                                      GNUNET_SCHEDULER_PRIORITY_BACKGROUND);
    }
  }
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls the client
 * @param obm the send message that was sent
 */
static void
handle_client_send (void *cls, const struct OutboundMessage *obm)
{
  struct TransportClient *tc = cls;
  struct PendingMessage *pm;
  const struct GNUNET_MessageHeader *obmm;
  uint32_t bytes_msg;
  struct VirtualLink *vl;
  enum GNUNET_MQ_PriorityPreferences pp;

  GNUNET_assert (CT_CORE == tc->type);
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  bytes_msg = ntohs (obmm->size);
  pp = (enum GNUNET_MQ_PriorityPreferences) ntohl (obm->priority);
  vl = GNUNET_CONTAINER_multipeermap_get (links, &obm->peer);
  if (NULL == vl)
  {
    /* Failure: don't have this peer as a neighbour (anymore).
       Might have gone down asynchronously, so this is NOT
       a protocol violation by CORE. Still count the event,
       as this should be rare. */
    GNUNET_SERVICE_client_continue (tc->client);
    GNUNET_STATISTICS_update (GST_stats,
                              "# messages dropped (neighbour unknown)",
                              1,
                              GNUNET_NO);
    return;
  }

  pm = GNUNET_malloc (sizeof (struct PendingMessage) + bytes_msg);
  pm->logging_uuid = logging_uuid_gen++;
  pm->prefs = pp;
  pm->client = tc;
  pm->vl = vl;
  pm->bytes_msg = bytes_msg;
  memcpy (&pm[1], obmm, bytes_msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u bytes as <%llu> to %s\n",
              bytes_msg,
              pm->logging_uuid,
              GNUNET_i2s (&obm->peer));
  GNUNET_CONTAINER_MDLL_insert (client,
                                tc->details.core.pending_msg_head,
                                tc->details.core.pending_msg_tail,
                                pm);
  GNUNET_CONTAINER_MDLL_insert (vl,
                                vl->pending_msg_head,
                                vl->pending_msg_tail,
                                pm);
  check_vl_transmission (vl);
}


/**
 * Communicator started.  Test message is well-formed.
 *
 * @param cls the client
 * @param cam the send message that was sent
 */
static int
check_communicator_available (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *cam)
{
  struct TransportClient *tc = cls;
  uint16_t size;

  if (CT_NONE != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  tc->type = CT_COMMUNICATOR;
  size = ntohs (cam->header.size) - sizeof (*cam);
  if (0 == size)
    return GNUNET_OK; /* receive-only communicator */
  GNUNET_MQ_check_zero_termination (cam);
  return GNUNET_OK;
}


/**
 * Send ACK to communicator (if requested) and free @a cmc.
 *
 * @param cmc context for which we are done handling the message
 */
static void
finish_cmc_handling (struct CommunicatorMessageContext *cmc)
{
  if (0 != ntohl (cmc->im.fc_on))
  {
    /* send ACK when done to communicator for flow control! */
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_TRANSPORT_IncomingMessageAck *ack;

    env = GNUNET_MQ_msg (ack, GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK);
    ack->reserved = htonl (0);
    ack->fc_id = cmc->im.fc_id;
    ack->sender = cmc->im.sender;
    GNUNET_MQ_send (cmc->tc->mq, env);
  }
  GNUNET_SERVICE_client_continue (cmc->tc->client);
  GNUNET_free (cmc);
}


/**
 * Client confirms that it is done handling message(s) to a particular
 * peer. We may now provide more messages to CORE for this peer.
 *
 * Notifies the respective queues that more messages can now be received.
 *
 * @param cls the client
 * @param rom the message that was sent
 */
static void
handle_client_recv_ok (void *cls, const struct RecvOkMessage *rom)
{
  struct TransportClient *tc = cls;
  struct VirtualLink *vl;
  uint32_t delta;
  struct CommunicatorMessageContext *cmc;

  if (CT_CORE != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  vl = GNUNET_CONTAINER_multipeermap_get (links, &rom->peer);
  if (NULL == vl)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              "# RECV_OK dropped: virtual link unknown",
                              1,
                              GNUNET_NO);
    GNUNET_SERVICE_client_continue (tc->client);
    return;
  }
  delta = ntohl (rom->increase_window_delta);
  vl->core_recv_window += delta;
  if (vl->core_recv_window <= 0)
    return;
  /* resume communicators */
  while (NULL != (cmc = vl->cmc_tail))
  {
    GNUNET_CONTAINER_DLL_remove (vl->cmc_head, vl->cmc_tail, cmc);
    finish_cmc_handling (cmc);
  }
}


/**
 * Communicator started.  Process the request.
 *
 * @param cls the client
 * @param cam the send message that was sent
 */
static void
handle_communicator_available (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *cam)
{
  struct TransportClient *tc = cls;
  uint16_t size;

  size = ntohs (cam->header.size) - sizeof (*cam);
  if (0 == size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Receive-only communicator connected\n");
    return; /* receive-only communicator */
  }
  tc->details.communicator.address_prefix =
    GNUNET_strdup ((const char *) &cam[1]);
  tc->details.communicator.cc =
    (enum GNUNET_TRANSPORT_CommunicatorCharacteristics) ntohl (cam->cc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Communicator with prefix `%s' connected\n",
              tc->details.communicator.address_prefix);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Communicator requests backchannel transmission.  Check the request.
 *
 * @param cls the client
 * @param cb the send message that was sent
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_communicator_backchannel (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorBackchannel *cb)
{
  const struct GNUNET_MessageHeader *inbox;
  const char *is;
  uint16_t msize;
  uint16_t isize;

  (void) cls;
  msize = ntohs (cb->header.size) - sizeof (*cb);
  inbox = (const struct GNUNET_MessageHeader *) &cb[1];
  isize = ntohs (inbox->size);
  if (isize >= msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  is = (const char *) inbox;
  is += isize;
  msize -= isize;
  GNUNET_assert (0 < msize);
  if ('\0' != is[msize - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Ensure ephemeral keys in our @a dv are current. If no current one exists,
 * set it up.
 *
 * @param dv[in,out] virtual link to update ephemeral for
 */
static void
update_ephemeral (struct DistanceVector *dv)
{
  struct EphemeralConfirmationPS ec;

  if (0 !=
      GNUNET_TIME_absolute_get_remaining (dv->ephemeral_validity).rel_value_us)
    return;
  dv->monotime = GNUNET_TIME_absolute_get_monotonic (GST_cfg);
  dv->ephemeral_validity =
    GNUNET_TIME_absolute_add (dv->monotime, EPHEMERAL_VALIDITY);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdhe_key_create2 (&dv->private_key));
  GNUNET_CRYPTO_ecdhe_key_get_public (&dv->private_key, &dv->ephemeral_key);
  ec.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL);
  ec.purpose.size = htonl (sizeof (ec));
  ec.target = dv->target;
  ec.ephemeral_key = dv->ephemeral_key;
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
                                                        &ec.purpose,
                                                        &dv->sender_sig));
}


/**
 * Send the message @a payload on @a queue.
 *
 * @param queue the queue to use for transmission
 * @param pm pending message to update once transmission is done, may be NULL!
 * @param payload the payload to send (encapsulated in a
 *        #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG).
 * @param payload_size number of bytes in @a payload
 */
static void
queue_send_msg (struct Queue *queue,
                struct PendingMessage *pm,
                const void *payload,
                size_t payload_size)
{
  struct Neighbour *n = queue->neighbour;
  struct GNUNET_TRANSPORT_SendMessageTo *smt;
  struct GNUNET_MQ_Envelope *env;

  queue->idle = GNUNET_NO;
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Queueing %u bytes of payload for transmission <%llu> on queue %llu to %s\n",
    (unsigned int) payload_size,
    pm->logging_uuid,
    (unsigned long long) queue->qid,
    GNUNET_i2s (&queue->neighbour->pid));
  env = GNUNET_MQ_msg_extra (smt,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG);
  smt->qid = queue->qid;
  smt->mid = queue->mid_gen;
  smt->receiver = n->pid;
  memcpy (&smt[1], payload, payload_size);
  {
    /* Pass the env to the communicator of queue for transmission. */
    struct QueueEntry *qe;

    qe = GNUNET_new (struct QueueEntry);
    qe->mid = queue->mid_gen++;
    qe->queue = queue;
    if (NULL != pm)
    {
      qe->pm = pm;
      GNUNET_assert (NULL == pm->qe);
      pm->qe = qe;
    }
    GNUNET_CONTAINER_DLL_insert (queue->queue_head, queue->queue_tail, qe);
    GNUNET_assert (CT_COMMUNICATOR == queue->tc->type);
    queue->queue_length++;
    queue->tc->details.communicator.total_queue_length++;
    if (COMMUNICATOR_TOTAL_QUEUE_LIMIT ==
        queue->tc->details.communicator.total_queue_length)
      queue->idle = GNUNET_NO;
    if (QUEUE_LENGTH_LIMIT == queue->queue_length)
      queue->idle = GNUNET_NO;
    GNUNET_MQ_send (queue->tc->mq, env);
  }
}


/**
 * Pick a queue of @a n under constraints @a options and schedule
 * transmission of @a hdr.
 *
 * @param n neighbour to send to
 * @param hdr message to send as payload
 * @param options whether queues must be confirmed or not,
 *        and whether we may pick multiple (2) queues
 */
static void
route_via_neighbour (const struct Neighbour *n,
                     const struct GNUNET_MessageHeader *hdr,
                     enum RouteMessageOptions options)
{
  struct GNUNET_TIME_Absolute now;
  unsigned int candidates;
  unsigned int sel1;
  unsigned int sel2;

  /* Pick one or two 'random' queues from n (under constraints of options) */
  now = GNUNET_TIME_absolute_get ();
  /* FIXME-OPTIMIZE: give queues 'weights' and pick proportional to
     weight in the future; weight could be assigned by observed
     bandwidth (note: not sure if we should do this for this type
     of control traffic though). */
  candidates = 0;
  for (struct Queue *pos = n->queue_head; NULL != pos;
       pos = pos->next_neighbour)
  {
    if ((0 == (options & RMO_UNCONFIRMED_ALLOWED)) ||
        (pos->validated_until.abs_value_us > now.abs_value_us))
      candidates++;
  }
  if (0 == candidates)
  {
    /* This can happen rarely if the last confirmed queue timed
       out just as we were beginning to process this message. */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Could not route message of type %u to %s: no valid queue\n",
                ntohs (hdr->type),
                GNUNET_i2s (&n->pid));
    GNUNET_STATISTICS_update (GST_stats,
                              "# route selection failed (all no valid queue)",
                              1,
                              GNUNET_NO);
    return;
  }

  sel1 = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, candidates);
  if (0 == (options & RMO_REDUNDANT))
    sel2 = candidates; /* picks none! */
  else
    sel2 = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, candidates);
  candidates = 0;
  for (struct Queue *pos = n->queue_head; NULL != pos;
       pos = pos->next_neighbour)
  {
    if ((0 == (options & RMO_UNCONFIRMED_ALLOWED)) ||
        (pos->validated_until.abs_value_us > now.abs_value_us))
    {
      if ((sel1 == candidates) || (sel2 == candidates))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Routing message of type %u to %s using %s (#%u)\n",
                    ntohs (hdr->type),
                    GNUNET_i2s (&n->pid),
                    pos->address,
                    (sel1 == candidates) ? 1 : 2);
        queue_send_msg (pos, NULL, hdr, ntohs (hdr->size));
      }
      candidates++;
    }
  }
}


/**
 * Structure of the key material used to encrypt backchannel messages.
 */
struct DVKeyState
{
  /**
   * State of our block cipher.
   */
  gcry_cipher_hd_t cipher;

  /**
   * Actual key material.
   */
  struct
  {

    /**
     * Key used for HMAC calculations (via #GNUNET_CRYPTO_hmac()).
     */
    struct GNUNET_CRYPTO_AuthKey hmac_key;

    /**
     * Symmetric key to use for encryption.
     */
    char aes_key[256 / 8];

    /**
     * Counter value to use during setup.
     */
    char aes_ctr[128 / 8];

  } material;
};


/**
 * Given the key material in @a km and the initialization vector
 * @a iv, setup the key material for the backchannel in @a key.
 *
 * @param km raw master secret
 * @param iv initialization vector
 * @param key[out] symmetric cipher and HMAC state to generate
 */
static void
dv_setup_key_state_from_km (const struct GNUNET_HashCode *km,
                            const struct GNUNET_ShortHashCode *iv,
                            struct DVKeyState *key)
{
  /* must match #dh_key_derive_eph_pub */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (&key->material,
                                    sizeof (key->material),
                                    "transport-backchannel-key",
                                    strlen ("transport-backchannel-key"),
                                    &km,
                                    sizeof (km),
                                    iv,
                                    sizeof (*iv)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deriving backchannel key based on KM %s and IV %s\n",
              GNUNET_h2s (km),
              GNUNET_sh2s (iv));
  gcry_cipher_open (&key->cipher,
                    GCRY_CIPHER_AES256 /* low level: go for speed */,
                    GCRY_CIPHER_MODE_CTR,
                    0 /* flags */);
  gcry_cipher_setkey (key->cipher,
                      &key->material.aes_key,
                      sizeof (key->material.aes_key));
  gcry_cipher_setctr (key->cipher,
                      &key->material.aes_ctr,
                      sizeof (key->material.aes_ctr));
}


/**
 * Derive backchannel encryption key material from @a priv_ephemeral
 * and @a target and @a iv.
 *
 * @param priv_ephemeral ephemeral private key to use
 * @param target the target peer to encrypt to
 * @param iv unique IV to use
 * @param key[out] set to the key material
 */
static void
dh_key_derive_eph_pid (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *priv_ephemeral,
  const struct GNUNET_PeerIdentity *target,
  const struct GNUNET_ShortHashCode *iv,
  struct DVKeyState *key)
{
  struct GNUNET_HashCode km;

  GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_ecdh_eddsa (priv_ephemeral,
                                                         &target->public_key,
                                                         &km));
  dv_setup_key_state_from_km (&km, iv, key);
}


/**
 * Derive backchannel encryption key material from #GST_my_private_key
 * and @a pub_ephemeral and @a iv.
 *
 * @param priv_ephemeral ephemeral private key to use
 * @param target the target peer to encrypt to
 * @param iv unique IV to use
 * @param key[out] set to the key material
 */
static void
dh_key_derive_eph_pub (const struct GNUNET_CRYPTO_EcdhePublicKey *pub_ephemeral,
                       const struct GNUNET_ShortHashCode *iv,
                       struct DVKeyState *key)
{
  struct GNUNET_HashCode km;

  GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_eddsa_ecdh (GST_my_private_key,
                                                         pub_ephemeral,
                                                         &km));
  dv_setup_key_state_from_km (&km, iv, key);
}


/**
 * Do HMAC calculation for backchannel messages over @a data using key
 * material from @a key.
 *
 * @param key key material (from DH)
 * @param hmac[out] set to the HMAC
 * @param data data to perform HMAC calculation over
 * @param data_size number of bytes in @a data
 */
static void
dv_hmac (const struct DVKeyState *key,
         struct GNUNET_HashCode *hmac,
         const void *data,
         size_t data_size)
{
  GNUNET_CRYPTO_hmac (&key->material.hmac_key, data, data_size, hmac);
}


/**
 * Perform backchannel encryption using symmetric secret in @a key
 * to encrypt data from @a in to @a dst.
 *
 * @param key[in,out] key material to use
 * @param dst where to write the result
 * @param in input data to encrypt (plaintext)
 * @param in_size number of bytes of input in @a in and available at @a dst
 */
static void
dv_encrypt (struct DVKeyState *key, const void *in, void *dst, size_t in_size)
{
  GNUNET_assert (0 ==
                 gcry_cipher_encrypt (key->cipher, dst, in_size, in, in_size));
}


/**
 * Perform backchannel encryption using symmetric secret in @a key
 * to encrypt data from @a in to @a dst.
 *
 * @param key[in,out] key material to use
 * @param ciph cipher text to decrypt
 * @param out[out] output data to generate (plaintext)
 * @param out_size number of bytes of input in @a ciph and available in @a out
 */
static void
dv_decrypt (struct DVKeyState *key,
            void *out,
            const void *ciph,
            size_t out_size)
{
  GNUNET_assert (
    0 == gcry_cipher_decrypt (key->cipher, out, out_size, ciph, out_size));
}


/**
 * Clean up key material in @a key.
 *
 * @param key key material to clean up (memory must not be free'd!)
 */
static void
dv_key_clean (struct DVKeyState *key)
{
  gcry_cipher_close (key->cipher);
  GNUNET_CRYPTO_zero_keys (&key->material, sizeof (key->material));
}


/**
 * Function to call to further operate on the now DV encapsulated
 * message @a hdr, forwarding it via @a next_hop under respect of
 * @a options.
 *
 * @param cls closure
 * @param next_hop next hop of the DV path
 * @param hdr encapsulated message, technically a `struct TransportDFBoxMessage`
 * @param options options of the original message
 */
typedef void (*DVMessageHandler) (void *cls,
                                  struct Neighbour *next_hop,
                                  const struct GNUNET_MessageHeader *hdr,
                                  enum RouteMessageOptions options);

/**
 * Pick a path of @a dv under constraints @a options and schedule
 * transmission of @a hdr.
 *
 * @param target neighbour to ultimately send to
 * @param num_dvhs length of the @a dvhs array
 * @param dvhs array of hops to send the message to
 * @param hdr message to send as payload
 * @param use function to call with the encapsulated message
 * @param use_cls closure for @a use
 * @param options whether path must be confirmed or not, to be passed to @a use
 */
static void
encapsulate_for_dv (struct DistanceVector *dv,
                    unsigned int num_dvhs,
                    struct DistanceVectorHop **dvhs,
                    const struct GNUNET_MessageHeader *hdr,
                    DVMessageHandler use,
                    void *use_cls,
                    enum RouteMessageOptions options)
{
  struct TransportDVBoxMessage box_hdr;
  struct TransportDVBoxPayloadP payload_hdr;
  uint16_t enc_body_size = ntohs (hdr->size);
  char enc[sizeof (struct TransportDVBoxPayloadP) + enc_body_size] GNUNET_ALIGN;
  struct TransportDVBoxPayloadP *enc_payload_hdr =
    (struct TransportDVBoxPayloadP *) enc;
  struct DVKeyState key;

  /* Encrypt payload */
  box_hdr.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX);
  box_hdr.total_hops = htons (0);
  update_ephemeral (dv);
  box_hdr.ephemeral_key = dv->ephemeral_key;
  payload_hdr.sender_sig = dv->sender_sig;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &box_hdr.iv,
                              sizeof (box_hdr.iv));
  dh_key_derive_eph_pid (&dv->private_key, &dv->target, &box_hdr.iv, &key);
  payload_hdr.sender = GST_my_identity;
  payload_hdr.monotonic_time = GNUNET_TIME_absolute_hton (dv->monotime);
  dv_encrypt (&key, &payload_hdr, enc_payload_hdr, sizeof (payload_hdr));
  dv_encrypt (&key,
              hdr,
              &enc[sizeof (struct TransportDVBoxPayloadP)],
              enc_body_size);
  dv_hmac (&key, &box_hdr.hmac, enc, sizeof (enc));
  dv_key_clean (&key);

  /* For each selected path, take the pre-computed header and body
     and add the path in the middle of the message; then send it. */
  for (unsigned int i = 0; i < num_dvhs; i++)
  {
    struct DistanceVectorHop *dvh = dvhs[i];
    unsigned int num_hops = dvh->distance + 1;
    char buf[sizeof (struct TransportDVBoxMessage) +
             sizeof (struct GNUNET_PeerIdentity) * num_hops +
             sizeof (struct TransportDVBoxPayloadP) +
             enc_body_size] GNUNET_ALIGN;
    struct GNUNET_PeerIdentity *dhops;

    box_hdr.header.size = htons (sizeof (buf));
    box_hdr.num_hops = htons (num_hops);
    memcpy (buf, &box_hdr, sizeof (box_hdr));
    dhops = (struct GNUNET_PeerIdentity *) &buf[sizeof (box_hdr)];
    memcpy (dhops,
            dvh->path,
            dvh->distance * sizeof (struct GNUNET_PeerIdentity));
    dhops[dvh->distance] = dv->target;
    if (GNUNET_EXTRA_LOGGING > 0)
    {
      char *path;

      path = GNUNET_strdup (GNUNET_i2s (&GST_my_identity));
      for (unsigned int i = 0; i <= num_hops; i++)
      {
        char *tmp;

        GNUNET_asprintf (&tmp, "%s-%s", path, GNUNET_i2s (&dhops[i]));
        GNUNET_free (path);
        path = tmp;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Routing message of type %u to %s using DV (#%u/%u) via %s\n",
                  ntohs (hdr->type),
                  GNUNET_i2s (&dv->target),
                  i + 1,
                  num_dvhs + 1,
                  path);
      GNUNET_free (path);
    }

    memcpy (&dhops[num_hops], enc, sizeof (enc));
    use (use_cls,
         dvh->next_hop,
         (const struct GNUNET_MessageHeader *) buf,
         options);
  }
}


/**
 * Wrapper around #route_via_neighbour() that matches the
 * #DVMessageHandler structure.
 *
 * @param cls unused
 * @param next_hop where to send next
 * @param hdr header of the message to send
 * @param options message options for queue selection
 */
static void
send_dv_to_neighbour (void *cls,
                      struct Neighbour *next_hop,
                      const struct GNUNET_MessageHeader *hdr,
                      enum RouteMessageOptions options)
{
  (void) cls;
  route_via_neighbour (next_hop, hdr, options);
}


/**
 * We need to transmit @a hdr to @a target.  If necessary, this may
 * involve DV routing.
 *
 * @param target peer to receive @a hdr
 * @param hdr header of the message to route and #GNUNET_free()
 * @param options which transmission channels are allowed
 */
static void
route_message (const struct GNUNET_PeerIdentity *target,
               const struct GNUNET_MessageHeader *hdr,
               enum RouteMessageOptions options)
{
  struct VirtualLink *vl;
  struct Neighbour *n;
  struct DistanceVector *dv;

  vl = GNUNET_CONTAINER_multipeermap_get (links, target);
  n = vl->n;
  dv = (0 != (options & RMO_DV_ALLOWED)) ? vl->dv : NULL;
  if (0 == (options & RMO_UNCONFIRMED_ALLOWED))
  {
    /* if confirmed is required, and we do not have anything
       confirmed, drop respective options */
    if (NULL == n)
      n = lookup_neighbour (target);
    if ((NULL == dv) && (0 != (options & RMO_DV_ALLOWED)))
      dv = GNUNET_CONTAINER_multipeermap_get (dv_routes, target);
  }
  if ((NULL == n) && (NULL == dv))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Cannot route message of type %u to %s: no route\n",
                ntohs (hdr->type),
                GNUNET_i2s (target));
    GNUNET_STATISTICS_update (GST_stats,
                              "# Messages dropped in routing: no acceptable method",
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Routing message of type %u to %s with options %X\n",
              ntohs (hdr->type),
              GNUNET_i2s (target),
              (unsigned int) options);
  /* If both dv and n are possible and we must choose:
     flip a coin for the choice between the two; for now 50/50 */
  if ((NULL != n) && (NULL != dv) && (0 == (options & RMO_REDUNDANT)))
  {
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2))
      n = NULL;
    else
      dv = NULL;
  }
  if ((NULL != n) && (NULL != dv))
    options &= ~RMO_REDUNDANT; /* We will do one DV and one direct, that's
                                  enough for redunancy, so clear the flag. */
  if (NULL != n)
  {
    route_via_neighbour (n, hdr, options);
  }
  if (NULL != dv)
  {
    struct DistanceVectorHop *hops[2];
    unsigned int res;

    res = pick_random_dv_hops (dv,
                               options,
                               hops,
                               (0 == (options & RMO_REDUNDANT)) ? 1 : 2);
    if (0 == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Failed to route message, could not determine DV path\n");
      return;
    }
    encapsulate_for_dv (dv,
                        res,
                        hops,
                        hdr,
                        &send_dv_to_neighbour,
                        NULL,
                        options & (~RMO_REDUNDANT));
  }
}


/**
 * Communicator requests backchannel transmission.  Process the request.
 * Just repacks it into our `struct TransportBackchannelEncapsulationMessage *`
 * (which for now has exactly the same format, only a different message type)
 * and passes it on for routing.
 *
 * @param cls the client
 * @param cb the send message that was sent
 */
static void
handle_communicator_backchannel (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorBackchannel *cb)
{
  struct TransportClient *tc = cls;
  const struct GNUNET_MessageHeader *inbox =
    (const struct GNUNET_MessageHeader *) &cb[1];
  uint16_t isize = ntohs (inbox->size);
  const char *is = ((const char *) &cb[1]) + isize;
  char
    mbuf[isize +
         sizeof (struct TransportBackchannelEncapsulationMessage)] GNUNET_ALIGN;
  struct TransportBackchannelEncapsulationMessage *be =
    (struct TransportBackchannelEncapsulationMessage *) mbuf;

  /* 0-termination of 'is' was checked already in
     #check_communicator_backchannel() */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Preparing backchannel transmission to %s:%s of type %u\n",
              GNUNET_i2s (&cb->pid),
              is,
              ntohs (inbox->size));
  /* encapsulate and encrypt message */
  be->header.type =
    htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION);
  be->header.size = htons (sizeof (mbuf));
  memcpy (&be[1], inbox, isize);
  memcpy (&mbuf[sizeof (struct TransportBackchannelEncapsulationMessage) +
                isize],
          is,
          strlen (is) + 1);
  route_message (&cb->pid, &be->header, RMO_DV_ALLOWED);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Address of our peer added.  Test message is well-formed.
 *
 * @param cls the client
 * @param aam the send message that was sent
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_add_address (void *cls,
                   const struct GNUNET_TRANSPORT_AddAddressMessage *aam)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_MQ_check_zero_termination (aam);
  return GNUNET_OK;
}


/**
 * Ask peerstore to store our address.
 *
 * @param cls an `struct AddressListEntry *`
 */
static void
store_pi (void *cls);


/**
 * Function called when peerstore is done storing our address.
 *
 * @param cls a `struct AddressListEntry`
 * @param success #GNUNET_YES if peerstore was successful
 */
static void
peerstore_store_own_cb (void *cls, int success)
{
  struct AddressListEntry *ale = cls;

  ale->sc = NULL;
  if (GNUNET_YES != success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store our own address `%s' in peerstore!\n",
                ale->address);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully stored our own address `%s' in peerstore!\n",
                ale->address);
  /* refresh period is 1/4 of expiration time, that should be plenty
     without being excessive. */
  ale->st =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (ale->expiration,
                                                               4ULL),
                                  &store_pi,
                                  ale);
}


/**
 * Ask peerstore to store our address.
 *
 * @param cls an `struct AddressListEntry *`
 */
static void
store_pi (void *cls)
{
  struct AddressListEntry *ale = cls;
  void *addr;
  size_t addr_len;
  struct GNUNET_TIME_Absolute expiration;

  ale->st = NULL;
  expiration = GNUNET_TIME_relative_to_absolute (ale->expiration);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing our address `%s' in peerstore until %s!\n",
              ale->address,
              GNUNET_STRINGS_absolute_time_to_string (expiration));
  GNUNET_HELLO_sign_address (ale->address,
                             ale->nt,
                             hello_mono_time,
                             GST_my_private_key,
                             &addr,
                             &addr_len);
  ale->sc = GNUNET_PEERSTORE_store (peerstore,
                                    "transport",
                                    &GST_my_identity,
                                    GNUNET_PEERSTORE_TRANSPORT_HELLO_KEY,
                                    addr,
                                    addr_len,
                                    expiration,
                                    GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
                                    &peerstore_store_own_cb,
                                    ale);
  GNUNET_free (addr);
  if (NULL == ale->sc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to store our address `%s' with peerstore\n",
                ale->address);
    ale->st =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &store_pi, ale);
  }
}


/**
 * Address of our peer added.  Process the request.
 *
 * @param cls the client
 * @param aam the send message that was sent
 */
static void
handle_add_address (void *cls,
                    const struct GNUNET_TRANSPORT_AddAddressMessage *aam)
{
  struct TransportClient *tc = cls;
  struct AddressListEntry *ale;
  size_t slen;

  /* 0-termination of &aam[1] was checked in #check_add_address */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Communicator added address `%s'!\n",
              (const char *) &aam[1]);
  slen = ntohs (aam->header.size) - sizeof (*aam);
  ale = GNUNET_malloc (sizeof (struct AddressListEntry) + slen);
  ale->tc = tc;
  ale->address = (const char *) &ale[1];
  ale->expiration = GNUNET_TIME_relative_ntoh (aam->expiration);
  ale->aid = aam->aid;
  ale->nt = (enum GNUNET_NetworkType) ntohl (aam->nt);
  memcpy (&ale[1], &aam[1], slen);
  GNUNET_CONTAINER_DLL_insert (tc->details.communicator.addr_head,
                               tc->details.communicator.addr_tail,
                               ale);
  ale->st = GNUNET_SCHEDULER_add_now (&store_pi, ale);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Address of our peer deleted.  Process the request.
 *
 * @param cls the client
 * @param dam the send message that was sent
 */
static void
handle_del_address (void *cls,
                    const struct GNUNET_TRANSPORT_DelAddressMessage *dam)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  for (struct AddressListEntry *ale = tc->details.communicator.addr_head;
       NULL != ale;
       ale = ale->next)
  {
    if (dam->aid != ale->aid)
      continue;
    GNUNET_assert (ale->tc == tc);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Communicator deleted address `%s'!\n",
                ale->address);
    free_address_list_entry (ale);
    GNUNET_SERVICE_client_continue (tc->client);
  }
  GNUNET_break (0);
  GNUNET_SERVICE_client_drop (tc->client);
}


/**
 * Given an inbound message @a msg from a communicator @a cmc,
 * demultiplex it based on the type calling the right handler.
 *
 * @param cmc context for demultiplexing
 * @param msg message to demultiplex
 */
static void
demultiplex_with_cmc (struct CommunicatorMessageContext *cmc,
                      const struct GNUNET_MessageHeader *msg);


/**
 * Communicator gave us an unencapsulated message to pass as-is to
 * CORE.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param mh the message that was received
 */
static void
handle_raw_message (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct VirtualLink *vl;
  uint16_t size = ntohs (mh->size);
  int have_core;

  if ((size > UINT16_MAX - sizeof (struct InboundMessage)) ||
      (size < sizeof (struct GNUNET_MessageHeader)))
  {
    struct GNUNET_SERVICE_Client *client = cmc->tc->client;

    GNUNET_break (0);
    finish_cmc_handling (cmc);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  vl = GNUNET_CONTAINER_multipeermap_get (links, &cmc->im.sender);
  if (NULL == vl)
  {
    /* FIXME: sender is giving us messages for CORE but we don't have
       the link up yet! I *suspect* this can happen right now (i.e.
       sender has verified us, but we didn't verify sender), but if
       we pass this on, CORE would be confused (link down, messages
       arrive).  We should investigate more if this happens often,
       or in a persistent manner, and possibly do "something" about
       it. Thus logging as error for now. */
    GNUNET_break_op (0);
    GNUNET_STATISTICS_update (GST_stats,
                              "# CORE messages droped (virtual link still down)",
                              1,
                              GNUNET_NO);

    finish_cmc_handling (cmc);
    return;
  }
  /* Forward to all CORE clients */
  have_core = GNUNET_NO;
  for (struct TransportClient *tc = clients_head; NULL != tc; tc = tc->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct InboundMessage *im;

    if (CT_CORE != tc->type)
      continue;
    have_core = GNUNET_YES;
    env = GNUNET_MQ_msg_extra (im, size, GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
    im->peer = cmc->im.sender;
    memcpy (&im[1], mh, size);
    GNUNET_MQ_send (tc->mq, env);
  }
  vl->core_recv_window--;
  if (GNUNET_NO == have_core)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Dropped message to CORE: no CORE client connected!\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delivered message from %s of type %u to CORE\n",
                GNUNET_i2s (&cmc->im.sender),
                ntohs (mh->type));
  if (vl->core_recv_window > 0)
  {
    finish_cmc_handling (cmc);
    return;
  }
  /* Wait with calling #finish_cmc_handling(cmc) until the message
     was processed by CORE MQs (for CORE flow control)! */
  GNUNET_CONTAINER_DLL_insert (vl->cmc_head, vl->cmc_tail, cmc);
}


/**
 * Communicator gave us a fragment box.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param fb the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_fragment_box (void *cls, const struct TransportFragmentBoxMessage *fb)
{
  uint16_t size = ntohs (fb->header.size);
  uint16_t bsize = size - sizeof (*fb);

  (void) cls;
  if (0 == bsize)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (bsize + ntohs (fb->frag_off) > ntohs (fb->msg_size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (fb->frag_off) >= ntohs (fb->msg_size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Clean up an idle cummulative acknowledgement data structure.
 *
 * @param cls a `struct AcknowledgementCummulator *`
 */
static void
destroy_ack_cummulator (void *cls)
{
  struct AcknowledgementCummulator *ac = cls;

  ac->task = NULL;
  GNUNET_assert (0 == ac->num_acks);
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (ack_cummulators, &ac->target, ac));
  GNUNET_free (ac);
}


/**
 * Do the transmission of a cummulative acknowledgement now.
 *
 * @param cls a `struct AcknowledgementCummulator *`
 */
static void
transmit_cummulative_ack_cb (void *cls)
{
  struct AcknowledgementCummulator *ac = cls;
  char buf[sizeof (struct TransportReliabilityAckMessage) +
           ac->ack_counter *
             sizeof (struct TransportCummulativeAckPayloadP)] GNUNET_ALIGN;
  struct TransportReliabilityAckMessage *ack =
    (struct TransportReliabilityAckMessage *) buf;
  struct TransportCummulativeAckPayloadP *ap;

  ac->task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending ACK with %u components to %s\n",
              ac->ack_counter,
              GNUNET_i2s (&ac->target));
  GNUNET_assert (0 < ac->ack_counter);
  ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK);
  ack->header.size =
    htons (sizeof (*ack) +
           ac->ack_counter * sizeof (struct TransportCummulativeAckPayloadP));
  ack->ack_counter = htonl (ac->ack_counter++);
  ap = (struct TransportCummulativeAckPayloadP *) &ack[1];
  for (unsigned int i = 0; i < ac->ack_counter; i++)
  {
    ap[i].ack_uuid = ac->ack_uuids[i].ack_uuid;
    ap[i].ack_delay = GNUNET_TIME_relative_hton (
      GNUNET_TIME_absolute_get_duration (ac->ack_uuids[i].receive_time));
  }
  route_message (&ac->target, &ack->header, RMO_DV_ALLOWED);
  ac->num_acks = 0;
  ac->task = GNUNET_SCHEDULER_add_delayed (ACK_CUMMULATOR_TIMEOUT,
                                           &destroy_ack_cummulator,
                                           ac);
}


/**
 * Transmit an acknowledgement for @a ack_uuid to @a pid delaying
 * transmission by at most @a ack_delay.
 *
 * @param pid target peer
 * @param ack_uuid UUID to ack
 * @param max_delay how long can the ACK wait
 */
static void
cummulative_ack (const struct GNUNET_PeerIdentity *pid,
                 const struct AcknowledgementUUIDP *ack_uuid,
                 struct GNUNET_TIME_Absolute max_delay)
{
  struct AcknowledgementCummulator *ac;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling ACK %s for transmission to %s\n",
              GNUNET_sh2s (&ack_uuid->value),
              GNUNET_i2s (pid));
  ac = GNUNET_CONTAINER_multipeermap_get (ack_cummulators, pid);
  if (NULL == ac)
  {
    ac = GNUNET_new (struct AcknowledgementCummulator);
    ac->target = *pid;
    ac->min_transmission_time = max_delay;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (
                     ack_cummulators,
                     &ac->target,
                     ac,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    if (MAX_CUMMULATIVE_ACKS == ac->num_acks)
    {
      /* must run immediately, ack buffer full! */
      GNUNET_SCHEDULER_cancel (ac->task);
      transmit_cummulative_ack_cb (ac);
    }
    GNUNET_SCHEDULER_cancel (ac->task);
    ac->min_transmission_time =
      GNUNET_TIME_absolute_min (ac->min_transmission_time, max_delay);
  }
  GNUNET_assert (ac->num_acks < MAX_CUMMULATIVE_ACKS);
  ac->ack_uuids[ac->num_acks].receive_time = GNUNET_TIME_absolute_get ();
  ac->ack_uuids[ac->num_acks].ack_uuid = *ack_uuid;
  ac->num_acks++;
  ac->task = GNUNET_SCHEDULER_add_at (ac->min_transmission_time,
                                      &transmit_cummulative_ack_cb,
                                      ac);
}


/**
 * Closure for #find_by_message_uuid.
 */
struct FindByMessageUuidContext
{
  /**
   * UUID to look for.
   */
  struct MessageUUIDP message_uuid;

  /**
   * Set to the reassembly context if found.
   */
  struct ReassemblyContext *rc;
};


/**
 * Iterator called to find a reassembly context by the message UUID in the
 * multihashmap32.
 *
 * @param cls a `struct FindByMessageUuidContext`
 * @param key a key (unused)
 * @param value a `struct ReassemblyContext`
 * @return #GNUNET_YES if not found, #GNUNET_NO if found
 */
static int
find_by_message_uuid (void *cls, uint32_t key, void *value)
{
  struct FindByMessageUuidContext *fc = cls;
  struct ReassemblyContext *rc = value;

  (void) key;
  if (0 == GNUNET_memcmp (&fc->message_uuid, &rc->msg_uuid))
  {
    fc->rc = rc;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Communicator gave us a fragment.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param fb the message that was received
 */
static void
handle_fragment_box (void *cls, const struct TransportFragmentBoxMessage *fb)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct Neighbour *n;
  struct ReassemblyContext *rc;
  const struct GNUNET_MessageHeader *msg;
  uint16_t msize;
  uint16_t fsize;
  uint16_t frag_off;
  char *target;
  struct GNUNET_TIME_Relative cdelay;
  struct FindByMessageUuidContext fc;

  n = lookup_neighbour (&cmc->im.sender);
  if (NULL == n)
  {
    struct GNUNET_SERVICE_Client *client = cmc->tc->client;

    GNUNET_break (0);
    finish_cmc_handling (cmc);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  if (NULL == n->reassembly_map)
  {
    n->reassembly_map = GNUNET_CONTAINER_multihashmap32_create (8);
    n->reassembly_heap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
    n->reassembly_timeout_task =
      GNUNET_SCHEDULER_add_delayed (REASSEMBLY_EXPIRATION,
                                    &reassembly_cleanup_task,
                                    n);
  }
  msize = ntohs (fb->msg_size);
  fc.message_uuid = fb->msg_uuid;
  fc.rc = NULL;
  GNUNET_CONTAINER_multihashmap32_get_multiple (n->reassembly_map,
                                                fb->msg_uuid.uuid,
                                                &find_by_message_uuid,
                                                &fc);
  if (NULL == (rc = fc.rc))
  {
    rc = GNUNET_malloc (sizeof (*rc) + msize + /* reassembly payload buffer */
                        (msize + 7) / 8 * sizeof (uint8_t) /* bitfield */);
    rc->msg_uuid = fb->msg_uuid;
    rc->neighbour = n;
    rc->msg_size = msize;
    rc->reassembly_timeout =
      GNUNET_TIME_relative_to_absolute (REASSEMBLY_EXPIRATION);
    rc->last_frag = GNUNET_TIME_absolute_get ();
    rc->hn = GNUNET_CONTAINER_heap_insert (n->reassembly_heap,
                                           rc,
                                           rc->reassembly_timeout.abs_value_us);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap32_put (
                     n->reassembly_map,
                     rc->msg_uuid.uuid,
                     rc,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    target = (char *) &rc[1];
    rc->bitfield = (uint8_t *) (target + rc->msg_size);
    rc->msg_missing = rc->msg_size;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received fragment at offset %u/%u from %s for NEW message %u\n",
                ntohs (fb->frag_off),
                msize,
                GNUNET_i2s (&cmc->im.sender),
                (unsigned int) fb->msg_uuid.uuid);
  }
  else
  {
    target = (char *) &rc[1];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received fragment at offset %u/%u from %s for message %u\n",
                ntohs (fb->frag_off),
                msize,
                GNUNET_i2s (&cmc->im.sender),
                (unsigned int) fb->msg_uuid.uuid);
  }
  if (msize != rc->msg_size)
  {
    GNUNET_break (0);
    finish_cmc_handling (cmc);
    return;
  }

  /* reassemble */
  fsize = ntohs (fb->header.size) - sizeof (*fb);
  if (0 == fsize)
  {
    GNUNET_break (0);
    finish_cmc_handling (cmc);
    return;
  }
  frag_off = ntohs (fb->frag_off);
  memcpy (&target[frag_off], &fb[1], fsize);
  /* update bitfield and msg_missing */
  for (unsigned int i = frag_off; i < frag_off + fsize; i++)
  {
    if (0 == (rc->bitfield[i / 8] & (1 << (i % 8))))
    {
      rc->bitfield[i / 8] |= (1 << (i % 8));
      rc->msg_missing--;
    }
  }

  /* Compute cummulative ACK */
  cdelay = GNUNET_TIME_absolute_get_duration (rc->last_frag);
  cdelay = GNUNET_TIME_relative_multiply (cdelay, rc->msg_missing / fsize);
  if (0 == rc->msg_missing)
    cdelay = GNUNET_TIME_UNIT_ZERO;
  cummulative_ack (&cmc->im.sender,
                   &fb->ack_uuid,
                   GNUNET_TIME_relative_to_absolute (cdelay));
  rc->last_frag = GNUNET_TIME_absolute_get ();
  /* is reassembly complete? */
  if (0 != rc->msg_missing)
  {
    finish_cmc_handling (cmc);
    return;
  }
  /* reassembly is complete, verify result */
  msg = (const struct GNUNET_MessageHeader *) &rc[1];
  if (ntohs (msg->size) != rc->msg_size)
  {
    GNUNET_break (0);
    free_reassembly_context (rc);
    finish_cmc_handling (cmc);
    return;
  }
  /* successful reassembly */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Fragment reassembly complete for message %u\n",
              (unsigned int) fb->msg_uuid.uuid);
  /* FIXME: check that the resulting msg is NOT a
     DV Box or Reliability Box, as that is NOT allowed! */
  demultiplex_with_cmc (cmc, msg);
  /* FIXME-OPTIMIZE: really free here? Might be bad if fragments are still
     en-route and we forget that we finished this reassembly immediately!
     -> keep around until timeout?
     -> shorten timeout based on ACK? */
  free_reassembly_context (rc);
}


/**
 * Communicator gave us a reliability box.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param rb the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_reliability_box (void *cls,
                       const struct TransportReliabilityBoxMessage *rb)
{
  (void) cls;
  GNUNET_MQ_check_boxed_message (rb);
  return GNUNET_YES;
}


/**
 * Communicator gave us a reliability box.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param rb the message that was received
 */
static void
handle_reliability_box (void *cls,
                        const struct TransportReliabilityBoxMessage *rb)
{
  struct CommunicatorMessageContext *cmc = cls;
  const struct GNUNET_MessageHeader *inbox =
    (const struct GNUNET_MessageHeader *) &rb[1];
  struct GNUNET_TIME_Relative rtt;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received reliability box from %s with UUID %s of type %u\n",
              GNUNET_i2s (&cmc->im.sender),
              GNUNET_sh2s (&rb->ack_uuid.value),
              (unsigned int) ntohs (inbox->type));
  rtt = GNUNET_TIME_UNIT_SECONDS; /* FIXME: should base this on "RTT", but we
                                     do not really have an RTT for the
                                     *incoming* queue (should we have
                                     the sender add it to the rb message?) */
  cummulative_ack (
    &cmc->im.sender,
    &rb->ack_uuid,
    (0 == ntohl (rb->ack_countdown))
      ? GNUNET_TIME_UNIT_ZERO_ABS
      : GNUNET_TIME_relative_to_absolute (
          GNUNET_TIME_relative_divide (rtt, 8 /* FIXME: magic constant */)));
  /* continue with inner message */
  /* FIXME: check that inbox is NOT a DV Box, fragment or another
     reliability box (not allowed!) */
  demultiplex_with_cmc (cmc, inbox);
}


/**
 * Check if we have advanced to another age since the last time.  If
 * so, purge ancient statistics (more than GOODPUT_AGING_SLOTS before
 * the current age)
 *
 * @param pd[in,out] data to update
 * @param age current age
 */
static void
update_pd_age (struct PerformanceData *pd, unsigned int age)
{
  unsigned int sage;

  if (age == pd->last_age)
    return; /* nothing to do */
  sage = GNUNET_MAX (pd->last_age, age - 2 * GOODPUT_AGING_SLOTS);
  for (unsigned int i = sage; i <= age - GOODPUT_AGING_SLOTS; i++)
  {
    struct TransmissionHistoryEntry *the = &pd->the[i % GOODPUT_AGING_SLOTS];

    the->bytes_sent = 0;
    the->bytes_received = 0;
  }
  pd->last_age = age;
}


/**
 * Update @a pd based on the latest @a rtt and the number of bytes
 * that were confirmed to be successfully transmitted.
 *
 * @param pd[in,out] data to update
 * @param rtt latest round-trip time
 * @param bytes_transmitted_ok number of bytes receiver confirmed as received
 */
static void
update_performance_data (struct PerformanceData *pd,
                         struct GNUNET_TIME_Relative rtt,
                         uint16_t bytes_transmitted_ok)
{
  uint64_t nval = rtt.rel_value_us;
  uint64_t oval = pd->aged_rtt.rel_value_us;
  unsigned int age = get_age ();
  struct TransmissionHistoryEntry *the = &pd->the[age % GOODPUT_AGING_SLOTS];

  if (oval == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    pd->aged_rtt = rtt;
  else
    pd->aged_rtt.rel_value_us = (nval + 7 * oval) / 8;
  update_pd_age (pd, age);
  the->bytes_received += bytes_transmitted_ok;
}


/**
 * We have successfully transmitted data via @a q, update metrics.
 *
 * @param q queue to update
 * @param rtt round trip time observed
 * @param bytes_transmitted_ok number of bytes successfully transmitted
 */
static void
update_queue_performance (struct Queue *q,
                          struct GNUNET_TIME_Relative rtt,
                          uint16_t bytes_transmitted_ok)
{
  update_performance_data (&q->pd, rtt, bytes_transmitted_ok);
}


/**
 * We have successfully transmitted data via @a dvh, update metrics.
 *
 * @param dvh distance vector path data to update
 * @param rtt round trip time observed
 * @param bytes_transmitted_ok number of bytes successfully transmitted
 */
static void
update_dvh_performance (struct DistanceVectorHop *dvh,
                        struct GNUNET_TIME_Relative rtt,
                        uint16_t bytes_transmitted_ok)
{
  update_performance_data (&dvh->pd, rtt, bytes_transmitted_ok);
}


/**
 * We have completed transmission of @a pm, remove it from
 * the transmission queues (and if it is a fragment, continue
 * up the tree as necessary).
 *
 * @param pm pending message that was transmitted
 */
static void
completed_pending_message (struct PendingMessage *pm)
{
  struct PendingMessage *pos;

  switch (pm->pmt)
  {
  case PMT_CORE:
  case PMT_RELIABILITY_BOX:
    /* Full message sent, we are done */
    client_send_response (pm);
    return;
  case PMT_FRAGMENT_BOX:
    /* Fragment sent over reliabile channel */
    free_fragment_tree (pm);
    pos = pm->frag_parent;
    GNUNET_CONTAINER_MDLL_remove (frag, pos->head_frag, pos->tail_frag, pm);
    GNUNET_free (pm);
    /* check if subtree is done */
    while ((NULL == pos->head_frag) && (pos->frag_off == pos->bytes_msg) &&
           (pos != pm))
    {
      pm = pos;
      pos = pm->frag_parent;
      GNUNET_CONTAINER_MDLL_remove (frag, pos->head_frag, pos->tail_frag, pm);
      GNUNET_free (pm);
    }

    /* Was this the last applicable fragmment? */
    if ((NULL == pos->head_frag) && (NULL == pos->frag_parent) &&
        (pos->frag_off == pos->bytes_msg))
      client_send_response (pos);
    return;
  }
}


/**
 * The @a pa was acknowledged, process the acknowledgement.
 *
 * @param pa the pending acknowledgement that was satisfied
 * @param ack_delay artificial delay from cummulative acks created by the
 * other peer
 */
static void
handle_acknowledged (struct PendingAcknowledgement *pa,
                     struct GNUNET_TIME_Relative ack_delay)
{
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (pa->transmission_time);
  if (delay.rel_value_us > ack_delay.rel_value_us)
    delay = GNUNET_TIME_UNIT_ZERO;
  else
    delay = GNUNET_TIME_relative_subtract (delay, ack_delay);
  if (NULL != pa->queue)
    update_queue_performance (pa->queue, delay, pa->message_size);
  if (NULL != pa->dvh)
    update_dvh_performance (pa->dvh, delay, pa->message_size);
  if (NULL != pa->pm)
    completed_pending_message (pa->pm);
  free_pending_acknowledgement (pa);
}


/**
 * Communicator gave us a reliability ack.  Check it is well-formed.
 *
 * @param cls a `struct CommunicatorMessageContext` (unused)
 * @param ra the message that was received
 * @return #GNUNET_Ok if @a ra is well-formed
 */
static int
check_reliability_ack (void *cls,
                       const struct TransportReliabilityAckMessage *ra)
{
  unsigned int n_acks;

  (void) cls;
  n_acks = (ntohs (ra->header.size) - sizeof (*ra)) /
           sizeof (struct TransportCummulativeAckPayloadP);
  if (0 == n_acks)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((ntohs (ra->header.size) - sizeof (*ra)) !=
      n_acks * sizeof (struct TransportCummulativeAckPayloadP))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Communicator gave us a reliability ack.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param ra the message that was received
 */
static void
handle_reliability_ack (void *cls,
                        const struct TransportReliabilityAckMessage *ra)
{
  struct CommunicatorMessageContext *cmc = cls;
  const struct TransportCummulativeAckPayloadP *ack;
  struct PendingAcknowledgement *pa;
  unsigned int n_acks;
  uint32_t ack_counter;

  n_acks = (ntohs (ra->header.size) - sizeof (*ra)) /
           sizeof (struct TransportCummulativeAckPayloadP);
  ack = (const struct TransportCummulativeAckPayloadP *) &ra[1];
  for (unsigned int i = 0; i < n_acks; i++)
  {
    pa =
      GNUNET_CONTAINER_multishortmap_get (pending_acks, &ack[i].ack_uuid.value);
    if (NULL == pa)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Received ACK from %s with UUID %s which is unknown to us!\n",
                  GNUNET_i2s (&cmc->im.sender),
                  GNUNET_sh2s (&ack[i].ack_uuid.value));
      GNUNET_STATISTICS_update (
        GST_stats,
        "# FRAGMENT_ACKS dropped, no matching pending message",
        1,
        GNUNET_NO);
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received ACK from %s with UUID %s\n",
                GNUNET_i2s (&cmc->im.sender),
                GNUNET_sh2s (&ack[i].ack_uuid.value));
    handle_acknowledged (pa, GNUNET_TIME_relative_ntoh (ack[i].ack_delay));
  }

  ack_counter = htonl (ra->ack_counter);
  (void) ack_counter; /* silence compiler warning for now */
  // FIXME-OPTIMIZE: track ACK losses based on ack_counter somewhere!
  // (DV and/or Neighbour?)
  finish_cmc_handling (cmc);
}


/**
 * Communicator gave us a backchannel encapsulation.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param be the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_backchannel_encapsulation (
  void *cls,
  const struct TransportBackchannelEncapsulationMessage *be)
{
  uint16_t size = ntohs (be->header.size) - sizeof (*be);
  const struct GNUNET_MessageHeader *inbox =
    (const struct GNUNET_MessageHeader *) &be[1];
  const char *is;
  uint16_t isize;

  (void) cls;
  if (ntohs (inbox->size) >= size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  isize = ntohs (inbox->size);
  is = ((const char *) inbox) + isize;
  size -= isize;
  if ('\0' != is[size - 1])
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Communicator gave us a backchannel encapsulation.  Process the request.
 * (We are the destination of the backchannel here.)
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param be the message that was received
 */
static void
handle_backchannel_encapsulation (
  void *cls,
  const struct TransportBackchannelEncapsulationMessage *be)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming *cbi;
  struct GNUNET_MQ_Envelope *env;
  struct TransportClient *tc;
  const struct GNUNET_MessageHeader *inbox =
    (const struct GNUNET_MessageHeader *) &be[1];
  uint16_t isize = ntohs (inbox->size);
  const char *target_communicator = ((const char *) inbox) + isize;

  /* Find client providing this communicator */
  for (tc = clients_head; NULL != tc; tc = tc->next)
    if ((CT_COMMUNICATOR == tc->type) &&
        (0 ==
         strcmp (tc->details.communicator.address_prefix, target_communicator)))
      break;
  if (NULL == tc)
  {
    char *stastr;

    GNUNET_asprintf (
      &stastr,
      "# Backchannel message dropped: target communicator `%s' unknown",
      target_communicator);
    GNUNET_STATISTICS_update (GST_stats, stastr, 1, GNUNET_NO);
    GNUNET_free (stastr);
    return;
  }
  /* Finally, deliver backchannel message to communicator */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering backchannel message from %s of type %u to %s\n",
              GNUNET_i2s (&cmc->im.sender),
              ntohs (inbox->type),
              target_communicator);
  env = GNUNET_MQ_msg_extra (
    cbi,
    isize,
    GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING);
  cbi->pid = cmc->im.sender;
  memcpy (&cbi[1], inbox, isize);
  GNUNET_MQ_send (tc->mq, env);
}


/**
 * Task called when we should check if any of the DV paths
 * we have learned to a target are due for garbage collection.
 *
 * Collects stale paths, and possibly frees the entire DV
 * entry if no paths are left. Otherwise re-schedules itself.
 *
 * @param cls a `struct DistanceVector`
 */
static void
path_cleanup_cb (void *cls)
{
  struct DistanceVector *dv = cls;
  struct DistanceVectorHop *pos;

  dv->timeout_task = NULL;
  while (NULL != (pos = dv->dv_head))
  {
    GNUNET_assert (dv == pos->dv);
    if (GNUNET_TIME_absolute_get_remaining (pos->timeout).rel_value_us > 0)
      break;
    free_distance_vector_hop (pos);
  }
  if (NULL == pos)
  {
    free_dv_route (dv);
    return;
  }
  dv->timeout_task =
    GNUNET_SCHEDULER_add_at (pos->timeout, &path_cleanup_cb, dv);
}


/**
 * The @a hop is a validated path to the respective target
 * peer and we should tell core about it -- and schedule
 * a job to revoke the state.
 *
 * @param hop a path to some peer that is the reason for activation
 */
static void
activate_core_visible_dv_path (struct DistanceVectorHop *hop)
{
  struct DistanceVector *dv = hop->dv;
  struct VirtualLink *vl;

  vl = GNUNET_CONTAINER_multipeermap_get (links, &dv->target);
  if (NULL != vl)
  {
    /* Link was already up, remember dv is also now available and we are done */
    vl->dv = dv;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Virtual link to %s could now also use DV!\n",
                GNUNET_i2s (&dv->target));
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new virtual link to %s using DV!\n",
              GNUNET_i2s (&dv->target));
  vl = GNUNET_new (struct VirtualLink);
  vl->message_uuid_ctr =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  vl->target = dv->target;
  vl->dv = dv;
  dv->vl = vl;
  vl->core_recv_window = RECV_WINDOW_SIZE;
  vl->visibility_task =
    GNUNET_SCHEDULER_add_at (hop->path_valid_until, &check_link_down, vl);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multipeermap_put (
                  links,
                  &vl->target,
                  vl,
                  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  /* We lacked a confirmed connection to the target
     before, so tell CORE about it (finally!) */
  cores_send_connect_info (&dv->target);
}


/**
 * We have learned a @a path through the network to some other peer, add it to
 * our DV data structure (returning #GNUNET_YES on success).
 *
 * We do not add paths if we have a sufficient number of shorter
 * paths to this target already (returning #GNUNET_NO).
 *
 * We also do not add problematic paths, like those where we lack the first
 * hop in our neighbour list (i.e. due to a topology change) or where some
 * non-first hop is in our neighbour list (returning #GNUNET_SYSERR).
 *
 * @param path the path we learned, path[0] should be us,
 *             and then path contains a valid path from us to
 * `path[path_len-1]` path[1] should be a direct neighbour (we should check!)
 * @param path_len number of entries on the @a path, at least three!
 * @param network_latency how long does the message take from us to
 * `path[path_len-1]`? set to "forever" if unknown
 * @param path_valid_until how long is this path considered validated? Maybe
 * be zero.
 * @return #GNUNET_YES on success,
 *         #GNUNET_NO if we have better path(s) to the target
 *         #GNUNET_SYSERR if the path is useless and/or invalid
 *                         (i.e. path[1] not a direct neighbour
 *                        or path[i+1] is a direct neighbour for i>0)
 */
static int
learn_dv_path (const struct GNUNET_PeerIdentity *path,
               unsigned int path_len,
               struct GNUNET_TIME_Relative network_latency,
               struct GNUNET_TIME_Absolute path_valid_until)
{
  struct DistanceVectorHop *hop;
  struct DistanceVector *dv;
  struct Neighbour *next_hop;
  unsigned int shorter_distance;

  if (path_len < 3)
  {
    /* what a boring path! not allowed! */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 == GNUNET_memcmp (&GST_my_identity, &path[0]));
  next_hop = lookup_neighbour (&path[1]);
  if (NULL == next_hop)
  {
    /* next hop must be a neighbour, otherwise this whole thing is useless! */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  for (unsigned int i = 2; i < path_len; i++)
    if (NULL != lookup_neighbour (&path[i]))
    {
      /* Useless path: we have a direct connection to some hop
         in the middle of the path, so this one is not even
         terribly useful for redundancy */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Path of %u hops useless: directly link to hop %u (%s)\n",
                  path_len,
                  i,
                  GNUNET_i2s (&path[i]));
      GNUNET_STATISTICS_update (GST_stats,
                                "# Useless DV path ignored: hop is neighbour",
                                1,
                                GNUNET_NO);
      return GNUNET_SYSERR;
    }
  dv = GNUNET_CONTAINER_multipeermap_get (dv_routes, &path[path_len - 1]);
  if (NULL == dv)
  {
    dv = GNUNET_new (struct DistanceVector);
    dv->target = path[path_len - 1];
    dv->timeout_task = GNUNET_SCHEDULER_add_delayed (DV_PATH_VALIDITY_TIMEOUT,
                                                     &path_cleanup_cb,
                                                     dv);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (
                     dv_routes,
                     &dv->target,
                     dv,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  /* Check if we have this path already! */
  shorter_distance = 0;
  for (struct DistanceVectorHop *pos = dv->dv_head; NULL != pos;
       pos = pos->next_dv)
  {
    if (pos->distance < path_len - 2)
      shorter_distance++;
    /* Note that the distances in 'pos' excludes us (path[0]) and
       the next_hop (path[1]), so we need to subtract two
       and check next_hop explicitly */
    if ((pos->distance == path_len - 2) && (pos->next_hop == next_hop))
    {
      int match = GNUNET_YES;

      for (unsigned int i = 0; i < pos->distance; i++)
      {
        if (0 != GNUNET_memcmp (&pos->path[i], &path[i + 2]))
        {
          match = GNUNET_NO;
          break;
        }
      }
      if (GNUNET_YES == match)
      {
        struct GNUNET_TIME_Relative last_timeout;

        /* Re-discovered known path, update timeout */
        GNUNET_STATISTICS_update (GST_stats,
                                  "# Known DV path refreshed",
                                  1,
                                  GNUNET_NO);
        last_timeout = GNUNET_TIME_absolute_get_remaining (pos->timeout);
        pos->timeout =
          GNUNET_TIME_relative_to_absolute (DV_PATH_VALIDITY_TIMEOUT);
        pos->path_valid_until =
          GNUNET_TIME_absolute_max (pos->path_valid_until, path_valid_until);
        GNUNET_CONTAINER_MDLL_remove (dv, dv->dv_head, dv->dv_tail, pos);
        GNUNET_CONTAINER_MDLL_insert (dv, dv->dv_head, dv->dv_tail, pos);
        if (0 <
            GNUNET_TIME_absolute_get_remaining (path_valid_until).rel_value_us)
          activate_core_visible_dv_path (pos);
        if (last_timeout.rel_value_us <
            GNUNET_TIME_relative_subtract (DV_PATH_VALIDITY_TIMEOUT,
                                           DV_PATH_DISCOVERY_FREQUENCY)
              .rel_value_us)
        {
          /* Some peer send DV learn messages too often, we are learning
             the same path faster than it would be useful; do not forward! */
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Rediscovered path too quickly, not forwarding further\n");
          return GNUNET_NO;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Refreshed known path to %s, forwarding further\n",
                    GNUNET_i2s (&dv->target));
        return GNUNET_YES;
      }
    }
  }
  /* Count how many shorter paths we have (incl. direct
     neighbours) before simply giving up on this one! */
  if (shorter_distance >= MAX_DV_PATHS_TO_TARGET)
  {
    /* We have a shorter path already! */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have many shorter DV paths %s, not forwarding further\n",
                GNUNET_i2s (&dv->target));
    return GNUNET_NO;
  }
  /* create new DV path entry */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Discovered new DV path to %s\n",
              GNUNET_i2s (&dv->target));
  hop = GNUNET_malloc (sizeof (struct DistanceVectorHop) +
                       sizeof (struct GNUNET_PeerIdentity) * (path_len - 2));
  hop->next_hop = next_hop;
  hop->dv = dv;
  hop->path = (const struct GNUNET_PeerIdentity *) &hop[1];
  memcpy (&hop[1],
          &path[2],
          sizeof (struct GNUNET_PeerIdentity) * (path_len - 2));
  hop->timeout = GNUNET_TIME_relative_to_absolute (DV_PATH_VALIDITY_TIMEOUT);
  hop->path_valid_until = path_valid_until;
  hop->distance = path_len - 2;
  hop->pd.aged_rtt = network_latency;
  GNUNET_CONTAINER_MDLL_insert (dv, dv->dv_head, dv->dv_tail, hop);
  GNUNET_CONTAINER_MDLL_insert (neighbour,
                                next_hop->dv_head,
                                next_hop->dv_tail,
                                hop);
  if (0 < GNUNET_TIME_absolute_get_remaining (path_valid_until).rel_value_us)
    activate_core_visible_dv_path (hop);
  return GNUNET_YES;
}


/**
 * Communicator gave us a DV learn message.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param dvl the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_dv_learn (void *cls, const struct TransportDVLearnMessage *dvl)
{
  uint16_t size = ntohs (dvl->header.size);
  uint16_t num_hops = ntohs (dvl->num_hops);
  const struct DVPathEntryP *hops = (const struct DVPathEntryP *) &dvl[1];

  (void) cls;
  if (size != sizeof (*dvl) + num_hops * sizeof (struct DVPathEntryP))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (num_hops > MAX_DV_HOPS_ALLOWED)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  for (unsigned int i = 0; i < num_hops; i++)
  {
    if (0 == GNUNET_memcmp (&dvl->initiator, &hops[i].hop))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (0 == GNUNET_memcmp (&GST_my_identity, &hops[i].hop))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_YES;
}


/**
 * Build and forward a DV learn message to @a next_hop.
 *
 * @param next_hop peer to send the message to
 * @param msg message received
 * @param bi_history bitmask specifying hops on path that were bidirectional
 * @param nhops length of the @a hops array
 * @param hops path the message traversed so far
 * @param in_time when did we receive the message, used to calculate network
 * delay
 */
static void
forward_dv_learn (const struct GNUNET_PeerIdentity *next_hop,
                  const struct TransportDVLearnMessage *msg,
                  uint16_t bi_history,
                  uint16_t nhops,
                  const struct DVPathEntryP *hops,
                  struct GNUNET_TIME_Absolute in_time)
{
  struct DVPathEntryP *dhops;
  char buf[sizeof (struct TransportDVLearnMessage) +
           (nhops + 1) * sizeof (struct DVPathEntryP)] GNUNET_ALIGN;
  struct TransportDVLearnMessage *fwd = (struct TransportDVLearnMessage *) buf;
  struct GNUNET_TIME_Relative nnd;

  /* compute message for forwarding */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding DV learn message originating from %s to %s\n",
              GNUNET_i2s (&msg->initiator),
              GNUNET_i2s2 (next_hop));
  GNUNET_assert (nhops < MAX_DV_HOPS_ALLOWED);
  fwd->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN);
  fwd->header.size = htons (sizeof (struct TransportDVLearnMessage) +
                            (nhops + 1) * sizeof (struct DVPathEntryP));
  fwd->num_hops = htons (nhops + 1);
  fwd->bidirectional = htons (bi_history);
  nnd = GNUNET_TIME_relative_add (GNUNET_TIME_absolute_get_duration (in_time),
                                  GNUNET_TIME_relative_ntoh (
                                    msg->non_network_delay));
  fwd->non_network_delay = GNUNET_TIME_relative_hton (nnd);
  fwd->init_sig = msg->init_sig;
  fwd->initiator = msg->initiator;
  fwd->challenge = msg->challenge;
  dhops = (struct DVPathEntryP *) &fwd[1];
  GNUNET_memcpy (dhops, hops, sizeof (struct DVPathEntryP) * nhops);
  dhops[nhops].hop = GST_my_identity;
  {
    struct DvHopPS dhp = {.purpose.purpose =
                            htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP),
                          .purpose.size = htonl (sizeof (dhp)),
                          .pred = dhops[nhops - 1].hop,
                          .succ = *next_hop,
                          .challenge = msg->challenge};

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
                                             &dhp.purpose,
                                             &dhops[nhops].hop_sig));
  }
  route_message (next_hop, &fwd->header, RMO_UNCONFIRMED_ALLOWED);
}


/**
 * Check signature of type #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR
 *
 * @param sender_monotonic_time monotonic time of the initiator
 * @param init the signer
 * @param challenge the challenge that was signed
 * @param init_sig signature presumably by @a init
 * @return #GNUNET_OK if the signature is valid
 */
static int
validate_dv_initiator_signature (
  struct GNUNET_TIME_AbsoluteNBO sender_monotonic_time,
  const struct GNUNET_PeerIdentity *init,
  const struct ChallengeNonceP *challenge,
  const struct GNUNET_CRYPTO_EddsaSignature *init_sig)
{
  struct DvInitPS ip = {.purpose.purpose = htonl (
                          GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR),
                        .purpose.size = htonl (sizeof (ip)),
                        .monotonic_time = sender_monotonic_time,
                        .challenge = *challenge};

  if (
    GNUNET_OK !=
    GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR,
                                &ip.purpose,
                                init_sig,
                                &init->public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Closure for #dv_neighbour_selection and #dv_neighbour_transmission.
 */
struct NeighbourSelectionContext
{
  /**
   * Original message we received.
   */
  const struct TransportDVLearnMessage *dvl;

  /**
   * The hops taken.
   */
  const struct DVPathEntryP *hops;

  /**
   * Time we received the message.
   */
  struct GNUNET_TIME_Absolute in_time;

  /**
   * Offsets of the selected peers.
   */
  uint32_t selections[MAX_DV_DISCOVERY_SELECTION];

  /**
   * Number of peers eligible for selection.
   */
  unsigned int num_eligible;

  /**
   * Number of peers that were selected for forwarding.
   */
  unsigned int num_selections;

  /**
   * Number of hops in @e hops
   */
  uint16_t nhops;

  /**
   * Bitmap of bidirectional connections encountered.
   */
  uint16_t bi_history;
};


/**
 * Function called for each neighbour during #handle_dv_learn.
 *
 * @param cls a `struct NeighbourSelectionContext *`
 * @param pid identity of the peer
 * @param value a `struct Neighbour`
 * @return #GNUNET_YES (always)
 */
static int
dv_neighbour_selection (void *cls,
                        const struct GNUNET_PeerIdentity *pid,
                        void *value)
{
  struct NeighbourSelectionContext *nsc = cls;

  (void) value;
  if (0 == GNUNET_memcmp (pid, &nsc->dvl->initiator))
    return GNUNET_YES; /* skip initiator */
  for (unsigned int i = 0; i < nsc->nhops; i++)
    if (0 == GNUNET_memcmp (pid, &nsc->hops[i].hop))
      return GNUNET_YES; /* skip peers on path */
  nsc->num_eligible++;
  return GNUNET_YES;
}


/**
 * Function called for each neighbour during #handle_dv_learn.
 * We call #forward_dv_learn() on the neighbour(s) selected
 * during #dv_neighbour_selection().
 *
 * @param cls a `struct NeighbourSelectionContext *`
 * @param pid identity of the peer
 * @param value a `struct Neighbour`
 * @return #GNUNET_YES (always)
 */
static int
dv_neighbour_transmission (void *cls,
                           const struct GNUNET_PeerIdentity *pid,
                           void *value)
{
  struct NeighbourSelectionContext *nsc = cls;

  (void) value;
  if (0 == GNUNET_memcmp (pid, &nsc->dvl->initiator))
    return GNUNET_YES; /* skip initiator */
  for (unsigned int i = 0; i < nsc->nhops; i++)
    if (0 == GNUNET_memcmp (pid, &nsc->hops[i].hop))
      return GNUNET_YES; /* skip peers on path */
  for (unsigned int i = 0; i < nsc->num_selections; i++)
  {
    if (nsc->selections[i] == nsc->num_eligible)
    {
      forward_dv_learn (pid,
                        nsc->dvl,
                        nsc->bi_history,
                        nsc->nhops,
                        nsc->hops,
                        nsc->in_time);
      break;
    }
  }
  nsc->num_eligible++;
  return GNUNET_YES;
}


/**
 * Computes the number of neighbours we should forward a DVInit
 * message to given that it has so far taken @a hops_taken hops
 * though the network and that the number of neighbours we have
 * in total is @a neighbour_count, out of which @a eligible_count
 * are not yet on the path.
 *
 * NOTE: technically we might want to include NSE in the formula to
 * get a better grip on the overall network size. However, for now
 * using NSE here would create a dependency issue in the build system.
 * => Left for later, hardcoded to 50 for now.
 *
 * The goal of the fomula is that we want to reach a total of LOG(NSE)
 * peers via DV (`target_total`).  We want the reach to be spread out
 * over various distances to the origin, with a bias towards shorter
 * distances.
 *
 * We make the strong assumption that the network topology looks
 * "similar" at other hops, in particular the @a neighbour_count
 * should be comparable at other hops.
 *
 * If the local neighbourhood is densely connected, we expect that @a
 * eligible_count is close to @a neighbour_count minus @a hops_taken
 * as a lot of the path is already known. In that case, we should
 * forward to few(er) peers to try to find a path out of the
 * neighbourhood. OTOH, if @a eligible_count is close to @a
 * neighbour_count, we should forward to many peers as we are either
 * still close to the origin (i.e.  @a hops_taken is small) or because
 * we managed to get beyond a local cluster.  We express this as
 * the `boost_factor` using the square of the fraction of eligible
 * neighbours (so if only 50% are eligible, we boost by 1/4, but if
 * 99% are eligible, the 'boost' will be almost 1).
 *
 * Second, the more hops we have taken, the larger the problem of an
 * exponential traffic explosion gets.  So we take the `target_total`,
 * and compute our degree such that at each distance d 2^{-d} peers
 * are selected (corrected by the `boost_factor`).
 *
 * @param hops_taken number of hops DVInit has travelled so far
 * @param neighbour_count number of neighbours we have in total
 * @param eligible_count number of neighbours we could in
 *        theory forward to
 */
static unsigned int
calculate_fork_degree (unsigned int hops_taken,
                       unsigned int neighbour_count,
                       unsigned int eligible_count)
{
  double target_total = 50.0; /* FIXME: use LOG(NSE)? */
  double eligible_ratio =
    ((double) eligible_count) / ((double) neighbour_count);
  double boost_factor = eligible_ratio * eligible_ratio;
  unsigned int rnd;
  double left;

  if (hops_taken >= 64)
  {
    GNUNET_break (0);
    return 0; /* precaution given bitshift below */
  }
  for (unsigned int i = 1; i < hops_taken; i++)
  {
    /* For each hop, subtract the expected number of targets
       reached at distance d (so what remains divided by 2^d) */
    target_total -= (target_total * boost_factor / (1LLU << i));
  }
  rnd =
    (unsigned int) floor (target_total * boost_factor / (1LLU << hops_taken));
  /* round up or down probabilistically depending on how close we were
     when floor()ing to rnd */
  left = target_total - (double) rnd;
  if (UINT32_MAX * left >
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX))
    rnd++; /* round up */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding DV learn message of %u hops %u(/%u/%u) times\n",
              hops_taken,
              rnd,
              eligible_count,
              neighbour_count);
  return rnd;
}


/**
 * Function called when peerstore is done storing a DV monotonic time.
 *
 * @param cls a `struct Neighbour`
 * @param success #GNUNET_YES if peerstore was successful
 */
static void
neighbour_store_dvmono_cb (void *cls, int success)
{
  struct Neighbour *n = cls;

  n->sc = NULL;
  if (GNUNET_YES != success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store other peer's monotonic time in peerstore!\n");
}


/**
 * Communicator gave us a DV learn message.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param dvl the message that was received
 */
static void
handle_dv_learn (void *cls, const struct TransportDVLearnMessage *dvl)
{
  struct CommunicatorMessageContext *cmc = cls;
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc;
  int bi_hop;
  uint16_t nhops;
  uint16_t bi_history;
  const struct DVPathEntryP *hops;
  int do_fwd;
  int did_initiator;
  struct GNUNET_TIME_Absolute in_time;
  struct Neighbour *n;

  nhops = ntohs (dvl->bidirectional); /* 0 = sender is initiator */
  bi_history = ntohs (dvl->bidirectional);
  hops = (const struct DVPathEntryP *) &dvl[1];
  if (0 == nhops)
  {
    /* sanity check */
    if (0 != GNUNET_memcmp (&dvl->initiator, &cmc->im.sender))
    {
      GNUNET_break (0);
      finish_cmc_handling (cmc);
      return;
    }
  }
  else
  {
    /* sanity check */
    if (0 != GNUNET_memcmp (&hops[nhops - 1].hop, &cmc->im.sender))
    {
      GNUNET_break (0);
      finish_cmc_handling (cmc);
      return;
    }
  }

  GNUNET_assert (CT_COMMUNICATOR == cmc->tc->type);
  cc = cmc->tc->details.communicator.cc;
  bi_hop = (GNUNET_TRANSPORT_CC_RELIABLE ==
            cc); // FIXME: add bi-directional flag to cc?
  in_time = GNUNET_TIME_absolute_get ();

  /* continue communicator here, everything else can happen asynchronous! */
  finish_cmc_handling (cmc);

  n = lookup_neighbour (&dvl->initiator);
  if (NULL != n)
  {
    if ((n->dv_monotime_available == GNUNET_YES) &&
        (GNUNET_TIME_absolute_ntoh (dvl->monotonic_time).abs_value_us <
         n->last_dv_learn_monotime.abs_value_us))
    {
      GNUNET_STATISTICS_update (GST_stats,
                                "# DV learn discarded due to time travel",
                                1,
                                GNUNET_NO);
      return;
    }
    if (GNUNET_OK != validate_dv_initiator_signature (dvl->monotonic_time,
                                                      &dvl->initiator,
                                                      &dvl->challenge,
                                                      &dvl->init_sig))
    {
      GNUNET_break_op (0);
      return;
    }
    n->last_dv_learn_monotime = GNUNET_TIME_absolute_ntoh (dvl->monotonic_time);
    if (GNUNET_YES == n->dv_monotime_available)
    {
      if (NULL != n->sc)
        GNUNET_PEERSTORE_store_cancel (n->sc);
      n->sc =
        GNUNET_PEERSTORE_store (peerstore,
                                "transport",
                                &dvl->initiator,
                                GNUNET_PEERSTORE_TRANSPORT_DVLEARN_MONOTIME,
                                &dvl->monotonic_time,
                                sizeof (dvl->monotonic_time),
                                GNUNET_TIME_UNIT_FOREVER_ABS,
                                GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                                &neighbour_store_dvmono_cb,
                                n);
    }
  }
  /* OPTIMIZE-FIXME: asynchronously (!) verify signatures!,
     If signature verification load too high, implement random drop strategy */
  for (unsigned int i = 0; i < nhops; i++)
  {
    struct DvHopPS dhp = {.purpose.purpose =
                            htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP),
                          .purpose.size = htonl (sizeof (dhp)),
                          .pred = (0 == i) ? dvl->initiator : hops[i - 1].hop,
                          .succ = (nhops - 1 == i) ? GST_my_identity
                                                   : hops[i + 1].hop,
                          .challenge = dvl->challenge};

    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP,
                                    &dhp.purpose,
                                    &hops[i].hop_sig,
                                    &hops[i].hop.public_key))
    {
      GNUNET_break_op (0);
      return;
    }
  }

  if (GNUNET_EXTRA_LOGGING > 0)
  {
    char *path;

    path = GNUNET_strdup (GNUNET_i2s (&dvl->initiator));
    for (unsigned int i = 0; i < nhops; i++)
    {
      char *tmp;

      GNUNET_asprintf (&tmp,
                       "%s%s%s",
                       path,
                       (bi_history & (1 << (nhops - i))) ? "<->" : "-->",
                       GNUNET_i2s (&hops[i].hop));
      GNUNET_free (path);
      path = tmp;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received DVInit via %s%s%s\n",
                path,
                bi_hop ? "<->" : "-->",
                GNUNET_i2s (&GST_my_identity));
    GNUNET_free (path);
  }

  do_fwd = GNUNET_YES;
  if (0 == GNUNET_memcmp (&GST_my_identity, &dvl->initiator))
  {
    struct GNUNET_PeerIdentity path[nhops + 1];
    struct GNUNET_TIME_Relative host_latency_sum;
    struct GNUNET_TIME_Relative latency;
    struct GNUNET_TIME_Relative network_latency;

    /* We initiated this, learn the forward path! */
    path[0] = GST_my_identity;
    path[1] = hops[0].hop;
    host_latency_sum = GNUNET_TIME_relative_ntoh (dvl->non_network_delay);

    // Need also something to lookup initiation time
    // to compute RTT! -> add RTT argument here?
    latency = GNUNET_TIME_UNIT_FOREVER_REL; // FIXME: initialize properly
    // (based on dvl->challenge, we can identify time of origin!)

    network_latency = GNUNET_TIME_relative_subtract (latency, host_latency_sum);
    /* assumption: latency on all links is the same */
    network_latency = GNUNET_TIME_relative_divide (network_latency, nhops);

    for (unsigned int i = 2; i <= nhops; i++)
    {
      struct GNUNET_TIME_Relative ilat;

      /* assumption: linear latency increase per hop */
      ilat = GNUNET_TIME_relative_multiply (network_latency, i);
      path[i] = hops[i - 1].hop;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Learned path with %u hops to %s with latency %s\n",
                  i,
                  GNUNET_i2s (&path[i]),
                  GNUNET_STRINGS_relative_time_to_string (ilat, GNUNET_YES));
      learn_dv_path (path,
                     i,
                     ilat,
                     GNUNET_TIME_relative_to_absolute (
                       ADDRESS_VALIDATION_LIFETIME));
    }
    /* as we initiated, do not forward again (would be circular!) */
    do_fwd = GNUNET_NO;
    return;
  }
  if (bi_hop)
  {
    /* last hop was bi-directional, we could learn something here! */
    struct GNUNET_PeerIdentity path[nhops + 2];

    path[0] = GST_my_identity;
    path[1] = hops[nhops - 1].hop; /* direct neighbour == predecessor! */
    for (unsigned int i = 0; i < nhops; i++)
    {
      int iret;

      if (0 == (bi_history & (1 << i)))
        break; /* i-th hop not bi-directional, stop learning! */
      if (i == nhops)
      {
        path[i + 2] = dvl->initiator;
      }
      else
      {
        path[i + 2] = hops[nhops - i - 2].hop;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Learned inverse path with %u hops to %s\n",
                  i + 1,
                  GNUNET_i2s (&path[i + 2]));
      iret = learn_dv_path (path,
                            i + 2,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_TIME_UNIT_ZERO_ABS);
      if (GNUNET_SYSERR == iret)
      {
        /* path invalid or too long to be interesting for US, thus should also
           not be interesting to our neighbours, cut path when forwarding to
           'i' hops, except of course for the one that goes back to the
           initiator */
        GNUNET_STATISTICS_update (GST_stats,
                                  "# DV learn not forwarded due invalidity of path",
                                  1,
                                  GNUNET_NO);
        do_fwd = GNUNET_NO;
        break;
      }
      if ((GNUNET_NO == iret) && (nhops == i + 1))
      {
        /* we have better paths, and this is the longest target,
           so there cannot be anything interesting later */
        GNUNET_STATISTICS_update (GST_stats,
                                  "# DV learn not forwarded, got better paths",
                                  1,
                                  GNUNET_NO);
        do_fwd = GNUNET_NO;
        break;
      }
    }
  }

  if (MAX_DV_HOPS_ALLOWED == nhops)
  {
    /* At limit, we're out of here! */
    finish_cmc_handling (cmc);
    return;
  }

  /* Forward to initiator, if path non-trivial and possible */
  bi_history = (bi_history << 1) | (bi_hop ? 1 : 0);
  did_initiator = GNUNET_NO;
  if ((1 < nhops) &&
      (GNUNET_YES ==
       GNUNET_CONTAINER_multipeermap_contains (neighbours, &dvl->initiator)))
  {
    /* send back to origin! */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending DVL back to initiator %s\n",
                GNUNET_i2s (&dvl->initiator));
    forward_dv_learn (&dvl->initiator, dvl, bi_history, nhops, hops, in_time);
    did_initiator = GNUNET_YES;
  }
  /* We forward under two conditions: either we still learned something
     ourselves (do_fwd), or the path was darn short and thus the initiator is
     likely to still be very interested in this (and we did NOT already
     send it back to the initiator) */
  if ((do_fwd) || ((nhops < MIN_DV_PATH_LENGTH_FOR_INITIATOR) &&
                   (GNUNET_NO == did_initiator)))
  {
    /* Pick random neighbours that are not yet on the path */
    struct NeighbourSelectionContext nsc;
    unsigned int n_cnt;

    n_cnt = GNUNET_CONTAINER_multipeermap_size (neighbours);
    nsc.nhops = nhops;
    nsc.dvl = dvl;
    nsc.bi_history = bi_history;
    nsc.hops = hops;
    nsc.in_time = in_time;
    nsc.num_eligible = 0;
    GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                           &dv_neighbour_selection,
                                           &nsc);
    if (0 == nsc.num_eligible)
      return; /* done here, cannot forward to anyone else */
    nsc.num_selections = calculate_fork_degree (nhops, n_cnt, nsc.num_eligible);
    nsc.num_selections =
      GNUNET_MIN (MAX_DV_DISCOVERY_SELECTION, nsc.num_selections);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Forwarding DVL to %u other peers\n",
                nsc.num_selections);
    for (unsigned int i = 0; i < nsc.num_selections; i++)
      nsc.selections[i] =
        (nsc.num_selections == n_cnt)
          ? i /* all were selected, avoid collisions by chance */
          : GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, n_cnt);
    nsc.num_eligible = 0;
    GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                           &dv_neighbour_transmission,
                                           &nsc);
  }
}


/**
 * Communicator gave us a DV box.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param dvb the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_dv_box (void *cls, const struct TransportDVBoxMessage *dvb)
{
  uint16_t size = ntohs (dvb->header.size);
  uint16_t num_hops = ntohs (dvb->num_hops);
  const struct GNUNET_PeerIdentity *hops =
    (const struct GNUNET_PeerIdentity *) &dvb[1];

  (void) cls;
  if (size < sizeof (*dvb) + num_hops * sizeof (struct GNUNET_PeerIdentity) +
               sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* This peer must not be on the path */
  for (unsigned int i = 0; i < num_hops; i++)
    if (0 == GNUNET_memcmp (&hops[i], &GST_my_identity))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  return GNUNET_YES;
}


/**
 * Create a DV Box message and queue it for transmission to
 * @ea next_hop.
 *
 * @param next_hop peer to receive the message next
 * @param total_hops how many hops did the message take so far
 * @param num_hops length of the @a hops array
 * @param origin origin of the message
 * @param hops next peer(s) to the destination, including destination
 * @param payload payload of the box
 * @param payload_size number of bytes in @a payload
 */
static void
forward_dv_box (struct Neighbour *next_hop,
                const struct TransportDVBoxMessage *hdr,
                uint16_t total_hops,
                uint16_t num_hops,
                const struct GNUNET_PeerIdentity *hops,
                const void *enc_payload,
                uint16_t enc_payload_size)
{
  char buf[sizeof (struct TransportDVBoxMessage) +
           num_hops * sizeof (struct GNUNET_PeerIdentity) + enc_payload_size];
  struct GNUNET_PeerIdentity *dhops =
    (struct GNUNET_PeerIdentity *) &buf[sizeof (struct TransportDVBoxMessage)];

  memcpy (buf, hdr, sizeof (*hdr));
  memcpy (dhops, hops, num_hops * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&dhops[num_hops], enc_payload, enc_payload_size);
  route_message (&next_hop->pid,
                 (const struct GNUNET_MessageHeader *) buf,
                 RMO_NONE);
}


/**
 * Free data structures associated with @a b.
 *
 * @param b data structure to release
 */
static void
free_backtalker (struct Backtalker *b)
{
  if (NULL != b->get)
  {
    GNUNET_PEERSTORE_iterate_cancel (b->get);
    b->get = NULL;
    GNUNET_assert (NULL != b->cmc);
    finish_cmc_handling (b->cmc);
    b->cmc = NULL;
  }
  if (NULL != b->task)
  {
    GNUNET_SCHEDULER_cancel (b->task);
    b->task = NULL;
  }
  if (NULL != b->sc)
  {
    GNUNET_PEERSTORE_store_cancel (b->sc);
    b->sc = NULL;
  }
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (backtalkers, &b->pid, b));
  GNUNET_free (b);
}


/**
 * Callback to free backtalker records.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct Backtalker`
 * @return #GNUNET_OK (always)
 */
static int
free_backtalker_cb (void *cls,
                    const struct GNUNET_PeerIdentity *pid,
                    void *value)
{
  struct Backtalker *b = value;

  (void) cls;
  (void) pid;
  free_backtalker (b);
  return GNUNET_OK;
}


/**
 * Function called when it is time to clean up a backtalker.
 *
 * @param cls a `struct Backtalker`
 */
static void
backtalker_timeout_cb (void *cls)
{
  struct Backtalker *b = cls;

  b->task = NULL;
  if (0 != GNUNET_TIME_absolute_get_remaining (b->timeout).rel_value_us)
  {
    b->task = GNUNET_SCHEDULER_add_at (b->timeout, &backtalker_timeout_cb, b);
    return;
  }
  GNUNET_assert (NULL == b->sc);
  free_backtalker (b);
}


/**
 * Function called with the monotonic time of a backtalker
 * by PEERSTORE. Updates the time and continues processing.
 *
 * @param cls a `struct Backtalker`
 * @param record the information found, NULL for the last call
 * @param emsg error message
 */
static void
backtalker_monotime_cb (void *cls,
                        const struct GNUNET_PEERSTORE_Record *record,
                        const char *emsg)
{
  struct Backtalker *b = cls;
  struct GNUNET_TIME_AbsoluteNBO *mtbe;
  struct GNUNET_TIME_Absolute mt;

  (void) emsg;
  if (NULL == record)
  {
    /* we're done with #backtalker_monotime_cb() invocations,
       continue normal processing */
    b->get = NULL;
    GNUNET_assert (NULL != b->cmc);
    if (0 != b->body_size)
      demultiplex_with_cmc (b->cmc,
                            (const struct GNUNET_MessageHeader *) &b[1]);
    else
      finish_cmc_handling (b->cmc);
    b->cmc = NULL;
    return;
  }
  if (sizeof (*mtbe) != record->value_size)
  {
    GNUNET_break (0);
    return;
  }
  mtbe = record->value;
  mt = GNUNET_TIME_absolute_ntoh (*mtbe);
  if (mt.abs_value_us > b->monotonic_time.abs_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Backtalker message from %s dropped, monotime in the past\n",
                GNUNET_i2s (&b->pid));
    GNUNET_STATISTICS_update (
      GST_stats,
      "# Backchannel messages dropped: monotonic time not increasing",
      1,
      GNUNET_NO);
    b->monotonic_time = mt;
    /* Setting body_size to 0 prevents call to #forward_backchannel_payload()
     */
    b->body_size = 0;
    return;
  }
}


/**
 * Function called by PEERSTORE when the store operation of
 * a backtalker's monotonic time is complete.
 *
 * @param cls the `struct Backtalker`
 * @param success #GNUNET_OK on success
 */
static void
backtalker_monotime_store_cb (void *cls, int success)
{
  struct Backtalker *b = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store backtalker's monotonic time in PEERSTORE!\n");
  }
  b->sc = NULL;
  b->task = GNUNET_SCHEDULER_add_at (b->timeout, &backtalker_timeout_cb, b);
}


/**
 * The backtalker @a b monotonic time changed. Update PEERSTORE.
 *
 * @param b a backtalker with updated monotonic time
 */
static void
update_backtalker_monotime (struct Backtalker *b)
{
  struct GNUNET_TIME_AbsoluteNBO mtbe;

  if (NULL != b->sc)
  {
    GNUNET_PEERSTORE_store_cancel (b->sc);
    b->sc = NULL;
  }
  else
  {
    GNUNET_SCHEDULER_cancel (b->task);
    b->task = NULL;
  }
  mtbe = GNUNET_TIME_absolute_hton (b->monotonic_time);
  b->sc =
    GNUNET_PEERSTORE_store (peerstore,
                            "transport",
                            &b->pid,
                            GNUNET_PEERSTORE_TRANSPORT_BACKCHANNEL_MONOTIME,
                            &mtbe,
                            sizeof (mtbe),
                            GNUNET_TIME_UNIT_FOREVER_ABS,
                            GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                            &backtalker_monotime_store_cb,
                            b);
}


/**
 * Communicator gave us a DV box.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param dvb the message that was received
 */
static void
handle_dv_box (void *cls, const struct TransportDVBoxMessage *dvb)
{
  struct CommunicatorMessageContext *cmc = cls;
  uint16_t size = ntohs (dvb->header.size) - sizeof (*dvb);
  uint16_t num_hops = ntohs (dvb->num_hops);
  const struct GNUNET_PeerIdentity *hops =
    (const struct GNUNET_PeerIdentity *) &dvb[1];
  const char *enc_payload = (const char *) &hops[num_hops];
  uint16_t enc_payload_size =
    size - (num_hops * sizeof (struct GNUNET_PeerIdentity));
  struct DVKeyState key;
  struct GNUNET_HashCode hmac;
  const char *hdr;
  size_t hdr_len;

  if (GNUNET_EXTRA_LOGGING > 0)
  {
    char *path;

    path = GNUNET_strdup (GNUNET_i2s (&GST_my_identity));
    for (unsigned int i = 0; i < num_hops; i++)
    {
      char *tmp;

      GNUNET_asprintf (&tmp, "%s->%s", path, GNUNET_i2s (&hops[i]));
      GNUNET_free (path);
      path = tmp;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received DVBox with remainig path %s\n",
                path);
    GNUNET_free (path);
  }

  if (num_hops > 0)
  {
    /* We're trying from the end of the hops array, as we may be
       able to find a shortcut unknown to the origin that way */
    for (int i = num_hops - 1; i >= 0; i--)
    {
      struct Neighbour *n;

      if (0 == GNUNET_memcmp (&hops[i], &GST_my_identity))
      {
        GNUNET_break_op (0);
        finish_cmc_handling (cmc);
        return;
      }
      n = lookup_neighbour (&hops[i]);
      if (NULL == n)
        continue;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Skipping %u/%u hops ahead while routing DV Box\n",
                  i,
                  num_hops);
      forward_dv_box (n,
                      dvb,
                      ntohs (dvb->total_hops) + 1,
                      num_hops - i - 1, /* number of hops left */
                      &hops[i + 1], /* remaining hops */
                      enc_payload,
                      enc_payload_size);
      GNUNET_STATISTICS_update (GST_stats,
                                "# DV hops skipped routing boxes",
                                i,
                                GNUNET_NO);
      GNUNET_STATISTICS_update (GST_stats,
                                "# DV boxes routed (total)",
                                1,
                                GNUNET_NO);
      finish_cmc_handling (cmc);
      return;
    }
    /* Woopsie, next hop not in neighbours, drop! */
    GNUNET_STATISTICS_update (GST_stats,
                              "# DV Boxes dropped: next hop unknown",
                              1,
                              GNUNET_NO);
    finish_cmc_handling (cmc);
    return;
  }
  /* We are the target. Unbox and handle message. */
  GNUNET_STATISTICS_update (GST_stats,
                            "# DV boxes opened (ultimate target)",
                            1,
                            GNUNET_NO);
  cmc->total_hops = ntohs (dvb->total_hops);

  dh_key_derive_eph_pub (&dvb->ephemeral_key, &dvb->iv, &key);
  hdr = (const char *) &dvb[1];
  hdr_len = ntohs (dvb->header.size) - sizeof (*dvb);
  dv_hmac (&key, &hmac, hdr, hdr_len);
  if (0 != GNUNET_memcmp (&hmac, &dvb->hmac))
  {
    /* HMAC missmatch, disard! */
    GNUNET_break_op (0);
    finish_cmc_handling (cmc);
    return;
  }
  /* begin actual decryption */
  {
    struct Backtalker *b;
    struct GNUNET_TIME_Absolute monotime;
    struct TransportDVBoxPayloadP ppay;
    char body[hdr_len - sizeof (ppay)] GNUNET_ALIGN;
    const struct GNUNET_MessageHeader *mh =
      (const struct GNUNET_MessageHeader *) body;

    GNUNET_assert (hdr_len >=
                   sizeof (ppay) + sizeof (struct GNUNET_MessageHeader));
    dv_decrypt (&key, &ppay, hdr, sizeof (ppay));
    dv_decrypt (&key, &body, &hdr[sizeof (ppay)], hdr_len - sizeof (ppay));
    dv_key_clean (&key);
    if (ntohs (mh->size) != sizeof (body))
    {
      GNUNET_break_op (0);
      finish_cmc_handling (cmc);
      return;
    }
    /* need to prevent box-in-a-box (and DV_LEARN) so check inbox type! */
    switch (ntohs (mh->type))
    {
    case GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX:
      GNUNET_break_op (0);
      finish_cmc_handling (cmc);
      return;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN:
      GNUNET_break_op (0);
      finish_cmc_handling (cmc);
      return;
    default:
      /* permitted, continue */
      break;
    }
    monotime = GNUNET_TIME_absolute_ntoh (ppay.monotonic_time);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Decrypted backtalk from %s\n",
                GNUNET_i2s (&ppay.sender));
    b = GNUNET_CONTAINER_multipeermap_get (backtalkers, &ppay.sender);
    if ((NULL != b) && (monotime.abs_value_us < b->monotonic_time.abs_value_us))
    {
      GNUNET_STATISTICS_update (
        GST_stats,
        "# Backchannel messages dropped: monotonic time not increasing",
        1,
        GNUNET_NO);
      finish_cmc_handling (cmc);
      return;
    }
    if ((NULL == b) ||
        (0 != GNUNET_memcmp (&b->last_ephemeral, &dvb->ephemeral_key)))
    {
      /* Check signature */
      struct EphemeralConfirmationPS ec;

      ec.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL);
      ec.purpose.size = htonl (sizeof (ec));
      ec.target = GST_my_identity;
      ec.ephemeral_key = dvb->ephemeral_key;
      if (
        GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL,
                                    &ec.purpose,
                                    &ppay.sender_sig,
                                    &ppay.sender.public_key))
      {
        /* Signature invalid, disard! */
        GNUNET_break_op (0);
        finish_cmc_handling (cmc);
        return;
      }
    }
    /* Update sender, we now know the real origin! */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "DVBox received for me from %s via %s\n",
                GNUNET_i2s2 (&ppay.sender),
                GNUNET_i2s (&cmc->im.sender));
    cmc->im.sender = ppay.sender;

    if (NULL != b)
    {
      /* update key cache and mono time */
      b->last_ephemeral = dvb->ephemeral_key;
      b->monotonic_time = monotime;
      update_backtalker_monotime (b);
      b->timeout =
        GNUNET_TIME_relative_to_absolute (BACKCHANNEL_INACTIVITY_TIMEOUT);

      demultiplex_with_cmc (cmc, mh);
      return;
    }
    /* setup data structure to cache signature AND check
       monotonic time with PEERSTORE before forwarding backchannel payload */
    b = GNUNET_malloc (sizeof (struct Backtalker) + sizeof (body));
    b->pid = ppay.sender;
    b->body_size = sizeof (body);
    memcpy (&b[1], body, sizeof (body));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (
                     backtalkers,
                     &b->pid,
                     b,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    b->monotonic_time = monotime; /* NOTE: to be checked still! */
    b->cmc = cmc;
    b->timeout =
      GNUNET_TIME_relative_to_absolute (BACKCHANNEL_INACTIVITY_TIMEOUT);
    b->task = GNUNET_SCHEDULER_add_at (b->timeout, &backtalker_timeout_cb, b);
    b->get =
      GNUNET_PEERSTORE_iterate (peerstore,
                                "transport",
                                &b->pid,
                                GNUNET_PEERSTORE_TRANSPORT_BACKCHANNEL_MONOTIME,
                                &backtalker_monotime_cb,
                                b);
  } /* end actual decryption */
}


/**
 * Client notified us about transmission from a peer.  Process the request.
 *
 * @param cls a `struct TransportClient` which sent us the message
 * @param obm the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_incoming_msg (void *cls,
                    const struct GNUNET_TRANSPORT_IncomingMessage *im)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_MQ_check_boxed_message (im);
  return GNUNET_OK;
}


/**
 * Communicator gave us a transport address validation challenge.  Process the
 * request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param tvc the message that was received
 */
static void
handle_validation_challenge (
  void *cls,
  const struct TransportValidationChallengeMessage *tvc)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct TransportValidationResponseMessage *tvr;

  if (cmc->total_hops > 0)
  {
    /* DV routing is not allowed for validation challenges! */
    GNUNET_break_op (0);
    finish_cmc_handling (cmc);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received address validation challenge %s\n",
              GNUNET_sh2s (&tvc->challenge.value));
  tvr = GNUNET_new (struct TransportValidationResponseMessage);
  tvr->header.type =
    htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_RESPONSE);
  tvr->header.size = htons (sizeof (*tvr));
  tvr->challenge = tvc->challenge;
  tvr->origin_time = tvc->sender_time;
  tvr->validity_duration = cmc->im.expected_address_validity;
  {
    /* create signature */
    struct TransportValidationPS tvp =
      {.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE),
       .purpose.size = htonl (sizeof (tvp)),
       .validity_duration = tvr->validity_duration,
       .challenge = tvc->challenge};

    GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
                                                          &tvp.purpose,
                                                          &tvr->signature));
  }
  route_message (&cmc->im.sender,
                 &tvr->header,
                 RMO_ANYTHING_GOES | RMO_REDUNDANT);
  finish_cmc_handling (cmc);
}


/**
 * Closure for #check_known_challenge.
 */
struct CheckKnownChallengeContext
{
  /**
   * Set to the challenge we are looking for.
   */
  const struct ChallengeNonceP *challenge;

  /**
   * Set to a matching validation state, if one was found.
   */
  struct ValidationState *vs;
};


/**
 * Test if the validation state in @a value matches the
 * challenge from @a cls.
 *
 * @param cls a `struct CheckKnownChallengeContext`
 * @param pid unused (must match though)
 * @param value a `struct ValidationState`
 * @return #GNUNET_OK if not matching, #GNUNET_NO if match found
 */
static int
check_known_challenge (void *cls,
                       const struct GNUNET_PeerIdentity *pid,
                       void *value)
{
  struct CheckKnownChallengeContext *ckac = cls;
  struct ValidationState *vs = value;

  (void) pid;
  if (0 != GNUNET_memcmp (&vs->challenge, ckac->challenge))
    return GNUNET_OK;
  ckac->vs = vs;
  return GNUNET_NO;
}


/**
 * Function called when peerstore is done storing a
 * validated address.
 *
 * @param cls a `struct ValidationState`
 * @param success #GNUNET_YES on success
 */
static void
peerstore_store_validation_cb (void *cls, int success)
{
  struct ValidationState *vs = cls;

  vs->sc = NULL;
  if (GNUNET_YES == success)
    return;
  GNUNET_STATISTICS_update (GST_stats,
                            "# Peerstore failed to store foreign address",
                            1,
                            GNUNET_NO);
}


/**
 * Task run periodically to validate some address based on #validation_heap.
 *
 * @param cls NULL
 */
static void
validation_start_cb (void *cls);


/**
 * Set the time for next_challenge of @a vs to @a new_time.
 * Updates the heap and if necessary reschedules the job.
 *
 * @param vs validation state to update
 * @param new_time new time for revalidation
 */
static void
update_next_challenge_time (struct ValidationState *vs,
                            struct GNUNET_TIME_Absolute new_time)
{
  struct GNUNET_TIME_Relative delta;

  if (new_time.abs_value_us == vs->next_challenge.abs_value_us)
    return; /* be lazy */
  vs->next_challenge = new_time;
  if (NULL == vs->hn)
    vs->hn =
      GNUNET_CONTAINER_heap_insert (validation_heap, vs, new_time.abs_value_us);
  else
    GNUNET_CONTAINER_heap_update_cost (vs->hn, new_time.abs_value_us);
  if ((vs != GNUNET_CONTAINER_heap_peek (validation_heap)) &&
      (NULL != validation_task))
    return;
  if (NULL != validation_task)
    GNUNET_SCHEDULER_cancel (validation_task);
  /* randomize a bit */
  delta.rel_value_us =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                              MIN_DELAY_ADDRESS_VALIDATION.rel_value_us);
  new_time = GNUNET_TIME_absolute_add (new_time, delta);
  validation_task =
    GNUNET_SCHEDULER_add_at (new_time, &validation_start_cb, NULL);
}


/**
 * Find the queue matching @a pid and @a address.
 *
 * @param pid peer the queue must go to
 * @param address address the queue must use
 * @return NULL if no such queue exists
 */
static struct Queue *
find_queue (const struct GNUNET_PeerIdentity *pid, const char *address)
{
  struct Neighbour *n;

  n = lookup_neighbour (pid);
  if (NULL == n)
    return NULL;
  for (struct Queue *pos = n->queue_head; NULL != pos;
       pos = pos->next_neighbour)
  {
    if (0 == strcmp (pos->address, address))
      return pos;
  }
  return NULL;
}


/**
 * Communicator gave us a transport address validation response.  Process the
 * request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call
 * #finish_cmc_handling() when done)
 * @param tvr the message that was received
 */
static void
handle_validation_response (
  void *cls,
  const struct TransportValidationResponseMessage *tvr)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct ValidationState *vs;
  struct CheckKnownChallengeContext ckac = {.challenge = &tvr->challenge,
                                            .vs = NULL};
  struct GNUNET_TIME_Absolute origin_time;
  struct Queue *q;
  struct Neighbour *n;
  struct VirtualLink *vl;

  /* check this is one of our challenges */
  (void) GNUNET_CONTAINER_multipeermap_get_multiple (validation_map,
                                                     &cmc->im.sender,
                                                     &check_known_challenge,
                                                     &ckac);
  if (NULL == (vs = ckac.vs))
  {
    /* This can happen simply if we 'forgot' the challenge by now,
       i.e. because we received the validation response twice */
    GNUNET_STATISTICS_update (GST_stats,
                              "# Validations dropped, challenge unknown",
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Validation response %s dropped, challenge unknown\n",
                GNUNET_sh2s (&tvr->challenge.value));
    finish_cmc_handling (cmc);
    return;
  }

  /* sanity check on origin time */
  origin_time = GNUNET_TIME_absolute_ntoh (tvr->origin_time);
  if ((origin_time.abs_value_us < vs->first_challenge_use.abs_value_us) ||
      (origin_time.abs_value_us > vs->last_challenge_use.abs_value_us))
  {
    GNUNET_break_op (0);
    finish_cmc_handling (cmc);
    return;
  }

  {
    /* check signature */
    struct TransportValidationPS tvp =
      {.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE),
       .purpose.size = htonl (sizeof (tvp)),
       .validity_duration = tvr->validity_duration,
       .challenge = tvr->challenge};

    if (
      GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE,
                                  &tvp.purpose,
                                  &tvr->signature,
                                  &cmc->im.sender.public_key))
    {
      GNUNET_break_op (0);
      finish_cmc_handling (cmc);
      return;
    }
  }

  /* validity is capped by our willingness to keep track of the
     validation entry and the maximum the other peer allows */
  vs->valid_until = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_min (GNUNET_TIME_relative_ntoh (
                                tvr->validity_duration),
                              MAX_ADDRESS_VALID_UNTIL));
  vs->validated_until =
    GNUNET_TIME_absolute_min (vs->valid_until,
                              GNUNET_TIME_relative_to_absolute (
                                ADDRESS_VALIDATION_LIFETIME));
  vs->validation_rtt = GNUNET_TIME_absolute_get_duration (origin_time);
  vs->challenge_backoff = GNUNET_TIME_UNIT_ZERO;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &vs->challenge,
                              sizeof (vs->challenge));
  vs->first_challenge_use = GNUNET_TIME_absolute_subtract (
    vs->validated_until,
    GNUNET_TIME_relative_multiply (vs->validation_rtt,
                                   VALIDATION_RTT_BUFFER_FACTOR));
  vs->last_challenge_use =
    GNUNET_TIME_UNIT_ZERO_ABS; /* challenge was not yet used */
  update_next_challenge_time (vs, vs->first_challenge_use);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Validation response %s accepted, address valid until %s\n",
              GNUNET_sh2s (&tvr->challenge.value),
              GNUNET_STRINGS_absolute_time_to_string (vs->valid_until));
  vs->sc = GNUNET_PEERSTORE_store (peerstore,
                                   "transport",
                                   &cmc->im.sender,
                                   GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY,
                                   vs->address,
                                   strlen (vs->address) + 1,
                                   vs->valid_until,
                                   GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
                                   &peerstore_store_validation_cb,
                                   vs);
  finish_cmc_handling (cmc);

  /* Finally, we now possibly have a confirmed (!) working queue,
     update queue status (if queue still is around) */
  q = find_queue (&vs->pid, vs->address);
  if (NULL == q)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              "# Queues lost at time of successful validation",
                              1,
                              GNUNET_NO);
    return;
  }
  q->validated_until = vs->validated_until;
  q->pd.aged_rtt = vs->validation_rtt;
  n = q->neighbour;
  vl = GNUNET_CONTAINER_multipeermap_get (links, &vs->pid);
  if (NULL != vl)
  {
    /* Link was already up, remember n is also now available and we are done */
    vl->n = n;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Virtual link to %s could now also direct neighbour!\n",
                GNUNET_i2s (&vs->pid));
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new virtual link to %s using direct neighbour!\n",
              GNUNET_i2s (&vs->pid));
  vl = GNUNET_new (struct VirtualLink);
  vl->target = n->pid;
  vl->n = n;
  n->vl = vl;
  vl->core_recv_window = RECV_WINDOW_SIZE;
  vl->visibility_task =
    GNUNET_SCHEDULER_add_at (q->validated_until, &check_link_down, vl);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multipeermap_put (
                  links,
                  &vl->target,
                  vl,
                  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  /* We lacked a confirmed connection to the target
     before, so tell CORE about it (finally!) */
  cores_send_connect_info (&n->pid);
}


/**
 * Incoming meessage.  Process the request.
 *
 * @param im the send message that was received
 */
static void
handle_incoming_msg (void *cls,
                     const struct GNUNET_TRANSPORT_IncomingMessage *im)
{
  struct TransportClient *tc = cls;
  struct CommunicatorMessageContext *cmc =
    GNUNET_new (struct CommunicatorMessageContext);

  cmc->tc = tc;
  cmc->im = *im;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message via communicator from peer %s\n",
              GNUNET_i2s (&im->sender));
  demultiplex_with_cmc (cmc, (const struct GNUNET_MessageHeader *) &im[1]);
}


/**
 * Given an inbound message @a msg from a communicator @a cmc,
 * demultiplex it based on the type calling the right handler.
 *
 * @param cmc context for demultiplexing
 * @param msg message to demultiplex
 */
static void
demultiplex_with_cmc (struct CommunicatorMessageContext *cmc,
                      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
    {GNUNET_MQ_hd_var_size (fragment_box,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT,
                            struct TransportFragmentBoxMessage,
                            &cmc),
     GNUNET_MQ_hd_var_size (reliability_box,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX,
                            struct TransportReliabilityBoxMessage,
                            &cmc),
     GNUNET_MQ_hd_var_size (reliability_ack,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK,
                            struct TransportReliabilityAckMessage,
                            &cmc),
     GNUNET_MQ_hd_var_size (backchannel_encapsulation,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION,
                            struct TransportBackchannelEncapsulationMessage,
                            &cmc),
     GNUNET_MQ_hd_var_size (dv_learn,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN,
                            struct TransportDVLearnMessage,
                            &cmc),
     GNUNET_MQ_hd_var_size (dv_box,
                            GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX,
                            struct TransportDVBoxMessage,
                            &cmc),
     GNUNET_MQ_hd_fixed_size (
       validation_challenge,
       GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_CHALLENGE,
       struct TransportValidationChallengeMessage,
       &cmc),
     GNUNET_MQ_hd_fixed_size (
       validation_response,
       GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_RESPONSE,
       struct TransportValidationResponseMessage,
       &cmc),
     GNUNET_MQ_handler_end ()};
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling message of type %u with %u bytes\n",
              (unsigned int) ntohs (msg->type),
              (unsigned int) ntohs (msg->size));
  ret = GNUNET_MQ_handle_message (handlers, msg);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cmc->tc->client);
    GNUNET_free (cmc);
    return;
  }
  if (GNUNET_NO == ret)
  {
    /* unencapsulated 'raw' message */
    handle_raw_message (&cmc, msg);
  }
}


/**
 * New queue became available.  Check message.
 *
 * @param cls the client
 * @param aqm the send message that was sent
 */
static int
check_add_queue_message (void *cls,
                         const struct GNUNET_TRANSPORT_AddQueueMessage *aqm)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_MQ_check_zero_termination (aqm);
  return GNUNET_OK;
}


/**
 * If necessary, generates the UUID for a @a pm
 *
 * @param pm pending message to generate UUID for.
 */
static void
set_pending_message_uuid (struct PendingMessage *pm)
{
  if (pm->msg_uuid_set)
    return;
  pm->msg_uuid.uuid = pm->vl->message_uuid_ctr++;
  pm->msg_uuid_set = GNUNET_YES;
}


/**
 * Setup data structure waiting for acknowledgements.
 *
 * @param queue queue the @a pm will be sent over
 * @param dvh path the message will take, may be NULL
 * @param pm the pending message for transmission
 * @return corresponding fresh pending acknowledgement
 */
static struct PendingAcknowledgement *
prepare_pending_acknowledgement (struct Queue *queue,
                                 struct DistanceVectorHop *dvh,
                                 struct PendingMessage *pm)
{
  struct PendingAcknowledgement *pa;

  pa = GNUNET_new (struct PendingAcknowledgement);
  pa->queue = queue;
  pa->dvh = dvh;
  pa->pm = pm;
  do
  {
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                                &pa->ack_uuid,
                                sizeof (pa->ack_uuid));
  } while (GNUNET_YES != GNUNET_CONTAINER_multishortmap_put (
                           pending_acks,
                           &pa->ack_uuid.value,
                           pa,
                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_CONTAINER_MDLL_insert (queue, queue->pa_head, queue->pa_tail, pa);
  GNUNET_CONTAINER_MDLL_insert (pm, pm->pa_head, pm->pa_tail, pa);
  if (NULL != dvh)
    GNUNET_CONTAINER_MDLL_insert (dvh, dvh->pa_head, dvh->pa_tail, pa);
  pa->transmission_time = GNUNET_TIME_absolute_get ();
  pa->message_size = pm->bytes_msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Waiting for ACKnowledgment `%s' for <%llu>\n",
              GNUNET_sh2s (&pa->ack_uuid.value),
              pm->logging_uuid);
  return pa;
}


/**
 * Fragment the given @a pm to the given @a mtu.  Adds
 * additional fragments to the neighbour as well. If the
 * @a mtu is too small, generates and error for the @a pm
 * and returns NULL.
 *
 * @param queue which queue to fragment for
 * @param dvh path the message will take, or NULL
 * @param pm pending message to fragment for transmission
 * @return new message to transmit
 */
static struct PendingMessage *
fragment_message (struct Queue *queue,
                  struct DistanceVectorHop *dvh,
                  struct PendingMessage *pm)
{
  struct PendingAcknowledgement *pa;
  struct PendingMessage *ff;
  uint16_t mtu;

  mtu = (0 == queue->mtu)
          ? UINT16_MAX - sizeof (struct GNUNET_TRANSPORT_SendMessageTo)
          : queue->mtu;
  set_pending_message_uuid (pm);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Fragmenting message %llu <%llu> to %s for MTU %u\n",
              (unsigned long long) pm->msg_uuid.uuid,
              pm->logging_uuid,
              GNUNET_i2s (&pm->vl->target),
              (unsigned int) mtu);
  pa = prepare_pending_acknowledgement (queue, dvh, pm);

  /* This invariant is established in #handle_add_queue_message() */
  GNUNET_assert (mtu > sizeof (struct TransportFragmentBoxMessage));

  /* select fragment for transmission, descending the tree if it has
     been expanded until we are at a leaf or at a fragment that is small
     enough
   */
  ff = pm;
  while (((ff->bytes_msg > mtu) || (pm == ff)) &&
         (ff->frag_off == ff->bytes_msg) && (NULL != ff->head_frag))
  {
    ff = ff->head_frag; /* descent into fragmented fragments */
  }

  if (((ff->bytes_msg > mtu) || (pm == ff)) && (pm->frag_off < pm->bytes_msg))
  {
    /* Did not yet calculate all fragments, calculate next fragment */
    struct PendingMessage *frag;
    struct TransportFragmentBoxMessage tfb;
    const char *orig;
    char *msg;
    uint16_t fragmax;
    uint16_t fragsize;
    uint16_t msize;
    uint16_t xoff = 0;

    orig = (const char *) &ff[1];
    msize = ff->bytes_msg;
    if (pm != ff)
    {
      const struct TransportFragmentBoxMessage *tfbo;

      tfbo = (const struct TransportFragmentBoxMessage *) orig;
      orig += sizeof (struct TransportFragmentBoxMessage);
      msize -= sizeof (struct TransportFragmentBoxMessage);
      xoff = ntohs (tfbo->frag_off);
    }
    fragmax = mtu - sizeof (struct TransportFragmentBoxMessage);
    fragsize = GNUNET_MIN (msize - ff->frag_off, fragmax);
    frag =
      GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct TransportFragmentBoxMessage) + fragsize);
    frag->logging_uuid = logging_uuid_gen++;
    frag->vl = pm->vl;
    frag->frag_parent = ff;
    frag->timeout = pm->timeout;
    frag->bytes_msg = sizeof (struct TransportFragmentBoxMessage) + fragsize;
    frag->pmt = PMT_FRAGMENT_BOX;
    msg = (char *) &frag[1];
    tfb.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT);
    tfb.header.size =
      htons (sizeof (struct TransportFragmentBoxMessage) + fragsize);
    tfb.ack_uuid = pa->ack_uuid;
    tfb.msg_uuid = pm->msg_uuid;
    tfb.frag_off = htons (ff->frag_off + xoff);
    tfb.msg_size = htons (pm->bytes_msg);
    memcpy (msg, &tfb, sizeof (tfb));
    memcpy (&msg[sizeof (tfb)], &orig[ff->frag_off], fragsize);
    GNUNET_CONTAINER_MDLL_insert (frag, ff->head_frag, ff->tail_frag, frag);
    ff->frag_off += fragsize;
    ff = frag;
  }

  /* Move head to the tail and return it */
  GNUNET_CONTAINER_MDLL_remove (frag,
                                ff->frag_parent->head_frag,
                                ff->frag_parent->tail_frag,
                                ff);
  GNUNET_CONTAINER_MDLL_insert_tail (frag,
                                     ff->frag_parent->head_frag,
                                     ff->frag_parent->tail_frag,
                                     ff);
  return ff;
}


/**
 * Reliability-box the given @a pm. On error (can there be any), NULL
 * may be returned, otherwise the "replacement" for @a pm (which
 * should then be added to the respective neighbour's queue instead of
 * @a pm).  If the @a pm is already fragmented or reliability boxed,
 * or itself an ACK, this function simply returns @a pm.
 *
 * @param queue which queue to prepare transmission for
 * @param dvh path the message will take, or NULL
 * @param pm pending message to box for transmission over unreliabile queue
 * @return new message to transmit
 */
static struct PendingMessage *
reliability_box_message (struct Queue *queue,
                         struct DistanceVectorHop *dvh,
                         struct PendingMessage *pm)
{
  struct TransportReliabilityBoxMessage rbox;
  struct PendingAcknowledgement *pa;
  struct PendingMessage *bpm;
  char *msg;

  if (PMT_CORE != pm->pmt)
    return pm; /* already fragmented or reliability boxed, or control message:
                  do nothing */
  if (NULL != pm->bpm)
    return pm->bpm; /* already computed earlier: do nothing */
  GNUNET_assert (NULL == pm->head_frag);
  if (pm->bytes_msg + sizeof (rbox) > UINT16_MAX)
  {
    /* failed hard */
    GNUNET_break (0);
    client_send_response (pm);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Preparing reliability box for message <%llu> to %s on queue %s\n",
              pm->logging_uuid,
              GNUNET_i2s (&pm->vl->target),
              queue->address);
  pa = prepare_pending_acknowledgement (queue, dvh, pm);

  bpm = GNUNET_malloc (sizeof (struct PendingMessage) + sizeof (rbox) +
                       pm->bytes_msg);
  bpm->logging_uuid = logging_uuid_gen++;
  bpm->vl = pm->vl;
  bpm->frag_parent = pm;
  GNUNET_CONTAINER_MDLL_insert (frag, pm->head_frag, pm->tail_frag, bpm);
  bpm->timeout = pm->timeout;
  bpm->pmt = PMT_RELIABILITY_BOX;
  bpm->bytes_msg = pm->bytes_msg + sizeof (rbox);
  set_pending_message_uuid (bpm);
  rbox.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX);
  rbox.header.size = htons (sizeof (rbox) + pm->bytes_msg);
  rbox.ack_countdown = htonl (0); // FIXME: implement ACK countdown support

  rbox.ack_uuid = pa->ack_uuid;
  msg = (char *) &bpm[1];
  memcpy (msg, &rbox, sizeof (rbox));
  memcpy (&msg[sizeof (rbox)], &pm[1], pm->bytes_msg);
  pm->bpm = bpm;
  return bpm;
}


/**
 * Change the value of the `next_attempt` field of @a pm
 * to @a next_attempt and re-order @a pm in the transmission
 * list as required by the new timestmap.
 *
 * @param pm a pending message to update
 * @param next_attempt timestamp to use
 */
static void
update_pm_next_attempt (struct PendingMessage *pm,
                        struct GNUNET_TIME_Absolute next_attempt)
{
  struct VirtualLink *vl = pm->vl;

  pm->next_attempt = next_attempt;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Next attempt for message <%llu> set to %s\n",
              pm->logging_uuid,
              GNUNET_STRINGS_absolute_time_to_string (next_attempt));

  if (NULL == pm->frag_parent)
  {
    struct PendingMessage *pos;

    /* re-insert sort in neighbour list */
    GNUNET_CONTAINER_MDLL_remove (vl,
                                  vl->pending_msg_head,
                                  vl->pending_msg_tail,
                                  pm);
    pos = vl->pending_msg_tail;
    while ((NULL != pos) &&
           (next_attempt.abs_value_us > pos->next_attempt.abs_value_us))
      pos = pos->prev_vl;
    GNUNET_CONTAINER_MDLL_insert_after (vl,
                                        vl->pending_msg_head,
                                        vl->pending_msg_tail,
                                        pos,
                                        pm);
  }
  else
  {
    /* re-insert sort in fragment list */
    struct PendingMessage *fp = pm->frag_parent;
    struct PendingMessage *pos;

    GNUNET_CONTAINER_MDLL_remove (frag, fp->head_frag, fp->tail_frag, pm);
    pos = fp->tail_frag;
    while ((NULL != pos) &&
           (next_attempt.abs_value_us > pos->next_attempt.abs_value_us))
      pos = pos->prev_frag;
    GNUNET_CONTAINER_MDLL_insert_after (frag,
                                        fp->head_frag,
                                        fp->tail_frag,
                                        pos,
                                        pm);
  }
}


/**
 * Context for #select_best_pending_from_link().
 */
struct PendingMessageScoreContext
{
  /**
   * Set to the best message that was found, NULL for none.
   */
  struct PendingMessage *best;

  /**
   * DVH that @e best should take, or NULL for direct transmission.
   */
  struct DistanceVectorHop *dvh;

  /**
   * What is the estimated total overhead for this message?
   */
  size_t real_overhead;

  /**
   * Number of pending messages we seriously considered this time.
   */
  unsigned int consideration_counter;

  /**
   * Did we have to fragment?
   */
  int frag;

  /**
   * Did we have to reliability box?
   */
  int relb;
};


/**
 * Select the best pending message from @a vl for transmission
 * via @a queue.
 *
 * @param sc[in,out] best message so far (NULL for none), plus scoring data
 * @param queue the queue that will be used for transmission
 * @param vl the virtual link providing the messages
 * @param dvh path we are currently considering, or NULL for none
 * @param overhead number of bytes of overhead to be expected
 *        from DV encapsulation (0 for without DV)
 */
static void
select_best_pending_from_link (struct PendingMessageScoreContext *sc,
                               struct Queue *queue,
                               struct VirtualLink *vl,
                               struct DistanceVectorHop *dvh,
                               size_t overhead)
{
  /* FIXME-NEXT: right now we ignore all the 'fancy' sorting
     we do on the pending message list, resulting in a
     linear time algorithm (PLUS linear time list management).
     So we should probably either avoid keeping a sorted list,
     or find a way to make the sorting useful here! */
  for (struct PendingMessage *pos = vl->pending_msg_head; NULL != pos;
       pos = pos->next_vl)
  {
    size_t real_overhead = overhead;
    int frag;
    int relb;

    if (NULL != pos->qe)
      continue; /* not eligible */
    sc->consideration_counter++;
    /* determine if we have to reliability-box, if so add reliability box
       overhead */
    relb = GNUNET_NO;
    if ((GNUNET_NO == frag) &&
        (0 == (pos->prefs & GNUNET_MQ_PREF_UNRELIABLE)) &&
        (GNUNET_TRANSPORT_CC_RELIABLE != queue->tc->details.communicator.cc))
    {
      relb = GNUNET_YES;
      real_overhead += sizeof (struct TransportReliabilityBoxMessage);
    }
    /* determine if we have to fragment, if so add fragmentation
       overhead! */
    frag = GNUNET_NO;
    if ( ( (0 != queue->mtu) &&
           (pos->bytes_msg + real_overhead > queue->mtu) ) ||
         (pos->bytes_msg > UINT16_MAX - sizeof (struct GNUNET_TRANSPORT_SendMessageTo)) ||
         (NULL != pos->head_frag /* fragments already exist, should
                                    respect that even if MTU is 0 for
                                    this queue */) )
    {
      frag = GNUNET_YES;
      relb = GNUNET_NO; /* if we fragment, we never also reliability box */
      if (GNUNET_TRANSPORT_CC_RELIABLE == queue->tc->details.communicator.cc)
      {
        /* FIXME-OPTIMIZE: we could use an optimized, shorter fragmentation
           header without the ACK UUID when using a *reliable* channel! */
      }
      real_overhead = overhead + sizeof (struct TransportFragmentBoxMessage);
    }

    /* Finally, compare to existing 'best' in sc to see if this 'pos' pending
       message would beat it! */
    if (NULL != sc->best)
    {
      /* FIXME-NEXT: CHECK if pos fits queue BETTER than pm, if not:
         continue; */
      /* NOTE: use 'overhead' to estimate need for fragmentation,
         prefer it if MTU is sufficient and close! */
    }
    sc->best = pos;
    sc->dvh = dvh;
    sc->frag = frag;
    sc->relb = relb;
  }
}


/**
 * We believe we are ready to transmit a `struct PendingMessage` on a
 * queue, the big question is which one!  We need to see if there is
 * one pending that is allowed by flow control and congestion control
 * and (ideally) matches our queue's performance profile.
 *
 * If such a message is found, we give the message to the communicator
 * for transmission (updating the tracker, and re-scheduling ourselves
 * if applicable).
 *
 * If no such message is found, the queue's `idle` field must be set
 * to #GNUNET_YES.
 *
 * @param cls the `struct Queue` to process transmissions for
 */
static void
transmit_on_queue (void *cls)
{
  struct Queue *queue = cls;
  struct Neighbour *n = queue->neighbour;
  struct PendingMessageScoreContext sc;
  struct PendingMessage *pm;

  queue->transmit_task = NULL;
  if (NULL == n->vl)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Virtual link `%s' is down, cannot have PM for queue `%s'\n",
                GNUNET_i2s (&n->pid),
                queue->address);
    queue->idle = GNUNET_YES;
    return;
  }
  memset (&sc, 0, sizeof (sc));
  select_best_pending_from_link (&sc, queue, n->vl, NULL, 0);
  if (NULL == sc.best)
  {
    /* Also look at DVH that have the n as first hop! */
    for (struct DistanceVectorHop *dvh = n->dv_head; NULL != dvh;
         dvh = dvh->next_neighbour)
    {
      select_best_pending_from_link (&sc,
                                     queue,
                                     dvh->dv->vl,
                                     dvh,
                                     sizeof (struct GNUNET_PeerIdentity) *
                                         (1 + dvh->distance) +
                                       sizeof (struct TransportDVBoxMessage) +
                                       sizeof (struct TransportDVBoxPayloadP));
    }
  }
  if (NULL == sc.best)
  {
    /* no message pending, nothing to do here! */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No pending messages, queue `%s' to %s now idle\n",
                queue->address,
                GNUNET_i2s (&n->pid));
    queue->idle = GNUNET_YES;
    return;
  }

  /* Given selection in `sc`, do transmission */
  pm = sc.best;
  if (GNUNET_YES == sc.frag)
  {
    pm = fragment_message (queue, sc.dvh, sc.best);
    if (NULL == pm)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Fragmentation failed queue %s to %s for <%llu>, trying again\n",
                  queue->address,
                  GNUNET_i2s (&n->pid),
                  pm->logging_uuid);
      schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
    }
  }
  else if (GNUNET_YES == sc.relb)
  {
    pm = reliability_box_message (queue, sc.dvh, sc.best);
    if (NULL == pm)
    {
      /* Reliability boxing failed, try next message... */
      GNUNET_log (
        GNUNET_ERROR_TYPE_DEBUG,
        "Reliability boxing failed queue %s to %s for <%llu>, trying again\n",
        queue->address,
        GNUNET_i2s (&n->pid),
        pm->logging_uuid);
      schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
      return;
    }
  }
  else
    pm = sc.best; /* no boxing required */

  /* Pass 'pm' for transission to the communicator */
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Passing message <%llu> to queue %s for peer %s (considered %u others)\n",
    pm->logging_uuid,
    queue->address,
    GNUNET_i2s (&n->pid),
    sc.consideration_counter);
  queue_send_msg (queue, pm, &pm[1], pm->bytes_msg);

  /* Check if this transmission somehow conclusively finished handing 'pm'
     even without any explicit ACKs */
  if ((PMT_CORE == pm->pmt) ||
      (GNUNET_TRANSPORT_CC_RELIABLE == queue->tc->details.communicator.cc))
  {
    completed_pending_message (pm);
  }
  else
  {
    /* Message not finished, waiting for acknowledgement.
       Update time by which we might retransmit 's' based on queue
       characteristics (i.e. RTT); it takes one RTT for the message to
       arrive and the ACK to come back in the best case; but the other
       side is allowed to delay ACKs by 2 RTTs, so we use 4 RTT before
       retransmitting.  Note that in the future this heuristic should
       likely be improved further (measure RTT stability, consider
       message urgency and size when delaying ACKs, etc.) */
    update_pm_next_attempt (pm,
                            GNUNET_TIME_relative_to_absolute (
                              GNUNET_TIME_relative_multiply (queue->pd.aged_rtt,
                                                             4)));
  }
  /* finally, re-schedule queue transmission task itself */
  schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
}


/**
 * Queue to a peer went down.  Process the request.
 *
 * @param cls the client
 * @param dqm the send message that was sent
 */
static void
handle_del_queue_message (void *cls,
                          const struct GNUNET_TRANSPORT_DelQueueMessage *dqm)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  for (struct Queue *queue = tc->details.communicator.queue_head; NULL != queue;
       queue = queue->next_client)
  {
    struct Neighbour *neighbour = queue->neighbour;

    if ((dqm->qid != queue->qid) ||
        (0 != GNUNET_memcmp (&dqm->receiver, &neighbour->pid)))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropped queue %s to peer %s\n",
                queue->address,
                GNUNET_i2s (&neighbour->pid));
    free_queue (queue);
    GNUNET_SERVICE_client_continue (tc->client);
    return;
  }
  GNUNET_break (0);
  GNUNET_SERVICE_client_drop (tc->client);
}


/**
 * Message was transmitted.  Process the request.
 *
 * @param cls the client
 * @param sma the send message that was sent
 */
static void
handle_send_message_ack (void *cls,
                         const struct GNUNET_TRANSPORT_SendMessageToAck *sma)
{
  struct TransportClient *tc = cls;
  struct QueueEntry *qe;
  struct PendingMessage *pm;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }

  /* find our queue entry matching the ACK */
  qe = NULL;
  for (struct Queue *queue = tc->details.communicator.queue_head; NULL != queue;
       queue = queue->next_client)
  {
    if (0 != GNUNET_memcmp (&queue->neighbour->pid, &sma->receiver))
      continue;
    for (struct QueueEntry *qep = queue->queue_head; NULL != qep;
         qep = qep->next)
    {
      if (qep->mid != sma->mid)
        continue;
      qe = qep;
      break;
    }
    break;
  }
  if (NULL == qe)
  {
    /* this should never happen */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (qe->queue->queue_head,
                               qe->queue->queue_tail,
                               qe);
  qe->queue->queue_length--;
  tc->details.communicator.total_queue_length--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ACK on queue %s to peer %s (new length: %u/%u)\n",
              qe->queue->address,
              GNUNET_i2s (&qe->queue->neighbour->pid),
              qe->queue->queue_length,
              tc->details.communicator.total_queue_length);
  GNUNET_SERVICE_client_continue (tc->client);

  /* if applicable, resume transmissions that waited on ACK */
  if (COMMUNICATOR_TOTAL_QUEUE_LIMIT - 1 ==
      tc->details.communicator.total_queue_length)
  {
    /* Communicator dropped below threshold, resume all queues
       incident with this client! */
    GNUNET_STATISTICS_update (
      GST_stats,
      "# Transmission throttled due to communicator queue limit",
      -1,
      GNUNET_NO);
    for (struct Queue *queue = tc->details.communicator.queue_head;
         NULL != queue;
         queue = queue->next_client)
      schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  }
  else if (QUEUE_LENGTH_LIMIT - 1 == qe->queue->queue_length)
  {
    /* queue dropped below threshold; only resume this one queue */
    GNUNET_STATISTICS_update (GST_stats,
                              "# Transmission throttled due to queue queue limit",
                              -1,
                              GNUNET_NO);
    schedule_transmit_on_queue (qe->queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  }

  if (NULL != (pm = qe->pm))
  {
    struct VirtualLink *vl;

    GNUNET_assert (qe == pm->qe);
    pm->qe = NULL;
    /* If waiting for this communicator may have blocked transmission
       of pm on other queues for this neighbour, force schedule
       transmit on queue for queues of the neighbour */
    vl = pm->vl;
    if (vl->pending_msg_head == pm)
      check_vl_transmission (vl);
  }
  GNUNET_free (qe);
}


/**
 * Iterator telling new MONITOR client about all existing
 * queues to peers.
 *
 * @param cls the new `struct TransportClient`
 * @param pid a connected peer
 * @param value the `struct Neighbour` with more information
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_client_queues (void *cls,
                      const struct GNUNET_PeerIdentity *pid,
                      void *value)
{
  struct TransportClient *tc = cls;
  struct Neighbour *neighbour = value;

  GNUNET_assert (CT_MONITOR == tc->type);
  for (struct Queue *q = neighbour->queue_head; NULL != q;
       q = q->next_neighbour)
  {
    struct MonitorEvent me = {.rtt = q->pd.aged_rtt,
                              .cs = q->cs,
                              .num_msg_pending = q->num_msg_pending,
                              .num_bytes_pending = q->num_bytes_pending};

    notify_monitor (tc, pid, q->address, q->nt, &me);
  }
  return GNUNET_OK;
}


/**
 * Initialize a monitor client.
 *
 * @param cls the client
 * @param start the start message that was sent
 */
static void
handle_monitor_start (void *cls,
                      const struct GNUNET_TRANSPORT_MonitorStart *start)
{
  struct TransportClient *tc = cls;

  if (CT_NONE != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  tc->type = CT_MONITOR;
  tc->details.monitor.peer = start->peer;
  tc->details.monitor.one_shot = ntohl (start->one_shot);
  GNUNET_CONTAINER_multipeermap_iterate (neighbours, &notify_client_queues, tc);
  GNUNET_SERVICE_client_mark_monitor (tc->client);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Find transport client providing communication service
 * for the protocol @a prefix.
 *
 * @param prefix communicator name
 * @return NULL if no such transport client is available
 */
static struct TransportClient *
lookup_communicator (const char *prefix)
{
  for (struct TransportClient *tc = clients_head; NULL != tc; tc = tc->next)
  {
    if (CT_COMMUNICATOR != tc->type)
      continue;
    if (0 == strcmp (prefix, tc->details.communicator.address_prefix))
      return tc;
  }
  GNUNET_log (
    GNUNET_ERROR_TYPE_WARNING,
    "Somone suggested use of communicator for `%s', but we do not have such a communicator!\n",
    prefix);
  return NULL;
}


/**
 * Signature of a function called with a communicator @a address of a peer
 * @a pid that an application wants us to connect to.
 *
 * @param pid target peer
 * @param address the address to try
 */
static void
suggest_to_connect (const struct GNUNET_PeerIdentity *pid, const char *address)
{
  static uint32_t idgen;
  struct TransportClient *tc;
  char *prefix;
  struct GNUNET_TRANSPORT_CreateQueue *cqm;
  struct GNUNET_MQ_Envelope *env;
  size_t alen;

  prefix = GNUNET_HELLO_address_to_prefix (address);
  if (NULL == prefix)
  {
    GNUNET_break (0); /* We got an invalid address!? */
    return;
  }
  tc = lookup_communicator (prefix);
  if (NULL == tc)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              "# Suggestions ignored due to missing communicator",
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Cannot connect to %s at `%s', no matching communicator present\n",
                GNUNET_i2s (pid),
                address);
    return;
  }
  /* forward suggestion for queue creation to communicator */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Request #%u for `%s' communicator to create queue to `%s'\n",
              (unsigned int) idgen,
              prefix,
              address);
  alen = strlen (address) + 1;
  env =
    GNUNET_MQ_msg_extra (cqm, alen, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE);
  cqm->request_id = htonl (idgen++);
  cqm->receiver = *pid;
  memcpy (&cqm[1], address, alen);
  GNUNET_MQ_send (tc->mq, env);
}


/**
 * The queue @a q (which matches the peer and address in @a vs) is
 * ready for queueing. We should now queue the validation request.
 *
 * @param q queue to send on
 * @param vs state to derive validation challenge from
 */
static void
validation_transmit_on_queue (struct Queue *q, struct ValidationState *vs)
{
  struct TransportValidationChallengeMessage tvc;

  vs->last_challenge_use = GNUNET_TIME_absolute_get ();
  tvc.header.type =
    htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_CHALLENGE);
  tvc.header.size = htons (sizeof (tvc));
  tvc.reserved = htonl (0);
  tvc.challenge = vs->challenge;
  tvc.sender_time = GNUNET_TIME_absolute_hton (vs->last_challenge_use);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending address validation challenge %s to %s\n",
              GNUNET_sh2s (&tvc.challenge.value),
              GNUNET_i2s (&q->neighbour->pid));
  queue_send_msg (q, NULL, &tvc, sizeof (tvc));
}


/**
 * Task run periodically to validate some address based on #validation_heap.
 *
 * @param cls NULL
 */
static void
validation_start_cb (void *cls)
{
  struct ValidationState *vs;
  struct Queue *q;

  (void) cls;
  validation_task = NULL;
  vs = GNUNET_CONTAINER_heap_peek (validation_heap);
  /* drop validations past their expiration */
  while (
    (NULL != vs) &&
    (0 == GNUNET_TIME_absolute_get_remaining (vs->valid_until).rel_value_us))
  {
    free_validation_state (vs);
    vs = GNUNET_CONTAINER_heap_peek (validation_heap);
  }
  if (NULL == vs)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Address validation task not scheduled anymore, nothing to do\n");
    return; /* woopsie, no more addresses known, should only
               happen if we're really a lonely peer */
  }
  q = find_queue (&vs->pid, vs->address);
  if (NULL == q)
  {
    vs->awaiting_queue = GNUNET_YES;
    suggest_to_connect (&vs->pid, vs->address);
  }
  else
    validation_transmit_on_queue (q, vs);
  /* Finally, reschedule next attempt */
  vs->challenge_backoff =
    GNUNET_TIME_randomized_backoff (vs->challenge_backoff,
                                    MAX_VALIDATION_CHALLENGE_FREQ);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address validation task will run again in %s\n",
              GNUNET_STRINGS_relative_time_to_string (vs->challenge_backoff,
                                                      GNUNET_YES));
  update_next_challenge_time (vs,
                              GNUNET_TIME_relative_to_absolute (
                                vs->challenge_backoff));
}


/**
 * Closure for #check_connection_quality.
 */
struct QueueQualityContext
{
  /**
   * Set to the @e k'th queue encountered.
   */
  struct Queue *q;

  /**
   * Set to the number of quality queues encountered.
   */
  unsigned int quality_count;

  /**
   * Set to the total number of queues encountered.
   */
  unsigned int num_queues;

  /**
   * Decremented for each queue, for selection of the
   * k-th queue in @e q.
   */
  unsigned int k;
};


/**
 * Check whether any queue to the given neighbour is
 * of a good "quality" and if so, increment the counter.
 * Also counts the total number of queues, and returns
 * the k-th queue found.
 *
 * @param cls a `struct QueueQualityContext *` with counters
 * @param pid peer this is about
 * @param value a `struct Neighbour`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
check_connection_quality (void *cls,
                          const struct GNUNET_PeerIdentity *pid,
                          void *value)
{
  struct QueueQualityContext *ctx = cls;
  struct Neighbour *n = value;
  int do_inc;

  (void) pid;
  do_inc = GNUNET_NO;
  for (struct Queue *q = n->queue_head; NULL != q; q = q->next_neighbour)
  {
    ctx->num_queues++;
    if (0 == ctx->k--)
      ctx->q = q;
    /* OPTIMIZE-FIXME: in the future, add reliability / goodput
       statistics and consider those as well here? */
    if (q->pd.aged_rtt.rel_value_us < DV_QUALITY_RTT_THRESHOLD.rel_value_us)
      do_inc = GNUNET_YES;
  }
  if (GNUNET_YES == do_inc)
    ctx->quality_count++;
  return GNUNET_OK;
}


/**
 * Task run when we CONSIDER initiating a DV learn
 * process. We first check that sending out a message is
 * even possible (queues exist), then that it is desirable
 * (if not, reschedule the task for later), and finally
 * we may then begin the job.  If there are too many
 * entries in the #dvlearn_map, we purge the oldest entry
 * using #lle_tail.
 *
 * @param cls NULL
 */
static void
start_dv_learn (void *cls)
{
  struct LearnLaunchEntry *lle;
  struct QueueQualityContext qqc;
  struct TransportDVLearnMessage dvl;

  (void) cls;
  dvlearn_task = NULL;
  if (0 == GNUNET_CONTAINER_multipeermap_size (neighbours))
    return; /* lost all connectivity, cannot do learning */
  qqc.quality_count = 0;
  qqc.num_queues = 0;
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &check_connection_quality,
                                         &qqc);
  if (qqc.quality_count > DV_LEARN_QUALITY_THRESHOLD)
  {
    struct GNUNET_TIME_Relative delay;
    unsigned int factor;

    /* scale our retries by how far we are above the threshold */
    factor = qqc.quality_count / DV_LEARN_QUALITY_THRESHOLD;
    delay = GNUNET_TIME_relative_multiply (DV_LEARN_BASE_FREQUENCY, factor);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "At connection quality %u, will launch DV learn in %s\n",
                qqc.quality_count,
                GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
    dvlearn_task = GNUNET_SCHEDULER_add_delayed (delay, &start_dv_learn, NULL);
    return;
  }
  /* remove old entries in #dvlearn_map if it has grown too big */
  while (MAX_DV_LEARN_PENDING >=
         GNUNET_CONTAINER_multishortmap_size (dvlearn_map))
  {
    lle = lle_tail;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multishortmap_remove (dvlearn_map,
                                                          &lle->challenge.value,
                                                          lle));
    GNUNET_CONTAINER_DLL_remove (lle_head, lle_tail, lle);
    GNUNET_free (lle);
  }
  /* setup data structure for learning */
  lle = GNUNET_new (struct LearnLaunchEntry);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &lle->challenge,
                              sizeof (lle->challenge));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting launch DV learn with challenge %s\n",
              GNUNET_sh2s (&lle->challenge.value));
  GNUNET_CONTAINER_DLL_insert (lle_head, lle_tail, lle);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multishortmap_put (
                  dvlearn_map,
                  &lle->challenge.value,
                  lle,
                  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  dvl.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN);
  dvl.header.size = htons (sizeof (dvl));
  dvl.num_hops = htons (0);
  dvl.bidirectional = htons (0);
  dvl.non_network_delay = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_ZERO);
  dvl.monotonic_time =
    GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_monotonic (GST_cfg));
  {
    struct DvInitPS dvip = {.purpose.purpose = htonl (
                              GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR),
                            .purpose.size = htonl (sizeof (dvip)),
                            .monotonic_time = dvl.monotonic_time,
                            .challenge = lle->challenge};

    GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
                                                          &dvip.purpose,
                                                          &dvl.init_sig));
  }
  dvl.initiator = GST_my_identity;
  dvl.challenge = lle->challenge;

  qqc.quality_count = 0;
  qqc.k = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, qqc.num_queues);
  qqc.num_queues = 0;
  qqc.q = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &check_connection_quality,
                                         &qqc);
  GNUNET_assert (NULL != qqc.q);

  /* Do this as close to transmission time as possible! */
  lle->launch_time = GNUNET_TIME_absolute_get ();

  queue_send_msg (qqc.q, NULL, &dvl, sizeof (dvl));
  /* reschedule this job, randomizing the time it runs (but no
     actual backoff!) */
  dvlearn_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_randomize (
                                                 DV_LEARN_BASE_FREQUENCY),
                                               &start_dv_learn,
                                               NULL);
}


/**
 * A new queue has been created, check if any address validation
 * requests have been waiting for it.
 *
 * @param cls a `struct Queue`
 * @param pid peer concerned (unused)
 * @param value a `struct ValidationState`
 * @return #GNUNET_NO if a match was found and we can stop looking
 */
static int
check_validation_request_pending (void *cls,
                                  const struct GNUNET_PeerIdentity *pid,
                                  void *value)
{
  struct Queue *q = cls;
  struct ValidationState *vs = value;

  (void) pid;
  if ((GNUNET_YES == vs->awaiting_queue) &&
      (0 == strcmp (vs->address, q->address)))
  {
    vs->awaiting_queue = GNUNET_NO;
    validation_transmit_on_queue (q, vs);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Function called with the monotonic time of a DV initiator
 * by PEERSTORE. Updates the time.
 *
 * @param cls a `struct Neighbour`
 * @param record the information found, NULL for the last call
 * @param emsg error message
 */
static void
neighbour_dv_monotime_cb (void *cls,
                          const struct GNUNET_PEERSTORE_Record *record,
                          const char *emsg)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_AbsoluteNBO *mtbe;

  (void) emsg;
  if (NULL == record)
  {
    /* we're done with #neighbour_dv_monotime_cb() invocations,
       continue normal processing */
    n->get = NULL;
    n->dv_monotime_available = GNUNET_YES;
    return;
  }
  if (sizeof (*mtbe) != record->value_size)
  {
    GNUNET_break (0);
    return;
  }
  mtbe = record->value;
  n->last_dv_learn_monotime =
    GNUNET_TIME_absolute_max (n->last_dv_learn_monotime,
                              GNUNET_TIME_absolute_ntoh (*mtbe));
}


/**
 * New queue became available.  Process the request.
 *
 * @param cls the client
 * @param aqm the send message that was sent
 */
static void
handle_add_queue_message (void *cls,
                          const struct GNUNET_TRANSPORT_AddQueueMessage *aqm)
{
  struct TransportClient *tc = cls;
  struct Queue *queue;
  struct Neighbour *neighbour;
  const char *addr;
  uint16_t addr_len;

  if (ntohl (aqm->mtu) <= sizeof (struct TransportFragmentBoxMessage))
  {
    /* MTU so small as to be useless for transmissions,
       required for #fragment_message()! */
    GNUNET_break_op (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  neighbour = lookup_neighbour (&aqm->receiver);
  if (NULL == neighbour)
  {
    neighbour = GNUNET_new (struct Neighbour);
    neighbour->pid = aqm->receiver;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (
                     neighbours,
                     &neighbour->pid,
                     neighbour,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    neighbour->get =
      GNUNET_PEERSTORE_iterate (peerstore,
                                "transport",
                                &neighbour->pid,
                                GNUNET_PEERSTORE_TRANSPORT_DVLEARN_MONOTIME,
                                &neighbour_dv_monotime_cb,
                                neighbour);
  }
  addr_len = ntohs (aqm->header.size) - sizeof (*aqm);
  addr = (const char *) &aqm[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New queue %s to %s available with QID %llu\n",
              addr,
              GNUNET_i2s (&aqm->receiver),
              (unsigned long long) aqm->qid);
  queue = GNUNET_malloc (sizeof (struct Queue) + addr_len);
  queue->tc = tc;
  queue->address = (const char *) &queue[1];
  queue->pd.aged_rtt = GNUNET_TIME_UNIT_FOREVER_REL;
  queue->qid = aqm->qid;
  queue->mtu = ntohl (aqm->mtu);
  queue->nt = (enum GNUNET_NetworkType) ntohl (aqm->nt);
  queue->cs = (enum GNUNET_TRANSPORT_ConnectionStatus) ntohl (aqm->cs);
  queue->neighbour = neighbour;
  queue->idle = GNUNET_YES;
  memcpy (&queue[1], addr, addr_len);
  /* notify monitors about new queue */
  {
    struct MonitorEvent me = {.rtt = queue->pd.aged_rtt, .cs = queue->cs};

    notify_monitors (&neighbour->pid, queue->address, queue->nt, &me);
  }
  GNUNET_CONTAINER_MDLL_insert (neighbour,
                                neighbour->queue_head,
                                neighbour->queue_tail,
                                queue);
  GNUNET_CONTAINER_MDLL_insert (client,
                                tc->details.communicator.queue_head,
                                tc->details.communicator.queue_tail,
                                queue);
  /* check if valdiations are waiting for the queue */
  (void)
    GNUNET_CONTAINER_multipeermap_get_multiple (validation_map,
                                                &aqm->receiver,
                                                &check_validation_request_pending,
                                                queue);
  /* look for traffic for this queue */
  schedule_transmit_on_queue (queue, GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  /* might be our first queue, try launching DV learning */
  if (NULL == dvlearn_task)
    dvlearn_task = GNUNET_SCHEDULER_add_now (&start_dv_learn, NULL);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Communicator tells us that our request to create a queue "worked", that
 * is setting up the queue is now in process.
 *
 * @param cls the `struct TransportClient`
 * @param cqr confirmation message
 */
static void
handle_queue_create_ok (void *cls,
                        const struct GNUNET_TRANSPORT_CreateQueueResponse *cqr)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            "# Suggestions succeeded at communicator",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Request #%u for communicator to create queue succeeded\n",
              (unsigned int) ntohs (cqr->request_id));
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Communicator tells us that our request to create a queue failed. This
 * usually indicates that the provided address is simply invalid or that the
 * communicator's resources are exhausted.
 *
 * @param cls the `struct TransportClient`
 * @param cqr failure message
 */
static void
handle_queue_create_fail (
  void *cls,
  const struct GNUNET_TRANSPORT_CreateQueueResponse *cqr)
{
  struct TransportClient *tc = cls;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Request #%u for communicator to create queue failed\n",
              (unsigned int) ntohs (cqr->request_id));
  GNUNET_STATISTICS_update (GST_stats,
                            "# Suggestions failed in queue creation at communicator",
                            1,
                            GNUNET_NO);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * We have received a `struct ExpressPreferenceMessage` from an application
 * client.
 *
 * @param cls handle to the client
 * @param msg the start message
 */
static void
handle_suggest_cancel (void *cls, const struct ExpressPreferenceMessage *msg)
{
  struct TransportClient *tc = cls;
  struct PeerRequest *pr;

  if (CT_APPLICATION != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  pr = GNUNET_CONTAINER_multipeermap_get (tc->details.application.requests,
                                          &msg->peer);
  if (NULL == pr)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  (void) stop_peer_request (tc, &pr->pid, pr);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Closure for #check_known_address.
 */
struct CheckKnownAddressContext
{
  /**
   * Set to the address we are looking for.
   */
  const char *address;

  /**
   * Set to a matching validation state, if one was found.
   */
  struct ValidationState *vs;
};


/**
 * Test if the validation state in @a value matches the
 * address from @a cls.
 *
 * @param cls a `struct CheckKnownAddressContext`
 * @param pid unused (must match though)
 * @param value a `struct ValidationState`
 * @return #GNUNET_OK if not matching, #GNUNET_NO if match found
 */
static int
check_known_address (void *cls,
                     const struct GNUNET_PeerIdentity *pid,
                     void *value)
{
  struct CheckKnownAddressContext *ckac = cls;
  struct ValidationState *vs = value;

  (void) pid;
  if (0 != strcmp (vs->address, ckac->address))
    return GNUNET_OK;
  ckac->vs = vs;
  return GNUNET_NO;
}


/**
 * Start address validation.
 *
 * @param pid peer the @a address is for
 * @param address an address to reach @a pid (presumably)
 */
static void
start_address_validation (const struct GNUNET_PeerIdentity *pid,
                          const char *address)
{
  struct GNUNET_TIME_Absolute now;
  struct ValidationState *vs;
  struct CheckKnownAddressContext ckac = {.address = address, .vs = NULL};

  (void) GNUNET_CONTAINER_multipeermap_get_multiple (validation_map,
                                                     pid,
                                                     &check_known_address,
                                                     &ckac);
  if (NULL != (vs = ckac.vs))
  {
    /* if 'vs' is not currently valid, we need to speed up retrying the
     * validation */
    if (vs->validated_until.abs_value_us < vs->next_challenge.abs_value_us)
    {
      /* reduce backoff as we got a fresh advertisement */
      vs->challenge_backoff =
        GNUNET_TIME_relative_min (FAST_VALIDATION_CHALLENGE_FREQ,
                                  GNUNET_TIME_relative_divide (vs->challenge_backoff,
                                                               2));
      update_next_challenge_time (vs,
                                  GNUNET_TIME_relative_to_absolute (
                                    vs->challenge_backoff));
    }
    return;
  }
  now = GNUNET_TIME_absolute_get ();
  vs = GNUNET_new (struct ValidationState);
  vs->pid = *pid;
  vs->valid_until =
    GNUNET_TIME_relative_to_absolute (ADDRESS_VALIDATION_LIFETIME);
  vs->first_challenge_use = now;
  vs->validation_rtt = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &vs->challenge,
                              sizeof (vs->challenge));
  vs->address = GNUNET_strdup (address);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting address validation `%s' of peer %s using challenge %s\n",
              address,
              GNUNET_i2s (pid),
              GNUNET_sh2s (&vs->challenge.value));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (
                   validation_map,
                   &vs->pid,
                   vs,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  update_next_challenge_time (vs, now);
}


/**
 * Function called by PEERSTORE for each matching record.
 *
 * @param cls closure
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 */
static void
handle_hello (void *cls,
              const struct GNUNET_PEERSTORE_Record *record,
              const char *emsg)
{
  struct PeerRequest *pr = cls;
  const char *val;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Got failure from PEERSTORE: %s\n",
                emsg);
    return;
  }
  val = record->value;
  if ((0 == record->value_size) || ('\0' != val[record->value_size - 1]))
  {
    GNUNET_break (0);
    return;
  }
  start_address_validation (&pr->pid, (const char *) record->value);
}


/**
 * We have received a `struct ExpressPreferenceMessage` from an application
 * client.
 *
 * @param cls handle to the client
 * @param msg the start message
 */
static void
handle_suggest (void *cls, const struct ExpressPreferenceMessage *msg)
{
  struct TransportClient *tc = cls;
  struct PeerRequest *pr;

  if (CT_NONE == tc->type)
  {
    tc->type = CT_APPLICATION;
    tc->details.application.requests =
      GNUNET_CONTAINER_multipeermap_create (16, GNUNET_YES);
  }
  if (CT_APPLICATION != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client suggested we talk to %s with preference %d at rate %u\n",
              GNUNET_i2s (&msg->peer),
              (int) ntohl (msg->pk),
              (int) ntohl (msg->bw.value__));
  pr = GNUNET_new (struct PeerRequest);
  pr->tc = tc;
  pr->pid = msg->peer;
  pr->bw = msg->bw;
  pr->pk = (enum GNUNET_MQ_PriorityPreferences) ntohl (msg->pk);
  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_put (
                      tc->details.application.requests,
                      &pr->pid,
                      pr,
                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_free (pr);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  pr->wc = GNUNET_PEERSTORE_watch (peerstore,
                                   "transport",
                                   &pr->pid,
                                   GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY,
                                   &handle_hello,
                                   pr);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Check #GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_HELLO_VALIDATION
 * messages.
 *
 * @param cls a `struct TransportClient *`
 * @param m message to verify
 * @return #GNUNET_OK on success
 */
static int
check_request_hello_validation (void *cls,
                                const struct RequestHelloValidationMessage *m)
{
  (void) cls;
  GNUNET_MQ_check_zero_termination (m);
  return GNUNET_OK;
}


/**
 * A client encountered an address of another peer. Consider validating it,
 * and if validation succeeds, persist it to PEERSTORE.
 *
 * @param cls a `struct TransportClient *`
 * @param m message to verify
 */
static void
handle_request_hello_validation (void *cls,
                                 const struct RequestHelloValidationMessage *m)
{
  struct TransportClient *tc = cls;

  start_address_validation (&m->peer, (const char *) &m[1]);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Free neighbour entry.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct Neighbour`
 * @return #GNUNET_OK (always)
 */
static int
free_neighbour_cb (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct Neighbour *neighbour = value;

  (void) cls;
  (void) pid;
  GNUNET_break (0); // should this ever happen?
  free_neighbour (neighbour);

  return GNUNET_OK;
}


/**
 * Free DV route entry.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct DistanceVector`
 * @return #GNUNET_OK (always)
 */
static int
free_dv_routes_cb (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct DistanceVector *dv = value;

  (void) cls;
  (void) pid;
  free_dv_route (dv);

  return GNUNET_OK;
}


/**
 * Free validation state.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct ValidationState`
 * @return #GNUNET_OK (always)
 */
static int
free_validation_state_cb (void *cls,
                          const struct GNUNET_PeerIdentity *pid,
                          void *value)
{
  struct ValidationState *vs = value;

  (void) cls;
  (void) pid;
  free_validation_state (vs);
  return GNUNET_OK;
}


/**
 * Free pending acknowledgement.
 *
 * @param cls NULL
 * @param key unused
 * @param value a `struct PendingAcknowledgement`
 * @return #GNUNET_OK (always)
 */
static int
free_pending_ack_cb (void *cls,
                     const struct GNUNET_ShortHashCode *key,
                     void *value)
{
  struct PendingAcknowledgement *pa = value;

  (void) cls;
  (void) key;
  free_pending_acknowledgement (pa);
  return GNUNET_OK;
}


/**
 * Free acknowledgement cummulator.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct AcknowledgementCummulator`
 * @return #GNUNET_OK (always)
 */
static int
free_ack_cummulator_cb (void *cls,
                        const struct GNUNET_PeerIdentity *pid,
                        void *value)
{
  struct AcknowledgementCummulator *ac = value;

  (void) cls;
  (void) pid;
  GNUNET_free (ac);
  return GNUNET_OK;
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 */
static void
do_shutdown (void *cls)
{
  struct LearnLaunchEntry *lle;
  (void) cls;

  GNUNET_CONTAINER_multipeermap_iterate (neighbours, &free_neighbour_cb, NULL);
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_NO);
    peerstore = NULL;
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
  GNUNET_CONTAINER_multipeermap_iterate (ack_cummulators,
                                         &free_ack_cummulator_cb,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (ack_cummulators);
  ack_cummulators = NULL;
  GNUNET_CONTAINER_multishortmap_iterate (pending_acks,
                                          &free_pending_ack_cb,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_destroy (pending_acks);
  pending_acks = NULL;
  GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_size (neighbours));
  GNUNET_CONTAINER_multipeermap_destroy (neighbours);
  neighbours = NULL;
  GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_size (links));
  GNUNET_CONTAINER_multipeermap_destroy (links);
  links = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (backtalkers,
                                         &free_backtalker_cb,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (backtalkers);
  backtalkers = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (validation_map,
                                         &free_validation_state_cb,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (validation_map);
  validation_map = NULL;
  while (NULL != (lle = lle_head))
  {
    GNUNET_CONTAINER_DLL_remove (lle_head, lle_tail, lle);
    GNUNET_free (lle);
  }
  GNUNET_CONTAINER_multishortmap_destroy (dvlearn_map);
  dvlearn_map = NULL;
  GNUNET_CONTAINER_heap_destroy (validation_heap);
  validation_heap = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (dv_routes, &free_dv_routes_cb, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (dv_routes);
  dv_routes = NULL;
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
  (void) cls;
  (void) service;
  /* setup globals */
  hello_mono_time = GNUNET_TIME_absolute_get_monotonic (c);
  GST_cfg = c;
  backtalkers = GNUNET_CONTAINER_multipeermap_create (16, GNUNET_YES);
  pending_acks = GNUNET_CONTAINER_multishortmap_create (32768, GNUNET_YES);
  ack_cummulators = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_YES);
  neighbours = GNUNET_CONTAINER_multipeermap_create (1024, GNUNET_YES);
  links = GNUNET_CONTAINER_multipeermap_create (512, GNUNET_YES);
  dv_routes = GNUNET_CONTAINER_multipeermap_create (1024, GNUNET_YES);
  dvlearn_map = GNUNET_CONTAINER_multishortmap_create (2 * MAX_DV_LEARN_PENDING,
                                                       GNUNET_YES);
  validation_map = GNUNET_CONTAINER_multipeermap_create (1024, GNUNET_YES);
  validation_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GST_my_private_key =
    GNUNET_CRYPTO_eddsa_key_create_from_configuration (GST_cfg);
  if (NULL == GST_my_private_key)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ (
        "Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (GST_my_private_key,
                                      &GST_my_identity.public_key);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "My identity is `%s'\n",
              GNUNET_i2s_full (&GST_my_identity));
  GST_stats = GNUNET_STATISTICS_create ("transport", GST_cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  peerstore = GNUNET_PEERSTORE_connect (GST_cfg);
  if (NULL == peerstore)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "transport",
  GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  /* communication with applications */
  GNUNET_MQ_hd_fixed_size (suggest,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST,
                           struct ExpressPreferenceMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (suggest_cancel,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST_CANCEL,
                           struct ExpressPreferenceMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (request_hello_validation,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_HELLO_VALIDATION,
                         struct RequestHelloValidationMessage,
                         NULL),
  /* communication with core */
  GNUNET_MQ_hd_fixed_size (client_start,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_START,
                           struct StartMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_send,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_SEND,
                         struct OutboundMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_recv_ok,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK,
                           struct RecvOkMessage,
                           NULL),
  /* communication with communicators */
  GNUNET_MQ_hd_var_size (communicator_available,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR,
                         struct GNUNET_TRANSPORT_CommunicatorAvailableMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (communicator_backchannel,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL,
                         struct GNUNET_TRANSPORT_CommunicatorBackchannel,
                         NULL),
  GNUNET_MQ_hd_var_size (add_address,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS,
                         struct GNUNET_TRANSPORT_AddAddressMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (del_address,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS,
                           struct GNUNET_TRANSPORT_DelAddressMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (incoming_msg,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG,
                         struct GNUNET_TRANSPORT_IncomingMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (queue_create_ok,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK,
                           struct GNUNET_TRANSPORT_CreateQueueResponse,
                           NULL),
  GNUNET_MQ_hd_fixed_size (queue_create_fail,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL,
                           struct GNUNET_TRANSPORT_CreateQueueResponse,
                           NULL),
  GNUNET_MQ_hd_var_size (add_queue_message,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP,
                         struct GNUNET_TRANSPORT_AddQueueMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (del_queue_message,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN,
                           struct GNUNET_TRANSPORT_DelQueueMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (send_message_ack,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK,
                           struct GNUNET_TRANSPORT_SendMessageToAck,
                           NULL),
  /* communication with monitors */
  GNUNET_MQ_hd_fixed_size (monitor_start,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_START,
                           struct GNUNET_TRANSPORT_MonitorStart,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of file gnunet-service-transport.c */
