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
 * - figure out how to transmit (selective) ACKs in case of uni-directional
 *   communicators (with/without core? DV-only?) When do we use ACKs?
 *   => communicators use selective ACKs for flow control
 *   => transport uses message-level ACKs for RTT, fragment confirmation
 *   => integrate DV into transport, use neither core nor communicators
 *      but rather give communicators transport-encapsulated messages
 *      (which could be core-data, background-channel traffic, or
 *       transport-to-transport traffic)
 *
 * Implement next:
 * - address validation: what is our plan here?
 *   #1 Peerstore only gets 'validated' addresses
 *   #2 transport needs another API to "trigger" validation!
 *      API may be used by core/application or communicators;
 *      => use yet another lib/MQ/connection?
 *   #3 transport should use validation to also establish
 *      effective flow control (for uni-directional transports!)
 *   #4 UDP broadcasting logic must be extended to use the new API
 *   #5 only validated addresses go to ATS for scheduling; that
 *      also ensures we know the RTT 
 *   #6 to ensure flow control and RTT are OK, we always do the
 *      'validation', even if address comes from PEERSTORE
 *   #7 
 * - ACK handling / retransmission
 * - address verification
 * - track RTT, distance, loss, etc.
 * - DV data structures:
 *   + learning
 *   + forgetting
 *   + using them!
 * - routing of messages (using DV data structures!)
 * - handling of DV-boxed messages that need to be forwarded
 * - backchannel message encryption & decryption
 * -
 *
 * Easy:
 * - use ATS bandwidth allocation callback and schedule transmissions!
 *
 * Plan:
 * - inform ATS about RTT, goodput/loss, overheads, etc. (GNUNET_ATS_session_update())
 *
 * Later:
 * - change transport-core API to provide proper flow control in both
 *   directions, allow multiple messages per peer simultaneously (tag
 *   confirmations with unique message ID), and replace quota-out with
 *   proper flow control;
 * - if messages are below MTU, consider adding ACKs and other stuff
 *   (requires planning at receiver, and additional MST-style demultiplex
 *    at receiver!)
 * - could avoid copying body of message into each fragment and keep
 *   fragments as just pointers into the original message and only
 *   fully build fragments just before transmission (optimization, should
 *   reduce CPU and memory use)
 *
 * Design realizations / discussion:
 * - communicators do flow control by calling MQ "notify sent"
 *   when 'ready'. They determine flow implicitly (i.e. TCP blocking)
 *   or explicitly via background channel FC ACKs.  As long as the
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
 *   => in this data structure, we should track ATS metrics (distance, RTT, etc.)
 *   as well as latest timestamps seen, goodput, fragments for transmission, etc.
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
#include "gnunet_ats_transport_service.h"
#include "gnunet_signatures.h"
#include "transport.h"


/**
 * What is the size we assume for a read operation in the
 * absence of an MTU for the purpose of flow control?
 */
#define IN_PACKET_SIZE_WITHOUT_MTU 128

/**
 * If a queue delays the next message by more than this number
 * of seconds we log a warning. Note: this is for testing,
 * the value chosen here might be too aggressively low!
 */
#define DELAY_WARN_THRESHOLD GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How long are ephemeral keys valid?
 */
#define EPHEMERAL_VALIDITY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * How long do we keep partially reassembled messages around before giving up?
 */
#define REASSEMBLY_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 4)

/**
 * How many messages can we have pending for a given communicator
 * process before we start to throttle that communicator?
 *
 * Used if a communicator might be CPU-bound and cannot handle the traffic.
 */
#define COMMUNICATOR_TOTAL_QUEUE_LIMIT 512

/**
 * How many messages can we have pending for a given session (queue to
 * a particular peer via a communicator) process before we start to
 * throttle that queue?
 *
 * Used if ATS assigns more bandwidth to a particular transmission
 * method than that transmission method can right now handle. (Yes,
 * ATS should eventually notice utilization below allocation and
 * adjust, but we don't want to queue up tons of messages in the
 * meantime). Must be significantly below
 * #COMMUNICATOR_TOTAL_QUEUE_LIMIT.
 */
#define SESSION_QUEUE_LIMIT 32


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Outer layer of an encapsulated backchannel message.
 */
struct TransportBackchannelEncapsulationMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Distance the backchannel message has traveled, to be updated at
   * each hop.  Used to bound the number of hops in case a backchannel
   * message is broadcast and thus travels without routing
   * information (during initial backchannel discovery).
   */
  uint32_t distance;

  /**
   * Target's peer identity (as backchannels may be transmitted
   * indirectly, or even be broadcast).
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Ephemeral key setup by the sender for @e target, used
   * to encrypt the payload.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  // FIXME: probably should add random IV here as well,
  // especially if we re-use ephemeral keys!

  /**
   * HMAC over the ciphertext of the encrypted, variable-size
   * body that follows.  Verified via DH of @e target and
   * @e ephemeral_key
   */
  struct GNUNET_HashCode hmac;

  /* Followed by encrypted, variable-size payload */
};


/**
 * Body by which a peer confirms that it is using an ephemeral key.
 */
struct EphemeralConfirmation
{

  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * How long is this signature over the ephemeral key valid?
   * Note that the receiver MUST IGNORE the absolute time, and
   * only interpret the value as a mononic time and reject
   * "older" values than the last one observed.  Even with this,
   * there is no real guarantee against replay achieved here,
   * as the latest timestamp is not persisted.  This is
   * necessary as we do not want to require synchronized
   * clocks and may not have a bidirectional communication
   * channel.  Communicators must protect against replay
   * attacks when using backchannel communication!
   */
  struct GNUNET_TIME_AbsoluteNBO ephemeral_validity;

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
struct TransportBackchannelRequestPayload
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
   * How long is this signature over the ephemeral key
   * valid?
   */
  struct GNUNET_TIME_AbsoluteNBO ephemeral_validity;

  /**
   * Current monotonic time of the sending transport service.  Used to
   * detect replayed messages.  Note that the receiver should remember
   * a list of the recently seen timestamps and only reject messages
   * if the timestamp is in the list, or the list is "full" and the
   * timestamp is smaller than the lowest in the list.  This list of
   * timestamps per peer should be persisted to guard against replays
   * after restarts.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /* Followed by a `struct GNUNET_MessageHeader` with a message
     for a communicator */

  /* Followed by a 0-termianted string specifying the name of
     the communicator which is to receive the message */

};


/**
 * Outer layer of an encapsulated unfragmented application message sent
 * over an unreliable channel.
 */
struct TransportReliabilityBox
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
  struct GNUNET_ShortHashCode msg_uuid;
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
   * Reserved. Zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * How long was the ACK delayed relative to the average time of
   * receipt of the messages being acknowledged?  Used to calculate
   * the average RTT by taking the receipt time of the ack minus the
   * average transmission time of the sender minus this value.
   */
  struct GNUNET_TIME_RelativeNBO avg_ack_delay;

  /* followed by any number of `struct GNUNET_ShortHashCode`
     messages providing ACKs */
};


/**
 * Outer layer of an encapsulated fragmented application message.
 */
struct TransportFragmentBox
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID of this fragment (and fragment transmission!). Will
   * change even if a fragement is retransmitted to make each
   * transmission attempt unique! Should be incremented by one for
   * each fragment transmission. If a client receives a duplicate
   * fragment (same @e frag_off), it must send
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT_ACK immediately.
   */
  uint32_t frag_uuid GNUNET_PACKED;

  /**
   * Original message ID for of the message that all the1
   * fragments belong to.  Must be the same for all fragments.
   */
  struct GNUNET_ShortHashCode msg_uuid;

  /**
   * Offset of this fragment in the overall message.
   */
  uint16_t frag_off GNUNET_PACKED;

  /**
   * Total size of the message that is being fragmented.
   */
  uint16_t msg_size GNUNET_PACKED;

};


/**
 * Outer layer of an fragmented application message sent over a queue
 * with finite MTU.  When a #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT is
 * received, the receiver has two RTTs or 64 further fragments with
 * the same basic message time to send an acknowledgement, possibly
 * acknowledging up to 65 fragments in one ACK.  ACKs must also be
 * sent immediately once all fragments were sent.
 */
struct TransportFragmentAckMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID of the lowest fragment UUID being acknowledged.
   */
  uint32_t frag_uuid GNUNET_PACKED;

  /**
   * Bitfield of up to 64 additional fragments following the
   * @e msg_uuid being acknowledged by this message.
   */
  uint64_t extra_acks GNUNET_PACKED;

  /**
   * Original message ID for of the message that all the
   * fragments belong to.
   */
  struct GNUNET_ShortHashCode msg_uuid;

  /**
   * How long was the ACK delayed relative to the average time of
   * receipt of the fragments being acknowledged?  Used to calculate
   * the average RTT by taking the receipt time of the ack minus the
   * average transmission time of the sender minus this value.
   */
  struct GNUNET_TIME_RelativeNBO avg_ack_delay;

  /**
   * How long until the receiver will stop trying reassembly
   * of this message?
   */
  struct GNUNET_TIME_RelativeNBO reassembly_timeout;
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
struct TransportDVLearn
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
   * peers for any reason should increment this value such as to
   * enable the origin to determine the actual network-only delay
   * in addition to the real-time delay (assuming the message loops
   * back to the origin).
   */
  struct GNUNET_TIME_Relative cummulative_non_network_delay;

  /**
   * Identity of the peer that started this learning activity.
   */
  struct GNUNET_PeerIdentity initiator;

  /* Followed by @e num_hops `struct GNUNET_PeerIdentity` values,
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
 */
struct TransportDVBox
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of total hops this messages travelled. In NBO.
   * @e origin sets this to zero, to be incremented at
   * each hop.
   */
  uint16_t total_hops GNUNET_PACKED;

  /**
   * Number of hops this messages includes. In NBO.
   */
  uint16_t num_hops GNUNET_PACKED;

  /**
   * Identity of the peer that originated the message.
   */
  struct GNUNET_PeerIdentity origin;

  /* Followed by @e num_hops `struct GNUNET_PeerIdentity` values;
     excluding the @e origin and the current peer, the last must be
     the ultimate target; if @e num_hops is zero, the receiver of this
     message is the ultimate target. */

  /* Followed by the actual message, which itself may be
     another box, but not a DV_LEARN or DV_BOX message! */
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
  CT_COMMUNICATOR = 3
};


/**
 * Entry in our cache of ephemeral keys we currently use.
 * This way, we only sign an ephemeral once per @e target,
 * and then can re-use it over multiple
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION
 * messages (as signing is expensive).
 */
struct EphemeralCacheEntry
{

  /**
   * Target's peer identity (we don't re-use ephemerals
   * to limit linkability of messages).
   */
  struct GNUNET_PeerIdentity target;

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
   * Our ephemeral key.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  /**
   * Our private ephemeral key.
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey private_key;

  /**
   * Node in the ephemeral cache for this entry.
   * Used for expiration.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;
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
   * at the end of this struct.
   */
  const struct GNUNET_PeerIdentity *path;

  /**
   * At what time do we forget about this path unless we see it again
   * while learning?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How many hops in total to the `target` (excluding @e next_hop and `target` itself),
   * thus 0 still means a distance of 2 hops (to @e next_hop and then to `target`)?
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
};


/**
 * Entry identifying transmission in one of our `struct
 * GNUNET_ATS_Sessions` which still awaits an ACK.  This is used to
 * ensure we do not overwhelm a communicator and limit the number of
 * messages outstanding per communicator (say in case communicator is
 * CPU bound) and per queue (in case ATS bandwidth allocation exceeds
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
   * ATS session this entry is queued with.
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Message ID used for this message with the queue used for transmission.
   */
  uint64_t mid;
};


/**
 * An ATS session is a message queue provided by a communicator
 * via which we can reach a particular neighbour.
 */
struct GNUNET_ATS_Session
{
  /**
   * Kept in a MDLL.
   */
  struct GNUNET_ATS_Session *next_neighbour;

  /**
   * Kept in a MDLL.
   */
  struct GNUNET_ATS_Session *prev_neighbour;

  /**
   * Kept in a MDLL.
   */
  struct GNUNET_ATS_Session *prev_client;

  /**
   * Kept in a MDLL.
   */
  struct GNUNET_ATS_Session *next_client;

  /**
   * Head of DLL of unacked transmission requests.
   */
  struct QueueEntry *queue_head;

  /**
   * End of DLL of unacked transmission requests.
   */
  struct QueueEntry *queue_tail;

  /**
   * Which neighbour is this ATS session for?
   */
  struct Neighbour *neighbour;

  /**
   * Which communicator offers this ATS session?
   */
  struct TransportClient *tc;

  /**
   * Address served by the ATS session.
   */
  const char *address;

  /**
   * Handle by which we inform ATS about this queue.
   */
  struct GNUNET_ATS_SessionRecord *sr;

  /**
   * Task scheduled for the time when this queue can (likely) transmit the
   * next message. Still needs to check with the @e tracker_out to be sure.
   */
  struct GNUNET_SCHEDULER_Task *transmit_task;

  /**
   * Our current RTT estimate for this ATS session.
   */
  struct GNUNET_TIME_Relative rtt;

  /**
   * Message ID generator for transmissions on this queue.
   */
  uint64_t mid_gen;

  /**
   * Unique identifier of this ATS session with the communicator.
   */
  uint32_t qid;

  /**
   * Maximum transmission unit supported by this ATS session.
   */
  uint32_t mtu;

  /**
   * Distance to the target of this ATS session.
   */
  uint32_t distance;

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
   * Network type offered by this ATS session.
   */
  enum GNUNET_NetworkType nt;

  /**
   * Connection status for this ATS session.
   */
  enum GNUNET_TRANSPORT_ConnectionStatus cs;

  /**
   * How much outbound bandwidth do we have available for this session?
   */
  struct GNUNET_BANDWIDTH_Tracker tracker_out;

  /**
   * How much inbound bandwidth do we have available for this session?
   */
  struct GNUNET_BANDWIDTH_Tracker tracker_in;
};


/**
 * Information we keep for a message that we are reassembling.
 */
struct ReassemblyContext
{

  /**
   * Original message ID for of the message that all the
   * fragments belong to.
   */
  struct GNUNET_ShortHashCode msg_uuid;

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
   * Task for sending ACK. We may send ACKs either because of hitting
   * the @e extra_acks limit, or based on time and @e num_acks.  This
   * task is for the latter case.
   */
  struct GNUNET_SCHEDULER_Task *ack_task;

  /**
   * At what time will we give up reassembly of this message?
   */
  struct GNUNET_TIME_Absolute reassembly_timeout;

  /**
   * Average delay of all acks in @e extra_acks and @e frag_uuid.
   * Should be reset to zero when @e num_acks is set to 0.
   */
  struct GNUNET_TIME_Relative avg_ack_delay;

  /**
   * Time we received the last fragment.  @e avg_ack_delay must be
   * incremented by now - @e last_frag multiplied by @e num_acks.
   */
  struct GNUNET_TIME_Absolute last_frag;

  /**
   * Bitfield of up to 64 additional fragments following @e frag_uuid
   * to be acknowledged in the next cummulative ACK.
   */
  uint64_t extra_acks;

  /**
   * Unique ID of the lowest fragment UUID to be acknowledged in the
   * next cummulative ACK.  Only valid if @e num_acks > 0.
   */
  uint32_t frag_uuid;

  /**
   * Number of ACKs we have accumulated so far.  Reset to 0
   * whenever we send a #GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT_ACK.
   */
  unsigned int num_acks;

  /**
   * How big is the message we are reassembling in total?
   */
  uint16_t msg_size;

  /**
   * How many bytes of the message are still missing?  Defragmentation
   * is complete when @e msg_missing == 0.
   */
  uint16_t msg_missing;

  /* Followed by @e msg_size bytes of the (partially) defragmented original message */

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
  struct GNUNET_CONTAINER_MultiShortmap *reassembly_map;

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
   * Head of list of messages pending for this neighbour.
   */
  struct PendingMessage *pending_msg_head;

  /**
   * Tail of list of messages pending for this neighbour.
   */
  struct PendingMessage *pending_msg_tail;

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
   * Head of DLL of ATS sessions to this peer.
   */
  struct GNUNET_ATS_Session *session_head;

  /**
   * Tail of DLL of ATS sessions to this peer.
   */
  struct GNUNET_ATS_Session *session_tail;

  /**
   * Task run to cleanup pending messages that have exceeded their timeout.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Quota at which CORE is allowed to transmit to this peer
   * according to ATS.
   *
   * FIXME: not yet used, tricky to get right given multiple queues!
   *        (=> Idea: let ATS set a quota per queue and we add them up here?)
   * FIXME: how do we set this value initially when we tell CORE?
   *    Options: start at a minimum value or at literally zero (before ATS?)
   *         (=> Current thought: clean would be zero!)
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota_out;

  /**
   * What is the earliest timeout of any message in @e pending_msg_tail?
   */
  struct GNUNET_TIME_Absolute earliest_timeout;

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
  PMT_RELIABILITY_BOX = 2,

  /**
   * Any type of acknowledgement.
   */
  PMT_ACKNOWLEDGEMENT = 3


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
   * Kept in a MDLL of messages for this @a target.
   */
  struct PendingMessage *next_neighbour;

  /**
   * Kept in a MDLL of messages for this @a target.
   */
  struct PendingMessage *prev_neighbour;

  /**
   * Kept in a MDLL of messages from this @a client (if @e pmt is #PMT_CORE)
   */
  struct PendingMessage *next_client;

  /**
   * Kept in a MDLL of messages from this @a client  (if @e pmt is #PMT_CORE)
   */
  struct PendingMessage *prev_client;

  /**
   * Kept in a MDLL of messages from this @a cpm (if @e pmt is #PMT_FRAGMENT_BOx)
   */
  struct PendingMessage *next_frag;

  /**
   * Kept in a MDLL of messages from this @a cpm  (if @e pmt is #PMT_FRAGMENT_BOX)
   */
  struct PendingMessage *prev_frag;

  /**
   * This message, reliability boxed. Only possibly available if @e pmt is #PMT_CORE.
   */
  struct PendingMessage *bpm;

  /**
   * Target of the request.
   */
  struct Neighbour *target;

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
  struct GNUNET_ShortHashCode msg_uuid;

  /**
   * Counter incremented per generated fragment.
   */
  uint32_t frag_uuidgen;

  /**
   * Type of the pending message.
   */
  enum PendingMessageType pmt;

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
    struct {

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
    struct {

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
    struct {
      /**
       * If @e type is #CT_COMMUNICATOR, this communicator
       * supports communicating using these addresses.
       */
      char *address_prefix;

      /**
       * Head of DLL of queues offered by this communicator.
       */
      struct GNUNET_ATS_Session *session_head;

      /**
       * Tail of DLL of queues offered by this communicator.
       */
      struct GNUNET_ATS_Session *session_tail;

      /**
       * Head of list of the addresses of this peer offered by this communicator.
       */
      struct AddressListEntry *addr_head;

      /**
       * Tail of list of the addresses of this peer offered by this communicator.
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

  } details;

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
 * Map from PIDs to `struct DistanceVector` entries describing
 * known paths to the peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *dv_routes;

/**
 * Database for peer's HELLOs.
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Heap sorting `struct EphemeralCacheEntry` by their
 * key/signature validity.
 */
static struct GNUNET_CONTAINER_Heap *ephemeral_heap;

/**
 * Hash map for looking up `struct EphemeralCacheEntry`s
 * by peer identity. (We may have ephemerals in our
 * cache for which we do not have a neighbour entry,
 * and similar many neighbours may not need ephemerals,
 * so we use a second map.)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *ephemeral_map;

/**
 * Task to free expired ephemerals.
 */
static struct GNUNET_SCHEDULER_Task *ephemeral_task;

/**
 * Our connection to ATS for allocation and bootstrapping.
 */
static struct GNUNET_ATS_TransportHandle *ats;


/**
 * Free cached ephemeral key.
 *
 * @param ece cached signature to free
 */
static void
free_ephemeral (struct EphemeralCacheEntry *ece)
{
  GNUNET_CONTAINER_multipeermap_remove (ephemeral_map,
                                        &ece->target,
                                        ece);
  GNUNET_CONTAINER_heap_remove_node (ece->hn);
  GNUNET_free (ece);
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
  return GNUNET_CONTAINER_multipeermap_get (neighbours,
					    pid);
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
 * Free a @dvh, and if it is the last path to the `target`,also
 * free the associated DV entry in #dv_routes.
 *
 * @param dvh hop to free
 */
static void
free_distance_vector_hop (struct DistanceVectorHop *dvh)
{
  struct Neighbour *n = dvh->next_hop;
  struct DistanceVector *dv = dvh->dv;

  GNUNET_CONTAINER_MDLL_remove (neighbour,
				n->dv_head,
				n->dv_tail,
				dvh);
  GNUNET_CONTAINER_MDLL_remove (dv,
				dv->dv_head,
				dv->dv_tail,
				dvh);
  GNUNET_free (dvh);
  if (NULL == dv->dv_head)
  {
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multipeermap_remove (dv_routes,
							 &dv->target,
							 dv));
    if (NULL != dv->timeout_task)
      GNUNET_SCHEDULER_cancel (dv->timeout_task);
    GNUNET_free (dv);
  }
}


/**
 * Free entry in #dv_routes.  First frees all hops to the target, and
 * the last target will implicitly free @a dv as well.
 *
 * @param dv route to free
 */
static void
free_dv_route (struct DistanceVector *dv)
{
  struct DistanceVectorHop *dvh;

  while (NULL != (dvh = dv->dv_head))
    free_distance_vector_hop (dvh);
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
  memcpy (&md[1],
	  address,
	  addr_len);
  GNUNET_MQ_send (tc->mq,
		  env);
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
  static struct GNUNET_PeerIdentity zero;

  for (struct TransportClient *tc = clients_head;
       NULL != tc;
       tc = tc->next)
  {
    if (CT_MONITOR != tc->type)
      continue;
    if (tc->details.monitor.one_shot)
      continue;
    if ( (0 != memcmp (&tc->details.monitor.peer,
		       &zero,
		       sizeof (zero))) &&
	 (0 != memcmp (&tc->details.monitor.peer,
		       peer,
		       sizeof (*peer))) )
      continue;
    notify_monitor (tc,
		    peer,
		    address,
		    nt,
		    me);
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
 * Free @a rc
 *
 * @param rc data structure to free
 */
static void
free_reassembly_context (struct ReassemblyContext *rc)
{
  struct Neighbour *n = rc->neighbour;

  GNUNET_assert (rc ==
		 GNUNET_CONTAINER_heap_remove_node (rc->hn));
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multishortmap_remove (n->reassembly_map,
							&rc->msg_uuid,
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
    if (0 == GNUNET_TIME_absolute_get_remaining (rc->reassembly_timeout).rel_value_us)
    {
      free_reassembly_context (rc);
      continue;
    }
    GNUNET_assert (NULL == n->reassembly_timeout_task);
    n->reassembly_timeout_task = GNUNET_SCHEDULER_add_at (rc->reassembly_timeout,
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
free_reassembly_cb (void *cls,
		    const struct GNUNET_ShortHashCode *key,
		    void *value)
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

  GNUNET_assert (NULL == neighbour->session_head);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (neighbours,
						       &neighbour->pid,
						       neighbour));
  if (NULL != neighbour->timeout_task)
    GNUNET_SCHEDULER_cancel (neighbour->timeout_task);
  if (NULL != neighbour->reassembly_map)
  {
    GNUNET_CONTAINER_multishortmap_iterate (neighbour->reassembly_map,
					    &free_reassembly_cb,
					    NULL);
    GNUNET_CONTAINER_multishortmap_destroy (neighbour->reassembly_map);
    neighbour->reassembly_map = NULL;
    GNUNET_CONTAINER_heap_destroy (neighbour->reassembly_heap);
    neighbour->reassembly_heap = NULL;
  }
  while (NULL != (dvh = neighbour->dv_head))
    free_distance_vector_hop (dvh);
  if (NULL != neighbour->reassembly_timeout_task)
    GNUNET_SCHEDULER_cancel (neighbour->reassembly_timeout_task);
  GNUNET_free (neighbour);
}


/**
 * Send message to CORE clients that we lost a connection.
 *
 * @param tc client to inform (must be CORE client)
 * @param pid peer the connection is for
 * @param quota_out current quota for the peer
 */
static void
core_send_connect_info (struct TransportClient *tc,
			const struct GNUNET_PeerIdentity *pid,
			struct GNUNET_BANDWIDTH_Value32NBO quota_out)
{
  struct GNUNET_MQ_Envelope *env;
  struct ConnectInfoMessage *cim;

  GNUNET_assert (CT_CORE == tc->type);
  env = GNUNET_MQ_msg (cim,
		       GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim->quota_out = quota_out;
  cim->id = *pid;
  GNUNET_MQ_send (tc->mq,
		  env);
}


/**
 * Send message to CORE clients that we gained a connection
 *
 * @param pid peer the queue was for
 * @param quota_out current quota for the peer
 */
static void
cores_send_connect_info (const struct GNUNET_PeerIdentity *pid,
			 struct GNUNET_BANDWIDTH_Value32NBO quota_out)
{
  for (struct TransportClient *tc = clients_head;
       NULL != tc;
       tc = tc->next)
  {
    if (CT_CORE != tc->type)
      continue;
    core_send_connect_info (tc,
			    pid,
			    quota_out);
  }
}


/**
 * Send message to CORE clients that we lost a connection.
 *
 * @param pid peer the connection was for
 */
static void
cores_send_disconnect_info (const struct GNUNET_PeerIdentity *pid)
{
  for (struct TransportClient *tc = clients_head;
       NULL != tc;
       tc = tc->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct DisconnectInfoMessage *dim;

    if (CT_CORE != tc->type)
      continue;
    env = GNUNET_MQ_msg (dim,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
    dim->peer = *pid;
    GNUNET_MQ_send (tc->mq,
		    env);
  }
}


/**
 * We believe we are ready to transmit a message on a queue. Double-checks
 * with the queue's "tracker_out" and then gives the message to the
 * communicator for transmission (updating the tracker, and re-scheduling
 * itself if applicable).
 *
 * @param cls the `struct GNUNET_ATS_Session` to process transmissions for
 */
static void
transmit_on_queue (void *cls);


/**
 * Schedule next run of #transmit_on_queue().  Does NOTHING if
 * we should run immediately or if the message queue is empty.
 * Test for no task being added AND queue not being empty to
 * transmit immediately afterwards!  This function must only
 * be called if the message queue is non-empty!
 *
 * @param queue the queue to do scheduling for
 */
static void
schedule_transmit_on_queue (struct GNUNET_ATS_Session *queue)
{
  struct Neighbour *n = queue->neighbour;
  struct PendingMessage *pm = n->pending_msg_head;
  struct GNUNET_TIME_Relative out_delay;
  unsigned int wsize;

  GNUNET_assert (NULL != pm);
  if (queue->tc->details.communicator.total_queue_length >= COMMUNICATOR_TOTAL_QUEUE_LIMIT)
  {
    GNUNET_STATISTICS_update (GST_stats,
			      "# Transmission throttled due to communicator queue limit",
			      1,
			      GNUNET_NO);
    return;
  }
  if (queue->queue_length >= SESSION_QUEUE_LIMIT)
  {
    GNUNET_STATISTICS_update (GST_stats,
			      "# Transmission throttled due to session queue limit",
			      1,
			      GNUNET_NO);
    return;
  }

  wsize = (0 == queue->mtu)
    ? pm->bytes_msg /* FIXME: add overheads? */
    : queue->mtu;
  out_delay = GNUNET_BANDWIDTH_tracker_get_delay (&queue->tracker_out,
						  wsize);
  out_delay = GNUNET_TIME_relative_max (GNUNET_TIME_absolute_get_remaining (pm->next_attempt),
					out_delay);
  if (0 == out_delay.rel_value_us)
    return; /* we should run immediately! */
  /* queue has changed since we were scheduled, reschedule again */
  queue->transmit_task = GNUNET_SCHEDULER_add_delayed (out_delay,
						       &transmit_on_queue,
						       queue);
  if (out_delay.rel_value_us > DELAY_WARN_THRESHOLD.rel_value_us)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Next transmission on queue `%s' in %s (high delay)\n",
		queue->address,
		GNUNET_STRINGS_relative_time_to_string (out_delay,
							GNUNET_YES));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Next transmission on queue `%s' in %s\n",
		queue->address,
		GNUNET_STRINGS_relative_time_to_string (out_delay,
							GNUNET_YES));
}


/**
 * Free @a session.
 *
 * @param session the session to free
 */
static void
free_session (struct GNUNET_ATS_Session *session)
{
  struct Neighbour *neighbour = session->neighbour;
  struct TransportClient *tc = session->tc;
  struct MonitorEvent me = {
    .cs = GNUNET_TRANSPORT_CS_DOWN,
    .rtt = GNUNET_TIME_UNIT_FOREVER_REL
  };
  struct QueueEntry *qe;
  int maxxed;

  if (NULL != session->transmit_task)
  {
    GNUNET_SCHEDULER_cancel (session->transmit_task);
    session->transmit_task = NULL;
  }
  GNUNET_CONTAINER_MDLL_remove (neighbour,
				neighbour->session_head,
				neighbour->session_tail,
				session);
  GNUNET_CONTAINER_MDLL_remove (client,
				tc->details.communicator.session_head,
				tc->details.communicator.session_tail,
				session);
  maxxed = (COMMUNICATOR_TOTAL_QUEUE_LIMIT >= tc->details.communicator.total_queue_length);
  while (NULL != (qe = session->queue_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->queue_head,
				 session->queue_tail,
				 qe);
    session->queue_length--;
    tc->details.communicator.total_queue_length--;
    GNUNET_free (qe);
  }
  GNUNET_assert (0 == session->queue_length);
  if ( (maxxed) &&
       (COMMUNICATOR_TOTAL_QUEUE_LIMIT < tc->details.communicator.total_queue_length) )
  {
    /* Communicator dropped below threshold, resume all queues */
    GNUNET_STATISTICS_update (GST_stats,
			      "# Transmission throttled due to communicator queue limit",
			      -1,
			      GNUNET_NO);
    for (struct GNUNET_ATS_Session *s = tc->details.communicator.session_head;
	 NULL != s;
	 s = s->next_client)
      schedule_transmit_on_queue (s);
  }
  notify_monitors (&neighbour->pid,
		   session->address,
		   session->nt,
		   &me);
  GNUNET_ATS_session_del (session->sr);
  GNUNET_BANDWIDTH_tracker_notification_stop (&session->tracker_in);
  GNUNET_BANDWIDTH_tracker_notification_stop (&session->tracker_out);
  GNUNET_free (session);
  if (NULL == neighbour->session_head)
  {
    cores_send_disconnect_info (&neighbour->pid);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected, cleaning up.\n",
              tc);
  GNUNET_CONTAINER_DLL_remove (clients_head,
                               clients_tail,
                               tc);
  switch (tc->type)
  {
  case CT_NONE:
    break;
  case CT_CORE:
    {
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
  case CT_COMMUNICATOR:
    {
      struct GNUNET_ATS_Session *q;
      struct AddressListEntry *ale;

      while (NULL != (q = tc->details.communicator.session_head))
	free_session (q);
      while (NULL != (ale = tc->details.communicator.addr_head))
	free_address_list_entry (ale);
      GNUNET_free (tc->details.communicator.address_prefix);
    }
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
  struct Neighbour *neighbour = value;

  core_send_connect_info (tc,
			  pid,
			  neighbour->quota_out);
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
handle_client_start (void *cls,
		     const struct StartMessage *start)
{
  struct TransportClient *tc = cls;
  uint32_t options;

  options = ntohl (start->options);
  if ( (0 != (1 & options)) &&
       (0 !=
        memcmp (&start->self,
                &GST_my_identity,
                sizeof (struct GNUNET_PeerIdentity)) ) )
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
check_client_send (void *cls,
		   const struct OutboundMessage *obm)
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
 * Free fragment tree below @e root, excluding @e root itself.
 *
 * @param root root of the tree to free
 */
static void
free_fragment_tree (struct PendingMessage *root)
{
  struct PendingMessage *frag;

  while (NULL != (frag = root->head_frag))
  {
    free_fragment_tree (frag);
    GNUNET_CONTAINER_MDLL_remove (frag,
				  root->head_frag,
				  root->tail_frag,
				  frag);
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
  struct Neighbour *target = pm->target;

  if (NULL != tc)
  {
    GNUNET_CONTAINER_MDLL_remove (client,
				  tc->details.core.pending_msg_head,
				  tc->details.core.pending_msg_tail,
				  pm);
  }
  GNUNET_CONTAINER_MDLL_remove (neighbour,
				target->pending_msg_head,
				target->pending_msg_tail,
				pm);
  free_fragment_tree (pm);
  GNUNET_free_non_null (pm->bpm);
  GNUNET_free (pm);
}


/**
 * Send a response to the @a pm that we have processed a
 * "send" request with status @a success. We
 * transmitted @a bytes_physical on the actual wire.
 * Sends a confirmation to the "core" client responsible
 * for the original request and free's @a pm.
 *
 * @param pm handle to the original pending message
 * @param success status code, #GNUNET_OK on success, #GNUNET_SYSERR
 *          for transmission failure
 * @param bytes_physical amount of bandwidth consumed
 */
static void
client_send_response (struct PendingMessage *pm,
		      int success,
		      uint32_t bytes_physical)
{
  struct TransportClient *tc = pm->client;
  struct Neighbour *target = pm->target;
  struct GNUNET_MQ_Envelope *env;
  struct SendOkMessage *som;

  if (NULL != tc)
  {
    env = GNUNET_MQ_msg (som,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
    som->success = htonl ((uint32_t) success);
    som->bytes_msg = htons (pm->bytes_msg);
    som->bytes_physical = htonl (bytes_physical);
    som->peer = target->pid;
    GNUNET_MQ_send (tc->mq,
		    env);
  }
  free_pending_message (pm);
}


/**
 * Checks the message queue for a neighbour for messages that have timed
 * out and purges them.
 *
 * @param cls a `struct Neighbour`
 */
static void
check_queue_timeouts (void *cls)
{
  struct Neighbour *n = cls;
  struct PendingMessage *pm;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute earliest_timeout;

  n->timeout_task = NULL;
  earliest_timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  now = GNUNET_TIME_absolute_get ();
  for (struct PendingMessage *pos = n->pending_msg_head;
       NULL != pos;
       pos = pm)
  {
    pm = pos->next_neighbour;
    if (pos->timeout.abs_value_us <= now.abs_value_us)
    {
      GNUNET_STATISTICS_update (GST_stats,
				"# messages dropped (timeout before confirmation)",
				1,
				GNUNET_NO);
      client_send_response (pm,
			    GNUNET_NO,
			    0);
      continue;
    }
    earliest_timeout = GNUNET_TIME_absolute_min (earliest_timeout,
						 pos->timeout);
  }
  n->earliest_timeout = earliest_timeout;
  if (NULL != n->pending_msg_head)
    n->timeout_task = GNUNET_SCHEDULER_add_at (earliest_timeout,
					       &check_queue_timeouts,
					       n);
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
  struct TransportClient *tc = cls;
  struct PendingMessage *pm;
  const struct GNUNET_MessageHeader *obmm;
  struct Neighbour *target;
  uint32_t bytes_msg;

  GNUNET_assert (CT_CORE == tc->type);
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  bytes_msg = ntohs (obmm->size);
  target = lookup_neighbour (&obm->peer);
  if (NULL == target)
  {
    /* Failure: don't have this peer as a neighbour (anymore).
       Might have gone down asynchronously, so this is NOT
       a protocol violation by CORE. Still count the event,
       as this should be rare. */
    struct GNUNET_MQ_Envelope *env;
    struct SendOkMessage *som;

    env = GNUNET_MQ_msg (som,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
    som->success = htonl (GNUNET_SYSERR);
    som->bytes_msg = htonl (bytes_msg);
    som->bytes_physical = htonl (0);
    som->peer = obm->peer;
    GNUNET_MQ_send (tc->mq,
		    env);
    GNUNET_SERVICE_client_continue (tc->client);
    GNUNET_STATISTICS_update (GST_stats,
			      "# messages dropped (neighbour unknown)",
			      1,
			      GNUNET_NO);
    return;
  }
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + bytes_msg);
  pm->client = tc;
  pm->target = target;
  pm->bytes_msg = bytes_msg;
  pm->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_ntoh (obm->timeout));
  memcpy (&pm[1],
	  &obm[1],
	  bytes_msg);
  GNUNET_CONTAINER_MDLL_insert (neighbour,
				target->pending_msg_head,
				target->pending_msg_tail,
				pm);
  GNUNET_CONTAINER_MDLL_insert (client,
				tc->details.core.pending_msg_head,
				tc->details.core.pending_msg_tail,
				pm);
  if (target->earliest_timeout.abs_value_us > pm->timeout.abs_value_us)
  {
    target->earliest_timeout.abs_value_us = pm->timeout.abs_value_us;
    if (NULL != target->timeout_task)
      GNUNET_SCHEDULER_cancel (target->timeout_task);
    target->timeout_task
      = GNUNET_SCHEDULER_add_at (target->earliest_timeout,
				 &check_queue_timeouts,
				 target);
  }
}


/**
 * Communicator started.  Test message is well-formed.
 *
 * @param cls the client
 * @param cam the send message that was sent
 */
static int
check_communicator_available (void *cls,
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
 * Communicator started.  Process the request.
 *
 * @param cls the client
 * @param cam the send message that was sent
 */
static void
handle_communicator_available (void *cls,
                               const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *cam)
{
  struct TransportClient *tc = cls;
  uint16_t size;

  size = ntohs (cam->header.size) - sizeof (*cam);
  if (0 == size)
    return; /* receive-only communicator */
  tc->details.communicator.address_prefix
    = GNUNET_strdup ((const char *) &cam[1]);
  tc->details.communicator.cc
    = (enum GNUNET_TRANSPORT_CommunicatorCharacteristics) ntohl (cam->cc);
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
check_communicator_backchannel (void *cls,
				const struct GNUNET_TRANSPORT_CommunicatorBackchannel *cb)
{
  const struct GNUNET_MessageHeader *inbox;
  const char *is;
  uint16_t msize;
  uint16_t isize;

  msize = ntohs (cb->header.size) - sizeof (*cb);
  if (UINT16_MAX - msize >
      sizeof (struct TransportBackchannelEncapsulationMessage) +
      sizeof (struct TransportBackchannelRequestPayload) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
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
  GNUNET_assert (msize > 0);
  if ('\0' != is[msize-1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Remove memory used by expired ephemeral keys.
 *
 * @param cls NULL
 */
static void
expire_ephemerals (void *cls)
{
  struct EphemeralCacheEntry *ece;

  (void) cls;
  ephemeral_task = NULL;
  while (NULL != (ece = GNUNET_CONTAINER_heap_peek (ephemeral_heap)))
  {
    if (0 == GNUNET_TIME_absolute_get_remaining (ece->ephemeral_validity).rel_value_us)
    {
      free_ephemeral (ece);
      continue;
    }
    ephemeral_task = GNUNET_SCHEDULER_add_at (ece->ephemeral_validity,
					      &expire_ephemerals,
					      NULL);
    return;
  }
}


/**
 * Lookup ephemeral key in our #ephemeral_map. If no valid one exists, generate
 * one, cache it and return it.
 *
 * @param pid peer to look up ephemeral for
 * @param private_key[out] set to the private key
 * @param ephemeral_key[out] set to the key
 * @param ephemeral_sender_sig[out] set to the signature
 * @param ephemeral_validity[out] set to the validity expiration time
 */
static void
lookup_ephemeral (const struct GNUNET_PeerIdentity *pid,
		  struct GNUNET_CRYPTO_EcdhePrivateKey *private_key,
		  struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral_key,
		  struct GNUNET_CRYPTO_EddsaSignature *ephemeral_sender_sig,
		  struct GNUNET_TIME_Absolute *ephemeral_validity)
{
  struct EphemeralCacheEntry *ece;
  struct EphemeralConfirmation ec;

  ece = GNUNET_CONTAINER_multipeermap_get (ephemeral_map,
					   pid);
  if ( (NULL != ece) &&
       (0 == GNUNET_TIME_absolute_get_remaining (ece->ephemeral_validity).rel_value_us) )
  {
    free_ephemeral (ece);
    ece = NULL;
  }
  if (NULL == ece)
  {
    ece = GNUNET_new (struct EphemeralCacheEntry);
    ece->target = *pid;
    ece->ephemeral_validity = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get_monotonic (GST_cfg),
							EPHEMERAL_VALIDITY);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CRYPTO_ecdhe_key_create2 (&ece->private_key));
    GNUNET_CRYPTO_ecdhe_key_get_public (&ece->private_key,
					&ece->ephemeral_key);
    ec.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL);
    ec.purpose.size = htonl (sizeof (ec));
    ec.target = *pid;
    ec.ephemeral_key = ece->ephemeral_key;
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
					     &ec.purpose,
					     &ece->sender_sig));
    ece->hn = GNUNET_CONTAINER_heap_insert (ephemeral_heap,
					    ece,
					    ece->ephemeral_validity.abs_value_us);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multipeermap_put (ephemeral_map,
						      &ece->target,
						      ece,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    if (NULL == ephemeral_task)
      ephemeral_task = GNUNET_SCHEDULER_add_at (ece->ephemeral_validity,
						&expire_ephemerals,
						NULL);
  }
  *private_key = ece->private_key;
  *ephemeral_key = ece->ephemeral_key;
  *ephemeral_sender_sig = ece->sender_sig;
  *ephemeral_validity = ece->ephemeral_validity;
}


/**
 * We need to transmit @a hdr to @a target.  If necessary, this may
 * involve DV routing or even broadcasting and fragmentation.
 *
 * @param target peer to receive @a hdr
 * @param hdr header of the message to route
 */
static void
route_message (const struct GNUNET_PeerIdentity *target,
	       struct GNUNET_MessageHeader *hdr)
{
  // FIXME: send hdr to target, free hdr (possibly using DV, possibly broadcasting)
  GNUNET_free (hdr);
}


/**
 * Communicator requests backchannel transmission.  Process the request.
 *
 * @param cls the client
 * @param cb the send message that was sent
 */
static void
handle_communicator_backchannel (void *cls,
				 const struct GNUNET_TRANSPORT_CommunicatorBackchannel *cb)
{
  struct TransportClient *tc = cls;
  struct GNUNET_CRYPTO_EcdhePrivateKey private_key;
  struct GNUNET_TIME_Absolute ephemeral_validity;
  struct TransportBackchannelEncapsulationMessage *enc;
  struct TransportBackchannelRequestPayload ppay;
  char *mpos;
  uint16_t msize;

  /* encapsulate and encrypt message */
  msize = ntohs (cb->header.size) - sizeof (*cb) + sizeof (struct TransportBackchannelRequestPayload);
  enc = GNUNET_malloc (sizeof (*enc) + msize);
  enc->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION);
  enc->header.size = htons (sizeof (*enc) + msize);
  enc->target = cb->pid;
  lookup_ephemeral (&cb->pid,
		    &private_key,
		    &enc->ephemeral_key,
		    &ppay.sender_sig,
		    &ephemeral_validity);
  // FIXME: setup 'iv'
#if FIXME
  dh_key_derive (&private_key,
		 &cb->pid,
		 &enc->iv,
		 &key);
#endif
  ppay.ephemeral_validity = GNUNET_TIME_absolute_hton (ephemeral_validity);
  ppay.monotonic_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_monotonic (GST_cfg));
  mpos = (char *) &enc[1];
#if FIXME
  encrypt (key,
	   &ppay,
	   &mpos,
	   sizeof (ppay));
  encrypt (key,
	   &cb[1],
	   &mpos,
	   ntohs (cb->header.size) - sizeof (*cb));
  hmac (key,
	&enc->hmac);
#endif
  route_message (&cb->pid,
		 &enc->header);
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
 */
static void
peerstore_store_cb (void *cls,
		    int success)
{
  struct AddressListEntry *ale = cls;

  ale->sc = NULL;
  if (GNUNET_YES != success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to store our own address `%s' in peerstore!\n",
		ale->address);
  /* refresh period is 1/4 of expiration time, that should be plenty
     without being excessive. */
  ale->st = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (ale->expiration,
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
  GNUNET_HELLO_sign_address (ale->address,
			     ale->nt,
			     expiration,
			     GST_my_private_key,
			     &addr,
			     &addr_len);
  ale->sc = GNUNET_PEERSTORE_store (peerstore,
				    "transport",
				    &GST_my_identity,
				    GNUNET_HELLO_PEERSTORE_KEY,
				    addr,
				    addr_len,
				    expiration,
				    GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
				    &peerstore_store_cb,
				    ale);
  GNUNET_free (addr);
  if (NULL == ale->sc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Failed to store our address `%s' with peerstore\n",
		ale->address);
    ale->st = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
					    &store_pi,
					    ale);
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

  slen = ntohs (aam->header.size) - sizeof (*aam);
  ale = GNUNET_malloc (sizeof (struct AddressListEntry) + slen);
  ale->tc = tc;
  ale->address = (const char *) &ale[1];
  ale->expiration = GNUNET_TIME_relative_ntoh (aam->expiration);
  ale->aid = aam->aid;
  ale->nt = (enum GNUNET_NetworkType) ntohl (aam->nt);
  memcpy (&ale[1],
          &aam[1],
          slen);
  GNUNET_CONTAINER_DLL_insert (tc->details.communicator.addr_head,
                               tc->details.communicator.addr_tail,
                               ale);
  ale->st = GNUNET_SCHEDULER_add_now (&store_pi,
				      ale);
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
    free_address_list_entry (ale);
    GNUNET_SERVICE_client_continue (tc->client);
  }
  GNUNET_break (0);
  GNUNET_SERVICE_client_drop (tc->client);
}


/**
 * Context from #handle_incoming_msg().  Closure for many
 * message handlers below.
 */
struct CommunicatorMessageContext
{
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

    env = GNUNET_MQ_msg (ack,
			 GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK);
    ack->reserved = htonl (0);
    ack->fc_id = cmc->im.fc_id;
    ack->sender = cmc->im.sender;
    GNUNET_MQ_send (cmc->tc->mq,
		    env);
  }
  GNUNET_SERVICE_client_continue (cmc->tc->client);
  GNUNET_free (cmc);
}


/**
 * Communicator gave us an unencapsulated message to pass as-is to
 * CORE.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param mh the message that was received
 */
static void
handle_raw_message (void *cls,
		    const struct GNUNET_MessageHeader *mh)
{
  struct CommunicatorMessageContext *cmc = cls;
  uint16_t size = ntohs (mh->size);

  if ( (size > UINT16_MAX - sizeof (struct InboundMessage)) ||
       (size < sizeof (struct GNUNET_MessageHeader)) )
  {
    struct GNUNET_SERVICE_Client *client = cmc->tc->client;

    GNUNET_break (0);
    finish_cmc_handling (cmc);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  /* Forward to all CORE clients */
  for (struct TransportClient *tc = clients_head;
       NULL != tc;
       tc = tc->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct InboundMessage *im;

    if (CT_CORE != tc->type)
      continue;
    env = GNUNET_MQ_msg_extra (im,
			       size,
			       GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
    im->peer = cmc->im.sender;
    memcpy (&im[1],
	    mh,
	    size);
    GNUNET_MQ_send (tc->mq,
		    env);
  }
  /* FIXME: consider doing this _only_ once the message
     was drained from the CORE MQs to extend flow control to CORE!
     (basically, increment counter in cmc, decrement on MQ send continuation! */
  finish_cmc_handling (cmc);
}


/**
 * Communicator gave us a fragment box.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param fb the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_fragment_box (void *cls,
		    const struct TransportFragmentBox *fb)
{
  uint16_t size = ntohs (fb->header.size);
  uint16_t bsize = size - sizeof (*fb);

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
 * Generate a fragment acknowledgement for an @a rc.
 *
 * @param rc context to generate ACK for, @a rc ACK state is reset
 */
static void
send_fragment_ack (struct ReassemblyContext *rc)
{
  struct TransportFragmentAckMessage *ack;

  ack = GNUNET_new (struct TransportFragmentAckMessage);
  ack->header.size = htons (sizeof (struct TransportFragmentAckMessage));
  ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT_ACK);
  ack->frag_uuid = htonl (rc->frag_uuid);
  ack->extra_acks = GNUNET_htonll (rc->extra_acks);
  ack->msg_uuid = rc->msg_uuid;
  ack->avg_ack_delay = GNUNET_TIME_relative_hton (rc->avg_ack_delay);
  if (0 == rc->msg_missing)
    ack->reassembly_timeout
      = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_FOREVER_REL); /* signal completion */
  else
    ack->reassembly_timeout
      = GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining (rc->reassembly_timeout));
  route_message (&rc->neighbour->pid,
		 &ack->header);
  rc->avg_ack_delay = GNUNET_TIME_UNIT_ZERO;
  rc->num_acks = 0;
  rc->extra_acks = 0LLU;
}


/**
 * Communicator gave us a fragment.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param fb the message that was received
 */
static void
handle_fragment_box (void *cls,
		     const struct TransportFragmentBox *fb)
{
  struct CommunicatorMessageContext *cmc = cls;
  struct Neighbour *n;
  struct ReassemblyContext *rc;
  const struct GNUNET_MessageHeader *msg;
  uint16_t msize;
  uint16_t fsize;
  uint16_t frag_off;
  uint32_t frag_uuid;
  char *target;
  struct GNUNET_TIME_Relative cdelay;
  int ack_now;

  n = GNUNET_CONTAINER_multipeermap_get (neighbours,
					 &cmc->im.sender);
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
    n->reassembly_map = GNUNET_CONTAINER_multishortmap_create (8,
							       GNUNET_YES);
    n->reassembly_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
    n->reassembly_timeout_task = GNUNET_SCHEDULER_add_delayed (REASSEMBLY_EXPIRATION,
							       &reassembly_cleanup_task,
							       n);
  }
  msize = ntohs (fb->msg_size);
  rc = GNUNET_CONTAINER_multishortmap_get (n->reassembly_map,
					   &fb->msg_uuid);
  if (NULL == rc)
  {
    rc = GNUNET_malloc (sizeof (*rc) +
			msize + /* reassembly payload buffer */
			(msize + 7) / 8 * sizeof (uint8_t) /* bitfield */);
    rc->msg_uuid = fb->msg_uuid;
    rc->neighbour = n;
    rc->msg_size = msize;
    rc->reassembly_timeout = GNUNET_TIME_relative_to_absolute (REASSEMBLY_EXPIRATION);
    rc->last_frag = GNUNET_TIME_absolute_get ();
    rc->hn = GNUNET_CONTAINER_heap_insert (n->reassembly_heap,
					   rc,
					   rc->reassembly_timeout.abs_value_us);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multishortmap_put (n->reassembly_map,
						       &rc->msg_uuid,
						       rc,
						       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    target = (char *) &rc[1];
    rc->bitfield = (uint8_t *) (target + rc->msg_size);
    rc->msg_missing = rc->msg_size;
  }
  else
  {
    target = (char *) &rc[1];
  }
  if (msize != rc->msg_size)
  {
    GNUNET_break (0);
    finish_cmc_handling (cmc);
    return;
  }

  /* reassemble */
  fsize = ntohs (fb->header.size) - sizeof (*fb);
  frag_off = ntohs (fb->frag_off);
  memcpy (&target[frag_off],
	  &fb[1],
	  fsize);
  /* update bitfield and msg_missing */
  for (unsigned int i=frag_off;i<frag_off+fsize;i++)
  {
    if (0 == (rc->bitfield[i / 8] & (1 << (i % 8))))
    {
      rc->bitfield[i / 8] |= (1 << (i % 8));
      rc->msg_missing--;
    }
  }

  /* Compute cummulative ACK */
  frag_uuid = ntohl (fb->frag_uuid);
  cdelay = GNUNET_TIME_absolute_get_duration (rc->last_frag);
  cdelay = GNUNET_TIME_relative_multiply (cdelay,
					  rc->num_acks);
  rc->last_frag = GNUNET_TIME_absolute_get ();
  rc->avg_ack_delay = GNUNET_TIME_relative_add (rc->avg_ack_delay,
						cdelay);
  ack_now = GNUNET_NO;
  if (0 == rc->num_acks)
  {
    /* case one: first ack */
    rc->frag_uuid = frag_uuid;
    rc->extra_acks = 0LLU;
    rc->num_acks = 1;
  }
  else if ( (frag_uuid >= rc->frag_uuid) &&
	    (frag_uuid <= rc->frag_uuid + 64) )
  {
    /* case two: ack fits after existing min UUID */
    if ( (frag_uuid == rc->frag_uuid) ||
	 (0 != (rc->extra_acks & (1LLU << (frag_uuid - rc->frag_uuid - 1)))) )
    {
      /* duplicate fragment, ack now! */
      ack_now = GNUNET_YES;
    }
    else
    {
      rc->extra_acks |= (1LLU << (frag_uuid - rc->frag_uuid - 1));
      rc->num_acks++;
    }
  }
  else if ( (rc->frag_uuid > frag_uuid) &&
	    ( ( (rc->frag_uuid == frag_uuid + 64) &&
		(0 == rc->extra_acks) ) ||
	      ( (rc->frag_uuid < frag_uuid + 64) &&
		(rc->extra_acks == (rc->extra_acks & ~ ((1LLU << (64 - (rc->frag_uuid - frag_uuid))) - 1LLU))) ) ) )
  {
    /* can fit ack by shifting extra acks and starting at
       frag_uid, test above esured that the bits we will
       shift 'extra_acks' by are all zero. */
    rc->extra_acks <<= (rc->frag_uuid - frag_uuid);
    rc->extra_acks |= (1LLU << (rc->frag_uuid - frag_uuid - 1));
    rc->frag_uuid = frag_uuid;
    rc->num_acks++;
  }
  if (65 == rc->num_acks) /* FIXME: maybe use smaller threshold? This is very aggressive. */
    ack_now = GNUNET_YES; /* maximum acks received */
  // FIXME: possibly also ACK based on RTT (but for that we'd need to
  // determine the session used for the ACK first!)

  /* is reassembly complete? */
  if (0 != rc->msg_missing)
  {
    if (ack_now)
      send_fragment_ack (rc);
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
  send_fragment_ack (rc);
  demultiplex_with_cmc (cmc,
			msg);
  /* FIXME: really free here? Might be bad if fragments are still
     en-route and we forget that we finished this reassembly immediately!
     -> keep around until timeout?
     -> shorten timeout based on ACK? */
  free_reassembly_context (rc);
}


/**
 * Communicator gave us a fragment acknowledgement.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param fa the message that was received
 */
static void
handle_fragment_ack (void *cls,
		     const struct TransportFragmentAckMessage *fa)
{
  struct CommunicatorMessageContext *cmc = cls;

  // FIXME: do work: identify original message; then identify fragments being acked;
  // remove those from the tree to prevent retransmission;
  // compute RTT
  // if entire message is ACKed, handle that as well.
  finish_cmc_handling (cmc);
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
		       const struct TransportReliabilityBox *rb)
{
  GNUNET_MQ_check_boxed_message (rb);
  return GNUNET_YES;
}


/**
 * Communicator gave us a reliability box.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param rb the message that was received
 */
static void
handle_reliability_box (void *cls,
			const struct TransportReliabilityBox *rb)
{
  struct CommunicatorMessageContext *cmc = cls;
  const struct GNUNET_MessageHeader *inbox = (const struct GNUNET_MessageHeader *) &rb[1];

  if (0 == ntohl (rb->ack_countdown))
  {
    struct TransportReliabilityAckMessage *ack;

    /* FIXME: implement cummulative ACKs and ack_countdown,
       then setting the avg_ack_delay field below: */
    ack = GNUNET_malloc (sizeof (*ack) +
			 sizeof (struct GNUNET_ShortHashCode));
    ack->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK);
    ack->header.size = htons (sizeof (*ack) +
			      sizeof (struct GNUNET_ShortHashCode));
    memcpy (&ack[1],
	    &rb->msg_uuid,
	    sizeof (struct GNUNET_ShortHashCode));
    route_message (&cmc->im.sender,
		   &ack->header);
  }
  /* continue with inner message */
  demultiplex_with_cmc (cmc,
			inbox);
}


/**
 * Communicator gave us a reliability ack.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param ra the message that was received
 */
static void
handle_reliability_ack (void *cls,
			const struct TransportReliabilityAckMessage *ra)
{
  struct CommunicatorMessageContext *cmc = cls;

  // FIXME: do work: find message that was acknowledged, and
  // remove from transmission queue; update RTT.
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
check_backchannel_encapsulation (void *cls,
				 const struct TransportBackchannelEncapsulationMessage *be)
{
  uint16_t size = ntohs (be->header.size);

  if (size - sizeof (*be) < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Communicator gave us a backchannel encapsulation.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param be the message that was received
 */
static void
handle_backchannel_encapsulation (void *cls,
				  const struct TransportBackchannelEncapsulationMessage *be)
{
  struct CommunicatorMessageContext *cmc = cls;

  if (0 != memcmp (&be->target,
		   &GST_my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* not for me, try to route to target */
    route_message (&be->target,
		   GNUNET_copy_message (&be->header));
    finish_cmc_handling (cmc);
    return;
  }
  // FIXME: compute shared secret
  // FIXME: check HMAC
  // FIXME: decrypt payload
  // FIXME: forward to specified communicator!
  // (using GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING)
  finish_cmc_handling (cmc);
}


/**
 * Communicator gave us a DV learn message.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param dvl the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_dv_learn (void *cls,
		const struct TransportDVLearn *dvl)
{
  uint16_t size = ntohs (dvl->header.size);
  uint16_t num_hops = ntohs (dvl->num_hops);
  const struct GNUNET_PeerIdentity *hops = (const struct GNUNET_PeerIdentity *) &dvl[1];

  if (size != sizeof (*dvl) + num_hops * sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  for (unsigned int i=0;i<num_hops;i++)
  {
    if (0 == memcmp (&dvl->initiator,
		     &hops[i],
		     sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (0 == memcmp (&GST_my_identity,
		     &hops[i],
		     sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_YES;
}


/**
 * Communicator gave us a DV learn message.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param dvl the message that was received
 */
static void
handle_dv_learn (void *cls,
		 const struct TransportDVLearn *dvl)
{
  struct CommunicatorMessageContext *cmc = cls;

  // FIXME: learn path from DV message (if bi-directional flags are set)
  // FIXME: expand DV message, forward on (unless path is getting too long)
  finish_cmc_handling (cmc);
}


/**
 * Communicator gave us a DV box.  Check the message.
 *
 * @param cls a `struct CommunicatorMessageContext`
 * @param dvb the send message that was sent
 * @return #GNUNET_YES if message is well-formed
 */
static int
check_dv_box (void *cls,
	      const struct TransportDVBox *dvb)
{
  uint16_t size = ntohs (dvb->header.size);
  uint16_t num_hops = ntohs (dvb->num_hops);
  const struct GNUNET_PeerIdentity *hops = (const struct GNUNET_PeerIdentity *) &dvb[1];
  const struct GNUNET_MessageHeader *inbox = (const struct GNUNET_MessageHeader *) &hops[num_hops];
  uint16_t isize;
  uint16_t itype;

  if (size < sizeof (*dvb) + num_hops * sizeof (struct GNUNET_PeerIdentity) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  isize = ntohs (inbox->size);
  if (size != sizeof (*dvb) + num_hops * sizeof (struct GNUNET_PeerIdentity) + isize)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  itype = ntohs (inbox->type);
  if ( (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX == itype) ||
       (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN == itype) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Communicator gave us a DV box.  Process the request.
 *
 * @param cls a `struct CommunicatorMessageContext` (must call #finish_cmc_handling() when done)
 * @param dvb the message that was received
 */
static void
handle_dv_box (void *cls,
	       const struct TransportDVBox *dvb)
{
  struct CommunicatorMessageContext *cmc = cls;
  uint16_t size = ntohs (dvb->header.size) - sizeof (*dvb);
  uint16_t num_hops = ntohs (dvb->num_hops);
  const struct GNUNET_PeerIdentity *hops = (const struct GNUNET_PeerIdentity *) &dvb[1];
  const struct GNUNET_MessageHeader *inbox = (const struct GNUNET_MessageHeader *) &hops[num_hops];

  if (num_hops > 0)
  {
    // FIXME: if we are not the target, shorten path and forward along.
    // Try from the _end_ of hops array if we know the given
    // neighbour (shortening the path!).
    // NOTE: increment total_hops!
    finish_cmc_handling (cmc);
    return;
  }
  /* We are the target. Unbox and handle message. */
  cmc->im.sender = dvb->origin;
  cmc->total_hops = ntohs (dvb->total_hops);
  demultiplex_with_cmc (cmc,
			inbox);
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
 * Incoming meessage.  Process the request.
 *
 * @param im the send message that was received
 */
static void
handle_incoming_msg (void *cls,
                     const struct GNUNET_TRANSPORT_IncomingMessage *im)
{
  struct TransportClient *tc = cls;
  struct CommunicatorMessageContext *cmc = GNUNET_new (struct CommunicatorMessageContext);

  cmc->tc = tc;
  cmc->im = *im;
  demultiplex_with_cmc (cmc,
			(const struct GNUNET_MessageHeader *) &im[1]);
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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (fragment_box,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT,
			   struct TransportFragmentBox,
			   &cmc),
    GNUNET_MQ_hd_fixed_size (fragment_ack,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT_ACK,
			     struct TransportFragmentAckMessage,
			     &cmc),
    GNUNET_MQ_hd_var_size (reliability_box,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX,
			   struct TransportReliabilityBox,
			   &cmc),
    GNUNET_MQ_hd_fixed_size (reliability_ack,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK,
			     struct TransportReliabilityAckMessage,
			     &cmc),
    GNUNET_MQ_hd_var_size (backchannel_encapsulation,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION,
			   struct TransportBackchannelEncapsulationMessage,
			   &cmc),
    GNUNET_MQ_hd_var_size (dv_learn,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN,
			   struct TransportDVLearn,
			   &cmc),
    GNUNET_MQ_hd_var_size (dv_box,
			   GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX,
			   struct TransportDVBox,
			   &cmc),
    GNUNET_MQ_handler_end()
  };
  int ret;

  ret = GNUNET_MQ_handle_message (handlers,
				  msg);
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
    handle_raw_message (&cmc,
			msg);
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
 * Bandwidth tracker informs us that the delay until we should receive
 * more has changed.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the delay changed
 */
static void
tracker_update_in_cb (void *cls)
{
  struct GNUNET_ATS_Session *queue = cls;
  struct GNUNET_TIME_Relative in_delay;
  unsigned int rsize;

  rsize = (0 == queue->mtu) ? IN_PACKET_SIZE_WITHOUT_MTU : queue->mtu;
  in_delay = GNUNET_BANDWIDTH_tracker_get_delay (&queue->tracker_in,
						 rsize);
  // FIXME: how exactly do we do inbound flow control?
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
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
			      &pm->msg_uuid,
			      sizeof (pm->msg_uuid));
  pm->msg_uuid_set = GNUNET_YES;
}


/**
 * Fragment the given @a pm to the given @a mtu.  Adds
 * additional fragments to the neighbour as well. If the
 * @a mtu is too small, generates and error for the @a pm
 * and returns NULL.
 *
 * @param pm pending message to fragment for transmission
 * @param mtu MTU to apply
 * @return new message to transmit
 */
static struct PendingMessage *
fragment_message (struct PendingMessage *pm,
		  uint16_t mtu)
{
  struct PendingMessage *ff;

  set_pending_message_uuid (pm);

  /* This invariant is established in #handle_add_queue_message() */
  GNUNET_assert (mtu > sizeof (struct TransportFragmentBox));

  /* select fragment for transmission, descending the tree if it has
     been expanded until we are at a leaf or at a fragment that is small enough */
  ff = pm;
  while ( ( (ff->bytes_msg > mtu) ||
	    (pm == ff) ) &&
	  (ff->frag_off == ff->bytes_msg) &&
	  (NULL != ff->head_frag) )
  {
    ff = ff->head_frag; /* descent into fragmented fragments */
  }

  if ( ( (ff->bytes_msg > mtu) ||
	 (pm == ff) ) &&
       (pm->frag_off < pm->bytes_msg) )
  {
    /* Did not yet calculate all fragments, calculate next fragment */
    struct PendingMessage *frag;
    struct TransportFragmentBox tfb;
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
      const struct TransportFragmentBox *tfbo;

      tfbo = (const struct TransportFragmentBox *) orig;
      orig += sizeof (struct TransportFragmentBox);
      msize -= sizeof (struct TransportFragmentBox);
      xoff = ntohs (tfbo->frag_off);
    }
    fragmax = mtu - sizeof (struct TransportFragmentBox);
    fragsize = GNUNET_MIN (msize - ff->frag_off,
			   fragmax);
    frag = GNUNET_malloc (sizeof (struct PendingMessage) +
			  sizeof (struct TransportFragmentBox) +
			  fragsize);
    frag->target = pm->target;
    frag->frag_parent = ff;
    frag->timeout = pm->timeout;
    frag->bytes_msg = sizeof (struct TransportFragmentBox) + fragsize;
    frag->pmt = PMT_FRAGMENT_BOX;
    msg = (char *) &frag[1];
    tfb.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT);
    tfb.header.size = htons (sizeof (struct TransportFragmentBox) +
			     fragsize);
    tfb.frag_uuid = htonl (pm->frag_uuidgen++);
    tfb.msg_uuid = pm->msg_uuid;
    tfb.frag_off = htons (ff->frag_off + xoff);
    tfb.msg_size = htons (pm->bytes_msg);
    memcpy (msg,
	    &tfb,
	    sizeof (tfb));
    memcpy (&msg[sizeof (tfb)],
	    &orig[ff->frag_off],
	    fragsize);
    GNUNET_CONTAINER_MDLL_insert (frag,
				  ff->head_frag,
				  ff->tail_frag,
				  frag);
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
 * @param pm pending message to box for transmission over unreliabile queue
 * @return new message to transmit
 */
static struct PendingMessage *
reliability_box_message (struct PendingMessage *pm)
{
  struct TransportReliabilityBox rbox;
  struct PendingMessage *bpm;
  char *msg;

  if (PMT_CORE != pm->pmt)
    return pm;  /* already fragmented or reliability boxed, or control message: do nothing */
  if (NULL != pm->bpm)
    return pm->bpm; /* already computed earlier: do nothing */
  GNUNET_assert (NULL == pm->head_frag);
  if (pm->bytes_msg + sizeof (rbox) > UINT16_MAX)
  {
    /* failed hard */
    GNUNET_break (0);
    client_send_response (pm,
			  GNUNET_NO,
			  0);
    return NULL;
  }
  bpm = GNUNET_malloc (sizeof (struct PendingMessage) +
		       sizeof (rbox) +
		       pm->bytes_msg);
  bpm->target = pm->target;
  bpm->frag_parent = pm;
  GNUNET_CONTAINER_MDLL_insert (frag,
				pm->head_frag,
				pm->tail_frag,
				bpm);
  bpm->timeout = pm->timeout;
  bpm->pmt = PMT_RELIABILITY_BOX;
  bpm->bytes_msg = pm->bytes_msg + sizeof (rbox);
  set_pending_message_uuid (bpm);
  rbox.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX);
  rbox.header.size = htons (sizeof (rbox) + pm->bytes_msg);
  rbox.ack_countdown = htonl (0); // FIXME: implement ACK countdown support
  rbox.msg_uuid = pm->msg_uuid;
  msg = (char *) &bpm[1];
  memcpy (msg,
	  &rbox,
	  sizeof (rbox));
  memcpy (&msg[sizeof (rbox)],
	  &pm[1],
	  pm->bytes_msg);
  pm->bpm = bpm;
  return bpm;
}


/**
 * We believe we are ready to transmit a message on a queue. Double-checks
 * with the queue's "tracker_out" and then gives the message to the
 * communicator for transmission (updating the tracker, and re-scheduling
 * itself if applicable).
 *
 * @param cls the `struct GNUNET_ATS_Session` to process transmissions for
 */
static void
transmit_on_queue (void *cls)
{
  struct GNUNET_ATS_Session *queue = cls;
  struct Neighbour *n = queue->neighbour;
  struct QueueEntry *qe;
  struct PendingMessage *pm;
  struct PendingMessage *s;
  uint32_t overhead;
  struct GNUNET_TRANSPORT_SendMessageTo *smt;
  struct GNUNET_MQ_Envelope *env;

  queue->transmit_task = NULL;
  if (NULL == (pm = n->pending_msg_head))
  {
    /* no message pending, nothing to do here! */
    return;
  }
  schedule_transmit_on_queue (queue);
  if (NULL != queue->transmit_task)
    return; /* do it later */
  overhead = 0;
  if (GNUNET_TRANSPORT_CC_RELIABLE != queue->tc->details.communicator.cc)
    overhead += sizeof (struct TransportReliabilityBox);
  s = pm;
  if ( ( (0 != queue->mtu) &&
	 (pm->bytes_msg + overhead > queue->mtu) ) ||
       (pm->bytes_msg > UINT16_MAX - sizeof (struct GNUNET_TRANSPORT_SendMessageTo)) ||
       (NULL != pm->head_frag /* fragments already exist, should
				 respect that even if MTU is 0 for
				 this queue */) )
    s = fragment_message (s,
			  (0 == queue->mtu)
			  ? UINT16_MAX - sizeof (struct GNUNET_TRANSPORT_SendMessageTo)
			  : queue->mtu);
  if (NULL == s)
  {
    /* Fragmentation failed, try next message... */
    schedule_transmit_on_queue (queue);
    return;
  }
  if (GNUNET_TRANSPORT_CC_RELIABLE != queue->tc->details.communicator.cc)
    s = reliability_box_message (s);
  if (NULL == s)
  {
    /* Reliability boxing failed, try next message... */
    schedule_transmit_on_queue (queue);
    return;
  }

  /* Pass 's' for transission to the communicator */
  qe = GNUNET_new (struct QueueEntry);
  qe->mid = queue->mid_gen++;
  qe->session = queue;
  // qe->pm = s; // FIXME: not so easy, reference management on 'free(s)'!
  GNUNET_CONTAINER_DLL_insert (queue->queue_head,
			       queue->queue_tail,
			       qe);
  env = GNUNET_MQ_msg_extra (smt,
			     s->bytes_msg,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG);
  smt->qid = queue->qid;
  smt->mid = qe->mid;
  smt->receiver = n->pid;
  memcpy (&smt[1],
	  &s[1],
	  s->bytes_msg);
  GNUNET_assert (CT_COMMUNICATOR == queue->tc->type);
  queue->queue_length++;
  queue->tc->details.communicator.total_queue_length++;
  GNUNET_MQ_send (queue->tc->mq,
		  env);

  // FIXME: do something similar to the logic below
  // in defragmentation / reliability ACK handling!

  /* Check if this transmission somehow conclusively finished handing 'pm'
     even without any explicit ACKs */
  if ( (PMT_CORE == s->pmt) &&
       (GNUNET_TRANSPORT_CC_RELIABLE == queue->tc->details.communicator.cc) )
  {
    /* Full message sent, and over reliabile channel */
    client_send_response (pm,
			  GNUNET_YES,
			  pm->bytes_msg);
  }
  else if ( (GNUNET_TRANSPORT_CC_RELIABLE == queue->tc->details.communicator.cc) &&
	    (PMT_FRAGMENT_BOX == s->pmt) )
  {
    struct PendingMessage *pos;

    /* Fragment sent over reliabile channel */
    free_fragment_tree (s);
    pos = s->frag_parent;
    GNUNET_CONTAINER_MDLL_remove (frag,
				  pos->head_frag,
				  pos->tail_frag,
				  s);
    GNUNET_free (s);
    /* check if subtree is done */
    while ( (NULL == pos->head_frag) &&
	    (pos->frag_off == pos->bytes_msg) &&
	    (pos != pm) )
    {
      s = pos;
      pos = s->frag_parent;
      GNUNET_CONTAINER_MDLL_remove (frag,
				    pos->head_frag,
				    pos->tail_frag,
				    s);
      GNUNET_free (s);
    }

    /* Was this the last applicable fragmment? */
    if ( (NULL == pm->head_frag) &&
	 (pm->frag_off == pm->bytes_msg) )
      client_send_response (pm,
			    GNUNET_YES,
			    pm->bytes_msg /* FIXME: calculate and add overheads! */);
  }
  else if (PMT_CORE != pm->pmt)
  {
    /* This was an acknowledgement of some type, always free */
    free_pending_message (pm);
  }
  else
  {
    /* message not finished, waiting for acknowledgement */
    struct Neighbour *neighbour = pm->target;
    /* Update time by which we might retransmit 's' based on queue
       characteristics (i.e. RTT); it takes one RTT for the message to
       arrive and the ACK to come back in the best case; but the other
       side is allowed to delay ACKs by 2 RTTs, so we use 4 RTT before
       retransmitting.  Note that in the future this heuristic should
       likely be improved further (measure RTT stability, consider
       message urgency and size when delaying ACKs, etc.) */
    s->next_attempt = GNUNET_TIME_relative_to_absolute
      (GNUNET_TIME_relative_multiply (queue->rtt,
				      4));
    if (s == pm)
    {
      struct PendingMessage *pos;

      /* re-insert sort in neighbour list */
      GNUNET_CONTAINER_MDLL_remove (neighbour,
				    neighbour->pending_msg_head,
				    neighbour->pending_msg_tail,
				    pm);
      pos = neighbour->pending_msg_tail;
      while ( (NULL != pos) &&
	      (pm->next_attempt.abs_value_us > pos->next_attempt.abs_value_us) )
	pos = pos->prev_neighbour;
      GNUNET_CONTAINER_MDLL_insert_after (neighbour,
					  neighbour->pending_msg_head,
					  neighbour->pending_msg_tail,
					  pos,
					  pm);
    }
    else
    {
      /* re-insert sort in fragment list */
      struct PendingMessage *fp = s->frag_parent;
      struct PendingMessage *pos;

      GNUNET_CONTAINER_MDLL_remove (frag,
				    fp->head_frag,
				    fp->tail_frag,
				    s);
      pos = fp->tail_frag;
      while ( (NULL != pos) &&
	      (s->next_attempt.abs_value_us > pos->next_attempt.abs_value_us) )
	pos = pos->prev_frag;
      GNUNET_CONTAINER_MDLL_insert_after (frag,
					  fp->head_frag,
					  fp->tail_frag,
					  pos,
					  s);
    }
  }

  /* finally, re-schedule queue transmission task itself */
  schedule_transmit_on_queue (queue);
}


/**
 * Bandwidth tracker informs us that the delay until we
 * can transmit again changed.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the delay changed
 */
static void
tracker_update_out_cb (void *cls)
{
  struct GNUNET_ATS_Session *queue = cls;
  struct Neighbour *n = queue->neighbour;

  if (NULL == n->pending_msg_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Bandwidth allocation updated for empty transmission queue `%s'\n",
		queue->address);
    return; /* no message pending, nothing to do here! */
  }
  GNUNET_SCHEDULER_cancel (queue->transmit_task);
  queue->transmit_task = NULL;
  schedule_transmit_on_queue (queue);
}


/**
 * Bandwidth tracker informs us that excessive outbound bandwidth was
 * allocated which is not being used.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the excess was noted
 */
static void
tracker_excess_out_cb (void *cls)
{
  /* FIXME: trigger excess bandwidth report to core? Right now,
     this is done internally within transport_api2_core already,
     but we probably want to change the logic and trigger it
     from here via a message instead! */
  /* TODO: maybe inform ATS at this point? */
  GNUNET_STATISTICS_update (GST_stats,
			    "# Excess outbound bandwidth reported",
			    1,
			    GNUNET_NO);
}



/**
 * Bandwidth tracker informs us that excessive inbound bandwidth was allocated
 * which is not being used.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the excess was noted
 */
static void
tracker_excess_in_cb (void *cls)
{
  /* TODO: maybe inform ATS at this point? */
  GNUNET_STATISTICS_update (GST_stats,
			    "# Excess inbound bandwidth reported",
			    1,
			    GNUNET_NO);
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
  struct GNUNET_ATS_Session *queue;
  struct Neighbour *neighbour;
  const char *addr;
  uint16_t addr_len;

  if (ntohl (aqm->mtu) <= sizeof (struct TransportFragmentBox))
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
    neighbour->earliest_timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
    neighbour->pid = aqm->receiver;
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multipeermap_put (neighbours,
						      &neighbour->pid,
 						      neighbour,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    cores_send_connect_info (&neighbour->pid,
			     GNUNET_BANDWIDTH_ZERO);
  }
  addr_len = ntohs (aqm->header.size) - sizeof (*aqm);
  addr = (const char *) &aqm[1];

  queue = GNUNET_malloc (sizeof (struct GNUNET_ATS_Session) + addr_len);
  queue->tc = tc;
  queue->address = (const char *) &queue[1];
  queue->rtt = GNUNET_TIME_UNIT_FOREVER_REL;
  queue->qid = aqm->qid;
  queue->mtu = ntohl (aqm->mtu);
  queue->nt = (enum GNUNET_NetworkType) ntohl (aqm->nt);
  queue->cs = (enum GNUNET_TRANSPORT_ConnectionStatus) ntohl (aqm->cs);
  queue->neighbour = neighbour;
  GNUNET_BANDWIDTH_tracker_init2 (&queue->tracker_in,
                                  &tracker_update_in_cb,
                                  queue,
                                  GNUNET_BANDWIDTH_ZERO,
                                  GNUNET_CONSTANTS_MAX_BANDWIDTH_CARRY_S,
                                  &tracker_excess_in_cb,
                                  queue);
  GNUNET_BANDWIDTH_tracker_init2 (&queue->tracker_out,
                                  &tracker_update_out_cb,
                                  queue,
                                  GNUNET_BANDWIDTH_ZERO,
                                  GNUNET_CONSTANTS_MAX_BANDWIDTH_CARRY_S,
                                  &tracker_excess_out_cb,
                                  queue);
  memcpy (&queue[1],
	  addr,
	  addr_len);
  /* notify ATS about new queue */
  {
    struct GNUNET_ATS_Properties prop = {
      .delay = GNUNET_TIME_UNIT_FOREVER_REL,
      .mtu = queue->mtu,
      .nt = queue->nt,
      .cc = tc->details.communicator.cc
    };

    queue->sr = GNUNET_ATS_session_add (ats,
					&neighbour->pid,
					queue->address,
					queue,
					&prop);
    if  (NULL == queue->sr)
    {
      /* This can only happen if the 'address' was way too long for ATS
	 (approaching 64k in strlen()!). In this case, the communicator
	 must be buggy and we drop it. */
      GNUNET_break (0);
      GNUNET_BANDWIDTH_tracker_notification_stop (&queue->tracker_in);
      GNUNET_BANDWIDTH_tracker_notification_stop (&queue->tracker_out);
      GNUNET_free (queue);
      if (NULL == neighbour->session_head)
      {
	cores_send_disconnect_info (&neighbour->pid);
	free_neighbour (neighbour);
      }
      GNUNET_SERVICE_client_drop (tc->client);
      return;
    }
  }
  /* notify monitors about new queue */
  {
    struct MonitorEvent me = {
      .rtt = queue->rtt,
      .cs = queue->cs
    };

    notify_monitors (&neighbour->pid,
		     queue->address,
		     queue->nt,
		     &me);
  }
  GNUNET_CONTAINER_MDLL_insert (neighbour,
				neighbour->session_head,
				neighbour->session_tail,
				queue);
  GNUNET_CONTAINER_MDLL_insert (client,
				tc->details.communicator.session_head,
				tc->details.communicator.session_tail,
				queue);
  GNUNET_SERVICE_client_continue (tc->client);
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
  for (struct GNUNET_ATS_Session *session = tc->details.communicator.session_head;
       NULL != session;
       session = session->next_client)
  {
    struct Neighbour *neighbour = session->neighbour;

    if ( (dqm->qid != session->qid) ||
	 (0 != memcmp (&dqm->receiver,
		       &neighbour->pid,
		       sizeof (struct GNUNET_PeerIdentity))) )
      continue;
    free_session (session);
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
  struct QueueEntry *queue;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }

  /* find our queue entry matching the ACK */
  queue = NULL;
  for (struct GNUNET_ATS_Session *session = tc->details.communicator.session_head;
       NULL != session;
       session = session->next_client)
  {
    if (0 != memcmp (&session->neighbour->pid,
		     &sma->receiver,
		     sizeof (struct GNUNET_PeerIdentity)))
      continue;
    for (struct QueueEntry *qe = session->queue_head;
	 NULL != qe;
	 qe = qe->next)
    {
      if (qe->mid != sma->mid)
	continue;
      queue = qe;
      break;
    }
    break;
  }
  if (NULL == queue)
  {
    /* this should never happen */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (queue->session->queue_head,
			       queue->session->queue_tail,
			       queue);
  queue->session->queue_length--;
  tc->details.communicator.total_queue_length--;
  GNUNET_SERVICE_client_continue (tc->client);

  /* if applicable, resume transmissions that waited on ACK */
  if (COMMUNICATOR_TOTAL_QUEUE_LIMIT - 1 == tc->details.communicator.total_queue_length)
  {
    /* Communicator dropped below threshold, resume all queues */
    GNUNET_STATISTICS_update (GST_stats,
			      "# Transmission throttled due to communicator queue limit",
			      -1,
			      GNUNET_NO);
    for (struct GNUNET_ATS_Session *session = tc->details.communicator.session_head;
	 NULL != session;
	 session = session->next_client)
      schedule_transmit_on_queue (session);
  }
  else if (SESSION_QUEUE_LIMIT - 1 == queue->session->queue_length)
  {
    /* queue dropped below threshold; only resume this one queue */
    GNUNET_STATISTICS_update (GST_stats,
			      "# Transmission throttled due to session queue limit",
			      -1,
			      GNUNET_NO);
    schedule_transmit_on_queue (queue->session);
  }

  /* TODO: we also should react on the status! */
  // FIXME: this probably requires queue->pm = s assignment!
  // FIXME: react to communicator status about transmission request. We got:
  sma->status; // OK success, SYSERR failure

  GNUNET_free (queue);
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
  for (struct GNUNET_ATS_Session *q = neighbour->session_head;
       NULL != q;
       q = q->next_neighbour)
  {
    struct MonitorEvent me = {
      .rtt = q->rtt,
      .cs = q->cs,
      .num_msg_pending = q->num_msg_pending,
      .num_bytes_pending = q->num_bytes_pending
    };

    notify_monitor (tc,
                    pid,
                    q->address,
                    q->nt,
                    &me);
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
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
					 &notify_client_queues,
					 tc);
  GNUNET_SERVICE_client_mark_monitor (tc->client);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Signature of a function called by ATS with the current bandwidth
 * allocation to be used as determined by ATS.
 *
 * @param cls closure, NULL
 * @param session session this is about
 * @param bandwidth_out assigned outbound bandwidth for the connection,
 *        0 to signal disconnect
 * @param bandwidth_in assigned inbound bandwidth for the connection,
 *        0 to signal disconnect
 */
static void
ats_allocation_cb (void *cls,
                   struct GNUNET_ATS_Session *session,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  (void) cls;
  GNUNET_BANDWIDTH_tracker_update_quota (&session->tracker_out,
                                         bandwidth_out);
  GNUNET_BANDWIDTH_tracker_update_quota (&session->tracker_in,
                                         bandwidth_in);
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
  for (struct TransportClient *tc = clients_head;
       NULL != tc;
       tc = tc->next)
  {
    if (CT_COMMUNICATOR != tc->type)
      continue;
    if (0 == strcmp (prefix,
		     tc->details.communicator.address_prefix))
      return tc;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      "ATS suggested use of communicator for `%s', but we do not have such a communicator!\n",
	      prefix);
  return NULL;
}


/**
 * Signature of a function called by ATS suggesting transport to
 * try connecting with a particular address.
 *
 * @param cls closure, NULL
 * @param pid target peer
 * @param address the address to try
 */
static void
ats_suggestion_cb (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   const char *address)
{
  static uint32_t idgen;
  struct TransportClient *tc;
  char *prefix;
  struct GNUNET_TRANSPORT_CreateQueue *cqm;
  struct GNUNET_MQ_Envelope *env;
  size_t alen;

  (void) cls;
  prefix = GNUNET_HELLO_address_to_prefix (address);
  if (NULL == prefix)
  {
    GNUNET_break (0); /* ATS gave invalid address!? */
    return;
  }
  tc = lookup_communicator (prefix);
  if (NULL == tc)
  {
    GNUNET_STATISTICS_update (GST_stats,
			      "# ATS suggestions ignored due to missing communicator",
			      1,
			      GNUNET_NO);
    return;
  }
  /* forward suggestion for queue creation to communicator */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Request #%u for `%s' communicator to create queue to `%s'\n",
	      (unsigned int) idgen,
	      prefix,
	      address);
  alen = strlen (address) + 1;
  env = GNUNET_MQ_msg_extra (cqm,
			     alen,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE);
  cqm->request_id = htonl (idgen++);
  cqm->receiver = *pid;
  memcpy (&cqm[1],
	  address,
	  alen);
  GNUNET_MQ_send (tc->mq,
		  env);
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
			    "# ATS suggestions succeeded at communicator",
			    1,
			    GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Request #%u for communicator to create queue succeeded\n",
	      (unsigned int) ntohs (cqr->request_id));
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Communicator tells us that our request to create a queue failed. This usually
 * indicates that the provided address is simply invalid or that the communicator's
 * resources are exhausted.
 *
 * @param cls the `struct TransportClient`
 * @param cqr failure message
 */
static void
handle_queue_create_fail (void *cls,
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
			    "# ATS suggestions failed in queue creation at communicator",
			    1,
			    GNUNET_NO);
  GNUNET_SERVICE_client_continue (tc->client);
}


/**
 * Check #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_CONSIDER_VERIFY
 * messages. We do nothing here, real verification is done later.
 *
 * @param cls a `struct TransportClient *`
 * @param msg message to verify
 * @return #GNUNET_OK
 */
static int
check_address_consider_verify (void *cls,
                               const struct GNUNET_TRANSPORT_AddressToVerify *hdr)
{
  (void) cls;
  (void) hdr;
  return GNUNET_OK;
}


/**
 * Given another peers address, consider checking it for validity
 * and then adding it to the Peerstore.
 *
 * @param cls a `struct TransportClient`
 * @param hdr message containing the raw address data and
 *        signature in the body, see #GNUNET_HELLO_extract_address()
 */
static void
handle_address_consider_verify (void *cls,
                                const struct GNUNET_TRANSPORT_AddressToVerify *hdr)
{
  char *address;
  enum GNUNET_NetworkType nt;
  struct GNUNET_TIME_Absolute expiration;

  (void) cls;
  // FIXME: pre-check: do we know this address already?
  // FIXME: pre-check: rate-limit signature verification / validation!
  address = GNUNET_HELLO_extract_address (&hdr[1],
                                          ntohs (hdr->header.size) - sizeof (*hdr),
                                          &hdr->peer,
                                          &nt,
                                          &expiration);
  if (NULL == address)
  {
    GNUNET_break_op (0);
    return;
  }
  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
    return; /* expired */
  // FIXME: do begin actual verification here!
  GNUNET_free (address);
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
 * Free ephemeral entry.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct Neighbour`
 * @return #GNUNET_OK (always)
 */
static int
free_ephemeral_cb (void *cls,
		   const struct GNUNET_PeerIdentity *pid,
		   void *value)
{
  struct EphemeralCacheEntry *ece = value;

  (void) cls;
  (void) pid;
  free_ephemeral (ece);
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
  (void) cls;

  if (NULL != ephemeral_task)
  {
    GNUNET_SCHEDULER_cancel (ephemeral_task);
    ephemeral_task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
					 &free_neighbour_cb,
					 NULL);
  if (NULL != ats)
  {
    GNUNET_ATS_transport_done (ats);
    ats = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore,
				 GNUNET_NO);
    peerstore = NULL;
  }
  if (NULL != GST_stats)
  {
    GNUNET_STATISTICS_destroy (GST_stats,
                               GNUNET_NO);
    GST_stats = NULL;
  }
  if (NULL != GST_my_private_key)
  {
    GNUNET_free (GST_my_private_key);
    GST_my_private_key = NULL;
  }
  GNUNET_CONTAINER_multipeermap_destroy (neighbours);
  neighbours = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (dv_routes,
					 &free_dv_routes_cb,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (dv_routes);
  dv_routes = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (ephemeral_map,
					 &free_ephemeral_cb,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (ephemeral_map);
  ephemeral_map = NULL;
  GNUNET_CONTAINER_heap_destroy (ephemeral_heap);
  ephemeral_heap = NULL;
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
  /* setup globals */
  GST_cfg = c;
  neighbours = GNUNET_CONTAINER_multipeermap_create (1024,
						     GNUNET_YES);
  dv_routes = GNUNET_CONTAINER_multipeermap_create (1024,
						    GNUNET_YES);
  ephemeral_map = GNUNET_CONTAINER_multipeermap_create (32,
                                                        GNUNET_YES);
  ephemeral_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GST_my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (GST_cfg);
  if (NULL == GST_my_private_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (GST_my_private_key,
                                      &GST_my_identity.public_key);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "My identity is `%s'\n",
             GNUNET_i2s_full (&GST_my_identity));
  GST_stats = GNUNET_STATISTICS_create ("transport",
                                        GST_cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  peerstore = GNUNET_PEERSTORE_connect (GST_cfg);
  if (NULL == peerstore)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ats = GNUNET_ATS_transport_init (GST_cfg,
                                   &ats_allocation_cb,
                                   NULL,
                                   &ats_suggestion_cb,
                                   NULL);
  if (NULL == ats)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("transport",
 GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 /* communication with core */
 GNUNET_MQ_hd_fixed_size (client_start,
			  GNUNET_MESSAGE_TYPE_TRANSPORT_START,
			  struct StartMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (client_send,
			GNUNET_MESSAGE_TYPE_TRANSPORT_SEND,
			struct OutboundMessage,
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
 GNUNET_MQ_hd_var_size (address_consider_verify,
			GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_CONSIDER_VERIFY,
			struct GNUNET_TRANSPORT_AddressToVerify,
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
