/*
 This file is part of GNUnet.
 Copyright (C) 2010-2016, 2018 GNUnet e.V.

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
 * Implement:
 * - manage fragmentation/defragmentation, retransmission, track RTT, loss, etc.
 *
 * Easy:
 * - use ATS bandwidth allocation callback and schedule transmissions!
 *
 * Plan:
 * - inform ATS about RTT, goodput/loss, overheads, etc.
 *
 * Later:
 * - change transport-core API to provide proper flow control in both
 *   directions, allow multiple messages per peer simultaneously (tag
 *   confirmations with unique message ID), and replace quota-out with
 *   proper flow control;
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

  /**
   * HMAC over the ciphertext of the encrypted, variable-size
   * body that follows.  Verified via DH of @e target and
   * @e ephemeral_key
   */
  struct GNUNET_HashCode hmac;

  /* Followed by encrypted, variable-size payload */
};


/**
 * Message by which a peer confirms that it is using an
 * ephemeral key.
 */
struct EphemeralConfirmation
{

  /**
   * Purpose is #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * How long is this signature over the ephemeral key
   * valid?
   */
  struct GNUNET_TIME_AbsoluteNBO ephemeral_validity;

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
   * Our current RTT estimate for this ATS session.
   */
  struct GNUNET_TIME_Relative rtt;

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
   * Network type offered by this ATS session.
   */
  enum GNUNET_NetworkType nt;

  /**
   * Connection status for this ATS session.
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
 * A neighbour that at least one communicator is connected to.
 */
struct Neighbour
{

  /**
   * Which peer is this about?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Head of list of messages pending for this neighbour.
   */
  struct PendingMessage *pending_msg_head;

  /**
   * Tail of list of messages pending for this neighbour.
   */
  struct PendingMessage *pending_msg_tail;

  /**
   * Head of DLL of ATS sessions to this peer.
   */
  struct GNUNET_ATS_Session *session_head;

  /**
   * Tail of DLL of ATS sessions to this peer.
   */
  struct GNUNET_ATS_Session *session_tail;

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

};


/**
 * Transmission request from CORE that is awaiting delivery.
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
   * Kept in a MDLL of messages from this @a client.
   */
  struct PendingMessage *next_client;

  /**
   * Kept in a MDLL of messages from this @a client.
   */
  struct PendingMessage *prev_client;

  /**
   * Target of the request.
   */
  struct Neighbour *target;

  /**
   * Client that issued the transmission request.
   */
  struct TransportClient *client;

  /**
   * Size of the original message.
   */
  uint32_t bytes_msg;

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
       * Head of list of messages pending for this client.
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
 * Release memory used by @a neighbour.
 *
 * @param neighbour neighbour entry to free
 */
static void
free_neighbour (struct Neighbour *neighbour)
{
  GNUNET_assert (NULL == neighbour->session_head);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (neighbours,
						       &neighbour->pid,
						       neighbour));
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
 * Free @a queue.
 *
 * @param queue the queue to free
 */
static void
free_queue (struct GNUNET_ATS_Session *queue)
{
  struct Neighbour *neighbour = queue->neighbour;
  struct TransportClient *tc = queue->tc;
  struct MonitorEvent me = {
    .cs = GNUNET_TRANSPORT_CS_DOWN,
    .rtt = GNUNET_TIME_UNIT_FOREVER_REL
  };

  GNUNET_CONTAINER_MDLL_remove (neighbour,
				neighbour->session_head,
				neighbour->session_tail,
				queue);
  GNUNET_CONTAINER_MDLL_remove (client,
				tc->details.communicator.session_head,
				tc->details.communicator.session_tail,
				queue);

  notify_monitors (&neighbour->pid,
		   queue->address,
		   queue->nt,
		   &me);
  GNUNET_BANDWIDTH_tracker_notification_stop (&queue->tracker_in);
  GNUNET_BANDWIDTH_tracker_notification_stop (&queue->tracker_out);
  GNUNET_free (queue);
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
	free_queue (q);
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
    som->bytes_msg = htonl (pm->bytes_msg);
    som->bytes_physical = htonl (bytes_physical);
    som->peer = target->pid;
    GNUNET_MQ_send (tc->mq,
		    env);
    GNUNET_CONTAINER_MDLL_remove (client,
				  tc->details.core.pending_msg_head,
				  tc->details.core.pending_msg_tail,
				  pm);
  }
  GNUNET_CONTAINER_MDLL_remove (neighbour,
				target->pending_msg_head,
				target->pending_msg_tail,
				pm);
  GNUNET_free (pm);
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
  pm = GNUNET_new (struct PendingMessage);
  pm->client = tc;
  pm->target = target;
  pm->bytes_msg = bytes_msg;
  GNUNET_CONTAINER_MDLL_insert (neighbour,
				target->pending_msg_head,
				target->pending_msg_tail,
				pm);
  GNUNET_CONTAINER_MDLL_insert (client,
				tc->details.core.pending_msg_head,
				tc->details.core.pending_msg_tail,
				pm);
  // FIXME: do the work, final continuation with call to:
  client_send_response (pm,
			GNUNET_NO,
			0);
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
 * Address of our peer added.  Test message is well-formed.
 *
 * @param cls the client
 * @param aam the send message that was sent
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
 * Client notified us about transmission from a peer.  Process the request.
 *
 * @param cls the client
 * @param obm the send message that was sent
 */
static int
check_incoming_msg (void *cls,
                    const struct GNUNET_TRANSPORT_IncomingMessage *im)
{
  struct TransportClient *tc = cls;
  uint16_t size;
  const struct GNUNET_MessageHeader *obmm;

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  size = ntohs (im->header.size) - sizeof (*im);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  obmm = (const struct GNUNET_MessageHeader *) &im[1];
  if (size != ntohs (obmm->size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Incoming meessage.  Process the request.
 *
 * @param cls the client
 * @param im the send message that was received
 */
static void
handle_incoming_msg (void *cls,
                     const struct GNUNET_TRANSPORT_IncomingMessage *im)
{
  struct TransportClient *tc = cls;

  GNUNET_SERVICE_client_continue (tc->client);
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
 * Bandwidth tracker informs us that the delay until we
 * can transmit again changed.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the delay changed
 */
static void
tracker_update_cb (void *cls)
{
  struct GNUNET_ATS_Session *queue = cls;

  // FIXME: re-schedule transmission tasks if applicable!
}


/**
 * Bandwidth tracker informs us that excessive bandwidth was allocated
 * which is not being used.
 *
 * @param cls a `struct GNUNET_ATS_Session` for which the excess was noted
 */
static void
tracker_excess_cb (void *cls)
{
  /* FIXME: what do we do? */
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

  neighbour = lookup_neighbour (&aqm->receiver);
  if (NULL == neighbour)
  {
    neighbour = GNUNET_new (struct Neighbour);
    neighbour->pid = aqm->receiver;
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multipeermap_put (neighbours,
						      &neighbour->pid,
 						      neighbour,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    cores_send_connect_info (&neighbour->pid,
			     GNUNET_BANDWIDTH_ZERO);
    // FIXME: notify ATS!
  }
  addr_len = ntohs (aqm->header.size) - sizeof (*aqm);
  addr = (const char *) &aqm[1];

  queue = GNUNET_malloc (sizeof (struct GNUNET_ATS_Session) + addr_len);
  queue->tc = tc;
  queue->address = (const char *) &queue[1];
  queue->rtt = GNUNET_TIME_UNIT_FOREVER_REL;
  queue->qid = aqm->qid;
  queue->mtu = ntohl (aqm->mtu);
  queue->distance = ntohl (aqm->distance);
  queue->nt = (enum GNUNET_NetworkType) ntohl (aqm->nt);
  queue->cs = (enum GNUNET_TRANSPORT_ConnectionStatus) ntohl (aqm->cs);
  queue->neighbour = neighbour;
  GNUNET_BANDWIDTH_tracker_init2 (&queue->tracker_in,
                                  &tracker_update_cb,
                                  queue,
                                  GNUNET_BANDWIDTH_ZERO,
                                  0 /* FIXME: max carry in seconds! */,
                                  &tracker_excess_cb,
                                  queue);
  GNUNET_BANDWIDTH_tracker_init2 (&queue->tracker_out,
                                  &tracker_update_cb,
                                  queue,
                                  GNUNET_BANDWIDTH_ZERO,
                                  0 /* FIXME: max carry in seconds! */,
                                  &tracker_excess_cb,
                                  queue);
  memcpy (&queue[1],
	  addr,
	  addr_len);
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
  // FIXME: possibly transmit queued messages?
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
  for (struct GNUNET_ATS_Session *queue = tc->details.communicator.session_head;
       NULL != queue;
       queue = queue->next_client)
  {
    struct Neighbour *neighbour = queue->neighbour;

    if ( (dqm->qid != queue->qid) ||
	 (0 != memcmp (&dqm->receiver,
		       &neighbour->pid,
		       sizeof (struct GNUNET_PeerIdentity))) )
      continue;
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

  if (CT_COMMUNICATOR != tc->type)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (tc->client);
    return;
  }
  GNUNET_SERVICE_client_continue (tc->client);
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
  GNUNET_break (0); // FIXME: implement
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
  struct TransportClient *tc;
  char *prefix;

  (void) cls;
  prefix = NULL; // FIXME
  tc = lookup_communicator (prefix);
  if (NULL == tc)
  {
    // STATS...
    return;
  }
  // FIXME: forward suggestion to tc
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
