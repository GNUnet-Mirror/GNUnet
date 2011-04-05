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
 * @file transport/gnunet-service-transport.c
 * @brief low-level P2P messaging
 * @author Christian Grothoff
 *
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
#include "gnunet_transport_plugin.h"
#include "transport.h"
#if HAVE_LIBGLPK
#include <glpk.h>
#endif

#define DEBUG_BLACKLIST GNUNET_NO

#define DEBUG_PING_PONG GNUNET_NO

#define DEBUG_TRANSPORT_HELLO GNUNET_NO

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
 * enough so that a drop is virtually never required.  Note that
 * this value must be about as large as 'TOTAL_MSGS' in the
 * 'test_transport_api_reliability.c', otherwise that testcase may
 * fail.
 */
#define MAX_PENDING (128 * 1024)

/**
 * Size of the per-transport blacklist hash maps.
 */
#define TRANSPORT_BLACKLIST_HT_SIZE 16

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
#define QUOTA_VIOLATION_DROP_THRESHOLD 10

/**
 * How long until a HELLO verification attempt should time out?
 * Must be rather small, otherwise a partially successful HELLO
 * validation (some addresses working) might not be available
 * before a client's request for a connection fails for good.
 * Besides, if a single request to an address takes a long time,
 * then the peer is unlikely worthwhile anyway.
 */
#define HELLO_VERIFICATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * How long is a PONG signature valid?  We'll recycle a signature until
 * 1/4 of this time is remaining.  PONGs should expire so that if our
 * external addresses change an adversary cannot replay them indefinitely.
 * OTOH, we don't want to spend too much time generating PONG signatures,
 * so they must have some lifetime to reduce our CPU usage.
 */
#define PONG_SIGNATURE_LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

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
 * Maximum frequency for re-evaluating latencies for all transport addresses.
 */
#define LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

/**
 * Maximum frequency for re-evaluating latencies for connected addresses.
 */
#define CONNECTED_LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

#define VERY_BIG_DOUBLE_VALUE 100000000000LL

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
   * Task used to re-validate addresses, updates latencies and
   * verifies liveness.
   */
  GNUNET_SCHEDULER_TaskIdentifier revalidate_task;

  /**
   * The address.
   */
  const void *addr;

  /**
   * Session (or NULL if no valid session currently exists or if the
   * plugin does not use sessions).
   */
  struct Session *session;

  struct ATS_ressource_cost * ressources;

  /**
   * What was the last latency observed for this address, plugin and peer?
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

  /**
   * Length of addr.
   */
  uint16_t addrlen;

  /**
   * Have we ever estimated the latency of this address?  Used to
   * ensure that the first time we add an address, we immediately
   * probe its latency.
   */
  int8_t estimated;

  /**
   * Are we currently connected via this address?  The first time we
   * successfully transmit or receive data to a peer via a particular
   * address, we set this to GNUNET_YES.  If we later get an error
   * (disconnect notification, transmission failure, timeout), we set
   * it back to GNUNET_NO.
   */
  int8_t connected;

  /**
   * Is this plugin currently busy transmitting to the specific target?
   * GNUNET_NO if not (initial, default state is GNUNET_NO).   Internal
   * messages do not count as 'in transmit'.
   */
  int8_t in_transmit;

  /**
   * Has this address been validated yet?
   */
  int8_t validated;

};


/**
 * Entry in linked list of network addresses for ourselves.  Also
 * includes a cached signature for 'struct TransportPongMessage's.
 */
struct OwnAddressList
{
  /**
   * This is a linked list.
   */
  struct OwnAddressList *next;

  /**
   * How long until we actually auto-expire this address (unless it is
   * re-confirmed by the transport)?
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * How long until the current signature expires? (ZERO if the
   * signature was never created).
   */
  struct GNUNET_TIME_Absolute pong_sig_expires;

  /**
   * Signature for a 'struct TransportPongMessage' for this address.
   */
  struct GNUNET_CRYPTO_RsaSignature pong_signature;

  /**
   * Length of addr.
   */
  uint32_t addrlen;

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
   * Set to GNUNET_YES if we need to scrap the existing list of
   * "addresses" and start fresh when we receive the next address
   * update from a transport.  Set to GNUNET_NO if we should just add
   * the new address to the list and wait for the commit call.
   */
  int rebuild;

  struct ATS_plugin * rc;

  /**
   * Hashmap of blacklisted peers for this particular transport.
   */
  struct GNUNET_CONTAINER_MultiHashMap *blacklist;
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

  /**
   * To which neighbour does this ready list belong to?
   */
  struct NeighbourList *neighbour;
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
   * Buffer for at most one payload message used when we receive
   * payload data before our PING-PONG has succeeded.  We then
   * store such messages in this intermediary buffer until the
   * connection is fully up.
   */
  struct GNUNET_MessageHeader *pre_connect_message_buffer;

  /**
   * Context for peerinfo iteration.
   * NULL after we are done processing peerinfo's information.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;

  /**
   * Public key for this peer.   Valid only if the respective flag is set below.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

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
   * the head of the message queue.  Actually triggered when the
   * transmission is timing out (we trigger instantly when we have
   * a chance of success).
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

  /**
   * How long until we should consider this peer dead
   * (if we don't receive another message in the
   * meantime)?
   */
  struct GNUNET_TIME_Absolute peer_timeout;

  /**
   * Tracker for inbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Tracker in_tracker;

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
   * How often has the other peer (recently) violated the
   * inbound traffic limit?  Incremented by 10 per violation,
   * decremented by 1 per non-violation (for each
   * time interval).
   */
  unsigned int quota_violation_count;

  /**
   * DV distance to this peer (1 if no DV is used).
   */
  uint32_t distance;

  /**
   * Have we seen an PONG from this neighbour in the past (and
   * not had a disconnect since)?
   */
  int received_pong;

  /**
   * Do we have a valid public key for this neighbour?
   */
  int public_key_valid;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Identity of the neighbour.
   */
  struct GNUNET_PeerIdentity peer;

};

/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address we are trying to validate,
 * or an empty address if we are just sending a PING to confirm that a
 * connection which the receiver (of the PING) initiated is still valid.
 */
struct TransportPingMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Challenge code (to ensure fresh reply).
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
 * signature signs our public key, an expiration time and our address.<p>
 *
 * This message is followed by our transport address that the PING tried
 * to confirm (if we liked it).  The address can be empty (zero bytes)
 * if the PING had not address either (and we received the request via
 * a connection that we initiated).
 */
struct TransportPongMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * Challenge code from PING (showing freshness).  Not part of what
   * is signed so that we can re-use signatures.
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What are we signing and why?  Two possible reason codes can be here:
   * GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN to confirm that this is a
   * plausible address for this peer (pid is set to identity of signer); or
   * GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_USING to confirm that this is
   * an address we used to connect to the peer with the given pid.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * When does this signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Either the identity of the peer Who signed this message, or the
   * identity of the peer that we're connected to using the given
   * address (depending on purpose.type).
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Size of address appended to this message (part of what is
   * being signed, hence not redundant).
   */
  uint32_t addrlen;

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
 * Context of currently active requests to peerinfo
 * for validation of HELLOs.
 */
struct CheckHelloValidatedContext;


/**
 * Entry in map of all HELLOs awaiting validation.
 */
struct ValidationEntry
{

  /**
   * NULL if this entry is not part of a larger HELLO validation.
   */
  struct CheckHelloValidatedContext *chvc;

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
   * Session being validated (or NULL for none).
   */
  struct Session *session;

  /**
   * Challenge number we used.
   */
  uint32_t challenge;

  /**
   * Length of addr.
   */
  uint16_t addrlen;

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

  /**
   * Number of validation entries currently referring to this
   * CHVC.
   */
  unsigned int ve_count;
};

struct ATS_ressource_cost
{
	int index;
	int atsi_index;
	struct ATS_ressource_cost * prev;
	struct ATS_ressource_cost * next;
	double c_1;
};

struct ATS_plugin
{
	struct ATS_plugin * prev;
	struct ATS_plugin * next;
	char * short_name;
	struct ATS_ressource_cost * head;
	struct ATS_ressource_cost * tail;
};

struct ATS_quality_metric
{
	int index;
	int atis_index;
	char * name;
};



/**
 * Our HELLO message.
 */
static struct GNUNET_HELLO_Message *our_hello;

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
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

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
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle for ats information
 */
static struct ATS_info *ats;

#if HAVE_LIBGLPK
static struct ATS_quality_metric qm[] =
{
		{1, 1028, "QUALITY_NET_DISTANCE"},
		{2, 1034, "QUALITY_NET_DELAY"},
};
static int available_quality_metrics = 2;
#endif

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
 * @param nexi target peer for which to transmit
 */
static void try_transmission_to_peer (struct NeighbourList *n);


void ats_init ();

void ats_shutdown ( );

void ats_notify_peer_connect (
		const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_TRANSPORT_ATS_Information *ats_data);

void ats_notify_peer_disconnect (
		const struct GNUNET_PeerIdentity *peer);

void ats_notify_ats_data (
		const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_TRANSPORT_ATS_Information *ats_data);

struct ForeignAddressList * ats_get_preferred_address (
		struct NeighbourList *n);

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
 * Is a particular peer blacklisted for a particular transport?
 *
 * @param peer the peer to check for
 * @param plugin the plugin used to connect to the peer
 *
 * @return GNUNET_YES if the peer is blacklisted, GNUNET_NO if not
 */
static int
is_blacklisted (const struct GNUNET_PeerIdentity *peer, struct TransportPlugin *plugin)
{

  if (plugin->blacklist != NULL)
    {
      if (GNUNET_CONTAINER_multihashmap_contains (plugin->blacklist, &peer->hashPubKey) == GNUNET_YES)
        {
#if DEBUG_BLACKLIST
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Peer `%s:%s' is blacklisted!\n",
                      plugin->short_name, GNUNET_i2s (peer));
#endif
          if (stats != NULL)
            GNUNET_STATISTICS_update (stats, "# blacklisted peers refused", 1, GNUNET_NO);
          return GNUNET_YES;
        }
    }

  return GNUNET_NO;
}


static void
add_peer_to_blacklist (struct GNUNET_PeerIdentity *peer, char *transport_name)
{
  struct TransportPlugin *plugin;

  plugin = find_transport(transport_name);
  if (plugin == NULL) /* Nothing to do */
    return;
  if (plugin->blacklist == NULL)
    plugin->blacklist = GNUNET_CONTAINER_multihashmap_create(TRANSPORT_BLACKLIST_HT_SIZE);
  GNUNET_assert(plugin->blacklist != NULL);
  GNUNET_CONTAINER_multihashmap_put(plugin->blacklist, &peer->hashPubKey,
				    NULL,
				    GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
}


/**
 * Read the blacklist file, containing transport:peer entries.
 * Provided the transport is loaded, set up hashmap with these
 * entries to blacklist peers by transport.
 *
 */
static void
read_blacklist_file (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *fn;
  char *data;
  size_t pos;
  size_t colon_pos;
  int tsize;
  struct GNUNET_PeerIdentity pid;
  struct stat frstat;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int entries_found;
  char *transport_name;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "TRANSPORT",
                                               "BLACKLIST_FILE",
                                               &fn))
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Option `%s' in section `%s' not specified!\n",
                  "BLACKLIST_FILE",
                  "TRANSPORT");
#endif
      return;
    }
  if (GNUNET_OK != GNUNET_DISK_file_test (fn))
    GNUNET_DISK_fn_write (fn, NULL, 0, GNUNET_DISK_PERM_USER_READ
        | GNUNET_DISK_PERM_USER_WRITE);
  if (0 != STAT (fn, &frstat))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not read blacklist file `%s'\n"), fn);
      GNUNET_free (fn);
      return;
    }
  if (frstat.st_size == 0)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklist file `%s' is empty.\n"),
                  fn);
#endif
      GNUNET_free (fn);
      return;
    }
  /* FIXME: use mmap */
  data = GNUNET_malloc_large (frstat.st_size);
  GNUNET_assert(data != NULL);
  if (frstat.st_size !=
      GNUNET_DISK_fn_read (fn, data, frstat.st_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to read blacklist from `%s'\n"), fn);
      GNUNET_free (fn);
      GNUNET_free (data);
      return;
    }
  entries_found = 0;
  pos = 0;
  while ((pos < frstat.st_size) && isspace ( (unsigned char) data[pos]))
    pos++;
  while ((frstat.st_size >= sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)) &&
         (pos <= frstat.st_size - sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)))
    {
      colon_pos = pos;
      while ((colon_pos < frstat.st_size) && (data[colon_pos] != ':') && !isspace ( (unsigned char) data[colon_pos]))
        colon_pos++;

      if (colon_pos >= frstat.st_size)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("Syntax error in blacklist file at offset %llu, giving up!\n"),
                      (unsigned long long) colon_pos);
          GNUNET_free (fn);
          GNUNET_free (data);
          return;
        }

      if (isspace( (unsigned char) data[colon_pos]))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Syntax error in blacklist file at offset %llu, skipping bytes.\n"),
                    (unsigned long long) colon_pos);
        pos = colon_pos;
        while ((pos < frstat.st_size) && isspace ( (unsigned char) data[pos]))
          pos++;
        continue;
      }
      tsize = colon_pos - pos;
      if ((pos >= frstat.st_size) || (pos + tsize >= frstat.st_size) || (tsize == 0))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("Syntax error in blacklist file at offset %llu, giving up!\n"),
                      (unsigned long long) colon_pos);
          GNUNET_free (fn);
          GNUNET_free (data);
          return;
        }

      if (tsize < 1)
        continue;

      transport_name = GNUNET_malloc(tsize + 1);
      memcpy(transport_name, &data[pos], tsize);
      pos = colon_pos + 1;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Read transport name %s in blacklist file.\n",
                  transport_name);
#endif
      memcpy (&enc, &data[pos], sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded));
      if (!isspace ( (unsigned char) enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1]))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("Syntax error in blacklist file at offset %llu, skipping bytes.\n"),
                      (unsigned long long) pos);
          pos++;
          while ((pos < frstat.st_size) && (!isspace ( (unsigned char) data[pos])))
            pos++;
          GNUNET_free_non_null(transport_name);
          continue;
        }
      enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] = '\0';
      if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char *) &enc, &pid.hashPubKey))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("Syntax error in blacklist file at offset %llu, skipping bytes `%s'.\n"),
                      (unsigned long long) pos,
                      &enc);
        }
      else
        {
          if (0 != memcmp (&pid,
                           &my_identity,
                           sizeof (struct GNUNET_PeerIdentity)))
            {
              entries_found++;
              add_peer_to_blacklist (&pid,
                                     transport_name);
            }
          else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                          _("Found myself `%s' in blacklist (useless, ignored)\n"),
                          GNUNET_i2s (&pid));
            }
        }
      pos = pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded);
      GNUNET_free_non_null(transport_name);
      while ((pos < frstat.st_size) && isspace ( (unsigned char) data[pos]))
        pos++;
    }
  GNUNET_STATISTICS_update (stats, "# Transport entries blacklisted", entries_found, GNUNET_NO);
  GNUNET_free (data);
  GNUNET_free (fn);
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
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission to client failed, closing connection.\n");
#endif
      /* fatal error with client, free message queue! */
      while (NULL != (q = client->message_queue_head))
        {
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bytes discarded (could not transmit to client)"),
				    ntohs (((const struct GNUNET_MessageHeader*)&q[1])->size),
				    GNUNET_NO);
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
 * Convert an address to a string.
 *
 * @param plugin name of the plugin responsible for the address
 * @param addr binary address
 * @param addr_len number of bytes in addr
 * @return NULL on error, otherwise address string
 */
static const char*
a2s (const char *plugin,
     const void *addr,
     uint16_t addr_len)
{
  struct TransportPlugin *p;

  if (plugin == NULL)
    return NULL;
  p = find_transport (plugin);
  if (p == NULL)
    return NULL;
  return p->api->address_to_string (p->api->cls,
				    addr,
				    addr_len);
}


/**
 * Mark the given FAL entry as 'connected' (and hence preferred for
 * sending); also mark all others for the same peer as 'not connected'
 * (since only one can be preferred).
 *
 * @param fal address to set to 'connected'
 */
static void
mark_address_connected (struct ForeignAddressList *fal)
{
  struct ForeignAddressList *pos;
  int cnt;

  GNUNET_assert (GNUNET_YES == fal->validated);
  if (fal->connected == GNUNET_YES)
    return; /* nothing to do */
  cnt = GNUNET_YES;
  pos = fal->ready_list->addresses;
  while (pos != NULL)
    {
      if (GNUNET_YES == pos->connected)
	{
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Marking address `%s' as no longer connected (due to connect on other address)\n",
		      a2s (pos->ready_list->plugin->short_name,
			   pos->addr,
			   pos->addrlen));
#endif
	  GNUNET_break (cnt == GNUNET_YES);
	  cnt = GNUNET_NO;
	  pos->connected = GNUNET_NO;
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# connected addresses"),
				    -1,
				    GNUNET_NO);
	}
      pos = pos->next;
    }
  fal->connected = GNUNET_YES;
  if (GNUNET_YES == cnt)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# connected addresses"),
				1,
				GNUNET_NO);
    }
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
                  ("Dropping message of type %u and size %u, have %u messages pending (%u is the soft limit)\n"),
		  ntohs (msg->type),
		  ntohs (msg->size),
                  client->message_count,
		  MAX_PENDING);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# messages dropped due to slow client"),
				1,
				GNUNET_NO);
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
 * @param n neighbour to notify about, can be NULL (on failure)
 * @param target target of the transmission
 * @param result status code for the transmission request
 */
static void
transmit_send_ok (struct TransportClient *client,
		  struct NeighbourList *n,
		  const struct GNUNET_PeerIdentity *target,
		  int result)
{
  struct SendOkMessage send_ok_msg;

  send_ok_msg.header.size = htons (sizeof (send_ok_msg));
  send_ok_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK);
  send_ok_msg.success = htonl (result);
  if (n != NULL)
    send_ok_msg.latency = GNUNET_TIME_relative_hton (n->latency);
  else
    send_ok_msg.latency = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_FOREVER_REL);
  send_ok_msg.peer = *target;
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
 *            client responsible for queuing the message
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

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes pending with plugins"),
			    - (int64_t) mq->message_buf_size,
			    GNUNET_NO);
  if (result == GNUNET_OK)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes successfully transmitted by plugins"),
				mq->message_buf_size,
				GNUNET_NO);
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes with transmission failure by plugins"),
				mq->message_buf_size,
				GNUNET_NO);
    }
  if (mq->specific_address != NULL)
    {
      if (result == GNUNET_OK)
	{
	  mq->specific_address->timeout =
	    GNUNET_TIME_relative_to_absolute
	    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
	  if (mq->specific_address->validated == GNUNET_YES)
	    mark_address_connected (mq->specific_address);
	}
      else
	{
	  if (mq->specific_address->connected != GNUNET_NO)
	    {
#if DEBUG_TRANSPORT
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Marking address `%s' as no longer connected (due to transmission problem)\n",
			  a2s (mq->specific_address->ready_list->plugin->short_name,
			       mq->specific_address->addr,
			       mq->specific_address->addrlen));
#endif
	      GNUNET_STATISTICS_update (stats,
					gettext_noop ("# connected addresses"),
					-1,
					GNUNET_NO);
	      mq->specific_address->connected = GNUNET_NO;
	    }
	}
      if (! mq->internal_msg)
	mq->specific_address->in_transmit = GNUNET_NO;
    }
  n = find_neighbour(&mq->neighbour_id);
  if (mq->client != NULL)
    transmit_send_ok (mq->client, n, target, result);
  GNUNET_free (mq);
  if (n != NULL)
    try_transmission_to_peer (n);
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

  /* Hack to prefer unix domain sockets */
  struct ForeignAddressList *unix_address = NULL;

  best_address = NULL;
  while (head != NULL)
    {
      addresses = head->addresses;
      while (addresses != NULL)
        {
          if ( (addresses->timeout.abs_value < now.abs_value) &&
	       (addresses->connected == GNUNET_YES) )
            {
#if DEBUG_TRANSPORT
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Marking long-time inactive connection to `%4s' as down.\n",
                          GNUNET_i2s (&neighbour->id));
#endif
	      GNUNET_STATISTICS_update (stats,
					gettext_noop ("# connected addresses"),
					-1,
					GNUNET_NO);
              addresses->connected = GNUNET_NO;
            }
          addresses = addresses->next;
        }

      addresses = head->addresses;
      while (addresses != NULL)
        {
#if DEBUG_TRANSPORT > 1
	  if (addresses->addr != NULL)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"Have address `%s' for peer `%4s' (status: %d, %d, %d, %u, %llums, %u)\n",
			a2s (head->plugin->short_name,
			     addresses->addr,
			     addresses->addrlen),
			GNUNET_i2s (&neighbour->id),
			addresses->connected,
			addresses->in_transmit,
			addresses->validated,
			addresses->connect_attempts,
			(unsigned long long) addresses->timeout.abs_value,
			(unsigned int) addresses->distance);
#endif
		 if (0==strcmp(head->plugin->short_name,"unix"))
		 {
			 if ((unix_address == NULL) || ((unix_address != NULL) &&
				 (addresses->latency.rel_value < unix_address->latency.rel_value)))
		 		unix_address = addresses;
		 }
          if ( ( (best_address == NULL) ||
		 (addresses->connected == GNUNET_YES) ||
		 (best_address->connected == GNUNET_NO) ) &&
	       (addresses->in_transmit == GNUNET_NO) &&
	       ( (best_address == NULL) ||
		 (addresses->latency.rel_value < best_address->latency.rel_value)) )
	    best_address = addresses;
	  /* FIXME: also give lower-latency addresses that are not
	     connected a chance some times... */
          addresses = addresses->next;
        }
      if (unix_address != NULL)
    	  break;
      head = head->next;
    }
  if (unix_address != NULL)
  {
	  best_address = unix_address;
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Found unix address, forced this address\n");
#endif
  }
  if (best_address != NULL)
    {
#if DEBUG_TRANSPORT

	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Best address found (`%s') has latency of %llu ms.\n",
		  (best_address->addrlen > 0)
		  ? a2s (best_address->ready_list->plugin->short_name,
		       best_address->addr,
		       best_address->addrlen)
		  : "<inbound>",
                  best_address->latency.rel_value);
#endif
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transmission attempts failed (no address)"),
				1,
				GNUNET_NO);
    }

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
try_transmission_to_peer (struct NeighbourList *n)
{
  struct ReadyList *rl;
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;
  ssize_t ret;
  int force_address;

  if (n->messages_head == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmission queue for `%4s' is empty\n",
		  GNUNET_i2s (&neighbour->id));
#endif
      return;                     /* nothing to do */
    }
  rl = NULL;
  mq = n->messages_head;
  force_address = GNUNET_YES;
  if (mq->specific_address == NULL)
    {
	  /* TODO: ADD ATS */
      mq->specific_address = ats_get_preferred_address(n);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transport selected peer address freely"),
				1,
				GNUNET_NO);
      force_address = GNUNET_NO;
    }
  if (mq->specific_address == NULL)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transport failed to selected peer address"),
				1,
				GNUNET_NO);
      timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
      if (timeout.rel_value == 0)
	{
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "No destination address available to transmit message of size %u to peer `%4s'\n",
		      mq->message_buf_size,
		      GNUNET_i2s (&mq->neighbour_id));
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bytes in message queue for other peers"),
				    - (int64_t) mq->message_buf_size,
				    GNUNET_NO);
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bytes discarded (no destination address available)"),
				    mq->message_buf_size,
				    GNUNET_NO);
	  if (mq->client != NULL)
	    transmit_send_ok (mq->client, n, &n->id, GNUNET_NO);
	  GNUNET_CONTAINER_DLL_remove (n->messages_head,
				       n->messages_tail,
				       mq);
	  GNUNET_free (mq);
	  return;               /* nobody ready */
	}
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# message delivery deferred (no address)"),
				1,
				GNUNET_NO);
      if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (n->retry_task);
      n->retry_task = GNUNET_SCHEDULER_add_delayed (timeout,
							    &retry_transmission_task,
							    n);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No validated destination address available to transmit message of size %u to peer `%4s', will wait %llums to find an address.\n",
		  mq->message_buf_size,
		  GNUNET_i2s (&mq->neighbour_id),
		  timeout.rel_value);
#endif
      /* FIXME: might want to trigger peerinfo lookup here
	 (unless that's already pending...) */
      return;
    }
  GNUNET_CONTAINER_DLL_remove (n->messages_head,
			       n->messages_tail,
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
	      (mq->specific_address->addr != NULL)
	      ? a2s (mq->plugin->short_name,
		     mq->specific_address->addr,
		     mq->specific_address->addrlen)
	      : "<inbound>",
	      rl->plugin->short_name);
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes in message queue for other peers"),
			    - (int64_t) mq->message_buf_size,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes pending with plugins"),
			    mq->message_buf_size,
			    GNUNET_NO);
  ret = rl->plugin->api->send (rl->plugin->api->cls,
			       &mq->neighbour_id,
			       mq->message_buf,
			       mq->message_buf_size,
			       mq->priority,
			       GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
			       mq->specific_address->session,
			       mq->specific_address->addr,
			       mq->specific_address->addrlen,
			       force_address,
			       &transmit_send_continuation, mq);
  if (ret == -1)
    {
      /* failure, but 'send' would not call continuation in this case,
	 so we need to do it here! */
      transmit_send_continuation (mq,
				  &mq->neighbour_id,
				  GNUNET_SYSERR);
    }
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
                 before getting SEND_OK! */
              GNUNET_break (0);
              return;
            }
          mq = mq->next;
        }
    }
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes in message queue for other peers"),
			    message_buf_size,
			    GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + message_buf_size);
  mq->specific_address = peer_address;
  mq->client = client;
  /* FIXME: this memcpy can be up to 7% of our total runtime! */
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
                                  &gc->addr_pos[1],
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
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# refreshed my HELLO"),
			    1,
			    GNUNET_NO);
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
  GNUNET_PEERINFO_add_peer (peerinfo, our_hello);
  npos = neighbours;
  while (npos != NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Transmitting updated `%s' to neighbour `%4s'\n",
                  "HELLO", GNUNET_i2s (&npos->id));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transmitted my HELLO to other peers"),
				1,
				GNUNET_NO);
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
update_addresses (struct TransportPlugin *plugin, 
		  int fresh)
{
  static struct GNUNET_TIME_Absolute last_update;
  struct GNUNET_TIME_Relative min_remaining;
  struct GNUNET_TIME_Relative remaining;
  struct GNUNET_TIME_Absolute now;
  struct OwnAddressList *pos;
  struct OwnAddressList *prev;
  struct OwnAddressList *next;
  int expired;

  if (plugin->address_update_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (plugin->address_update_task);
  plugin->address_update_task = GNUNET_SCHEDULER_NO_TASK;
  now = GNUNET_TIME_absolute_get ();
  min_remaining = GNUNET_TIME_UNIT_FOREVER_REL;
  expired = (GNUNET_TIME_absolute_get_duration (last_update).rel_value > (HELLO_ADDRESS_EXPIRATION.rel_value / 4));
  prev = NULL;
  pos = plugin->addresses;
  while (pos != NULL)
    {
      next = pos->next;
      if (pos->expires.abs_value < now.abs_value)
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
          if (remaining.rel_value < min_remaining.rel_value)
            min_remaining = remaining;
          prev = pos;
        }
      pos = next;
    }

  if (expired || fresh)
    {
      last_update = now;
      refresh_hello ();
    }
  min_remaining = GNUNET_TIME_relative_min (min_remaining,
					    GNUNET_TIME_relative_divide (HELLO_ADDRESS_EXPIRATION,
									 2));
  plugin->address_update_task
    = GNUNET_SCHEDULER_add_delayed (min_remaining,
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
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    update_addresses (plugin, GNUNET_NO);
}


/**
 * Iterator over hash map entries that NULLs the session of validation
 * entries that match the given session.
 *
 * @param cls closure (the 'struct Session*' to match against)
 * @param key current key code (peer ID, not used)
 * @param value value in the hash map ('struct ValidationEntry*')
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
remove_session_validations (void *cls,
			    const GNUNET_HashCode * key,
			    void *value)
{
  struct Session *session = cls;
  struct ValidationEntry *ve = value;

  if (session == ve->session)
    ve->session = NULL;
  return GNUNET_YES;
}


/**
 * We've been disconnected from the other peer (for some
 * connection-oriented transport).  Either quickly
 * re-establish the connection or signal the disconnect
 * to the CORE.
 *
 * Only signal CORE level disconnect if ALL addresses
 * for the peer are exhausted.
 *
 * @param p overall plugin context
 * @param nl neighbour that was disconnected
 */
static void
try_fast_reconnect (struct TransportPlugin *p,
		    struct NeighbourList *nl)
{
  /* FIXME-MW: fast reconnect / transport switching not implemented... */
  /* Note: the idea here is to hide problems with transports (or
     switching between plugins) from the core to eliminate the need to
     re-negotiate session keys and the like; OTOH, we should tell core
     quickly (much faster than timeout) `if a connection was lost and
     could not be re-established (i.e. other peer went down or is
     unable / refuses to communicate);

     So we should consider:
     1) ideally: our own willingness / need to connect
     2) prior failures to connect to this peer (by plugin)
     3) ideally: reasons why other peer terminated (as far as knowable)

     Most importantly, it must be POSSIBLE for another peer to terminate
     a connection for a while (without us instantly re-establishing it).
     Similarly, if another peer is gone we should quickly notify CORE.
     OTOH, if there was a minor glitch (i.e. crash of gnunet-service-transport
     on the other end), we should reconnect in such a way that BOTH CORE
     services never even notice.
     Furthermore, the same mechanism (or small variation) could be used
     to switch to a better-performing plugin (ATS).

     Finally, this needs to be tested throughly... */     							

  /*
   * GNUNET_NO in the call below makes transport disconnect the peer,
   * even if only a single address (out of say, six) went away.  This
   * function must be careful to ONLY disconnect if the peer is gone,
   * not just a specifi address.
   *
   * More specifically, half the places it was used had it WRONG.
   */

  /* No reconnect, signal disconnect instead! */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "Disconnecting peer `%4s', %s\n", GNUNET_i2s(&nl->id),
            "try_fast_reconnect");
  disconnect_neighbour (nl, GNUNET_YES);
}


/**
 * Function that will be called whenever the plugin internally
 * cleans up a session pointer and hence the service needs to
 * discard all of those sessions as well.  Plugins that do not
 * use sessions can simply omit calling this function and always
 * use NULL wherever a session pointer is needed.
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being destoyed
 */
static void
plugin_env_session_end  (void *cls,
			 const struct GNUNET_PeerIdentity *peer,
			 struct Session *session)
{
  struct TransportPlugin *p = cls;
  struct NeighbourList *nl;
  struct ReadyList *rl;
  struct ForeignAddressList *pos;
  struct ForeignAddressList *prev;

  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
					 &remove_session_validations,
					 session);
  nl = find_neighbour (peer);
  if (nl == NULL)
    return; /* was never marked as connected */
  rl = nl->plugins;
  while (rl != NULL)
    {
      if (rl->plugin == p)
	break;
      rl = rl->next;
    }
  if (rl == NULL)
    return; /* was never marked as connected */
  prev = NULL;
  pos = rl->addresses;
  while ( (pos != NULL) &&
	  (pos->session != session) )
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    return; /* was never marked as connected */
  pos->session = NULL;
  if (pos->addrlen != 0)
    {
      if (nl->received_pong != GNUNET_NO)
	try_fast_reconnect (p, nl);
      return;
    }
  /* was inbound connection, free 'pos' */
  if (prev == NULL)
    rl->addresses = pos->next;
  else
    prev->next = pos->next;
  if (GNUNET_SCHEDULER_NO_TASK != pos->revalidate_task)
    {
      GNUNET_SCHEDULER_cancel (pos->revalidate_task);
      pos->revalidate_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_free (pos);
  if (nl->received_pong == GNUNET_NO)
    return; /* nothing to do, never connected... */
  /* check if we have any validated addresses left */
  pos = rl->addresses;
  while (pos != NULL)
    {
      if (pos->validated)
	{
	  try_fast_reconnect (p, nl);
	  return;
	}
      pos = pos->next;
    }
  /* no valid addresses left, signal disconnect! */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "Disconnecting peer `%4s', %s\n", GNUNET_i2s(&nl->id),
            "plugin_env_session_end");
  /* FIXME: This doesn't mean there are no addresses left for this PEER,
   * it means there aren't any left for this PLUGIN/PEER combination! So
   * calling disconnect_neighbor here with GNUNET_NO forces disconnect
   * when it isn't necessary. Using GNUNET_YES at least checks to see
   * if there are any addresses that work first, so as not to overdo it.
   * --NE
   */
  disconnect_neighbour (nl, GNUNET_YES);
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
                           uint16_t addrlen,
                           struct GNUNET_TIME_Relative expires)
{
  struct TransportPlugin *p = cls;
  struct OwnAddressList *al;
  struct GNUNET_TIME_Absolute abex;

  GNUNET_assert (addr != NULL);
  abex = GNUNET_TIME_relative_to_absolute (expires);
  GNUNET_assert (p == find_transport (name));
  al = p->addresses;
  while (al != NULL)
    {
      if ( (addrlen == al->addrlen) && 
	   (0 == memcmp (addr, &al[1], addrlen)) )
        {	      
	  al->expires = abex;
	  update_addresses (p, GNUNET_NO);
          return;
        }
      al = al->next;
    }
  al = GNUNET_malloc (sizeof (struct OwnAddressList) + addrlen);
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
  struct ConnectInfoMessage * cim;
  struct TransportClient *cpos;
  uint32_t ats_count;
  size_t size;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Notifying clients about connection from `%s'\n",
	      GNUNET_i2s (peer));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# peers connected"),
			    1,
			    GNUNET_NO);

  ats_count = 2;
  size  = sizeof (struct ConnectInfoMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
	  GNUNET_break(0);
  }
  cim = GNUNET_malloc (size);

  cim->header.size = htons (size);
  cim->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  cim->ats_count = htonl(2);
  (&(cim->ats))[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  (&(cim->ats))[0].value = htonl (distance);
  (&(cim->ats))[1].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY);
  (&(cim->ats))[1].value = htonl ((uint32_t) latency.rel_value);
  (&(cim->ats))[2].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  (&(cim->ats))[2].value = htonl (0);
  memcpy (&cim->id, peer, sizeof (struct GNUNET_PeerIdentity));

  /* notify ats about connecting peer */
  ats_notify_peer_connect (peer, &(cim->ats));

  cpos = clients;
  while (cpos != NULL)
    {
      transmit_to_client (cpos, &(cim->header), GNUNET_NO);
      cpos = cpos->next;
    }

  GNUNET_free (cim);
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
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# peers connected"),
			    -1,
			    GNUNET_NO);
  dim.header.size = htons (sizeof (struct DisconnectInfoMessage));
  dim.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  dim.reserved = htonl (0);
  memcpy (&dim.peer, peer, sizeof (struct GNUNET_PeerIdentity));

  /* notify ats about connecting peer */
  ats_notify_peer_disconnect (peer);

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
 * @param session session to look for, NULL for 'any'; otherwise
 *        can be used for the service to "learn" this session ID
 *        if 'addr' matches
 * @param addr binary address
 * @param addrlen length of addr
 * @return NULL if no such entry exists
 */
static struct ForeignAddressList *
find_peer_address(struct NeighbourList *neighbour,
		  const char *tname,
		  struct Session *session,
		  const char *addr,
		  uint16_t addrlen)
{
  struct ReadyList *head;
  struct ForeignAddressList *pos;

  head = neighbour->plugins;
  while (head != NULL)
    {
      if (0 == strcmp (tname, head->plugin->short_name))
	break;
      head = head->next;
    }
  if (head == NULL)
    return NULL;
  pos = head->addresses;
  while ( (pos != NULL) &&
	  ( (pos->addrlen != addrlen) ||
	    (memcmp(pos->addr, addr, addrlen) != 0) ) )
    {
      if ( (session != NULL) &&
	   (pos->session == session) )
	return pos;
      pos = pos->next;
    }
  if ( (session != NULL) && (pos != NULL) )
    pos->session = session; /* learn it! */
  return pos;
}


/**
 * Get the peer address struct for the given neighbour and
 * address.  If it doesn't yet exist, create it.
 *
 * @param neighbour which peer we care about
 * @param tname name of the transport plugin
 * @param session session of the plugin, or NULL for none
 * @param addr binary address
 * @param addrlen length of addr
 * @return NULL if we do not have a transport plugin for 'tname'
 */
static struct ForeignAddressList *
add_peer_address (struct NeighbourList *neighbour,
		  const char *tname,
		  struct Session *session,
		  const char *addr,
		  uint16_t addrlen)
{
  struct ReadyList *head;
  struct ForeignAddressList *ret;

  ret = find_peer_address (neighbour, tname, session, addr, addrlen);
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
  ret->session = session;
  if (addrlen > 0)
    {
      ret->addr = (const char*) &ret[1];
      memcpy (&ret[1], addr, addrlen);
    }
  else
    {
      ret->addr = NULL;
    }
  ret->ressources = NULL;
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
   * Session, or NULL.
   */
  struct Session *session;

  /**
   * Set to GNUNET_YES if the address exists.
   */
  int exists;

  /**
   * Length of addr.
   */
  uint16_t addrlen;

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
  if ( (ve->session != NULL) &&
       (caec->session == ve->session) )
    {
      caec->exists = GNUNET_YES;
      return GNUNET_NO;
    }
  return GNUNET_YES;
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

  if (GNUNET_SCHEDULER_NO_TASK != va->timeout_task)
    GNUNET_SCHEDULER_cancel (va->timeout_task);
  GNUNET_free (va->transport_name);
  if (va->chvc != NULL)
    {
      va->chvc->ve_count--;
      if (va->chvc->ve_count == 0)
	{
	  GNUNET_CONTAINER_DLL_remove (chvc_head,
				       chvc_tail,
				       va->chvc);
	  GNUNET_free (va->chvc);
	}
      va->chvc = NULL;
    }
  GNUNET_free (va);
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

  va->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# address validation timeouts"),
			    1,
			    GNUNET_NO);
  GNUNET_CRYPTO_hash (&va->publicKey,
		      sizeof (struct
			      GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &pid.hashPubKey);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_remove (validation_map,
						      &pid.hashPubKey,
						      va));
  abort_validation (NULL, NULL, va);
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
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# disconnects due to timeout"),
			    1,
			    GNUNET_NO);
  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  disconnect_neighbour (n, GNUNET_NO);
}


/**
 * Schedule the job that will cause us to send a PING to the
 * foreign address to evaluate its validity and latency.
 *
 * @param fal address to PING
 */
static void
schedule_next_ping (struct ForeignAddressList *fal);


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
			     const void *addr,
			     uint16_t addrlen)
{
  struct NeighbourList *n = cls;
  struct ForeignAddressList *fal;
  int try;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# valid peer addresses returned by PEERINFO"),
			    1,
			    GNUNET_NO);
  try = GNUNET_NO;
  fal = find_peer_address (n, tname, NULL, addr, addrlen);
  if (fal == NULL)
    {
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Adding address `%s' (%s) for peer `%4s' due to PEERINFO data for %llums.\n",
		  a2s (tname, addr, addrlen),
		  tname,
		  GNUNET_i2s (&n->id),
		  expiration.abs_value);
#endif
      fal = add_peer_address (n, tname, NULL, addr, addrlen);
      if (fal == NULL)
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# previously validated addresses lacking transport"),
				    1,
				    GNUNET_NO);
	}
      else
	{
	  fal->expires = GNUNET_TIME_absolute_max (expiration,
						   fal->expires);
	  schedule_next_ping (fal);
	}
      try = GNUNET_YES;
    }
  else
    {
      fal->expires = GNUNET_TIME_absolute_max (expiration,
					       fal->expires);
    }
  if (fal == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Failed to add new address for `%4s'\n",
		  GNUNET_i2s (&n->id));
      return GNUNET_OK;
    }
  if (fal->validated == GNUNET_NO)
    {
      fal->validated = GNUNET_YES;
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# peer addresses considered valid"),
				1,
				GNUNET_NO);
    }
  if (try == GNUNET_YES)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Have new addresses, will try to trigger transmissions.\n");
      try_transmission_to_peer (n);
    }
  return GNUNET_OK;
}


/**
 * Add addresses in validated HELLO "h" to the set of addresses
 * we have for this peer.
 *
 * @param cls closure ('struct NeighbourList*')
 * @param peer id of the peer, NULL for last call
 * @param h hello message for the peer (can be NULL)
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
add_hello_for_peer (void *cls,
		    const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_HELLO_Message *h,
		    const char *err_msg)
{
  struct NeighbourList *n = cls;

  if (err_msg != NULL)
  {
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      _("Error in communication with PEERINFO service\n"));
	/* return; */
  }
  if ((peer == NULL))
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# outstanding peerinfo iterate requests"),
                                -1,
                                GNUNET_NO);
      n->piter = NULL;
      return;
    }
  if (h == NULL)
    return; /* no HELLO available */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peerinfo had `%s' message for peer `%4s', adding existing addresses.\n",
	      "HELLO",
	      GNUNET_i2s (peer));
#endif
  if (GNUNET_YES != n->public_key_valid)
    {
      GNUNET_HELLO_get_key (h, &n->publicKey);
      n->public_key_valid = GNUNET_YES;
    }
  GNUNET_HELLO_iterate_addresses (h,
				  GNUNET_NO,
				  &add_to_foreign_address_list,
				  n);
}


/**
 * Create a fresh entry in our neighbour list for the given peer.
 * Will try to transmit our current HELLO to the new neighbour.
 * Do not call this function directly, use 'setup_peer_check_blacklist.
 *
 * @param peer the peer for which we create the entry
 * @param do_hello should we schedule transmitting a HELLO
 * @return the new neighbour list entry
 */
static struct NeighbourList *
setup_new_neighbour (const struct GNUNET_PeerIdentity *peer,
		     int do_hello)
{
  struct NeighbourList *n;
  struct TransportPlugin *tp;
  struct ReadyList *rl;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Setting up state for neighbour `%4s'\n",
	      GNUNET_i2s (peer));
#endif
  GNUNET_assert (our_hello != NULL);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# active neighbours"),
			    1,
			    GNUNET_NO);
  n = GNUNET_malloc (sizeof (struct NeighbourList));
  n->next = neighbours;
  neighbours = n;
  n->id = *peer;
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
				 GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
				 MAX_BANDWIDTH_CARRY_S);
  tp = plugins;
  while (tp != NULL)
    {
      if ((tp->api->send != NULL) && (!is_blacklisted(peer, tp)))
        {
          rl = GNUNET_malloc (sizeof (struct ReadyList));
	  rl->neighbour = n;
          rl->next = n->plugins;
          n->plugins = rl;
          rl->plugin = tp;
          rl->addresses = NULL;
        }
      tp = tp->next;
    }
  n->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  n->distance = -1;
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                  &neighbour_timeout_task, n);
  if (do_hello)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# peerinfo new neighbor iterate requests"),
                                1,
                                GNUNET_NO);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# outstanding peerinfo iterate requests"),
                                1,
                                GNUNET_NO);
      n->piter = GNUNET_PEERINFO_iterate (peerinfo, peer,
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  &add_hello_for_peer, n);

      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# HELLO's sent to new neighbors"),
                                1,
                                GNUNET_NO);
      transmit_to_peer (NULL, NULL, 0,
			HELLO_ADDRESS_EXPIRATION,
			(const char *) our_hello, GNUNET_HELLO_size(our_hello),
			GNUNET_NO, n);
    }
  return n;
}


/**
 * Function called after we have checked if communicating
 * with a given peer is acceptable.
 *
 * @param cls closure
 * @param n NULL if communication is not acceptable
 */
typedef void (*SetupContinuation)(void *cls,
				  struct NeighbourList *n);


/**
 * Information kept for each client registered to perform
 * blacklisting.
 */
struct Blacklisters
{
  /**
   * This is a linked list.
   */
  struct Blacklisters *next;

  /**
   * This is a linked list.
   */
  struct Blacklisters *prev;

  /**
   * Client responsible for this entry.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Blacklist check that we're currently performing.
   */
  struct BlacklistCheck *bc;

};


/**
 * Head of DLL of blacklisting clients.
 */
static struct Blacklisters *bl_head;

/**
 * Tail of DLL of blacklisting clients.
 */
static struct Blacklisters *bl_tail;


/**
 * Context we use when performing a blacklist check.
 */
struct BlacklistCheck
{

  /**
   * This is a linked list.
   */
  struct BlacklistCheck *next;

  /**
   * This is a linked list.
   */
  struct BlacklistCheck *prev;

  /**
   * Peer being checked.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Option for setup neighbour afterwards.
   */
  int do_hello;

  /**
   * Continuation to call with the result.
   */
  SetupContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * Current transmission request handle for this client, or NULL if no
   * request is pending.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

  /**
   * Our current position in the blacklisters list.
   */
  struct Blacklisters *bl_pos;

  /**
   * Current task performing the check.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

};

/**
 * Head of DLL of active blacklisting queries.
 */
static struct BlacklistCheck *bc_head;

/**
 * Tail of DLL of active blacklisting queries.
 */
static struct BlacklistCheck *bc_tail;


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the 'struct BlacklistCheck*'
 * @param tc unused
 */
static void
do_blacklist_check (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Transmit blacklist query to the client.
 *
 * @param cls the 'struct BlacklistCheck'
 * @param size number of bytes allowed
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
transmit_blacklist_message (void *cls,
			    size_t size,
			    void *buf)
{
  struct BlacklistCheck *bc = cls;
  struct Blacklisters *bl;
  struct BlacklistMessage bm;

  bc->th = NULL;
  if (size == 0)
    {
      GNUNET_assert (bc->task == GNUNET_SCHEDULER_NO_TASK);
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					   bc);
      return 0;
    }
  bl = bc->bl_pos;
  bm.header.size = htons (sizeof (struct BlacklistMessage));
  bm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY);
  bm.is_allowed = htonl (0);
  bm.peer = bc->peer;
  memcpy (buf, &bm, sizeof (bm));
  GNUNET_SERVER_receive_done (bl->client, GNUNET_OK);
  return sizeof (bm);
}


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the 'struct BlacklistCheck*'
 * @param tc unused
 */
static void
do_blacklist_check (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BlacklistCheck *bc = cls;
  struct Blacklisters *bl;

  bc->task = GNUNET_SCHEDULER_NO_TASK;
  bl = bc->bl_pos;
  if (bl == NULL)
    {
      bc->cont (bc->cont_cls,
		setup_new_neighbour (&bc->peer, bc->do_hello));		
      GNUNET_free (bc);
      return;
    }
  if (bl->bc == NULL)
    {
      bl->bc = bc;
      bc->th = GNUNET_SERVER_notify_transmit_ready (bl->client,
						    sizeof (struct BlacklistMessage),
						    GNUNET_TIME_UNIT_FOREVER_REL,
						    &transmit_blacklist_message,
						    bc);
    }
}


/**
 * Obtain a 'struct NeighbourList' for the given peer.  If such an entry
 * does not yet exist, check the blacklist.  If the blacklist says creating
 * one is acceptable, create one and call the continuation; otherwise
 * call the continuation with NULL.
 *
 * @param peer peer to setup or look up a struct NeighbourList for
 * @param do_hello should we also schedule sending our HELLO to the peer
 *        if this is a new record
 * @param cont function to call with the 'struct NeigbhbourList*'
 * @param cont_cls closure for cont
 */
static void
setup_peer_check_blacklist (const struct GNUNET_PeerIdentity *peer,
			    int do_hello,
			    SetupContinuation cont,
			    void *cont_cls)
{
  struct NeighbourList *n;
  struct BlacklistCheck *bc;

  n = find_neighbour(peer);
  if (n != NULL)
    {
      if (cont != NULL)
        cont (cont_cls, n);
      return;
    }
  if (bl_head == NULL)
    {
      if (cont != NULL)
        cont (cont_cls, setup_new_neighbour (peer, do_hello));
      else
        setup_new_neighbour(peer, do_hello);
      return;
    }
  bc = GNUNET_malloc (sizeof (struct BlacklistCheck));
  GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, bc);
  bc->peer = *peer;
  bc->do_hello = do_hello;
  bc->cont = cont;
  bc->cont_cls = cont_cls;
  bc->bl_pos = bl_head;
  bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
				       bc);
}


/**
 * Function called with the result of querying a new blacklister about
 * it being allowed (or not) to continue to talk to an existing neighbour.
 *
 * @param cls the original 'struct NeighbourList'
 * @param n NULL if we need to disconnect
 */
static void
confirm_or_drop_neighbour (void *cls,
			   struct NeighbourList *n)
{
  struct NeighbourList * orig = cls;

  if (n == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting peer `%4s', %s\n", GNUNET_i2s(&orig->id),
              "confirm_or_drop_neighboUr");
      disconnect_neighbour (orig, GNUNET_NO);
    }
}


/**
 * Handle a request to start a blacklist.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_blacklist_init (void *cls,
		       struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  struct Blacklisters *bl;
  struct BlacklistCheck *bc;
  struct NeighbourList *n;

  bl = bl_head;
  while (bl != NULL)
    {
      if (bl->client == client)
	{
	  GNUNET_break (0);
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
	  return;
	}
      bl = bl->next;
    }
  bl = GNUNET_malloc (sizeof (struct Blacklisters));
  bl->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert_after (bl_head, bl_tail, bl_tail, bl);
  /* confirm that all existing connections are OK! */
  n = neighbours;
  while (NULL != n)
    {
      bc = GNUNET_malloc (sizeof (struct BlacklistCheck));
      GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, bc);
      bc->peer = n->id;
      bc->do_hello = GNUNET_NO;
      bc->cont = &confirm_or_drop_neighbour;
      bc->cont_cls = n;
      bc->bl_pos = bl;
      if (n == neighbours) /* all would wait for the same client, no need to
			      create more than just the first task right now */
	bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					     bc);
      n = n->next;
    }
}


/**
 * Handle a request to blacklist a peer.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_blacklist_reply (void *cls,
			struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
{
  const struct BlacklistMessage *msg = (const struct BlacklistMessage*) message;
  struct Blacklisters *bl;
  struct BlacklistCheck *bc;

  bl = bl_head;
  while ( (bl != NULL) &&
	  (bl->client != client) )
    bl = bl->next;
  if (bl == NULL)
    {
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  bc = bl->bc;
  bl->bc = NULL;
  if (ntohl (msg->is_allowed) == GNUNET_SYSERR)
    {
      bc->cont (bc->cont_cls, NULL);
      GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, bc);
      GNUNET_free (bc);
    }
  else
    {
      bc->bl_pos = bc->bl_pos->next;
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					   bc);
    }
  /* check if any other bc's are waiting for this blacklister */
  bc = bc_head;
  while (bc != NULL)
    {
      if ( (bc->bl_pos == bl) &&
	   (GNUNET_SCHEDULER_NO_TASK == bc->task) )
	bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
					     bc);
      bc = bc->next;
    }
}


/**
 * Send periodic PING messages to a given foreign address.
 *
 * @param cls our 'struct PeriodicValidationContext*'
 * @param tc task context
 */
static void
send_periodic_ping (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForeignAddressList *peer_address = cls;
  struct TransportPlugin *tp;
  struct ValidationEntry *va;
  struct NeighbourList *neighbour;
  struct TransportPingMessage ping;
  struct CheckAddressExistsClosure caec;
  char * message_buf;
  uint16_t hello_size;
  size_t slen;
  size_t tsize;

  peer_address->revalidate_task = GNUNET_SCHEDULER_NO_TASK;
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;
  tp = peer_address->ready_list->plugin;
  neighbour = peer_address->ready_list->neighbour;
  if (GNUNET_YES != neighbour->public_key_valid)
    {
      /* no public key yet, try again later */
      schedule_next_ping (peer_address);
      return;
    }
  caec.addr = peer_address->addr;
  caec.addrlen = peer_address->addrlen;
  caec.tname = tp->short_name;
  caec.session = peer_address->session;
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
                  "Some validation of address `%s' via `%s' for peer `%4s' already in progress.\n",
		  (peer_address->addr != NULL)
                  ? a2s (tp->short_name,
			 peer_address->addr,
			 peer_address->addrlen)
		  : "<inbound>",
                  tp->short_name,
                  GNUNET_i2s (&neighbour->id));
#endif
      schedule_next_ping (peer_address);
      return;
    }
  va = GNUNET_malloc (sizeof (struct ValidationEntry) + peer_address->addrlen);
  va->transport_name = GNUNET_strdup (tp->short_name);
  va->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                            UINT_MAX);
  va->send_time = GNUNET_TIME_absolute_get();
  va->session = peer_address->session;
  if (peer_address->addr != NULL)
    {
      va->addr = (const void*) &va[1];
      memcpy (&va[1], peer_address->addr, peer_address->addrlen);
      va->addrlen = peer_address->addrlen;
    }
  memcpy(&va->publicKey,
	 &neighbour->publicKey,
	 sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  va->timeout_task = GNUNET_SCHEDULER_add_delayed (HELLO_VERIFICATION_TIMEOUT,
                                                   &timeout_hello_validation,
                                                   va);
  GNUNET_CONTAINER_multihashmap_put (validation_map,
                                     &neighbour->id.hashPubKey,
                                     va,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  if (peer_address->validated != GNUNET_YES)
    hello_size = GNUNET_HELLO_size(our_hello);
  else
    hello_size = 0;

  tsize = sizeof(struct TransportPingMessage) + hello_size;

  if (peer_address->addr != NULL)
    {
      slen = strlen (tp->short_name) + 1;
      tsize += slen + peer_address->addrlen;
    }
  else
    {
      slen = 0; /* make gcc happy */
    }
  message_buf = GNUNET_malloc(tsize);
  ping.header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  ping.challenge = htonl(va->challenge);
  memcpy(&ping.target, &neighbour->id, sizeof(struct GNUNET_PeerIdentity));
  if (peer_address->validated != GNUNET_YES)
    {
      memcpy(message_buf, our_hello, hello_size);
    }

  if (peer_address->addr != NULL)
    {
      ping.header.size = htons(sizeof(struct TransportPingMessage) +
			       peer_address->addrlen +
			       slen);
      memcpy(&message_buf[hello_size + sizeof (struct TransportPingMessage)],
	     tp->short_name,
	     slen);
      memcpy(&message_buf[hello_size + sizeof (struct TransportPingMessage) + slen],
	     peer_address->addr,
	     peer_address->addrlen);
    }
  else
    {
      ping.header.size = htons(sizeof(struct TransportPingMessage));
    }

  memcpy(&message_buf[hello_size],
         &ping,
         sizeof(struct TransportPingMessage));

#if DEBUG_TRANSPORT_REVALIDATION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing re-validation of address `%s' via `%s' for peer `%4s' sending `%s' (%u bytes) and `%s'\n",
              (peer_address->addr != NULL)
	      ? a2s (peer_address->plugin->short_name,
		     peer_address->addr,
		     peer_address->addrlen)
	      : "<inbound>",
              tp->short_name,
              GNUNET_i2s (&neighbour->id),
              "HELLO", hello_size,
              "PING");
#endif
  if (peer_address->validated != GNUNET_YES)
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# PING with HELLO messages sent"),
                              1,
                              GNUNET_NO);
  else
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# PING without HELLO messages sent"),
                              1,
                              GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PING messages sent for re-validation"),
			    1,
			    GNUNET_NO);
  transmit_to_peer (NULL, peer_address,
                    GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                    HELLO_VERIFICATION_TIMEOUT,
                    message_buf, tsize,
                    GNUNET_YES, neighbour);
  GNUNET_free(message_buf);
  schedule_next_ping (peer_address);
}


/**
 * Schedule the job that will cause us to send a PING to the
 * foreign address to evaluate its validity and latency.
 *
 * @param fal address to PING
 */
static void
schedule_next_ping (struct ForeignAddressList *fal)
{
  struct GNUNET_TIME_Relative delay;

  if (fal->revalidate_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  delay = GNUNET_TIME_absolute_get_remaining (fal->expires);
  delay.rel_value /= 2; /* do before expiration */
  delay = GNUNET_TIME_relative_min (delay,
				    LATENCY_EVALUATION_MAX_DELAY);
  if (GNUNET_YES != fal->estimated)
    {
      delay = GNUNET_TIME_UNIT_ZERO;
      fal->estimated = GNUNET_YES;
    }				
  if (GNUNET_YES == fal->connected)
    {
      delay = GNUNET_TIME_relative_min (delay,
					CONNECTED_LATENCY_EVALUATION_MAX_DELAY);
    }
  /* FIXME: also adjust delay based on how close the last
     observed latency is to the latency of the best alternative */
  /* bound how fast we can go */
  delay = GNUNET_TIME_relative_max (delay,
				    GNUNET_TIME_UNIT_SECONDS);
  /* randomize a bit (to avoid doing all at the same time) */
  delay.rel_value += GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000);
  fal->revalidate_task = GNUNET_SCHEDULER_add_delayed(delay,
						      &send_periodic_ping,
						      fal);
}




/**
 * Function that will be called if we receive some payload
 * from another peer.
 *
 * @param message the payload
 * @param n peer who claimed to be the sender
 */
static void
handle_payload_message (const struct GNUNET_MessageHeader *message,
						struct NeighbourList *n)
{
  struct InboundMessage *im;
  struct TransportClient *cpos;
  uint16_t msize;

  msize = ntohs (message->size);
  if (n->received_pong == GNUNET_NO)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received message of type %u and size %u from `%4s', but no pong yet!!\n",
                  ntohs (message->type),
                  ntohs (message->size),
                  GNUNET_i2s (&n->id));
      GNUNET_free_non_null (n->pre_connect_message_buffer);
      n->pre_connect_message_buffer = GNUNET_malloc (msize);
      memcpy (n->pre_connect_message_buffer, message, msize);
      return;
    }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received message of type %u and size %u from `%4s', sending to all clients.\n",
	      ntohs (message->type),
	      ntohs (message->size),
	      GNUNET_i2s (&n->id));
#endif
  if (GNUNET_YES == GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker,
						      (ssize_t) msize))
    {
      n->quota_violation_count++;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,			
		  "Bandwidth quota (%u b/s) violation detected (total of %u).\n",
		  n->in_tracker.available_bytes_per_s__,
		  n->quota_violation_count);
#endif
      /* Discount 32k per violation */
      GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker,
					- 32 * 1024);		
    }
  else
    {
      if (n->quota_violation_count > 0)
	{
	  /* try to add 32k back */
	  GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker,
					    32 * 1024);
	  n->quota_violation_count--;
	}
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# payload received from other peers"),
			    msize,
			    GNUNET_NO);
  /* transmit message to all clients */
  uint32_t ats_count = 2;
  size_t size = sizeof (struct InboundMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) + msize;
  if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
	  GNUNET_break(0);

  im = GNUNET_malloc (size);
  im->header.size = htons (size);
  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
  im->peer = n->id;
  im->ats_count = htonl(ats_count);
  /* Setting ATS data */
  (&(im->ats))[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  (&(im->ats))[0].value = htonl (n->distance);
  (&(im->ats))[1].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY);
  (&(im->ats))[1].value = htonl ((uint32_t) n->latency.rel_value);
  (&(im->ats))[ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  (&(im->ats))[ats_count].value = htonl (0);

  memcpy (&((&(im->ats))[ats_count+1]), message, msize);
  cpos = clients;
  while (cpos != NULL)
    {
      transmit_to_client (cpos, &im->header, GNUNET_YES);
      cpos = cpos->next;
    }
  GNUNET_free (im);
}


/**
 * Iterator over hash map entries.  Checks if the given validation
 * entry is for the same challenge as what is given in the PONG.
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
  struct OwnAddressList *oal;
  struct TransportPlugin *tp;
  struct GNUNET_MessageHeader *prem;
  uint16_t ps;
  const char *addr;
  size_t slen;
  size_t alen;

  ps = ntohs (pong->header.size);
  if (ps < sizeof (struct TransportPongMessage))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
  addr = (const char*) &pong[1];
  slen = strlen (ve->transport_name) + 1;
  if ( (ps - sizeof (struct TransportPongMessage) < slen) ||
       (ve->challenge != challenge) ||
       (addr[slen-1] != '\0') ||
       (0 != strcmp (addr, ve->transport_name)) ||
       (ntohl (pong->purpose.size)
	!= sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
	sizeof (uint32_t) +
	sizeof (struct GNUNET_TIME_AbsoluteNBO) +
	sizeof (struct GNUNET_PeerIdentity) + ps - sizeof (struct TransportPongMessage)) )
    {
      return GNUNET_YES;
    }

  alen = ps - sizeof (struct TransportPongMessage) - slen;
  switch (ntohl (pong->purpose.purpose))
    {
    case GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN:
      if ( (ve->addrlen + slen != ntohl (pong->addrlen)) ||
	   (0 != memcmp (&addr[slen],
			 ve->addr,
			 ve->addrlen)) )
        {
          return GNUNET_YES; /* different entry, keep trying! */
        }
      if (0 != memcmp (&pong->pid,
		       key,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  GNUNET_break_op (0);
	  return GNUNET_NO;
	}
      if (GNUNET_OK !=
	  GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
				    &pong->purpose,
				    &pong->signature,
				    &ve->publicKey))
	{
	  GNUNET_break_op (0);
	  return GNUNET_NO;
	}

#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Confirmed validity of address, peer `%4s' has address `%s' (%s).\n",
		  GNUNET_h2s (key),
		  a2s (ve->transport_name,
		       (const struct sockaddr *) ve->addr,
		       ve->addrlen),
		  ve->transport_name);
#endif
      break;
    case GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_USING:
      if (0 != memcmp (&pong->pid,
			 &my_identity,
			 sizeof (struct GNUNET_PeerIdentity)))
	{
	  GNUNET_break_op (0);
	  return GNUNET_NO;
	}
      if (ve->addrlen != 0)
        {
          /* must have been for a different validation entry */
          return GNUNET_YES;
        }
      tp = find_transport (ve->transport_name);
      if (tp == NULL)
	{
	  GNUNET_break (0);
	  return GNUNET_YES;
	}
      oal = tp->addresses;
      while (NULL != oal)
	{
	  if ( (oal->addrlen == alen) &&
	       (0 == memcmp (&oal[1],
			     &addr[slen],
			     alen)) )
	    break;
	  oal = oal->next;
	}
      if (oal == NULL)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Not accepting PONG with address `%s' since I cannot confirm having this address.\n"),
		      a2s (ve->transport_name,
			   &addr[slen],
			   alen));
	  return GNUNET_NO;	
	}
      if (GNUNET_OK !=
	  GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_USING,
				    &pong->purpose,
				    &pong->signature,
				    &ve->publicKey))
	{
	  GNUNET_break_op (0);
	  return GNUNET_NO;
	}

#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Confirmed that peer `%4s' is talking to us using address `%s' (%s) for us.\n",
		  GNUNET_h2s (key),
		  a2s (ve->transport_name,
		       &addr[slen],
		       alen),
		  ve->transport_name);
#endif
      break;
    default:
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
  if (GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh (pong->expiration)).rel_value == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Received expired signature.  Check system time.\n"));
      return GNUNET_NO;
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# address validation successes"),
			    1,
			    GNUNET_NO);
  /* create the updated HELLO */
  GNUNET_CRYPTO_hash (&ve->publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &target.hashPubKey);
  if (ve->addr != NULL)
    {
      avac.done = GNUNET_NO;
      avac.ve = ve;
      hello = GNUNET_HELLO_create (&ve->publicKey,
				   &add_validated_address,
				   &avac);
      GNUNET_PEERINFO_add_peer (peerinfo,
				hello);
      GNUNET_free (hello);
    }
  n = find_neighbour (&target);
  if (n != NULL)
    {
      n->publicKey = ve->publicKey;
      n->public_key_valid = GNUNET_YES;
      fal = add_peer_address (n,
			      ve->transport_name,
			      ve->session,
			      ve->addr,
			      ve->addrlen);
      GNUNET_assert (fal != NULL);
      fal->expires = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
      fal->validated = GNUNET_YES;
      mark_address_connected (fal);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# peer addresses considered valid"),
				1,
				GNUNET_NO);
      fal->latency = GNUNET_TIME_absolute_get_duration (ve->send_time);
      schedule_next_ping (fal);
      if (n->latency.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
	n->latency = fal->latency;
      else
	n->latency.rel_value = (fal->latency.rel_value + n->latency.rel_value) / 2;

      n->distance = fal->distance;
      if (GNUNET_NO == n->received_pong)
	{
	  n->received_pong = GNUNET_YES;

	  notify_clients_connect (&target, n->latency, n->distance);
	  if (NULL != (prem = n->pre_connect_message_buffer))
	    {
	      n->pre_connect_message_buffer = NULL;
	      handle_payload_message (prem, n);
	      GNUNET_free (prem);
	    }
	}
      if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (n->retry_task);
	  n->retry_task = GNUNET_SCHEDULER_NO_TASK;
	  try_transmission_to_peer (n);
	}
    }

  /* clean up validation entry */
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (validation_map,
						       key,
						       ve));
  abort_validation (NULL, NULL, ve);
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
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PONG messages received"),
			    1,
			    GNUNET_NO);
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

}


/**
 * Try to validate a neighbour's address by sending him our HELLO and a PING.
 *
 * @param cls the 'struct ValidationEntry*'
 * @param neighbour neighbour to validate, NULL if validation failed
 */
static void
transmit_hello_and_ping (void *cls,
			 struct NeighbourList *neighbour)
{
  struct ValidationEntry *va = cls;
  struct ForeignAddressList *peer_address;
  struct TransportPingMessage ping;
  uint16_t hello_size;
  size_t tsize;
  char * message_buf;
  struct GNUNET_PeerIdentity id;
  size_t slen;

  GNUNET_CRYPTO_hash (&va->publicKey,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &id.hashPubKey);
  if (neighbour == NULL)
    {
      /* FIXME: stats... */
      GNUNET_break (GNUNET_OK ==
		    GNUNET_CONTAINER_multihashmap_remove (validation_map,
							  &id.hashPubKey,
							  va));
      abort_validation (NULL, NULL, va);
      return;
    }
  neighbour->publicKey = va->publicKey;
  neighbour->public_key_valid = GNUNET_YES;
  peer_address = add_peer_address (neighbour,
				   va->transport_name, NULL,
				   (const void*) &va[1],
				   va->addrlen);
  if (peer_address == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to add peer `%4s' for plugin `%s'\n",
                  GNUNET_i2s (&neighbour->id),
		  va->transport_name);
      GNUNET_break (GNUNET_OK ==
		    GNUNET_CONTAINER_multihashmap_remove (validation_map,
							  &id.hashPubKey,
							  va));
      abort_validation (NULL, NULL, va);
      return;
    }
  hello_size = GNUNET_HELLO_size(our_hello);
  slen = strlen(va->transport_name) + 1;
  tsize = sizeof(struct TransportPingMessage) + hello_size + va->addrlen + slen;
  message_buf = GNUNET_malloc(tsize);
  ping.challenge = htonl(va->challenge);
  ping.header.size = htons(sizeof(struct TransportPingMessage) + slen + va->addrlen);
  ping.header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  memcpy(&ping.target, &neighbour->id, sizeof(struct GNUNET_PeerIdentity));
  memcpy(message_buf, our_hello, hello_size);
  memcpy(&message_buf[hello_size],
	 &ping,
	 sizeof(struct TransportPingMessage));
  memcpy(&message_buf[hello_size + sizeof (struct TransportPingMessage)],
	 va->transport_name,
	 slen);
  memcpy(&message_buf[hello_size + sizeof (struct TransportPingMessage) + slen],
	 &va[1],
	 va->addrlen);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing validation of address `%s' via `%s' for peer `%4s' sending `%s' (%u bytes) and `%s' (%u bytes)\n",
	      (va->addrlen == 0)
	      ? "<inbound>"
	      : a2s (va->transport_name,
		     (const void*) &va[1], va->addrlen),
	      va->transport_name,
	      GNUNET_i2s (&neighbour->id),
	      "HELLO", hello_size,
	      "PING", sizeof (struct TransportPingMessage) + va->addrlen + slen);
#endif

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PING messages sent for initial validation"),
			    1,
			    GNUNET_NO);
  transmit_to_peer (NULL, peer_address,
		    GNUNET_SCHEDULER_PRIORITY_DEFAULT,
		    HELLO_VERIFICATION_TIMEOUT,
		    message_buf, tsize,
		    GNUNET_YES, neighbour);
  GNUNET_free(message_buf);
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
                const void *addr,
		uint16_t addrlen)
{
  struct CheckHelloValidatedContext *chvc = cls;
  struct GNUNET_PeerIdentity id;
  struct TransportPlugin *tp;
  struct ValidationEntry *va;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct CheckAddressExistsClosure caec;
  struct OwnAddressList *oal;

  GNUNET_assert (addr != NULL);

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# peer addresses scheduled for validation"),
			    1,
			    GNUNET_NO);
  tp = find_transport (tname);
  if (tp == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO |
                  GNUNET_ERROR_TYPE_BULK,
                  _
                  ("Transport `%s' not loaded, will not try to validate peer address using this transport.\n"),
                  tname);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# peer addresses not validated (plugin not available)"),
				1,
				GNUNET_NO);
      return GNUNET_OK;
    }
  /* check if this is one of our own addresses */
  oal = tp->addresses;
  while (NULL != oal)
    {
      if ( (oal->addrlen == addrlen) &&
	   (0 == memcmp (&oal[1],
			 addr,
			 addrlen)) )
	{
	  /* not plausible, this address is equivalent to our own address! */
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# peer addresses not validated (loopback)"),
				    1,
				    GNUNET_NO);
	  return GNUNET_OK;
	}
      oal = oal->next;
    }
  GNUNET_HELLO_get_key (chvc->hello, &pk);
  GNUNET_CRYPTO_hash (&pk,
                      sizeof (struct
                              GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id.hashPubKey);

  if (is_blacklisted(&id, tp))
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Attempted to validate blacklisted peer `%s' using `%s'!\n",
		  GNUNET_i2s(&id),
		  tname);
#endif
      return GNUNET_OK;
    }

  caec.addr = addr;
  caec.addrlen = addrlen;
  caec.session = NULL;
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
		  a2s (tname, addr, addrlen),
		  tname,
		  GNUNET_i2s (&id));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# peer addresses not validated (in progress)"),
				1,
				GNUNET_NO);
      return GNUNET_OK;
    }
  va = GNUNET_malloc (sizeof (struct ValidationEntry) + addrlen);
  va->chvc = chvc;
  chvc->ve_count++;
  va->transport_name = GNUNET_strdup (tname);
  va->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                            UINT_MAX);
  va->send_time = GNUNET_TIME_absolute_get();
  va->addr = (const void*) &va[1];
  memcpy (&va[1], addr, addrlen);
  va->addrlen = addrlen;
  GNUNET_HELLO_get_key (chvc->hello,
			&va->publicKey);
  va->timeout_task = GNUNET_SCHEDULER_add_delayed (HELLO_VERIFICATION_TIMEOUT,
						   &timeout_hello_validation,
						   va);
  GNUNET_CONTAINER_multihashmap_put (validation_map,
				     &id.hashPubKey,
				     va,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  setup_peer_check_blacklist (&id, GNUNET_NO,
			      &transmit_hello_and_ping,
			      va);
  return GNUNET_OK;
}


/**
 * Check if addresses in validated hello "h" overlap with
 * those in "chvc->hello" and validate the rest.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param h hello message for the peer (can be NULL)
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
check_hello_validated (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_HELLO_Message *h,
                       const char *err_msg)
{
  struct CheckHelloValidatedContext *chvc = cls;
  struct GNUNET_HELLO_Message *plain_hello;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct GNUNET_PeerIdentity target;
  struct NeighbourList *n;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
   /* return; */
  }

  if (peer == NULL)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# outstanding peerinfo iterate requests"),
                                -1,
                                GNUNET_NO);
      chvc->piter = NULL;
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
	  GNUNET_PEERINFO_add_peer (peerinfo, plain_hello);
	  GNUNET_free (plain_hello);
#if DEBUG_TRANSPORT_HELLO
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "PEERINFO had no `%s' message for peer `%4s', full validation needed.\n",
		      "HELLO",
		      GNUNET_i2s (&target));
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# new HELLOs requiring full validation"),
				    1,
				    GNUNET_NO);
	  GNUNET_HELLO_iterate_addresses (chvc->hello,
					  GNUNET_NO,
					  &run_validation,
					  chvc);
	}
      else
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# duplicate HELLO (peer known)"),
				    1,
				    GNUNET_NO);
	}
      chvc->ve_count--;
      if (chvc->ve_count == 0)
	{
	  GNUNET_CONTAINER_DLL_remove (chvc_head,
				       chvc_tail,
				       chvc);
	  GNUNET_free (chvc);	
	}
      return;
    }
  if (h == NULL)
    return;
#if DEBUG_TRANSPORT_HELLO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "PEERINFO had `%s' message for peer `%4s', validating only new addresses.\n",
	      "HELLO",
	      GNUNET_i2s (peer));
#endif
  chvc->hello_known = GNUNET_YES;
  n = find_neighbour (peer);
  if (n != NULL)
    {
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Calling hello_iterate_addresses for %s!\n",
                  GNUNET_i2s (peer));
#endif
      GNUNET_HELLO_iterate_addresses (h,
				      GNUNET_NO,
				      &add_to_foreign_address_list,
				      n);
      try_transmission_to_peer (n);
    }
  else
    {
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No existing neighbor record for %s!\n",
                  GNUNET_i2s (peer));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# no existing neighbour record (validating HELLO)"),
				1,
				GNUNET_NO);
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# HELLO validations (update case)"),
			    1,
			    GNUNET_NO);
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
#if DEBUG_TRANSPORT_HELLO > 2
  char *my_id;
#endif
  hsize = ntohs (message->size);
  if ((ntohs (message->type) != GNUNET_MESSAGE_TYPE_HELLO) ||
      (hsize < sizeof (struct GNUNET_MessageHeader)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# HELLOs received for validation"),
			    1,
			    GNUNET_NO);

  /* first, check if load is too high */
  if (GNUNET_SCHEDULER_get_load (GNUNET_SCHEDULER_PRIORITY_BACKGROUND) > MAX_HELLO_LOAD)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# HELLOs ignored due to high load"),
				1,
				GNUNET_NO);
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Ignoring `%s' for `%4s', load too high.\n",
                  "HELLO",
                  GNUNET_i2s (&target));
#endif
      return GNUNET_OK;
    }
  hello = (const struct GNUNET_HELLO_Message *) message;
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, &publicKey))
    {
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Unable to get public key from `%s' for `%4s'!\n",
                  "HELLO",
                  GNUNET_i2s (&target));
#endif
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }

  GNUNET_CRYPTO_hash (&publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &target.hashPubKey);

#if DEBUG_TRANSPORT_HELLO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message for `%4s'\n",
              "HELLO",
              GNUNET_i2s (&target));
#endif

  if (0 == memcmp (&my_identity,
		   &target,
		   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# HELLOs ignored for validation (is my own HELLO)"),
				1,
				GNUNET_NO);
      return GNUNET_OK;
    }
  chvc = chvc_head;
  while (NULL != chvc)
    {
      if (GNUNET_HELLO_equals (hello,
			       chvc->hello,
			       GNUNET_TIME_absolute_get ()).abs_value > 0)
	{
#if DEBUG_TRANSPORT_HELLO > 2
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Received duplicate `%s' message for `%4s'; ignored\n",
		      "HELLO",
		      GNUNET_i2s (&target));
#endif
	  return GNUNET_OK; /* validation already pending */
	}
      if (GNUNET_HELLO_size(hello) == GNUNET_HELLO_size (chvc->hello))
	GNUNET_break (0 != memcmp (hello, chvc->hello,
				   GNUNET_HELLO_size(hello)));
      chvc = chvc->next;
    }

#if BREAK_TESTS
  struct NeighbourList *temp_neighbor = find_neighbour(&target);
  if ((NULL != temp_neighbor))
    {
      fprintf(stderr, "Already know peer, ignoring hello\n");
      return GNUNET_OK;
    }
#endif

#if DEBUG_TRANSPORT_HELLO > 2
  if (plugin != NULL)
    {
      my_id = GNUNET_strdup(GNUNET_i2s(plugin->env.my_identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Starting validation of `%s' message for `%4s' via '%s' of size %u\n",
                  my_id,
                  "HELLO",
                  GNUNET_i2s (&target),
                  plugin->short_name,
                  GNUNET_HELLO_size(hello));
      GNUNET_free(my_id);
    }
#endif
  chvc = GNUNET_malloc (sizeof (struct CheckHelloValidatedContext) + hsize);
  chvc->ve_count = 1;
  chvc->hello = (const struct GNUNET_HELLO_Message *) &chvc[1];
  memcpy (&chvc[1], hello, hsize);
  GNUNET_CONTAINER_DLL_insert (chvc_head,
			       chvc_tail,
			       chvc);
  /* finally, check if HELLO was previously validated
     (continuation will then schedule actual validation) */
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# peerinfo process hello iterate requests"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# outstanding peerinfo iterate requests"),
                            1,
                            GNUNET_NO);
  chvc->piter = GNUNET_PEERINFO_iterate (peerinfo,
                                         &target,
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
 * @param check GNUNET_YES to check if ALL addresses for this peer
 *              are gone, GNUNET_NO to force a disconnect of the peer
 *              regardless of whether other addresses exist.
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
                {
                  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                            "NOT Disconnecting from `%4s', still have live addresses!\n",
                            GNUNET_i2s (&n->id));
                  return;             /* still connected */
                }
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
	  if (peer_pos->connected == GNUNET_YES)
	    GNUNET_STATISTICS_update (stats,
				      gettext_noop ("# connected addresses"),
				      -1,
				      GNUNET_NO);
	  if (GNUNET_YES == peer_pos->validated)
	    GNUNET_STATISTICS_update (stats,
				      gettext_noop ("# peer addresses considered valid"),
				      -1,
				      GNUNET_NO);
	  if (GNUNET_SCHEDULER_NO_TASK != peer_pos->revalidate_task)
	    {
	      GNUNET_SCHEDULER_cancel (peer_pos->revalidate_task);
	      peer_pos->revalidate_task = GNUNET_SCHEDULER_NO_TASK;
	    }
          GNUNET_free(peer_pos);
        }
      GNUNET_free (rpos);
    }

  /* free all messages on the queue */
  while (NULL != (mq = n->messages_head))
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes in message queue for other peers"),
				- (int64_t) mq->message_buf_size,
				GNUNET_NO);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes discarded due to disconnect"),
				mq->message_buf_size,
				GNUNET_NO);
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
      GNUNET_SCHEDULER_cancel (n->timeout_task);
      n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (n->retry_task);
      n->retry_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (n->piter != NULL)
    {
      GNUNET_PEERINFO_iterate_cancel (n->piter);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# outstanding peerinfo iterate requests"),
                                -1,
                                GNUNET_NO);
      n->piter = NULL;
    }
  /* finally, free n itself */
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# active neighbours"),
			    -1,
			    GNUNET_NO);
  GNUNET_free_non_null (n->pre_connect_message_buffer);
  GNUNET_free (n);
}


/**
 * We have received a PING message from someone.  Need to send a PONG message
 * in response to the peer by any means necessary.
 */
static int
handle_ping(void *cls, const struct GNUNET_MessageHeader *message,
	    const struct GNUNET_PeerIdentity *peer,
	    struct Session *session,
	    const char *sender_address,
	    uint16_t sender_address_len)
{
  struct TransportPlugin *plugin = cls;
  struct SessionHeader *session_header = (struct SessionHeader*) session;
  struct TransportPingMessage *ping;
  struct TransportPongMessage *pong;
  struct NeighbourList *n;
  struct ReadyList *rl;
  struct ForeignAddressList *fal;
  struct OwnAddressList *oal;
  const char *addr;
  size_t alen;
  size_t slen;

  if (ntohs (message->size) < sizeof (struct TransportPingMessage))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }

  ping = (struct TransportPingMessage *) message;
  if (0 != memcmp (&ping->target,
                   plugin->env.my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Received `%s' message from `%s' destined for `%s' which is not me!\n"),
		  "PING",
		  (sender_address != NULL)
		  ? a2s (plugin->short_name,
			 (const struct sockaddr *)sender_address,
			 sender_address_len)
		  : "<inbound>",
		  GNUNET_i2s (&ping->target));
      return GNUNET_SYSERR;
    }
#if DEBUG_PING_PONG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
	      "Processing `%s' from `%s'\n",
	      "PING",
	      (sender_address != NULL)
	      ? a2s (plugin->short_name,
		     (const struct sockaddr *)sender_address,
		     sender_address_len)
	      : "<inbound>");
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PING messages received"),
			    1,
			    GNUNET_NO);
  addr = (const char*) &ping[1];
  alen = ntohs (message->size) - sizeof (struct TransportPingMessage);
  slen = strlen (plugin->short_name) + 1;
  if (alen == 0)
    {
      /* peer wants to confirm that we have an outbound connection to him */
      if (session == NULL)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Refusing to create PONG since I do not have a session with `%s'.\n"),
		      GNUNET_i2s (peer));
	  return GNUNET_SYSERR;
	}
      pong = GNUNET_malloc (sizeof (struct TransportPongMessage) + sender_address_len + slen);
      pong->header.size = htons (sizeof (struct TransportPongMessage) + sender_address_len + slen);
      pong->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
      pong->purpose.size =
	htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
	       sizeof (uint32_t) +
	       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
	       sizeof (struct GNUNET_PeerIdentity) + sender_address_len + slen);
      pong->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_USING);
      pong->challenge = ping->challenge;
      pong->addrlen = htonl(sender_address_len + slen);
      memcpy(&pong->pid,
	     peer,
	     sizeof(struct GNUNET_PeerIdentity));
      memcpy (&pong[1],
	      plugin->short_name,
	      slen);
      if ((sender_address!=NULL) && (sender_address_len > 0))
		  memcpy (&((char*)&pong[1])[slen],
			  sender_address,
			  sender_address_len);
      if (GNUNET_TIME_absolute_get_remaining (session_header->pong_sig_expires).rel_value < PONG_SIGNATURE_LIFETIME.rel_value / 4)
	{
	  /* create / update cached sig */
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Creating PONG signature to indicate active connection.\n");
#endif
	  session_header->pong_sig_expires = GNUNET_TIME_relative_to_absolute (PONG_SIGNATURE_LIFETIME);
	  pong->expiration = GNUNET_TIME_absolute_hton (session_header->pong_sig_expires);
	  GNUNET_assert (GNUNET_OK ==
			 GNUNET_CRYPTO_rsa_sign (my_private_key,
						 &pong->purpose,
						 &session_header->pong_signature));
	}
      else
	{
	  pong->expiration = GNUNET_TIME_absolute_hton (session_header->pong_sig_expires);
	}
      memcpy (&pong->signature,
	      &session_header->pong_signature,
	      sizeof (struct GNUNET_CRYPTO_RsaSignature));


    }
  else
    {
      /* peer wants to confirm that this is one of our addresses */
      addr += slen;
      alen -= slen;
      if (GNUNET_OK !=
	  plugin->api->check_address (plugin->api->cls,
				      addr,
				      alen))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Not confirming PING with address `%s' since I cannot confirm having this address.\n"),
		      a2s (plugin->short_name,
			   addr,
			   alen));
	  return GNUNET_NO;
	}
      oal = plugin->addresses;
      while (NULL != oal)
	{
	  if ( (oal->addrlen == alen) &&
	       (0 == memcmp (addr,
			     &oal[1],
			     alen)) )
	    break;
	  oal = oal->next;
	}
      pong = GNUNET_malloc (sizeof (struct TransportPongMessage) + alen + slen);
      pong->header.size = htons (sizeof (struct TransportPongMessage) + alen + slen);
      pong->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
      pong->purpose.size =
	htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
	       sizeof (uint32_t) +
	       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
	       sizeof (struct GNUNET_PeerIdentity) + alen + slen);
      pong->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN);
      pong->challenge = ping->challenge;
      pong->addrlen = htonl(alen + slen);
      memcpy(&pong->pid,
	     &my_identity,
	     sizeof(struct GNUNET_PeerIdentity));
      memcpy (&pong[1], plugin->short_name, slen);
      memcpy (&((char*)&pong[1])[slen], addr, alen);
      if ( (oal != NULL) &&
	   (GNUNET_TIME_absolute_get_remaining (oal->pong_sig_expires).rel_value < PONG_SIGNATURE_LIFETIME.rel_value / 4) )
	{
	  /* create / update cached sig */
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Creating PONG signature to indicate ownership.\n");
#endif
	  oal->pong_sig_expires = GNUNET_TIME_absolute_min (oal->expires,
							    GNUNET_TIME_relative_to_absolute (PONG_SIGNATURE_LIFETIME));
	  pong->expiration = GNUNET_TIME_absolute_hton (oal->pong_sig_expires);
	  GNUNET_assert (GNUNET_OK ==
			 GNUNET_CRYPTO_rsa_sign (my_private_key,
						 &pong->purpose,
						 &oal->pong_signature));	
	  memcpy (&pong->signature,
		  &oal->pong_signature,
		  sizeof (struct GNUNET_CRYPTO_RsaSignature));
	}
      else if (oal == NULL)
	{
	  /* not using cache (typically DV-only) */
	  pong->expiration = GNUNET_TIME_absolute_hton (GNUNET_TIME_relative_to_absolute (PONG_SIGNATURE_LIFETIME));
	  GNUNET_assert (GNUNET_OK ==
			 GNUNET_CRYPTO_rsa_sign (my_private_key,
						 &pong->purpose,
						 &pong->signature));	
	}
      else
	{
	  /* can used cached version */
	  pong->expiration = GNUNET_TIME_absolute_hton (oal->pong_sig_expires);
	  memcpy (&pong->signature,
		  &oal->pong_signature,
		  sizeof (struct GNUNET_CRYPTO_RsaSignature));
	}
    }
  n = find_neighbour(peer);
  GNUNET_assert (n != NULL);
  /* first try reliable response transmission */
  rl = n->plugins;
  while (rl != NULL)
    {
      fal = rl->addresses;
      while (fal != NULL)
	{
	  if (-1 != rl->plugin->api->send (rl->plugin->api->cls,
					   peer,
					   (const char*) pong,
					   ntohs (pong->header.size),
					   TRANSPORT_PONG_PRIORITY,
					   HELLO_VERIFICATION_TIMEOUT,
					   fal->session,
					   fal->addr,
					   fal->addrlen,
					   GNUNET_SYSERR,
					   NULL, NULL))
	    {
	      /* done! */
	      GNUNET_STATISTICS_update (stats,
					gettext_noop ("# PONGs unicast via reliable transport"),
					1,
					GNUNET_NO);
	      GNUNET_free (pong);
	      return GNUNET_OK;
	    }
	  fal = fal->next;
	}
      rl = rl->next;
    }
  /* no reliable method found, do multicast */
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# PONGs multicast to all available addresses"),
			    1,
			    GNUNET_NO);
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
 * Function called by the plugin for each received message.
 * Update data volumes, possibly notify plugins about
 * reducing the rate at which they read from the socket
 * and generally forward to our receive callback.
 *
 * @param cls the "struct TransportPlugin *" we gave to the plugin
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @param ats_data information for automatic transport selection
 * @param ats_count number of elements in ats not including 0-terminator
 * @param session identifier used for this session (can be NULL)
 * @param sender_address binary address of the sender (if observed)
 * @param sender_address_len number of bytes in sender_address
 * @return how long in ms the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
static struct GNUNET_TIME_Relative
plugin_env_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_TRANSPORT_ATS_Information *ats_data,
                    uint32_t ats_count,
                    struct Session *session,
                    const char *sender_address,
                    uint16_t sender_address_len)
{
  struct TransportPlugin *plugin = cls;
  struct ReadyList *service_context;
  struct ForeignAddressList *peer_address;
  uint16_t msize;
  struct NeighbourList *n;
  struct GNUNET_TIME_Relative ret;
  if (is_blacklisted (peer, plugin))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  uint32_t distance;
  int c;

  n = find_neighbour (peer);
  if (n == NULL)
    n = setup_new_neighbour (peer, GNUNET_YES);
  service_context = n->plugins;
  while ((service_context != NULL) && (plugin != service_context->plugin))
    service_context = service_context->next;
  GNUNET_assert ((plugin->api->send == NULL) || (service_context != NULL));
  peer_address = NULL;
  distance = 1;
  for (c=0; c<ats_count; c++)
  {
	  if (ntohl(ats_data[c].type) == GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE)
	  {
		  distance = ntohl(ats_data[c].value);
	  }
  }
  /* notify ATS about incoming data */
  ats_notify_ats_data(peer, ats_data);

  if (message != NULL)
    {
      if ( (session != NULL) ||
	   (sender_address != NULL) )
	peer_address = add_peer_address (n,
					 plugin->short_name,
					 session,
					 sender_address,
					 sender_address_len);
      if (peer_address != NULL)
	{
	  peer_address->distance = distance;
	  if (GNUNET_YES == peer_address->validated)
	    mark_address_connected (peer_address);
	  peer_address->timeout
	    =
	    GNUNET_TIME_relative_to_absolute
	    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
	  schedule_next_ping (peer_address);
	}
      /* update traffic received amount ... */
      msize = ntohs (message->size);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# bytes received from other peers"),
				msize,
				GNUNET_NO);
      n->distance = distance;
      n->peer_timeout =
	GNUNET_TIME_relative_to_absolute
	(GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
      GNUNET_SCHEDULER_cancel (n->timeout_task);
      n->timeout_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
				      &neighbour_timeout_task, n);
      if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
	{
	  /* dropping message due to frequent inbound volume violations! */
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING |
		      GNUNET_ERROR_TYPE_BULK,
		      _
		      ("Dropping incoming message due to repeated bandwidth quota (%u b/s) violations (total of %u).\n"),
		      n->in_tracker.available_bytes_per_s__,
		      n->quota_violation_count);
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bandwidth quota violations by other peers"),
				    1,
				    GNUNET_NO);
	  return GNUNET_CONSTANTS_QUOTA_VIOLATION_TIMEOUT;
	}

#if DEBUG_PING_PONG
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Received message of type %u and size %u from `%4s', sending to all clients.\n",
                      ntohs (message->type),
                      ntohs (message->size),
		      GNUNET_i2s (peer));
#endif
      switch (ntohs (message->type))
	{
	case GNUNET_MESSAGE_TYPE_HELLO:
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# HELLO messages received from other peers"),
				    1,
				    GNUNET_NO);
	  process_hello (plugin, message);
	  break;
	case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
	  handle_ping (plugin, message, peer, session, sender_address, sender_address_len);
	  break;
	case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
	  handle_pong (plugin, message, peer, sender_address, sender_address_len);
	  break;
	default:
	  handle_payload_message (message, n);
	  break;
	}
    }
  ret = GNUNET_BANDWIDTH_tracker_get_delay (&n->in_tracker, 0);
  if (ret.rel_value > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Throttling read (%llu bytes excess at %u b/s), waiting %llums before reading more.\n",
		  (unsigned long long) n->in_tracker.consumption_since_last_update__,
		  (unsigned int) n->in_tracker.available_bytes_per_s__,
		  (unsigned long long) ret.rel_value);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# ms throttling suggested"),
				(int64_t) ret.rel_value,
				GNUNET_NO);
    }
  return ret;
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
  const struct StartMessage *start;
  struct TransportClient *c;
  struct ConnectInfoMessage * cim;
  struct NeighbourList *n;
  uint32_t ats_count;
  size_t size;

  start = (const struct StartMessage*) message;
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
  if ( (GNUNET_NO != ntohl (start->do_check)) &&
       (0 != memcmp (&start->self,
		     &my_identity,
		     sizeof (struct GNUNET_PeerIdentity))) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Rejecting control connection from peer `%s', which is not me!\n"),
		  GNUNET_i2s (&start->self));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
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
      ats_count = 2;
      size  = sizeof (struct ConnectInfoMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
      if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
      {
    	  GNUNET_break(0);
      }
      cim = GNUNET_malloc (size);
      cim->header.size = htons (size);
      cim->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
      cim->ats_count = htonl(ats_count);
      (&(cim->ats))[2].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
      (&(cim->ats))[2].value = htonl (0);
      n = neighbours;
      while (n != NULL)
	  {
		  if (GNUNET_YES == n->received_pong)
		  {
			  (&(cim->ats))[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
			  (&(cim->ats))[0].value = htonl (n->distance);
			  (&(cim->ats))[1].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY);
			  (&(cim->ats))[1].value = htonl ((uint32_t) n->latency.rel_value);
			  cim->id = n->id;
			  transmit_to_client (c, &cim->header, GNUNET_NO);
		  }
	    n = n->next;
      }
      GNUNET_free (cim);
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

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# HELLOs received from clients"),
			    1,
			    GNUNET_NO);
  ret = process_hello (NULL, message);
  GNUNET_SERVER_receive_done (client, ret);
}


/**
 * Closure for 'transmit_client_message'; followed by
 * 'msize' bytes of the actual message.
 */
struct TransmitClientMessageContext
{
  /**
   * Client on whom's behalf we are sending.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Timeout for the transmission.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Message priority.
   */
  uint32_t priority;

  /**
   * Size of the message in bytes.
   */
  uint16_t msize;
};


/**
 * Schedule transmission of a message we got from a client to a peer.
 *
 * @param cls the 'struct TransmitClientMessageContext*'
 * @param n destination, or NULL on error (in that case, drop the message)
 */
static void
transmit_client_message (void *cls,
			 struct NeighbourList *n)
{
  struct TransmitClientMessageContext *tcmc = cls;
  struct TransportClient *tc;

  tc = clients;
  while ((tc != NULL) && (tc->client != tcmc->client))
    tc = tc->next;

  if (n != NULL)
    {
      transmit_to_peer (tc, NULL, tcmc->priority,
			GNUNET_TIME_absolute_get_remaining (tcmc->timeout),
			(char *)&tcmc[1],
			tcmc->msize, GNUNET_NO, n);
    }
  GNUNET_SERVER_receive_done (tcmc->client, GNUNET_OK);
  GNUNET_SERVER_client_drop (tcmc->client);
  GNUNET_free (tcmc);
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
  const struct OutboundMessage *obm;
  const struct GNUNET_MessageHeader *obmm;
  struct TransmitClientMessageContext *tcmc;
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
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# payload received for other peers"),
			    size,
			    GNUNET_NO);
  obm = (const struct OutboundMessage *) message;
  obmm = (const struct GNUNET_MessageHeader *) &obm[1];
  msize = size - sizeof (struct OutboundMessage);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client with target `%4s' and message of type %u and size %u\n",
              "SEND", GNUNET_i2s (&obm->peer),
              ntohs (obmm->type),
              msize);

  tcmc = GNUNET_malloc (sizeof (struct TransmitClientMessageContext) + msize);
  tcmc->client = client;
  tcmc->priority = ntohl (obm->priority);
  tcmc->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_ntoh (obm->timeout));
  tcmc->msize = msize;
  /* FIXME: this memcpy can be up to 7% of our total runtime */
  memcpy (&tcmc[1], obmm, msize);
  GNUNET_SERVER_client_keep (client);
  setup_peer_check_blacklist (&obm->peer, GNUNET_YES,
			      &transmit_client_message,
			      tcmc);
}


/**
 * Handle request connect message
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_request_connect (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct TransportRequestConnectMessage *trcm =
    (const struct TransportRequestConnectMessage *) message;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# REQUEST CONNECT messages received"),
                            1,
                            GNUNET_NO);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received a request connect message for peer %s\n", GNUNET_i2s(&trcm->peer));
  setup_peer_check_blacklist (&trcm->peer, GNUNET_YES,
                              NULL, NULL);
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

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# SET QUOTA messages received"),
			    1,
			    GNUNET_NO);
  n = find_neighbour (&qsm->peer);
  if (n == NULL)
    {
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# SET QUOTA messages ignored (no such peer)"),
				1,
				GNUNET_NO);
      return;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request (new quota %u, old quota %u) from client for peer `%4s'\n",
              "SET_QUOTA",
	      (unsigned int) ntohl (qsm->quota.value__),
	      (unsigned int) n->in_tracker.available_bytes_per_s__,
	      GNUNET_i2s (&qsm->peer));
#endif
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker,
					 qsm->quota);
  if (0 == ntohl (qsm->quota.value__))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Disconnecting peer `%4s', %s\n", GNUNET_i2s(&n->id),
                "SET_QUOTA");
      disconnect_neighbour (n, GNUNET_NO);
    }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Take the given address and append it to the set of results sent back to
 * the client.
 *
 * @param cls the transmission context used ('struct GNUNET_SERVER_TransmitContext*')
 * @param address the resolved name, NULL to indicate the last response
 */
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
  struct GNUNET_TIME_Absolute timeout;
  struct GNUNET_TIME_Relative rtimeout;
  int32_t numeric;

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
  timeout = GNUNET_TIME_absolute_ntoh (alum->timeout);
  rtimeout = GNUNET_TIME_absolute_get_remaining (timeout);
  numeric = ntohl (alum->numeric_only);
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
  lsPlugin->api->address_pretty_printer (lsPlugin->api->cls,
					 nameTransport,
                                         address, addressLen,
					 numeric,
                                         rtimeout,
                                         &transmit_address_to_client, tc);
}


/**
 * Setup the environment for this plugin.
 */
static void
create_environment (struct TransportPlugin *plug)
{
  plug->env.cfg = cfg;
  plug->env.my_identity = &my_identity;
  plug->env.our_hello = &our_hello;
  plug->env.cls = plug;
  plug->env.receive = &plugin_env_receive;
  plug->env.notify_address = &plugin_env_notify_address;
  plug->env.session_end = &plugin_env_session_end;
  plug->env.max_connections = max_connect_per_transport;
  plug->env.stats = stats;
}


/**
 * Start the specified transport (load the plugin).
 */
static void
start_transport (struct GNUNET_SERVER_Handle *server,
		 const char *name)
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
  struct Blacklisters *bl;
  struct BlacklistCheck *bc;

  if (client == NULL)
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Client disconnected, cleaning up.\n");
#endif
  /* clean up blacklister */
  bl = bl_head;
  while (bl != NULL)
    {
      if (bl->client == client)
	{
	  bc = bc_head;
	  while (bc != NULL)
	    {
	      if (bc->bl_pos == bl)
		{
		  bc->bl_pos = bl->next;
		  if (bc->th != NULL)
		    {
		      GNUNET_CONNECTION_notify_transmit_ready_cancel (bc->th);
		      bc->th = NULL;		
		    }
		  if (bc->task == GNUNET_SCHEDULER_NO_TASK)
		    bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check,
							 bc);
		  break;
		}
	      bc = bc->next;
	    }
	  GNUNET_CONTAINER_DLL_remove (bl_head,
				       bl_tail,
				       bl);
	  GNUNET_SERVER_client_drop (bl->client);
	  GNUNET_free (bl);
	  break;
	}
      bl = bl->next;
    }
  /* clean up 'normal' clients */
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
  struct ATS_plugin * rc;

  while (neighbours != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting peer `%4s', %s\n", GNUNET_i2s(&neighbours->id),
              "SHUTDOWN_TASK");
      disconnect_neighbour (neighbours, GNUNET_NO);
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transport service is unloading plugins...\n");
#endif
  while (NULL != (plug = plugins))
    {
      plugins = plug->next;
      if (plug->address_update_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (plug->address_update_task);
	  plug->address_update_task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug->short_name);
      while (NULL != (al = plug->addresses))
        {
          plug->addresses = al->next;
          GNUNET_free (al);
        }
      rc = plug->rc;
      struct ATS_ressource_cost * t;
      while (rc->head != NULL)
      {
    	  t = rc->head;
    	  GNUNET_CONTAINER_DLL_remove(rc->head, rc->tail, rc->head);
    	  GNUNET_free(t);
      }

      GNUNET_free(plug->rc);
      GNUNET_free (plug);
    }
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  GNUNET_free_non_null (our_hello);

  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
					 &abort_validation,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (validation_map);
  validation_map = NULL;

  ats_shutdown(ats);

  /* free 'chvc' data structure */
  while (NULL != (chvc = chvc_head))
    {
      chvc_head = chvc->next;
      if (chvc->piter != NULL)
        {
          GNUNET_PEERINFO_iterate_cancel (chvc->piter);
          GNUNET_STATISTICS_update (stats,
                                    gettext_noop ("# outstanding peerinfo iterate requests"),
                                    -1,
                                    GNUNET_NO);
        }
      else
	GNUNET_break (0);
      GNUNET_assert (chvc->ve_count == 0);
      GNUNET_free (chvc);
    }
  chvc_tail = NULL;

  if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
      stats = NULL;
    }
  if (peerinfo != NULL)
    {
      GNUNET_PEERINFO_disconnect (peerinfo);
      peerinfo = NULL;
    }
  /* Can we assume those are gone by now, or do we need to clean up
     explicitly!? */
  GNUNET_break (bl_head == NULL);
  GNUNET_break (bc_head == NULL);
}

struct ATS_mechanism
{
	struct ATS_mechanism * prev;
	struct ATS_mechanism * next;
	struct ForeignAddressList * addr;
	struct TransportPlugin * plugin;
	struct ATS_peer * peer;
	int col_index;
	int	id;
	struct ATS_ressource_cost * rc;
};

struct ATS_peer
{
	int id;
	struct GNUNET_PeerIdentity peer;
	struct NeighbourList * n;
	struct ATS_mechanism * m_head;
	struct ATS_mechanism * m_tail;

	/* preference value f */
	double f;
	int	t;
};

struct ATS_result
{
	int c_mechs;
	int c_peers;
	int solution;
};

struct ATS_ressource
{
	/* index in ressources array */
	int index;
	/* depending ATSi parameter to calculcate limits */
	int atis_index;
	/* cfg option to load limits */
	char * cfg_param;
	/* lower bound */
	double c_min;
	/* upper bound */
	double c_max;

	/* cofficients for the specific plugins */
	double c_unix;
	double c_tcp;
	double c_udp;
	double c_http;
	double c_https;
	double c_wlan;
	double c_default;
};

static struct ATS_ressource ressources[] =
{
		/* FIXME: the coefficients for the specific plugins */
		{1, 7, "LAN_BW_LIMIT", 0, VERY_BIG_DOUBLE_VALUE, 0, 1, 1, 2, 2, 1, 3},
		{2, 7, "WAN_BW_LIMIT", 0, VERY_BIG_DOUBLE_VALUE, 0, 1, 1, 2, 2, 2, 3},
		{3, 4, "WLAN_ENERGY_LIMIT", VERY_BIG_DOUBLE_VALUE, 0, 0, 0, 0, 0, 2, 1}
/*
		{4, 4, "COST_ENERGY_CONSUMPTION", VERY_BIG_DOUBLE_VALUE},
		{5, 5, "COST_CONNECT", VERY_BIG_DOUBLE_VALUE},
		{6, 6, "COST_BANDWITH_AVAILABLE", VERY_BIG_DOUBLE_VALUE},
		{7, 7, "COST_NETWORK_OVERHEAD", VERY_BIG_DOUBLE_VALUE},*/
};

static int available_ressources = 3;



struct ATS_info
{

	/**
	 * Time of last execution
	 */
	struct GNUNET_TIME_Absolute last;
	/**
	 * Minimum intervall between two executions
	 */
	struct GNUNET_TIME_Relative min_delta;
	/**
	 * Regular intervall when execution is triggered
	 */
	struct GNUNET_TIME_Relative exec_intervall;
	/**
	 * Maximum execution time per calculation
	 */
	struct GNUNET_TIME_Relative max_exec_duration;
	/**
	 * Maximum number of LP iterations per calculation
	 */
	int max_iterations;

	GNUNET_SCHEDULER_TaskIdentifier ats_task;

	struct ATS_plugin * head;
	struct ATS_plugin * tail;
};

#define DEBUG_ATS GNUNET_YES
#define VERBOSE_ATS GNUNET_NO


/** solve the bandwidth distribution problem
 * @param max_it maximum iterations
 * @param max_dur maximum duration in ms
 * @param D	weight for diversity
 * @param U weight for utility
 * @param R weight for relativity
 * @param v_b_min minimal bandwidth per peer
 * @param v_n_min minimum number of connections
 * @param res result struct
 * @return GNUNET_SYSERR if glpk is not available, number of mechanisms used
 */
static int ats_solve_problem (int max_it, int max_dur , double D, double U, double R, int v_b_min, int v_n_min, struct ATS_result *res)
{
#if !HAVE_LIBGLPK
	if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "no glpk installed\n");
	return GNUNET_SYSERR;
#else
	if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "glpk installed\n");
#endif
	glp_prob *prob;

	int c;
	int c_peers = 0;
	int c_mechs = 0;
	int result;
	int solution;

	int c_c_ressources = 0;
	int c_q_metrics = available_quality_metrics;

	//double M = 10000000000; // ~10 GB
	//double M = VERY_BIG_DOUBLE_VALUE;
	double M = 100000;
	double Q[c_q_metrics+1];
	for (c=1; c<=c_q_metrics; c++)
	{
		Q[c] = 1;
	}

	struct NeighbourList *next = neighbours;
	while (next!=NULL)
	{
		struct ReadyList *r_next = next->plugins;
		while (r_next != NULL)
		{
			struct ForeignAddressList * a_next = r_next->addresses;
			while (a_next != NULL)
			{
				c_mechs++;
				a_next = a_next->next;
			}
			r_next = r_next->next;
		}
		next = next->next;
		c_peers++;
	}

	if (c_mechs==0)
	{
		if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No addresses for bw distribution available\n", c_peers);
		return 0;
	}

	struct ATS_mechanism * mechanisms = GNUNET_malloc((1+c_mechs) * sizeof (struct ATS_mechanism));
	struct ATS_peer * peers = GNUNET_malloc((1+c_peers) * sizeof (struct ATS_peer));

	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Found mechanisms: %i\n", c_mechs);
	c_mechs = 1;
	c_peers = 1;
	next = neighbours;
	while (next!=NULL)
	{
		peers[c_peers].peer = next->id;
		peers[c_peers].m_head = NULL;
		peers[c_peers].m_tail = NULL;
		// FIXME
		peers[c_peers].f = 1.0 / c_mechs;

		struct ReadyList *r_next = next->plugins;
		while (r_next != NULL)
		{
			struct ForeignAddressList * a_next = r_next->addresses;
			while (a_next != NULL)
			{
				//struct ATS_ressource_cost *rc;

				if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%i Peer: `%s' plugin `%s' %x:\n", c_mechs, GNUNET_i2s(&next->id), r_next->plugin->short_name, a_next);
				mechanisms[c_mechs].addr = a_next;
				mechanisms[c_mechs].col_index = c_mechs;
				mechanisms[c_mechs].peer = &peers[c_peers];
				mechanisms[c_mechs].next = NULL;
				mechanisms[c_mechs].plugin = r_next->plugin;
				mechanisms[c_mechs].rc = GNUNET_malloc (available_ressources * sizeof (struct ATS_ressource_cost));

				//rc = a_next->ressources;
				/* get address specific ressource costs */
				/*
				while (rc != NULL)
				{
					memcpy(&mechanisms[c_mechs].rc[rc->index], rc, sizeof (struct ATS_ressource_cost));
					if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Set address specific rc %s = %f \n", ressources[rc->index].cfg_param, mechanisms[c_mechs].rc[rc->index].c_1);
					c_c_ressources ++;
					rc = rc->next;
				}
				// get plugin specific ressourc costs


				rc = mechanisms[c_mechs].plugin->rc->head;
				while (rc != NULL)
				{
					if ((mechanisms[c_mechs].rc[rc->index].c_1 == 0) && (rc->c_1 != 0))
					{
						memcpy(&mechanisms[c_mechs].rc[rc->index], rc, sizeof (struct ATS_ressource_cost));
						c_c_ressources++;
					}
					if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Set plugin specific rc %s = %f \n", ressources[rc->index].cfg_param, mechanisms[c_mechs].rc[rc->index].c_1);
					rc = rc->next;
				}*/

				GNUNET_CONTAINER_DLL_insert_tail(peers[c_peers].m_head, peers[c_peers].m_tail, &mechanisms[c_mechs]);
				c_mechs++;
				a_next = a_next->next;
			}
			r_next = r_next->next;
		}
		c_peers++;
		next = next->next;
	}
	c_mechs--;
	c_peers--;

	if (v_n_min > c_peers)
		v_n_min = c_peers;

	/* number of variables == coloumns */
	//int c_cols = 2 * c_mechs + 3 + c_q_metrics;
	/* number of constraints == rows */
	//int c_rows = 2 * c_peers + 2 * c_mechs + c_c_ressources + c_q_metrics + 3;

	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Creating problem with: %i peers, %i mechanisms, %i resource entries, %i quality metrics \n", c_peers, c_mechs, c_c_ressources, c_q_metrics);

	int size = 1 + 3 + 10 *c_mechs + c_peers + (c_q_metrics*c_mechs)+ c_q_metrics + c_c_ressources ;
	//int size = 1 + 8 *c_mechs +2 + c_mechs + c_peers + (c_q_metrics*c_mechs)+c_q_metrics + c_c_ressources ;
	int row_index;
	int array_index=1;
	int * ia = GNUNET_malloc (size * sizeof (int));
	int * ja = GNUNET_malloc (size * sizeof (int));
	double * ar = GNUNET_malloc(size* sizeof (double));

	prob = glp_create_prob();
	glp_set_prob_name(prob, "gnunet ats bandwidth distribution");
	glp_set_obj_dir(prob, GLP_MAX);

	/* adding columns */
	char * name;
	glp_add_cols(prob, 2 * c_mechs);
	/* adding b_t cols */
	for (c=1; c <= c_mechs; c++)
	{
		GNUNET_asprintf(&name, "b%i",c);
		glp_set_col_name(prob, c, name);
		GNUNET_free (name);
		glp_set_col_bnds(prob, c, GLP_LO, 0.0, 0.0);
		glp_set_obj_coef(prob, c, 1);

	}
	/* adding n_t cols */
	for (c=c_mechs+1; c <= 2*c_mechs; c++)
	{
		GNUNET_asprintf(&name, "n%i",(c-c_mechs));
		glp_set_col_name(prob, c, name);
		GNUNET_free (name);
		glp_set_col_bnds(prob, c, GLP_DB, 0.0, 1.0);
		glp_set_col_kind(prob, c, GLP_IV);
		glp_set_obj_coef(prob, c, 0);
	}

	/* feasibility constraints */
	/* Constraint 1: one address per peer*/
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 1\n");
	row_index = 1;
	glp_add_rows(prob, c_peers);
	for (c=1; c<=c_peers; c++)
	{
		glp_set_row_bnds(prob, row_index, GLP_FX, 1.0, 1.0);

		struct ATS_mechanism *m = peers[c].m_head;
		while (m!=NULL)
		{
			ia[array_index] = row_index;
			ja[array_index] = (c_mechs + m->col_index);
			ar[array_index] = 1;
			if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
			array_index++;
			m = m->next;
		}
		row_index++;
	}

	/* Constraint 2: only active mechanism gets bandwidth assigned */
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 2\n");
	glp_add_rows(prob, c_mechs);
	for (c=1; c<=c_mechs; c++)
	{
		/* b_t - n_t * M <= 0 */
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
		glp_set_row_bnds(prob, row_index, GLP_UP, 0.0, 0.0);

		ia[array_index] = row_index;
		ja[array_index] = mechanisms[c].col_index;
		ar[array_index] = 1;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
		ia[array_index] = row_index;
		ja[array_index] = c_mechs + mechanisms[c].col_index;
		ar[array_index] = -M;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
		row_index ++;
	}

	/* Constraint 3: minimum bandwidth*/
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 3\n");
	glp_add_rows(prob, c_mechs);
	for (c=1; c<=c_mechs; c++)
	{
		/* b_t - n_t * b_min <= 0 */
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
		glp_set_row_bnds(prob, row_index, GLP_LO, 0.0, 0.0);

		ia[array_index] = row_index;
		ja[array_index] = mechanisms[c].col_index;
		ar[array_index] = 1;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
		ia[array_index] = row_index;
		ja[array_index] = c_mechs + mechanisms[c].col_index;
		ar[array_index] = -v_b_min;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
		row_index ++;
	}
	int c2;
	/* Constraint 4: max ressource capacity */
	/* V cr: bt * ct_r <= cr_max
	 * */

	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 4\n");
	glp_add_rows(prob, available_ressources);
	//double ct_max = 0.0;
	//double ct_1 = 0.0;
/*
	for (c=0; c<available_ressources; c++)
	{
		ct_max = ressources[c].c_max;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] %f\n",row_index, ct_max);
		glp_set_row_bnds(prob, row_index, GLP_DB, 0.0, ct_max);

		for (c2=1; c2<=c_mechs; c2++)
		{
			if (mechanisms[c2].rc[c].c_1 != 0)
			{
			ia[array_index] = row_index;
			ja[array_index] = mechanisms[c2].col_index;
			ar[array_index] = mechanisms[c2].rc[c].c_1;
			if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
			array_index++;
			}
		}
		row_index ++;
	}*/

	/* Constraint 5: min number of connections*/
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 5\n");
	glp_add_rows(prob, 1);
	for (c=1; c<=c_mechs; c++)
	{
		// b_t - n_t * b_min >= 0
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
		glp_set_row_bnds(prob, row_index, GLP_LO, v_n_min, 0.0);

		ia[array_index] = row_index;
		ja[array_index] = c_mechs + mechanisms[c].col_index;
		ar[array_index] = 1;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
	}
	row_index ++;

	/* optimisation constraints*/

	/* adding columns */
	glp_add_cols(prob, 3 + c_q_metrics);

	glp_set_col_name(prob, (2*c_mechs) + 1, "d");
	glp_set_obj_coef(prob, (2*c_mechs) + 1, D);
	glp_set_col_bnds(prob, (2*c_mechs) + 1, GLP_LO, 0.0, 0.0);
	glp_set_col_name(prob, (2*c_mechs) + 2, "u");
	glp_set_obj_coef(prob, (2*c_mechs) + 2, U);
	glp_set_col_bnds(prob, (2*c_mechs) + 2, GLP_LO, 0.0, 0.0);
	glp_set_col_name(prob, (2*c_mechs) + 3, "r");
	glp_set_obj_coef(prob, (2*c_mechs) + 3, R);
	glp_set_col_bnds(prob, (2*c_mechs) + 3, GLP_LO, 0.0, 0.0);

	for (c=1; c<= c_q_metrics; c++)
	{
		GNUNET_asprintf(&name, "Q_%s",qm[c-1].name);
		glp_set_col_name(prob, (2*c_mechs) + 3 + c, name);
		glp_set_col_bnds(prob, (2*c_mechs) + 3 + c, GLP_LO, 0.0, 0.0);
		GNUNET_free (name);
		glp_set_obj_coef(prob, (2*c_mechs) + 3 + c, Q[c]);
	}

	// Constraint 6: optimize for diversity
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 6\n");
	glp_add_rows(prob, 1);
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
	glp_set_row_bnds(prob, row_index, GLP_FX, 0.0, 0.0);
	//glp_set_row_bnds(prob, row_index, GLP_UP, 0.0, 0.0);
	for (c=1; c<=c_mechs; c++)
	{
		// b_t - n_t * b_min >= 0
		ia[array_index] = row_index;
		ja[array_index] = c_mechs + mechanisms[c].col_index;
		ar[array_index] = 1;
		//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
	}
	ia[array_index] = row_index;
	ja[array_index] = (2*c_mechs) + 1;
	ar[array_index] = -1;
	//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
	array_index++;
	row_index ++;


	// Constraint 7: optimize for quality

	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 7\n");
    glp_add_rows(prob, available_quality_metrics);
	for (c=1; c <= c_q_metrics; c++)
	{
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
		glp_set_row_bnds(prob, row_index, GLP_FX, 0.0, 0.0);

		for (c2=1; c2<=c_mechs; c2++)
		{
			double value = 0;
			ia[array_index] = row_index;
			ja[array_index] = c2;
			if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY)
			{
				if (mechanisms[c2].addr->latency.rel_value == -1)
					value = 0;
				if (mechanisms[c2].addr->latency.rel_value == 0)
					value = 0 ;
				else
					value = 100 / (double) mechanisms[c2].addr->latency.rel_value;

				//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "DELAY VALUE %f %llu\n",value, mechanisms[c2].addr->latency.rel_value);
			}
			if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE)
			{
				if (mechanisms[c2].addr->distance == -1)
					value = 0;
				else if (mechanisms[c2].addr->distance == 0)
					value = 0;
				else value =  (double) 10 / mechanisms[c2].addr->distance;
				//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "DISTANCE VALUE %f %lli\n",value,  mechanisms[c2].addr->distance);
			}
			ar[array_index] = (mechanisms[c2].peer->f) * value ;
			//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: %s [%i,%i]=%f \n",array_index, qm[c-1].name, ia[array_index], ja[array_index], ar[array_index]);
			array_index++;
		}

		ia[array_index] = row_index;
		ja[array_index] = (2*c_mechs) + 3 +c;
		ar[array_index] = -1;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
		row_index++;
	}

	// Constraint 8: optimize bandwidth utility
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 8\n");
	glp_add_rows(prob, 1);
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
	glp_set_row_bnds(prob, row_index, GLP_FX, 0.0, 0.0);
	for (c=1; c<=c_mechs; c++)
	{
		ia[array_index] = row_index;
		ja[array_index] = c;
		ar[array_index] = mechanisms[c].peer->f;
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;
	}
	ia[array_index] = row_index;
	ja[array_index] = (2*c_mechs) + 2;
	ar[array_index] = -1;
#if VERBOSE_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
#endif

	array_index++;
	row_index ++;

	// Constraint 9: optimize relativity
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Constraint 9\n");
	glp_add_rows(prob, c_peers);
	for (c=1; c<=c_peers; c++)
	{
		glp_set_row_bnds(prob, row_index, GLP_LO, 0.0, 0.0);

		struct ATS_mechanism *m = peers[c].m_head;
		while (m!=NULL)
		{
			ia[array_index] = row_index;
			ja[array_index] = m->col_index;
			ar[array_index] = 1;
			//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
			array_index++;
			m = m->next;
		}
		ia[array_index] = row_index;
		ja[array_index] = (2*c_mechs) + 3;
		ar[array_index] = -1;
		//if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",array_index, ia[array_index], ja[array_index], ar[array_index]);
		array_index++;

		row_index++;
	}
	glp_load_matrix(prob, array_index-1, ia, ja, ar);

	glp_smcp opt_lp;
	glp_init_smcp(&opt_lp);
	if (VERBOSE_ATS)
		opt_lp.msg_lev = GLP_MSG_ALL;
	else
		opt_lp.msg_lev = GLP_MSG_OFF;
	result = glp_simplex(prob, &opt_lp);

	glp_iocp opt_mlp;
	glp_init_iocp(&opt_mlp);
	/* maximum duration */
	opt_mlp.tm_lim = max_dur;
	/* output level */
	if (VERBOSE_ATS)
		opt_mlp.msg_lev = GLP_MSG_ALL;
	else
		opt_mlp.msg_lev = GLP_MSG_OFF;

	result = glp_intopt (prob, &opt_mlp);
	solution =  glp_mip_status (prob);

#if WRITE_MLP
	if (c_peers > 1)
	{
		char * filename;

		GNUNET_asprintf (&filename, "ats_mlp_p%i_m%i.mlp",c_peers, c_mechs);
		if (GNUNET_NO == GNUNET_DISK_file_test(filename))
			glp_write_lp (prob, NULL, filename);
		GNUNET_free (filename);
	}
#endif
#if VERBOSE_ATS



	switch (result) {
	case GLP_ESTOP  :    /* search terminated by application */
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Search terminated by application ");
		break;
	case GLP_EITLIM :    /* iteration limit exceeded */
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Iteration limit exceeded ");
		break;
	break;
	case GLP_ETMLIM :    /* time limit exceeded */
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Time limit exceeded ");
	break;
	case GLP_ENOPFS :    /* no primal feasible solution */
	case GLP_ENODFS :    /* no dual feasible solution */
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No feasible solution");
	break;

	case GLP_EBADB  :    /* invalid basis */
	case GLP_ESING  :    /* singular matrix */
	case GLP_ECOND  :    /* ill-conditioned matrix */
	case GLP_EBOUND :    /* invalid bounds */
	case GLP_EFAIL  :    /* solver failed */
	case GLP_EOBJLL :    /* objective lower limit reached */
	case GLP_EOBJUL :    /* objective upper limit reached */
	case GLP_EROOT  :    /* root LP optimum not provided */
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid Input data: %i\n", result);
	break;

	break;
		default:
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem has been solved\n");
	break;
	}

	switch (solution) {
		case GLP_UNDEF:
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MIP solution is undeﬁned\n");
			break;
		case GLP_OPT:
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MIP solution is integer optimal\n");
			break;
		case GLP_FEAS:
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MIP solution is integer feasible, however, its optimality (or non-optimality) has not been proven, \n");
			break;
		case GLP_NOFEAS:
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MI problem has no integer feasible solution\n");
			break;
			break;
		default:
			break;
	}
#endif
	int check;
	int error = GNUNET_NO;
	double bw;
	struct ATS_mechanism *t = NULL;
	for (c=1; c<= (c_peers); c++ )
	{
		check = GNUNET_NO;
		t = peers[c].m_head;
		while (t!=NULL)
		{
			bw = glp_get_col_prim(prob, t->col_index);
			if (bw > 1.0)
			{
				if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[%i][%i] `%s' %s %s %f\n", c, t->col_index, GNUNET_h2s(&peers[c].peer.hashPubKey), t->plugin->short_name, glp_get_col_name(prob,t->col_index), bw);
				if (check ==GNUNET_YES)
					error = GNUNET_YES;
				if (check ==GNUNET_NO)
					check = GNUNET_YES;
			}
			GNUNET_assert (error != GNUNET_YES);
			t = t->next;
		}
	}

	for (c=1; c<= c_q_metrics; c++ )
	{
		if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n", glp_get_col_name(prob,2*c_mechs+3+c), glp_get_col_prim(prob,2*c_mechs+3+c));
	}
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n", glp_get_col_name(prob,2*c_mechs+1), glp_get_col_prim(prob,2*c_mechs+1));
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n", glp_get_col_name(prob,2*c_mechs+2), glp_get_col_prim(prob,2*c_mechs+2));
	if (VERBOSE_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n", glp_get_col_name(prob,2*c_mechs+3), glp_get_col_prim(prob,2*c_mechs+3));

	res->c_mechs = c_mechs;
	res->c_peers = c_peers;
	res->solution = solution;

	/* clean up */


	glp_delete_prob(prob);

	GNUNET_free (ja);
	GNUNET_free (ia);
	GNUNET_free (ar);

	for (c=0; c<c_mechs; c++)
	{
		GNUNET_free_non_null (mechanisms[c].rc);
	}

	GNUNET_free(mechanisms);
	GNUNET_free(peers);

	return c_mechs;

}

void ats_calculate_bandwidth_distribution ()
{
	static int glpk = GNUNET_YES;
	struct GNUNET_TIME_Absolute start;
	struct GNUNET_TIME_Relative duration;
	struct ATS_result result;
	int c_mechs = 0;

	struct GNUNET_TIME_Relative delta = GNUNET_TIME_absolute_get_difference(ats->last,GNUNET_TIME_absolute_get());
	if (delta.rel_value < ats->min_delta.rel_value)
	{
#if DEBUG_ATS
		//GNUNET_log (GNUNET_ERROR_TYPE_BULK, "Minimum time between cycles not reached\n");
#endif
		return;
	}

	int dur = 500;
	if (INT_MAX < ats->max_exec_duration.rel_value)
		dur = INT_MAX;
	else
		dur = (int) ats->max_exec_duration.rel_value;

	start = GNUNET_TIME_absolute_get();

	if (glpk==GNUNET_YES)
	{
		start = GNUNET_TIME_absolute_get();
		c_mechs = ats_solve_problem(5000, 5000, 1.0, 1.0, 1.0, 1000, 5, &result);
		duration = GNUNET_TIME_absolute_get_difference(start,GNUNET_TIME_absolute_get());
		if (c_mechs > 0)
		{
			if (DEBUG_ATS) {GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MLP execution time in [ms] for %i mechanisms: %llu\n", c_mechs, duration.rel_value);}
			GNUNET_STATISTICS_set (stats, "ATS duration", duration.rel_value, GNUNET_NO);
			GNUNET_STATISTICS_set (stats, "ATS mechanisms", result.c_mechs, GNUNET_NO);
			GNUNET_STATISTICS_set (stats, "ATS peers", result.c_peers, GNUNET_NO);
			GNUNET_STATISTICS_set (stats, "ATS solution", result.solution, GNUNET_NO);
			GNUNET_STATISTICS_set (stats, "ATS timestamp", start.abs_value, GNUNET_NO);
		}
		else if (c_mechs == 0)
		{
			if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MLP not executed: no addresses\n");
		}
		else glpk = GNUNET_NO;
	}
	ats->last = GNUNET_TIME_absolute_get();
}



void
ats_schedule_calculation (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct ATS_info *ats = (struct ATS_info *) cls;
	if (ats==NULL)
		return;

	ats->ats_task = GNUNET_SCHEDULER_NO_TASK;
	if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
	    return;

#if DEBUG_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Running scheduled calculation\n");
#endif
	ats_calculate_bandwidth_distribution (ats);

	ats->ats_task = GNUNET_SCHEDULER_add_delayed (ats->exec_intervall,
	                                &ats_schedule_calculation, ats);
}

void ats_init ()
{
	ats = GNUNET_malloc(sizeof (struct ATS_info));

	ats->min_delta = ATS_MIN_INTERVAL;
	ats->exec_intervall = ATS_EXEC_INTERVAL;
	ats->max_exec_duration = ATS_MAX_EXEC_DURATION;
	ats->max_iterations = ATS_MAX_ITERATIONS;
	ats->ats_task = GNUNET_SCHEDULER_NO_TASK;

	int c = 0;
	unsigned long long  value;
	char * section;
	/* loading cost ressources */
	for (c=0; c<available_ressources; c++)
	{
		GNUNET_asprintf(&section,"%s_UP",ressources[c].cfg_param);
		if (GNUNET_CONFIGURATION_have_value(cfg, "transport", section))
		{
			GNUNET_CONFIGURATION_get_value_number(cfg, "transport",section, &value);
			if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Found ressource cost: [%s] = %llu\n", section, value);
			ressources[c].c_max = value;
		}
		GNUNET_free (section);
		GNUNET_asprintf(&section,"%s_DOWN",ressources[c].cfg_param);
		if (GNUNET_CONFIGURATION_have_value(cfg, "transport", section))
		{
			GNUNET_CONFIGURATION_get_value_number(cfg, "transport",section, &value);
			if (DEBUG_ATS) GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Found ressource cost: [%s] = %llu\n", section, value);
			ressources[c].c_min = value;
		}
		GNUNET_free (section);
	}

	ats->ats_task = GNUNET_SCHEDULER_add_now(&ats_schedule_calculation, ats);
}


void ats_shutdown ()
{
#if DEBUG_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ats_destroy\n");
#endif
	if (ats->ats_task != GNUNET_SCHEDULER_NO_TASK)
		GNUNET_SCHEDULER_cancel(ats->ats_task);
	ats->ats_task = GNUNET_SCHEDULER_NO_TASK;
/*
	struct ATS_plugin * p;
	struct ATS_ressource_cost * rc;

	p = ats->head;
	{
		GNUNET_CONTAINER_DLL_remove (ats->head,ats->tail, p);
		rc = p->head;
		while (p != NULL)
		{
			GNUNET_CONTAINER_DLL_remove (p->head,p->tail, rc);
			GNUNET_free(rc);
			rc = p->head;
		}
		GNUNET_free(p->short_name);
		GNUNET_free(p);
		p = ats->head;
	}
*/
	GNUNET_free (ats);
}


void ats_notify_peer_connect (
		const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_TRANSPORT_ATS_Information *ats_data)
{
	int c = 0;
#if DEBUG_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ats_notify_peer_connect: %s\n",GNUNET_i2s(peer));
#endif

	while (ntohl(ats_data[c].type)!=0)
	{
#if DEBUG_ATS
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ats type [%i]: %i\n",ntohl(ats_data[c].type), ntohl(ats_data[c].value));
#endif
		c++;
	}
	ats_calculate_bandwidth_distribution(ats);
}

void ats_notify_peer_disconnect (
		const struct GNUNET_PeerIdentity *peer)
{
#if DEBUG_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ats_notify_peer_disconnect: %s\n",GNUNET_i2s(peer));
#endif
	ats_calculate_bandwidth_distribution (ats);
}


void ats_notify_ats_data (
		const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_TRANSPORT_ATS_Information *ats_data)
{
#if DEBUG_ATS
	GNUNET_log (GNUNET_ERROR_TYPE_BULK, "ATS_notify_ats_data: %s\n",GNUNET_i2s(peer));
#endif
	ats_calculate_bandwidth_distribution(ats);
}

struct ForeignAddressList * ats_get_preferred_address (
		struct NeighbourList *n)
{
#if DEBUG_ATS
	//GNUNET_log (GNUNET_ERROR_TYPE_BULK, "ats_get_prefered_transport for peer: %s\n",GNUNET_i2s(&n->id));
#endif
	struct ReadyList *next = n->plugins;
	while (next != NULL)
	{
#if DEBUG_ATS
		//GNUNET_log (GNUNET_ERROR_TYPE_BULK, "plugin: %s %i\n",next->plugin->short_name,strcmp(next->plugin->short_name,"unix"));
#endif
		next = next->next;
	}
	return find_ready_address(n);
}

/**
 * Initiate transport service.
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
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_START, sizeof (struct StartMessage)},
    {&handle_hello, NULL,
     GNUNET_MESSAGE_TYPE_HELLO, 0},
    {&handle_send, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_SEND, 0},
    {&handle_request_connect, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT, sizeof(struct TransportRequestConnectMessage)},
    {&handle_set_quota, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA, sizeof (struct QuotaSetMessage)},
    {&handle_address_lookup, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP,
     0},
    {&handle_blacklist_init, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT, sizeof (struct GNUNET_MessageHeader)},
    {&handle_blacklist_reply, NULL,
     GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY, sizeof (struct BlacklistMessage)},
    {NULL, NULL, 0, 0}
  };
  char *plugs;
  char *pos;
  int no_transports;
  unsigned long long tneigh;
  char *keyfile;

  cfg = c;
  stats = GNUNET_STATISTICS_create ("transport", cfg);
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
      GNUNET_SCHEDULER_shutdown ();
      if (stats != NULL)
	{
	  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
	  stats = NULL;
	}
      GNUNET_CONTAINER_multihashmap_destroy (validation_map);
      validation_map = NULL;
      return;
    }

  max_connect_per_transport = (uint32_t) tneigh;
  peerinfo = GNUNET_PEERINFO_connect (cfg);
  if (peerinfo == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not access PEERINFO service.  Exiting.\n"));	
      GNUNET_SCHEDULER_shutdown ();
      if (stats != NULL)
	{
	  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
	  stats = NULL;
	}
      GNUNET_CONTAINER_multihashmap_destroy (validation_map);
      validation_map = NULL;
      GNUNET_free (keyfile);
      return;
    }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      if (stats != NULL)
	{
	  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
	  stats = NULL;
	}
      GNUNET_CONTAINER_multihashmap_destroy (validation_map);
      validation_map = NULL;
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);
  /* setup notification */
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
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
  if (no_transports)
    refresh_hello ();

  ats_init();

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transport service ready.\n"));
#endif
  /* If we have a blacklist file, read from it */
  read_blacklist_file(cfg);
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
  a2s (NULL, NULL, 0); /* make compiler happy */
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "transport",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-transport.c */
