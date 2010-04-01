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
 * @file dv/gnunet-service-dv.c
 * @brief the distance vector service, primarily handles gossip of nearby
 * peers and sending/receiving DV messages from core and decapsulating
 * them
 *
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_crypto_lib.h"
#include "dv.h"

/**
 * DV Service Context stuff goes here...
 */

/**
 * Handle to the core service api.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * The configuration for this service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The scheduler for this service.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * How often do we check about sending out more peer information (if
 * we are connected to no peers previously).
 */
#define GNUNET_DV_DEFAULT_SEND_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500))

/**
 * How long do we wait at most between sending out information?
 */
#define GNUNET_DV_MAX_SEND_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5))

/**
 * How long can we have not heard from a peer and
 * still have it in our tables?
 */
#define GNUNET_DV_PEER_EXPIRATION_TIME GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1000))

/**
 * Priority for gossip.
 */
#define GNUNET_DV_DHT_GOSSIP_PRIORITY (GNUNET_EXTREME_PRIORITY / 10)

/**
 * How often should we check if expiration time has elapsed for
 * some peer?
 */
#define GNUNET_DV_MAINTAIN_FREQUENCY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5))

/**
 * How long to allow a message to be delayed?
 */
#define DV_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5))

/**
 * Priority to use for DV data messages.
 */
#define DV_PRIORITY 0

/**
 * The client, should be the DV plugin connected to us.  Hopefully
 * this client will never change, although if the plugin dies
 * and returns for some reason it may happen.
 */
static struct GNUNET_SERVER_Client * client_handle;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

/**
 * Task to run to gossip about peers.  Will reschedule itself forever until shutdown!
 */
GNUNET_SCHEDULER_TaskIdentifier gossip_task;

/**
 * Struct where neighbor information is stored.
 */
struct DistantNeighbor *referees;

static struct GNUNET_TIME_Relative client_transmit_timeout;

static struct GNUNET_TIME_Relative default_dv_delay;

static size_t default_dv_priority = 0;


/**
 * Pending message struct, also a test to see if these can
 * safely ONLY be freed by callback.
 */
struct PendingMessage
{
  /**
   * Copy of message to be sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Size of message to be sent
   */
  size_t msg_size;

  /**
   * Transmit handle, for cancellation if necessary.
   */
  struct GNUNET_CORE_TransmitHandle *transmit_handle;

};


/**
 * Context created whenever a direct peer connects to us,
 * used to gossip other peers to it.
 */
struct NeighborSendContext
{
  /**
   * The peer we will gossip to.
   */
  struct DirectNeighbor *toNeighbor;

  /**
   * The timeout for this task.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * The task associated with this context.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

};


/**
 * Struct to hold information for updating existing neighbors
 */
struct NeighborUpdateInfo
{
  /**
   * Cost
   */
  unsigned int cost;

  /**
   * The existing neighbor
   */
  struct DistantNeighbor *neighbor;

  /**
   * The referrer of the possibly existing peer
   */
  struct DirectNeighbor *referrer;

  /**
   * The time we heard about this peer
   */
  struct GNUNET_TIME_Absolute now;
};

/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DirectNeighbor
{
  /**
   * Identity of neighbor.
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * PublicKey of neighbor.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  /**
   * Head of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_head;

  /**
   * Tail of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_tail;

  /**
   * The sending context for gossiping peers to this neighbor.
   */
  struct NeighborSendContext *send_context;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;
};


/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DistantNeighbor
{
  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *next;

  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *prev;

  /**
   * Node in min heap
   */
  struct GNUNET_CONTAINER_HeapNode *min_loc;

  /**
   * Node in max heap
   */
  struct GNUNET_CONTAINER_HeapNode *max_loc;

  /**
   * Identity of referrer (next hop towards 'neighbor').
   */
  struct DirectNeighbor *referrer;

  /**
   * Identity of neighbor.
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * PublicKey of neighbor.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  /**
   * Last time we received routing information from this peer
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;

  /**
   * Random identifier *we* use for this peer, to be used as shortcut
   * instead of sending full peer id for each message
   */
  unsigned int our_id;

  /**
   * Random identifier the *referrer* uses for this peer.
   */
  unsigned int referrer_id;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;

};

struct PeerIteratorContext
{
  /**
   * The actual context, to be freed later.
   */
  struct GNUNET_PEERINFO_IteratorContext *ic;

  /**
   * The neighbor about which we are concerned.
   */
  struct DirectNeighbor *neighbor;

};

/**
 * Context used for creating hello messages when
 * gossips are received.
 */
struct HelloContext
{
  /**
   * Identity of distant neighbor.
   */
  struct GNUNET_PeerIdentity *distant_peer;

  /**
   * Identity of direct neighbor, via which we send this message.
   */
  const struct GNUNET_PeerIdentity *direct_peer;

  /**
   * How many addresses do we need to add (always starts at 1, then set to 0)
   */
  int addresses_to_add;

};

/**
 * Global construct
 */
struct GNUNET_DV_Context
{
  /**
   * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for all
   * directly connected peers.
   */
  struct GNUNET_CONTAINER_MultiHashMap *direct_neighbors;

  /**
   * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for
   * peers connected via DV (extended neighborhood).  Does ALSO
   * include any peers that are in 'direct_neighbors'; for those
   * peers, the cost will be zero and the referrer all zeros.
   */
  struct GNUNET_CONTAINER_MultiHashMap *extended_neighbors;

  /**
   * We use the min heap (min refers to cost) to prefer
   * gossipping about peers with small costs.
   */
  struct GNUNET_CONTAINER_Heap *neighbor_min_heap;

  /**
   * We use the max heap (max refers to cost) for general
   * iterations over all peers and to remove the most costly
   * connection if we have too many.
   */
  struct GNUNET_CONTAINER_Heap *neighbor_max_heap;

  unsigned long long fisheye_depth;

  unsigned long long max_table_size;

  unsigned int neighbor_id_loc;

  int closing;

};

static struct GNUNET_DV_Context ctx;

struct FindDestinationContext
{
  unsigned int tid;
  struct DistantNeighbor *dest;
};


/**
 * We've been given a target ID based on the random numbers that
 * we assigned to our DV-neighborhood.  Find the entry for the
 * respective neighbor.
 */
static int
find_destination (void *cls,
                  struct GNUNET_CONTAINER_HeapNode *node,
                  void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindDestinationContext *fdc = cls;
  struct DistantNeighbor *dn = element;

  if (fdc->tid != dn->our_id)
    return GNUNET_YES;
  fdc->dest = dn;
  return GNUNET_NO;
}

/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t transmit_to_plugin (void *cls,
                           size_t size, void *buf)
{
  struct GNUNET_DV_MessageReceived *msg = cls;
  int msize;

  if (buf == NULL)
    return 0;

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Transmit to plugin sending message of type %d!\n", "dv", ntohs(msg->header.type));
#endif

  msize = ntohs(msg->header.size);
  GNUNET_assert(size >= msize);

  memcpy(buf, msg, msize);
  /* FIXME: this causes crash? GNUNET_free(msg);*/
  return msize;
}


void send_to_plugin(const struct GNUNET_PeerIdentity * sender,
                    const struct GNUNET_MessageHeader *message,
                    size_t message_size,
                    struct GNUNET_PeerIdentity *distant_neighbor,
                    size_t cost)
{
  struct GNUNET_DV_MessageReceived *received_msg;
  int size;

  size = sizeof(struct GNUNET_DV_MessageReceived) + sizeof(struct GNUNET_PeerIdentity) + message_size;
  received_msg = GNUNET_malloc(size);
  received_msg->header.size = htons(size);
  received_msg->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECEIVE);
  received_msg->sender_address_len = sizeof(struct GNUNET_PeerIdentity);
  received_msg->distance = htonl(cost);
  received_msg->msg_len = htons(message_size);
  /* Set the sender in this message to be the original sender! */
  memcpy(&received_msg->sender, &distant_neighbor, sizeof(struct GNUNET_PeerIdentity));
  /* Copy the intermediate sender to the end of the message, this is how the transport identifies this peer */
  memcpy(&received_msg[1], sender, sizeof(struct GNUNET_PeerIdentity));
  /* Copy the actual message after the sender */
  memcpy(&received_msg[1 + sizeof(struct GNUNET_PeerIdentity)], message, message_size);

  if (client_handle != NULL)
    {
      GNUNET_SERVER_notify_transmit_ready (client_handle,
                                           size, client_transmit_timeout,
                                           &transmit_to_plugin, received_msg);
    }

}


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t core_transmit_notify (void *cls,
                             size_t size, void *buf)
{
  struct PendingMessage *pending_message = cls;
  size_t ssize;

  if (buf == NULL)
    {
      /* FIXME: error handling: try again? free pending_message? */
      return 0;
    }
  ssize = pending_message->msg_size;
  GNUNET_assert(size >= ssize);
  memcpy(buf, pending_message->msg, ssize);
  GNUNET_free(pending_message->msg);
  GNUNET_free(pending_message);
  return ssize;
}

/**
 * Send a DV data message via DV.
 *
 * @param recipient the ultimate recipient of this message
 * @param the original sender of the message
 * @param message the packed message
 * @param importance what priority to send this message with
 * @param timeout how long to possibly delay sending this message
 */
static int
send_message (const struct GNUNET_PeerIdentity * recipient,
              const struct GNUNET_PeerIdentity * sender,
              const struct GNUNET_MessageHeader * message,
              unsigned int importance, struct GNUNET_TIME_Relative timeout)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int cost;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *target;
  struct DistantNeighbor *source;
  struct PendingMessage *pending_message;

  msg_size = ntohs (message->size) + sizeof (p2p_dv_MESSAGE_Data);

  target = GNUNET_CONTAINER_multihashmap_get (ctx.extended_neighbors,
                                              &recipient->hashPubKey);
  if (target == NULL)
    {
      /* target unknown to us, drop! */
      return GNUNET_SYSERR;
    }
  recipient_id = target->referrer_id;

  source = GNUNET_CONTAINER_multihashmap_get (ctx.extended_neighbors,
                                      &sender->hashPubKey);
  if (source == NULL)
    {
      if (0 != (memcmp (&my_identity,
                        sender, sizeof (struct GNUNET_PeerIdentity))))
        {
          /* sender unknown to us, drop! */
          return GNUNET_SYSERR;
        }
      sender_id = 0;            /* 0 == us */
    }
  else
    {
      /* find out the number that we use when we gossip about
         the sender */
      sender_id = source->our_id;
    }

  cost = target->cost;
  pending_message = GNUNET_malloc(sizeof(struct PendingMessage));
  pending_message->msg = GNUNET_malloc (msg_size);
  toSend = (p2p_dv_MESSAGE_Data *)pending_message->msg;
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DATA);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
  memcpy (&toSend[1], message, ntohs (message->size));
  pending_message->msg_size = msg_size;

  pending_message->transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, importance, timeout, &target->referrer->identity, msg_size, &core_transmit_notify, pending_message);
  if (NULL == pending_message->transmit_handle)
    {
      GNUNET_free (pending_message->msg);
      GNUNET_free (pending_message);
      return GNUNET_SYSERR;
    }

  /*coreAPI->ciphertext_send (&target->referrer->identity,
                            &toSend->header, importance, maxdelay);*/
  return (int) cost;
}


/**
 * Core handler for dv data messages.  Whatever this message
 * contains all we really have to do is rip it out of its
 * DV layering and give it to our pal the DV plugin to report
 * in with.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param latency the latency of the connection we received the message from
 * @param distance the distance to the immediate peer
 */
static int handle_dv_data_message (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message!\n", "dv", "DV DATA");
#endif

  const p2p_dv_MESSAGE_Data *incoming = (const p2p_dv_MESSAGE_Data *) message;
  const struct GNUNET_MessageHeader *packed_message = (const struct GNUNET_MessageHeader *) &incoming[1];
  struct DirectNeighbor *dn;
  struct DistantNeighbor *pos;
  unsigned int sid;             /* Sender id */
  unsigned int tid;             /* Target id */
  struct GNUNET_PeerIdentity original_sender;
  struct GNUNET_PeerIdentity destination;
  struct FindDestinationContext fdc;
  int ret;

  if ((ntohs (incoming->header.size) <
       sizeof (p2p_dv_MESSAGE_Data) + sizeof (struct GNUNET_MessageHeader))
      || (ntohs (incoming->header.size) !=
          (sizeof (p2p_dv_MESSAGE_Data) + ntohs (packed_message->size))))
    {
      return GNUNET_SYSERR;
    }

  dn = GNUNET_CONTAINER_multihashmap_get (ctx.direct_neighbors,
                                  &peer->hashPubKey);
  if (dn == NULL)
    {
      return GNUNET_OK;
    }
  sid = ntohl (incoming->sender);
  pos = dn->referee_head;
  while ((NULL != pos) && (pos->referrer_id != sid))
    pos = pos->next;
  if (pos == NULL)
    {
      /* unknown sender */
      return GNUNET_OK;
    }
  original_sender = pos->identity;
  tid = ntohl (incoming->recipient);
  if (tid == 0)
    {
      /* 0 == us */

      /* FIXME: Will we support wrapped messages being these types? Probably not, they should
       * be encrypted messages that need decrypting and junk like that.
       */
      GNUNET_break_op (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP);
      GNUNET_break_op (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_DATA);
      if ( (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP) &&
          (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_DATA) )
      {
        send_to_plugin(peer, packed_message, ntohs(packed_message->size), &pos->identity, pos->cost);
      }

      return GNUNET_OK;
    }

  /* FIXME: this is the *only* per-request operation we have in DV
     that is O(n) in relation to the number of connected peers; a
     hash-table lookup could easily solve this (minor performance
     issue) */
  fdc.tid = tid;
  fdc.dest = NULL;
  GNUNET_CONTAINER_heap_iterate (ctx.neighbor_max_heap,
                                 &find_destination, &fdc);
  if (fdc.dest == NULL)
    {
      return GNUNET_OK;
    }
  destination = fdc.dest->identity;

  if (0 == memcmp (&destination, peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      /* FIXME: create stat: routing loop-discard! */
      return GNUNET_OK;
    }

  /* At this point we have a message, and we need to forward it on to the
   * next DV hop.
   */
  /* FIXME: Can't send message on, we have to behave.
   * We have to tell core we have a message for the next peer, and let
   * transport do transport selection on how to get this message to 'em */
  /*ret = send_message (&destination,
                      &original_sender,
                      packed_message, DV_PRIORITY, DV_DELAY);*/
  ret = send_message(&destination, &original_sender, packed_message, default_dv_priority, default_dv_delay);

  if (ret != GNUNET_SYSERR)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}


/**
 * Thread which chooses a peer to gossip about and a peer to gossip
 * to, then constructs the message and sends it out.  Will run until
 * done_module_dv is called.
 */
static void
neighbor_send_task (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighborSendContext *send_context = cls;
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Entering neighbor_send_task...\n",
              GNUNET_i2s(&my_identity));
  char * encPeerAbout;
  char * encPeerTo;
#endif
  struct DistantNeighbor *about;
  struct DirectNeighbor *to;

  p2p_dv_MESSAGE_NeighborInfo *message;
  struct PendingMessage *pending_message;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Called with reason shutdown, shutting down!\n",
              GNUNET_i2s(&my_identity));
#endif
    send_context->toNeighbor->send_context = NULL;
    GNUNET_free(send_context);
    return;
  }


  /* FIXME: this may become a problem, because the heap walk has only one internal "walker".  This means
   * that if two neighbor_send_tasks are operating in lockstep (which is quite possible, given default
   * values for all connected peers) there may be a serious bias as to which peers get gossiped about!
   * Probably the *best* way to fix would be to have an opaque pointer to the walk position passed as
   * part of the walk_get_next call.  Then the heap would have to keep a list of walks, or reset the walk
   * whenever a modification has been detected.  Yuck either way.  Perhaps we could iterate over the heap
   * once to get a list of peers to gossip about and gossip them over time... But then if one goes away
   * in the mean time that becomes nasty.  For now we'll just assume that the walking is done
   * asynchronously enough to avoid major problems (-;
   */
  about = GNUNET_CONTAINER_heap_walk_get_next (ctx.neighbor_min_heap);
  to = send_context->toNeighbor;

  if ((about != NULL) && (to != about->referrer /* split horizon */ ) &&
#if SUPPORT_HIDING
      (about->hidden == GNUNET_NO) &&
#endif
      (to != NULL) &&
      (0 != memcmp (&about->identity,
                        &to->identity, sizeof (struct GNUNET_PeerIdentity))))
    {
#if DEBUG_DV
      encPeerAbout = GNUNET_strdup(GNUNET_i2s(&about->identity));
      encPeerTo = GNUNET_strdup(GNUNET_i2s(&to->identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Sending info about peer %s to directly connected peer %s\n",
                  GNUNET_i2s(&my_identity),
                  encPeerAbout, encPeerTo);
      GNUNET_free(encPeerAbout);
      GNUNET_free(encPeerTo);
#endif
      pending_message = GNUNET_malloc(sizeof(struct PendingMessage));
      pending_message->msg = GNUNET_malloc(sizeof(p2p_dv_MESSAGE_NeighborInfo));
      message = (p2p_dv_MESSAGE_NeighborInfo *)pending_message->msg;
      message->header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
      message->header.type = htons (GNUNET_MESSAGE_TYPE_DV_GOSSIP);
      message->cost = htonl (about->cost);
      message->neighbor_id = htonl (about->our_id);

      memcpy (&message->pkey, &about->pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
      memcpy (&message->neighbor,
              &about->identity, sizeof (struct GNUNET_PeerIdentity));

      pending_message->msg_size = sizeof(p2p_dv_MESSAGE_NeighborInfo);
      pending_message->transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, default_dv_priority, default_dv_delay, &to->identity, sizeof(p2p_dv_MESSAGE_NeighborInfo), &core_transmit_notify, pending_message);

      if (NULL == pending_message->transmit_handle)
        {
          GNUNET_free (pending_message->msg);
          GNUNET_free (pending_message);
          return;
        }
      /*coreAPI->ciphertext_send (&to->identity, &message.header,
                                GNUNET_DV_DHT_GOSSIP_PRIORITY,
                                ctx.send_interval);*/
    }

  GNUNET_SCHEDULER_add_delayed(sched, send_context->timeout, &neighbor_send_task, send_context);
  return;
}


/**
 * Handle START-message.  This is the first message sent to us
 * by the client (can only be one!).
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

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client\n", "START");
#endif

  GNUNET_assert(client_handle == NULL);
  client_handle = client;

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Service server's handler for message send requests (which come
 * bubbling up to us through the DV plugin).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void send_dv_message (void *cls,
                      struct GNUNET_SERVER_Client * client,
                      const struct GNUNET_MessageHeader * message)
{
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message!\n", "dv", "SEND");
#endif
  if (client_handle == NULL)
  {
    client_handle = client;
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Setting initial client handle!\n", "dv");
#endif
  }
  else if (client_handle != client)
  {
    client_handle = client;
    /* What should we do in this case, assert fail or just log the warning? */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s: Setting client handle (was a different client!)!\n", "dv");
  }

  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

static int handle_dv_gossip_message (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message,
                                     struct GNUNET_TIME_Relative latency,
                                     uint32_t distance);

/**
 * List of handlers for the messages understood by this
 * service.
 *
 * Hmm... will we need to register some handlers with core and
 * some handlers with our server here?  Because core should be
 * getting the incoming DV messages (from whichever lower level
 * transport) and then our server should be getting messages
 * from the dv_plugin, right?
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dv_data_message, GNUNET_MESSAGE_TYPE_DV_DATA, 0},
  {&handle_dv_gossip_message, GNUNET_MESSAGE_TYPE_DV_GOSSIP, 0},
  {NULL, 0, 0}
};


static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&send_dv_message, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND, 0},
  {&handle_start, NULL, GNUNET_MESSAGE_TYPE_DV_START, 0},
  {NULL, NULL, 0, 0}
};


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CORE_disconnect (coreAPI);
}

/**
 * To be called on core init/fail.
 */
void core_init (void *cls,
                struct GNUNET_CORE_Handle * server,
                const struct GNUNET_PeerIdentity *identity,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded * publicKey)
{

  if (server == NULL)
    {
      GNUNET_SCHEDULER_cancel(sched, cleanup_task);
      GNUNET_SCHEDULER_add_now(sched, &shutdown_task, NULL);
      return;
    }
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dv", GNUNET_i2s(identity));
#endif
  memcpy(&my_identity, identity, sizeof(struct GNUNET_PeerIdentity));
  coreAPI = server;
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int update_matching_neighbors (void *cls,
                                      const GNUNET_HashCode * key,
                                      void *value)
{
  struct NeighborUpdateInfo * update_info = cls;
  struct DistantNeighbor *distant_neighbor = value;

  if (update_info->referrer == distant_neighbor->referrer) /* Direct neighbor matches, update it's info and return GNUNET_NO */
  {
    /* same referrer, cost change! */
    GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_max_heap,
                                       update_info->neighbor->max_loc, update_info->cost);
    GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_min_heap,
                                       update_info->neighbor->min_loc, update_info->cost);
    update_info->neighbor->last_activity = update_info->now;
    update_info->neighbor->cost = update_info->cost;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


/**
 * Free a DistantNeighbor node, including removing it
 * from the referer's list.
 */
static void
distant_neighbor_free (struct DistantNeighbor *referee)
{
  struct DirectNeighbor *referrer;

  referrer = referee->referrer;
  if (referrer != NULL)
    {
      GNUNET_CONTAINER_DLL_remove (referrer->referee_head,
                         referrer->referee_tail, referee);
    }
  GNUNET_CONTAINER_heap_remove_node (ctx.neighbor_max_heap, referee->max_loc);
  GNUNET_CONTAINER_heap_remove_node (ctx.neighbor_min_heap, referee->min_loc);
  GNUNET_CONTAINER_multihashmap_remove_all (ctx.extended_neighbors,
                                    &referee->identity.hashPubKey);
  GNUNET_free (referee);
}


/**
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when the cost for a neighbor
 * needs to be updated.
 *
 * @param peer identity of the peer whose info is being added/updated
 * @param pkey public key of the peer whose info is being added/updated
 * @param referrer_peer_id id to use when sending to 'peer'
 * @param referrer if this is a gossiped peer, who did we hear it from?
 * @param cost the cost of communicating with this peer via 'referrer'
 */
static void
addUpdateNeighbor (const struct GNUNET_PeerIdentity * peer, struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey,
                   unsigned int referrer_peer_id,
                   struct DirectNeighbor *referrer, unsigned int cost)
{
  struct DistantNeighbor *neighbor;
  struct DistantNeighbor *max;
  struct GNUNET_TIME_Absolute now;
  struct NeighborUpdateInfo *neighbor_update;
  unsigned int our_id;

  now = GNUNET_TIME_absolute_get ();
  our_id = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, RAND_MAX - 1) + 1;

  neighbor = GNUNET_CONTAINER_multihashmap_get (ctx.extended_neighbors,
                                                &peer->hashPubKey);
  neighbor_update = GNUNET_malloc(sizeof(struct NeighborUpdateInfo));
  neighbor_update->neighbor = neighbor;
  neighbor_update->cost = cost;
  neighbor_update->now = now;
  neighbor_update->referrer = referrer;

  /* Either we do not know this peer, or we already do but via a different immediate peer */
  if ((neighbor == NULL) ||
      (GNUNET_CONTAINER_multihashmap_get_multiple(ctx.extended_neighbors,
                                                  &peer->hashPubKey,
                                                  &update_matching_neighbors,
                                                  neighbor_update) != GNUNET_SYSERR))
    {
      /* new neighbor! */
      if (cost > ctx.fisheye_depth)
        {
          /* too costly */
          GNUNET_free(neighbor_update);
          return;
        }
      if (ctx.max_table_size <=
          GNUNET_CONTAINER_multihashmap_size (ctx.extended_neighbors))
        {
          /* remove most expensive entry */
          max = GNUNET_CONTAINER_heap_peek (ctx.neighbor_max_heap);
          if (cost > max->cost)
            {
              /* new entry most expensive, don't create */
              GNUNET_free(neighbor_update);
              return;
            }
          if (max->cost > 0)
            {
              /* only free if this is not a direct connection;
                 we could theoretically have more direct
                 connections than DV entries allowed total! */
              distant_neighbor_free (max);
            }
        }

      neighbor = GNUNET_malloc (sizeof (struct DistantNeighbor));
      GNUNET_CONTAINER_DLL_insert (referrer->referee_head,
                         referrer->referee_tail, neighbor);
      neighbor->max_loc = GNUNET_CONTAINER_heap_insert (ctx.neighbor_max_heap,
                                                        neighbor, cost);
      neighbor->min_loc = GNUNET_CONTAINER_heap_insert (ctx.neighbor_min_heap,
                                                        neighbor, cost);
      neighbor->referrer = referrer;
      memcpy (&neighbor->identity, peer, sizeof (struct GNUNET_PeerIdentity));
      if (pkey != NULL) /* pkey will be null on direct neighbor addition */
        memcpy (&neighbor->pkey, pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
      neighbor->last_activity = now;
      neighbor->cost = cost;
      neighbor->referrer_id = referrer_peer_id;
      neighbor->our_id = our_id;
      neighbor->hidden =
        (cost == 0) ? (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 4) ==
                       0) : GNUNET_NO;
      GNUNET_CONTAINER_multihashmap_put (ctx.extended_neighbors, &peer->hashPubKey,
                                 neighbor,
                                 GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  else
    {
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Already know peer %s distance %d, referrer id %d!\n", "dv", GNUNET_i2s(peer), cost, referrer_peer_id);
#endif
    }
#if DEBUG_DV
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Size of extended_neighbors is %d\n", "dv", GNUNET_CONTAINER_multihashmap_size(ctx.extended_neighbors));
#endif
  GNUNET_free(neighbor_update);
  /* Old logic to remove entry and replace, not needed now as we only want to remove when full
   * or when the referring peer disconnects from us.
   */
  /*
  GNUNET_DLL_remove (neighbor->referrer->referee_head,
                     neighbor->referrer->referee_tail, neighbor);
  neighbor->referrer = referrer;
  GNUNET_DLL_insert (referrer->referee_head,
                     referrer->referee_tail, neighbor);
  GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_max_heap,
                                     neighbor->max_loc, cost);
  GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_min_heap,
                                     neighbor->min_loc, cost);
  neighbor->referrer_id = referrer_peer_id;
  neighbor->last_activity = now;
  neighbor->cost = cost;
  */
}


static size_t
generate_hello_address (void *cls, size_t max, void *buf)
{
  struct HelloContext *hello_context = cls;
  char *addr_buffer;
  size_t offset;
  size_t size;
  size_t ret;

  if (hello_context->addresses_to_add == 0)
    return 0;

  /* Hello "address" will be concatenation of distant peer and direct peer identities */
  size = 2 * sizeof(struct GNUNET_PeerIdentity);
  fprintf(stdout, "size is %lu, max is %lu\n", size, max);
  GNUNET_assert(max >= size);

  addr_buffer = GNUNET_malloc(size);
  offset = 0;
  /* Copy the distant peer identity to buffer */
  memcpy(addr_buffer, hello_context->distant_peer, sizeof(struct GNUNET_PeerIdentity));
  offset += sizeof(struct GNUNET_PeerIdentity);
  /* Copy the direct peer identity to buffer */
  memcpy(&addr_buffer[offset], hello_context->direct_peer, sizeof(struct GNUNET_PeerIdentity));
  ret = GNUNET_HELLO_add_address ("dv",
                                  GNUNET_TIME_relative_to_absolute
                                  (GNUNET_TIME_UNIT_HOURS), addr_buffer, size,
                                  buf, max);

  hello_context->addresses_to_add--;

  return ret;
}


/**
 * Core handler for dv gossip messages.  These will be used
 * by us to create a HELLO message for the newly peer containing
 * which direct peer we can connect through, and what the cost
 * is.  This HELLO will then be scheduled for validation by the
 * transport service so that it can be used by all others.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param latency the latency of the connection we received the message from
 * @param distance the distance to the immediate peer
 */
static int handle_dv_gossip_message (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message,
                                     struct GNUNET_TIME_Relative latency,
                                     uint32_t distance)
{
  struct HelloContext *hello_context;
  struct GNUNET_HELLO_Message *hello_msg;
  struct DirectNeighbor *referrer;
  p2p_dv_MESSAGE_NeighborInfo *enc_message = (p2p_dv_MESSAGE_NeighborInfo *)message;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_NeighborInfo))
    {
      return GNUNET_SYSERR;     /* invalid message */
    }

#if DEBUG_DV
  char * encPeerAbout;
  char * encPeerFrom;

  encPeerAbout = GNUNET_strdup(GNUNET_i2s(&enc_message->neighbor));
  encPeerFrom = GNUNET_strdup(GNUNET_i2s(peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives %s message from peer %s about peer %s!\n", "dv", "DV GOSSIP", encPeerFrom, encPeerAbout);
  GNUNET_free(encPeerAbout);
  GNUNET_free(encPeerFrom);
#endif

  referrer = GNUNET_CONTAINER_multihashmap_get (ctx.direct_neighbors,
                                                &peer->hashPubKey);
  if (referrer == NULL)
    return GNUNET_OK;

  addUpdateNeighbor (&enc_message->neighbor, &enc_message->pkey,
                     ntohl (enc_message->neighbor_id),
                     referrer, ntohl (enc_message->cost) + 1);

  hello_context = GNUNET_malloc(sizeof(struct HelloContext));
  hello_context->direct_peer = peer;
  hello_context->distant_peer = &enc_message->neighbor;
  hello_context->addresses_to_add = 1;
  hello_msg = GNUNET_HELLO_create(&enc_message->pkey, &generate_hello_address, hello_context);

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Sending %s message to plugin!\n", "dv", "HELLO");
#endif

  send_to_plugin(&enc_message->neighbor, GNUNET_HELLO_get_header(hello_msg), GNUNET_HELLO_size(hello_msg), hello_context->distant_peer, ntohl(enc_message->cost) + 1);
  return GNUNET_OK;
}

static void
process_peerinfo (void *cls,
         const struct GNUNET_PeerIdentity *peer,
         const struct GNUNET_HELLO_Message *hello, uint32_t trust)
{
  struct PeerIteratorContext *peerinfo_iterator = cls;
  struct DirectNeighbor *neighbor = peerinfo_iterator->neighbor;

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: process_peerinfo called!\n", "dv");
#endif

  if ((peer == NULL))/* && (neighbor->pkey == NULL))*/
    {
      /* FIXME: Remove peer! */
      return;
    }

  if (memcmp(&neighbor->identity, peer, sizeof(struct GNUNET_PeerIdentity) != 0))
    return;

  if ((hello != NULL) && (GNUNET_HELLO_get_key (hello, &neighbor->pkey) == GNUNET_OK))
    {
      neighbor->send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, neighbor->send_context);
    }
}

/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with peer
 * @param distance reported distance (DV) to peer
 */
void handle_core_connect (void *cls,
                          const struct GNUNET_PeerIdentity * peer,
                          struct GNUNET_TIME_Relative latency,
                          uint32_t distance)
{
  struct DirectNeighbor *neighbor;
  struct PeerIteratorContext *peerinfo_iterator;
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core connect message for peer %s distance %d!\n", "dv", GNUNET_i2s(peer), distance);
#endif

  if ((distance == 0) && (GNUNET_CONTAINER_multihashmap_get(ctx.direct_neighbors, &peer->hashPubKey) == NULL))
  {
    peerinfo_iterator = GNUNET_malloc(sizeof(struct PeerIteratorContext));
    neighbor = GNUNET_malloc (sizeof (struct DirectNeighbor));
    neighbor->send_context = GNUNET_malloc(sizeof(struct NeighborSendContext));
    neighbor->send_context->toNeighbor = neighbor;
    neighbor->send_context->timeout = default_dv_delay; /* FIXME: base this on total gossip tasks, or bandwidth */
    memcpy (&neighbor->identity, peer, sizeof (struct GNUNET_PeerIdentity));
    /*memcpy (&neighbor->pkey, ,sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));*/
    GNUNET_CONTAINER_multihashmap_put (ctx.direct_neighbors,
                               &peer->hashPubKey,
                               neighbor, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    addUpdateNeighbor (peer, NULL, 0, neighbor, 0);
    peerinfo_iterator->neighbor = neighbor;
    peerinfo_iterator->ic = GNUNET_PEERINFO_iterate (cfg,
                                            sched,
                                            peer,
                                            0,
                                            GNUNET_TIME_relative_multiply
                                            (GNUNET_TIME_UNIT_SECONDS, 15),
                                            &process_peerinfo, peerinfo_iterator);
    /* Only add once we get the publicKey of this guy
     *
     * neighbor->send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, neighbor->send_context);
     */
  }
  else
  {
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Distance (%d) greater than 0 or already know about peer (%s), not re-adding!\n", "dv", distance, GNUNET_i2s(peer));
#endif
    return;
  }
}

/**
 * Method called whenever a given peer either connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void handle_core_disconnect (void *cls,
                             const struct GNUNET_PeerIdentity * peer)
{
  struct DirectNeighbor *neighbor;
  struct DistantNeighbor *referee;

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core peer disconnect message!\n", "dv");
#endif

  neighbor =
    GNUNET_CONTAINER_multihashmap_get (ctx.direct_neighbors, &peer->hashPubKey);
  if (neighbor == NULL)
    {
      return;
    }
  while (NULL != (referee = neighbor->referee_head))
    distant_neighbor_free (referee);
  GNUNET_assert (neighbor->referee_tail == NULL);
  GNUNET_CONTAINER_multihashmap_remove (ctx.direct_neighbors,
                                &peer->hashPubKey, neighbor);
  if ((neighbor->send_context != NULL) && (neighbor->send_context->task != GNUNET_SCHEDULER_NO_TASK))
    GNUNET_SCHEDULER_cancel(sched, neighbor->send_context->task);
  GNUNET_free (neighbor);
}


/**
 * Process dv requests.
 *
 * @param cls closure
 * @param scheduler scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *scheduler,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_TIME_Relative timeout;
  unsigned long long max_hosts;
  timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  sched = scheduler;
  cfg = c;

  /* FIXME: Read from config, or calculate, or something other than this! */
  max_hosts = 50;
  ctx.max_table_size = 100;
  ctx.fisheye_depth = 3;

  ctx.neighbor_min_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  ctx.neighbor_max_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);

  ctx.direct_neighbors = GNUNET_CONTAINER_multihashmap_create (max_hosts);
  ctx.extended_neighbors =
    GNUNET_CONTAINER_multihashmap_create (ctx.max_table_size * 3);

  client_transmit_timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  default_dv_delay = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  coreAPI =
  GNUNET_CORE_connect (sched,
                       cfg,
                       timeout,
                       NULL, /* FIXME: anything we want to pass around? */
                       &core_init,
                       NULL, /* Don't care about pre-connects */
                       &handle_core_connect,
                       &handle_core_disconnect,
                       NULL,
                       GNUNET_NO,
                       NULL,
                       GNUNET_NO,
                       core_handlers);

  if (coreAPI == NULL)
    return;
  /* load (server); Huh? */

  /* Scheduled the task to clean up when shutdown is called */
  cleanup_task = GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The main function for the dv service.
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
                              "dv",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}
