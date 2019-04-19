/*
     This file is part of GNUnet.
     Copyright (C) 2013-2015 GNUnet e.V.

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
 * @file rps/gnunet-service-rps.c
 * @brief rps service implementation
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_core_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_nse_service.h"
#include "gnunet_statistics_service.h"
#include "rps.h"
#include "rps-test_util.h"
#include "gnunet-service-rps_sampler.h"
#include "gnunet-service-rps_custommap.h"
#include "gnunet-service-rps_view.h"

#include <math.h>
#include <inttypes.h>
#include <string.h>

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO check for overflows

// TODO align message structs

// TODO connect to friends

// TODO blacklist? (-> mal peer detection on top of brahms)

// hist_size_init, hist_size_max

/***********************************************************************
 * Old gnunet-service-rps_peers.c
***********************************************************************/

/**
 * Set a peer flag of given peer context.
 */
#define SET_PEER_FLAG(peer_ctx, mask) ((peer_ctx->peer_flags) |= (mask))

/**
 * Get peer flag of given peer context.
 */
#define check_peer_flag_set(peer_ctx, mask)\
  ((peer_ctx->peer_flags) & (mask) ? GNUNET_YES : GNUNET_NO)

/**
 * Unset flag of given peer context.
 */
#define UNSET_PEER_FLAG(peer_ctx, mask) ((peer_ctx->peer_flags) &= ~(mask))

/**
 * Get channel flag of given channel context.
 */
#define check_channel_flag_set(channel_flags, mask)\
  ((*channel_flags) & (mask) ? GNUNET_YES : GNUNET_NO)

/**
 * Unset flag of given channel context.
 */
#define unset_channel_flag(channel_flags, mask) ((*channel_flags) &= ~(mask))



/**
 * Pending operation on peer consisting of callback and closure
 *
 * When an operation cannot be executed right now this struct is used to store
 * the callback and closure for later execution.
 */
struct PeerPendingOp
{
  /**
   * Callback
   */
  PeerOp op;

  /**
   * Closure
   */
  void *op_cls;
};

/**
 * List containing all messages that are yet to be send
 *
 * This is used to keep track of all messages that have not been sent yet. When
 * a peer is to be removed the pending messages can be removed properly.
 */
struct PendingMessage
{
  /**
   * DLL next, prev
   */
  struct PendingMessage *next;
  struct PendingMessage *prev;

  /**
   * The envelope to the corresponding message
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * The corresponding context
   */
  struct PeerContext *peer_ctx;

  /**
   * The message type
   */
  const char *type;
};

/**
 * @brief Context for a channel
 */
struct ChannelCtx;

/**
 * Struct used to keep track of other peer's status
 *
 * This is stored in a multipeermap.
 * It contains information such as cadet channels, a message queue for sending,
 * status about the channels, the pending operations on this peer and some flags
 * about the status of the peer itself. (online, valid, ...)
 */
struct PeerContext
{
  /**
   * The Sub this context belongs to.
   */
  struct Sub *sub;

  /**
   * Message queue open to client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Channel open to client.
   */
  struct ChannelCtx *send_channel_ctx;

  /**
   * Channel open from client.
   */
  struct ChannelCtx *recv_channel_ctx;

  /**
   * Array of pending operations on this peer.
   */
  struct PeerPendingOp *pending_ops;

  /**
   * Handle to the callback given to cadet_ntfy_tmt_rdy()
   *
   * To be canceled on shutdown.
   */
  struct PendingMessage *online_check_pending;

  /**
   * Number of pending operations.
   */
  unsigned int num_pending_ops;

  /**
   * Identity of the peer
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Flags indicating status of peer
   */
  uint32_t peer_flags;

  /**
   * Last time we received something from that peer.
   */
  struct GNUNET_TIME_Absolute last_message_recv;

  /**
   * Last time we received a keepalive message.
   */
  struct GNUNET_TIME_Absolute last_keepalive;

  /**
   * DLL with all messages that are yet to be sent
   */
  struct PendingMessage *pending_messages_head;
  struct PendingMessage *pending_messages_tail;

  /**
   * This is pobably followed by 'statistical' data (when we first saw
   * it, how did we get its ID, how many pushes (in a timeinterval),
   * ...)
   */
  uint32_t round_pull_req;
};

/**
 * @brief Closure to #valid_peer_iterator
 */
struct PeersIteratorCls
{
  /**
   * Iterator function
   */
  PeersIterator iterator;

  /**
   * Closure to iterator
   */
  void *cls;
};

/**
 * @brief Context for a channel
 */
struct ChannelCtx
{
  /**
   * @brief The channel itself
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * @brief The peer context associated with the channel
   */
  struct PeerContext *peer_ctx;

  /**
   * @brief When channel destruction needs to be delayed (because it is called
   * from within the cadet routine of another channel destruction) this task
   * refers to the respective _SCHEDULER_Task.
   */
  struct GNUNET_SCHEDULER_Task *destruction_task;
};


#if ENABLE_MALICIOUS

/**
 * If type is 2 This struct is used to store the attacked peers in a DLL
 */
struct AttackedPeer
{
  /**
   * DLL
   */
  struct AttackedPeer *next;
  struct AttackedPeer *prev;

  /**
   * PeerID
   */
  struct GNUNET_PeerIdentity peer_id;
};

#endif /* ENABLE_MALICIOUS */

/**
 * @brief This number determines the number of slots for files that represent
 * histograms
 */
#define HISTOGRAM_FILE_SLOTS 32

/**
 * @brief The size (in bytes) a file needs to store the histogram
 *
 * Per slot: 1 newline, up to 4 chars,
 * Additionally: 1 null termination
 */
#define SIZE_DUMP_FILE (HISTOGRAM_FILE_SLOTS * 5) + 1

/**
 * @brief One Sub.
 *
 * Essentially one instance of brahms that only connects to other instances
 * with the same (secret) value.
 */
struct Sub
{
  /**
   * @brief Hash of the shared value that defines Subs.
   */
  struct GNUNET_HashCode hash;

  /**
   * @brief Port to communicate to other peers.
   */
  struct GNUNET_CADET_Port *cadet_port;

  /**
   * @brief Hashmap of valid peers.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *valid_peers;

  /**
   * @brief Filename of the file that stores the valid peers persistently.
   */
  char *filename_valid_peers;

  /**
   * Set of all peers to keep track of them.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peer_map;

  /**
   * @brief This is the minimum estimate used as sampler size.
   *
   * It is configured by the user.
   */
  unsigned int sampler_size_est_min;

  /**
   * The size of sampler we need to be able to satisfy the Brahms protocol's
   * need of random peers.
   *
   * This is one minimum size the sampler grows to.
   */
  unsigned int sampler_size_est_need;

  /**
   * Time interval the do_round task runs in.
   */
  struct GNUNET_TIME_Relative round_interval;

  /**
   * Sampler used for the Brahms protocol itself.
   */
  struct RPS_Sampler *sampler;

#ifdef TO_FILE_FULL
  /**
   * Name to log view to
   */
  char *file_name_view_log;
#endif /* TO_FILE_FULL */

#ifdef TO_FILE
#ifdef TO_FILE_FULL
  /**
   * Name to log number of observed peers to
   */
  char *file_name_observed_log;
#endif /* TO_FILE_FULL */

  /**
   * @brief Count the observed peers
   */
  uint32_t num_observed_peers;

  /**
   * @brief Multipeermap (ab-) used to count unique peer_ids
   */
  struct GNUNET_CONTAINER_MultiPeerMap *observed_unique_peers;
#endif /* TO_FILE */

  /**
   * List to store peers received through pushes temporary.
   */
  struct CustomPeerMap *push_map;

  /**
   * List to store peers received through pulls temporary.
   */
  struct CustomPeerMap *pull_map;

  /**
   * @brief This is the estimate used as view size.
   *
   * It is initialised with the minimum
   */
  unsigned int view_size_est_need;

  /**
   * @brief This is the minimum estimate used as view size.
   *
   * It is configured by the user.
   */
  unsigned int view_size_est_min;

  /**
   * @brief The view.
   */
  struct View *view;

  /**
   * Identifier for the main task that runs periodically.
   */
  struct GNUNET_SCHEDULER_Task *do_round_task;

  /* === stats === */

  /**
   * @brief Counts the executed rounds.
   */
  uint32_t num_rounds;

  /**
   * @brief This array accumulates the number of received pushes per round.
   *
   * Number at index i represents the number of rounds with i observed pushes.
   */
  uint32_t push_recv[HISTOGRAM_FILE_SLOTS];

  /**
   * @brief Histogram of deltas between the expected and actual number of
   * received pushes.
   *
   * As half of the entries are expected to be negative, this is shifted by
   * #HISTOGRAM_FILE_SLOTS/2.
   */
  uint32_t push_delta[HISTOGRAM_FILE_SLOTS];

  /**
   * @brief Number of pull replies with this delay measured in rounds.
   *
   * Number at index i represents the number of pull replies with a delay of i
   * rounds.
   */
  uint32_t pull_delays[HISTOGRAM_FILE_SLOTS];
};


/***********************************************************************
 * Globals
***********************************************************************/

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handler to CADET.
 */
struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Handle to CORE
 */
struct GNUNET_CORE_Handle *core_handle;

/**
 * @brief PeerMap to keep track of connected peers.
 */
struct GNUNET_CONTAINER_MultiPeerMap *map_single_hop;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity own_identity;

/**
 * Percentage of total peer number in the view
 * to send random PUSHes to
 */
static float alpha;

/**
 * Percentage of total peer number in the view
 * to send random PULLs to
 */
static float beta;

/**
 * Handler to NSE.
 */
static struct GNUNET_NSE_Handle *nse;

/**
 * Handler to PEERINFO.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo_handle;

/**
 * Handle for cancellation of iteration over peers.
 */
static struct GNUNET_PEERINFO_NotifyContext *peerinfo_notify_handle;


#if ENABLE_MALICIOUS
/**
 * Type of malicious peer
 *
 * 0 Don't act malicious at all - Default
 * 1 Try to maximise representation
 * 2 Try to partition the network
 * 3 Combined attack
 */
static uint32_t mal_type;

/**
 * Other malicious peers
 */
static struct GNUNET_PeerIdentity *mal_peers;

/**
 * Hashmap of malicious peers used as set.
 * Used to more efficiently check whether we know that peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *mal_peer_set;

/**
 * Number of other malicious peers
 */
static uint32_t num_mal_peers;


/**
 * If type is 2 this is the DLL of attacked peers
 */
static struct AttackedPeer *att_peers_head;
static struct AttackedPeer *att_peers_tail;

/**
 * This index is used to point to an attacked peer to
 * implement the round-robin-ish way to select attacked peers.
 */
static struct AttackedPeer *att_peer_index;

/**
 * Hashmap of attacked peers used as set.
 * Used to more efficiently check whether we know that peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *att_peer_set;

/**
 * Number of attacked peers
 */
static uint32_t num_attacked_peers;

/**
 * If type is 1 this is the attacked peer
 */
static struct GNUNET_PeerIdentity attacked_peer;

/**
 * The limit of PUSHes we can send in one round.
 * This is an assumption of the Brahms protocol and either implemented
 * via proof of work
 * or
 * assumend to be the bandwidth limitation.
 */
static uint32_t push_limit = 10000;
#endif /* ENABLE_MALICIOUS */

/**
 * @brief Main Sub.
 *
 * This is run in any case by all peers and connects to all peers without
 * specifying a shared value.
 */
static struct Sub *msub;

/**
 * @brief Maximum number of valid peers to keep.
 * TODO read from config
 */
static const uint32_t num_valid_peers_max = UINT32_MAX;

/***********************************************************************
 * /Globals
***********************************************************************/


static void
do_round (void *cls);

static void
do_mal_round (void *cls);


/**
 * @brief Get the #PeerContext associated with a peer
 *
 * @param peer_map The peer map containing the context
 * @param peer the peer id
 *
 * @return the #PeerContext
 */
static struct PeerContext *
get_peer_ctx (const struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
              const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *ctx;
  int ret;

  ret = GNUNET_CONTAINER_multipeermap_contains (peer_map, peer);
  GNUNET_assert (GNUNET_YES == ret);
  ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);
  GNUNET_assert (NULL != ctx);
  return ctx;
}

/**
 * @brief Check whether we have information about the given peer.
 *
 * FIXME probably deprecated. Make this the new _online.
 *
 * @param peer_map The peer map to check for the existence of @a peer
 * @param peer peer in question
 *
 * @return #GNUNET_YES if peer is known
 *         #GNUNET_NO  if peer is not knwon
 */
static int
check_peer_known (const struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
                  const struct GNUNET_PeerIdentity *peer)
{
  if (NULL != peer_map)
  {
    return GNUNET_CONTAINER_multipeermap_contains (peer_map, peer);
  }
  else
  {
    return GNUNET_NO;
  }
}


/**
 * @brief Create a new #PeerContext and insert it into the peer map
 *
 * @param sub The Sub this context belongs to.
 * @param peer the peer to create the #PeerContext for
 *
 * @return the #PeerContext
 */
static struct PeerContext *
create_peer_ctx (struct Sub *sub,
                 const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *ctx;
  int ret;

  GNUNET_assert (GNUNET_NO == check_peer_known (sub->peer_map, peer));

  ctx = GNUNET_new (struct PeerContext);
  ctx->peer_id = *peer;
  ctx->sub = sub;
  ret = GNUNET_CONTAINER_multipeermap_put (sub->peer_map, peer, ctx,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  GNUNET_assert (GNUNET_OK == ret);
  if (sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                          "# known peers",
                          GNUNET_CONTAINER_multipeermap_size (sub->peer_map),
                          GNUNET_NO);
  }
  return ctx;
}


/**
 * @brief Create or get a #PeerContext
 *
 * @param sub The Sub to which the created context belongs to
 * @param peer the peer to get the associated context to
 *
 * @return the context
 */
static struct PeerContext *
create_or_get_peer_ctx (struct Sub *sub,
                        const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == check_peer_known (sub->peer_map, peer))
  {
    return create_peer_ctx (sub, peer);
  }
  return get_peer_ctx (sub->peer_map, peer);
}


/**
 * @brief Check whether we have a connection to this @a peer
 *
 * Also sets the #Peers_ONLINE flag accordingly
 *
 * @param peer_ctx Context of the peer of which connectivity is to be checked
 *
 * @return #GNUNET_YES if we are connected
 *         #GNUNET_NO  otherwise
 */
static int
check_connected (struct PeerContext *peer_ctx)
{
  /* If we don't know about this peer we don't know whether it's online */
  if (GNUNET_NO == check_peer_known (peer_ctx->sub->peer_map,
                                     &peer_ctx->peer_id))
  {
    return GNUNET_NO;
  }
  /* Get the context */
  peer_ctx = get_peer_ctx (peer_ctx->sub->peer_map, &peer_ctx->peer_id);
  /* If we have no channel to this peer we don't know whether it's online */
  if ( (NULL == peer_ctx->send_channel_ctx) &&
       (NULL == peer_ctx->recv_channel_ctx) )
  {
    UNSET_PEER_FLAG (peer_ctx, Peers_ONLINE);
    return GNUNET_NO;
  }
  /* Otherwise (if we have a channel, we know that it's online */
  SET_PEER_FLAG (peer_ctx, Peers_ONLINE);
  return GNUNET_YES;
}


/**
 * @brief The closure to #get_rand_peer_iterator.
 */
struct GetRandPeerIteratorCls
{
  /**
   * @brief The index of the peer to return.
   * Will be decreased until 0.
   * Then current peer is returned.
   */
  uint32_t index;

  /**
   * @brief Pointer to peer to return.
   */
  const struct GNUNET_PeerIdentity *peer;
};


/**
 * @brief Iterator function for #get_random_peer_from_peermap.
 *
 * Implements #GNUNET_CONTAINER_PeerMapIterator.
 * Decreases the index until the index is null.
 * Then returns the current peer.
 *
 * @param cls the #GetRandPeerIteratorCls containing index and peer
 * @param peer current peer
 * @param value unused
 *
 * @return  #GNUNET_YES if we should continue to
 *          iterate,
 *          #GNUNET_NO if not.
 */
static int
get_rand_peer_iterator (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct GetRandPeerIteratorCls *iterator_cls = cls;
  (void) value;

  if (0 >= iterator_cls->index)
  {
    iterator_cls->peer = peer;
    return GNUNET_NO;
  }
  iterator_cls->index--;
  return GNUNET_YES;
}


/**
 * @brief Get a random peer from @a peer_map
 *
 * @param valid_peers Peer map containing valid peers from which to select a
 * random one
 *
 * @return a random peer
 */
static const struct GNUNET_PeerIdentity *
get_random_peer_from_peermap (struct GNUNET_CONTAINER_MultiPeerMap *valid_peers)
{
  struct GetRandPeerIteratorCls *iterator_cls;
  const struct GNUNET_PeerIdentity *ret;

  iterator_cls = GNUNET_new (struct GetRandPeerIteratorCls);
  iterator_cls->index = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
      GNUNET_CONTAINER_multipeermap_size (valid_peers));
  (void) GNUNET_CONTAINER_multipeermap_iterate (valid_peers,
                                                get_rand_peer_iterator,
                                                iterator_cls);
  ret = iterator_cls->peer;
  GNUNET_free (iterator_cls);
  return ret;
}


/**
 * @brief Add a given @a peer to valid peers.
 *
 * If valid peers are already #num_valid_peers_max, delete a peer previously.
 *
 * @param peer The peer that is added to the valid peers.
 * @param valid_peers Peer map of valid peers to which to add the @a peer
 *
 * @return #GNUNET_YES if no other peer had to be removed
 *         #GNUNET_NO  otherwise
 */
static int
add_valid_peer (const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_CONTAINER_MultiPeerMap *valid_peers)
{
  const struct GNUNET_PeerIdentity *rand_peer;
  int ret;

  ret = GNUNET_YES;
  /* Remove random peers until there is space for a new one */
  while (num_valid_peers_max <=
         GNUNET_CONTAINER_multipeermap_size (valid_peers))
  {
    rand_peer = get_random_peer_from_peermap (valid_peers);
    GNUNET_CONTAINER_multipeermap_remove_all (valid_peers, rand_peer);
    ret = GNUNET_NO;
  }
  (void) GNUNET_CONTAINER_multipeermap_put (valid_peers, peer, NULL,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  if (valid_peers == msub->valid_peers)
  {
    GNUNET_STATISTICS_set (stats,
                           "# valid peers",
                           GNUNET_CONTAINER_multipeermap_size (valid_peers),
                           GNUNET_NO);
  }
  return ret;
}

static void
remove_pending_message (struct PendingMessage *pending_msg, int cancel);

/**
 * @brief Set the peer flag to living and
 *        call the pending operations on this peer.
 *
 * Also adds peer to #valid_peers.
 *
 * @param peer_ctx the #PeerContext of the peer to set online
 */
static void
set_peer_online (struct PeerContext *peer_ctx)
{
  struct GNUNET_PeerIdentity *peer;
  unsigned int i;

  peer = &peer_ctx->peer_id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Peer %s is online and valid, calling %i pending operations on it\n",
      GNUNET_i2s (peer),
      peer_ctx->num_pending_ops);

  if (NULL != peer_ctx->online_check_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Removing pending online check for peer %s\n",
         GNUNET_i2s (&peer_ctx->peer_id));
    // TODO wait until cadet sets mq->cancel_impl
    //GNUNET_MQ_send_cancel (peer_ctx->online_check_pending->ev);
    remove_pending_message (peer_ctx->online_check_pending, GNUNET_YES);
    peer_ctx->online_check_pending = NULL;
  }

  SET_PEER_FLAG (peer_ctx, Peers_ONLINE);

  /* Call pending operations */
  for (i = 0; i < peer_ctx->num_pending_ops; i++)
  {
    peer_ctx->pending_ops[i].op (peer_ctx->pending_ops[i].op_cls, peer);
  }
  GNUNET_array_grow (peer_ctx->pending_ops, peer_ctx->num_pending_ops, 0);
}

static void
cleanup_destroyed_channel (void *cls,
                           const struct GNUNET_CADET_Channel *channel);

/* Declaration of handlers */
static void
handle_peer_check (void *cls,
                   const struct GNUNET_MessageHeader *msg);

static void
handle_peer_push (void *cls,
                  const struct GNUNET_MessageHeader *msg);

static void
handle_peer_pull_request (void *cls,
                          const struct GNUNET_MessageHeader *msg);

static int
check_peer_pull_reply (void *cls,
                       const struct GNUNET_RPS_P2P_PullReplyMessage *msg);

static void
handle_peer_pull_reply (void *cls,
                        const struct GNUNET_RPS_P2P_PullReplyMessage *msg);

/* End declaration of handlers */

/**
 * @brief Allocate memory for a new channel context and insert it into DLL
 *
 * @param peer_ctx context of the according peer
 *
 * @return The channel context
 */
static struct ChannelCtx *
add_channel_ctx (struct PeerContext *peer_ctx)
{
  struct ChannelCtx *channel_ctx;
  channel_ctx = GNUNET_new (struct ChannelCtx);
  channel_ctx->peer_ctx = peer_ctx;
  return channel_ctx;
}


/**
 * @brief Free memory and NULL pointers.
 *
 * @param channel_ctx The channel context.
 */
static void
remove_channel_ctx (struct ChannelCtx *channel_ctx)
{
  struct PeerContext *peer_ctx = channel_ctx->peer_ctx;

  if (NULL != channel_ctx->destruction_task)
  {
    GNUNET_SCHEDULER_cancel (channel_ctx->destruction_task);
    channel_ctx->destruction_task = NULL;
  }

  GNUNET_free (channel_ctx);

  if (NULL == peer_ctx) return;
  if (channel_ctx == peer_ctx->send_channel_ctx)
  {
    peer_ctx->send_channel_ctx = NULL;
    peer_ctx->mq = NULL;
  }
  else if (channel_ctx == peer_ctx->recv_channel_ctx)
  {
    peer_ctx->recv_channel_ctx = NULL;
  }
}


/**
 * @brief Get the channel of a peer. If not existing, create.
 *
 * @param peer_ctx Context of the peer of which to get the channel
 * @return the #GNUNET_CADET_Channel used to send data to @a peer_ctx
 */
struct GNUNET_CADET_Channel *
get_channel (struct PeerContext *peer_ctx)
{
  /* There exists a copy-paste-clone in run() */
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_fixed_size (peer_check,
                             GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (peer_push,
                             GNUNET_MESSAGE_TYPE_RPS_PP_PUSH,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (peer_pull_request,
                             GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (peer_pull_reply,
                           GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY,
                           struct GNUNET_RPS_P2P_PullReplyMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };


  if (NULL == peer_ctx->send_channel_ctx)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to establish channel to peer %s\n",
         GNUNET_i2s (&peer_ctx->peer_id));
    peer_ctx->send_channel_ctx = add_channel_ctx (peer_ctx);
    peer_ctx->send_channel_ctx->channel =
      GNUNET_CADET_channel_create (cadet_handle,
                                   peer_ctx->send_channel_ctx, /* context */
                                   &peer_ctx->peer_id,
                                   &peer_ctx->sub->hash,
                                   GNUNET_CADET_OPTION_RELIABLE,
                                   NULL, /* WindowSize handler */
                                   &cleanup_destroyed_channel, /* Disconnect handler */
                                   cadet_handlers);
  }
  GNUNET_assert (NULL != peer_ctx->send_channel_ctx);
  GNUNET_assert (NULL != peer_ctx->send_channel_ctx->channel);
  return peer_ctx->send_channel_ctx->channel;
}


/**
 * Get the message queue (#GNUNET_MQ_Handle) of a specific peer.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 *
 * @param peer_ctx Context of the peer of whicht to get the mq
 * @return the #GNUNET_MQ_Handle
 */
static struct GNUNET_MQ_Handle *
get_mq (struct PeerContext *peer_ctx)
{
  if (NULL == peer_ctx->mq)
  {
    peer_ctx->mq = GNUNET_CADET_get_mq (get_channel (peer_ctx));
  }
  return peer_ctx->mq;
}

/**
 * @brief Add an envelope to a message passed to mq to list of pending messages
 *
 * @param peer_ctx Context of the peer for which to insert the envelope
 * @param ev envelope to the message
 * @param type type of the message to be sent
 * @return pointer to pending message
 */
static struct PendingMessage *
insert_pending_message (struct PeerContext *peer_ctx,
                        struct GNUNET_MQ_Envelope *ev,
                        const char *type)
{
  struct PendingMessage *pending_msg;

  pending_msg = GNUNET_new (struct PendingMessage);
  pending_msg->ev = ev;
  pending_msg->peer_ctx = peer_ctx;
  pending_msg->type = type;
  GNUNET_CONTAINER_DLL_insert (peer_ctx->pending_messages_head,
                               peer_ctx->pending_messages_tail,
                               pending_msg);
  return pending_msg;
}


/**
 * @brief Remove a pending message from the respective DLL
 *
 * @param pending_msg the pending message to remove
 * @param cancel whether to cancel the pending message, too
 */
static void
remove_pending_message (struct PendingMessage *pending_msg, int cancel)
{
  struct PeerContext *peer_ctx;
  (void) cancel;

  peer_ctx = pending_msg->peer_ctx;
  GNUNET_assert (NULL != peer_ctx);
  GNUNET_CONTAINER_DLL_remove (peer_ctx->pending_messages_head,
                               peer_ctx->pending_messages_tail,
                               pending_msg);
  // TODO wait for the cadet implementation of message cancellation
  //if (GNUNET_YES == cancel)
  //{
  //  GNUNET_MQ_send_cancel (pending_msg->ev);
  //}
  GNUNET_free (pending_msg);
}


/**
 * @brief This is called in response to the first message we sent as a
 * online check.
 *
 * @param cls #PeerContext of peer with pending online check
 */
static void
mq_online_check_successful (void *cls)
{
  struct PeerContext *peer_ctx = cls;

  if (NULL != peer_ctx->online_check_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Online check for peer %s was successfull\n",
        GNUNET_i2s (&peer_ctx->peer_id));
    remove_pending_message (peer_ctx->online_check_pending, GNUNET_YES);
    peer_ctx->online_check_pending = NULL;
    set_peer_online (peer_ctx);
    (void) add_valid_peer (&peer_ctx->peer_id, peer_ctx->sub->valid_peers);
  }
}

/**
 * Issue a check whether peer is online
 *
 * @param peer_ctx the context of the peer
 */
static void
check_peer_online (struct PeerContext *peer_ctx)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Get informed about peer %s getting online\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE);
  peer_ctx->online_check_pending =
    insert_pending_message (peer_ctx, ev, "Check online");
  mq = get_mq (peer_ctx);
  GNUNET_MQ_notify_sent (ev,
                         mq_online_check_successful,
                         peer_ctx);
  GNUNET_MQ_send (mq, ev);
  if (peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# pending online checks",
                              1,
                              GNUNET_NO);
  }
}


/**
 * @brief Check whether function of type #PeerOp was already scheduled
 *
 * The array with pending operations will probably never grow really big, so
 * iterating over it should be ok.
 *
 * @param peer_ctx Context of the peer to check for the operation
 * @param peer_op the operation (#PeerOp) on the peer
 *
 * @return #GNUNET_YES if this operation is scheduled on that peer
 *         #GNUNET_NO  otherwise
 */
static int
check_operation_scheduled (const struct PeerContext *peer_ctx,
                           const PeerOp peer_op)
{
  unsigned int i;

  for (i = 0; i < peer_ctx->num_pending_ops; i++)
    if (peer_op == peer_ctx->pending_ops[i].op)
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * @brief Callback for scheduler to destroy a channel
 *
 * @param cls Context of the channel
 */
static void
destroy_channel (struct ChannelCtx *channel_ctx)
{
  struct GNUNET_CADET_Channel *channel;

  if (NULL != channel_ctx->destruction_task)
  {
    GNUNET_SCHEDULER_cancel (channel_ctx->destruction_task);
    channel_ctx->destruction_task = NULL;
  }
  GNUNET_assert (channel_ctx->channel != NULL);
  channel = channel_ctx->channel;
  channel_ctx->channel = NULL;
  GNUNET_CADET_channel_destroy (channel);
  remove_channel_ctx (channel_ctx);
}


/**
 * @brief Destroy a cadet channel.
 *
 * This satisfies the function signature of #GNUNET_SCHEDULER_TaskCallback.
 *
 * @param cls
 */
static void
destroy_channel_cb (void *cls)
{
  struct ChannelCtx *channel_ctx = cls;

  channel_ctx->destruction_task = NULL;
  destroy_channel (channel_ctx);
}


/**
 * @brief Schedule the destruction of a channel for immediately afterwards.
 *
 * In case a channel is to be destroyed from within the callback to the
 * destruction of another channel (send channel), we cannot call
 * GNUNET_CADET_channel_destroy directly, but need to use this scheduling
 * construction.
 *
 * @param channel_ctx channel to be destroyed.
 */
static void
schedule_channel_destruction (struct ChannelCtx *channel_ctx)
{
  GNUNET_assert (NULL ==
                 channel_ctx->destruction_task);
  GNUNET_assert (NULL !=
                 channel_ctx->channel);
  channel_ctx->destruction_task =
    GNUNET_SCHEDULER_add_now (&destroy_channel_cb,
                              channel_ctx);
}


/**
 * @brief Remove peer
 *
 * - Empties the list with pending operations
 * - Empties the list with pending messages
 * - Cancels potentially existing online check
 * - Schedules closing of send and recv channels
 * - Removes peer from peer map
 *
 * @param peer_ctx Context of the peer to be destroyed
 * @return #GNUNET_YES if peer was removed
 *         #GNUNET_NO  otherwise
 */
static int
destroy_peer (struct PeerContext *peer_ctx)
{
  GNUNET_assert (NULL != peer_ctx);
  GNUNET_assert (NULL != peer_ctx->sub->peer_map);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (peer_ctx->sub->peer_map,
                                              &peer_ctx->peer_id))
  {
    return GNUNET_NO;
  }
  SET_PEER_FLAG (peer_ctx, Peers_TO_DESTROY);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to remove peer %s\n",
       GNUNET_i2s (&peer_ctx->peer_id));
  UNSET_PEER_FLAG (peer_ctx, Peers_ONLINE);

  /* Clear list of pending operations */
  // TODO this probably leaks memory
  //      ('only' the cls to the function. Not sure what to do with it)
  GNUNET_array_grow (peer_ctx->pending_ops,
                     peer_ctx->num_pending_ops,
                     0);
  /* Remove all pending messages */
  while (NULL != peer_ctx->pending_messages_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Removing unsent %s\n",
         peer_ctx->pending_messages_head->type);
    /* Cancle pending message, too */
    if ( (NULL != peer_ctx->online_check_pending) &&
         (0 == memcmp (peer_ctx->pending_messages_head,
                     peer_ctx->online_check_pending,
                     sizeof (struct PendingMessage))) )
      {
        peer_ctx->online_check_pending = NULL;
        if (peer_ctx->sub == msub)
        {
          GNUNET_STATISTICS_update (stats,
                                    "# pending online checks",
                                    -1,
                                    GNUNET_NO);
        }
      }
    remove_pending_message (peer_ctx->pending_messages_head,
                            GNUNET_YES);
  }

  /* If we are still waiting for notification whether this peer is online
   * cancel the according task */
  if (NULL != peer_ctx->online_check_pending)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Removing pending online check for peer %s\n",
                GNUNET_i2s (&peer_ctx->peer_id));
    // TODO wait until cadet sets mq->cancel_impl
    //GNUNET_MQ_send_cancel (peer_ctx->online_check_pending->ev);
    remove_pending_message (peer_ctx->online_check_pending,
                            GNUNET_YES);
    peer_ctx->online_check_pending = NULL;
  }

  if (NULL != peer_ctx->send_channel_ctx)
  {
    /* This is possibly called from within channel destruction */
    peer_ctx->send_channel_ctx->peer_ctx = NULL;
    schedule_channel_destruction (peer_ctx->send_channel_ctx);
    peer_ctx->send_channel_ctx = NULL;
    peer_ctx->mq = NULL;
  }
  if (NULL != peer_ctx->recv_channel_ctx)
  {
    /* This is possibly called from within channel destruction */
    peer_ctx->recv_channel_ctx->peer_ctx = NULL;
    schedule_channel_destruction (peer_ctx->recv_channel_ctx);
    peer_ctx->recv_channel_ctx = NULL;
  }

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_remove_all (peer_ctx->sub->peer_map,
                                                &peer_ctx->peer_id))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "removing peer from peer_ctx->sub->peer_map failed\n");
  }
  if (peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                          "# known peers",
                          GNUNET_CONTAINER_multipeermap_size (peer_ctx->sub->peer_map),
                          GNUNET_NO);
  }
  GNUNET_free (peer_ctx);
  return GNUNET_YES;
}


/**
 * Iterator over hash map entries. Deletes all contexts of peers.
 *
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
peermap_clear_iterator (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct Sub *sub = cls;
  (void) value;

  destroy_peer (get_peer_ctx (sub->peer_map, key));
  return GNUNET_YES;
}


/**
 * @brief This is called once a message is sent.
 *
 * Removes the pending message
 *
 * @param cls type of the message that was sent
 */
static void
mq_notify_sent_cb (void *cls)
{
  struct PendingMessage *pending_msg = (struct PendingMessage *) cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "%s was sent.\n",
      pending_msg->type);
  if (pending_msg->peer_ctx->sub == msub)
  {
    if (0 == strncmp ("PULL REPLY", pending_msg->type, 10))
      GNUNET_STATISTICS_update(stats, "# pull replys sent", 1, GNUNET_NO);
    if (0 == strncmp ("PULL REQUEST", pending_msg->type, 12))
      GNUNET_STATISTICS_update(stats, "# pull requests sent", 1, GNUNET_NO);
    if (0 == strncmp ("PUSH", pending_msg->type, 4))
      GNUNET_STATISTICS_update(stats, "# pushes sent", 1, GNUNET_NO);
    if (0 == strncmp ("PULL REQUEST", pending_msg->type, 12) &&
                      NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
          &pending_msg->peer_ctx->peer_id))
      GNUNET_STATISTICS_update(stats,
                               "# pull requests sent (multi-hop peer)",
                               1,
                               GNUNET_NO);
  }
  /* Do not cancle message */
  remove_pending_message (pending_msg, GNUNET_NO);
}


/**
 * @brief Iterator function for #store_valid_peers.
 *
 * Implements #GNUNET_CONTAINER_PeerMapIterator.
 * Writes single peer to disk.
 *
 * @param cls the file handle to write to.
 * @param peer current peer
 * @param value unused
 *
 * @return  #GNUNET_YES if we should continue to
 *          iterate,
 *          #GNUNET_NO if not.
 */
static int
store_peer_presistently_iterator (void *cls,
                                  const struct GNUNET_PeerIdentity *peer,
                                  void *value)
{
  const struct GNUNET_DISK_FileHandle *fh = cls;
  char peer_string[128];
  int size;
  ssize_t ret;
  (void) value;

  if (NULL == peer)
  {
    return GNUNET_YES;
  }
  size = GNUNET_snprintf (peer_string,
                          sizeof (peer_string),
                          "%s\n",
                          GNUNET_i2s_full (peer));
  GNUNET_assert (53 == size);
  ret = GNUNET_DISK_file_write (fh,
                                peer_string,
                                size);
  GNUNET_assert (size == ret);
  return GNUNET_YES;
}


/**
 * @brief Store the peers currently in #valid_peers to disk.
 *
 * @param sub Sub for which to store the valid peers
 */
static void
store_valid_peers (const struct Sub *sub)
{
  struct GNUNET_DISK_FileHandle *fh;
  uint32_t number_written_peers;
  int ret;

  if (0 == strncmp ("DISABLE", sub->filename_valid_peers, 7))
  {
    return;
  }

  ret = GNUNET_DISK_directory_create_for_file (sub->filename_valid_peers);
  if (GNUNET_SYSERR == ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to create directory for file `%s'\n",
        sub->filename_valid_peers);
    GNUNET_break (0);
  }
  else if (GNUNET_NO == ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Directory for file `%s' exists but is not writable for us\n",
        sub->filename_valid_peers);
    GNUNET_break (0);
  }
  fh = GNUNET_DISK_file_open (sub->filename_valid_peers,
                              GNUNET_DISK_OPEN_WRITE |
                                  GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_READ |
                                  GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fh)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to write valid peers to file `%s'\n",
        sub->filename_valid_peers);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Writing %u valid peers to disk\n",
      GNUNET_CONTAINER_multipeermap_size (sub->valid_peers));
  number_written_peers =
    GNUNET_CONTAINER_multipeermap_iterate (sub->valid_peers,
                                           store_peer_presistently_iterator,
                                           fh);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  GNUNET_assert (number_written_peers ==
      GNUNET_CONTAINER_multipeermap_size (sub->valid_peers));
}


/**
 * @brief Convert string representation of peer id to peer id.
 *
 * Counterpart to #GNUNET_i2s_full.
 *
 * @param string_repr The string representation of the peer id
 *
 * @return The peer id
 */
static const struct GNUNET_PeerIdentity *
s2i_full (const char *string_repr)
{
  struct GNUNET_PeerIdentity *peer;
  size_t len;
  int ret;

  peer = GNUNET_new (struct GNUNET_PeerIdentity);
  len = strlen (string_repr);
  if (52 > len)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to convert string representation of PeerID to PeerID\n"
        "Sting representation: %s (len %lu) - too short\n",
        string_repr,
        len);
    GNUNET_break (0);
  }
  else if (52 < len)
  {
    len = 52;
  }
  ret = GNUNET_CRYPTO_eddsa_public_key_from_string (string_repr,
                                                    len,
                                                    &peer->public_key);
  if (GNUNET_OK != ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to convert string representation of PeerID to PeerID\n"
        "Sting representation: %s\n",
        string_repr);
    GNUNET_break (0);
  }
  return peer;
}


/**
 * @brief Restore the peers on disk to #valid_peers.
 *
 * @param sub Sub for which to restore the valid peers
 */
static void
restore_valid_peers (const struct Sub *sub)
{
  off_t file_size;
  uint32_t num_peers;
  struct GNUNET_DISK_FileHandle *fh;
  char *buf;
  ssize_t size_read;
  char *iter_buf;
  char *str_repr;
  const struct GNUNET_PeerIdentity *peer;

  if (0 == strncmp ("DISABLE", sub->filename_valid_peers, 7))
  {
    return;
  }

  if (GNUNET_OK != GNUNET_DISK_file_test (sub->filename_valid_peers))
  {
    return;
  }
  fh = GNUNET_DISK_file_open (sub->filename_valid_peers,
                              GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  GNUNET_assert (NULL != fh);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_handle_size (fh, &file_size));
  num_peers = file_size / 53;
  buf = GNUNET_malloc (file_size);
  size_read = GNUNET_DISK_file_read (fh, buf, file_size);
  GNUNET_assert (size_read == file_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Restoring %" PRIu32 " peers from file `%s'\n",
      num_peers,
      sub->filename_valid_peers);
  for (iter_buf = buf; iter_buf < buf + file_size - 1; iter_buf += 53)
  {
    str_repr = GNUNET_strndup (iter_buf, 53);
    peer = s2i_full (str_repr);
    GNUNET_free (str_repr);
    add_valid_peer (peer, sub->valid_peers);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Restored valid peer %s from disk\n",
        GNUNET_i2s_full (peer));
  }
  iter_buf = NULL;
  GNUNET_free (buf);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "num_peers: %" PRIu32 ", _size (sub->valid_peers): %u\n",
      num_peers,
      GNUNET_CONTAINER_multipeermap_size (sub->valid_peers));
  if (num_peers != GNUNET_CONTAINER_multipeermap_size (sub->valid_peers))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Number of restored peers does not match file size. Have probably duplicates.\n");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Restored %u valid peers from disk\n",
      GNUNET_CONTAINER_multipeermap_size (sub->valid_peers));
}


/**
 * @brief Delete storage of peers that was created with #initialise_peers ()
 *
 * @param sub Sub for which the storage is deleted
 */
static void
peers_terminate (struct Sub *sub)
{
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multipeermap_iterate (sub->peer_map,
                                             &peermap_clear_iterator,
                                             sub))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Iteration destroying peers was aborted.\n");
  }
  GNUNET_CONTAINER_multipeermap_destroy (sub->peer_map);
  sub->peer_map = NULL;
  store_valid_peers (sub);
  GNUNET_free (sub->filename_valid_peers);
  sub->filename_valid_peers = NULL;
  GNUNET_CONTAINER_multipeermap_destroy (sub->valid_peers);
  sub->valid_peers = NULL;
}


/**
 * Iterator over #valid_peers hash map entries.
 *
 * @param cls Closure that contains iterator function and closure
 * @param peer current peer id
 * @param value value in the hash map - unused
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
valid_peer_iterator (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     void *value)
{
  struct PeersIteratorCls *it_cls = cls;
  (void) value;

  return it_cls->iterator (it_cls->cls, peer);
}


/**
 * @brief Get all currently known, valid peer ids.
 *
 * @param valid_peers Peer map containing the valid peers in question
 * @param iterator function to call on each peer id
 * @param it_cls extra argument to @a iterator
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
static int
get_valid_peers (struct GNUNET_CONTAINER_MultiPeerMap *valid_peers,
                 PeersIterator iterator,
                 void *it_cls)
{
  struct PeersIteratorCls *cls;
  int ret;

  cls = GNUNET_new (struct PeersIteratorCls);
  cls->iterator = iterator;
  cls->cls = it_cls;
  ret = GNUNET_CONTAINER_multipeermap_iterate (valid_peers,
                                               valid_peer_iterator,
                                               cls);
  GNUNET_free (cls);
  return ret;
}


/**
 * @brief Add peer to known peers.
 *
 * This function is called on new peer_ids from 'external' sources
 * (client seed, cadet get_peers(), ...)
 *
 * @param sub Sub with the peer map that the @a peer will be added to
 * @param peer the new #GNUNET_PeerIdentity
 *
 * @return #GNUNET_YES if peer was inserted
 *         #GNUNET_NO  otherwise
 */
static int
insert_peer (struct Sub *sub,
             const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_YES == check_peer_known (sub->peer_map, peer))
  {
    return GNUNET_NO; /* We already know this peer - nothing to do */
  }
  (void) create_peer_ctx (sub, peer);
  return GNUNET_YES;
}


/**
 * @brief Check whether flags on a peer are set.
 *
 * @param peer_map Peer map that is expected to contain the @a peer
 * @param peer the peer to check the flag of
 * @param flags the flags to check
 *
 * @return #GNUNET_SYSERR if peer is not known
 *         #GNUNET_YES    if all given flags are set
 *         #GNUNET_NO     otherwise
 */
static int
check_peer_flag (const struct GNUNET_CONTAINER_MultiPeerMap *peer_map,
                 const struct GNUNET_PeerIdentity *peer,
                 enum Peers_PeerFlags flags)
{
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == check_peer_known (peer_map, peer))
  {
    return GNUNET_SYSERR;
  }
  peer_ctx = get_peer_ctx (peer_map, peer);
  return check_peer_flag_set (peer_ctx, flags);
}

/**
 * @brief Try connecting to a peer to see whether it is online
 *
 * If not known yet, insert into known peers
 *
 * @param sub Sub which would contain the @a peer
 * @param peer the peer whose online is to be checked
 * @return #GNUNET_YES if the check was issued
 *         #GNUNET_NO  otherwise
 */
static int
issue_peer_online_check (struct Sub *sub,
                         const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  (void) insert_peer (sub, peer); // TODO even needed?
  peer_ctx = get_peer_ctx (sub->peer_map, peer);
  if ( (GNUNET_NO == check_peer_flag (sub->peer_map, peer, Peers_ONLINE)) &&
       (NULL == peer_ctx->online_check_pending) )
  {
    check_peer_online (peer_ctx);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * @brief Check if peer is removable.
 *
 * Check if
 *  - a recv channel exists
 *  - there are pending messages
 *  - there is no pending pull reply
 *
 * @param peer_ctx Context of the peer in question
 * @return #GNUNET_YES    if peer is removable
 *         #GNUNET_NO     if peer is NOT removable
 *         #GNUNET_SYSERR if peer is not known
 */
static int
check_removable (const struct PeerContext *peer_ctx)
{
  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (peer_ctx->sub->peer_map,
                                                           &peer_ctx->peer_id))
  {
    return GNUNET_SYSERR;
  }

  if ( (NULL != peer_ctx->recv_channel_ctx) ||
       (NULL != peer_ctx->pending_messages_head) ||
       (GNUNET_YES == check_peer_flag_set (peer_ctx, Peers_PULL_REPLY_PENDING)) )
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * @brief Check whether @a peer is actually a peer.
 *
 * A valid peer is a peer that we know exists eg. we were connected to once.
 *
 * @param valid_peers Peer map that would contain the @a peer
 * @param peer peer in question
 *
 * @return #GNUNET_YES if peer is valid
 *         #GNUNET_NO  if peer is not valid
 */
static int
check_peer_valid (const struct GNUNET_CONTAINER_MultiPeerMap *valid_peers,
                  const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_contains (valid_peers, peer);
}


/**
 * @brief Indicate that we want to send to the other peer
 *
 * This establishes a sending channel
 *
 * @param peer_ctx Context of the target peer
 */
static void
indicate_sending_intention (struct PeerContext *peer_ctx)
{
  GNUNET_assert (GNUNET_YES == check_peer_known (peer_ctx->sub->peer_map,
                                                 &peer_ctx->peer_id));
  (void) get_channel (peer_ctx);
}


/**
 * @brief Check whether other peer has the intention to send/opened channel
 *        towars us
 *
 * @param peer_ctx Context of the peer in question
 *
 * @return #GNUNET_YES if peer has the intention to send
 *         #GNUNET_NO  otherwise
 */
static int
check_peer_send_intention (const struct PeerContext *peer_ctx)
{
  if (NULL != peer_ctx->recv_channel_ctx)
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Handle the channel a peer opens to us.
 *
 * @param cls The closure - Sub
 * @param channel The channel the peer wants to establish
 * @param initiator The peer's peer ID
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
static void *
handle_inbound_channel (void *cls,
                        struct GNUNET_CADET_Channel *channel,
                        const struct GNUNET_PeerIdentity *initiator)
{
  struct PeerContext *peer_ctx;
  struct ChannelCtx *channel_ctx;
  struct Sub *sub = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "New channel was established to us (Peer %s).\n",
      GNUNET_i2s (initiator));
  GNUNET_assert (NULL != channel); /* according to cadet API */
  /* Make sure we 'know' about this peer */
  peer_ctx = create_or_get_peer_ctx (sub, initiator);
  set_peer_online (peer_ctx);
  (void) add_valid_peer (&peer_ctx->peer_id, peer_ctx->sub->valid_peers);
  channel_ctx = add_channel_ctx (peer_ctx);
  channel_ctx->channel = channel;
  /* We only accept one incoming channel per peer */
  if (GNUNET_YES == check_peer_send_intention (get_peer_ctx (sub->peer_map,
                                                             initiator)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Already got one receive channel. Destroying old one.\n");
    GNUNET_break_op (0);
    destroy_channel (peer_ctx->recv_channel_ctx);
    peer_ctx->recv_channel_ctx = channel_ctx;
    /* return the channel context */
    return channel_ctx;
  }
  peer_ctx->recv_channel_ctx = channel_ctx;
  return channel_ctx;
}


/**
 * @brief Check whether a sending channel towards the given peer exists
 *
 * @param peer_ctx Context of the peer in question
 *
 * @return #GNUNET_YES if a sending channel towards that peer exists
 *         #GNUNET_NO  otherwise
 */
static int
check_sending_channel_exists (const struct PeerContext *peer_ctx)
{
  if (GNUNET_NO == check_peer_known (peer_ctx->sub->peer_map,
                                     &peer_ctx->peer_id))
  { /* If no such peer exists, there is no channel */
    return GNUNET_NO;
  }
  if (NULL == peer_ctx->send_channel_ctx)
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * @brief Destroy the send channel of a peer e.g. stop indicating a sending
 *        intention to another peer
 *
 * @param peer_ctx Context to the peer
 * @return #GNUNET_YES if channel was destroyed
 *         #GNUNET_NO  otherwise
 */
static int
destroy_sending_channel (struct PeerContext *peer_ctx)
{
  if (GNUNET_NO == check_peer_known (peer_ctx->sub->peer_map,
                                     &peer_ctx->peer_id))
  {
    return GNUNET_NO;
  }
  if (NULL != peer_ctx->send_channel_ctx)
  {
    destroy_channel (peer_ctx->send_channel_ctx);
    (void) check_connected (peer_ctx);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * @brief Send a message to another peer.
 *
 * Keeps track about pending messages so they can be properly removed when the
 * peer is destroyed.
 *
 * @param peer_ctx Context of the peer to which the message is to be sent
 * @param ev envelope of the message
 * @param type type of the message
 */
static void
send_message (struct PeerContext *peer_ctx,
              struct GNUNET_MQ_Envelope *ev,
              const char *type)
{
  struct PendingMessage *pending_msg;
  struct GNUNET_MQ_Handle *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending message to %s of type %s\n",
	      GNUNET_i2s (&peer_ctx->peer_id),
	      type);
  pending_msg = insert_pending_message (peer_ctx, ev, type);
  mq = get_mq (peer_ctx);
  GNUNET_MQ_notify_sent (ev,
                         mq_notify_sent_cb,
                         pending_msg);
  GNUNET_MQ_send (mq, ev);
}

/**
 * @brief Schedule a operation on given peer
 *
 * Avoids scheduling an operation twice.
 *
 * @param peer_ctx Context of the peer for which to schedule the operation
 * @param peer_op the operation to schedule
 * @param cls Closure to @a peer_op
 *
 * @return #GNUNET_YES if the operation was scheduled
 *         #GNUNET_NO  otherwise
 */
static int
schedule_operation (struct PeerContext *peer_ctx,
                    const PeerOp peer_op,
                    void *cls)
{
  struct PeerPendingOp pending_op;

  GNUNET_assert (GNUNET_YES == check_peer_known (peer_ctx->sub->peer_map,
                                                 &peer_ctx->peer_id));

  //TODO if ONLINE execute immediately

  if (GNUNET_NO == check_operation_scheduled (peer_ctx, peer_op))
  {
    pending_op.op = peer_op;
    pending_op.op_cls = cls;
    GNUNET_array_append (peer_ctx->pending_ops,
                         peer_ctx->num_pending_ops,
                         pending_op);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

/***********************************************************************
 * /Old gnunet-service-rps_peers.c
***********************************************************************/


/***********************************************************************
 * Housekeeping with clients
***********************************************************************/

/**
 * Closure used to pass the client and the id to the callback
 * that replies to a client's request
 */
struct ReplyCls
{
  /**
   * DLL
   */
  struct ReplyCls *next;
  struct ReplyCls *prev;

  /**
   * The identifier of the request
   */
  uint32_t id;

  /**
   * The handle to the request
   */
  struct RPS_SamplerRequestHandle *req_handle;

  /**
   * The client handle to send the reply to
   */
  struct ClientContext *cli_ctx;
};


/**
 * Struct used to store the context of a connected client.
 */
struct ClientContext
{
  /**
   * DLL
   */
  struct ClientContext *next;
  struct ClientContext *prev;

  /**
   * The message queue to communicate with the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * @brief How many updates this client expects to receive.
   */
  int64_t view_updates_left;

  /**
   * @brief Whether this client wants to receive stream updates.
   * Either #GNUNET_YES or #GNUNET_NO
   */
  int8_t stream_update;

  /**
   * The client handle to send the reply to
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * The #Sub this context belongs to
   */
  struct Sub *sub;
};

/**
 * DLL with all clients currently connected to us
 */
struct ClientContext *cli_ctx_head;
struct ClientContext *cli_ctx_tail;

/***********************************************************************
 * /Housekeeping with clients
***********************************************************************/





/***********************************************************************
 * Util functions
***********************************************************************/


/**
 * Print peerlist to log.
 */
static void
print_peer_list (struct GNUNET_PeerIdentity *list,
		 unsigned int len)
{
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing peer list of length %u at %p:\n",
       len,
       list);
  for (i = 0 ; i < len ; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i, GNUNET_i2s (&list[i]));
  }
}


/**
 * Remove peer from list.
 */
static void
rem_from_list (struct GNUNET_PeerIdentity **peer_list,
               unsigned int *list_size,
               const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  struct GNUNET_PeerIdentity *tmp;

  tmp = *peer_list;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing peer %s from list at %p\n",
       GNUNET_i2s (peer),
       tmp);

  for ( i = 0 ; i < *list_size ; i++ )
  {
    if (0 == GNUNET_memcmp (&tmp[i], peer))
    {
      if (i < *list_size -1)
      { /* Not at the last entry -- shift peers left */
        memmove (&tmp[i], &tmp[i +1],
                ((*list_size) - i -1) * sizeof (struct GNUNET_PeerIdentity));
      }
      /* Remove last entry (should be now useless PeerID) */
      GNUNET_array_grow (tmp, *list_size, (*list_size) -1);
    }
  }
  *peer_list = tmp;
}


/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is online.
 * Implements #PeerOp
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
static void
insert_in_view_op (void *cls,
                   const struct GNUNET_PeerIdentity *peer);

/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is online.
 *
 * @param sub Sub in with the view to insert in
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
static int
insert_in_view (struct Sub *sub,
                const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  int online;
  int ret;

  online = check_peer_flag (sub->peer_map, peer, Peers_ONLINE);
  peer_ctx = get_peer_ctx (sub->peer_map, peer); // TODO indirection needed?
  if ( (GNUNET_NO == online) ||
       (GNUNET_SYSERR == online) ) /* peer is not even known */
  {
    (void) issue_peer_online_check (sub, peer);
    (void) schedule_operation (peer_ctx, insert_in_view_op, sub);
    return GNUNET_NO;
  }
  /* Open channel towards peer to keep connection open */
  indicate_sending_intention (peer_ctx);
  ret = View_put (sub->view, peer);
  if (peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                           "view size",
                           View_size (peer_ctx->sub->view),
                           GNUNET_NO);
  }
  return ret;
}


/**
 * @brief Send view to client
 *
 * @param cli_ctx the context of the client
 * @param view_array the peerids of the view as array (can be empty)
 * @param view_size the size of the view array (can be 0)
 */
static void
send_view (const struct ClientContext *cli_ctx,
           const struct GNUNET_PeerIdentity *view_array,
           uint64_t view_size)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_DEBUG_ViewReply *out_msg;
  struct Sub *sub;

  if (NULL == view_array)
  {
    if (NULL == cli_ctx->sub) sub = msub;
    else sub = cli_ctx->sub;
    view_size = View_size (sub->view);
    view_array = View_get_as_array (sub->view);
  }

  ev = GNUNET_MQ_msg_extra (out_msg,
                            view_size * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REPLY);
  out_msg->num_peers = htonl (view_size);

  GNUNET_memcpy (&out_msg[1],
                 view_array,
                 view_size * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_MQ_send (cli_ctx->mq, ev);
}


/**
 * @brief Send peer from biased stream to client.
 *
 * TODO merge with send_view, parameterise
 *
 * @param cli_ctx the context of the client
 * @param view_array the peerids of the view as array (can be empty)
 * @param view_size the size of the view array (can be 0)
 */
static void
send_stream_peers (const struct ClientContext *cli_ctx,
                   uint64_t num_peers,
                   const struct GNUNET_PeerIdentity *peers)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_DEBUG_StreamReply *out_msg;

  GNUNET_assert (NULL != peers);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REPLY);
  out_msg->num_peers = htonl (num_peers);

  GNUNET_memcpy (&out_msg[1],
                 peers,
                 num_peers * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_MQ_send (cli_ctx->mq, ev);
}


/**
 * @brief sends updates to clients that are interested
 *
 * @param sub Sub for which to notify clients
 */
static void
clients_notify_view_update (const struct Sub *sub)
{
  struct ClientContext *cli_ctx_iter;
  uint64_t num_peers;
  const struct GNUNET_PeerIdentity *view_array;

  num_peers = View_size (sub->view);
  view_array = View_get_as_array(sub->view);
  /* check size of view is small enough */
  if (GNUNET_MAX_MESSAGE_SIZE < num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "View is too big to send\n");
    return;
  }

  for (cli_ctx_iter = cli_ctx_head;
       NULL != cli_ctx_iter;
       cli_ctx_iter = cli_ctx_iter->next)
  {
    if (1 < cli_ctx_iter->view_updates_left)
    {
      /* Client wants to receive limited amount of updates */
      cli_ctx_iter->view_updates_left -= 1;
    } else if (1 == cli_ctx_iter->view_updates_left)
    {
      /* Last update of view for client */
      cli_ctx_iter->view_updates_left = -1;
    } else if (0 > cli_ctx_iter->view_updates_left) {
      /* Client is not interested in updates */
      continue;
    }
    /* else _updates_left == 0 - infinite amount of updates */

    /* send view */
    send_view (cli_ctx_iter, view_array, num_peers);
  }
}


/**
 * @brief sends updates to clients that are interested
 *
 * @param num_peers Number of peers to send
 * @param peers the array of peers to send
 */
static void
clients_notify_stream_peer (const struct Sub *sub,
                            uint64_t num_peers,
                            const struct GNUNET_PeerIdentity *peers)
                            // TODO enum StreamPeerSource)
{
  struct ClientContext *cli_ctx_iter;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Got peer (%s) from biased stream - update all clients\n",
      GNUNET_i2s (peers));

  for (cli_ctx_iter = cli_ctx_head;
       NULL != cli_ctx_iter;
       cli_ctx_iter = cli_ctx_iter->next)
  {
    if (GNUNET_YES == cli_ctx_iter->stream_update &&
        (sub == cli_ctx_iter->sub || sub == msub))
    {
      send_stream_peers (cli_ctx_iter, num_peers, peers);
    }
  }
}


/**
 * Put random peer from sampler into the view as history update.
 *
 * @param ids Array of Peers to insert into view
 * @param num_peers Number of peers to insert
 * @param cls Closure - The Sub for which this is to be done
 */
static void
hist_update (const struct GNUNET_PeerIdentity *ids,
             uint32_t num_peers,
             void *cls)
{
  unsigned int i;
  struct Sub *sub = cls;

  for (i = 0; i < num_peers; i++)
  {
    int inserted;
    if (GNUNET_YES != check_peer_known (sub->peer_map, &ids[i]))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Peer in history update not known!\n");
      continue;
    }
    inserted = insert_in_view (sub, &ids[i]);
    if (GNUNET_OK == inserted)
    {
      clients_notify_stream_peer (sub, 1, &ids[i]);
    }
#ifdef TO_FILE_FULL
    to_file (sub->file_name_view_log,
             "+%s\t(hist)",
             GNUNET_i2s_full (ids));
#endif /* TO_FILE_FULL */
  }
  clients_notify_view_update (sub);
}


/**
 * Wrapper around #RPS_sampler_resize()
 *
 * If we do not have enough sampler elements, double current sampler size
 * If we have more than enough sampler elements, halv current sampler size
 *
 * @param sampler The sampler to resize
 * @param new_size New size to which to resize
 */
static void
resize_wrapper (struct RPS_Sampler *sampler, uint32_t new_size)
{
  unsigned int sampler_size;

  // TODO statistics
  // TODO respect the min, max
  sampler_size = RPS_sampler_get_size (sampler);
  if (sampler_size > new_size * 4)
  { /* Shrinking */
    RPS_sampler_resize (sampler, sampler_size / 2);
  }
  else if (sampler_size < new_size)
  { /* Growing */
    RPS_sampler_resize (sampler, sampler_size * 2);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler_size is now %u\n", sampler_size);
}


/**
 * Add all peers in @a peer_array to @a peer_map used as set.
 *
 * @param peer_array array containing the peers
 * @param num_peers number of peers in @peer_array
 * @param peer_map the peermap to use as set
 */
static void
add_peer_array_to_set (const struct GNUNET_PeerIdentity *peer_array,
                       unsigned int num_peers,
                       struct GNUNET_CONTAINER_MultiPeerMap *peer_map)
{
  unsigned int i;
  if (NULL == peer_map)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to add peers to non-existing peermap.\n");
    return;
  }

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_CONTAINER_multipeermap_put (peer_map,
                                       &peer_array[i],
                                       NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    if (msub->peer_map == peer_map)
    {
      GNUNET_STATISTICS_set (stats,
                            "# known peers",
                            GNUNET_CONTAINER_multipeermap_size (peer_map),
                            GNUNET_NO);
    }
  }
}


/**
 * Send a PULL REPLY to @a peer_id
 *
 * @param peer_ctx Context of the peer to send the reply to
 * @param peer_ids the peers to send to @a peer_id
 * @param num_peer_ids the number of peers to send to @a peer_id
 */
static void
send_pull_reply (struct PeerContext *peer_ctx,
                 const struct GNUNET_PeerIdentity *peer_ids,
                 unsigned int num_peer_ids)
{
  uint32_t send_size;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_P2P_PullReplyMessage *out_msg;

  /* Compute actual size */
  send_size = sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) +
              num_peer_ids * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < send_size)
    /* Compute number of peers to send
     * If too long, simply truncate */
    // TODO select random ones via permutation
    //      or even better: do good protocol design
    send_size =
      (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE -
       sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
       sizeof (struct GNUNET_PeerIdentity);
  else
    send_size = num_peer_ids;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to send PULL REPLY with %u peers to %s\n",
      send_size, GNUNET_i2s (&peer_ctx->peer_id));

  ev = GNUNET_MQ_msg_extra (out_msg,
                            send_size * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = htonl (send_size);
  GNUNET_memcpy (&out_msg[1], peer_ids,
         send_size * sizeof (struct GNUNET_PeerIdentity));

  send_message (peer_ctx, ev, "PULL REPLY");
  if (peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update(stats, "# pull reply send issued", 1, GNUNET_NO);
  }
  // TODO check with send intention: as send_channel is used/opened we indicate
  // a sending intention without intending it.
  // -> clean peer afterwards?
  // -> use recv_channel?
}


/**
 * Insert PeerID in #pull_map
 *
 * Called once we know a peer is online.
 *
 * @param cls Closure - Sub with the pull map to insert into
 * @param peer Peer to insert
 */
static void
insert_in_pull_map (void *cls,
                    const struct GNUNET_PeerIdentity *peer)
{
  struct Sub *sub = cls;

  CustomPeerMap_put (sub->pull_map, peer);
}


/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is online.
 * Implements #PeerOp
 *
 * @param cls Closure - Sub with view to insert peer into
 * @param peer the peer to insert
 */
static void
insert_in_view_op (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct Sub *sub = cls;
  int inserted;

  inserted = insert_in_view (sub, peer);
  if (GNUNET_OK == inserted)
  {
    clients_notify_stream_peer (sub, 1, peer);
  }
}


/**
 * Update sampler with given PeerID.
 * Implements #PeerOp
 *
 * @param cls Closure - Sub containing the sampler to insert into
 * @param peer Peer to insert
 */
static void
insert_in_sampler (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct Sub *sub = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating samplers with peer %s from insert_in_sampler()\n",
       GNUNET_i2s (peer));
  RPS_sampler_update (sub->sampler, peer);
  if (0 < RPS_sampler_count_id (sub->sampler, peer))
  {
    /* Make sure we 'know' about this peer */
    (void) issue_peer_online_check (sub, peer);
    /* Establish a channel towards that peer to indicate we are going to send
     * messages to it */
    //indicate_sending_intention (peer);
  }
  if (sub == msub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# observed peers in gossip",
                              1,
                              GNUNET_NO);
  }
#ifdef TO_FILE
  sub->num_observed_peers++;
  GNUNET_CONTAINER_multipeermap_put
    (sub->observed_unique_peers,
     peer,
     NULL,
     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  uint32_t num_observed_unique_peers =
    GNUNET_CONTAINER_multipeermap_size (sub->observed_unique_peers);
  GNUNET_STATISTICS_set (stats,
                         "# unique peers in gossip",
                         num_observed_unique_peers,
                         GNUNET_NO);
#ifdef TO_FILE_FULL
  to_file (sub->file_name_observed_log,
          "%" PRIu32 " %" PRIu32 " %f\n",
          sub->num_observed_peers,
          num_observed_unique_peers,
          1.0*num_observed_unique_peers/sub->num_observed_peers)
#endif /* TO_FILE_FULL */
#endif /* TO_FILE */
}


/**
 * @brief This is called on peers from external sources (cadet, peerinfo, ...)
 *        If the peer is not known, online check is issued and it is
 *        scheduled to be inserted in sampler and view.
 *
 * "External sources" refer to every source except the gossip.
 *
 * @param sub Sub for which @a peer was received
 * @param peer peer to insert/peer received
 */
static void
got_peer (struct Sub *sub,
          const struct GNUNET_PeerIdentity *peer)
{
  /* If we did not know this peer already, insert it into sampler and view */
  if (GNUNET_YES == issue_peer_online_check (sub, peer))
  {
    schedule_operation (get_peer_ctx (sub->peer_map, peer),
                        &insert_in_sampler, sub);
    schedule_operation (get_peer_ctx (sub->peer_map, peer),
                        &insert_in_view_op, sub);
  }
  if (sub == msub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# learnd peers",
                              1,
                              GNUNET_NO);
  }
}


/**
 * @brief Checks if there is a sending channel and if it is needed
 *
 * @param peer_ctx Context of the peer to check
 * @return GNUNET_YES if sending channel exists and is still needed
 *         GNUNET_NO  otherwise
 */
static int
check_sending_channel_needed (const struct PeerContext *peer_ctx)
{
  /* struct GNUNET_CADET_Channel *channel; */
  if (GNUNET_NO == check_peer_known (peer_ctx->sub->peer_map,
                                     &peer_ctx->peer_id))
  {
    return GNUNET_NO;
  }
  if (GNUNET_YES == check_sending_channel_exists (peer_ctx))
  {
    if ( (0 < RPS_sampler_count_id (peer_ctx->sub->sampler,
                                    &peer_ctx->peer_id)) ||
         (GNUNET_YES == View_contains_peer (peer_ctx->sub->view,
                                            &peer_ctx->peer_id)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (peer_ctx->sub->push_map,
                                                     &peer_ctx->peer_id)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (peer_ctx->sub->pull_map,
                                                     &peer_ctx->peer_id)) ||
         (GNUNET_YES == check_peer_flag (peer_ctx->sub->peer_map,
                                         &peer_ctx->peer_id,
                                         Peers_PULL_REPLY_PENDING)))
    { /* If we want to keep the connection to peer open */
      return GNUNET_YES;
    }
    return GNUNET_NO;
  }
  return GNUNET_NO;
}


/**
 * @brief remove peer from our knowledge, the view, push and pull maps and
 * samplers.
 *
 * @param sub Sub with the data structures the peer is to be removed from
 * @param peer the peer to remove
 */
static void
remove_peer (struct Sub *sub,
             const struct GNUNET_PeerIdentity *peer)
{
  (void) View_remove_peer (sub->view,
                           peer);
  CustomPeerMap_remove_peer (sub->pull_map,
                             peer);
  CustomPeerMap_remove_peer (sub->push_map,
                             peer);
  RPS_sampler_reinitialise_by_value (sub->sampler,
                                     peer);
  /* We want to destroy the peer now.
   * Sometimes, it just seems that it's already been removed from the peer_map,
   * so check the peer_map first. */
  if (GNUNET_YES == check_peer_known (sub->peer_map,
                                      peer))
  {
    destroy_peer (get_peer_ctx (sub->peer_map,
                                peer));
  }
}


/**
 * @brief Remove data that is not needed anymore.
 *
 * If the sending channel is no longer needed it is destroyed.
 *
 * @param sub Sub in which the current peer is to be cleaned
 * @param peer the peer whose data is about to be cleaned
 */
static void
clean_peer (struct Sub *sub,
            const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == check_sending_channel_needed (get_peer_ctx (sub->peer_map,
                                                               peer)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to remove send channel to peer %s\n",
        GNUNET_i2s (peer));
    #if ENABLE_MALICIOUS
    if (0 != GNUNET_memcmp (&attacked_peer,
                                              peer))
      (void) destroy_sending_channel (get_peer_ctx (sub->peer_map,
                                                    peer));
    #else /* ENABLE_MALICIOUS */
    (void) destroy_sending_channel (get_peer_ctx (sub->peer_map,
                                                  peer));
    #endif /* ENABLE_MALICIOUS */
  }

  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (sub->peer_map,
                                                           peer))
  {
    /* Peer was already removed by callback on destroyed channel */
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Peer was removed from our knowledge during cleanup\n");
    return;
  }

  if ( (GNUNET_NO == check_peer_send_intention (get_peer_ctx (sub->peer_map,
                                                              peer))) &&
       (GNUNET_NO == View_contains_peer (sub->view, peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (sub->push_map, peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (sub->push_map, peer)) &&
       (0 == RPS_sampler_count_id (sub->sampler, peer)) &&
       (GNUNET_YES == check_removable (get_peer_ctx (sub->peer_map, peer))) )
  { /* We can safely remove this peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to remove peer %s\n",
        GNUNET_i2s (peer));
    remove_peer (sub, peer);
    return;
  }
}


/**
 * @brief This is called when a channel is destroyed.
 *
 * Removes peer completely from our knowledge if the send_channel was destroyed
 * Otherwise simply delete the recv_channel
 * Also check if the knowledge about this peer is still needed.
 * If not, remove this peer from our knowledge.
 *
 * @param cls The closure - Context to the channel
 * @param channel The channel being closed
 */
static void
cleanup_destroyed_channel (void *cls,
                           const struct GNUNET_CADET_Channel *channel)
{
  struct ChannelCtx *channel_ctx = cls;
  struct PeerContext *peer_ctx = channel_ctx->peer_ctx;
  (void) channel;

  channel_ctx->channel = NULL;
  remove_channel_ctx (channel_ctx);
  if (NULL != peer_ctx &&
      peer_ctx->send_channel_ctx == channel_ctx &&
      GNUNET_YES == check_sending_channel_needed (channel_ctx->peer_ctx))
  {
    remove_peer (peer_ctx->sub, &peer_ctx->peer_id);
  }
}

/***********************************************************************
 * /Util functions
***********************************************************************/



/***********************************************************************
 * Sub
***********************************************************************/

/**
 * @brief Create a new Sub
 *
 * @param hash Hash of value shared among rps instances on other hosts that
 *        defines a subgroup to sample from.
 * @param sampler_size Size of the sampler
 * @param round_interval Interval (in average) between two rounds
 *
 * @return Sub
 */
struct Sub *
new_sub (const struct GNUNET_HashCode *hash,
         uint32_t sampler_size,
         struct GNUNET_TIME_Relative round_interval)
{
  struct Sub *sub;

  sub = GNUNET_new (struct Sub);

  /* With the hash generated from the secret value this service only connects
   * to rps instances that share the value */
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_fixed_size (peer_check,
                             GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (peer_push,
                             GNUNET_MESSAGE_TYPE_RPS_PP_PUSH,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (peer_pull_request,
                             GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (peer_pull_reply,
                           GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY,
                           struct GNUNET_RPS_P2P_PullReplyMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  sub->hash = *hash;
  sub->cadet_port =
    GNUNET_CADET_open_port (cadet_handle,
                            &sub->hash,
                            &handle_inbound_channel, /* Connect handler */
                            sub, /* cls */
                            NULL, /* WindowSize handler */
                            &cleanup_destroyed_channel, /* Disconnect handler */
                            cadet_handlers);
  if (NULL == sub->cadet_port)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "Cadet port `%s' is already in use.\n",
        GNUNET_APPLICATION_PORT_RPS);
    GNUNET_assert (0);
  }

  /* Set up general data structure to keep track about peers */
  sub->valid_peers = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "rps",
                                               "FILENAME_VALID_PEERS",
                                               &sub->filename_valid_peers))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "rps",
                               "FILENAME_VALID_PEERS");
  }
  if (0 != strncmp ("DISABLE", sub->filename_valid_peers, 7))
  {
    char *tmp_filename_valid_peers;
    char str_hash[105];

    GNUNET_snprintf (str_hash,
		     sizeof (str_hash),
		     GNUNET_h2s_full (hash));
    tmp_filename_valid_peers = sub->filename_valid_peers;
    GNUNET_asprintf (&sub->filename_valid_peers,
		     "%s%s",
		     tmp_filename_valid_peers,
		     str_hash);
    GNUNET_free (tmp_filename_valid_peers);
  }
  sub->peer_map = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);

  /* Set up the sampler */
  sub->sampler_size_est_min = sampler_size;
  sub->sampler_size_est_need = sampler_size;;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "MINSIZE is %u\n", sub->sampler_size_est_min);
  GNUNET_assert (0 != round_interval.rel_value_us);
  sub->round_interval = round_interval;
  sub->sampler = RPS_sampler_init (sampler_size,
                                  round_interval);

  /* Logging of internals */
#ifdef TO_FILE_FULL
  sub->file_name_view_log = store_prefix_file_name (&own_identity, "view");
#endif /* TO_FILE_FULL */
#ifdef TO_FILE
#ifdef TO_FILE_FULL
  sub->file_name_observed_log = store_prefix_file_name (&own_identity,
                                                       "observed");
#endif /* TO_FILE_FULL */
  sub->num_observed_peers = 0;
  sub->observed_unique_peers = GNUNET_CONTAINER_multipeermap_create (1,
                                                                    GNUNET_NO);
#endif /* TO_FILE */

  /* Set up data structures for gossip */
  sub->push_map = CustomPeerMap_create (4);
  sub->pull_map = CustomPeerMap_create (4);
  sub->view_size_est_min = sampler_size;;
  sub->view = View_create (sub->view_size_est_min);
  if (sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                           "view size aim",
                           sub->view_size_est_min,
                           GNUNET_NO);
  }

  /* Start executing rounds */
  sub->do_round_task = GNUNET_SCHEDULER_add_now (&do_round, sub);

  return sub;
}


#ifdef TO_FILE
/**
 * @brief Write all numbers in the given array into the given file
 *
 * Single numbers devided by a newline
 *
 * @param hist_array[] the array to dump
 * @param file_name file to dump into
 */
static void
write_histogram_to_file (const uint32_t hist_array[],
                         const char *file_name)
{
  char collect_str[SIZE_DUMP_FILE + 1] = "";
  char *recv_str_iter;
  char *file_name_full;

  recv_str_iter = collect_str;
  file_name_full = store_prefix_file_name (&own_identity,
                                           file_name);
  for (uint32_t i = 0; i < HISTOGRAM_FILE_SLOTS; i++)
  {
    char collect_str_tmp[8];

    GNUNET_snprintf (collect_str_tmp,
		     sizeof (collect_str_tmp),
		     "%" PRIu32 "\n",
		     hist_array[i]);
    recv_str_iter = stpncpy (recv_str_iter,
                             collect_str_tmp,
                             6);
  }
  (void) stpcpy (recv_str_iter,
                 "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Writing push stats to disk\n");
  to_file_w_len (file_name_full,
                 SIZE_DUMP_FILE,
                 collect_str);
  GNUNET_free (file_name_full);
}
#endif /* TO_FILE */


/**
 * @brief Destroy Sub.
 *
 * @param sub Sub to destroy
 */
static void
destroy_sub (struct Sub *sub)
{
  GNUNET_assert (NULL != sub);
  GNUNET_assert (NULL != sub->do_round_task);
  GNUNET_SCHEDULER_cancel (sub->do_round_task);
  sub->do_round_task = NULL;

  /* Disconnect from cadet */
  GNUNET_CADET_close_port (sub->cadet_port);
  sub->cadet_port= NULL;

  /* Clean up data structures for peers */
  RPS_sampler_destroy (sub->sampler);
  sub->sampler = NULL;
  View_destroy (sub->view);
  sub->view = NULL;
  CustomPeerMap_destroy (sub->push_map);
  sub->push_map = NULL;
  CustomPeerMap_destroy (sub->pull_map);
  sub->pull_map = NULL;
  peers_terminate (sub);

  /* Free leftover data structures */
#ifdef TO_FILE_FULL
  GNUNET_free (sub->file_name_view_log);
  sub->file_name_view_log = NULL;
#endif /* TO_FILE_FULL */
#ifdef TO_FILE
#ifdef TO_FILE_FULL
  GNUNET_free (sub->file_name_observed_log);
  sub->file_name_observed_log = NULL;
#endif /* TO_FILE_FULL */

  /* Write push frequencies to disk */
  write_histogram_to_file (sub->push_recv,
                           "push_recv");

  /* Write push deltas to disk */
  write_histogram_to_file (sub->push_delta,
                           "push_delta");

  /* Write pull delays to disk */
  write_histogram_to_file (sub->pull_delays,
                           "pull_delays");

  GNUNET_CONTAINER_multipeermap_destroy (sub->observed_unique_peers);
  sub->observed_unique_peers = NULL;
#endif /* TO_FILE */

  GNUNET_free (sub);
}


/***********************************************************************
 * /Sub
***********************************************************************/


/***********************************************************************
 * Core handlers
***********************************************************************/

/**
 * @brief Callback on initialisation of Core.
 *
 * @param cls - unused
 * @param my_identity - unused
 */
void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *my_identity)
{
  (void) cls;
  (void) my_identity;

  map_single_hop = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);
}


/**
 * @brief Callback for core.
 * Method called whenever a given peer connects.
 *
 * @param cls closure - unused
 * @param peer peer identity this notification is about
 * @return closure given to #core_disconnects as peer_cls
 */
void *
core_connects (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               struct GNUNET_MQ_Handle *mq)
{
  (void) cls;
  (void) mq;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_put (map_single_hop,
						    peer,
						    NULL,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return NULL;
}


/**
 * @brief Callback for core.
 * Method called whenever a peer disconnects.
 *
 * @param cls closure - unused
 * @param peer peer identity this notification is about
 * @param peer_cls closure given in #core_connects - unused
 */
void
core_disconnects (void *cls,
                  const struct GNUNET_PeerIdentity *peer,
                  void *peer_cls)
{
  (void) cls;
  (void) peer_cls;

  GNUNET_CONTAINER_multipeermap_remove_all (map_single_hop, peer);
}

/***********************************************************************
 * /Core handlers
***********************************************************************/


/**
 * @brief Destroy the context for a (connected) client
 *
 * @param cli_ctx Context to destroy
 */
static void
destroy_cli_ctx (struct ClientContext *cli_ctx)
{
  GNUNET_assert (NULL != cli_ctx);
  GNUNET_CONTAINER_DLL_remove (cli_ctx_head,
                               cli_ctx_tail,
                               cli_ctx);
  if (NULL != cli_ctx->sub)
  {
    destroy_sub (cli_ctx->sub);
    cli_ctx->sub = NULL;
  }
  GNUNET_free (cli_ctx);
}


/**
 * @brief Update sizes in sampler and view on estimate update from nse service
 *
 * @param sub Sub
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 */
static void
adapt_sizes (struct Sub *sub, double logestimate, double std_dev)
{
  double estimate;
  //double scale; // TODO this might go gloabal/config

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a ns estimate - logest: %f, std_dev: %f (old_size: %u)\n",
       logestimate, std_dev, RPS_sampler_get_size (sub->sampler));
  //scale = .01;
  estimate = GNUNET_NSE_log_estimate_to_n (logestimate);
  // GNUNET_NSE_log_estimate_to_n (logestimate);
  estimate = pow (estimate, 1.0 / 3);
  // TODO add if std_dev is a number
  // estimate += (std_dev * scale);
  if (sub->view_size_est_min < ceil (estimate))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing estimate to %f\n", estimate);
    sub->sampler_size_est_need = estimate;
    sub->view_size_est_need = estimate;
  } else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not using estimate %f\n", estimate);
    //sub->sampler_size_est_need = sub->view_size_est_min;
    sub->view_size_est_need = sub->view_size_est_min;
  }
  if (sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                           "view size aim",
                           sub->view_size_est_need,
                           GNUNET_NO);
  }

  /* If the NSE has changed adapt the lists accordingly */
  resize_wrapper (sub->sampler, sub->sampler_size_est_need);
  View_change_len (sub->view, sub->view_size_est_need);
}


/**
 * Function called by NSE.
 *
 * Updates sizes of sampler list and view and adapt those lists
 * accordingly.
 *
 * implements #GNUNET_NSE_Callback
 *
 * @param cls Closure - unused
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 */
static void
nse_callback (void *cls,
              struct GNUNET_TIME_Absolute timestamp,
              double logestimate, double std_dev)
{
  (void) cls;
  (void) timestamp;
  struct ClientContext *cli_ctx_iter;

  adapt_sizes (msub, logestimate, std_dev);
  for (cli_ctx_iter = cli_ctx_head;
      NULL != cli_ctx_iter;
      cli_ctx_iter = cli_ctx_iter->next)
  {
    if (NULL != cli_ctx_iter->sub)
    {
      adapt_sizes (cli_ctx_iter->sub, logestimate, std_dev);
    }
  }
}


/**
 * @brief This function is called, when the client seeds peers.
 * It verifies that @a msg is well-formed.
 *
 * @param cls the closure (#ClientContext)
 * @param msg the message
 * @return #GNUNET_OK if @a msg is well-formed
 *         #GNUNET_SYSERR otherwise
 */
static int
check_client_seed (void *cls, const struct GNUNET_RPS_CS_SeedMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  uint16_t msize = ntohs (msg->header.size);
  uint32_t num_peers = ntohl (msg->num_peers);

  msize -= sizeof (struct GNUNET_RPS_CS_SeedMessage);
  if ( (msize / sizeof (struct GNUNET_PeerIdentity) != num_peers) ||
       (msize % sizeof (struct GNUNET_PeerIdentity) != 0) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu32 " peers, have space for %lu peers\n",
        ntohl (msg->num_peers),
        (msize / sizeof (struct GNUNET_PeerIdentity)));
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cli_ctx->client);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle seed from the client.
 *
 * @param cls closure
 * @param message the actual message
 */
static void
handle_client_seed (void *cls,
                    const struct GNUNET_RPS_CS_SeedMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  struct GNUNET_PeerIdentity *peers;
  uint32_t num_peers;
  uint32_t i;

  num_peers = ntohl (msg->num_peers);
  peers = (struct GNUNET_PeerIdentity *) &msg[1];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client seeded peers:\n");
  print_peer_list (peers, num_peers);

  for (i = 0; i < num_peers; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating samplers with seed %" PRIu32 ": %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    if (NULL != msub) got_peer (msub, &peers[i]); /* Condition needed? */
    if (NULL != cli_ctx->sub) got_peer (cli_ctx->sub, &peers[i]);
  }
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * Handle RPS request from the client.
 *
 * @param cls Client context
 * @param message Message containing the numer of updates the client wants to
 * receive
 */
static void
handle_client_view_request (void *cls,
                            const struct GNUNET_RPS_CS_DEBUG_ViewRequest *msg)
{
  struct ClientContext *cli_ctx = cls;
  uint64_t num_updates;

  num_updates = ntohl (msg->num_updates);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requested %" PRIu64 " updates of view.\n",
       num_updates);

  GNUNET_assert (NULL != cli_ctx);
  cli_ctx->view_updates_left = num_updates;
  send_view (cli_ctx, NULL, 0);
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief Handle the cancellation of the view updates.
 *
 * @param cls The client context
 * @param msg Unused
 */
static void
handle_client_view_cancel (void *cls,
                           const struct GNUNET_MessageHeader *msg)
{
  struct ClientContext *cli_ctx = cls;
  (void) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client does not want to receive updates of view any more.\n");

  GNUNET_assert (NULL != cli_ctx);
  cli_ctx->view_updates_left = 0;
  GNUNET_SERVICE_client_continue (cli_ctx->client);
  if (GNUNET_YES == cli_ctx->stream_update)
  {
    destroy_cli_ctx (cli_ctx);
  }
}


/**
 * Handle RPS request for biased stream from the client.
 *
 * @param cls Client context
 * @param message unused
 */
static void
handle_client_stream_request (void *cls,
                              const struct GNUNET_RPS_CS_DEBUG_StreamRequest *msg)
{
  struct ClientContext *cli_ctx = cls;
  (void) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requested peers from biased stream.\n");
  cli_ctx->stream_update = GNUNET_YES;

  GNUNET_assert (NULL != cli_ctx);
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief Handles the cancellation of the stream of biased peer ids
 *
 * @param cls The client context
 * @param msg unused
 */
static void
handle_client_stream_cancel (void *cls,
                             const struct GNUNET_MessageHeader *msg)
{
  struct ClientContext *cli_ctx = cls;
  (void) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client canceled receiving peers from biased stream.\n");
  cli_ctx->stream_update = GNUNET_NO;

  GNUNET_assert (NULL != cli_ctx);
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief Create and start a Sub.
 *
 * @param cls Closure - unused
 * @param msg Message containing the necessary information
 */
static void
handle_client_start_sub (void *cls,
                         const struct GNUNET_RPS_CS_SubStartMessage *msg)
{
  struct ClientContext *cli_ctx = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client requested start of a new sub.\n");
  if (NULL != cli_ctx->sub &&
      0 != memcmp (&cli_ctx->sub->hash,
                   &msg->hash,
                   sizeof (struct GNUNET_HashCode)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Already have a Sub with different share for this client. Remove old one, add new.\n");
    destroy_sub (cli_ctx->sub);
    cli_ctx->sub = NULL;
  }
  cli_ctx->sub = new_sub (&msg->hash,
                         msub->sampler_size_est_min, // TODO make api input?
                         GNUNET_TIME_relative_ntoh (msg->round_interval));
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief Destroy the Sub
 *
 * @param cls Closure - unused
 * @param msg Message containing the hash that identifies the Sub
 */
static void
handle_client_stop_sub (void *cls,
                        const struct GNUNET_RPS_CS_SubStopMessage *msg)
{
  struct ClientContext *cli_ctx = cls;

  GNUNET_assert (NULL != cli_ctx->sub);
  if (0 != memcmp (&cli_ctx->sub->hash, &msg->hash, sizeof (struct GNUNET_HashCode)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Share of current sub and request differ!\n");
  }
  destroy_sub (cli_ctx->sub);
  cli_ctx->sub = NULL;
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * Handle a CHECK_LIVE message from another peer.
 *
 * This does nothing. But without calling #GNUNET_CADET_receive_done()
 * the channel is blocked for all other communication.
 *
 * @param cls Closure - Context of channel
 * @param msg Message - unused
 */
static void
handle_peer_check (void *cls,
                   const struct GNUNET_MessageHeader *msg)
{
  const struct ChannelCtx *channel_ctx = cls;
  const struct GNUNET_PeerIdentity *peer = &channel_ctx->peer_ctx->peer_id;
  (void) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received CHECK_LIVE (%s)\n", GNUNET_i2s (peer));
  if (channel_ctx->peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# pending online checks",
                              -1,
                              GNUNET_NO);
  }

  GNUNET_CADET_receive_done (channel_ctx->channel);
}


/**
 * Handle a PUSH message from another peer.
 *
 * Check the proof of work and store the PeerID
 * in the temporary list for pushed PeerIDs.
 *
 * @param cls Closure - Context of channel
 * @param msg Message - unused
 */
static void
handle_peer_push (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  const struct ChannelCtx *channel_ctx = cls;
  const struct GNUNET_PeerIdentity *peer = &channel_ctx->peer_ctx->peer_id;
  (void) msg;

  // (check the proof of work (?))

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received PUSH (%s)\n",
       GNUNET_i2s (peer));
  if (channel_ctx->peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update(stats, "# push message received", 1, GNUNET_NO);
    if (NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
                                                             peer))
    {
      GNUNET_STATISTICS_update (stats,
                                "# push message received (multi-hop peer)",
                                1,
                                GNUNET_NO);
    }
  }

  #if ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;

  if ( (1 == mal_type) ||
       (3 == mal_type) )
  { /* Try to maximise representation */
    tmp_att_peer = GNUNET_new (struct AttackedPeer);
    tmp_att_peer->peer_id = *peer;
    if (NULL == att_peer_set)
      att_peer_set = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
    if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
                                                             peer))
    {
      GNUNET_CONTAINER_DLL_insert (att_peers_head,
                                   att_peers_tail,
                                   tmp_att_peer);
      add_peer_array_to_set (peer, 1, att_peer_set);
    }
    else
    {
      GNUNET_free (tmp_att_peer);
    }
  }


  else if (2 == mal_type)
  {
    /* We attack one single well-known peer - simply ignore */
  }
  #endif /* ENABLE_MALICIOUS */

  /* Add the sending peer to the push_map */
  CustomPeerMap_put (channel_ctx->peer_ctx->sub->push_map, peer);

  GNUNET_break_op (check_peer_known (channel_ctx->peer_ctx->sub->peer_map,
                                     &channel_ctx->peer_ctx->peer_id));
  GNUNET_CADET_receive_done (channel_ctx->channel);
}


/**
 * Handle PULL REQUEST request message from another peer.
 *
 * Reply with the view of PeerIDs.
 *
 * @param cls Closure - Context of channel
 * @param msg Message - unused
 */
static void
handle_peer_pull_request (void *cls,
                          const struct GNUNET_MessageHeader *msg)
{
  const struct ChannelCtx *channel_ctx = cls;
  struct PeerContext *peer_ctx = channel_ctx->peer_ctx;
  const struct GNUNET_PeerIdentity *peer = &peer_ctx->peer_id;
  const struct GNUNET_PeerIdentity *view_array;
  (void) msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REQUEST (%s)\n", GNUNET_i2s (peer));
  if (peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update(stats,
                             "# pull request message received",
                             1,
                             GNUNET_NO);
    if (NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
                                                             &peer_ctx->peer_id))
    {
      GNUNET_STATISTICS_update (stats,
                                "# pull request message received (multi-hop peer)",
                                1,
                                GNUNET_NO);
    }
  }

  #if ENABLE_MALICIOUS
  if (1 == mal_type
      || 3 == mal_type)
  { /* Try to maximise representation */
    send_pull_reply (peer_ctx, mal_peers, num_mal_peers);
  }

  else if (2 == mal_type)
  { /* Try to partition network */
    if (0 == GNUNET_memcmp (&attacked_peer, peer))
    {
      send_pull_reply (peer_ctx, mal_peers, num_mal_peers);
    }
  }
  #endif /* ENABLE_MALICIOUS */

  GNUNET_break_op (check_peer_known (channel_ctx->peer_ctx->sub->peer_map,
                                     &channel_ctx->peer_ctx->peer_id));
  GNUNET_CADET_receive_done (channel_ctx->channel);
  view_array = View_get_as_array (channel_ctx->peer_ctx->sub->view);
  send_pull_reply (peer_ctx,
                   view_array,
                   View_size (channel_ctx->peer_ctx->sub->view));
}


/**
 * Check whether we sent a corresponding request and
 * whether this reply is the first one.
 *
 * @param cls Closure - Context of channel
 * @param msg Message containing the replied peers
 */
static int
check_peer_pull_reply (void *cls,
                       const struct GNUNET_RPS_P2P_PullReplyMessage *msg)
{
  struct ChannelCtx *channel_ctx = cls;
  struct PeerContext *sender_ctx = channel_ctx->peer_ctx;

  if (sizeof (struct GNUNET_RPS_P2P_PullReplyMessage) > ntohs (msg->header.size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  if ((ntohs (msg->header.size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
      sizeof (struct GNUNET_PeerIdentity) != ntohl (msg->num_peers))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu32 " peers, have space for %lu peers\n",
        ntohl (msg->num_peers),
        (ntohs (msg->header.size) - sizeof (struct GNUNET_RPS_P2P_PullReplyMessage)) /
            sizeof (struct GNUNET_PeerIdentity));
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES != check_peer_flag (sender_ctx->sub->peer_map,
                                     &sender_ctx->peer_id,
                                     Peers_PULL_REPLY_PENDING))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Received a pull reply from a peer (%s) we didn't request one from!\n",
        GNUNET_i2s (&sender_ctx->peer_id));
    if (sender_ctx->sub == msub)
    {
      GNUNET_STATISTICS_update (stats,
                                "# unrequested pull replies",
                                1,
                                GNUNET_NO);
    }
  }
  return GNUNET_OK;
}


/**
 * Handle PULL REPLY message from another peer.
 *
 * @param cls Closure
 * @param msg The message header
 */
static void
handle_peer_pull_reply (void *cls,
                        const struct GNUNET_RPS_P2P_PullReplyMessage *msg)
{
  const struct ChannelCtx *channel_ctx = cls;
  const struct GNUNET_PeerIdentity *sender = &channel_ctx->peer_ctx->peer_id;
  const struct GNUNET_PeerIdentity *peers;
  struct Sub *sub = channel_ctx->peer_ctx->sub;
  uint32_t i;
#if ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
#endif /* ENABLE_MALICIOUS */

  sub->pull_delays[sub->num_rounds - channel_ctx->peer_ctx->round_pull_req]++;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REPLY (%s)\n", GNUNET_i2s (sender));
  if (channel_ctx->peer_ctx->sub == msub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# pull reply messages received",
                              1,
                              GNUNET_NO);
    if (NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
          &channel_ctx->peer_ctx->peer_id))
    {
      GNUNET_STATISTICS_update (stats,
                                "# pull reply messages received (multi-hop peer)",
                                1,
                                GNUNET_NO);
    }
  }

  #if ENABLE_MALICIOUS
  // We shouldn't even receive pull replies as we're not sending
  if (2 == mal_type)
  {
  }
  #endif /* ENABLE_MALICIOUS */

  /* Do actual logic */
  peers = (const struct GNUNET_PeerIdentity *) &msg[1];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PULL REPLY received, got following %u peers:\n",
       ntohl (msg->num_peers));

  for (i = 0; i < ntohl (msg->num_peers); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    #if ENABLE_MALICIOUS
    if ((NULL != att_peer_set) &&
        (1 == mal_type || 3 == mal_type))
    { /* Add attacked peer to local list */
      // TODO check if we sent a request and this was the first reply
      if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
                                                               &peers[i])
          && GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (mal_peer_set,
                                                                  &peers[i]))
      {
        tmp_att_peer = GNUNET_new (struct AttackedPeer);
        tmp_att_peer->peer_id = peers[i];
        GNUNET_CONTAINER_DLL_insert (att_peers_head,
                                     att_peers_tail,
                                     tmp_att_peer);
        add_peer_array_to_set (&peers[i], 1, att_peer_set);
      }
      continue;
    }
    #endif /* ENABLE_MALICIOUS */
    /* Make sure we 'know' about this peer */
    (void) insert_peer (channel_ctx->peer_ctx->sub,
                        &peers[i]);

    if (GNUNET_YES == check_peer_valid (channel_ctx->peer_ctx->sub->valid_peers,
                                        &peers[i]))
    {
      CustomPeerMap_put (channel_ctx->peer_ctx->sub->pull_map,
                         &peers[i]);
    }
    else
    {
      schedule_operation (channel_ctx->peer_ctx,
                          insert_in_pull_map,
                          channel_ctx->peer_ctx->sub); /* cls */
      (void) issue_peer_online_check (channel_ctx->peer_ctx->sub,
                                      &peers[i]);
    }
  }

  UNSET_PEER_FLAG (get_peer_ctx (channel_ctx->peer_ctx->sub->peer_map,
                                 sender),
                   Peers_PULL_REPLY_PENDING);
  clean_peer (channel_ctx->peer_ctx->sub,
              sender);

  GNUNET_break_op (check_peer_known (channel_ctx->peer_ctx->sub->peer_map,
                                     sender));
  GNUNET_CADET_receive_done (channel_ctx->channel);
}


/**
 * Compute a random delay.
 * A uniformly distributed value between mean + spread and mean - spread.
 *
 * For example for mean 4 min and spread 2 the minimum is (4 min - (1/2 * 4 min))
 * It would return a random value between 2 and 6 min.
 *
 * @param mean the mean time until the next round
 * @param spread the inverse amount of deviation from the mean
 */
static struct GNUNET_TIME_Relative
compute_rand_delay (struct GNUNET_TIME_Relative mean,
                    unsigned int spread)
{
  struct GNUNET_TIME_Relative half_interval;
  struct GNUNET_TIME_Relative ret;
  unsigned int rand_delay;
  unsigned int max_rand_delay;

  if (0 == spread)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not accepting spread of 0\n");
    GNUNET_break (0);
    GNUNET_assert (0);
  }
  GNUNET_assert (0 != mean.rel_value_us);

  /* Compute random time value between spread * mean and spread * mean */
  half_interval = GNUNET_TIME_relative_divide (mean, spread);

  max_rand_delay = GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us / mean.rel_value_us * (2/spread);
  /**
   * Compute random value between (0 and 1) * round_interval
   * via multiplying round_interval with a 'fraction' (0 to value)/value
   */
  rand_delay = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, max_rand_delay);
  ret = GNUNET_TIME_relative_saturating_multiply (mean,  rand_delay);
  ret = GNUNET_TIME_relative_divide   (ret, max_rand_delay);
  ret = GNUNET_TIME_relative_add      (ret, half_interval);

  if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == ret.rel_value_us)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Returning FOREVER_REL\n");

  return ret;
}


/**
 * Send single pull request
 *
 * @param peer_ctx Context to the peer to send request to
 */
static void
send_pull_request (struct PeerContext *peer_ctx)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (GNUNET_NO == check_peer_flag (peer_ctx->sub->peer_map,
                                               &peer_ctx->peer_id,
                                               Peers_PULL_REPLY_PENDING));
  SET_PEER_FLAG (peer_ctx,
                 Peers_PULL_REPLY_PENDING);
  peer_ctx->round_pull_req = peer_ctx->sub->num_rounds;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PULL REQUEST to peer %s.\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
  send_message (peer_ctx,
                ev,
                "PULL REQUEST");
  if (peer_ctx->sub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# pull request send issued",
                              1,
                              GNUNET_NO);
    if (NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
                                                             &peer_ctx->peer_id))
    {
      GNUNET_STATISTICS_update (stats,
                                "# pull request send issued (multi-hop peer)",
                                1,
                                GNUNET_NO);
    }
  }
}


/**
 * Send single push
 *
 * @param peer_ctx Context of peer to send push to
 */
static void
send_push (struct PeerContext *peer_ctx)
{
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PUSH to peer %s.\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
  send_message (peer_ctx, ev, "PUSH");
  if (peer_ctx->sub)
  {
    GNUNET_STATISTICS_update (stats,
                              "# push send issued",
                              1,
                              GNUNET_NO);
    if (NULL != map_single_hop &&
        GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (map_single_hop,
                                                             &peer_ctx->peer_id))
    {
      GNUNET_STATISTICS_update (stats,
                                "# push send issued (multi-hop peer)",
                                1,
                                GNUNET_NO);
    }
  }
}


#if ENABLE_MALICIOUS


/**
 * @brief This function is called, when the client tells us to act malicious.
 * It verifies that @a msg is well-formed.
 *
 * @param cls the closure (#ClientContext)
 * @param msg the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_client_act_malicious (void *cls,
                            const struct GNUNET_RPS_CS_ActMaliciousMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  uint16_t msize = ntohs (msg->header.size);
  uint32_t num_peers = ntohl (msg->num_peers);

  msize -= sizeof (struct GNUNET_RPS_CS_ActMaliciousMessage);
  if ( (msize / sizeof (struct GNUNET_PeerIdentity) != num_peers) ||
       (msize % sizeof (struct GNUNET_PeerIdentity) != 0) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "message says it sends %" PRIu32 " peers, have space for %lu peers\n",
        ntohl (msg->num_peers),
        (msize / sizeof (struct GNUNET_PeerIdentity)));
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cli_ctx->client);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Turn RPS service to act malicious.
 *
 * @param cls Closure
 * @param client The client that sent the message
 * @param msg The message header
 */
static void
handle_client_act_malicious (void *cls,
                             const struct GNUNET_RPS_CS_ActMaliciousMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  struct GNUNET_PeerIdentity *peers;
  uint32_t num_mal_peers_sent;
  uint32_t num_mal_peers_old;
  struct Sub *sub = cli_ctx->sub;

  if (NULL == sub) sub = msub;
  /* Do actual logic */
  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  mal_type = ntohl (msg->type);
  if (NULL == mal_peer_set)
    mal_peer_set = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now acting malicious type %" PRIu32 ", got %" PRIu32 " peers.\n",
       mal_type,
       ntohl (msg->num_peers));

  if (1 == mal_type)
  { /* Try to maximise representation */
    /* Add other malicious peers to those we already know */

    num_mal_peers_sent = ntohl (msg->num_peers);
    num_mal_peers_old = num_mal_peers;
    GNUNET_array_grow (mal_peers,
                       num_mal_peers,
                       num_mal_peers + num_mal_peers_sent);
    GNUNET_memcpy (&mal_peers[num_mal_peers_old],
            peers,
            num_mal_peers_sent * sizeof (struct GNUNET_PeerIdentity));

    /* Add all mal peers to mal_peer_set */
    add_peer_array_to_set (&mal_peers[num_mal_peers_old],
                           num_mal_peers_sent,
                           mal_peer_set);

    /* Substitute do_round () with do_mal_round () */
    GNUNET_assert (NULL != sub->do_round_task);
    GNUNET_SCHEDULER_cancel (sub->do_round_task);
    sub->do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, sub);
  }

  else if ( (2 == mal_type) ||
            (3 == mal_type) )
  { /* Try to partition the network */
    /* Add other malicious peers to those we already know */

    num_mal_peers_sent = ntohl (msg->num_peers) - 1;
    num_mal_peers_old = num_mal_peers;
    GNUNET_assert (GNUNET_MAX_MALLOC_CHECKED > num_mal_peers_sent);
    GNUNET_array_grow (mal_peers,
                       num_mal_peers,
                       num_mal_peers + num_mal_peers_sent);
    if (NULL != mal_peers &&
        0 != num_mal_peers)
    {
      GNUNET_memcpy (&mal_peers[num_mal_peers_old],
              peers,
              num_mal_peers_sent * sizeof (struct GNUNET_PeerIdentity));

      /* Add all mal peers to mal_peer_set */
      add_peer_array_to_set (&mal_peers[num_mal_peers_old],
                             num_mal_peers_sent,
                             mal_peer_set);
    }

    /* Store the one attacked peer */
    GNUNET_memcpy (&attacked_peer,
            &msg->attacked_peer,
            sizeof (struct GNUNET_PeerIdentity));
    /* Set the flag of the attacked peer to valid to avoid problems */
    if (GNUNET_NO == check_peer_known (sub->peer_map, &attacked_peer))
    {
      (void) issue_peer_online_check (sub, &attacked_peer);
    }

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Attacked peer is %s\n",
         GNUNET_i2s (&attacked_peer));

    /* Substitute do_round () with do_mal_round () */
    if (NULL != sub->do_round_task)
    {
      /* Probably in shutdown */
      GNUNET_SCHEDULER_cancel (sub->do_round_task);
      sub->do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, sub);
    }
  }
  else if (0 == mal_type)
  { /* Stop acting malicious */
    GNUNET_array_grow (mal_peers, num_mal_peers, 0);

    /* Substitute do_mal_round () with do_round () */
    GNUNET_SCHEDULER_cancel (sub->do_round_task);
    sub->do_round_task = GNUNET_SCHEDULER_add_now (&do_round, sub);
  }
  else
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_continue (cli_ctx->client);
  }
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * Send out PUSHes and PULLs maliciously.
 *
 * This is executed regylary.
 *
 * @param cls Closure - Sub
 */
static void
do_mal_round (void *cls)
{
  uint32_t num_pushes;
  uint32_t i;
  struct GNUNET_TIME_Relative time_next_round;
  struct AttackedPeer *tmp_att_peer;
  struct Sub *sub = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to execute next round maliciously type %" PRIu32 ".\n",
      mal_type);
  sub->do_round_task = NULL;
  GNUNET_assert (mal_type <= 3);
  /* Do malicious actions */
  if (1 == mal_type)
  { /* Try to maximise representation */

    /* The maximum of pushes we're going to send this round */
    num_pushes = GNUNET_MIN (GNUNET_MIN (push_limit,
                                         num_attacked_peers),
                             GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send %" PRIu32 " pushes\n",
         num_pushes);

    /* Send PUSHes to attacked peers */
    for (i = 0 ; i < num_pushes ; i++)
    {
      if (att_peers_tail == att_peer_index)
        att_peer_index = att_peers_head;
      else
        att_peer_index = att_peer_index->next;

      send_push (get_peer_ctx (sub->peer_map, &att_peer_index->peer_id));
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0 ; i < num_pushes * alpha ; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (get_peer_ctx (sub->peer_map, &tmp_att_peer->peer_id));
    }
  }


  else if (2 == mal_type)
  { /**
     * Try to partition the network
     * Send as many pushes to the attacked peer as possible
     * That is one push per round as it will ignore more.
     */
    (void) issue_peer_online_check (sub, &attacked_peer);
    if (GNUNET_YES == check_peer_flag (sub->peer_map,
                                       &attacked_peer,
                                       Peers_ONLINE))
      send_push (get_peer_ctx (sub->peer_map, &attacked_peer));
  }


  if (3 == mal_type)
  { /* Combined attack */

    /* Send PUSH to attacked peers */
    if (GNUNET_YES == check_peer_known (sub->peer_map, &attacked_peer))
    {
      (void) issue_peer_online_check (sub, &attacked_peer);
      if (GNUNET_YES == check_peer_flag (sub->peer_map,
                                         &attacked_peer,
                                         Peers_ONLINE))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Goding to send push to attacked peer (%s)\n",
            GNUNET_i2s (&attacked_peer));
        send_push (get_peer_ctx (sub->peer_map, &attacked_peer));
      }
    }
    (void) issue_peer_online_check (sub, &attacked_peer);

    /* The maximum of pushes we're going to send this round */
    num_pushes = GNUNET_MIN (GNUNET_MIN (push_limit - 1,
                                         num_attacked_peers),
                             GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send %" PRIu32 " pushes\n",
         num_pushes);

    for (i = 0; i < num_pushes; i++)
    {
      if (att_peers_tail == att_peer_index)
        att_peer_index = att_peers_head;
      else
        att_peer_index = att_peer_index->next;

      send_push (get_peer_ctx (sub->peer_map, &att_peer_index->peer_id));
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0; i < num_pushes * alpha; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (get_peer_ctx (sub->peer_map, &tmp_att_peer->peer_id));
    }
  }

  /* Schedule next round */
  time_next_round = compute_rand_delay (sub->round_interval, 2);

  GNUNET_assert (NULL == sub->do_round_task);
  sub->do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round,
                                                    &do_mal_round, sub);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}
#endif /* ENABLE_MALICIOUS */


/**
 * Send out PUSHes and PULLs, possibly update #view, samplers.
 *
 * This is executed regylary.
 *
 * @param cls Closure - Sub
 */
static void
do_round (void *cls)
{
  unsigned int i;
  const struct GNUNET_PeerIdentity *view_array;
  unsigned int *permut;
  unsigned int a_peers; /* Number of peers we send pushes to */
  unsigned int b_peers; /* Number of peers we send pull requests to */
  uint32_t first_border;
  uint32_t second_border;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_PeerIdentity *update_peer;
  struct Sub *sub = cls;

  sub->num_rounds++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to execute next round.\n");
  if (sub == msub)
  {
    GNUNET_STATISTICS_update (stats, "# rounds", 1, GNUNET_NO);
  }
  sub->do_round_task = NULL;
#ifdef TO_FILE_FULL
  to_file (sub->file_name_view_log,
           "___ new round ___");
#endif /* TO_FILE_FULL */
  view_array = View_get_as_array (sub->view);
  for (i = 0; i < View_size (sub->view); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "\t%s\n", GNUNET_i2s (&view_array[i]));
#ifdef TO_FILE_FULL
    to_file (sub->file_name_view_log,
             "=%s\t(do round)",
             GNUNET_i2s_full (&view_array[i]));
#endif /* TO_FILE_FULL */
  }


  /* Send pushes and pull requests */
  if (0 < View_size (sub->view))
  {
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           View_size (sub->view));

    /* Send PUSHes */
    a_peers = ceil (alpha * View_size (sub->view));

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send pushes to %u (ceil (%f * %u)) peers.\n",
         a_peers, alpha, View_size (sub->view));
    for (i = 0; i < a_peers; i++)
    {
      peer = view_array[permut[i]];
      // FIXME if this fails schedule/loop this for later
      send_push (get_peer_ctx (sub->peer_map, &peer));
    }

    /* Send PULL requests */
    b_peers = ceil (beta * View_size (sub->view));
    first_border = a_peers;
    second_border = a_peers + b_peers;
    if (second_border > View_size (sub->view))
    {
      first_border = View_size (sub->view) - b_peers;
      second_border = View_size (sub->view);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to send pulls to %u (ceil (%f * %u)) peers.\n",
        b_peers, beta, View_size (sub->view));
    for (i = first_border; i < second_border; i++)
    {
      peer = view_array[permut[i]];
      if ( GNUNET_NO == check_peer_flag (sub->peer_map,
                                         &peer,
                                         Peers_PULL_REPLY_PENDING))
      { // FIXME if this fails schedule/loop this for later
        send_pull_request (get_peer_ctx (sub->peer_map, &peer));
      }
    }

    GNUNET_free (permut);
    permut = NULL;
  }


  /* Update view */
  /* TODO see how many peers are in push-/pull- list! */

  if ((CustomPeerMap_size (sub->push_map) <= alpha * sub->view_size_est_need) &&
      (0 < CustomPeerMap_size (sub->push_map)) &&
      (0 < CustomPeerMap_size (sub->pull_map)))
  { /* If conditions for update are fulfilled, update */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Update of the view.\n");

    uint32_t final_size;
    uint32_t peers_to_clean_size;
    struct GNUNET_PeerIdentity *peers_to_clean;

    peers_to_clean = NULL;
    peers_to_clean_size = 0;
    GNUNET_array_grow (peers_to_clean,
                       peers_to_clean_size,
                       View_size (sub->view));
    GNUNET_memcpy (peers_to_clean,
            view_array,
            View_size (sub->view) * sizeof (struct GNUNET_PeerIdentity));

    /* Seems like recreating is the easiest way of emptying the peermap */
    View_clear (sub->view);
#ifdef TO_FILE_FULL
    to_file (sub->file_name_view_log,
             "--- emptied ---");
#endif /* TO_FILE_FULL */

    first_border  = GNUNET_MIN (ceil (alpha * sub->view_size_est_need),
                                CustomPeerMap_size (sub->push_map));
    second_border = first_border +
                    GNUNET_MIN (floor (beta  * sub->view_size_est_need),
                                CustomPeerMap_size (sub->pull_map));
    final_size    = second_border +
      ceil ((1 - (alpha + beta)) * sub->view_size_est_need);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "first border: %" PRIu32 ", second border: %" PRIu32 ", final size: %"PRIu32 "\n",
        first_border,
        second_border,
        final_size);

    /* Update view with peers received through PUSHes */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (sub->push_map));
    for (i = 0; i < first_border; i++)
    {
      int inserted;
      inserted = insert_in_view (sub,
                                 CustomPeerMap_get_peer_by_index (sub->push_map,
                                                                  permut[i]));
      if (GNUNET_OK == inserted)
      {
        clients_notify_stream_peer (sub,
            1,
            CustomPeerMap_get_peer_by_index (sub->push_map, permut[i]));
      }
#ifdef TO_FILE_FULL
      to_file (sub->file_name_view_log,
               "+%s\t(push list)",
               GNUNET_i2s_full (&view_array[i]));
#endif /* TO_FILE_FULL */
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers received through PULLs */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (sub->pull_map));
    for (i = first_border; i < second_border; i++)
    {
      int inserted;
      inserted = insert_in_view (sub,
          CustomPeerMap_get_peer_by_index (sub->pull_map,
                                           permut[i - first_border]));
      if (GNUNET_OK == inserted)
      {
        clients_notify_stream_peer (sub,
            1,
            CustomPeerMap_get_peer_by_index (sub->pull_map,
                                             permut[i - first_border]));
      }
#ifdef TO_FILE_FULL
      to_file (sub->file_name_view_log,
               "+%s\t(pull list)",
               GNUNET_i2s_full (&view_array[i]));
#endif /* TO_FILE_FULL */
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers from history */
    RPS_sampler_get_n_rand_peers (sub->sampler,
                                  final_size - second_border,
                                  hist_update,
                                  sub);
    // TODO change the peer_flags accordingly

    for (i = 0; i < View_size (sub->view); i++)
      rem_from_list (&peers_to_clean, &peers_to_clean_size, &view_array[i]);

    /* Clean peers that were removed from the view */
    for (i = 0; i < peers_to_clean_size; i++)
    {
#ifdef TO_FILE_FULL
      to_file (sub->file_name_view_log,
               "-%s",
               GNUNET_i2s_full (&peers_to_clean[i]));
#endif /* TO_FILE_FULL */
      clean_peer (sub, &peers_to_clean[i]);
    }

    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, 0);
    clients_notify_view_update (sub);
  } else {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No update of the view.\n");
    if (sub == msub)
    {
      GNUNET_STATISTICS_update(stats, "# rounds blocked", 1, GNUNET_NO);
      if (CustomPeerMap_size (sub->push_map) > alpha * sub->view_size_est_need &&
          !(0 >= CustomPeerMap_size (sub->pull_map)))
        GNUNET_STATISTICS_update(stats, "# rounds blocked - too many pushes", 1, GNUNET_NO);
      if (CustomPeerMap_size (sub->push_map) > alpha * sub->view_size_est_need &&
          (0 >= CustomPeerMap_size (sub->pull_map)))
        GNUNET_STATISTICS_update(stats, "# rounds blocked - too many pushes, no pull replies", 1, GNUNET_NO);
      if (0 >= CustomPeerMap_size (sub->push_map) &&
          !(0 >= CustomPeerMap_size (sub->pull_map)))
        GNUNET_STATISTICS_update(stats, "# rounds blocked - no pushes", 1, GNUNET_NO);
      if (0 >= CustomPeerMap_size (sub->push_map) &&
          (0 >= CustomPeerMap_size (sub->pull_map)))
        GNUNET_STATISTICS_update(stats, "# rounds blocked - no pushes, no pull replies", 1, GNUNET_NO);
      if (0 >= CustomPeerMap_size (sub->pull_map) &&
          CustomPeerMap_size (sub->push_map) > alpha * sub->view_size_est_need &&
          0 >= CustomPeerMap_size (sub->push_map))
        GNUNET_STATISTICS_update(stats, "# rounds blocked - no pull replies", 1, GNUNET_NO);
    }
  }
  // TODO independent of that also get some peers from CADET_get_peers()?
  if (CustomPeerMap_size (sub->push_map) < HISTOGRAM_FILE_SLOTS)
  {
    sub->push_recv[CustomPeerMap_size (sub->push_map)]++;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Push map size too big for histogram (%u, %u)\n",
         CustomPeerMap_size (sub->push_map),
         HISTOGRAM_FILE_SLOTS);
  }
  // FIXME check bounds of histogram
  sub->push_delta[(int32_t) (CustomPeerMap_size (sub->push_map) -
                   (alpha * sub->view_size_est_need)) +
                          (HISTOGRAM_FILE_SLOTS/2)]++;
  if (sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
        "# peers in push map at end of round",
        CustomPeerMap_size (sub->push_map),
        GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "# peers in pull map at end of round",
        CustomPeerMap_size (sub->pull_map),
        GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "# peers in view at end of round",
        View_size (sub->view),
        GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "# expected pushes",
        alpha * sub->view_size_est_need,
        GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "delta expected - received pushes",
        CustomPeerMap_size (sub->push_map) - (alpha * sub->view_size_est_need),
        GNUNET_NO);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u pushes and %u pulls last round (alpha (%.2f) * view_size (sub->view%u) = %.2f)\n",
       CustomPeerMap_size (sub->push_map),
       CustomPeerMap_size (sub->pull_map),
       alpha,
       View_size (sub->view),
       alpha * View_size (sub->view));

  /* Update samplers */
  for (i = 0; i < CustomPeerMap_size (sub->push_map); i++)
  {
    update_peer = CustomPeerMap_get_peer_by_index (sub->push_map, i);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from push list\n",
         GNUNET_i2s (update_peer));
    insert_in_sampler (sub, update_peer);
    clean_peer (sub, update_peer); /* This cleans only if it is not in the view */
  }

  for (i = 0; i < CustomPeerMap_size (sub->pull_map); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from pull list\n",
         GNUNET_i2s (CustomPeerMap_get_peer_by_index (sub->pull_map, i)));
    insert_in_sampler (sub, CustomPeerMap_get_peer_by_index (sub->pull_map, i));
    /* This cleans only if it is not in the view */
    clean_peer (sub, CustomPeerMap_get_peer_by_index (sub->pull_map, i));
  }


  /* Empty push/pull lists */
  CustomPeerMap_clear (sub->push_map);
  CustomPeerMap_clear (sub->pull_map);

  if (sub == msub)
  {
    GNUNET_STATISTICS_set (stats,
                           "view size",
                           View_size(sub->view),
                           GNUNET_NO);
  }

  struct GNUNET_TIME_Relative time_next_round;

  time_next_round = compute_rand_delay (sub->round_interval, 2);

  /* Schedule next round */
  sub->do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round,
                                                     &do_round, sub);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}


/**
 * This is called from GNUNET_CADET_get_peers().
 *
 * It is called on every peer(ID) that cadet somehow has contact with.
 * We use those to initialise the sampler.
 *
 * implements #GNUNET_CADET_PeersCB
 *
 * @param cls Closure - Sub
 * @param peer Peer, or NULL on "EOF".
 * @param tunnel Do we have a tunnel towards this peer?
 * @param n_paths Number of known paths towards this peer.
 * @param best_path How long is the best path?
 *                  (0 = unknown, 1 = ourselves, 2 = neighbor)
 */
void
init_peer_cb (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              int tunnel, /* "Do we have a tunnel towards this peer?" */
              unsigned int n_paths, /* "Number of known paths towards this peer" */
              unsigned int best_path) /* "How long is the best path?
                                       * (0 = unknown, 1 = ourselves, 2 = neighbor)" */
{
  struct Sub *sub = cls;
  (void) tunnel;
  (void) n_paths;
  (void) best_path;

  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from cadet\n",
         GNUNET_i2s (peer));
    got_peer (sub, peer);
  }
}


/**
 * @brief Iterator function over stored, valid peers.
 *
 * We initialise the sampler with those.
 *
 * @param cls Closure - Sub
 * @param peer the peer id
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
valid_peers_iterator (void *cls,
                      const struct GNUNET_PeerIdentity *peer)
{
  struct Sub *sub = cls;

  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got stored, valid peer %s\n",
         GNUNET_i2s (peer));
    got_peer (sub, peer);
  }
  return GNUNET_YES;
}


/**
 * Iterator over peers from peerinfo.
 *
 * @param cls Closure - Sub
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param error message
 */
void
process_peerinfo_peers (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_HELLO_Message *hello,
                        const char *err_msg)
{
  struct Sub *sub = cls;
  (void) hello;
  (void) err_msg;

  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from peerinfo\n",
         GNUNET_i2s (peer));
    got_peer (sub, peer);
  }
}


/**
 * Task run during shutdown.
 *
 * @param cls Closure - unused
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  struct ClientContext *client_ctx;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "RPS service is going down\n");

  /* Clean all clients */
  for (client_ctx = cli_ctx_head;
       NULL != cli_ctx_head;
       client_ctx = cli_ctx_head)
  {
    destroy_cli_ctx (client_ctx);
  }
  if (NULL != msub)
  {
    destroy_sub (msub);
    msub = NULL;
  }

  /* Disconnect from other services */
  GNUNET_PEERINFO_notify_cancel (peerinfo_notify_handle);
  GNUNET_PEERINFO_disconnect (peerinfo_handle);
  peerinfo_handle = NULL;
  GNUNET_NSE_disconnect (nse);
  if (NULL != map_single_hop)
  {
    /* core_init was called - core was initialised */
    /* disconnect first, so no callback tries to access missing peermap */
    GNUNET_CORE_disconnect (core_handle);
    core_handle = NULL;
    GNUNET_CONTAINER_multipeermap_destroy (map_single_hop);
    map_single_hop = NULL;
  }

  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
                               GNUNET_NO);
    stats = NULL;
  }
  GNUNET_CADET_disconnect (cadet_handle);
  cadet_handle = NULL;
#if ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
  GNUNET_array_grow (mal_peers,
                     num_mal_peers,
                     0);
  if (NULL != mal_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (mal_peer_set);
  if (NULL != att_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (att_peer_set);
  while (NULL != att_peers_head)
  {
    tmp_att_peer = att_peers_head;
    GNUNET_CONTAINER_DLL_remove (att_peers_head,
                                 att_peers_tail,
                                 tmp_att_peer);
    GNUNET_free (tmp_att_peer);
  }
#endif /* ENABLE_MALICIOUS */
  close_all_files();
}


/**
 * Handle client connecting to the service.
 *
 * @param cls unused
 * @param client the new client
 * @param mq the message queue of @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct ClientContext *cli_ctx;
  (void) cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client connected\n");
  if (NULL == client)
    return client; /* Server was destroyed before a client connected. Shutting down */
  cli_ctx = GNUNET_new (struct ClientContext);
  cli_ctx->mq = mq;
  cli_ctx->view_updates_left = -1;
  cli_ctx->stream_update = GNUNET_NO;
  cli_ctx->client = client;
  GNUNET_CONTAINER_DLL_insert (cli_ctx_head,
                               cli_ctx_tail,
                               cli_ctx);
  return cli_ctx;
}

/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *internal_cls)
{
  struct ClientContext *cli_ctx = internal_cls;

  (void) cls;
  GNUNET_assert (client == cli_ctx->client);
  if (NULL == client)
  {/* shutdown task - destroy all clients */
    while (NULL != cli_ctx_head)
      destroy_cli_ctx (cli_ctx_head);
  }
  else
  { /* destroy this client */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Client disconnected. Destroy its context.\n");
    destroy_cli_ctx (cli_ctx);
  }
}


/**
 * Handle random peer sampling clients.
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
  struct GNUNET_TIME_Relative round_interval;
  long long unsigned int sampler_size;
  char hash_port_string[] = GNUNET_APPLICATION_PORT_RPS;
  struct GNUNET_HashCode hash;

  (void) cls;
  (void) service;

  GNUNET_log_setup ("rps",
                    GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_DEBUG),
                    NULL);
  cfg = c;
  /* Get own ID */
  GNUNET_CRYPTO_get_peer_identity (cfg,
                                   &own_identity); // TODO check return value
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STARTING SERVICE (rps) for peer [%s]\n",
              GNUNET_i2s (&own_identity));
#if ENABLE_MALICIOUS
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Malicious execution compiled in.\n");
#endif /* ENABLE_MALICIOUS */

  /* Get time interval from the configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "RPS",
                                           "ROUNDINTERVAL",
                                           &round_interval))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "ROUNDINTERVAL");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Get initial size of sampler/view from the configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "RPS",
                                             "MINSIZE",
                                             &sampler_size))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "MINSIZE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  cadet_handle = GNUNET_CADET_connect (cfg);
  GNUNET_assert (NULL != cadet_handle);
  core_handle = GNUNET_CORE_connect (cfg,
                                     NULL, /* cls */
                                     core_init, /* init */
                                     core_connects, /* connects */
                                     core_disconnects, /* disconnects */
                                     NULL); /* handlers */
  GNUNET_assert (NULL != core_handle);


  alpha = 0.45;
  beta  = 0.45;


  /* Set up main Sub */
  GNUNET_CRYPTO_hash (hash_port_string,
                      strlen (hash_port_string),
                      &hash);
  msub = new_sub (&hash,
                 sampler_size, /* Will be overwritten by config */
                 round_interval);


  peerinfo_handle = GNUNET_PEERINFO_connect (cfg);

  /* connect to NSE */
  nse = GNUNET_NSE_connect (cfg, nse_callback, NULL);

  //LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  //GNUNET_CADET_get_peers (cadet_handle, &init_peer_cb, msub);
  // TODO send push/pull to each of those peers?
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting stored valid peers\n");
  restore_valid_peers (msub);
  get_valid_peers (msub->valid_peers, valid_peers_iterator, msub);

  peerinfo_notify_handle = GNUNET_PEERINFO_notify (cfg,
                                                   GNUNET_NO,
                                                   process_peerinfo_peers,
                                                   msub);

  LOG (GNUNET_ERROR_TYPE_INFO, "Ready to receive requests from clients\n");

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  stats = GNUNET_STATISTICS_create ("rps", cfg);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("rps",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (client_seed,
   GNUNET_MESSAGE_TYPE_RPS_CS_SEED,
   struct GNUNET_RPS_CS_SeedMessage,
   NULL),
#if ENABLE_MALICIOUS
 GNUNET_MQ_hd_var_size (client_act_malicious,
   GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS,
   struct GNUNET_RPS_CS_ActMaliciousMessage,
   NULL),
#endif /* ENABLE_MALICIOUS */
 GNUNET_MQ_hd_fixed_size (client_view_request,
   GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REQUEST,
   struct GNUNET_RPS_CS_DEBUG_ViewRequest,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_view_cancel,
   GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_CANCEL,
   struct GNUNET_MessageHeader,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_stream_request,
   GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REQUEST,
   struct GNUNET_RPS_CS_DEBUG_StreamRequest,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_stream_cancel,
   GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_CANCEL,
   struct GNUNET_MessageHeader,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_start_sub,
   GNUNET_MESSAGE_TYPE_RPS_CS_SUB_START,
   struct GNUNET_RPS_CS_SubStartMessage,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_stop_sub,
   GNUNET_MESSAGE_TYPE_RPS_CS_SUB_STOP,
   struct GNUNET_RPS_CS_SubStopMessage,
   NULL),
 GNUNET_MQ_handler_end());

/* end of gnunet-service-rps.c */
