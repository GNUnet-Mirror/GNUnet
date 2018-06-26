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

#define LOG(kind, ...) GNUNET_log(kind, __VA_ARGS__)

// TODO modify @brief in every file

// TODO check for overflows

// TODO align message structs

// TODO connect to friends

// TODO store peers somewhere persistent

// TODO blacklist? (-> mal peer detection on top of brahms)

// hist_size_init, hist_size_max

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our own identity.
 */
static struct GNUNET_PeerIdentity own_identity;


/**
 * @brief Port used for cadet.
 *
 * Don't compute multiple times through making it global
 */
static struct GNUNET_HashCode port;

/***********************************************************************
 * Old gnunet-service-rps_peers.c
***********************************************************************/

/**
 * Set a peer flag of given peer context.
 */
#define set_peer_flag(peer_ctx, mask) ((peer_ctx->peer_flags) |= (mask))

/**
 * Get peer flag of given peer context.
 */
#define check_peer_flag_set(peer_ctx, mask)\
  ((peer_ctx->peer_flags) & (mask) ? GNUNET_YES : GNUNET_NO)

/**
 * Unset flag of given peer context.
 */
#define unset_peer_flag(peer_ctx, mask) ((peer_ctx->peer_flags) &= ~(mask))

/**
 * Set a channel flag of given channel context.
 */
#define set_channel_flag(channel_flags, mask) ((*channel_flags) |= (mask))

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
 * Struct used to keep track of other peer's status
 *
 * This is stored in a multipeermap.
 * It contains information such as cadet channels, a message queue for sending,
 * status about the channels, the pending operations on this peer and some flags
 * about the status of the peer itself. (live, valid, ...)
 */
struct PeerContext
{
  /**
   * Message queue open to client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Channel open to client.
   */
  struct GNUNET_CADET_Channel *send_channel;

  /**
   * Flags to the sending channel
   */
  uint32_t *send_channel_flags;

  /**
   * Channel open from client.
   */
  struct GNUNET_CADET_Channel *recv_channel; // unneeded?

  /**
   * Flags to the receiving channel
   */
  uint32_t *recv_channel_flags;

  /**
   * Array of pending operations on this peer.
   */
  struct PeerPendingOp *pending_ops;

  /**
   * Handle to the callback given to cadet_ntfy_tmt_rdy()
   *
   * To be canceled on shutdown.
   */
  struct PendingMessage *liveliness_check_pending;

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
   * him, how did we get his ID, how many pushes (in a timeinterval),
   * ...)
   */
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
 * @brief Hashmap of valid peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *valid_peers;

/**
 * @brief Maximum number of valid peers to keep.
 * TODO read from config
 */
static uint32_t num_valid_peers_max = UINT32_MAX;

/**
 * @brief Filename of the file that stores the valid peers persistently.
 */
static char *filename_valid_peers;

/**
 * Set of all peers to keep track of them.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peer_map;

/**
 * Cadet handle.
 */
static struct GNUNET_CADET_Handle *cadet_handle;



/**
 * @brief Get the #PeerContext associated with a peer
 *
 * @param peer the peer id
 *
 * @return the #PeerContext
 */
static struct PeerContext *
get_peer_ctx (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *ctx;
  int ret;

  ret = GNUNET_CONTAINER_multipeermap_contains (peer_map, peer);
  GNUNET_assert (GNUNET_YES == ret);
  ctx = GNUNET_CONTAINER_multipeermap_get (peer_map, peer);
  GNUNET_assert (NULL != ctx);
  return ctx;
}

int
Peers_check_peer_known (const struct GNUNET_PeerIdentity *peer);

/**
 * @brief Create a new #PeerContext and insert it into the peer map
 *
 * @param peer the peer to create the #PeerContext for
 *
 * @return the #PeerContext
 */
static struct PeerContext *
create_peer_ctx (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *ctx;
  int ret;

  GNUNET_assert (GNUNET_NO == Peers_check_peer_known (peer));

  ctx = GNUNET_new (struct PeerContext);
  ctx->peer_id = *peer;
  ctx->send_channel_flags = GNUNET_new (uint32_t);
  ctx->recv_channel_flags = GNUNET_new (uint32_t);
  ret = GNUNET_CONTAINER_multipeermap_put (peer_map, peer, ctx,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  GNUNET_assert (GNUNET_OK == ret);
  return ctx;
}


/**
 * @brief Create or get a #PeerContext
 *
 * @param peer the peer to get the associated context to
 *
 * @return the context
 */
static struct PeerContext *
create_or_get_peer_ctx (const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return create_peer_ctx (peer);
  }
  return get_peer_ctx (peer);
}

void
Peers_unset_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);

void
Peers_set_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);

/**
 * @brief Check whether we have a connection to this @a peer
 *
 * Also sets the #Peers_ONLINE flag accordingly
 *
 * @param peer the peer in question
 *
 * @return #GNUNET_YES if we are connected
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_connected (const struct GNUNET_PeerIdentity *peer)
{
  const struct PeerContext *peer_ctx;

  /* If we don't know about this peer we don't know whether it's online */
  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_NO;
  }
  /* Get the context */
  peer_ctx = get_peer_ctx (peer);
  /* If we have no channel to this peer we don't know whether it's online */
  if ( (NULL == peer_ctx->send_channel) &&
       (NULL == peer_ctx->recv_channel) )
  {
    Peers_unset_peer_flag (peer, Peers_ONLINE);
    return GNUNET_NO;
  }
  /* Otherwise (if we have a channel, we know that it's online */
  Peers_set_peer_flag (peer, Peers_ONLINE);
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
 * @param peer_map the peer_map to get the peer from
 *
 * @return a random peer
 */
static const struct GNUNET_PeerIdentity *
get_random_peer_from_peermap (const struct
                              GNUNET_CONTAINER_MultiPeerMap *peer_map)
{
  struct GetRandPeerIteratorCls *iterator_cls;
  const struct GNUNET_PeerIdentity *ret;

  iterator_cls = GNUNET_new (struct GetRandPeerIteratorCls);
  iterator_cls->index = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
      GNUNET_CONTAINER_multipeermap_size (peer_map));
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
 * @param peer the peer that is added to the valid peers.
 *
 * @return #GNUNET_YES if no other peer had to be removed
 *         #GNUNET_NO  otherwise
 */
static int
add_valid_peer (const struct GNUNET_PeerIdentity *peer)
{
  const struct GNUNET_PeerIdentity *rand_peer;
  int ret;

  ret = GNUNET_YES;
  while (GNUNET_CONTAINER_multipeermap_size (valid_peers) >= num_valid_peers_max)
  {
    rand_peer = get_random_peer_from_peermap (valid_peers);
    GNUNET_CONTAINER_multipeermap_remove_all (valid_peers, rand_peer);
    ret = GNUNET_NO;
  }
  (void) GNUNET_CONTAINER_multipeermap_put (valid_peers, peer, NULL,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
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
 * @param peer_ctx the #PeerContext of the peer to set live
 */
static void
set_peer_live (struct PeerContext *peer_ctx)
{
  struct GNUNET_PeerIdentity *peer;
  unsigned int i;

  peer = &peer_ctx->peer_id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Peer %s is live and valid, calling %i pending operations on it\n",
      GNUNET_i2s (peer),
      peer_ctx->num_pending_ops);

  if (NULL != peer_ctx->liveliness_check_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Removing pending liveliness check for peer %s\n",
         GNUNET_i2s (&peer_ctx->peer_id));
    // TODO wait until cadet sets mq->cancel_impl
    //GNUNET_MQ_send_cancel (peer_ctx->liveliness_check_pending->ev);
    remove_pending_message (peer_ctx->liveliness_check_pending, GNUNET_YES);
    peer_ctx->liveliness_check_pending = NULL;
  }

  (void) add_valid_peer (peer);
  set_peer_flag (peer_ctx, Peers_ONLINE);

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
 * @brief Get the channel of a peer. If not existing, create.
 *
 * @param peer the peer id
 * @return the #GNUNET_CADET_Channel used to send data to @a peer
 */
struct GNUNET_CADET_Channel *
get_channel (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  struct GNUNET_PeerIdentity *ctx_peer;
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


  peer_ctx = get_peer_ctx (peer);
  if (NULL == peer_ctx->send_channel)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to establish channel to peer %s\n",
         GNUNET_i2s (peer));
    ctx_peer = GNUNET_new (struct GNUNET_PeerIdentity);
    *ctx_peer = *peer;
    peer_ctx->send_channel =
      GNUNET_CADET_channel_create (cadet_handle,
                                   (struct GNUNET_PeerIdentity *) ctx_peer, /* context */
                                   peer,
                                   &port,
                                   GNUNET_CADET_OPTION_RELIABLE,
                                   NULL, /* WindowSize handler */
                                   cleanup_destroyed_channel, /* Disconnect handler */
                                   cadet_handlers);
  }
  GNUNET_assert (NULL != peer_ctx->send_channel);
  return peer_ctx->send_channel;
}


/**
 * Get the message queue (#GNUNET_MQ_Handle) of a specific peer.
 *
 * If we already have a message queue open to this client,
 * simply return it, otherways create one.
 *
 * @param peer the peer to get the mq to
 * @return the #GNUNET_MQ_Handle
 */
static struct GNUNET_MQ_Handle *
get_mq (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);

  if (NULL == peer_ctx->mq)
  {
    peer_ctx->mq = GNUNET_CADET_get_mq (get_channel (peer));
  }
  return peer_ctx->mq;
}

/**
 * @brief Add an envelope to a message passed to mq to list of pending messages
 *
 * @param peer peer the message was sent to
 * @param ev envelope to the message
 * @param type type of the message to be sent
 * @return pointer to pending message
 */
static struct PendingMessage *
insert_pending_message (const struct GNUNET_PeerIdentity *peer,
                        struct GNUNET_MQ_Envelope *ev,
                        const char *type)
{
  struct PendingMessage *pending_msg;
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);
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
 * @param cancel cancel the pending message, too
 */
static void
remove_pending_message (struct PendingMessage *pending_msg, int cancel)
{
  struct PeerContext *peer_ctx;

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
 * liveliness check.
 *
 * @param cls #PeerContext of peer with pending liveliness check
 */
static void
mq_liveliness_check_successful (void *cls)
{
  struct PeerContext *peer_ctx = cls;

  if (NULL != peer_ctx->liveliness_check_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Liveliness check for peer %s was successfull\n",
        GNUNET_i2s (&peer_ctx->peer_id));
    //GNUNET_free (peer_ctx->liveliness_check_pending);
    remove_pending_message (peer_ctx->liveliness_check_pending, GNUNET_YES);
    peer_ctx->liveliness_check_pending = NULL;
    set_peer_live (peer_ctx);
  }
}

/**
 * Issue a check whether peer is live
 *
 * @param peer_ctx the context of the peer
 */
static void
check_peer_live (struct PeerContext *peer_ctx)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Get informed about peer %s getting live\n",
       GNUNET_i2s (&peer_ctx->peer_id));

  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE);
  //peer_ctx->liveliness_check_pending = GNUNET_new (struct PendingMessage);
  //peer_ctx->liveliness_check_pending->ev = ev;
  //peer_ctx->liveliness_check_pending->peer_ctx = peer_ctx;
  //peer_ctx->liveliness_check_pending->type = "Check liveliness";
  peer_ctx->liveliness_check_pending =
    insert_pending_message (&peer_ctx->peer_id, ev, "Check liveliness");
  mq = get_mq (&peer_ctx->peer_id);
  GNUNET_MQ_notify_sent (ev,
                         mq_liveliness_check_successful,
                         peer_ctx);
  GNUNET_MQ_send (mq, ev);
}


/**
 * @brief Check whether function of type #PeerOp was already scheduled
 *
 * The array with pending operations will probably never grow really big, so
 * iterating over it should be ok.
 *
 * @param peer the peer to check
 * @param peer_op the operation (#PeerOp) on the peer
 *
 * @return #GNUNET_YES if this operation is scheduled on that peer
 *         #GNUNET_NO  otherwise
 */
static int
check_operation_scheduled (const struct GNUNET_PeerIdentity *peer,
                           const PeerOp peer_op)
{
  const struct PeerContext *peer_ctx;
  unsigned int i;

  peer_ctx = get_peer_ctx (peer);
  for (i = 0; i < peer_ctx->num_pending_ops; i++)
    if (peer_op == peer_ctx->pending_ops[i].op)
      return GNUNET_YES;
  return GNUNET_NO;
}

int
Peers_remove_peer (const struct GNUNET_PeerIdentity *peer);

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
  Peers_remove_peer (key);
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
  if (0 == strncmp ("PULL REPLY", pending_msg->type, 10))
    GNUNET_STATISTICS_update(stats, "# pull replys sent", 1, GNUNET_NO);
  if (0 == strncmp ("PULL REQUEST", pending_msg->type, 12))
    GNUNET_STATISTICS_update(stats, "# pull requests sent", 1, GNUNET_NO);
  if (0 == strncmp ("PUSH", pending_msg->type, 4))
    GNUNET_STATISTICS_update(stats, "# pushes sent", 1, GNUNET_NO);
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
 */
static void
store_valid_peers ()
{
  struct GNUNET_DISK_FileHandle *fh;
  uint32_t number_written_peers;
  int ret;

  if (0 == strncmp ("DISABLE", filename_valid_peers, 7))
  {
    return;
  }

  ret = GNUNET_DISK_directory_create_for_file (filename_valid_peers);
  if (GNUNET_SYSERR == ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to create directory for file `%s'\n",
        filename_valid_peers);
    GNUNET_break (0);
  }
  else if (GNUNET_NO == ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Directory for file `%s' exists but is not writable for us\n",
        filename_valid_peers);
    GNUNET_break (0);
  }
  fh = GNUNET_DISK_file_open (filename_valid_peers,
                              GNUNET_DISK_OPEN_WRITE |
                                  GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_READ |
                                  GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fh)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Not able to write valid peers to file `%s'\n",
        filename_valid_peers);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Writing %u valid peers to disk\n",
      GNUNET_CONTAINER_multipeermap_size (valid_peers));
  number_written_peers =
    GNUNET_CONTAINER_multipeermap_iterate (valid_peers,
                                           store_peer_presistently_iterator,
                                           fh);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  GNUNET_assert (number_written_peers ==
      GNUNET_CONTAINER_multipeermap_size (valid_peers));
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
 */
static void
restore_valid_peers ()
{
  off_t file_size;
  uint32_t num_peers;
  struct GNUNET_DISK_FileHandle *fh;
  char *buf;
  ssize_t size_read;
  char *iter_buf;
  char *str_repr;
  const struct GNUNET_PeerIdentity *peer;

  if (0 == strncmp ("DISABLE", filename_valid_peers, 7))
  {
    return;
  }

  if (GNUNET_OK != GNUNET_DISK_file_test (filename_valid_peers))
  {
    return;
  }
  fh = GNUNET_DISK_file_open (filename_valid_peers,
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
      filename_valid_peers);
  for (iter_buf = buf; iter_buf < buf + file_size - 1; iter_buf += 53)
  {
    str_repr = GNUNET_strndup (iter_buf, 53);
    peer = s2i_full (str_repr);
    GNUNET_free (str_repr);
    add_valid_peer (peer);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Restored valid peer %s from disk\n",
        GNUNET_i2s_full (peer));
  }
  iter_buf = NULL;
  GNUNET_free (buf);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "num_peers: %" PRIu32 ", _size (valid_peers): %u\n",
      num_peers,
      GNUNET_CONTAINER_multipeermap_size (valid_peers));
  if (num_peers != GNUNET_CONTAINER_multipeermap_size (valid_peers))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Number of restored peers does not match file size. Have probably duplicates.\n");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Restored %u valid peers from disk\n",
      GNUNET_CONTAINER_multipeermap_size (valid_peers));
}


/**
 * @brief Initialise storage of peers
 *
 * @param fn_valid_peers filename of the file used to store valid peer ids
 * @param cadet_h cadet handle
 * @param own_id own peer identity
 */
void
Peers_initialise (char* fn_valid_peers,
                  struct GNUNET_CADET_Handle *cadet_h,
                  const struct GNUNET_PeerIdentity *own_id)
{
  filename_valid_peers = GNUNET_strdup (fn_valid_peers);
  cadet_handle = cadet_h;
  own_identity = *own_id;
  peer_map = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);
  valid_peers = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_NO);
  restore_valid_peers ();
}


/**
 * @brief Delete storage of peers that was created with #Peers_initialise ()
 */
void
Peers_terminate ()
{
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multipeermap_iterate (peer_map,
                                             peermap_clear_iterator,
                                             NULL))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Iteration destroying peers was aborted.\n");
  }
  GNUNET_CONTAINER_multipeermap_destroy (peer_map);
  peer_map = NULL;
  store_valid_peers ();
  GNUNET_free (filename_valid_peers);
  GNUNET_CONTAINER_multipeermap_destroy (valid_peers);
}


/**
 * Iterator over #valid_peers hash map entries.
 *
 * @param cls closure - unused
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

  return it_cls->iterator (it_cls->cls,
                           peer);
}


/**
 * @brief Get all currently known, valid peer ids.
 *
 * @param it function to call on each peer id
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
Peers_get_valid_peers (PeersIterator iterator,
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
 * @param peer the new #GNUNET_PeerIdentity
 *
 * @return #GNUNET_YES if peer was inserted
 *         #GNUNET_NO  otherwise (if peer was already known or
 *                     peer was #own_identity)
 */
int
Peers_insert_peer (const struct GNUNET_PeerIdentity *peer)
{
  if ( (GNUNET_YES == Peers_check_peer_known (peer)) ||
       (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, &own_identity)) )
  {
    return GNUNET_NO; /* We already know this peer - nothing to do */
  }
  (void) create_peer_ctx (peer);
  return GNUNET_YES;
}

int
Peers_check_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags);

/**
 * @brief Try connecting to a peer to see whether it is online
 *
 * If not known yet, insert into known peers
 *
 * @param peer the peer whose liveliness is to be checked
 * @return #GNUNET_YES if peer had to be inserted
 *         #GNUNET_NO  otherwise (if peer was already known or
 *                     peer was #own_identity)
 */
int
Peers_issue_peer_liveliness_check (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  int ret;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, &own_identity))
  {
    return GNUNET_NO;
  }
  ret = Peers_insert_peer (peer);
  peer_ctx = get_peer_ctx (peer);
  if (GNUNET_NO == Peers_check_peer_flag (peer, Peers_ONLINE))
  {
    check_peer_live (peer_ctx);
  }
  return ret;
}


/**
 * @brief Check if peer is removable.
 *
 * Check if
 *  - a recv channel exists
 *  - there are pending messages
 *  - there is no pending pull reply
 *
 * @param peer the peer in question
 * @return #GNUNET_YES    if peer is removable
 *         #GNUNET_NO     if peer is NOT removable
 *         #GNUNET_SYSERR if peer is not known
 */
int
Peers_check_removable (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    return GNUNET_SYSERR;
  }

  peer_ctx = get_peer_ctx (peer);
  if ( (NULL != peer_ctx->recv_channel) ||
       (NULL != peer_ctx->pending_messages_head) ||
       (GNUNET_NO == check_peer_flag_set (peer_ctx, Peers_PULL_REPLY_PENDING)) )
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

uint32_t *
Peers_get_channel_flag (const struct GNUNET_PeerIdentity *peer,
                        enum Peers_ChannelRole role);

int
Peers_check_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags);

/**
 * @brief Remove peer
 *
 * @param peer the peer to clean
 * @return #GNUNET_YES if peer was removed
 *         #GNUNET_NO  otherwise
 */
int
Peers_remove_peer (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;
  uint32_t *channel_flag;

  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (peer_map, peer))
  {
    return GNUNET_NO;
  }

  peer_ctx = get_peer_ctx (peer);
  set_peer_flag (peer_ctx, Peers_TO_DESTROY);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to remove peer %s\n",
       GNUNET_i2s (&peer_ctx->peer_id));
  Peers_unset_peer_flag (peer, Peers_ONLINE);

  GNUNET_array_grow (peer_ctx->pending_ops, peer_ctx->num_pending_ops, 0);
  while (NULL != peer_ctx->pending_messages_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Removing unsent %s\n",
        peer_ctx->pending_messages_head->type);
    /* Cancle pending message, too */
    remove_pending_message (peer_ctx->pending_messages_head, GNUNET_YES);
  }
  /* If we are still waiting for notification whether this peer is live
   * cancel the according task */
  if (NULL != peer_ctx->liveliness_check_pending)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
         "Removing pending liveliness check for peer %s\n",
         GNUNET_i2s (&peer_ctx->peer_id));
    // TODO wait until cadet sets mq->cancel_impl
    //GNUNET_MQ_send_cancel (peer_ctx->liveliness_check_pending->ev);
    GNUNET_free (peer_ctx->liveliness_check_pending);
    peer_ctx->liveliness_check_pending = NULL;
  }
  channel_flag = Peers_get_channel_flag (peer, Peers_CHANNEL_ROLE_SENDING);
  if (NULL != peer_ctx->send_channel &&
      GNUNET_YES != Peers_check_channel_flag (channel_flag, Peers_CHANNEL_DESTROING))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Destroying send channel\n");
    GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
    peer_ctx->send_channel = NULL;
    peer_ctx->mq = NULL;
  }
  channel_flag = Peers_get_channel_flag (peer, Peers_CHANNEL_ROLE_RECEIVING);
  if (NULL != peer_ctx->recv_channel &&
      GNUNET_YES != Peers_check_channel_flag (channel_flag, Peers_CHANNEL_DESTROING))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Destroying recv channel\n");
    GNUNET_CADET_channel_destroy (peer_ctx->recv_channel);
    peer_ctx->recv_channel = NULL;
  }

  GNUNET_free (peer_ctx->send_channel_flags);
  GNUNET_free (peer_ctx->recv_channel_flags);

  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_remove_all (peer_map, &peer_ctx->peer_id))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "removing peer from peer_map failed\n");
  }
  GNUNET_free (peer_ctx);
  return GNUNET_YES;
}


/**
 * @brief set flags on a given peer.
 *
 * @param peer the peer to set flags on
 * @param flags the flags
 */
void
Peers_set_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags)
{
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);
  set_peer_flag (peer_ctx, flags);
}


/**
 * @brief unset flags on a given peer.
 *
 * @param peer the peer to unset flags on
 * @param flags the flags
 */
void
Peers_unset_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags)
{
  struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);
  unset_peer_flag (peer_ctx, flags);
}


/**
 * @brief Check whether flags on a peer are set.
 *
 * @param peer the peer to check the flag of
 * @param flags the flags to check
 *
 * @return #GNUNET_SYSERR if peer is not known
 *         #GNUNET_YES    if all given flags are set
 *         #GNUNET_NO     otherwise
 */
int
Peers_check_peer_flag (const struct GNUNET_PeerIdentity *peer, enum Peers_PeerFlags flags)
{
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_SYSERR;
  }
  peer_ctx = get_peer_ctx (peer);
  return check_peer_flag_set (peer_ctx, flags);
}


/**
 * @brief set flags on a given channel.
 *
 * @param channel the channel to set flags on
 * @param flags the flags
 */
void
Peers_set_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags)
{
  set_channel_flag (channel_flags, flags);
}


/**
 * @brief unset flags on a given channel.
 *
 * @param channel the channel to unset flags on
 * @param flags the flags
 */
void
Peers_unset_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags)
{
  unset_channel_flag (channel_flags, flags);
}


/**
 * @brief Check whether flags on a channel are set.
 *
 * @param channel the channel to check the flag of
 * @param flags the flags to check
 *
 * @return #GNUNET_YES if all given flags are set
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_channel_flag (uint32_t *channel_flags, enum Peers_ChannelFlags flags)
{
  return check_channel_flag_set (channel_flags, flags);
}

/**
 * @brief Get the flags for the channel in @a role for @a peer.
 *
 * @param peer Peer to get the channel flags for.
 * @param role Role of channel to get flags for
 *
 * @return The flags.
 */
uint32_t *
Peers_get_channel_flag (const struct GNUNET_PeerIdentity *peer,
                        enum Peers_ChannelRole role)
{
  const struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);
  if (Peers_CHANNEL_ROLE_SENDING == role)
  {
    return peer_ctx->send_channel_flags;
  }
  else if (Peers_CHANNEL_ROLE_RECEIVING == role)
  {
    return peer_ctx->recv_channel_flags;
  }
  else
  {
    GNUNET_assert (0);
  }
}

/**
 * @brief Check whether we have information about the given peer.
 *
 * FIXME probably deprecated. Make this the new _online.
 *
 * @param peer peer in question
 *
 * @return #GNUNET_YES if peer is known
 *         #GNUNET_NO  if peer is not knwon
 */
int
Peers_check_peer_known (const struct GNUNET_PeerIdentity *peer)
{
  if (NULL != peer_map)
  {
    return GNUNET_CONTAINER_multipeermap_contains (peer_map, peer);
  } else
  {
    return GNUNET_NO;
  }
}


/**
 * @brief Check whether @a peer is actually a peer.
 *
 * A valid peer is a peer that we know exists eg. we were connected to once.
 *
 * @param peer peer in question
 *
 * @return #GNUNET_YES if peer is valid
 *         #GNUNET_NO  if peer is not valid
 */
int
Peers_check_peer_valid (const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_contains (valid_peers, peer);
}


/**
 * @brief Indicate that we want to send to the other peer
 *
 * This establishes a sending channel
 *
 * @param peer the peer to establish channel to
 */
void
Peers_indicate_sending_intention (const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (GNUNET_YES == Peers_check_peer_known (peer));
  (void) get_channel (peer);
}


/**
 * @brief Check whether other peer has the intention to send/opened channel
 *        towars us
 *
 * @param peer the peer in question
 *
 * @return #GNUNET_YES if peer has the intention to send
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_peer_send_intention (const struct GNUNET_PeerIdentity *peer)
{
  const struct PeerContext *peer_ctx;

  peer_ctx = get_peer_ctx (peer);
  if (NULL != peer_ctx->recv_channel)
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Handle the channel a peer opens to us.
 *
 * @param cls The closure
 * @param channel The channel the peer wants to establish
 * @param initiator The peer's peer ID
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
void *
Peers_handle_inbound_channel (void *cls,
                              struct GNUNET_CADET_Channel *channel,
                              const struct GNUNET_PeerIdentity *initiator)
{
  struct PeerContext *peer_ctx;
  struct GNUNET_PeerIdentity *ctx_peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "New channel was established to us (Peer %s).\n",
      GNUNET_i2s (initiator));
  GNUNET_assert (NULL != channel); /* according to cadet API */
  /* Make sure we 'know' about this peer */
  peer_ctx = create_or_get_peer_ctx (initiator);
  set_peer_live (peer_ctx);
  ctx_peer = GNUNET_new (struct GNUNET_PeerIdentity);
  *ctx_peer = *initiator;
  /* We only accept one incoming channel per peer */
  if (GNUNET_YES == Peers_check_peer_send_intention (initiator))
  {
    set_channel_flag (peer_ctx->recv_channel_flags,
                      Peers_CHANNEL_ESTABLISHED_TWICE);
    //GNUNET_CADET_channel_destroy (channel);
    GNUNET_CADET_channel_destroy (peer_ctx->recv_channel);
    peer_ctx->recv_channel = channel;
    /* return the channel context */
    return ctx_peer;
  }
  peer_ctx->recv_channel = channel;
  return ctx_peer;
}


/**
 * @brief Check whether a sending channel towards the given peer exists
 *
 * @param peer the peer to check for
 *
 * @return #GNUNET_YES if a sending channel towards that peer exists
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_sending_channel_exists (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == Peers_check_peer_known (peer))
  { /* If no such peer exists, there is no channel */
    return GNUNET_NO;
  }
  peer_ctx = get_peer_ctx (peer);
  if (NULL == peer_ctx->send_channel)
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * @brief check whether the given channel is the sending channel of the given
 *        peer
 *
 * @param peer the peer in question
 * @param channel the channel to check for
 * @param role either #Peers_CHANNEL_ROLE_SENDING, or
 *                    #Peers_CHANNEL_ROLE_RECEIVING
 *
 * @return #GNUNET_YES if the given chennel is the sending channel of the peer
 *         #GNUNET_NO  otherwise
 */
int
Peers_check_channel_role (const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_CADET_Channel *channel,
                          enum Peers_ChannelRole role)
{
  const struct PeerContext *peer_ctx;

  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_NO;
  }
  peer_ctx = get_peer_ctx (peer);
  if ( (Peers_CHANNEL_ROLE_SENDING == role) &&
       (channel == peer_ctx->send_channel) )
  {
    return GNUNET_YES;
  }
  if ( (Peers_CHANNEL_ROLE_RECEIVING == role) &&
       (channel == peer_ctx->recv_channel) )
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * @brief Destroy the send channel of a peer e.g. stop indicating a sending
 *        intention to another peer
 *
 * If there is also no channel to receive messages from that peer, remove it
 * from the peermap.
 * TODO really?
 *
 * @peer the peer identity of the peer whose sending channel to destroy
 * @return #GNUNET_YES if channel was destroyed
 *         #GNUNET_NO  otherwise
 */
int
Peers_destroy_sending_channel (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_NO;
  }
  peer_ctx = get_peer_ctx (peer);
  if (NULL != peer_ctx->send_channel)
  {
    set_channel_flag (peer_ctx->send_channel_flags, Peers_CHANNEL_CLEAN);
    GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
    peer_ctx->send_channel = NULL;
    peer_ctx->mq = NULL;
    (void) Peers_check_connected (peer);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * This is called when a channel is destroyed.
 *
 * @param cls The closure
 * @param channel The channel being closed
 */
void
Peers_cleanup_destroyed_channel (void *cls,
                                 const struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_PeerIdentity *peer = cls;
  struct PeerContext *peer_ctx;

  if (GNUNET_NO == Peers_check_peer_known (peer))
  {/* We don't want to implicitly create a context that we're about to kill */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "channel (%s) without associated context was destroyed\n",
       GNUNET_i2s (peer));
    return;
  }
  peer_ctx = get_peer_ctx (peer);

  /* If our peer issued the destruction of the channel, the #Peers_TO_DESTROY
   * flag will be set. In this case simply make sure that the channels are
   * cleaned. */
  /* FIXME This distinction seems to be redundant */
  if (Peers_check_peer_flag (peer, Peers_TO_DESTROY))
  {/* We initiatad the destruction of this particular peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Peer is in the process of being destroyed\n");
    if (channel == peer_ctx->send_channel)
    {
      peer_ctx->send_channel = NULL;
      peer_ctx->mq = NULL;
    }
    else if (channel == peer_ctx->recv_channel)
    {
      peer_ctx->recv_channel = NULL;
    }

    if (NULL != peer_ctx->send_channel)
    {
      GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
      peer_ctx->send_channel = NULL;
      peer_ctx->mq = NULL;
    }
    if (NULL != peer_ctx->recv_channel)
    {
      GNUNET_CADET_channel_destroy (peer_ctx->recv_channel);
      peer_ctx->recv_channel = NULL;
    }
    /* Set the #Peers_ONLINE flag accordingly */
    (void) Peers_check_connected (peer);
    return;
  }

  else
  { /* We did not initiate the destruction of this peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Peer is NOT in the process of being destroyed\n");
    if (channel == peer_ctx->send_channel)
    { /* Something (but us) killd the channel - clean up peer */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "send channel (%s) was destroyed - cleaning up\n",
          GNUNET_i2s (peer));
      peer_ctx->send_channel = NULL;
      peer_ctx->mq = NULL;
    }
    else if (channel == peer_ctx->recv_channel)
    { /* Other peer doesn't want to send us messages anymore */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Peer %s destroyed recv channel - cleaning up channel\n",
           GNUNET_i2s (peer));
      peer_ctx->recv_channel = NULL;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "unknown channel (%s) was destroyed\n",
           GNUNET_i2s (peer));
    }
  }
  (void) Peers_check_connected (peer);
}

/**
 * @brief Send a message to another peer.
 *
 * Keeps track about pending messages so they can be properly removed when the
 * peer is destroyed.
 *
 * @param peer receeiver of the message
 * @param ev envelope of the message
 * @param type type of the message
 */
void
Peers_send_message (const struct GNUNET_PeerIdentity *peer,
                    struct GNUNET_MQ_Envelope *ev,
                    const char *type)
{
  struct PendingMessage *pending_msg;
  struct GNUNET_MQ_Handle *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending message to %s of type %s\n",
	      GNUNET_i2s (peer),
	      type);
  pending_msg = insert_pending_message (peer, ev, type);
  mq = get_mq (peer);
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
 * @param peer the peer we want to schedule the operation for once it gets live
 *
 * @return #GNUNET_YES if the operation was scheduled
 *         #GNUNET_NO  otherwise
 */
int
Peers_schedule_operation (const struct GNUNET_PeerIdentity *peer,
                          const PeerOp peer_op)
{
  struct PeerPendingOp pending_op;
  struct PeerContext *peer_ctx;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, &own_identity))
  {
    return GNUNET_NO;
  }
  GNUNET_assert (GNUNET_YES == Peers_check_peer_known (peer));

  //TODO if LIVE/ONLINE execute immediately

  if (GNUNET_NO == check_operation_scheduled (peer, peer_op))
  {
    peer_ctx = get_peer_ctx (peer);
    pending_op.op = peer_op;
    pending_op.op_cls = NULL;
    GNUNET_array_append (peer_ctx->pending_ops,
                         peer_ctx->num_pending_ops,
                         pending_op);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * @brief Get the recv_channel of @a peer.
 * Needed to correctly handle (call #GNUNET_CADET_receive_done()) incoming
 * messages.
 *
 * @param peer The peer to get the recv_channel from.
 *
 * @return The recv_channel.
 */
struct GNUNET_CADET_Channel *
Peers_get_recv_channel (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *peer_ctx;

  GNUNET_assert (GNUNET_YES == Peers_check_peer_known (peer));
  peer_ctx = get_peer_ctx (peer);
  return peer_ctx->recv_channel;
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
   * DLL with handles to single requests from the client
   */
  struct ReplyCls *rep_cls_head;
  struct ReplyCls *rep_cls_tail;

  /**
   * @brief How many updates this client expects to receive.
   */
  int64_t view_updates_left;

  /**
   * The client handle to send the reply to
   */
  struct GNUNET_SERVICE_Client *client;
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
 * Globals
***********************************************************************/

/**
 * Sampler used for the Brahms protocol itself.
 */
static struct RPS_Sampler *prot_sampler;

/**
 * Sampler used for the clients.
 */
static struct RPS_Sampler *client_sampler;

/**
 * Name to log view to
 */
static const char *file_name_view_log;

#ifdef TO_FILE
/**
 * Name to log number of observed peers to
 */
static const char *file_name_observed_log;

/**
 * @brief Count the observed peers
 */
static uint32_t num_observed_peers;

/**
 * @brief Multipeermap (ab-) used to count unique peer_ids
 */
static struct GNUNET_CONTAINER_MultiPeerMap *observed_unique_peers;
#endif /* TO_FILE */

/**
 * The size of sampler we need to be able to satisfy the client's need
 * of random peers.
 */
static unsigned int sampler_size_client_need;

/**
 * The size of sampler we need to be able to satisfy the Brahms protocol's
 * need of random peers.
 *
 * This is one minimum size the sampler grows to.
 */
static unsigned int sampler_size_est_need;

/**
 * @brief This is the minimum estimate used as sampler size.
 *
 * It is configured by the user.
 */
static unsigned int sampler_size_est_min;

/**
 * @brief This is the estimate used as view size.
 *
 * It is initialised with the minimum
 */
static unsigned int view_size_est_need;

/**
 * @brief This is the minimum estimate used as view size.
 *
 * It is configured by the user.
 */
static unsigned int view_size_est_min;

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
 * Identifier for the main task that runs periodically.
 */
static struct GNUNET_SCHEDULER_Task *do_round_task;

/**
 * Time inverval the do_round task runs in.
 */
static struct GNUNET_TIME_Relative round_interval;

/**
 * List to store peers received through pushes temporary.
 */
static struct CustomPeerMap *push_map;

/**
 * List to store peers received through pulls temporary.
 */
static struct CustomPeerMap *pull_map;

/**
 * Handler to NSE.
 */
static struct GNUNET_NSE_Handle *nse;

/**
 * Handler to CADET.
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * @brief Port to communicate to other peers.
 */
static struct GNUNET_CADET_Port *cadet_port;

/**
 * Handler to PEERINFO.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo_handle;

/**
 * Handle for cancellation of iteration over peers.
 */
static struct GNUNET_PEERINFO_NotifyContext *peerinfo_notify_handle;

/**
 * Request counter.
 *
 * Counts how many requets clients already issued.
 * Only needed in the beginning to check how many of the 64 deltas
 * we already have
 */
static unsigned int req_counter;

/**
 * Time of the last request we received.
 *
 * Used to compute the expected request rate.
 */
static struct GNUNET_TIME_Absolute last_request;

/**
 * Size of #request_deltas.
 */
#define REQUEST_DELTAS_SIZE 64
static unsigned int request_deltas_size = REQUEST_DELTAS_SIZE;

/**
 * Last 64 deltas between requests
 */
static struct GNUNET_TIME_Relative request_deltas[REQUEST_DELTAS_SIZE];

/**
 * The prediction of the rate of requests
 */
static struct GNUNET_TIME_Relative request_rate;


#ifdef ENABLE_MALICIOUS
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


/***********************************************************************
 * /Globals
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
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&tmp[i], peer))
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
 * Sum all time relatives of an array.
 */
static struct GNUNET_TIME_Relative
T_relative_sum (const struct GNUNET_TIME_Relative *rel_array,
		uint32_t arr_size)
{
  struct GNUNET_TIME_Relative sum;
  uint32_t i;

  sum = GNUNET_TIME_UNIT_ZERO;
  for ( i = 0 ; i < arr_size ; i++ )
  {
    sum = GNUNET_TIME_relative_add (sum, rel_array[i]);
  }
  return sum;
}


/**
 * Compute the average of given time relatives.
 */
static struct GNUNET_TIME_Relative
T_relative_avg (const struct GNUNET_TIME_Relative *rel_array,
		uint32_t arr_size)
{
  return GNUNET_TIME_relative_divide (T_relative_sum (rel_array,
						      arr_size),
				      arr_size);
}


/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is live.
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
 * Called once we know a peer is live.
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
static int
insert_in_view (const struct GNUNET_PeerIdentity *peer)
{
  int online;

  online = Peers_check_peer_flag (peer, Peers_ONLINE);
  if ( (GNUNET_NO == online) ||
       (GNUNET_SYSERR == online) ) /* peer is not even known */
  {
    (void) Peers_issue_peer_liveliness_check (peer);
    (void) Peers_schedule_operation (peer, insert_in_view_op);
    return GNUNET_NO;
  }
  /* Open channel towards peer to keep connection open */
  Peers_indicate_sending_intention (peer);
  return View_put (peer);
}

/**
 * @brief sends updates to clients that are interested
 */
static void
clients_notify_view_update (void);

/**
 * Put random peer from sampler into the view as history update.
 */
static void
hist_update (void *cls,
	     struct GNUNET_PeerIdentity *ids,
	     uint32_t num_peers)
{
  unsigned int i;

  for (i = 0; i < num_peers; i++)
  {
    (void) insert_in_view (&ids[i]);
    to_file (file_name_view_log,
             "+%s\t(hist)",
             GNUNET_i2s_full (ids));
  }
  clients_notify_view_update();
}


/**
 * Wrapper around #RPS_sampler_resize()
 *
 * If we do not have enough sampler elements, double current sampler size
 * If we have more than enough sampler elements, halv current sampler size
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
 * Wrapper around #RPS_sampler_resize() resizing the client sampler
 */
static void
client_resize_wrapper ()
{
  uint32_t bigger_size;

  // TODO statistics

  bigger_size = GNUNET_MAX (sampler_size_est_need, sampler_size_client_need);

  // TODO respect the min, max
  resize_wrapper (client_sampler, bigger_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sampler_size_client is now %" PRIu32 "\n",
      bigger_size);
}


/**
 * Estimate request rate
 *
 * Called every time we receive a request from the client.
 */
static void
est_request_rate()
{
  struct GNUNET_TIME_Relative max_round_duration;

  if (request_deltas_size > req_counter)
    req_counter++;
  if ( 1 < req_counter)
  {
    /* Shift last request deltas to the right */
    memmove (&request_deltas[1],
        request_deltas,
        (req_counter - 1) * sizeof (struct GNUNET_TIME_Relative));

    /* Add current delta to beginning */
    request_deltas[0] =
        GNUNET_TIME_absolute_get_difference (last_request,
                                             GNUNET_TIME_absolute_get ());
    request_rate = T_relative_avg (request_deltas, req_counter);
    request_rate = (request_rate.rel_value_us < 1) ?
      GNUNET_TIME_relative_get_unit_ () : request_rate;

    /* Compute the duration a round will maximally take */
    max_round_duration =
        GNUNET_TIME_relative_add (round_interval,
                                  GNUNET_TIME_relative_divide (round_interval, 2));

    /* Set the estimated size the sampler has to have to
     * satisfy the current client request rate */
    sampler_size_client_need =
        max_round_duration.rel_value_us / request_rate.rel_value_us;

    /* Resize the sampler */
    client_resize_wrapper ();
  }
  last_request = GNUNET_TIME_absolute_get ();
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
  }
}


/**
 * Send a PULL REPLY to @a peer_id
 *
 * @param peer_id the peer to send the reply to.
 * @param peer_ids the peers to send to @a peer_id
 * @param num_peer_ids the number of peers to send to @a peer_id
 */
static void
send_pull_reply (const struct GNUNET_PeerIdentity *peer_id,
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
      send_size, GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_extra (out_msg,
                            send_size * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY);
  out_msg->num_peers = htonl (send_size);
  GNUNET_memcpy (&out_msg[1], peer_ids,
         send_size * sizeof (struct GNUNET_PeerIdentity));

  Peers_send_message (peer_id, ev, "PULL REPLY");
  GNUNET_STATISTICS_update(stats, "# pull reply send issued", 1, GNUNET_NO);
}


/**
 * Insert PeerID in #pull_map
 *
 * Called once we know a peer is live.
 */
static void
insert_in_pull_map (void *cls,
		    const struct GNUNET_PeerIdentity *peer)
{
  CustomPeerMap_put (pull_map, peer);
}


/**
 * Insert PeerID in #view
 *
 * Called once we know a peer is live.
 * Implements #PeerOp
 */
static void
insert_in_view_op (void *cls,
		const struct GNUNET_PeerIdentity *peer)
{
  (void) insert_in_view (peer);
}


/**
 * Update sampler with given PeerID.
 * Implements #PeerOp
 */
static void
insert_in_sampler (void *cls,
		   const struct GNUNET_PeerIdentity *peer)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating samplers with peer %s from insert_in_sampler()\n",
       GNUNET_i2s (peer));
  RPS_sampler_update (prot_sampler,   peer);
  RPS_sampler_update (client_sampler, peer);
  if (0 < RPS_sampler_count_id (prot_sampler, peer))
  {
    /* Make sure we 'know' about this peer */
    (void) Peers_issue_peer_liveliness_check (peer);
    /* Establish a channel towards that peer to indicate we are going to send
     * messages to it */
    //Peers_indicate_sending_intention (peer);
  }
  #ifdef TO_FILE
  num_observed_peers++;
  GNUNET_CONTAINER_multipeermap_put
    (observed_unique_peers,
     peer,
     NULL,
     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  uint32_t num_observed_unique_peers = GNUNET_CONTAINER_multipeermap_size (
      observed_unique_peers);
  to_file (file_name_observed_log,
          "%" PRIu32 " %" PRIu32 " %f\n",
          num_observed_peers,
          num_observed_unique_peers,
          1.0*num_observed_unique_peers/num_observed_peers)
  #endif /* TO_FILE */
}

/**
 * @brief This is called on peers from external sources (cadet, peerinfo, ...)
 *        If the peer is not known, liveliness check is issued and it is
 *        scheduled to be inserted in sampler and view.
 *
 * "External sources" refer to every source except the gossip.
 *
 * @param peer peer to insert
 */
static void
got_peer (const struct GNUNET_PeerIdentity *peer)
{
  /* If we did not know this peer already, insert it into sampler and view */
  if (GNUNET_YES == Peers_issue_peer_liveliness_check (peer))
  {
    Peers_schedule_operation (peer, insert_in_sampler);
    Peers_schedule_operation (peer, insert_in_view_op);
  }
}

/**
 * @brief Checks if there is a sending channel and if it is needed
 *
 * @param peer the peer whose sending channel is checked
 * @return GNUNET_YES if sending channel exists and is still needed
 *         GNUNET_NO  otherwise
 */
static int
check_sending_channel_needed (const struct GNUNET_PeerIdentity *peer)
{
  /* struct GNUNET_CADET_Channel *channel; */
  if (GNUNET_NO == Peers_check_peer_known (peer))
  {
    return GNUNET_NO;
  }
  if (GNUNET_YES == Peers_check_sending_channel_exists (peer))
  {
    if ( (0 < RPS_sampler_count_id (prot_sampler, peer)) ||
         (GNUNET_YES == View_contains_peer (peer)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (push_map, peer)) ||
         (GNUNET_YES == CustomPeerMap_contains_peer (pull_map, peer)) ||
         (GNUNET_YES == Peers_check_peer_flag (peer, Peers_PULL_REPLY_PENDING)))
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
 * @param peer the peer to remove
 */
static void
remove_peer (const struct GNUNET_PeerIdentity *peer)
{
  (void) View_remove_peer (peer);
  CustomPeerMap_remove_peer (pull_map, peer);
  CustomPeerMap_remove_peer (push_map, peer);
  RPS_sampler_reinitialise_by_value (prot_sampler, peer);
  RPS_sampler_reinitialise_by_value (client_sampler, peer);
  Peers_remove_peer (peer);
}


/**
 * @brief Remove data that is not needed anymore.
 *
 * If the sending channel is no longer needed it is destroyed.
 *
 * @param peer the peer whose data is about to be cleaned
 */
static void
clean_peer (const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_NO == check_sending_channel_needed (peer))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to remove send channel to peer %s\n",
        GNUNET_i2s (peer));
    #ifdef ENABLE_MALICIOUS
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&attacked_peer, peer))
      (void) Peers_destroy_sending_channel (peer);
    #else /* ENABLE_MALICIOUS */
    (void) Peers_destroy_sending_channel (peer);
    #endif /* ENABLE_MALICIOUS */
  }

  if ( (GNUNET_NO == Peers_check_peer_send_intention (peer)) &&
       (GNUNET_NO == View_contains_peer (peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (push_map, peer)) &&
       (GNUNET_NO == CustomPeerMap_contains_peer (push_map, peer)) &&
       (0 == RPS_sampler_count_id (prot_sampler,   peer)) &&
       (0 == RPS_sampler_count_id (client_sampler, peer)) &&
       (GNUNET_NO != Peers_check_removable (peer)) )
  { /* We can safely remove this peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to remove peer %s\n",
        GNUNET_i2s (peer));
    remove_peer (peer);
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
 * @param cls The closure
 * @param channel The channel being closed
 * @param channel_ctx The context associated with this channel
 */
static void
cleanup_destroyed_channel (void *cls,
                           const struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_PeerIdentity *peer = cls;
  uint32_t *channel_flag;
  struct PeerContext *peer_ctx;

  GNUNET_assert (NULL != peer);

  if (GNUNET_NO == Peers_check_peer_known (peer))
  { /* We don't know a context to that peer */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "channel (%s) without associated context was destroyed\n",
         GNUNET_i2s (peer));
    GNUNET_free (peer);
    return;
  }

  peer_ctx = get_peer_ctx (peer);
  if (GNUNET_YES == Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_RECEIVING))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Callback on destruction of recv-channel was called (%s)\n",
        GNUNET_i2s (peer));
    set_channel_flag (peer_ctx->recv_channel_flags, Peers_CHANNEL_DESTROING);
  } else if (GNUNET_YES == Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_SENDING))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Callback on destruction of send-channel was called (%s)\n",
        GNUNET_i2s (peer));
    set_channel_flag (peer_ctx->send_channel_flags, Peers_CHANNEL_DESTROING);
  } else {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "Channel to be destroyed has is neither sending nor receiving role\n");
  }

  if (GNUNET_YES == Peers_check_peer_flag (peer, Peers_TO_DESTROY))
  { /* We are in the middle of removing that peer from our knowledge. In this
       case simply make sure that the channels are cleaned. */
    Peers_cleanup_destroyed_channel (cls, channel);
    to_file (file_name_view_log,
             "-%s\t(cleanup channel, ourself)",
             GNUNET_i2s_full (peer));
    GNUNET_free (peer);
    return;
  }

  if (GNUNET_YES ==
      Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_SENDING))
  { /* Channel used for sending was destroyed */
    /* Possible causes of channel destruction:
     *  - ourselves  -> cleaning send channel -> clean context
     *  - other peer -> peer probably went down -> remove
     */
    channel_flag = Peers_get_channel_flag (peer, Peers_CHANNEL_ROLE_SENDING);
    if (GNUNET_YES == Peers_check_channel_flag (channel_flag, Peers_CHANNEL_CLEAN))
    { /* We are about to clean the sending channel. Clean the respective
       * context */
      Peers_cleanup_destroyed_channel (cls, channel);
      GNUNET_free (peer);
      return;
    }
    else
    { /* Other peer destroyed our sending channel that he is supposed to keep
       * open. It probably went down. Remove it from our knowledge. */
      Peers_cleanup_destroyed_channel (cls, channel);
      remove_peer (peer);
      GNUNET_free (peer);
      return;
    }
  }
  else if (GNUNET_YES ==
      Peers_check_channel_role (peer, channel, Peers_CHANNEL_ROLE_RECEIVING))
  { /* Channel used for receiving was destroyed */
    /* Possible causes of channel destruction:
     *  - ourselves  -> peer tried to establish channel twice -> clean context
     *  - other peer -> peer doesn't want to send us data -> clean
     */
    channel_flag = Peers_get_channel_flag (peer, Peers_CHANNEL_ROLE_RECEIVING);
    if (GNUNET_YES ==
        Peers_check_channel_flag (channel_flag, Peers_CHANNEL_ESTABLISHED_TWICE))
    { /* Other peer tried to establish a channel to us twice. We do not accept
       * that. Clean the context. */
      Peers_cleanup_destroyed_channel (cls, channel);
      GNUNET_free (peer);
      return;
    }
    else
    { /* Other peer doesn't want to send us data anymore. We are free to clean
       * it. */
      Peers_cleanup_destroyed_channel (cls, channel);
      clean_peer (peer);
      GNUNET_free (peer);
      return;
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Destroyed channel is neither sending nor receiving channel\n");
  }
  GNUNET_free (peer);
}

/***********************************************************************
 * /Util functions
***********************************************************************/

static void
destroy_reply_cls (struct ReplyCls *rep_cls)
{
  struct ClientContext *cli_ctx;

  cli_ctx = rep_cls->cli_ctx;
  GNUNET_assert (NULL != cli_ctx);
  if (NULL != rep_cls->req_handle)
  {
    RPS_sampler_request_cancel (rep_cls->req_handle);
  }
  GNUNET_CONTAINER_DLL_remove (cli_ctx->rep_cls_head,
                               cli_ctx->rep_cls_tail,
                               rep_cls);
  GNUNET_free (rep_cls);
}


static void
destroy_cli_ctx (struct ClientContext *cli_ctx)
{
  GNUNET_assert (NULL != cli_ctx);
  if (NULL != cli_ctx->rep_cls_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to destroy the context of a client that still has pending requests. Going to clean those\n");
    while (NULL != cli_ctx->rep_cls_head)
      destroy_reply_cls (cli_ctx->rep_cls_head);
  }
  GNUNET_CONTAINER_DLL_remove (cli_ctx_head,
                               cli_ctx_tail,
                               cli_ctx);
  GNUNET_free (cli_ctx);
}


/**
 * Function called by NSE.
 *
 * Updates sizes of sampler list and view and adapt those lists
 * accordingly.
 */
static void
nse_callback (void *cls,
	      struct GNUNET_TIME_Absolute timestamp,
              double logestimate, double std_dev)
{
  double estimate;
  //double scale; // TODO this might go gloabal/config

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a ns estimate - logest: %f, std_dev: %f (old_size: %u)\n",
       logestimate, std_dev, RPS_sampler_get_size (prot_sampler));
  //scale = .01;
  estimate = GNUNET_NSE_log_estimate_to_n (logestimate);
  // GNUNET_NSE_log_estimate_to_n (logestimate);
  estimate = pow (estimate, 1.0 / 3);
  // TODO add if std_dev is a number
  // estimate += (std_dev * scale);
  if (view_size_est_min < ceil (estimate))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing estimate to %f\n", estimate);
    sampler_size_est_need = estimate;
    view_size_est_need = estimate;
  } else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not using estimate %f\n", estimate);
    //sampler_size_est_need = view_size_est_min;
    view_size_est_need = view_size_est_min;
  }

  /* If the NSE has changed adapt the lists accordingly */
  resize_wrapper (prot_sampler, sampler_size_est_need);
  client_resize_wrapper ();
}


/**
 * Callback called once the requested PeerIDs are ready.
 *
 * Sends those to the requesting client.
 */
static void
client_respond (void *cls,
                struct GNUNET_PeerIdentity *peer_ids,
                uint32_t num_peers)
{
  struct ReplyCls *reply_cls = cls;
  uint32_t i;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ReplyMessage *out_msg;
  uint32_t size_needed;
  struct ClientContext *cli_ctx;

  GNUNET_assert (NULL != reply_cls);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sampler returned %" PRIu32 " peers:\n",
       num_peers);
  for (i = 0; i < num_peers; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  %" PRIu32 ": %s\n",
         i,
         GNUNET_i2s (&peer_ids[i]));
  }

  size_needed = sizeof (struct GNUNET_RPS_CS_ReplyMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  GNUNET_assert (GNUNET_MAX_MESSAGE_SIZE >= size_needed);

  ev = GNUNET_MQ_msg_extra (out_msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_REPLY);
  out_msg->num_peers = htonl (num_peers);
  out_msg->id = htonl (reply_cls->id);

  GNUNET_memcpy (&out_msg[1],
          peer_ids,
          num_peers * sizeof (struct GNUNET_PeerIdentity));

  cli_ctx = reply_cls->cli_ctx;
  GNUNET_assert (NULL != cli_ctx);
  reply_cls->req_handle = NULL;
  destroy_reply_cls (reply_cls);
  GNUNET_MQ_send (cli_ctx->mq, ev);
}


/**
 * Handle RPS request from the client.
 *
 * @param cls closure
 * @param message the actual message
 */
static void
handle_client_request (void *cls,
                       const struct GNUNET_RPS_CS_RequestMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  uint32_t num_peers;
  uint32_t size_needed;
  struct ReplyCls *reply_cls;
  uint32_t i;

  num_peers = ntohl (msg->num_peers);
  size_needed = sizeof (struct GNUNET_RPS_CS_RequestMessage) +
                num_peers * sizeof (struct GNUNET_PeerIdentity);

  if (GNUNET_MAX_MESSAGE_SIZE < size_needed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message received from client has size larger than expected\n");
    GNUNET_SERVICE_client_drop (cli_ctx->client);
    return;
  }

  for (i = 0 ; i < num_peers ; i++)
    est_request_rate();

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client requested %" PRIu32 " random peer(s).\n",
       num_peers);

  reply_cls = GNUNET_new (struct ReplyCls);
  reply_cls->id = ntohl (msg->id);
  reply_cls->cli_ctx = cli_ctx;
  reply_cls->req_handle = RPS_sampler_get_n_rand_peers (client_sampler,
                                                        client_respond,
                                                        reply_cls,
                                                        num_peers);

  GNUNET_assert (NULL != cli_ctx);
  GNUNET_CONTAINER_DLL_insert (cli_ctx->rep_cls_head,
                               cli_ctx->rep_cls_tail,
                               reply_cls);
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief Handle a message that requests the cancellation of a request
 *
 * @param cls unused
 * @param message the message containing the id of the request
 */
static void
handle_client_request_cancel (void *cls,
                              const struct GNUNET_RPS_CS_RequestCancelMessage *msg)
{
  struct ClientContext *cli_ctx = cls;
  struct ReplyCls *rep_cls;

  GNUNET_assert (NULL != cli_ctx);
  GNUNET_assert (NULL != cli_ctx->rep_cls_head);
  rep_cls = cli_ctx->rep_cls_head;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Client cancels request with id %" PRIu32 "\n",
      ntohl (msg->id));
  while ( (NULL != rep_cls->next) &&
          (rep_cls->id != ntohl (msg->id)) )
    rep_cls = rep_cls->next;
  GNUNET_assert (rep_cls->id == ntohl (msg->id));
  destroy_reply_cls (rep_cls);
  GNUNET_SERVICE_client_continue (cli_ctx->client);
}


/**
 * @brief This function is called, when the client seeds peers.
 * It verifies that @a msg is well-formed.
 *
 * @param cls the closure (#ClientContext)
 * @param msg the message
 * @return #GNUNET_OK if @a msg is well-formed
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
  //peers = GNUNET_new_array (num_peers, struct GNUNET_PeerIdentity);
  //GNUNET_memcpy (peers, &msg[1], num_peers * sizeof (struct GNUNET_PeerIdentity));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client seeded peers:\n");
  print_peer_list (peers, num_peers);

  for (i = 0; i < num_peers; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating samplers with seed %" PRIu32 ": %s\n",
         i,
         GNUNET_i2s (&peers[i]));

    got_peer (&peers[i]);
  }

  ////GNUNET_free (peers);

  GNUNET_SERVICE_client_continue (cli_ctx->client);
}

/**
 * @brief Send view to client
 *
 * @param cli_ctx the context of the client
 * @param view_array the peerids of the view as array (can be empty)
 * @param view_size the size of the view array (can be 0)
 */
void
send_view (const struct ClientContext *cli_ctx,
           const struct GNUNET_PeerIdentity *view_array,
           uint64_t view_size)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_DEBUG_ViewReply *out_msg;

  if (NULL == view_array)
  {
    view_size = View_size ();
    view_array = View_get_as_array();
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
 * @brief sends updates to clients that are interested
 */
static void
clients_notify_view_update (void)
{
  struct ClientContext *cli_ctx_iter;
  uint64_t num_peers;
  const struct GNUNET_PeerIdentity *view_array;

  num_peers = View_size ();
  view_array = View_get_as_array();
  /* check size of view is small enough */
  if (GNUNET_MAX_MESSAGE_SIZE < num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "View is too big to send\n");
    return;
  }

  for (cli_ctx_iter = cli_ctx_head;
       NULL != cli_ctx_iter;
       cli_ctx_iter = cli_ctx_head->next)
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
 * Handle RPS request from the client.
 *
 * @param cls closure
 * @param message the actual message
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
 * Handle a CHECK_LIVE message from another peer.
 *
 * This does nothing. But without calling #GNUNET_CADET_receive_done()
 * the channel is blocked for all other communication.
 *
 * @param cls Closure
 * @param msg The message header
 */
static void
handle_peer_check (void *cls,
                   const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PeerIdentity *peer = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received CHECK_LIVE (%s)\n", GNUNET_i2s (peer));

  GNUNET_CADET_receive_done (Peers_get_recv_channel (peer));
}

/**
 * Handle a PUSH message from another peer.
 *
 * Check the proof of work and store the PeerID
 * in the temporary list for pushed PeerIDs.
 *
 * @param cls Closure
 * @param msg The message header
 */
static void
handle_peer_push (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PeerIdentity *peer = cls;

  // (check the proof of work (?))

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received PUSH (%s)\n",
       GNUNET_i2s (peer));
  GNUNET_STATISTICS_update(stats, "# push message received", 1, GNUNET_NO);

  #ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;

  if ( (1 == mal_type) ||
       (3 == mal_type) )
  { /* Try to maximise representation */
    tmp_att_peer = GNUNET_new (struct AttackedPeer);
    tmp_att_peer->peer_id = *peer;
    if (NULL == att_peer_set)
      att_peer_set = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
    if (GNUNET_NO ==
	GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
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
  CustomPeerMap_put (push_map, peer);

  GNUNET_break_op (Peers_check_peer_known (peer));
  GNUNET_CADET_receive_done (Peers_get_recv_channel (peer));
}


/**
 * Handle PULL REQUEST request message from another peer.
 *
 * Reply with the view of PeerIDs.
 *
 * @param cls Closure
 * @param msg The message header
 */
static void
handle_peer_pull_request (void *cls,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PeerIdentity *peer = cls;
  const struct GNUNET_PeerIdentity *view_array;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REQUEST (%s)\n", GNUNET_i2s (peer));
  GNUNET_STATISTICS_update(stats, "# pull request message received", 1, GNUNET_NO);

  #ifdef ENABLE_MALICIOUS
  if (1 == mal_type
      || 3 == mal_type)
  { /* Try to maximise representation */
    send_pull_reply (peer, mal_peers, num_mal_peers);
  }

  else if (2 == mal_type)
  { /* Try to partition network */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&attacked_peer, peer))
    {
      send_pull_reply (peer, mal_peers, num_mal_peers);
    }
  }
  #endif /* ENABLE_MALICIOUS */

  GNUNET_break_op (Peers_check_peer_known (peer));
  GNUNET_CADET_receive_done (Peers_get_recv_channel (peer));
  view_array = View_get_as_array ();
  send_pull_reply (peer, view_array, View_size ());
}


/**
 * Check whether we sent a corresponding request and
 * whether this reply is the first one.
 *
 * @param cls Closure
 * @param msg The message header
 */
static int
check_peer_pull_reply (void *cls,
                       const struct GNUNET_RPS_P2P_PullReplyMessage *msg)
{
  struct GNUNET_PeerIdentity *sender = cls;

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

  if (GNUNET_YES != Peers_check_peer_flag (sender, Peers_PULL_REPLY_PENDING))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Received a pull reply from a peer we didn't request one from!\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
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
  const struct GNUNET_PeerIdentity *peers;
  struct GNUNET_PeerIdentity *sender = cls;
  uint32_t i;
#ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
#endif /* ENABLE_MALICIOUS */

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PULL REPLY (%s)\n", GNUNET_i2s (sender));
  GNUNET_STATISTICS_update(stats, "# pull reply messages received", 1, GNUNET_NO);

  #ifdef ENABLE_MALICIOUS
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

    #ifdef ENABLE_MALICIOUS
    if ((NULL != att_peer_set) &&
        (1 == mal_type || 3 == mal_type))
    { /* Add attacked peer to local list */
      // TODO check if we sent a request and this was the first reply
      if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (att_peer_set,
                                                               &peers[i])
          && GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (mal_peer_set,
                                                                  &peers[i])
          && 0 != GNUNET_CRYPTO_cmp_peer_identity (&peers[i],
                                                   &own_identity))
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
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity,
                                              &peers[i]))
    {
      /* Make sure we 'know' about this peer */
      (void) Peers_insert_peer (&peers[i]);

      if (GNUNET_YES == Peers_check_peer_valid (&peers[i]))
      {
        CustomPeerMap_put (pull_map, &peers[i]);
      }
      else
      {
        Peers_schedule_operation (&peers[i], insert_in_pull_map);
        (void) Peers_issue_peer_liveliness_check (&peers[i]);
      }
    }
  }

  Peers_unset_peer_flag (sender, Peers_PULL_REPLY_PENDING);
  clean_peer (sender);

  GNUNET_break_op (Peers_check_peer_known (sender));
  GNUNET_CADET_receive_done (Peers_get_recv_channel (sender));
}


/**
 * Compute a random delay.
 * A uniformly distributed value between mean + spread and mean - spread.
 *
 * For example for mean 4 min and spread 2 the minimum is (4 min - (1/2 * 4 min))
 * It would return a random value between 2 and 6 min.
 *
 * @param mean the mean
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
 * @param peer_id the peer to send the pull request to.
 */
static void
send_pull_request (const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (GNUNET_NO == Peers_check_peer_flag (peer,
                                                     Peers_PULL_REPLY_PENDING));
  Peers_set_peer_flag (peer, Peers_PULL_REPLY_PENDING);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PULL REQUEST to peer %s.\n",
       GNUNET_i2s (peer));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST);
  Peers_send_message (peer, ev, "PULL REQUEST");
  GNUNET_STATISTICS_update(stats, "# pull request send issued", 1, GNUNET_NO);
}


/**
 * Send single push
 *
 * @param peer_id the peer to send the push to.
 */
static void
send_push (const struct GNUNET_PeerIdentity *peer_id)
{
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to send PUSH to peer %s.\n",
       GNUNET_i2s (peer_id));

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_RPS_PP_PUSH);
  Peers_send_message (peer_id, ev, "PUSH");
  GNUNET_STATISTICS_update(stats, "# push send issued", 1, GNUNET_NO);
}


static void
do_round (void *cls);

static void
do_mal_round (void *cls);

#ifdef ENABLE_MALICIOUS


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
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }

  else if ( (2 == mal_type) ||
            (3 == mal_type) )
  { /* Try to partition the network */
    /* Add other malicious peers to those we already know */

    num_mal_peers_sent = ntohl (msg->num_peers) - 1;
    num_mal_peers_old = num_mal_peers;
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
    if (GNUNET_NO == Peers_check_peer_known (&attacked_peer))
    {
      (void) Peers_issue_peer_liveliness_check (&attacked_peer);
    }

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Attacked peer is %s\n",
         GNUNET_i2s (&attacked_peer));

    /* Substitute do_round () with do_mal_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_mal_round, NULL);
  }
  else if (0 == mal_type)
  { /* Stop acting malicious */
    GNUNET_array_grow (mal_peers, num_mal_peers, 0);

    /* Substitute do_mal_round () with do_round () */
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
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
 */
static void
do_mal_round (void *cls)
{
  uint32_t num_pushes;
  uint32_t i;
  struct GNUNET_TIME_Relative time_next_round;
  struct AttackedPeer *tmp_att_peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to execute next round maliciously type %" PRIu32 ".\n",
      mal_type);
  do_round_task = NULL;
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

      send_push (&att_peer_index->peer_id);
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0 ; i < num_pushes * alpha ; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (&tmp_att_peer->peer_id);
    }
  }


  else if (2 == mal_type)
  { /**
     * Try to partition the network
     * Send as many pushes to the attacked peer as possible
     * That is one push per round as it will ignore more.
     */
    (void) Peers_issue_peer_liveliness_check (&attacked_peer);
    if (GNUNET_YES == Peers_check_peer_flag (&attacked_peer, Peers_ONLINE))
      send_push (&attacked_peer);
  }


  if (3 == mal_type)
  { /* Combined attack */

    /* Send PUSH to attacked peers */
    if (GNUNET_YES == Peers_check_peer_known (&attacked_peer))
    {
      (void) Peers_issue_peer_liveliness_check (&attacked_peer);
      if (GNUNET_YES == Peers_check_peer_flag (&attacked_peer, Peers_ONLINE))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Goding to send push to attacked peer (%s)\n",
            GNUNET_i2s (&attacked_peer));
        send_push (&attacked_peer);
      }
    }
    (void) Peers_issue_peer_liveliness_check (&attacked_peer);

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

      send_push (&att_peer_index->peer_id);
    }

    /* Send PULLs to some peers to learn about additional peers to attack */
    tmp_att_peer = att_peer_index;
    for (i = 0; i < num_pushes * alpha; i++)
    {
      if (att_peers_tail == tmp_att_peer)
        tmp_att_peer = att_peers_head;
      else
        att_peer_index = tmp_att_peer->next;

      send_pull_request (&tmp_att_peer->peer_id);
    }
  }

  /* Schedule next round */
  time_next_round = compute_rand_delay (round_interval, 2);

  //do_round_task = GNUNET_SCHEDULER_add_delayed (round_interval, &do_mal_round,
  //NULL);
  GNUNET_assert (NULL == do_round_task);
  do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round,
						&do_mal_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}
#endif /* ENABLE_MALICIOUS */

/**
 * Send out PUSHes and PULLs, possibly update #view, samplers.
 *
 * This is executed regylary.
 */
static void
do_round (void *cls)
{
  uint32_t i;
  const struct GNUNET_PeerIdentity *view_array;
  unsigned int *permut;
  unsigned int a_peers; /* Number of peers we send pushes to */
  unsigned int b_peers; /* Number of peers we send pull requests to */
  uint32_t first_border;
  uint32_t second_border;
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_PeerIdentity *update_peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Going to execute next round.\n");
  GNUNET_STATISTICS_update(stats, "# rounds", 1, GNUNET_NO);
  do_round_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Printing view:\n");
  to_file (file_name_view_log,
           "___ new round ___");
  view_array = View_get_as_array ();
  for (i = 0; i < View_size (); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "\t%s\n", GNUNET_i2s (&view_array[i]));
    to_file (file_name_view_log,
             "=%s\t(do round)",
             GNUNET_i2s_full (&view_array[i]));
  }


  /* Send pushes and pull requests */
  if (0 < View_size ())
  {
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           View_size ());

    /* Send PUSHes */
    a_peers = ceil (alpha * View_size ());

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Going to send pushes to %u (ceil (%f * %u)) peers.\n",
         a_peers, alpha, View_size ());
    for (i = 0; i < a_peers; i++)
    {
      peer = view_array[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_push (&peer);
      }
    }

    /* Send PULL requests */
    b_peers = ceil (beta * View_size ());
    first_border = a_peers;
    second_border = a_peers + b_peers;
    if (second_border > View_size ())
    {
      first_border = View_size () - b_peers;
      second_border = View_size ();
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Going to send pulls to %u (ceil (%f * %u)) peers.\n",
        b_peers, beta, View_size ());
    for (i = first_border; i < second_border; i++)
    {
      peer = view_array[permut[i]];
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&own_identity, &peer) &&
          GNUNET_NO == Peers_check_peer_flag (&peer, Peers_PULL_REPLY_PENDING)) // TODO
      { // FIXME if this fails schedule/loop this for later
        send_pull_request (&peer);
      }
    }

    GNUNET_free (permut);
    permut = NULL;
  }


  /* Update view */
  /* TODO see how many peers are in push-/pull- list! */

  if ((CustomPeerMap_size (push_map) <= alpha * view_size_est_need) &&
      (0 < CustomPeerMap_size (push_map)) &&
      (0 < CustomPeerMap_size (pull_map)))
  //if (GNUNET_YES) // disable blocking temporarily
  { /* If conditions for update are fulfilled, update */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Update of the view.\n");

    uint32_t final_size;
    uint32_t peers_to_clean_size;
    struct GNUNET_PeerIdentity *peers_to_clean;

    peers_to_clean = NULL;
    peers_to_clean_size = 0;
    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, View_size ());
    GNUNET_memcpy (peers_to_clean,
            view_array,
            View_size () * sizeof (struct GNUNET_PeerIdentity));

    /* Seems like recreating is the easiest way of emptying the peermap */
    View_clear ();
    to_file (file_name_view_log,
             "--- emptied ---");

    first_border  = GNUNET_MIN (ceil (alpha * view_size_est_need),
                                CustomPeerMap_size (push_map));
    second_border = first_border +
                    GNUNET_MIN (floor (beta  * view_size_est_need),
                                CustomPeerMap_size (pull_map));
    final_size    = second_border +
      ceil ((1 - (alpha + beta)) * view_size_est_need);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "first border: %" PRIu32 ", second border: %" PRIu32 ", final size: %"PRIu32 "\n",
        first_border,
        second_border,
        final_size);

    /* Update view with peers received through PUSHes */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (push_map));
    for (i = 0; i < first_border; i++)
    {
      (void) insert_in_view (CustomPeerMap_get_peer_by_index (push_map,
                                                              permut[i]));
      to_file (file_name_view_log,
               "+%s\t(push list)",
               GNUNET_i2s_full (&view_array[i]));
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers received through PULLs */
    permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
                                           CustomPeerMap_size (pull_map));
    for (i = first_border; i < second_border; i++)
    {
      (void) insert_in_view (CustomPeerMap_get_peer_by_index (pull_map,
            permut[i - first_border]));
      to_file (file_name_view_log,
               "+%s\t(pull list)",
               GNUNET_i2s_full (&view_array[i]));
      // TODO change the peer_flags accordingly
    }
    GNUNET_free (permut);
    permut = NULL;

    /* Update view with peers from history */
    RPS_sampler_get_n_rand_peers (prot_sampler,
                                  hist_update,
                                  NULL,
                                  final_size - second_border);
    // TODO change the peer_flags accordingly

    for (i = 0; i < View_size (); i++)
      rem_from_list (&peers_to_clean, &peers_to_clean_size, &view_array[i]);

    /* Clean peers that were removed from the view */
    for (i = 0; i < peers_to_clean_size; i++)
    {
      to_file (file_name_view_log,
               "-%s",
               GNUNET_i2s_full (&peers_to_clean[i]));
      clean_peer (&peers_to_clean[i]);
      //peer_destroy_channel_send (sender);
    }

    GNUNET_array_grow (peers_to_clean, peers_to_clean_size, 0);
    clients_notify_view_update();
  } else {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "No update of the view.\n");
    GNUNET_STATISTICS_update(stats, "# rounds blocked", 1, GNUNET_NO);
    if (CustomPeerMap_size (push_map) > alpha * View_size () &&
        !(0 >= CustomPeerMap_size (pull_map)))
      GNUNET_STATISTICS_update(stats, "# rounds blocked - too many pushes", 1, GNUNET_NO);
    if (CustomPeerMap_size (push_map) > alpha * View_size () &&
        (0 >= CustomPeerMap_size (pull_map)))
      GNUNET_STATISTICS_update(stats, "# rounds blocked - too many pushes, no pull replies", 1, GNUNET_NO);
    if (0 >= CustomPeerMap_size (push_map) &&
        !(0 >= CustomPeerMap_size (pull_map)))
      GNUNET_STATISTICS_update(stats, "# rounds blocked - no pushes", 1, GNUNET_NO);
    if (0 >= CustomPeerMap_size (push_map) &&
        (0 >= CustomPeerMap_size (pull_map)))
      GNUNET_STATISTICS_update(stats, "# rounds blocked - no pushes, no pull replies", 1, GNUNET_NO);
    if (0 >= CustomPeerMap_size (pull_map) &&
        CustomPeerMap_size (push_map) > alpha * View_size () &&
        0 >= CustomPeerMap_size (push_map))
      GNUNET_STATISTICS_update(stats, "# rounds blocked - no pull replies", 1, GNUNET_NO);
  }
  // TODO independent of that also get some peers from CADET_get_peers()?
  GNUNET_STATISTICS_set (stats,
      "# peers in push map at end of round",
      CustomPeerMap_size (push_map),
      GNUNET_NO);
  GNUNET_STATISTICS_set (stats,
      "# peers in pull map at end of round",
      CustomPeerMap_size (pull_map),
      GNUNET_NO);
  GNUNET_STATISTICS_set (stats,
      "# peers in view at end of round",
      View_size (),
      GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u pushes and %u pulls last round (alpha (%.2f) * view_size (%u) = %.2f)\n",
       CustomPeerMap_size (push_map),
       CustomPeerMap_size (pull_map),
       alpha,
       View_size (),
       alpha * View_size ());

  /* Update samplers */
  for (i = 0; i < CustomPeerMap_size (push_map); i++)
  {
    update_peer = CustomPeerMap_get_peer_by_index (push_map, i);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from push list\n",
         GNUNET_i2s (update_peer));
    insert_in_sampler (NULL, update_peer);
    clean_peer (update_peer); /* This cleans only if it is not in the view */
    //peer_destroy_channel_send (sender);
  }

  for (i = 0; i < CustomPeerMap_size (pull_map); i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Updating with peer %s from pull list\n",
         GNUNET_i2s (CustomPeerMap_get_peer_by_index (pull_map, i)));
    insert_in_sampler (NULL, CustomPeerMap_get_peer_by_index (pull_map, i));
    /* This cleans only if it is not in the view */
    clean_peer (CustomPeerMap_get_peer_by_index (pull_map, i));
    //peer_destroy_channel_send (sender);
  }


  /* Empty push/pull lists */
  CustomPeerMap_clear (push_map);
  CustomPeerMap_clear (pull_map);

  struct GNUNET_TIME_Relative time_next_round;

  time_next_round = compute_rand_delay (round_interval, 2);

  /* Schedule next round */
  do_round_task = GNUNET_SCHEDULER_add_delayed (time_next_round,
						&do_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished round\n");
}


/**
 * This is called from GNUNET_CADET_get_peers().
 *
 * It is called on every peer(ID) that cadet somehow has contact with.
 * We use those to initialise the sampler.
 */
void
init_peer_cb (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              int tunnel, // "Do we have a tunnel towards this peer?"
              unsigned int n_paths, // "Number of known paths towards this peer"
              unsigned int best_path) // "How long is the best path?
                                      // (0 = unknown, 1 = ourselves, 2 = neighbor)"
{
  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from cadet\n",
         GNUNET_i2s (peer));
    got_peer (peer);
  }
}

/**
 * @brief Iterator function over stored, valid peers.
 *
 * We initialise the sampler with those.
 *
 * @param cls the closure
 * @param peer the peer id
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
valid_peers_iterator (void *cls,
                      const struct GNUNET_PeerIdentity *peer)
{
  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got stored, valid peer %s\n",
         GNUNET_i2s (peer));
    got_peer (peer);
  }
  return GNUNET_YES;
}


/**
 * Iterator over peers from peerinfo.
 *
 * @param cls closure
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
  if (NULL != peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got peer_id %s from peerinfo\n",
         GNUNET_i2s (peer));
    got_peer (peer);
  }
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct ClientContext *client_ctx;
  struct ReplyCls *reply_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "RPS is going down\n");

  /* Clean all clients */
  for (client_ctx = cli_ctx_head;
       NULL != cli_ctx_head;
       client_ctx = cli_ctx_head)
  {
    /* Clean pending requests to the sampler */
    for (reply_cls = client_ctx->rep_cls_head;
         NULL != client_ctx->rep_cls_head;
         reply_cls = client_ctx->rep_cls_head)
    {
      RPS_sampler_request_cancel (reply_cls->req_handle);
      GNUNET_CONTAINER_DLL_remove (client_ctx->rep_cls_head,
                                   client_ctx->rep_cls_tail,
                                   reply_cls);
      GNUNET_free (reply_cls);
    }
    GNUNET_CONTAINER_DLL_remove (cli_ctx_head, cli_ctx_tail, client_ctx);
    GNUNET_free (client_ctx);
  }
  GNUNET_PEERINFO_notify_cancel (peerinfo_notify_handle);
  GNUNET_PEERINFO_disconnect (peerinfo_handle);

  if (NULL != do_round_task)
  {
    GNUNET_SCHEDULER_cancel (do_round_task);
    do_round_task = NULL;
  }

  Peers_terminate ();

  GNUNET_NSE_disconnect (nse);
  RPS_sampler_destroy (prot_sampler);
  RPS_sampler_destroy (client_sampler);
  GNUNET_CADET_close_port (cadet_port);
  GNUNET_CADET_disconnect (cadet_handle);
  View_destroy ();
  CustomPeerMap_destroy (push_map);
  CustomPeerMap_destroy (pull_map);
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  #ifdef ENABLE_MALICIOUS
  struct AttackedPeer *tmp_att_peer;
  /* it is ok to free this const during shutdown: */
  GNUNET_free ((char *) file_name_view_log);
  #ifdef TO_FILE
  GNUNET_free ((char *) file_name_observed_log);
  GNUNET_CONTAINER_multipeermap_destroy (observed_unique_peers);
  #endif /* TO_FILE */
  GNUNET_array_grow (mal_peers, num_mal_peers, 0);
  if (NULL != mal_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (mal_peer_set);
  if (NULL != att_peer_set)
    GNUNET_CONTAINER_multipeermap_destroy (att_peer_set);
  while (NULL != att_peers_head)
  {
    tmp_att_peer = att_peers_head;
    GNUNET_CONTAINER_DLL_remove (att_peers_head, att_peers_tail, tmp_att_peer);
    GNUNET_free (tmp_att_peer);
  }
  #endif /* ENABLE_MALICIOUS */
}


/**
 * Handle client connecting to the service.
 *
 * @param cls NULL
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client connected\n");
  if (NULL == client)
    return client; /* Server was destroyed before a client connected. Shutting down */
  cli_ctx = GNUNET_new (struct ClientContext);
  cli_ctx->mq = GNUNET_SERVICE_client_get_mq (client);
  cli_ctx->view_updates_left = -1;
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
  char* fn_valid_peers;

  GNUNET_log_setup ("rps", GNUNET_error_type_to_string (GNUNET_ERROR_TYPE_DEBUG), NULL);
  cfg = c;


  /* Get own ID */
  GNUNET_CRYPTO_get_peer_identity (cfg, &own_identity); // TODO check return value
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "STARTING SERVICE (rps) for peer [%s]\n",
              GNUNET_i2s (&own_identity));
  #ifdef ENABLE_MALICIOUS
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Malicious execution compiled in.\n");
  #endif /* ENABLE_MALICIOUS */



  /* Get time interval from the configuration */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg, "RPS",
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
      GNUNET_CONFIGURATION_get_value_number (cfg, "RPS", "MINSIZE",
        (long long unsigned int *) &sampler_size_est_min))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "RPS", "MINSIZE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  sampler_size_est_need = sampler_size_est_min;
  view_size_est_min = sampler_size_est_min;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "MINSIZE is %u\n", sampler_size_est_min);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "rps",
                                               "FILENAME_VALID_PEERS",
                                               &fn_valid_peers))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "rps", "FILENAME_VALID_PEERS");
  }


  View_create (view_size_est_min);

  /* file_name_view_log */
  file_name_view_log = store_prefix_file_name (&own_identity, "view");
  #ifdef TO_FILE
  file_name_observed_log = store_prefix_file_name (&own_identity, "observed");
  observed_unique_peers = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
  #endif /* TO_FILE */

  /* connect to NSE */
  nse = GNUNET_NSE_connect (cfg, nse_callback, NULL);


  alpha = 0.45;
  beta  = 0.45;


  /* Initialise cadet */
  /* There exists a copy-paste-clone in get_channel() */
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

  cadet_handle = GNUNET_CADET_connect (cfg);
  GNUNET_assert (NULL != cadet_handle);
  GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_RPS,
                      strlen (GNUNET_APPLICATION_PORT_RPS),
                      &port);
  cadet_port = GNUNET_CADET_open_port (cadet_handle,
                                       &port,
                                       &Peers_handle_inbound_channel, /* Connect handler */
                                       NULL, /* cls */
                                       NULL, /* WindowSize handler */
                                       cleanup_destroyed_channel, /* Disconnect handler */
                                       cadet_handlers);


  peerinfo_handle = GNUNET_PEERINFO_connect (cfg);
  Peers_initialise (fn_valid_peers, cadet_handle, &own_identity);
  GNUNET_free (fn_valid_peers);

  /* Initialise sampler */
  struct GNUNET_TIME_Relative half_round_interval;
  struct GNUNET_TIME_Relative  max_round_interval;

  half_round_interval = GNUNET_TIME_relative_divide (round_interval, 2);
  max_round_interval = GNUNET_TIME_relative_add (round_interval, half_round_interval);

  prot_sampler =   RPS_sampler_init     (sampler_size_est_need, max_round_interval);
  client_sampler = RPS_sampler_mod_init (sampler_size_est_need, max_round_interval);

  /* Initialise push and pull maps */
  push_map = CustomPeerMap_create (4);
  pull_map = CustomPeerMap_create (4);


  //LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting peers from CADET\n");
  //GNUNET_CADET_get_peers (cadet_handle, &init_peer_cb, NULL);
  // TODO send push/pull to each of those peers?
  // TODO read stored valid peers from last run
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting stored valid peers\n");
  Peers_get_valid_peers (valid_peers_iterator, NULL);

  peerinfo_notify_handle = GNUNET_PEERINFO_notify (cfg,
                                                   GNUNET_NO,
                                                   process_peerinfo_peers,
                                                   NULL);

  LOG (GNUNET_ERROR_TYPE_INFO, "Ready to receive requests from clients\n");

  do_round_task = GNUNET_SCHEDULER_add_now (&do_round, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduled first round\n");

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
 GNUNET_MQ_hd_fixed_size (client_request,
   GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST,
   struct GNUNET_RPS_CS_RequestMessage,
   NULL),
 GNUNET_MQ_hd_fixed_size (client_request_cancel,
   GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST_CANCEL,
   struct GNUNET_RPS_CS_RequestCancelMessage,
   NULL),
 GNUNET_MQ_hd_var_size (client_seed,
   GNUNET_MESSAGE_TYPE_RPS_CS_SEED,
   struct GNUNET_RPS_CS_SeedMessage,
   NULL),
#ifdef ENABLE_MALICIOUS
 GNUNET_MQ_hd_var_size (client_act_malicious,
   GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS,
   struct GNUNET_RPS_CS_ActMaliciousMessage,
   NULL),
#endif /* ENABLE_MALICIOUS */
 GNUNET_MQ_hd_fixed_size (client_view_request,
   GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REQUEST,
   struct GNUNET_RPS_CS_DEBUG_ViewRequest,
   NULL),
 GNUNET_MQ_handler_end());

/* end of gnunet-service-rps.c */
