/*
     This file is part of GNUnet.
     Copyright (C)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file rps/gnunet-service-rps_peers.c
 * @brief utilities for managing (information about) peers
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include <inttypes.h>
#include "rps.h"
#include "gnunet-service-rps_peers.h"



#define LOG(kind, ...) GNUNET_log_from(kind,"rps-peers",__VA_ARGS__)


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
 * Own #GNUNET_PeerIdentity.
 */
static const struct GNUNET_PeerIdentity *own_identity;

/**
 * Cadet handle.
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * @brief Disconnect handler
 */
static GNUNET_CADET_DisconnectEventHandler cleanup_destroyed_channel;

/**
 * @brief cadet handlers
 */
static const struct GNUNET_MQ_MessageHandler *cadet_handlers;



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
    GNUNET_free (peer_ctx->liveliness_check_pending);
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
  struct GNUNET_HashCode port;

  peer_ctx = get_peer_ctx (peer);
  if (NULL == peer_ctx->send_channel)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Trying to establish channel to peer %s\n",
         GNUNET_i2s (peer));
    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_RPS,
                        strlen (GNUNET_APPLICATION_PORT_RPS),
                        &port);
    peer_ctx->send_channel =
      GNUNET_CADET_channel_create (cadet_handle,
                                   (struct GNUNET_PeerIdentity *) peer, /* context */
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
    (void) get_channel (peer);
    peer_ctx->mq = GNUNET_CADET_get_mq (peer_ctx->send_channel);
  }
  return peer_ctx->mq;
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
    GNUNET_free (peer_ctx->liveliness_check_pending);
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
  peer_ctx->liveliness_check_pending = GNUNET_new (struct PendingMessage);
  peer_ctx->liveliness_check_pending->ev = ev;
  peer_ctx->liveliness_check_pending->peer_ctx = peer_ctx;
  peer_ctx->liveliness_check_pending->type = "Check liveliness";
  mq = get_mq (&peer_ctx->peer_id);
  GNUNET_MQ_notify_sent (ev,
                         mq_liveliness_check_successful,
                         peer_ctx);
  GNUNET_MQ_send (mq, ev);
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
 */
static void
remove_pending_message (struct PendingMessage *pending_msg)
{
  struct PeerContext *peer_ctx;

  peer_ctx = pending_msg->peer_ctx;
  GNUNET_CONTAINER_DLL_remove (peer_ctx->pending_messages_head,
                               peer_ctx->pending_messages_tail,
                               pending_msg);
  GNUNET_MQ_send_cancel (peer_ctx->pending_messages_head->ev);
  GNUNET_free (pending_msg);
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
  remove_pending_message (pending_msg);
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
        "Sting representation: %s (len %u) - too short\n",
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
 * @param disconnect_handler Disconnect handler
 * @param c_handlers cadet handlers
 * @param own_id own peer identity
 */
void
Peers_initialise (char* fn_valid_peers,
                  struct GNUNET_CADET_Handle *cadet_h,
                  GNUNET_CADET_DisconnectEventHandler disconnect_handler,
                  const struct GNUNET_MQ_MessageHandler *c_handlers,
                  const struct GNUNET_PeerIdentity *own_id)
{
  filename_valid_peers = GNUNET_strdup (fn_valid_peers);
  cadet_handle = cadet_h;
  cleanup_destroyed_channel = disconnect_handler;
  cadet_handlers = c_handlers;
  own_identity = own_id;
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
       (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, own_identity)) )
  {
    return GNUNET_NO; /* We already know this peer - nothing to do */
  }
  (void) create_peer_ctx (peer);
  return GNUNET_YES;
}


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

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, own_identity))
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
    remove_pending_message (peer_ctx->pending_messages_head);
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
  if (NULL != peer_ctx->send_channel)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Destroying send channel\n");
    GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
    peer_ctx->send_channel = NULL;
  }
  if (NULL != peer_ctx->recv_channel)
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
  return GNUNET_CONTAINER_multipeermap_contains (peer_map, peer);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "New channel was established to us (Peer %s).\n",
      GNUNET_i2s (initiator));
  GNUNET_assert (NULL != channel); /* according to cadet API */
  /* Make sure we 'know' about this peer */
  peer_ctx = create_or_get_peer_ctx (initiator);
  set_peer_live (peer_ctx);
  /* We only accept one incoming channel per peer */
  if (GNUNET_YES == Peers_check_peer_send_intention (initiator))
  {
    set_channel_flag (peer_ctx->recv_channel_flags,
                      Peers_CHANNEL_ESTABLISHED_TWICE);
    GNUNET_CADET_channel_destroy (channel);
    /* return the channel context */
    return &peer_ctx->peer_id;
  }
  peer_ctx->recv_channel = channel;
  return &peer_ctx->peer_id;
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
 * @param channel_ctx The context associated with this channel
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
    if (channel == peer_ctx->send_channel)
      peer_ctx->send_channel = NULL;
    else if (channel == peer_ctx->recv_channel)
      peer_ctx->recv_channel = NULL;

    if (NULL != peer_ctx->send_channel)
    {
      GNUNET_CADET_channel_destroy (peer_ctx->send_channel);
      peer_ctx->send_channel = NULL;
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
    if (channel == peer_ctx->send_channel)
    { /* Something (but us) killd the channel - clean up peer */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "send channel (%s) was destroyed - cleaning up\n",
          GNUNET_i2s (peer));
      peer_ctx->send_channel = NULL;
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

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, own_identity))
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

/* end of gnunet-service-rps_peers.c */
