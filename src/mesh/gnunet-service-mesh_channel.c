/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"

#include "mesh_enc.h"
#include "mesh_protocol_enc.h"

#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_local.h"
#include "gnunet-service-mesh_tunnel.h"

#define LOG(level, ...) GNUNET_log_from(level,"mesh-chn",__VA_ARGS__)

#define MESH_RETRANSMIT_TIME    GNUNET_TIME_UNIT_SECONDS
#define MESH_RETRANSMIT_MARGIN  4


/**
 * All the states a connection can be in.
 */
enum MeshChannelState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_CHANNEL_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  MESH_CHANNEL_SENT,

  /**
   * Connection confirmed, ready to carry traffic..
   */
  MESH_CHANNEL_READY,
};



/**
 * Info needed to retry a message in case it gets lost.
 */
struct MeshReliableMessage
{
    /**
     * Double linked list, FIFO style
     */
  struct MeshReliableMessage    *next;
  struct MeshReliableMessage    *prev;

    /**
     * Type of message (payload, channel management).
     */
  int16_t type;

    /**
     * Tunnel Reliability queue this message is in.
     */
  struct MeshChannelReliability  *rel;

    /**
     * ID of the message (ACK needed to free)
     */
  uint32_t                      mid;

    /**
     * When was this message issued (to calculate ACK delay)
     */
  struct GNUNET_TIME_Absolute   timestamp;

  /* struct GNUNET_MESH_Data with payload */
};


/**
 * Info about the traffic state for a client in a channel.
 */
struct MeshChannelReliability
{
    /**
     * Channel this is about.
     */
  struct MeshChannel *ch;

    /**
     * DLL of messages sent and not yet ACK'd.
     */
  struct MeshReliableMessage        *head_sent;
  struct MeshReliableMessage        *tail_sent;

    /**
     * Messages pending to send.
     */
  unsigned int                      n_sent;

    /**
     * DLL of messages received out of order.
     */
  struct MeshReliableMessage        *head_recv;
  struct MeshReliableMessage        *tail_recv;

    /**
     * Messages received.
     */
  unsigned int                      n_recv;

    /**
     * Next MID to use for outgoing traffic.
     */
  uint32_t                          mid_send;

    /**
     * Next MID expected for incoming traffic.
     */
  uint32_t                          mid_recv;

    /**
     * Can we send data to the client?
     */
  int                               client_ready;

    /**
     * Task to resend/poll in case no ACK is received.
     */
  GNUNET_SCHEDULER_TaskIdentifier   retry_task;

    /**
     * Counter for exponential backoff.
     */
  struct GNUNET_TIME_Relative       retry_timer;

    /**
     * How long does it usually take to get an ACK.
     */
  struct GNUNET_TIME_Relative       expected_delay;
};


/**
 * Struct containing all information regarding a channel to a remote client.
 */
struct MeshChannel
{
    /**
     * Tunnel this channel is in.
     */
  struct MeshTunnel3 *t;

    /**
     * Destination port of the channel.
     */
  uint32_t port;

    /**
     * Global channel number ( < GNUNET_MESH_LOCAL_CHANNEL_ID_CLI)
     */
  MESH_ChannelNumber gid;

    /**
     * Local tunnel number for root (owner) client.
     * ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI or 0 )
     */
  MESH_ChannelNumber lid_root;

    /**
     * Local tunnel number for local destination clients (incoming number)
     * ( >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV or 0).
     */
  MESH_ChannelNumber lid_dest;

    /**
     * Channel state.
     */
  enum MeshChannelState state;

    /**
     * Is the tunnel bufferless (minimum latency)?
     */
  int nobuffer;

    /**
     * Is the tunnel reliable?
     */
  int reliable;

    /**
     * Last time the channel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Client owner of the tunnel, if any
     */
  struct MeshClient *root;

    /**
     * Client destination of the tunnel, if any.
     */
  struct MeshClient *dest;

    /**
     * Flag to signal the destruction of the channel.
     * If this is set GNUNET_YES the channel will be destroyed
     * when the queue is empty.
     */
  int destroy;

    /**
     * Total messages pending for this channel, payload or not.
     */
  unsigned int pending_messages;

    /**
     * Reliability data.
     * Only present (non-NULL) at the owner of a tunnel.
     */
  struct MeshChannelReliability *root_rel;

    /**
     * Reliability data.
     * Only present (non-NULL) at the destination of a tunnel.
     */
  struct MeshChannelReliability *dest_rel;

};


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 *
 * @param copy Message that is no longer needed: remote peer got it.
 */
static void
rel_message_free (struct MeshReliableMessage *copy);

/**
 * We have received a message out of order, or the client is not ready.
 * Buffer it until we receive an ACK from the client or the missing
 * message from the channel.
 *
 * @param msg Message to buffer (MUST be of type MESH_DATA).
 * @param rel Reliability data to the corresponding direction.
 */
static void
add_buffered_data (const struct GNUNET_MESH_Data *msg,
                   struct MeshChannelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *prev;
  uint32_t mid;
  uint16_t size;

  size = ntohs (msg->header.size);
  mid = ntohl (msg->mid);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data %u\n", mid);

  copy = GNUNET_malloc (sizeof (*copy) + size);
  copy->mid = mid;
  copy->rel = rel;
  memcpy (&copy[1], msg, size);

  rel->n_recv++;

  // FIXME do something better than O(n), although n < 64...
  // FIXME start from the end (most messages are the latest ones)
  for (prev = rel->head_recv; NULL != prev; prev = prev->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " prev %u\n", prev->mid);
    if (GMC_is_pid_bigger (prev->mid, mid))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " bingo!\n");
      GNUNET_CONTAINER_DLL_insert_before (rel->head_recv, rel->tail_recv,
                                          prev, copy);
      return;
    }
  }
    LOG (GNUNET_ERROR_TYPE_DEBUG, " insert at tail!\n");
    GNUNET_CONTAINER_DLL_insert_tail (rel->head_recv, rel->tail_recv, copy);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data END\n");
}


/**
 * Send data to a client.
 *
 * If the client is ready, send directly, otherwise buffer while listening
 * for a local ACK.
 *
 * @param ch Channel
 * @param msg Message.
 * @param fwd Is this a fwd (root->dest) message?
 */
static void
send_client_data (struct MeshChannel *ch,
                  const struct GNUNET_MESH_Data *msg,
                  int fwd)
{
  if (fwd)
  {
    if (ch->dest_rel->client_ready)
      GML_send_data (ch->dest, msg, ch->lid_dest);
    else
      add_buffered_data (msg, ch->dest_rel);
  }
  else
  {
    if (ch->root_rel->client_ready)
      GML_send_data (ch->root, msg, ch->lid_root);
    else
      add_buffered_data (msg, ch->root_rel);
  }
}


/**
 * Add a client to a channel, initializing all needed data structures.
 *
 * @param ch Channel to which add the client.
 * @param c Client which to add to the channel.
 */
void
GMCH_add_client (struct MeshChannel *ch, struct MeshClient *c)
{
  if (NULL != ch->dest)
  {
    GNUNET_break (0);
    return;
  }

  /* Assign local id as destination */
  ch->lid_dest = GML_get_next_chid (c);

  /* Store in client's hashmap */
  GML_channel_add (c, ch->lid_dest, ch);

  GNUNET_break (NULL == ch->dest_rel);
  ch->dest_rel = GNUNET_new (struct MeshChannelReliability);
  ch->dest_rel->ch = ch;
  ch->dest_rel->expected_delay = MESH_RETRANSMIT_TIME;

  ch->dest = c;
}


/**
 * Destroy all reliable messages queued for a channel,
 * during a channel destruction.
 * Frees the reliability structure itself.
 *
 * @param rel Reliability data for a channel.
 */
static void
channel_rel_free_all (struct MeshChannelReliability *rel)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  if (NULL == rel)
    return;

  for (copy = rel->head_recv; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
    GNUNET_free (copy);
  }
  for (copy = rel->head_sent; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
    GNUNET_free (copy);
  }
  if (GNUNET_SCHEDULER_NO_TASK != rel->retry_task)
    GNUNET_SCHEDULER_cancel (rel->retry_task);
  GNUNET_free (rel);
}


/**
 * Mark future messages as ACK'd.
 *
 * @param rel Reliability data.
 * @param msg DataACK message with a bitfield of future ACK'd messages.
 */
static void
channel_rel_free_sent (struct MeshChannelReliability *rel,
                       const struct GNUNET_MESH_DataACK *msg)
{
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;
  uint64_t bitfield;
  uint64_t mask;
  uint32_t mid;
  uint32_t target;
  unsigned int i;

  bitfield = msg->futures;
  mid = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "free_sent_reliable %u %llX\n",
              mid, bitfield);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              " rel %p, head %p\n",
              rel, rel->head_sent);
  for (i = 0, copy = rel->head_sent;
       i < 64 && NULL != copy && 0 != bitfield;
       i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                " trying bit %u (mid %u)\n",
                i, mid + i + 1);
    mask = 0x1LL << i;
    if (0 == (bitfield & mask))
     continue;

    LOG (GNUNET_ERROR_TYPE_DEBUG, " set!\n");
    /* Bit was set, clear the bit from the bitfield */
    bitfield &= ~mask;

    /* The i-th bit was set. Do we have that copy? */
    /* Skip copies with mid < target */
    target = mid + i + 1;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " target %u\n", target);
    while (NULL != copy && GMC_is_pid_bigger (target, copy->mid))
     copy = copy->next;

    /* Did we run out of copies? (previously freed, it's ok) */
    if (NULL == copy)
    {
     LOG (GNUNET_ERROR_TYPE_DEBUG, "run out of copies...\n");
     return;
    }

    /* Did we overshoot the target? (previously freed, it's ok) */
    if (GMC_is_pid_bigger (copy->mid, target))
    {
     LOG (GNUNET_ERROR_TYPE_DEBUG, " next copy %u\n", copy->mid);
     continue;
    }

    /* Now copy->mid == target, free it */
    next = copy->next;
    rel_message_free (copy);
    copy = next;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "free_sent_reliable END\n");
}


/**
 * We haven't received an ACK after a certain time: restransmit the message.
 *
 * @param cls Closure (MeshReliableMessage with the message to restransmit)
 * @param tc TaskContext.
 */
static void
channel_retransmit_message (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshChannelReliability *rel = cls;
  struct MeshReliableMessage *copy;
  struct MeshChannel *ch;
  struct GNUNET_MESH_Data *payload;
  int fwd;

  rel->retry_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  ch = rel->ch;
  copy = rel->head_sent;
  if (NULL == copy)
  {
    GNUNET_break (0);
    return;
  }

  /* Search the message to be retransmitted in the outgoing queue.
   * Check only the queue for the connection that is going to be used,
   * if the message is stuck in some other connection's queue we shouldn't
   * act upon it:
   * - cancelling it and sending the new one doesn't guarantee it's delivery,
   *   the old connection could be temporary stalled or the queue happened to
   *   be long at time of insertion.
   * - not sending the new one could cause terrible delays the old connection
   *   is stalled.
   */
//   FIXME access to queue elements is limited
  payload = (struct GNUNET_MESH_Data *) &copy[1];
  fwd = (rel == ch->root_rel);
//   c = GMT_get_connection (ch->t, fwd);
//   hop = connection_get_hop (c, fwd);
//   for (q = hop->queue_head; NULL != q; q = q->next)
//   {
//     if (ntohs (payload->header.type) == q->type && ch == q->ch)
//     {
//       struct GNUNET_MESH_Data *queued_data = q->cls;
// 
//       if (queued_data->mid == payload->mid)
//         break;
//     }
//   }

  /* Message not found in the queue that we are going to use. */
//   if (NULL == q)
//   {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! RETRANSMIT %u\n", copy->mid);

    GMCH_send_prebuilt_message (&payload->header, ch, fwd);
    GNUNET_STATISTICS_update (stats, "# data retransmitted", 1, GNUNET_NO);
//   }
//   else
//   {
//     LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! ALREADY IN QUEUE %u\n", copy->mid);
//   }

  rel->retry_timer = GNUNET_TIME_STD_BACKOFF (rel->retry_timer);
  rel->retry_task = GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                                  &channel_retransmit_message,
                                                  cls);
}


/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 *
 * @param copy Message that is no longer needed: remote peer got it.
 */
static void
rel_message_free (struct MeshReliableMessage *copy)
{
  struct MeshChannelReliability *rel;
  struct GNUNET_TIME_Relative time;

  rel = copy->rel;
  time = GNUNET_TIME_absolute_get_duration (copy->timestamp);
  rel->expected_delay.rel_value_us *= 7;
  rel->expected_delay.rel_value_us += time.rel_value_us;
  rel->expected_delay.rel_value_us /= 8;
  rel->n_sent--;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! Freeing %u\n", copy->mid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    n_sent %u\n", rel->n_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!!!  took %s\n",
              GNUNET_STRINGS_relative_time_to_string (time, GNUNET_NO));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!!!  new expected delay %s\n",
              GNUNET_STRINGS_relative_time_to_string (rel->expected_delay,
                                                      GNUNET_NO));
  rel->retry_timer = rel->expected_delay;
  GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
  GNUNET_free (copy);
}



/**
 * Channel was ACK'd by remote peer, mark as ready and cancel retransmission.
 *
 * @param ch Channel to mark as ready.
 * @param fwd Was the CREATE message sent fwd?
 */
static void
channel_confirm (struct MeshChannel *ch, int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  channel confirm %s %s:%X\n",
              fwd ? "FWD" : "BCK", GMT_2s (ch->t), ch->gid);
  ch->state = MESH_CHANNEL_READY;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  for (copy = rel->head_sent; NULL != copy; copy = next)
  {
    struct GNUNET_MessageHeader *msg;

    next = copy->next;
    msg = (struct GNUNET_MessageHeader *) &copy[1];
    if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE)
    {
      rel_message_free (copy);
      /* TODO return? */
    }
  }
  send_ack (NULL, ch, fwd);
}


/**
 * Save a copy to retransmit in case it gets lost.
 *
 * Initializes all needed callbacks and timers.
 *
 * @param ch Channel this message goes on.
 * @param msg Message to copy.
 * @param fwd Is this fwd traffic?
 */
static void
channel_save_copy (struct MeshChannel *ch,
                   const struct GNUNET_MessageHeader *msg,
                   int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  uint32_t mid;
  uint16_t type;
  uint16_t size;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  mid = rel->mid_send;
  type = ntohs (msg->type);
  size = ntohs (msg->size);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! SAVE %u\n", mid);
  copy = GNUNET_malloc (sizeof (struct MeshReliableMessage) + size);
  copy->mid = mid;
  copy->timestamp = GNUNET_TIME_absolute_get ();
  copy->rel = rel;
  copy->type = type;
  memcpy (&copy[1], msg, size);
  rel->n_sent++;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " n_sent %u\n", rel->n_sent);
  GNUNET_CONTAINER_DLL_insert_tail (rel->head_sent, rel->tail_sent, copy);
  if (GNUNET_SCHEDULER_NO_TASK == rel->retry_task)
  {
    rel->retry_timer =
        GNUNET_TIME_relative_multiply (rel->expected_delay,
                                        MESH_RETRANSMIT_MARGIN);
    rel->retry_task =
        GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                      &channel_retransmit_message,
                                      rel);
  }
}



/**
 * Send a buffered message to the client, for in order delivery or
 * as result of client ACK.
 *
 * @param ch Channel on which to empty the message buffer.
 * @param c Client to send to.
 * @param rel Reliability structure to corresponding peer.
 *            If rel == bck_rel, this is FWD data.
 */
static void
send_client_buffered_data (struct MeshChannel *ch,
                                   struct MeshClient *c,
                                   int fwd)
{
  struct MeshReliableMessage *copy;
  struct MeshChannelReliability *rel;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data\n");
  rel = fwd ? ch->dest_rel : ch->root_rel;
  if (GNUNET_NO == rel->client_ready)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "client not ready\n");
    return;
  }

  copy = rel->head_recv;
  /* We never buffer channel management messages */
  if (NULL != copy)
  {
    if (copy->mid == rel->mid_recv || GNUNET_NO == ch->reliable)
    {
      struct GNUNET_MESH_Data *msg = (struct GNUNET_MESH_Data *) &copy[1];

      LOG (GNUNET_ERROR_TYPE_DEBUG,
                  " have %u! now expecting %u\n",
                  copy->mid, rel->mid_recv + 1);
      send_client_data (ch, msg, fwd);
      rel->n_recv--;
      rel->mid_recv++;
      GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
      GNUNET_free (copy);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
                  " reliable && don't have %u, next is %u\n",
                  rel->mid_recv,
                  copy->mid);
      return;
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data END\n");
}




/**
 * Destroy a channel and free all resources.
 *
 * @param ch Channel to destroy.
 */
static void
channel_destroy (struct MeshChannel *ch)
{
  struct MeshClient *c;

  if (NULL == ch)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying channel %s:%u\n",
              GMT_2s (ch->t), ch->gid);
  GMCH_debug (ch);

  c = ch->root;
  if (NULL != c)
  {
    GML_channel_remove (c, ch->lid_root, ch);
  }

  c = ch->dest;
  if (NULL != c)
  {
    GML_channel_remove (c, ch->lid_dest, ch);
  }

  channel_rel_free_all (ch->root_rel);
  channel_rel_free_all (ch->dest_rel);

  GMT_remove_channel (ch->t, ch);
  GNUNET_STATISTICS_update (stats, "# channels", -1, GNUNET_NO);

  GNUNET_free (ch);
}


/**
 * Create a new channel.
 *
 * @param t Tunnel this channel is in.
 * @param owner Client that owns the channel, NULL for foreign channels.
 * @param lid_root Local ID for root client.
 *
 * @return A new initialized channel. NULL on error.
 */
static struct MeshChannel *
channel_new (struct MeshTunnel3 *t,
             struct MeshClient *owner, MESH_ChannelNumber lid_root)
{
  struct MeshChannel *ch;

  ch = GNUNET_new (struct MeshChannel);
  ch->root = owner;
  ch->lid_root = lid_root;
  ch->t = t;

  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);

  if (NULL != owner)
  {
    ch->gid = GMT_get_next_chid (t);
    GML_channel_add (owner, lid_root, ch);
  }
  GMT_add_channel (t, ch);

  return ch;
}


/**
 * Set options in a channel, extracted from a bit flag field
 *
 * @param ch Channel to set options to.
 * @param options Bit array in host byte order.
 */
static void
channel_set_options (struct MeshChannel *ch, uint32_t options)
{
  ch->nobuffer = (options & GNUNET_MESH_OPTION_NOBUFFER) != 0 ?
                 GNUNET_YES : GNUNET_NO;
  ch->reliable = (options & GNUNET_MESH_OPTION_RELIABLE) != 0 ?
                 GNUNET_YES : GNUNET_NO;
}



/**
 * Confirm we got a channel create.
 *
 * @param ch The channel to confirm.
 * @param fwd Should we send the ACK fwd?
 */
static void
channel_send_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  sending channel %s ack for channel %s:%X\n",
              fwd ? "FWD" : "BCK", GMT_2s (ch->t),
              ch->gid);

  msg.chid = htonl (ch->gid);
  GMCH_send_prebuilt_message (&msg.header, ch, !fwd);
}


/**
 * Iterator for deleting each channel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local channel id (used to access the hashmap).
 * @param value The value stored at the key (channel to destroy).
 *
 * @return GNUNET_OK, keep iterating.
 */
static int
channel_destroy_iterator (void *cls,
                          uint32_t key,
                          void *value)
{
  struct MeshChannel *ch = value;
  struct MeshClient *c = cls;
  struct MeshTunnel3 *t;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              " Channel %X (%X / %X) destroy, due to client %s shutdown.\n",
              ch->gid, ch->lid_root, ch->lid_dest, GML_2s (c));
  GMCH_debug (ch);

  if (c == ch->dest)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " Client %s is destination.\n", GML_2s (c));
  }
  if (c == ch->root)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " Client %s is owner.\n", GML_2s (c));
  }

  t = ch->t;
  GMCH_send_destroy (ch);
  channel_destroy (ch);
  GMT_destroy_if_empty (t);

  return GNUNET_OK;
}


/**
 * Handle a loopback message: call the appropriate handler for the message type.
 *
 * @param ch Channel this message is on.
 * @param msgh Message header.
 * @param fwd Is this FWD traffic?
 */
void
handle_loopback (struct MeshChannel *ch,
                 const struct GNUNET_MessageHeader *msgh,
                 int fwd)
{
  uint16_t type;

  type = ntohs (msgh->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Loopback %s message!\n",
       GNUNET_MESH_DEBUG_M2S (type));

  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      GMCH_handle_data (ch, (struct GNUNET_MESH_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_DATA_ACK:
      GMCH_handle_data_ack (ch, (struct GNUNET_MESH_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
       // FIXME store channel in loopback tunnel?
      GMCH_handle_create ((struct GNUNET_MESH_ChannelCreate *) msgh,
                          fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
      GMCH_handle_ack (ch,
                       (struct GNUNET_MESH_ChannelManage *) msgh,
                       fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      GMCH_handle_destroy (ch,
                           (struct GNUNET_MESH_ChannelManage *) msgh,
                           fwd);
      break;

    default:
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "end-to-end message not known (%u)\n",
           ntohs (msgh->type));
  }
}



/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Get channel ID.
 *
 * @param ch Channel.
 *
 * @return ID
 */
MESH_ChannelNumber
GMCH_get_id (const struct MeshChannel *ch)
{
  return ch->gid;
}


/**
 * Get the channel tunnel.
 *
 * @param ch Channel to get the tunnel from.
 *
 * @return tunnel of the channel.
 */
struct MeshTunnel3 *
GMCH_get_tunnel (const struct MeshChannel *ch)
{
  return ch->t;
}


/**
 * Get free buffer space towards the client on a specific channel.
 *
 * @param ch Channel.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - 64]
 */
unsigned int
GMCH_get_buffer (struct MeshChannel *ch, int fwd)
{
  struct MeshChannelReliability *rel;

  rel = fwd ? ch->dest_rel : ch->root_rel;

  /* If rel is NULL it means that the end is not yet created,
   * most probably is a loopback channel at the point of sending
   * the ChannelCreate to itself.
   */
  if (NULL == rel)
    return 64;

  return (64 - rel->n_recv);
}


/**
 * Is the root client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return GNUNET_YES in case it is.
 */
int
GMCH_is_origin (struct MeshChannel *ch, int fwd)
{
  struct MeshClient *c;

  c = fwd ? ch->root : ch->dest;
  return NULL != c;
}


/**
 * Is the destination client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return GNUNET_YES in case it is.
 */
int
GMCH_is_terminal (struct MeshChannel *ch, int fwd)
{
  struct MeshClient *c;

  c = fwd ? ch->dest : ch->root;
  return NULL != c;
}


/**
 * Notify the destination client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
void
GMCH_send_create (struct MeshChannel *ch)
{
  uint32_t opt;

  if (NULL == ch->dest)
    return;

  opt = 0;
  opt |= GNUNET_YES == ch->reliable ? GNUNET_MESH_OPTION_RELIABLE : 0;
  opt |= GNUNET_YES == ch->nobuffer ? GNUNET_MESH_OPTION_NOBUFFER : 0;
  GML_send_channel_create (ch->dest, ch->lid_dest, ch->port, opt,
                           GMT_get_destination (ch->t));

}

/**
 * Notify a client that the channel is no longer valid.
 * FIXME send on tunnel if some client == NULL?
 *
 * @param ch Channel that is destroyed.
 */
void
GMCH_send_destroy (struct MeshChannel *ch)
{
  if (NULL != ch->root)
    GML_send_channel_destroy (ch->root, ch->lid_root);

  if (NULL != ch->dest)
    GML_send_channel_destroy (ch->dest, ch->lid_dest);
}


/**
 * Send data on a channel.
 *
 * If the destination is local, send it to client, otherwise encrypt and
 * send to next hop.
 *
 * @param ch Channel
 * @param msg Message.
 * @param fwd Is this a fwd (root->dest) message?
 */
void
GMCH_send_data (struct MeshChannel *ch,
                const struct GNUNET_MESH_Data *msg,
                int fwd)
{
}


/**
 * Send an end-to-end ACK message for the most recent in-sequence payload.
 *
 * If channel is not reliable, do nothing.
 *
 * @param ch Channel this is about.
 * @param fwd Is for FWD traffic? (ACK dest->owner)
 */
void
GMCH_send_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_DataACK msg;
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  unsigned int delta;
  uint64_t mask;
  uint16_t type;

  if (GNUNET_NO == ch->reliable)
  {
    return;
  }
  rel = fwd ? ch->dest_rel : ch->root_rel;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "send_data_ack for %u\n",
              rel->mid_recv - 1);

  type = GNUNET_MESSAGE_TYPE_MESH_DATA_ACK;
  msg.header.type = htons (type);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (ch->gid);
  msg.mid = htonl (rel->mid_recv - 1);
  msg.futures = 0;
  for (copy = rel->head_recv; NULL != copy; copy = copy->next)
  {
    if (copy->type != type)
      continue;
    delta = copy->mid - rel->mid_recv;
    if (63 < delta)
      break;
    mask = 0x1LL << delta;
    msg.futures |= mask;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                " setting bit for %u (delta %u) (%llX) -> %llX\n",
                copy->mid, delta, mask, msg.futures);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " final futures %llX\n", msg.futures);

  GMCH_send_prebuilt_message (&msg.header, ch, fwd);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_data_ack END\n");
}


/**
 * Log channel info.
 *
 * @param ch Channel.
 */
void
GMCH_debug (struct MeshChannel *ch)
{
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*** DEBUG NULL CHANNEL ***\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %s:%X (%p)\n",
              GMT_2s (ch->t), ch->gid, ch);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  root %p/%p\n",
              ch->root, ch->root_rel);
  if (NULL != ch->root)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cli %s\n", GML_2s (ch->root));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ready %s\n",
                ch->root_rel->client_ready ? "YES" : "NO");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  id %X\n", ch->lid_root);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  dest %p/%p\n",
              ch->dest, ch->dest_rel);
  if (NULL != ch->dest)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cli %s\n", GML_2s (ch->dest));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ready %s\n",
                ch->dest_rel->client_ready ? "YES" : "NO");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  id %X\n", ch->lid_dest);
  }
}


/**
 * Handler for mesh network payload traffic.
 *
 * @param ch Channel for the message.
 * @param message Unencryted data message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 */
void
GMCH_handle_data (struct MeshChannel *ch,
                  const struct GNUNET_MESH_Data *msg,
                  int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshClient *c;
  uint32_t mid;

  /*  Initialize FWD/BCK data */
  c   = fwd ? ch->dest     : ch->root;
  rel = fwd ? ch->dest_rel : ch->root_rel;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_STATISTICS_update (stats, "# data received", 1, GNUNET_NO);

  mid = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " mid %u\n", mid);

  if (GNUNET_NO == ch->reliable ||
      ( !GMC_is_pid_bigger (rel->mid_recv, mid) &&
        GMC_is_pid_bigger (rel->mid_recv + 64, mid) ) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! RECV %u\n", mid);
    if (GNUNET_YES == ch->reliable)
    {
      /* Is this the exact next expected messasge? */
      if (mid == rel->mid_recv)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "as expected\n");
        rel->mid_recv++;
        send_client_data (ch, msg, fwd);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "save for later\n");
        add_buffered_data (msg, rel);
      }
    }
    else
    {
      /* Tunnel is unreliable: send to clients directly */
      /* FIXME: accept Out Of Order traffic */
      rel->mid_recv = mid + 1;
      send_client_data (ch, msg, fwd);
    }
  }
  else
  {
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                " MID %u not expected (%u - %u), dropping!\n",
                mid, rel->mid_recv, rel->mid_recv + 64);
  }

  GMCH_send_ack (ch, fwd);
}


/**
 * Handler for mesh network traffic end-to-end ACKs.
 *
 * @param t Tunnel on which we got this message.
 * @param message Data message.
 * @param fwd Is this a fwd ACK? (dest->orig)
 */
void
GMCH_handle_data_ack (struct MeshChannel *ch,
                      const struct GNUNET_MESH_DataACK *msg,
                      int fwd)
{
  struct MeshChannelReliability *rel;
  struct MeshReliableMessage *copy;
  struct MeshReliableMessage *next;
  uint32_t ack;
  int work;

  ack = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! %s ACK %u\n",
              (GNUNET_YES == fwd) ? "FWD" : "BCK", ack);

  if (GNUNET_YES == fwd)
  {
    rel = ch->root_rel;
  }
  else
  {
    rel = ch->dest_rel;
  }
  if (NULL == rel)
  {
    GNUNET_break (0);
    return;
  }

  for (work = GNUNET_NO, copy = rel->head_sent; copy != NULL; copy = next)
  {
    if (GMC_is_pid_bigger (copy->mid, ack))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "!!!  head %u, out!\n", copy->mid);
      channel_rel_free_sent (rel, msg);
      break;
    }
    work = GNUNET_YES;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!!!  id %u\n", copy->mid);
    next = copy->next;
    rel_message_free (copy);
  }
  /* ACK client if needed */
//   channel_send_ack (t, type, GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK == type);

  /* If some message was free'd, update the retransmission delay*/
  if (GNUNET_YES == work)
  {
    if (GNUNET_SCHEDULER_NO_TASK != rel->retry_task)
    {
      GNUNET_SCHEDULER_cancel (rel->retry_task);
      if (NULL == rel->head_sent)
      {
        rel->retry_task = GNUNET_SCHEDULER_NO_TASK;
      }
      else
      {
        struct GNUNET_TIME_Absolute new_target;
        struct GNUNET_TIME_Relative delay;

        delay = GNUNET_TIME_relative_multiply (rel->retry_timer,
                                               MESH_RETRANSMIT_MARGIN);
        new_target = GNUNET_TIME_absolute_add (rel->head_sent->timestamp,
                                               delay);
        delay = GNUNET_TIME_absolute_get_remaining (new_target);
        rel->retry_task =
            GNUNET_SCHEDULER_add_delayed (delay,
                                          &channel_retransmit_message,
                                          rel);
      }
    }
    else
      GNUNET_break (0);
  }
}


/**
 * Handler for channel create messages.
 *
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 */
struct MeshChannel *
GMCH_handle_create (const struct GNUNET_MESH_ChannelCreate *msg,
                    int fwd)
{
  MESH_ChannelNumber chid;
  struct MeshChannel *ch;
  struct MeshClient *c;
  uint32_t port;

  chid = ntohl (msg->chid);

  /* Create channel */
  ch = channel_new (NULL, NULL, 0); /* FIXME pass t */
  ch->gid = chid;
  channel_set_options (ch, ntohl (msg->opt));

  /* Find a destination client */
  port = ntohl (msg->port);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   port %u\n", port);
  c = GML_client_get_by_port (port);
  if (NULL == c)
  {
    /* TODO send reject */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  no client has port registered\n");
    channel_destroy (ch);
    return NULL;
  }

  GMCH_add_client (ch, c);
  if (GNUNET_YES == ch->reliable)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!!! Reliable\n");

  GMCH_send_create (ch);
  GMCH_send_ack (ch, fwd);

  if (GNUNET_NO == ch->dest_rel->client_ready)
  {
    GML_send_ack (ch->dest, ch->lid_dest);
    ch->dest_rel->client_ready = GNUNET_YES;
  }

  return ch;
}


/**
 * Handler for channel ack messages.
 *
 * @param ch Channel.
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 */
void
GMCH_handle_ack (struct MeshChannel *ch,
                 const struct GNUNET_MESH_ChannelManage *msg,
                 int fwd)
{
  channel_confirm (ch, !fwd);
}


/**
 * Handler for channel destroy messages.
 *
 * @param ch Channel to be destroyed of.
 * @param msg Message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 */
void
GMCH_handle_destroy (struct MeshChannel *ch,
                     const struct GNUNET_MESH_ChannelManage *msg,
                     int fwd)
{
  if ( (fwd && NULL == ch->dest) || (!fwd && NULL == ch->root) )
  {
    /* Not for us (don't destroy twice a half-open loopback channel) */
    return;
  }

  GMCH_send_destroy (ch);
  channel_destroy (ch);
}


/**
 * Sends an already built message on a channel.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
void
GMCH_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                            struct MeshChannel *ch, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send on Channel %s:%X %s\n",
       GMT_2s (ch->t), ch->gid, fwd ? "FWD" : "BCK");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
       GNUNET_MESH_DEBUG_M2S (ntohs (message->type)));

  if (GMT_is_loopback (ch->t))
  {
    handle_loopback (ch, message, fwd);
    return;
  }

  GMT_send_prebuilt_message (message, ch->t, ch, fwd);
}
