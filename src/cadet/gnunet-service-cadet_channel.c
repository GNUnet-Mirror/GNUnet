/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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

#include "cadet.h"
#include "cadet_protocol.h"

#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_local.h"
#include "gnunet-service-cadet_tunnel.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"cadet-chn",__VA_ARGS__)

#define CADET_RETRANSMIT_TIME    GNUNET_TIME_relative_multiply(\
                                    GNUNET_TIME_UNIT_MILLISECONDS, 250)
#define CADET_RETRANSMIT_MARGIN  4


/**
 * All the states a connection can be in.
 */
enum CadetChannelState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  CADET_CHANNEL_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  CADET_CHANNEL_SENT,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  CADET_CHANNEL_READY,
};


/**
 * Info holder for channel messages in queues.
 */
struct CadetChannelQueue
{
  /**
   * Tunnel Queue.
   */
  struct CadetTunnelQueue *tq;

  /**
   * Message type (DATA/DATA_ACK)
   */
  uint16_t type;

  /**
   * Message copy (for DATAs, to start retransmission timer)
   */
  struct CadetReliableMessage *copy;

  /**
   * Reliability (for DATA_ACKs, to access rel->ack_q)
   */
  struct CadetChannelReliability *rel;
};


/**
 * Info needed to retry a message in case it gets lost.
 */
struct CadetReliableMessage
{
    /**
     * Double linked list, FIFO style
     */
  struct CadetReliableMessage   *next;
  struct CadetReliableMessage   *prev;

    /**
     * Type of message (payload, channel management).
     */
  int16_t                       type;

    /**
     * Tunnel Reliability queue this message is in.
     */
  struct CadetChannelReliability *rel;

    /**
     * ID of the message (ACK needed to free)
     */
  uint32_t                      mid;

  /**
   * Tunnel Queue.
   */
  struct CadetChannelQueue      *chq;

    /**
     * When was this message issued (to calculate ACK delay)
     */
  struct GNUNET_TIME_Absolute   timestamp;

  /* struct GNUNET_CADET_Data with payload */
};


/**
 * Info about the traffic state for a client in a channel.
 */
struct CadetChannelReliability
{
    /**
     * Channel this is about.
     */
  struct CadetChannel *ch;

    /**
     * DLL of messages sent and not yet ACK'd.
     */
  struct CadetReliableMessage        *head_sent;
  struct CadetReliableMessage        *tail_sent;

    /**
     * DLL of messages received out of order.
     */
  struct CadetReliableMessage        *head_recv;
  struct CadetReliableMessage        *tail_recv;

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
     * Handle for queued unique data CREATE, DATA_ACK.
     */
  struct CadetChannelQueue           *uniq;

    /**
     * Can we send data to the client?
     */
  int                               client_ready;

  /**
   * Can the client send data to us?
   */
  int                               client_allowed;

    /**
     * Task to resend/poll in case no ACK is received.
     */
  struct GNUNET_SCHEDULER_Task *   retry_task;

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
struct CadetChannel
{
    /**
     * Tunnel this channel is in.
     */
  struct CadetTunnel *t;

    /**
     * Destination port of the channel.
     */
  uint32_t port;

    /**
     * Global channel number ( < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
     */
  CADET_ChannelNumber gid;

    /**
     * Local tunnel number for root (owner) client.
     * ( >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI or 0 )
     */
  CADET_ChannelNumber lid_root;

    /**
     * Local tunnel number for local destination clients (incoming number)
     * ( >= GNUNET_CADET_LOCAL_CHANNEL_ID_SERV or 0).
     */
  CADET_ChannelNumber lid_dest;

    /**
     * Channel state.
     */
  enum CadetChannelState state;

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
  struct CadetClient *root;

    /**
     * Client destination of the tunnel, if any.
     */
  struct CadetClient *dest;

    /**
     * Flag to signal the destruction of the channel.
     * If this is set GNUNET_YES the channel will be destroyed
     * when the queue is empty.
     */
  int destroy;

    /**
     * Total (reliable) messages pending ACK for this channel.
     */
  unsigned int pending_messages;

    /**
     * Reliability data.
     * Only present (non-NULL) at the owner of a tunnel.
     */
  struct CadetChannelReliability *root_rel;

    /**
     * Reliability data.
     * Only present (non-NULL) at the destination of a tunnel.
     */
  struct CadetChannelReliability *dest_rel;

};


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (memory efficient handle).
 */
extern GNUNET_PEER_Id myid;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/


/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 *
 * @param copy Message that is no longer needed: remote peer got it.
 * @param update_time Is the timing information relevant?
 *                    If this message is ACK in a batch the timing information
 *                    is skewed by the retransmission, count only for the
 *                    retransmitted message.
 *
 * @return #GNUNET_YES if channel was destroyed as a result of the call,
 *         #GNUNET_NO otherwise.
 */
static int
rel_message_free (struct CadetReliableMessage *copy, int update_time);

/**
 * send a channel create message.
 *
 * @param ch Channel for which to send.
 */
static void
send_create (struct CadetChannel *ch);

/**
 * Confirm we got a channel create, FWD ack.
 *
 * @param ch The channel to confirm.
 * @param fwd Should we send a FWD ACK? (going dest->root)
 */
static void
send_ack (struct CadetChannel *ch, int fwd);



/**
 * Test if the channel is loopback: both root and dest are on the local peer.
 *
 * @param ch Channel to test.
 *
 * @return #GNUNET_YES if channel is loopback, #GNUNET_NO otherwise.
 */
static int
is_loopback (const struct CadetChannel *ch)
{
  if (NULL != ch->t)
    return GCT_is_loopback (ch->t);

  return (NULL != ch->root && NULL != ch->dest);
}


/**
 * Save a copy of the data message for later retransmission.
 *
 * @param msg Message to copy.
 * @param mid Message ID.
 * @param rel Reliability data for retransmission.
 */
static struct CadetReliableMessage *
copy_message (const struct GNUNET_CADET_Data *msg, uint32_t mid,
              struct CadetChannelReliability *rel)
{
  struct CadetReliableMessage *copy;
  uint16_t size;

  size = ntohs (msg->header.size);
  copy = GNUNET_malloc (sizeof (*copy) + size);
  copy->mid = mid;
  copy->rel = rel;
  copy->type = GNUNET_MESSAGE_TYPE_CADET_DATA;
  memcpy (&copy[1], msg, size);

  return copy;
}

/**
 * We have received a message out of order, or the client is not ready.
 * Buffer it until we receive an ACK from the client or the missing
 * message from the channel.
 *
 * @param msg Message to buffer (MUST be of type CADET_DATA).
 * @param rel Reliability data to the corresponding direction.
 */
static void
add_buffered_data (const struct GNUNET_CADET_Data *msg,
                   struct CadetChannelReliability *rel)
{
  struct CadetReliableMessage *copy;
  struct CadetReliableMessage *prev;
  uint32_t mid;

  mid = ntohl (msg->mid);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data MID %u (%u)\n",
       mid, rel->n_recv);

  rel->n_recv++;

  // FIXME do something better than O(n), although n < 64...
  // FIXME start from the end (most messages are the latest ones)
  for (prev = rel->head_recv; NULL != prev; prev = prev->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " prev %u\n", prev->mid);
    if (prev->mid == mid)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " already there!\n");
      rel->n_recv--;
      return;
    }
    else if (GC_is_pid_bigger (prev->mid, mid))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " bingo!\n");
      copy = copy_message (msg, mid, rel);
      GNUNET_CONTAINER_DLL_insert_before (rel->head_recv, rel->tail_recv,
                                          prev, copy);
      return;
    }
  }
  copy = copy_message (msg, mid, rel);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " insert at tail! (now: %u)\n", rel->n_recv);
  GNUNET_CONTAINER_DLL_insert_tail (rel->head_recv, rel->tail_recv, copy);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "add_buffered_data END\n");
}


/**
 * Add a destination client to a channel, initializing all data structures
 * in the channel and the client.
 *
 * @param ch Channel to which add the destination.
 * @param c Client which to add to the channel.
 */
static void
add_destination (struct CadetChannel *ch, struct CadetClient *c)
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
  ch->dest_rel = GNUNET_new (struct CadetChannelReliability);
  ch->dest_rel->ch = ch;
  ch->dest_rel->expected_delay.rel_value_us = 0;
  ch->dest_rel->retry_timer = CADET_RETRANSMIT_TIME;

  ch->dest = c;
}


/**
 * Set options in a channel, extracted from a bit flag field.
 *
 * @param ch Channel to set options to.
 * @param options Bit array in host byte order.
 */
static void
channel_set_options (struct CadetChannel *ch, uint32_t options)
{
  ch->nobuffer = (options & GNUNET_CADET_OPTION_NOBUFFER) != 0 ?
  GNUNET_YES : GNUNET_NO;
  ch->reliable = (options & GNUNET_CADET_OPTION_RELIABLE) != 0 ?
  GNUNET_YES : GNUNET_NO;
}


/**
 * Get a bit flag field with the options of a channel.
 *
 * @param ch Channel to get options from.
 *
 * @return Bit array in host byte order.
 */
static uint32_t
channel_get_options (struct CadetChannel *ch)
{
  uint32_t options;

  options = 0;
  if (ch->nobuffer)
    options |= GNUNET_CADET_OPTION_NOBUFFER;
  if (ch->reliable)
    options |= GNUNET_CADET_OPTION_RELIABLE;

  return options;
}


/**
 * Notify a client that the channel is no longer valid.
 *
 * @param ch Channel that is destroyed.
 * @param local_only Should we avoid sending it to other peers?
 */
static void
send_destroy (struct CadetChannel *ch, int local_only)
{
  struct GNUNET_CADET_ChannelManage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (ch->gid);

  /* If root is not NULL, notify.
   * If it's NULL, check lid_root. When a local destroy comes in, root
   * is set to NULL but lid_root is left untouched. In this case, do nothing,
   * the client is the one who requested the channel to be destroyed.
   */
  if (NULL != ch->root)
    GML_send_channel_destroy (ch->root, ch->lid_root);
  else if (0 == ch->lid_root && GNUNET_NO == local_only)
    GCCH_send_prebuilt_message (&msg.header, ch, GNUNET_NO, NULL);

  if (NULL != ch->dest)
    GML_send_channel_destroy (ch->dest, ch->lid_dest);
  else if (0 == ch->lid_dest && GNUNET_NO == local_only)
    GCCH_send_prebuilt_message (&msg.header, ch, GNUNET_YES, NULL);
}


/**
 * Notify the destination client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
static void
send_client_create (struct CadetChannel *ch)
{
  uint32_t opt;

  if (NULL == ch->dest)
    return;

  opt = 0;
  opt |= GNUNET_YES == ch->reliable ? GNUNET_CADET_OPTION_RELIABLE : 0;
  opt |= GNUNET_YES == ch->nobuffer ? GNUNET_CADET_OPTION_NOBUFFER : 0;
  GML_send_channel_create (ch->dest, ch->lid_dest, ch->port, opt,
                           GCT_get_destination (ch->t));

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
send_client_data (struct CadetChannel *ch,
                  const struct GNUNET_CADET_Data *msg,
                  int fwd)
{
  if (fwd)
  {
    if (ch->dest_rel->client_ready)
    {
      GML_send_data (ch->dest, msg, ch->lid_dest);
      ch->dest_rel->client_ready = GNUNET_NO;
      ch->dest_rel->mid_recv++;
    }
    else
      add_buffered_data (msg, ch->dest_rel);
  }
  else
  {
    if (ch->root_rel->client_ready)
    {
      GML_send_data (ch->root, msg, ch->lid_root);
      ch->root_rel->client_ready = GNUNET_NO;
      ch->root_rel->mid_recv++;
    }
    else
      add_buffered_data (msg, ch->root_rel);
  }
}


/**
 * Send a buffered message to the client, for in order delivery or
 * as result of client ACK.
 *
 * @param ch Channel on which to empty the message buffer.
 * @param c Client to send to.
 * @param fwd Is this to send FWD data?.
 */
static void
send_client_buffered_data (struct CadetChannel *ch,
                           struct CadetClient *c,
                           int fwd)
{
  struct CadetReliableMessage *copy;
  struct CadetChannelReliability *rel;

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
      struct GNUNET_CADET_Data *msg = (struct GNUNET_CADET_Data *) &copy[1];

      LOG (GNUNET_ERROR_TYPE_DEBUG, " have %u! now expecting %u\n",
           copy->mid, rel->mid_recv + 1);
      send_client_data (ch, msg, fwd);
      rel->n_recv--;
      GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
      LOG (GNUNET_ERROR_TYPE_DEBUG, " COPYFREE RECV %u (%p), %u left\n",
           copy->mid, copy, rel->n_recv);
      GNUNET_free (copy);
      GCCH_send_data_ack (ch, fwd);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " reliable && don't have %u, next is %u\n",
           rel->mid_recv, copy->mid);
      if (GNUNET_YES == ch->destroy)
      {
        /* We don't have the next data piece and the remote peer has closed the
         * channel. We won't receive it anymore, so just destroy the channel.
         * FIXME: wait some time to allow other connections to
         *        deliver missing messages
         */
        send_destroy (ch, GNUNET_YES);
        GCCH_destroy (ch);
      }
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_buffered_data END\n");
}


/**
 * Allow a client to send more data.
 *
 * In case the client was already allowed to send data, do nothing.
 *
 * @param ch Channel.
 * @param fwd Is this a FWD ACK? (FWD ACKs are sent to root)
 */
static void
send_client_ack (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel = fwd ? ch->root_rel : ch->dest_rel;
  struct CadetClient *c = fwd ? ch->root : ch->dest;

  if (NULL == c)
  {
    GNUNET_break (GNUNET_NO != ch->destroy);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  sending %s ack to client on channel %s\n",
       GC_f2s (fwd), GCCH_2s (ch));

  if (NULL == rel)
  {
    GNUNET_break (0);
    return;
  }

  if (GNUNET_YES == rel->client_allowed)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  already allowed\n");
    return;
  }
  rel->client_allowed = GNUNET_YES;

  GML_send_ack (c, fwd ? ch->lid_root : ch->lid_dest);
}


/**
 * Notify the root that the destination rejected the channel.
 *
 * @param ch Rejected channel.
 */
static void
send_client_nack (struct CadetChannel *ch)
{
  if (NULL == ch->root)
  {
    GNUNET_break (0);
    return;
  }
  GML_send_channel_nack (ch->root, ch->lid_root);
}


/**
 * We haven't received an ACK after a certain time: restransmit the message.
 *
 * @param cls Closure (CadetChannelReliability with the message to restransmit)
 * @param tc TaskContext.
 */
static void
channel_retransmit_message (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetChannelReliability *rel = cls;
  struct CadetReliableMessage *copy;
  struct CadetChannel *ch;
  struct GNUNET_CADET_Data *payload;
  int fwd;

  rel->retry_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  ch = rel->ch;
  copy = rel->head_sent;
  if (NULL == copy)
  {
    GNUNET_break (0); // FIXME tripped in rps testcase
    return;
  }

  payload = (struct GNUNET_CADET_Data *) &copy[1];
  fwd = (rel == ch->root_rel);

  /* Message not found in the queue that we are going to use. */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "RETRANSMIT MID %u\n", copy->mid);

  GCCH_send_prebuilt_message (&payload->header, ch, fwd, copy);
  GNUNET_STATISTICS_update (stats, "# data retransmitted", 1, GNUNET_NO);
}


/**
 * We haven't received an Channel ACK after a certain time: resend the CREATE.
 *
 * @param cls Closure (CadetChannelReliability of the channel to recreate)
 * @param tc TaskContext.
 */
static void
channel_recreate (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetChannelReliability *rel = cls;

  rel->retry_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "RE-CREATE\n");
  GNUNET_STATISTICS_update (stats, "# data retransmitted", 1, GNUNET_NO);

  if (rel == rel->ch->root_rel)
  {
    send_create (rel->ch);
  }
  else if (rel == rel->ch->dest_rel)
  {
    send_ack (rel->ch, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }

}


/**
 * Message has been sent: start retransmission timer.
 *
 * @param cls Closure (queue structure).
 * @param t Tunnel.
 * @param q Queue handler (no longer valid).
 * @param type Type of message.
 * @param size Size of the message.
 */
static void
ch_message_sent (void *cls,
                 struct CadetTunnel *t,
                 struct CadetTunnelQueue *q,
                 uint16_t type, size_t size)
{
  struct CadetChannelQueue *chq = cls;
  struct CadetReliableMessage *copy = chq->copy;
  struct CadetChannelReliability *rel;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "channel_message_sent callback %s\n",
       GC_m2s (chq->type));

  switch (chq->type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "data MID %u sent\n", copy->mid);
      GNUNET_assert (chq == copy->chq);
      copy->timestamp = GNUNET_TIME_absolute_get ();
      rel = copy->rel;
      if (NULL == rel->retry_task)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  scheduling retry in 4 * %s\n",
             GNUNET_STRINGS_relative_time_to_string (rel->expected_delay,
                                                     GNUNET_YES));
        if (0 != rel->expected_delay.rel_value_us)
        {
          rel->retry_timer =
          GNUNET_TIME_relative_multiply (rel->expected_delay,
                                         CADET_RETRANSMIT_MARGIN);
        }
        else
        {
          rel->retry_timer = CADET_RETRANSMIT_TIME;
        }
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  using delay %s\n",
             GNUNET_STRINGS_relative_time_to_string (rel->retry_timer,
                                                     GNUNET_NO));
        rel->retry_task =
            GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                          &channel_retransmit_message, rel);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "retry running %p\n", rel->retry_task);
      }
      copy->chq = NULL;
      break;


    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "sent %s\n", GC_m2s (chq->type));
      rel = chq->rel;
      GNUNET_assert (rel->uniq == chq);
      rel->uniq = NULL;

      if (CADET_CHANNEL_READY != rel->ch->state
          && GNUNET_MESSAGE_TYPE_CADET_DATA_ACK != type
          && GNUNET_NO == rel->ch->destroy)
      {
        GNUNET_assert (NULL == rel->retry_task);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "STD BACKOFF %s\n",
             GNUNET_STRINGS_relative_time_to_string (rel->retry_timer,
                                                     GNUNET_NO));
        rel->retry_timer = GNUNET_TIME_STD_BACKOFF (rel->retry_timer);
        rel->retry_task = GNUNET_SCHEDULER_add_delayed (rel->retry_timer,
                                                        &channel_recreate, rel);
      }
      break;

    default:
      GNUNET_break (0);
  }

  GNUNET_free (chq);
}


/**
 * send a channel create message.
 *
 * @param ch Channel for which to send.
 */
static void
send_create (struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelCreate msgcc;

  msgcc.header.size = htons (sizeof (msgcc));
  msgcc.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE);
  msgcc.chid = htonl (ch->gid);
  msgcc.port = htonl (ch->port);
  msgcc.opt = htonl (channel_get_options (ch));

  GCCH_send_prebuilt_message (&msgcc.header, ch, GNUNET_YES, NULL);
}


/**
 * Confirm we got a channel create or FWD ack.
 *
 * @param ch The channel to confirm.
 * @param fwd Should we send a FWD ACK? (going dest->root)
 */
static void
send_ack (struct CadetChannel *ch, int fwd)
{
  struct GNUNET_CADET_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending channel %s ack for channel %s\n",
       GC_f2s (fwd), GCCH_2s (ch));

  msg.chid = htonl (ch->gid);
  GCCH_send_prebuilt_message (&msg.header, ch, !fwd, NULL);
}


/**
 * Send a message and don't keep any info about it: we won't need to cancel it
 * or resend it.
 *
 * @param msg Header of the message to fire away.
 * @param ch Channel on which the message should go.
 * @param force Is this a forced (undroppable) message?
 */
static void
fire_and_forget (const struct GNUNET_MessageHeader *msg,
                 struct CadetChannel *ch,
                 int force)
{
  GNUNET_break (NULL == GCT_send_prebuilt_message (msg, ch->t, NULL,
                                                   force, NULL, NULL));
}


/**
 * Notify that a channel create didn't succeed.
 *
 * @param ch The channel to reject.
 */
static void
send_nack (struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  sending channel NACK for channel %s\n",
       GCCH_2s (ch));

  msg.chid = htonl (ch->gid);
  GCCH_send_prebuilt_message (&msg.header, ch, GNUNET_NO, NULL);
}


/**
 * Destroy all reliable messages queued for a channel,
 * during a channel destruction.
 * Frees the reliability structure itself.
 *
 * @param rel Reliability data for a channel.
 */
static void
channel_rel_free_all (struct CadetChannelReliability *rel)
{
  struct CadetReliableMessage *copy;
  struct CadetReliableMessage *next;

  if (NULL == rel)
    return;

  for (copy = rel->head_recv; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_recv, rel->tail_recv, copy);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " COPYFREE ALL RECV %p\n", copy);
    GNUNET_break (NULL == copy->chq);
    GNUNET_free (copy);
  }
  for (copy = rel->head_sent; NULL != copy; copy = next)
  {
    next = copy->next;
    GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " COPYFREE ALL SEND %p\n", copy);
    if (NULL != copy->chq)
    {
      if (NULL != copy->chq->tq)
      {
        GCT_cancel (copy->chq->tq);
        /* ch_message_sent will free copy->q */
      }
      else
      {
        GNUNET_free (copy->chq);
        GNUNET_break (0);
      }
    }
    GNUNET_free (copy);
  }
  if (NULL != rel->uniq && NULL != rel->uniq->tq)
  {
    GCT_cancel (rel->uniq->tq);
    /* ch_message_sent is called freeing uniq */
  }
  if (NULL != rel->retry_task)
  {
    GNUNET_SCHEDULER_cancel (rel->retry_task);
    rel->retry_task = NULL;
  }
  GNUNET_free (rel);
}


/**
 * Mark future messages as ACK'd.
 *
 * @param rel Reliability data.
 * @param msg DataACK message with a bitfield of future ACK'd messages.
 */
static void
channel_rel_free_sent (struct CadetChannelReliability *rel,
                       const struct GNUNET_CADET_DataACK *msg)
{
  struct CadetReliableMessage *copy;
  struct CadetReliableMessage *next;
  uint64_t bitfield;
  uint64_t mask;
  uint32_t mid;
  uint32_t target;
  unsigned int i;

  bitfield = msg->futures;
  mid = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "free_sent_reliable %u %llX\n", mid, bitfield);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " rel %p, head %p\n", rel, rel->head_sent);
  for (i = 0, copy = rel->head_sent;
       i < 64 && NULL != copy && 0 != bitfield;
       i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " trying bit %u (mid %u)\n", i, mid + i + 1);
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
    while (NULL != copy && GC_is_pid_bigger (target, copy->mid))
      copy = copy->next;

    /* Did we run out of copies? (previously freed, it's ok) */
    if (NULL == copy)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "run out of copies...\n");
      return;
    }

    /* Did we overshoot the target? (previously freed, it's ok) */
    if (GC_is_pid_bigger (copy->mid, target))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " next copy %u\n", copy->mid);
      i += copy->mid - target - 1;   /* MID: 90, t = 85, i += 4 (i++ later) */
      mask = (0x1LL << (i + 1)) - 1; /* Mask = i-th bit and all before */
      bitfield &= ~mask;             /* Clear all bits up to MID - 1 */
      continue;
    }

    /* Now copy->mid == target, free it */
    next = copy->next;
    GNUNET_break (GNUNET_YES != rel_message_free (copy, GNUNET_YES));
    copy = next;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "free_sent_reliable END\n");
}


/**
 * Destroy a reliable message after it has been acknowledged, either by
 * direct mid ACK or bitfield. Updates the appropriate data structures and
 * timers and frees all memory.
 *
 * @param copy Message that is no longer needed: remote peer got it.
 * @param update_time Is the timing information relevant?
 *                    If this message is ACK in a batch the timing information
 *                    is skewed by the retransmission, count only for the
 *                    retransmitted message.
 *
 * @return #GNUNET_YES if channel was destroyed as a result of the call,
 *         #GNUNET_NO otherwise.
 */
static int
rel_message_free (struct CadetReliableMessage *copy, int update_time)
{
  struct CadetChannelReliability *rel;
  struct GNUNET_TIME_Relative time;

  rel = copy->rel;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "TIME Freeing %u\n", copy->mid);
  if (update_time)
  {
    time = GNUNET_TIME_absolute_get_duration (copy->timestamp);
    if (0 == rel->expected_delay.rel_value_us)
      rel->expected_delay = time;
    else
    {
      rel->expected_delay.rel_value_us *= 7;
      rel->expected_delay.rel_value_us += time.rel_value_us;
      rel->expected_delay.rel_value_us /= 8;
    }
    LOG (GNUNET_ERROR_TYPE_INFO, "TIME  message   %12s\n",
         GNUNET_STRINGS_relative_time_to_string (time, GNUNET_NO));
    LOG (GNUNET_ERROR_TYPE_INFO, "TIME  new delay %12s\n",
         GNUNET_STRINGS_relative_time_to_string (rel->expected_delay,
                                                 GNUNET_NO));
    rel->retry_timer = rel->expected_delay;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "TIME batch free, ignoring timing\n");
  }
  rel->ch->pending_messages--;
  if (NULL != copy->chq)
  {
    GCT_cancel (copy->chq->tq);
    /* copy->q is set to NULL by ch_message_sent */
  }
  GNUNET_CONTAINER_DLL_remove (rel->head_sent, rel->tail_sent, copy);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " COPYFREE SEND %p\n", copy);
  GNUNET_free (copy);

  if (GNUNET_NO != rel->ch->destroy && 0 == rel->ch->pending_messages)
  {
    GCCH_destroy (rel->ch);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Channel was ACK'd by remote peer, mark as ready and cancel retransmission.
 *
 * @param ch Channel to mark as ready.
 * @param fwd Was the ACK message a FWD ACK? (dest->root, SYNACK)
 */
static void
channel_confirm (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel;
  enum CadetChannelState oldstate;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  if (NULL == rel)
  {
    GNUNET_break (GNUNET_NO != ch->destroy);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  channel confirm %s %s\n",
       GC_f2s (fwd), GCCH_2s (ch));
  oldstate = ch->state;
  ch->state = CADET_CHANNEL_READY;

  if (CADET_CHANNEL_READY != oldstate || GNUNET_YES == is_loopback (ch))
  {
    rel->client_ready = GNUNET_YES;
    rel->expected_delay = rel->retry_timer;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  confirm retry timer %s\n",
         GNUNET_STRINGS_relative_time_to_string (rel->retry_timer, GNUNET_NO));
    if (GCT_get_connections_buffer (ch->t) > 0 || GCT_is_loopback (ch->t))
      send_client_ack (ch, fwd);

    if (NULL != rel->retry_task)
    {
      GNUNET_SCHEDULER_cancel (rel->retry_task);
      rel->retry_task = NULL;
    }
    else if (NULL != rel->uniq)
    {
      GCT_cancel (rel->uniq->tq);
      /* ch_message_sent will free and NULL uniq */
    }
    else if (GNUNET_NO == is_loopback (ch))
    {
      /* We SHOULD have been trying to retransmit this! */
      GNUNET_break (0);
    }
  }

  /* In case of a FWD ACK (SYNACK) send a BCK ACK (ACK). */
  if (GNUNET_YES == fwd)
    send_ack (ch, GNUNET_NO);
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
static struct CadetReliableMessage *
channel_save_copy (struct CadetChannel *ch,
                   const struct GNUNET_MessageHeader *msg,
                   int fwd)
{
  struct CadetChannelReliability *rel;
  struct CadetReliableMessage *copy;
  uint32_t mid;
  uint16_t type;
  uint16_t size;

  rel = fwd ? ch->root_rel : ch->dest_rel;
  mid = rel->mid_send - 1;
  type = ntohs (msg->type);
  size = ntohs (msg->size);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "save MID %u %s\n", mid, GC_m2s (type));
  copy = GNUNET_malloc (sizeof (struct CadetReliableMessage) + size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  at %p\n", copy);
  copy->mid = mid;
  copy->rel = rel;
  copy->type = type;
  memcpy (&copy[1], msg, size);
  GNUNET_CONTAINER_DLL_insert_tail (rel->head_sent, rel->tail_sent, copy);
  ch->pending_messages++;

  return copy;
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
static struct CadetChannel *
channel_new (struct CadetTunnel *t,
             struct CadetClient *owner,
             CADET_ChannelNumber lid_root)
{
  struct CadetChannel *ch;

  ch = GNUNET_new (struct CadetChannel);
  ch->root = owner;
  ch->lid_root = lid_root;
  ch->t = t;

  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);

  if (NULL != owner)
  {
    ch->gid = GCT_get_next_chid (t);
    GML_channel_add (owner, lid_root, ch);
  }
  GCT_add_channel (t, ch);

  return ch;
}


/**
 * Handle a loopback message: call the appropriate handler for the message type.
 *
 * @param ch Channel this message is on.
 * @param msgh Message header.
 * @param fwd Is this FWD traffic?
 */
void
handle_loopback (struct CadetChannel *ch,
                 const struct GNUNET_MessageHeader *msgh,
                 int fwd)
{
  uint16_t type;

  type = ntohs (msgh->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Loopback %s %s message!\n",
       GC_f2s (fwd), GC_m2s (type));

  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "SEND loopback %u (%u)\n",
           ntohl (((struct GNUNET_CADET_Data *) msgh)->mid), ntohs (msgh->size));
      GCCH_handle_data (ch, (struct GNUNET_CADET_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
      GCCH_handle_data_ack (ch, (struct GNUNET_CADET_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
      GCCH_handle_create (ch->t,
                          (struct GNUNET_CADET_ChannelCreate *) msgh);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
      GCCH_handle_ack (ch,
                       (struct GNUNET_CADET_ChannelManage *) msgh,
                       fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK:
      GCCH_handle_nack (ch);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
      GCCH_handle_destroy (ch,
                           (struct GNUNET_CADET_ChannelManage *) msgh,
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
 * Destroy a channel and free all resources.
 *
 * @param ch Channel to destroy.
 */
void
GCCH_destroy (struct CadetChannel *ch)
{
  struct CadetClient *c;
  struct CadetTunnel *t;

  if (NULL == ch)
    return;
  if (2 == ch->destroy)
    return; /* recursive call */
  ch->destroy = 2;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying channel %s:%u\n",
              GCT_2s (ch->t), ch->gid);
  GCCH_debug (ch);

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

  t = ch->t;
  GCT_remove_channel (t, ch);
  GNUNET_STATISTICS_update (stats, "# channels", -1, GNUNET_NO);

  GNUNET_free (ch);
  GCT_destroy_if_empty (t);
}


/**
 * Get the channel's public ID.
 *
 * @param ch Channel.
 *
 * @return ID used to identify the channel with the remote peer.
 */
CADET_ChannelNumber
GCCH_get_id (const struct CadetChannel *ch)
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
struct CadetTunnel *
GCCH_get_tunnel (const struct CadetChannel *ch)
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
GCCH_get_buffer (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel;

  rel = fwd ? ch->dest_rel : ch->root_rel;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   get buffer, channel %s\n", GCCH_2s (ch));
  GCCH_debug (ch);
  /* If rel is NULL it means that the end is not yet created,
   * most probably is a loopback channel at the point of sending
   * the ChannelCreate to itself.
   */
  if (NULL == rel)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  rel is NULL: max\n");
    return 64;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "   n_recv %d\n", rel->n_recv);
  return (64 - rel->n_recv);
}


/**
 * Get flow control status of end point: is client allow to send?
 *
 * @param ch Channel.
 * @param fwd Is query about FWD traffic? (Request root status).
 *
 * @return #GNUNET_YES if client is allowed to send us data.
 */
int
GCCH_get_allowed (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel;

  rel = fwd ? ch->root_rel : ch->dest_rel;

  if (NULL == rel)
  {
    /* Probably shutting down: root/dest NULL'ed to mark disconnection */
    GNUNET_break (GNUNET_NO != ch->destroy);
    return 0;
  }

  return rel->client_allowed;
}


/**
 * Is the root client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return #GNUNET_YES in case it is.
 */
int
GCCH_is_origin (struct CadetChannel *ch, int fwd)
{
  struct CadetClient *c;

  c = fwd ? ch->root : ch->dest;
  return NULL != c;
}


/**
 * Is the destination client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return #GNUNET_YES in case it is.
 */
int
GCCH_is_terminal (struct CadetChannel *ch, int fwd)
{
  struct CadetClient *c;

  c = fwd ? ch->dest : ch->root;
  return NULL != c;
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
GCCH_send_data_ack (struct CadetChannel *ch, int fwd)
{
  struct GNUNET_CADET_DataACK msg;
  struct CadetChannelReliability *rel;
  struct CadetReliableMessage *copy;
  unsigned int delta;
  uint64_t mask;
  uint32_t ack;

  if (GNUNET_NO == ch->reliable)
    return;

  rel = fwd ? ch->dest_rel : ch->root_rel;
  ack = rel->mid_recv - 1;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_DATA_ACK);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (ch->gid);
  msg.mid = htonl (ack);

  msg.futures = 0LL;
  for (copy = rel->head_recv; NULL != copy; copy = copy->next)
  {
    if (copy->type != GNUNET_MESSAGE_TYPE_CADET_DATA)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " Type %s, expected DATA\n",
           GC_m2s (copy->type));
      continue;
    }
    GNUNET_assert (GC_is_pid_bigger(copy->mid, ack));
    delta = copy->mid - (ack + 1);
    if (63 < delta)
      break;
    mask = 0x1LL << delta;
    msg.futures |= mask;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         " setting bit for %u (delta %u) (%llX) -> %llX\n",
         copy->mid, delta, mask, msg.futures);
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "===> DATA_ACK for %u + %llX\n",
       ack, msg.futures);

  GCCH_send_prebuilt_message (&msg.header, ch, !fwd, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_data_ack END\n");
}


/**
 * Allow a client to send us more data, in case it was choked.
 *
 * @param ch Channel.
 * @param fwd Is this about FWD traffic? (Root client).
 */
void
GCCH_allow_client (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel;
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMCH allow\n");

  if (CADET_CHANNEL_READY != ch->state)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " channel not ready yet!\n");
    return;
  }

  if (GNUNET_YES == ch->reliable)
  {
    rel = fwd ? ch->root_rel : ch->dest_rel;
    if (NULL == rel)
    {
      GNUNET_break (GNUNET_NO != ch->destroy);
      return;
    }
    if (NULL != rel->head_sent)
    {
      if (64 <= rel->mid_send - rel->head_sent->mid)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, " too big MID gap! Wait for ACK.\n");
        return;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, " gap ok: %u - %u\n",
             rel->head_sent->mid, rel->mid_send);
        struct CadetReliableMessage *aux;
        for (aux = rel->head_sent; NULL != aux; aux = aux->next)
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG, "   - sent mid %u\n", aux->mid);
        }
      }
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " head sent is NULL\n");
    }
  }

  if (is_loopback (ch))
    buffer = GCCH_get_buffer (ch, fwd);
  else
    buffer = GCT_get_connections_buffer (ch->t);

  if (0 == buffer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " no buffer space.\n");
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, " buffer space %u, allowing\n", buffer);
  send_client_ack (ch, fwd);
}


/**
 * Log channel info.
 *
 * @param ch Channel.
 */
void
GCCH_debug (struct CadetChannel *ch)
{
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*** DEBUG NULL CHANNEL ***\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %s:%X (%p)\n",
              GCT_2s (ch->t), ch->gid, ch);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  root %p/%p\n",
              ch->root, ch->root_rel);
  if (NULL != ch->root)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cli %s\n", GML_2s (ch->root));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ready %s\n",
                ch->root_rel->client_ready ? "YES" : "NO");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  id %X\n", ch->lid_root);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  recv %d\n", ch->root_rel->n_recv);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  MID r: %d, s: %d\n",
         ch->root_rel->mid_recv, ch->root_rel->mid_send);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  dest %p/%p\n",
              ch->dest, ch->dest_rel);
  if (NULL != ch->dest)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cli %s\n", GML_2s (ch->dest));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ready %s\n",
                ch->dest_rel->client_ready ? "YES" : "NO");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  id %X\n", ch->lid_dest);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  recv %d\n", ch->dest_rel->n_recv);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  MID r: %d, s: %d\n",
         ch->dest_rel->mid_recv, ch->dest_rel->mid_send);

  }
}


/**
 * Handle an ACK given by a client.
 *
 * Mark client as ready and send him any buffered data we could have for him.
 *
 * @param ch Channel.
 * @param fwd Is this a "FWD ACK"? (FWD ACKs are sent by dest and go BCK)
 */
void
GCCH_handle_local_ack (struct CadetChannel *ch, int fwd)
{
  struct CadetChannelReliability *rel;
  struct CadetClient *c;

  rel = fwd ? ch->dest_rel : ch->root_rel;
  c   = fwd ? ch->dest     : ch->root;

  rel->client_ready = GNUNET_YES;
  send_client_buffered_data (ch, c, fwd);

  if (GNUNET_YES == ch->destroy && 0 == rel->n_recv)
  {
    send_destroy (ch, GNUNET_YES);
    GCCH_destroy (ch);
    return;
  }
  /* if loopback is marked for destruction, no need to ACK to the other peer,
   * it requested the destruction and is already gone, therefore, else if.
   */
  else if (is_loopback (ch))
  {
    unsigned int buffer;

    buffer = GCCH_get_buffer (ch, fwd);
    if (0 < buffer)
      GCCH_allow_client (ch, fwd);

    return;
  }
  GCT_send_connection_acks (ch->t);
}


/**
 * Handle data given by a client.
 *
 * Check whether the client is allowed to send in this tunnel, save if channel
 * is reliable and send an ACK to the client if there is still buffer space
 * in the tunnel.
 *
 * @param ch Channel.
 * @param c Client which sent the data.
 * @param fwd Is this a FWD data?
 * @param message Data message.
 * @param size Size of data.
 *
 * @return GNUNET_OK if everything goes well, GNUNET_SYSERR in case of en error.
 */
int
GCCH_handle_local_data (struct CadetChannel *ch,
                        struct CadetClient *c, int fwd,
                        const struct GNUNET_MessageHeader *message,
                        size_t size)
{
  struct CadetChannelReliability *rel;
  struct GNUNET_CADET_Data *payload;
  uint16_t p2p_size = sizeof(struct GNUNET_CADET_Data) + size;
  unsigned char cbuf[p2p_size];
  unsigned char buffer;

  /* Is the client in the channel? */
  if ( !( (fwd &&
           ch->root == c)
         ||
          (!fwd &&
           ch->dest == c) ) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  rel = fwd ? ch->root_rel : ch->dest_rel;

  if (GNUNET_NO == rel->client_allowed)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  rel->client_allowed = GNUNET_NO;

  /* Ok, everything is correct, send the message. */
  payload = (struct GNUNET_CADET_Data *) cbuf;
  payload->mid = htonl (rel->mid_send);
  rel->mid_send++;
  memcpy (&payload[1], message, size);
  payload->header.size = htons (p2p_size);
  payload->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_DATA);
  payload->chid = htonl (ch->gid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on channel...\n");
  GCCH_send_prebuilt_message (&payload->header, ch, fwd, NULL);

  if (is_loopback (ch))
    buffer = GCCH_get_buffer (ch, fwd);
  else
    buffer = GCT_get_connections_buffer (ch->t);

  if (0 < buffer)
    GCCH_allow_client (ch, fwd);

  return GNUNET_OK;
}


/**
 * Handle a channel destroy requested by a client.
 *
 * TODO: add "reason" field
 *
 * Destroy the channel and the tunnel in case this was the last channel.
 *
 * @param ch Channel.
 * @param c Client that requested the destruction (to avoid notifying him).
 * @param is_root Is the request coming from root?
 */
void
GCCH_handle_local_destroy (struct CadetChannel *ch,
                           struct CadetClient *c,
                           int is_root)
{
  ch->destroy = GNUNET_YES;
  /* Cleanup after the tunnel */
  if (GNUNET_NO == is_root && c == ch->dest)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " Client %s is destination.\n", GML_2s (c));
    GML_client_delete_channel (c, ch, ch->lid_dest);
    ch->dest = NULL;
  }
  if (GNUNET_YES == is_root && c == ch->root)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " Client %s is owner.\n", GML_2s (c));
    GML_client_delete_channel (c, ch, ch->lid_root);
    ch->root = NULL;
  }

  send_destroy (ch, GNUNET_NO);
  if (0 == ch->pending_messages)
    GCCH_destroy (ch);
}


/**
 * Handle a channel create requested by a client.
 *
 * Create the channel and the tunnel in case this was the first0 channel.
 *
 * @param c Client that requested the creation (will be the root).
 * @param msg Create Channel message.
 *
 * @return GNUNET_OK if everything went fine, GNUNET_SYSERR otherwise.
 */
int
GCCH_handle_local_create (struct CadetClient *c,
                          struct GNUNET_CADET_ChannelMessage *msg)
{
  struct CadetChannel *ch;
  struct CadetTunnel *t;
  struct CadetPeer *peer;
  CADET_ChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  towards %s:%u\n",
              GNUNET_i2s (&msg->peer), ntohl (msg->port));
  chid = ntohl (msg->channel_id);

  /* Sanity check for duplicate channel IDs */
  if (NULL != GML_channel_get (c, chid))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  peer = GCP_get (&msg->peer);
  GCP_add_tunnel (peer);
  t = GCP_get_tunnel (peer);

  if (GCP_get_short_id (peer) == myid)
  {
    GCT_change_cstate (t, CADET_TUNNEL_READY);
  }
  else
  {
    /* FIXME change to a tunnel API, eliminate ch <-> peer connection */
    GCP_connect (peer);
  }

  /* Create channel */
  ch = channel_new (t, c, chid);
  if (NULL == ch)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ch->port = ntohl (msg->port);
  channel_set_options (ch, ntohl (msg->opt));

  /* In unreliable channels, we'll use the DLL to buffer BCK data */
  ch->root_rel = GNUNET_new (struct CadetChannelReliability);
  ch->root_rel->ch = ch;
  ch->root_rel->retry_timer = CADET_RETRANSMIT_TIME;
  ch->root_rel->expected_delay.rel_value_us = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "CREATED CHANNEL %s\n", GCCH_2s (ch));

  send_create (ch);

  return GNUNET_OK;
}


/**
 * Handler for cadet network payload traffic.
 *
 * @param ch Channel for the message.
 * @param msg Unencryted data message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GCCH_handle_data (struct CadetChannel *ch,
                  const struct GNUNET_CADET_Data *msg,
                  int fwd)
{
  struct CadetChannelReliability *rel;
  struct CadetClient *c;
  uint32_t mid;

  /* If this is a remote (non-loopback) channel, find 'fwd'. */
  if (GNUNET_SYSERR == fwd)
  {
    if (is_loopback (ch))
    {
      /* It is a loopback channel after all... */
      GNUNET_break (0);
      return;
    }
    fwd = (NULL != ch->dest) ? GNUNET_YES : GNUNET_NO;
  }

  /*  Initialize FWD/BCK data */
  c   = fwd ? ch->dest     : ch->root;
  rel = fwd ? ch->dest_rel : ch->root_rel;

  if (NULL == c)
  {
    GNUNET_break (GNUNET_NO != ch->destroy);
    return;
  }

  if (CADET_CHANNEL_READY != ch->state)
  {
    if (GNUNET_NO == fwd)
    {
      /* If we are the root, this means the other peer has sent traffic before
       * receiving our ACK. Even if the SYNACK goes missing, no traffic should
       * be sent before the ACK.
       */
      GNUNET_break_op (0);
      return;
    }
    /* If we are the dest, this means that the SYNACK got to the root but
     * the ACK went missing. Treat this as an ACK.
     */
    channel_confirm (ch, GNUNET_NO);
  }

  GNUNET_STATISTICS_update (stats, "# data received", 1, GNUNET_NO);

  mid = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_INFO, "<=== DATA %u %s on channel %s\n",
       mid, GC_f2s (fwd), GCCH_2s (ch));

  if (GNUNET_NO == ch->reliable ||
      ( !GC_is_pid_bigger (rel->mid_recv, mid) &&
        GC_is_pid_bigger (rel->mid_recv + 64, mid) ) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "RECV MID %u (%u)\n",
         mid, ntohs (msg->header.size));
    if (GNUNET_YES == ch->reliable)
    {
      /* Is this the exact next expected messasge? */
      if (mid == rel->mid_recv)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "as expected, sending to client\n");
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
    if (GC_is_pid_bigger (rel->mid_recv, mid))
    {
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_WARNING,
          "MID %u on channel %s not expected (window: %u - %u). Dropping!\n",
          mid, GCCH_2s (ch), rel->mid_recv, rel->mid_recv + 63);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Duplicate MID %u, channel %s (expecting MID %u). Re-sending ACK!\n",
           mid, GCCH_2s (ch), rel->mid_recv);
      if (NULL != rel->uniq)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
            "We are trying to send an ACK, but don't seem have the "
            "bandwidth. Try to increase your ats QUOTA in you config file\n");
      }

    }
  }

  GCCH_send_data_ack (ch, fwd);
}


/**
 * Handler for cadet network traffic end-to-end ACKs.
 *
 * @param ch Channel on which we got this message.
 * @param msg Data message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GCCH_handle_data_ack (struct CadetChannel *ch,
                      const struct GNUNET_CADET_DataACK *msg,
                      int fwd)
{
  struct CadetChannelReliability *rel;
  struct CadetReliableMessage *copy;
  struct CadetReliableMessage *next;
  uint32_t ack;
  int work;

  /* If this is a remote (non-loopback) channel, find 'fwd'. */
  if (GNUNET_SYSERR == fwd)
  {
    if (is_loopback (ch))
    {
      /* It is a loopback channel after all... */
      GNUNET_break (0);
      return;
    }
    /* Inverted: if message came 'FWD' is a 'BCK ACK'. */
    fwd = (NULL != ch->dest) ? GNUNET_NO : GNUNET_YES;
  }

  ack = ntohl (msg->mid);
  LOG (GNUNET_ERROR_TYPE_INFO, "<=== %s ACK %u + %llX\n",
       GC_f2s (fwd), ack, msg->futures);

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
    GNUNET_break_op (GNUNET_NO != ch->destroy);
    return;
  }

  /* Free ACK'd copies: no need to retransmit those anymore FIXME refactor */
  for (work = GNUNET_NO, copy = rel->head_sent; copy != NULL; copy = next)
  {
    if (GC_is_pid_bigger (copy->mid, ack))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  head %u, out!\n", copy->mid);
      channel_rel_free_sent (rel, msg);
      break;
    }
    work = GNUNET_YES;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  id %u\n", copy->mid);
    next = copy->next;
    if (GNUNET_YES == rel_message_free (copy, GNUNET_YES))
      return;
  }

  /* ACK client if needed and possible */
  GCCH_allow_client (ch, fwd);

  /* If some message was free'd, update the retransmission delay */
  if (GNUNET_YES == work)
  {
    if (NULL != rel->retry_task)
    {
      GNUNET_SCHEDULER_cancel (rel->retry_task);
      rel->retry_task = NULL;
      if (NULL != rel->head_sent && NULL == rel->head_sent->chq)
      {
        struct GNUNET_TIME_Absolute new_target;
        struct GNUNET_TIME_Relative delay;

        delay = GNUNET_TIME_relative_multiply (rel->retry_timer,
                                               CADET_RETRANSMIT_MARGIN);
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
    {
      /* Work was done but no task was pending? Shouldn't happen! */
      GNUNET_break (0);
    }
  }
}


/**
 * Handler for channel create messages.
 *
 * Does not have fwd parameter because it's always 'FWD': channel is incoming.
 *
 * @param t Tunnel this channel will be in.
 * @param msg Channel crate message.
 */
struct CadetChannel *
GCCH_handle_create (struct CadetTunnel *t,
                    const struct GNUNET_CADET_ChannelCreate *msg)
{
  CADET_ChannelNumber chid;
  struct CadetChannel *ch;
  struct CadetClient *c;
  int new_channel;

  chid = ntohl (msg->chid);
  ch = GCT_get_channel (t, chid);
  if (NULL == ch)
  {
    /* Create channel */
    ch = channel_new (t, NULL, 0);
    ch->gid = chid;
    channel_set_options (ch, ntohl (msg->opt));
    new_channel = GNUNET_YES;
  }
  else
  {
    new_channel = GNUNET_NO;
  }

  if (GNUNET_YES == new_channel || GCT_is_loopback (t))
  {
    /* Find a destination client */
    ch->port = ntohl (msg->port);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   port %u\n", ch->port);
    c = GML_client_get_by_port (ch->port);
    if (NULL == c)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  no client has port registered\n");
      if (is_loopback (ch))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  loopback: destroy on handler\n");
        send_nack (ch);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  not loopback: destroy now\n");
        send_nack (ch);
        GCCH_destroy (ch);
      }
      return NULL;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  client %p has port registered\n", c);
    }

    add_destination (ch, c);
    if (GNUNET_YES == ch->reliable)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Reliable\n");
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Not Reliable\n");

    send_client_create (ch);
    ch->state =  CADET_CHANNEL_SENT;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  duplicate create channel\n");
    if (NULL != ch->dest_rel->retry_task)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  clearing retry task\n");
      /* we were waiting to re-send our 'SYNACK', wait no more! */
      GNUNET_SCHEDULER_cancel (ch->dest_rel->retry_task);
      ch->dest_rel->retry_task = NULL;
    }
    else if (NULL != ch->dest_rel->uniq)
    {
      /* we are waiting to for our 'SYNACK' to leave the queue, all done! */
      return ch;
    }
  }
  send_ack (ch, GNUNET_YES);

  return ch;
}


/**
 * Handler for channel NACK messages.
 *
 * NACK messages always go dest -> root, no need for 'fwd' or 'msg' parameter.
 *
 * @param ch Channel.
 */
void
GCCH_handle_nack (struct CadetChannel *ch)
{
  send_client_nack (ch);
  GCCH_destroy (ch);
}


/**
 * Handler for channel ack messages.
 *
 * @param ch Channel.
 * @param msg Message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GCCH_handle_ack (struct CadetChannel *ch,
                 const struct GNUNET_CADET_ChannelManage *msg,
                 int fwd)
{
  /* If this is a remote (non-loopback) channel, find 'fwd'. */
  if (GNUNET_SYSERR == fwd)
  {
    if (is_loopback (ch))
    {
      /* It is a loopback channel after all... */
      GNUNET_break (0);
      return;
    }
    fwd = (NULL != ch->dest) ? GNUNET_YES : GNUNET_NO;
  }

  channel_confirm (ch, !fwd);
}


/**
 * Handler for channel destroy messages.
 *
 * @param ch Channel to be destroyed of.
 * @param msg Message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GCCH_handle_destroy (struct CadetChannel *ch,
                     const struct GNUNET_CADET_ChannelManage *msg,
                     int fwd)
{
  struct CadetChannelReliability *rel;

  /* If this is a remote (non-loopback) channel, find 'fwd'. */
  if (GNUNET_SYSERR == fwd)
  {
    if (is_loopback (ch))
    {
      /* It is a loopback channel after all... */
      GNUNET_break (0);
      return;
    }
    fwd = (NULL != ch->dest) ? GNUNET_YES : GNUNET_NO;
  }

  GCCH_debug (ch);
  if ( (fwd && NULL == ch->dest) || (!fwd && NULL == ch->root) )
  {
    /* Not for us (don't destroy twice a half-open loopback channel) */
    return;
  }

  rel = fwd ? ch->dest_rel : ch->root_rel;
  if (0 == rel->n_recv)
  {
    send_destroy (ch, GNUNET_YES);
    GCCH_destroy (ch);
  }
  else
  {
    ch->destroy = GNUNET_YES;
  }
}


/**
 * Sends an already built message on a channel.
 *
 * If the channel is on a loopback tunnel, notifies the appropriate destination
 * client locally.
 *
 * On a normal channel passes the message to the tunnel for encryption and
 * sending on a connection.
 *
 * This function DOES NOT save the message for retransmission.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 * @param existing_copy This is a retransmission, don't save a copy.
 */
void
GCCH_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                            struct CadetChannel *ch, int fwd,
                            void *existing_copy)
{
  struct CadetChannelQueue *chq;
  uint16_t type;

  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_INFO, "===> %s %s on channel %s\n",
       GC_m2s (type), GC_f2s (fwd), GCCH_2s (ch));

  if (GCT_is_loopback (ch->t))
  {
    handle_loopback (ch, message, fwd);
    return;
  }

  switch (type)
  {
    struct GNUNET_CADET_Data *payload;
    case GNUNET_MESSAGE_TYPE_CADET_DATA:

      payload = (struct GNUNET_CADET_Data *) message;
      LOG (GNUNET_ERROR_TYPE_INFO, "===> %s %u\n",
           GC_m2s (type), ntohl (payload->mid));
      if (GNUNET_YES == ch->reliable)
      {
        chq = GNUNET_new (struct CadetChannelQueue);
        chq->type = type;
        if (NULL == existing_copy)
          chq->copy = channel_save_copy (ch, message, fwd);
        else
        {
          chq->copy = (struct CadetReliableMessage *) existing_copy;
          if (NULL != chq->copy->chq)
          {
            /* Last retransmission was queued but not yet sent!
             * This retransmission was scheduled by a ch_message_sent which
             * followed a very fast RTT, so the tiny delay made the
             * retransmission function to execute before the previous
             * retransmitted message even had a chance to leave the peer.
             * Cancel this message and wait until the pending
             * retransmission leaves the peer and ch_message_sent starts
             * the timer for the next one.
             */
            GNUNET_free (chq);
            LOG (GNUNET_ERROR_TYPE_DEBUG,
                 "  exisitng copy not yet transmitted!\n");
            return;
          }
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "  using existing copy: %p {r:%p q:%p t:%u}\n",
               existing_copy,
               chq->copy->rel, chq->copy->chq, chq->copy->type);
        }
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  new chq: %p\n", chq);
        chq->copy->chq = chq;
        chq->tq = GCT_send_prebuilt_message (message, ch->t, NULL,
                                             NULL != existing_copy,
                                             &ch_message_sent, chq);
        /* q itself is stored in copy */
        GNUNET_assert (NULL != chq->tq || GNUNET_NO != ch->destroy);
      }
      else
      {
        fire_and_forget (message, ch, GNUNET_NO);
      }
      break;


    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
      chq = GNUNET_new (struct CadetChannelQueue);
      chq->type = type;
      chq->rel = fwd ? ch->root_rel : ch->dest_rel;
      if (NULL != chq->rel->uniq)
      {
        if (NULL != chq->rel->uniq->tq)
        {
          GCT_cancel (chq->rel->uniq->tq);
          /* ch_message_sent is called, freeing and NULLing uniq */
          GNUNET_break (NULL == chq->rel->uniq);
        }
        else
        {
          GNUNET_break (0);
          GNUNET_free (chq->rel->uniq);
        }
      }

      chq->tq = GCT_send_prebuilt_message (message, ch->t, NULL, GNUNET_YES,
                                           &ch_message_sent, chq);
      if (NULL == chq->tq)
      {
        GNUNET_break (0);
        GCT_debug (ch->t, GNUNET_ERROR_TYPE_ERROR);
        GNUNET_free (chq);
        chq = NULL;
        return;
      }
      chq->rel->uniq = chq;
      break;


    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK:
      fire_and_forget (message, ch, GNUNET_YES);
      break;


    default:
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "type %s unknown!\n", GC_m2s (type));
      fire_and_forget (message, ch, GNUNET_YES);
  }
}


/**
 * Get the static string for identification of the channel.
 *
 * @param ch Channel.
 *
 * @return Static string with the channel IDs.
 */
const char *
GCCH_2s (const struct CadetChannel *ch)
{
  static char buf[64];

  if (NULL == ch)
    return "(NULL Channel)";

  SPRINTF (buf, "%s:%u gid:%X (%X / %X)",
           GCT_2s (ch->t), ch->port, ch->gid, ch->lid_root, ch->lid_dest);

  return buf;
}
