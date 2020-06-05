/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_channel.c
 * @brief logical links between CADET clients
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * TODO:
 * - Congestion/flow control:
 *   + estimate max bandwidth using bursts and use to for CONGESTION CONTROL!
 *     (and figure out how/where to use this!)
 *   + figure out flow control without ACKs (unreliable traffic!)
 * - revisit handling of 'unbuffered' traffic!
 *   (need to push down through tunnel into connection selection)
 * - revisit handling of 'buffered' traffic: 4 is a rather small buffer; maybe
 *   reserve more bits in 'options' to allow for buffer size control?
 */
#include "platform.h"
#include "cadet.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_tunnels.h"
#include "gnunet-service-cadet_paths.h"

#define LOG(level, ...) GNUNET_log_from (level, "cadet-chn", __VA_ARGS__)

/**
 * How long do we initially wait before retransmitting?
 */
#define CADET_INITIAL_RETRANSMIT_TIME \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * How long do we wait before dropping state about incoming
 * connection to closed port?
 */
#define TIMEOUT_CLOSED_PORT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long do we wait at least before retransmitting ever?
 */
#define MIN_RTT_DELAY \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 75)

/**
 * Maximum message ID into the future we accept for out-of-order messages.
 * If the message is more than this into the future, we drop it.  This is
 * important both to detect values that are actually in the past, as well
 * as to limit adversarially triggerable memory consumption.
 *
 * Note that right now we have "max_pending_messages = 4" hard-coded in
 * the logic below, so a value of 4 would suffice here. But we plan to
 * allow larger windows in the future...
 */
#define MAX_OUT_OF_ORDER_DISTANCE 1024


/**
 * All the states a channel can be in.
 */
enum CadetChannelState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  CADET_CHANNEL_NEW,

  /**
   * Channel is to a port that is not open, we're waiting for the
   * port to be opened.
   */
  CADET_CHANNEL_LOOSE,

  /**
   * CHANNEL_OPEN message sent, waiting for CHANNEL_OPEN_ACK.
   */
  CADET_CHANNEL_OPEN_SENT,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  CADET_CHANNEL_READY
};


/**
 * Info needed to retry a message in case it gets lost.
 * Note that we DO use this structure also for unreliable
 * messages.
 */
struct CadetReliableMessage
{
  /**
   * Double linked list, FIFO style
   */
  struct CadetReliableMessage *next;

  /**
   * Double linked list, FIFO style
   */
  struct CadetReliableMessage *prev;

  /**
   * Which channel is this message in?
   */
  struct CadetChannel *ch;

  /**
   * Entry in the tunnels queue for this message, NULL if it has left
   * the tunnel.  Used to cancel transmission in case we receive an
   * ACK in time.
   */
  struct CadetTunnelQueueEntry *qe;

  /**
   * Data message we are trying to send.
   */
  struct GNUNET_CADET_ChannelAppDataMessage *data_message;

  /**
   * How soon should we retry if we fail to get an ACK?
   * Messages in the queue are sorted by this value.
   */
  struct GNUNET_TIME_Absolute next_retry;

  /**
   * How long do we wait for an ACK after transmission?
   * Use for the back-off calculation.
   */
  struct GNUNET_TIME_Relative retry_delay;

  /**
   * Time when we first successfully transmitted the message
   * (that is, set @e num_transmissions to 1).
   */
  struct GNUNET_TIME_Absolute first_transmission_time;

  /**
   * Identifier of the connection that this message took when it
   * was first transmitted.  Only useful if @e num_transmissions is 1.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier connection_taken;

  /**
   * How often was this message transmitted?  #GNUNET_SYSERR if there
   * was an error transmitting the message, #GNUNET_NO if it was not
   * yet transmitted ever, otherwise the number of (re) transmissions.
   */
  int num_transmissions;
};


/**
 * List of received out-of-order data messages.
 */
struct CadetOutOfOrderMessage
{
  /**
   * Double linked list, FIFO style
   */
  struct CadetOutOfOrderMessage *next;

  /**
   * Double linked list, FIFO style
   */
  struct CadetOutOfOrderMessage *prev;

  /**
   * ID of the message (messages up to this point needed
   * before we give this one to the client).
   */
  struct ChannelMessageIdentifier mid;

  /**
   * The envelope with the payload of the out-of-order message
   */
  struct GNUNET_MQ_Envelope *env;
};


/**
 * Client endpoint of a `struct CadetChannel`.  A channel may be a
 * loopback channel, in which case it has two of these endpoints.
 * Note that flow control also is required in both directions.
 */
struct CadetChannelClient
{
  /**
   * Client handle.  Not by itself sufficient to designate
   * the client endpoint, as the same client handle may
   * be used for both the owner and the destination, and
   * we thus also need the channel ID to identify the client.
   */
  struct CadetClient *c;

  /**
   * Head of DLL of messages received out of order or while client was unready.
   */
  struct CadetOutOfOrderMessage *head_recv;

  /**
   * Tail DLL of messages received out of order or while client was unready.
   */
  struct CadetOutOfOrderMessage *tail_recv;

  /**
   * Local tunnel number for this client.
   * (if owner >= #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI,
   *  otherwise < #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * Number of entries currently in @a head_recv DLL.
   */
  unsigned int num_recv;

  /**
   * Can we send data to the client?
   */
  int client_ready;
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
   * Client owner of the tunnel, if any.
   * (Used if this channel represends the initiating end of the tunnel.)
   */
  struct CadetChannelClient *owner;

  /**
   * Client destination of the tunnel, if any.
   * (Used if this channel represents the listening end of the tunnel.)
   */
  struct CadetChannelClient *dest;

  /**
   * Last entry in the tunnel's queue relating to control messages
   * (#GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN or
   * #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK).  Used to cancel
   * transmission in case we receive updated information.
   */
  struct CadetTunnelQueueEntry *last_control_qe;

  /**
   * Head of DLL of messages sent and not yet ACK'd.
   */
  struct CadetReliableMessage *head_sent;

  /**
   * Tail of DLL of messages sent and not yet ACK'd.
   */
  struct CadetReliableMessage *tail_sent;

  /**
   * Task to resend/poll in case no ACK is received.
   */
  struct GNUNET_SCHEDULER_Task *retry_control_task;

  /**
   * Task to resend/poll in case no ACK is received.
   */
  struct GNUNET_SCHEDULER_Task *retry_data_task;

  /**
   * Last time the channel was used
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Destination port of the channel.
   */
  struct GNUNET_HashCode port;

  /**
   * Hash'ed port of the channel with initiator and destination PID.
   */
  struct GNUNET_HashCode h_port;

  /**
   * Counter for exponential backoff.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Bitfield of already-received messages past @e mid_recv.
   */
  uint64_t mid_futures;

  /**
   * Next MID expected for incoming traffic.
   */
  struct ChannelMessageIdentifier mid_recv;

  /**
   * Next MID to use for outgoing traffic.
   */
  struct ChannelMessageIdentifier mid_send;

  /**
   * Total (reliable) messages pending ACK for this channel.
   */
  unsigned int pending_messages;

  /**
   * Maximum (reliable) messages pending ACK for this channel
   * before we throttle the client.
   */
  unsigned int max_pending_messages;

  /**
   * Number identifying this channel in its tunnel.
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;

  /**
   * Channel state.
   */
  enum CadetChannelState state;

  /**
   * Count how many ACKs we skipped, used to prevent long
   * sequences of ACK skipping.
   */
  unsigned int skip_ack_series;

  /**
   * Is the tunnel bufferless (minimum latency)?
   */
  int nobuffer;

  /**
   * Is the tunnel reliable?
   */
  int reliable;

  /**
   * Is the tunnel out-of-order?
   */
  int out_of_order;

  /**
   * Is this channel a loopback channel, where the destination is us again?
   */
  int is_loopback;

  /**
   * Flag to signal the destruction of the channel.  If this is set to
   * #GNUNET_YES the channel will be destroyed once the queue is
   * empty.
   */
  int destroy;

  /**
   * Type of message to be droped. See GCT_send.
   */
  uint16_t type GNUNET_PACKED;
  
};

/**
 * Assign type of message to drop.
 * @param ch CadetChannel to assign type to drop. 
 * @param message GNUNET_CADET_RequestDropCadetMessage to get the type from.
 */
void
GCCH_assign_type_to_drop(struct CadetChannel *ch, const struct GNUNET_CADET_RequestDropCadetMessage *message)
{

  ch->type = message->type;
  
}

/**
 * Check if type of message is the one to drop.
 * @param ch CadetChannel to check for message type to drop. 
 * @param message GNUNET_MessageHeader to compare the type with.
 */
int
GCCH_is_type_to_drop(struct CadetChannel *ch, const struct GNUNET_MessageHeader *message)
{

  if (ch->type == message->type)
  {
    ch->type = 0;
    return GNUNET_YES;
  }
  else
    return GNUNET_NO;
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
  static char buf[128];

  GNUNET_snprintf (buf,
                   sizeof(buf),
                   "Channel %s:%s ctn:%X(%X/%X)",
                   (GNUNET_YES == ch->is_loopback)
                   ? "loopback"
                   : GNUNET_i2s (GCP_get_id (GCT_get_destination (ch->t))),
                   GNUNET_h2s (&ch->port),
                   ch->ctn,
                   (NULL == ch->owner)
                   ? 0
                   : ntohl (ch->owner->ccn.channel_of_client),
                   (NULL == ch->dest)
                   ? 0
                   : ntohl (ch->dest->ccn.channel_of_client));
  return buf;
}


/**
 * Hash the @a port and @a initiator and @a listener to
 * calculate the "challenge" @a h_port we send to the other
 * peer on #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN.
 *
 * @param[out] h_port set to the hash of @a port, @a initiator and @a listener
 * @param port cadet port, as seen by CADET clients
 * @param listener peer that is listining on @a port
 */
void
GCCH_hash_port (struct GNUNET_HashCode *h_port,
                const struct GNUNET_HashCode *port,
                const struct GNUNET_PeerIdentity *listener)
{
  struct GNUNET_HashContext *hc;

  hc = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_CRYPTO_hash_context_read (hc, port, sizeof(*port));
  GNUNET_CRYPTO_hash_context_read (hc, listener, sizeof(*listener));
  GNUNET_CRYPTO_hash_context_finish (hc, h_port);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Calculated port hash %s\n",
       GNUNET_h2s (h_port));
}


/**
 * Get the channel's public ID.
 *
 * @param ch Channel.
 *
 * @return ID used to identify the channel with the remote peer.
 */
struct GNUNET_CADET_ChannelTunnelNumber
GCCH_get_id (const struct CadetChannel *ch)
{
  return ch->ctn;
}


/**
 * Release memory associated with @a ccc
 *
 * @param ccc data structure to clean up
 */
static void
free_channel_client (struct CadetChannelClient *ccc)
{
  struct CadetOutOfOrderMessage *com;

  while (NULL != (com = ccc->head_recv))
  {
    GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, com);
    ccc->num_recv--;
    GNUNET_MQ_discard (com->env);
    GNUNET_free (com);
  }
  GNUNET_free (ccc);
}


/**
 * Destroy the given channel.
 *
 * @param ch channel to destroy
 */
static void
channel_destroy (struct CadetChannel *ch)
{
  struct CadetReliableMessage *crm;

  while (NULL != (crm = ch->head_sent))
  {
    GNUNET_assert (ch == crm->ch);
    if (NULL != crm->qe)
    {
      GCT_send_cancel (crm->qe);
      crm->qe = NULL;
    }
    GNUNET_CONTAINER_DLL_remove (ch->head_sent, ch->tail_sent, crm);
    GNUNET_free (crm->data_message);
    GNUNET_free (crm);
  }
  if (CADET_CHANNEL_LOOSE == ch->state)
  {
    GSC_drop_loose_channel (&ch->h_port, ch);
  }
  if (NULL != ch->owner)
  {
    free_channel_client (ch->owner);
    ch->owner = NULL;
  }
  if (NULL != ch->dest)
  {
    free_channel_client (ch->dest);
    ch->dest = NULL;
  }
  if (NULL != ch->last_control_qe)
  {
    GCT_send_cancel (ch->last_control_qe);
    ch->last_control_qe = NULL;
  }
  if (NULL != ch->retry_data_task)
  {
    GNUNET_SCHEDULER_cancel (ch->retry_data_task);
    ch->retry_data_task = NULL;
  }
  if (NULL != ch->retry_control_task)
  {
    GNUNET_SCHEDULER_cancel (ch->retry_control_task);
    ch->retry_control_task = NULL;
  }
  if (GNUNET_NO == ch->is_loopback)
  {
    GCT_remove_channel (ch->t, ch, ch->ctn);
    ch->t = NULL;
  }
  GNUNET_free (ch);
}


/**
 * Send a channel create message.
 *
 * @param cls Channel for which to send.
 */
static void
send_channel_open (void *cls);


/**
 * Function called once the tunnel confirms that we sent the
 * create message.  Delays for a bit until we retry.
 *
 * @param cls our `struct CadetChannel`.
 * @param cid identifier of the connection within the tunnel, NULL
 *            if transmission failed
 */
static void
channel_open_sent_cb (void *cls,
                      const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetChannel *ch = cls;

  GNUNET_assert (NULL != ch->last_control_qe);
  ch->last_control_qe = NULL;
  ch->retry_time = GNUNET_TIME_STD_BACKOFF (ch->retry_time);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sent CADET_CHANNEL_OPEN on %s, retrying in %s\n",
       GCCH_2s (ch),
       GNUNET_STRINGS_relative_time_to_string (ch->retry_time, GNUNET_YES));
  ch->retry_control_task =
    GNUNET_SCHEDULER_add_delayed (ch->retry_time, &send_channel_open, ch);
}


/**
 * Send a channel open message.
 *
 * @param cls Channel for which to send.
 */
static void
send_channel_open (void *cls)
{
  struct CadetChannel *ch = cls;
  struct GNUNET_CADET_ChannelOpenMessage msgcc;

  ch->retry_control_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CHANNEL_OPEN message for %s\n",
       GCCH_2s (ch));
  msgcc.header.size = htons (sizeof(msgcc));
  msgcc.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN);
  // TODO This will be removed in a major release, because this will be a protocol breaking change. We set the deprecated "reliable" bit here that was removed.
  msgcc.opt = 2;
  msgcc.h_port = ch->h_port;
  msgcc.ctn = ch->ctn;
  ch->state = CADET_CHANNEL_OPEN_SENT;
  if (NULL != ch->last_control_qe)
    GCT_send_cancel (ch->last_control_qe);
  ch->last_control_qe =
    GCT_send (ch->t, &msgcc.header, &channel_open_sent_cb, ch, &msgcc.ctn);
  GNUNET_assert (NULL == ch->retry_control_task);
}


/**
 * Function called once and only once after a channel was bound
 * to its tunnel via #GCT_add_channel() is ready for transmission.
 * Note that this is only the case for channels that this peer
 * initiates, as for incoming channels we assume that they are
 * ready for transmission immediately upon receiving the open
 * message.  Used to bootstrap the #GCT_send() process.
 *
 * @param ch the channel for which the tunnel is now ready
 */
void
GCCH_tunnel_up (struct CadetChannel *ch)
{
  GNUNET_assert (NULL == ch->retry_control_task);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tunnel up, sending CHANNEL_OPEN on %s now\n",
       GCCH_2s (ch));
  ch->retry_control_task = GNUNET_SCHEDULER_add_now (&send_channel_open, ch);
}


/**
 * Create a new channel.
 *
 * @param owner local client owning the channel
 * @param ccn local number of this channel at the @a owner
 * @param destination peer to which we should build the channel
 * @param port desired port at @a destination
 * @param options options for the channel
 * @return handle to the new channel
 */
struct CadetChannel *
GCCH_channel_local_new (struct CadetClient *owner,
                        struct GNUNET_CADET_ClientChannelNumber ccn,
                        struct CadetPeer *destination,
                        const struct GNUNET_HashCode *port,
                        uint32_t options)
{
  struct CadetChannel *ch;
  struct CadetChannelClient *ccco;

  ccco = GNUNET_new (struct CadetChannelClient);
  ccco->c = owner;
  ccco->ccn = ccn;
  ccco->client_ready = GNUNET_YES;

  ch = GNUNET_new (struct CadetChannel);
  ch->mid_recv.mid = htonl (1);  /* The OPEN_ACK counts as message 0! */
  ch->nobuffer = GNUNET_NO;
  ch->reliable = GNUNET_YES;
  ch->out_of_order = GNUNET_NO;
  ch->max_pending_messages =
    (ch->nobuffer) ? 1 : 4; /* FIXME: 4!? Do not hardcode! */
  ch->owner = ccco;
  ch->port = *port;
  GCCH_hash_port (&ch->h_port, port, GCP_get_id (destination));
  if (0 == GNUNET_memcmp (&my_full_id, GCP_get_id (destination)))
  {
    struct OpenPort *op;

    ch->is_loopback = GNUNET_YES;
    op = GNUNET_CONTAINER_multihashmap_get (open_ports, &ch->h_port);
    if (NULL == op)
    {
      /* port closed, wait for it to possibly open */
      ch->state = CADET_CHANNEL_LOOSE;
      (void) GNUNET_CONTAINER_multihashmap_put (
        loose_channels,
        &ch->h_port,
        ch,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Created loose incoming loopback channel to port %s\n",
           GNUNET_h2s (&ch->port));
    }
    else
    {
      GCCH_bind (ch, op->c, &op->port);
    }
  }
  else
  {
    ch->t = GCP_get_tunnel (destination, GNUNET_YES);
    ch->retry_time = CADET_INITIAL_RETRANSMIT_TIME;
    ch->ctn = GCT_add_channel (ch->t, ch);
  }
  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created channel to port %s at peer %s for %s using %s\n",
       GNUNET_h2s (port),
       GCP_2s (destination),
       GSC_2s (owner),
       (GNUNET_YES == ch->is_loopback) ? "loopback" : GCT_2s (ch->t));
  return ch;
}


/**
 * We had an incoming channel to a port that is closed.
 * It has not been opened for a while, drop it.
 *
 * @param cls the channel to drop
 */
static void
timeout_closed_cb (void *cls)
{
  struct CadetChannel *ch = cls;

  ch->retry_control_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Closing incoming channel to port %s from peer %s due to timeout\n",
       GNUNET_h2s (&ch->port),
       GCP_2s (GCT_get_destination (ch->t)));
  channel_destroy (ch);
}


/**
 * Create a new channel based on a request coming in over the network.
 *
 * @param t tunnel to the remote peer
 * @param ctn identifier of this channel in the tunnel
 * @param h_port desired hash of local port
 * @param options options for the channel
 * @return handle to the new channel
 */
struct CadetChannel *
GCCH_channel_incoming_new (struct CadetTunnel *t,
                           struct GNUNET_CADET_ChannelTunnelNumber ctn,
                           const struct GNUNET_HashCode *h_port,
                           uint32_t options)
{
  struct CadetChannel *ch;
  struct OpenPort *op;

  ch = GNUNET_new (struct CadetChannel);
  ch->h_port = *h_port;
  ch->t = t;
  ch->ctn = ctn;
  ch->retry_time = CADET_INITIAL_RETRANSMIT_TIME;
  ch->nobuffer = GNUNET_NO;
  ch->reliable = GNUNET_YES;
  ch->out_of_order = GNUNET_NO;
  ch->max_pending_messages =
    (ch->nobuffer) ? 1 : 4; /* FIXME: 4!? Do not hardcode! */
  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);

  op = GNUNET_CONTAINER_multihashmap_get (open_ports, h_port);
  if (NULL == op)
  {
    /* port closed, wait for it to possibly open */
    ch->state = CADET_CHANNEL_LOOSE;
    (void) GNUNET_CONTAINER_multihashmap_put (
      loose_channels,
      &ch->h_port,
      ch,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    GNUNET_assert (NULL == ch->retry_control_task);
    ch->retry_control_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT_CLOSED_PORT,
                                                           &timeout_closed_cb,
                                                           ch);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Created loose incoming channel to port %s from peer %s\n",
         GNUNET_h2s (&ch->port),
         GCP_2s (GCT_get_destination (ch->t)));
  }
  else
  {
    GCCH_bind (ch, op->c, &op->port);
  }
  GNUNET_STATISTICS_update (stats, "# channels", 1, GNUNET_NO);
  return ch;
}


/**
 * Function called once the tunnel confirms that we sent the
 * ACK message.  Just remembers it was sent, we do not expect
 * ACKs for ACKs ;-).
 *
 * @param cls our `struct CadetChannel`.
 * @param cid identifier of the connection within the tunnel, NULL
 *            if transmission failed
 */
static void
send_ack_cb (void *cls,
             const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetChannel *ch = cls;

  GNUNET_assert (NULL != ch->last_control_qe);
  ch->last_control_qe = NULL;
}


/**
 * Compute and send the current #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK to the other peer.
 *
 * @param ch channel to send the #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK for
 */
static void
send_channel_data_ack (struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelDataAckMessage msg;

  if (GNUNET_NO == ch->reliable)
    return; /* no ACKs */
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK);
  msg.header.size = htons (sizeof(msg));
  msg.ctn = ch->ctn;
  msg.mid.mid = htonl (ntohl (ch->mid_recv.mid));
  msg.futures = GNUNET_htonll (ch->mid_futures);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending DATA_ACK %u:%llX via %s\n",
       (unsigned int) ntohl (msg.mid.mid),
       (unsigned long long) ch->mid_futures,
       GCCH_2s (ch));
  if (NULL != ch->last_control_qe)
    GCT_send_cancel (ch->last_control_qe);
  ch->last_control_qe = GCT_send (ch->t, &msg.header, &send_ack_cb, ch, &msg.ctn);
}


/**
 * Send our initial #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK to the client confirming that the
 * connection is up.
 *
 * @param cls the `struct CadetChannel`
 */
static void
send_open_ack (void *cls)
{
  struct CadetChannel *ch = cls;
  struct GNUNET_CADET_ChannelOpenAckMessage msg;

  ch->retry_control_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CHANNEL_OPEN_ACK on %s\n",
       GCCH_2s (ch));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK);
  msg.header.size = htons (sizeof(msg));
  msg.reserved = htonl (0);
  msg.ctn = ch->ctn;
  msg.port = ch->port;
  if (NULL != ch->last_control_qe)
    GCT_send_cancel (ch->last_control_qe);
  ch->last_control_qe = GCT_send (ch->t, &msg.header, &send_ack_cb, ch, &msg.ctn);
}


/**
 * We got a #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN message again for
 * this channel.  If the binding was successful, (re)transmit the
 * #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK.
 *
 * @param ch channel that got the duplicate open
 * @param cti identifier of the connection that delivered the message
 */
void
GCCH_handle_duplicate_open (
  struct CadetChannel *ch,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti)
{
  if (NULL == ch->dest)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring duplicate CHANNEL_OPEN on %s: port is closed\n",
         GCCH_2s (ch));
    return;
  }
  if (NULL != ch->retry_control_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring duplicate CHANNEL_OPEN on %s: control message is pending\n",
         GCCH_2s (ch));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Retransmitting CHANNEL_OPEN_ACK on %s\n",
       GCCH_2s (ch));
  ch->retry_control_task = GNUNET_SCHEDULER_add_now (&send_open_ack, ch);
}


/**
 * Send a #GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK to the client to solicit more messages.
 *
 * @param ch channel the ack is for
 * @param to_owner #GNUNET_YES to send to owner,
 *                 #GNUNET_NO to send to dest
 */
static void
send_ack_to_client (struct CadetChannel *ch, int to_owner)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalAck *ack;
  struct CadetChannelClient *ccc;

  ccc = (GNUNET_YES == to_owner) ? ch->owner : ch->dest;
  if (NULL == ccc)
  {
    /* This can happen if we are just getting ACKs after
       our local client already disconnected. */
    GNUNET_assert (GNUNET_YES == ch->destroy);
    return;
  }
  env = GNUNET_MQ_msg (ack, GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  ack->ccn = ccc->ccn;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CADET_LOCAL_ACK to %s (%s) at ccn %X (%u/%u pending)\n",
       GSC_2s (ccc->c),
       (GNUNET_YES == to_owner) ? "owner" : "dest",
       ntohl (ack->ccn.channel_of_client),
       ch->pending_messages,
       ch->max_pending_messages);
  GSC_send_to_client (ccc->c, env);
}


/**
 * A client is bound to the port that we have a channel
 * open to.  Send the acknowledgement for the connection
 * request and establish the link with the client.
 *
 * @param ch open incoming channel
 * @param c client listening on the respective @a port
 * @param port the port @a is listening on
 */
void
GCCH_bind (struct CadetChannel *ch,
           struct CadetClient *c,
           const struct GNUNET_HashCode *port)
{
  uint32_t options;
  struct CadetChannelClient *cccd;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Binding %s from %s to port %s of %s\n",
       GCCH_2s (ch),
       GCT_2s (ch->t),
       GNUNET_h2s (&ch->port),
       GSC_2s (c));
  if (NULL != ch->retry_control_task)
  {
    /* there might be a timeout task here */
    GNUNET_SCHEDULER_cancel (ch->retry_control_task);
    ch->retry_control_task = NULL;
  }
  options = 0;
  cccd = GNUNET_new (struct CadetChannelClient);
  GNUNET_assert (NULL == ch->dest);
  ch->dest = cccd;
  ch->port = *port;
  cccd->c = c;
  cccd->client_ready = GNUNET_YES;
  cccd->ccn = GSC_bind (c,
                        ch,
                        (GNUNET_YES == ch->is_loopback)
                        ? GCP_get (&my_full_id, GNUNET_YES)
                        : GCT_get_destination (ch->t),
                        port,
                        options);
  GNUNET_assert (ntohl (cccd->ccn.channel_of_client) <
                 GNUNET_CADET_LOCAL_CHANNEL_ID_CLI);
  ch->mid_recv.mid = htonl (1);  /* The OPEN counts as message 0! */
  if (GNUNET_YES == ch->is_loopback)
  {
    ch->state = CADET_CHANNEL_OPEN_SENT;
    GCCH_handle_channel_open_ack (ch, NULL, port);
  }
  else
  {
    /* notify other peer that we accepted the connection */
    ch->state = CADET_CHANNEL_READY;
    ch->retry_control_task = GNUNET_SCHEDULER_add_now (&send_open_ack, ch);
  }
  /* give client it's initial supply of ACKs */
  GNUNET_assert (ntohl (cccd->ccn.channel_of_client) <
                 GNUNET_CADET_LOCAL_CHANNEL_ID_CLI);
  for (unsigned int i = 0; i < ch->max_pending_messages; i++)
    send_ack_to_client (ch, GNUNET_NO);
}


/**
 * One of our clients has disconnected, tell the other one that we
 * are finished. Done asynchronously to avoid concurrent modification
 * issues if this is the same client.
 *
 * @param cls the `struct CadetChannel` where one of the ends is now dead
 */
static void
signal_remote_destroy_cb (void *cls)
{
  struct CadetChannel *ch = cls;
  struct CadetChannelClient *ccc;

  /* Find which end is left... */
  ch->retry_control_task = NULL;
  ccc = (NULL != ch->owner) ? ch->owner : ch->dest;
  GSC_handle_remote_channel_destroy (ccc->c, ccc->ccn, ch);
  channel_destroy (ch);
}


/**
 * Destroy locally created channel.  Called by the local client, so no
 * need to tell the client.
 *
 * @param ch channel to destroy
 * @param c client that caused the destruction
 * @param ccn client number of the client @a c
 */
void
GCCH_channel_local_destroy (struct CadetChannel *ch,
                            struct CadetClient *c,
                            struct GNUNET_CADET_ClientChannelNumber ccn)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s asks for destruction of %s\n",
       GSC_2s (c),
       GCCH_2s (ch));
  GNUNET_assert (NULL != c);
  if ((NULL != ch->owner) && (c == ch->owner->c) &&
      (ccn.channel_of_client == ch->owner->ccn.channel_of_client))
  {
    free_channel_client (ch->owner);
    ch->owner = NULL;
  }
  else if ((NULL != ch->dest) && (c == ch->dest->c) &&
           (ccn.channel_of_client == ch->dest->ccn.channel_of_client))
  {
    free_channel_client (ch->dest);
    ch->dest = NULL;
  }
  else
  {
    GNUNET_assert (0);
  }

  if (GNUNET_YES == ch->destroy)
  {
    /* other end already destroyed, with the local client gone, no need
       to finish transmissions, just destroy immediately. */
    channel_destroy (ch);
    return;
  }
  if ((NULL != ch->head_sent) && ((NULL != ch->owner) || (NULL != ch->dest)))
  {
    /* Wait for other end to destroy us as well,
       and otherwise allow send queue to be transmitted first */
    ch->destroy = GNUNET_YES;
    return;
  }
  if ((GNUNET_YES == ch->is_loopback) &&
      ((NULL != ch->owner) || (NULL != ch->dest)))
  {
    if (NULL != ch->retry_control_task)
      GNUNET_SCHEDULER_cancel (ch->retry_control_task);
    ch->retry_control_task =
      GNUNET_SCHEDULER_add_now (&signal_remote_destroy_cb, ch);
    return;
  }
  if (GNUNET_NO == ch->is_loopback)
  {
    /* If the we ever sent the CHANNEL_CREATE, we need to send a destroy message. */
    switch (ch->state)
    {
    case CADET_CHANNEL_NEW:
      /* We gave up on a channel that we created as a client to a remote
         target, but that never went anywhere. Nothing to do here. */
      break;

    case CADET_CHANNEL_LOOSE:
      break;

    default:
      GCT_send_channel_destroy (ch->t, ch->ctn);
    }
  }
  /* Nothing left to do, just finish destruction */
  channel_destroy (ch);
}


/**
 * We got an acknowledgement for the creation of the channel
 * (the port is open on the other side).  Verify that the
 * other end really has the right port, and begin transmissions.
 *
 * @param ch channel to destroy
 * @param cti identifier of the connection that delivered the message
 * @param port port number (needed to verify receiver knows the port)
 */
void
GCCH_handle_channel_open_ack (
  struct CadetChannel *ch,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti,
  const struct GNUNET_HashCode *port)
{
  switch (ch->state)
  {
  case CADET_CHANNEL_NEW:
    /* this should be impossible */
    GNUNET_break (0);
    break;

  case CADET_CHANNEL_LOOSE:
    /* This makes no sense. */
    GNUNET_break_op (0);
    break;

  case CADET_CHANNEL_OPEN_SENT:
    if (NULL == ch->owner)
    {
      /* We're not the owner, wrong direction! */
      GNUNET_break_op (0);
      return;
    }
    if (0 != GNUNET_memcmp (&ch->port, port))
    {
      /* Other peer failed to provide the right port,
         refuse connection. */
      GNUNET_break_op (0);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received CHANNEL_OPEN_ACK for waiting %s, entering READY state\n",
         GCCH_2s (ch));
    if (NULL != ch->retry_control_task)   /* can be NULL if ch->is_loopback */
    {
      GNUNET_SCHEDULER_cancel (ch->retry_control_task);
      ch->retry_control_task = NULL;
    }
    ch->state = CADET_CHANNEL_READY;
    /* On first connect, send client as many ACKs as we allow messages
       to be buffered! */
    for (unsigned int i = 0; i < ch->max_pending_messages; i++)
      send_ack_to_client (ch, GNUNET_YES);
    break;

  case CADET_CHANNEL_READY:
    /* duplicate ACK, maybe we retried the CREATE. Ignore. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received duplicate channel OPEN_ACK for %s\n",
         GCCH_2s (ch));
    GNUNET_STATISTICS_update (stats, "# duplicate CREATE_ACKs", 1, GNUNET_NO);
    break;
  }
}


/**
 * Test if element @a e1 comes before element @a e2.
 *
 * @param cls closure, to a flag where we indicate duplicate packets
 * @param m1 a message of to sort
 * @param m2 another message to sort
 * @return #GNUNET_YES if @e1 < @e2, otherwise #GNUNET_NO
 */
static int
is_before (void *cls,
           struct CadetOutOfOrderMessage *m1,
           struct CadetOutOfOrderMessage *m2)
{
  int *duplicate = cls;
  uint32_t v1 = ntohl (m1->mid.mid);
  uint32_t v2 = ntohl (m2->mid.mid);
  uint32_t delta;

  delta = v2 - v1;
  if (0 == delta)
    *duplicate = GNUNET_YES;
  if (delta > (uint32_t) INT_MAX)
  {
    /* in overflow range, we can safely assume we wrapped around */
    return GNUNET_NO;
  }
  else
  {
    /* result is small, thus v2 > v1, thus m1 < m2 */
    return GNUNET_YES;
  }
}


/**
 * We got payload data for a channel.  Pass it on to the client
 * and send an ACK to the other end (once flow control allows it!)
 *
 * @param ch channel that got data
 * @param cti identifier of the connection that delivered the message
 * @param msg message that was received
 */
void
GCCH_handle_channel_plaintext_data (
  struct CadetChannel *ch,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti,
  const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalData *ld;
  struct CadetChannelClient *ccc;
  size_t payload_size;
  struct CadetOutOfOrderMessage *com;
  int duplicate;
  uint32_t mid_min;
  uint32_t mid_max;
  uint32_t mid_msg;
  uint32_t delta;

  GNUNET_assert (GNUNET_NO == ch->is_loopback);
  if ((NULL == ch->owner) && (NULL == ch->dest))
  {
    /* This client is gone, but we still have messages to send to
       the other end (which is why @a ch is not yet dead).  However,
       we cannot pass messages to our client anymore. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping incoming payload on %s as this end is already closed\n",
         GCCH_2s (ch));
    /* send back DESTROY notification to stop further retransmissions! */
    if (GNUNET_YES == ch->destroy)
      GCT_send_channel_destroy (ch->t, ch->ctn);
    return;
  }
  payload_size = ntohs (msg->header.size) - sizeof(*msg);
  env = GNUNET_MQ_msg_extra (ld,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA);
  ld->ccn = (NULL == ch->dest) ? ch->owner->ccn : ch->dest->ccn;
  GNUNET_memcpy (&ld[1], &msg[1], payload_size);
  ccc = (NULL != ch->owner) ? ch->owner : ch->dest;
  if (GNUNET_YES == ccc->client_ready)
  {
    /*
     * We ad-hoc send the message if
     * - The channel is out-of-order
     * - The channel is reliable and MID matches next expected MID
     * - The channel is unreliable and MID is before lowest seen MID
     */if ((GNUNET_YES == ch->out_of_order) ||
        ((msg->mid.mid == ch->mid_recv.mid) && (GNUNET_YES == ch->reliable)) ||
        ((GNUNET_NO == ch->reliable) &&
         (ntohl (msg->mid.mid) >= ntohl (ch->mid_recv.mid)) &&
         ((NULL == ccc->head_recv) ||
          (ntohl (msg->mid.mid) < ntohl (ccc->head_recv->mid.mid)))))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Giving %u bytes of payload with MID %u from %s to client %s\n",
           (unsigned int) payload_size,
           ntohl (msg->mid.mid),
           GCCH_2s (ch),
           GSC_2s (ccc->c));
      ccc->client_ready = GNUNET_NO;
      GSC_send_to_client (ccc->c, env);
      if (GNUNET_NO == ch->out_of_order)
        ch->mid_recv.mid = htonl (1 + ntohl (msg->mid.mid));
      else
        ch->mid_recv.mid = htonl (1 + ntohl (ch->mid_recv.mid));
      ch->mid_futures >>= 1;
      if ((GNUNET_YES == ch->out_of_order) && (GNUNET_NO == ch->reliable))
      {
        /* possibly shift by more if we skipped messages */
        uint64_t delta = htonl (msg->mid.mid) - 1 - ntohl (ch->mid_recv.mid);

        if (delta > 63)
          ch->mid_futures = 0;
        else
          ch->mid_futures >>= delta;
        ch->mid_recv.mid = htonl (1 + ntohl (msg->mid.mid));
      }
      send_channel_data_ack (ch);
      return;
    }
  }

  if (GNUNET_YES == ch->reliable)
  {
    /* check if message ought to be dropped because it is ancient/too distant/duplicate */
    mid_min = ntohl (ch->mid_recv.mid);
    mid_max = mid_min + ch->max_pending_messages;
    mid_msg = ntohl (msg->mid.mid);
    if (((uint32_t) (mid_msg - mid_min) > ch->max_pending_messages) ||
        ((uint32_t) (mid_max - mid_msg) > ch->max_pending_messages))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s at %u drops ancient or far-future message %u\n",
           GCCH_2s (ch),
           (unsigned int) mid_min,
           ntohl (msg->mid.mid));

      GNUNET_STATISTICS_update (stats,
                                "# duplicate DATA (ancient or future)",
                                1,
                                GNUNET_NO);
      GNUNET_MQ_discard (env);
      send_channel_data_ack (ch);
      return;
    }
    /* mark bit for future ACKs */
    delta = mid_msg - mid_min - 1;   /* overflow/underflow are OK here */
    if (delta < 64)
    {
      if (0 != (ch->mid_futures & (1LLU << delta)))
      {
        /* Duplicate within the queue, drop also */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Duplicate payload of %u bytes on %s (mid %u) dropped\n",
             (unsigned int) payload_size,
             GCCH_2s (ch),
             ntohl (msg->mid.mid));
        GNUNET_STATISTICS_update (stats, "# duplicate DATA", 1, GNUNET_NO);
        GNUNET_MQ_discard (env);
        send_channel_data_ack (ch);
        return;
      }
      ch->mid_futures |= (1LLU << delta);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Marked bit %llX for mid %u (base: %u); now: %llX\n",
           (1LLU << delta),
           mid_msg,
           mid_min,
           ch->mid_futures);
    }
  }
  else /* ! ch->reliable */
  {
    struct CadetOutOfOrderMessage *next_msg;

    /**
     * We always send if possible in this case.
     * It is guaranteed that the queued MID < received MID
     **/
    if ((NULL != ccc->head_recv) && (GNUNET_YES == ccc->client_ready))
    {
      next_msg = ccc->head_recv;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Giving queued MID %u from %s to client %s\n",
           ntohl (next_msg->mid.mid),
           GCCH_2s (ch),
           GSC_2s (ccc->c));
      ccc->client_ready = GNUNET_NO;
      GSC_send_to_client (ccc->c, next_msg->env);
      ch->mid_recv.mid = htonl (1 + ntohl (next_msg->mid.mid));
      ch->mid_futures >>= 1;
      send_channel_data_ack (ch);
      GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, next_msg);
      ccc->num_recv--;
      /* Do not process duplicate MID */
      if (msg->mid.mid == next_msg->mid.mid)     /* Duplicate */
      {
        /* Duplicate within the queue, drop */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Message on %s (mid %u) dropped, duplicate\n",
             GCCH_2s (ch),
             ntohl (msg->mid.mid));
        GNUNET_free (next_msg);
        GNUNET_MQ_discard (env);
        return;
      }
      GNUNET_free (next_msg);
    }

    if (ntohl (msg->mid.mid) < ntohl (ch->mid_recv.mid)) /* Old */
    {
      /* Duplicate within the queue, drop */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Message on %s (mid %u) dropped, old.\n",
           GCCH_2s (ch),
           ntohl (msg->mid.mid));
      GNUNET_MQ_discard (env);
      return;
    }

    /* Channel is unreliable, so we do not ACK. But we also cannot
       allow buffering everything, so check if we have space... */
    if (ccc->num_recv >= ch->max_pending_messages)
    {
      struct CadetOutOfOrderMessage *drop;

      /* Yep, need to drop. Drop the oldest message in
         the buffer. */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Queue full due slow client on %s, dropping oldest message\n",
           GCCH_2s (ch));
      GNUNET_STATISTICS_update (stats,
                                "# messages dropped due to slow client",
                                1,
                                GNUNET_NO);
      drop = ccc->head_recv;
      GNUNET_assert (NULL != drop);
      GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, drop);
      ccc->num_recv--;
      GNUNET_MQ_discard (drop->env);
      GNUNET_free (drop);
    }
  }

  /* Insert message into sorted out-of-order queue */
  com = GNUNET_new (struct CadetOutOfOrderMessage);
  com->mid = msg->mid;
  com->env = env;
  duplicate = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert_sorted (struct CadetOutOfOrderMessage,
                                      is_before,
                                      &duplicate,
                                      ccc->head_recv,
                                      ccc->tail_recv,
                                      com);
  ccc->num_recv++;
  if (GNUNET_YES == duplicate)
  {
    /* Duplicate within the queue, drop also (this is not covered by
       the case above if "delta" >= 64, which could be the case if
       max_pending_messages is also >= 64 or if our client is unready
       and we are seeing retransmissions of the message our client is
       blocked on. */LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Duplicate payload of %u bytes on %s (mid %u) dropped\n",
         (unsigned int) payload_size,
         GCCH_2s (ch),
         ntohl (msg->mid.mid));
    GNUNET_STATISTICS_update (stats, "# duplicate DATA", 1, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, com);
    ccc->num_recv--;
    GNUNET_MQ_discard (com->env);
    GNUNET_free (com);
    send_channel_data_ack (ch);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queued %s payload of %u bytes on %s-%X(%p) (mid %u, need %u first)\n",
       (GNUNET_YES == ccc->client_ready) ? "out-of-order" : "client-not-ready",
       (unsigned int) payload_size,
       GCCH_2s (ch),
       ntohl (ccc->ccn.channel_of_client),
       ccc,
       ntohl (msg->mid.mid),
       ntohl (ch->mid_recv.mid));
  /* NOTE: this ACK we _could_ skip, as the packet is out-of-order and
     the sender may already be transmitting the previous one.  Needs
     experimental evaluation to see if/when this ACK helps or
     hurts. (We might even want another option.) */
  send_channel_data_ack (ch);
}


/**
 * Function called once the tunnel has sent one of our messages.
 * If the message is unreliable, simply frees the `crm`. If the
 * message was reliable, calculate retransmission time and
 * wait for ACK (or retransmit).
 *
 * @param cls the `struct CadetReliableMessage` that was sent
 * @param cid identifier of the connection within the tunnel, NULL
 *            if transmission failed
 */
static void
data_sent_cb (void *cls,
              const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid);


/**
 * We need to retry a transmission, the last one took too long to
 * be acknowledged.
 *
 * @param cls the `struct CadetChannel` where we need to retransmit
 */
static void
retry_transmission (void *cls)
{
  struct CadetChannel *ch = cls;
  struct CadetReliableMessage *crm = ch->head_sent;

  ch->retry_data_task = NULL;
  GNUNET_assert (NULL == crm->qe);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Retrying transmission on %s of message %u\n",
       GCCH_2s (ch),
       (unsigned int) ntohl (crm->data_message->mid.mid));
  crm->qe = GCT_send (ch->t, &crm->data_message->header, &data_sent_cb, crm, &crm->data_message->ctn);
  GNUNET_assert (NULL == ch->retry_data_task);
}


/**
 * We got an PLAINTEXT_DATA_ACK for a message in our queue, remove it from
 * the queue and tell our client that it can send more.
 *
 * @param ch the channel that got the PLAINTEXT_DATA_ACK
 * @param cti identifier of the connection that delivered the message
 * @param crm the message that got acknowledged
 */
static void
handle_matching_ack (struct CadetChannel *ch,
                     const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti,
                     struct CadetReliableMessage *crm)
{
  GNUNET_CONTAINER_DLL_remove (ch->head_sent, ch->tail_sent, crm);
  ch->pending_messages--;
  GNUNET_assert (ch->pending_messages < ch->max_pending_messages);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received DATA_ACK on %s for message %u (%u ACKs pending)\n",
       GCCH_2s (ch),
       (unsigned int) ntohl (crm->data_message->mid.mid),
       ch->pending_messages);
  if (NULL != crm->qe)
  {
    GCT_send_cancel (crm->qe);
    crm->qe = NULL;
  }
  if ((1 == crm->num_transmissions) && (NULL != cti))
  {
    GCC_ack_observed (cti);
    if (0 == GNUNET_memcmp (cti, &crm->connection_taken))
    {
      GCC_latency_observed (cti,
                            GNUNET_TIME_absolute_get_duration (
                              crm->first_transmission_time));
    }
  }
  GNUNET_free (crm->data_message);
  GNUNET_free (crm);
  send_ack_to_client (ch, (NULL == ch->owner) ? GNUNET_NO : GNUNET_YES);
}


/**
 * We got an acknowledgement for payload data for a channel.
 * Possibly resume transmissions.
 *
 * @param ch channel that got the ack
 * @param cti identifier of the connection that delivered the message
 * @param ack details about what was received
 */
void
GCCH_handle_channel_plaintext_data_ack (
  struct CadetChannel *ch,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti,
  const struct GNUNET_CADET_ChannelDataAckMessage *ack)
{
  struct CadetReliableMessage *crm;
  struct CadetReliableMessage *crmn;
  int found;
  uint32_t mid_base;
  uint64_t mid_mask;
  unsigned int delta;

  GNUNET_break (GNUNET_NO == ch->is_loopback);
  if (GNUNET_NO == ch->reliable)
  {
    /* not expecting ACKs on unreliable channel, odd */
    GNUNET_break_op (0);
    return;
  }
  /* mid_base is the MID of the next message that the
     other peer expects (i.e. that is missing!), everything
     LOWER (but excluding mid_base itself) was received. */
  mid_base = ntohl (ack->mid.mid);
  mid_mask = GNUNET_htonll (ack->futures);
  found = GNUNET_NO;
  for (crm = ch->head_sent; NULL != crm; crm = crmn)
  {
    crmn = crm->next;
    delta = (unsigned int) (ntohl (crm->data_message->mid.mid) - mid_base);
    if (delta >= UINT_MAX - ch->max_pending_messages)
    {
      /* overflow, means crm was a bit in the past, so this ACK counts for it. */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got DATA_ACK with base %u satisfying past message %u on %s\n",
           (unsigned int) mid_base,
           ntohl (crm->data_message->mid.mid),
           GCCH_2s (ch));
      handle_matching_ack (ch, cti, crm);
      found = GNUNET_YES;
      continue;
    }
    delta--;
    if (delta >= 64)
      continue;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Testing bit %llX for mid %u (base: %u)\n",
         (1LLU << delta),
         ntohl (crm->data_message->mid.mid),
         mid_base);
    if (0 != (mid_mask & (1LLU << delta)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got DATA_ACK with mask for %u on %s\n",
           ntohl (crm->data_message->mid.mid),
           GCCH_2s (ch));
      handle_matching_ack (ch, cti, crm);
      found = GNUNET_YES;
    }
  }
  if (GNUNET_NO == found)
  {
    /* ACK for message we already dropped, might have been a
       duplicate ACK? Ignore. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Duplicate DATA_ACK on %s, ignoring\n",
         GCCH_2s (ch));
    GNUNET_STATISTICS_update (stats, "# duplicate DATA_ACKs", 1, GNUNET_NO);
    return;
  }
  if (NULL != ch->retry_data_task)
  {
    GNUNET_SCHEDULER_cancel (ch->retry_data_task);
    ch->retry_data_task = NULL;
  }
  if ((NULL != ch->head_sent) && (NULL == ch->head_sent->qe))
    ch->retry_data_task = GNUNET_SCHEDULER_add_at (ch->head_sent->next_retry,
                                                   &retry_transmission,
                                                   ch);
}


/**
 * Destroy channel, based on the other peer closing the
 * connection.  Also needs to remove this channel from
 * the tunnel.
 *
 * @param ch channel to destroy
 * @param cti identifier of the connection that delivered the message,
 *            NULL if we are simulating receiving a destroy due to shutdown
 */
void
GCCH_handle_remote_destroy (
  struct CadetChannel *ch,
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *cti)
{
  struct CadetChannelClient *ccc;

  GNUNET_assert (GNUNET_NO == ch->is_loopback);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received remote channel DESTROY for %s\n",
       GCCH_2s (ch));
  if (GNUNET_YES == ch->destroy)
  {
    /* Local client already gone, this is instant-death. */
    channel_destroy (ch);
    return;
  }
  ccc = (NULL != ch->owner) ? ch->owner : ch->dest;
  if ((NULL != ccc) && (NULL != ccc->head_recv))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Lost end of transmission due to remote shutdown on %s\n",
         GCCH_2s (ch));
    /* FIXME: change API to notify client about truncated transmission! */
  }
  ch->destroy = GNUNET_YES;
  if (NULL != ccc)
    GSC_handle_remote_channel_destroy (ccc->c, ccc->ccn, ch);
  channel_destroy (ch);
}


/**
 * Test if element @a e1 comes before element @a e2.
 *
 * @param cls closure, to a flag where we indicate duplicate packets
 * @param crm1 an element of to sort
 * @param crm2 another element to sort
 * @return #GNUNET_YES if @e1 < @e2, otherwise #GNUNET_NO
 */
static int
cmp_crm_by_next_retry (void *cls,
                       struct CadetReliableMessage *crm1,
                       struct CadetReliableMessage *crm2)
{
  if (crm1->next_retry.abs_value_us < crm2->next_retry.abs_value_us)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Function called once the tunnel has sent one of our messages.
 * If the message is unreliable, simply frees the `crm`. If the
 * message was reliable, calculate retransmission time and
 * wait for ACK (or retransmit).
 *
 * @param cls the `struct CadetReliableMessage` that was sent
 * @param cid identifier of the connection within the tunnel, NULL
 *            if transmission failed
 */
static void
data_sent_cb (void *cls,
              const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetReliableMessage *crm = cls;
  struct CadetChannel *ch = crm->ch;

  GNUNET_assert (GNUNET_NO == ch->is_loopback);
  GNUNET_assert (NULL != crm->qe);
  crm->qe = NULL;
  GNUNET_CONTAINER_DLL_remove (ch->head_sent, ch->tail_sent, crm);
  if (GNUNET_NO == ch->reliable)
  {
    GNUNET_free (crm->data_message);
    GNUNET_free (crm);
    ch->pending_messages--;
    send_ack_to_client (ch, (NULL == ch->owner) ? GNUNET_NO : GNUNET_YES);
    return;
  }
  if (NULL == cid)
  {
    /* There was an error sending. */
    crm->num_transmissions = GNUNET_SYSERR;
  }
  else if (GNUNET_SYSERR != crm->num_transmissions)
  {
    /* Increment transmission counter, and possibly store @a cid
       if this was the first transmission. */
    crm->num_transmissions++;
    if (1 == crm->num_transmissions)
    {
      crm->first_transmission_time = GNUNET_TIME_absolute_get ();
      crm->connection_taken = *cid;
      GCC_ack_expected (cid);
    }
  }
  if ((0 == crm->retry_delay.rel_value_us) && (NULL != cid))
  {
    struct CadetConnection *cc = GCC_lookup (cid);

    if (NULL != cc)
      crm->retry_delay = GCC_get_metrics (cc)->aged_latency;
    else
      crm->retry_delay = ch->retry_time;
  }
  crm->retry_delay = GNUNET_TIME_STD_BACKOFF (crm->retry_delay);
  crm->retry_delay = GNUNET_TIME_relative_max (crm->retry_delay, MIN_RTT_DELAY);
  crm->next_retry = GNUNET_TIME_relative_to_absolute (crm->retry_delay);

  GNUNET_CONTAINER_DLL_insert_sorted (struct CadetReliableMessage,
                                      cmp_crm_by_next_retry,
                                      NULL,
                                      ch->head_sent,
                                      ch->tail_sent,
                                      crm);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message %u sent, next transmission on %s in %s\n",
       (unsigned int) ntohl (crm->data_message->mid.mid),
       GCCH_2s (ch),
       GNUNET_STRINGS_relative_time_to_string (
         GNUNET_TIME_absolute_get_remaining (
           ch->head_sent->next_retry),
         GNUNET_YES));
  if (NULL == ch->head_sent->qe)
  {
    if (NULL != ch->retry_data_task)
      GNUNET_SCHEDULER_cancel (ch->retry_data_task);
    ch->retry_data_task = GNUNET_SCHEDULER_add_at (ch->head_sent->next_retry,
                                                   &retry_transmission,
                                                   ch);
  }
}


/**
 * Handle data given by a client.
 *
 * Check whether the client is allowed to send in this tunnel, save if
 * channel is reliable and send an ACK to the client if there is still
 * buffer space in the tunnel.
 *
 * @param ch Channel.
 * @param sender_ccn ccn of the sender
 * @param buf payload to transmit.
 * @param buf_len number of bytes in @a buf
 * @return #GNUNET_OK if everything goes well,
 *         #GNUNET_SYSERR in case of an error.
 */
int
GCCH_handle_local_data (struct CadetChannel *ch,
                        struct GNUNET_CADET_ClientChannelNumber sender_ccn,
                        const char *buf,
                        size_t buf_len)
{
  struct CadetReliableMessage *crm;

  if (ch->pending_messages >= ch->max_pending_messages)
  {
    GNUNET_break (0);  /* Fails: #5370 */
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES == ch->destroy)
  {
    /* we are going down, drop messages */
    return GNUNET_OK;
  }
  ch->pending_messages++;

  if (GNUNET_YES == ch->is_loopback)
  {
    struct CadetChannelClient *receiver;
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_LocalData *ld;
    int ack_to_owner;

    env =
      GNUNET_MQ_msg_extra (ld, buf_len, GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA);
    if ((NULL != ch->owner) &&
        (sender_ccn.channel_of_client == ch->owner->ccn.channel_of_client))
    {
      receiver = ch->dest;
      ack_to_owner = GNUNET_YES;
    }
    else if ((NULL != ch->dest) &&
             (sender_ccn.channel_of_client == ch->dest->ccn.channel_of_client))
    {
      receiver = ch->owner;
      ack_to_owner = GNUNET_NO;
    }
    else
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    GNUNET_assert (NULL != receiver);
    ld->ccn = receiver->ccn;
    GNUNET_memcpy (&ld[1], buf, buf_len);
    if (GNUNET_YES == receiver->client_ready)
    {
      ch->pending_messages--;
      GSC_send_to_client (receiver->c, env);
      send_ack_to_client (ch, ack_to_owner);
    }
    else
    {
      struct CadetOutOfOrderMessage *oom;

      oom = GNUNET_new (struct CadetOutOfOrderMessage);
      oom->env = env;
      GNUNET_CONTAINER_DLL_insert_tail (receiver->head_recv,
                                        receiver->tail_recv,
                                        oom);
      receiver->num_recv++;
    }
    return GNUNET_OK;
  }

  /* Everything is correct, send the message. */
  crm = GNUNET_malloc (sizeof(*crm));
  crm->ch = ch;
  crm->data_message = GNUNET_malloc (
    sizeof(struct GNUNET_CADET_ChannelAppDataMessage) + buf_len);
  crm->data_message->header.size =
    htons (sizeof(struct GNUNET_CADET_ChannelAppDataMessage) + buf_len);
  crm->data_message->header.type =
    htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA);
  ch->mid_send.mid = htonl (ntohl (ch->mid_send.mid) + 1);
  crm->data_message->mid = ch->mid_send;
  crm->data_message->ctn = ch->ctn;
  GNUNET_memcpy (&crm->data_message[1], buf, buf_len);
  GNUNET_CONTAINER_DLL_insert_tail (ch->head_sent, ch->tail_sent, crm);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending message %u from local client to %s with %u bytes\n",
       ntohl (crm->data_message->mid.mid),
       GCCH_2s (ch),
       buf_len);
  if (NULL != ch->retry_data_task)
  {
    GNUNET_SCHEDULER_cancel (ch->retry_data_task);
    ch->retry_data_task = NULL;
  }
  crm->qe = GCT_send (ch->t, &crm->data_message->header, &data_sent_cb, crm, &crm->data_message->ctn);
  GNUNET_assert (NULL == ch->retry_data_task);
  return GNUNET_OK;
}


/**
 * Handle ACK from client on local channel.  Means the client is ready
 * for more data, see if we have any for it.
 *
 * @param ch channel to destroy
 * @param client_ccn ccn of the client sending the ack
 */
void
GCCH_handle_local_ack (struct CadetChannel *ch,
                       struct GNUNET_CADET_ClientChannelNumber client_ccn)
{
  struct CadetChannelClient *ccc;
  struct CadetOutOfOrderMessage *com;

  if ((NULL != ch->owner) &&
      (ch->owner->ccn.channel_of_client == client_ccn.channel_of_client))
    ccc = ch->owner;
  else if ((NULL != ch->dest) &&
           (ch->dest->ccn.channel_of_client == client_ccn.channel_of_client))
    ccc = ch->dest;
  else
    GNUNET_assert (0);
  ccc->client_ready = GNUNET_YES;
  com = ccc->head_recv;
  if (NULL == com)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got LOCAL_ACK, %s-%X ready to receive more data, but none pending on %s-%X(%p)!\n",
         GSC_2s (ccc->c),
         ntohl (client_ccn.channel_of_client),
         GCCH_2s (ch),
         ntohl (ccc->ccn.channel_of_client),
         ccc);
    return;   /* none pending */
  }
  if (GNUNET_YES == ch->is_loopback)
  {
    int to_owner;

    /* Messages are always in-order, just send */
    GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, com);
    ccc->num_recv--;
    GSC_send_to_client (ccc->c, com->env);
    /* Notify sender that we can receive more */
    if ((NULL != ch->owner) &&
        (ccc->ccn.channel_of_client == ch->owner->ccn.channel_of_client))
    {
      to_owner = GNUNET_NO;
    }
    else
    {
      GNUNET_assert ((NULL != ch->dest) && (ccc->ccn.channel_of_client ==
                                            ch->dest->ccn.channel_of_client));
      to_owner = GNUNET_YES;
    }
    send_ack_to_client (ch, to_owner);
    GNUNET_free (com);
    return;
  }

  if ((com->mid.mid != ch->mid_recv.mid) && (GNUNET_NO == ch->out_of_order) &&
      (GNUNET_YES == ch->reliable))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got LOCAL_ACK, %s-%X ready to receive more data (but next one is out-of-order %u vs. %u)!\n",
         GSC_2s (ccc->c),
         ntohl (ccc->ccn.channel_of_client),
         ntohl (com->mid.mid),
         ntohl (ch->mid_recv.mid));
    return;   /* missing next one in-order */
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got LOCAL_ACK, giving payload message %u to %s-%X on %s\n",
       ntohl (com->mid.mid),
       GSC_2s (ccc->c),
       ntohl (ccc->ccn.channel_of_client),
       GCCH_2s (ch));

  /* all good, pass next message to client */
  GNUNET_CONTAINER_DLL_remove (ccc->head_recv, ccc->tail_recv, com);
  ccc->num_recv--;
  /* FIXME: if unreliable, this is not aggressive
     enough, as it would be OK to have lost some! */

  ch->mid_recv.mid = htonl (1 + ntohl (com->mid.mid));
  ch->mid_futures >>= 1; /* equivalent to division by 2 */
  ccc->client_ready = GNUNET_NO;
  GSC_send_to_client (ccc->c, com->env);
  GNUNET_free (com);
  send_channel_data_ack (ch);
  if (NULL != ccc->head_recv)
    return;
  if (GNUNET_NO == ch->destroy)
    return;
  GCT_send_channel_destroy (ch->t, ch->ctn);
  channel_destroy (ch);
}


#define LOG2(level, ...) \
  GNUNET_log_from_nocheck (level, "cadet-chn", __VA_ARGS__)


/**
 * Log channel info.
 *
 * @param ch Channel.
 * @param level Debug level to use.
 */
void
GCCH_debug (struct CadetChannel *ch, enum GNUNET_ErrorType level)
{
#if ! defined(GNUNET_CULL_LOGGING)
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-chn",
                                       __FILE__,
                                       __FUNCTION__,
                                       __LINE__);
  if (0 == do_log)
    return;

  if (NULL == ch)
  {
    LOG2 (level, "CHN *** DEBUG NULL CHANNEL ***\n");
    return;
  }
  LOG2 (level, "CHN %s:%X (%p)\n", GCT_2s (ch->t), ch->ctn, ch);
  if (NULL != ch->owner)
  {
    LOG2 (level,
          "CHN origin %s ready %s local-id: %u\n",
          GSC_2s (ch->owner->c),
          ch->owner->client_ready ? "YES" : "NO",
          ntohl (ch->owner->ccn.channel_of_client));
  }
  if (NULL != ch->dest)
  {
    LOG2 (level,
          "CHN destination %s ready %s local-id: %u\n",
          GSC_2s (ch->dest->c),
          ch->dest->client_ready ? "YES" : "NO",
          ntohl (ch->dest->ccn.channel_of_client));
  }
  LOG2 (level,
        "CHN  Message IDs recv: %d (%LLX), send: %d\n",
        ntohl (ch->mid_recv.mid),
        (unsigned long long) ch->mid_futures,
        ntohl (ch->mid_send.mid));
#endif
}


/* end of gnunet-service-cadet_channel.c */
