
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_channel.c
 * @brief logical links between CADET clients
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * TODO:
 * - introduce shutdown so we can have half-closed channels, modify
 *   destroy to include MID to have FIN-ACK equivalents, etc.
 * - estimate max bandwidth using bursts and use to for CONGESTION CONTROL!
 * - check that '0xFFULL' really is sufficient for flow control!
 * - revisit handling of 'unreliable' traffic!
 * - revisit handling of 'out-of-order' option, especially in combination with/without 'reliable'.
 * - figure out flow control without ACKs (unreliable traffic!)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"

#define LOG(level,...) GNUNET_log_from (level,"cadet-chn",__VA_ARGS__)

/**
 * How long do we initially wait before retransmitting?
 */
#define CADET_INITIAL_RETRANSMIT_TIME GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * How long do we wait before dropping state about incoming
 * connection to closed port?
 */
#define TIMEOUT_CLOSED_PORT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)


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
   * Data message we are trying to send.
   */
  struct GNUNET_CADET_ChannelAppDataMessage data_message;

  /* followed by variable-size payload */
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
 * Struct containing all information regarding a channel to a remote client.
 */
struct CadetChannel
{
  /**
   * Tunnel this channel is in.
   */
  struct CadetTunnel *t;

  /**
   * Last entry in the tunnel's queue relating to control messages
   * (#GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN or
   * #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK).  Used to cancel
   * transmission in case we receive updated information.
   */
  struct CadetTunnelQueueEntry *last_control_qe;

  /**
   * Client owner of the tunnel, if any.
   * (Used if this channel represends the initiating end of the tunnel.)
   */
  struct CadetClient *owner;

  /**
   * Client destination of the tunnel, if any.
   * (Used if this channel represents the listening end of the tunnel.)
   */
  struct CadetClient *dest;

  /**
   * Head of DLL of messages sent and not yet ACK'd.
   */
  struct CadetReliableMessage *head_sent;

  /**
   * Tail of DLL of messages sent and not yet ACK'd.
   */
  struct CadetReliableMessage *tail_sent;

  /**
   * Head of DLL of messages received out of order or while client was unready.
   */
  struct CadetOutOfOrderMessage *head_recv;

  /**
   * Tail DLL of messages received out of order or while client was unready.
   */
  struct CadetOutOfOrderMessage *tail_recv;

  /**
   * Task to resend/poll in case no ACK is received.
   */
  struct GNUNET_SCHEDULER_Task *retry_task;

  /**
   * Last time the channel was used
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Destination port of the channel.
   */
  struct GNUNET_HashCode port;

  /**
   * Counter for exponential backoff.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * How long does it usually take to get an ACK.
   */
  struct GNUNET_TIME_Relative expected_delay;

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
   * Local tunnel number for local client owning the channel.
   * ( >= #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI or 0 )
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * Channel state.
   */
  enum CadetChannelState state;

  /**
   * Can we send data to the client?
   */
  int client_ready;

  /**
   * Can the client send data to us?
   */
  int client_allowed;

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
   * Flag to signal the destruction of the channel.  If this is set to
   * #GNUNET_YES the channel will be destroyed once the queue is
   * empty.
   */
  int destroy;

};


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
                   sizeof (buf),
                   "Channel %s:%s ctn:%X(%X)",
                   GNUNET_i2s (GCP_get_id (GCT_get_destination (ch->t))),
                   GNUNET_h2s (&ch->port),
                   ch->ctn,
                   ntohl (ch->ccn.channel_of_client));
  return buf;
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
 * Destroy the given channel.
 *
 * @param ch channel to destroy
 */
static void
channel_destroy (struct CadetChannel *ch)
{
  struct CadetReliableMessage *crm;
  struct CadetOutOfOrderMessage *com;

  while (NULL != (crm = ch->head_sent))
  {
    GNUNET_assert (ch == crm->ch);
    if (NULL != crm->qe)
    {
      GCT_send_cancel (crm->qe);
      crm->qe = NULL;
    }
    GNUNET_CONTAINER_DLL_remove (ch->head_sent,
                                 ch->tail_sent,
                                 crm);
    GNUNET_free (crm);
  }
  while (NULL != (com = ch->head_recv))
  {
    GNUNET_CONTAINER_DLL_remove (ch->head_recv,
                                 ch->tail_recv,
                                 com);
    GNUNET_MQ_discard (com->env);
    GNUNET_free (com);
  }
  if (NULL != ch->last_control_qe)
  {
    GCT_send_cancel (ch->last_control_qe);
    ch->last_control_qe = NULL;
  }
  if (NULL != ch->retry_task)
  {
    GNUNET_SCHEDULER_cancel (ch->retry_task);
    ch->retry_task = NULL;
  }
  GCT_remove_channel (ch->t,
                      ch,
                      ch->ctn);
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
 */
static void
channel_open_sent_cb (void *cls)
{
  struct CadetChannel *ch = cls;

  ch->last_control_qe = NULL;
  ch->retry_time = GNUNET_TIME_STD_BACKOFF (ch->retry_time);
  ch->retry_task = GNUNET_SCHEDULER_add_delayed (ch->retry_time,
                                                 &send_channel_open,
                                                 ch);
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
  uint32_t options;

  ch->retry_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CHANNEL_OPEN message for %s\n",
       GCCH_2s (ch));
  options = 0;
  if (ch->nobuffer)
    options |= GNUNET_CADET_OPTION_NOBUFFER;
  if (ch->reliable)
    options |= GNUNET_CADET_OPTION_RELIABLE;
  if (ch->out_of_order)
    options |= GNUNET_CADET_OPTION_OUT_OF_ORDER;
  msgcc.header.size = htons (sizeof (msgcc));
  msgcc.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN);
  msgcc.opt = htonl (options);
  msgcc.port = ch->port;
  msgcc.ctn = ch->ctn;
  ch->state = CADET_CHANNEL_OPEN_SENT;
  ch->last_control_qe = GCT_send (ch->t,
                                  &msgcc.header,
                                  &channel_open_sent_cb,
                                  ch);
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
  GNUNET_assert (NULL == ch->retry_task);
  ch->retry_task = GNUNET_SCHEDULER_add_now (&send_channel_open,
                                             ch);
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

  ch = GNUNET_new (struct CadetChannel);
  ch->nobuffer = (0 != (options & GNUNET_CADET_OPTION_NOBUFFER));
  ch->reliable = (0 != (options & GNUNET_CADET_OPTION_RELIABLE));
  ch->out_of_order = (0 != (options & GNUNET_CADET_OPTION_OUT_OF_ORDER));
  ch->max_pending_messages = (ch->nobuffer) ? 1 : 32; /* FIXME: 32!? Do not hardcode! */
  ch->owner = owner;
  ch->ccn = ccn;
  ch->port = *port;
  ch->t = GCP_get_tunnel (destination,
                          GNUNET_YES);
  ch->retry_time = CADET_INITIAL_RETRANSMIT_TIME;
  ch->ctn = GCT_add_channel (ch->t,
                             ch);
  GNUNET_STATISTICS_update (stats,
                            "# channels",
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created channel to port %s at peer %s for client %s using tunnel %s\n",
       GNUNET_h2s (port),
       GCP_2s (destination),
       GSC_2s (owner),
       GCT_2s (ch->t));
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

  ch->retry_task = NULL;
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
 * @param port desired local port
 * @param options options for the channel
 * @return handle to the new channel
 */
struct CadetChannel *
GCCH_channel_incoming_new (struct CadetTunnel *t,
                           struct GNUNET_CADET_ChannelTunnelNumber ctn,
                           const struct GNUNET_HashCode *port,
                           uint32_t options)
{
  struct CadetChannel *ch;
  struct CadetClient *c;

  ch = GNUNET_new (struct CadetChannel);
  ch->port = *port;
  ch->t = t;
  ch->ctn = ctn;
  ch->retry_time = CADET_INITIAL_RETRANSMIT_TIME;
  ch->nobuffer = (0 != (options & GNUNET_CADET_OPTION_NOBUFFER));
  ch->reliable = (0 != (options & GNUNET_CADET_OPTION_RELIABLE));
  ch->out_of_order = (0 != (options & GNUNET_CADET_OPTION_OUT_OF_ORDER));
  ch->max_pending_messages = (ch->nobuffer) ? 1 : 32; /* FIXME: 32!? Do not hardcode! */
  GNUNET_STATISTICS_update (stats,
                            "# channels",
                            1,
                            GNUNET_NO);

  c = GNUNET_CONTAINER_multihashmap_get (open_ports,
                                         port);
  if (NULL == c)
  {
    /* port closed, wait for it to possibly open */
    (void) GNUNET_CONTAINER_multihashmap_put (loose_channels,
                                              port,
                                              ch,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    ch->retry_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT_CLOSED_PORT,
                                                   &timeout_closed_cb,
                                                   ch);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Created loose incoming channel to port %s from peer %s\n",
         GNUNET_h2s (&ch->port),
         GCP_2s (GCT_get_destination (ch->t)));
  }
  else
  {
    GCCH_bind (ch,
               c);
  }
  GNUNET_STATISTICS_update (stats,
                            "# channels",
                            1,
                            GNUNET_NO);
  return ch;
}


/**
 * Function called once the tunnel confirms that we sent the
 * ACK message.  Just remembers it was sent, we do not expect
 * ACKs for ACKs ;-).
 *
 * @param cls our `struct CadetChannel`.
 */
static void
send_ack_cb (void *cls)
{
  struct CadetChannel *ch = cls;

  ch->last_control_qe = NULL;
}


/**
 * Compute and send the current ACK to the other peer.
 *
 * @param ch channel to send the ACK for
 */
static void
send_channel_data_ack (struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelDataAckMessage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK);
  msg.header.size = htons (sizeof (msg));
  msg.ctn = ch->ctn;
  msg.mid.mid = htonl (ntohl (ch->mid_recv.mid) - 1);
  msg.futures = GNUNET_htonll (ch->mid_futures);
  if (NULL != ch->last_control_qe)
    GCT_send_cancel (ch->last_control_qe);
  ch->last_control_qe = GCT_send (ch->t,
                                  &msg.header,
                                  &send_ack_cb,
                                  ch);
}


/**
 * Send our initial ACK to the client confirming that the
 * connection is up.
 *
 * @param cls the `struct CadetChannel`
 */
static void
send_connect_ack (void *cls)
{
  struct CadetChannel *ch = cls;

  ch->retry_task = NULL;
  send_channel_data_ack (ch);
}


/**
 * Send a LOCAL ACK to the client to solicit more messages.
 *
 * @param ch channel the ack is for
 * @param c client to send the ACK to
 */
static void
send_ack_to_client (struct CadetChannel *ch,
                    struct CadetClient *c)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalAck *ack;

  env = GNUNET_MQ_msg (ack,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  ack->ccn = ch->ccn;
  GSC_send_to_client (c,
                      env);
}


/**
 * A client is bound to the port that we have a channel
 * open to.  Send the acknowledgement for the connection
 * request and establish the link with the client.
 *
 * @param ch open incoming channel
 * @param c client listening on the respective port
 */
void
GCCH_bind (struct CadetChannel *ch,
           struct CadetClient *c)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalChannelCreateMessage *tcm;
  uint32_t options;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Binding %s from tunnel %s to port %s of client %s\n",
       GCCH_2s (ch),
       GCT_2s (ch->t),
       GNUNET_h2s (&ch->port),
       GSC_2s (c));
  if (NULL != ch->retry_task)
  {
    /* there might be a timeout task here */
    GNUNET_SCHEDULER_cancel (ch->retry_task);
    ch->retry_task = NULL;
  }
  options = 0;
  if (ch->nobuffer)
    options |= GNUNET_CADET_OPTION_NOBUFFER;
  if (ch->reliable)
    options |= GNUNET_CADET_OPTION_RELIABLE;
  if (ch->out_of_order)
    options |= GNUNET_CADET_OPTION_OUT_OF_ORDER;
  ch->dest = c;
  ch->ccn = GSC_bind (c,
                      ch,
                      GCT_get_destination (ch->t),
                      &ch->port,
                      options);
  ch->mid_recv.mid = htonl (1); /* The CONNECT counts as message 0! */

  /* notify other peer that we accepted the connection */
  ch->retry_task = GNUNET_SCHEDULER_add_now (&send_connect_ack,
                                             ch);
  /* give client it's initial supply of ACKs */
  env = GNUNET_MQ_msg (tcm,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE);
  tcm->ccn = ch->ccn;
  tcm->peer = *GCP_get_id (GCT_get_destination (ch->t));
  tcm->port = ch->port;
  tcm->opt = htonl (options);
  GSC_send_to_client (ch->dest,
                      env);
  for (unsigned int i=0;i<ch->max_pending_messages;i++)
    send_ack_to_client (ch,
                        ch->owner);
}


/**
 * Destroy locally created channel.  Called by the
 * local client, so no need to tell the client.
 *
 * @param ch channel to destroy
 */
void
GCCH_channel_local_destroy (struct CadetChannel *ch)
{
  if (GNUNET_YES == ch->destroy)
  {
    /* other end already destroyed, with the local client gone, no need
       to finish transmissions, just destroy immediately. */
    channel_destroy (ch);
    return;
  }
  if (NULL != ch->head_sent)
  {
    /* allow send queue to train first */
    ch->destroy = GNUNET_YES;
    return;
  }
  /* If the we ever sent the CHANNEL_CREATE, we need to send a destroy message. */
  if (CADET_CHANNEL_NEW != ch->state)
    GCT_send_channel_destroy (ch->t,
                              ch->ctn);
  /* Now finish our clean up */
  channel_destroy (ch);
}


/**
 * Destroy channel that was incoming.  Called by the
 * local client, so no need to tell the client.
 *
 * @param ch channel to destroy
 */
void
GCCH_channel_incoming_destroy (struct CadetChannel *ch)
{
  if (GNUNET_YES == ch->destroy)
  {
    /* other end already destroyed, with the remote client gone, no need
       to finish transmissions, just destroy immediately. */
    channel_destroy (ch);
    return;
  }
  if (NULL != ch->head_recv)
  {
    /* allow local client to see all data first */
    ch->destroy = GNUNET_YES;
    return;
  }
  /* Nothing left to do, just finish destruction */
  GCT_send_channel_destroy (ch->t,
                            ch->ctn);
  channel_destroy (ch);
}


/**
 * We got an acknowledgement for the creation of the channel
 * (the port is open on the other side). Begin transmissions.
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_channel_open_ack (struct CadetChannel *ch)
{
  switch (ch->state)
  {
  case CADET_CHANNEL_NEW:
    /* this should be impossible */
    GNUNET_break (0);
    break;
  case CADET_CHANNEL_OPEN_SENT:
    if (NULL == ch->owner)
    {
      /* We're not the owner, wrong direction! */
      GNUNET_break_op (0);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received channel OPEN_ACK for waiting %s, entering READY state\n",
         GCCH_2s (ch));
    GNUNET_SCHEDULER_cancel (ch->retry_task);
    ch->retry_task = NULL;
    ch->state = CADET_CHANNEL_READY;
    /* On first connect, send client as many ACKs as we allow messages
       to be buffered! */
    for (unsigned int i=0;i<ch->max_pending_messages;i++)
      send_ack_to_client (ch,
                          ch->owner);
    break;
  case CADET_CHANNEL_READY:
    /* duplicate ACK, maybe we retried the CREATE. Ignore. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received duplicate channel OPEN_ACK for %s\n",
         GCCH_2s (ch));
    GNUNET_STATISTICS_update (stats,
                              "# duplicate CREATE_ACKs",
                              1,
                              GNUNET_NO);
    break;
  }
}


/**
 * Test if element @a e1 comes before element @a e2.
 *
 * TODO: use opportunity to create generic list insertion sort
 * logic in container!
 *
 * @param cls closure, our `struct CadetChannel`
 * @param e1 an element of to sort
 * @param e2 another element to sort
 * @return #GNUNET_YES if @e1 < @e2, otherwise #GNUNET_NO
 */
static int
is_before (void *cls,
           void *e1,
           void *e2)
{
  struct CadetOutOfOrderMessage *m1 = e1;
  struct CadetOutOfOrderMessage *m2 = e2;
  uint32_t v1 = ntohl (m1->mid.mid);
  uint32_t v2 = ntohl (m2->mid.mid);
  uint32_t delta;

  delta = v1 - v2;
  if (delta > (uint32_t) INT_MAX)
  {
    /* in overflow range, we can safely assume we wrapped around */
    return GNUNET_NO;
  }
  else
  {
    return GNUNET_YES;
  }
}


/**
 * We got payload data for a channel.  Pass it on to the client
 * and send an ACK to the other end (once flow control allows it!)
 *
 * @param ch channel that got data
 */
void
GCCH_handle_channel_plaintext_data (struct CadetChannel *ch,
                                    const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalData *ld;
  struct CadetOutOfOrderMessage *com;
  size_t payload_size;

  payload_size = ntohs (msg->header.size) - sizeof (*msg);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receicved %u bytes of application data on %s\n",
       (unsigned int) payload_size,
       GCCH_2s (ch));
  env = GNUNET_MQ_msg_extra (ld,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA);
  ld->ccn = ch->ccn;
  GNUNET_memcpy (&ld[1],
                 &msg[1],
                 payload_size);
  if ( (GNUNET_YES == ch->client_ready) &&
       ( (GNUNET_YES == ch->out_of_order) ||
         (msg->mid.mid == ch->mid_recv.mid) ) )
  {
    GSC_send_to_client (ch->owner ? ch->owner : ch->dest,
                        env);
    ch->mid_recv.mid = htonl (1 + ntohl (ch->mid_recv.mid));
    ch->mid_futures >>= 1;
  }
  else
  {
    /* FIXME-SECURITY: if the element is WAY too far ahead,
       drop it (can't buffer too much!) */
    com = GNUNET_new (struct CadetOutOfOrderMessage);
    com->mid = msg->mid;
    com->env = env;
    /* sort into list ordered by "is_before" */
    if ( (NULL == ch->head_recv) ||
         (GNUNET_YES == is_before (ch,
                                   com,
                                   ch->head_recv)) )
    {
      GNUNET_CONTAINER_DLL_insert (ch->head_recv,
                                   ch->tail_recv,
                                   com);
    }
    else
    {
      struct CadetOutOfOrderMessage *pos;

      for (pos = ch->head_recv;
           NULL != pos;
           pos = pos->next)
      {
        if (GNUNET_YES !=
            is_before (ch,
                       pos,
                       com))
          break;
      }
      if (NULL == pos)
        GNUNET_CONTAINER_DLL_insert_tail (ch->head_recv,
                                          ch->tail_recv,
                                          com);
      else
        GNUNET_CONTAINER_DLL_insert_after (ch->head_recv,
                                           ch->tail_recv,
                                           com,
                                           pos->prev);
    }
  }
}


/**
 * We got an acknowledgement for payload data for a channel.
 * Possibly resume transmissions.
 *
 * @param ch channel that got the ack
 * @param ack details about what was received
 */
void
GCCH_handle_channel_plaintext_data_ack (struct CadetChannel *ch,
                                        const struct GNUNET_CADET_ChannelDataAckMessage *ack)
{
  struct CadetReliableMessage *crm;

  if (GNUNET_NO == ch->reliable)
  {
    /* not expecting ACKs on unreliable channel, odd */
    GNUNET_break_op (0);
    return;
  }
  for (crm = ch->head_sent;
        NULL != crm;
       crm = crm->next)
    if (ack->mid.mid == crm->data_message.mid.mid)
      break;
  if (NULL == crm)
  {
    /* ACK for message we already dropped, might have been a
       duplicate ACK? Ignore. */
    GNUNET_STATISTICS_update (stats,
                              "# duplicate DATA_ACKs",
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (ch->head_sent,
                               ch->tail_sent,
                               crm);
  ch->pending_messages--;
  GNUNET_free (crm);
  GNUNET_assert (ch->pending_messages < ch->max_pending_messages);
  send_ack_to_client (ch,
                      (NULL == ch->owner) ? ch->dest : ch->owner);
}


/**
 * Destroy channel, based on the other peer closing the
 * connection.  Also needs to remove this channel from
 * the tunnel.
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_remote_destroy (struct CadetChannel *ch)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalChannelDestroyMessage *tdm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received remote channel DESTROY for %s\n",
       GCCH_2s (ch));
  ch->destroy = GNUNET_YES;
  env = GNUNET_MQ_msg (tdm,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY);
  tdm->ccn = ch->ccn;
  GSC_send_to_client ((NULL != ch->owner) ? ch->owner : ch->dest,
                      env);
  channel_destroy (ch);
}


/**
 * Function called once the tunnel has sent one of our messages.
 * If the message is unreliable, simply frees the `crm`. If the
 * message was reliable, calculate retransmission time and
 * wait for ACK (or retransmit).
 *
 * @param cls the `struct CadetReliableMessage` that was sent
 */
static void
data_sent_cb (void *cls);


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

  ch->retry_task = NULL;
  GNUNET_assert (NULL == crm->qe);
  crm->qe = GCT_send (ch->t,
                      &crm->data_message.header,
                      &data_sent_cb,
                      crm);
}


/**
 * Check if we can now allow the client to transmit, and if so,
 * let the client know about it.
 *
 * @param ch channel to check
 */
static void
GCCH_check_allow_client (struct CadetChannel *ch)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalAck *msg;

  if (GNUNET_YES == ch->client_allowed)
    return; /* client already allowed! */
  if (CADET_CHANNEL_READY != ch->state)
  {
    /* destination did not yet ACK our CREATE! */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s not yet ready, throttling client until ACK.\n",
         GCCH_2s (ch));
    return;
  }
  if (ch->pending_messages > ch->max_pending_messages)
  {
    /* Too many messages in queue. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Message queue still too long on %s, throttling client until ACK.\n",
         GCCH_2s (ch));
    return;
  }
  if ( (NULL != ch->head_sent) &&
       (64 <= ntohl (ch->mid_send.mid) - ntohl (ch->head_sent->data_message.mid.mid)) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Gap in ACKs too big on %s, throttling client until ACK.\n",
         GCCH_2s (ch));
    return;
  }
  ch->client_allowed = GNUNET_YES;


  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending local ack to %s client\n",
       GCCH_2s (ch));
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  msg->ccn = ch->ccn;
  GSC_send_to_client (ch->owner ? ch->owner : ch->dest,
                      env);
}


/**
 * Function called once the tunnel has sent one of our messages.
 * If the message is unreliable, simply frees the `crm`. If the
 * message was reliable, calculate retransmission time and
 * wait for ACK (or retransmit).
 *
 * @param cls the `struct CadetReliableMessage` that was sent
 */
static void
data_sent_cb (void *cls)
{
  struct CadetReliableMessage *crm = cls;
  struct CadetChannel *ch = crm->ch;
  struct CadetReliableMessage *off;

  crm->qe = NULL;
  GNUNET_CONTAINER_DLL_remove (ch->head_sent,
                               ch->tail_sent,
                               crm);
  if (GNUNET_NO == ch->reliable)
  {
    GNUNET_free (crm);
    ch->pending_messages--;
    GCCH_check_allow_client (ch);
    return;
  }
  if (0 == crm->retry_delay.rel_value_us)
    crm->retry_delay = ch->expected_delay;
  crm->next_retry = GNUNET_TIME_relative_to_absolute (crm->retry_delay);

  /* find position for re-insertion into the DLL */
  if ( (NULL == ch->head_sent) ||
       (crm->next_retry.abs_value_us < ch->head_sent->next_retry.abs_value_us) )
  {
    /* insert at HEAD, also (re)schedule retry task! */
    GNUNET_CONTAINER_DLL_insert (ch->head_sent,
                                 ch->tail_sent,
                                 crm);
    if (NULL != ch->retry_task)
      GNUNET_SCHEDULER_cancel (ch->retry_task);
    ch->retry_task = GNUNET_SCHEDULER_add_delayed (crm->retry_delay,
                                                   &retry_transmission,
                                                   ch);
    return;
  }
  for (off = ch->head_sent; NULL != off; off = off->next)
    if (crm->next_retry.abs_value_us < off->next_retry.abs_value_us)
      break;
  if (NULL == off)
  {
    /* insert at tail */
    GNUNET_CONTAINER_DLL_insert_tail (ch->head_sent,
                                      ch->tail_sent,
                                      crm);
  }
  else
  {
    /* insert before off */
    GNUNET_CONTAINER_DLL_insert_after (ch->head_sent,
                                       ch->tail_sent,
                                       off->prev,
                                       crm);
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
 * @param message payload to transmit.
 * @return #GNUNET_OK if everything goes well,
 *         #GNUNET_SYSERR in case of an error.
 */
int
GCCH_handle_local_data (struct CadetChannel *ch,
                        const struct GNUNET_MessageHeader *message)
{
  uint16_t payload_size = ntohs (message->size);
  struct CadetReliableMessage *crm;

  if (GNUNET_NO == ch->client_allowed)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  ch->client_allowed = GNUNET_NO;
  ch->pending_messages++;

  /* Everything is correct, send the message. */
  crm = GNUNET_malloc (sizeof (*crm) + payload_size);
  crm->ch = ch;
  crm->data_message.header.size = htons (sizeof (struct GNUNET_CADET_ChannelAppDataMessage) + payload_size);
  crm->data_message.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA);
  ch->mid_send.mid = htonl (ntohl (ch->mid_send.mid) + 1);
  crm->data_message.mid = ch->mid_send;
  crm->data_message.ctn = ch->ctn;
  GNUNET_memcpy (&crm[1],
                 message,
                 payload_size);
  GNUNET_CONTAINER_DLL_insert (ch->head_sent,
                               ch->tail_sent,
                               crm);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending %u bytes from local client to %s\n",
       payload_size,
       GCCH_2s (ch));
  crm->qe = GCT_send (ch->t,
                      &crm->data_message.header,
                      &data_sent_cb,
                      crm);
  GCCH_check_allow_client (ch);
  return GNUNET_OK;
}


/**
 * Try to deliver messages to the local client, if it is ready for more.
 *
 * @param ch channel to process
 */
static void
send_client_buffered_data (struct CadetChannel *ch)
{
  struct CadetOutOfOrderMessage *com;

  if (GNUNET_NO == ch->client_ready)
    return; /* client not ready */
  com = ch->head_recv;
  if (NULL == com)
    return; /* none pending */
  if ( (com->mid.mid != ch->mid_recv.mid) &&
       (GNUNET_NO == ch->out_of_order) )
    return; /* missing next one in-order */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Passing payload message to client on %s\n",
              GCCH_2s (ch));

  /* all good, pass next message to client */
  GNUNET_CONTAINER_DLL_remove (ch->head_recv,
                               ch->tail_recv,
                               com);
  /* FIXME: if unreliable, this is not aggressive
     enough, as it would be OK to have lost some! */
  ch->mid_recv.mid = htonl (1 + ntohl (com->mid.mid));
  ch->mid_futures >>= 1; /* equivalent to division by 2 */
  GSC_send_to_client (ch->owner ? ch->owner : ch->dest,
                      com->env);
  GNUNET_free (com);
  if ( (0xFFULL == (ch->mid_futures & 0xFFULL)) &&
       (GNUNET_YES == ch->reliable) )
  {
    /* The next 15 messages were also already received (0xFF), this
       suggests that the sender may be blocked on flow control
       urgently waiting for an ACK from us. (As we have an inherent
       maximum of 64 bits, and 15 is getting too close for comfort.)
       So we should send one now. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sender on %s likely blocked on flow-control, sending ACK now.\n",
                GCCH_2s (ch));
    if (GNUNET_YES == ch->reliable)
      send_channel_data_ack (ch);
  }

  if (NULL != ch->head_recv)
    return;
  if (GNUNET_NO == ch->destroy)
    return;
  GCT_send_channel_destroy (ch->t,
                            ch->ctn);
  channel_destroy (ch);
}


/**
 * Handle ACK from client on local channel.
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_local_ack (struct CadetChannel *ch)
{
  ch->client_ready = GNUNET_YES;
  send_client_buffered_data (ch);
}


#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-chn",__VA_ARGS__)


/**
 * Log channel info.
 *
 * @param ch Channel.
 * @param level Debug level to use.
 */
void
GCCH_debug (struct CadetChannel *ch,
            enum GNUNET_ErrorType level)
{
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-chn",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  if (NULL == ch)
  {
    LOG2 (level, "CHN *** DEBUG NULL CHANNEL ***\n");
    return;
  }
  LOG2 (level,
        "CHN %s:%X (%p)\n",
        GCT_2s (ch->t),
        ch->ctn,
        ch);
  if (NULL != ch->owner)
  {
    LOG2 (level,
          "CHN origin %s ready %s local-id: %u\n",
          GSC_2s (ch->owner),
          ch->client_ready ? "YES" : "NO",
          ntohl (ch->ccn.channel_of_client));
  }
  if (NULL != ch->dest)
  {
    LOG2 (level,
          "CHN destination %s ready %s local-id: %u\n",
          GSC_2s (ch->dest),
          ch->client_ready ? "YES" : "NO",
          ntohl (ch->ccn.channel_of_client));
  }
  LOG2 (level,
        "CHN  Message IDs recv: %d (%LLX), send: %d\n",
        ntohl (ch->mid_recv.mid),
        (unsigned long long) ch->mid_futures,
        ntohl (ch->mid_send.mid));
}



/* end of gnunet-service-cadet-new_channel.c */
