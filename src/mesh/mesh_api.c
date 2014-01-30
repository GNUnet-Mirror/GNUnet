/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)
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
 * @file mesh/mesh_api.c
 * @brief mesh api: client implementation of new mesh service
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "mesh.h"
#include "mesh_protocol.h"

#define LOG(kind,...) GNUNET_log_from (kind, "mesh-api",__VA_ARGS__)

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Transmission queue to the service
 */
struct GNUNET_MESH_TransmitHandle
{

    /**
     * Double Linked list
     */
  struct GNUNET_MESH_TransmitHandle *next;

    /**
     * Double Linked list
     */
  struct GNUNET_MESH_TransmitHandle *prev;

    /**
     * Channel this message is sent on / for (may be NULL for control messages).
     */
  struct GNUNET_MESH_Channel *channel;

    /**
     * Callback to obtain the message to transmit, or NULL if we
     * got the message in 'data'.  Notice that messages built
     * by 'notify' need to be encapsulated with information about
     * the 'target'.
     */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

    /**
     * Closure for 'notify'
     */
  void *notify_cls;

    /**
     * How long is this message valid.  Once the timeout has been
     * reached, the message must no longer be sent.  If this
     * is a message with a 'notify' callback set, the 'notify'
     * function should be called with 'buf' NULL and size 0.
     */
  struct GNUNET_TIME_Absolute timeout;

    /**
     * Task triggering a timeout, can be NO_TASK if the timeout is FOREVER.
     */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

    /**
     * Size of 'data' -- or the desired size of 'notify' if 'data' is NULL.
     */
  size_t size;
};


/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle
{

    /**
     * Handle to the server connection, to send messages later
     */
  struct GNUNET_CLIENT_Connection *client;

    /**
     * Set of handlers used for processing incoming messages in the channels
     */
  const struct GNUNET_MESH_MessageHandler *message_handlers;

  /**
   * Number of handlers in the handlers array.
   */
  unsigned int n_handlers;

  /**
   * Ports open.
   */
  const uint32_t *ports;

  /**
   * Number of ports.
   */
  unsigned int n_ports;

    /**
     * Double linked list of the channels this client is connected to, head.
     */
  struct GNUNET_MESH_Channel *channels_head;

    /**
     * Double linked list of the channels this client is connected to, tail.
     */
  struct GNUNET_MESH_Channel *channels_tail;

    /**
     * Callback for inbound channel creation
     */
  GNUNET_MESH_InboundChannelNotificationHandler *new_channel;

    /**
     * Callback for inbound channel disconnection
     */
  GNUNET_MESH_ChannelEndHandler *cleaner;

    /**
     * Handle to cancel pending transmissions in case of disconnection
     */
  struct GNUNET_CLIENT_TransmitHandle *th;

    /**
     * Closure for all the handlers given by the client
     */
  void *cls;

    /**
     * Messages to send to the service, head.
     */
  struct GNUNET_MESH_TransmitHandle *th_head;

    /**
     * Messages to send to the service, tail.
     */
  struct GNUNET_MESH_TransmitHandle *th_tail;

    /**
     * chid of the next channel to create (to avoid reusing IDs often)
     */
  MESH_ChannelNumber next_chid;

    /**
     * Have we started the task to receive messages from the service
     * yet? We do this after we send the 'MESH_LOCAL_CONNECT' message.
     */
  int in_receive;

  /**
   * Configuration given by the client, in case of reconnection
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Time to the next reconnect in case one reconnect fails
   */
  struct GNUNET_TIME_Relative reconnect_time;

  /**
   * Task for trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Monitor callback
   */
  GNUNET_MESH_ChannelsCB channels_cb;

  /**
   * Monitor callback closure.
   */
  void *channels_cls;

  /**
   * Channel callback.
   */
  GNUNET_MESH_ChannelCB channel_cb;

  /**
   * Channel callback closure.
   */
  void *channel_cls;

  /**
   * Monitor callback
   */
  GNUNET_MESH_PeersCB peers_cb;

  /**
   * Monitor callback closure.
   */
  void *peers_cls;

  /**
   * Monitor callback
   */
  GNUNET_MESH_TunnelsCB tunnels_cb;

  /**
   * Monitor callback closure.
   */
  void *tunnels_cls;

  /**
   * Tunnel callback.
   */
  GNUNET_MESH_TunnelCB tunnel_cb;

  /**
   * Tunnel callback closure.
   */
  void *tunnel_cls;
};


/**
 * Description of a peer
 */
struct GNUNET_MESH_Peer
{
    /**
     * ID of the peer in short form
     */
  GNUNET_PEER_Id id;

  /**
   * Channel this peer belongs to
   */
  struct GNUNET_MESH_Channel *t;
};


/**
 * Opaque handle to a channel.
 */
struct GNUNET_MESH_Channel
{

    /**
     * DLL next
     */
  struct GNUNET_MESH_Channel *next;

    /**
     * DLL prev
     */
  struct GNUNET_MESH_Channel *prev;

    /**
     * Handle to the mesh this channel belongs to
     */
  struct GNUNET_MESH_Handle *mesh;

    /**
     * Local ID of the channel
     */
  MESH_ChannelNumber chid;

    /**
     * Port number.
     */
  uint32_t port;

    /**
     * Other end of the channel.
     */
  GNUNET_PEER_Id peer;

  /**
   * Any data the caller wants to put in here
   */
  void *ctx;

    /**
     * Size of packet queued in this channel
     */
  unsigned int packet_size;

    /**
     * Channel options: reliability, etc.
     */
  enum GNUNET_MESH_ChannelOption options;

    /**
     * Are we allowed to send to the service?
     */
  int allow_send;

};


/**
 * Implementation state for mesh's message queue.
 */
struct MeshMQState
{
  /**
   * The current transmit handle, or NULL
   * if no transmit is active.
   */
  struct GNUNET_MESH_TransmitHandle *th;

  /**
   * Channel to send the data over.
   */
  struct GNUNET_MESH_Channel *channel;
};


/******************************************************************************/
/***********************         DECLARATIONS         *************************/
/******************************************************************************/

/**
 * Function called to send a message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, the mesh handle
 * @param size number of bytes available in buf
 * @param buf where the callee should write the connect message
 * @return number of bytes written to buf
 */
static size_t
send_callback (void *cls, size_t size, void *buf);


/******************************************************************************/
/***********************     AUXILIARY FUNCTIONS      *************************/
/******************************************************************************/

/**
 * Check if transmission is a payload packet.
 *
 * @param th Transmission handle.
 *
 * @return GNUNET_YES if it is a payload packet,
 *         GNUNET_NO if it is a mesh management packet.
 */
static int
th_is_payload (struct GNUNET_MESH_TransmitHandle *th)
{
  return (th->notify != NULL) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Check whether there is any message ready in the queue and find the size.
 *
 * @param h Mesh handle.
 *
 * @return The size of the first ready message in the queue,
 *         0 if there is none.
 */
static size_t
message_ready_size (struct GNUNET_MESH_Handle *h)
{
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_Channel *ch;

  for (th = h->th_head; NULL != th; th = th->next)
  {
    ch = th->channel;
    if (GNUNET_NO == th_is_payload (th))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  message internal\n");
      return th->size;
    }
    if (GNUNET_YES == ch->allow_send)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  message payload ok\n");
      return th->size;
    }
  }
  return 0;
}


/**
 * Get the channel handler for the channel specified by id from the given handle
 * @param h Mesh handle
 * @param chid ID of the wanted channel
 * @return handle to the required channel or NULL if not found
 */
static struct GNUNET_MESH_Channel *
retrieve_channel (struct GNUNET_MESH_Handle *h, MESH_ChannelNumber chid)
{
  struct GNUNET_MESH_Channel *ch;

  ch = h->channels_head;
  while (ch != NULL)
  {
    if (ch->chid == chid)
      return ch;
    ch = ch->next;
  }
  return NULL;
}


/**
 * Create a new channel and insert it in the channel list of the mesh handle
 *
 * @param h Mesh handle
 * @param chid Desired chid of the channel, 0 to assign one automatically.
 *
 * @return Handle to the created channel.
 */
static struct GNUNET_MESH_Channel *
create_channel (struct GNUNET_MESH_Handle *h, MESH_ChannelNumber chid)
{
  struct GNUNET_MESH_Channel *ch;

  ch = GNUNET_new (struct GNUNET_MESH_Channel);
  GNUNET_CONTAINER_DLL_insert (h->channels_head, h->channels_tail, ch);
  ch->mesh = h;
  if (0 == chid)
  {
    ch->chid = h->next_chid;
    while (NULL != retrieve_channel (h, h->next_chid))
    {
      h->next_chid++;
      h->next_chid &= ~GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
      h->next_chid |= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
    }
  }
  else
  {
    ch->chid = chid;
  }
  ch->allow_send = GNUNET_NO;
  return ch;
}


/**
 * Destroy the specified channel.
 * - Destroys all peers, calling the disconnect callback on each if needed
 * - Cancels all outgoing traffic for that channel, calling respective notifys
 * - Calls cleaner if channel was inbound
 * - Frees all memory used
 *
 * @param ch Pointer to the channel.
 * @param call_cleaner Whether to call the cleaner handler.
 *
 * @return Handle to the required channel or NULL if not found.
 */
static void
destroy_channel (struct GNUNET_MESH_Channel *ch, int call_cleaner)
{
  struct GNUNET_MESH_Handle *h;
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_TransmitHandle *next;

  LOG (GNUNET_ERROR_TYPE_DEBUG, " destroy_channel %X\n", ch->chid);

  if (NULL == ch)
  {
    GNUNET_break (0);
    return;
  }
  h = ch->mesh;

  GNUNET_CONTAINER_DLL_remove (h->channels_head, h->channels_tail, ch);

  /* signal channel destruction */
  if ( (NULL != h->cleaner) && (0 != ch->peer) && (GNUNET_YES == call_cleaner) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " calling cleaner\n");
    h->cleaner (h->cls, ch, ch->ctx);
  }

  /* check that clients did not leave messages behind in the queue */
  for (th = h->th_head; NULL != th; th = next)
  {
    next = th->next;
    if (th->channel != ch)
      continue;
    /* Clients should have aborted their requests already.
     * Management traffic should be ok, as clients can't cancel that.
     * If the service crashed and we are reconnecting, it's ok.
     */
    GNUNET_break (GNUNET_NO == th_is_payload (th)
                  || GNUNET_NO == h->in_receive);
    GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);

    /* clean up request */
    if (GNUNET_SCHEDULER_NO_TASK != th->timeout_task)
      GNUNET_SCHEDULER_cancel (th->timeout_task);
    GNUNET_free (th);
  }

  /* if there are no more pending requests with mesh service, cancel active request */
  /* Note: this should be unnecessary... */
  if ((0 == message_ready_size (h)) && (NULL != h->th))
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }

  if (0 != ch->peer)
    GNUNET_PEER_change_rc (ch->peer, -1);
  GNUNET_free (ch);
  return;
}


/**
 * Notify client that the transmission has timed out
 *
 * @param cls closure
 * @param tc task context
 */
static void
timeout_transmission (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_TransmitHandle *th = cls;
  struct GNUNET_MESH_Handle *mesh;

  mesh = th->channel->mesh;
  GNUNET_CONTAINER_DLL_remove (mesh->th_head, mesh->th_tail, th);
  th->channel->packet_size = 0;
  if (GNUNET_YES == th_is_payload (th))
    th->notify (th->notify_cls, 0, NULL);
  GNUNET_free (th);
  if ((0 == message_ready_size (mesh)) && (NULL != mesh->th))
  {
    /* nothing ready to transmit, no point in asking for transmission */
    GNUNET_CLIENT_notify_transmit_ready_cancel (mesh->th);
    mesh->th = NULL;
  }
}


/**
 * Add a transmit handle to the transmission queue and set the
 * timeout if needed.
 *
 * @param h mesh handle with the queue head and tail
 * @param th handle to the packet to be transmitted
 */
static void
add_to_queue (struct GNUNET_MESH_Handle *h,
              struct GNUNET_MESH_TransmitHandle *th)
{
  GNUNET_CONTAINER_DLL_insert_tail (h->th_head, h->th_tail, th);
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us == th->timeout.abs_value_us)
    return;
  th->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (th->timeout), &timeout_transmission, th);
}


/**
 * Auxiliary function to send an already constructed packet to the service.
 * Takes care of creating a new queue element, copying the message and
 * calling the tmt_rdy function if necessary.
 *
 * @param h mesh handle
 * @param msg message to transmit
 * @param channel channel this send is related to (NULL if N/A)
 */
static void
send_packet (struct GNUNET_MESH_Handle *h,
             const struct GNUNET_MessageHeader *msg,
             struct GNUNET_MESH_Channel *channel);


/**
 * Send an ack on the channel to confirm the processing of a message.
 *
 * @param ch Channel on which to send the ACK.
 */
static void
send_ack (struct GNUNET_MESH_Channel *ch)
{
  struct GNUNET_MESH_LocalAck msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending ACK on channel %X\n", ch->chid);
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.header.size = htons (sizeof (msg));
  msg.channel_id = htonl (ch->chid);

  send_packet (ch->mesh, &msg.header, ch);
  return;
}



/**
 * Reconnect callback: tries to reconnect again after a failer previous
 * reconnecttion
 * @param cls closure (mesh handle)
 * @param tc task context
 */
static void
reconnect_cbk (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Send a connect packet to the service with the applications and types
 * requested by the user.
 *
 * @param h The mesh handle.
 *
 */
static void
send_connect (struct GNUNET_MESH_Handle *h)
{
  size_t size;

  size = sizeof (struct GNUNET_MESH_ClientConnect);
  size += h->n_ports * sizeof (uint32_t);
  {
    char buf[size] GNUNET_ALIGN;
    struct GNUNET_MESH_ClientConnect *msg;
    uint32_t *ports;
    uint16_t i;

    /* build connection packet */
    msg = (struct GNUNET_MESH_ClientConnect *) buf;
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT);
    msg->header.size = htons (size);
    ports = (uint32_t *) &msg[1];
    for (i = 0; i < h->n_ports; i++)
    {
      ports[i] = htonl (h->ports[i]);
      LOG (GNUNET_ERROR_TYPE_DEBUG, " port %u\n",
           h->ports[i]);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending %lu bytes long message with %u ports\n",
         ntohs (msg->header.size), h->n_ports);
    send_packet (h, &msg->header, NULL);
  }
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the mesh
 *
 * @return GNUNET_YES in case of sucess, GNUNET_NO otherwise (service down...)
 */
static int
do_reconnect (struct GNUNET_MESH_Handle *h)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*****************************\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*******   RECONNECT   *******\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*****************************\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "******** on %p *******\n", h);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*****************************\n");

  /* disconnect */
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
  }

  /* connect again */
  h->client = GNUNET_CLIENT_connect ("mesh", h->cfg);
  if (h->client == NULL)
  {
    h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_time,
                                                      &reconnect_cbk, h);
    h->reconnect_time =
        GNUNET_TIME_relative_min (GNUNET_TIME_UNIT_SECONDS,
                                  GNUNET_TIME_relative_multiply
                                  (h->reconnect_time, 2));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Next retry in %s\n",
         GNUNET_STRINGS_relative_time_to_string (h->reconnect_time,
                                                 GNUNET_NO));
    GNUNET_break (0);
    return GNUNET_NO;
  }
  else
  {
    h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
  }
  send_connect (h);
  return GNUNET_YES;
}

/**
 * Reconnect callback: tries to reconnect again after a failer previous
 * reconnecttion
 * @param cls closure (mesh handle)
 * @param tc task context
 */
static void
reconnect_cbk (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  do_reconnect (h);
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the mesh
 *
 * @return GNUNET_YES in case of sucess, GNUNET_NO otherwise (service down...)
 */
static void
reconnect (struct GNUNET_MESH_Handle *h)
{
  struct GNUNET_MESH_Channel *ch;
  struct GNUNET_MESH_Channel *next;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Requested RECONNECT, destroying all channels\n");
  h->in_receive = GNUNET_NO;
  for (ch = h->channels_head; NULL != ch; ch = next)
  {
    next = ch->next;
    destroy_channel (ch, GNUNET_YES);
  }
  if (GNUNET_SCHEDULER_NO_TASK == h->reconnect_task)
    h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_time,
                                                      &reconnect_cbk, h);
}


/******************************************************************************/
/***********************      RECEIVE HANDLERS     ****************************/
/******************************************************************************/

/**
 * Process the new channel notification and add it to the channels in the handle
 *
 * @param h     The mesh handle
 * @param msg   A message with the details of the new incoming channel
 */
static void
process_channel_created (struct GNUNET_MESH_Handle *h,
                        const struct GNUNET_MESH_ChannelMessage *msg)
{
  struct GNUNET_MESH_Channel *ch;
  MESH_ChannelNumber chid;
  uint32_t port;

  chid = ntohl (msg->channel_id);
  port = ntohl (msg->port);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Creating incoming channel %X:%u\n", chid, port);
  if (chid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL != h->new_channel)
  {
    void *ctx;

    ch = create_channel (h, chid);
    ch->allow_send = GNUNET_NO;
    ch->peer = GNUNET_PEER_intern (&msg->peer);
    ch->mesh = h;
    ch->chid = chid;
    ch->port = port;
    ch->options = ntohl (msg->opt);

    LOG (GNUNET_ERROR_TYPE_DEBUG, "  created channel %p\n", ch);
    ctx = h->new_channel (h->cls, ch, &msg->peer, ch->port, ch->options);
    if (NULL != ctx)
      ch->ctx = ctx;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "User notified\n");
  }
  else
  {
    struct GNUNET_MESH_ChannelMessage d_msg;

    LOG (GNUNET_ERROR_TYPE_DEBUG, "No handler for incoming channels\n");

    d_msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY);
    d_msg.header.size = htons (sizeof (struct GNUNET_MESH_ChannelMessage));
    d_msg.channel_id = msg->channel_id;
    memset (&d_msg.peer, 0, sizeof (struct GNUNET_PeerIdentity));
    d_msg.port = 0;
    d_msg.opt = 0;

    send_packet (h, &d_msg.header, NULL);
  }
  return;
}


/**
 * Process the channel destroy notification and free associated resources
 *
 * @param h     The mesh handle
 * @param msg   A message with the details of the channel being destroyed
 */
static void
process_channel_destroy (struct GNUNET_MESH_Handle *h,
                         const struct GNUNET_MESH_ChannelMessage *msg)
{
  struct GNUNET_MESH_Channel *ch;
  MESH_ChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel Destroy received from service\n");
  chid = ntohl (msg->channel_id);
  ch = retrieve_channel (h, chid);

  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "channel %X unknown\n", chid);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " destroying channel %X\n", ch->chid);
  destroy_channel (ch, GNUNET_YES);
}


/**
 * Process the incoming data packets, call appropriate handlers.
 *
 * @param h         The mesh handle
 * @param message   A message encapsulating the data
 */
static void
process_incoming_data (struct GNUNET_MESH_Handle *h,
                       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MessageHeader *payload;
  const struct GNUNET_MESH_MessageHandler *handler;
  struct GNUNET_MESH_LocalData *dmsg;
  struct GNUNET_MESH_Channel *ch;
  size_t size;
  unsigned int i;
  uint16_t type;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a data message!\n");
  dmsg = (struct GNUNET_MESH_LocalData *) message;
  ch = retrieve_channel (h, ntohl (dmsg->id));
  payload = (struct GNUNET_MessageHeader *) &dmsg[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  %s data on channel %s [%X]\n",
       GM_f2s (ch->chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV),
       GNUNET_i2s (GNUNET_PEER_resolve2 (ch->peer)), ntohl (dmsg->id));

  size = ntohs (message->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  %u bytes\n", size);

  if (NULL == ch)
  {
    /* Channel was ignored/destroyed, probably service didn't get it yet */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ignored!\n");
    return;
  }
  type = ntohs (payload->type);
  size = ntohs (payload->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  payload type %s\n", GM_m2s (type));
  for (i = 0; i < h->n_handlers; i++)
  {
    handler = &h->message_handlers[i];
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    checking handler for type %u\n",
         handler->type);
    if (handler->type == type)
    {
      if (GNUNET_OK !=
          handler->callback (h->cls, ch, &ch->ctx, payload))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "callback caused disconnection\n");
        GNUNET_MESH_channel_destroy (ch);
        return;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "callback completed successfully\n");
        return;
      }
    }
  }
}


/**
 * Process a local ACK message, enabling the client to send
 * more data to the service.
 *
 * @param h Mesh handle.
 * @param message Message itself.
 */
static void
process_ack (struct GNUNET_MESH_Handle *h,
             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_LocalAck *msg;
  struct GNUNET_MESH_Channel *ch;
  MESH_ChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got an ACK!\n");
  msg = (struct GNUNET_MESH_LocalAck *) message;
  chid = ntohl (msg->channel_id);
  ch = retrieve_channel (h, chid);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "ACK on unknown channel %X\n", chid);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on channel %X!\n", ch->chid);
  ch->allow_send = GNUNET_YES;
  if (NULL == h->th && 0 < ch->packet_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  tmt rdy was NULL, requesting!\n");
    h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, ch->packet_size,
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 GNUNET_YES, &send_callback, h);
  }
}


/*
 * Process a local reply about info on all channels, pass info to the user.
 *
 * @param h Mesh handle.
 * @param message Message itself.
 */
// static void
// process_get_channels (struct GNUNET_MESH_Handle *h,
//                      const struct GNUNET_MessageHeader *message)
// {
//   struct GNUNET_MESH_LocalInfo *msg;
//
//   GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Get Channels messasge received\n");
//
//   if (NULL == h->channels_cb)
//   {
//     GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  ignored\n");
//     return;
//   }
//
//   msg = (struct GNUNET_MESH_LocalInfo *) message;
//   if (ntohs (message->size) !=
//       (sizeof (struct GNUNET_MESH_LocalInfo) +
//        sizeof (struct GNUNET_PeerIdentity)))
//   {
//     GNUNET_break_op (0);
//     GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
//                 "Get channels message: size %hu - expected %u\n",
//                 ntohs (message->size),
//                 sizeof (struct GNUNET_MESH_LocalInfo));
//     return;
//   }
//   h->channels_cb (h->channels_cls,
//                   ntohl (msg->channel_id),
//                   &msg->owner,
//                   &msg->destination);
// }



/*
 * Process a local monitor_channel reply, pass info to the user.
 *
 * @param h Mesh handle.
 * @param message Message itself.
 */
// static void
// process_show_channel (struct GNUNET_MESH_Handle *h,
//                      const struct GNUNET_MessageHeader *message)
// {
//   struct GNUNET_MESH_LocalInfo *msg;
//   size_t esize;
//
//   GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Show Channel messasge received\n");
//
//   if (NULL == h->channel_cb)
//   {
//     GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  ignored\n");
//     return;
//   }
//
//   /* Verify message sanity */
//   msg = (struct GNUNET_MESH_LocalInfo *) message;
//   esize = sizeof (struct GNUNET_MESH_LocalInfo);
//   if (ntohs (message->size) != esize)
//   {
//     GNUNET_break_op (0);
//     GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
//                 "Show channel message: size %hu - expected %u\n",
//                 ntohs (message->size),
//                 esize);
//
//     h->channel_cb (h->channel_cls, NULL, NULL);
//     h->channel_cb = NULL;
//     h->channel_cls = NULL;
//
//     return;
//   }
//
//   h->channel_cb (h->channel_cls,
//                  &msg->destination,
//                  &msg->owner);
// }




/*
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param h Mesh handle.
 * @param message Message itself.
 */
static void
process_get_tunnels (struct GNUNET_MESH_Handle *h,
                     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_LocalInfoTunnel *msg;
  uint16_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Get Tunnels messasge received\n");

  if (NULL == h->tunnels_cb)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ignored\n");
    return;
  }

  size = ntohs (message->size);
  if (sizeof (struct GNUNET_MESH_LocalInfoTunnel) > size)
  {
    h->tunnels_cb (h->tunnel_cls, NULL, 0, 0, 0, 0);
    h->tunnels_cb = NULL;
    h->tunnels_cls = NULL;
    return;
  }

  msg = (struct GNUNET_MESH_LocalInfoTunnel *) message;
  h->tunnels_cb (h->tunnel_cls,
                 &msg->destination,
                 ntohl (msg->channels),
                 ntohl (msg->connections),
                 ntohs (msg->estate),
                 ntohs (msg->cstate));

}



/*
 * Process a local monitor_channel reply, pass info to the user.
 *
 * @param h Mesh handle.
 * @param message Message itself.
 */
static void
process_get_tunnel (struct GNUNET_MESH_Handle *h,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_LocalInfoTunnel *msg;
  size_t esize;
  size_t msize;
  unsigned int ch_n;
  unsigned int c_n;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Get Tunnel messasge received\n");
  if (NULL == h->tunnel_cb)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  ignored\n");
    return;
  }

  /* Verify message sanity */
  msg = (struct GNUNET_MESH_LocalInfoTunnel *) message;
  msize = ntohs (message->size);
  esize = sizeof (struct GNUNET_MESH_LocalInfoTunnel);
  if (esize > msize)
  {
    GNUNET_break_op (0);
    h->tunnel_cb (h->tunnel_cls, NULL, 0, 0, 0, 0);
    goto clean_cls;
  }
  ch_n = ntohl (msg->channels);
  c_n = ntohl (msg->connections);
  esize += ch_n * sizeof (MESH_ChannelNumber);
  esize += c_n * sizeof (struct GNUNET_HashCode);
  if (msize != esize)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "m:%u, e: %u (%u ch, %u conn)\n",
                msize, esize, ch_n, c_n);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u (%u ch, %u conn)\n",
                sizeof (struct GNUNET_MESH_LocalInfoTunnel),
                sizeof (MESH_ChannelNumber), sizeof (struct GNUNET_HashCode));
    h->tunnel_cb (h->tunnel_cls, NULL, 0, 0, 0, 0);
    goto clean_cls;
  }

  /* Call Callback with tunnel info. */
  h->tunnel_cb (h->tunnel_cls, &msg->destination,
                ch_n, c_n,
                ntohs (msg->estate), ntohs (msg->cstate));

clean_cls:
  h->tunnel_cb = NULL;
  h->tunnel_cls = NULL;
}

/**
 * Function to process all messages received from the service
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
msg_received (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MESH_Handle *h = cls;
  uint16_t type;

  if (msg == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Mesh service disconnected, reconnecting\n", h);
    reconnect (h);
    return;
  }
  type = ntohs (msg->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received a message: %s\n",
       GM_m2s (type));
  switch (type)
  {
    /* Notify of a new incoming channel */
  case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    process_channel_created (h, (struct GNUNET_MESH_ChannelMessage *) msg);
    break;
    /* Notify of a channel disconnection */
  case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY: /* TODO separate(gid problem)*/
  case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_NACK:
    process_channel_destroy (h, (struct GNUNET_MESH_ChannelMessage *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA:
    process_incoming_data (h, msg);
    break;
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK:
    process_ack (h, msg);
    break;
//   case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNELS:
//     process_get_channels (h, msg);
//     break;
//   case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNEL:
//     process_show_channel (h, msg);
//     break;
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS:
    process_get_tunnels (h, msg);
    break;
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL:
    process_get_tunnel (h, msg);
    break;
//   case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNEL:
//     process_show_channel (h, msg);
//     break;
  default:
    /* We shouldn't get any other packages, log and ignore */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "unsolicited message form service (type %s)\n",
         GM_m2s (ntohs (msg->type)));
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "message processed\n");
  if (GNUNET_YES == h->in_receive)
  {
    GNUNET_CLIENT_receive (h->client, &msg_received, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "in receive off, not calling CLIENT_receive\n");
  }
}


/******************************************************************************/
/************************       SEND FUNCTIONS     ****************************/
/******************************************************************************/

/**
 * Function called to send a message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, the mesh handle
 * @param size number of bytes available in buf
 * @param buf where the callee should write the connect message
 * @return number of bytes written to buf
 */
static size_t
send_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_Handle *h = cls;
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_TransmitHandle *next;
  struct GNUNET_MESH_Channel *ch;
  char *cbuf = buf;
  size_t tsize;
  size_t psize;
  size_t nsize;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "# Send packet() Buffer %u\n", size);
  if ((0 == size) || (NULL == buf))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "# Received NULL send callback on %p\n", h);
    reconnect (h);
    h->th = NULL;
    return 0;
  }
  tsize = 0;
  next = h->th_head;
  nsize = message_ready_size (h);
  while ((NULL != (th = next)) && (0 < nsize) && (size >= nsize))
  {
    ch = th->channel;
    if (GNUNET_YES == th_is_payload (th))
    {
      struct GNUNET_MESH_LocalData *dmsg;
      struct GNUNET_MessageHeader *mh;

      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  payload\n");
      if (GNUNET_NO == ch->allow_send)
      {
        /* This channel is not ready to transmit yet, try next message */
        next = th->next;
        continue;
      }
      ch->packet_size = 0;
      GNUNET_assert (size >= th->size);
      dmsg = (struct GNUNET_MESH_LocalData *) cbuf;
      mh = (struct GNUNET_MessageHeader *) &dmsg[1];
      psize = th->notify (th->notify_cls,
                          size - sizeof (struct GNUNET_MESH_LocalData),
                          mh);
      if (psize > 0)
      {
        psize += sizeof (struct GNUNET_MESH_LocalData);
        GNUNET_assert (size >= psize);
        dmsg->header.size = htons (psize);
        dmsg->id = htonl (ch->chid);
        dmsg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "#  payload type %s\n",
             GM_m2s (ntohs (mh->type)));
                ch->allow_send = GNUNET_NO;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "#  callback returned size 0, "
             "application canceled transmission\n");
      }
    }
    else
    {
      struct GNUNET_MessageHeader *mh = (struct GNUNET_MessageHeader *) &th[1];

      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  mesh internal traffic, type %s\n",
           GM_m2s (ntohs (mh->type)));
      memcpy (cbuf, &th[1], th->size);
      psize = th->size;
    }
    if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (th->timeout_task);
    GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);
    GNUNET_free (th);
    next = h->th_head;
    nsize = message_ready_size (h);
    cbuf += psize;
    size -= psize;
    tsize += psize;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "#  total size: %u\n", tsize);
  h->th = NULL;
  size = message_ready_size (h);
  if (0 != size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "#  next size: %u\n", size);
    h->th =
        GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_callback, h);
  }
  else
  {
    if (NULL != h->th_head)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  can't transmit any more\n");
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG, "#  nothing left to transmit\n");
  }
  if (GNUNET_NO == h->in_receive)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "# start receiving from service\n");
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &msg_received, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "# Send packet() END\n");
  return tsize;
}


/**
 * Auxiliary function to send an already constructed packet to the service.
 * Takes care of creating a new queue element, copying the message and
 * calling the tmt_rdy function if necessary.
 *
 * @param h mesh handle
 * @param msg message to transmit
 * @param channel channel this send is related to (NULL if N/A)
 */
static void
send_packet (struct GNUNET_MESH_Handle *h,
             const struct GNUNET_MessageHeader *msg,
             struct GNUNET_MESH_Channel *channel)
{
  struct GNUNET_MESH_TransmitHandle *th;
  size_t msize;

  LOG (GNUNET_ERROR_TYPE_DEBUG, " Sending message to service: %s\n",
       GM_m2s(ntohs(msg->type)));
  msize = ntohs (msg->size);
  th = GNUNET_malloc (sizeof (struct GNUNET_MESH_TransmitHandle) + msize);
  th->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  th->size = msize;
  th->channel = channel;
  memcpy (&th[1], msg, msize);
  add_to_queue (h, th);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  queued\n");
  if (NULL != h->th)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  calling ntfy tmt rdy for %u bytes\n", msize);
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client, msize,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &send_callback, h);
}


/******************************************************************************/
/**********************      API CALL DEFINITIONS     *************************/
/******************************************************************************/

struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, void *cls,
                     GNUNET_MESH_InboundChannelNotificationHandler new_channel,
                     GNUNET_MESH_ChannelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const uint32_t *ports)
{
  struct GNUNET_MESH_Handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GNUNET_MESH_connect()\n");
  h = GNUNET_new (struct GNUNET_MESH_Handle);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " addr %p\n", h);
  h->cfg = cfg;
  h->new_channel = new_channel;
  h->cleaner = cleaner;
  h->client = GNUNET_CLIENT_connect ("mesh", cfg);
  if (h->client == NULL)
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  h->cls = cls;
  h->message_handlers = handlers;
  h->ports = ports;
  h->next_chid = GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
  h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL != ports && ports[0] != 0 && NULL == new_channel)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "no new channel handler given, ports parameter is useless!!\n");
  }
  if ((NULL == ports || ports[0] == 0) && NULL != new_channel)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "no ports given, new channel handler will never be called!!\n");
  }
  /* count handlers */
  for (h->n_handlers = 0;
       handlers && handlers[h->n_handlers].type;
       h->n_handlers++) ;
  for (h->n_ports = 0;
       ports && ports[h->n_ports];
       h->n_ports++) ;
  send_connect (h);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "GNUNET_MESH_connect() END\n");
  return h;
}


void
GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle)
{
  struct GNUNET_MESH_Channel *ch;
  struct GNUNET_MESH_Channel *aux;
  struct GNUNET_MESH_TransmitHandle *th;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "MESH DISCONNECT\n");

  ch = handle->channels_head;
  while (NULL != ch)
  {
    aux = ch->next;
    if (ch->chid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    {
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "channel %X not destroyed\n", ch->chid);
    }
    destroy_channel (ch, GNUNET_YES);
    ch = aux;
  }
  while ( (th = handle->th_head) != NULL)
  {
    struct GNUNET_MessageHeader *msg;

    /* Make sure it is an allowed packet (everything else should have been
     * already canceled).
     */
    GNUNET_break (GNUNET_NO == th_is_payload (th));
    msg = (struct GNUNET_MessageHeader *) &th[1];
    switch (ntohs(msg->type))
    {
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT:
      case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
      case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNELS:
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNEL:
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL:
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS:
        break;
      default:
        GNUNET_break (0);
        LOG (GNUNET_ERROR_TYPE_ERROR, "unexpected msg %u\n",
             ntohs(msg->type));
    }

    GNUNET_CONTAINER_DLL_remove (handle->th_head, handle->th_tail, th);
    GNUNET_free (th);
  }

  if (NULL != handle->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
    handle->th = NULL;
  }
  if (NULL != handle->client)
  {
    GNUNET_CLIENT_disconnect (handle->client);
    handle->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel(handle->reconnect_task);
    handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (handle);
}


/**
 * Create a new channel towards a remote peer.
 *
 * If the destination port is not open by any peer or the destination peer
 * does not accept the channel, #GNUNET_MESH_ChannelEndHandler will be called
 * for this channel.
 *
 * @param h mesh handle
 * @param channel_ctx client's channel context to associate with the channel
 * @param peer peer identity the channel should go to
 * @param port Port number.
 * @param options MeshOption flag field, with all desired option bits set to 1.
 *
 * @return handle to the channel
 */
struct GNUNET_MESH_Channel *
GNUNET_MESH_channel_create (struct GNUNET_MESH_Handle *h,
                            void *channel_ctx,
                            const struct GNUNET_PeerIdentity *peer,
                            uint32_t port,
                            enum GNUNET_MESH_ChannelOption options)
{
  struct GNUNET_MESH_Channel *ch;
  struct GNUNET_MESH_ChannelMessage msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new channel to %s:%u\n",
       GNUNET_i2s (peer), port);
  ch = create_channel (h, 0);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  at %p\n", ch);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  number %X\n", ch->chid);
  ch->ctx = channel_ctx;
  ch->peer = GNUNET_PEER_intern (peer);
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE);
  msg.header.size = htons (sizeof (struct GNUNET_MESH_ChannelMessage));
  msg.channel_id = htonl (ch->chid);
  msg.port = htonl (port);
  msg.peer = *peer;
  msg.opt = htonl (options);
  ch->allow_send = 0;
  send_packet (h, &msg.header, ch);
  return ch;
}


void
GNUNET_MESH_channel_destroy (struct GNUNET_MESH_Channel *channel)
{
  struct GNUNET_MESH_Handle *h;
  struct GNUNET_MESH_ChannelMessage msg;
  struct GNUNET_MESH_TransmitHandle *th;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying channel\n");
  h = channel->mesh;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY);
  msg.header.size = htons (sizeof (struct GNUNET_MESH_ChannelMessage));
  msg.channel_id = htonl (channel->chid);
  memset (&msg.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  msg.port = 0;
  msg.opt = 0;
  th = h->th_head;
  while (th != NULL)
  {
    struct GNUNET_MESH_TransmitHandle *aux;
    if (th->channel == channel)
    {
      aux = th->next;
      /* FIXME call the handler? */
      if (GNUNET_YES == th_is_payload (th))
        th->notify (th->notify_cls, 0, NULL);
      GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);
      GNUNET_free (th);
      th = aux;
    }
    else
      th = th->next;
  }

  destroy_channel (channel, GNUNET_YES);
  send_packet (h, &msg.header, NULL);
}


/**
 * Get information about a channel.
 *
 * @param channel Channel handle.
 * @param option Query (GNUNET_MESH_OPTION_*).
 * @param ... dependant on option, currently not used
 *
 * @return Union with an answer to the query.
 */
const union GNUNET_MESH_ChannelInfo *
GNUNET_MESH_channel_get_info (struct GNUNET_MESH_Channel *channel,
                              enum GNUNET_MESH_ChannelOption option, ...)
{
  static int bool_flag;
  const union GNUNET_MESH_ChannelInfo *ret;

  switch (option)
  {
    case GNUNET_MESH_OPTION_NOBUFFER:
    case GNUNET_MESH_OPTION_RELIABLE:
    case GNUNET_MESH_OPTION_OOORDER:
      if (0 != (option & channel->options))
        bool_flag = GNUNET_YES;
      else
        bool_flag = GNUNET_NO;
      ret = (const union GNUNET_MESH_ChannelInfo *) &bool_flag;
      break;
    case GNUNET_MESH_OPTION_PEER:
      ret = (const union GNUNET_MESH_ChannelInfo *) GNUNET_PEER_resolve2 (channel->peer);
      break;
    default:
      GNUNET_break (0);
      return NULL;
  }

  return ret;
}

struct GNUNET_MESH_TransmitHandle *
GNUNET_MESH_notify_transmit_ready (struct GNUNET_MESH_Channel *channel, int cork,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  struct GNUNET_MESH_TransmitHandle *th;

  GNUNET_assert (NULL != channel);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "MESH NOTIFY TRANSMIT READY\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    on channel %X\n", channel->chid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    allow_send %d\n", channel->allow_send);
  if (channel->chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    to origin\n");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    to destination\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    payload size %u\n", notify_size);
  GNUNET_assert (NULL != notify);
  GNUNET_assert (0 == channel->packet_size); // Only one data packet allowed
  th = GNUNET_new (struct GNUNET_MESH_TransmitHandle);
  th->channel = channel;
  th->timeout = GNUNET_TIME_relative_to_absolute (maxdelay);
  th->size = notify_size + sizeof (struct GNUNET_MESH_LocalData);
  channel->packet_size = th->size;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    total size %u\n", th->size);
  th->notify = notify;
  th->notify_cls = notify_cls;
  add_to_queue (channel->mesh, th);
  if (NULL != channel->mesh->th)
    return th;
  if (GNUNET_NO == channel->allow_send)
    return th;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    call client notify tmt rdy\n");
  channel->mesh->th =
      GNUNET_CLIENT_notify_transmit_ready (channel->mesh->client, th->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &send_callback,
                                           channel->mesh);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "MESH NOTIFY TRANSMIT READY END\n");
  return th;
}


void
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle *th)
{
  struct GNUNET_MESH_Handle *mesh;

  th->channel->packet_size = 0;
  mesh = th->channel->mesh;
  if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (th->timeout_task);
  GNUNET_CONTAINER_DLL_remove (mesh->th_head, mesh->th_tail, th);
  GNUNET_free (th);
  if ((0 == message_ready_size (mesh)) && (NULL != mesh->th))
  {
    /* queue empty, no point in asking for transmission */
    GNUNET_CLIENT_notify_transmit_ready_cancel (mesh->th);
    mesh->th = NULL;
  }
}


void
GNUNET_MESH_receive_done (struct GNUNET_MESH_Channel *channel)
{
  send_ack (channel);
}


static void
send_info_request (struct GNUNET_MESH_Handle *h, uint16_t type)
{
  struct GNUNET_MessageHeader msg;

  msg.size = htons (sizeof (msg));
  msg.type = htons (type);
  send_packet (h, &msg, NULL);
}

/**
 * Request information about the running mesh peer.
 * The callback will be called for every channel known to the service,
 * listing all active peers that blong to the channel.
 *
 * If called again on the same handle, it will overwrite the previous
 * callback and cls. To retrieve the cls, monitor_cancel must be
 * called first.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_channels (struct GNUNET_MESH_Handle *h,
                         GNUNET_MESH_ChannelsCB callback,
                         void *callback_cls)
{
  send_info_request (h, GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNELS);
  h->channels_cb = callback;
  h->channels_cls = callback_cls;
}


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Mesh handle.
 *
 * @return Closure given to GNUNET_MESH_monitor, if any.
 */
void *
GNUNET_MESH_get_channels_cancel (struct GNUNET_MESH_Handle *h)
{
  void *cls;

  cls = h->channels_cls;
  h->channels_cb = NULL;
  h->channels_cls = NULL;
  return cls;
}


/**
 * Request information about the running mesh peer.
 * The callback will be called for every peer known to the service.
 *
 * If called again on the same handle, it will overwrite the previous
 * callback and cls. To retrieve the cls, monitor_cancel must be
 * called first.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_peers (struct GNUNET_MESH_Handle *h,
                       GNUNET_MESH_PeersCB callback,
                       void *callback_cls)
{
  send_info_request (h, GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_PEERS);
  h->peers_cb = callback;
  h->peers_cls = callback_cls;
}



/**
 * Request information about the running mesh peer.
 * The callback will be called for every tunnel known to the service.
 *
 * If called again on the same handle, it will overwrite the previous
 * callback and cls. To retrieve the cls, monitor_cancel must be
 * called first.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_tunnels (struct GNUNET_MESH_Handle *h,
                         GNUNET_MESH_TunnelsCB callback,
                         void *callback_cls)
{
  send_info_request (h, GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);
  h->tunnels_cb = callback;
  h->tunnels_cls = callback_cls;
}


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param h Mesh handle.
 *
 * @return Closure given to GNUNET_MESH_monitor, if any.
 */
void *
GNUNET_MESH_get_tunnels_cancel (struct GNUNET_MESH_Handle *h)
{
  void *cls;

  h->tunnels_cb = NULL;
  cls = h->tunnels_cls;
  h->tunnels_cls = NULL;

  return cls;
}



/**
 * Request information about the running mesh peer.
 * The callback will be called for every channel known to the service,
 * listing all active peers that blong to the channel.
 *
 * If called again on the same handle, it will overwrite the previous
 * callback and cls. To retrieve the cls, monitor_cancel must be
 * called first.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the mesh peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_get_tunnel (struct GNUNET_MESH_Handle *h,
                        const struct GNUNET_PeerIdentity *id,
                        GNUNET_MESH_TunnelCB callback,
                        void *callback_cls)
{
  struct GNUNET_MESH_LocalInfo msg;

  memset (&msg, 0, sizeof (msg));
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL);
  msg.peer = *id;
  send_packet (h, &msg.header, NULL);
  h->tunnel_cb = callback;
  h->tunnel_cls = callback_cls;
}


/**
 * Request information about a specific channel of the running mesh peer.
 *
 * WARNING: unstable API, likely to change in the future!
 * FIXME Add destination option.
 *
 * @param h Handle to the mesh peer.
 * @param initiator ID of the owner of the channel.
 * @param channel_number Channel number.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
void
GNUNET_MESH_show_channel (struct GNUNET_MESH_Handle *h,
                         struct GNUNET_PeerIdentity *initiator,
                         unsigned int channel_number,
                         GNUNET_MESH_ChannelCB callback,
                         void *callback_cls)
{
  struct GNUNET_MESH_LocalInfo msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_CHANNEL);
  msg.peer = *initiator;
  msg.channel_id = htonl (channel_number);
//   msg.reserved = 0;
  send_packet (h, &msg.header, NULL);
  h->channel_cb = callback;
  h->channel_cls = callback_cls;
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
mesh_mq_ntr (void *cls, size_t size,
             void *buf)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct MeshMQState *state = GNUNET_MQ_impl_state (mq);
  const struct GNUNET_MessageHeader *msg = GNUNET_MQ_impl_current (mq);
  uint16_t msize;

  state->th = NULL;
  if (NULL == buf)
  {
    GNUNET_MQ_inject_error (mq, GNUNET_MQ_ERROR_WRITE);
    return 0;
  }
  msize = ntohs (msg->size);
  GNUNET_assert (msize <= size);
  memcpy (buf, msg, msize);
  GNUNET_MQ_impl_send_continue (mq);
  return msize;
}


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
mesh_mq_send_impl (struct GNUNET_MQ_Handle *mq,
                   const struct GNUNET_MessageHeader *msg, void *impl_state)
{
  struct MeshMQState *state = impl_state;

  GNUNET_assert (NULL == state->th);
  state->th =
      GNUNET_MESH_notify_transmit_ready (state->channel,
                                         /* FIXME: add option for corking */
                                         GNUNET_NO,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         ntohs (msg->size),
                                         mesh_mq_ntr, mq);

}


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free 'mq', but should
 * take care of 'impl_state'.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
mesh_mq_destroy_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct MeshMQState *state = impl_state;

  if (NULL != state->th)
    GNUNET_MESH_notify_transmit_ready_cancel (state->th);

  GNUNET_free (state);
}


/**
 * Create a message queue for a mesh channel.
 * The message queue can only be used to transmit messages,
 * not to receive them.
 *
 * @param channel the channel to create the message qeue for
 * @return a message queue to messages over the channel
 */
struct GNUNET_MQ_Handle *
GNUNET_MESH_mq_create (struct GNUNET_MESH_Channel *channel)
{
  struct GNUNET_MQ_Handle *mq;
  struct MeshMQState *state;

  state = GNUNET_new (struct MeshMQState);
  state->channel = channel;

  mq = GNUNET_MQ_queue_for_callbacks (mesh_mq_send_impl,
                                      mesh_mq_destroy_impl,
                                      NULL, /* FIXME: cancel impl. */
                                      state,
                                      NULL, /* no msg handlers */
                                      NULL, /* no err handlers */
                                      NULL); /* no handler cls */
  return mq;
}

