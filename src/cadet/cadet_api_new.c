/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

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
 * @file cadet/cadet_api.c
 * @brief cadet api: client implementation of cadet service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_cadet_service.h"
#include "cadet.h"
#include "cadet_protocol.h"

#define LOG(kind,...) GNUNET_log_from (kind, "cadet-api",__VA_ARGS__)

/**
 * Ugly legacy hack.
 */
union CadetInfoCB
{

  /**
   * Channel callback.
   */
  GNUNET_CADET_ChannelCB channel_cb;

  /**
   * Monitor callback
   */
  GNUNET_CADET_PeersCB peers_cb;

  /**
   * Monitor callback
   */
  GNUNET_CADET_PeerCB peer_cb;

  /**
   * Monitor callback
   */
  GNUNET_CADET_TunnelsCB tunnels_cb;

  /**
   * Tunnel callback.
   */
  GNUNET_CADET_TunnelCB tunnel_cb;
};


/**
 * Opaque handle to the service.
 */
struct GNUNET_CADET_Handle
{
  /**
   * Message queue.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Ports open.
   */
  struct GNUNET_CONTAINER_MultiHashMap *ports;

  /**
   * Channels open.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *channels;

  /**
   * child of the next channel to create (to avoid reusing IDs often)
   */
  struct GNUNET_CADET_ClientChannelNumber next_ccn;

  /**
   * Configuration given by the client, in case of reconnection
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Task for trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Callback for an info task (only one active at a time).
   */
  union CadetInfoCB info_cb;

  /**
   * Info callback closure for @c info_cb.
   */
  void *info_cls;

  /**
   * Time to the next reconnect in case one reconnect fails
   */
  struct GNUNET_TIME_Relative reconnect_time;

};


/**
 * Opaque handle to a channel.
 */
struct GNUNET_CADET_Channel
{

  /**
   * Other end of the channel.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Handle to the cadet this channel belongs to
   */
  struct GNUNET_CADET_Handle *cadet;

  /**
   * Channel's port, if incoming.
   */
  struct GNUNET_CADET_Port *incoming_port;

  /**
   * Any data the caller wants to put in here, used for the
   * various callbacks (@e disconnects, @e window_changes, handlers).
   */
  void *ctx;

  /**
   * Message Queue for the channel (which we are implementing).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Task to allow mq to send more traffic.
   */
  struct GNUNET_SCHEDULER_Task *mq_cont;

  /**
   * Pending envelope with a message to be transmitted to the
   * service as soon as we are allowed to.  Should only be
   * non-NULL if @e allow_send is 0.
   */
  struct GNUNET_MQ_Envelope *pending_env;

  /**
   * Window change handler.
   */
  GNUNET_CADET_WindowSizeEventHandler window_changes;

  /**
   * Disconnect handler.
   */
  GNUNET_CADET_DisconnectEventHandler disconnects;

  /**
   * Local ID of the channel, #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI bit is set if outbound.
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * Channel options: reliability, etc.
   */
  enum GNUNET_CADET_ChannelOption options;

  /**
   * How many messages are we allowed to send to the service right now?
   */
  unsigned int allow_send;

};


/**
 * Opaque handle to a port.
 */
struct GNUNET_CADET_Port
{

  /**
   * Port "number"
   */
  struct GNUNET_HashCode id;

  /**
   * Handle to the CADET session this port belongs to.
   */
  struct GNUNET_CADET_Handle *cadet;

  /**
   * Callback handler for incoming channels on this port.
   */
  GNUNET_CADET_InboundChannelNotificationHandler *handler;

  /**
   * Closure for @a handler.
   */
  void *cls;

  /**
   * Handler for incoming channels on this port
   */
  GNUNET_CADET_ConnectEventHandler connects;

  /**
   * Closure for @ref connects
   */
  void *connects_cls;

  /**
   * Window size change handler.
   */
  GNUNET_CADET_WindowSizeEventHandler window_changes;

  /**
   * Handler called when an incoming channel is destroyed.
   */
  GNUNET_CADET_DisconnectEventHandler disconnects;

  /**
   * Payload handlers for incoming channels.
   */
  struct GNUNET_MQ_MessageHandler *handlers;
};


/**
 * Find the Port struct for a hash.
 *
 * @param h CADET handle.
 * @param hash HashCode for the port number.
 * @return The port handle if known, NULL otherwise.
 */
static struct GNUNET_CADET_Port *
find_port (const struct GNUNET_CADET_Handle *h,
	   const struct GNUNET_HashCode *hash)
{
  return GNUNET_CONTAINER_multihashmap_get (h->ports,
                                            hash);
}


/**
 * Get the channel handler for the channel specified by id from the given handle
 *
 * @param h Cadet handle
 * @param ccn ID of the wanted channel
 * @return handle to the required channel or NULL if not found
 */
static struct GNUNET_CADET_Channel *
find_channel (struct GNUNET_CADET_Handle *h,
              struct GNUNET_CADET_ClientChannelNumber ccn)
{
  return GNUNET_CONTAINER_multihashmap32_get (h->channels,
                                              ntohl (ccn.channel_of_client));
}


/**
 * Create a new channel and insert it in the channel list of the cadet handle
 *
 * @param h Cadet handle
 * @param ccnp pointer to desired ccn of the channel, NULL to assign one automatically.
 * @return Handle to the created channel.
 */
static struct GNUNET_CADET_Channel *
create_channel (struct GNUNET_CADET_Handle *h,
                const struct GNUNET_CADET_ClientChannelNumber *ccnp)
{
  struct GNUNET_CADET_Channel *ch;
  struct GNUNET_CADET_ClientChannelNumber ccn;

  ch = GNUNET_new (struct GNUNET_CADET_Channel);
  ch->cadet = h;
  if (NULL == ccnp)
  {
    while (NULL !=
           find_channel (h,
                         h->next_ccn))
      h->next_ccn.channel_of_client
        = htonl (GNUNET_CADET_LOCAL_CHANNEL_ID_CLI | (1 + ntohl (h->next_ccn.channel_of_client)));
    ccn = h->next_ccn;
  }
  else
  {
    ccn = *ccnp;
  }
  ch->ccn = ccn;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (h->channels,
                                                      ntohl (ch->ccn.channel_of_client),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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
 */
static void
destroy_channel (struct GNUNET_CADET_Channel *ch)
{
  struct GNUNET_CADET_Handle *h = ch->cadet;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying channel %X of %p\n",
       ch->ccn,
       h);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (h->channels,
                                                         ntohl (ch->ccn.channel_of_client),
                                                         ch));
  if (NULL != ch->mq_cont)
  {
    GNUNET_SCHEDULER_cancel (ch->mq_cont);
    ch->mq_cont = NULL;
  }
  /* signal channel destruction */
  if (NULL != ch->disconnects)
    ch->disconnects (ch->ctx,
                     ch);
  if (NULL != ch->pending_env)
    GNUNET_MQ_discard (ch->pending_env);
  GNUNET_MQ_destroy (ch->mq);
  GNUNET_free (ch);
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the cadet
 */
static void
reconnect (struct GNUNET_CADET_Handle *h);


/**
 * Reconnect callback: tries to reconnect again after a failer previous
 * reconnecttion
 *
 * @param cls closure (cadet handle)
 */
static void
reconnect_cbk (void *cls)
{
  struct GNUNET_CADET_Handle *h = cls;

  h->reconnect_task = NULL;
  reconnect (h);
}


/**
 * Function called during #reconnect() to destroy
 * all channels that are still open.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param cid chanenl ID
 * @param value a `struct GNUNET_CADET_Channel` to destroy
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_channel_on_reconnect_cb (void *cls,
                                 uint32_t cid,
                                 void *value)
{
  /* struct GNUNET_CADET_Handle *handle = cls; */
  struct GNUNET_CADET_Channel *ch = value;

  destroy_channel (ch);
  return GNUNET_OK;
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the cadet
 *
 * @return #GNUNET_YES in case of sucess, #GNUNET_NO otherwise (service down...)
 */
static void
schedule_reconnect (struct GNUNET_CADET_Handle *h)
{
  if (NULL != h->reconnect_task)
    return;
  GNUNET_CONTAINER_multihashmap32_iterate (h->channels,
                                           &destroy_channel_on_reconnect_cb,
                                           h);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->reconnect_time,
                                    &reconnect_cbk,
                                    h);
  h->reconnect_time
    = GNUNET_TIME_STD_BACKOFF (h->reconnect_time);
}


/**
 * Notify the application about a change in the window size (if needed).
 *
 * @param ch Channel to notify about.
 */
static void
notify_window_size (struct GNUNET_CADET_Channel *ch)
{
  if (NULL != ch->window_changes)
    ch->window_changes (ch->ctx,
                        ch, /* FIXME: remove 'ch'? */
                        ch->allow_send);
}


/**
 * Allow the MQ implementation to send the next message.
 *
 * @param cls Closure (channel whose mq to activate).
 */
static void
cadet_mq_send_continue (void *cls)
{
  struct GNUNET_CADET_Channel *ch = cls;

  ch->mq_cont = NULL;
  GNUNET_assert (NULL == ch->pending_env);
  GNUNET_MQ_impl_send_continue (ch->mq);
}


/**
 * Transmit the next message from our queue.
 *
 * @param cls Closure (channel whose mq to activate).
 */
static void
cadet_mq_send_now (void *cls)
{
  struct GNUNET_CADET_Channel *ch = cls;
  struct GNUNET_MQ_Envelope *env = ch->pending_env;

  ch->mq_cont = NULL;
  if (0 == ch->allow_send)
  {
    /* how did we get here? */
    GNUNET_break (0);
    return;
  }
  if (NULL == env)
  {
    /* how did we get here? */
    GNUNET_break (0);
    return;
  }
  ch->allow_send--;
  GNUNET_MQ_impl_send_in_flight (ch->mq);
  ch->pending_env = NULL;
  GNUNET_MQ_notify_sent (env,
                         &cadet_mq_send_continue,
                         ch);
  GNUNET_MQ_send (ch->cadet->mq,
                  env);
}


/**
 * Implement sending functionality of a message queue for
 * us sending messages to a peer.
 *
 * Encapsulates the payload message in a #GNUNET_CADET_LocalData message
 * in order to label the message with the channel ID and send the
 * encapsulated message to the service.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
cadet_mq_send_impl (struct GNUNET_MQ_Handle *mq,
                    const struct GNUNET_MessageHeader *msg,
                    void *impl_state)
{
  struct GNUNET_CADET_Channel *ch = impl_state;
  struct GNUNET_CADET_Handle *h = ch->cadet;
  uint16_t msize;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalData *cadet_msg;

  if (NULL == h->mq)
  {
    /* We're currently reconnecting, pretend this worked */
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }

  /* check message size for sanity */
  msize = ntohs (msg->size);
  if (msize > GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }
  env = GNUNET_MQ_msg_nested_mh (cadet_msg,
                                 GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA,
                                 msg);
  cadet_msg->ccn = ch->ccn;
  GNUNET_assert (NULL == ch->pending_env);
  ch->pending_env = env;
  if (0 < ch->allow_send)
    ch->mq_cont
      = GNUNET_SCHEDULER_add_now (&cadet_mq_send_now,
                                  ch);
}


/**
 * Handle destruction of a message queue.  Implementations must not
 * free @a mq, but should take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
cadet_mq_destroy_impl (struct GNUNET_MQ_Handle *mq,
                       void *impl_state)
{
  struct GNUNET_CADET_Channel *ch = impl_state;

  GNUNET_assert (mq == ch->mq);
  ch->mq = NULL;
}


/**
 * We had an error processing a message we forwarded from a peer to
 * the CADET service.  We should just complain about it but otherwise
 * continue processing.
 *
 * @param cls closure with our `struct GNUNET_CADET_Channel`
 * @param error error code
 */
static void
cadet_mq_error_handler (void *cls,
                        enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_Channel *ch = cls;

  GNUNET_break (0);
  if (GNUNET_MQ_ERROR_NO_MATCH == error)
  {
    /* Got a message we did not understand, still try to continue! */
    GNUNET_CADET_receive_done (ch);
  }
  else
  {
    schedule_reconnect (ch->cadet);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 * Should basically undo whatever #mq_send_impl() did.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
cadet_mq_cancel_impl (struct GNUNET_MQ_Handle *mq,
                     void *impl_state)
{
  struct GNUNET_CADET_Channel *ch = impl_state;

  GNUNET_assert (NULL != ch->pending_env);
  GNUNET_MQ_discard (ch->pending_env);
  ch->pending_env = NULL;
}


/**
 * Process the new channel notification and add it to the channels in the handle
 *
 * @param h     The cadet handle
 * @param msg   A message with the details of the new incoming channel
 */
static void
handle_channel_created (void *cls,
                        const struct GNUNET_CADET_LocalChannelCreateMessage *msg)
{
  struct GNUNET_CADET_Handle *h = cls;
  struct GNUNET_CADET_Channel *ch;
  struct GNUNET_CADET_Port *port;
  const struct GNUNET_HashCode *port_number;
  struct GNUNET_CADET_ClientChannelNumber ccn;

  ccn = msg->ccn;
  port_number = &msg->port;
  if (ntohl (ccn.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
  {
    GNUNET_break (0);
    return;
  }
  port = find_port (h,
                    port_number);
  if (NULL == port)
  {
    /* We could have closed the port but the service didn't know about it yet
     * This is not an error.
     */
    struct GNUNET_CADET_LocalChannelDestroyMessage *d_msg;
    struct GNUNET_MQ_Envelope *env;

    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No handler for incoming channel %X (on port %s, recently closed?)\n",
         ntohl (ccn.channel_of_client),
         GNUNET_h2s (port_number));
    env = GNUNET_MQ_msg (d_msg,
                         GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY);
    d_msg->ccn = msg->ccn;
    GNUNET_MQ_send (h->mq,
                    env);
    return;
  }

  ch = create_channel (h,
                       &ccn);
  ch->peer = msg->peer;
  ch->cadet = h;
  ch->incoming_port = port;
  ch->options = ntohl (msg->opt);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating incoming channel %X [%s] %p\n",
       ntohl (ccn.channel_of_client),
       GNUNET_h2s (port_number),
       ch);

  GNUNET_assert (NULL != port->connects);
  ch->window_changes = port->window_changes;
  ch->disconnects = port->disconnects;
  ch->mq = GNUNET_MQ_queue_for_callbacks (&cadet_mq_send_impl,
                                          &cadet_mq_destroy_impl,
                                          &cadet_mq_cancel_impl,
                                          ch,
                                          port->handlers,
                                          &cadet_mq_error_handler,
                                          ch);
  ch->ctx = port->connects (port->cls,
                            ch,
                            &msg->peer);
  GNUNET_MQ_set_handlers_closure (ch->mq,
                                  ch->ctx);
}


/**
 * Process the channel destroy notification and free associated resources
 *
 * @param h     The cadet handle
 * @param msg   A message with the details of the channel being destroyed
 */
static void
handle_channel_destroy (void *cls,
                        const struct GNUNET_CADET_LocalChannelDestroyMessage *msg)
{
  struct GNUNET_CADET_Handle *h = cls;
  struct GNUNET_CADET_Channel *ch;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received channel destroy for channel %X from CADET service\n",
       ntohl (msg->ccn.channel_of_client));
  ch = find_channel (h,
                     msg->ccn);
  if (NULL == ch)
  {
    GNUNET_break (0);
    return;
  }
  destroy_channel (ch);
}


/**
 * Check that message received from CADET service is well-formed.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param message the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_local_data (void *cls,
                  const struct GNUNET_CADET_LocalData *message)
{
  struct GNUNET_CADET_Handle *h = cls;
  struct GNUNET_CADET_Channel *ch;
  uint16_t size;

  size = ntohs (message->header.size);
  if (sizeof (*message) + sizeof (struct GNUNET_MessageHeader) > size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  ch = find_channel (h,
                     message->ccn);
  if (NULL == ch)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Process the incoming data packets, call appropriate handlers.
 *
 * @param h       The cadet handle
 * @param message A message encapsulating the data
 */
static void
handle_local_data (void *cls,
                   const struct GNUNET_CADET_LocalData *message)
{
  struct GNUNET_CADET_Handle *h = cls;
  const struct GNUNET_MessageHeader *payload;
  struct GNUNET_CADET_Channel *ch;
  uint16_t type;
  int fwd;

  ch = find_channel (h,
                     message->ccn);
  if (NULL == ch)
  {
    GNUNET_break (0);
    reconnect (h);
    return;
  }

  payload = (const struct GNUNET_MessageHeader *) &message[1];
  type = ntohs (payload->type);
  fwd = ntohl (ch->ccn.channel_of_client) <= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a %s data on channel %s [%X] of type %u\n",
       fwd ? "FWD" : "BWD",
       GNUNET_i2s (&ch->peer),
       ntohl (message->ccn.channel_of_client),
       type);
  GNUNET_MQ_inject_message (ch->mq,
                            payload);
}


/**
 * Process a local ACK message, enabling the client to send
 * more data to the service.
 *
 * @param h Cadet handle.
 * @param message Message itself.
 */
static void
handle_local_ack (void *cls,
                  const struct GNUNET_CADET_LocalAck *message)
{
  struct GNUNET_CADET_Handle *h = cls;
  struct GNUNET_CADET_Channel *ch;

  ch = find_channel (h,
                     message->ccn);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ACK on unknown channel %X\n",
         ntohl (message->ccn.channel_of_client));
    return;
  }
  ch->allow_send++;
  if (NULL == ch->pending_env)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got an ACK on mq channel %X, allow send now %u!\n",
         ntohl (ch->ccn.channel_of_client),
         ch->allow_send);
    notify_window_size (ch);
    return;
  }
  if (NULL != ch->mq_cont)
    return; /* already working on it! */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got an ACK on mq channel %X, sending pending message!\n",
       ntohl (ch->ccn.channel_of_client));
  ch->mq_cont
    = GNUNET_SCHEDULER_add_now (&cadet_mq_send_now,
                                ch);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure, a `struct GNUNET_CORE_Handle *`
 * @param error error code
 */
static void
handle_mq_error (void *cls,
                 enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_Handle *h = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MQ ERROR: %u\n",
              error);
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  reconnect (h);
}


/**
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param cls Closure (Cadet handle).
 * @param msg Message itself.
 */
static void
handle_get_peers (void *cls,
                  const struct GNUNET_CADET_LocalInfoPeer *msg)
{
  struct GNUNET_CADET_Handle *h = cls;

  if (NULL == h->info_cb.peers_cb)
    return;
  h->info_cb.peers_cb (h->info_cls,
                       &msg->destination,
                       (int) ntohs (msg->tunnel),
                       (unsigned int) ntohs (msg->paths),
                       0);
}


/**
 * Check that message received from CADET service is well-formed.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param message the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_get_peer (void *cls,
                const struct GNUNET_CADET_LocalInfoPeer *message)
{
  size_t msize = sizeof (struct GNUNET_CADET_LocalInfoPeer);
  const struct GNUNET_PeerIdentity *paths_array;
  size_t esize;
  unsigned int epaths;
  unsigned int paths;
  unsigned int peers;

  esize = ntohs (message->header.size);
  if (esize < msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != ((esize - msize) % sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  peers = (esize - msize) / sizeof (struct GNUNET_PeerIdentity);
  epaths = ntohs (message->paths);
  paths_array = (const struct GNUNET_PeerIdentity *) &message[1];
  paths = 0;
  for (unsigned int i = 0; i < peers; i++)
    if (0 == memcmp (&paths_array[i],
                     &message->destination,
                     sizeof (struct GNUNET_PeerIdentity)))
      paths++;
  if (paths != epaths)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a local peer info reply, pass info to the user.
 *
 * @param cls Closure (Cadet handle).
 * @param message Message itself.
 */
static void
handle_get_peer (void *cls,
                 const struct GNUNET_CADET_LocalInfoPeer *message)
{
  struct GNUNET_CADET_Handle *h = cls;
  const struct GNUNET_PeerIdentity *paths_array;
  unsigned int paths;
  unsigned int path_length;
  int neighbor;
  unsigned int peers;

  if (NULL == h->info_cb.peer_cb)
    return;
  paths = ntohs (message->paths);
  paths_array = (const struct GNUNET_PeerIdentity *) &message[1];
  peers = (ntohs (message->header.size) - sizeof (*message))
          / sizeof (struct GNUNET_PeerIdentity);
  path_length = 0;
  neighbor = GNUNET_NO;

  for (unsigned int i = 0; i < peers; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                " %s\n",
                GNUNET_i2s (&paths_array[i]));
    path_length++;
    if (0 == memcmp (&paths_array[i], &message->destination,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
      if (1 == path_length)
        neighbor = GNUNET_YES;
      path_length = 0;
    }
  }

  /* Call Callback with tunnel info. */
  paths_array = (const struct GNUNET_PeerIdentity *) &message[1];
  h->info_cb.peer_cb (h->info_cls,
                      &message->destination,
                      (int) ntohs (message->tunnel),
                      neighbor,
                      paths,
                      paths_array);
}


/**
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param cls Closure (Cadet handle).
 * @param message Message itself.
 */
static void
handle_get_tunnels (void *cls,
                    const struct GNUNET_CADET_LocalInfoTunnel *msg)
{
  struct GNUNET_CADET_Handle *h = cls;

  if (NULL == h->info_cb.tunnels_cb)
    return;
  h->info_cb.tunnels_cb (h->info_cls,
                         &msg->destination,
                         ntohl (msg->channels),
                         ntohl (msg->connections),
                         ntohs (msg->estate),
                         ntohs (msg->cstate));

}


/**
 * Check that message received from CADET service is well-formed.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param msg the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_get_tunnel (void *cls,
                  const struct GNUNET_CADET_LocalInfoTunnel *msg)
{
  unsigned int ch_n;
  unsigned int c_n;
  size_t esize;
  size_t msize;

  /* Verify message sanity */
  msize = ntohs (msg->header.size);
  esize = sizeof (struct GNUNET_CADET_LocalInfoTunnel);
  if (esize > msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ch_n = ntohl (msg->channels);
  c_n = ntohl (msg->connections);
  esize += ch_n * sizeof (struct GNUNET_CADET_ChannelTunnelNumber);
  esize += c_n * sizeof (struct GNUNET_CADET_ConnectionTunnelIdentifier);
  if (msize != esize)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "m:%u, e: %u (%u ch, %u conn)\n",
                (unsigned int) msize,
                (unsigned int) esize,
                ch_n,
                c_n);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a local tunnel info reply, pass info to the user.
 *
 * @param cls Closure (Cadet handle).
 * @param msg Message itself.
 */
static void
handle_get_tunnel (void *cls,
                   const struct GNUNET_CADET_LocalInfoTunnel *msg)
{
  struct GNUNET_CADET_Handle *h = cls;
  unsigned int ch_n;
  unsigned int c_n;
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *conns;
  const struct GNUNET_CADET_ChannelTunnelNumber *chns;

  if (NULL == h->info_cb.tunnel_cb)
    return;

  ch_n = ntohl (msg->channels);
  c_n = ntohl (msg->connections);

  /* Call Callback with tunnel info. */
  conns = (const struct GNUNET_CADET_ConnectionTunnelIdentifier *) &msg[1];
  chns = (const struct GNUNET_CADET_ChannelTunnelNumber *) &conns[c_n];
  h->info_cb.tunnel_cb (h->info_cls,
                        &msg->destination,
                        ch_n,
                        c_n,
                        chns,
                        conns,
                        ntohs (msg->estate),
                        ntohs (msg->cstate));
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the cadet
 */
static void
reconnect (struct GNUNET_CADET_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (channel_created,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE,
                             struct GNUNET_CADET_LocalChannelCreateMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (channel_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY,
                             struct GNUNET_CADET_LocalChannelDestroyMessage,
                             h),
    GNUNET_MQ_hd_var_size (local_data,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA,
                           struct GNUNET_CADET_LocalData,
                           h),
    GNUNET_MQ_hd_fixed_size (local_ack,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK,
                             struct GNUNET_CADET_LocalAck,
                             h),
    GNUNET_MQ_hd_fixed_size (get_peers,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS,
                             struct GNUNET_CADET_LocalInfoPeer,
                             h),
    GNUNET_MQ_hd_var_size (get_peer,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER,
                           struct GNUNET_CADET_LocalInfoPeer,
                           h),
    GNUNET_MQ_hd_fixed_size (get_tunnels,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS,
                             struct GNUNET_CADET_LocalInfoTunnel,
                             h),
    GNUNET_MQ_hd_var_size (get_tunnel,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL,
                           struct GNUNET_CADET_LocalInfoTunnel,
                           h),
    GNUNET_MQ_handler_end ()
  };

  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "cadet",
                                 handlers,
                                 &handle_mq_error,
                                 h);
  if (NULL == h->mq)
  {
    schedule_reconnect (h);
    return;
  }
  h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Function called during #GNUNET_CADET_disconnect() to destroy
 * all channels that are still open.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param cid chanenl ID
 * @param value a `struct GNUNET_CADET_Channel` to destroy
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_channel_cb (void *cls,
                    uint32_t cid,
                    void *value)
{
  /* struct GNUNET_CADET_Handle *handle = cls; */
  struct GNUNET_CADET_Channel *ch = value;

  if (ntohl (ch->ccn.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "channel %X not destroyed\n",
         ntohl (ch->ccn.channel_of_client));
  }
  destroy_channel (ch);
  return GNUNET_OK;
}


/**
 * Function called during #GNUNET_CADET_disconnect() to destroy
 * all ports that are still open.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param id port ID
 * @param value a `struct GNUNET_CADET_Channel` to destroy
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_port_cb (void *cls,
                 const struct GNUNET_HashCode *id,
                 void *value)
{
  /* struct GNUNET_CADET_Handle *handle = cls; */
  struct GNUNET_CADET_Port *port = value;

  GNUNET_break (0);
  GNUNET_CADET_close_port (port);
  return GNUNET_OK;
}


/**
 * Disconnect from the cadet service. All channels will be destroyed. All channel
 * disconnect callbacks will be called on any still connected peers, notifying
 * about their disconnection. The registered inbound channel cleaner will be
 * called should any inbound channels still exist.
 *
 * @param handle connection to cadet to disconnect
 */
void
GNUNET_CADET_disconnect (struct GNUNET_CADET_Handle *handle)
{
  GNUNET_CONTAINER_multihashmap_iterate (handle->ports,
                                         &destroy_port_cb,
                                         handle);
  GNUNET_CONTAINER_multihashmap_destroy (handle->ports);
  handle->ports = NULL;
  GNUNET_CONTAINER_multihashmap32_iterate (handle->channels,
                                           &destroy_channel_cb,
                                           handle);
  GNUNET_CONTAINER_multihashmap32_destroy (handle->channels);
  handle->channels = NULL;
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_free (handle);
}


/**
 * Close a port opened with @a GNUNET_CADET_open_port().
 * The @a new_channel callback will no longer be called.
 *
 * @param p Port handle.
 */
void
GNUNET_CADET_close_port (struct GNUNET_CADET_Port *p)
{
  struct GNUNET_CADET_PortMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE);
  msg->port = p->id;
  GNUNET_MQ_send (p->cadet->mq,
                  env);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (p->cadet->ports,
                                                       &p->id,
                                                       p));
  GNUNET_free_non_null (p->handlers);
  GNUNET_free (p);
}


/**
 * Destroy an existing channel.
 *
 * The existing end callback for the channel will be called immediately.
 * Any pending outgoing messages will be sent but no incoming messages will be
 * accepted and no data callbacks will be called.
 *
 * @param channel Channel handle, becomes invalid after this call.
 */
void
GNUNET_CADET_channel_destroy (struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_CADET_Handle *h = channel->cadet;
  struct GNUNET_CADET_LocalChannelDestroyMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != h->mq)
  {
    env = GNUNET_MQ_msg (msg,
                         GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY);
    msg->ccn = channel->ccn;
    GNUNET_MQ_send (h->mq,
                    env);
  }
  destroy_channel (channel);
}


/**
 * Get information about a channel.
 *
 * @param channel Channel handle.
 * @param option Query (GNUNET_CADET_OPTION_*).
 * @param ... dependant on option, currently not used
 *
 * @return Union with an answer to the query.
 */
const union GNUNET_CADET_ChannelInfo *
GNUNET_CADET_channel_get_info (struct GNUNET_CADET_Channel *channel,
                               enum GNUNET_CADET_ChannelOption option,
                               ...)
{
  static int bool_flag;

  switch (option)
  {
    case GNUNET_CADET_OPTION_NOBUFFER:
    case GNUNET_CADET_OPTION_RELIABLE:
    case GNUNET_CADET_OPTION_OUT_OF_ORDER:
      if (0 != (option & channel->options))
        bool_flag = GNUNET_YES;
      else
        bool_flag = GNUNET_NO;
      return (const union GNUNET_CADET_ChannelInfo *) &bool_flag;
      break;
    case GNUNET_CADET_OPTION_PEER:
      return (const union GNUNET_CADET_ChannelInfo *) &channel->peer;
      break;
    default:
      GNUNET_break (0);
      return NULL;
  }
}


/**
 * Send an ack on the channel to confirm the processing of a message.
 *
 * @param ch Channel on which to send the ACK.
 */
void
GNUNET_CADET_receive_done (struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_CADET_LocalAck *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ACK on channel %X\n",
       ntohl (channel->ccn.channel_of_client));
  msg->ccn = channel->ccn;
  GNUNET_MQ_send (channel->cadet->mq,
                  env);
}


/**
 * Send message of @a type to CADET service of @a h
 *
 * @param h handle to CADET service
 * @param type message type of trivial information request to send
 */
static void
send_info_request (struct GNUNET_CADET_Handle *h,
                   uint16_t type)
{
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       type);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Request a debug dump on the service's STDERR.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h cadet handle
 */
void
GNUNET_CADET_request_dump (struct GNUNET_CADET_Handle *h)
{
  send_info_request (h,
                     GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_DUMP);
}


/**
 * Request information about peers known to the running cadet service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_peers (struct GNUNET_CADET_Handle *h,
                       GNUNET_CADET_PeersCB callback,
                       void *callback_cls)
{
  if (NULL != h->info_cb.peers_cb)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  send_info_request (h,
                     GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  h->info_cb.peers_cb = callback;
  h->info_cls = callback_cls;
  return GNUNET_OK;
}


/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Cadet handle.
 * @return Closure given to GNUNET_CADET_get_peers().
 */
void *
GNUNET_CADET_get_peers_cancel (struct GNUNET_CADET_Handle *h)
{
  void *cls = h->info_cls;

  h->info_cb.peers_cb = NULL;
  h->info_cls = NULL;
  return cls;
}


/**
 * Request information about a peer known to the running cadet peer.
 * The callback will be called for the tunnel once.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_peer (struct GNUNET_CADET_Handle *h,
                       const struct GNUNET_PeerIdentity *id,
                       GNUNET_CADET_PeerCB callback,
                       void *callback_cls)
{
  struct GNUNET_CADET_LocalInfo *msg;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != h->info_cb.peer_cb)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
  msg->peer = *id;
  GNUNET_MQ_send (h->mq,
                  env);
  h->info_cb.peer_cb = callback;
  h->info_cls = callback_cls;
  return GNUNET_OK;
}


/**
 * Request information about tunnels of the running cadet peer.
 * The callback will be called for every tunnel of the service.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_tunnels (struct GNUNET_CADET_Handle *h,
                         GNUNET_CADET_TunnelsCB callback,
                         void *callback_cls)
{
  if (NULL != h->info_cb.tunnels_cb)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  send_info_request (h,
                     GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS);
  h->info_cb.tunnels_cb = callback;
  h->info_cls = callback_cls;
  return GNUNET_OK;
}


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param h Cadet handle.
 * @return Closure given to GNUNET_CADET_get_tunnels().
 */
void *
GNUNET_CADET_get_tunnels_cancel (struct GNUNET_CADET_Handle *h)
{
  void *cls = h->info_cls;

  h->info_cb.tunnels_cb = NULL;
  h->info_cls = NULL;
  return cls;
}


/**
 * Request information about a tunnel of the running cadet peer.
 * The callback will be called for the tunnel once.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_get_tunnel (struct GNUNET_CADET_Handle *h,
                        const struct GNUNET_PeerIdentity *id,
                        GNUNET_CADET_TunnelCB callback,
                        void *callback_cls)
{
  struct GNUNET_CADET_LocalInfo *msg;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != h->info_cb.tunnel_cb)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
  msg->peer = *id;
  GNUNET_MQ_send (h->mq,
                  env);
  h->info_cb.tunnel_cb = callback;
  h->info_cls = callback_cls;
  return GNUNET_OK;
}


/**
 * Transitional function to convert an unsigned int port to a hash value.
 * WARNING: local static value returned, NOT reentrant!
 * WARNING: do not use this function for new code!
 *
 * @param port Numerical port (unsigned int format).
 *
 * @return A GNUNET_HashCode usable for the new CADET API.
 */
const struct GNUNET_HashCode *
GC_u2h (uint32_t port)
{
  static struct GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "This is a transitional function, use proper crypto hashes as CADET ports\n");
  GNUNET_CRYPTO_hash (&port,
                      sizeof (port),
                      &hash);
  return &hash;
}


/**
 * Connect to the MQ-based cadet service.
 *
 * @param cfg Configuration to use.
 *
 * @return Handle to the cadet service NULL on error.
 */
struct GNUNET_CADET_Handle *
GNUNET_CADET_connecT (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CADET_Handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GNUNET_CADET_connecT()\n");
  h = GNUNET_new (struct GNUNET_CADET_Handle);
  h->cfg = cfg;
  h->ports = GNUNET_CONTAINER_multihashmap_create (4,
                                                   GNUNET_YES);
  h->channels = GNUNET_CONTAINER_multihashmap32_create (4);
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_break (0);
    GNUNET_CADET_disconnect (h);
    return NULL;
  }
  h->next_ccn.channel_of_client = htonl (GNUNET_CADET_LOCAL_CHANNEL_ID_CLI);
  h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
  h->reconnect_task = NULL;

  return h;
}


/**
 * Open a port to receive incomming MQ-based channels.
 *
 * @param h CADET handle.
 * @param port Hash identifying the port.
 * @param connects Function called when an incoming channel is connected.
 * @param connects_cls Closure for the @a connects handler.
 * @param window_changes Function called when the transmit window size changes.
 * @param disconnects Function called when a channel is disconnected.
 * @param handlers Callbacks for messages we care about, NULL-terminated.
 * @return Port handle.
 */
struct GNUNET_CADET_Port *
GNUNET_CADET_open_porT (struct GNUNET_CADET_Handle *h,
                        const struct GNUNET_HashCode *port,
                        GNUNET_CADET_ConnectEventHandler connects,
                        void * connects_cls,
                        GNUNET_CADET_WindowSizeEventHandler window_changes,
                        GNUNET_CADET_DisconnectEventHandler disconnects,
                        const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_CADET_PortMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_Port *p;

  GNUNET_assert (NULL != connects);
  GNUNET_assert (NULL != disconnects);

  p = GNUNET_new (struct GNUNET_CADET_Port);
  p->cadet = h;
  p->id = *port;
  p->connects = connects;
  p->cls = connects_cls;
  p->window_changes = window_changes;
  p->disconnects = disconnects;
  p->handlers = GNUNET_MQ_copy_handlers (handlers);

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (h->ports,
						    &p->id,
						    p,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN);
  msg->port = p->id;
  GNUNET_MQ_send (h->mq,
                  env);
  return p;
}


/**
 * Create a new channel towards a remote peer.
 *
 * If the destination port is not open by any peer or the destination peer
 * does not accept the channel, #GNUNET_CADET_ChannelEndHandler will be called
 * for this channel.
 *
 * @param h CADET handle.
 * @param channel_cls Closure for the channel. It's given to:
 *                    - The disconnect handler @a disconnects
 *                    - Each message type callback in @a handlers
 * @param destination Peer identity the channel should go to.
 * @param port Identification of the destination port.
 * @param options CadetOption flag field, with all desired option bits set to 1.
 * @param window_changes Function called when the transmit window size changes.
 * @param disconnects Function called when the channel is disconnected.
 * @param handlers Callbacks for messages we care about, NULL-terminated.
 * @return Handle to the channel.
 */
struct GNUNET_CADET_Channel *
GNUNET_CADET_channel_creatE (struct GNUNET_CADET_Handle *h,
                             void *channel_cls,
                             const struct GNUNET_PeerIdentity *destination,
                             const struct GNUNET_HashCode *port,
                             enum GNUNET_CADET_ChannelOption options,
                             GNUNET_CADET_WindowSizeEventHandler window_changes,
                             GNUNET_CADET_DisconnectEventHandler disconnects,
                             const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_CADET_Channel *ch;
  struct GNUNET_CADET_LocalChannelCreateMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert (NULL != disconnects);
  ch = create_channel (h,
                       NULL);
  ch->ctx = channel_cls;
  ch->peer = *destination;
  ch->options = options;
  ch->window_changes = window_changes;
  ch->disconnects = disconnects;

  /* Create MQ for channel */
  ch->mq = GNUNET_MQ_queue_for_callbacks (&cadet_mq_send_impl,
                                          &cadet_mq_destroy_impl,
                                          &cadet_mq_cancel_impl,
                                          ch,
                                          handlers,
                                          &cadet_mq_error_handler,
                                          ch);
  GNUNET_MQ_set_handlers_closure (ch->mq, channel_cls);

  /* Request channel creation to service */
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE);
  msg->ccn = ch->ccn;
  msg->port = *port;
  msg->peer = *destination;
  msg->opt = htonl (options);
  GNUNET_MQ_send (h->mq,
                  env);
  return ch;
}


/**
 * Obtain the message queue for a connected peer.
 *
 * @param channel The channel handle from which to get the MQ.
 *
 * @return NULL if @a channel is not yet connected.
 */
struct GNUNET_MQ_Handle *
GNUNET_CADET_get_mq (const struct GNUNET_CADET_Channel *channel)
{
  return channel->mq;
}

/* end of cadet_api.c */
