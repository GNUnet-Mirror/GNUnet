/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @file core/core_api.c
 * @brief core service; this is the main API for encrypted P2P
 *        communications
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "core.h"

#define LOG(kind,...) GNUNET_log_from (kind, "core-api",__VA_ARGS__)


/**
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle
{

  /**
   * Corresponding peer record.
   */
  struct PeerRecord *peer;

  /**
   * Function that will be called to get the actual request
   * (once we are ready to transmit this request to the core).
   * The function will be called with a NULL buffer to signal
   * timeout.
   */
  GNUNET_CONNECTION_TransmitReadyNotify get_message;

  /**
   * Closure for @e get_message.
   */
  void *get_message_cls;

  /**
   * Deadline for the transmission (the request does not get cancelled
   * at this time, this is merely how soon the application wants this out).
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * When did this request get queued?
   */
  struct GNUNET_TIME_Absolute request_time;

  /**
   * How important is this message?
   */
  enum GNUNET_CORE_Priority priority;

  /**
   * Is corking allowed?
   */
  int cork;

  /**
   * Size of this request.
   */
  uint16_t msize;

  /**
   * Send message request ID for this request.
   */
  uint16_t smr_id;

};


/**
 * Information we track for each peer.
 */
struct PeerRecord
{

  /**
   * Corresponding CORE handle.
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   * Pending request, if any. 'th->peer' is set to NULL if the
   * request is not active.
   */
  struct GNUNET_CORE_TransmitHandle th;

  /**
   * Peer the record is about.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * SendMessageRequest ID generator for this peer.
   */
  uint16_t smr_id_gen;

};


/**
 * Context for the core service connection.
 */
struct GNUNET_CORE_Handle
{

  /**
   * Configuration we're using.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Closure for the various callbacks.
   */
  void *cls;

  /**
   * Function to call once we've handshaked with the core service.
   */
  GNUNET_CORE_StartupCallback init;

  /**
   * Function to call whenever we're notified about a peer connecting.
   */
  GNUNET_CORE_ConnectEventHandler connects;

  /**
   * Function to call whenever we're notified about a peer disconnecting.
   */
  GNUNET_CORE_DisconnectEventHandler disconnects;

  /**
   * Function to call whenever we receive an inbound message.
   */
  GNUNET_CORE_MessageCallback inbound_notify;

  /**
   * Function to call whenever we receive an outbound message.
   */
  GNUNET_CORE_MessageCallback outbound_notify;

  /**
   * Function handlers for messages of particular type.
   */
  struct GNUNET_CORE_MessageHandler *handlers;

  /**
   * Our message queue for transmissions to the service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Hash map listing all of the peers that we are currently
   * connected to.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peers;

  /**
   * Identity of this peer.
   */
  struct GNUNET_PeerIdentity me;

  /**
   * ID of reconnect task (if any).
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Number of entries in the handlers array.
   */
  unsigned int hcnt;

  /**
   * For inbound notifications without a specific handler, do
   * we expect to only receive headers?
   */
  int inbound_hdr_only;

  /**
   * For outbound notifications without a specific handler, do
   * we expect to only receive headers?
   */
  int outbound_hdr_only;

  /**
   * Are we currently disconnected and hence unable to forward
   * requests?
   */
  int currently_down;

};


/**
 * Our current client connection went down.  Clean it up
 * and try to reconnect!
 *
 * @param h our handle to the core service
 */
static void
reconnect (struct GNUNET_CORE_Handle *h);


/**
 * Task schedule to try to re-connect to core.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param tc task context
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_CORE_Handle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to CORE service after delay\n");
  reconnect (h);
}


/**
 * Notify clients about disconnect and free the entry for connected
 * peer.
 *
 * @param cls the `struct GNUNET_CORE_Handle *`
 * @param key the peer identity (not used)
 * @param value the `struct PeerRecord` to free.
 * @return #GNUNET_YES (continue)
 */
static int
disconnect_and_free_peer_entry (void *cls,
				const struct GNUNET_PeerIdentity *key,
                                void *value)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct GNUNET_CORE_TransmitHandle *th;
  struct PeerRecord *pr = value;

  if (NULL != h->disconnects)
    h->disconnects (h->cls,
                    &pr->peer);
  /* all requests should have been cancelled, clean up anyway, just in case */
  th = &pr->th;
  if (NULL != th->peer)
  {
    GNUNET_break (0);
    th->peer = NULL;
  }
  /* done with 'voluntary' cleanups, now on to normal freeing */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (h->peers,
                                                       key,
                                                       pr));
  GNUNET_assert (pr->ch == h);
  GNUNET_free (pr);
  return GNUNET_YES;
}


/**
 * Close down any existing connection to the CORE service and
 * try re-establishing it later.
 *
 * @param h our handle
 */
static void
reconnect_later (struct GNUNET_CORE_Handle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  h->currently_down = GNUNET_YES;
  GNUNET_assert (h->reconnect_task == NULL);
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->retry_backoff,
                                    &reconnect_task,
                                    h);
  GNUNET_CONTAINER_multipeermap_iterate (h->peers,
                                         &disconnect_and_free_peer_entry,
                                         h);
  h->retry_backoff = GNUNET_TIME_STD_BACKOFF (h->retry_backoff);
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
  struct GNUNET_CORE_Handle *h = cls;

  reconnect_later (h);
}


/**
 * Handle  init  reply message  received  from  CORE service.   Notify
 * application  that we  are now  connected  to the  CORE.  Also  fake
 * loopback connection.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param m the init reply
 */
static void
handle_init_reply (void *cls,
                   const struct InitReplyMessage *m)
{
  struct GNUNET_CORE_Handle *h = cls;
  GNUNET_CORE_StartupCallback init;
  struct PeerRecord *pr;

  GNUNET_break (0 == ntohl (m->reserved));
  GNUNET_break (GNUNET_YES == h->currently_down);
  h->currently_down = GNUNET_NO;
  h->retry_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  if (NULL != (init = h->init))
  {
    /* mark so we don't call init on reconnect */
    h->init = NULL;
    h->me = m->my_identity;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Connected to core service of peer `%s'.\n",
         GNUNET_i2s (&h->me));
    init (h->cls,
          &h->me);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Successfully reconnected to core service.\n");
    GNUNET_break (0 == memcmp (&h->me,
                               &m->my_identity,
                               sizeof (struct GNUNET_PeerIdentity)));
  }
  /* fake 'connect to self' */
  pr = GNUNET_new (struct PeerRecord);
  pr->peer = h->me;
  pr->ch = h;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (h->peers,
                                                    &h->me,
                                                    pr,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (NULL != h->connects)
    h->connects (h->cls,
                 &pr->peer);
}


/**
 * Handle connect message received from CORE service.
 * Notify the application about the new connection.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param cnm the connect message
 */
static void
handle_connect_notify (void *cls,
                       const struct ConnectNotifyMessage * cnm)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;

  GNUNET_break (GNUNET_NO == h->currently_down);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received notification about connection from `%s'.\n",
       GNUNET_i2s (&cnm->peer));
  if (0 == memcmp (&h->me,
                   &cnm->peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* connect to self!? */
    GNUNET_break (0);
    return;
  }
  pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
                                          &cnm->peer);
  if (NULL != pr)
  {
    GNUNET_break (0);
    reconnect_later (h);
    return;
  }
  pr = GNUNET_new (struct PeerRecord);
  pr->peer = cnm->peer;
  pr->ch = h;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (h->peers,
                                                    &cnm->peer,
                                                    pr,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (NULL != h->connects)
    h->connects (h->cls,
                 &pr->peer);
}


/**
 * Handle disconnect message received from CORE service.
 * Notify the application about the lost connection.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param dnm message about the disconnect event
 */
static void
handle_disconnect_notify (void *cls,
                          const struct DisconnectNotifyMessage * dnm)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;

  GNUNET_break (GNUNET_NO == h->currently_down);
  if (0 == memcmp (&h->me,
                   &dnm->peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* connection to self!? */
    GNUNET_break (0);
    return;
  }
  GNUNET_break (0 == ntohl (dnm->reserved));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received notification about disconnect from `%s'.\n",
       GNUNET_i2s (&dnm->peer));
  pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
                                          &dnm->peer);
  if (NULL == pr)
  {
    GNUNET_break (0);
    reconnect_later (h);
    return;
  }
  disconnect_and_free_peer_entry (h,
                                  &dnm->peer,
                                  pr);
}


/**
 * Check that message received from CORE service is well-formed.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param ntm the message we got
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_notify_inbound (void *cls,
                      const struct NotifyTrafficMessage *ntm)
{
  struct GNUNET_CORE_Handle *h = cls;
  uint16_t msize;
  const struct GNUNET_MessageHeader *em;

  GNUNET_break (GNUNET_NO == h->currently_down);
  msize = ntohs (ntm->header.size) - sizeof (struct NotifyTrafficMessage);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  if ( (GNUNET_NO == h->inbound_hdr_only) &&
       (msize != ntohs (em->size)) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle inbound message received from CORE service.  If applicable,
 * notify the application.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param ntm the message we got from CORE.
 */
static void
handle_notify_inbound (void *cls,
                       const struct NotifyTrafficMessage *ntm)
{
  struct GNUNET_CORE_Handle *h = cls;
  const struct GNUNET_MessageHeader *em;
  struct PeerRecord *pr;
  uint16_t et;

  GNUNET_break (GNUNET_NO == h->currently_down);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received inbound message from `%s'.\n",
       GNUNET_i2s (&ntm->peer));
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  et = ntohs (em->type);
  for (unsigned int hpos = 0; NULL != h->handlers[hpos].callback; hpos++)
  {
    const struct GNUNET_CORE_MessageHandler *mh;

    mh = &h->handlers[hpos];
    if (mh->type != et)
      continue;
    if ( (mh->expected_size != ntohs (em->size)) &&
         (0 != mh->expected_size) )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Unexpected message size %u for message of type %u from peer `%s'\n",
           htons (em->size),
           mh->type,
           GNUNET_i2s (&ntm->peer));
      GNUNET_break_op (0);
      continue;
    }
    pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
                                            &ntm->peer);
    if (NULL == pr)
    {
      GNUNET_break (0);
      reconnect_later (h);
      return;
    }
    if (GNUNET_OK !=
        h->handlers[hpos].callback (h->cls,
                                    &ntm->peer,
                                    em))
    {
      /* error in processing, do not process other messages! */
      break;
    }
  }
  if (NULL != h->inbound_notify)
    h->inbound_notify (h->cls,
                       &ntm->peer,
                       em);
}


/**
 * Check that message received from CORE service is well-formed.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param ntm the message we got
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_notify_outbound (void *cls,
                       const struct NotifyTrafficMessage *ntm)
{
  struct GNUNET_CORE_Handle *h = cls;
  uint16_t msize;
  const struct GNUNET_MessageHeader *em;

  GNUNET_break (GNUNET_NO == h->currently_down);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received outbound message from `%s'.\n",
       GNUNET_i2s (&ntm->peer));
  msize = ntohs (ntm->header.size) - sizeof (struct NotifyTrafficMessage);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  if ( (GNUNET_NO == h->outbound_hdr_only) &&
       (msize != ntohs (em->size)) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle outbound message received from CORE service.  If applicable,
 * notify the application.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param ntm the message we got
 */
static void
handle_notify_outbound (void *cls,
                        const struct NotifyTrafficMessage *ntm)
{
  struct GNUNET_CORE_Handle *h = cls;
  const struct GNUNET_MessageHeader *em;

  GNUNET_break (GNUNET_NO == h->currently_down);
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received notification about transmission to `%s'.\n",
       GNUNET_i2s (&ntm->peer));
  if (NULL == h->outbound_notify)
  {
    GNUNET_break (0);
    return;
  }
  h->outbound_notify (h->cls,
                      &ntm->peer,
                      em);
}


/**
 * Handle message received from CORE service notifying us that we are
 * now allowed to send a message to a peer.  If that message is still
 * pending, put it into the queue to be transmitted.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param ntm the message we got
 */
static void
handle_send_ready (void *cls,
                   const struct SendMessageReady *smr)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;
  struct GNUNET_CORE_TransmitHandle *th;
  struct SendMessage *sm;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_TIME_Relative overdue;
  unsigned int ret;

  GNUNET_break (GNUNET_NO == h->currently_down);
  pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
                                          &smr->peer);
  if (NULL == pr)
  {
    GNUNET_break (0);
    reconnect_later (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received notification about transmission readiness to `%s'.\n",
       GNUNET_i2s (&smr->peer));
  if (NULL == pr->th.peer)
  {
    /* request must have been cancelled between the original request
     * and the response from CORE, ignore CORE's readiness */
    return;
  }
  th = &pr->th;
  if (ntohs (smr->smr_id) != th->smr_id)
  {
    /* READY message is for expired or cancelled message,
     * ignore! (we should have already sent another request) */
    return;
  }
  /* ok, all good, send message out! */
  th->peer = NULL;
  env = GNUNET_MQ_msg_extra (sm,
                             th->msize,
                             GNUNET_MESSAGE_TYPE_CORE_SEND);
  sm->priority = htonl ((uint32_t) th->priority);
  sm->deadline = GNUNET_TIME_absolute_hton (th->deadline);
  sm->peer = pr->peer;
  sm->cork = htonl ((uint32_t) th->cork);
  sm->reserved = htonl (0);
  ret = th->get_message (th->get_message_cls,
                         th->msize,
                         &sm[1]);
  sm->header.size = htons (ret);
  th->msize = ret;
  // GNUNET_assert (ret == th->msize); /* NOTE: API change! */
  delay = GNUNET_TIME_absolute_get_duration (th->request_time);
  overdue = GNUNET_TIME_absolute_get_duration (th->deadline);
  if (overdue.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Transmitting overdue %u bytes to `%s' at priority %u with %s delay %s\n",
         ret,
         GNUNET_i2s (&pr->peer),
         (unsigned int) th->priority,
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES),
         (th->cork) ? " (corked)" : "");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmitting %u bytes to `%s' at priority %u with %s delay %s\n",
         ret,
         GNUNET_i2s (&pr->peer),
         (unsigned int) th->priority,
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES),
         (th->cork) ? " (corked)" : "");
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Our current client connection went down.  Clean it up and try to
 * reconnect!
 *
 * @param h our handle to the core service
 */
static void
reconnect (struct GNUNET_CORE_Handle *h)
{
  GNUNET_MQ_hd_fixed_size (init_reply,
                           GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY,
                           struct InitReplyMessage);
  GNUNET_MQ_hd_fixed_size (connect_notify,
                           GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT,
                           struct ConnectNotifyMessage);
  GNUNET_MQ_hd_fixed_size (disconnect_notify,
                           GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT,
                           struct DisconnectNotifyMessage);
  GNUNET_MQ_hd_var_size (notify_inbound,
                         GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND,
                         struct NotifyTrafficMessage);
  GNUNET_MQ_hd_var_size (notify_outbound,
                         GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND,
                         struct NotifyTrafficMessage);
  GNUNET_MQ_hd_fixed_size (send_ready,
                           GNUNET_MESSAGE_TYPE_CORE_SEND_READY,
                           struct SendMessageReady);
 struct GNUNET_MQ_MessageHandler handlers[] = {
    make_init_reply_handler (h),
    make_connect_notify_handler (h),
    make_disconnect_notify_handler (h),
    make_notify_inbound_handler (h),
    make_notify_outbound_handler (h),
    make_send_ready_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct InitMessage *init;
  struct GNUNET_MQ_Envelope *env;
  uint32_t opt;
  uint16_t *ts;

  GNUNET_assert (NULL == h->mq);
  GNUNET_assert (GNUNET_YES == h->currently_down);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "core",
                                 handlers,
                                 &handle_mq_error,
                                 h);
  if (NULL == h->mq)
  {
    reconnect_later (h);
    return;
  }
  env = GNUNET_MQ_msg_extra (init,
                             sizeof (uint16_t) * h->hcnt,
                             GNUNET_MESSAGE_TYPE_CORE_INIT);
  opt = 0;
  if (NULL != h->inbound_notify)
  {
    if (h->inbound_hdr_only)
      opt |= GNUNET_CORE_OPTION_SEND_HDR_INBOUND;
    else
      opt |= GNUNET_CORE_OPTION_SEND_FULL_INBOUND;
  }
  if (NULL != h->outbound_notify)
  {
    if (h->outbound_hdr_only)
      opt |= GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND;
    else
      opt |= GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND;
  }
  LOG (GNUNET_ERROR_TYPE_INFO,
       "(Re)connecting to CORE service, monitoring messages of type %u\n",
       opt);
  init->options = htonl (opt);
  ts = (uint16_t *) &init[1];
  for (unsigned int hpos = 0; hpos < h->hcnt; hpos++)
    ts[hpos] = htons (h->handlers[hpos].type);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Connect to the core service.  Note that the connection may complete
 * (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call once we have successfully
 *        connected to the core service
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 * @param inbound_hdr_only set to #GNUNET_YES if inbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if @a inbound_notify is NULLL
 * @param outbound_notify function to call for all outbound messages, can be NULL
 * @param outbound_hdr_only set to #GNUNET_YES if outbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if @a outbound_notify is NULLL
 * @param handlers callbacks for messages we care about, NULL-terminated
 * @return handle to the core service (only useful for disconnect until 'init' is called);
 *                NULL on error (in this case, init is never called)
 */
struct GNUNET_CORE_Handle *
GNUNET_CORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers)
{
  struct GNUNET_CORE_Handle *h;
  unsigned int hcnt;

  h = GNUNET_new (struct GNUNET_CORE_Handle);
  h->cfg = cfg;
  h->cls = cls;
  h->init = init;
  h->connects = connects;
  h->disconnects = disconnects;
  h->inbound_notify = inbound_notify;
  h->outbound_notify = outbound_notify;
  h->inbound_hdr_only = inbound_hdr_only;
  h->outbound_hdr_only = outbound_hdr_only;
  h->currently_down = GNUNET_YES;
  h->peers = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  hcnt = 0;
  if (NULL != handlers)
    while (NULL != handlers[hcnt].callback)
      hcnt++;
  h->handlers = GNUNET_new_array (hcnt + 1,
                                  struct GNUNET_CORE_MessageHandler);
  if (NULL != handlers)
    memcpy (h->handlers,
            handlers,
            hcnt * sizeof (struct GNUNET_CORE_MessageHandler));
  h->hcnt = hcnt;
  GNUNET_assert (hcnt <
                 (GNUNET_SERVER_MAX_MESSAGE_SIZE -
                  sizeof (struct InitMessage)) / sizeof (uint16_t));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to CORE service\n");
  reconnect (h);
  return h;
}


/**
 * Disconnect from the core service.  This function can only
 * be called *after* all pending #GNUNET_CORE_notify_transmit_ready()
 * requests have been explicitly canceled.
 *
 * @param handle connection to core to disconnect
 */
void
GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting from CORE service\n");
  GNUNET_CONTAINER_multipeermap_iterate (handle->peers,
                                         &disconnect_and_free_peer_entry,
                                         handle);
  GNUNET_CONTAINER_multipeermap_destroy (handle->peers);
  handle->peers = NULL;
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  GNUNET_free (handle->handlers);
  GNUNET_free (handle);
}


/**
 * Ask the core to call @a notify once it is ready to transmit the
 * given number of bytes to the specified @a target.  Must only be
 * called after a connection to the respective peer has been
 * established (and the client has been informed about this).  You may
 * have one request of this type pending for each connected peer at
 * any time.  If a peer disconnects, the application MUST call
 * #GNUNET_CORE_notify_transmit_ready_cancel on the respective
 * transmission request, if one such request is pending.
 *
 * @param handle connection to core service
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait? Only effective if @a cork is #GNUNET_YES
 * @param target who should receive the message, never NULL (can be this peer's identity for loopback)
 * @param notify_size how many bytes of buffer space does @a notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout; clients MUST cancel
 *        all pending transmission requests DURING the disconnect
 *        handler
 * @param notify_cls closure for @a notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (request already pending);
 *         if NULL is returned, @a notify will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct GNUNET_CORE_Handle *handle,
                                   int cork,
                                   enum GNUNET_CORE_Priority priority,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   const struct GNUNET_PeerIdentity *target,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  struct PeerRecord *pr;
  struct GNUNET_CORE_TransmitHandle *th;
  struct SendMessageRequest *smr;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert (NULL != notify);
  if ( (notify_size > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE) ||
       (notify_size + sizeof (struct SendMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE) )
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asking core for transmission of %u bytes to `%s'\n",
       (unsigned int) notify_size,
       GNUNET_i2s (target));
  pr = GNUNET_CONTAINER_multipeermap_get (handle->peers,
                                          target);
  if (NULL == pr)
  {
    /* attempt to send to peer that is not connected */
    GNUNET_break (0);
    return NULL;
  }
  if (NULL != pr->th.peer)
  {
    /* attempting to queue a second request for the same destination */
    GNUNET_break (0);
    return NULL;
  }
  th = &pr->th;
  memset (th,
          0,
          sizeof (struct GNUNET_CORE_TransmitHandle));
  th->peer = pr;
  th->get_message = notify;
  th->get_message_cls = notify_cls;
  th->request_time = GNUNET_TIME_absolute_get ();
  if (GNUNET_YES == cork)
    th->deadline = GNUNET_TIME_relative_to_absolute (maxdelay);
  else
    th->deadline = th->request_time;
  th->priority = priority;
  th->msize = notify_size;
  th->cork = cork;
  env = GNUNET_MQ_msg (smr,
                       GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST);
  smr->priority = htonl ((uint32_t) th->priority);
  smr->deadline = GNUNET_TIME_absolute_hton (th->deadline);
  smr->peer = pr->peer;
  smr->reserved = htonl (0);
  smr->size = htons (th->msize);
  smr->smr_id = htons (th->smr_id = pr->smr_id_gen++);
  GNUNET_MQ_send (handle->mq,
                  env);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmission request added to queue\n");
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by #GNUNET_CORE_notify_transmit_ready().
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle *th)
{
  struct PeerRecord *pr = th->peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Aborting transmission request to core for %u bytes to `%s'\n",
       (unsigned int) th->msize,
       GNUNET_i2s (&pr->peer));
  th->peer = NULL;
}


/**
 * Check if the given peer is currently connected. This function is for special
 * cirumstances (GNUNET_TESTBED uses it), normal users of the CORE API are
 * expected to track which peers are connected based on the connect/disconnect
 * callbacks from #GNUNET_CORE_connect().  This function is NOT part of the
 * 'versioned', 'official' API. The difference between this function and the
 * function GNUNET_CORE_is_peer_connected() is that this one returns
 * synchronously after looking in the CORE API cache. The function
 * GNUNET_CORE_is_peer_connected() sends a message to the CORE service and hence
 * its response is given asynchronously.
 *
 * @param h the core handle
 * @param pid the identity of the peer to check if it has been connected to us
 * @return #GNUNET_YES if the peer is connected to us; #GNUNET_NO if not
 */
int
GNUNET_CORE_is_peer_connected_sync (const struct GNUNET_CORE_Handle *h,
                                    const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multipeermap_contains (h->peers,
                                                 pid);
}


/* end of core_api.c */
