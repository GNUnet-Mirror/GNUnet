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
 * Information we track for each peer.
 */
struct PeerRecord
{

  /**
   * Corresponding CORE handle.
   */
  struct GNUNET_CORE_Handle *h;

  /**
   * Message queue for the peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Message we are currently trying to pass to the CORE service
   * for this peer (from @e mq).
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Value the client returned when we connected, used
   * as the closure in various places.
   */
  void *client_cls;

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
   * Function handlers for messages of particular type.
   */
  struct GNUNET_MQ_MessageHandler *handlers;

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
   * Did we ever get INIT?
   */
  int have_init;

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
  struct PeerRecord *pr = value;

  GNUNET_assert (pr->h == h);
  if (NULL != h->disconnects)
    h->disconnects (h->cls,
                    &pr->peer,
		    pr->client_cls);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (h->peers,
                                                       key,
                                                       pr));
  GNUNET_MQ_destroy (pr->mq);
  GNUNET_assert (NULL == pr->mq);
  if (NULL != pr->env)
  {
    GNUNET_MQ_discard (pr->env);
    pr->env = NULL;
  }
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
  GNUNET_assert (NULL == h->reconnect_task);
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
 * Error handler for the message queue to the CORE service.
 * On errors, we reconnect.
 *
 * @param cls closure, a `struct GNUNET_CORE_Handle *`
 * @param error error code
 */
static void
handle_mq_error (void *cls,
                 enum GNUNET_MQ_Error error)
{
  struct GNUNET_CORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "MQ ERROR: %d\n",
       error);
  reconnect_later (h);
}


/**
 * Inquire with CORE what options should be set for a message
 * so that it is transmitted with the given @a priority and
 * the given @a cork value.
 *
 * @param cork desired corking
 * @param priority desired message priority
 * @param[out] flags set to `flags` value for #GNUNET_MQ_set_options()
 * @return `extra` argument to give to #GNUNET_MQ_set_options()
 */
const void *
GNUNET_CORE_get_mq_options (int cork,
			    enum GNUNET_CORE_Priority priority,
			    uint64_t *flags)
{
  *flags = ((uint64_t) priority) + (((uint64_t) cork) << 32);
  return NULL;
}


/**
 * Implement sending functionality of a message queue for
 * us sending messages to a peer.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
core_mq_send_impl (struct GNUNET_MQ_Handle *mq,
		   const struct GNUNET_MessageHeader *msg,
		   void *impl_state)
{
  struct PeerRecord *pr = impl_state;
  struct GNUNET_CORE_Handle *h = pr->h;
  struct SendMessageRequest *smr;
  struct SendMessage *sm;
  struct GNUNET_MQ_Envelope *env;
  uint16_t msize;
  uint64_t flags;
  int cork;
  enum GNUNET_CORE_Priority priority;

  if (NULL == h->mq)
  {
    /* We're currently reconnecting, pretend this worked */
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }
  GNUNET_assert (NULL == pr->env);
  /* extract options from envelope */
  env = GNUNET_MQ_get_current_envelope (mq);
  GNUNET_break (NULL ==
		GNUNET_MQ_env_get_options (env,
					   &flags));
  cork = (int) (flags >> 32);
  priority = (uint32_t) flags;

  /* check message size for sanity */
  msize = ntohs (msg->size);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct SendMessage))
  {
    GNUNET_break (0);
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }

  /* ask core for transmission */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asking core for transmission of %u bytes to `%s'\n",
       (unsigned int) msize,
       GNUNET_i2s (&pr->peer));
  env = GNUNET_MQ_msg (smr,
                       GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST);
  smr->priority = htonl ((uint32_t) priority);
  smr->peer = pr->peer;
  smr->reserved = htonl (0);
  smr->size = htons (msize);
  smr->smr_id = htons (++pr->smr_id_gen);
  GNUNET_MQ_send (h->mq,
                  env);

  /* prepare message with actual transmission data */
  pr->env = GNUNET_MQ_msg_nested_mh (sm,
				     GNUNET_MESSAGE_TYPE_CORE_SEND,
				     msg);
  sm->priority = htonl ((uint32_t) priority);
  sm->peer = pr->peer;
  sm->cork = htonl ((uint32_t) cork);
  sm->reserved = htonl (0);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Calling get_message with buffer of %u bytes (%s)\n",
       (unsigned int) msize,
       cork ? "corked" : "uncorked");
}


/**
 * Handle destruction of a message queue.  Implementations must not
 * free @a mq, but should take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
core_mq_destroy_impl (struct GNUNET_MQ_Handle *mq,
		      void *impl_state)
{
  struct PeerRecord *pr = impl_state;

  GNUNET_assert (mq == pr->mq);
  pr->mq = NULL;
}


/**
 * Implementation function that cancels the currently sent message.
 * Should basically undo whatever #mq_send_impl() did.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
core_mq_cancel_impl (struct GNUNET_MQ_Handle *mq,
		     void *impl_state)
{
  struct PeerRecord *pr = impl_state;

  GNUNET_assert (NULL != pr->env);
  GNUNET_MQ_discard (pr->env);
  pr->env = NULL;
}


/**
 * We had an error processing a message we forwarded from a peer to
 * the CORE service.  We should just complain about it but otherwise
 * continue processing.
 *
 * @param cls closure
 * @param error error code
 */
static void
core_mq_error_handler (void *cls,
                       enum GNUNET_MQ_Error error)
{
  /* struct PeerRecord *pr = cls; */

  GNUNET_break_op (0);
}


/**
 * Add the given peer to the list of our connected peers
 * and create the respective data structures and notify
 * the application.
 *
 * @param h the core handle
 * @param peer the peer that is connecting to us
 */
static void
connect_peer (struct GNUNET_CORE_Handle *h,
	      const struct GNUNET_PeerIdentity *peer)
{
  struct PeerRecord *pr;
  uint64_t flags;
  const void *extra;

  pr = GNUNET_new (struct PeerRecord);
  pr->peer = *peer;
  pr->h = h;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (h->peers,
                                                    &pr->peer,
                                                    pr,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  pr->mq = GNUNET_MQ_queue_for_callbacks (&core_mq_send_impl,
					  &core_mq_destroy_impl,
					  &core_mq_cancel_impl,
					  pr,
					  h->handlers,
					  &core_mq_error_handler,
					  pr);
  /* get our default options */
  extra = GNUNET_CORE_get_mq_options (GNUNET_NO,
				      GNUNET_CORE_PRIO_BEST_EFFORT,
				      &flags);
  GNUNET_MQ_set_options (pr->mq,
			 flags,
			 extra);
  if (NULL != h->connects)
  {
    pr->client_cls = h->connects (h->cls,
				  &pr->peer,
				  pr->mq);
    GNUNET_MQ_set_handlers_closure (pr->mq,
				    pr->client_cls);
  }
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

  GNUNET_break (0 == ntohl (m->reserved));
  h->retry_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  if (NULL != (init = h->init))
  {
    /* mark so we don't call init on reconnect */
    h->init = NULL;
    h->me = m->my_identity;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Connected to core service of peer `%s'.\n",
         GNUNET_i2s (&h->me));
    h->have_init = GNUNET_YES;
    init (h->cls,
          &h->me);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Successfully reconnected to core service.\n");
    if (GNUNET_NO == h->have_init)
    {
      h->me = m->my_identity;
      h->have_init = GNUNET_YES;
    }
    else
    {
      GNUNET_break (0 == memcmp (&h->me,
                                 &m->my_identity,
                                 sizeof (struct GNUNET_PeerIdentity)));
    }
  }
  /* fake 'connect to self' */
  connect_peer (h,
		&h->me);
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
                       const struct ConnectNotifyMessage *cnm)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;

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
  connect_peer (h,
		&cnm->peer);
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
                          const struct DisconnectNotifyMessage *dnm)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;

  if (0 == memcmp (&h->me,
                   &dnm->peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* disconnect from self!? */
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
                                  &pr->peer,
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
  uint16_t msize;
  const struct GNUNET_MessageHeader *em;

  msize = ntohs (ntm->header.size) - sizeof (struct NotifyTrafficMessage);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  if (msize != ntohs (em->size))
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received inbound message from `%s'.\n",
       GNUNET_i2s (&ntm->peer));
  em = (const struct GNUNET_MessageHeader *) &ntm[1];
  pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
					  &ntm->peer);
  if (NULL == pr)
  {
    GNUNET_break (0);
    reconnect_later (h);
    return;
  }
  GNUNET_MQ_inject_message (pr->mq,
			    em);
}


/**
 * Handle message received from CORE service notifying us that we are
 * now allowed to send a message to a peer.  If that message is still
 * pending, put it into the queue to be transmitted.
 *
 * @param cls the `struct GNUNET_CORE_Handle`
 * @param smr the message we got
 */
static void
handle_send_ready (void *cls,
                   const struct SendMessageReady *smr)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct PeerRecord *pr;

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
  if (NULL == pr->env)
  {
    /* request must have been cancelled between the original request
     * and the response from CORE, ignore CORE's readiness */
    return;
  }
  if (ntohs (smr->smr_id) != pr->smr_id_gen)
  {
    /* READY message is for expired or cancelled message,
     * ignore! (we should have already sent another request) */
    return;
  }

  /* ok, all good, send message out! */
  GNUNET_MQ_send (h->mq,
		  pr->env);
  pr->env = NULL;
  GNUNET_MQ_impl_send_continue (pr->mq);
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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (init_reply,
                             GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY,
                             struct InitReplyMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (connect_notify,
                             GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT,
                             struct ConnectNotifyMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (disconnect_notify,
                             GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT,
                             struct DisconnectNotifyMessage,
                             h),
    GNUNET_MQ_hd_var_size (notify_inbound,
                           GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND,
                           struct NotifyTrafficMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (send_ready,
                             GNUNET_MESSAGE_TYPE_CORE_SEND_READY,
                             struct SendMessageReady,
                             h),
    GNUNET_MQ_handler_end ()
  };
  struct InitMessage *init;
  struct GNUNET_MQ_Envelope *env;
  uint16_t *ts;

  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
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
  LOG (GNUNET_ERROR_TYPE_INFO,
       "(Re)connecting to CORE service\n");
  init->options = htonl (0);
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
 * @param handlers callbacks for messages we care about, NULL-terminated
 * @return handle to the core service (only useful for disconnect until @a init is called);
 *                NULL on error (in this case, init is never called)
 */
struct GNUNET_CORE_Handle *
GNUNET_CORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
                     const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_CORE_Handle *h;

  h = GNUNET_new (struct GNUNET_CORE_Handle);
  h->cfg = cfg;
  h->cls = cls;
  h->init = init;
  h->connects = connects;
  h->disconnects = disconnects;
  h->peers = GNUNET_CONTAINER_multipeermap_create (128,
						   GNUNET_NO);
  h->handlers = GNUNET_MQ_copy_handlers (handlers);
  h->hcnt = GNUNET_MQ_count_handlers (handlers);
  GNUNET_assert (h->hcnt <
                 (GNUNET_SERVER_MAX_MESSAGE_SIZE -
                  sizeof (struct InitMessage)) / sizeof (uint16_t));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to CORE service\n");
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_CORE_disconnect (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the core service.
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
 * Obtain the message queue for a connected peer.
 *
 * @param h the core handle
 * @param pid the identity of the peer to check if it has been connected to us
 * @return NULL if peer is not connected
 */
struct GNUNET_MQ_Handle *
GNUNET_CORE_get_mq (const struct GNUNET_CORE_Handle *h,
		    const struct GNUNET_PeerIdentity *pid)
{
  struct PeerRecord *pr;

  pr = GNUNET_CONTAINER_multipeermap_get (h->peers,
					  pid);
  if (NULL == pr)
    return NULL;
  return pr->mq;
}


/* end of core_api.c */
