/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file transport/transport_api_core.c
 * @brief library to access the transport service for message exchange
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_core_service.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-api-core",__VA_ARGS__)

/**
 * If we could not send any payload to a peer for this amount of
 * time, we print a warning.
 */
#define UNREADY_WARN_TIME GNUNET_TIME_UNIT_MINUTES

/**
 * How large to start with for the hashmap of neighbours.
 */
#define STARTING_NEIGHBOURS_SIZE 16


/**
 * Entry in hash table of all of our current (connected) neighbours.
 */
struct Neighbour
{
  /**
   * Overall transport handle.
   */
  struct GNUNET_TRANSPORT_CoreHandle *h;

  /**
   * Active message queue for the peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Envelope with the message we are currently transmitting (or NULL).
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Closure for @e mq handlers.
   */
  void *handlers_cls;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Outbound bandwidh tracker.
   */
  struct GNUNET_BANDWIDTH_Tracker out_tracker;

  /**
   * Entry in our readyness heap (which is sorted by @e next_ready
   * value).  NULL if there is no pending transmission request for
   * this neighbour or if we're waiting for @e is_ready to become
   * true AFTER the @e out_tracker suggested that this peer's quota
   * has been satisfied (so once @e is_ready goes to #GNUNET_YES,
   * we should immediately go back into the heap).
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Task to trigger MQ when we have enough bandwidth for the
   * next transmission.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Sending consumed more bytes on wire than payload was announced
   * This overhead is added to the delay of next sending operation
   */
  unsigned long long traffic_overhead;

  /**
   * Is this peer currently ready to receive a message?
   */
  int is_ready;

  /**
   * Size of the message in @e env.
   */
  uint16_t env_size;

};



/**
 * Handle for the transport service (includes all of the
 * state for the transport service).
 */
struct GNUNET_TRANSPORT_CoreHandle
{

  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Functions to call for received data (template for
   * new message queues).
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * function to call on connect events
   */
  GNUNET_TRANSPORT_NotifyConnecT nc_cb;

  /**
   * function to call on disconnect events
   */
  GNUNET_TRANSPORT_NotifyDisconnecT nd_cb;

  /**
   * function to call on excess bandwidth events
   */
  GNUNET_TRANSPORT_NotifyExcessBandwidtH neb_cb;

  /**
   * My client connection to the transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * My configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Hash map of the current connected neighbours of this peer.
   * Maps peer identities to `struct Neighbour` entries.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *neighbours;

  /**
   * Peer identity as assumed by this process, or all zeros.
   */
  struct GNUNET_PeerIdentity self;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we check that @e self matches what the service thinks?
   * (if #GNUNET_NO, then @e self is all zeros!).
   */
  int check_self;

};


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_CoreHandle *h);


/**
 * Get the neighbour list entry for the given peer
 *
 * @param h our context
 * @param peer peer to look up
 * @return NULL if no such peer entry exists
 */
static struct Neighbour *
neighbour_find (struct GNUNET_TRANSPORT_CoreHandle *h,
                const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_get (h->neighbours,
                                            peer);
}


/**
 * Function called by the bandwidth tracker if we have excess
 * bandwidth.
 *
 * @param cls the `struct Neighbour` that has excess bandwidth
 */
static void
notify_excess_cb (void *cls)
{
  struct Neighbour *n = cls;
  struct GNUNET_TRANSPORT_CoreHandle *h = n->h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying CORE that more bandwidth is available for %s\n",
       GNUNET_i2s (&n->id));

  if (NULL != h->neb_cb)
    h->neb_cb (h->cls,
               &n->id,
               n->handlers_cls);
}


/**
 * Iterator over hash map entries, for deleting state of a neighbour.
 *
 * @param cls the `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param key peer identity
 * @param value value in the hash map, the neighbour entry to delete
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
neighbour_delete (void *cls,
		  const struct GNUNET_PeerIdentity *key,
                  void *value)
{
  struct GNUNET_TRANSPORT_CoreHandle *handle = cls;
  struct Neighbour *n = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dropping entry for neighbour `%s'.\n",
       GNUNET_i2s (key));
  GNUNET_BANDWIDTH_tracker_notification_stop (&n->out_tracker);
  if (NULL != handle->nd_cb)
    handle->nd_cb (handle->cls,
                   &n->id,
                   n->handlers_cls);
  if (NULL != n->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (n->timeout_task);
    n->timeout_task = NULL;
  }
  if (NULL != n->env)
  {
    GNUNET_MQ_send_cancel (n->env);
    n->env = NULL;
  }
  GNUNET_MQ_destroy (n->mq);
  GNUNET_assert (NULL == n->mq);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (handle->neighbours,
                                                       key,
                                                       n));
  GNUNET_free (n);
  return GNUNET_YES;
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Error receiving from transport service, disconnecting temporarily.\n");
  disconnect_and_schedule_reconnect (h);
}


/**
 * Function we use for checking incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param msg message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_hello (void *cls,
             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PeerIdentity me;

  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) msg,
                           &me))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param msg message received
 */
static void
handle_hello (void *cls,
              const struct GNUNET_MessageHeader *msg)
{
  /* we do not care => FIXME: signal in options to NEVER send HELLOs! */
}


/**
 * A message from the handler's message queue to a neighbour was
 * transmitted.  Now trigger (possibly delayed) notification of the
 * neighbour's message queue that we are done and thus ready for
 * the next message.
 *
 * @param cls the `struct Neighbour` where the message was sent
 */
static void
notify_send_done (void *cls)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_Relative delay;

  n->timeout_task = NULL;
  if (NULL != n->env)
  {
    GNUNET_BANDWIDTH_tracker_consume (&n->out_tracker,
                                      n->env_size + n->traffic_overhead);
    n->traffic_overhead = 0;
    n->env = NULL;
  }
  delay = GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                              128);
  if (0 == delay.rel_value_us)
  {
    n->is_ready = GNUNET_YES;
    GNUNET_MQ_impl_send_continue (n->mq);
    return;
  }
  /* cannot send even a small message without violating
     quota, wait a before notifying MQ */
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                  &notify_send_done,
                                                  n);
}


/**
 * Implement sending functionality of a message queue.
 * Called one message at a time. Should send the @a msg
 * to the transport service and then notify the queue
 * once we are ready for the next one.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
mq_send_impl (struct GNUNET_MQ_Handle *mq,
              const struct GNUNET_MessageHeader *msg,
              void *impl_state)
{
  struct Neighbour *n = impl_state;
  struct GNUNET_TRANSPORT_CoreHandle *h = n->h;
  struct OutboundMessage *obm;
  uint16_t msize;

  GNUNET_assert (GNUNET_YES == n->is_ready);
  msize = ntohs (msg->size);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*obm))
  {
    GNUNET_break (0);
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }
  n->env = GNUNET_MQ_msg_nested_mh (obm,
                                    GNUNET_MESSAGE_TYPE_TRANSPORT_SEND,
                                    msg);
  obm->reserved = htonl (0);
  obm->timeout = GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_MINUTES); /* FIXME: to be removed */
  obm->peer = n->id;
  GNUNET_assert (NULL == n->timeout_task);
  n->is_ready = GNUNET_NO;
  n->env_size = ntohs (msg->size);
  GNUNET_MQ_notify_sent (n->env,
                         &notify_send_done,
                         n);
  GNUNET_MQ_send (h->mq,
                  n->env);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queued message for neighbour `%s'.\n",
       GNUNET_i2s (&n->id));
}


/**
 * Handle destruction of a message queue.  Implementations must not
 * free @a mq, but should take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
mq_destroy_impl (struct GNUNET_MQ_Handle *mq,
                 void *impl_state)
{
  struct Neighbour *n = impl_state;

  GNUNET_assert (mq == n->mq);
  n->mq = NULL;
}


/**
 * Implementation function that cancels the currently sent message.
 * Should basically undo whatever #mq_send_impl() did.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
mq_cancel_impl (struct GNUNET_MQ_Handle *mq,
                void *impl_state)
{
  struct Neighbour *n = impl_state;

  GNUNET_assert (GNUNET_NO == n->is_ready);
  if (NULL != n->env)
  {
    GNUNET_MQ_send_cancel (n->env);
    n->env = NULL;
  }

  n->is_ready = GNUNET_YES;
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
peer_mq_error_handler (void *cls,
                       enum GNUNET_MQ_Error error)
{
  /* struct Neighbour *n = cls; */

  GNUNET_break_op (0);
}


/**
 * The outbound quota has changed in a way that may require
 * us to reset the timeout.  Update the timeout.
 *
 * @param cls the `struct Neighbour` for which the timeout changed
 */
static void
outbound_bw_tracker_update (void *cls)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_Relative delay;

  if (NULL == n->timeout_task)
    return;
  delay = GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                              128);
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                  &notify_send_done,
                                                  n);
}


/**
 * Function we use for handling incoming connect messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param cim message received
 */
static void
handle_connect (void *cls,
                const struct ConnectInfoMessage *cim)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving CONNECT message for `%s' with quota %u\n",
       GNUNET_i2s (&cim->id),
       ntohl (cim->quota_out.value__));
  n = neighbour_find (h, &cim->id);
  if (NULL != n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  n = GNUNET_new (struct Neighbour);
  n->id = cim->id;
  n->h = h;
  n->is_ready = GNUNET_YES;
  n->traffic_overhead = 0;
  GNUNET_BANDWIDTH_tracker_init2 (&n->out_tracker,
                                  &outbound_bw_tracker_update,
                                  n,
                                  GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                  MAX_BANDWIDTH_CARRY_S,
                                  &notify_excess_cb,
                                  n);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (h->neighbours,
                                                    &n->id,
                                                    n,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  GNUNET_BANDWIDTH_tracker_update_quota (&n->out_tracker,
                                         cim->quota_out);
  n->mq = GNUNET_MQ_queue_for_callbacks (&mq_send_impl,
                                         &mq_destroy_impl,
                                         &mq_cancel_impl,
                                         n,
                                         h->handlers,
                                         &peer_mq_error_handler,
                                         n);
  if (NULL != h->nc_cb)
  {
    n->handlers_cls = h->nc_cb (h->cls,
                                &n->id,
                                n->mq);
    GNUNET_MQ_set_handlers_closure (n->mq,
                                    n->handlers_cls);
  }
}


/**
 * Function we use for handling incoming disconnect messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param dim message received
 */
static void
handle_disconnect (void *cls,
                   const struct DisconnectInfoMessage *dim)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  GNUNET_break (ntohl (dim->reserved) == 0);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving DISCONNECT message for `%s'.\n",
       GNUNET_i2s (&dim->peer));
  n = neighbour_find (h, &dim->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 neighbour_delete (h,
                                   &dim->peer,
                                   n));
}


/**
 * Function we use for handling incoming send-ok messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param okm message received
 */
static void
handle_send_ok (void *cls,
                const struct SendOkMessage *okm)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;
  uint32_t bytes_msg;
  uint32_t bytes_physical;

  bytes_msg = ntohl (okm->bytes_msg);
  bytes_physical = ntohl (okm->bytes_physical);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving SEND_OK message, transmission to %s %s.\n",
       GNUNET_i2s (&okm->peer),
       ntohl (okm->success) == GNUNET_OK ? "succeeded" : "failed");
  n = neighbour_find (h,
                      &okm->peer);
  if (NULL == n)
  {
    /* We should never get a 'SEND_OK' for a peer that we are not
       connected to */
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  if (bytes_physical > bytes_msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Overhead for %u byte message was %u\n",
         bytes_msg,
         bytes_physical - bytes_msg);
    n->traffic_overhead += bytes_physical - bytes_msg;
  }
}


/**
 * Function we use for checking incoming "inbound" messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param im message received
 */
static int
check_recv (void *cls,
             const struct InboundMessage *im)
{
  const struct GNUNET_MessageHeader *imm;
  uint16_t size;

  size = ntohs (im->header.size) - sizeof (*im);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  imm = (const struct GNUNET_MessageHeader *) &im[1];
  if (ntohs (imm->size) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param im message received
 */
static void
handle_recv (void *cls,
             const struct InboundMessage *im)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  const struct GNUNET_MessageHeader *imm
    = (const struct GNUNET_MessageHeader *) &im[1];
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u with %u bytes from `%s'.\n",
       (unsigned int) ntohs (imm->type),
       (unsigned int) ntohs (imm->size),
       GNUNET_i2s (&im->peer));
  n = neighbour_find (h, &im->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  GNUNET_MQ_inject_message (n->mq,
                            imm);
}


/**
 * Function we use for handling incoming set quota messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param msg message received
 */
static void
handle_set_quota (void *cls,
                  const struct QuotaSetMessage *qm)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  n = neighbour_find (h,
		      &qm->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving SET_QUOTA message for `%s' with quota %u\n",
       GNUNET_i2s (&qm->peer),
       ntohl (qm->quota.value__));
  GNUNET_BANDWIDTH_tracker_update_quota (&n->out_tracker,
                                         qm->quota);
}


/**
 * Try again to connect to transport service.
 *
 * @param cls the handle to the transport service
 */
static void
reconnect (void *cls)
{
  GNUNET_MQ_hd_var_size (hello,
                         GNUNET_MESSAGE_TYPE_HELLO,
                         struct GNUNET_MessageHeader);
  GNUNET_MQ_hd_fixed_size (connect,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT,
                           struct ConnectInfoMessage);
  GNUNET_MQ_hd_fixed_size (disconnect,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT,
                           struct DisconnectInfoMessage);
  GNUNET_MQ_hd_fixed_size (send_ok,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK,
                           struct SendOkMessage);
  GNUNET_MQ_hd_var_size (recv,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_RECV,
                         struct InboundMessage);
  GNUNET_MQ_hd_fixed_size (set_quota,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA,
                           struct QuotaSetMessage);
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_hello_handler (h),
    make_connect_handler (h),
    make_disconnect_handler (h),
    make_send_ok_handler (h),
    make_recv_handler (h),
    make_set_quota_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct StartMessage *s;
  uint32_t options;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "transport",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  env = GNUNET_MQ_msg (s,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  options = 0;
  if (h->check_self)
    options |= 1;
  if (NULL != h->handlers)
    options |= 2;
  s->options = htonl (options);
  s->self = h->self;
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_CoreHandle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  /* Forget about all neighbours that we used to be connected to */
  GNUNET_CONTAINER_multipeermap_iterate (h->neighbours,
                                         &neighbour_delete,
                                         h);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to transport service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay,
                                               GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                    &reconnect,
                                    h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Checks if a given peer is connected to us and get the message queue.
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return NULL if disconnected, otherwise message queue for @a peer
 */
struct GNUNET_MQ_Handle *
GNUNET_TRANSPORT_core_get_mq (struct GNUNET_TRANSPORT_CoreHandle *handle,
                              const struct GNUNET_PeerIdentity *peer)
{
  struct Neighbour *n;

  n = neighbour_find (handle,
                      peer);
  if (NULL == n)
    return NULL;
  return n->mq;
}


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param nd function to call on disconnect events
 * @param neb function to call if we have excess bandwidth to a peer
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CoreHandle *
GNUNET_TRANSPORT_core_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			       const struct GNUNET_PeerIdentity *self,
			       const struct GNUNET_MQ_MessageHandler *handlers,
			       void *cls,
			       GNUNET_TRANSPORT_NotifyConnecT nc,
			       GNUNET_TRANSPORT_NotifyDisconnecT nd,
			       GNUNET_TRANSPORT_NotifyExcessBandwidtH neb)
{
  struct GNUNET_TRANSPORT_CoreHandle *h;
  unsigned int i;

  h = GNUNET_new (struct GNUNET_TRANSPORT_CoreHandle);
  if (NULL != self)
  {
    h->self = *self;
    h->check_self = GNUNET_YES;
  }
  h->cfg = cfg;
  h->cls = cls;
  h->nc_cb = nc;
  h->nd_cb = nd;
  h->neb_cb = neb;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  if (NULL != handlers)
  {
    for (i=0;NULL != handlers[i].cb; i++) ;
    h->handlers = GNUNET_new_array (i + 1,
                                    struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (h->handlers,
		   handlers,
		   i * sizeof (struct GNUNET_MQ_MessageHandler));
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service\n");
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free_non_null (h->handlers);
    GNUNET_free (h);
    return NULL;
  }
  h->neighbours =
    GNUNET_CONTAINER_multipeermap_create (STARTING_NEIGHBOURS_SIZE,
                                          GNUNET_YES);
  return h;
}


/**
 * Disconnect from the transport service.
 *
 * @param handle handle to the service as returned from #GNUNET_TRANSPORT_connect()
 */
void
GNUNET_TRANSPORT_core_disconnect (struct GNUNET_TRANSPORT_CoreHandle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transport disconnect called!\n");
  /* this disconnects all neighbours... */
  if (NULL == handle->reconnect_task)
    disconnect_and_schedule_reconnect (handle);
  /* and now we stop trying to connect again... */
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_destroy (handle->neighbours);
  handle->neighbours = NULL;
  GNUNET_free_non_null (handle->handlers);
  handle->handlers = NULL;
  GNUNET_free (handle);
}


/* end of transport_api_core.c */
