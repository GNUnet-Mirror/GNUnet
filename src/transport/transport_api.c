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
 * @file transport/transport_api.c
 * @brief library to access the low-level P2P IO service
 * @author Christian Grothoff
 *
 * TODO:
 * - test test test
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-api",__VA_ARGS__)

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
 * Handle for a message that should be transmitted to the service.
 * Used for both control messages and normal messages.
 */
struct GNUNET_TRANSPORT_TransmitHandle
{

  /**
   * We keep all requests in a DLL.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *next;

  /**
   * We keep all requests in a DLL.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *prev;

  /**
   * Neighbour for this handle, NULL for control messages.
   */
  struct Neighbour *neighbour;

  /**
   * Function to call when @e notify_size bytes are available
   * for transmission.
   */
  GNUNET_TRANSPORT_TransmitReadyNotify notify;

  /**
   * Closure for @e notify.
   */
  void *notify_cls;

  /**
   * Time at which this request was originally scheduled.
   */
  struct GNUNET_TIME_Absolute request_start;

  /**
   * Timeout for this request, 0 for control messages.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task to trigger request timeout if the request is stalled due to
   * congestion.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * How many bytes is our notify callback waiting for?
   */
  size_t notify_size;

};


/**
 * Entry in hash table of all of our current (connected) neighbours.
 */
struct Neighbour
{
  /**
   * Overall transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *h;

  /**
   * Active transmit handle or NULL.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *th;

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
   * Last time when this peer received payload from us.
   */
  struct GNUNET_TIME_Absolute last_payload;

  /**
   * Task to trigger warnings if we do not get SEND_OK after a while.
   */
  struct GNUNET_SCHEDULER_Task *unready_warn_task;

  /**
   * Is this peer currently ready to receive a message?
   */
  int is_ready;

  /**
   * Sending consumed more bytes on wire than payload was announced
   * This overhead is added to the delay of next sending operation
   */
  size_t traffic_overhead;
};



/**
 * Handle for the transport service (includes all of the
 * state for the transport service).
 */
struct GNUNET_TRANSPORT_Handle
{

  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Function to call for received data.
   */
  GNUNET_TRANSPORT_ReceiveCallback rec;

  /**
   * function to call on connect events
   */
  GNUNET_TRANSPORT_NotifyConnect nc_cb;

  /**
   * function to call on disconnect events
   */
  GNUNET_TRANSPORT_NotifyDisconnect nd_cb;

  /**
   * function to call on excess bandwidth events
   */
  GNUNET_TRANSPORT_NotifyExcessBandwidth neb_cb;

  /**
   * The current HELLO message for this peer.  Updated
   * whenever transports change their addresses.
   */
  struct GNUNET_MessageHeader *my_hello;

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
   * Heap sorting peers with pending messages by the timestamps that
   * specify when we could next send a message to the respective peer.
   * Excludes control messages (which can always go out immediately).
   * Maps time stamps to `struct Neighbour` entries.
   */
  struct GNUNET_CONTAINER_Heap *ready_heap;

  /**
   * Peer identity as assumed by this process, or all zeros.
   */
  struct GNUNET_PeerIdentity self;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * ID of the task trying to trigger transmission for a peer while
   * maintaining bandwidth quotas.  In use if there are no control
   * messages and the smallest entry in the @e ready_heap has a time
   * stamp in the future.
   */
  struct GNUNET_SCHEDULER_Task *quota_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we check that @e self matches what the service thinks?
   * (if #GNUNET_NO, then @e self is all zeros!).
   */
  int check_self;

  /**
   * Reconnect in progress
   */
  int reconnecting;
};


/**
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 *
 * @param h transport service to schedule a transmission for
 */
static void
schedule_transmission (struct GNUNET_TRANSPORT_Handle *h);


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_Handle *h);


/**
 * A neighbour has not gotten a SEND_OK in a  while. Print a warning.
 *
 * @param cls the `struct Neighbour`
 */
static void
do_warn_unready (void *cls)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (n->last_payload);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Lacking SEND_OK, no payload could be send to %s for %s\n",
              GNUNET_i2s (&n->id),
              GNUNET_STRINGS_relative_time_to_string (delay,
                                                      GNUNET_YES));
  n->unready_warn_task
    = GNUNET_SCHEDULER_add_delayed (UNREADY_WARN_TIME,
                                    &do_warn_unready,
                                    n);
}


/**
 * Get the neighbour list entry for the given peer
 *
 * @param h our context
 * @param peer peer to look up
 * @return NULL if no such peer entry exists
 */
static struct Neighbour *
neighbour_find (struct GNUNET_TRANSPORT_Handle *h,
                const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_get (h->neighbours,
                                            peer);
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

  if (NULL == n->hn)
    return;
  delay = GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                              n->th->notify_size + n->traffic_overhead);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New outbound delay %s us\n",
       GNUNET_STRINGS_relative_time_to_string (delay,
                                               GNUNET_NO));
  GNUNET_CONTAINER_heap_update_cost (n->h->ready_heap,
                                     n->hn,
                                     delay.rel_value_us);
  schedule_transmission (n->h);
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
  struct GNUNET_TRANSPORT_Handle *h = n->h;

  if (NULL != h->neb_cb)
    h->neb_cb (h->cls,
               &n->id);
}


/**
 * Add neighbour to our list
 *
 * @return NULL if this API is currently disconnecting from the service
 */
static struct Neighbour *
neighbour_add (struct GNUNET_TRANSPORT_Handle *h,
               const struct GNUNET_PeerIdentity *pid)
{
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating entry for neighbour `%s'.\n",
       GNUNET_i2s (pid));
  n = GNUNET_new (struct Neighbour);
  n->id = *pid;
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
  return n;
}


/**
 * Iterator over hash map entries, for deleting state of a neighbour.
 *
 * @param cls the `struct GNUNET_TRANSPORT_Handle *`
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
  struct GNUNET_TRANSPORT_Handle *handle = cls;
  struct Neighbour *n = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dropping entry for neighbour `%s'.\n",
       GNUNET_i2s (key));
  GNUNET_BANDWIDTH_tracker_notification_stop (&n->out_tracker);
  if (NULL != handle->nd_cb)
    handle->nd_cb (handle->cls,
                   &n->id);
  if (NULL != n->unready_warn_task)
  {
    GNUNET_SCHEDULER_cancel (n->unready_warn_task);
    n->unready_warn_task = NULL;
  }
  GNUNET_assert (NULL == n->th);
  GNUNET_assert (NULL == n->hn);
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
 * @param cls closure with the `struct GNUNET_TRANSPORT_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Error receiving from transport service, disconnecting temporarily.\n");
  h->reconnecting = GNUNET_YES;
  disconnect_and_schedule_reconnect (h);
}


/**
 * Function we use for checking incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving (my own) HELLO message (%u bytes), I am `%s'.\n",
       (unsigned int) ntohs (msg->size),
       GNUNET_i2s (&me));
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param msg message received
 */
static void
handle_hello (void *cls,
              const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;

  GNUNET_free_non_null (h->my_hello);
  h->my_hello = GNUNET_copy_message (msg);
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
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving CONNECT message for `%s'.\n",
       GNUNET_i2s (&cim->id));
  n = neighbour_find (h, &cim->id);
  if (NULL != n)
  {
    GNUNET_break (0);
    h->reconnecting = GNUNET_YES;
    disconnect_and_schedule_reconnect (h);
    return;
  }
  n = neighbour_add (h,
                     &cim->id);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving CONNECT message for `%s' with quota %u\n",
       GNUNET_i2s (&cim->id),
       ntohl (cim->quota_out.value__));
  GNUNET_BANDWIDTH_tracker_update_quota (&n->out_tracker,
                                         cim->quota_out);
  if (NULL != h->nc_cb)
    h->nc_cb (h->cls,
              &n->id);
}


/**
 * Function we use for handling incoming disconnect messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param dim message received
 */
static void
handle_disconnect (void *cls,
                   const struct DisconnectInfoMessage *dim)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct Neighbour *n;

  GNUNET_break (ntohl (dim->reserved) == 0);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving DISCONNECT message for `%s'.\n",
       GNUNET_i2s (&dim->peer));
  n = neighbour_find (h, &dim->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    h->reconnecting = GNUNET_YES;
    disconnect_and_schedule_reconnect (h);
    return;
  }
  neighbour_delete (h,
                    &dim->peer,
                    n);
}


/**
 * Function we use for handling incoming send-ok messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param okm message received
 */
static void
handle_send_ok (void *cls,
                const struct SendOkMessage *okm)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
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
    h->reconnecting = GNUNET_YES;
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
  GNUNET_break (GNUNET_NO == n->is_ready);
  n->is_ready = GNUNET_YES;
  if (NULL != n->unready_warn_task)
  {
    GNUNET_SCHEDULER_cancel (n->unready_warn_task);
    n->unready_warn_task = NULL;
  }
  if ((NULL != n->th) && (NULL == n->hn))
  {
    GNUNET_assert (NULL != n->th->timeout_task);
    GNUNET_SCHEDULER_cancel (n->th->timeout_task);
    n->th->timeout_task = NULL;
    /* we've been waiting for this (congestion, not quota,
     * caused delayed transmission) */
    n->hn = GNUNET_CONTAINER_heap_insert (h->ready_heap,
                                          n,
                                          0);
  }
  schedule_transmission (h);
}


/**
 * Function we use for checking incoming "inbound" messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param im message received
 */
static int
check_recv (void *cls,
             const struct InboundMessage *im)
{
  const struct GNUNET_MessageHeader *imm;
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <
      sizeof (struct InboundMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  imm = (const struct GNUNET_MessageHeader *) &im[1];
  if (ntohs (imm->size) + sizeof (struct InboundMessage) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param im message received
 */
static void
handle_recv (void *cls,
             const struct InboundMessage *im)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
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
    h->reconnecting = GNUNET_YES;
    disconnect_and_schedule_reconnect (h);
    return;
  }
  if (NULL != h->rec)
    h->rec (h->cls,
            &im->peer,
            imm);
}


/**
 * Function we use for handling incoming set quota messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param msg message received
 */
static void
handle_set_quota (void *cls,
                  const struct QuotaSetMessage *qm)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct Neighbour *n;

  n = neighbour_find (h, &qm->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    h->reconnecting = GNUNET_YES;
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
 * A transmission request could not be satisfied because of
 * network congestion.  Notify the initiator and clean up.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TransmitHandle`
 */
static void
timeout_request_due_to_congestion (void *cls)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;
  struct Neighbour *n = th->neighbour;
  struct GNUNET_TIME_Relative delay;

  n->th->timeout_task = NULL;
  delay = GNUNET_TIME_absolute_get_duration (th->request_start);
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Discarding %u bytes of payload message after %s delay due to congestion\n",
       th->notify_size,
       GNUNET_STRINGS_relative_time_to_string (delay,
                                               GNUNET_YES));
  GNUNET_assert (th == n->th);
  GNUNET_assert (NULL == n->hn);
  n->th = NULL;
  th->notify (th->notify_cls,
              0,
              NULL);
  GNUNET_free (th);
}


/**
 * Transmit ready message(s) to service.
 *
 * @param h handle to transport
 */
static void
transmit_ready (struct GNUNET_TRANSPORT_Handle *h)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct GNUNET_TIME_Relative delay;
  struct Neighbour *n;
  struct OutboundMessage *obm;
  struct GNUNET_MQ_Envelope *env;
  size_t mret;

  GNUNET_assert (NULL != h->mq);
  while (NULL != (n = GNUNET_CONTAINER_heap_peek (h->ready_heap)))
  {
    th = n->th;
    if (GNUNET_YES != n->is_ready)
    {
      /* peer not ready, wait for notification! */
      GNUNET_assert (n == GNUNET_CONTAINER_heap_remove_root (h->ready_heap));
      n->hn = NULL;
      GNUNET_assert (NULL == n->th->timeout_task);
      th->timeout_task
        = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                        (th->timeout),
                                        &timeout_request_due_to_congestion,
                                        th);
      continue;
    }
    if (GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                            th->notify_size).rel_value_us > 0)
      break;                    /* too early */
    GNUNET_assert (n == GNUNET_CONTAINER_heap_remove_root (h->ready_heap));
    n->hn = NULL;
    n->th = NULL;
    env = GNUNET_MQ_msg_extra (obm,
                               th->notify_size,
                               GNUNET_MESSAGE_TYPE_TRANSPORT_SEND);
    mret = th->notify (th->notify_cls,
                       th->notify_size,
                       &obm[1]);
    if (0 == mret)
    {
      GNUNET_free (th);
      GNUNET_MQ_discard (env);
      continue;
    }
    obm->header.size = htons (mret + sizeof (*obm));
    if (NULL != n->unready_warn_task)
      n->unready_warn_task
        = GNUNET_SCHEDULER_add_delayed (UNREADY_WARN_TIME,
                                        &do_warn_unready,
                                        n);
    n->last_payload = GNUNET_TIME_absolute_get ();
    n->is_ready = GNUNET_NO;
    obm->reserved = htonl (0);
    obm->timeout =
      GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining
                                 (th->timeout));
    obm->peer = n->id;
    GNUNET_MQ_send (h->mq,
                    env);
    GNUNET_BANDWIDTH_tracker_consume (&n->out_tracker,
                                      mret);
    delay = GNUNET_TIME_absolute_get_duration (th->request_start);
    if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Added %u bytes of payload message for %s after %s delay at %u b/s\n",
           mret,
           GNUNET_i2s (&n->id),
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES),
           (unsigned int) n->out_tracker.available_bytes_per_s__);
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Added %u bytes of payload message for %s after %s delay at %u b/s\n",
           mret,
           GNUNET_i2s (&n->id),
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES),
           (unsigned int) n->out_tracker.available_bytes_per_s__);
    GNUNET_free (th);
  }
  /* if there are more pending messages, try to schedule those */
  schedule_transmission (h);
}


/**
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 *
 * @param cls transport service to schedule a transmission for
 */
static void
schedule_transmission_task (void *cls)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct Neighbour *n;

  h->quota_task = NULL;
  GNUNET_assert (NULL != h->mq);
  /* destroy all requests that have timed out */
  while ( (NULL != (n = GNUNET_CONTAINER_heap_peek (h->ready_heap))) &&
          (0 == GNUNET_TIME_absolute_get_remaining (n->th->timeout).rel_value_us) )
  {
    /* notify client that the request could not be satisfied within
     * the given time constraints */
    th = n->th;
    n->th = NULL;
    GNUNET_assert (n == GNUNET_CONTAINER_heap_remove_root (h->ready_heap));
    n->hn = NULL;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Signalling timeout for transmission to peer %s due to congestion\n",
         GNUNET_i2s (&n->id));
    GNUNET_assert (0 == th->notify (th->notify_cls,
                                    0,
                                    NULL));
    GNUNET_free (th);
  }
  n = GNUNET_CONTAINER_heap_peek (h->ready_heap);
  if (NULL == n)
    return;                   /* no pending messages */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Calling notify_transmit_ready\n");
  transmit_ready (h);
}


/**
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 *
 * @param h transport service to schedule a transmission for
 */
static void
schedule_transmission (struct GNUNET_TRANSPORT_Handle *h)
{
  struct GNUNET_TIME_Relative delay;
  struct Neighbour *n;

  GNUNET_assert (NULL != h->mq);
  if (NULL != h->quota_task)
  {
    GNUNET_SCHEDULER_cancel (h->quota_task);
    h->quota_task = NULL;
  }
  if (NULL != (n = GNUNET_CONTAINER_heap_peek (h->ready_heap)))
  {
    delay =
        GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                            n->th->notify_size + n->traffic_overhead);
    n->traffic_overhead = 0;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No work to be done, not scheduling transmission.\n");
    return;                     /* no work to be done */
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling next transmission to service in %s\n",
       GNUNET_STRINGS_relative_time_to_string (delay,
                                               GNUNET_YES));
  h->quota_task =
      GNUNET_SCHEDULER_add_delayed (delay,
                                    &schedule_transmission_task,
                                    h);
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
  struct GNUNET_TRANSPORT_Handle *h = cls;
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
  h->reconnecting = GNUNET_NO;
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
  if (NULL != h->rec)
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
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_Handle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  /* Forget about all neighbours that we used to be connected to */
  GNUNET_CONTAINER_multipeermap_iterate (h->neighbours,
                                         &neighbour_delete,
                                         h);
  if (NULL != h->quota_task)
  {
    GNUNET_SCHEDULER_cancel (h->quota_task);
    h->quota_task = NULL;
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
 * Set transport metrics for a peer and a direction.
 *
 * @param handle transport handle
 * @param peer the peer to set the metric for
 * @param prop the performance metrics to set
 * @param delay_in inbound delay to introduce
 * @param delay_out outbound delay to introduce
 *
 * Note: Delay restrictions in receiving direction will be enforced
 * with one message delay.
 */
void
GNUNET_TRANSPORT_set_traffic_metric (struct GNUNET_TRANSPORT_Handle *handle,
				     const struct GNUNET_PeerIdentity *peer,
				     const struct GNUNET_ATS_Properties *prop,
                                     struct GNUNET_TIME_Relative delay_in,
                                     struct GNUNET_TIME_Relative delay_out)
{
  struct GNUNET_MQ_Envelope *env;
  struct TrafficMetricMessage *msg;

  if (NULL == handle->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  GNUNET_ATS_properties_hton (&msg->properties,
                              prop);
  msg->delay_in = GNUNET_TIME_relative_hton (delay_in);
  msg->delay_out = GNUNET_TIME_relative_hton (delay_out);
  GNUNET_MQ_send (handle->mq,
                  env);
}


/**
 * Checks if a given peer is connected to us
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return #GNUNET_YES (connected) or #GNUNET_NO (disconnected)
 */
int
GNUNET_TRANSPORT_check_peer_connected (struct GNUNET_TRANSPORT_Handle *handle,
                                       const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (handle->neighbours,
                                              peer))
    return GNUNET_YES;
  return GNUNET_NO;
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
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_PeerIdentity *self,
                          void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd)
{
  return GNUNET_TRANSPORT_connect2 (cfg,
                                    self,
                                    cls,
                                    rec,
                                    nc,
                                    nd,
                                    NULL);
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
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const struct GNUNET_PeerIdentity *self,
                           void *cls,
                           GNUNET_TRANSPORT_ReceiveCallback rec,
                           GNUNET_TRANSPORT_NotifyConnect nc,
                           GNUNET_TRANSPORT_NotifyDisconnect nd,
                           GNUNET_TRANSPORT_NotifyExcessBandwidth neb)
{
  struct GNUNET_TRANSPORT_Handle *h;

  h = GNUNET_new (struct GNUNET_TRANSPORT_Handle);
  if (NULL != self)
  {
    h->self = *self;
    h->check_self = GNUNET_YES;
  }
  h->cfg = cfg;
  h->cls = cls;
  h->rec = rec;
  h->nc_cb = nc;
  h->nd_cb = nd;
  h->neb_cb = neb;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  h->neighbours =
    GNUNET_CONTAINER_multipeermap_create (STARTING_NEIGHBOURS_SIZE,
                                          GNUNET_YES);
  h->ready_heap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  return h;
}


/**
 * Disconnect from the transport service.
 *
 * @param handle handle to the service as returned from #GNUNET_TRANSPORT_connect()
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle)
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
  if (NULL != handle->quota_task)
  {
    GNUNET_SCHEDULER_cancel (handle->quota_task);
    handle->quota_task = NULL;
  }
  GNUNET_free_non_null (handle->my_hello);
  handle->my_hello = NULL;
  GNUNET_CONTAINER_heap_destroy (handle->ready_heap);
  handle->ready_heap = NULL;
  GNUNET_free (handle);
}


/**
 * Check if we could queue a message of the given size for
 * transmission.  The transport service will take both its
 * internal buffers and bandwidth limits imposed by the
 * other peer into consideration when answering this query.
 *
 * @param handle connection to transport service
 * @param target who should receive the message
 * @param size how big is the message we want to transmit?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for @a notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using #GNUNET_TRANSPORT_notify_transmit_ready_cancel)
 */
struct GNUNET_TRANSPORT_TransmitHandle *
GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle *handle,
                                        const struct GNUNET_PeerIdentity *target,
                                        size_t size,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_TransmitReadyNotify notify,
                                        void *notify_cls)
{
  struct Neighbour *n;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct GNUNET_TIME_Relative delay;

  n = neighbour_find (handle, target);
  if (NULL == n)
  {
    /* only use this function
     * once a connection has been established */
    GNUNET_assert (0);
    return NULL;
  }
  if (NULL != n->th)
  {
    /* attempt to send two messages at the same time to the same peer */
    GNUNET_assert (0);
    return NULL;
  }
  GNUNET_assert (NULL == n->hn);
  th = GNUNET_new (struct GNUNET_TRANSPORT_TransmitHandle);
  th->neighbour = n;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->request_start = GNUNET_TIME_absolute_get ();
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  th->notify_size = size;
  n->th = th;
  /* calculate when our transmission should be ready */
  delay = GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                              size + n->traffic_overhead);
  n->traffic_overhead = 0;
  if (delay.rel_value_us > timeout.rel_value_us)
    delay.rel_value_us = 0;        /* notify immediately (with failure) */
  if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "At bandwidth %u byte/s next transmission to %s in %s\n",
         (unsigned int) n->out_tracker.available_bytes_per_s__,
         GNUNET_i2s (target),
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "At bandwidth %u byte/s next transmission to %s in %s\n",
         (unsigned int) n->out_tracker.available_bytes_per_s__,
         GNUNET_i2s (target),
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  n->hn = GNUNET_CONTAINER_heap_insert (handle->ready_heap,
                                        n,
                                        delay.rel_value_us);
  schedule_transmission (handle);
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle returned from #GNUNET_TRANSPORT_notify_transmit_ready()
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  struct Neighbour *n;

  GNUNET_assert (NULL == th->next);
  GNUNET_assert (NULL == th->prev);
  n = th->neighbour;
  GNUNET_assert (th == n->th);
  n->th = NULL;
  if (NULL != n->hn)
  {
    GNUNET_CONTAINER_heap_remove_node (n->hn);
    n->hn = NULL;
  }
  else
  {
    GNUNET_assert (NULL != th->timeout_task);
    GNUNET_SCHEDULER_cancel (th->timeout_task);
    th->timeout_task = NULL;
  }
  GNUNET_free (th);
}


/* end of transport_api.c */
