/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * Linked list of functions to call whenever our HELLO is updated.
 */
struct GNUNET_TRANSPORT_GetHelloHandle
{

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *next;

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *prev;

  /**
   * Transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *handle;

  /**
   * Callback to call once we got our HELLO.
   */
  GNUNET_TRANSPORT_HelloUpdateCallback rec;

  /**
   * Task for calling the HelloUpdateCallback when we already have a HELLO
   */
  struct GNUNET_SCHEDULER_Task *notify_task;

  /**
   * Closure for @e rec.
   */
  void *rec_cls;

};


/**
 * Entry in linked list for a try-connect request.
 */
struct GNUNET_TRANSPORT_TryConnectHandle
{
  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_TryConnectHandle *prev;

  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_TryConnectHandle *next;

  /**
   * Peer we should try to connect to.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Transport service handle this request is part of.
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * Message transmission request to communicate to service.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *tth;

  /**
   * Function to call upon completion (of request transmission).
   */
  GNUNET_TRANSPORT_TryConnectCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

};


/**
 * Entry in linked list for all offer-HELLO requests.
 */
struct GNUNET_TRANSPORT_OfferHelloHandle
{
  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *prev;

  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *next;

  /**
   * Transport service handle we use for transmission.
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * Transmission handle for this request.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *tth;

  /**
   * Function to call once we are done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont
   */
  void *cls;

  /**
   * The HELLO message to be transmitted.
   */
  struct GNUNET_MessageHeader *msg;
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
   * Head of DLL of control messages.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *control_head;

  /**
   * Tail of DLL of control messages.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *control_tail;

  /**
   * The current HELLO message for this peer.  Updated
   * whenever transports change their addresses.
   */
  struct GNUNET_MessageHeader *my_hello;

  /**
   * My client connection to the transport service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle to our registration with the client for notification.
   */
  struct GNUNET_CLIENT_TransmitHandle *cth;

  /**
   * Linked list of pending requests for our HELLO.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *hwl_head;

  /**
   * Linked list of pending requests for our HELLO.
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *hwl_tail;

  /**
   * Linked list of pending try connect requests head
   */
  struct GNUNET_TRANSPORT_TryConnectHandle *tc_head;

  /**
   * Linked list of pending try connect requests tail
   */
  struct GNUNET_TRANSPORT_TryConnectHandle *tc_tail;

  /**
   * Linked list of pending offer HELLO requests head
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh_head;

  /**
   * Linked list of pending offer HELLO requests tail
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh_tail;

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
 * @param tc scheduler context
 */
static void
do_warn_unready (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
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
      n->hn, delay.rel_value_us);
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
 * Function we use for handling incoming messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
demultiplexer (void *cls,
               const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  const struct DisconnectInfoMessage *dim;
  const struct ConnectInfoMessage *cim;
  const struct InboundMessage *im;
  const struct GNUNET_MessageHeader *imm;
  const struct SendOkMessage *okm;
  const struct QuotaSetMessage *qm;
  struct GNUNET_TRANSPORT_GetHelloHandle *hwl;
  struct GNUNET_TRANSPORT_GetHelloHandle *next_hwl;
  struct Neighbour *n;
  struct GNUNET_PeerIdentity me;
  uint16_t size;
  uint32_t bytes_msg;
  uint32_t bytes_physical;

  GNUNET_assert (NULL != h->client);
  if (GNUNET_YES == h->reconnecting)
  {
    return;
  }
  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Error receiving from transport service, disconnecting temporarily.\n");
    h->reconnecting = GNUNET_YES;
    disconnect_and_schedule_reconnect (h);
    return;
  }
  GNUNET_CLIENT_receive (h->client,
                         &demultiplexer,
                         h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  size = ntohs (msg->size);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_HELLO:
    if (GNUNET_OK !=
        GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) msg,
                             &me))
    {
      GNUNET_break (0);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving (my own) HELLO message (%u bytes), I am `%s'.\n",
         (unsigned int) size,
         GNUNET_i2s (&me));
    GNUNET_free_non_null (h->my_hello);
    h->my_hello = NULL;
    if (size < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break (0);
      break;
    }
    h->my_hello = GNUNET_copy_message (msg);
    hwl = h->hwl_head;
    while (NULL != hwl)
    {
      next_hwl = hwl->next;
      hwl->rec (hwl->rec_cls,
                h->my_hello);
      hwl = next_hwl;
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT:
    if (size < sizeof (struct ConnectInfoMessage))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    cim = (const struct ConnectInfoMessage *) msg;
    if (size !=
        sizeof (struct ConnectInfoMessage))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving CONNECT message for `%s'.\n",
         GNUNET_i2s (&cim->id));
    n = neighbour_find (h, &cim->id);
    if (NULL != n)
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
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
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT:
    if (size != sizeof (struct DisconnectInfoMessage))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    dim = (const struct DisconnectInfoMessage *) msg;
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
      break;
    }
    neighbour_delete (h,
                      &dim->peer,
                      n);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK:
    if (size != sizeof (struct SendOkMessage))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    okm = (const struct SendOkMessage *) msg;
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
      break;
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
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_RECV:
    if (size <
        sizeof (struct InboundMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    im = (const struct InboundMessage *) msg;
    imm = (const struct GNUNET_MessageHeader *) &im[1];
    if (ntohs (imm->size) + sizeof (struct InboundMessage) != size)
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
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
      break;
    }
    if (NULL != h->rec)
      h->rec (h->cls,
              &im->peer,
              imm);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA:
    if (size != sizeof (struct QuotaSetMessage))
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    qm = (const struct QuotaSetMessage *) msg;
    n = neighbour_find (h, &qm->peer);
    if (NULL == n)
    {
      GNUNET_break (0);
      h->reconnecting = GNUNET_YES;
      disconnect_and_schedule_reconnect (h);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving SET_QUOTA message for `%s' with quota %u\n",
         GNUNET_i2s (&qm->peer),
         ntohl (qm->quota.value__));
    GNUNET_BANDWIDTH_tracker_update_quota (&n->out_tracker,
                                           qm->quota);
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Received unexpected message of type %u in %s:%u\n"),
         ntohs (msg->type),
         __FILE__,
         __LINE__);
    GNUNET_break (0);
    break;
  }
}


/**
 * A transmission request could not be satisfied because of
 * network congestion.  Notify the initiator and clean up.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TransmitHandle`
 * @param tc scheduler context
 */
static void
timeout_request_due_to_congestion (void *cls,
                                   const struct GNUNET_SCHEDULER_TaskContext *tc)
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
 * Transmit message(s) to service.
 *
 * @param cls handle to transport
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
transport_notify_ready (void *cls,
                        size_t size,
                        void *buf)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct GNUNET_TIME_Relative delay;
  struct Neighbour *n;
  char *cbuf;
  struct OutboundMessage obm;
  size_t ret;
  size_t nret;
  size_t mret;

  GNUNET_assert (NULL != h->client);
  h->cth = NULL;
  if (NULL == buf)
  {
    /* transmission failed */
    disconnect_and_schedule_reconnect (h);
    return 0;
  }

  cbuf = buf;
  ret = 0;
  /* first send control messages */
  while ( (NULL != (th = h->control_head)) &&
          (th->notify_size <= size) )
  {
    GNUNET_CONTAINER_DLL_remove (h->control_head,
                                 h->control_tail,
                                 th);
    nret = th->notify (th->notify_cls,
                       size,
                       &cbuf[ret]);
    delay = GNUNET_TIME_absolute_get_duration (th->request_start);
    if (delay.rel_value_us > GNUNET_CONSTANTS_LATENCY_WARN.rel_value_us)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Added %u bytes of control message at %u after %s delay\n",
           nret,
           ret,
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES));
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Added %u bytes of control message at %u after %s delay\n",
           nret,
           ret,
           GNUNET_STRINGS_relative_time_to_string (delay,
                                                   GNUNET_YES));
    GNUNET_free (th);
    ret += nret;
    size -= nret;
  }

  /* then, if possible and no control messages pending, send data messages */
  while ( (NULL == h->control_head) &&
          (NULL != (n = GNUNET_CONTAINER_heap_peek (h->ready_heap))) )
  {
    if (GNUNET_YES != n->is_ready)
    {
      /* peer not ready, wait for notification! */
      GNUNET_assert (n == GNUNET_CONTAINER_heap_remove_root (h->ready_heap));
      n->hn = NULL;
      GNUNET_assert (NULL == n->th->timeout_task);
      n->th->timeout_task
        = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                        (n->th->timeout),
                                        &timeout_request_due_to_congestion,
                                        n->th);
      continue;
    }
    th = n->th;
    if (th->notify_size + sizeof (struct OutboundMessage) > size)
      break;                    /* does not fit */
    if (GNUNET_BANDWIDTH_tracker_get_delay
        (&n->out_tracker,
         th->notify_size).rel_value_us > 0)
      break;                    /* too early */
    GNUNET_assert (n == GNUNET_CONTAINER_heap_remove_root (h->ready_heap));
    n->hn = NULL;
    n->th = NULL;
    GNUNET_assert (size >= sizeof (struct OutboundMessage));
    mret = th->notify (th->notify_cls,
                       size - sizeof (struct OutboundMessage),
                       &cbuf[ret + sizeof (struct OutboundMessage)]);
    GNUNET_assert (mret <= size - sizeof (struct OutboundMessage));
    if (0 == mret)
    {
      GNUNET_free (th);
      continue;
    }
    if (NULL != n->unready_warn_task)
      n->unready_warn_task
        = GNUNET_SCHEDULER_add_delayed (UNREADY_WARN_TIME,
                                        &do_warn_unready,
                                        n);
    n->last_payload = GNUNET_TIME_absolute_get ();
    n->is_ready = GNUNET_NO;
    GNUNET_assert (mret + sizeof (struct OutboundMessage) <
                   GNUNET_SERVER_MAX_MESSAGE_SIZE);
    obm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND);
    obm.header.size = htons (mret + sizeof (struct OutboundMessage));
    obm.reserved = htonl (0);
    obm.timeout =
      GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining
                                 (th->timeout));
    obm.peer = n->id;
    memcpy (&cbuf[ret],
            &obm,
            sizeof (struct OutboundMessage));
    ret += (mret + sizeof (struct OutboundMessage));
    size -= (mret + sizeof (struct OutboundMessage));
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
    break;
  }
  /* if there are more pending messages, try to schedule those */
  schedule_transmission (h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting %u bytes to transport service\n",
       ret);
  return ret;
}


/**
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 *
 * @param cls transport service to schedule a transmission for
 * @param tc scheduler context
 */
static void
schedule_transmission_task (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  size_t size;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct Neighbour *n;

  h->quota_task = NULL;
  GNUNET_assert (NULL != h->client);
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
  if (NULL != h->cth)
    return;
  if (NULL != h->control_head)
  {
    size = h->control_head->notify_size;
  }
  else
  {
    n = GNUNET_CONTAINER_heap_peek (h->ready_heap);
    if (NULL == n)
      return;                   /* no pending messages */
    size = n->th->notify_size + sizeof (struct OutboundMessage);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Calling notify_transmit_ready\n");
  h->cth
    = GNUNET_CLIENT_notify_transmit_ready (h->client,
                                           size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO,
                                           &transport_notify_ready,
                                           h);
  GNUNET_assert (NULL != h->cth);
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

  GNUNET_assert (NULL != h->client);
  if (NULL != h->quota_task)
  {
    GNUNET_SCHEDULER_cancel (h->quota_task);
    h->quota_task = NULL;
  }
  if (NULL != h->control_head)
    delay = GNUNET_TIME_UNIT_ZERO;
  else if (NULL != (n = GNUNET_CONTAINER_heap_peek (h->ready_heap)))
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
 * Queue control request for transmission to the transport
 * service.
 *
 * @param h handle to the transport service
 * @param size number of bytes to be transmitted
 * @param notify function to call to get the content
 * @param notify_cls closure for @a notify
 * @return a `struct GNUNET_TRANSPORT_TransmitHandle`
 */
static struct GNUNET_TRANSPORT_TransmitHandle *
schedule_control_transmit (struct GNUNET_TRANSPORT_Handle *h,
                           size_t size,
                           GNUNET_TRANSPORT_TransmitReadyNotify notify,
                           void *notify_cls)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Control transmit of %u bytes requested\n",
       size);
  th = GNUNET_new (struct GNUNET_TRANSPORT_TransmitHandle);
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->notify_size = size;
  th->request_start = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_DLL_insert_tail (h->control_head,
                                    h->control_tail,
                                    th);
  schedule_transmission (h);
  return th;
}


/**
 * Transmit START message to service.
 *
 * @param cls unused
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
send_start (void *cls,
            size_t size,
            void *buf)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct StartMessage s;
  uint32_t options;

  if (NULL == buf)
  {
    /* Can only be shutdown, just give up */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Shutdown while trying to transmit START request.\n");
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting START request.\n");
  GNUNET_assert (size >= sizeof (struct StartMessage));
  s.header.size = htons (sizeof (struct StartMessage));
  s.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  options = 0;
  if (h->check_self)
    options |= 1;
  if (NULL != h->rec)
    options |= 2;
  s.options = htonl (options);
  s.self = h->self;
  memcpy (buf, &s, sizeof (struct StartMessage));
  GNUNET_CLIENT_receive (h->client, &demultiplexer, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (struct StartMessage);
}


/**
 * Try again to connect to transport service.
 *
 * @param cls the handle to the transport service
 * @param tc scheduler context
 */
static void
reconnect (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;

  h->reconnect_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* shutdown, just give up */
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  GNUNET_assert (NULL == h->client);
  GNUNET_assert (NULL == h->control_head);
  GNUNET_assert (NULL == h->control_tail);
  h->reconnecting = GNUNET_NO;
  h->client = GNUNET_CLIENT_connect ("transport", h->cfg);

  GNUNET_assert (NULL != h->client);
  schedule_control_transmit (h, sizeof (struct StartMessage),
                             &send_start, h);
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
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  GNUNET_assert (NULL == h->reconnect_task);
  if (NULL != h->cth)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
    h->cth = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
/*    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Client disconnect done \n");*/
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
  while ((NULL != (th = h->control_head)))
  {
    GNUNET_CONTAINER_DLL_remove (h->control_head,
                                 h->control_tail,
                                 th);
    th->notify (th->notify_cls,
                0,
                NULL);
    GNUNET_free (th);
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
 * Cancel control request for transmission to the transport service.
 *
 * @param th handle to the transport service
 * @param tth transmit handle to cancel
 */
static void
cancel_control_transmit (struct GNUNET_TRANSPORT_Handle *th,
                         struct GNUNET_TRANSPORT_TransmitHandle *tth)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling transmit of contral transmission requested\n");
  GNUNET_CONTAINER_DLL_remove (th->control_head,
                               th->control_tail,
                               tth);
  GNUNET_free (tth);
}


/**
 * Send #GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT message to the
 * service.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TryConnectHandle`
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
send_try_connect (void *cls,
                  size_t size,
                  void *buf)
{
  struct GNUNET_TRANSPORT_TryConnectHandle *tch = cls;
  struct TransportRequestConnectMessage msg;

  tch->tth = NULL;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Discarding REQUEST_CONNECT request to `%s' due to error in transport service connection.\n",
         GNUNET_i2s (&tch->pid));
    if (NULL != tch->cb)
      tch->cb (tch->cb_cls,
               GNUNET_SYSERR);
    GNUNET_TRANSPORT_try_connect_cancel (tch);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting `%s' request with respect to `%s'.\n",
       "REQUEST_CONNECT",
       GNUNET_i2s (&tch->pid));
  GNUNET_assert (size >= sizeof (struct TransportRequestConnectMessage));
  msg.header.size = htons (sizeof (struct TransportRequestConnectMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT);
  msg.reserved = htonl (0);
  msg.peer = tch->pid;
  memcpy (buf, &msg, sizeof (msg));
  if (NULL != tch->cb)
    tch->cb (tch->cb_cls, GNUNET_OK);
  GNUNET_TRANSPORT_try_connect_cancel (tch);
  return sizeof (struct TransportRequestConnectMessage);
}


/**
 * Ask the transport service to establish a connection to
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 * @param cb callback to be called when request was transmitted to transport
 *         service
 * @param cb_cls closure for the callback
 * @return a `struct GNUNET_TRANSPORT_TryConnectHandle` handle or
 *         NULL on failure (cb will not be called)
 */
struct GNUNET_TRANSPORT_TryConnectHandle *
GNUNET_TRANSPORT_try_connect (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_PeerIdentity *target,
                              GNUNET_TRANSPORT_TryConnectCallback cb,
                              void *cb_cls)
{
  struct GNUNET_TRANSPORT_TryConnectHandle *tch;

  if (NULL == handle->client)
    return NULL;
  tch = GNUNET_new (struct GNUNET_TRANSPORT_TryConnectHandle);
  tch->th = handle;
  tch->pid = *target;
  tch->cb = cb;
  tch->cb_cls = cb_cls;
  tch->tth = schedule_control_transmit (handle,
                                        sizeof (struct TransportRequestConnectMessage),
                                        &send_try_connect, tch);
  GNUNET_CONTAINER_DLL_insert (handle->tc_head,
                               handle->tc_tail,
                               tch);
  return tch;
}


/**
 * Cancel the request to transport to try a connect
 * Callback will not be called
 *
 * @param tch the handle to cancel
 */
void
GNUNET_TRANSPORT_try_connect_cancel (struct GNUNET_TRANSPORT_TryConnectHandle *tch)
{
  struct GNUNET_TRANSPORT_Handle *th;

  th = tch->th;
  if (NULL != tch->tth)
    cancel_control_transmit (th, tch->tth);
  GNUNET_CONTAINER_DLL_remove (th->tc_head,
                               th->tc_tail,
                               tch);
  GNUNET_free (tch);
}


/**
 * Send HELLO message to the service.
 *
 * @param cls the HELLO message to send
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
send_hello (void *cls,
            size_t size,
            void *buf)
{
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh = cls;
  struct GNUNET_MessageHeader *msg = ohh->msg;
  uint16_t ssize;
  struct GNUNET_SCHEDULER_TaskContext tc;

  tc.read_ready = NULL;
  tc.write_ready = NULL;
  tc.reason = GNUNET_SCHEDULER_REASON_TIMEOUT;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Timeout while trying to transmit `%s' request.\n",
         "HELLO");
    if (NULL != ohh->cont)
      ohh->cont (ohh->cls,
                 &tc);
    GNUNET_free (msg);
    GNUNET_CONTAINER_DLL_remove (ohh->th->oh_head,
                                 ohh->th->oh_tail,
                                 ohh);
    GNUNET_free (ohh);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting `%s' request.\n",
       "HELLO");
  ssize = ntohs (msg->size);
  GNUNET_assert (size >= ssize);
  memcpy (buf,
          msg,
          ssize);
  GNUNET_free (msg);
  tc.reason = GNUNET_SCHEDULER_REASON_READ_READY;
  if (NULL != ohh->cont)
    ohh->cont (ohh->cls,
               &tc);
  GNUNET_CONTAINER_DLL_remove (ohh->th->oh_head,
                               ohh->th->oh_tail,
                               ohh);
  GNUNET_free (ohh);
  return ssize;
}


/**
 * Send traffic metric message to the service.
 *
 * @param cls the message to send
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
send_metric (void *cls,
             size_t size,
             void *buf)
{
  struct TrafficMetricMessage *msg = cls;
  uint16_t ssize;

  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Timeout while trying to transmit TRAFFIC_METRIC request.\n");
    GNUNET_free (msg);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting TRAFFIC_METRIC request.\n");
  ssize = ntohs (msg->header.size);
  GNUNET_assert (size >= ssize);
  memcpy (buf, msg, ssize);
  GNUNET_free (msg);
  return ssize;
}


/**
 * Set transport metrics for a peer and a direction
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
  struct TrafficMetricMessage *msg;

  msg = GNUNET_new (struct TrafficMetricMessage);
  msg->header.size = htons (sizeof (struct TrafficMetricMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  GNUNET_ATS_properties_hton (&msg->properties,
                              prop);
  msg->delay_in = GNUNET_TIME_relative_hton (delay_in);
  msg->delay_out = GNUNET_TIME_relative_hton (delay_out);
  schedule_control_transmit (handle,
                             sizeof (struct TrafficMetricMessage),
                             &send_metric,
                             msg);
}


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent,
 * 	tc reason #GNUNET_SCHEDULER_REASON_TIMEOUT for fail
 * 	tc reasong #GNUNET_SCHEDULER_REASON_READ_READY for success
 * @param cont_cls closure for @a cont
 * @return a `struct GNUNET_TRANSPORT_OfferHelloHandle` handle or NULL on failure,
 *      in case of failure @a cont will not be called
 *
 */
struct GNUNET_TRANSPORT_OfferHelloHandle *
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_TaskCallback cont,
                              void *cont_cls)
{
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_PeerIdentity peer;
  uint16_t size;

  if (NULL == handle->client)
    return NULL;
  GNUNET_break (ntohs (hello->type) == GNUNET_MESSAGE_TYPE_HELLO);
  size = ntohs (hello->size);
  GNUNET_break (size >= sizeof (struct GNUNET_MessageHeader));
  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hello,
                           &peer))
  {
    GNUNET_break (0);
    return NULL;
  }

  msg = GNUNET_malloc (size);
  memcpy (msg, hello, size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Offering HELLO message of `%s' to transport for validation.\n",
       GNUNET_i2s (&peer));

  ohh = GNUNET_new (struct GNUNET_TRANSPORT_OfferHelloHandle);
  ohh->th = handle;
  ohh->cont = cont;
  ohh->cls = cont_cls;
  ohh->msg = msg;
  ohh->tth = schedule_control_transmit (handle,
                                        size,
                                        &send_hello,
                                        ohh);
  GNUNET_CONTAINER_DLL_insert (handle->oh_head,
                               handle->oh_tail,
                               ohh);
  return ohh;
}


/**
 * Cancel the request to transport to offer the HELLO message
 *
 * @param ohh the handle for the operation to cancel
 */
void
GNUNET_TRANSPORT_offer_hello_cancel (struct GNUNET_TRANSPORT_OfferHelloHandle *ohh)
{
  struct GNUNET_TRANSPORT_Handle *th = ohh->th;

  cancel_control_transmit (ohh->th, ohh->tth);
  GNUNET_CONTAINER_DLL_remove (th->oh_head,
                               th->oh_tail,
                               ohh);
  GNUNET_free (ohh->msg);
  GNUNET_free (ohh);
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
 * Task to call the HelloUpdateCallback of the GetHelloHandle
 *
 * @param cls the `struct GNUNET_TRANSPORT_GetHelloHandle`
 * @param tc the scheduler task context
 */
static void
call_hello_update_cb_async (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh = cls;

  GNUNET_assert (NULL != ghh->handle->my_hello);
  GNUNET_assert (NULL != ghh->notify_task);
  ghh->notify_task = NULL;
  ghh->rec (ghh->rec_cls,
            ghh->handle->my_hello);
}


/**
 * Obtain the HELLO message for this peer.  The callback given in this function
 * is never called synchronously.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for @a rec
 * @return handle to cancel the operation
 */
struct GNUNET_TRANSPORT_GetHelloHandle *
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls)
{
  struct GNUNET_TRANSPORT_GetHelloHandle *hwl;

  hwl = GNUNET_new (struct GNUNET_TRANSPORT_GetHelloHandle);
  hwl->rec = rec;
  hwl->rec_cls = rec_cls;
  hwl->handle = handle;
  GNUNET_CONTAINER_DLL_insert (handle->hwl_head,
                               handle->hwl_tail,
                               hwl);
  if (NULL != handle->my_hello)
    hwl->notify_task = GNUNET_SCHEDULER_add_now (&call_hello_update_cb_async,
                                                 hwl);
  return hwl;
}


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param ghh handle to cancel
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_GetHelloHandle *ghh)
{
  struct GNUNET_TRANSPORT_Handle *handle = ghh->handle;

  if (NULL != ghh->notify_task)
    GNUNET_SCHEDULER_cancel (ghh->notify_task);
  GNUNET_CONTAINER_DLL_remove (handle->hwl_head,
                               handle->hwl_tail,
                               ghh);
  GNUNET_free (ghh);
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
  struct GNUNET_TRANSPORT_Handle *ret;

  ret = GNUNET_new (struct GNUNET_TRANSPORT_Handle);
  if (NULL != self)
  {
    ret->self = *self;
    ret->check_self = GNUNET_YES;
  }
  ret->cfg = cfg;
  ret->cls = cls;
  ret->rec = rec;
  ret->nc_cb = nc;
  ret->nd_cb = nd;
  ret->neb_cb = neb;
  ret->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  ret->client = GNUNET_CLIENT_connect ("transport",
                                       cfg);
  if (NULL == ret->client)
  {
    GNUNET_free (ret);
    return NULL;
  }
  ret->neighbours =
    GNUNET_CONTAINER_multipeermap_create (STARTING_NEIGHBOURS_SIZE,
                                          GNUNET_YES);
  ret->ready_heap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  schedule_control_transmit (ret,
                             sizeof (struct StartMessage),
                             &send_start,
                             ret);
  return ret;
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
  GNUNET_assert (NULL == handle->tc_head);
  GNUNET_assert (NULL == handle->tc_tail);
  GNUNET_assert (NULL == handle->hwl_head);
  GNUNET_assert (NULL == handle->hwl_tail);
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
    /* use GNUNET_TRANSPORT_try_connect first, only use this function
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
