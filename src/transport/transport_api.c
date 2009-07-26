/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/transport_api.c
 * @brief library to access the low-level P2P IO service
 * @author Christian Grothoff
 *
 * TODO:
 * - set_quota with low bandwidth should cause peer
 *   disconnects (currently never does that) (MINOR)
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * After how long do we give up on transmitting a HELLO
 * to the service?
 */
#define OFFER_HELLO_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * After how long do we give automatically retry an unsuccessful
 * CONNECT request?
 */
#define CONNECT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 750)

/**
 * How long should ARM wait when starting up the
 * transport service before reporting back?
 */
#define START_SERVICE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How long should ARM wait when stopping the
 * transport service before reporting back?
 */
#define STOP_SERVICE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Entry in linked list of all of our current neighbours.
 */
struct NeighbourList
{

  /**
   * This is a linked list.
   */
  struct NeighbourList *next;

  /**
   * Active transmit handle, can be NULL.  Used to move
   * from ready to wait list on disconnect and to block
   * two transmissions to the same peer from being scheduled
   * at the same time.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *transmit_handle;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * At what time did we reset last_sent last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we sent since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_sent;

  /**
   * Quota for outbound traffic to the neighbour in bytes/ms.
   */
  uint32_t quota_out;

  /**
   * Set to GNUNET_YES if we are currently allowed to
   * transmit a message to the transport service for this
   * peer, GNUNET_NO otherwise.
   */
  int transmit_ok;

  /**
   * Set to GNUNET_YES if we have received an ACK for the
   * given peer.  Peers that receive our HELLO always respond
   * with an ACK to let us know that we are successfully
   * communicating.  Note that a PING can not be used for this
   * since PINGs are only send if a HELLO address requires
   * confirmation (and also, PINGs are not passed to the
   * transport API itself).
   */
  int received_ack;

};


/**
 * Linked list of requests from clients for our HELLO
 * that were deferred.
 */
struct HelloWaitList
{

  /**
   * This is a linked list.
   */
  struct HelloWaitList *next;

  /**
   * Reference back to our transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *handle;

  /**
   * Callback to call once we got our HELLO.
   */
  GNUNET_TRANSPORT_ReceiveCallback rec;

  /**
   * Closure for rec.
   */
  void *rec_cls;

  /**
   * When to time out (call rec with NULL).
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task (used to trigger timeout,
   * cancel if we get the HELLO in time).
   */
  GNUNET_SCHEDULER_TaskIdentifier task;


};


/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle
{

  /**
   * We keep the transmit handles that are waiting for
   * a transport-level connection in a doubly linked list.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *next;

  /**
   * We keep the transmit handles that are waiting for
   * a transport-level connection in a doubly linked list.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *prev;

  /**
   * Handle of the main transport data structure.
   */
  struct GNUNET_TRANSPORT_Handle *handle;

  /**
   * Neighbour for this handle, can be NULL if the service
   * is not yet connected to the target.
   */
  struct NeighbourList *neighbour;

  /**
   * Which peer is this transmission going to be for?  All
   * zeros if it is control-traffic to the service.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Function to call when notify_size bytes are available
   * for transmission.
   */
  GNUNET_NETWORK_TransmitReadyNotify notify;

  /**
   * Closure for notify.
   */
  void *notify_cls;

  /**
   * transmit_ready task Id.  The task is used to introduce the
   * artificial delay that may be required to maintain the bandwidth
   * limits.  Later, this will be the ID of the "transmit_timeout"
   * task which is used to signal a timeout if the transmission could
   * not be done in a timely fashion.
   */
  GNUNET_SCHEDULER_TaskIdentifier notify_delay_task;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How many bytes is our notify callback waiting for?
   */
  size_t notify_size;

  /**
   * How important is this message?
   */
  unsigned int priority;

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
   * The current HELLO message for this peer.  Updated
   * whenever transports change their addresses.
   */
  struct GNUNET_HELLO_Message *my_hello;

  /**
   * My client connection to the transport service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle to our registration with the client for notification.
   */
  struct GNUNET_NETWORK_TransmitHandle *network_handle;

  /**
   * Linked list of transmit handles that are waiting for the
   * transport to connect to the respective peer.  When we
   * receive notification that the transport connected to a
   * peer, we go over this list and check if someone has already
   * requested a transmission to the new peer; if so, we trigger
   * the next step.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *connect_wait_head;

  /**
   * Linked list of transmit handles that are waiting for the
   * transport to be ready for transmission to the respective
   * peer.  When we
   * receive notification that the transport disconnected from
   * a peer, we go over this list and move the entry back to
   * the connect_wait list.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *connect_ready_head;

  /**
   * Linked list of pending requests for our HELLO.
   */
  struct HelloWaitList *hwl_head;

  /**
   * My scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * My configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Linked list of the current neighbours of this peer.
   */
  struct NeighbourList *neighbours;

  /**
   * ID of the task trying to reconnect to the
   * service.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Do we currently have a transmission pending?
   * (schedule transmission was called but has not
   * yet succeeded)?
   */
  int transmission_scheduled;
};


static struct NeighbourList *
find_neighbour (struct GNUNET_TRANSPORT_Handle *h,
                const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourList *pos;

  pos = h->neighbours;
  while ((pos != NULL) &&
         (0 != memcmp (peer, &pos->id, sizeof (struct GNUNET_PeerIdentity))))
    pos = pos->next;
  return pos;
}


/**
 * Schedule the task to send one message from the
 * connect_ready list to the service.
 */
static void schedule_transmission (struct GNUNET_TRANSPORT_Handle *h);


/**
 * Transmit message to client...
 */
static size_t
transport_notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;
  size_t ret;
  char *cbuf;

  h->network_handle = NULL;
  h->transmission_scheduled = GNUNET_NO;
  if (buf == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Could not transmit to transport service, cancelling pending requests\n");
#endif
      th = h->connect_ready_head;
      if (th->next != NULL)
        th->next->prev = NULL;
      h->connect_ready_head = th->next;
      if (NULL != (n = th->neighbour))
        {
          GNUNET_assert (n->transmit_handle == th);
          n->transmit_handle = NULL;
        }
      GNUNET_assert (0 == th->notify (th->notify_cls, 0, NULL));
      GNUNET_free (th);
      return 0;
    } 
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ready to transmit %u bytes to transport service\n", size);
#endif
  cbuf = buf;
  ret = 0;
  h->network_handle = NULL;
  h->transmission_scheduled = GNUNET_NO;
  do
    {
      th = h->connect_ready_head;
      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  /* remove existing time out task (only applies if
	     this is not the first iteration of the loop) */
	  GNUNET_SCHEDULER_cancel (h->sched,
				   th->notify_delay_task);
	  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_assert (th->notify_size <= size);
      if (th->next != NULL)
        th->next->prev = NULL;
      h->connect_ready_head = th->next;
      if (NULL != (n = th->neighbour))
        {
          GNUNET_assert (n->transmit_handle == th);
          n->transmit_handle = NULL;
        }
      ret += th->notify (th->notify_cls, size, &cbuf[ret]);
      GNUNET_free (th);
      if (n != NULL)
        n->last_sent += ret;
      size -= ret;
    }
  while ((h->connect_ready_head != NULL) &&
         (h->connect_ready_head->notify_size <= size));
  if (h->connect_ready_head != NULL)
    schedule_transmission (h);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting %u bytes to transport service\n", ret);
#endif
  return ret;
}


/**
 * Schedule the task to send one message from the
 * connect_ready list to the service.
 */
static void
schedule_transmission (struct GNUNET_TRANSPORT_Handle *h)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  GNUNET_assert (NULL == h->network_handle);
  if (h->client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Could not yet schedule transmission: we are not yet connected to the transport service!\n");
      return; /* not yet connected */
    }
  th = h->connect_ready_head;
  if (th == NULL)
    return; /* no request pending */
  if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      /* remove existing time out task, will be integrated
	 with transmit_ready notification! */
      GNUNET_SCHEDULER_cancel (h->sched,
			       th->notify_delay_task);
      th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }
  h->transmission_scheduled = GNUNET_YES;
  h->network_handle = GNUNET_CLIENT_notify_transmit_ready (h->client,
                                                           th->notify_size,
                                                           GNUNET_TIME_absolute_get_remaining
                                                           (th->timeout),
                                                           &transport_notify_ready,
                                                           h);
  GNUNET_assert (NULL != h->network_handle);
}


/**
 * Insert the given transmit handle in the given sorted
 * doubly linked list based on timeout.
 *
 * @param head pointer to the head of the linked list
 * @param th element to insert into the list
 */
static void
insert_transmit_handle (struct GNUNET_TRANSPORT_TransmitHandle **head,
                        struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  struct GNUNET_TRANSPORT_TransmitHandle *pos;
  struct GNUNET_TRANSPORT_TransmitHandle *prev;

  pos = *head;
  prev = NULL;
  while ((pos != NULL) && (pos->timeout.value < th->timeout.value))
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    {
      th->next = *head;
      if (th->next != NULL)
        th->next->prev = th;
      *head = th;
    }
  else
    {
      th->next = pos;
      th->prev = prev;
      prev->next = th;
      if (pos != NULL)
        pos->prev = th;
    }
}


/**
 * Cancel a pending notify delay task (if pending) and also remove the
 * given transmit handle from whatever list is on.
 *
 * @param th handle for the transmission request to manipulate
 */
static void
remove_from_any_list (struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  struct GNUNET_TRANSPORT_Handle *h;

  h = th->handle;
  if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (h->sched, th->notify_delay_task);
      th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (th->prev == NULL)
    {
      if (th == h->connect_wait_head)
        h->connect_wait_head = th->next;
      else
        h->connect_ready_head = th->next;
    }
  else
    {
      th->prev->next = th->next;
    }
  if (th->next != NULL)
    th->next->prev = th->prev;
}


/**
 * Schedule a request to connect to the given
 * neighbour (and if successful, add the specified
 * handle to the wait list).
 *
 * @param th handle for a request to transmit once we
 *        have connected
 */
static void
try_connect (struct GNUNET_TRANSPORT_TransmitHandle *th);


/**
 * Called when our transmit request timed out before any transport
 * reported success connecting to the desired peer or before the
 * transport was ready to receive.  Signal error and free
 * TransmitHandle.
 */
static void
transmit_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;

  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
  if (th->neighbour != NULL)
    th->neighbour->transmit_handle = NULL;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Request for transmission to peer `%s' timed out.\n",
	      GNUNET_i2s(&th->target));
#endif
  remove_from_any_list (th);
  th->notify (th->notify_cls, 0, NULL);
  GNUNET_free (th);
}




/**
 * Queue control request for transmission to the transport
 * service.
 *
 * @param size number of bytes to be transmitted
 * @param at_head request must be added to the head of the queue
 *        (otherwise request will be appended)
 * @param timeout how long this transmission can wait (at most)
 * @param notify function to call to get the content
 * @param notify_cls closure for notify
 */
static void
schedule_control_transmit (struct GNUNET_TRANSPORT_Handle *h,
                           size_t size,
                           int at_head,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_NETWORK_TransmitReadyNotify notify,
                           void *notify_cls)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  th = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_TransmitHandle));
  th->handle = h;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  th->notify_size = size;
  th->notify_delay_task 
    = GNUNET_SCHEDULER_add_delayed (h->sched,
				    GNUNET_NO,
				    GNUNET_SCHEDULER_PRIORITY_KEEP,
				    GNUNET_SCHEDULER_NO_TASK,
				    timeout,
				    &transmit_timeout, th);    
  if (at_head)
    {
      th->next = h->connect_ready_head;
      h->connect_ready_head = th;
      if (th->next != NULL)
        th->next->prev = th;
    }
  else
    {
      insert_transmit_handle (&h->connect_ready_head, th);
    }
  if (GNUNET_NO == h->transmission_scheduled)
    schedule_transmission (h);
}


/**
 * Update the quota values for the given neighbour now.
 */
static void
update_quota (struct NeighbourList *n)
{
  struct GNUNET_TIME_Relative delta;
  uint64_t allowed;
  uint64_t remaining;

  delta = GNUNET_TIME_absolute_get_duration (n->last_quota_update);
  allowed = delta.value * n->quota_out;
  if (n->last_sent < allowed)
    {
      remaining = allowed - n->last_sent;
      if (n->quota_out > 0)
        remaining /= n->quota_out;
      else
        remaining = 0;
      if (remaining > MAX_BANDWIDTH_CARRY)
        remaining = MAX_BANDWIDTH_CARRY;
      n->last_sent = 0;
      n->last_quota_update = GNUNET_TIME_absolute_get ();
      n->last_quota_update.value -= remaining;
    }
  else
    {
      n->last_sent -= allowed;
      n->last_quota_update = GNUNET_TIME_absolute_get ();
    }
}


struct SetQuotaContext
{
  struct GNUNET_TRANSPORT_Handle *handle;

  struct GNUNET_PeerIdentity target;

  GNUNET_SCHEDULER_Task cont;

  void *cont_cls;

  struct GNUNET_TIME_Absolute timeout;

  uint32_t quota_in;
};


static size_t
send_set_quota (void *cls, size_t size, void *buf)
{
  struct SetQuotaContext *sqc = cls;
  struct QuotaSetMessage *msg;

  if (buf == NULL)
    {
      GNUNET_SCHEDULER_add_continuation (sqc->handle->sched,
                                         GNUNET_NO,
                                         sqc->cont,
                                         sqc->cont_cls,
                                         GNUNET_SCHEDULER_REASON_TIMEOUT);
      GNUNET_free (sqc);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request with respect to `%4s'.\n",
              "SET_QUOTA", GNUNET_i2s (&sqc->target));
#endif
  GNUNET_assert (size >= sizeof (struct QuotaSetMessage));
  msg = buf;
  msg->header.size = htons (sizeof (struct QuotaSetMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  msg->quota_in = htonl (sqc->quota_in);
  memcpy (&msg->peer, &sqc->target, sizeof (struct GNUNET_PeerIdentity));
  if (sqc->cont != NULL)
    GNUNET_SCHEDULER_add_continuation (sqc->handle->sched,
                                       GNUNET_NO,
                                       sqc->cont,
                                       sqc->cont_cls,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_free (sqc);
  return sizeof (struct QuotaSetMessage);
}


/**
 * Set the share of incoming bandwidth for the given
 * peer to the specified amount.
 *
 * @param handle connection to transport service
 * @param target who's bandwidth quota is being changed
 * @param quota_in incoming bandwidth quota in bytes per ms; 0 can
 *        be used to force all traffic to be discarded
 * @param quota_out outgoing bandwidth quota in bytes per ms; 0 can
 *        be used to force all traffic to be discarded
 * @param timeout how long to wait until signaling failure if
 *        we can not communicate the quota change
 * @param cont continuation to call when done, will be called
 *        either with reason "TIMEOUT" or with reason "PREREQ_DONE"
 * @param cont_cls closure for continuation
 */
void
GNUNET_TRANSPORT_set_quota (struct GNUNET_TRANSPORT_Handle *handle,
                            const struct GNUNET_PeerIdentity *target,
                            uint32_t quota_in,
                            uint32_t quota_out,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct NeighbourList *n;
  struct SetQuotaContext *sqc;

  n = find_neighbour (handle, target);
  if (n != NULL)
    {
      update_quota (n);
      if (n->quota_out < quota_out)
        n->last_quota_update = GNUNET_TIME_absolute_get ();
      n->quota_out = quota_out;
    }
  sqc = GNUNET_malloc (sizeof (struct SetQuotaContext));
  sqc->handle = handle;
  sqc->target = *target;
  sqc->cont = cont;
  sqc->cont_cls = cont_cls;
  sqc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  sqc->quota_in = quota_in;
  schedule_control_transmit (handle,
                             sizeof (struct QuotaSetMessage),
                             GNUNET_NO, timeout, &send_set_quota, sqc);
}


/**
 * A "get_hello" request has timed out.  Signal the client
 * and clean up.
 */
static void
hello_wait_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HelloWaitList *hwl = cls;
  struct HelloWaitList *pos;
  struct HelloWaitList *prev;

  hwl->task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_TIME_absolute_get_remaining (hwl->timeout).value > 0)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("First attempt to obtain `%s' from transport service failed, will try again for %llums.\n"),
		  "HELLO",
		  GNUNET_TIME_absolute_get_remaining (hwl->timeout).value);
#endif
      hwl->task = GNUNET_SCHEDULER_add_delayed (hwl->handle->sched,
                                                GNUNET_YES,
                                                GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                GNUNET_SCHEDULER_NO_TASK,
                                                GNUNET_TIME_absolute_get_remaining (hwl->timeout),
                                                &hello_wait_timeout, hwl);
      return;      
    }
  /* signal timeout */
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _("Timeout trying to obtain `%s' from transport service.\n"),
              "HELLO");
  prev = NULL;
  pos = hwl->handle->hwl_head;
  while (pos != hwl)
    {
      GNUNET_assert (pos != NULL);
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    hwl->handle->hwl_head = hwl->next;
  else
    prev->next = hwl->next;
  if (hwl->rec != NULL)
    hwl->rec (hwl->rec_cls, GNUNET_TIME_UNIT_ZERO, NULL, NULL);
  GNUNET_free (hwl);
}


/**
 * Obtain the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param timeout how long to wait for the HELLO
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_TRANSPORT_ReceiveCallback rec,
                            void *rec_cls)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct GNUNET_PeerIdentity me;
  struct HelloWaitList *hwl;

  if (handle->my_hello == NULL)
    {
      hwl = GNUNET_malloc (sizeof (struct HelloWaitList));
      hwl->next = handle->hwl_head;
      handle->hwl_head = hwl;
      hwl->handle = handle;
      hwl->rec = rec;
      hwl->rec_cls = rec_cls;
      hwl->timeout = GNUNET_TIME_relative_to_absolute (timeout);
      hwl->task = GNUNET_SCHEDULER_add_delayed (handle->sched,
                                                GNUNET_YES,
                                                GNUNET_SCHEDULER_PRIORITY_KEEP,
                                                GNUNET_SCHEDULER_NO_TASK,
                                                timeout,
                                                &hello_wait_timeout, hwl);
      return;
    }
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_key (handle->my_hello, &pk));
  GNUNET_CRYPTO_hash (&pk,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &me.hashPubKey);

  rec (rec_cls,
       GNUNET_TIME_UNIT_ZERO,
       &me, (const struct GNUNET_MessageHeader *) handle->my_hello);
}


static size_t
send_hello (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hello = cls;
  uint16_t msize;

  if (buf == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Timeout while trying to transmit `%s' request.\n",
                  "HELLO");
#endif
      GNUNET_free (hello);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request.\n", "HELLO");
#endif
  msize = ntohs (hello->size);
  GNUNET_assert (size >= msize);
  memcpy (buf, hello, msize);
  GNUNET_free (hello);
  return msize;
}


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello)
{
  struct GNUNET_MessageHeader *hc;
  uint16_t size;

  if (handle->client == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Not connected to transport service, dropping offered HELLO\n");
#endif
      return;
    }
  GNUNET_break (ntohs (hello->type) == GNUNET_MESSAGE_TYPE_HELLO);
  size = ntohs (hello->size);
  GNUNET_break (size >= sizeof (struct GNUNET_MessageHeader));
  hc = GNUNET_malloc (size);
  memcpy (hc, hello, size);
  schedule_control_transmit (handle,
                             size,
                             GNUNET_NO, OFFER_HELLO_TIMEOUT, &send_hello, hc);
}


/**
 * Function we use for handling incoming messages.
 */
static void demultiplexer (void *cls, const struct GNUNET_MessageHeader *msg);


static size_t
send_start (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *s = buf;

  if (buf == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Timeout while trying to transmit `%s' request.\n",
                  "START");
#endif
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request.\n", "START");
#endif
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  s->size = htons (sizeof (struct GNUNET_MessageHeader));
  s->type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * We're ready to transmit the request that the transport service
 * should connect to a new peer.  In addition to sending the
 * request, schedule the next phase for the transmission processing
 * that caused the connect request in the first place.
 */
static size_t
request_connect (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;
  struct TryConnectMessage *tcm;
  struct GNUNET_TRANSPORT_Handle *h;

  GNUNET_assert (th->notify_delay_task == GNUNET_SCHEDULER_NO_TASK);
  h = th->handle;
  if (buf == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to transmit `%s' request for `%4s' to service.\n",
		  "TRY_CONNECT",
		  GNUNET_i2s(&th->target));
#endif
      th->notify (th->notify_cls, 0, NULL);
      GNUNET_free (th);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' message for `%4s'.\n",
              "TRY_CONNECT", GNUNET_i2s (&th->target));
#endif
  GNUNET_assert (size >= sizeof (struct TryConnectMessage));
  tcm = buf;
  tcm->header.size = htons (sizeof (struct TryConnectMessage));
  tcm->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TRY_CONNECT);
  tcm->reserved = htonl (0);
  memcpy (&tcm->peer, &th->target, sizeof (struct GNUNET_PeerIdentity));
  th->notify_delay_task
    = GNUNET_SCHEDULER_add_delayed (h->sched,
                                    GNUNET_NO,
                                    GNUNET_SCHEDULER_PRIORITY_KEEP,
                                    GNUNET_SCHEDULER_NO_TASK,
				    GNUNET_TIME_absolute_get_remaining
				    (th->timeout),
				    &transmit_timeout, th);
  insert_transmit_handle (&h->connect_wait_head, th);
  return sizeof (struct TryConnectMessage);
}


/**
 * Schedule a request to connect to the given
 * neighbour (and if successful, add the specified
 * handle to the wait list).
 *
 * @param th handle for a request to transmit once we
 *        have connected
 */
static void
try_connect (struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  GNUNET_assert (th->notify_delay_task == GNUNET_SCHEDULER_NO_TASK);  
  schedule_control_transmit (th->handle,
                             sizeof (struct TryConnectMessage),
                             GNUNET_NO,
                             GNUNET_TIME_absolute_get_remaining (th->timeout),
                             &request_connect, th);
}


/**
 * Task for delayed attempts to reconnect to a peer.
 *
 * @param cls must be a transmit handle that determines the peer
 *        to which we will try to connect
 * @param tc scheduler information about why we were triggered (not used)
 */
static void
try_connect_task (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;  

  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
  try_connect (th);
}


/**
 * Remove neighbour from our list.  Will automatically
 * trigger a re-connect attempt if we have messages pending
 * for this peer.
 * 
 * @param h our state
 * @param peer the peer to remove
 */
static void
remove_neighbour (struct GNUNET_TRANSPORT_Handle *h,
                  const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourList *prev;
  struct NeighbourList *pos;
  struct GNUNET_TRANSPORT_TransmitHandle *th;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing neighbour `%s' from list of connected peers.\n",
	      GNUNET_i2s (peer));
#endif
  prev = NULL;
  pos = h->neighbours;
  while ((pos != NULL) &&
         (0 != memcmp (peer, 
		       &pos->id, 
		       sizeof (struct GNUNET_PeerIdentity))))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_break (0);
      return;
    }
  if (prev == NULL)
    h->neighbours = pos->next;
  else
    prev->next = pos->next;
  if (NULL != (th = pos->transmit_handle))
    {
      pos->transmit_handle = NULL;
      th->neighbour = NULL;
      remove_from_any_list (th);
      if (GNUNET_TIME_absolute_get_remaining (th->timeout).value <= CONNECT_RETRY_TIMEOUT.value)
	{
	  /* signal error */
	  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == th->notify_delay_task);
	  transmit_timeout (th, NULL);	  
	}
      else
	{
	  /* try again in a bit */
	  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == th->notify_delay_task);
	  th->notify_delay_task 
	    = GNUNET_SCHEDULER_add_delayed (h->sched,
					    GNUNET_NO,
					    GNUNET_SCHEDULER_PRIORITY_KEEP,
					    GNUNET_SCHEDULER_NO_TASK,
					    CONNECT_RETRY_TIMEOUT,
					    &try_connect_task,
					    th);
	}
    }
  if (h->nc_cb != NULL)
    h->nd_cb (h->cls, peer);
  GNUNET_free (pos);
}


/**
 * Try again to connect to transport service.
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct GNUNET_TRANSPORT_TransmitHandle *pos;
  struct NeighbourList *n;

  /* Forget about all neighbours that we used to be connected
     to */
  while (NULL != (n = h->neighbours))
    remove_neighbour (h, &n->id);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to transport service.\n");
#endif
  GNUNET_assert (h->client == NULL);
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  h->client = GNUNET_CLIENT_connect (h->sched, "transport", h->cfg);
  GNUNET_assert (h->client != NULL);
  /* make sure we don't send "START" twice,
     remove existing entry from queue (if present) */
  pos = h->connect_ready_head;
  while (pos != NULL)
    {
      if (pos->notify == &send_start)
        {
          if (pos->prev == NULL)
            h->connect_ready_head = pos->next;
          else
            pos->prev->next = pos->next;
          if (pos->next != NULL)
            pos->next->prev = pos->prev;
          GNUNET_assert (pos->neighbour == NULL);
          GNUNET_free (pos);
          break;
        }
      pos = pos->next;
    }
  schedule_control_transmit (h,
                             sizeof (struct GNUNET_MessageHeader),
                             GNUNET_YES,
                             GNUNET_TIME_UNIT_FOREVER_REL, 
			     &send_start, NULL);
  GNUNET_CLIENT_receive (h->client,
                         &demultiplexer, h, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 */
static void
schedule_reconnect (struct GNUNET_TRANSPORT_Handle *h)
{
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling task to reconnect to transport service in %llu ms.\n",
              h->reconnect_delay.value);
#endif
  GNUNET_assert (h->client == NULL);
  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->sched,
                                    GNUNET_NO,
                                    GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                    GNUNET_SCHEDULER_NO_TASK,
                                    h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_UNIT_SECONDS;
}


/**
 * We are connected to the respective peer, check the
 * bandwidth limits and schedule the transmission.
 */
static void schedule_request (struct GNUNET_TRANSPORT_TransmitHandle *th);


/**
 * Function called by the scheduler when the timeout
 * for bandwidth availablility for the target
 * neighbour is reached.
 */
static void
transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;

  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
  schedule_request (th);
}


/**
 * Remove the given transmit handle from the wait list.  Does NOT free
 * it.
 */
static void
remove_from_wait_list (struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  if (th->prev == NULL)
    th->handle->connect_wait_head = th->next;
  else
    th->prev->next = th->next;
  if (th->next != NULL)
    th->next->prev = th->prev;
}


/**
 * We are connected to the respective peer, check the
 * bandwidth limits and schedule the transmission.
 */
static void
schedule_request (struct GNUNET_TRANSPORT_TransmitHandle *th)
{
  struct GNUNET_TRANSPORT_Handle *h;
  struct GNUNET_TIME_Relative duration;
  struct NeighbourList *n;
  uint64_t available;

  h = th->handle;
  n = th->neighbour;
  if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (h->sched, th->notify_delay_task);
      th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }
  /* check outgoing quota */
  duration = GNUNET_TIME_absolute_get_duration (n->last_quota_update);
  if (duration.value > MIN_QUOTA_REFRESH_TIME)
    {
      update_quota (n);
      duration = GNUNET_TIME_absolute_get_duration (n->last_quota_update);
    }
  available = duration.value * n->quota_out;
  if (available < n->last_sent + th->notify_size)
    {
      /* calculate how much bandwidth we'd still need to
         accumulate and based on that how long we'll have
         to wait... */
      available = n->last_sent + th->notify_size - available;
      duration = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                                available / n->quota_out);
      if (th->timeout.value <
          GNUNET_TIME_relative_to_absolute (duration).value)
        {
          /* signal timeout! */
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Would need %llu ms before bandwidth is available for delivery to `%4s', that is too long.  Signaling timeout.\n",
                      duration.value,
		      GNUNET_i2s(&th->target));
#endif
          remove_from_wait_list (th);
          th->notify (th->notify_cls, 0, NULL);
          GNUNET_free (th);
          return;
        }
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Need more bandwidth, delaying delivery to `%4s' by %llu ms\n",
		  GNUNET_i2s(&th->target),
                  duration.value);
#endif
      th->notify_delay_task
        = GNUNET_SCHEDULER_add_delayed (h->sched,
                                        GNUNET_NO,
                                        GNUNET_SCHEDULER_PRIORITY_KEEP,
                                        GNUNET_SCHEDULER_NO_TASK,
                                        duration, &transmit_ready, th);
      return;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bandwidth available for transmission to `%4s'\n",
              GNUNET_i2s (&n->id));
#endif
  if (GNUNET_NO == n->transmit_ok)
    {
      /* we may be ready, but transport service is not;
         wait for SendOkMessage or timeout */
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Need to wait for transport service `%s' message\n",
                  "SEND_OK");
#endif
      th->notify_delay_task
        = GNUNET_SCHEDULER_add_delayed (h->sched,
                                        GNUNET_NO,
                                        GNUNET_SCHEDULER_PRIORITY_KEEP,
                                        GNUNET_SCHEDULER_NO_TASK,
                                        GNUNET_TIME_absolute_get_remaining
                                        (th->timeout), &transmit_timeout, th);
      return;
    }
  n->transmit_ok = GNUNET_NO;
  remove_from_wait_list (th);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Moving message for `%4s' to ready list\n",
	      GNUNET_i2s(&n->id));
#endif
  insert_transmit_handle (&h->connect_ready_head, th);
  if (GNUNET_NO == h->transmission_scheduled)
    schedule_transmission (h);
}


/**
 * Add neighbour to our list
 */
static void
add_neighbour (struct GNUNET_TRANSPORT_Handle *h,
               uint32_t quota_out,
               struct GNUNET_TIME_Relative latency,
               const struct GNUNET_PeerIdentity *pid)
{
  struct NeighbourList *n;
  struct GNUNET_TRANSPORT_TransmitHandle *prev;
  struct GNUNET_TRANSPORT_TransmitHandle *pos;
  struct GNUNET_TRANSPORT_TransmitHandle *next;

  /* check for duplicates */
  if (NULL != find_neighbour (h, pid))
    {
      GNUNET_break (0);
      return;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating entry for new neighbour `%4s'.\n", GNUNET_i2s (pid));
#endif
  n = GNUNET_malloc (sizeof (struct NeighbourList));
  n->id = *pid;
  n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->quota_out = quota_out;
  n->next = h->neighbours;
  n->transmit_ok = GNUNET_YES;
  h->neighbours = n;
  if (h->nc_cb != NULL)
    h->nc_cb (h->cls, &n->id, latency);
  prev = NULL;
  pos = h->connect_wait_head;
  while (pos != NULL)
    {
      next = pos->next;
      if (0 == memcmp (pid,
                       &pos->target, sizeof (struct GNUNET_PeerIdentity)))
        {
          pos->neighbour = n;
          GNUNET_assert (NULL == n->transmit_handle);
          n->transmit_handle = pos;
          if (prev == NULL)
            h->connect_wait_head = next;
          else
            prev->next = next;
          if (GNUNET_YES == n->received_ack)
            {
#if DEBUG_TRANSPORT
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Found pending request for `%4s' will trigger it now.\n",
			  GNUNET_i2s (&pos->target));
#endif
	      if (pos->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
		{
		  GNUNET_SCHEDULER_cancel (h->sched, pos->notify_delay_task);
		  pos->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
		}
              schedule_request (pos);
            }
          else
            {
#if DEBUG_TRANSPORT
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Found pending request for `%4s' but still need `%s' before proceeding.\n",
			  GNUNET_i2s (&pos->target),
			  "ACK");
#endif
            }
          break;
        }
      prev = pos;
      pos = next;
    }
}


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *

 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param dc function to call on disconnect events
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect (struct GNUNET_SCHEDULER_Handle *sched,
                          const struct GNUNET_CONFIGURATION_Handle *cfg,
                          void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd)
{
  struct GNUNET_TRANSPORT_Handle *ret;

  GNUNET_ARM_start_service ("peerinfo",
                            cfg, sched, START_SERVICE_TIMEOUT, NULL, NULL);
  GNUNET_ARM_start_service ("transport",
                            cfg, sched, START_SERVICE_TIMEOUT, NULL, NULL);
  ret = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_Handle));
  ret->sched = sched;
  ret->cfg = cfg;
  ret->cls = cls;
  ret->rec = rec;
  ret->nc_cb = nc;
  ret->nd_cb = nd;
  ret->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  schedule_reconnect (ret);
  return ret;
}


/**
 * These stop activities must be run in a fresh
 * scheduler that is NOT in shutdown mode.
 */
static void
stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_Handle *handle = cls;
  GNUNET_ARM_stop_service ("transport",
                           handle->cfg,
                           tc->sched, STOP_SERVICE_TIMEOUT, NULL, NULL);
  GNUNET_ARM_stop_service ("peerinfo",
                           handle->cfg,
                           tc->sched, STOP_SERVICE_TIMEOUT, NULL, NULL);
}


/**
 * Disconnect from the transport service.
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;
  struct HelloWaitList *hwl;
  struct GNUNET_CLIENT_Connection *client;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transport disconnect called!\n");
#endif
  while (NULL != (th = handle->connect_ready_head))
    {
      handle->connect_ready_head = th->next;
      th->notify (th->notify_cls, 0, NULL);
      GNUNET_free (th);
    }
  while (NULL != (th = handle->connect_wait_head))
    {
      handle->connect_wait_head = th->next;
      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (handle->sched, th->notify_delay_task);
          th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      th->notify (th->notify_cls, 0, NULL);
      GNUNET_free (th);
    }
  while (NULL != (n = handle->neighbours))
    {
      handle->neighbours = n->next;
      GNUNET_free (n);
    }
  while (NULL != (hwl = handle->hwl_head))
    {
      handle->hwl_head = hwl->next;
      GNUNET_SCHEDULER_cancel (handle->sched, hwl->task);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Disconnect while trying to obtain `%s' from transport service.\n"),
		  "HELLO");
      if (hwl->rec != NULL)
        hwl->rec (hwl->rec_cls, GNUNET_TIME_UNIT_ZERO, NULL, NULL);
      GNUNET_free (hwl);
    }
  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->sched, handle->reconnect_task);
      handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_free_non_null (handle->my_hello);
  handle->my_hello = NULL;
  GNUNET_SCHEDULER_run (&stop_task, handle);
  if (NULL != (client = handle->client))
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Disconnecting from transport service for good.\n");
#endif
      handle->client = NULL;
      GNUNET_CLIENT_disconnect (client);
    }
  if (client == NULL)
    GNUNET_free (handle);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
demultiplexer (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  const struct DisconnectInfoMessage *dim;
  const struct ConnectInfoMessage *cim;
  const struct InboundMessage *im;
  const struct GNUNET_MessageHeader *imm;
  const struct SendOkMessage *okm;
  struct HelloWaitList *hwl;
  struct NeighbourList *n;
  struct GNUNET_PeerIdentity me;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  uint16_t size;

  if ((msg == NULL) || (h->client == NULL))
    {
      if (h->client != NULL)
        {
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Error receiving from transport service, disconnecting temporarily.\n");
#endif
          if (h->network_handle != NULL)
            {
              GNUNET_NETWORK_notify_transmit_ready_cancel (h->network_handle);
              h->network_handle = NULL;
              h->transmission_scheduled = GNUNET_NO;
	      th = h->connect_ready_head;
	      /* add timeout again, we cancelled the transmit_ready task! */
	      GNUNET_assert (th->notify_delay_task == GNUNET_SCHEDULER_NO_TASK);
	      th->notify_delay_task 
		= GNUNET_SCHEDULER_add_delayed (h->sched,
						GNUNET_NO,
						GNUNET_SCHEDULER_PRIORITY_KEEP,
						GNUNET_SCHEDULER_NO_TASK,
						GNUNET_TIME_absolute_get_remaining(th->timeout),
						&transmit_timeout, 
						th);    
            }
          GNUNET_CLIENT_disconnect (h->client);
          h->client = NULL;
          schedule_reconnect (h);
        }
      else
        {
          /* shutdown initiated from 'GNUNET_TRANSPORT_disconnect',
             finish clean up work! */
          GNUNET_free (h);
        }
      return;
    }
  GNUNET_CLIENT_receive (h->client,
                         &demultiplexer, h, GNUNET_TIME_UNIT_FOREVER_REL);
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
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving (my own) `%s' message, I am `%4s'.\n",
                  "HELLO", GNUNET_i2s (&me));
#endif
      GNUNET_free_non_null (h->my_hello);
      h->my_hello = NULL;
      if (size < sizeof (struct GNUNET_MessageHeader))
        {
          GNUNET_break (0);
          break;
        }
      h->my_hello = GNUNET_malloc (size);
      memcpy (h->my_hello, msg, size);
      while (NULL != (hwl = h->hwl_head))
        {
          h->hwl_head = hwl->next;
          GNUNET_SCHEDULER_cancel (h->sched, hwl->task);
          GNUNET_TRANSPORT_get_hello (h,
                                      GNUNET_TIME_UNIT_ZERO,
                                      hwl->rec, hwl->rec_cls);
          GNUNET_free (hwl);
        }
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT:
      if (size != sizeof (struct ConnectInfoMessage))
        {
          GNUNET_break (0);
          break;
        }
      cim = (const struct ConnectInfoMessage *) msg;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message for `%4s'.\n",
                  "CONNECT", GNUNET_i2s (&cim->id));
#endif
      add_neighbour (h,
                     ntohl (cim->quota_out),
                     GNUNET_TIME_relative_ntoh (cim->latency), &cim->id);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT:
      if (size != sizeof (struct DisconnectInfoMessage))
        {
          GNUNET_break (0);
          break;
        }
      dim = (const struct DisconnectInfoMessage *) msg;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message for `%4s'.\n",
                  "DISCONNECT", GNUNET_i2s (&dim->peer));
#endif
      remove_neighbour (h, &dim->peer);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK:
      if (size != sizeof (struct SendOkMessage))
        {
          GNUNET_break (0);
          break;
        }
      okm = (const struct SendOkMessage *) msg;
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message, transmission %s.\n", "SEND_OK",
		  ntohl(okm->success) == GNUNET_OK ? "succeeded" : "failed");
#endif
      n = find_neighbour (h, &okm->peer);
      GNUNET_assert (n != NULL);
      n->transmit_ok = GNUNET_YES;
      if (n->transmit_handle != NULL)
        {
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Processing pending message for `%4s'\n",
		      GNUNET_i2s(&n->id));
#endif
          GNUNET_SCHEDULER_cancel (h->sched,
                                   n->transmit_handle->notify_delay_task);
          n->transmit_handle->notify_delay_task =
            GNUNET_SCHEDULER_NO_TASK;
          GNUNET_assert (GNUNET_YES == n->received_ack);
          schedule_request (n->transmit_handle);
        }
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_RECV:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message.\n", "RECV");
#endif
      if (size <
          sizeof (struct InboundMessage) +
          sizeof (struct GNUNET_MessageHeader))
        {
          GNUNET_break (0);
          break;
        }
      im = (const struct InboundMessage *) msg;
      imm = (const struct GNUNET_MessageHeader *) &im[1];
      if (ntohs (imm->size) + sizeof (struct InboundMessage) != size)
        {
          GNUNET_break (0);
          break;
        }
      switch (ntohs (imm->type))
        {
        case GNUNET_MESSAGE_TYPE_TRANSPORT_ACK:
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Receiving `%s' message from `%4s'.\n",
                      "ACK", GNUNET_i2s (&im->peer));
#endif
          n = find_neighbour (h, &im->peer);
          if (n == NULL)
            {
              GNUNET_break (0);
              break;
            }
          if (n->received_ack == GNUNET_NO)
            {
              n->received_ack = GNUNET_YES;
              if (NULL != n->transmit_handle)
                {
#if DEBUG_TRANSPORT
                  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                              "Peer connected, scheduling delayed message for deliverery now.\n");
#endif
                  schedule_request (n->transmit_handle);
                }
            }
          break;
        default:
#if DEBUG_TRANSPORT
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Received message of type %u from `%4s'.\n",
                      ntohs (imm->type), GNUNET_i2s (&im->peer));
#endif
          if (h->rec != NULL)
            h->rec (h->cls,
                    GNUNET_TIME_relative_ntoh (im->latency), &im->peer, imm);
          break;
        }
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Received unexpected message of type %u in %s:%u\n"),
                  ntohs (msg->type), __FILE__, __LINE__);
      GNUNET_break (0);
      break;
    }
}


struct ClientTransmitWrapper
{
  GNUNET_NETWORK_TransmitReadyNotify notify;
  void *notify_cls;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
};


/**
 * Transmit message of a client destined for another
 * peer to the service.
 */
static size_t
client_notify_wrapper (void *cls, size_t size, void *buf)
{
  struct ClientTransmitWrapper *ctw = cls;
  struct OutboundMessage *obm;
  struct GNUNET_MessageHeader *hdr;
  size_t ret;

  if (size == 0)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmission request could not be satisfied.\n");
#endif
      ret = ctw->notify (ctw->notify_cls, 0, NULL);
      GNUNET_assert (ret == 0);
      GNUNET_free (ctw);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct OutboundMessage));
  obm = buf;
  ret = ctw->notify (ctw->notify_cls,
                     size - sizeof (struct OutboundMessage),
                     (void *) &obm[1]);
  if (ret == 0)
    {
      /* Need to reset flag, no SEND means no SEND_OK! */
      ctw->th->neighbour->transmit_ok = GNUNET_YES;
      GNUNET_free (ctw);
      return 0;
    }
  GNUNET_assert (ret >= sizeof (struct GNUNET_MessageHeader));
  hdr = (struct GNUNET_MessageHeader *) &obm[1];
  GNUNET_assert (ntohs (hdr->size) == ret);
  GNUNET_assert (ret + sizeof (struct OutboundMessage) <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' message with data for `%4s'\n",
              "SEND", GNUNET_i2s (&ctw->th->target));
#endif
  ret += sizeof (struct OutboundMessage);
  obm->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND);
  obm->header.size = htons (ret);
  obm->priority = htonl (ctw->th->priority);
  obm->peer = ctw->th->target;
  GNUNET_free (ctw);
  return ret;
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
 * @param priority how important is the message?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using GNUNET_TRANSPORT_notify_transmit_ready_cancel)
 */
struct GNUNET_TRANSPORT_TransmitHandle *
GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle
                                        *handle,
                                        const struct GNUNET_PeerIdentity
                                        *target, size_t size,
					unsigned int priority,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_NETWORK_TransmitReadyNotify
                                        notify, void *notify_cls)
{
  struct GNUNET_TRANSPORT_TransmitHandle *pos;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;
  struct ClientTransmitWrapper *ctw;

  if (size + sizeof (struct OutboundMessage) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return NULL;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport service for transmission of %u bytes to peer `%4s'.\n",
              size, GNUNET_i2s (target));
#endif
  n = find_neighbour (handle, target);
  if ( (n != NULL) &&
       (n->transmit_handle != NULL) )
    return NULL; /* already have a request pending for this peer! */
  ctw = GNUNET_malloc (sizeof (struct ClientTransmitWrapper));
  th = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_TransmitHandle));
  ctw->notify = notify;
  ctw->notify_cls = notify_cls;
  ctw->th = th;
  th->handle = handle;
  th->neighbour = n;
  th->target = *target;
  th->notify = &client_notify_wrapper;
  th->notify_cls = ctw;
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  th->notify_size = size + sizeof (struct OutboundMessage);
  th->priority = priority;
  if (NULL == n)
    {
      pos = handle->connect_wait_head;
      while (pos != NULL)
        {
          GNUNET_assert (0 != memcmp (target,
                                      &pos->target,
                                      sizeof (struct GNUNET_PeerIdentity)));
          pos = pos->next;
        }
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Will now try to connect to `%4s'.\n", GNUNET_i2s (target));
#endif
      try_connect (th);
      return th;
    }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmission request queued for transmission to transport service.\n");
#endif
  GNUNET_assert (NULL == n->transmit_handle);
  n->transmit_handle = th;
  if (GNUNET_YES != n->received_ack)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%4s' is not yet confirmed connected, scheduling timeout (%llu ms) only.\n",
		  GNUNET_i2s (target), timeout.value);
#endif
      th->notify_delay_task
	= GNUNET_SCHEDULER_add_delayed (handle->sched,
					GNUNET_NO,
					GNUNET_SCHEDULER_PRIORITY_KEEP,
					GNUNET_SCHEDULER_NO_TASK,
					timeout, &transmit_timeout, th);
      return th;
    }
  
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peer `%4s' is ready to receive, scheduling message for delivery now.\n",
	      GNUNET_i2s (target));
#endif
  schedule_request (th);
  return th;
}


/**
 * Cancel the specified transmission-ready
 * notification.
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *th)
{
  struct GNUNET_TRANSPORT_Handle *h;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmission request of %u bytes to `%4s' was cancelled.\n",
	      th->notify_size - sizeof(struct OutboundMessage),
	      GNUNET_i2s (&th->target));
#endif
  GNUNET_assert (th->notify == &client_notify_wrapper);
  remove_from_any_list (th);
  h = th->handle;
  if ((h->connect_ready_head == NULL) && (h->network_handle != NULL))
    {
      GNUNET_NETWORK_notify_transmit_ready_cancel (h->network_handle);
      h->network_handle = NULL;
      h->transmission_scheduled = GNUNET_NO;
    }
  GNUNET_free (th->notify_cls);
  GNUNET_free (th);
}


/* end of transport_api.c */
