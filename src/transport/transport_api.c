/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
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
 * After how long do we automatically retry an unsuccessful
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
 * What stage are we in for transmission processing?
 */
enum TransmitStage
  {
    /**
     * No active message.
     */
    TS_NEW = 0,

    /**
     * Message in local queue, not given to service.
     */
    TS_QUEUED = 1,

    /**
     * Message given to service, not confirmed (no SEND_OK).
     */
    TS_TRANSMITTED = 2,

    /**
     * One message was given to service and before it was confirmed,
     * another one was already queued (waiting for SEND_OK to pass on
     * to service).
     */
    TS_TRANSMITTED_QUEUED = 3
  };


/**
 * Handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle
{

  /**
   * Neighbour for this handle, NULL for control-traffic.
   */
  struct NeighbourList *neighbour;

  /**
   * Function to call when notify_size bytes are available
   * for transmission.
   */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

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
 * Handle for a control message queue entry.
 */
struct ControlMessage
{

  /**
   * This is a doubly-linked list.
   */
  struct ControlMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct ControlMessage *prev;

  /**
   * Overall transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *h;

  /**
   * Function to call when notify_size bytes are available
   * for transmission.
   */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

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
   * How many bytes is our notify callback waiting for?
   */
  size_t notify_size;

};


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
   * Overall transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *h;

  /**
   * Active transmit handle; available if 'transmit_forbidden'
   * is GNUNET_NO.
   */
  struct GNUNET_TRANSPORT_TransmitHandle transmit_handle;

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
   * Set to GNUNET_NO if we are currently allowed to accept a
   * message to the transport service for this peer, GNUNET_YES
   * if we have one and are waiting for transmission, GNUNET_SYSERR
   * if we are waiting for confirmation AND have already accepted
   * yet another message.
   */
  enum TransmitStage transmit_stage;

  /**
   * Have we received a notification that this peer is connected
   * to us right now?
   */
  int is_connected;

};


/**
 * Linked list of requests from clients for our HELLO that were
 * deferred.
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
  GNUNET_TRANSPORT_HelloUpdateCallback rec;

  /**
   * Closure for rec.
   */
  void *rec_cls;

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
   * Head of DLL of control messages.
   */
  struct ControlMessage *control_head;

  /**
   * Tail of DLL of control messages.
   */
  struct ControlMessage *control_tail;

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
  struct GNUNET_CLIENT_TransmitHandle *network_handle;

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
   * ID of the task trying to reconnect to the service.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * ID of the task trying to trigger transmission for a peer
   * while maintaining bandwidth quotas.
   */
  GNUNET_SCHEDULER_TaskIdentifier quota_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

};


// FIXME: replace with hash map!
/**
 * Get the neighbour list entry for the given peer
 *
 * @param h our context
 * @param peer peer to look up
 * @return NULL if no such peer entry exists
 */
static struct NeighbourList *
neighbour_find (struct GNUNET_TRANSPORT_Handle *h,
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
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 */
static void schedule_transmission (struct GNUNET_TRANSPORT_Handle *h);


/**
 * Function called by the scheduler when the timeout for bandwidth
 * availablility for the target neighbour is reached.
 *
 * @param cls the 'struct GNUNET_TRANSPORT_Handle*'
 * @param tc scheduler context
 */
static void
quota_transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;

  h->quota_task = GNUNET_SCHEDULER_NO_TASK;
  schedule_transmission (h);
}


/**
 * Update the quota values for the given neighbour now.
 *
 * @param n neighbour to update
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


/**
 * Figure out which transmission to a peer can be done right now.
 * If none can, schedule a task to call 'schedule_transmission'
 * whenever a peer transmission can be done in the future and
 * return NULL.  Otherwise return the next transmission to be
 * performed.
 *
 * @param h handle to transport
 * @return NULL to wait longer before doing any peer transmissions
 */
static struct GNUNET_TRANSPORT_TransmitHandle *
schedule_peer_transmission (struct GNUNET_TRANSPORT_Handle *h)
{
  struct GNUNET_TRANSPORT_TransmitHandle *ret;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;
  struct NeighbourList *next;
  struct GNUNET_TIME_Relative retry_time;
  struct GNUNET_TIME_Relative duration;
  uint64_t available;

  if (h->quota_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (h->sched,
			       h->quota_task);
      h->quota_task = GNUNET_SCHEDULER_NO_TASK;
    }
  retry_time = GNUNET_TIME_UNIT_FOREVER_REL;
  ret = NULL;
  next = h->neighbours;
  while (NULL != (n = next))
    {
      next = n->next;
      if (n->transmit_stage != TS_QUEUED)
	continue; /* not eligible */
      th = &n->transmit_handle;
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
	  if (duration.value == 0)
	    duration = GNUNET_TIME_UNIT_MILLISECONDS;
	  if (th->timeout.value <
	      GNUNET_TIME_relative_to_absolute (duration).value)
	    {
	      /* signal timeout! */
#if DEBUG_TRANSPORT
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Would need %llu ms before bandwidth is available for delivery to `%4s', that is too long.  Signaling timeout.\n",
			  duration.value, GNUNET_i2s (&n->id));
#endif
	      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
		{
		  GNUNET_SCHEDULER_cancel (h->sched, th->notify_delay_task);
		  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
		}	      
	      n->transmit_stage = TS_NEW;
	      if (NULL != th->notify)
		GNUNET_assert (0 == th->notify (th->notify_cls, 0, NULL));
	      continue;
	    }
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Need more bandwidth, delaying delivery to `%4s' by %llu ms\n",
		      GNUNET_i2s (&n->id), duration.value);
#endif
	  retry_time = GNUNET_TIME_relative_min (retry_time,
						 duration);
	  continue;
	}
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Bandwidth available for transmission to `%4s'\n",
		  GNUNET_i2s (&n->id));
#endif
      if ( (ret == NULL) ||
	   (ret->priority < th->priority) )
	ret = th;
    }
  if (ret == NULL)
    h->quota_task = GNUNET_SCHEDULER_add_delayed (h->sched,
						  retry_time,
						  &quota_transmit_ready,
						  h);
  return ret;
}


/**
 * Transmit message(s) to service.
 *
 * @param cls handle to transport 
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
transport_notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct ControlMessage *cm;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;
  struct OutboundMessage obm;
  size_t ret;
  size_t mret;
  char *cbuf;

  h->network_handle = NULL;
  if (buf == NULL)
    {
      schedule_transmission (h);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ready to transmit %u bytes to transport service\n", size);
#endif
  cbuf = buf;
  ret = 0;
  while ( (NULL != (cm = h->control_head)) &&
	  (cm->notify_size <= size) )
    {
      if (cm->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (h->sched, cm->notify_delay_task);
          cm->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      GNUNET_CONTAINER_DLL_remove (h->control_head,
				   h->control_tail,
				   cm);
      ret += cm->notify (cm->notify_cls, size, &cbuf[ret]);
      GNUNET_free (cm);
      size -= ret;
    }
  while ( (NULL != (th = schedule_peer_transmission (h))) &&
	  (th->notify_size <= size) )
    {
      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (h->sched, th->notify_delay_task);
          th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      n = th->neighbour;
      switch (n->transmit_stage)
	{
	case TS_NEW:
	  GNUNET_break (0);
	  break;
	case TS_QUEUED:
	  n->transmit_stage = TS_TRANSMITTED;
	  break;
	case TS_TRANSMITTED:
	  GNUNET_break (0);
	  break;
	case TS_TRANSMITTED_QUEUED:
	  GNUNET_break (0);
	  break;
	default:
	  GNUNET_break (0);
	}
      GNUNET_assert (size >= sizeof (struct OutboundMessage));
      mret = th->notify (th->notify_cls, 
			 size - sizeof (struct OutboundMessage),
			 &cbuf[ret + sizeof (struct OutboundMessage)]);
      GNUNET_assert (mret <= size - sizeof (struct OutboundMessage));
      if (mret != 0)	
	{
	  obm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND);
	  obm.header.size = htons (mret + sizeof (struct OutboundMessage));
	  obm.priority = htonl (th->priority);
	  obm.timeout = GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining (th->timeout));
	  obm.peer = n->id;
	  memcpy (&cbuf[ret], &obm, sizeof (struct OutboundMessage));
	  ret += (mret + sizeof (struct OutboundMessage));
	  size -= (mret + sizeof (struct OutboundMessage));
	}
      else
	{
	  switch (n->transmit_stage)
	    {
	    case TS_NEW:
	      GNUNET_break (0);
	      break;
	    case TS_QUEUED:
	      GNUNET_break (0);
	      break;
	    case TS_TRANSMITTED:
	      n->transmit_stage = TS_NEW;
	      break;
	    case TS_TRANSMITTED_QUEUED:
	      GNUNET_break (0);
	      break;
	    default:
	      GNUNET_break (0);
	    }
	}
    }
  schedule_transmission (h);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting %u bytes to transport service\n", ret);
#endif
  return ret;
}


/**
 * Schedule the task to send one message, either from the control
 * list or the peer message queues  to the service.
 */
static void
schedule_transmission (struct GNUNET_TRANSPORT_Handle *h)
{  
  size_t size;
  struct GNUNET_TIME_Relative timeout;
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  if (NULL != h->network_handle)
    return;
  if (h->client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Could not yet schedule transmission: we are not yet connected to the transport service!\n");
      return;                   /* not yet connected */
    }
  if (NULL != h->control_head) 
    {
      size = h->control_head->notify_size;
      timeout = GNUNET_TIME_UNIT_FOREVER_REL;
    }
  else
    {
      th = schedule_peer_transmission (h);
      if (th == NULL)
	{
	  /* no transmission ready right now */
	  return;
	}
      size = th->notify_size;
      timeout = GNUNET_TIME_absolute_get_remaining (th->timeout);
    }
  h->network_handle = 
    GNUNET_CLIENT_notify_transmit_ready (h->client,
					 size,
					 timeout,
					 GNUNET_NO,
					 &transport_notify_ready,
					 h);
  GNUNET_assert (NULL != h->network_handle);
}


/**
 * Called when our transmit request timed out before any transport
 * reported success connecting to the desired peer or before the
 * transport was ready to receive.  Signal error and free
 * TransmitHandle.
 */
static void
control_transmit_timeout (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ControlMessage *th = cls;

  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != th->notify)
    th->notify (th->notify_cls, 0, NULL);
  GNUNET_CONTAINER_DLL_remove (th->h->control_head,
			       th->h->control_tail,
			       th);
  GNUNET_free (th);
}


/**
 * Queue control request for transmission to the transport
 * service.
 *
 * @param h handle to the transport service
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
                           GNUNET_CONNECTION_TransmitReadyNotify notify,
                           void *notify_cls)
{
  struct ControlMessage *th;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Control transmit of %u bytes within %llums requested\n",
              size, (unsigned long long) timeout.value);
#endif
  th = GNUNET_malloc (sizeof (struct ControlMessage));
  th->h = h;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->notify_size = size;
  th->notify_delay_task
    = GNUNET_SCHEDULER_add_delayed (h->sched,
                                    timeout, &control_transmit_timeout, th);
  if (at_head)    
    GNUNET_CONTAINER_DLL_insert (h->control_head,
				 h->control_tail,
				 th);
  else
    GNUNET_CONTAINER_DLL_insert_after (h->control_head,
				       h->control_tail,
				       h->control_tail,
				       th);
  schedule_transmission (h);
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


/**
 * Send SET_QUOTA message to the service.
 *
 * @param cls the 'struct SetQuotaContext'
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_set_quota (void *cls, size_t size, void *buf)
{
  struct SetQuotaContext *sqc = cls;
  struct QuotaSetMessage *msg;

  if (buf == NULL)
    {
      GNUNET_SCHEDULER_add_continuation (sqc->handle->sched,
                                         sqc->cont,
                                         sqc->cont_cls,
                                         GNUNET_SCHEDULER_REASON_TIMEOUT);
      GNUNET_free (sqc);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request with respect to `%4s'.\n",
              "SET_QUOTA", 
	      GNUNET_i2s (&sqc->target));
#endif
  GNUNET_assert (size >= sizeof (struct QuotaSetMessage));
  msg = buf;
  msg->header.size = htons (sizeof (struct QuotaSetMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  msg->quota_in = htonl (sqc->quota_in);
  memcpy (&msg->peer, &sqc->target, sizeof (struct GNUNET_PeerIdentity));
  if (sqc->cont != NULL)
    GNUNET_SCHEDULER_add_continuation (sqc->handle->sched,
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
 * @param quota_in incoming bandwidth quota in bytes per ms
 * @param quota_out outgoing bandwidth quota in bytes per ms
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

  n = neighbour_find (handle, target);
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
 * Obtain the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls)
{
  struct HelloWaitList *hwl;

  hwl = GNUNET_malloc (sizeof (struct HelloWaitList));
  hwl->next = handle->hwl_head;
  handle->hwl_head = hwl;
  hwl->handle = handle;
  hwl->rec = rec;
  hwl->rec_cls = rec_cls;
  if (handle->my_hello == NULL)
    return;    
  rec (rec_cls, (const struct GNUNET_MessageHeader *) handle->my_hello);
}



/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param handle connection to transport service
 * @param rec function previously registered to be called with the HELLOs
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_Handle *handle,
				   GNUNET_TRANSPORT_HelloUpdateCallback rec,
				   void *rec_cls)
{
  struct HelloWaitList *pos;
  struct HelloWaitList *prev;

  prev = NULL;
  pos = handle->hwl_head;
  while (pos != NULL)
    {
      if ( (pos->rec == rec) &&
	   (pos->rec_cls == rec_cls) )
	break;
      prev = pos;
      pos = pos->next;
    }
  GNUNET_break (pos != NULL);
  if (pos == NULL)
    return;
  if (prev == NULL)
    handle->hwl_head = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos);
}


/**
 * Send HELLO message to the service.
 *
 * @param cls the HELLO message to send
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
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
 * Transmit START message to service.
 *
 * @param cls unused
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_start (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *s = buf;

  if (buf == NULL)
    {
      /* Can only be shutdown, just give up */
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Shutdown while trying to transmit `%s' request.\n",
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
 * Free neighbour. 
 * 
 * @param n the entry to free
 */
static void
neighbour_free (struct NeighbourList *n)
{
  struct GNUNET_TRANSPORT_Handle *h;
  struct NeighbourList *prev;
  struct NeighbourList *pos;

  h = n->h;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing neighbour `%s' from list of connected peers.\n",
              GNUNET_i2s (&n->id));
#endif
  GNUNET_break (n->is_connected == GNUNET_NO);
  GNUNET_break (n->transmit_stage == TS_NEW);

  prev = NULL;
  pos = h->neighbours;
  while (pos != n)
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    h->neighbours = n->next;
  else
    prev->next = n->next;
  GNUNET_free (n);
}


/**
 * Mark neighbour as disconnected. 
 * 
 * @param n the entry to mark as disconnected
 */
static void
neighbour_disconnect (struct NeighbourList *n)
{
  struct GNUNET_TRANSPORT_Handle *h = n->h;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing neighbour `%s' from list of connected peers.\n",
              GNUNET_i2s (&n->id));
#endif
  GNUNET_break (n->is_connected == GNUNET_YES);
  n->is_connected = GNUNET_NO;
  if (h->nc_cb != NULL)
    h->nd_cb (h->cls, &n->id);
  if (n->transmit_stage == TS_NEW)
    neighbour_free (n);
}


/**
 * Function we use for handling incoming messages.
 *
 * @param cls closure (struct GNUNET_TRANSPORT_Handle *)
 * @param msg message received, NULL on timeout or fatal error
 */
static void demultiplexer (void *cls, 
			   const struct GNUNET_MessageHeader *msg);


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
  struct ControlMessage *pos;
  struct NeighbourList *n;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    {
      /* shutdown, just give up */
      return;
    }
  /* Forget about all neighbours that we used to be connected to */
  n = h->neighbours;
  while (NULL != n)
    {
      if (n->is_connected)
	neighbour_disconnect (n);
      n = n->next;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to transport service.\n");
#endif
  GNUNET_assert (h->client == NULL);
  h->client = GNUNET_CLIENT_connect (h->sched, "transport", h->cfg);
  GNUNET_assert (h->client != NULL);
  /* make sure we don't send "START" twice, remove existing entry from
     queue (if present) */
  pos = h->control_head;
  while (pos != NULL)
    {
      if (pos->notify == &send_start)
        {
	  GNUNET_CONTAINER_DLL_remove (h->control_head,
				       h->control_tail,
				       pos);
          if (GNUNET_SCHEDULER_NO_TASK != pos->notify_delay_task)
            {
              GNUNET_SCHEDULER_cancel (h->sched, pos->notify_delay_task);
              pos->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
            }
          GNUNET_free (pos);
          break;
        }
      pos = pos->next;
    }
  schedule_control_transmit (h,
                             sizeof (struct GNUNET_MessageHeader),
                             GNUNET_YES,
                             GNUNET_TIME_UNIT_FOREVER_REL, &send_start, NULL);
  GNUNET_CLIENT_receive (h->client,
                         &demultiplexer, h, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
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
                                    h->reconnect_delay, &reconnect, h);
  if (h->reconnect_delay.value == 0)
    {
      h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
    }
  else 
    {
      h->reconnect_delay = GNUNET_TIME_relative_multiply (h->reconnect_delay, 2);
      h->reconnect_delay = GNUNET_TIME_relative_min (GNUNET_TIME_UNIT_SECONDS,
						     h->reconnect_delay);
    }
}


/**
 * Add neighbour to our list
 */
static struct NeighbourList *
neighbour_add (struct GNUNET_TRANSPORT_Handle *h,
               const struct GNUNET_PeerIdentity *pid)
{
  struct NeighbourList *n;

  /* check for duplicates */
  if (NULL != (n = neighbour_find (h, pid)))
    {
      GNUNET_break (0);
      return n;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating entry for neighbour `%4s'.\n", 
	      GNUNET_i2s (pid));
#endif
  n = GNUNET_malloc (sizeof (struct NeighbourList));
  n->id = *pid;
  n->last_quota_update = GNUNET_TIME_absolute_get ();
  n->next = h->neighbours;
  n->quota_out = GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT;
  n->h = h;
  h->neighbours = n;  
  return n;
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
 * @param nd function to call on disconnect events
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

  GNUNET_ARM_start_services (cfg, sched, "peerinfo", "transport", NULL);
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
  while (NULL != (n = handle->neighbours))
    {
      handle->neighbours = n->next;
      switch (n->transmit_stage)
	{
	case TS_NEW:
	case TS_TRANSMITTED:
	  /* nothing to do */
	  break;
	case TS_QUEUED:
	case TS_TRANSMITTED_QUEUED:
	  th = &n->transmit_handle;
	  if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
	    {
	      GNUNET_SCHEDULER_cancel (handle->sched,
				       th->notify_delay_task);
	      th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
	    }
	  GNUNET_assert (0 == th->notify (th->notify_cls, 0, NULL));        
	  break;
	default:
	  GNUNET_break (0);
	}
      GNUNET_free (n);
    }
  while (NULL != (hwl = handle->hwl_head))
    {
      handle->hwl_head = hwl->next;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Disconnect while notification for `%s' still registered.\n"),
                  "HELLO");
      if (hwl->rec != NULL)
        hwl->rec (hwl->rec_cls, NULL);
      GNUNET_free (hwl);
    }
  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->sched, handle->reconnect_task);
      handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (handle->quota_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->sched, handle->quota_task);
      handle->quota_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_free_non_null (handle->my_hello);
  handle->my_hello = NULL;
  GNUNET_ARM_stop_services (handle->cfg, handle->sched, "transport",
                            "peerinfo", NULL);
  if (NULL != handle->network_handle)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (handle->network_handle);
      handle->network_handle = NULL;
    }
  if (NULL != (client = handle->client))
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Disconnecting from transport service for good.\n");
#endif
      handle->client = NULL;
      GNUNET_CLIENT_disconnect (client);
    }
  GNUNET_free (handle);
}


/**
 * Function we use for handling incoming messages.
 *
 * @param cls closure (struct GNUNET_TRANSPORT_Handle *)
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
  struct HelloWaitList *next_hwl;
  struct NeighbourList *n;
  struct GNUNET_PeerIdentity me;
  uint16_t size;

  if (h->client == NULL)
    {
      /* shutdown initiated from 'GNUNET_TRANSPORT_disconnect',
	 finish clean up work! */
      GNUNET_free (h);
      return;
    }
  if (msg == NULL) 
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Error receiving from transport service, disconnecting temporarily.\n");
#endif
      if (h->network_handle != NULL)
	{
	  GNUNET_CLIENT_notify_transmit_ready_cancel (h->network_handle);
	  h->network_handle = NULL;
	}
      GNUNET_CLIENT_disconnect (h->client);
      h->client = NULL;
      schedule_reconnect (h);
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
      hwl = h->hwl_head;
      while (NULL != hwl)
        {
	  next_hwl = hwl->next;
          hwl->rec (hwl->rec_cls,
		    (const struct GNUNET_MessageHeader *) h->my_hello);
	  hwl = next_hwl;
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
      n = neighbour_find (h, &cim->id);
      if (n == NULL)
	n = neighbour_add (h,
			   &cim->id);
      GNUNET_break (n->is_connected == GNUNET_NO);
      n->is_connected = GNUNET_YES;
      if (h->nc_cb != NULL)
	h->nc_cb (h->cls, &n->id,
		  GNUNET_TIME_relative_ntoh (cim->latency), 
		  ntohs (cim->distance));
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
                  "DISCONNECT",
		  GNUNET_i2s (&dim->peer));
#endif
      n = neighbour_find (h, &dim->peer);
      GNUNET_break (n != NULL);      
      if (n != NULL)
	neighbour_disconnect (n);      	
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
                  ntohl (okm->success) == GNUNET_OK ? "succeeded" : "failed");
#endif
      n = neighbour_find (h, &okm->peer);
      GNUNET_assert (n != NULL);
      switch (n->transmit_stage)
	{
	case TS_NEW:
	  GNUNET_break (0);
	  break;
	case TS_QUEUED:
	  GNUNET_break (0);
	  break;
	case TS_TRANSMITTED:
	  n->transmit_stage = TS_NEW;
	  break;
	case TS_TRANSMITTED_QUEUED:
	  n->transmit_stage = TS_QUEUED;
	  schedule_transmission (h);
	  break;
	default:
	  GNUNET_break (0);
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
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received message of type %u from `%4s'.\n",
		  ntohs (imm->type), GNUNET_i2s (&im->peer));
#endif      
      n = neighbour_find (h, &im->peer);
      if (n == NULL)
	n = neighbour_add (h, &im->peer);
      if (n == NULL) 
	break;
      if (h->rec != NULL)
	h->rec (h->cls, &im->peer, imm,
		GNUNET_TIME_relative_ntoh (im->latency), ntohs(im->distance));
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


/**
 * Called when our transmit request timed out before any transport
 * reported success connecting to the desired peer or before the
 * transport was ready to receive.  Signal error and free
 * TransmitHandle.
 *
 * @param cls the 'struct GNUNET_TRANSPORT_TransmitHandle*' that is timing out
 * @param tc scheduler context
 */
static void
peer_transmit_timeout (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th = cls;
  struct NeighbourList *n;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  void *notify_cls;

  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
  n = th->neighbour;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Triggering timeout for request to transmit to `%4s' (%d)\n",
	      GNUNET_i2s (&n->id),
	      n->transmit_stage);
#endif  
  notify = th->notify;
  notify_cls = th->notify_cls;
  switch (n->transmit_stage)
    {
    case TS_NEW:
      GNUNET_break (0);
      break;
    case TS_QUEUED:
      n->transmit_stage = TS_NEW;
      if (n->is_connected == GNUNET_NO)
	neighbour_free (n);
      break;
    case TS_TRANSMITTED:
      GNUNET_break (0);
      break;
    case TS_TRANSMITTED_QUEUED:
      n->transmit_stage = TS_TRANSMITTED;
      break;
    default:
      GNUNET_break (0);
    }
  if (NULL != notify)
    notify (notify_cls, 0, NULL);
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
                                        GNUNET_CONNECTION_TransmitReadyNotify
                                        notify, void *notify_cls)
{
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct NeighbourList *n;

  if (size + sizeof (struct OutboundMessage) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Message size is %d, max allowed is %d.\n",
                  size + sizeof (struct OutboundMessage), GNUNET_SERVER_MAX_MESSAGE_SIZE);
#endif
      GNUNET_break (0);
      return NULL;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport service for transmission of %u bytes to peer `%4s'.\n",
              size, GNUNET_i2s (target));
#endif
  n = neighbour_find (handle, target);
  if (n == NULL)
    n = neighbour_add (handle, target);
  if (n == NULL) 
    return NULL;
  switch (n->transmit_stage)
    {
    case TS_NEW:
      n->transmit_stage = TS_QUEUED;
      break;
    case TS_QUEUED:
      GNUNET_break (0);
      return NULL;
    case TS_TRANSMITTED:
      n->transmit_stage = TS_TRANSMITTED_QUEUED;
      break;
    case TS_TRANSMITTED_QUEUED:
      GNUNET_break (0);
      return NULL;
    default:
      GNUNET_break (0);
      return NULL;
    }
  th = &n->transmit_handle;
  th->neighbour = n;
  th->notify = notify;
  th->notify_cls = notify_cls;
  th->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  th->notify_size = size + sizeof (struct OutboundMessage);
  th->priority = priority;
  th->notify_delay_task
    = GNUNET_SCHEDULER_add_delayed (handle->sched, timeout,
				    &peer_transmit_timeout, th);
  schedule_transmission (handle);
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *th)
{
  struct NeighbourList *n;

  n = th->neighbour;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmission request of %u bytes to `%4s' was cancelled.\n",
              th->notify_size - sizeof (struct OutboundMessage),
              GNUNET_i2s (&n->id));
#endif
  switch (n->transmit_stage)
    {
    case TS_NEW:
      GNUNET_break (0);
      break;
    case TS_QUEUED:
      n->transmit_stage = TS_NEW;
      if (n->is_connected == GNUNET_NO)
	neighbour_free (n);
      break;
    case TS_TRANSMITTED:
      GNUNET_break (0);
      break;
    case TS_TRANSMITTED_QUEUED:
      n->transmit_stage = TS_TRANSMITTED;
      break;
    default:
      GNUNET_break (0);
    }
}


/* end of transport_api.c */
