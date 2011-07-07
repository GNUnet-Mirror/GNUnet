/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api.c
 * @brief library to access the low-level P2P IO service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_bandwidth_lib.h"
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
 * How large to start with for the hashmap of neighbours.
 */
#define STARTING_NEIGHBOURS_SIZE 10


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
  uint32_t priority;

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
 * Context for storing information about attempted next transmission.
 */
struct TryTransmitContext
{

  /**
   * Main transport handle.
   */
  struct GNUNET_TRANSPORT_Handle *h;

  /**
   * Returned transmission handle.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *ret;

  /**
   * Time to retry the send task.
   */
  struct GNUNET_TIME_Relative retry_time;
};

/**
 * Entry in hash table of all of our current neighbours.
 */
struct NeighbourList
{
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
   * Outbound bandwidh tracker.
   */
  struct GNUNET_BANDWIDTH_Tracker out_tracker;

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

  /**
   * Are we in the middle of disconnecting the peer already?
   */
  unsigned int in_disconnect;

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
   * My configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Linked list of the current neighbours of this peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *neighbours;

  /**
   * Peer identity as assumed by this process, or all zeros.
   */
  struct GNUNET_PeerIdentity self;

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

  /**
   * Set once we are in the process of disconnecting from the
   * service.
   */
  int in_disconnect;

  /**
   * Should we check that 'self' matches what the service thinks?
   * (if GNUNET_NO, then 'self' is all zeros!).
   */
  int check_self;
};

struct HelloContext
{

  /**
   * Size of the HELLO copied to end of struct.
   */
  uint16_t size;

  /**
   * Continuation to call once HELLO sent.
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Closure to call with the continuation.
   */
  void *cont_cls;

  /* HELLO */
};


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
  return GNUNET_CONTAINER_multihashmap_get(h->neighbours, &peer->hashPubKey);
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
 * Iterator over hash map entries, attempt to schedule
 * a transmission to entries in the neighbour hashmap.
 *
 * @param cls closure a TryTransmitContext
 * @param key current key code
 * @param value value in the hash map, the neighbour entry to consider
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
try_schedule_transmission (void *cls,
                           const GNUNET_HashCode * key,
                           void *value)
{
  struct NeighbourList *n = value;
  struct TryTransmitContext *try_transmit_ctx = cls;
  struct GNUNET_TIME_Relative duration;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  struct GNUNET_TRANSPORT_TransmitHandle *th;
  struct GNUNET_TIME_Absolute duration_abs;

  if (n->transmit_stage != TS_QUEUED)
    return GNUNET_YES; /* not eligible, keep iterating */
  if (n->is_connected != GNUNET_YES)
    return GNUNET_YES; /* keep iterating */

  th = &n->transmit_handle;
  GNUNET_break (n == th->neighbour);
  /* check outgoing quota */
  duration = GNUNET_BANDWIDTH_tracker_get_delay (&n->out_tracker,
                                                 th->notify_size - sizeof (struct OutboundMessage));
  duration_abs = GNUNET_TIME_relative_to_absolute (duration);
  if (th->timeout.abs_value < duration_abs.abs_value)
    {
      /* signal timeout! */
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Would need %llu ms before bandwidth is available for delivery to `%4s', that is too long.  Signaling timeout.\n",
                  duration.rel_value,
                  GNUNET_i2s (&n->id));
#endif
      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (th->notify_delay_task);
	  th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      n->transmit_stage = TS_NEW;
      if (NULL != (notify = th->notify))
        {
          th->notify = NULL;
          GNUNET_assert (0 == notify (th->notify_cls, 0, NULL));
        }
      return GNUNET_YES; /* keep iterating */
    }
  if (duration.rel_value > 0)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Need more bandwidth (%u b/s allowed, %u b needed), delaying delivery to `%4s' by %llu ms\n",
                  (unsigned int) n->out_tracker.available_bytes_per_s__,
                  (unsigned int) th->notify_size - sizeof (struct OutboundMessage),
                  GNUNET_i2s (&n->id),
                  (unsigned long long) duration.rel_value);
#endif
      try_transmit_ctx->retry_time = GNUNET_TIME_relative_min (try_transmit_ctx->retry_time,
                                                               duration);
      return GNUNET_YES; /* keep iterating */
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Have %u bytes of bandwidth available for transmission to `%4s' right now\n",
              th->notify_size - sizeof (struct OutboundMessage),
              GNUNET_i2s (&n->id));
#endif

  if ( (try_transmit_ctx->ret == NULL) ||
       (try_transmit_ctx->ret->priority < th->priority) )
    try_transmit_ctx->ret = th;
  return GNUNET_YES;
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
  struct TryTransmitContext try_transmit_ctx;

  if (h->quota_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (h->quota_task);
      h->quota_task = GNUNET_SCHEDULER_NO_TASK;
    }
  try_transmit_ctx.h = h;
  try_transmit_ctx.ret = NULL;
  try_transmit_ctx.retry_time = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CONTAINER_multihashmap_iterate(h->neighbours, 
					&try_schedule_transmission, 
					&try_transmit_ctx);
  if (try_transmit_ctx.ret == NULL)
    h->quota_task = GNUNET_SCHEDULER_add_delayed (try_transmit_ctx.retry_time,
						  &quota_transmit_ready,
						  h);
  return try_transmit_ctx.ret;
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
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  size_t ret;
  size_t mret;
  size_t nret;
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
          GNUNET_SCHEDULER_cancel (cm->notify_delay_task);
          cm->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      GNUNET_CONTAINER_DLL_remove (h->control_head,
				   h->control_tail,
				   cm);
      nret = cm->notify (cm->notify_cls, size, &cbuf[ret]);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Added %u bytes of control message at %u\n",
		  nret,
		  ret);
#endif
      GNUNET_free (cm);
      ret += nret;
      size -= nret;
    }
  while ( (NULL != (th = schedule_peer_transmission (h))) &&
	  (th->notify_size <= size) )
    {
      if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (th->notify_delay_task);
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
      notify = th->notify;
      th->notify = NULL;
      mret = notify (th->notify_cls,
		     size - sizeof (struct OutboundMessage),
		     &cbuf[ret + sizeof (struct OutboundMessage)]);
      GNUNET_assert (mret <= size - sizeof (struct OutboundMessage));
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Message of %u bytes with timeout %llums constructed for `%4s'\n",
		  (unsigned int) mret,
		  (unsigned long long) GNUNET_TIME_absolute_get_remaining (th->timeout).rel_value,
		  GNUNET_i2s (&n->id));
#endif
      if (mret != 0)	
	{
	  GNUNET_assert (mret + sizeof (struct OutboundMessage) < GNUNET_SERVER_MAX_MESSAGE_SIZE);
	  obm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SEND);
	  obm.header.size = htons (mret + sizeof (struct OutboundMessage));
	  obm.priority = htonl (th->priority);
	  obm.timeout = GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining (th->timeout));
	  obm.peer = n->id;
	  memcpy (&cbuf[ret], &obm, sizeof (struct OutboundMessage));
	  ret += (mret + sizeof (struct OutboundMessage));
	  size -= (mret + sizeof (struct OutboundMessage));
	  GNUNET_BANDWIDTH_tracker_consume (&n->out_tracker, mret);
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
	      n->transmit_stage = TS_QUEUED;
	      continue;
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Could not yet schedule transmission: we are not yet connected to the transport service!\n"));
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
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Could not yet schedule transmission: none ready\n");
#endif
	  return;
	}
      size = th->notify_size;
      timeout = GNUNET_TIME_absolute_get_remaining (th->timeout);
    }
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Calling notify_transmit_ready\n");
#endif
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
  struct ControlMessage *cm;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Control transmit of %u bytes within %llums requested\n",
              size, (unsigned long long) timeout.rel_value);
#endif
  cm = GNUNET_malloc (sizeof (struct ControlMessage));
  cm->h = h;
  cm->notify = notify;
  cm->notify_cls = notify_cls;
  cm->notify_size = size;
  cm->notify_delay_task
    = GNUNET_SCHEDULER_add_delayed (timeout, &control_transmit_timeout, cm);
  if (at_head)
    GNUNET_CONTAINER_DLL_insert (h->control_head,
				 h->control_tail,
				 cm);
  else
    GNUNET_CONTAINER_DLL_insert_after (h->control_head,
				       h->control_tail,
				       h->control_tail,
				       cm);
  schedule_transmission (h);
}


/**
 * FIXME: document
 */
struct SetQuotaContext
{
  /**
   * FIXME: document
   */
  struct GNUNET_TRANSPORT_Handle *handle;

  /**
   * FIXME: document
   */
  struct GNUNET_PeerIdentity target;

  /**
   * FIXME: document
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * FIXME: document
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * FIXME: document
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota_in;
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
      if (sqc->cont != NULL)
        GNUNET_SCHEDULER_add_continuation (sqc->cont,
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
  msg->quota = sqc->quota_in;
  memcpy (&msg->peer, &sqc->target, sizeof (struct GNUNET_PeerIdentity));
  if (sqc->cont != NULL)
    GNUNET_SCHEDULER_add_continuation (sqc->cont,
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
 */
void
GNUNET_TRANSPORT_set_quota (struct GNUNET_TRANSPORT_Handle *handle,
                            const struct GNUNET_PeerIdentity *target,
                            struct GNUNET_BANDWIDTH_Value32NBO quota_in,
                            struct GNUNET_BANDWIDTH_Value32NBO quota_out)
{
  struct NeighbourList *n;
  struct SetQuotaContext *sqc;

  n = neighbour_find (handle, target);
  if (n != NULL)
    {
#if DEBUG_TRANSPORT
      if (ntohl (quota_out.value__) != n->out_tracker.available_bytes_per_s__)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Quota changed from %u to %u for peer `%s'\n",
		    (unsigned int) n->out_tracker.available_bytes_per_s__,
		    (unsigned int) ntohl (quota_out.value__),
		    GNUNET_i2s (target));
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Quota remains at %u for peer `%s'\n",
		    (unsigned int) n->out_tracker.available_bytes_per_s__,
		    GNUNET_i2s (target));
#endif
      GNUNET_BANDWIDTH_tracker_update_quota (&n->out_tracker,
					     quota_out);
    }
  else
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Quota changed to %u for peer `%s', but I have no such neighbour!\n",
		  (unsigned int) ntohl (quota_out.value__),
		  GNUNET_i2s (target));
#endif
    }
  sqc = GNUNET_malloc (sizeof (struct SetQuotaContext));
  sqc->handle = handle;
  sqc->target = *target;
  sqc->cont = NULL;
  sqc->cont_cls = NULL;
  sqc->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_FOREVER_REL);
  sqc->quota_in = quota_in;
  schedule_control_transmit (handle,
                             sizeof (struct QuotaSetMessage),
                             GNUNET_NO, 
			     GNUNET_TIME_UNIT_FOREVER_REL, &send_set_quota, sqc);
}


/**
 * Ask the transport service to establish a connection to 
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 */
void
GNUNET_TRANSPORT_try_connect (struct GNUNET_TRANSPORT_Handle *handle,
			      const struct GNUNET_PeerIdentity *target)
{
  /* old API does nothing */
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
    {
#if DEBUG_TRANSPORT_HELLO
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "No HELLO yet, waiting to receive it from transport service\n");
#endif
      return;
    }
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
  struct HelloContext *hc = cls;
  uint16_t ssize;
  if (buf == NULL)
    {
#if DEBUG_TRANSPORT_TIMEOUT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Timeout while trying to transmit `%s' request.\n",
                  "HELLO");
#endif
      if (NULL != hc->cont)
	GNUNET_SCHEDULER_add_now(hc->cont, hc->cont_cls);
      GNUNET_free (hc);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request.\n", "HELLO");
#endif
  GNUNET_assert (size >= hc->size);
  memcpy (buf, &hc[1], hc->size);

  if (hc->cont != NULL)
    {
      GNUNET_SCHEDULER_add_continuation(hc->cont, hc->cont_cls, GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
  ssize = hc->size;
  GNUNET_free (hc);
  return ssize;
}


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent
 * @param cls closure for continuation
 *
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_Task cont,
                              void *cls)
{
  uint16_t size;
  struct GNUNET_PeerIdentity peer;
  struct HelloContext *hc;

  GNUNET_break (ntohs (hello->type) == GNUNET_MESSAGE_TYPE_HELLO);
  size = ntohs (hello->size);
  GNUNET_break (size >= sizeof (struct GNUNET_MessageHeader));
  if (GNUNET_OK != GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message*) hello,
					&peer))
    {
      GNUNET_break (0);
      return;
    }
  hc = GNUNET_malloc(sizeof(struct HelloContext) + size);
  hc->size = size;
  hc->cont = cont;
  hc->cont_cls = cls;
  memcpy (&hc[1], hello, size);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Offering `%s' message of `%4s' to transport for validation.\n",
	      "HELLO",
	      GNUNET_i2s (&peer));
#endif

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
  struct GNUNET_TRANSPORT_Handle *h = cls;
  struct StartMessage s;

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
  GNUNET_assert (size >= sizeof (struct StartMessage));
  s.header.size = htons (sizeof (struct StartMessage));
  s.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  s.do_check = htonl (h->check_self);
  s.self = h->self;
  memcpy (buf, &s, sizeof (struct StartMessage));
  return sizeof (struct StartMessage);
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

  /* Added so task gets canceled when a disconnect is received! */
  /* Method 1
  if (n->transmit_handle.notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(n->transmit_handle.notify_delay_task);
      n->transmit_handle.notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
      n->transmit_handle.notify = NULL;
    }
  */
  /* NATE: if the above is not needed, then clearly this assertion
     should hold (I've checked the code and I'm pretty sure this is
     true. -CG 
     FIXME: remove above comments once we've seen tests pass with the assert... */
  GNUNET_assert (n->transmit_handle.notify_delay_task == GNUNET_SCHEDULER_NO_TASK);
  GNUNET_assert (n->transmit_handle.notify == NULL);
  h = n->h;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing neighbour `%s' from list of connected peers.\n",
              GNUNET_i2s (&n->id));
#endif
  GNUNET_break (n->is_connected == GNUNET_NO);
  GNUNET_break (n->transmit_stage == TS_NEW);

  GNUNET_assert(GNUNET_YES == 
		GNUNET_CONTAINER_multihashmap_remove(h->neighbours, 
						     &n->id.hashPubKey, 
						     n));
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
  /* FIXME: this 'in_disconnect' flag is dubious; we should define 
     clearly what disconnect means for pending 'notify_transmit_ready'
     requests; maybe a good approach is to REQUIRE clients to 
     call 'notify_transmit_ready_cancel' on pending requests on disconnect
     and otherwise FAIL HARD with an assertion failure before 
     'neighbour_free' right here (transmit_stage would be forced
     to 'TS_NEW') */
  n->in_disconnect = GNUNET_YES;
  if (h->nd_cb != NULL)
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
 * Iterator over hash map entries, for getting rid of a neighbor
 * upon a reconnect call.
 *
 * @param cls closure (NULL)
 * @param key current key code
 * @param value value in the hash map, the neighbour entry to forget
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
forget_neighbours (void *cls,
                   const GNUNET_HashCode * key,
                   void *value)
{
  struct NeighbourList *n = value;

#if DEBUG_TRANSPORT_DISCONNECT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting due to reconnect being called\n");
#endif
  if (n->is_connected)
    neighbour_disconnect (n);

  return GNUNET_YES;
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
  struct ControlMessage *pos;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    {
      /* shutdown, just give up */
      return;
    }
  /* Forget about all neighbours that we used to be connected to */
  GNUNET_CONTAINER_multihashmap_iterate(h->neighbours, 
					&forget_neighbours, 
					NULL);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connecting to transport service.\n");
#endif
  GNUNET_assert (h->client == NULL);
  h->client = GNUNET_CLIENT_connect ("transport", h->cfg);
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
              GNUNET_SCHEDULER_cancel (pos->notify_delay_task);
              pos->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
            }
          GNUNET_free (pos);
          break;
        }
      pos = pos->next;
    }
  schedule_control_transmit (h,
                             sizeof (struct StartMessage),
                             GNUNET_YES,
                             GNUNET_TIME_UNIT_FOREVER_REL, &send_start, h);
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
              h->reconnect_delay.rel_value);
#endif
  GNUNET_assert (h->client == NULL);
  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  if (h->reconnect_delay.rel_value == 0)
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
 * Send request connect message to the service.
 *
 * @param cls the TransportRequestConnectMessage
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_transport_request_connect (void *cls, size_t size, void *buf)
{
  struct TransportRequestConnectMessage *trcm = cls;

  if (buf == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Buffer null for %s\n",
                  "REQUEST_CONNECT");
#endif
      GNUNET_free (trcm);
      return 0;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting `%s' request for `%4s'.\n",
              "REQUEST_CONNECT",
              GNUNET_i2s (&trcm->peer));
#endif
  GNUNET_assert (size >= sizeof (struct TransportRequestConnectMessage));
  memcpy(buf, trcm, sizeof(struct TransportRequestConnectMessage));
  GNUNET_free (trcm);
  return sizeof(struct TransportRequestConnectMessage);
}

/**
 * Create and send a request connect message to
 * the transport service for a particular peer.
 *
 * @param h handle to the transport service
 * @param n the neighbor to send the request connect message about
 *
 */
static void 
send_request_connect_message(struct GNUNET_TRANSPORT_Handle *h, struct NeighbourList *n)
{
  struct TransportRequestConnectMessage *trcm;

  trcm = GNUNET_malloc(sizeof(struct TransportRequestConnectMessage));
  trcm->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT);
  trcm->header.size = htons(sizeof(struct TransportRequestConnectMessage));
  memcpy(&trcm->peer, &n->id, sizeof(struct GNUNET_PeerIdentity));
  schedule_control_transmit (h,
                             sizeof (struct TransportRequestConnectMessage),
                             GNUNET_NO,
                             GNUNET_TIME_UNIT_FOREVER_REL, &send_transport_request_connect, trcm);
}


/**
 * Add neighbour to our list
 *
 * @return NULL if this API is currently disconnecting from the service
 */
static struct NeighbourList *
neighbour_add (struct GNUNET_TRANSPORT_Handle *h,
               const struct GNUNET_PeerIdentity *pid)
{
  struct NeighbourList *n;

  if (GNUNET_YES == h->in_disconnect)
    return NULL;
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
  n->h = h;
  GNUNET_BANDWIDTH_tracker_init (&n->out_tracker,
				 GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
				 MAX_BANDWIDTH_CARRY_S);
  GNUNET_CONTAINER_multihashmap_put (h->neighbours,
                                     &pid->hashPubKey,
                                     n,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  return n;
}


/**
 * Iterator over hash map entries, for deleting state of a neighbor.
 *
 * @param cls closure (NULL)
 * @param key current key code
 * @param value value in the hash map, the neighbour entry to delete
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
delete_neighbours (void *cls,
                   const GNUNET_HashCode * key,
                   void *value)
{
  struct NeighbourList *n = value;
  struct GNUNET_TRANSPORT_TransmitHandle *th;

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
          GNUNET_SCHEDULER_cancel (th->notify_delay_task);
          th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      GNUNET_assert (0 == th->notify (th->notify_cls, 0, NULL));
      break;
    default:
      GNUNET_break (0);
    }
  GNUNET_free (n);
  return GNUNET_YES;
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
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  const struct GNUNET_PeerIdentity *self,
                          void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd)
{
  struct GNUNET_TRANSPORT_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_Handle));
  if (self != NULL)
    {
      ret->self = *self;
      ret->check_self = GNUNET_YES;
    }
  ret->cfg = cfg;
  ret->cls = cls;
  ret->rec = rec;
  ret->nc_cb = nc;
  ret->nd_cb = nd;
  ret->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ret->neighbours = GNUNET_CONTAINER_multihashmap_create(STARTING_NEIGHBOURS_SIZE);
  schedule_reconnect (ret);
  return ret;
}


/**
 * Disconnect from the transport service.
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle)
{
  struct HelloWaitList *hwl;
  struct GNUNET_CLIENT_Connection *client;
  struct ControlMessage *cm;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transport disconnect called!\n");
#endif
  /* FIXME: this flag is dubious, we should be able to do this
     more cleanly; also, we should probably do 'disconnect'
     callbacks for every connected peer here, i.e. by calling
     the iterator with 'forget_neighbours' instead of 'delete_neighbours'.
  */
  
  handle->in_disconnect = GNUNET_YES;

  GNUNET_assert (GNUNET_SYSERR !=
		 GNUNET_CONTAINER_multihashmap_iterate(handle->neighbours,
						       &delete_neighbours,
						       handle));
  GNUNET_CONTAINER_multihashmap_destroy (handle->neighbours);

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

  /* Check for still scheduled control messages, cancel delay tasks if so */
  /* Added because somehow a notify_delay_task is remaining scheduled and is ever so annoying */
  while ( (NULL != (cm = handle->control_head)))
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Disconnect before control message sent!\n");
#endif
      if (cm->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (cm->notify_delay_task);
          cm->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
        }
      GNUNET_CONTAINER_DLL_remove (handle->control_head,
                                   handle->control_tail,
                                   cm);
      GNUNET_free (cm);
    }
  /* end check */

  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->reconnect_task);
      handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (handle->quota_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->quota_task);
      handle->quota_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_free_non_null (handle->my_hello);
  handle->my_hello = NULL;

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
      GNUNET_CLIENT_disconnect (client, GNUNET_YES);
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
  uint32_t ats_count;

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
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
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
      if (size < sizeof (struct ConnectInfoMessage))
        {
          GNUNET_break (0);
          break;
        }
      cim = (const struct ConnectInfoMessage *) msg;
      ats_count = ntohl (cim->ats_count);
      if (size != sizeof (struct ConnectInfoMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information))
        {
          GNUNET_break (0);
          break;
        }
      if (0 == memcmp (&cim->id,
		       &h->self,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* connect to self!? */
	  GNUNET_break (0);
	  break;
	}
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receiving `%s' message for `%4s'.\n",
                  "CONNECT", GNUNET_i2s (&cim->id));
#endif
      n = neighbour_find (h, &cim->id);
      if (n == NULL)
    	  n = neighbour_add (h, &cim->id);
      if (n == NULL)
		 return;
      GNUNET_break (n->is_connected == GNUNET_NO);
      n->is_connected = GNUNET_YES;
      /* FIXME */
      if (h->nc_cb != NULL)
    	  h->nc_cb (h->cls, &n->id,
		  &cim->ats,ats_count);
      /* FIXEND */
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT:
      if (size != sizeof (struct DisconnectInfoMessage))
        {
          GNUNET_break (0);
          break;
        }
      dim = (const struct DisconnectInfoMessage *) msg;
      GNUNET_break (ntohl (dim->reserved) == 0);
      if (0 == memcmp (&dim->peer,
		       &h->self,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* discconnect from self!? */
	  GNUNET_break (0);
	  break;
	}
#if DEBUG_TRANSPORT_DISCONNECT
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
      GNUNET_break (0 == ntohl (im->reserved));
      ats_count = ntohl(im->ats_count);
      //imm = (const struct GNUNET_MessageHeader *) &im[1];
      imm = (const struct GNUNET_MessageHeader *) &((&(im->ats))[ats_count+1]);

      if (ntohs (imm->size) + sizeof (struct InboundMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) != size)
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
	{
	  GNUNET_break (0);
	  break;
	}
      if (n->is_connected != GNUNET_YES)
	{
	  GNUNET_break (0);
	  break;
	}
      /* FIXME: */
      if (h->rec != NULL)
		h->rec (h->cls, &im->peer, imm,
			&im->ats, ats_count);
      /* ENDFIX */
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
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      "Triggering timeout for request to transmit to `%4s' (%d)\n",
	      GNUNET_i2s (&n->id),
	      n->transmit_stage);
#endif
  notify = th->notify;
  th->notify = NULL;
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
                                        uint32_t priority,
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
                  size + sizeof (struct OutboundMessage), GNUNET_SERVER_MAX_MESSAGE_SIZE - 1);
#endif
      GNUNET_break (0);
      return NULL;
    }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport service for transmission of %u bytes to peer `%4s' within %llu ms.\n",
              size, GNUNET_i2s (target),
	      (unsigned long long) timeout.rel_value);
#endif
  n = neighbour_find (handle, target);
  if (n == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created neighbour entry for peer `%s'\n",
                  GNUNET_i2s (target));
      n = neighbour_add (handle, target);
    }
  if (n == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Could not create neighbour entry for peer `%s'\n",
		  GNUNET_i2s (target));
      return NULL;
    }

  /**
   *  Send a request connect message if not connected,
   *  otherwise we will never send anything to
   *  transport service
   */
  if (n->is_connected == GNUNET_NO)
    {
      send_request_connect_message(handle, n);
    }

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
    = GNUNET_SCHEDULER_add_delayed (timeout,
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

  th->notify = NULL;
  n = th->neighbour;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmission request of %u bytes to `%4s' was canceled.\n",
              th->notify_size - sizeof (struct OutboundMessage),
              GNUNET_i2s (&n->id));
#endif
  if (th->notify_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (th->notify_delay_task);
      th->notify_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }
  switch (n->transmit_stage)
    {
    case TS_NEW:
      GNUNET_assert (0);
      break;
    case TS_QUEUED:
      n->transmit_stage = TS_NEW;
      if ( (n->in_disconnect == GNUNET_NO) &&
	   (n->is_connected == GNUNET_NO) )
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
