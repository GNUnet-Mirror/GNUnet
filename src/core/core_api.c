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
 * @file core/core_api.c
 * @brief core service; this is the main API for encrypted P2P
 *        communications
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "core.h"


/**
 * Information we track for each peer.
 */
struct PeerRecord
{

  /**
   * We generally do NOT keep peer records in a DLL; this
   * DLL is only used IF this peer's 'pending_head' message
   * is ready for transmission.  
   */
  struct PeerRecord *prev;

  /**
   * We generally do NOT keep peer records in a DLL; this
   * DLL is only used IF this peer's 'pending_head' message
   * is ready for transmission. 
   */
  struct PeerRecord *next;

  /**
   * Peer the record is about.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Corresponding core handle.
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   * Head of doubly-linked list of pending requests.
   * Requests are sorted by deadline *except* for HEAD,
   * which is only modified upon transmission to core.
   */
  struct GNUNET_CORE_TransmitHandle *pending_head;

  /**
   * Tail of doubly-linked list of pending requests.
   */
  struct GNUNET_CORE_TransmitHandle *pending_tail;

  /**
   * Pending callback waiting for peer information, or NULL for none.
   */
  GNUNET_CORE_PeerConfigurationInfoCallback pcic;

  /**
   * Closure for pcic.
   */
  void *pcic_cls;

  /**
   * Pointer to free when we call pcic.
   */
  void *pcic_ptr;

  /**
   * Request information ID for the given pcic (needed in case a
   * request is cancelled after being submitted to core and a new
   * one is generated; in this case, we need to avoid matching the
   * reply to the first (cancelled) request to the second request).
   */
  uint32_t rim_id;

  /**
   * ID of timeout task for the 'pending_head' handle
   * which is the one with the smallest timeout. 
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Current size of the queue of pending requests.
   */
  unsigned int queue_size;

  /**
   * SendMessageRequest ID generator for this peer.
   */
  uint16_t smr_id_gen;
  
};


/**
 * Entry in a doubly-linked list of control messages to be transmitted
 * to the core service.  Control messages include traffic allocation,
 * connection requests and of course our initial 'init' request.
 * 
 * The actual message is allocated at the end of this struct.
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
   * Function to run after transmission failed/succeeded.
   */
  GNUNET_CORE_ControlContinuation cont;
  
  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Transmit handle (if one is associated with this ControlMessage), or NULL.
   */
  struct GNUNET_CORE_TransmitHandle *th;
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
   * Function to call whenever we're notified about a peer changing status.
   */  
  GNUNET_CORE_PeerStatusEventHandler status_events;
  
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
  const struct GNUNET_CORE_MessageHandler *handlers;

  /**
   * Our connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for our current transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *cth;

  /**
   * Head of doubly-linked list of pending requests.
   */
  struct ControlMessage *control_pending_head;

  /**
   * Tail of doubly-linked list of pending requests.
   */
  struct ControlMessage *control_pending_tail;

  /**
   * Head of doubly-linked list of peers that are core-approved
   * to send their next message.
   */
  struct PeerRecord *ready_peer_head;

  /**
   * Tail of doubly-linked list of peers that are core-approved
   * to send their next message.
   */
  struct PeerRecord *ready_peer_tail;

  /**
   * Hash map listing all of the peers that we are currently
   * connected to.
   */
  struct GNUNET_CONTAINER_MultiHashMap *peers;

  /**
   * Identity of this peer.
   */
  struct GNUNET_PeerIdentity me;

  /**
   * ID of reconnect task (if any).
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Request information ID generator.
   */
  uint32_t rim_id_gen;

  /**
   * Number of messages we are allowed to queue per target.
   */
  unsigned int queue_size;

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
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle
{

  /**
   * We keep active transmit handles in a doubly-linked list.
   */
  struct GNUNET_CORE_TransmitHandle *next;

  /**
   * We keep active transmit handles in a doubly-linked list.
   */
  struct GNUNET_CORE_TransmitHandle *prev;

  /**
   * Corresponding peer record.
   */
  struct PeerRecord *peer;

  /**
   * Corresponding SEND_REQUEST message.  Only non-NULL 
   * while SEND_REQUEST message is pending.
   */
  struct ControlMessage *cm;

  /**
   * Function that will be called to get the actual request
   * (once we are ready to transmit this request to the core).
   * The function will be called with a NULL buffer to signal
   * timeout.
   */
  GNUNET_CONNECTION_TransmitReadyNotify get_message;

  /**
   * Closure for get_message.
   */
  void *get_message_cls;

  /**
   * Timeout for this handle.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How important is this message?
   */
  uint32_t priority;

  /**
   * Size of this request.
   */
  uint16_t msize;

  /**
   * Send message request ID for this request.
   */
  uint16_t smr_id;

  /**
   * Is corking allowed?
   */
  int cork;

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
 * @param cls the 'struct GNUNET_CORE_Handle'
 * @param tc task context
 */
static void
reconnect_task (void *cls, 
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CORE_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connecting to CORE service after delay\n");
#endif
  reconnect (h);
}


/**
 * Notify clients about disconnect and free 
 * the entry for connected peer.
 *
 * @param cls the 'struct GNUNET_CORE_Handle*'
 * @param key the peer identity (not used)
 * @param value the 'struct PeerRecord' to free.
 * @return GNUNET_YES (continue)
 */
static int
disconnect_and_free_peer_entry (void *cls,
				const GNUNET_HashCode *key,
				void *value)
{
  static struct GNUNET_BANDWIDTH_Value32NBO zero;
  struct GNUNET_CORE_Handle *h = cls;
  struct GNUNET_CORE_TransmitHandle *th;
  struct PeerRecord *pr = value;
  GNUNET_CORE_PeerConfigurationInfoCallback pcic;

  while (NULL != (th = pr->pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (pr->pending_head,
				   pr->pending_tail,
				   th);
      pr->queue_size--;
      GNUNET_assert (0 == 
		     th->get_message (th->get_message_cls,
				      0, NULL));
      if (th->cm != NULL)
	th->cm->th = NULL;
      GNUNET_free (th);
    }
  if (NULL != (pcic = pr->pcic))
    {
      pr->pcic = NULL;
      GNUNET_free_non_null (pr->pcic_ptr);
      pr->pcic_ptr = NULL;
      pcic (pr->pcic_cls,
	    &pr->peer,
	    zero,
	    0, 
	    GNUNET_TIME_UNIT_FOREVER_REL,
	    0);
    }
  if (pr->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pr->timeout_task);
      pr->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_assert (pr->queue_size == 0);
  if ( (pr->prev != NULL) ||
       (pr->next != NULL) ||
       (h->ready_peer_head == pr) )
    GNUNET_CONTAINER_DLL_remove (h->ready_peer_head,
				 h->ready_peer_tail,
				 pr);
  if (h->disconnects != NULL)
    h->disconnects (h->cls,
		    &pr->peer);    
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (h->peers,
						       key,
						       pr));
  GNUNET_assert (pr->pending_head == NULL);
  GNUNET_assert (pr->pending_tail == NULL);
  GNUNET_assert (pr->ch = h);
  GNUNET_assert (pr->queue_size == 0);
  GNUNET_assert (pr->timeout_task == GNUNET_SCHEDULER_NO_TASK);
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
  struct ControlMessage *cm;
  struct PeerRecord *pr;

  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  if (h->client != NULL)
    {
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = NULL;
      h->cth = NULL;
      GNUNET_CONTAINER_multihashmap_iterate (h->peers,
					     &disconnect_and_free_peer_entry,
					     h);
    }
  while (NULL != (pr = h->ready_peer_head))    
    GNUNET_CONTAINER_DLL_remove (h->ready_peer_head,
				 h->ready_peer_tail,
				 pr);
  h->currently_down = GNUNET_YES;
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->retry_backoff,
						    &reconnect_task,
						    h);
  while (NULL != (cm = h->control_pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
				   h->control_pending_tail,
				   cm);
      if (cm->th != NULL)
	cm->th->cm = NULL; 
      if (cm->cont != NULL)
	cm->cont (cm->cont_cls, GNUNET_NO);
      GNUNET_free (cm);
    }
  GNUNET_assert (h->control_pending_head == NULL);
  h->retry_backoff = GNUNET_TIME_relative_min (GNUNET_TIME_UNIT_SECONDS,
					       h->retry_backoff);
  h->retry_backoff = GNUNET_TIME_relative_multiply (h->retry_backoff, 2);
}


/**
 * Check the list of pending requests, send the next
 * one to the core.
 *
 * @param h core handle
 * @param ignore_currently_down transmit message even if not initialized?
 */
static void
trigger_next_request (struct GNUNET_CORE_Handle *h,
		      int ignore_currently_down);


/**
 * The given request hit its timeout.  Remove from the
 * doubly-linked list and call the respective continuation.
 *
 * @param cls the transmit handle of the request that timed out
 * @param tc context, can be NULL (!)
 */
static void
transmission_timeout (void *cls, 
		      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Send a control message to the peer asking for transmission
 * of the message in the given peer record.
 *
 * @param pr peer to request transmission to
 */
static void
request_next_transmission (struct PeerRecord *pr)
{
  struct GNUNET_CORE_Handle *h = pr->ch;
  struct ControlMessage *cm;
  struct SendMessageRequest *smr;
  struct GNUNET_CORE_TransmitHandle *th;

  if (pr->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pr->timeout_task);
      pr->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL == (th = pr->pending_head))
    {
      trigger_next_request (h, GNUNET_NO);
      return;
    }
  if (th->cm != NULL)
    return; /* already done */
  GNUNET_assert (pr->prev == NULL);
  GNUNET_assert (pr->next == NULL);
  pr->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining (th->timeout),
						   &transmission_timeout,
						   pr);
  cm = GNUNET_malloc (sizeof (struct ControlMessage) + 
		      sizeof (struct SendMessageRequest));
  th->cm = cm;
  cm->th = th;
  smr = (struct SendMessageRequest*) &cm[1];
  smr->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST);
  smr->header.size = htons (sizeof (struct SendMessageRequest));
  smr->priority = htonl (th->priority);
  smr->deadline = GNUNET_TIME_absolute_hton (th->timeout);
  smr->peer = pr->peer;
  smr->queue_size = htonl (pr->queue_size);
  smr->size = htons (th->msize);
  smr->smr_id = htons (th->smr_id = pr->smr_id_gen++);
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
				    h->control_pending_tail,
				    cm);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding SEND REQUEST for peer `%s' to message queue\n",
	      GNUNET_i2s (&pr->peer));
#endif
  trigger_next_request (h, GNUNET_NO);
}


/**
 * The given request hit its timeout.  Remove from the
 * doubly-linked list and call the respective continuation.
 *
 * @param cls the transmit handle of the request that timed out
 * @param tc context, can be NULL (!)
 */
static void
transmission_timeout (void *cls, 
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerRecord *pr = cls;
  struct GNUNET_CORE_Handle *h = pr->ch;
  struct GNUNET_CORE_TransmitHandle *th;
  
  pr->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  th = pr->pending_head;
  GNUNET_CONTAINER_DLL_remove (pr->pending_head,
                               pr->pending_tail,
                               th);
  pr->queue_size--;
  if ( (pr->prev != NULL) ||
       (pr->next != NULL) ||
       (pr == h->ready_peer_head) )
    {
      /* the request that was 'approved' by core was
	 canceled before it could be transmitted; remove
	 us from the 'ready' list */
      GNUNET_CONTAINER_DLL_remove (h->ready_peer_head,
				   h->ready_peer_tail,
				   pr);
    }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Signalling timeout of request for transmission to CORE service\n");
#endif
  GNUNET_assert (0 == th->get_message (th->get_message_cls, 0, NULL));
  request_next_transmission (pr);
}


/**
 * Transmit the next message to the core service.
 */
static size_t
transmit_message (void *cls,
		  size_t size, 
		  void *buf)
{
  struct GNUNET_CORE_Handle *h = cls;
  struct ControlMessage *cm;
  struct GNUNET_CORE_TransmitHandle *th;
  struct PeerRecord *pr;
  struct SendMessage *sm;
  const struct GNUNET_MessageHeader *hdr;
  uint16_t msize;
  size_t ret;

  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  h->cth = NULL;
  if (buf == NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmission failed, initiating reconnect\n");
#endif
      reconnect_later (h);
      return 0;
    }
  /* first check for control messages */
  if (NULL != (cm = h->control_pending_head))
    {
      hdr = (const struct GNUNET_MessageHeader*) &cm[1];
      msize = ntohs (hdr->size);
      if (size < msize)
	{
	  trigger_next_request (h, GNUNET_NO);
	  return 0;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting control message with %u bytes of type %u to core.\n",
		  (unsigned int) msize,
		  (unsigned int) ntohs (hdr->type));
#endif
      memcpy (buf, hdr, msize);
      GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
				   h->control_pending_tail,
				   cm);     
      if (cm->th != NULL)
	cm->th->cm = NULL;
      if (NULL != cm->cont)
	cm->cont (cm->cont_cls, GNUNET_OK);
      GNUNET_free (cm);
      trigger_next_request (h, GNUNET_NO);
      return msize;
    }
  /* now check for 'ready' P2P messages */
  if (NULL != (pr = h->ready_peer_head))
    {
      GNUNET_assert (pr->pending_head != NULL);
      th = pr->pending_head;
      if (size < th->msize + sizeof (struct SendMessage))
	{
	  trigger_next_request (h, GNUNET_NO);
	  return 0;
	}
      GNUNET_CONTAINER_DLL_remove (h->ready_peer_head,
				   h->ready_peer_tail,
				   pr);
      GNUNET_CONTAINER_DLL_remove (pr->pending_head,
				   pr->pending_tail,
				   th);
      pr->queue_size--;
      if (pr->timeout_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (pr->timeout_task);
	  pr->timeout_task = GNUNET_SCHEDULER_NO_TASK;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting SEND request to `%s' with %u bytes.\n",
		  GNUNET_i2s (&pr->peer),
		  (unsigned int) th->msize);
#endif
      sm = (struct SendMessage *) buf;
      sm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND);
      sm->priority = htonl (th->priority);
      sm->deadline = GNUNET_TIME_absolute_hton (th->timeout);
      sm->peer = pr->peer;
      sm->cork = htonl ((uint32_t) th->cork);
      sm->reserved = htonl (0);
      ret = th->get_message (th->get_message_cls,
			     size - sizeof (struct SendMessage),
			     &sm[1]);
 
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting SEND request to `%s' yielded %u bytes.\n",
		  GNUNET_i2s (&pr->peer),
		  ret);
#endif
     if (0 == ret)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Size of clients message to peer %s is 0!\n",
		      GNUNET_i2s(&pr->peer));
#endif
	  /* client decided to send nothing! */
	  request_next_transmission (pr);
	  GNUNET_free (th);
   	  return 0;	  
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Produced SEND message to core with %u bytes payload\n",
		  (unsigned int) ret);
#endif
      GNUNET_assert (ret >= sizeof (struct GNUNET_MessageHeader));
      if (ret + sizeof (struct SendMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  request_next_transmission (pr);
	  GNUNET_free (th);
   	  return 0;
	}
      ret += sizeof (struct SendMessage);
      sm->header.size = htons (ret);
      GNUNET_assert (ret <= size);
      GNUNET_free (th);
      request_next_transmission (pr);
      return ret;
    }
  return 0;
}


/**
 * Check the list of pending requests, send the next
 * one to the core.
 *
 * @param h core handle
 * @param ignore_currently_down transmit message even if not initialized?
 */
static void
trigger_next_request (struct GNUNET_CORE_Handle *h,
		      int ignore_currently_down)
{
  uint16_t msize;

  if ( (GNUNET_YES == h->currently_down) &&
       (ignore_currently_down == GNUNET_NO) )
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Core connection down, not processing queue\n");
#endif
      return;
    }
  if (NULL != h->cth)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Request pending, not processing queue\n");
#endif
      return;
    }
  if (h->control_pending_head != NULL)
    msize = ntohs (((struct GNUNET_MessageHeader*) &h->control_pending_head[1])->size);    
  else if (h->ready_peer_head != NULL) 
    msize = h->ready_peer_head->pending_head->msize + sizeof (struct SendMessage);    
  else
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Request queue empty, not processing queue\n");
#endif
      return; /* no pending message */
    }
  h->cth = GNUNET_CLIENT_notify_transmit_ready (h->client,
						msize,
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_NO,
						&transmit_message, h);
}


/**
 * Handler for notification messages received from the core.
 *
 * @param cls our "struct GNUNET_CORE_Handle"
 * @param msg the message received from the core service
 */
static void
main_notify_handler (void *cls, 
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_Handle *h = cls;
  const struct InitReplyMessage *m;
  const struct ConnectNotifyMessage *cnm;
  const struct DisconnectNotifyMessage *dnm;
  const struct NotifyTrafficMessage *ntm;
  const struct GNUNET_MessageHeader *em;
  const struct ConfigurationInfoMessage *cim;
  const struct PeerStatusNotifyMessage *psnm;
  const struct SendMessageReady *smr;
  const struct GNUNET_CORE_MessageHandler *mh;
  GNUNET_CORE_StartupCallback init;
  GNUNET_CORE_PeerConfigurationInfoCallback pcic;
  struct PeerRecord *pr;
  struct GNUNET_CORE_TransmitHandle *th;
  unsigned int hpos;
  int trigger;
  uint16_t msize;
  uint16_t et;
  uint32_t ats_count;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Client was disconnected from core service, trying to reconnect.\n"));
      reconnect_later (h);
      return;
    }
  msize = ntohs (msg->size);
#if DEBUG_CORE > 2
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing message of type %u and size %u from core service\n",
              ntohs (msg->type), msize);
#endif
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY:
      if (ntohs (msg->size) != sizeof (struct InitReplyMessage))
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      m = (const struct InitReplyMessage *) msg;
      GNUNET_break (0 == ntohl (m->reserved));
      /* start our message processing loop */
      if (GNUNET_YES == h->currently_down)
	{
	  h->currently_down = GNUNET_NO;
	  trigger_next_request (h, GNUNET_NO);
	}
      h->retry_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
      GNUNET_CRYPTO_hash (&m->publicKey,
			  sizeof (struct
				  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			  &h->me.hashPubKey);
      if (NULL != (init = h->init))
	{
	  /* mark so we don't call init on reconnect */
	  h->init = NULL;
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connected to core service of peer `%s'.\n",
		      GNUNET_i2s (&h->me));
#endif
	  init (h->cls, h, &h->me, &m->publicKey);
	}
      else
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Successfully reconnected to core service.\n");
#endif
	}
      /* fake 'connect to self' */
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &h->me.hashPubKey);
      GNUNET_assert (pr == NULL);
      pr = GNUNET_malloc (sizeof (struct PeerRecord));
      pr->peer = h->me;
      pr->ch = h;
      GNUNET_assert (GNUNET_YES ==
		     GNUNET_CONTAINER_multihashmap_put (h->peers,
							&h->me.hashPubKey,
							pr,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
      if (NULL != h->connects)
	h->connects (h->cls,
		     &h->me,
		     NULL);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT:
      if (msize < sizeof (struct ConnectNotifyMessage))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      cnm = (const struct ConnectNotifyMessage *) msg;
      ats_count = ntohl (cnm->ats_count);
      if ( (msize != sizeof (struct ConnectNotifyMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)) ||
	   (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR != ntohl ((&cnm->ats)[ats_count].type)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about connection from `%s'.\n",
		  GNUNET_i2s (&cnm->peer));
#endif
      if (0 == memcmp (&h->me,
		       &cnm->peer,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* connect to self!? */
	  GNUNET_break (0);
	  return;
	}
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &cnm->peer.hashPubKey);
      if (pr != NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      pr = GNUNET_malloc (sizeof (struct PeerRecord));
      pr->peer = cnm->peer;
      pr->ch = h;
      GNUNET_assert (GNUNET_YES ==
		     GNUNET_CONTAINER_multihashmap_put (h->peers,
							&cnm->peer.hashPubKey,
							pr,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
      if (NULL != h->connects)
	h->connects (h->cls,
		     &cnm->peer,
		     &cnm->ats);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT:
      if (msize != sizeof (struct DisconnectNotifyMessage))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      dnm = (const struct DisconnectNotifyMessage *) msg;
      if (0 == memcmp (&h->me,
		       &dnm->peer,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* connection to self!? */
	  GNUNET_break (0);
	  return;
	}
      GNUNET_break (0 == ntohl (dnm->reserved));
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about disconnect from `%s'.\n",
		  GNUNET_i2s (&dnm->peer));
#endif
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &dnm->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      trigger = ( (pr->prev != NULL) ||
		  (pr->next != NULL) ||
		  (h->ready_peer_head == pr) );
      disconnect_and_free_peer_entry (h, &dnm->peer.hashPubKey, pr);
      if (trigger)
	trigger_next_request (h, GNUNET_NO);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_STATUS_CHANGE:
      if (NULL == h->status_events)
        {
          GNUNET_break (0);
	  return;
        }
      if (msize < sizeof (struct PeerStatusNotifyMessage))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      psnm = (const struct PeerStatusNotifyMessage *) msg;
      if (0 == memcmp (&h->me,
		       &psnm->peer,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* self-change!? */
	  GNUNET_break (0);
	  return;
	}
      ats_count = ntohl (psnm->ats_count);
      if ( (msize != sizeof (struct PeerStatusNotifyMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)) ||
	   (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR != ntohl ((&psnm->ats)[ats_count].type)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
#if DEBUG_CORE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about status change by `%s'.\n",
		  GNUNET_i2s (&psnm->peer));
#endif
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &psnm->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      h->status_events (h->cls,
			&psnm->peer,
			psnm->bandwidth_in,
			psnm->bandwidth_out,
			GNUNET_TIME_absolute_ntoh (psnm->timeout),
			&psnm->ats);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND:
      if (msize < sizeof (struct NotifyTrafficMessage))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      ntm = (const struct NotifyTrafficMessage *) msg;

      ats_count = ntohl (ntm->ats_count);
      if ( (msize < sizeof (struct NotifyTrafficMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)
	    + sizeof (struct GNUNET_MessageHeader)) ||
	   (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR != ntohl ((&ntm->ats)[ats_count].type)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      em = (const struct GNUNET_MessageHeader *) &(&ntm->ats)[ats_count+1];
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received message of type %u and size %u from peer `%4s'\n",
                  ntohs (em->type), 
		  ntohs (em->size),
		  GNUNET_i2s (&ntm->peer));
#endif
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &ntm->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      if ((GNUNET_NO == h->inbound_hdr_only) &&
          (msize != ntohs (em->size) + sizeof (struct NotifyTrafficMessage) + 
	   + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      et = ntohs (em->type);
      for (hpos = 0; hpos < h->hcnt; hpos++)
        {
          mh = &h->handlers[hpos];
          if (mh->type != et)
            continue;
          if ((mh->expected_size != ntohs (em->size)) &&
              (mh->expected_size != 0))
            {
              GNUNET_break (0);
              continue;
            }
          if (GNUNET_OK !=
              h->handlers[hpos].callback (h->cls, &ntm->peer, em,
					  &ntm->ats))
            {
              /* error in processing, do not process other messages! */
              break;
            }
        }
      if (NULL != h->inbound_notify)
        h->inbound_notify (h->cls, &ntm->peer, em,
			   &ntm->ats);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND:
      if (msize < sizeof (struct NotifyTrafficMessage))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      ntm = (const struct NotifyTrafficMessage *) msg;
      if (0 == memcmp (&h->me,
		       &ntm->peer,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* self-change!? */
	  GNUNET_break (0);
	  return;
	}
      ats_count = ntohl (ntm->ats_count);
      if ( (msize < sizeof (struct NotifyTrafficMessage) + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)
	    + sizeof (struct GNUNET_MessageHeader)) ||
	   (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR != ntohl ((&ntm->ats)[ats_count].type)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      em = (const struct GNUNET_MessageHeader *) &(&ntm->ats)[ats_count+1];
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &ntm->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about transmission to `%s'.\n",
		  GNUNET_i2s (&ntm->peer));
#endif
      if ((GNUNET_NO == h->outbound_hdr_only) &&
          (msize != ntohs (em->size) + sizeof (struct NotifyTrafficMessage) 
	   + ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)) )
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      if (NULL == h->outbound_notify)
        {
          GNUNET_break (0);
          break;
        }
      h->outbound_notify (h->cls, &ntm->peer, em,
			  &ntm->ats);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_SEND_READY:
      if (msize != sizeof (struct SendMessageReady))
        {
          GNUNET_break (0);
	  reconnect_later (h);
	  return;
        }
      smr = (const struct SendMessageReady *) msg;
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &smr->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about transmission readiness to `%s'.\n",
		  GNUNET_i2s (&smr->peer));
#endif
      if (pr->pending_head == NULL)
        {
	  /* request must have been cancelled between the original request
	     and the response from core, ignore core's readiness */
          break;
        }

      th = pr->pending_head;
      if (ntohs (smr->smr_id) != th->smr_id)
	{
	  /* READY message is for expired or cancelled message,
	     ignore! (we should have already sent another request) */
	  break;
	}
      if ( (pr->prev != NULL) ||
	   (pr->next != NULL) ||
	   (h->ready_peer_head == pr) )
	{
	  /* we should not already be on the ready list... */
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      GNUNET_CONTAINER_DLL_insert (h->ready_peer_head,
				   h->ready_peer_tail,
				   pr);
      trigger_next_request (h, GNUNET_NO);
      break;
    case GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO:
      if (ntohs (msg->size) != sizeof (struct ConfigurationInfoMessage))
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      cim = (const struct ConfigurationInfoMessage*) msg;
      if (0 == memcmp (&h->me,
		       &cim->peer,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  /* self-change!? */
	  GNUNET_break (0);
	  return;
	}
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received notification about configuration update for `%s' with RIM %u.\n",
		  GNUNET_i2s (&cim->peer),
		  (unsigned int) ntohl (cim->rim_id));
#endif
      pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					      &cim->peer.hashPubKey);
      if (pr == NULL)
	{
	  GNUNET_break (0);
	  reconnect_later (h);
	  return;
	}
      if (pr->rim_id != ntohl (cim->rim_id))
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Reservation ID mismatch in notification...\n");
#endif
	  break;
	}
      pcic = pr->pcic;
      pr->pcic = NULL;
      GNUNET_free_non_null (pr->pcic_ptr);
      pr->pcic_ptr = NULL;
      if (pcic != NULL)
	pcic (pr->pcic_cls,
	      &pr->peer,
	      cim->bw_out,
	      ntohl (cim->reserved_amount),
	      GNUNET_TIME_relative_ntoh (cim->reserve_delay),
	      GNUNET_ntohll (cim->preference));
      break;
    default:
      reconnect_later (h);
      return;
    }
  GNUNET_CLIENT_receive (h->client,
			 &main_notify_handler, h, 
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Task executed once we are done transmitting the INIT message.
 * Starts our 'receive' loop.
 *
 * @param cls the 'struct GNUNET_CORE_Handle'
 * @param success were we successful
 */
static void
init_done_task (void *cls, 
		int success)
{
  struct GNUNET_CORE_Handle *h = cls;

  if (success == GNUNET_SYSERR)
    return; /* shutdown */
  if (success == GNUNET_NO)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Failed to exchange INIT with core, retrying\n");
#endif
      if (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK)
	reconnect_later (h);
      return;
    }
  GNUNET_CLIENT_receive (h->client,
                         &main_notify_handler, 
			 h, 
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Our current client connection went down.  Clean it up
 * and try to reconnect!
 *
 * @param h our handle to the core service
 */
static void
reconnect (struct GNUNET_CORE_Handle *h)
{
  struct ControlMessage *cm;
  struct InitMessage *init;
  uint32_t opt;
  uint16_t msize;
  uint16_t *ts;
  unsigned int hpos;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Reconnecting to CORE service\n");
#endif
  GNUNET_assert (h->client == NULL);
  GNUNET_assert (h->currently_down == GNUNET_YES);
  h->client = GNUNET_CLIENT_connect ("core", h->cfg);
  if (h->client == NULL)
    {
      reconnect_later (h);
      return;
    }
  msize = h->hcnt * sizeof (uint16_t) + sizeof (struct InitMessage);
  cm = GNUNET_malloc (sizeof (struct ControlMessage) +
		      msize);
  cm->cont = &init_done_task;
  cm->cont_cls = h;
  init = (struct InitMessage*) &cm[1];
  init->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_INIT);
  init->header.size = htons (msize);
  opt = GNUNET_CORE_OPTION_SEND_CONNECT | GNUNET_CORE_OPTION_SEND_DISCONNECT;
  if (h->status_events != NULL)
    opt |= GNUNET_CORE_OPTION_SEND_STATUS_CHANGE;
  if (h->inbound_notify != NULL)
    {
      if (h->inbound_hdr_only)
        opt |= GNUNET_CORE_OPTION_SEND_HDR_INBOUND;
      else
        opt |= GNUNET_CORE_OPTION_SEND_FULL_INBOUND;
    }
  if (h->outbound_notify != NULL)
    {
      if (h->outbound_hdr_only)
        opt |= GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND;
      else
        opt |= GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND;
    }
  init->options = htonl (opt);
  ts = (uint16_t *) &init[1];
  for (hpos = 0; hpos < h->hcnt; hpos++)
    ts[hpos] = htons (h->handlers[hpos].type);
  GNUNET_CONTAINER_DLL_insert (h->control_pending_head,
			       h->control_pending_tail,
			       cm);
  trigger_next_request (h, GNUNET_YES);
}



/**
 * Connect to the core service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param queue_size size of the per-peer message queue
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call on timeout or once we have successfully
 *        connected to the core service; note that timeout is only meaningful if init is not NULL
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param status_events function to call on changes to peer connection status, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 * @param inbound_hdr_only set to GNUNET_YES if inbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if inbound_notify is NULLL
 * @param outbound_notify function to call for all outbound messages, can be NULL
 * @param outbound_hdr_only set to GNUNET_YES if outbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if outbound_notify is NULLL
 * @param handlers callbacks for messages we care about, NULL-terminated
 * @return handle to the core service (only useful for disconnect until 'init' is called);
 *                NULL on error (in this case, init is never called)
 */
struct GNUNET_CORE_Handle *
GNUNET_CORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     unsigned int queue_size,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ConnectEventHandler connects,
                     GNUNET_CORE_DisconnectEventHandler disconnects,
		     GNUNET_CORE_PeerStatusEventHandler status_events,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers)
{
  struct GNUNET_CORE_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_Handle));
  h->cfg = cfg;
  h->queue_size = queue_size;
  h->cls = cls;
  h->init = init;
  h->connects = connects;
  h->disconnects = disconnects;
  h->status_events = status_events;
  h->inbound_notify = inbound_notify;
  h->outbound_notify = outbound_notify;
  h->inbound_hdr_only = inbound_hdr_only;
  h->outbound_hdr_only = outbound_hdr_only;
  h->handlers = handlers;
  h->hcnt = 0;
  h->currently_down = GNUNET_YES;
  h->peers = GNUNET_CONTAINER_multihashmap_create (128);
  h->retry_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  while (handlers[h->hcnt].callback != NULL)
    h->hcnt++;
  GNUNET_assert (h->hcnt <
                 (GNUNET_SERVER_MAX_MESSAGE_SIZE -
                  sizeof (struct InitMessage)) / sizeof (uint16_t));
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connecting to CORE service\n");
#endif
  reconnect (h);
  return h;
}


/**
 * Disconnect from the core service.  This function can only 
 * be called *after* all pending 'GNUNET_CORE_notify_transmit_ready'
 * requests have been explicitly canceled.
 *
 * @param handle connection to core to disconnect
 */
void
GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle)
{
  struct ControlMessage *cm;
  
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting from CORE service\n");
#endif
  if (handle->cth != NULL)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (handle->cth);
      handle->cth = NULL;
    }
  if (handle->client != NULL)
    {
      GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
      handle->client = NULL;
    }
  while (NULL != (cm = handle->control_pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (handle->control_pending_head,
				   handle->control_pending_tail,
				   cm);
      if (cm->th != NULL)
	cm->th->cm = NULL;
      if (cm->cont != NULL)
	cm->cont (cm->cont_cls, GNUNET_SYSERR);
      GNUNET_free (cm);
    }
  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (handle->reconnect_task);
      handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_CONTAINER_multihashmap_iterate (handle->peers,
					 &disconnect_and_free_peer_entry,
					 handle);
  GNUNET_CONTAINER_multihashmap_destroy (handle->peers);
  GNUNET_break (handle->ready_peer_head == NULL);
  GNUNET_free (handle);
}


/**
 * Ask the core to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".    Must only be
 * called after a connection to the respective peer has been
 * established (and the client has been informed about this).
 *
 * @param handle connection to core service
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target who should receive the message,
 *        use NULL for this peer (loopback)
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *
GNUNET_CORE_notify_transmit_ready (struct GNUNET_CORE_Handle *handle,
				   int cork,
                                   uint32_t priority,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   const struct GNUNET_PeerIdentity *target,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  struct PeerRecord *pr;
  struct GNUNET_CORE_TransmitHandle *th;
  struct GNUNET_CORE_TransmitHandle *pos;
  struct GNUNET_CORE_TransmitHandle *prev;
  struct GNUNET_CORE_TransmitHandle *minp;

  pr = GNUNET_CONTAINER_multihashmap_get (handle->peers,
					  &target->hashPubKey);
  if (NULL == pr)
    {
      /* attempt to send to peer that is not connected */
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                 "Attempting to send to peer `%s' from peer `%s', but not connected!\n",
                 GNUNET_i2s(target), GNUNET_h2s(&handle->me.hashPubKey));
      GNUNET_break (0);
      return NULL;
    }
  GNUNET_assert (notify_size + sizeof (struct SendMessage) <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
  th = GNUNET_malloc (sizeof (struct GNUNET_CORE_TransmitHandle));
  th->peer = pr;
  GNUNET_assert(NULL != notify);
  th->get_message = notify;
  th->get_message_cls = notify_cls;
  th->timeout = GNUNET_TIME_relative_to_absolute (maxdelay);
  th->priority = priority;
  th->msize = notify_size;
  th->cork = cork;
  /* bound queue size */
  if (pr->queue_size == handle->queue_size)
    {
      /* find lowest-priority entry, but skip the head of the list */
      minp = pr->pending_head->next;
      prev = minp;
      while (prev != NULL)
	{
	  if (prev->priority < minp->priority)
	    minp = prev;
	  prev = prev->next;
	}
      if (minp == NULL) 
	{
	  GNUNET_break (handle->queue_size != 0);
	  GNUNET_break (pr->queue_size == 1);
	  GNUNET_free(th);
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Dropping transmission request: cannot drop queue head and limit is one\n");
#endif
	  return NULL;
	}
      if (priority <= minp->priority)
	{
#if DEBUG_CORE
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Dropping transmission request: priority too low\n");
#endif
	  GNUNET_free(th);
	  return NULL; /* priority too low */
	}
      GNUNET_CONTAINER_DLL_remove (pr->pending_head,
				   pr->pending_tail,
				   minp);
      pr->queue_size--;
      GNUNET_assert (0 ==
		     minp->get_message (minp->get_message_cls,
					0, NULL));
      GNUNET_free (minp);
    }

  /* Order entries by deadline, but SKIP 'HEAD' if
     we're in the 'ready_peer_*' DLL */
  pos = pr->pending_head;
  if ( (pr->prev != NULL) ||
       (pr->next != NULL) ||
       (pr == handle->ready_peer_head) )
    {
      GNUNET_assert (pos != NULL);
      pos = pos->next; /* skip head */
    }

  /* insertion sort */
  prev = pos;
  while ( (pos != NULL) &&
	  (pos->timeout.abs_value < th->timeout.abs_value) )	  
    {
      prev = pos;
      pos = pos->next;
    }
  GNUNET_CONTAINER_DLL_insert_after (pr->pending_head,
				     pr->pending_tail,
				     prev,
				     th);
  pr->queue_size++;
  /* was the request queue previously empty? */
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmission request added to queue\n");
#endif
  if (pr->pending_head == th) 
    request_next_transmission (pr);
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *th)
{
  struct PeerRecord *pr = th->peer;
  struct GNUNET_CORE_Handle *h = pr->ch;
  int was_head;
  
  was_head = (pr->pending_head == th);
  GNUNET_CONTAINER_DLL_remove (pr->pending_head,
			       pr->pending_tail,
			       th);    
  pr->queue_size--;
  if (th->cm != NULL)
    {
      /* we're currently in the control queue, remove */
      GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
				   h->control_pending_tail,
				   th->cm);
      GNUNET_free (th->cm);      
    }
  GNUNET_free (th);
  if (was_head)
    {
      if ( (pr->prev != NULL) ||
	   (pr->next != NULL) ||
	   (pr == h->ready_peer_head) )
	{
	  /* the request that was 'approved' by core was
	     canceled before it could be transmitted; remove
	     us from the 'ready' list */
	  GNUNET_CONTAINER_DLL_remove (h->ready_peer_head,
				       h->ready_peer_tail,
				       pr);
	}
      request_next_transmission (pr);
    }
}


/* ****************** GNUNET_CORE_peer_request_connect ******************** */

/**
 * Handle for a request to the core to connect to
 * a particular peer.  Can be used to cancel the request
 * (before the 'cont'inuation is called).
 */
struct GNUNET_CORE_PeerRequestHandle
{

  /**
   * Link to control message.
   */
  struct ControlMessage *cm;

  /**
   * Core handle used.
   */
  struct GNUNET_CORE_Handle *h;

  /**
   * Continuation to run when done.
   */
  GNUNET_CORE_ControlContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

};


/**
 * Continuation called when the control message was transmitted.
 * Calls the original continuation and frees the remaining
 * resources.
 *
 * @param cls the 'struct GNUNET_CORE_PeerRequestHandle'
 * @param success was the request transmitted?
 */
static void
peer_request_connect_cont (void *cls,
			   int success)
{
  struct GNUNET_CORE_PeerRequestHandle *ret = cls;
  
  if (ret->cont != NULL)
    ret->cont (ret->cont_cls, success);    
  GNUNET_free (ret);
}


/**
 * Request that the core should try to connect to a particular peer.
 * Once the request has been transmitted to the core, the continuation
 * function will be called.  Note that this does NOT mean that a
 * connection was successfully established -- it only means that the
 * core will now try.  Successful establishment of the connection
 * will be signalled to the 'connects' callback argument of
 * 'GNUNET_CORE_connect' only.  If the core service does not respond
 * to our connection attempt within the given time frame, 'cont' will
 * be called with the TIMEOUT reason code.
 *
 * @param h core handle
 * @param timeout how long to try to talk to core
 * @param peer who should we connect to
 * @param cont function to call once the request has been completed (or timed out)
 * @param cont_cls closure for cont
 *
 * @return NULL on error or already connected,
 *         otherwise handle for cancellation
 */
struct GNUNET_CORE_PeerRequestHandle *
GNUNET_CORE_peer_request_connect (struct GNUNET_CORE_Handle *h,
				  struct GNUNET_TIME_Relative timeout,
				  const struct GNUNET_PeerIdentity * peer,
				  GNUNET_CORE_ControlContinuation cont,
				  void *cont_cls)
{
  struct GNUNET_CORE_PeerRequestHandle *ret;
  struct ControlMessage *cm;
  struct ConnectMessage *msg;

  if (NULL != GNUNET_CONTAINER_multihashmap_get (h->peers,
                                          &peer->hashPubKey))
    {
#if DEBUG_CORE
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
		 "Peers are already connected!\n");
#endif
      return NULL;
    }
  
  cm = GNUNET_malloc (sizeof (struct ControlMessage) + 
		      sizeof (struct ConnectMessage));
  msg = (struct ConnectMessage*) &cm[1];
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT);
  msg->header.size = htons (sizeof (struct ConnectMessage));
  msg->reserved = htonl (0);
  msg->timeout = GNUNET_TIME_relative_hton (timeout);
  msg->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
				    h->control_pending_tail,
				    cm);
  ret = GNUNET_malloc (sizeof (struct GNUNET_CORE_PeerRequestHandle));
  ret->h = h;
  ret->cm = cm;
  ret->cont = cont;
  ret->cont_cls = cont_cls;
  cm->cont = &peer_request_connect_cont;
  cm->cont_cls = ret;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Queueing REQUEST_CONNECT request\n");
#endif
  trigger_next_request (h, GNUNET_NO);
  return ret;
}


/**
 * Cancel a pending request to connect to a particular peer.  Must not
 * be called after the 'cont' function was invoked.
 *
 * @param req request handle that was returned for the original request
 */
void
GNUNET_CORE_peer_request_connect_cancel (struct GNUNET_CORE_PeerRequestHandle *req)
{
  struct GNUNET_CORE_Handle *h = req->h;
  struct ControlMessage *cm = req->cm;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "A CHANGE PREFERENCE request was cancelled!\n");
#endif
  GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
			       h->control_pending_tail,
			       cm);
  GNUNET_free (cm);
  GNUNET_free (req);
}


/* ****************** GNUNET_CORE_peer_change_preference ******************** */


struct GNUNET_CORE_InformationRequestContext 
{
  
  /**
   * Our connection to the service.
   */
  struct GNUNET_CORE_Handle *h;

  /**
   * Link to control message, NULL if CM was sent.
   */ 
  struct ControlMessage *cm;

  /**
   * Link to peer record.
   */
  struct PeerRecord *pr;
};


/**
 * CM was sent, remove link so we don't double-free.
 *
 * @param cls the 'struct GNUNET_CORE_InformationRequestContext'
 * @param success were we successful?
 */
static void
change_preference_send_continuation (void *cls,
				     int success)
{
  struct GNUNET_CORE_InformationRequestContext *irc = cls;

  irc->cm = NULL;
}


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param h core handle
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bw_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bw_out" to "-1" to avoid changing
 *                the current value; otherwise "bw_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bw_out" might not increase
 *                as specified since the upper bound is generally
 *                determined by the other peer!
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 * @return NULL on error
 */
struct GNUNET_CORE_InformationRequestContext *
GNUNET_CORE_peer_change_preference (struct GNUNET_CORE_Handle *h,
				    const struct GNUNET_PeerIdentity *peer,
				    struct GNUNET_TIME_Relative timeout,
				    struct GNUNET_BANDWIDTH_Value32NBO bw_out,
				    int32_t amount,
				    uint64_t preference,
				    GNUNET_CORE_PeerConfigurationInfoCallback info,
				    void *info_cls)
{
  struct GNUNET_CORE_InformationRequestContext *irc;
  struct PeerRecord *pr;
  struct RequestInfoMessage *rim;
  struct ControlMessage *cm;

  pr = GNUNET_CONTAINER_multihashmap_get (h->peers,
					  &peer->hashPubKey);
  if (NULL == pr)
    {
      /* attempt to change preference on peer that is not connected */
      GNUNET_break (0);
      return NULL;
    }
  if (pr->pcic != NULL)
    {
      /* second change before first one is done */
      GNUNET_break (0);
      return NULL;
    }
  irc = GNUNET_malloc (sizeof (struct GNUNET_CORE_InformationRequestContext));
  irc->h = h;
  irc->pr = pr;
  cm = GNUNET_malloc (sizeof (struct ControlMessage) +
		      sizeof (struct RequestInfoMessage));
  cm->cont = &change_preference_send_continuation;
  cm->cont_cls = irc;
  irc->cm = cm;
  rim = (struct RequestInfoMessage*) &cm[1];
  rim->header.size = htons (sizeof (struct RequestInfoMessage));
  rim->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO);
  rim->rim_id = htonl (pr->rim_id = h->rim_id_gen++);
  rim->limit_outbound = bw_out;
  rim->reserve_inbound = htonl (amount);
  rim->preference_change = GNUNET_htonll(preference);
  rim->peer = *peer;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Queueing CHANGE PREFERENCE request for peer `%s' with RIM %u\n",
	      GNUNET_i2s (peer),
	      (unsigned int) pr->rim_id);
#endif
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
				    h->control_pending_tail,
				    cm); 
  pr->pcic = info;
  pr->pcic_cls = info_cls;
  pr->pcic_ptr = irc; /* for free'ing irc */
  trigger_next_request (h, GNUNET_NO);
  return irc;
}


/**
 * Cancel request for getting information about a peer.
 * Note that an eventual change in preference, trust or bandwidth
 * assignment MAY have already been committed at the time, 
 * so cancelling a request is NOT sure to undo the original
 * request.  The original request may or may not still commit.
 * The only thing cancellation ensures is that the callback
 * from the original request will no longer be called.
 *
 * @param irc context returned by the original GNUNET_CORE_peer_get_info call
 */
void
GNUNET_CORE_peer_change_preference_cancel (struct GNUNET_CORE_InformationRequestContext *irc)
{
  struct GNUNET_CORE_Handle *h = irc->h;
  struct PeerRecord *pr = irc->pr;

  GNUNET_assert (pr->pcic_ptr == irc);
  if (irc->cm != NULL)
    {
      GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
				   h->control_pending_tail,
				   irc->cm);
      GNUNET_free (irc->cm);
    }
  pr->pcic = NULL;
  pr->pcic_cls = NULL;
  pr->pcic_ptr = NULL;
  GNUNET_free (irc);
}


/* end of core_api.c */
