/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/peerinfo_api.c
 * @brief API to access peerinfo service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_time_lib.h"
#include "peerinfo.h"

#define LOG(kind,...) GNUNET_log_from (kind, "peerinfo-api",__VA_ARGS__)


/**
 * Entry in the transmission queue to PEERINFO service.  We use
 * the same structure for queueing 'iteration' requests and
 * actual 'add' messages.
 */
struct GNUNET_PEERINFO_AddContext
{
  /**
   * This is a linked list.
   */
  struct GNUNET_PEERINFO_AddContext *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_PEERINFO_AddContext *prev;

  /**
   * Handle to the PEERINFO service.
   */
  struct GNUNET_PEERINFO_Handle *h;

  /**
   * Function to call after request has been transmitted, or NULL.
   */
  GNUNET_PEERINFO_Continuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Number of bytes of the request message (follows after this struct).
   */
  size_t size;

};


/**
 * Context for an iteration request.
 */
struct GNUNET_PEERINFO_IteratorContext
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERINFO_IteratorContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERINFO_IteratorContext *prev;

  /**
   * Handle to the PEERINFO service.
   */
  struct GNUNET_PEERINFO_Handle *h;

  /**
   * Function to call with the results.
   */
  GNUNET_PEERINFO_Processor callback;

  /**
   * Closure for 'callback'.
   */
  void *callback_cls;

  /**
   * Our entry in the transmission queue.
   */
  struct GNUNET_PEERINFO_AddContext *ac;

  /**
   * Task responsible for timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Peer we are interested in (only valid if iteration was restricted to one peer).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Is 'peer' set?
   */
  int have_peer;

  /**
   * Are we now receiving?
   */
  int in_receive;
};


/**
 * Handle to the peerinfo service.
 */
struct GNUNET_PEERINFO_Handle
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of transmission queue.
   */
  struct GNUNET_PEERINFO_AddContext *ac_head;

  /**
   * Tail of transmission queue.
   */
  struct GNUNET_PEERINFO_AddContext *ac_tail;

  /**
   * Handle for the current transmission request, or NULL if none is pending.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of iterator DLL.
   */
  struct GNUNET_PEERINFO_IteratorContext *ic_head;

  /**
   * Tail of iterator DLL.
   */
  struct GNUNET_PEERINFO_IteratorContext *ic_tail;

  /**
   * ID for a reconnect task.
   */
  GNUNET_SCHEDULER_TaskIdentifier r_task;

  /**
   * Set to GNUNET_YES if we are currently receiving replies from the
   * service.
   */
  int in_receive;

};


/**
 * Connect to the peerinfo service.
 *
 * @param cfg configuration to use
 * @return NULL on error (configuration related, actual connection
 *         establishment may happen asynchronously).
 */
struct GNUNET_PEERINFO_Handle *
GNUNET_PEERINFO_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PEERINFO_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_Handle));
  h->client = GNUNET_CLIENT_connect ("peerinfo", cfg);
  h->cfg = cfg;
  return h;
}


/**
 * Disconnect from the peerinfo service.  Note that all iterators must
 * have completed or have been cancelled by the time this function is
 * called (otherwise, calling this function is a serious error).
 * Furthermore, if 'GNUNET_PEERINFO_add_peer' operations are still
 * pending, they will be cancelled silently on disconnect.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERINFO_disconnect (struct GNUNET_PEERINFO_Handle *h)
{
  struct GNUNET_PEERINFO_AddContext *ac;
  struct GNUNET_PEERINFO_IteratorContext *ic;

  while (NULL != (ic = h->ic_head))
  {
    GNUNET_break (GNUNET_YES == ic->in_receive);
    ic->in_receive = GNUNET_NO;
    GNUNET_PEERINFO_iterate_cancel (ic);
  }
  while (NULL != (ac = h->ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->ac_head, h->ac_tail, ac);
    if (NULL != ac->cont)
      ac->cont (ac->cont_cls, _("aborted due to explicit disconnect request"));
    GNUNET_free (ac);
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (h);
}


/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_PEERINFO_Handle *h);


/**
 * Close the existing connection to PEERINFO and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERINFO_Handle *h);


/**
 * Task scheduled to re-try connecting to the peerinfo service.
 *
 * @param cls the 'struct GNUNET_PEERINFO_Handle'
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PEERINFO_Handle *h = cls;

  h->r_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
}


/**
 * Close the existing connection to PEERINFO and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERINFO_Handle *h)
{
  if (GNUNET_SCHEDULER_NO_TASK != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->in_receive = GNUNET_NO;
  h->client = GNUNET_CLIENT_connect ("peerinfo", h->cfg);
  if (NULL == h->client)
  {
    h->r_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                      h);
    return;
  }
  trigger_transmit (h);
}


/**
 * Transmit the request at the head of the transmission queue
 * and trigger continuation (if any).
 *
 * @param cls the 'struct GNUNET_PEERINFO_Handle' (with the queue)
 * @param size size of the buffer (0 on error)
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
do_transmit (void *cls, size_t size, void *buf)
{
  struct GNUNET_PEERINFO_Handle *h = cls;
  struct GNUNET_PEERINFO_AddContext *ac = h->ac_head;
  size_t ret;

  h->th = NULL;
  if (NULL == ac)
    return 0; /* request was cancelled in the meantime */
  if (NULL == buf)
  {
    /* peerinfo service died */
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Failed to transmit message to `%s' service.\n", "PEERINFO");
    GNUNET_CONTAINER_DLL_remove (h->ac_head, h->ac_tail, ac);
    reconnect (h);
    if (NULL != ac->cont)
      ac->cont (ac->cont_cls, _("failed to transmit request (service down?)"));
    GNUNET_free (ac);
    return 0;
  }
  ret = ac->size;
  if (size < ret)
  {
    /* change in head of queue (i.e. cancel + add), try again */
    trigger_transmit (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting request of size %u to `%s' service.\n", ret, "PEERINFO");
  memcpy (buf, &ac[1], ret);
  GNUNET_CONTAINER_DLL_remove (h->ac_head, h->ac_tail, ac);
  trigger_transmit (h);
  if (NULL != ac->cont)
    ac->cont (ac->cont_cls, NULL);
  GNUNET_free (ac);
  return ret;
}


/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_PEERINFO_Handle *h)
{
  struct GNUNET_PEERINFO_AddContext *ac;

  if (NULL == (ac = h->ac_head))
    return; /* no requests queued */
  if (NULL != h->th)
    return; /* request already pending */
  if (GNUNET_YES == h->in_receive)
    return; /* still reading replies from last request */
  if (NULL == h->client)
  {
    /* disconnected, try to reconnect */
    reconnect (h);
    return;
  }
  h->th =
    GNUNET_CLIENT_notify_transmit_ready (h->client, ac->size,
					 GNUNET_TIME_UNIT_FOREVER_REL,
					 GNUNET_YES,
					 &do_transmit, h);
}


/**
 * Add a host to the persistent list.  This method operates in
 * semi-reliable mode: if the transmission is not completed by
 * the time 'GNUNET_PEERINFO_disconnect' is called, it will be
 * aborted.  Furthermore, if a second HELLO is added for the
 * same peer before the first one was transmitted, PEERINFO may
 * merge the two HELLOs prior to transmission to the service.
 *
 * @param h handle to the peerinfo service
 * @param hello the verified (!) HELLO message
 * @param cont continuation to call when done, NULL is allowed
 * @param cont_cls closure for 'cont'
 * @return handle to cancel add operation; all pending
 *         'add' operations will be cancelled automatically
 *        on disconnect, so it is not necessary to keep this
 *        handle (unless 'cont' is NULL and at some point
 *        calling 'cont' must be prevented)
 */
struct GNUNET_PEERINFO_AddContext *
GNUNET_PEERINFO_add_peer (struct GNUNET_PEERINFO_Handle *h,
                          const struct GNUNET_HELLO_Message *hello,
			  GNUNET_PEERINFO_Continuation cont,
			  void *cont_cls)
{
  uint16_t hs = GNUNET_HELLO_size (hello);
  struct GNUNET_PEERINFO_AddContext *ac;
  struct GNUNET_PeerIdentity peer;

  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_id (hello, &peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding peer `%s' to PEERINFO database (%u bytes of `%s')\n",
       GNUNET_i2s (&peer), hs, "HELLO");
  ac = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_AddContext) + hs);
  ac->h = h;
  ac->size = hs;
  ac->cont = cont;
  ac->cont_cls = cont_cls;
  memcpy (&ac[1], hello, hs);
  GNUNET_CONTAINER_DLL_insert_tail (h->ac_head, h->ac_tail, ac);
  trigger_transmit (h);
  return ac;
}


/**
 * Cancel pending 'add' operation.  Must only be called before
 * either 'cont' or 'GNUNET_PEERINFO_disconnect' are invoked.
 *
 * @param ac handle for the add operation to cancel
 */
void 
GNUNET_PEERINFO_add_peer_cancel (struct GNUNET_PEERINFO_AddContext *ac)
{
  struct GNUNET_PEERINFO_Handle *h = ac->h;

  GNUNET_CONTAINER_DLL_remove (h->ac_head, h->ac_tail, ac);
  GNUNET_free (ac);
}


/**
 * Type of a function to call when we receive a message from the
 * service.  Call the iterator with the result and (if applicable)
 * continue to receive more messages or trigger processing the next
 * event (if applicable).
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
peerinfo_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERINFO_Handle *h = cls;
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  GNUNET_PEERINFO_Processor cb;
  struct GNUNET_PeerIdentity id;
  void *cb_cls;
  uint16_t ms;

  GNUNET_assert (NULL != ic);
  h->in_receive = GNUNET_NO;
  ic->in_receive = GNUNET_NO;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  if (NULL == msg)
  {
    /* peerinfo service died, signal error */
    GNUNET_PEERINFO_iterate_cancel (ic);
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, NULL,
	  _("Failed to receive response from `PEERINFO' service."));
    return;
  }

  if (GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END == ntohs (msg->type))
  {
    /* normal end of list of peers, signal end, process next pending request */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received end of list of peers from `%s' service\n", "PEERINFO");
    GNUNET_PEERINFO_iterate_cancel (ic);   
    trigger_transmit (h);
    if (NULL != cb)
      cb (cb_cls, NULL, NULL, NULL);
    return;
  }

  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
  {
    /* malformed message */
    GNUNET_break (0);
    GNUNET_PEERINFO_iterate_cancel (ic);
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, NULL,
	  _("Received invalid message from `PEERINFO' service."));
    return;
  }
  im = (const struct InfoMessage *) msg;
  GNUNET_break (0 == ntohl (im->reserved));
  if ( (GNUNET_YES == ic->have_peer) &&
       (0 != memcmp (&ic->peer, &im->peer, sizeof (struct GNUNET_PeerIdentity))) )
  {
    /* bogus message (from a different iteration call?); out of sequence! */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Received HELLO for peer `%s', expected peer `%s'\n",
	 GNUNET_h2s (&im->peer.hashPubKey),
	 GNUNET_i2s (&ic->peer));
    
    GNUNET_break (0);
    GNUNET_PEERINFO_iterate_cancel (ic);
    reconnect (h);
    if (NULL != cb)      
      cb (cb_cls, NULL, NULL,
	  _("Received invalid message from `PEERINFO' service."));
    return;
  }
  hello = NULL;
  if (ms > sizeof (struct InfoMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    hello = (const struct GNUNET_HELLO_Message *) &im[1];
    if (ms != sizeof (struct InfoMessage) + GNUNET_HELLO_size (hello))
    {
      /* malformed message */
      GNUNET_break (0);
      GNUNET_PEERINFO_iterate_cancel (ic);
      reconnect (h);
      if (NULL != cb)      
        cb (cb_cls, NULL, NULL,
	    _("Received invalid message from `PEERINFO' service."));
      return;
    }
    if (GNUNET_OK != GNUNET_HELLO_get_id (hello, &id))
    {
      /* malformed message */
      GNUNET_break (0);
      GNUNET_PEERINFO_iterate_cancel (ic);
      reconnect (h);
      if (NULL != cb)      
        cb (cb_cls, NULL, NULL,
	    _("Received invalid message from `PEERINFO' service."));
      return;
    }
    if (0 != memcmp (&im->peer, &id, sizeof (struct GNUNET_PeerIdentity)))
    {
      /* malformed message */
      GNUNET_break (0);
      GNUNET_PEERINFO_iterate_cancel (ic);
      reconnect (h);
      if (NULL != cb)      
        cb (cb_cls, NULL, NULL,
	    _("Received invalid message from `PEERINFO' service."));
      return;
    }
  }

  /* normal data message */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u bytes of `%s' information about peer `%s' from `%s' service\n",
       (hello == NULL) ? 0 : (unsigned int) GNUNET_HELLO_size (hello), "HELLO",
       GNUNET_i2s (&im->peer), "PEERINFO");
  h->in_receive = GNUNET_YES;
  ic->in_receive = GNUNET_YES;
  GNUNET_CLIENT_receive (h->client, &peerinfo_handler, h,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
  if (NULL != cb)
    cb (cb_cls, &im->peer, hello, NULL);
}


/**
 * We've transmitted the iteration request.  Now get ready to process
 * the results (or handle transmission error).
 *
 * @param cls the 'struct GNUNET_PEERINFO_IteratorContext'
 * @param emsg error message, NULL if transmission worked
 */
static void
iterator_start_receive (void *cls, const char *emsg)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = cls;
  struct GNUNET_PEERINFO_Handle *h = ic->h;
  GNUNET_PEERINFO_Processor cb;
  void *cb_cls;

  ic->ac = NULL;
  if (NULL != emsg)
  {
    cb = ic->callback;
    cb_cls = ic->callback_cls;
    GNUNET_PEERINFO_iterate_cancel (ic);
    reconnect (h);
    if (NULL != cb)
      cb (cb_cls, NULL, NULL, emsg);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Waiting for response from `%s' service.\n",
       "PEERINFO");
  ic->in_receive = GNUNET_YES;
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &peerinfo_handler, h,
			   GNUNET_TIME_absolute_get_remaining (ic->timeout));
  }
}


/**
 * Peerinfo iteration request has timed out.
 *
 * @param cls the 'struct GNUNET_PEERINFO_IteratorContext*'
 * @param tc scheduler context
 */
static void
signal_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = cls;
  GNUNET_PEERINFO_Processor cb;
  void *cb_cls;

  ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cb = ic->callback;
  cb_cls = ic->callback_cls;
  GNUNET_PEERINFO_iterate_cancel (ic);
  if (NULL != cb)
    cb (cb_cls, NULL, NULL,
	_("Timeout transmitting iteration request to `PEERINFO' service."));
}


/**
 * Call a method for each known matching host and change its trust
 * value.  The callback method will be invoked once for each matching
 * host and then finally once with a NULL pointer.  After that final
 * invocation, the iterator context must no longer be used.
 *
 * Instead of calling this function with 'peer == NULL' it is often
 * better to use 'GNUNET_PEERINFO_notify'.
 *
 * @param h handle to the peerinfo service
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate (struct GNUNET_PEERINFO_Handle *h,
                         const struct GNUNET_PeerIdentity *peer,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_PEERINFO_Processor callback, void *callback_cls)
{
  struct GNUNET_MessageHeader *lapm;
  struct ListPeerMessage *lpm;
  struct GNUNET_PEERINFO_IteratorContext *ic;
  struct GNUNET_PEERINFO_AddContext *ac;

  ic = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_IteratorContext));
  if (NULL == peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting list of peers from PEERINFO service\n");
    ac =
        GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_AddContext) +
                       sizeof (struct GNUNET_MessageHeader));
    ac->size = sizeof (struct GNUNET_MessageHeader);
    lapm = (struct GNUNET_MessageHeader *) &ac[1];
    lapm->size = htons (sizeof (struct GNUNET_MessageHeader));
    lapm->type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting information on peer `%4s' from PEERINFO service\n",
         GNUNET_i2s (peer));
    ac =
        GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_AddContext) +
                       sizeof (struct ListPeerMessage));
    ac->size = sizeof (struct ListPeerMessage);
    lpm = (struct ListPeerMessage *) &ac[1];
    lpm->header.size = htons (sizeof (struct ListPeerMessage));
    lpm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET);
    memcpy (&lpm->peer, peer, sizeof (struct GNUNET_PeerIdentity));
    ic->have_peer = GNUNET_YES;
    ic->peer = *peer;
  }
  ic->h = h;
  ic->ac = ac;
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &signal_timeout, ic);
  ac->cont = &iterator_start_receive;
  ac->cont_cls = ic;
  GNUNET_CONTAINER_DLL_insert_tail (h->ac_head, h->ac_tail, ac);
  GNUNET_CONTAINER_DLL_insert_tail (h->ic_head,
				    h->ic_tail,
				    ic);
  trigger_transmit (h);
  return ic;
}


/**
 * Cancel an iteration over peer information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_PEERINFO_iterate_cancel (struct GNUNET_PEERINFO_IteratorContext *ic)
{
  struct GNUNET_PEERINFO_Handle *h;

  h = ic->h;
  if (GNUNET_SCHEDULER_NO_TASK != ic->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ic->callback = NULL;
  if (GNUNET_YES == ic->in_receive)
    return;                     /* need to finish processing */
  GNUNET_CONTAINER_DLL_remove (h->ic_head,
			       h->ic_tail,
			       ic);
  if (NULL != ic->ac)
  {
    GNUNET_CONTAINER_DLL_remove (h->ac_head, h->ac_tail, ic->ac);
    GNUNET_free (ic->ac);
  }
  GNUNET_free (ic);
}


/* end of peerinfo_api.c */
