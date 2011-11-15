/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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

#define LOG(kind,...) GNUNET_log_from (kind, "nse-api",__VA_ARGS__)

/**
 * Function to call after transmission has succeeded.
 *
 * @param cls closure
 * @param success GNUNET_OK if transmission worked, GNUNET_SYSERR on error
 */
typedef void (*TransmissionContinuation) (void *cls, int success);


/**
 * Entry in the transmission queue to PEERINFO service.
 */
struct TransmissionQueueEntry
{
  /**
   * This is a linked list.
   */
  struct TransmissionQueueEntry *next;

  /**
   * This is a linked list.
   */
  struct TransmissionQueueEntry *prev;

  /**
   * Function to call after request has been transmitted, or NULL (in which
   * case we must consider sending the next entry immediately).
   */
  TransmissionContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes of the request message (follows after this struct).
   */
  size_t size;

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
  struct TransmissionQueueEntry *tq_head;

  /**
   * Tail of transmission queue.
   */
  struct TransmissionQueueEntry *tq_tail;

  /**
   * Handle for the current transmission request, or NULL if none is pending.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

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
  struct GNUNET_PEERINFO_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_Handle));
  ret->client = GNUNET_CLIENT_connect ("peerinfo", cfg);
  ret->cfg = cfg;
  return ret;
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
  struct TransmissionQueueEntry *tqe;

  while (NULL != (tqe = h->tq_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->tq_head, h->tq_tail, tqe);
    if (tqe->cont != NULL)
      tqe->cont (tqe->cont_cls, GNUNET_SYSERR);
    GNUNET_free (tqe);
  }
  if (h->th != NULL)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
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
  if (h->r_task != GNUNET_SCHEDULER_NO_TASK)
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
    GNUNET_CLIENT_disconnect (h->client, GNUNET_SYSERR);
    h->client = NULL;
  }
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
  struct TransmissionQueueEntry *tqe = h->tq_head;
  size_t ret;

  h->th = NULL;
  if (tqe == NULL)
    return 0;
  if (buf == NULL)
  {
#if DEBUG_PEERINFO
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         _("Failed to transmit message to `%s' service.\n"), "PEERINFO");
#endif
    GNUNET_CONTAINER_DLL_remove (h->tq_head, h->tq_tail, tqe);
    reconnect (h);
    if (tqe->cont != NULL)
      tqe->cont (tqe->cont_cls, GNUNET_SYSERR);
    GNUNET_free (tqe);
    return 0;
  }
  ret = tqe->size;
  GNUNET_assert (size >= ret);
  memcpy (buf, &tqe[1], ret);
#if DEBUG_PEERINFO
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting request of size %u to `%s' service.\n", ret, "PEERINFO");
#endif
  GNUNET_CONTAINER_DLL_remove (h->tq_head, h->tq_tail, tqe);
  if (tqe->cont != NULL)
    tqe->cont (tqe->cont_cls, GNUNET_OK);
  else
    trigger_transmit (h);
  GNUNET_free (tqe);
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
  struct TransmissionQueueEntry *tqe;

  if (NULL == (tqe = h->tq_head))
    return;
  if (h->th != NULL)
    return;
  if (h->in_receive == GNUNET_YES)
    return;
  if (NULL == h->client)
  {
    reconnect (h);
    return;
  }
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client, tqe->size,
                                           GNUNET_TIME_absolute_get_remaining
                                           (tqe->timeout), GNUNET_YES,
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
 */
void
GNUNET_PEERINFO_add_peer (struct GNUNET_PEERINFO_Handle *h,
                          const struct GNUNET_HELLO_Message *hello)
{
  uint16_t hs = GNUNET_HELLO_size (hello);
  struct TransmissionQueueEntry *tqe;

#if DEBUG_PEERINFO
  struct GNUNET_PeerIdentity peer;

  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_id (hello, &peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding peer `%s' to PEERINFO database (%u bytes of `%s')\n",
       GNUNET_i2s (&peer), hs, "HELLO");
#endif
  tqe = GNUNET_malloc (sizeof (struct TransmissionQueueEntry) + hs);
  tqe->size = hs;
  tqe->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  memcpy (&tqe[1], hello, hs);
  GNUNET_CONTAINER_DLL_insert_after (h->tq_head, h->tq_tail, h->tq_tail, tqe);
  trigger_transmit (h);
}


/**
 * Context for an iteration request.
 */
struct GNUNET_PEERINFO_IteratorContext
{
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
  struct TransmissionQueueEntry *tqe;

  /**
   * Task responsible for timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Are we now receiving?
   */
  int in_receive;
};


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
peerinfo_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = cls;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  ic->h->in_receive = GNUNET_NO;
  if (msg == NULL)
  {
    reconnect (ic->h);
    if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (ic->timeout_task);
    if (ic->callback != NULL)
      ic->callback (ic->callback_cls, NULL, NULL,
                    _("Failed to receive response from `PEERINFO' service."));
    GNUNET_free (ic);
    return;
  }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END)
  {
#if DEBUG_PEERINFO
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received end of list of peers from `%s' service\n", "PEERINFO");
#endif
    trigger_transmit (ic->h);
    if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (ic->timeout_task);
    if (ic->callback != NULL)
      ic->callback (ic->callback_cls, NULL, NULL, NULL);
    GNUNET_free (ic);
    return;
  }
  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
  {
    GNUNET_break (0);
    reconnect (ic->h);
    if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (ic->timeout_task);
    if (ic->callback != NULL)
      ic->callback (ic->callback_cls, NULL, NULL,
                    _("Received invalid message from `PEERINFO' service.\n"));
    GNUNET_free (ic);
    return;
  }
  im = (const struct InfoMessage *) msg;
  GNUNET_break (0 == ntohl (im->reserved));
  hello = NULL;
  if (ms > sizeof (struct InfoMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    hello = (const struct GNUNET_HELLO_Message *) &im[1];
    if (ms != sizeof (struct InfoMessage) + GNUNET_HELLO_size (hello))
    {
      GNUNET_break (0);
      reconnect (ic->h);
      if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (ic->timeout_task);
      if (ic->callback != NULL)
        ic->callback (ic->callback_cls, NULL, NULL,
                      _("Received invalid message from `PEERINFO' service.\n"));
      GNUNET_free (ic);
      return;
    }
  }
#if DEBUG_PEERINFO
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u bytes of `%s' information about peer `%s' from `%s' service\n",
       (hello == NULL) ? 0 : (unsigned int) GNUNET_HELLO_size (hello), "HELLO",
       GNUNET_i2s (&im->peer), "PEERINFO");
#endif
  ic->h->in_receive = GNUNET_YES;
  if (ic->callback != NULL)
    ic->callback (ic->callback_cls, &im->peer, hello, NULL);
  GNUNET_CLIENT_receive (ic->h->client, &peerinfo_handler, ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
}


/**
 * We've transmitted the iteration request.  Now get ready to process
 * the results (or handle transmission error).
 *
 * @param cls the 'struct GNUNET_PEERINFO_IteratorContext'
 * @param transmit_success GNUNET_OK if transmission worked
 */
static void
iterator_start_receive (void *cls, int transmit_success)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = cls;

  if (GNUNET_OK != transmit_success)
  {
    if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (ic->timeout_task);
      ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    reconnect (ic->h);
    if (ic->callback != NULL)
      ic->callback (ic->callback_cls, NULL, NULL,
                    _
                    ("Failed to transmit iteration request to `PEERINFO' service\n"));
    GNUNET_free (ic);
    return;
  }
#if DEBUG_PEERINFO
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Waiting for response from `%s' service.\n",
       "PEERINFO");
#endif
  ic->h->in_receive = GNUNET_YES;
  ic->in_receive = GNUNET_YES;
  ic->tqe = NULL;
  GNUNET_CLIENT_receive (ic->h->client, &peerinfo_handler, ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
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

  ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (!ic->in_receive)
    GNUNET_CONTAINER_DLL_remove (ic->h->tq_head, ic->h->tq_tail, ic->tqe);
  else
    reconnect (ic->h);
  ic->callback (ic->callback_cls, NULL, NULL,
                _
                ("Timeout transmitting iteration request to `PEERINFO' service.\n"));
  ic->callback = NULL;
  GNUNET_free_non_null (ic->tqe);
  GNUNET_free (ic);
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
  struct TransmissionQueueEntry *tqe;

  if (peer == NULL)
  {
#if DEBUG_PEERINFO
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting list of peers from PEERINFO service\n");
#endif
    tqe =
        GNUNET_malloc (sizeof (struct TransmissionQueueEntry) +
                       sizeof (struct GNUNET_MessageHeader));
    tqe->size = sizeof (struct GNUNET_MessageHeader);
    lapm = (struct GNUNET_MessageHeader *) &tqe[1];
    lapm->size = htons (sizeof (struct GNUNET_MessageHeader));
    lapm->type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
  }
  else
  {
#if DEBUG_PEERINFO
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting information on peer `%4s' from PEERINFO service\n",
         GNUNET_i2s (peer));
#endif
    tqe =
        GNUNET_malloc (sizeof (struct TransmissionQueueEntry) +
                       sizeof (struct ListPeerMessage));
    tqe->size = sizeof (struct ListPeerMessage);
    lpm = (struct ListPeerMessage *) &tqe[1];
    lpm->header.size = htons (sizeof (struct ListPeerMessage));
    lpm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET);
    memcpy (&lpm->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  }
  ic = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_IteratorContext));
  ic->h = h;
  ic->tqe = tqe;
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &signal_timeout, ic);
  tqe->timeout = ic->timeout;
  tqe->cont = &iterator_start_receive;
  tqe->cont_cls = ic;
  tqe->timeout = ic->timeout;
  GNUNET_CONTAINER_DLL_insert_after (h->tq_head, h->tq_tail, h->tq_tail, tqe);
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
  if (ic->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ic->callback = NULL;
  if (GNUNET_YES == ic->in_receive)
    return;                     /* need to finish processing */
  GNUNET_CONTAINER_DLL_remove (ic->h->tq_head, ic->h->tq_tail, ic->tqe);
  GNUNET_free (ic->tqe);
  GNUNET_free (ic);
}


/* end of peerinfo_api.c */
