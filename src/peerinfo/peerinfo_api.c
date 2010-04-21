/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/peerinfo_api.c
 * @brief API to access peerinfo service
 * @author Christian Grothoff
 *
 * TODO:
 * - document NEW API implementation
 * - add timeout for iteration
 * - implement cancellation of iteration
 * - prevent transmit during receive!
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_time_lib.h"
#include "peerinfo.h"

/**
 * Function to call after transmission has succeeded.
 * 
 * @param cls closure
 * @param success GNUNET_OK if transmission worked, GNUNET_SYSERR on error
 */
typedef void (*TransmissionContinuation)(void *cls,
					 int success);


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
   * When this request times out.
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
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

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

};


/**
 * Connect to the peerinfo service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return NULL on error (configuration related, actual connection
 *         etablishment may happen asynchronously).
 */
struct GNUNET_PEERINFO_Handle *
GNUNET_PEERINFO_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 struct GNUNET_SCHEDULER_Handle *sched)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_PEERINFO_Handle *ret;

  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_Handle));
  ret->client = client;
  ret->cfg = cfg;
  ret->sched = sched;
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
      GNUNET_CONTAINER_DLL_remove (h->tq_head,
				   h->tq_tail,
				   tqe);
      if (tqe->cont != NULL)
	tqe->cont (tqe->cont_cls, GNUNET_SYSERR);
      GNUNET_free (tqe);
    }
  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
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
reconnect (struct GNUNET_PEERINFO_Handle *h)
{
  GNUNET_CLIENT_disconnect (h->client, GNUNET_SYSERR);
  h->client = GNUNET_CLIENT_connect (h->sched, "client", h->cfg);
  GNUNET_assert (h->client != NULL);
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
  if (buf == NULL)
    {
#if DEBUG_PEERINFO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _
                  ("Failed to transmit message of type %u to `%s' service.\n"),
                  ntohs (msg->type), "peerinfo");
#endif
      GNUNET_CONTAINER_DLL_remove (h->tq_head,
				   h->tq_tail,
				   tqe);
      reconnect (h);
      trigger_transmit (h);
      if (tqe->cont != NULL)
	tqe->cont (tqe->cont_cls, GNUNET_SYSERR);
      GNUNET_free (tqe);
      return 0;
    }
  ret = tqe->size;
  GNUNET_assert (size >= ret);
  memcpy (buf, &tqe[1], ret);
  GNUNET_CONTAINER_DLL_remove (h->tq_head,
			       h->tq_tail,
			       tqe);
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

  /* FIXME: need to handle case where we are still *receiving* (and then
     do nothing here as well!) */
  if (NULL == (tqe = h->tq_head))
    return;
  if (h->th != NULL)
    return;
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
					       tqe->size,
					       GNUNET_TIME_absolute_get_remaining (tqe->timeout),
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
 */
void
GNUNET_PEERINFO_add_peer_new (struct GNUNET_PEERINFO_Handle *h,
			      const struct GNUNET_HELLO_Message *hello)
{
  uint16_t hs = GNUNET_HELLO_size (hello);
  struct TransmissionQueueEntry *tqe;
  
#if DEBUG_PEERINFO
  struct GNUNET_PeerIdentity peer;
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_id (hello, &peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding peer `%s' to PEERINFO database (%u bytes of `%s')\n",
	      GNUNET_i2s(&peer),
	      hs,
	      "HELLO");
#endif
  tqe = GNUNET_malloc (sizeof (struct TransmissionQueueEntry) + hs);
  tqe->size = hs;
  tqe->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  memcpy (&tqe[1], hello, hs);
  GNUNET_CONTAINER_DLL_insert_after (h->tq_head,
				     h->tq_tail,
				     h->tq_tail,
				     tqe);
  trigger_transmit (h);
}


/**
 * Context for an iteration request.
 */
struct GNUNET_PEERINFO_NewIteratorContext
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
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;
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
  struct GNUNET_PEERINFO_NewIteratorContext *ic = cls;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to receive response from `%s' service.\n"),
                  "peerinfo");
      reconnect (ic->h);
      trigger_transmit (ic->h);
      ic->callback (ic->callback_cls, NULL, NULL, 1);
      GNUNET_free (ic);
      return;
    }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END)
    {
#if DEBUG_PEERINFO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received end of list of peers from peerinfo database\n");
#endif
      trigger_transmit (ic->h);
      ic->callback (ic->callback_cls, NULL, NULL, 0);
      GNUNET_free (ic);
      return;
    }
  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
    {
      GNUNET_break (0);
      reconnect (ic->h);
      trigger_transmit (ic->h);
      ic->callback (ic->callback_cls, NULL, NULL, 2);
      GNUNET_free (ic);
      return;
    }
  im = (const struct InfoMessage *) msg;
  hello = NULL;
  if (ms > sizeof (struct InfoMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      hello = (const struct GNUNET_HELLO_Message *) &im[1];
      if (ms != sizeof (struct InfoMessage) + GNUNET_HELLO_size (hello))
        {
	  GNUNET_break (0);
	  reconnect (ic->h);
	  trigger_transmit (ic->h);
	  ic->callback (ic->callback_cls, NULL, NULL, 2);
	  GNUNET_free (ic);
          return;
        }
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %u bytes of `%s' information about peer `%s' from PEERINFO database\n",
	      (hello == NULL) ? 0 : (unsigned int) GNUNET_HELLO_size (hello),
	      "HELLO",
	      GNUNET_i2s (&im->peer));
#endif
  ic->callback (ic->callback_cls, &im->peer, hello, ntohl (im->trust));
  GNUNET_CLIENT_receive (ic->h->client,
                         &peerinfo_handler,
                         ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
}


/**
 * We've transmitted the iteration request.  Now get ready to process
 * the results (or handle transmission error).
 *
 * @param cls the 'struct GNUNET_PEERINFO_NewIteratorContext'
 * @param transmit_success GNUNET_OK if transmission worked
 */
static void
iterator_start_receive (void *cls,
			int transmit_success)
{
  struct GNUNET_PEERINFO_NewIteratorContext *ic = cls;

  if (GNUNET_OK != transmit_success)
    {
      ic->callback (ic->callback_cls, NULL, NULL, 2);
      reconnect (ic->h);
      trigger_transmit (ic->h);
      GNUNET_free (ic);
      return;
    }  
  GNUNET_CLIENT_receive (ic->h->client,
                         &peerinfo_handler,
                         ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
}


/**
 * Call a method for each known matching host and change its trust
 * value.  The callback method will be invoked once for each matching
 * host and then finally once with a NULL pointer.  After that final
 * invocation, the iterator context must no longer be used.
 *
 * Note that the last call can be triggered by timeout or by simply
 * being done; however, the trust argument will be set to zero if we
 * are done, 1 if we timed out and 2 for fatal error.
 *
 * Instead of calling this function with 'peer == NULL' and 'trust ==
 * 0', it is often better to use 'GNUNET_PEERINFO_notify'.
 * 
 * @param h handle to the peerinfo service
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param trust_delta how much to change the trust in all matching peers
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error (in this case, 'callback' is never called!), 
 *         otherwise an iterator context
 */
struct GNUNET_PEERINFO_NewIteratorContext *
GNUNET_PEERINFO_iterate_new (struct GNUNET_PEERINFO_Handle *h,
			     const struct GNUNET_PeerIdentity *peer,
			     int trust_delta,
			     struct GNUNET_TIME_Relative timeout,
			     GNUNET_PEERINFO_Processor callback,
			     void *callback_cls)
{
  struct ListAllPeersMessage *lapm;
  struct ListPeerMessage *lpm;
  struct GNUNET_PEERINFO_NewIteratorContext *ic;
  struct TransmissionQueueEntry *tqe;

#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Requesting list of peers from peerinfo database\n");
#endif
  if (peer == NULL)
    {
      tqe = GNUNET_malloc (sizeof (struct TransmissionQueueEntry) +
			   sizeof (struct ListAllPeersMessage));
      tqe->size = sizeof (struct ListAllPeersMessage);
      lapm = (struct ListAllPeersMessage *) &tqe[1];
      lapm->header.size = htons (sizeof (struct ListAllPeersMessage));
      lapm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
      lapm->trust_change = htonl (trust_delta);
    }
  else
    {
      tqe = GNUNET_malloc (sizeof (struct TransmissionQueueEntry) +
			   sizeof (struct ListPeerMessage));
      tqe->size = sizeof (struct ListPeerMessage);
      lpm = (struct ListPeerMessage *) &tqe[1];
      lpm->header.size = htons (sizeof (struct ListPeerMessage));
      lpm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET);
      lpm->trust_change = htonl (trust_delta);
      memcpy (&lpm->peer, peer, sizeof (struct GNUNET_PeerIdentity));
    }
  ic = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_NewIteratorContext));
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  tqe->timeout = ic->timeout;
  tqe->cont = &iterator_start_receive;
  tqe->cont_cls = ic;
  /* FIXME: sort DLL by timeout? */
  /* FIXME: add timeout task!? */
  GNUNET_CONTAINER_DLL_insert_after (h->tq_head,
				     h->tq_tail,
				     h->tq_tail,
				     tqe);
  trigger_transmit (h);
  return ic;
}



/**
 * Cancel an iteration over peer information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_PEERINFO_iterate_cancel_new (struct GNUNET_PEERINFO_NewIteratorContext *ic)
{
  GNUNET_assert (0); 
  // FIXME: not implemented
}





/* ***************************** OLD API ****************************** */




#define ADD_PEER_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


struct CAFContext
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_MessageHeader *msg;
};


static size_t
copy_and_free (void *cls, size_t size, void *buf)
{
  struct CAFContext *cc = cls;
  struct GNUNET_MessageHeader *msg = cc->msg;
  uint16_t msize;

  if (buf == NULL)
    {
#if DEBUG_PEERINFO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _
                  ("Failed to transmit message of type %u to `%s' service.\n"),
                  ntohs (msg->type), "peerinfo");
#endif
      GNUNET_free (msg);
      GNUNET_CLIENT_disconnect (cc->client, GNUNET_NO);
      GNUNET_free (cc);
      return 0;
    }
  msize = ntohs (msg->size);
  GNUNET_assert (size >= msize);
  memcpy (buf, msg, msize);
  GNUNET_free (msg);
  GNUNET_CLIENT_disconnect (cc->client, GNUNET_YES);
  GNUNET_free (cc);
  return msize;
}



/**
 * Add a host to the persistent list.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer identity of the peer
 * @param hello the verified (!) HELLO message
 */
void
GNUNET_PEERINFO_add_peer (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_SCHEDULER_Handle *sched,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_HELLO_Message *hello)
{
  struct GNUNET_CLIENT_Connection *client;
  struct PeerAddMessage *pam;
  uint16_t hs;
  struct CAFContext *cc;

#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding peer `%s' to peerinfo database\n",
	      GNUNET_i2s(peer));
#endif
  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not connect to `%s' service.\n"), "peerinfo");
      return;
    }
  hs = GNUNET_HELLO_size (hello);
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Size of `%s' is %u bytes\n",
	      "HELLO",
	      (unsigned int) GNUNET_HELLO_size (hello));
#endif  
  pam = GNUNET_malloc (sizeof (struct PeerAddMessage) + hs);
  pam->header.size = htons (hs + sizeof (struct PeerAddMessage));
  pam->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_ADD);
  memcpy (&pam->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&pam[1], hello, hs);
  cc = GNUNET_malloc (sizeof (struct CAFContext));
  cc->client = client;
  cc->msg = &pam->header;
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       ntohs (pam->header.size),
                                       ADD_PEER_TIMEOUT, 
				       GNUNET_NO,
				       &copy_and_free, cc);
}


/**
 * Context for the info handler.
 */
struct GNUNET_PEERINFO_IteratorContext
{

  /**
   * Our connection to the PEERINFO service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Function to call with information.
   */
  GNUNET_PEERINFO_Processor callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * When should we time out?
   */
  struct GNUNET_TIME_Absolute timeout;

};


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
info_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = cls;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to receive response from `%s' service.\n"),
                  "peerinfo");
      ic->callback (ic->callback_cls, NULL, NULL, 1);
      GNUNET_CLIENT_disconnect (ic->client, GNUNET_NO);
      GNUNET_free (ic);
      return;
    }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END)
    {
#if DEBUG_PEERINFO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received end of list of peers from peerinfo database\n");
#endif
      ic->callback (ic->callback_cls, NULL, NULL, 0);
      GNUNET_CLIENT_disconnect (ic->client, GNUNET_NO);
      GNUNET_free (ic);
      return;
    }
  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
    {
      GNUNET_break (0);
      ic->callback (ic->callback_cls, NULL, NULL, 2);
      GNUNET_CLIENT_disconnect (ic->client, GNUNET_NO);
      GNUNET_free (ic);
      return;
    }
  im = (const struct InfoMessage *) msg;
  hello = NULL;
  if (ms > sizeof (struct InfoMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      hello = (const struct GNUNET_HELLO_Message *) &im[1];
      if (ms != sizeof (struct InfoMessage) + GNUNET_HELLO_size (hello))
        {
          GNUNET_break (0);
          ic->callback (ic->callback_cls, NULL, NULL, 2);
          GNUNET_CLIENT_disconnect (ic->client, GNUNET_NO);
          GNUNET_free (ic);
          return;
        }
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %u bytes of `%s' information about peer `%s' from PEERINFO database\n",
	      (hello == NULL) ? 0 : (unsigned int) GNUNET_HELLO_size (hello),
	      "HELLO",
	      GNUNET_i2s (&im->peer));
#endif
  ic->callback (ic->callback_cls, &im->peer, hello, ntohl (im->trust));
  GNUNET_CLIENT_receive (ic->client,
                         &info_handler,
                         ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
}


/**
 * Call a method for each known matching host and change
 * its trust value.  The method will be invoked once for
 * each host and then finally once with a NULL pointer.
 * Note that the last call can be triggered by timeout or
 * by simply being done; however, the trust argument will
 * be set to zero if we are done and to 1 if we timed out.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param trust_delta how much to change the trust in all matching peers
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error, otherwise an iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         struct GNUNET_SCHEDULER_Handle *sched,
                         const struct GNUNET_PeerIdentity *peer,
                         int trust_delta,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_PEERINFO_Processor callback,
                         void *callback_cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct ListAllPeersMessage *lapm;
  struct ListPeerMessage *lpm;
  struct GNUNET_PEERINFO_IteratorContext *ihc;

  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not connect to `%s' service.\n"), "peerinfo");
      return NULL;
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Requesting list of peers from peerinfo database\n");
#endif
  if (peer == NULL)
    {
      ihc = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_IteratorContext) +
			   sizeof (struct ListAllPeersMessage));
      lapm = (struct ListAllPeersMessage *) &ihc[1];
      lapm->header.size = htons (sizeof (struct ListAllPeersMessage));
      lapm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
      lapm->trust_change = htonl (trust_delta);
    }
  else
    {
      ihc = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_IteratorContext) +
			   sizeof (struct ListPeerMessage));
      lpm = (struct ListPeerMessage *) &ihc[1];
      lpm->header.size = htons (sizeof (struct ListPeerMessage));
      lpm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET);
      lpm->trust_change = htonl (trust_delta);
      memcpy (&lpm->peer, peer, sizeof (struct GNUNET_PeerIdentity));
    }
  ihc->client = client;
  ihc->callback = callback;
  ihc->callback_cls = callback_cls;
  ihc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (GNUNET_OK != 
      GNUNET_CLIENT_transmit_and_get_response (client,
					       (const struct GNUNET_MessageHeader*) &ihc[1],
					       timeout,
					       GNUNET_YES,
					       &info_handler,
					       ihc))
    {
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (ihc->client, GNUNET_NO);
      GNUNET_free (ihc);
      return NULL;
    }
  return ihc;
}


/**
 * Cancel an iteration over peer information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_PEERINFO_iterate_cancel (struct GNUNET_PEERINFO_IteratorContext *ic)
{
  GNUNET_CLIENT_disconnect (ic->client, GNUNET_NO);
  GNUNET_free (ic);
}


/* end of peerinfo_api.c */
