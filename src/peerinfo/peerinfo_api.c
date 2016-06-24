/*
     This file is part of GNUnet.
     Copyright (C) 2001-2014 GNUnet e.V.

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
 * @file peerinfo/peerinfo_api.c
 * @brief API to access peerinfo service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "peerinfo.h"

#define LOG(kind,...) GNUNET_log_from (kind, "peerinfo-api",__VA_ARGS__)


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
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * Peer we are interested in (only valid if iteration was restricted to one peer).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Is @e peer set?
   */
  int have_peer;

  /**
   * Only include friends in reply?
   */
  int include_friend_only;

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
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *r_task;

};


/**
 * Close the existing connection to PEERINFO and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERINFO_Handle *h);


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

  h = GNUNET_new (struct GNUNET_PEERINFO_Handle);
  h->cfg = cfg;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the peerinfo service.  Note that all iterators must
 * have completed or have been cancelled by the time this function is
 * called (otherwise, calling this function is a serious error).
 * Furthermore, if #GNUNET_PEERINFO_add_peer() operations are still
 * pending, they will be cancelled silently on disconnect.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERINFO_disconnect (struct GNUNET_PEERINFO_Handle *h)
{
  struct GNUNET_PEERINFO_IteratorContext *ic;

  while (NULL != (ic = h->ic_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->ic_head,
                                 h->ic_tail,
                                 ic);
    GNUNET_free (ic);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = NULL;
  }
  GNUNET_free (h);
}


/**
 * Task scheduled to re-try connecting to the peerinfo service.
 *
 * @param cls the `struct GNUNET_PEERINFO_Handle *`
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_PEERINFO_Handle *h = cls;

  h->r_task = NULL;
  reconnect (h);
}


/**
 * We encountered an error, reconnect to the PEERINFO service.
 *
 * @param h handle to reconnect
 */
static void
do_reconnect (struct GNUNET_PEERINFO_Handle *h)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;

  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  if (NULL != ic)
  {
    GNUNET_CONTAINER_DLL_remove (h->ic_head,
                                 h->ic_tail,
                                 ic);
    if (NULL != ic->callback)
      ic->callback (ic->callback_cls,
                    NULL,
                    NULL,
                    _("Failed to receive response from `PEERINFO' service."));
    GNUNET_free (ic);
  }
  h->r_task = GNUNET_SCHEDULER_add_now (&reconnect_task,
                                        h);
}


/**
 * We got a disconnect after asking regex to do the announcement.
 * Retry.
 *
 * @param cls the `struct GNUNET_PEERINFO_Handle` to retry
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERINFO_Handle *h = cls;

  do_reconnect (h);
}



/**
 * Function called when we receive an info message. Check it is
 * well-formed.
 *
 * @param cls closure
 * @param im message received
 * @return #GNUNET_OK if the message is OK
 */
static int
check_info (void *cls,
            const struct InfoMessage *im)
{
  struct GNUNET_PEERINFO_Handle *h = cls;
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;
  uint16_t ms = ntohs (im->header.size) - sizeof (*im);

  if (0 != ntohl (im->reserved))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == ic)
  {
    /* didn't expect a response, bad */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ( (GNUNET_YES == ic->have_peer) &&
       (0 != memcmp (&ic->peer,
                     &im->peer,
                     sizeof (struct GNUNET_PeerIdentity))) )
  {
    /* bogus message (from a different iteration call?); out of sequence! */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Received HELLO for peer `%s', expected peer `%s'\n",
	 GNUNET_i2s (&im->peer),
	 GNUNET_i2s (&ic->peer));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ms > sizeof (struct GNUNET_MessageHeader))
  {
    const struct GNUNET_HELLO_Message *hello;
    struct GNUNET_PeerIdentity id;

    hello = (const struct GNUNET_HELLO_Message *) &im[1];
    if (ms != GNUNET_HELLO_size (hello))
    {
      /* malformed message */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_get_id (hello,
                             &id))
    {
      /* malformed message */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (0 != memcmp (&im->peer,
                     &id,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
      /* malformed message */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  else if (0 != ms)
  {
    /* malformed message */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle info message.
 *
 * @param cls closure
 * @param im message received
 */
static void
handle_info (void *cls,
             const struct InfoMessage *im)
{
  struct GNUNET_PEERINFO_Handle *h = cls;
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  ms = ntohs (im->header.size);
  hello = (0 == ms) ? NULL : (const struct GNUNET_HELLO_Message *) &im[1];
  if (NULL != ic->callback)
    ic->callback (ic->callback_cls,
                  &im->peer,
                  hello,
                  NULL);
}


/**
 * Send the next IC request at the head of the queue.
 *
 * @param h handle
 */
static void
send_ic_request (struct GNUNET_PEERINFO_Handle *h)
{
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;
  struct GNUNET_MQ_Envelope *env;
  struct ListAllPeersMessage *lapm;
  struct ListPeerMessage *lpm;

  if (NULL == ic)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == h->mq)
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_NO == ic->have_peer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting list of peers from PEERINFO service\n");
    env = GNUNET_MQ_msg (lapm,
                         GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
    lapm->include_friend_only = htonl (ic->include_friend_only);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Requesting information on peer `%s' from PEERINFO service\n",
         GNUNET_i2s (&ic->peer));
    env = GNUNET_MQ_msg (lpm,
                         GNUNET_MESSAGE_TYPE_PEERINFO_GET);
    lpm->include_friend_only = htonl (ic->include_friend_only);
    lpm->peer = ic->peer;
  }
  GNUNET_MQ_send (h->mq,
                  env);
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
handle_end_iteration (void *cls,
                      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERINFO_Handle *h = cls;
  struct GNUNET_PEERINFO_IteratorContext *ic = h->ic_head;

  if (NULL == ic)
  {
    /* didn't expect a response, reconnect */
    GNUNET_break (0);
    reconnect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received end of list of peers from PEERINFO service\n");
  GNUNET_CONTAINER_DLL_remove (h->ic_head,
			       h->ic_tail,
			       ic);
  if (NULL != h->ic_head)
    send_ic_request (h);
  if (NULL != ic->callback)
    ic->callback (ic->callback_cls,
                  NULL,
                  NULL,
                  NULL);
  GNUNET_free (ic);
}


/**
 * Close the existing connection to PEERINFO and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERINFO_Handle *h)
{
  GNUNET_MQ_hd_var_size (info,
                         GNUNET_MESSAGE_TYPE_PEERINFO_INFO,
                         struct InfoMessage);
  GNUNET_MQ_hd_fixed_size (end_iteration,
                           GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END,
                           struct GNUNET_MessageHeader);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_info_handler (h),
    make_end_iteration_handler (h),
    GNUNET_MQ_handler_end ()
  };

  if (NULL != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = NULL;
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "peerinfo",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL != h->ic_head)
    send_ic_request (h);
}


/**
 * Call a method for each known matching host.  The callback method
 * will be invoked once for each matching host and then finally once
 * with a NULL pointer.  After that final invocation, the iterator
 * context must no longer be used.
 *
 * Instead of calling this function with `peer == NULL` it is often
 * better to use #GNUNET_PEERINFO_notify().
 *
 * @param h handle to the peerinfo service
 * @param include_friend_only include HELLO messages for friends only
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param callback the method to call for each peer
 * @param callback_cls closure for @a callback
 * @return iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate (struct GNUNET_PEERINFO_Handle *h,
                         int include_friend_only,
                         const struct GNUNET_PeerIdentity *peer,
                         GNUNET_PEERINFO_Processor callback,
                         void *callback_cls)
{
  struct GNUNET_PEERINFO_IteratorContext *ic;

  ic = GNUNET_new (struct GNUNET_PEERINFO_IteratorContext);
  ic->h = h;
  ic->include_friend_only = include_friend_only;
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  if (NULL != peer)
  {
    ic->have_peer = GNUNET_YES;
    ic->peer = *peer;
  }
  GNUNET_CONTAINER_DLL_insert_tail (h->ic_head,
				    h->ic_tail,
				    ic);
  if (h->ic_head == ic)
    send_ic_request (h);
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
  struct GNUNET_PEERINFO_Handle *h = ic->h;

  ic->callback = NULL;
  if (ic == h->ic_head)
    return;
  GNUNET_CONTAINER_DLL_remove (h->ic_head,
			       h->ic_tail,
			       ic);
  GNUNET_free (ic);
}


/**
 * Add a host to the persistent list.  This method operates in
 * semi-reliable mode: if the transmission is not completed by
 * the time #GNUNET_PEERINFO_disconnect() is called, it will be
 * aborted.  Furthermore, if a second HELLO is added for the
 * same peer before the first one was transmitted, PEERINFO may
 * merge the two HELLOs prior to transmission to the service.
 *
 * @param h handle to the peerinfo service
 * @param hello the verified (!) HELLO message
 * @param cont continuation to call when done, NULL is allowed
 * @param cont_cls closure for @a cont
 * @return handle to cancel add operation; all pending
 *         'add' operations will be cancelled automatically
 *        on disconnect, so it is not necessary to keep this
 *        handle (unless @a cont is NULL and at some point
 *        calling @a cont must be prevented)
 */
struct GNUNET_MQ_Envelope *
GNUNET_PEERINFO_add_peer (struct GNUNET_PEERINFO_Handle *h,
                          const struct GNUNET_HELLO_Message *hello,
			  GNUNET_MQ_NotifyCallback cont,
			  void *cont_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_PeerIdentity peer;

  if (NULL == h->mq)
    return NULL;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id (hello,
                                      &peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding peer `%s' to PEERINFO database\n",
       GNUNET_i2s (&peer));
  env = GNUNET_MQ_msg_copy ((const struct GNUNET_MessageHeader *) hello);
  if (NULL != cont)
    GNUNET_MQ_notify_sent (env,
                           cont,
                           cont_cls);
  GNUNET_MQ_send (h->mq,
                  env);
  return env;
}


/* end of peerinfo_api.c */
