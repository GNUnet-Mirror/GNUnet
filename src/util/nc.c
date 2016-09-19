/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2016 GNUnet e.V.

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
 * @file util/nc.c
 * @brief convenience functions for transmission of
 *        messages to multiple clients
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-nc", __VA_ARGS__)


/**
 * Lists of subscribers we manage for notifications.
 */
struct SubscriberList
{

  /**
   * This is a doubly linked list.
   */
  struct SubscriberList *next;

  /**
   * This is a doubly linked list.
   */
  struct SubscriberList *prev;

  /**
   * Overall context this subscriber belongs to.
   */
  struct GNUNET_NotificationContext *nc;

  /**
   * Handle where we registered with @e mq to be told about
   * the MQ's destruction.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *mq_nh;
  
  /**
   * Message queue for the subscriber.
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 * The notification context is the key datastructure for a convenience
 * API used for transmission of notifications to the subscriber until the
 * subscriber disconnects (or the notification context is destroyed, in
 * which case we disconnect these subscribers).  Essentially, all
 * (notification) messages are queued up until the subscriber is able to
 * read them.
 */
struct GNUNET_NotificationContext
{

  /**
   * Head of list of subscribers receiving notifications.
   */
  struct SubscriberList *subscribers_head;

  /**
   * Tail of list of subscribers receiving notifications.
   */
  struct SubscriberList *subscribers_tail;

  /**
   * Maximum number of optional messages to queue per subscriber.
   */
  unsigned int queue_length;

};


/**
 * Subscriber has disconnected, clean up.
 *
 * @param cls our `struct SubscriberList *`
 */
static void
handle_mq_destroy (void *cls)
{
  struct SubscriberList *pos = cls; 
  struct GNUNET_NotificationContext *nc = pos->nc;

  GNUNET_CONTAINER_DLL_remove (nc->subscribers_head,
			       nc->subscribers_tail,
			       pos);
  GNUNET_free (pos);
}


/**
 * Create a new notification context.
 *
 * @param queue_length maximum number of messages to keep in
 *        the notification queue; optional messages are dropped
 *        if the queue gets longer than this number of messages
 * @return handle to the notification context
 */
struct GNUNET_NotificationContext *
GNUNET_notification_context_create (unsigned int queue_length)
{
  struct GNUNET_NotificationContext *nc;

  nc = GNUNET_new (struct GNUNET_NotificationContext);
  nc->queue_length = queue_length;
  return nc;
}


/**
 * Destroy the context, force disconnect for all subscribers.
 *
 * @param nc context to destroy.
 */
void
GNUNET_notification_context_destroy (struct GNUNET_NotificationContext *nc)
{
  struct SubscriberList *pos;

  while (NULL != (pos = nc->subscribers_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->subscribers_head,
				 nc->subscribers_tail,
				 pos);
    GNUNET_MQ_destroy_notify_cancel (pos->mq_nh);
    GNUNET_free (pos);
  }
  GNUNET_free (nc);
}


/**
 * Add a subscriber to the notification context.
 *
 * @param nc context to modify
 * @param mq message queue add
 */
void
GNUNET_notification_context_add (struct GNUNET_NotificationContext *nc,
				 struct GNUNET_MQ_Handle *mq)
{
  struct SubscriberList *cl;

  for (cl = nc->subscribers_head; NULL != cl; cl = cl->next)
    if (cl->mq == mq)
      return; /* already present */
  cl = GNUNET_new (struct SubscriberList);
  GNUNET_CONTAINER_DLL_insert (nc->subscribers_head,
			       nc->subscribers_tail,
			       cl);
  cl->nc = nc;
  cl->mq = mq;
  cl->mq_nh = GNUNET_MQ_destroy_notify (cl->mq,
					&handle_mq_destroy,
					cl);
}


/**
 * Send a message to all subscribers of this context.
 *
 * @param nc context to modify
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_notification_context_broadcast (struct GNUNET_NotificationContext *nc,
				       const struct GNUNET_MessageHeader *msg,
				       int can_drop)
{
  struct SubscriberList *pos;
  struct GNUNET_MQ_Envelope *env;

  for (pos = nc->subscribers_head; NULL != pos; pos = pos->next)
  {
    if ( (GNUNET_YES == can_drop) &&
	 (GNUNET_MQ_get_length (pos->mq) > nc->queue_length) )
      continue;
    env = GNUNET_MQ_msg_copy (msg);
    GNUNET_MQ_send (pos->mq,
		    env);
  }
}


/**
 * Return active number of subscribers in this context.
 *
 * @param nc context to query
 * @return number of current subscribers
 */
unsigned int
GNUNET_notification_context_get_size (struct GNUNET_NotificationContext *nc)
{
  unsigned int num;
  struct SubscriberList *pos;

  num = 0;
  for (pos = nc->subscribers_head; NULL != pos; pos = pos->next)
    num++;
  return num;
}

/* end of nc.c */
