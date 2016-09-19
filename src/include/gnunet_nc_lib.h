/*
     This file is part of GNUnet.
     Copyright (C) 2012-2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * General-purpose broadcast mechanism for message queues
 *
 * @defgroup mq  NC library
 * General-purpose broadcast mechanism for message queues
 *
 * @see [Documentation](https://gnunet.org/nc)
 *
 * @{
 */
#ifndef GNUNET_NC_H
#define GNUNET_NC_H


/**
 * The notification context is the key datastructure for a convenience
 * API used for transmission of notifications to the subscriber until the
 * subscriber disconnects (or the notification context is destroyed, in
 * which case we disconnect these subscribers).  Essentially, all
 * (notification) messages are queued up until the subscriber is able to
 * read them.
 */
struct GNUNET_NotificationContext;


/**
 * Create a new notification context.
 *
 * @param queue_length maximum number of messages to keep in
 *        the notification queue; optional messages are dropped
 *        if the queue gets longer than this number of messages
 * @return handle to the notification context
 */
struct GNUNET_NotificationContext *
GNUNET_notification_context_create (unsigned int queue_length);


/**
 * Destroy the context, force disconnect for all subscribers.
 *
 * @param nc context to destroy.
 */
void
GNUNET_notification_context_destroy (struct GNUNET_NotificationContext *nc);


/**
 * Add a subscriber to the notification context.
 *
 * @param nc context to modify
 * @param mq message queue add
 */
void
GNUNET_notification_context_add (struct GNUNET_NotificationContext *nc,
				 struct GNUNET_MQ_Handle *mq);


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
				       int can_drop);

/**
 * Return active number of subscribers in this context.
 *
 * @param nc context to query
 * @return number of current subscribers
 */
unsigned int
GNUNET_notification_context_get_size (struct GNUNET_NotificationContext *nc);

#endif
