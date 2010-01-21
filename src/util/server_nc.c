/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/server_nc.c
 * @brief convenience functions for transmission of
 *        a notification stream 
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"


struct PendingMessageList
{

  struct PendingMessageList *next;

  const struct GNUNET_MessageHeader *msg;

  int can_drop;

};


struct ClientList
{

  struct ClientList *next;

  struct GNUNET_SERVER_Client *client;

  struct GNUNET_CONNECTION_TransmitHandle *th;

  struct PendingMessageList *pending;

  unsigned int num_pending;

};


/**
 * The notification context is the key datastructure for a conveniance
 * API used for transmission of notifications to the client until the
 * client disconnects (or the notification context is destroyed, in
 * which case we disconnect these clients).  Essentially, all
 * (notification) messages are queued up until the client is able to
 * read them.
 */
struct GNUNET_SERVER_NotificationContext
{

  struct GNUNET_SERVER_Handle *server;

  struct ClientList *clients;

  unsigned int queue_length;

};


static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_SERVER_NotificationContext *nc = cls;
  struct ClientList *pos;
  struct ClientList *prev;
  struct PendingMessageList *pml;

  prev = NULL;
  pos = nc->clients;
  while (NULL != pos)
    {
      if (pos->client == client)
	break;
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    return;
  if (prev == NULL)
    nc->clients = pos->next;
  else
    prev->next = pos->next;
  while (NULL != (pml = pos->pending))
    {
      pos->pending = pml->next;
      GNUNET_free (pml);
    }
  GNUNET_free (pos);
}


/**
 * Create a new notification context.
 *
 * @param server server for which this function creates the context
 * @param queue_length maximum number of messages to keep in
 *        the notification queue; optional messages are dropped
 *        it the queue gets longer than this number of messages
 * @return handle to the notification context
 */
struct GNUNET_SERVER_NotificationContext *
GNUNET_SERVER_notification_context_create (struct GNUNET_SERVER_Handle *server,
					   unsigned int queue_length)
{
  struct GNUNET_SERVER_NotificationContext *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_SERVER_NotificationContext));
  ret->server = server;
  ret->queue_length = queue_length;
  GNUNET_SERVER_disconnect_notify (server,
				   &handle_client_disconnect,
				   ret);
  return ret;
}


/**
 * Destroy the context, force disconnect for all clients.
 *
 * @param nc context to destroy.
 */
void
GNUNET_SERVER_notification_context_destroy (struct GNUNET_SERVER_NotificationContext *nc)
{
  struct ClientList *pos;
  struct PendingMessageList *pml;

  while (NULL != (pos = nc->clients))
    {
      nc->clients = pos->next;
      GNUNET_SERVER_receive_done (pos->client, GNUNET_NO);
      GNUNET_SERVER_client_drop (pos->client); 
      while (NULL != (pml = pos->pending))
	{
	  pos->pending = pml->next;
	  GNUNET_free (pml);
	}
      GNUNET_free (pos);
    }
  GNUNET_SERVER_disconnect_notify_cancel (nc->server,
					  &handle_client_disconnect,
					  nc);
  GNUNET_free (nc);
}


/**
 * Add a client to the notification context.
 *
 * @param nc context to modify
 * @param client client to add
 */
void
GNUNET_SERVER_notification_context_add (struct GNUNET_SERVER_NotificationContext *nc,
					struct GNUNET_SERVER_Client *client)
{
}


/**
 * Send a message to a particular client; must have
 * already been added to the notification context.
 *
 * @param nc context to modify
 * @param client client to transmit to
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_unicast (struct GNUNET_SERVER_NotificationContext *nc,
					    struct GNUNET_SERVER_Client *client,
					    const struct GNUNET_MessageHeader *msg,
					    int can_drop)
{
}


/**
 * Send a message to all clients of this context.
 *
 * @param nc context to modify
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_broadcast (struct GNUNET_SERVER_NotificationContext *nc,
					      const struct GNUNET_MessageHeader *msg,
					      int can_drop)
{
}


/* end of server_nc.c */
