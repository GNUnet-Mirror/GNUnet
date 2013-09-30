/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/server_nc.c
 * @brief convenience functions for transmission of
 *        a notification stream
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-server-nc", __VA_ARGS__)


/**
 * Entry in list of messages pending to be transmitted.
 */
struct PendingMessageList
{

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessageList *next;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessageList *prev;

  /**
   * Message to transmit (allocated at the end of this
   * struct, do not free)
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Can this message be dropped?
   */
  int can_drop;

};


/**
 * Lists of clients we manage for notifications.
 */
struct ClientList
{

  /**
   * This is a doubly linked list.
   */
  struct ClientList *next;

  /**
   * This is a doubly linked list.
   */
  struct ClientList *prev;

  /**
   * Overall context this client belongs to.
   */
  struct GNUNET_SERVER_NotificationContext *nc;

  /**
   * Handle to the client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Handle for pending transmission request to the client (or NULL).
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Head of linked list of requests queued for transmission.
   */
  struct PendingMessageList *pending_head;

  /**
   * Tail of linked list of requests queued for transmission.
   */
  struct PendingMessageList *pending_tail;

  /**
   * Number of messages currently in the list.
   */
  unsigned int num_pending;

};


/**
 * The notification context is the key datastructure for a convenience
 * API used for transmission of notifications to the client until the
 * client disconnects (or the notification context is destroyed, in
 * which case we disconnect these clients).  Essentially, all
 * (notification) messages are queued up until the client is able to
 * read them.
 */
struct GNUNET_SERVER_NotificationContext
{

  /**
   * Server we do notifications for.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Head of list of clients receiving notifications.
   */
  struct ClientList *clients_head;

  /**
   * Tail of list of clients receiving notifications.
   */
  struct ClientList *clients_tail;

  /**
   * Maximum number of optional messages to queue per client.
   */
  unsigned int queue_length;

};


/**
 * Client has disconnected, clean up.
 *
 * @param cls our 'struct GNUNET_SERVER_NotificationContext *'
 * @param client handle of client that disconnected
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_SERVER_NotificationContext *nc = cls;
  struct ClientList *pos;
  struct PendingMessageList *pml;

  if (NULL == client)
  {
    nc->server = NULL;
    return;
  }
  for (pos = nc->clients_head; NULL != pos; pos = pos->next)
    if (pos->client == client)
      break;
  if (NULL == pos)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client disconnected, cleaning up %u messages in NC queue\n",
       pos->num_pending);
  GNUNET_CONTAINER_DLL_remove (nc->clients_head,
			       nc->clients_tail,
			       pos);
  while (NULL != (pml = pos->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (pos->pending_head, pos->pending_tail, pml);
    GNUNET_free (pml);
    pos->num_pending--;
  }
  if (NULL != pos->th)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (pos->th);
    pos->th = NULL;
  }
  GNUNET_SERVER_client_drop (client);
  GNUNET_assert (0 == pos->num_pending);
  GNUNET_free (pos);
}


/**
 * Create a new notification context.
 *
 * @param server server for which this function creates the context
 * @param queue_length maximum number of messages to keep in
 *        the notification queue; optional messages are dropped
 *        if the queue gets longer than this number of messages
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
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, ret);
  return ret;
}


/**
 * Destroy the context, force disconnect for all clients.
 *
 * @param nc context to destroy.
 */
void
GNUNET_SERVER_notification_context_destroy (struct
                                            GNUNET_SERVER_NotificationContext
                                            *nc)
{
  struct ClientList *pos;
  struct PendingMessageList *pml;

  while (NULL != (pos = nc->clients_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->clients_head,
				 nc->clients_tail,
				 pos);
    if (NULL != pos->th)
    {
      GNUNET_SERVER_notify_transmit_ready_cancel(pos->th);
      pos->th = NULL;
    }
    GNUNET_SERVER_client_drop (pos->client);
    while (NULL != (pml = pos->pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos->pending_head, pos->pending_tail, pml);
      GNUNET_free (pml);
      pos->num_pending--;
    }
    GNUNET_assert (0 == pos->num_pending);
    GNUNET_free (pos);
  }
  if (NULL != nc->server)
    GNUNET_SERVER_disconnect_notify_cancel (nc->server,
                                            &handle_client_disconnect, nc);
  GNUNET_free (nc);
}


/**
 * Add a client to the notification context.
 *
 * @param nc context to modify
 * @param client client to add
 */
void
GNUNET_SERVER_notification_context_add (struct GNUNET_SERVER_NotificationContext
                                        *nc,
                                        struct GNUNET_SERVER_Client *client)
{
  struct ClientList *cl;

  for (cl = nc->clients_head; NULL != cl; cl = cl->next)
    if (cl->client == client)
      return; /* already present */    
  cl = GNUNET_malloc (sizeof (struct ClientList));
  GNUNET_CONTAINER_DLL_insert (nc->clients_head,
			       nc->clients_tail,
			       cl);
  cl->nc = nc;
  cl->client = client;
  GNUNET_SERVER_client_keep (client);
}


/**
 * Function called to notify a client about the socket begin ready to
 * queue more data.  "buf" will be NULL and "size" zero if the socket
 * was closed for writing in the meantime.
 *
 * @param cls the 'struct ClientList *'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_message (void *cls, size_t size, void *buf)
{
  struct ClientList *cl = cls;
  char *cbuf = buf;
  struct PendingMessageList *pml;
  uint16_t msize;
  size_t ret;

  cl->th = NULL;
  if (NULL == buf)
  {
    /* 'cl' should be freed via disconnect notification shortly */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to transmit message from NC queue to client\n");
    return 0;
  }
  ret = 0;
  while (NULL != (pml = cl->pending_head))
  {
    msize = ntohs (pml->msg->size);
    if (size < msize)
      break;
    GNUNET_CONTAINER_DLL_remove (cl->pending_head, cl->pending_tail, pml);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Copying message of type %u and size %u from pending queue to transmission buffer\n",
         ntohs (pml->msg->type), msize);
    memcpy (&cbuf[ret], pml->msg, msize);
    ret += msize;
    size -= msize;
    GNUNET_free (pml);
    cl->num_pending--;
  }
  if (NULL != pml)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Have %u messages left in NC queue, will try transmission again\n",
         cl->num_pending);
    cl->th =
        GNUNET_SERVER_notify_transmit_ready (cl->client, ntohs (pml->msg->size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_message, cl);
  }
  else
  {
    GNUNET_assert (0 == cl->num_pending);
  }
  return ret;
}


/**
 * Send a message to a particular client.
 *
 * @param nc context to modify
 * @param client client to transmit to
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
static void
do_unicast (struct GNUNET_SERVER_NotificationContext *nc,
            struct ClientList *client, const struct GNUNET_MessageHeader *msg,
            int can_drop)
{
  struct PendingMessageList *pml;
  uint16_t size;

  if ((client->num_pending > nc->queue_length) && (GNUNET_YES == can_drop))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Dropping message of type %u and size %u due to full queue (%u entries)\n",
         ntohs (msg->type), ntohs (msg->size), (unsigned int) nc->queue_length);
    return;                     /* drop! */
  }
  if (client->num_pending > nc->queue_length)
  {
    /* FIXME: consider checking for other messages in the
     * queue that are 'droppable' */
  }
  client->num_pending++;
  size = ntohs (msg->size);
  pml = GNUNET_malloc (sizeof (struct PendingMessageList) + size);
  pml->msg = (const struct GNUNET_MessageHeader *) &pml[1];
  pml->can_drop = can_drop;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding message of type %u and size %u to pending queue (which has %u entries)\n",
       ntohs (msg->type), ntohs (msg->size), (unsigned int) nc->queue_length);
  memcpy (&pml[1], msg, size);
  /* append */
  GNUNET_CONTAINER_DLL_insert_tail (client->pending_head, client->pending_tail,
                                    pml);
  if (NULL == client->th)
    client->th =
        GNUNET_SERVER_notify_transmit_ready (client->client,
                                             ntohs (client->pending_head->
                                                    msg->size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_message, client);
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
GNUNET_SERVER_notification_context_unicast (struct
                                            GNUNET_SERVER_NotificationContext
                                            *nc,
                                            struct GNUNET_SERVER_Client *client,
                                            const struct GNUNET_MessageHeader
                                            *msg, int can_drop)
{
  struct ClientList *pos;

  for (pos = nc->clients_head; NULL != pos; pos = pos->next)
    if (pos->client == client)
      break;
  GNUNET_assert (NULL != pos);
  do_unicast (nc, pos, msg, can_drop);
}


/**
 * Send a message to all clients of this context.
 *
 * @param nc context to modify
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_broadcast (struct
                                              GNUNET_SERVER_NotificationContext
                                              *nc,
                                              const struct GNUNET_MessageHeader
                                              *msg, int can_drop)
{
  struct ClientList *pos;

  for (pos = nc->clients_head; NULL != pos; pos = pos->next)
    do_unicast (nc, pos, msg, can_drop);
}


/* end of server_nc.c */
