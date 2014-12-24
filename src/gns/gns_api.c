/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gns_api.c
 * @brief library to access the GNS service
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "gns.h"
#include "gnunet_gns_service.h"


#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/**
 * Handle to a lookup request
 */
struct GNUNET_GNS_LookupRequest
{

  /**
   * DLL
   */
  struct GNUNET_GNS_LookupRequest *next;

  /**
   * DLL
   */
  struct GNUNET_GNS_LookupRequest *prev;

  /**
   * handle to gns
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * processor to call on lookup result
   */
  GNUNET_GNS_LookupResultProcessor lookup_proc;

  /**
   * processor closure
   */
  void *proc_cls;

  /**
   * request id
   */
  uint32_t r_id;

};


/**
 * Entry in our list of messages to be (re-)transmitted.
 */
struct PendingMessage
{
  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *prev;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *next;

  /**
   * Size of the message.
   */
  size_t size;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * This message has been transmitted.  GNUNET_NO if the message is
   * in the "pending" DLL, GNUNET_YES if it has been transmitted to
   * the service via the current client connection.
   */
  int transmitted;

};


/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of linked list of shorten messages we would like to transmit.
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of shorten messages we would like to transmit.
   */
  struct PendingMessage *pending_tail;

  /**
   * Head of linked list of lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_LookupRequest *lookup_head;

  /**
   * Tail of linked list of lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_LookupRequest *lookup_tail;

  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * How long do we wait until we try to reconnect?
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;

  /**
   * Did we start our receive loop yet?
   */
  int in_receive;

};


/**
 * Try to send messages from list of messages to send
 * @param handle GNS_Handle
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle);


/**
 * Reconnect to GNS service.
 *
 * @param handle the handle to the GNS service
 */
static void
reconnect (struct GNUNET_GNS_Handle *handle)
{
  GNUNET_assert (NULL == handle->client);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect to GNS\n");
  handle->client = GNUNET_CLIENT_connect ("gns", handle->cfg);
  GNUNET_assert (NULL != handle->client);
  process_pending_messages (handle);
}


/**
 * Reconnect to GNS
 *
 * @param cls the handle
 * @param tc task context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our handle
 */
static void
force_reconnect (struct GNUNET_GNS_Handle *handle)
{
  struct GNUNET_GNS_LookupRequest *lh;
  struct PendingMessage *p;

  GNUNET_CLIENT_disconnect (handle->client);
  handle->client = NULL;
  handle->in_receive = GNUNET_NO;
  for (lh = handle->lookup_head; NULL != lh; lh = lh->next)
  {
    p = (struct PendingMessage *) &lh[1];
    if (GNUNET_NO == p->transmitted)
      continue;
    p->transmitted = GNUNET_NO;
    GNUNET_CONTAINER_DLL_insert (handle->pending_head,
				 handle->pending_tail,
				 p);
  }
  handle->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task = GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
                                                    &reconnect_task,
                                                    handle);
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 *
 * @param cls the closure
 * @param size size of pending data
 * @param buf buffer with pending data
 * @return size data transmitted
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf);


/**
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
process_message (void *cls, const struct GNUNET_MessageHeader *msg);


/**
 * Try to send messages from list of messages to send
 *
 * @param handle the GNS handle
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle)
{
  struct PendingMessage *p = handle->pending_head;

  if (NULL == handle->client)
    return; /* wait for reconnect */
  if (NULL != handle->th)
    return; /* transmission request already pending */

  while ((NULL != p) && (p->transmitted == GNUNET_YES))
    p = p->next;
  if (NULL == p)
    return; /* no messages pending */

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to transmit %u bytes\n",
       (unsigned int) p->size);
  handle->th =
    GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                         p->size,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_NO, &transmit_pending,
                                         handle);
  GNUNET_break (NULL != handle->th);
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 *
 * @param cls the closure
 * @param size size of pending data
 * @param buf buffer with pending data
 * @return size data transmitted
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_GNS_Handle *handle = cls;
  char *cbuf = buf;
  struct PendingMessage *p;
  size_t tsize;

  handle->th = NULL;
  if ((0 == size) || (NULL == buf))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Transmission to GNS service failed!\n");
    force_reconnect (handle);
    return 0;
  }
  if (NULL == (p = handle->pending_head))
    return 0;

  tsize = 0;
  while ((NULL != (p = handle->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[tsize], &p[1], p->size);
    tsize += p->size;
    size -= p->size;
    p->transmitted = GNUNET_YES;
    GNUNET_CONTAINER_DLL_remove (handle->pending_head,
				 handle->pending_tail,
				 p);
    if (GNUNET_YES != handle->in_receive)
    {
      GNUNET_CLIENT_receive (handle->client, &process_message, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      handle->in_receive = GNUNET_YES;
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending %u bytes\n",
       (unsigned int) tsize);
  process_pending_messages (handle);
  return tsize;
}


/**
 * Process a given reply to the lookup request
 *
 * @param qe a queue entry
 * @param msg the lookup message received
 */
static void
process_lookup_reply (struct GNUNET_GNS_LookupRequest *qe,
                      const struct GNUNET_GNS_ClientLookupResultMessage *msg)
{
  struct GNUNET_GNS_Handle *handle = qe->gns_handle;
  struct PendingMessage *p = (struct PendingMessage *) &qe[1];
  GNUNET_GNS_LookupResultProcessor proc;
  void *proc_cls;
  uint32_t rd_count = ntohl (msg->rd_count);
  struct GNUNET_GNSRECORD_Data rd[rd_count];
  size_t mlen;

  if (GNUNET_YES != p->transmitted)
  {
    /* service send reply to query we never managed to send!? */
    GNUNET_break (0);
    force_reconnect (handle);
    return;
  }
  mlen = ntohs (msg->header.size);
  mlen -= sizeof (struct GNUNET_GNS_ClientLookupResultMessage);
  proc = qe->lookup_proc;
  proc_cls = qe->proc_cls;
  GNUNET_CONTAINER_DLL_remove (handle->lookup_head, handle->lookup_tail, qe);
  GNUNET_free (qe);
  if (GNUNET_SYSERR == GNUNET_GNSRECORD_records_deserialize (mlen,
                                                             (const char*) &msg[1],
                                                             rd_count,
                                                             rd))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Failed to deserialize lookup reply from GNS service!\n"));
    proc (proc_cls, 0, NULL);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Received lookup reply from GNS service (%u records)\n",
	 (unsigned int) rd_count);
    proc (proc_cls, rd_count, rd);
  }
}


/**
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
process_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_GNS_Handle *handle = cls;
  struct GNUNET_GNS_LookupRequest *lr;
  const struct GNUNET_GNS_ClientLookupResultMessage *lookup_msg;
  uint32_t r_id;

  if (NULL == msg)
  {
    force_reconnect (handle);
    return;
  }

  GNUNET_CLIENT_receive (handle->client, &process_message, handle,
			 GNUNET_TIME_UNIT_FOREVER_REL);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Got LOOKUP_RESULT msg\n");
    if (ntohs (msg->size) < sizeof (struct GNUNET_GNS_ClientLookupResultMessage))
    {
      GNUNET_break (0);
      force_reconnect (handle);
      return;
    }
    lookup_msg = (const struct GNUNET_GNS_ClientLookupResultMessage *) msg;
    r_id = ntohl (lookup_msg->id);
    for (lr = handle->lookup_head; NULL != lr; lr = lr->next)
      if (lr->r_id == r_id)
      {
	process_lookup_reply(lr, lookup_msg);
	break;
      }
    break;
  default:
    GNUNET_break (0);
    force_reconnect (handle);
    return;
  }
}


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNS_Handle *handle;

  handle = GNUNET_new (struct GNUNET_GNS_Handle);
  handle->cfg = cfg;
  reconnect (handle);
  return handle;
}


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle handle of the GNS connection to stop
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle)
{
  if (NULL != handle->client)
  {
    GNUNET_CLIENT_disconnect (handle->client);
    handle->client = NULL;
  }
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_assert (NULL == handle->lookup_head);
  GNUNET_free (handle);
}


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_GNS_lookup_cancel (struct GNUNET_GNS_LookupRequest *lr)
{
  struct PendingMessage *p = (struct PendingMessage*) &lr[1];

  GNUNET_assert (NULL != lr->gns_handle);
  if (GNUNET_NO == p->transmitted)
    GNUNET_CONTAINER_DLL_remove (lr->gns_handle->pending_head,
                                 lr->gns_handle->pending_tail,
                                 p);
  GNUNET_CONTAINER_DLL_remove (lr->gns_handle->lookup_head,
                               lr->gns_handle->lookup_tail,
                               lr);
  GNUNET_free (lr);
}


/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone the zone to start the resolution in
 * @param type the record type to look up
 * @param options local options for the lookup
 * @param shorten_zone_key the private key of the shorten zone (can be NULL)
 * @param proc processor to call on result
 * @param proc_cls closure for @a proc
 * @return handle to the get request
 */
struct GNUNET_GNS_LookupRequest*
GNUNET_GNS_lookup (struct GNUNET_GNS_Handle *handle,
		   const char *name,
		   const struct GNUNET_CRYPTO_EcdsaPublicKey *zone,
		   uint32_t type,
		   enum GNUNET_GNS_LocalOptions options,
		   const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_zone_key,
		   GNUNET_GNS_LookupResultProcessor proc,
		   void *proc_cls)
{
  /* IPC to shorten gns names, return shorten_handle */
  struct GNUNET_GNS_ClientLookupMessage *lookup_msg;
  struct GNUNET_GNS_LookupRequest *lr;
  size_t msize;
  struct PendingMessage *pending;

  if (NULL == name)
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to lookup `%s' in GNS\n",
       name);
  msize = sizeof (struct GNUNET_GNS_ClientLookupMessage)
    + strlen (name) + 1;
  if (msize > UINT16_MAX)
  {
    GNUNET_break (0);
    return NULL;
  }
  lr = GNUNET_malloc (sizeof (struct GNUNET_GNS_LookupRequest) +
		      sizeof (struct PendingMessage) + msize);
  lr->gns_handle = handle;
  lr->lookup_proc = proc;
  lr->proc_cls = proc_cls;
  lr->r_id = handle->r_id_gen++;
  pending = (struct PendingMessage *)&lr[1];
  pending->size = msize;
  pending->r_id = lr->r_id;
  GNUNET_CONTAINER_DLL_insert_tail (handle->lookup_head,
                                    handle->lookup_tail, lr);

  lookup_msg = (struct GNUNET_GNS_ClientLookupMessage *) &pending[1];
  lookup_msg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_LOOKUP);
  lookup_msg->header.size = htons (msize);
  lookup_msg->id = htonl (lr->r_id);
  lookup_msg->options = htons ((uint16_t) options);
  lookup_msg->zone = *zone;
  lookup_msg->type = htonl (type);
  if (NULL != shorten_zone_key)
  {
    lookup_msg->have_key = htons (GNUNET_YES);
    lookup_msg->shorten_key = *shorten_zone_key;
  }
  memcpy (&lookup_msg[1], name, strlen (name) + 1);
  GNUNET_CONTAINER_DLL_insert_tail (handle->pending_head,
				    handle->pending_tail,
				    pending);
  process_pending_messages (handle);
  return lr;
}


/* end of gns_api.c */
