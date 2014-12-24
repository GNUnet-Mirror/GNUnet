/*
     This file is part of GNUnet.
     (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file namecache/namecache_api.c
 * @brief API to access the NAMECACHE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_constants.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_namecache_service.h"
#include "namecache.h"


#define LOG(kind,...) GNUNET_log_from (kind, "namecache-api",__VA_ARGS__)


/**
 * An QueueEntry used to store information for a pending
 * NAMECACHE record operation
 */
struct GNUNET_NAMECACHE_QueueEntry
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMECACHE_QueueEntry *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMECACHE_QueueEntry *prev;

  /**
   * Main handle to access the namecache.
   */
  struct GNUNET_NAMECACHE_Handle *nsh;

  /**
   * Continuation to call
   */
  GNUNET_NAMECACHE_ContinuationWithStatus cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Function to call with the blocks we get back; or NULL.
   */
  GNUNET_NAMECACHE_BlockProcessor block_proc;

  /**
   * Closure for @e block_proc.
   */
  void *block_proc_cls;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;

};


/**
 * Message in linked list we should send to the service.  The
 * actual binary message follows this struct.
 */
struct PendingMessage
{

  /**
   * Kept in a DLL.
   */
  struct PendingMessage *next;

  /**
   * Kept in a DLL.
   */
  struct PendingMessage *prev;

  /**
   * Size of the message.
   */
  size_t size;

};


/**
 * Connection to the NAMECACHE service.
 */
struct GNUNET_NAMECACHE_Handle
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
   * Head of linked list of pending messages to send to the service
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of pending messages to send to the service
   */
  struct PendingMessage *pending_tail;

  /**
   * Head of pending namecache queue entries
   */
  struct GNUNET_NAMECACHE_QueueEntry *op_head;

  /**
   * Tail of pending namecache queue entries
   */
  struct GNUNET_NAMECACHE_QueueEntry *op_tail;

  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Delay introduced before we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;

  /**
   * Did we start to receive yet?
   */
  int is_receiving;

  /**
   * The last operation id used for a NAMECACHE operation
   */
  uint32_t last_op_id_used;

};


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMECACHE_Handle *h);


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE.
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_lookup_block_response (struct GNUNET_NAMECACHE_QueueEntry *qe,
			      const struct LookupBlockResponseMessage *msg,
			      size_t size)
{
  struct GNUNET_GNSRECORD_Block *block;
  char buf[size + sizeof (struct GNUNET_GNSRECORD_Block)
	   - sizeof (struct LookupBlockResponseMessage)];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "LOOKUP_BLOCK_RESPONSE");
  if (0 == GNUNET_TIME_absolute_ntoh (msg->expire).abs_value_us)
  {
    /* no match found */
    if (NULL != qe->block_proc)
      qe->block_proc (qe->block_proc_cls, NULL);
    return GNUNET_OK;
  }

  block = (struct GNUNET_GNSRECORD_Block *) buf;
  block->signature = msg->signature;
  block->derived_key = msg->derived_key;
  block->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  block->purpose.size = htonl (size - sizeof (struct LookupBlockResponseMessage) +
			       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
			       sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  block->expiration_time = msg->expire;
  memcpy (&block[1],
	  &msg[1],
	  size - sizeof (struct LookupBlockResponseMessage));
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_verify (block))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL != qe->block_proc)
    qe->block_proc (qe->block_proc_cls, block);
  else
    GNUNET_break (0);
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_block_cache_response (struct GNUNET_NAMECACHE_QueueEntry *qe,
			    const struct BlockCacheResponseMessage *msg,
			    size_t size)
{
  int res;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "BLOCK_CACHE_RESPONSE");
  res = ntohl (msg->op_result);
  /* TODO: add actual error message from namecache to response... */
  if (NULL != qe->cont)
    qe->cont (qe->cont_cls,
	      res,
	      (GNUNET_OK == res)
	      ? NULL
	      : _("Namecache failed to cache block"));
  return GNUNET_OK;
}


/**
 * Handle incoming messages for record operations
 *
 * @param qe the respective zone iteration handle
 * @param msg the message we received
 * @param type the message type in host byte order
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_NO if we notified the client about
 *         the error, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
manage_record_operations (struct GNUNET_NAMECACHE_QueueEntry *qe,
                          const struct GNUNET_MessageHeader *msg,
                          uint16_t type,
			  size_t size)
{
  /* handle different message type */
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE:
    if (size < sizeof (struct LookupBlockResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_lookup_block_response (qe, (const struct LookupBlockResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE:
    if (size != sizeof (struct BlockCacheResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_block_cache_response (qe, (const struct BlockCacheResponseMessage *) msg, size);
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the `struct GNUNET_NAMECACHE_SchedulingHandle`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_namecache_message (void *cls,
			   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;
  const struct GNUNET_NAMECACHE_Header *gm;
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  uint16_t size;
  uint16_t type;
  uint32_t r_id;
  int ret;

  if (NULL == msg)
  {
    force_reconnect (h);
    return;
  }
  size = ntohs (msg->size);
  type = ntohs (msg->type);
  if (size < sizeof (struct GNUNET_NAMECACHE_Header))
  {
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (h->client,
			   &process_namecache_message, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  gm = (const struct GNUNET_NAMECACHE_Header *) msg;
  r_id = ntohl (gm->r_id);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message type %u size %u op %u\n",
       (unsigned int) type,
       (unsigned int) size,
       (unsigned int) r_id);

  /* Is it a record related operation ? */
  for (qe = h->op_head; qe != NULL; qe = qe->next)
    if (qe->op_id == r_id)
      break;
  if (NULL != qe)
  {
    ret = manage_record_operations (qe, msg, type, size);
    if (GNUNET_SYSERR == ret)
    {
      /* protocol error, need to reconnect */
      h->reconnect = GNUNET_YES;
    }
    else
    {
      /* client was notified about success or failure, clean up 'qe' */
      GNUNET_CONTAINER_DLL_remove (h->op_head,
				   h->op_tail,
				   qe);
      GNUNET_free (qe);
    }
  }
  if (GNUNET_YES == h->reconnect)
  {
    force_reconnect (h);
    return;
  }
  GNUNET_CLIENT_receive (h->client, &process_namecache_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param h handle to use
 */
static void
do_transmit (struct GNUNET_NAMECACHE_Handle *h);


/**
 * We can now transmit a message to NAMECACHE. Do it.
 *
 * @param cls the `struct GNUNET_NAMECACHE_Handle`
 * @param size number of bytes we can transmit
 * @param buf where to copy the messages
 * @return number of bytes copied into @a buf
 */
static size_t
transmit_message_to_namecache (void *cls,
			       size_t size,
			       void *buf)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  h->th = NULL;
  if ((0 == size) || (NULL == buf))
  {
    force_reconnect (h);
    return 0;
  }
  ret = 0;
  cbuf = buf;
  while ( (NULL != (p = h->pending_head)) &&
	  (p->size <= size) )
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (h->pending_head,
				 h->pending_tail,
				 p);
    if (GNUNET_NO == h->is_receiving)
    {
      h->is_receiving = GNUNET_YES;
      GNUNET_CLIENT_receive (h->client,
			     &process_namecache_message, h,
                             GNUNET_TIME_UNIT_FOREVER_REL);
    }
    GNUNET_free (p);
  }
  do_transmit (h);
  return ret;
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param h handle to use
 */
static void
do_transmit (struct GNUNET_NAMECACHE_Handle *h)
{
  struct PendingMessage *p;

  if (NULL != h->th)
    return; /* transmission request already pending */
  if (NULL == (p = h->pending_head))
    return; /* transmission queue empty */
  if (NULL == h->client)
    return;                     /* currently reconnecting */
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, p->size,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       GNUNET_NO, &transmit_message_to_namecache,
					       h);
  GNUNET_break (NULL != h->th);
}


/**
 * Reconnect to namecache service.
 *
 * @param h the handle to the NAMECACHE service
 */
static void
reconnect (struct GNUNET_NAMECACHE_Handle *h)
{
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("namecache", h->cfg);
  GNUNET_assert (NULL != h->client);
  do_transmit (h);
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;

  h->reconnect_task = NULL;
  reconnect (h);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMECACHE_Handle *h)
{
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  h->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Reconnecting to namecache\n");
  h->is_receiving = GNUNET_NO;
  h->client = NULL;
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
						    &reconnect_task,
						    h);
}


/**
 * Get a fresh operation id to distinguish between namecache requests
 *
 * @param h the namecache handle
 * @return next operation id to use
 */
static uint32_t
get_op_id (struct GNUNET_NAMECACHE_Handle *h)
{
  return h->last_op_id_used++;
}


/**
 * Initialize the connection with the NAMECACHE service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_NAMECACHE_Handle *
GNUNET_NAMECACHE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMECACHE_Handle *h;

  h = GNUNET_new (struct GNUNET_NAMECACHE_Handle);
  h->cfg = cfg;
  h->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect_task, h);
  h->last_op_id_used = 0;
  return h;
}


/**
 * Disconnect from the namecache service (and free associated
 * resources).
 *
 * @param h handle to the namecache
 */
void
GNUNET_NAMECACHE_disconnect (struct GNUNET_NAMECACHE_Handle *h)
{
  struct PendingMessage *p;
  struct GNUNET_NAMECACHE_QueueEntry *q;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  GNUNET_assert (NULL != h);
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  while (NULL != (p = h->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->pending_head, h->pending_tail, p);
    GNUNET_free (p);
  }
  GNUNET_break (NULL == h->op_head);
  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, q);
    GNUNET_free (q);
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_free (h);
}


/**
 * Store an item in the namecache.  If the item is already present,
 * it is replaced with the new record.
 *
 * @param h handle to the namecache
 * @param block block to store
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_block_cache (struct GNUNET_NAMECACHE_Handle *h,
			      const struct GNUNET_GNSRECORD_Block *block,
			      GNUNET_NAMECACHE_ContinuationWithStatus cont,
			      void *cont_cls)
{
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct BlockCacheMessage *msg;
  uint32_t rid;
  size_t blen;
  size_t msg_size;

  GNUNET_assert (NULL != h);
  blen = ntohl (block->purpose.size)
    - sizeof (struct GNUNET_TIME_AbsoluteNBO)
    - sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose);
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMECACHE_QueueEntry);
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  /* setup msg */
  msg_size = sizeof (struct BlockCacheMessage) + blen;
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct BlockCacheMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->expire = block->expiration_time;
  msg->signature = block->signature;
  msg->derived_key = block->derived_key;
  memcpy (&msg[1], &block[1], blen);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending `%s' message with size %u and expiration %s\n",
       "NAMECACHE_BLOCK_CACHE",
       (unsigned int) msg_size,
       GNUNET_STRINGS_absolute_time_to_string (GNUNET_TIME_absolute_ntoh (msg->expire)));
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return qe;
}


/**
 * Get a result for a particular key from the namecache.  The processor
 * will only be called once.
 *
 * @param h handle to the namecache
 * @param derived_hash hash of zone key combined with name to lookup
 * @param proc function to call on the matching block, or with
 *        NULL if there is no matching block
 * @param proc_cls closure for proc
 * @return a handle that can be used to cancel
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_lookup_block (struct GNUNET_NAMECACHE_Handle *h,
			       const struct GNUNET_HashCode *derived_hash,
			       GNUNET_NAMECACHE_BlockProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct LookupBlockMessage *msg;
  size_t msg_size;
  uint32_t rid;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for block under %s\n",
       GNUNET_h2s (derived_hash));
  rid = get_op_id(h);
  qe = GNUNET_new (struct GNUNET_NAMECACHE_QueueEntry);
  qe->nsh = h;
  qe->block_proc = proc;
  qe->block_proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  msg_size = sizeof (struct LookupBlockMessage);
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct LookupBlockMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->query = *derived_hash;
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return qe;
}


/**
 * Cancel a namecache operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMECACHE_cancel (struct GNUNET_NAMECACHE_QueueEntry *qe)
{
  struct GNUNET_NAMECACHE_Handle *h = qe->nsh;

  GNUNET_assert (NULL != qe);
  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, qe);
  GNUNET_free(qe);
}


/* end of namecache_api.c */
