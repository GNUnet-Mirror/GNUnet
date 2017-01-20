/*
     This file is part of GNUnet.
     Copyright (C) 2010-2013, 2016 GNUnet e.V.

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
 * Connection to the NAMECACHE service.
 */
struct GNUNET_NAMECACHE_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Message queue to service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

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
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay introduced before we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;

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
 * Find queue entry for the given @a rid.
 *
 * @param h handle to search
 * @param rid request ID to look for
 * @return NULL if not found, otherwise the queue entry (removed from the queue)
 */
static struct GNUNET_NAMECACHE_QueueEntry *
find_qe (struct GNUNET_NAMECACHE_Handle *h,
         uint32_t rid)
{
  struct GNUNET_NAMECACHE_QueueEntry *qe;

  for (qe = h->op_head; qe != NULL; qe = qe->next)
  {
    if (qe->op_id == rid)
    {
      GNUNET_CONTAINER_DLL_remove (h->op_head,
				   h->op_tail,
				   qe);
      return qe;
    }
  }
  return NULL;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE.
 *
 * @param cls the `struct GNUNET_NAMECACHE_Handle`
 * @param msg the message we received
 */
static int
check_lookup_block_response (void *cls,
                             const struct LookupBlockResponseMessage *msg)
{
  /* any length will do, format validation is in handler */
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE.
 *
 * @param cls the `struct GNUNET_NAMECACHE_Handle`
 * @param msg the message we received
 */
static void
handle_lookup_block_response (void *cls,
			      const struct LookupBlockResponseMessage *msg)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;
  size_t size;
  struct GNUNET_NAMECACHE_QueueEntry *qe;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received LOOKUP_BLOCK_RESPONSE\n");
  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
  if (NULL == qe)
    return;
  if (0 == GNUNET_TIME_absolute_ntoh (msg->expire).abs_value_us)
  {
    /* no match found */
    if (NULL != qe->block_proc)
      qe->block_proc (qe->block_proc_cls,
                      NULL);
    GNUNET_free (qe);
    return;
  }
  size = ntohs (msg->gns_header.header.size)
    - sizeof (struct LookupBlockResponseMessage);
  {
    char buf[size + sizeof (struct GNUNET_GNSRECORD_Block)] GNUNET_ALIGN;
    struct GNUNET_GNSRECORD_Block *block;

    block = (struct GNUNET_GNSRECORD_Block *) buf;
    block->signature = msg->signature;
    block->derived_key = msg->derived_key;
    block->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    block->purpose.size = htonl (size +
                                 sizeof (struct GNUNET_TIME_AbsoluteNBO) +
                                 sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
    block->expiration_time = msg->expire;
    GNUNET_memcpy (&block[1],
            &msg[1],
            size);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_block_verify (block))
    {
      GNUNET_break (0);
      if (NULL != qe->block_proc)
        qe->block_proc (qe->block_proc_cls,
                        NULL);
      force_reconnect (h);
    }
    else
    {
      if (NULL != qe->block_proc)
        qe->block_proc (qe->block_proc_cls,
                        block);
    }
  }
  GNUNET_free (qe);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE
 *
 * @param cls the `struct GNUNET_NAMECACHE_Handle`
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static void
handle_block_cache_response (void *cls,
                             const struct BlockCacheResponseMessage *msg)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  int res;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received BLOCK_CACHE_RESPONSE\n");
  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
  if (NULL == qe)
    return;
  res = ntohl (msg->op_result);
  /* TODO: add actual error message from namecache to response... */
  if (NULL != qe->cont)
    qe->cont (qe->cont_cls,
	      res,
	      (GNUNET_OK == res)
	      ? NULL
	      : _("Namecache failed to cache block"));
  GNUNET_free (qe);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NAMECACHE_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAMECACHE_Handle *h = cls;

  force_reconnect (h);
}


/**
 * Reconnect to namecache service.
 *
 * @param h the handle to the NAMECACHE service
 */
static void
reconnect (struct GNUNET_NAMECACHE_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (lookup_block_response,
                           GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE,
                           struct LookupBlockResponseMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (block_cache_response,
                             GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE,
                             struct BlockCacheResponseMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "namecache",
                                 handlers,
                                 &mq_error_handler,
                                 h);
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
reconnect_task (void *cls)
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
  struct GNUNET_NAMECACHE_QueueEntry *qe;

  h->reconnect = GNUNET_NO;
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  while (NULL != (qe = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 qe);
    if (NULL != qe->cont)
      qe->cont (qe->cont_cls,
                GNUNET_SYSERR,
                _("Error communicating with namecache service"));
    GNUNET_free (qe);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Reconnecting to namecache\n");
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
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
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
  struct GNUNET_NAMECACHE_QueueEntry *q;

  GNUNET_break (NULL == h->op_head);
  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 q);
    GNUNET_free (q);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
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
 * @param cont_cls closure for @a cont
 * @return handle to abort the request, NULL on error
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_block_cache (struct GNUNET_NAMECACHE_Handle *h,
			      const struct GNUNET_GNSRECORD_Block *block,
			      GNUNET_NAMECACHE_ContinuationWithStatus cont,
			      void *cont_cls)
{
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  struct BlockCacheMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  uint32_t rid;
  size_t blen;

  if (NULL == h->mq)
    return NULL;
  blen = ntohl (block->purpose.size)
    - sizeof (struct GNUNET_TIME_AbsoluteNBO)
    - sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose);
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMECACHE_QueueEntry);
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    qe);
  /* send msg */
  env = GNUNET_MQ_msg_extra (msg,
                             blen,
                             GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE);
  msg->gns_header.r_id = htonl (rid);
  msg->expire = block->expiration_time;
  msg->signature = block->signature;
  msg->derived_key = block->derived_key;
  GNUNET_memcpy (&msg[1],
          &block[1],
          blen);
  GNUNET_MQ_send (h->mq,
                  env);
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
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to cancel, NULL on error
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_lookup_block (struct GNUNET_NAMECACHE_Handle *h,
			       const struct GNUNET_HashCode *derived_hash,
			       GNUNET_NAMECACHE_BlockProcessor proc,
                               void *proc_cls)
{
  struct GNUNET_NAMECACHE_QueueEntry *qe;
  struct LookupBlockMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  uint32_t rid;

  if (NULL == h->mq)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for block under %s\n",
       GNUNET_h2s (derived_hash));
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMECACHE_QueueEntry);
  qe->nsh = h;
  qe->block_proc = proc;
  qe->block_proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    qe);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK);
  msg->gns_header.r_id = htonl (rid);
  msg->query = *derived_hash;
  GNUNET_MQ_send (h->mq,
                  env);
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

  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               qe);
  GNUNET_free(qe);
}


/* end of namecache_api.c */
