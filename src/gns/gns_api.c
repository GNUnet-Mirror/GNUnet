/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
   * @e lookup_proc closure
   */
  void *proc_cls;

  /**
   * Envelope with the message for this queue entry.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * request id
   */
  uint32_t r_id;

};

/**
 * Handle to a lookup request
 */
struct GNUNET_GNS_ReverseLookupRequest
{

  /**
   * DLL
   */
  struct GNUNET_GNS_ReverseLookupRequest *next;

  /**
   * DLL
   */
  struct GNUNET_GNS_ReverseLookupRequest *prev;

  /**
   * handle to gns
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * processor to call on lookup result
   */
  GNUNET_GNS_ReverseLookupResultProcessor lookup_proc;

  /**
   * @e lookup_proc closure
   */
  void *proc_cls;

  /**
   * Envelope with the message for this queue entry.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * request id
   */
  uint32_t r_id;

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
   * Connection to service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of linked list of active lookup requests.
   */
  struct GNUNET_GNS_LookupRequest *lookup_head;

  /**
   * Tail of linked list of active lookup requests.
   */
  struct GNUNET_GNS_LookupRequest *lookup_tail;

  /**
   * Head of linked list of active reverse lookup requests.
   */
  struct GNUNET_GNS_ReverseLookupRequest *rev_lookup_head;

  /**
   * Tail of linked list of active reverse lookup requests.
   */
  struct GNUNET_GNS_ReverseLookupRequest *rev_lookup_tail;
  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How long do we wait until we try to reconnect?
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;

};


/**
 * Reconnect to GNS service.
 *
 * @param handle the handle to the GNS service
 */
static void
reconnect (struct GNUNET_GNS_Handle *handle);


/**
 * Reconnect to GNS
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
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
  GNUNET_MQ_destroy (handle->mq);
  handle->mq = NULL;
  handle->reconnect_backoff
    = GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
				    &reconnect_task,
				    handle);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_GNS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_GNS_Handle *handle = cls;
  LOG (GNUNET_ERROR_TYPE_WARNING, "Problem with message queue. error: %i\n",
       error);
  force_reconnect (handle);
}

/**
 * Check validity of message received from the GNS service
 *
 * @param cls the `struct GNUNET_GNS_Handle *`
 * @param loookup_msg the incoming message
 */
static int
check_rev_result (void *cls,
              const struct ReverseLookupResultMessage *lookup_msg)
{
  size_t mlen = ntohs (lookup_msg->header.size) - sizeof (*lookup_msg);
  char *name;
  
  name = (char*) &lookup_msg[1];
  if ('\0' != name[mlen-1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for messages received from the GNS service
 *
 * @param cls the `struct GNUNET_GNS_Handle *`
 * @param loookup_msg the incoming message
 */
static void
handle_rev_result (void *cls,
                   const struct ReverseLookupResultMessage *lookup_msg)
{
  struct GNUNET_GNS_Handle *handle = cls;
  char *name;
  uint32_t r_id = ntohl (lookup_msg->id);
  struct GNUNET_GNS_ReverseLookupRequest *rlr;
  GNUNET_GNS_ReverseLookupResultProcessor proc;
  void *proc_cls;

  name = (char*)&lookup_msg[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received reverse lookup reply from GNS service (%s)\n",
       name);
  for (rlr = handle->rev_lookup_head; NULL != rlr; rlr = rlr->next)
    if (rlr->r_id == r_id)
      break;
  if (NULL == rlr)
    return;
  proc = rlr->lookup_proc;
  proc_cls = rlr->proc_cls;
  GNUNET_CONTAINER_DLL_remove (handle->rev_lookup_head,
                               handle->rev_lookup_tail,
                               rlr);
  GNUNET_free (rlr);
  proc (proc_cls,
        name);
}



/**
 * Check validity of message received from the GNS service
 *
 * @param cls the `struct GNUNET_GNS_Handle *`
 * @param loookup_msg the incoming message
 */
static int
check_result (void *cls,
              const struct LookupResultMessage *lookup_msg)
{
  size_t mlen = ntohs (lookup_msg->header.size) - sizeof (*lookup_msg);
  uint32_t rd_count = ntohl (lookup_msg->rd_count);
  struct GNUNET_GNSRECORD_Data rd[rd_count];

  if (GNUNET_SYSERR ==
      GNUNET_GNSRECORD_records_deserialize (mlen,
                                            (const char*) &lookup_msg[1],
                                            rd_count,
                                            rd))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for messages received from the GNS service
 *
 * @param cls the `struct GNUNET_GNS_Handle *`
 * @param loookup_msg the incoming message
 */
static void
handle_result (void *cls,
               const struct LookupResultMessage *lookup_msg)
{
  struct GNUNET_GNS_Handle *handle = cls;
  size_t mlen = ntohs (lookup_msg->header.size) - sizeof (*lookup_msg);
  uint32_t rd_count = ntohl (lookup_msg->rd_count);
  struct GNUNET_GNSRECORD_Data rd[rd_count];
  uint32_t r_id = ntohl (lookup_msg->id);
  struct GNUNET_GNS_LookupRequest *lr;
  GNUNET_GNS_LookupResultProcessor proc;
  void *proc_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received lookup reply from GNS service (%u records)\n",
       (unsigned int) rd_count);
  for (lr = handle->lookup_head; NULL != lr; lr = lr->next)
    if (lr->r_id == r_id)
      break;
  if (NULL == lr)
    return;
  proc = lr->lookup_proc;
  proc_cls = lr->proc_cls;
  GNUNET_CONTAINER_DLL_remove (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  GNUNET_free (lr);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_GNSRECORD_records_deserialize (mlen,
                                                       (const char*) &lookup_msg[1],
                                                       rd_count,
                                                       rd));
  proc (proc_cls,
        rd_count,
        rd);
}


/**
 * Reconnect to GNS service.
 *
 * @param handle the handle to the GNS service
 */
static void
reconnect (struct GNUNET_GNS_Handle *handle)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT,
                           struct LookupResultMessage,
                           handle),
    GNUNET_MQ_hd_var_size (rev_result,
                           GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP_RESULT,
                           struct ReverseLookupResultMessage,
                           handle),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_GNS_LookupRequest *lh;
  struct GNUNET_GNS_ReverseLookupRequest *rlh;

  GNUNET_assert (NULL == handle->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect to GNS\n");
  handle->mq = GNUNET_CLIENT_connecT (handle->cfg,
                                      "gns",
                                      handlers,
                                      &mq_error_handler,
                                      handle);
  if (NULL == handle->mq)
    return;
  for (lh = handle->lookup_head; NULL != lh; lh = lh->next)
    GNUNET_MQ_send_copy (handle->mq,
                         lh->env);
  for (rlh = handle->rev_lookup_head; NULL != rlh; rlh = rlh->next)
    GNUNET_MQ_send_copy (handle->mq,
                         rlh->env);
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
  if (NULL == handle->mq)
  {
    GNUNET_free (handle);
    return NULL;
  }
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
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_assert (NULL == handle->lookup_head);
  GNUNET_assert (NULL == handle->rev_lookup_head);
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
  struct GNUNET_GNS_Handle *handle = lr->gns_handle;

  GNUNET_CONTAINER_DLL_remove (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  GNUNET_MQ_discard (lr->env);
  GNUNET_free (lr);
}

/**
 * Cancel pending reverse lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_GNS_reverse_lookup_cancel (struct GNUNET_GNS_ReverseLookupRequest *lr)
{
  struct GNUNET_GNS_Handle *handle = lr->gns_handle;

  GNUNET_CONTAINER_DLL_remove (handle->rev_lookup_head,
                               handle->rev_lookup_tail,
                               lr);
  GNUNET_MQ_discard (lr->env);
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
  struct LookupMessage *lookup_msg;
  struct GNUNET_GNS_LookupRequest *lr;
  size_t nlen;

  if (NULL == name)
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to lookup `%s' in GNS\n",
       name);
  nlen = strlen (name) + 1;
  if (nlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*lr))
  {
    GNUNET_break (0);
    return NULL;
  }
  lr = GNUNET_new (struct GNUNET_GNS_LookupRequest);
  lr->gns_handle = handle;
  lr->lookup_proc = proc;
  lr->proc_cls = proc_cls;
  lr->r_id = handle->r_id_gen++;
  lr->env = GNUNET_MQ_msg_extra (lookup_msg,
                                 nlen,
                                 GNUNET_MESSAGE_TYPE_GNS_LOOKUP);
  lookup_msg->id = htonl (lr->r_id);
  lookup_msg->options = htons ((uint16_t) options);
  lookup_msg->zone = *zone;
  lookup_msg->type = htonl (type);
  if (NULL != shorten_zone_key)
  {
    lookup_msg->have_key = htons (GNUNET_YES);
    lookup_msg->shorten_key = *shorten_zone_key;
  }
  GNUNET_memcpy (&lookup_msg[1],
                 name,
                 nlen);
  GNUNET_CONTAINER_DLL_insert (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq,
                         lr->env);
  return lr;
}

/**
 * Perform an asynchronous reverse lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param zone_key zone to find a name for
 * @param root_key our zone
 * @param proc processor to call on result
 * @param proc_cls closure for @a proc
 * @return handle to the request
 */
struct GNUNET_GNS_ReverseLookupRequest*
GNUNET_GNS_reverse_lookup (struct GNUNET_GNS_Handle *handle,
                           const struct GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
                           const struct GNUNET_CRYPTO_EcdsaPublicKey *root_key,
                           GNUNET_GNS_ReverseLookupResultProcessor proc,
                           void *proc_cls)
{
  /* IPC to shorten gns names, return shorten_handle */
  struct ReverseLookupMessage *rev_lookup_msg;
  struct GNUNET_GNS_ReverseLookupRequest *lr;

  if ((NULL == zone_key) || (NULL == root_key))
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to reverse lookup in GNS\n");
  lr = GNUNET_new (struct GNUNET_GNS_ReverseLookupRequest);
  lr->gns_handle = handle;
  lr->lookup_proc = proc;
  lr->proc_cls = proc_cls;
  lr->r_id = handle->r_id_gen++;
  lr->env = GNUNET_MQ_msg (rev_lookup_msg,
                           GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP);
  rev_lookup_msg->id = htonl (lr->r_id);
  rev_lookup_msg->zone_pkey = *zone_key;
  rev_lookup_msg->root_pkey = *root_key;
  GNUNET_CONTAINER_DLL_insert (handle->rev_lookup_head,
                               handle->rev_lookup_tail,
                               lr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq,
                         lr->env);
  return lr;
}
/* end of gns_api.c */
