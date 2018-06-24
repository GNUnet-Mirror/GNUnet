/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include "gns_api.h"


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

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Problem with message queue. error: %i\n",
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
check_result (void *cls,
              const struct LookupResultMessage *lookup_msg)
{
  size_t mlen = ntohs (lookup_msg->header.size) - sizeof (*lookup_msg);
  uint32_t rd_count = ntohl (lookup_msg->rd_count);
  struct GNUNET_GNSRECORD_Data rd[rd_count];

  (void) cls;
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

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_GNSRECORD_records_deserialize (mlen,
                                                       (const char*) &lookup_msg[1],
                                                       rd_count,
                                                       rd));
  proc (proc_cls,
        rd_count,
        rd);
  GNUNET_CONTAINER_DLL_remove (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  if (NULL != lr->env)
    GNUNET_MQ_discard (lr->env);
  GNUNET_free (lr);
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
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_GNS_LookupRequest *lh;

  GNUNET_assert (NULL == handle->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect to GNS\n");
  handle->mq = GNUNET_CLIENT_connect (handle->cfg,
                                      "gns",
                                      handlers,
                                      &mq_error_handler,
                                      handle);
  if (NULL == handle->mq)
    return;
  for (lh = handle->lookup_head; NULL != lh; lh = lh->next)
    GNUNET_MQ_send_copy (handle->mq,
                         lh->env);
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
  GNUNET_free (handle);
}


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 * @return closure from the lookup result processor
 */
void *
GNUNET_GNS_lookup_cancel (struct GNUNET_GNS_LookupRequest *lr)
{
  struct GNUNET_GNS_Handle *handle = lr->gns_handle;
  void *ret;

  GNUNET_CONTAINER_DLL_remove (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  GNUNET_MQ_discard (lr->env);
  ret = lr->proc_cls;
  GNUNET_free (lr);
  return ret;
}


/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone the zone to start the resolution in
 * @param type the record type to look up
 * @param options local options for the lookup
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
  if (nlen >= GNUNET_MAX_MESSAGE_SIZE - sizeof (*lr))
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


/* end of gns_api.c */
