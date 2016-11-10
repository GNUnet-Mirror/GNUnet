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
 * @file credential/credential_api.c
 * @brief library to access the CREDENTIAL service
 * @author Adnan Husain
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "credential.h"
#include "gnunet_credential_service.h"
#include "gnunet_identity_service.h"


#define LOG(kind,...) GNUNET_log_from (kind, "credential-api",__VA_ARGS__)

/**
 * Handle to a lookup request
 */
struct GNUNET_CREDENTIAL_LookupRequest
{

  /**
   * DLL
   */
  struct GNUNET_CREDENTIAL_LookupRequest *next;

  /**
   * DLL
   */
  struct GNUNET_CREDENTIAL_LookupRequest *prev;

  /**
   * handle to credential service
   */
  struct GNUNET_CREDENTIAL_Handle *credential_handle;

  /**
   * processor to call on lookup result
   */
  GNUNET_CREDENTIAL_LookupResultProcessor lookup_proc;

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
 * Connection to the CREDENTIAL service.
 */
struct GNUNET_CREDENTIAL_Handle
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
  struct GNUNET_CREDENTIAL_LookupRequest *lookup_head;

  /**
   * Tail of linked list of active lookup requests.
   */
  struct GNUNET_CREDENTIAL_LookupRequest *lookup_tail;

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
 * Reconnect to CREDENTIAL service.
 *
 * @param handle the handle to the CREDENTIAL service
 */
static void
reconnect (struct GNUNET_CREDENTIAL_Handle *handle);


/**
 * Reconnect to CREDENTIAL
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_CREDENTIAL_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our handle
 */
static void
force_reconnect (struct GNUNET_CREDENTIAL_Handle *handle)
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
 * @param cls closure with the `struct GNUNET_CREDENTIAL_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_CREDENTIAL_Handle *handle = cls;

  force_reconnect (handle);
}


/**
 * Check validity of message received from the CREDENTIAL service
 *
 * @param cls the `struct GNUNET_CREDENTIAL_Handle *`
 * @param loookup_msg the incoming message
 */
static int
check_result (void *cls,
              const struct LookupResultMessage *lookup_msg)
{
  //TODO
  return GNUNET_OK;
}


/**
 * Handler for messages received from the CREDENTIAL service
 *
 * @param cls the `struct GNUNET_CREDENTIAL_Handle *`
 * @param loookup_msg the incoming message
 */
static void
handle_result (void *cls,
               const struct LookupResultMessage *lookup_msg)
{
  struct GNUNET_CREDENTIAL_Handle *handle = cls;
  uint32_t cd_count = ntohl (lookup_msg->cd_count);
  struct GNUNET_CREDENTIAL_RecordData cd[cd_count];
  uint32_t r_id = ntohl (lookup_msg->id);
  struct GNUNET_CREDENTIAL_LookupRequest *lr;
  GNUNET_CREDENTIAL_LookupResultProcessor proc;
  void *proc_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received lookup reply from CREDENTIAL service (%u credentials)\n",
       (unsigned int) cd_count);
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
  /**
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CREDENTIAL_records_deserialize (mlen,
                                                       (const char*) &lookup_msg[1],
                                                       rd_count,
                                                         rd));
                                                         */
  proc (proc_cls,
        NULL,
        cd_count,
        cd); // TODO
}


/**
 * Reconnect to CREDENTIAL service.
 *
 * @param handle the handle to the CREDENTIAL service
 */
static void
reconnect (struct GNUNET_CREDENTIAL_Handle *handle)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_CREDENTIAL_LOOKUP_RESULT,
                           struct LookupResultMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CREDENTIAL_LookupRequest *lh;

  GNUNET_assert (NULL == handle->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect to CREDENTIAL\n");
  handle->mq = GNUNET_CLIENT_connecT (handle->cfg,
                                      "credential",
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
 * Initialize the connection with the CREDENTIAL service.
 *
 * @param cfg configuration to use
 * @return handle to the CREDENTIAL service, or NULL on error
 */
struct GNUNET_CREDENTIAL_Handle *
GNUNET_CREDENTIAL_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CREDENTIAL_Handle *handle;

  handle = GNUNET_new (struct GNUNET_CREDENTIAL_Handle);
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
 * Shutdown connection with the CREDENTIAL service.
 *
 * @param handle handle of the CREDENTIAL connection to stop
 */
void
GNUNET_CREDENTIAL_disconnect (struct GNUNET_CREDENTIAL_Handle *handle)
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
 */
void
GNUNET_CREDENTIAL_lookup_cancel (struct GNUNET_CREDENTIAL_LookupRequest *lr)
{
  struct GNUNET_CREDENTIAL_Handle *handle = lr->credential_handle;

  GNUNET_CONTAINER_DLL_remove (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  GNUNET_MQ_discard (lr->env);
  GNUNET_free (lr);
}


/**
 * Perform an asynchronous lookup operation for a credential.
 *
 * @param handle handle to the Credential service
 * @param credential the credential to look up
 * @param subject Ego to check the credential for
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_LookupRequest*
GNUNET_CREDENTIAL_lookup (struct GNUNET_CREDENTIAL_Handle *handle,
                          const char *credential,
                          const struct GNUNET_IDENTITY_Ego *subject,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *subject_key,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key,
                          uint32_t credential_flags,
                          uint32_t max_delegation_depth,
                          GNUNET_CREDENTIAL_LookupResultProcessor proc,
                          void *proc_cls)
{
  /* IPC to shorten credential names, return shorten_handle */
  struct LookupMessage *lookup_msg;
  struct GNUNET_CREDENTIAL_LookupRequest *lr;
  size_t nlen;

  if (NULL == credential)
  {
    GNUNET_break (0);
    return NULL;
  }
  //DEBUG LOG
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to lookup `%s' in CREDENTIAL\n",
       credential);
  nlen = strlen (credential) + 1;
  if (nlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*lr))
  {
    GNUNET_break (0);
    return NULL;
  }
  lr = GNUNET_new (struct GNUNET_CREDENTIAL_LookupRequest);
  lr->credential_handle = handle;
  lr->lookup_proc = proc;
  lr->proc_cls = proc_cls;
  lr->r_id = handle->r_id_gen++;
  lr->env = GNUNET_MQ_msg_extra (lookup_msg,
                                 nlen,
                                 GNUNET_MESSAGE_TYPE_CREDENTIAL_LOOKUP);
  lookup_msg->id = htonl (lr->r_id);
  lookup_msg->subject_key = *subject_key;
  lookup_msg->issuer_key =  *issuer_key;
  GNUNET_memcpy (&lookup_msg[1],
                 credential,
                 nlen);
  GNUNET_CONTAINER_DLL_insert (handle->lookup_head,
                               handle->lookup_tail,
                               lr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq,
                         lr->env);
  return lr;
}


/* end of credential_api.c */
