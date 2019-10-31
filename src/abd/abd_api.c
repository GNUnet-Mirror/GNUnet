/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file abd/abd_api.c
 * @brief library to access the ABD service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "abd.h"
#include "abd_serialization.h"
#include "gnunet_abd_service.h"
#include "gnunet_identity_service.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "abd-api", __VA_ARGS__)

/**
 * Handle to a verify request
 */
struct GNUNET_ABD_Request
{

  /**
   * DLL
   */
  struct GNUNET_ABD_Request *next;

  /**
   * DLL
   */
  struct GNUNET_ABD_Request *prev;

  /**
   * handle to abd service
   */
  struct GNUNET_ABD_Handle *abd_handle;

  /**
   * processor to call on verify result
   */
  GNUNET_ABD_CredentialResultProcessor verify_proc;

  /**
   * @e verify_proc closure
   */
  void *proc_cls;

  /**
   * processor to call on intermediate result
   */
  GNUNET_ABD_IntermediateResultProcessor int_proc;

  /**
   * @e verify_proc2 closure
   */
  void *proc2_cls;

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
 * Connection to the ABD service.
 */
struct GNUNET_ABD_Handle
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
   * Head of linked list of active verify requests.
   */
  struct GNUNET_ABD_Request *request_head;

  /**
   * Tail of linked list of active verify requests.
   */
  struct GNUNET_ABD_Request *request_tail;

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
 * Reconnect to ABD service.
 *
 * @param handle the handle to the ABD service
 */
static void
reconnect (struct GNUNET_ABD_Handle *handle);


/**
 * Reconnect to ABD
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_ABD_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our handle
 */
static void
force_reconnect (struct GNUNET_ABD_Handle *handle)
{
  GNUNET_MQ_destroy (handle->mq);
  handle->mq = NULL;
  handle->reconnect_backoff =
    GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
                                  &reconnect_task,
                                  handle);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_ABD_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_ABD_Handle *handle = cls;

  force_reconnect (handle);
}


/**
 * Check validity of message received from the ABD service
 *
 * @param cls the `struct GNUNET_ABD_Handle *`
 * @param vr_msg the incoming message
 */
static int
check_result (void *cls, const struct DelegationChainResultMessage *vr_msg)
{
  // TODO
  return GNUNET_OK;
}


/**
 * Handler for messages received from the ABD service
 *
 * @param cls the `struct GNUNET_ABD_Handle *`
 * @param vr_msg the incoming message
 */
static void
handle_result (void *cls, const struct DelegationChainResultMessage *vr_msg)
{
  struct GNUNET_ABD_Handle *handle = cls;
  uint32_t r_id = ntohl (vr_msg->id);
  struct GNUNET_ABD_Request *vr;
  size_t mlen = ntohs (vr_msg->header.size) - sizeof (*vr_msg);
  uint32_t d_count = ntohl (vr_msg->d_count);
  uint32_t c_count = ntohl (vr_msg->c_count);
  struct GNUNET_ABD_Delegation d_chain[d_count];
  struct GNUNET_ABD_Delegate dels[c_count];
  GNUNET_ABD_CredentialResultProcessor proc;
  void *proc_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received verify reply from ABD service\n");
  for (vr = handle->request_head; NULL != vr; vr = vr->next)
    if (vr->r_id == r_id)
      break;
  if (NULL == vr)
    return;
  proc = vr->verify_proc;
  proc_cls = vr->proc_cls;
  GNUNET_CONTAINER_DLL_remove (handle->request_head, handle->request_tail, vr);
  GNUNET_MQ_discard (vr->env);
  GNUNET_free (vr);
  GNUNET_assert (
    GNUNET_OK ==
    GNUNET_ABD_delegation_chain_deserialize (mlen,
                                             (const char *) &vr_msg[1],
                                             d_count,
                                             d_chain,
                                             c_count,
                                             dels));
  if (GNUNET_NO == ntohl (vr_msg->del_found))
  {
    proc (proc_cls, 0, NULL, 0,
          NULL);
  }
  else
  {
    proc (proc_cls, d_count, d_chain, c_count, dels);
  }
}


static int
check_intermediate (void *cls, const struct
                    DelegationChainIntermediateMessage *vr_msg)
{
  // TODO
  return GNUNET_OK;
}


static void
handle_intermediate (void *cls, const struct
                     DelegationChainIntermediateMessage *vr_msg)
{
  struct GNUNET_ABD_Handle *handle = cls;
  uint32_t r_id = ntohl (vr_msg->id);
  uint32_t size = ntohl (vr_msg->size);
  bool is_bw = ntohs (vr_msg->is_bw);
  struct GNUNET_ABD_Request *vr;
  GNUNET_ABD_IntermediateResultProcessor proc;
  void *proc_cls;
  struct GNUNET_ABD_Delegation *dd;


  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received intermediate reply from ABD service\n");

  for (vr = handle->request_head; NULL != vr; vr = vr->next)
    if (vr->r_id == r_id)
      break;
  if (NULL == vr)
    return;

  proc = vr->int_proc;
  proc_cls = vr->proc2_cls;

  dd = GNUNET_new (struct GNUNET_ABD_Delegation);
  GNUNET_assert (
    GNUNET_OK ==
    GNUNET_ABD_delegation_chain_deserialize (size,
                                             (const char *) &vr_msg[1],
                                             1,
                                             dd,
                                             0,
                                             NULL));
  proc (proc_cls, dd, is_bw);
}


/**
 * Reconnect to ABD service.
 *
 * @param handle the handle to the ABD service
 */
static void
reconnect (struct GNUNET_ABD_Handle *handle)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  {GNUNET_MQ_hd_var_size (result,
                          GNUNET_MESSAGE_TYPE_ABD_VERIFY_RESULT,
                          struct DelegationChainResultMessage,
                          handle),
   GNUNET_MQ_hd_var_size (result,
                          GNUNET_MESSAGE_TYPE_ABD_COLLECT_RESULT,
                          struct DelegationChainResultMessage,
                          handle),
   GNUNET_MQ_hd_var_size (intermediate,
                          GNUNET_MESSAGE_TYPE_ABD_INTERMEDIATE_RESULT,
                          struct DelegationChainIntermediateMessage,
                          handle),
   GNUNET_MQ_handler_end ()};
  struct GNUNET_ABD_Request *vr;

  GNUNET_assert (NULL == handle->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect to ABD\n");
  handle->mq = GNUNET_CLIENT_connect (handle->cfg,
                                      "abd",
                                      handlers,
                                      &mq_error_handler,
                                      handle);
  if (NULL == handle->mq)
    return;
  for (vr = handle->request_head; NULL != vr; vr = vr->next)
    GNUNET_MQ_send_copy (handle->mq, vr->env);
}


/**
 * Initialize the connection with the ABD service.
 *
 * @param cfg configuration to use
 * @return handle to the ABD service, or NULL on error
 */
struct GNUNET_ABD_Handle *
GNUNET_ABD_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ABD_Handle *handle;

  handle = GNUNET_new (struct GNUNET_ABD_Handle);
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
 * Shutdown connection with the ABD service.
 *
 * @param handle handle of the ABD connection to stop
 */
void
GNUNET_ABD_disconnect (struct GNUNET_ABD_Handle *handle)
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
  GNUNET_assert (NULL == handle->request_head);
  GNUNET_free (handle);
}


/**
 * Cancel pending verify request
 *
 * @param lr the verify request to cancel
 */
void
GNUNET_ABD_request_cancel (struct GNUNET_ABD_Request *lr)
{
  struct GNUNET_ABD_Handle *handle = lr->abd_handle;

  GNUNET_CONTAINER_DLL_remove (handle->request_head, handle->request_tail, lr);
  GNUNET_MQ_discard (lr->env);
  GNUNET_free (lr);
}


/**
 * Performs attribute collection.
 * Collects all abds of subject to fulfill the
 * attribute, if possible
 *
 * @param handle handle to the Credential service
 * @param issuer_key the issuer public key
 * @param issuer_attribute the issuer attribute
 * @param subject_key the subject public key
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_ABD_Request *
GNUNET_ABD_collect (
  struct GNUNET_ABD_Handle *handle,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key,
  const char *issuer_attribute,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *subject_key,
  enum GNUNET_ABD_AlgoDirectionFlags direction,
  GNUNET_ABD_CredentialResultProcessor proc,
  void *proc_cls,
  GNUNET_ABD_IntermediateResultProcessor proc2,
  void *proc2_cls)
{
  /* IPC to shorten abd names, return shorten_handle */
  struct CollectMessage *c_msg;
  struct GNUNET_ABD_Request *vr;
  size_t nlen;

  if (NULL == issuer_attribute)
  {
    GNUNET_break (0);
    return NULL;
  }

  // DEBUG LOG
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to collect `%s' in ABD\n",
       issuer_attribute);
  nlen = strlen (issuer_attribute) + 1;
  if (nlen >= GNUNET_MAX_MESSAGE_SIZE - sizeof (*vr))
  {
    GNUNET_break (0);
    return NULL;
  }
  vr = GNUNET_new (struct GNUNET_ABD_Request);
  vr->abd_handle = handle;
  vr->verify_proc = proc;
  vr->proc_cls = proc_cls;
  vr->int_proc =  proc2;
  vr->proc2_cls = proc2_cls;
  vr->r_id = handle->r_id_gen++;
  vr->env =
    GNUNET_MQ_msg_extra (c_msg, nlen, GNUNET_MESSAGE_TYPE_ABD_COLLECT);
  c_msg->id = htonl (vr->r_id);
  c_msg->subject_key = *subject_key;
  c_msg->issuer_key = *issuer_key;
  c_msg->issuer_attribute_len = htons (strlen (issuer_attribute));
  c_msg->resolution_algo = htons (direction);

  GNUNET_memcpy (&c_msg[1], issuer_attribute, strlen (issuer_attribute));
  GNUNET_CONTAINER_DLL_insert (handle->request_head, handle->request_tail, vr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq, vr->env);
  return vr;
}


/**
 * Performs attribute verification.
 * Checks if there is a delegation chain from
 * attribute ``issuer_attribute'' issued by the issuer
 * with public key ``issuer_key'' maps to the attribute
 * ``subject_attribute'' claimed by the subject with key
 * ``subject_key''
 *
 * @param handle handle to the Credential service
 * @param issuer_key the issuer public key
 * @param issuer_attribute the issuer attribute
 * @param subject_key the subject public key
 * @param delegate_count number of delegates provided
 * @param delegates subject delegates
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_ABD_Request *
GNUNET_ABD_verify (
  struct GNUNET_ABD_Handle *handle,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key,
  const char *issuer_attribute,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *subject_key,
  uint32_t delegate_count,
  const struct GNUNET_ABD_Delegate *delegates,
  enum GNUNET_ABD_AlgoDirectionFlags direction,
  GNUNET_ABD_CredentialResultProcessor proc,
  void *proc_cls,
  GNUNET_ABD_IntermediateResultProcessor proc2,
  void *proc2_cls)
{
  /* IPC to shorten abd names, return shorten_handle */
  struct VerifyMessage *v_msg;
  struct GNUNET_ABD_Request *vr;
  size_t nlen;
  size_t clen;

  if ((NULL == issuer_attribute) || (NULL == delegates))
  {
    GNUNET_break (0);
    return NULL;
  }

  clen = GNUNET_ABD_delegates_get_size (delegate_count, delegates);

  // DEBUG LOG
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to verify `%s' in ABD\n",
       issuer_attribute);
  nlen = strlen (issuer_attribute) + 1 + clen;
  if (nlen >= GNUNET_MAX_MESSAGE_SIZE - sizeof (*vr))
  {
    GNUNET_break (0);
    return NULL;
  }
  vr = GNUNET_new (struct GNUNET_ABD_Request);
  vr->abd_handle = handle;
  vr->verify_proc = proc;
  vr->proc_cls = proc_cls;
  vr->int_proc =  proc2;
  vr->proc2_cls = proc2_cls;
  vr->r_id = handle->r_id_gen++;
  vr->env =
    GNUNET_MQ_msg_extra (v_msg, nlen, GNUNET_MESSAGE_TYPE_ABD_VERIFY);
  v_msg->id = htonl (vr->r_id);
  v_msg->subject_key = *subject_key;
  v_msg->d_count = htonl (delegate_count);
  v_msg->issuer_key = *issuer_key;
  v_msg->issuer_attribute_len = htons (strlen (issuer_attribute));
  v_msg->resolution_algo = htons (direction);

  GNUNET_memcpy (&v_msg[1], issuer_attribute, strlen (issuer_attribute));
  GNUNET_ABD_delegates_serialize (delegate_count,
                                  delegates,
                                  clen,
                                  ((char *) &v_msg[1])
                                  + strlen (issuer_attribute) + 1);
  GNUNET_CONTAINER_DLL_insert (handle->request_head, handle->request_tail, vr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq, vr->env);
  return vr;
}


/* end of abd_api.c */
