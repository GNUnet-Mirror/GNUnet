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
#include "gnunet_signatures.h"
#include "credential.h"
#include "gnunet_credential_service.h"
#include "gnunet_identity_service.h"


#define LOG(kind,...) GNUNET_log_from (kind, "credential-api",__VA_ARGS__)

/**
 * Handle to a verify request
 */
struct GNUNET_CREDENTIAL_Request
{

  /**
   * DLL
   */
  struct GNUNET_CREDENTIAL_Request *next;

  /**
   * DLL
   */
  struct GNUNET_CREDENTIAL_Request *prev;

  /**
   * handle to credential service
   */
  struct GNUNET_CREDENTIAL_Handle *credential_handle;

  /**
   * processor to call on verify result
   */
  GNUNET_CREDENTIAL_VerifyResultProcessor verify_proc;

  /**
   * @e verify_proc closure
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
   * Head of linked list of active verify requests.
   */
  struct GNUNET_CREDENTIAL_Request *verify_head;

  /**
   * Tail of linked list of active verify requests.
   */
  struct GNUNET_CREDENTIAL_Request *verify_tail;

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
              const struct VerifyResultMessage *vr_msg)
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
               const struct VerifyResultMessage *vr_msg)
{
  struct GNUNET_CREDENTIAL_Handle *handle = cls;
  uint32_t r_id = ntohl (vr_msg->id);
  struct GNUNET_CREDENTIAL_Request *vr;
  GNUNET_CREDENTIAL_VerifyResultProcessor proc;
  void *proc_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received verify reply from CREDENTIAL service\n");
  for (vr = handle->verify_head; NULL != vr; vr = vr->next)
    if (vr->r_id == r_id)
      break;
  if (NULL == vr)
    return;
  proc = vr->verify_proc;
  proc_cls = vr->proc_cls;
  GNUNET_CONTAINER_DLL_remove (handle->verify_head,
                               handle->verify_tail,
                               vr);
  GNUNET_free (vr);
  /**
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CREDENTIAL_records_deserialize (mlen,
                                                       (const char*) &lookup_msg[1],
                                                       rd_count,
                                                         rd));
                                                         */
  proc (proc_cls,
        NULL,
        GNUNET_NO); // TODO
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
                           GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT,
                           struct VerifyResultMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CREDENTIAL_Request *vr;

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
  for (vr = handle->verify_head; NULL != vr; vr = vr->next)
    GNUNET_MQ_send_copy (handle->mq,
                         vr->env);
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
  GNUNET_assert (NULL == handle->verify_head);
  GNUNET_free (handle);
}


/**
 * Cancel pending verify request
 *
 * @param lr the verify request to cancel
 */
void
GNUNET_CREDENTIAL_verify_cancel (struct GNUNET_CREDENTIAL_Request *vr)
{
  struct GNUNET_CREDENTIAL_Handle *handle = vr->credential_handle;

  GNUNET_CONTAINER_DLL_remove (handle->verify_head,
                               handle->verify_tail,
                               vr);
  GNUNET_MQ_discard (vr->env);
  GNUNET_free (vr);
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
 * @param subject_attribute the attribute claimed by the subject
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_Request*
GNUNET_CREDENTIAL_verify (struct GNUNET_CREDENTIAL_Handle *handle,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key,
                          const char *issuer_attribute,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *subject_key,
                          const char *subject_attribute,
                          GNUNET_CREDENTIAL_VerifyResultProcessor proc,
                          void *proc_cls)
{
  /* IPC to shorten credential names, return shorten_handle */
  struct VerifyMessage *v_msg;
  struct GNUNET_CREDENTIAL_Request *vr;
  size_t nlen;

  if (NULL == issuer_attribute || NULL == subject_attribute)
  {
    GNUNET_break (0);
    return NULL;
  }
  //DEBUG LOG
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to verify `%s' in CREDENTIAL\n",
       issuer_attribute);
  nlen = strlen (issuer_attribute) + 1 + strlen (subject_attribute) + 1;
  if (nlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*vr))
  {
    GNUNET_break (0);
    return NULL;
  }
  vr = GNUNET_new (struct GNUNET_CREDENTIAL_Request);
  vr->credential_handle = handle;
  vr->verify_proc = proc;
  vr->proc_cls = proc_cls;
  vr->r_id = handle->r_id_gen++;
  vr->env = GNUNET_MQ_msg_extra (v_msg,
                                 nlen,
                                 GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY);
  v_msg->id = htonl (vr->r_id);
  v_msg->subject_key = *subject_key;
  v_msg->issuer_key =  *issuer_key;
  GNUNET_memcpy (&v_msg[1],
                 issuer_attribute,
                 strlen (issuer_attribute));
  GNUNET_memcpy (((char*)&v_msg[1]) + strlen (issuer_attribute) + 1,
                 subject_attribute,
                 strlen (subject_attribute));
  GNUNET_CONTAINER_DLL_insert (handle->verify_head,
                               handle->verify_tail,
                               vr);
  if (NULL != handle->mq)
    GNUNET_MQ_send_copy (handle->mq,
                         vr->env);
  return vr;
}

/**
 * Issue an attribute to a subject
 *
 * @param handle handle to the Credential service
 * @param issuer the ego that should be used to issue the attribute
 * @param subject the subject of the attribute
 * @param attribute the name of the attribute
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_CredentialRecordData *
GNUNET_CREDENTIAL_issue (struct GNUNET_CREDENTIAL_Handle *handle,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                         struct GNUNET_CRYPTO_EcdsaPublicKey *subject,
                         const char *attribute)
{
  struct GNUNET_CREDENTIAL_CredentialRecordData *crd;

  crd = GNUNET_malloc (sizeof (struct GNUNET_CREDENTIAL_CredentialRecordData) + strlen (attribute) + 1);

  crd->purpose.size = htonl (strlen (attribute) + 1 +
                             sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
                			       sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			                       sizeof (struct GNUNET_TIME_AbsoluteNBO));
  crd->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CREDENTIAL);
  GNUNET_CRYPTO_ecdsa_key_get_public (issuer,
                                      &crd->issuer_key);
  crd->subject_key = *subject;
  GNUNET_memcpy (&crd[1],
                 attribute,
                 strlen (attribute));
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign (issuer,
                                &crd->purpose,
                                &crd->sig))
  {
    GNUNET_break (0);
    GNUNET_free (crd);
    return NULL;
  }
  return crd;
}




/* end of credential_api.c */
