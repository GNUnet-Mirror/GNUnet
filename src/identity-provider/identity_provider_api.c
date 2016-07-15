/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file identity-provider/identity_provider_api.c
 * @brief api to interact with the identity provider service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_mq_lib.h"
#include "gnunet_identity_provider_service.h"
#include "identity_provider.h"

#define LOG(kind,...) GNUNET_log_from (kind, "identity-api",__VA_ARGS__)



/**
 * Handle for an operation with the service.
 */
struct GNUNET_IDENTITY_PROVIDER_Operation
{

  /**
   * Main handle.
   */
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *prev;

  /**
   * Message to send to the service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke with the result of the transmission; @e cb
   * will be NULL in this case.
   */
  GNUNET_IDENTITY_PROVIDER_ExchangeCallback ex_cb;

  /**
   * Continuation to invoke with the result of the transmission for
   * 'issue' operations (@e cont will be NULL in this case).
   */
  GNUNET_IDENTITY_PROVIDER_IssueCallback iss_cb;

  /**
   * Envelope with the message for this queue entry.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * Closure for @e cont or @e cb.
   */
  void *cls;

};


/**
 * Handle for the service.
 */
struct GNUNET_IDENTITY_PROVIDER_Handle
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
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Head of active operations.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *op_tail;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Connection to service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;

};


/**
 * Try again to connect to the service.
 *
 * @param cls handle to the service.
 */
static void
reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *handle);

/**
 * Reconnect
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our handle
 */
static void
force_reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *handle)
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
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;
  force_reconnect (handle);
}

/**
 * Check validity of message received from the service
 *
 * @param cls the `struct GNUNET_IDENTITY_PROVIDER_Handle *`
 * @param result_msg the incoming message
 */
static int
check_exchange_result (void *cls,
              const struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *erm)
{
  char *str;
  size_t size = ntohs (erm->header.size) - sizeof (*erm);
  

  str = (char *) &erm[1];
  if ( (size > sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage)) &&
       ('\0' != str[size - sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage) - 1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Check validity of message received from the service
 *
 * @param cls the `struct GNUNET_IDENTITY_PROVIDER_Handle *`
 * @param result_msg the incoming message
 */
static int
check_result (void *cls,
              const struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm)
{
  char *str;
  size_t size = ntohs (irm->header.size) - sizeof (*irm);
  str = (char*) &irm[1];
  if ( (size > sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage)) &&
       ('\0' != str[size - sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) - 1]) )
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
handle_exchange_result (void *cls,
                        const struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *erm)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_Token token;
  uint64_t ticket_nonce;
  uint32_t r_id = ntohl (erm->id);
  char *str;
  
  for (op = handle->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;
  str = GNUNET_strdup ((char*)&erm[1]);
  op = handle->op_head;
  GNUNET_CONTAINER_DLL_remove (handle->op_head,
                               handle->op_tail,
                               op);
  token.data = str;
  ticket_nonce = ntohl (erm->ticket_nonce);
  if (NULL != op->ex_cb)
    op->ex_cb (op->cls, &token, ticket_nonce);
  GNUNET_free (str);
  GNUNET_free (op);

}

/**
 * Handler for messages received from the GNS service
 *
 * @param cls the `struct GNUNET_GNS_Handle *`
 * @param loookup_msg the incoming message
 */
static void
handle_result (void *cls,
               const struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_Token token;
  struct GNUNET_IDENTITY_PROVIDER_Ticket ticket;
  uint32_t r_id = ntohl (irm->id);
  char *str;
  char *label_str;
  char *ticket_str;
  char *token_str;

  for (op = handle->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;
  str = GNUNET_strdup ((char*)&irm[1]);
  label_str = strtok (str, ",");

  if (NULL == label_str)
  {
    GNUNET_free (str);
    GNUNET_break (0);
    return;
  }
  ticket_str = strtok (NULL, ",");
  if (NULL == ticket_str)
  {
    GNUNET_free (str);
    GNUNET_break (0);
    return;
  }
  token_str = strtok (NULL, ",");
  if (NULL == token_str)
  {
    GNUNET_free (str);
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (handle->op_head,
                               handle->op_tail,
                               op);
  ticket.data = ticket_str;
  token.data = token_str;
  if (NULL != op->iss_cb)
    op->iss_cb (op->cls, label_str, &ticket, &token);
  GNUNET_free (str);
  GNUNET_free (op);

}

/**
 * Try again to connect to the service.
 *
 * @param cls handle to the identity provider service.
 */
static void
reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  GNUNET_MQ_hd_var_size (result,
                         GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_RESULT,
                         struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage);
  GNUNET_MQ_hd_var_size (exchange_result,
                         GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE_RESULT,
                         struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_result_handler (h),
    make_exchange_result_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;

  GNUNET_assert (NULL == h->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to identity provider service.\n");

  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "identity-provider",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  for (op = h->op_head; NULL != op; op = op->next)
    GNUNET_MQ_send_copy (h->mq,
                         op->env);
}


/**
 * Connect to the identity provider service.
 *
 * @param cfg the configuration to use
 * @return handle to use
 */
struct GNUNET_IDENTITY_PROVIDER_Handle *
GNUNET_IDENTITY_PROVIDER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  h = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Handle);
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
 * Issue an identity token
 *
 * @param id identity service to query
 * @param service_name for which service is an identity wanted
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_issue_token (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss_key,
                                      const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                                      const char* scopes,
                                      struct GNUNET_TIME_Absolute expiration,
                                      uint64_t nonce,
                                      GNUNET_IDENTITY_PROVIDER_IssueCallback cb,
                                      void *cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_IssueMessage *im;
  size_t slen;

  slen = strlen (scopes) + 1;
  if (slen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = id;
  op->iss_cb = cb;
  op->cls = cb_cls;
  op->r_id = id->r_id_gen++;
  op->env = GNUNET_MQ_msg_extra (im,
                                 slen,
                                 GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE);
  im->id = op->r_id;
  im->iss_key = *iss_key;
  im->aud_key = *aud_key;
  im->nonce = htonl (nonce);
  im->expiration = GNUNET_TIME_absolute_hton (expiration);
  GNUNET_memcpy (&im[1], scopes, slen);
  GNUNET_CONTAINER_DLL_insert_tail (id->op_head,
                                    id->op_tail,
                                    op);
  if (NULL != id->mq)
    GNUNET_MQ_send_copy (id->mq,
                         op->env);
  return op;
}


/**
 * Exchange a token ticket for a token
 *
 * @param id identity provider service
 * @param ticket ticket to exchange
 * @param cont function to call once the operation finished
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_exchange_ticket (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                          const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *aud_privkey,
                                          GNUNET_IDENTITY_PROVIDER_ExchangeCallback cont,
                                          void *cont_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage *em;
  size_t slen;
  char *ticket_str;

  ticket_str = GNUNET_IDENTITY_PROVIDER_ticket_to_string (ticket);

  slen = strlen (ticket_str) + 1;
  if (slen >= GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage))
  {
    GNUNET_free (ticket_str);
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = id;
  op->ex_cb = cont;
  op->cls = cont_cls;
  op->r_id = id->r_id_gen++;
  op->env = GNUNET_MQ_msg_extra (em,
                                 slen,
                                 GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE);
  em->aud_privkey = *aud_privkey;
  em->id = htonl (op->r_id);
  GNUNET_memcpy (&em[1], ticket_str, slen);
  GNUNET_free (ticket_str);
  GNUNET_CONTAINER_DLL_insert_tail (id->op_head,
                                    id->op_tail,
                                    op);
  if (NULL != id->mq)
    GNUNET_MQ_send_copy (id->mq,
                         op->env);
  return op;
}


/**
 * Cancel an operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_IDENTITY_PROVIDER_cancel (struct GNUNET_IDENTITY_PROVIDER_Operation *op)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = op->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  GNUNET_MQ_discard (op->env);
  GNUNET_free (op);
}


/**
 * Disconnect from service
 *
 * @param h handle to destroy
 */
void
GNUNET_IDENTITY_PROVIDER_disconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  GNUNET_assert (NULL != h);
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
  GNUNET_assert (NULL == h->op_head);
  GNUNET_free (h);
}

/**
 * Convenience API
 */


/**
 * Destroy token
 *
 * @param token the token
 */
void
GNUNET_IDENTITY_PROVIDER_token_destroy(struct GNUNET_IDENTITY_PROVIDER_Token *token)
{
  GNUNET_assert (NULL != token);
  if (NULL != token->data)
    GNUNET_free (token->data);
  GNUNET_free (token);
}

/**
 * Returns string representation of token. A JSON-Web-Token.
 *
 * @param token the token
 * @return The JWT (must be freed)
 */
char *
GNUNET_IDENTITY_PROVIDER_token_to_string (const struct GNUNET_IDENTITY_PROVIDER_Token *token)
{
  return GNUNET_strdup (token->data);
}

/**
 * Returns string representation of ticket. Base64-Encoded
 *
 * @param ticket the ticket
 * @return the Base64-Encoded ticket
 */
char *
GNUNET_IDENTITY_PROVIDER_ticket_to_string (const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket)
{
  return GNUNET_strdup (ticket->data);
}

/**
 * Created a ticket from a string (Base64 encoded ticket)
 *
 * @param input Base64 encoded ticket
 * @param ticket pointer where the ticket is stored
 * @return GNUNET_OK
 */
int
GNUNET_IDENTITY_PROVIDER_string_to_ticket (const char* input,
                                           struct GNUNET_IDENTITY_PROVIDER_Ticket **ticket)
{
  *ticket = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_Ticket));
  (*ticket)->data = GNUNET_strdup (input);
  return GNUNET_OK;
}


/**
 * Destroys a ticket
 *
 * @param ticket the ticket to destroy
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_destroy(struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket)
{
  GNUNET_assert (NULL != ticket);
  if (NULL != ticket->data)
    GNUNET_free (ticket->data);
  GNUNET_free (ticket);
}





/* end of identity_provider_api.c */
