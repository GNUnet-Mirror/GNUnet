/*
     This file is part of GNUnet.
     Copyright (C) 2016 Christian Grothoff (and other contributing authors)

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
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;

};


/**
 * Try again to connect to the service.
 *
 * @param cls handle to the service.
 * @param tc scheduler context
 */
static void
reconnect (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  GNUNET_assert (h->reconnect_task == NULL);

  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to identity provider service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay, GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls,
		 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_Token token;
  struct GNUNET_IDENTITY_PROVIDER_Ticket ticket;
  const struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm;
  const struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *erm;
  char *str;
  uint16_t size;

  if (NULL == msg)
  {
    reschedule_connect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d from identity provider service\n",
       ntohs (msg->type));
  size = ntohs (msg->size);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_RESULT:
    if (size < sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage))
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    irm = (const struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *) msg;
    str = (char *) &irm[1];
    if ( (size > sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage)) &&
	 ('\0' != str[size - sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) - 1]) )
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    if (size == sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage))
      str = NULL;

    op = h->op_head;
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_CLIENT_receive (h->client, &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    ticket.data = str;
    if (NULL != op->iss_cb)
      op->iss_cb (op->cls, &ticket);
    GNUNET_free (op);
    break;
   case GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE_RESULT:
    if (size < sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage))
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    erm = (const struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *) msg;
    str = (char *) &erm[1];
    if ( (size > sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage)) &&
	 ('\0' != str[size - sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage) - 1]) )
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    if (size == sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage))
      str = NULL;

    op = h->op_head;
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_CLIENT_receive (h->client, &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    token.data = str;
    if (NULL != op->ex_cb)
      op->ex_cb (op->cls, &token);
    GNUNET_free (op);
    break;
  
  default:
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h identity handle
 */
static void
transmit_next (struct GNUNET_IDENTITY_PROVIDER_Handle *h);


/**
 * Transmit next message to service.
 *
 * @param cls the `struct GNUNET_IDENTITY_PROVIDER_Handle`.
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_next_message (void *cls,
		   size_t size,
		   void *buf)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op = h->op_head;
  size_t ret;

  h->th = NULL;
  if (NULL == op)
    return 0;
  ret = ntohs (op->msg->size);
  if (ret > size)
  {
    reschedule_connect (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending message of type %d to identity provider service\n",
       ntohs (op->msg->type));
  memcpy (buf, op->msg, ret);
  if ( (NULL == op->iss_cb) &&
       (NULL == op->ex_cb) )
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_free (op);
    transmit_next (h);
  }
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client,
			   &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return ret;
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h identity provider handle
 */
static void
transmit_next (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op = h->op_head;

  GNUNET_assert (NULL == h->th);
  if (NULL == op)
    return;
  if (NULL == h->client)
    return;
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
					       ntohs (op->msg->size),
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       GNUNET_NO,
					       &send_next_message,
					       h);
}


/**
 * Try again to connect to the service.
 *
 * @param cls handle to the identity provider service.
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to identity provider service.\n");
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("identity-provider", h->cfg);
  GNUNET_assert (NULL != h->client);
  transmit_next (h);
  GNUNET_assert (NULL != h->th);
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
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  h->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, h);
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
  op = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_Operation) +
		      sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueMessage) +
		      slen);
  op->h = id;
  op->iss_cb = cb;
  op->cls = cb_cls;
  im = (struct GNUNET_IDENTITY_PROVIDER_IssueMessage *) &op[1];
  im->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE);
  im->header.size = htons (sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueMessage) +
			    slen);
  im->iss_key = *iss_key;
  im->aud_key = *aud_key;
  im->nonce = htonl (nonce);
  im->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&im[1], scopes, slen);
  op->msg = &im->header;
  GNUNET_CONTAINER_DLL_insert_tail (id->op_head,
				    id->op_tail,
				    op);
  if (NULL == id->th)
    transmit_next (id);
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
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_Operation) +
                      sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage) +
                      slen);
  op->h = id;
  op->ex_cb = cont;
  op->cls = cont_cls;
  em = (struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage *) &op[1];
  em->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE);
  em->header.size = htons (sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage) +
                           slen);
  em->aud_privkey = *aud_privkey;
  memcpy (&em[1], ticket_str, slen);
  GNUNET_free (ticket_str);
  op->msg = &em->header;
  GNUNET_CONTAINER_DLL_insert_tail (id->op_head,
                                    id->op_tail,
                                    op);
  if (NULL == id->th)
    transmit_next (id);
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

  if ( (h->op_head != op) ||
       (NULL == h->client) )
  {
    /* request not active, can simply remove */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client aborted non-head operation, simply removing it\n");
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    GNUNET_free (op);
    return;
  }
  if (NULL != h->th)
  {
    /* request active but not yet with service, can still abort */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client aborted head operation prior to transmission, aborting it\n");
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    GNUNET_free (op);
    transmit_next (h);
    return;
  }
  /* request active with service, simply ensure continuations are not called */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client aborted active request, NULLing continuation\n");
  op->ex_cb = NULL;
  op->iss_cb = NULL;
}


/**
 * Disconnect from service
 *
 * @param h handle to destroy
 */
void
GNUNET_IDENTITY_PROVIDER_disconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;

  GNUNET_assert (NULL != h);
  if (h->reconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  while (NULL != (op = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    GNUNET_free (op);
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
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
