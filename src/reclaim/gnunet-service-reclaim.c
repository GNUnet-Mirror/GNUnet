/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file src/reclaim/gnunet-service-reclaim.c
 * @brief reclaim Service
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-reclaim_tickets.h"
#include "gnunet_constants.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_protocols.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_signatures.h"
#include "reclaim.h"

/**
 * First pass state
 */
#define STATE_INIT 0

/**
 * Normal operation state
 */
#define STATE_POST_INIT 1

/**
 * Minimum interval between updates
 */
#define MIN_WAIT_TIME GNUNET_TIME_UNIT_MINUTES


/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Namestore handle
 */
static struct GNUNET_NAMESTORE_Handle *nsh;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * Update task
 */
static struct GNUNET_SCHEDULER_Task *update_task;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * An idp client
 */
struct IdpClient;

/**
 * A ticket iteration operation.
 */
struct TicketIteration
{
  /**
   * DLL
   */
  struct TicketIteration *next;

  /**
   * DLL
   */
  struct TicketIteration *prev;

  /**
   * Client which intiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * The operation id fot the iteration in the response for the client
   */
  uint32_t r_id;

  /**
   * The ticket iterator
   */
  struct RECLAIM_TICKETS_Iterator *iter;
};


/**
 * An attribute iteration operation.
 */
struct AttributeIterator
{
  /**
   * Next element in the DLL
   */
  struct AttributeIterator *next;

  /**
   * Previous element in the DLL
   */
  struct AttributeIterator *prev;

  /**
   * IDP client which intiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The operation id fot the zone iteration in the response for the client
   */
  uint32_t request_id;
};


/**
 * An idp client
 */
struct IdpClient
{
  /**
   * DLL
   */
  struct IdpClient *prev;

  /**
   * DLL
   */
  struct IdpClient *next;

  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of the DLL of
   * Attribute iteration operations in
   * progress initiated by this client
   */
  struct AttributeIterator *attr_iter_head;

  /**
   * Tail of the DLL of
   * Attribute iteration operations
   * in progress initiated by this client
   */
  struct AttributeIterator *attr_iter_tail;

  /**
   * Head of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_head;

  /**
   * Tail of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_tail;

  /**
   * Head of DLL of ticket revocation ops
   */
  struct TicketRevocationOperation *revoke_op_head;

  /**
   * Tail of DLL of ticket revocation ops
   */
  struct TicketRevocationOperation *revoke_op_tail;

  /**
   * Head of DLL of ticket issue ops
   */
  struct TicketIssueOperation *issue_op_head;

  /**
   * Tail of DLL of ticket issue ops
   */
  struct TicketIssueOperation *issue_op_tail;

  /**
   * Head of DLL of ticket consume ops
   */
  struct ConsumeTicketOperation *consume_op_head;

  /**
   * Tail of DLL of ticket consume ops
   */
  struct ConsumeTicketOperation *consume_op_tail;

  /**
   * Head of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_head;

  /**
   * Tail of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_tail;
  /**
   * Head of DLL of attribute delete ops
   */
  struct AttributeDeleteHandle *delete_op_head;

  /**
   * Tail of DLL of attribute delete ops
   */
  struct AttributeDeleteHandle *delete_op_tail;
};


/**
 * Handle for attribute deletion request
 */
struct AttributeDeleteHandle
{
  /**
   * DLL
   */
  struct AttributeDeleteHandle *next;

  /**
   * DLL
   */
  struct AttributeDeleteHandle *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;


  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The attribute to delete
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *claim;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_head;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_tail;

  /**
   * Attribute label
   */
  char *label;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Handle for attribute store request
 */
struct AttributeStoreHandle
{
  /**
   * DLL
   */
  struct AttributeStoreHandle *next;

  /**
   * DLL
   */
  struct AttributeStoreHandle *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Identity pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pkey;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The attribute to store
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *claim;

  /**
   * The attribute expiration interval
   */
  struct GNUNET_TIME_Relative exp;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Handle for ticket consume request
 */
struct ConsumeTicketOperation
{
  /**
   * DLL
   */
  struct ConsumeTicketOperation *next;

  /**
   * DLL
   */
  struct ConsumeTicketOperation *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * Ticket consume handle
   */
  struct RECLAIM_TICKETS_ConsumeHandle *ch;
};


/**
 * Updated attribute IDs
 */
struct TicketAttributeUpdateEntry
{
  /**
   * DLL
   */
  struct TicketAttributeUpdateEntry *next;

  /**
   * DLL
   */
  struct TicketAttributeUpdateEntry *prev;

  /**
   * The old ID
   */
  uint64_t old_id;

  /**
   * The new ID
   */
  uint64_t new_id;
};


/**
 * Ticket revocation request handle
 */
struct TicketRevocationOperation
{
  /**
   * DLL
   */
  struct TicketRevocationOperation *prev;

  /**
   * DLL
   */
  struct TicketRevocationOperation *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Revocation handle
   */
  struct RECLAIM_TICKETS_RevokeHandle *rh;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Ticket issue operation handle
 */
struct TicketIssueOperation
{
  /**
   * DLL
   */
  struct TicketIssueOperation *prev;

  /**
   * DLL
   */
  struct TicketIssueOperation *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * DLL for ego handles to egos containing the RECLAIM_ATTRS in a
 * map in json_t format
 *
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego handle
   */
  struct GNUNET_IDENTITY_Ego *ego;

  /**
   * Attribute map. Contains the attributes as json_t
   */
  struct GNUNET_CONTAINER_MultiHashMap *attr_map;
};


/**
 * Client list
 */
static struct IdpClient *client_list_head = NULL;

/**
 * Client list
 */
static struct IdpClient *client_list_tail = NULL;


/**
 * Cleanup attribute delete handle
 *
 * @param adh the attribute to cleanup
 */
static void
cleanup_adh (struct AttributeDeleteHandle *adh)
{
  struct TicketRecordsEntry *le;
  if (NULL != adh->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (adh->ns_it);
  if (NULL != adh->ns_qe)
    GNUNET_NAMESTORE_cancel (adh->ns_qe);
  if (NULL != adh->label)
    GNUNET_free (adh->label);
  if (NULL != adh->claim)
    GNUNET_free (adh->claim);
  while (NULL != (le = adh->tickets_to_update_head)) {
    GNUNET_CONTAINER_DLL_remove (adh->tickets_to_update_head,
                                 adh->tickets_to_update_tail,
                                 le);
    if (NULL != le->label)
      GNUNET_free (le->label);
    if (NULL != le->data)
      GNUNET_free (le->data);
    GNUNET_free (le);
  }
  GNUNET_free (adh);
}


/**
 * Cleanup attribute store handle
 *
 * @param handle handle to clean up
 */
static void
cleanup_as_handle (struct AttributeStoreHandle *ash)
{
  if (NULL != ash->ns_qe)
    GNUNET_NAMESTORE_cancel (ash->ns_qe);
  if (NULL != ash->claim)
    GNUNET_free (ash->claim);
  GNUNET_free (ash);
}


/**
 * Cleanup client
 *
 * @param idp the client to clean up
 */
static void
cleanup_client (struct IdpClient *idp)
{
  struct AttributeIterator *ai;
  struct TicketIteration *ti;
  struct TicketRevocationOperation *rop;
  struct TicketIssueOperation *iss;
  struct ConsumeTicketOperation *ct;
  struct AttributeStoreHandle *as;
  struct AttributeDeleteHandle *adh;

  while (NULL != (iss = idp->issue_op_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->issue_op_head, idp->issue_op_tail, iss);
    GNUNET_free (iss);
  }
  while (NULL != (ct = idp->consume_op_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->consume_op_head,
                                 idp->consume_op_tail,
                                 ct);
    if (NULL != ct->ch)
      RECLAIM_TICKETS_consume_cancel (ct->ch);
    GNUNET_free (ct);
  }
  while (NULL != (as = idp->store_op_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->store_op_head, idp->store_op_tail, as);
    cleanup_as_handle (as);
  }
  while (NULL != (adh = idp->delete_op_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->delete_op_head, idp->delete_op_tail, adh);
    cleanup_adh (adh);
  }

  while (NULL != (ai = idp->attr_iter_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head, idp->attr_iter_tail, ai);
    GNUNET_free (ai);
  }
  while (NULL != (rop = idp->revoke_op_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->revoke_op_head, idp->revoke_op_tail, rop);
    if (NULL != rop->rh)
      RECLAIM_TICKETS_revoke_cancel (rop->rh);
    GNUNET_free (rop);
  }
  while (NULL != (ti = idp->ticket_iter_head)) {
    GNUNET_CONTAINER_DLL_remove (idp->ticket_iter_head,
                                 idp->ticket_iter_tail,
                                 ti);
    if (NULL != ti->iter)
      RECLAIM_TICKETS_iteration_stop (ti->iter);
    GNUNET_free (ti);
  }
  GNUNET_free (idp);
}


/**
 * Cleanup task
 */
static void
cleanup ()
{
  struct IdpClient *cl;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");

  while (NULL != (cl = client_list_head))
  {
    GNUNET_CONTAINER_DLL_remove (client_list_head,
                                 client_list_tail,
                                 cl);
    cleanup_client (cl);
  }
  RECLAIM_TICKETS_deinit ();
  if (NULL != timeout_task)
    GNUNET_SCHEDULER_cancel (timeout_task);
  if (NULL != update_task)
    GNUNET_SCHEDULER_cancel (update_task);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != nsh)
    GNUNET_NAMESTORE_disconnect (nsh);
}


/**
 * Shutdown task
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down...\n");
  cleanup ();
}


/**
 * Sends a ticket result message to the client
 *
 * @param client the client to send to
 * @param r_id the request message ID to reply to
 * @param ticket the ticket to include (may be NULL)
 * @param success the success status of the request
 */
static void
send_ticket_result (const struct IdpClient *client,
                    uint32_t r_id,
                    const struct GNUNET_RECLAIM_Ticket *ticket,
                    uint32_t success)
{
  struct TicketResultMessage *irm;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_RECLAIM_Ticket *ticket_buf;

  if (NULL != ticket) {
    env = GNUNET_MQ_msg_extra (irm,
                               sizeof (struct GNUNET_RECLAIM_Ticket),
                               GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
    ticket_buf = (struct GNUNET_RECLAIM_Ticket *)&irm[1];
    *ticket_buf = *ticket;
  } else {
    env = GNUNET_MQ_msg (irm, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
  }
  // TODO add success member
  irm->id = htonl (r_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending TICKET_RESULT message\n");
  GNUNET_MQ_send (client->mq, env);
}


/**
 * Issue ticket result
 *
 * @param cls out ticket issue operation handle
 * @param ticket the issued ticket
 * @param success issue success status (GNUNET_OK if successful)
 * @param emsg error message (NULL of success is GNUNET_OK)
 */
static void
issue_ticket_result_cb (void *cls,
                        struct GNUNET_RECLAIM_Ticket *ticket,
                        int32_t success,
                        const char *emsg)
{
  struct TicketIssueOperation *tio = cls;
  if (GNUNET_OK != success) {
    send_ticket_result (tio->client, tio->r_id, NULL, GNUNET_SYSERR);
    GNUNET_CONTAINER_DLL_remove (tio->client->issue_op_head,
                                 tio->client->issue_op_tail,
                                 tio);
    GNUNET_free (tio);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error issuing ticket: %s\n", emsg);
    return;
  }
  send_ticket_result (tio->client, tio->r_id, ticket, GNUNET_SYSERR);
  GNUNET_CONTAINER_DLL_remove (tio->client->issue_op_head,
                               tio->client->issue_op_tail,
                               tio);
  GNUNET_free (tio);
}


/**
 * Check issue ticket message
 *
 * @cls unused
 * @im message to check
 * @return GNUNET_OK if message is ok
 */
static int
check_issue_ticket_message (void *cls, const struct IssueTicketMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct IssueTicketMessage)) {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle ticket issue message
 *
 * @param cls our client
 * @param im the message
 */
static void
handle_issue_ticket_message (void *cls, const struct IssueTicketMessage *im)
{
  struct TicketIssueOperation *tio;
  struct IdpClient *idp = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;
  size_t attrs_len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ISSUE_TICKET message\n");
  tio = GNUNET_new (struct TicketIssueOperation);
  attrs_len = ntohs (im->attr_len);
  attrs = GNUNET_RECLAIM_ATTRIBUTE_list_deserialize ((char *)&im[1], attrs_len);
  tio->r_id = ntohl (im->id);
  tio->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->issue_op_head, idp->issue_op_tail, tio);
  RECLAIM_TICKETS_issue (&im->identity,
                         attrs,
                         &im->rp,
                         &issue_ticket_result_cb,
                         tio);
  GNUNET_SERVICE_client_continue (idp->client);
  GNUNET_RECLAIM_ATTRIBUTE_list_destroy (attrs);
}



/**********************************************************
 * Revocation
 **********************************************************/

/**
 * Handles revocation result
 *
 * @param cls our revocation operation handle
 * @param success revocation result (GNUNET_OK if successful)
 */
static void
revoke_result_cb (void *cls, int32_t success)
{
  struct TicketRevocationOperation *rop = cls;
  struct GNUNET_MQ_Envelope *env;
  struct RevokeTicketResultMessage *trm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending REVOKE_TICKET_RESULT message\n");
  rop->rh = NULL;
  env = GNUNET_MQ_msg (trm, GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT);
  trm->id = htonl (rop->r_id);
  trm->success = htonl (success);
  GNUNET_MQ_send (rop->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (rop->client->revoke_op_head,
                               rop->client->revoke_op_tail,
                               rop);
  GNUNET_free (rop);
}


/**
 * Check revocation message format
 *
 * @param cls unused
 * @param im the message to check
 * @return GNUNET_OK if message is ok
 */
static int
check_revoke_ticket_message (void *cls, const struct RevokeTicketMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct RevokeTicketMessage)) {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a revocation message to a ticket.
 *
 * @param cls our client
 * @param rm the message to handle
 */
static void
handle_revoke_ticket_message (void *cls, const struct RevokeTicketMessage *rm)
{
  struct TicketRevocationOperation *rop;
  struct IdpClient *idp = cls;
  struct GNUNET_RECLAIM_Ticket *ticket;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received REVOKE_TICKET message\n");
  rop = GNUNET_new (struct TicketRevocationOperation);
  ticket = (struct GNUNET_RECLAIM_Ticket *)&rm[1];
  rop->r_id = ntohl (rm->id);
  rop->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->revoke_op_head, idp->revoke_op_tail, rop);
  rop->rh
    = RECLAIM_TICKETS_revoke (ticket, &rm->identity, &revoke_result_cb, rop);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handle a ticket consume result
 *
 * @param cls our consume ticket operation handle
 * @param identity the attribute authority
 * @param attrs the attribute/claim list
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
consume_result_cb (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                   const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                   int32_t success,
                   const char *emsg)
{
  struct ConsumeTicketOperation *cop = cls;
  struct ConsumeTicketResultMessage *crm;
  struct GNUNET_MQ_Envelope *env;
  char *data_tmp;
  size_t attrs_len;
  if (GNUNET_OK != success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error consuming ticket: %s\n", emsg);
  }
  attrs_len = GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (attrs);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CONSUME_TICKET_RESULT message\n");
  env = GNUNET_MQ_msg_extra (crm,
                             attrs_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT);
  crm->id = htonl (cop->r_id);
  crm->attrs_len = htons (attrs_len);
  crm->identity = *identity;
  crm->result = htonl (success);
  data_tmp = (char *)&crm[1];
  GNUNET_RECLAIM_ATTRIBUTE_list_serialize (attrs, data_tmp);
  GNUNET_MQ_send (cop->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (cop->client->consume_op_head,
                               cop->client->consume_op_tail,
                               cop);
  GNUNET_free (cop);
}


/**
 * Check a consume ticket message
 *
 * @param cls unused
 * @param cm the message to handle
 */
static int
check_consume_ticket_message (void *cls, const struct ConsumeTicketMessage *cm)
{
  uint16_t size;

  size = ntohs (cm->header.size);
  if (size <= sizeof (struct ConsumeTicketMessage)) {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a consume ticket message
 *
 * @param cls our client handle
 * @cm the message to handle
 */
static void
handle_consume_ticket_message (void *cls, const struct ConsumeTicketMessage *cm)
{
  struct ConsumeTicketOperation *cop;
  struct GNUNET_RECLAIM_Ticket *ticket;
  struct IdpClient *idp = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received CONSUME_TICKET message\n");
  cop = GNUNET_new (struct ConsumeTicketOperation);
  cop->r_id = ntohl (cm->id);
  cop->client = idp;
  ticket = (struct GNUNET_RECLAIM_Ticket *)&cm[1];
  cop->ch
    = RECLAIM_TICKETS_consume (&cm->identity, ticket, &consume_result_cb, cop);
  GNUNET_CONTAINER_DLL_insert (idp->consume_op_head, idp->consume_op_tail, cop);
  GNUNET_SERVICE_client_continue (idp->client);
}

/*****************************************
 * Attribute store
 *****************************************/


/**
 * Attribute store result handler
 *
 * @param cls our attribute store handle
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
attr_store_cont (void *cls, int32_t success, const char *emsg)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_MQ_Envelope *env;
  struct SuccessResultMessage *acr_msg;

  ash->ns_qe = NULL;
  GNUNET_CONTAINER_DLL_remove (ash->client->store_op_head,
                               ash->client->store_op_tail,
                               ash);

  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store attribute %s\n",
                emsg);
    cleanup_as_handle (ash);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SUCCESS_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg, GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE);
  acr_msg->id = htonl (ash->r_id);
  acr_msg->op_result = htonl (GNUNET_OK);
  GNUNET_MQ_send (ash->client->mq, env);
  cleanup_as_handle (ash);
}


/**
 * Add a new attribute
 *
 * @param cls the AttributeStoreHandle
 */
static void
attr_store_task (void *cls)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_GNSRECORD_Data rd[1];
  char *buf;
  char *label;
  size_t buf_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Storing attribute\n");
  buf_size = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (ash->claim);
  buf = GNUNET_malloc (buf_size);
  // Give the ash a new id if unset
  if (0 == ash->claim->id)
    ash->claim->id
      = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  GNUNET_RECLAIM_ATTRIBUTE_serialize (ash->claim, buf);
  label
    = GNUNET_STRINGS_data_to_string_alloc (&ash->claim->id, sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypting with label %s\n", label);

  rd[0].data_size = buf_size;
  rd[0].data = buf;
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd[0].expiration_time = ash->exp.rel_value_us;
  ash->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &ash->identity,
                                               label,
                                               1,
                                               rd,
                                               &attr_store_cont,
                                               ash);
  GNUNET_free (buf);
}


/**
 * Check an attribute store message
 *
 * @param cls unused
 * @param sam the message to check
 */
static int
check_attribute_store_message (void *cls,
                               const struct AttributeStoreMessage *sam)
{
  uint16_t size;

  size = ntohs (sam->header.size);
  if (size <= sizeof (struct AttributeStoreMessage)) {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an attribute store message
 *
 * @param cls our client
 * @param sam the message to handle
 */
static void
handle_attribute_store_message (void *cls,
                                const struct AttributeStoreMessage *sam)
{
  struct AttributeStoreHandle *ash;
  struct IdpClient *idp = cls;
  size_t data_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ATTRIBUTE_STORE message\n");

  data_len = ntohs (sam->attr_len);

  ash = GNUNET_new (struct AttributeStoreHandle);
  ash->claim = GNUNET_RECLAIM_ATTRIBUTE_deserialize ((char *)&sam[1], data_len);

  ash->r_id = ntohl (sam->id);
  ash->identity = sam->identity;
  ash->exp.rel_value_us = GNUNET_ntohll (sam->exp);
  GNUNET_CRYPTO_ecdsa_key_get_public (&sam->identity, &ash->identity_pkey);

  GNUNET_SERVICE_client_continue (idp->client);
  ash->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->store_op_head, idp->store_op_tail, ash);
  GNUNET_SCHEDULER_add_now (&attr_store_task, ash);
}


/**
 * Send a deletion success response
 *
 * @param adh our attribute deletion handle
 * @param success the success status
 */
static void
send_delete_response (struct AttributeDeleteHandle *adh, int32_t success)
{
  struct GNUNET_MQ_Envelope *env;
  struct SuccessResultMessage *acr_msg;

  GNUNET_CONTAINER_DLL_remove (adh->client->delete_op_head,
                               adh->client->delete_op_tail,
                               adh);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SUCCESS_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg, GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE);
  acr_msg->id = htonl (adh->r_id);
  acr_msg->op_result = htonl (success);
  GNUNET_MQ_send (adh->client->mq, env);
}


/**
 * Namestore iteration within attribute deletion.
 * We need to reissue tickets with the deleted attribute removed.
 *
 * @param cls our attribute deletion handle
 * @param zone the private key of the ticket issuer
 * @param label the label of the record
 * @param rd_count number of records
 * @param rd record data
 */
static void
ticket_iter (void *cls,
             const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AttributeDeleteHandle *adh = cls;
  struct TicketRecordsEntry *le;
  int has_changed = GNUNET_NO;

  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF != rd[i].record_type)
      continue;
    if (0 != memcmp (rd[i].data, &adh->claim->id, sizeof (uint64_t)))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Attribute to delete found (%s)\n",
                adh->label);
    has_changed = GNUNET_YES;
    break;
  }
  if (GNUNET_YES == has_changed) {
    le = GNUNET_new (struct TicketRecordsEntry);
    le->data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    le->data = GNUNET_malloc (le->data_size);
    le->rd_count = rd_count;
    le->label = GNUNET_strdup (label);
    GNUNET_GNSRECORD_records_serialize (rd_count, rd, le->data_size, le->data);
    GNUNET_CONTAINER_DLL_insert (adh->tickets_to_update_head,
                                 adh->tickets_to_update_tail,
                                 le);
  }
  GNUNET_NAMESTORE_zone_iterator_next (adh->ns_it, 1);
}


/**
 * Recursion prototype for function
 * @param cls our deletion handle
 */
static void
update_tickets (void *cls);


/**
 * Callback called when a ticket was updated
 *
 * @param cls our attribute deletion handle
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
ticket_updated (void *cls, int32_t success, const char *emsg)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_qe = NULL;
  GNUNET_SCHEDULER_add_now (&update_tickets, adh);
}


/**
 * Update tickets: Remove shared attribute which has just been deleted.
 * This method is called recursively until all tickets are processed.
 * Eventually, the updated tickets are stored using ``update_tickets''.
 *
 * @param cls our attribute deletion handle
 */
static void
update_tickets (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  struct TicketRecordsEntry *le;
  if (NULL == adh->tickets_to_update_head) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Finished updatding tickets, success\n");
    send_delete_response (adh, GNUNET_OK);
    cleanup_adh (adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Updating %s\n",
              adh->tickets_to_update_head->label);
  le = adh->tickets_to_update_head;
  GNUNET_CONTAINER_DLL_remove (adh->tickets_to_update_head,
                               adh->tickets_to_update_tail,
                               le);
  struct GNUNET_GNSRECORD_Data rd[le->rd_count];
  struct GNUNET_GNSRECORD_Data rd_new[le->rd_count - 1];
  GNUNET_GNSRECORD_records_deserialize (le->data_size,
                                        le->data,
                                        le->rd_count,
                                        rd);
  int j = 0;
  for (int i = 0; i < le->rd_count; i++) {
    if ((GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF == rd[i].record_type)
        && (0 == memcmp (rd[i].data, &adh->claim->id, sizeof (uint64_t))))
      continue;
    rd_new[j] = rd[i];
    j++;
  }
  adh->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &adh->identity,
                                               le->label,
                                               j,
                                               rd_new,
                                               &ticket_updated,
                                               adh);
  GNUNET_free (le->label);
  GNUNET_free (le->data);
  GNUNET_free (le);
}


/**
 * Done collecting affected tickets, start updating.
 *
 * @param cls our attribute deletion handle
 */
static void
ticket_iter_fin (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_it = NULL;
  GNUNET_SCHEDULER_add_now (&update_tickets, adh);
}


/**
 * Error collecting affected tickets. Abort.
 *
 * @param cls our attribute deletion handle
 */
static void
ticket_iter_err (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_it = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Namestore error on delete %s\n",
              adh->label);
  send_delete_response (adh, GNUNET_SYSERR);
  cleanup_adh (adh);
}


/**
 * Start processing tickets which may still contain reference to deleted
 * attribute.
 *
 * @param cls attribute deletion handle
 */
static void
start_ticket_update (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_it = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                      &adh->identity,
                                                      &ticket_iter_err,
                                                      adh,
                                                      &ticket_iter,
                                                      adh,
                                                      &ticket_iter_fin,
                                                      adh);
}


/**
 * Attribute deleted callback
 *
 * @param cls our handle
 * @param success success status
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
attr_delete_cont (void *cls, int32_t success, const char *emsg)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error deleting attribute %s\n",
                adh->label);
    send_delete_response (adh, GNUNET_SYSERR);
    cleanup_adh (adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating tickets...\n");
  GNUNET_SCHEDULER_add_now (&start_ticket_update, adh);
}


/**
 * Check attribute delete message format
 *
 * @cls unused
 * @dam message to check
 */
static int
check_attribute_delete_message (void *cls,
                                const struct AttributeDeleteMessage *dam)
{
  uint16_t size;

  size = ntohs (dam->header.size);
  if (size <= sizeof (struct AttributeDeleteMessage)) {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle attribute deletion
 *
 * @param cls our client
 * @param dam deletion message
 */
static void
handle_attribute_delete_message (void *cls,
                                 const struct AttributeDeleteMessage *dam)
{
  struct AttributeDeleteHandle *adh;
  struct IdpClient *idp = cls;
  size_t data_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ATTRIBUTE_DELETE message\n");

  data_len = ntohs (dam->attr_len);

  adh = GNUNET_new (struct AttributeDeleteHandle);
  adh->claim = GNUNET_RECLAIM_ATTRIBUTE_deserialize ((char *)&dam[1], data_len);

  adh->r_id = ntohl (dam->id);
  adh->identity = dam->identity;
  adh->label
    = GNUNET_STRINGS_data_to_string_alloc (&adh->claim->id, sizeof (uint64_t));
  GNUNET_SERVICE_client_continue (idp->client);
  adh->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->delete_op_head, idp->delete_op_tail, adh);
  adh->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &adh->identity,
                                               adh->label,
                                               0,
                                               NULL,
                                               &attr_delete_cont,
                                               adh);
}


/*************************************************
 * Attrubute iteration
 *************************************************/


/**
 * Done iterating over attributes
 *
 * @param cls our iterator handle
 */
static void
attr_iter_finished (void *cls)
{
  struct AttributeIterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeResultMessage *arm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending ATTRIBUTE_RESULT message\n");
  env = GNUNET_MQ_msg (arm, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (0);
  GNUNET_MQ_send (ai->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (ai->client->attr_iter_head,
                               ai->client->attr_iter_tail,
                               ai);
  GNUNET_free (ai);
}

/**
 * Error iterating over attributes. Abort.
 *
 * @param cls our attribute iteration handle
 */
static void
attr_iter_error (void *cls)
{
  struct AttributeIterator *ai = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to iterate over attributes\n");
  attr_iter_finished (ai);
}


/**
 * Got record. Return if it is an attribute.
 *
 * @param cls our attribute iterator
 * @param zone zone we are iterating
 * @param label label of the records
 * @param rd_count record count
 * @param rd records
 */
static void
attr_iter_cb (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AttributeIterator *ai = cls;
  struct AttributeResultMessage *arm;
  struct GNUNET_MQ_Envelope *env;
  char *data_tmp;

  if (rd_count != 1) {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
    return;
  }

  if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR != rd->record_type) {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found attribute under: %s\n", label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending ATTRIBUTE_RESULT message\n");
  env = GNUNET_MQ_msg_extra (arm,
                             rd->data_size,
                             GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (rd->data_size);
  GNUNET_CRYPTO_ecdsa_key_get_public (zone, &arm->identity);
  data_tmp = (char *)&arm[1];
  GNUNET_memcpy (data_tmp, rd->data, rd->data_size);
  GNUNET_MQ_send (ai->client->mq, env);
}


/**
 * Iterate over zone to get attributes
 *
 * @param cls our client
 * @param ais_msg the iteration message to start
 */
static void
handle_iteration_start (void *cls,
                        const struct AttributeIterationStartMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_START message\n");
  ai = GNUNET_new (struct AttributeIterator);
  ai->request_id = ntohl (ais_msg->id);
  ai->client = idp;
  ai->identity = ais_msg->identity;

  GNUNET_CONTAINER_DLL_insert (idp->attr_iter_head, idp->attr_iter_tail, ai);
  ai->ns_it = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                     &ai->identity,
                                                     &attr_iter_error,
                                                     ai,
                                                     &attr_iter_cb,
                                                     ai,
                                                     &attr_iter_finished,
                                                     ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handle iteration stop message from client
 *
 * @param cls the client
 * @param ais_msg the stop message
 */
static void
handle_iteration_stop (void *cls,
                       const struct AttributeIterationStopMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ATTRIBUTE_ITERATION_STOP");
  rid = ntohl (ais_msg->id);
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai) {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head, idp->attr_iter_tail, ai);
  GNUNET_free (ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Client requests next attribute from iterator
 *
 * @param cls the client
 * @param ais_msg the message
 */
static void
handle_iteration_next (void *cls,
                       const struct AttributeIterationNextMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_NEXT message\n");
  rid = ntohl (ais_msg->id);
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai) {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
  GNUNET_SERVICE_client_continue (idp->client);
}

/******************************************************
 * Ticket iteration
 ******************************************************/

/**
 * Got a ticket. Return to client
 *
 * @param cls our ticket iterator
 * @param ticket the ticket
 */
static void
ticket_iter_cb (void *cls, struct GNUNET_RECLAIM_Ticket *ticket)
{
  struct TicketIteration *ti = cls;
  struct GNUNET_MQ_Envelope *env;
  struct TicketResultMessage *trm;

  if (NULL == ticket) {
    /* send empty response to indicate end of list */
    env = GNUNET_MQ_msg (trm, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
    GNUNET_CONTAINER_DLL_remove (ti->client->ticket_iter_head,
                                 ti->client->ticket_iter_tail,
                                 ti);
  } else {
    env = GNUNET_MQ_msg_extra (trm,
                               sizeof (struct GNUNET_RECLAIM_Ticket),
                               GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
    memcpy (&trm[1], ticket, sizeof (struct GNUNET_RECLAIM_Ticket));
  }
  trm->id = htonl (ti->r_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending TICKET_RESULT message\n");
  GNUNET_MQ_send (ti->client->mq, env);
  if (NULL == ticket)
    GNUNET_free (ti);
}


/**
 * Client requests a ticket iteration
 *
 * @param cls the client
 * @param tis_msg the iteration request message
 */
static void
handle_ticket_iteration_start (
  void *cls,
  const struct TicketIterationStartMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_START message\n");
  ti = GNUNET_new (struct TicketIteration);
  ti->r_id = ntohl (tis_msg->id);
  ti->client = client;

  GNUNET_CONTAINER_DLL_insert (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  ti->iter
    = RECLAIM_TICKETS_iteration_start (&tis_msg->identity, &ticket_iter_cb, ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Client has had enough tickets
 *
 * @param cls the client
 * @param tis_msg the stop message
 */
static void
handle_ticket_iteration_stop (void *cls,
                              const struct TicketIterationStopMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "TICKET_ITERATION_STOP");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti) {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  RECLAIM_TICKETS_iteration_stop (ti->iter);
  GNUNET_CONTAINER_DLL_remove (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  GNUNET_free (ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Client requests next result.
 *
 * @param cls the client
 * @param tis_msg the message
 */
static void
handle_ticket_iteration_next (void *cls,
                              const struct TicketIterationNextMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_NEXT message\n");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti) {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  RECLAIM_TICKETS_iteration_next (ti->iter);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Main function that will be run
 *
 * @param cls closure
 * @param c the configuration used
 * @param server the service handle
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *server)
{
  cfg = c;

  if (GNUNET_OK != RECLAIM_TICKETS_init (cfg)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to initialize TICKETS subsystem.\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  // Connect to identity and namestore services
  nsh = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == nsh) {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "error connecting to namestore");
  }

  identity_handle = GNUNET_IDENTITY_connect (cfg, NULL, NULL);

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
}


/**
 * Called whenever a client is disconnected.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct IdpClient *idp = app_ctx;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected\n", client);
  GNUNET_CONTAINER_DLL_remove (client_list_head,
                               client_list_tail,
                               idp);
  cleanup_client (idp);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct IdpClient *idp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", client);
  idp = GNUNET_new (struct IdpClient);
  idp->client = client;
  idp->mq = mq;
  GNUNET_CONTAINER_DLL_insert (client_list_head,
                               client_list_tail,
                               idp);
  return idp;
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "reclaim",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (attribute_store_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE,
                         struct AttributeStoreMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (attribute_delete_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE,
                         struct AttributeDeleteMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (
    iteration_start,
    GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START,
    struct AttributeIterationStartMessage,
    NULL),
  GNUNET_MQ_hd_fixed_size (iteration_next,
                           GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT,
                           struct AttributeIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (iteration_stop,
                           GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP,
                           struct AttributeIterationStopMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (issue_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET,
                         struct IssueTicketMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (consume_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET,
                         struct ConsumeTicketMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (ticket_iteration_start,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START,
                           struct TicketIterationStartMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (ticket_iteration_next,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT,
                           struct TicketIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (ticket_iteration_stop,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP,
                           struct TicketIterationStopMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (revoke_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET,
                         struct RevokeTicketMessage,
                         NULL),
  GNUNET_MQ_handler_end ());
/* end of gnunet-service-reclaim.c */
