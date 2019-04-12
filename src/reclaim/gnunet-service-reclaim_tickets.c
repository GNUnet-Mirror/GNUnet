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
 * @file src/reclaim/gnunet-service-reclaim_tickets.c
 * @brief reclaim tickets
 *
 */
#include "gnunet-service-reclaim_tickets.h"

/**
 * A reference to a ticket stored in GNS
 */
struct TicketReference
{
  /**
   * DLL
   */
  struct TicketReference *next;

  /**
   * DLL
   */
  struct TicketReference *prev;

  /**
   * Attributes
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;

  /**
   * Tickets
   */
  struct GNUNET_RECLAIM_Ticket ticket;
};


/**
 * Ticket issue request handle
 */
struct TicketIssueHandle
{
  /**
   * Attributes to issue
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Ticket reference list
   */
  struct TicketReference *ticket_refs_head;

  /**
   * Ticket reference list
   */
  struct TicketReference *ticket_refs_tail;

  /**
   * Number of references
   */
  uint32_t ticket_ref_num;

  /**
   * Callback
   */
  RECLAIM_TICKETS_TicketResult cb;

  /**
   * Callback cls
   */
  void *cb_cls;

};

/**
 * Ticket iterator
 */
struct RECLAIM_TICKETS_Iterator
{
  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Issuer pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pub;

  /**
   * Namestore queue entry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Iter callback
   */
  RECLAIM_TICKETS_TicketIter cb;

  /**
   * Iter cls
   */
  void *cb_cls;

  /**
   * Ticket reference list
   */
  struct TicketReference *tickets_head;

  /**
   * Ticket reference list
   */
  struct TicketReference *tickets_tail;
};

static struct GNUNET_NAMESTORE_Handle *nsh;

/**
 * Cleanup ticket consume handle
 * @param handle the handle to clean up
 */
static void
cleanup_issue_handle (struct TicketIssueHandle *handle)
{
  struct TicketReference *tr;
  struct TicketReference *tr_tmp;
  if (NULL != handle->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (handle->attrs);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  for (tr = handle->ticket_refs_head; NULL != tr;)
  {
    if (NULL != tr->attrs)
      GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
    tr_tmp = tr;
    tr = tr->next;
    GNUNET_free (tr_tmp);
  }
  GNUNET_free (handle);
}



static void
store_ticket_refs_cont (void *cls,
                        int32_t success,
                        const char *emsg)
{
  struct TicketIssueHandle *handle = cls;
  handle->ns_qe = NULL;
  if (GNUNET_OK != success)
  {
    handle->cb (handle->cb_cls,
                NULL,
                GNUNET_SYSERR,
                "Error storing updated ticket refs in GNS");
    cleanup_issue_handle (handle);
    return;
  }
  handle->cb (handle->cb_cls,
              &handle->ticket,
              GNUNET_OK,
              NULL);
  cleanup_issue_handle (handle);
}



static void
update_ticket_refs (void* cls)
{
  struct TicketIssueHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data refs_rd[handle->ticket_ref_num];
  struct TicketReference *tr;
  char* buf;
  size_t buf_size;

  tr = handle->ticket_refs_head;
  for (int i = 0; i < handle->ticket_ref_num; i++)
  {
    buf_size = GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (tr->attrs);
    buf_size += sizeof (struct GNUNET_RECLAIM_Ticket);
    buf = GNUNET_malloc (buf_size);
    memcpy (buf, &tr->ticket, sizeof (struct GNUNET_RECLAIM_Ticket));
    GNUNET_RECLAIM_ATTRIBUTE_list_serialize (tr->attrs,
                                             buf + sizeof (struct GNUNET_RECLAIM_Ticket));
    refs_rd[i].data = buf;
    refs_rd[i].data_size = buf_size;
    refs_rd[i].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
    refs_rd[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF;
    refs_rd[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION |
      GNUNET_GNSRECORD_RF_PRIVATE;
    tr = tr->next;
  }

  handle->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                                  &handle->identity,
                                                  GNUNET_GNS_EMPTY_LABEL_AT,
                                                  handle->ticket_ref_num,
                                                  refs_rd,
                                                  &store_ticket_refs_cont,
                                                  handle);
  for (int i = 0; i < handle->ticket_ref_num; i++)
    GNUNET_free ((char*)refs_rd[i].data);
}



static void
ticket_lookup_cb (void *cls,
                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                  const char *label,
                  unsigned int rd_count,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct TicketIssueHandle *handle = cls;
  struct TicketReference *tr;
  const char* attr_data;
  size_t attr_data_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received tickets from local namestore.\n");
  handle->ns_qe = NULL;
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF != rd[i].record_type)
      continue;
    tr = GNUNET_new (struct TicketReference);
    memcpy (&tr->ticket, rd[i].data,
            sizeof (struct GNUNET_RECLAIM_Ticket));
    if (0 != memcmp (&tr->ticket.identity,
                     &handle->ticket.identity,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      //Not our ticket
      GNUNET_free (tr);
      continue;
    }
    attr_data = rd[i].data + sizeof (struct GNUNET_RECLAIM_Ticket);
    attr_data_len = rd[i].data_size - sizeof (struct GNUNET_RECLAIM_Ticket);
    tr->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (attr_data,
                                                           attr_data_len);
    GNUNET_CONTAINER_DLL_insert (handle->ticket_refs_head,
                                 handle->ticket_refs_tail,
                                 tr);
    handle->ticket_ref_num++;
  }
  tr = GNUNET_new (struct TicketReference);
  tr->ticket = handle->ticket;
  tr->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_dup (handle->attrs);
  GNUNET_CONTAINER_DLL_insert (handle->ticket_refs_head,
                               handle->ticket_refs_tail,
                               tr);
  handle->ticket_ref_num++;
  GNUNET_SCHEDULER_add_now (&update_ticket_refs, handle);
}

static void
ticket_lookup_error_cb (void *cls)
{
  struct TicketIssueHandle *handle = cls;
  handle->ns_qe = NULL;
  handle->cb (handle->cb_cls,
              &handle->ticket,
              GNUNET_SYSERR,
              "Error checking for ticketsin GNS\n");
  cleanup_issue_handle (handle);
}

static void
store_ticket_issue_cont (void *cls,
                         int32_t success,
                         const char *emsg)
{
  struct TicketIssueHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    handle->cb (handle->cb_cls,
                &handle->ticket,
                GNUNET_SYSERR,
                "Error storing AuthZ ticket in GNS");
    return;
  }
  /* First, local references to tickets */
  handle->ns_qe = GNUNET_NAMESTORE_records_lookup (nsh,
                                                   &handle->identity,
                                                   GNUNET_GNS_EMPTY_LABEL_AT,
                                                   &ticket_lookup_error_cb,
                                                   handle,
                                                   &ticket_lookup_cb,
                                                   handle);
}

static int
create_sym_key_from_ecdh (const struct GNUNET_HashCode *new_key_hash,
                          struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                          struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded new_key_hash_str;

  GNUNET_CRYPTO_hash_to_enc (new_key_hash,
                             &new_key_hash_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating symmetric rsa key from %s\n", (char*)&new_key_hash_str);
  static const char ctx_key[] = "gnuid-aes-ctx-key";
  GNUNET_CRYPTO_kdf (skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                     new_key_hash, sizeof (struct GNUNET_HashCode),
                     ctx_key, strlen (ctx_key),
                     NULL, 0);
  static const char ctx_iv[] = "gnuid-aes-ctx-iv";
  GNUNET_CRYPTO_kdf (iv, sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector),
                     new_key_hash, sizeof (struct GNUNET_HashCode),
                     ctx_iv, strlen (ctx_iv),
                     NULL, 0);
  return GNUNET_OK;
}


static int
serialize_authz_record (const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                        struct GNUNET_CRYPTO_EcdhePrivateKey **ecdh_privkey,
                        char **result)
{
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pubkey;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_HashCode new_key_hash;
  ssize_t enc_size;
  char *enc_keyinfo;
  char *buf;
  char *write_ptr;
  char attrs_str_len;
  char* label;

  GNUNET_assert (NULL != attrs->list_head);
  attrs_str_len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next) {
    attrs_str_len += 15 + 1; //TODO propery calculate
  }
  buf = GNUNET_malloc (attrs_str_len);
  write_ptr = buf;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Writing attributes\n");
  for (le = attrs->list_head; NULL != le; le = le->next) {
    label = GNUNET_STRINGS_data_to_string_alloc (&le->claim->id,
                                                 sizeof (uint64_t));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Adding attribute to record: %s\n", label);

    GNUNET_memcpy (write_ptr,
                   label,
                   strlen (label));
    write_ptr[strlen (label)] = ',';
    write_ptr += strlen (label) + 1;
    GNUNET_free (label);
  }
  write_ptr--;
  write_ptr[0] = '\0'; //replace last , with a 0-terminator
  // ECDH keypair E = eG
  *ecdh_privkey = GNUNET_CRYPTO_ecdhe_key_create();
  GNUNET_CRYPTO_ecdhe_key_get_public (*ecdh_privkey,
                                      &ecdh_pubkey);
  enc_keyinfo = GNUNET_malloc (attrs_str_len);
  // Derived key K = H(eB)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_ecdsa (*ecdh_privkey,
                                                        &ticket->audience,
                                                        &new_key_hash));
  create_sym_key_from_ecdh (&new_key_hash, &skey, &iv);
  enc_size = GNUNET_CRYPTO_symmetric_encrypt (buf,
                                              attrs_str_len,
                                              &skey, &iv,
                                              enc_keyinfo);
  *result = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+
                           enc_size);
  GNUNET_memcpy (*result,
                 &ecdh_pubkey,
                 sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
  GNUNET_memcpy (*result + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                 enc_keyinfo,
                 enc_size);
  GNUNET_free (enc_keyinfo);
  GNUNET_free (buf);
  return sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+enc_size;
}



static void
issue_ticket (struct TicketIssueHandle *ih)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct GNUNET_GNSRECORD_Data code_record[1];
  char *authz_record_data;
  size_t authz_record_len;
  char *label;

  //TODO rename function
  authz_record_len = serialize_authz_record (&ih->ticket,
                                             ih->attrs,
                                             &ecdhe_privkey,
                                             &authz_record_data);
  code_record[0].data = authz_record_data;
  code_record[0].data_size = authz_record_len;
  code_record[0].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
  code_record[0].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_AUTHZ;
  code_record[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

  label = GNUNET_STRINGS_data_to_string_alloc (&ih->ticket.rnd,
                                               sizeof (uint64_t));
  //Publish record
  ih->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                              &ih->identity,
                                              label,
                                              1,
                                              code_record,
                                              &store_ticket_issue_cont,
                                              ih);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (label);
  GNUNET_free (authz_record_data);
}




void
RECLAIM_TICKETS_issue_ticket (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                              const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                              const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
                              RECLAIM_TICKETS_TicketResult cb,
                              void* cb_cls)
{
  struct TicketIssueHandle *tih;
  tih = GNUNET_new (struct TicketIssueHandle);
  tih->cb = cb;
  tih->cb_cls = cb_cls;
  tih->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_dup (attrs);
  tih->identity = *identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (identity,
                                      &tih->ticket.identity);
  tih->ticket.rnd =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                              UINT64_MAX);
  tih->ticket.audience = *audience;
  issue_ticket (tih);
}


static void
cleanup_iter (struct RECLAIM_TICKETS_Iterator *iter)
{
  struct TicketReference *tr;
  struct TicketReference *tr_tmp;
  if (NULL != iter->ns_qe)
    GNUNET_NAMESTORE_cancel (iter->ns_qe);
  for (tr = iter->tickets_head; NULL != tr;)
  {
    if (NULL != tr->attrs)
      GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
    tr_tmp = tr;
    tr = tr->next;
    GNUNET_free (tr_tmp);
  }
  GNUNET_free (iter);
}

static void
do_cleanup_iter (void* cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  cleanup_iter (iter);
}

/**
 * Perform ticket iteration step
 *
 * @param ti ticket iterator to process
 */
static void
run_ticket_iteration_round (struct RECLAIM_TICKETS_Iterator *iter)
{
  struct TicketReference *tr;
  if (NULL == iter->tickets_head)
  {
    //No more tickets
    iter->cb (iter->cb_cls,
              NULL);
    GNUNET_SCHEDULER_add_now (&do_cleanup_iter, iter);
    return;
  }
  tr = iter->tickets_head;
  GNUNET_CONTAINER_DLL_remove (iter->tickets_head,
                               iter->tickets_tail,
                               tr);
  iter->cb (iter->cb_cls,
            &tr->ticket);
  if (NULL != tr->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
  GNUNET_free (tr);
}

static void
collect_tickets_cb (void *cls,
                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                  const char *label,
                  unsigned int rd_count,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  struct TicketReference *tr;
  size_t attr_data_len;
  const char* attr_data;
  iter->ns_qe = NULL;

  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF != rd[i].record_type)
      continue;
    tr = GNUNET_new (struct TicketReference);
    memcpy (&tr->ticket, rd[i].data,
            sizeof (struct GNUNET_RECLAIM_Ticket));
    if (0 != memcmp (&tr->ticket.identity,
                     &iter->identity_pub,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      //Not our ticket
      GNUNET_free (tr);
      continue;
    }
    attr_data = rd[i].data + sizeof (struct GNUNET_RECLAIM_Ticket);
    attr_data_len = rd[i].data_size - sizeof (struct GNUNET_RECLAIM_Ticket);
    tr->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (attr_data,
                                                           attr_data_len);
    GNUNET_CONTAINER_DLL_insert (iter->tickets_head,
                                 iter->tickets_tail,
                                 tr);
  }
  run_ticket_iteration_round (iter);
}

static void
collect_tickets_error_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  iter->ns_qe = NULL;
  iter->cb (iter->cb_cls,
            NULL);
  cleanup_iter (iter);
}

void
RECLAIM_TICKETS_iteration_next (struct RECLAIM_TICKETS_Iterator *iter)
{
  run_ticket_iteration_round (iter);
}

void
RECLAIM_TICKETS_iteration_stop (struct RECLAIM_TICKETS_Iterator *iter)
{
  cleanup_iter (iter);
}

struct RECLAIM_TICKETS_Iterator*
RECLAIM_TICKETS_iteration_start (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                 RECLAIM_TICKETS_TicketIter cb,
                                 void* cb_cls)
{
  struct RECLAIM_TICKETS_Iterator *iter;

  iter = GNUNET_new (struct RECLAIM_TICKETS_Iterator);
  iter->identity = *identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (identity,
                                      &iter->identity_pub);
  iter->cb = cb;
  iter->cb_cls = cb_cls;
  iter->ns_qe = GNUNET_NAMESTORE_records_lookup (nsh,
                                                 identity,
                                                 GNUNET_GNS_EMPTY_LABEL_AT,
                                                 &collect_tickets_error_cb,
                                                 iter,
                                                 &collect_tickets_cb,
                                                 iter);
  return iter;
}




int
RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  //Connect to identity and namestore services
  nsh = GNUNET_NAMESTORE_connect (c);
  if (NULL == nsh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error connecting to namestore\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

void
RECLAIM_TICKETS_deinit (void)
{
  if (NULL != nsh)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
}
