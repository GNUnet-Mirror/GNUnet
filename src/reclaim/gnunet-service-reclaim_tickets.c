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

struct ParallelLookup;

struct RECLAIM_TICKETS_ConsumeHandle {
  /**
   * Ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * LookupRequest
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pub;

  /**
   * Lookup DLL
   */
  struct ParallelLookup *parallel_lookups_head;

  /**
   * Lookup DLL
   */
  struct ParallelLookup *parallel_lookups_tail;

  /**
   * Kill task
   */
  struct GNUNET_SCHEDULER_Task *kill_task;

  /**
   * Attributes
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;

  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;

  /**
   * Callback
   */
  RECLAIM_TICKETS_ConsumeCallback cb;

  /**
   * Callbacl closure
   */
  void *cb_cls;
};

/**
 * Handle for a parallel GNS lookup job
 */
struct ParallelLookup {
  /* DLL */
  struct ParallelLookup *next;

  /* DLL */
  struct ParallelLookup *prev;

  /* The GNS request */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /* The handle the return to */
  struct RECLAIM_TICKETS_ConsumeHandle *handle;

  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;

  /* The label to look up */
  char *label;
};


/**
 * A reference to a ticket stored in GNS
 */
struct TicketReference {
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
struct TicketIssueHandle {
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
struct RECLAIM_TICKETS_Iterator {
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

/* Namestore handle */
static struct GNUNET_NAMESTORE_Handle *nsh;

/* GNS handle */
static struct GNUNET_GNS_Handle *gns;

/* Handle to the statistics service */
static struct GNUNET_STATISTICS_Handle *stats;


/**
 * Cleanup ticket consume handle
 * @param cth the handle to clean up
 */
static void cleanup_cth (struct RECLAIM_TICKETS_ConsumeHandle *cth)
{
  struct ParallelLookup *lu;
  struct ParallelLookup *tmp;
  if (NULL != cth->lookup_request)
    GNUNET_GNS_lookup_cancel (cth->lookup_request);
  for (lu = cth->parallel_lookups_head; NULL != lu;) {
    GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free (lu->label);
    tmp = lu->next;
    GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail, lu);
    GNUNET_free (lu);
    lu = tmp;
  }

  if (NULL != cth->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (cth->attrs);
  GNUNET_free (cth);
}


static void
process_parallel_lookup_result (void *cls, uint32_t rd_count,
                                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ParallelLookup *parallel_lookup = cls;
  struct RECLAIM_TICKETS_ConsumeHandle *cth = parallel_lookup->handle;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *attr_le;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parallel lookup finished (count=%u)\n",
              rd_count);

  GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                               cth->parallel_lookups_tail, parallel_lookup);
  GNUNET_free (parallel_lookup->label);

  GNUNET_STATISTICS_update (
      stats, "attribute_lookup_time_total",
      GNUNET_TIME_absolute_get_duration (parallel_lookup->lookup_start_time)
          .rel_value_us,
      GNUNET_YES);
  GNUNET_STATISTICS_update (stats, "attribute_lookups_count", 1, GNUNET_YES);


  GNUNET_free (parallel_lookup);
  if (1 != rd_count)
    GNUNET_break (0); // TODO
  if (rd->record_type == GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR) {
    attr_le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
    attr_le->claim =
        GNUNET_RECLAIM_ATTRIBUTE_deserialize (rd->data, rd->data_size);
    GNUNET_CONTAINER_DLL_insert (cth->attrs->list_head, cth->attrs->list_tail,
                                 attr_le);
  }
  if (NULL != cth->parallel_lookups_head)
    return; // Wait for more
  /* Else we are done */

  GNUNET_SCHEDULER_cancel (cth->kill_task);
  cth->cb (cth->cb_cls, &cth->ticket.identity, cth->attrs, GNUNET_OK, NULL);
  cleanup_cth (cth);
}


static void abort_parallel_lookups (void *cls)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth = cls;
  struct ParallelLookup *lu;
  struct ParallelLookup *tmp;

  cth->kill_task = NULL;
  for (lu = cth->parallel_lookups_head; NULL != lu;) {
    GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free (lu->label);
    tmp = lu->next;
    GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail, lu);
    GNUNET_free (lu);
    lu = tmp;
  }
  cth->cb (cth->cb_cls, NULL, NULL, GNUNET_SYSERR, "Aborted");
}


static void lookup_authz_cb (void *cls, uint32_t rd_count,
                             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth = cls;
  struct ParallelLookup *parallel_lookup;
  char *lbl;

  cth->lookup_request = NULL;

  GNUNET_STATISTICS_update (
      stats, "reclaim_authz_lookup_time_total",
      GNUNET_TIME_absolute_get_duration (cth->lookup_start_time).rel_value_us,
      GNUNET_YES);
  GNUNET_STATISTICS_update (stats, "reclaim_authz_lookups_count", 1,
                            GNUNET_YES);

  for (int i = 0; i < rd_count; i++) {
    lbl = GNUNET_STRINGS_data_to_string_alloc (rd[i].data, rd[i].data_size);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Attribute ref found %s\n", lbl);
    parallel_lookup = GNUNET_new (struct ParallelLookup);
    parallel_lookup->handle = cth;
    parallel_lookup->label = lbl;
    parallel_lookup->lookup_start_time = GNUNET_TIME_absolute_get ();
    parallel_lookup->lookup_request = GNUNET_GNS_lookup (
        gns, lbl, &cth->ticket.identity, GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR,
        GNUNET_GNS_LO_DEFAULT, &process_parallel_lookup_result,
        parallel_lookup);
    GNUNET_CONTAINER_DLL_insert (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail, parallel_lookup);
  }
  cth->kill_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 3),
      &abort_parallel_lookups, cth);
}


struct RECLAIM_TICKETS_ConsumeHandle *
RECLAIM_TICKETS_consume (const struct GNUNET_CRYPTO_EcdsaPrivateKey *id,
                         const struct GNUNET_RECLAIM_Ticket *ticket,
                         RECLAIM_TICKETS_ConsumeCallback cb, void *cb_cls)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth;
  char *label;
  cth = GNUNET_new (struct RECLAIM_TICKETS_ConsumeHandle);

  cth->identity = *id;
  GNUNET_CRYPTO_ecdsa_key_get_public (&cth->identity, &cth->identity_pub);
  cth->attrs = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  cth->ticket = *ticket;
  cth->cb = cb;
  cth->cb_cls = cb_cls;
  label =
      GNUNET_STRINGS_data_to_string_alloc (&cth->ticket.rnd, sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Looking for AuthZ info under %s\n",
              label);
  cth->lookup_start_time = GNUNET_TIME_absolute_get ();
  cth->lookup_request = GNUNET_GNS_lookup (
      gns, label, &cth->ticket.identity, GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF,
      GNUNET_GNS_LO_DEFAULT, &lookup_authz_cb, cth);
  GNUNET_free (label);
  return cth;
}

void RECLAIM_TICKETS_consume_cancel (struct RECLAIM_TICKETS_ConsumeHandle *cth)
{
  cleanup_cth (cth);
  return;
}


/*******************************
 * Ticket issue
 *******************************/

/**
 * Cleanup ticket consume handle
 * @param handle the handle to clean up
 */
static void cleanup_issue_handle (struct TicketIssueHandle *handle)
{
  struct TicketReference *tr;
  struct TicketReference *tr_tmp;
  if (NULL != handle->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (handle->attrs);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  for (tr = handle->ticket_refs_head; NULL != tr;) {
    if (NULL != tr->attrs)
      GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
    tr_tmp = tr;
    tr = tr->next;
    GNUNET_free (tr_tmp);
  }
  GNUNET_free (handle);
}


static void store_ticket_refs_cont (void *cls, int32_t success,
                                    const char *emsg)
{
  struct TicketIssueHandle *handle = cls;
  handle->ns_qe = NULL;
  if (GNUNET_OK != success) {
    handle->cb (handle->cb_cls, NULL, GNUNET_SYSERR,
                "Error storing updated ticket refs in GNS");
    cleanup_issue_handle (handle);
    return;
  }
  handle->cb (handle->cb_cls, &handle->ticket, GNUNET_OK, NULL);
  cleanup_issue_handle (handle);
}


static void update_ticket_refs (void *cls)
{
  struct TicketIssueHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data refs_rd[handle->ticket_ref_num];
  struct TicketReference *tr;

  tr = handle->ticket_refs_head;
  for (int i = 0; i < handle->ticket_ref_num; i++) {
    refs_rd[i].data = &tr->ticket;
    refs_rd[i].data_size = sizeof (struct GNUNET_RECLAIM_Ticket);
    refs_rd[i].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
    refs_rd[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF;
    refs_rd[i].flags =
        GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;
    tr = tr->next;
  }

  handle->ns_qe = GNUNET_NAMESTORE_records_store (
      nsh, &handle->identity, GNUNET_GNS_EMPTY_LABEL_AT, handle->ticket_ref_num,
      refs_rd, &store_ticket_refs_cont, handle);
}


static void ticket_lookup_cb (void *cls,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                              const char *label, unsigned int rd_count,
                              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct TicketIssueHandle *handle = cls;
  struct TicketReference *tr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received tickets from local namestore.\n");
  handle->ns_qe = NULL;
  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF != rd[i].record_type)
      continue;
    tr = GNUNET_new (struct TicketReference);
    memcpy (&tr->ticket, rd[i].data, sizeof (struct GNUNET_RECLAIM_Ticket));
    if (0 != memcmp (&tr->ticket.identity, &handle->ticket.identity,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))) {
      // Not our ticket
      GNUNET_free (tr);
      continue;
    }
    GNUNET_CONTAINER_DLL_insert (handle->ticket_refs_head,
                                 handle->ticket_refs_tail, tr);
    handle->ticket_ref_num++;
  }
  tr = GNUNET_new (struct TicketReference);
  tr->ticket = handle->ticket;
  tr->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_dup (handle->attrs);
  GNUNET_CONTAINER_DLL_insert (handle->ticket_refs_head,
                               handle->ticket_refs_tail, tr);
  handle->ticket_ref_num++;
  GNUNET_SCHEDULER_add_now (&update_ticket_refs, handle);
}


/**
 * TODO maybe we should cleanup the ATTRREFS here?
 */
static void ticket_lookup_error_cb (void *cls)
{
  struct TicketIssueHandle *handle = cls;
  handle->ns_qe = NULL;
  handle->cb (handle->cb_cls, &handle->ticket, GNUNET_SYSERR,
              "Error checking for ticketsin GNS\n");
  cleanup_issue_handle (handle);
}

static void store_ticket_issue_cont (void *cls, int32_t success,
                                     const char *emsg)
{
  struct TicketIssueHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    handle->cb (handle->cb_cls, &handle->ticket, GNUNET_SYSERR,
                "Error storing AuthZ ticket in GNS");
    return;
  }
  /* First, local references to tickets */
  handle->ns_qe = GNUNET_NAMESTORE_records_lookup (
      nsh, &handle->identity, GNUNET_GNS_EMPTY_LABEL_AT,
      &ticket_lookup_error_cb, handle, &ticket_lookup_cb, handle);
}


static void issue_ticket (struct TicketIssueHandle *ih)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_GNSRECORD_Data *attrs_record;
  char *label;
  size_t list_len = 0;
  int i;

  for (le = ih->attrs->list_head; NULL != le; le = le->next)
    list_len++;

  attrs_record =
      GNUNET_malloc (list_len * sizeof (struct GNUNET_GNSRECORD_Data));
  i = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next) {
    attrs_record[i].data = &le->claim->id;
    attrs_record[i].data_size = sizeof (le->claim->id);
    attrs_record[i].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
    attrs_record[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF;
    attrs_record[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  }

  label =
      GNUNET_STRINGS_data_to_string_alloc (&ih->ticket.rnd, sizeof (uint64_t));
  // Publish record
  ih->ns_qe = GNUNET_NAMESTORE_records_store (nsh, &ih->identity, label,
                                              list_len, attrs_record,
                                              &store_ticket_issue_cont, ih);
  GNUNET_free (attrs_record);
  GNUNET_free (label);
}


void RECLAIM_TICKETS_issue (
    const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
    const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
    const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
    RECLAIM_TICKETS_TicketResult cb, void *cb_cls)
{
  struct TicketIssueHandle *tih;
  tih = GNUNET_new (struct TicketIssueHandle);
  tih->cb = cb;
  tih->cb_cls = cb_cls;
  tih->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_dup (attrs);
  tih->identity = *identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (identity, &tih->ticket.identity);
  tih->ticket.rnd =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  tih->ticket.audience = *audience;
  issue_ticket (tih);
}

/************************************
 * Ticket iteration
 ************************************/

static void cleanup_iter (struct RECLAIM_TICKETS_Iterator *iter)
{
  struct TicketReference *tr;
  struct TicketReference *tr_tmp;
  if (NULL != iter->ns_qe)
    GNUNET_NAMESTORE_cancel (iter->ns_qe);
  for (tr = iter->tickets_head; NULL != tr;) {
    if (NULL != tr->attrs)
      GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
    tr_tmp = tr;
    tr = tr->next;
    GNUNET_free (tr_tmp);
  }
  GNUNET_free (iter);
}

static void do_cleanup_iter (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  cleanup_iter (iter);
}

/**
 * Perform ticket iteration step
 *
 * @param ti ticket iterator to process
 */
static void run_ticket_iteration_round (struct RECLAIM_TICKETS_Iterator *iter)
{
  struct TicketReference *tr;
  if (NULL == iter->tickets_head) {
    // No more tickets
    iter->cb (iter->cb_cls, NULL);
    GNUNET_SCHEDULER_add_now (&do_cleanup_iter, iter);
    return;
  }
  tr = iter->tickets_head;
  GNUNET_CONTAINER_DLL_remove (iter->tickets_head, iter->tickets_tail, tr);
  iter->cb (iter->cb_cls, &tr->ticket);
  if (NULL != tr->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (tr->attrs);
  GNUNET_free (tr);
}

static void
collect_tickets_cb (void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                    const char *label, unsigned int rd_count,
                    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  struct TicketReference *tr;
  iter->ns_qe = NULL;

  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKETREF != rd[i].record_type)
      continue;
    tr = GNUNET_new (struct TicketReference);
    memcpy (&tr->ticket, rd[i].data, sizeof (struct GNUNET_RECLAIM_Ticket));
    if (0 != memcmp (&tr->ticket.identity, &iter->identity_pub,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))) {
      // Not our ticket
      GNUNET_free (tr);
      continue;
    }
    GNUNET_CONTAINER_DLL_insert (iter->tickets_head, iter->tickets_tail, tr);
  }
  run_ticket_iteration_round (iter);
}

static void collect_tickets_error_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  iter->ns_qe = NULL;
  iter->cb (iter->cb_cls, NULL);
  cleanup_iter (iter);
}

void RECLAIM_TICKETS_iteration_next (struct RECLAIM_TICKETS_Iterator *iter)
{
  run_ticket_iteration_round (iter);
}

void RECLAIM_TICKETS_iteration_stop (struct RECLAIM_TICKETS_Iterator *iter)
{
  cleanup_iter (iter);
}

struct RECLAIM_TICKETS_Iterator *RECLAIM_TICKETS_iteration_start (
    const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
    RECLAIM_TICKETS_TicketIter cb, void *cb_cls)
{
  struct RECLAIM_TICKETS_Iterator *iter;

  iter = GNUNET_new (struct RECLAIM_TICKETS_Iterator);
  iter->identity = *identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (identity, &iter->identity_pub);
  iter->cb = cb;
  iter->cb_cls = cb_cls;
  iter->ns_qe = GNUNET_NAMESTORE_records_lookup (
      nsh, identity, GNUNET_GNS_EMPTY_LABEL_AT, &collect_tickets_error_cb, iter,
      &collect_tickets_cb, iter);
  return iter;
}


int RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  // Connect to identity and namestore services
  nsh = GNUNET_NAMESTORE_connect (c);
  if (NULL == nsh) {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "error connecting to namestore");
    return GNUNET_SYSERR;
  }
  gns = GNUNET_GNS_connect (c);
  if (NULL == gns) {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to gns");
    return GNUNET_SYSERR;
  }
  stats = GNUNET_STATISTICS_create ("reclaim", c);
  return GNUNET_OK;
}

void RECLAIM_TICKETS_deinit (void)
{
  if (NULL != nsh)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
  if (NULL != gns)
    GNUNET_GNS_disconnect (gns);
  gns = NULL;
  if (NULL != stats) {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}
