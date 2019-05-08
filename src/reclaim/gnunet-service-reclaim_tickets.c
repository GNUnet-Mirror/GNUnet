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
#include <inttypes.h>

#include "gnunet-service-reclaim_tickets.h"

#define DEFAULT_TICKET_REFRESH_INTERVAL GNUNET_TIME_UNIT_HOURS

struct ParallelLookup;


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


struct RECLAIM_TICKETS_ConsumeHandle
{
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
struct ParallelLookup
{
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
   * Namestore queue entry
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Iter callback
   */
  RECLAIM_TICKETS_TicketIter cb;

  /**
   * Iter cls
   */
  void *cb_cls;
};


struct RevokedAttributeEntry
{
  /**
   * DLL
   */
  struct RevokedAttributeEntry *next;

  /**
   * DLL
   */
  struct RevokedAttributeEntry *prev;

  /**
   * Old ID of the attribute
   */
  uint64_t old_id;

  /**
   * New ID of the attribute
   */
  uint64_t new_id;
};


/**
 * Ticket revocation request handle
 */
struct RECLAIM_TICKETS_RevokeHandle
{
  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Callback
   */
  RECLAIM_TICKETS_RevokeCallback cb;

  /**
   * Callback cls
   */
  void *cb_cls;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Revoked attributes
   */
  struct RevokedAttributeEntry *attrs_head;

  /**
   * Revoked attributes
   */
  struct RevokedAttributeEntry *attrs_tail;

  /**
   * Current attribute to move
   */
  struct RevokedAttributeEntry *move_attr;

  /**
   * Number of attributes in ticket
   */
  unsigned int ticket_attrs;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_head;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_tail;
};

/**
 * Ticket expiration interval
 */
static struct GNUNET_TIME_Relative ticket_refresh_interval;

/* Namestore handle */
static struct GNUNET_NAMESTORE_Handle *nsh;

/* GNS handle */
static struct GNUNET_GNS_Handle *gns;

/* Handle to the statistics service */
static struct GNUNET_STATISTICS_Handle *stats;

static void
move_attrs (struct RECLAIM_TICKETS_RevokeHandle *rh);

static void
move_attrs_cont (void *cls)
{
  move_attrs ((struct RECLAIM_TICKETS_RevokeHandle *)cls);
}

/**
 * Cleanup revoke handle
 *
 * @param rh the ticket revocation handle
 */
static void
cleanup_rvk (struct RECLAIM_TICKETS_RevokeHandle *rh)
{
  struct RevokedAttributeEntry *ae;
  struct TicketRecordsEntry *le;
  if (NULL != rh->ns_qe)
    GNUNET_NAMESTORE_cancel (rh->ns_qe);
  if (NULL != rh->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (rh->ns_it);
  while (NULL != (ae = rh->attrs_head)) {
    GNUNET_CONTAINER_DLL_remove (rh->attrs_head, rh->attrs_tail, ae);
    GNUNET_free (ae);
  }
  while (NULL != (le = rh->tickets_to_update_head)) {
    GNUNET_CONTAINER_DLL_remove (rh->tickets_to_update_head,
                                 rh->tickets_to_update_head, le);
    if (NULL != le->data)
      GNUNET_free (le->data);
    if (NULL != le->label)
      GNUNET_free (le->label);
    GNUNET_free (le);
  }
  GNUNET_free (rh);
}

static void
del_attr_finished (void *cls, int32_t success, const char *emsg)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error removing attribute: %s\n",
                emsg);
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  rvk->move_attr = rvk->move_attr->next;
  GNUNET_SCHEDULER_add_now (&move_attrs_cont, rvk);
}

static void
move_attr_finished (void *cls, int32_t success, const char *emsg)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  char *label;
  rvk->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error moving attribute: %s\n", emsg);
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  label = GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->old_id,
                                               sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing attribute %s\n", label);
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh, &rvk->identity, label, 0,
                                               NULL, &del_attr_finished, rvk);
}


static void
rvk_move_attr_cb (void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                  const char *label, unsigned int rd_count,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *claim;
  struct GNUNET_GNSRECORD_Data new_rd;
  struct RevokedAttributeEntry *le;
  char *new_label;
  char *attr_data;
  rvk->ns_qe = NULL;
  if (0 == rd_count) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "The attribute %s no longer exists!\n", label);
    le = rvk->move_attr;
    rvk->move_attr = le->next;
    GNUNET_CONTAINER_DLL_remove (rvk->attrs_head, rvk->attrs_tail, le);
    GNUNET_free (le);
    GNUNET_SCHEDULER_add_now (&move_attrs_cont, rvk);
    return;
  }
  /** find a new place for this attribute **/
  rvk->move_attr->new_id =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  new_rd = *rd;
  claim = GNUNET_RECLAIM_ATTRIBUTE_deserialize (rd->data, rd->data_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Attribute to update: Name=%s, ID=%" PRIu64 "\n", claim->name,
              claim->id);
  claim->id = rvk->move_attr->new_id;
  new_rd.data_size = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (claim);
  attr_data = GNUNET_malloc (rd->data_size);
  new_rd.data_size = GNUNET_RECLAIM_ATTRIBUTE_serialize (claim, attr_data);
  new_rd.data = attr_data;
  new_label = GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->new_id,
                                                   sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute %s\n", new_label);
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (
      nsh, &rvk->identity, new_label, 1, &new_rd, &move_attr_finished, rvk);
  GNUNET_free (new_label);
  GNUNET_free (claim);
  GNUNET_free (attr_data);
}


static void
rvk_ticket_update (void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                   const char *label, unsigned int rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct TicketRecordsEntry *le;
  struct RevokedAttributeEntry *ae;
  int has_changed = GNUNET_NO;

  /** Let everything point to the old record **/
  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF != rd[i].record_type)
      continue;
    for (ae = rvk->attrs_head; NULL != ae; ae = ae->next) {
      if (0 != memcmp (rd[i].data, &ae->old_id, sizeof (uint64_t)))
        continue;
      has_changed = GNUNET_YES;
      break;
    }
    if (GNUNET_YES == has_changed)
      break;
  }
  if (GNUNET_YES == has_changed) {
    le = GNUNET_new (struct TicketRecordsEntry);
    le->data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    le->data = GNUNET_malloc (le->data_size);
    le->rd_count = rd_count;
    le->label = GNUNET_strdup (label);
    GNUNET_GNSRECORD_records_serialize (rd_count, rd, le->data_size, le->data);
    GNUNET_CONTAINER_DLL_insert (rvk->tickets_to_update_head,
                                 rvk->tickets_to_update_tail, le);
  }
  GNUNET_NAMESTORE_zone_iterator_next (rvk->ns_it, 1);
}


static void
process_tickets (void *cls);


static void
ticket_processed (void *cls, int32_t success, const char *emsg)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_qe = NULL;
  GNUNET_SCHEDULER_add_now (&process_tickets, rvk);
}

static void
process_tickets (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct TicketRecordsEntry *le;
  struct RevokedAttributeEntry *ae;
  if (NULL == rvk->tickets_to_update_head) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished updatding tickets, success\n");
    rvk->cb (rvk->cb_cls, GNUNET_OK);
    cleanup_rvk (rvk);
    return;
  }
  le = rvk->tickets_to_update_head;
  GNUNET_CONTAINER_DLL_remove (rvk->tickets_to_update_head,
                               rvk->tickets_to_update_tail, le);
  struct GNUNET_GNSRECORD_Data rd[le->rd_count];
  GNUNET_GNSRECORD_records_deserialize (le->data_size, le->data, le->rd_count,
                                        rd);
  for (int i = 0; i < le->rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF != rd[i].record_type)
      continue;
    for (ae = rvk->attrs_head; NULL != ae; ae = ae->next) {
      if (0 != memcmp (rd[i].data, &ae->old_id, sizeof (uint64_t)))
        continue;
      rd[i].data = &ae->new_id;
    }
  }
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (
      nsh, &rvk->identity, le->label, le->rd_count, rd, &ticket_processed, rvk);
  GNUNET_free (le->label);
  GNUNET_free (le->data);
  GNUNET_free (le);
}

static void
rvk_ticket_update_finished (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_it = NULL;
  GNUNET_SCHEDULER_add_now (&process_tickets, rvk);
}


static void
rvk_ns_iter_err (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_it = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Namestore error on revocation (id=%" PRIu64 "\n",
              rvk->move_attr->old_id);
  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


static void
rvk_ns_err (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_qe = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Namestore error on revocation (id=%" PRIu64 "\n",
              rvk->move_attr->old_id);
  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


static void
move_attrs (struct RECLAIM_TICKETS_RevokeHandle *rvk)
{
  char *label;

  if (NULL == rvk->move_attr) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished moving attributes\n");
    rvk->ns_it = GNUNET_NAMESTORE_zone_iteration_start (
        nsh, &rvk->identity, &rvk_ns_iter_err, rvk, &rvk_ticket_update, rvk,
        &rvk_ticket_update_finished, rvk);
    return;
  }
  label = GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->old_id,
                                               sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Moving attribute %s\n", label);

  rvk->ns_qe = GNUNET_NAMESTORE_records_lookup (
      nsh, &rvk->identity, label, &rvk_ns_err, rvk, &rvk_move_attr_cb, rvk);
  GNUNET_free (label);
}


static void
remove_ticket_cont (void *cls, int32_t success, const char *emsg)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleted ticket\n");
  if (0 == rvk->ticket_attrs) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "No attributes to move... strange\n");
    rvk->cb (rvk->cb_cls, GNUNET_OK);
    cleanup_rvk (rvk);
    return;
  }
  rvk->move_attr = rvk->attrs_head;
  move_attrs (rvk);
}


static void
revoke_attrs_cb (void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                 const char *label, unsigned int rd_count,
                 const struct GNUNET_GNSRECORD_Data *rd)

{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct RevokedAttributeEntry *le;
  rvk->ns_qe = NULL;
  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF != rd[i].record_type)
      continue;
    le = GNUNET_new (struct RevokedAttributeEntry);
    le->old_id = *((uint64_t *)rd[i].data);
    GNUNET_CONTAINER_DLL_insert (rvk->attrs_head, rvk->attrs_tail, le);
    rvk->ticket_attrs++;
  }

  /** Now, remove ticket **/
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh, &rvk->identity, label, 0,
                                               NULL, &remove_ticket_cont, rvk);
}


static void
rvk_attrs_err_cb (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


struct RECLAIM_TICKETS_RevokeHandle *
RECLAIM_TICKETS_revoke (const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                        RECLAIM_TICKETS_RevokeCallback cb, void *cb_cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk;
  char *label;

  rvk = GNUNET_new (struct RECLAIM_TICKETS_RevokeHandle);
  rvk->cb = cb;
  rvk->cb_cls = cb_cls;
  rvk->identity = *identity;
  rvk->ticket = *ticket;
  GNUNET_CRYPTO_ecdsa_key_get_public (&rvk->identity, &rvk->ticket.identity);
  /** Get shared attributes **/
  label = GNUNET_STRINGS_data_to_string_alloc (&ticket->rnd, sizeof (uint64_t));

  rvk->ns_qe = GNUNET_NAMESTORE_records_lookup (
      nsh, identity, label, &rvk_attrs_err_cb, rvk, &revoke_attrs_cb, rvk);
  return rvk;
}


void
RECLAIM_TICKETS_revoke_cancel (struct RECLAIM_TICKETS_RevokeHandle *rh)
{
  cleanup_rvk (rh);
}
/*******************************
 * Ticket consume
 *******************************/

/**
 * Cleanup ticket consume handle
 * @param cth the handle to clean up
 */
static void
cleanup_cth (struct RECLAIM_TICKETS_ConsumeHandle *cth)
{
  struct ParallelLookup *lu;
  if (NULL != cth->lookup_request)
    GNUNET_GNS_lookup_cancel (cth->lookup_request);
  if (NULL != cth->kill_task)
    GNUNET_SCHEDULER_cancel (cth->kill_task);
  while (NULL != (lu = cth->parallel_lookups_head)) {
    if (NULL != lu->lookup_request)
      GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free_non_null (lu->label);
    GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail, lu);
    GNUNET_free (lu);
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

  cth->cb (cth->cb_cls, &cth->ticket.identity, cth->attrs, GNUNET_OK, NULL);
  cleanup_cth (cth);
}


static void
abort_parallel_lookups (void *cls)
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


static void
lookup_authz_cb (void *cls, uint32_t rd_count,
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
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF != rd[i].record_type)
      continue;
    lbl = GNUNET_STRINGS_data_to_string_alloc (rd[i].data, rd[i].data_size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Attribute ref found %s\n", lbl);
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
  if (NULL != cth->parallel_lookups_head) {
    cth->kill_task = GNUNET_SCHEDULER_add_delayed (
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 3),
        &abort_parallel_lookups, cth);
    return;
  }
  cth->cb (cth->cb_cls, &cth->ticket.identity, cth->attrs, GNUNET_OK, NULL);
  cleanup_cth (cth);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for AuthZ info under %s\n",
              label);
  cth->lookup_start_time = GNUNET_TIME_absolute_get ();
  cth->lookup_request = GNUNET_GNS_lookup (
      gns, label, &cth->ticket.identity, GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF,
      GNUNET_GNS_LO_DEFAULT, &lookup_authz_cb, cth);
  GNUNET_free (label);
  return cth;
}

void
RECLAIM_TICKETS_consume_cancel (struct RECLAIM_TICKETS_ConsumeHandle *cth)
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
static void
cleanup_issue_handle (struct TicketIssueHandle *handle)
{
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free (handle);
}


static void
store_ticket_issue_cont (void *cls, int32_t success, const char *emsg)
{
  struct TicketIssueHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success) {
    handle->cb (handle->cb_cls, &handle->ticket, GNUNET_SYSERR,
                "Error storing AuthZ ticket in GNS");
    return;
  }
  handle->cb (handle->cb_cls, &handle->ticket, GNUNET_OK, NULL);
  cleanup_issue_handle (handle);
}


static void
issue_ticket (struct TicketIssueHandle *ih)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_GNSRECORD_Data *attrs_record;
  char *label;
  size_t list_len = 1;
  int i;

  for (le = ih->attrs->list_head; NULL != le; le = le->next)
    list_len++;

  attrs_record =
      GNUNET_malloc (list_len * sizeof (struct GNUNET_GNSRECORD_Data));
  i = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next) {
    attrs_record[i].data = &le->claim->id;
    attrs_record[i].data_size = sizeof (le->claim->id);
    //FIXME: Should this be the attribute expiration time or ticket refresh intv
    attrs_record[i].expiration_time = ticket_refresh_interval.rel_value_us;
    attrs_record[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF;
    attrs_record[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    i++;
  }
  attrs_record[i].data = &ih->ticket;
  attrs_record[i].data_size = sizeof (struct GNUNET_RECLAIM_Ticket);
  attrs_record[i].expiration_time = ticket_refresh_interval.rel_value_us;
  attrs_record[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET;
  attrs_record[i].flags =
      GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;

  label =
      GNUNET_STRINGS_data_to_string_alloc (&ih->ticket.rnd, sizeof (uint64_t));
  // Publish record
  ih->ns_qe = GNUNET_NAMESTORE_records_store (nsh, &ih->identity, label,
                                              list_len, attrs_record,
                                              &store_ticket_issue_cont, ih);
  GNUNET_free (attrs_record);
  GNUNET_free (label);
}


void
RECLAIM_TICKETS_issue (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
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

static void
cleanup_iter (struct RECLAIM_TICKETS_Iterator *iter)
{
  if (NULL != iter->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (iter->ns_it);
  GNUNET_free (iter);
}


static void
collect_tickets_cb (void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                    const char *label, unsigned int rd_count,
                    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;

  for (int i = 0; i < rd_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET != rd[i].record_type)
      continue;
    iter->cb (iter->cb_cls, (struct GNUNET_RECLAIM_Ticket *)rd[i].data);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (iter->ns_it, 1);
}


static void
collect_tickets_finished_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  iter->ns_it = NULL;
  iter->cb (iter->cb_cls, NULL);
  cleanup_iter (iter);
}


static void
collect_tickets_error_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  iter->ns_it = NULL;
  iter->cb (iter->cb_cls, NULL);
  cleanup_iter (iter);
}


void
RECLAIM_TICKETS_iteration_next (struct RECLAIM_TICKETS_Iterator *iter)
{
  GNUNET_NAMESTORE_zone_iterator_next (iter->ns_it, 1);
}


void
RECLAIM_TICKETS_iteration_stop (struct RECLAIM_TICKETS_Iterator *iter)
{
  GNUNET_NAMESTORE_zone_iteration_stop (iter->ns_it);
  cleanup_iter (iter);
}


struct RECLAIM_TICKETS_Iterator *
RECLAIM_TICKETS_iteration_start (
    const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
    RECLAIM_TICKETS_TicketIter cb, void *cb_cls)
{
  struct RECLAIM_TICKETS_Iterator *iter;

  iter = GNUNET_new (struct RECLAIM_TICKETS_Iterator);
  iter->cb = cb;
  iter->cb_cls = cb_cls;
  iter->ns_it = GNUNET_NAMESTORE_zone_iteration_start (
      nsh, identity, &collect_tickets_error_cb, iter, &collect_tickets_cb, iter,
      &collect_tickets_finished_cb, iter);
  return iter;
}


int
RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  // Get ticket expiration time (relative) from config
  if (GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_time (c,
                                              "reclaim",
                                              "TICKET_REFRESH_INTERVAL",
                                              &ticket_refresh_interval)) {
    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Configured refresh interval for tickets: %s\n",
      GNUNET_STRINGS_relative_time_to_string (ticket_refresh_interval,
                                              GNUNET_YES));
  } else {
    ticket_refresh_interval = DEFAULT_TICKET_REFRESH_INTERVAL;
  }
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

void
RECLAIM_TICKETS_deinit (void)
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
