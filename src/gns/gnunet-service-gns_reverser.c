/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file gns/gnunet-service-gns_reverser.c
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */


#include "platform.h"
#include "gnunet_gns_service.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_reverser.h"

struct ReverseRecordEntry
{
  /**
   * DLL
   */
  struct ReverseRecordEntry *next;

  /**
   * DLL
   */
  struct ReverseRecordEntry *prev;

  /**
   * ReverseRecord
   */
  struct GNUNET_GNSRECORD_ReverseRecord *record;

  /**
   * Record length
   */
  size_t record_len;

};

struct IteratorHandle
{
  /**
   * Records found
   */
  struct ReverseRecordEntry *records_head;

  /**
   * Records found
   */
  struct ReverseRecordEntry *records_tail;

  /**
   * Record count
   */
  uint64_t record_count;

  /**
   * Current delegation to expect
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey target;

  /**
   * Queue entry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

};

struct ReverseTreeNode
{
  /**
   * DLL
   */
  struct ReverseTreeNode *next;

  /**
   * DLL
   */
  struct ReverseTreeNode *prev;

  /**
   * Resolved name until now
   */
  char *name;

  /**
   * Depth of the resolution at this node
   */
  uint8_t depth;

  /**
   * The pkey of the namespace
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

};


struct GNS_ReverserHandle
{
  /**
   * GNS resolver handle
   */
  struct GNS_ResolverHandle *rh;

  /**
   * The authority to look for
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey authority;

  /**
   * Resolution candidate queue
   */
  struct ReverseTreeNode *node_queue_head;

  /**
   * Resolution candidate queue
   */
  struct ReverseTreeNode *node_queue_tail;

  /**
   * Max depth for the resolution
   */
  uint8_t max_depth;

  /**
   * Result callback
   */
  GNS_ReverseResultProcessor proc;

  /**
   * Callback closure
   */
  void *proc_cls;
};

/**
 * Reverse record collection task
 */
static struct GNUNET_SCHEDULER_Task *reverse_record_check_task;

/**
 * NS iterator task
 */
static struct GNUNET_SCHEDULER_Task *it_task;

/**
 * GNS lookup handle
 */
static struct GNS_ResolverHandle *gns_lookup_reverse;

/**
 * NS handle
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * NS Iterator
 */
static struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * The zone target for reverse record resolution
 */
static struct GNUNET_CRYPTO_EcdsaPublicKey myzone;

/**
 * The zone target for reverse record resolution
 */
static struct GNUNET_CRYPTO_EcdsaPrivateKey pzone;

/**
 * The nick of our zone
 */
static char *mynick;


static void
cleanup_handle (struct GNS_ReverserHandle *rh)
{
  struct ReverseTreeNode *rtn;

  for (rtn = rh->node_queue_head; NULL != rtn; rtn = rh->node_queue_head)
  {
    if (NULL != rtn->name)
      GNUNET_free (rtn->name);
        GNUNET_CONTAINER_DLL_remove (rh->node_queue_head,
                                 rh->node_queue_tail,
                                 rtn);
        GNUNET_free (rtn);
  }
  GNUNET_free (rh);
}

static void
handle_gns_result (void *cls,
                   uint32_t rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ReverserHandle *rh = cls;
  const struct GNUNET_GNSRECORD_ReverseRecord *rr;
  struct ReverseTreeNode *rtn;
  char *result;
  const char *name;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got result (%d)\n", rd_count);

  for (int i = 0; i < rd_count; i++)
  {
    /**
     * Check if we are in the delegation set
     */
    if (GNUNET_GNSRECORD_TYPE_REVERSE != rd[i].record_type)
      continue;
    rr = rd[i].data;
    name = (const char*) &rr[1];
    if (0 == memcmp (&rh->authority,
                     &rr->pkey,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      //Found!
      GNUNET_asprintf (&result,
                       "%s.%s.gnu",
                       rh->node_queue_head->name,
                       name);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found path from %s\n", result);

      rh->proc (rh->proc_cls, result);
      cleanup_handle (rh);
      GNUNET_free (result);
      return;
    } else {
      if (rh->node_queue_head->depth >= rh->max_depth)
        break;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found REVERSE from %s\n", name);

      rtn = GNUNET_new (struct ReverseTreeNode);
      if (NULL == rh->node_queue_head->name)
        rtn->name = GNUNET_strdup (name);
      else
        GNUNET_asprintf (&rtn->name,
                         "%s.%s",
                         rh->node_queue_head->name,
                         name);
      rtn->depth = rh->node_queue_head->depth + 1;
      rtn->pkey = rr->pkey;
      GNUNET_CONTAINER_DLL_insert_tail (rh->node_queue_head,
                                        rh->node_queue_tail,
                                        rtn);
    }
  }

  /**
   * Done here remove node from queue
   */
  rtn = rh->node_queue_head;
  if (NULL != rtn)
    GNUNET_CONTAINER_DLL_remove (rh->node_queue_head,
                                 rh->node_queue_tail,
                                 rtn);
  if (NULL == rh->node_queue_head)
  {
    //No luck
    rh->proc (rh->proc_cls, NULL);
    cleanup_handle (rh);
    return;
  }
  rh->rh = GNS_resolver_lookup (&rh->node_queue_head->pkey,
                                GNUNET_GNSRECORD_TYPE_REVERSE,
                                "+.gnu",
                                NULL,
                                GNUNET_GNS_LO_DEFAULT,
                                &handle_gns_result,
                                rh);
}

/**
 * Reverse lookup of a specific zone
 * calls RecordLookupProcessor on result or timeout
 *
 * @param target the zone to perform the lookup in
 * @param authority the authority
 * @param proc the processor to call
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ReverserHandle *
GNS_reverse_lookup (const struct GNUNET_CRYPTO_EcdsaPublicKey *target,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *authority,
                    GNS_ReverseResultProcessor proc,
                    void *proc_cls)
{
  struct GNS_ReverserHandle *rh;
  struct ReverseTreeNode *rtn;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting reverse resolution\n");
  rh = GNUNET_new (struct GNS_ReverserHandle);
  rh->proc = proc;
  rh->proc_cls = proc_cls;
  rtn = GNUNET_new (struct ReverseTreeNode);
  rtn->name = NULL;
  rtn->pkey = *target;
  rtn->depth = 0;
  GNUNET_CONTAINER_DLL_insert (rh->node_queue_head,
                               rh->node_queue_tail,
                               rtn);
  rh->authority = *authority;
  rh->max_depth = 3; //TODO make argument
  rh->rh = GNS_resolver_lookup (target,
                                GNUNET_GNSRECORD_TYPE_REVERSE,
                                "+.gnu",
                                NULL,
                                GNUNET_GNS_LO_DEFAULT,
                                &handle_gns_result,
                                rh);
  return rh;
}

/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_reverse_lookup_cancel (struct GNS_ReverserHandle *rh)
{
  cleanup_handle (rh);
  return;
}

/********************************************
 * Reverse iterator
 * ******************************************/


static void
next_it (void *cls);

static void
handle_gns_result_iter (void *cls,
                        uint32_t rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IteratorHandle *ith = cls;
  struct ReverseRecordEntry *rr;
  gns_lookup_reverse = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS for REVERSE (%s)\n", mynick);


  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_PKEY != rd->record_type))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNS invalid REVERSE (%s)\n", mynick);
    gns_lookup_reverse = NULL;
    it_task = GNUNET_SCHEDULER_add_now (&next_it, ith);
    return;
  }


  rr = GNUNET_new (struct ReverseRecordEntry);
  rr->record_len = sizeof (struct GNUNET_GNSRECORD_ReverseRecord)
    + strlen (mynick) + 1;
  rr->record = GNUNET_malloc (rr->record_len);
  rr->record->pkey = ith->target;
  rr->record->expiration.abs_value_us = rd->expiration_time;
  GNUNET_memcpy ((char*)&rr->record[1],
                 mynick,
                 strlen (mynick));
  GNUNET_CONTAINER_DLL_insert (ith->records_head,
                               ith->records_tail,
                               rr);
  ith->record_count++;
  it_task = GNUNET_SCHEDULER_add_now (&next_it, ith);
}

static void
next_it (void *cls)
{
  it_task = NULL;
  GNUNET_assert (NULL != namestore_iter);
  GNUNET_NAMESTORE_zone_iterator_next (namestore_iter);
}

static void
iterator_cb (void *cls,
             const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IteratorHandle *ith = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey zone;
  char *name;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "iterating for REVERSE (%s / %s)\n",
              label,
              mynick);


  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_PKEY != rd->record_type))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "wrong format (%s)\n", mynick);


    it_task = GNUNET_SCHEDULER_add_now (&next_it, ith);
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (key,
                                      &zone);
  if (0 != memcmp (&zone, &myzone,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "wrong zone (%s)\n", mynick);


    it_task = GNUNET_SCHEDULER_add_now (&next_it, ith);
    return;
  }
  ith->target = *((struct GNUNET_CRYPTO_EcdsaPublicKey *) rd->data);
  GNUNET_asprintf (&name,
                  "%s.gnu",
                  mynick);
  gns_lookup_reverse = GNS_resolver_lookup (&ith->target,
                                            GNUNET_GNSRECORD_TYPE_PKEY,
                                            name,
                                            NULL,
                                            GNUNET_GNS_LO_DEFAULT,
                                            &handle_gns_result_iter,
                                            ith);
  GNUNET_free (name);
}

static void check_reverse_records (void *cls);

static void
store_reverse (void *cls,
               int32_t success,
               const char *emsg)
{
  struct IteratorHandle *ith = cls;
  struct ReverseRecordEntry *rr;

  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                emsg);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stored records (%s)\n", mynick);

  for (rr = ith->records_head; NULL != rr; rr = ith->records_head)
  {
    GNUNET_CONTAINER_DLL_remove (ith->records_head,
                                 ith->records_tail,
                                 rr);
    GNUNET_free (rr->record);
    GNUNET_free (rr);
  }
  reverse_record_check_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_DAYS,
                                                            &check_reverse_records,
                                                            NULL);
  GNUNET_free (ith);
}

static void
finished_cb (void *cls)
{
  struct IteratorHandle *ith = cls;
  struct ReverseRecordEntry *rr;
  struct GNUNET_GNSRECORD_Data rd[ith->record_count];

  memset (rd, 0, sizeof (struct GNUNET_GNSRECORD_Data) * ith->record_count);

  rr = ith->records_head;
  for (int i = 0; i < ith->record_count; i++)
  {
    rd[i].data_size = rr->record_len;
    rd[i].data = GNUNET_malloc (rr->record_len);
    rd[i].record_type = GNUNET_GNSRECORD_TYPE_REVERSE;
    rd[i].expiration_time = rr->record->expiration.abs_value_us;
    GNUNET_memcpy ((char*) rd[i].data,
                   rr->record,
                   rr->record_len);
    rr = rr->next;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished iterating for REVERSE\n");

  ith->ns_qe = GNUNET_NAMESTORE_records_store (ns,
                                               &pzone,
                                               "+",
                                               ith->record_count,
                                               rd,
                                               &store_reverse,
                                               ith);
  namestore_iter = NULL;

}

static void
it_error (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Error iterating for REVERSE\n");
}

static void
check_reverse_records (void *cls)
{
  struct IteratorHandle *ith;
  ith = GNUNET_new (struct IteratorHandle);
  ith->record_count = 0;
  reverse_record_check_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Start iterating for REVERSE (%s)\n", mynick);
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                          NULL,
                                                          &it_error,
                                                          ith,
                                                          &iterator_cb,
                                                          ith,
                                                          &finished_cb,
                                                          ith);
}


/**
 * Initialize reverser
 *
 * @param nh handle to a namestore
 * @param key the private key of the gns-reverse zone
 * @param name the name of the gns-reverse zone
 * @return GNUNET_OK
 */
int
GNS_reverse_init (struct GNUNET_NAMESTORE_Handle *nh,
                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                  const char *nick)
{
  GNUNET_asprintf (&mynick,
                   "%s",
                   nick);
  GNUNET_CRYPTO_ecdsa_key_get_public (zone,
                                      &myzone);
  GNUNET_memcpy (&pzone,
                 zone,
                 sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  ns = nh;
  reverse_record_check_task = GNUNET_SCHEDULER_add_now (&check_reverse_records,
                                                        NULL);
  return GNUNET_OK;
}

/**
 * Cleanup reverser
 */
void
GNS_reverse_done ()
{
  if (NULL != mynick)
    GNUNET_free (mynick);
  if (NULL != it_task)
    GNUNET_SCHEDULER_cancel (it_task);
  if (NULL != reverse_record_check_task)
    GNUNET_SCHEDULER_cancel (reverse_record_check_task);
  if (NULL != gns_lookup_reverse)
    GNS_resolver_lookup_cancel (gns_lookup_reverse);
  if (NULL != namestore_iter)
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
}

