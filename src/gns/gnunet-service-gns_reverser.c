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
   * Current delegation to expect
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey target;

  /**
   * The zone target for reverse record resolution
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey myzone;

  /**
   * The nick of our zone
   */
  char *mynick;

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

void
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
}

void
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

void
next_it (void *cls);

void
handle_gns_result_iter (void *cls,
                        uint32_t rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IteratorHandle *ith = cls;
  struct ReverseRecordEntry *rr;
  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_PKEY != rd->record_type))
  {
    gns_lookup_reverse = NULL;
    GNUNET_SCHEDULER_add_now (&next_it, NULL);
    return;
  }


  rr = GNUNET_new (struct ReverseRecordEntry);
  rr->record = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_ReverseRecord)
                              + strlen (ith->mynick) + 1);
  rr->record->pkey = ith->target;
  rr->record->expiration.abs_value_us = rd->expiration_time;
  GNUNET_memcpy ((char*)&rr->record[1],
                 ith->mynick,
                 strlen (ith->mynick));
  GNUNET_CONTAINER_DLL_insert (ith->records_head,
                               ith->records_tail,
                               rr);
  GNUNET_SCHEDULER_add_now (&next_it, NULL);
}

void
next_it (void *cls)
{
  GNUNET_assert (NULL != namestore_iter);
  GNUNET_NAMESTORE_zone_iterator_next (namestore_iter);
}

void
iterator_cb (void *cls,
             const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IteratorHandle *ith = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey *target;
  struct GNUNET_CRYPTO_EcdsaPublicKey zone;

  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_PKEY != rd->record_type))
  {
    GNUNET_SCHEDULER_add_now (&next_it, NULL);
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (key,
                                      &zone);
  if (0 != memcmp (&zone, &ith->myzone,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_SCHEDULER_add_now (&next_it, NULL);
    return;
  }
  target = (struct GNUNET_CRYPTO_EcdsaPublicKey *) rd->data;
  gns_lookup_reverse = GNS_resolver_lookup (target,
                                            GNUNET_GNSRECORD_TYPE_PKEY,
                                            ith->mynick,
                                            NULL,
                                            GNUNET_GNS_LO_DEFAULT,
                                            &handle_gns_result_iter,
                                            ith);
}

void check_reverse_records (void *cls);

void
finished_cb (void *cls)
{
  struct IteratorHandle *ith = cls;
  struct ReverseRecordEntry *rr;

  //TODO add results to namestore!
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

}

void
it_error (void *cls)
{
  finished_cb (cls);
}

void
check_reverse_records (void *cls)
{
  struct IteratorHandle *ith = cls;
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                          NULL,
                                                          &it_error,
                                                          ith,
                                                          &iterator_cb,
                                                          ith,
                                                          &finished_cb,
                                                          ith);
}

void
GNS_reverse_init (const struct GNUNET_CONFIGURATION_Handle *c,
                  const struct GNUNET_NAMESTORE_Handle *nh,
                  const struct GNUNET_CRYPTO_EcdsaPublicKey *myzone,
                  const char *mynick)
{
  struct IteratorHandle *ith;

  ns = ns;
  ith = GNUNET_new (struct IteratorHandle);
  ith->mynick = GNUNET_strdup (mynick);
  ith->myzone = *myzone;
  reverse_record_check_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_DAYS,
                                                            &check_reverse_records,
                                                            NULL);
}

