/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file fs/gnunet-service-fs_put.c
 * @brief API to PUT zero-anonymity index data from our datastore into the DHT
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_put.h"


/**
 * How often do we at most PUT content into the DHT?
 */
#define MAX_DHT_PUT_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Context for each zero-anonymity iterator.
 */
struct PutOperator
{

  /**
   * Request to datastore for DHT PUTs (or NULL).
   */
  struct GNUNET_DATASTORE_QueueEntry *dht_qe;

  /**
   * Type we request from the datastore.
   */
  enum GNUNET_BLOCK_Type dht_put_type;

  /**
   * ID of task that collects blocks for DHT PUTs.
   */
  GNUNET_SCHEDULER_TaskIdentifier dht_task;

  /**
   * How many entires with zero anonymity of our type do we currently
   * estimate to have in the database?
   */
  uint64_t zero_anonymity_count_estimate;

  /**
   * Current offset when iterating the database.
   */
  uint64_t current_offset;
};


/**
 * ANY-terminated list of our operators (one per type
 * of block that we're putting into the DHT).
 */
static struct PutOperator operators[] = {
  {NULL, GNUNET_BLOCK_TYPE_FS_KBLOCK, 0, 0, 0},
  {NULL, GNUNET_BLOCK_TYPE_FS_SBLOCK, 0, 0, 0},
  {NULL, GNUNET_BLOCK_TYPE_FS_NBLOCK, 0, 0, 0},
  {NULL, GNUNET_BLOCK_TYPE_ANY, 0, 0, 0}
};


/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 *
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
gather_dht_put_blocks (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 *
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
delay_dht_put_blocks (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PutOperator *po = cls;
  struct GNUNET_TIME_Relative delay;

  po->dht_task = GNUNET_SCHEDULER_NO_TASK;
  if (tc != NULL && 0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (po->zero_anonymity_count_estimate > 0)
  {
    delay =
        GNUNET_TIME_relative_divide (GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY,
                                     po->zero_anonymity_count_estimate);
    delay = GNUNET_TIME_relative_min (delay, MAX_DHT_PUT_FREQ);
  }
  else
  {
    /* if we have NO zero-anonymity content yet, wait 5 minutes for some to
     * (hopefully) appear */
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5);
  }
  po->dht_task =
      GNUNET_SCHEDULER_add_delayed (delay, &gather_dht_put_blocks, po);
}


/**
 * Store content in DHT.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_dht_put_content (void *cls, const GNUNET_HashCode * key, size_t size,
                         const void *data, enum GNUNET_BLOCK_Type type,
                         uint32_t priority, uint32_t anonymity,
                         struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct PutOperator *po = cls;

  po->dht_qe = NULL;
  if (key == NULL)
  {
    po->zero_anonymity_count_estimate = po->current_offset - 1;
    po->current_offset = 0;
    po->dht_task = GNUNET_SCHEDULER_add_now (&delay_dht_put_blocks, po);
    return;
  }
  po->zero_anonymity_count_estimate =
      GNUNET_MAX (po->current_offset, po->zero_anonymity_count_estimate);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Retrieved block `%s' of type %u for DHT PUT\n", GNUNET_h2s (key),
              type);
  GNUNET_DHT_put (GSF_dht, key, 5 /* DEFAULT_PUT_REPLICATION */ ,
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, type, size, data,
                  expiration, GNUNET_TIME_UNIT_FOREVER_REL,
                  &delay_dht_put_blocks, po);
}


/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 *
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
gather_dht_put_blocks (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PutOperator *po = cls;

  po->dht_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  po->dht_qe =
      GNUNET_DATASTORE_get_zero_anonymity (GSF_dsh, po->current_offset++, 0,
                                           UINT_MAX,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           po->dht_put_type,
                                           &process_dht_put_content, po);
  if (NULL == po->dht_qe)
    po->dht_task = GNUNET_SCHEDULER_add_now (&delay_dht_put_blocks, po);
}


/**
 * Setup the module.
 */
void
GSF_put_init_ ()
{
  unsigned int i;

  i = 0;
  while (operators[i].dht_put_type != GNUNET_BLOCK_TYPE_ANY)
  {
    operators[i].dht_task =
        GNUNET_SCHEDULER_add_now (&gather_dht_put_blocks, &operators[i]);
    i++;
  }
}


/**
 * Shutdown the module.
 */
void
GSF_put_done_ ()
{
  struct PutOperator *po;
  unsigned int i;

  i = 0;
  while ((po = &operators[i])->dht_put_type != GNUNET_BLOCK_TYPE_ANY)
  {
    if (GNUNET_SCHEDULER_NO_TASK != po->dht_task)
    {
      GNUNET_SCHEDULER_cancel (po->dht_task);
      po->dht_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != po->dht_qe)
    {
      GNUNET_DATASTORE_cancel (po->dht_qe);
      po->dht_qe = NULL;
    }
    i++;
  }
}

/* end of gnunet-service-fs_put.c */
