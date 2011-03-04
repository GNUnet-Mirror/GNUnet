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
 * Request to datastore for DHT PUTs (or NULL).
 */
static struct GNUNET_DATASTORE_QueueEntry *dht_qe;

/**
 * Type we will request for the next DHT PUT round from the datastore.
 */
static enum GNUNET_BLOCK_Type dht_put_type = GNUNET_BLOCK_TYPE_FS_KBLOCK;

/**
 * ID of task that collects blocks for DHT PUTs.
 */
static GNUNET_SCHEDULER_TaskIdentifier dht_task;

/**
 * How many entires with zero anonymity do we currently estimate
 * to have in the database?
 */
static unsigned int zero_anonymity_count_estimate;


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
 * If the DHT PUT gathering task is not currently running, consider
 * (re)scheduling it with the appropriate delay.
 */
static void
consider_dht_put_gathering (void *cls)
{
  struct GNUNET_TIME_Relative delay;

  if (GSF_dsh == NULL)
    return;
  if (dht_qe != NULL)
    return;
  if (dht_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  if (zero_anonymity_count_estimate > 0)
    {
      delay = GNUNET_TIME_relative_divide (GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY,
					   zero_anonymity_count_estimate);
      delay = GNUNET_TIME_relative_min (delay,
					MAX_DHT_PUT_FREQ);
    }
  else
    {
      /* if we have NO zero-anonymity content yet, wait 5 minutes for some to
	 (hopefully) appear */
      delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5);
    }
  dht_task = GNUNET_SCHEDULER_add_delayed (delay,
					   &gather_dht_put_blocks,
					   cls);
}


/**
 * Function called upon completion of the DHT PUT operation.
 */
static void
dht_put_continuation (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DATASTORE_get_next (GSF_dsh, GNUNET_YES);
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
process_dht_put_content (void *cls,
			 const GNUNET_HashCode * key,
			 size_t size,
			 const void *data,
			 enum GNUNET_BLOCK_Type type,
			 uint32_t priority,
			 uint32_t anonymity,
			 struct GNUNET_TIME_Absolute
			 expiration, uint64_t uid)
{ 
  static unsigned int counter;
  static GNUNET_HashCode last_vhash;
  static GNUNET_HashCode vhash;

  if (key == NULL)
    {
      dht_qe = NULL;
      consider_dht_put_gathering (cls);
      return;
    }
  /* slightly funky code to estimate the total number of values with zero
     anonymity from the maximum observed length of a monotonically increasing 
     sequence of hashes over the contents */
  GNUNET_CRYPTO_hash (data, size, &vhash);
  if (GNUNET_CRYPTO_hash_cmp (&vhash, &last_vhash) <= 0)
    {
      if (zero_anonymity_count_estimate > 0)
	zero_anonymity_count_estimate /= 2;
      counter = 0;
    }
  last_vhash = vhash;
  if (counter < 31)
    counter++;
  if (zero_anonymity_count_estimate < (1 << counter))
    zero_anonymity_count_estimate = (1 << counter);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Retrieved block `%s' of type %u for DHT PUT\n",
	      GNUNET_h2s (key),
	      type);
#endif
  GNUNET_DHT_put (GSF_dht,
		  key,
		  DEFAULT_PUT_REPLICATION,
		  GNUNET_DHT_RO_NONE,
		  type,
		  size,
		  data,
		  expiration,
		  GNUNET_TIME_UNIT_FOREVER_REL,
		  &dht_put_continuation,
		  cls);
}


/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 * 
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
gather_dht_put_blocks (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  dht_task = GNUNET_SCHEDULER_NO_TASK;
  if (GSF_dsh == NULL)
    return;
  if (dht_put_type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    dht_put_type = GNUNET_BLOCK_TYPE_FS_KBLOCK;
  dht_qe = GNUNET_DATASTORE_get_zero_anonymity (GSF_dsh, 
						0, UINT_MAX,
						GNUNET_TIME_UNIT_FOREVER_REL,
						dht_put_type++,
						&process_dht_put_content, NULL);
  GNUNET_assert (dht_qe != NULL);
}


/**
 * Setup the module.
 * 
 * @param cfg configuration to use
 */
void
GSF_put_init_ (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  dht_task = GNUNET_SCHEDULER_add_now (&gather_dht_put_blocks, NULL);
}


/**
 * Shutdown the module.
 */
void
GSF_put_done_ ()
{
  if (GNUNET_SCHEDULER_NO_TASK != dht_task)
    {
      GNUNET_SCHEDULER_cancel (dht_task);
      dht_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL != dht_qe)
    {
      GNUNET_DATASTORE_cancel (dht_qe);
      dht_qe = NULL;
    }
}

/* end of gnunet-service-fs_put.c */
