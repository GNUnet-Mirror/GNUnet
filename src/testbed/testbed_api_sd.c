/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_sd.c
 * @brief functions to calculate standard deviation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "testbed_api_sd.h"

/**
 * An entry to hold data which will be used to calculate SD
 */
struct SDEntry
{
  /**
   * DLL next pointer
   */
  struct SDEntry *next;

  /**
   * DLL prev pointer
   */
  struct SDEntry *prev;

  /**
   * The value to store
   */
  unsigned int amount;
};


/**
 * Opaque handle for calculating SD
 */
struct SDHandle
{
  /**
   * DLL head for storing entries
   */
  struct SDEntry *head;

  /**
   * DLL tail for storing entries
   */
  struct SDEntry *tail;

  /**
   * Squared sum of data values
   */
  unsigned long long sqsum;

  /**
   * Sum of the data values
   */
  unsigned long sum;

  /**
   * The average of data amounts
   */
  float avg;

  /**
   * The variance
   */
  double vr;

  /**
   * Number of data values; also the length of DLL containing SDEntries
   */
  unsigned int cnt;

  /**
   * max number of entries we can have in the DLL
   */
  unsigned int max_cnt;
};


/**
 * Initialize standard deviation calculation handle
 *
 * @param max_cnt the maximum number of readings to keep
 * @return the initialized handle
 */
struct SDHandle *
GNUNET_TESTBED_SD_init_ (unsigned int max_cnt)
{
  struct SDHandle *h;

  GNUNET_assert (1 < max_cnt);
  h = GNUNET_new (struct SDHandle);
  h->max_cnt = max_cnt;
  return h;
}


/**
 * Frees the memory allocated to the SD handle
 *
 * @param h the SD handle
 */
void
GNUNET_TESTBED_SD_destroy_ (struct SDHandle *h)
{
  struct SDEntry *entry;

  while (NULL != (entry = h->head))
  {
    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, entry);
    GNUNET_free (entry);
  }
  GNUNET_free (h);
}


/**
 * Add a reading to SD
 *
 * @param h the SD handle
 * @param amount the reading value
 */
void
GNUNET_TESTBED_SD_add_data_ (struct SDHandle *h, unsigned int amount)
{
  struct SDEntry *entry;
  double sqavg;
  double sqsum_avg;

  entry = NULL;
  if (h->cnt == h->max_cnt)
  {
    entry = h->head;
    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, entry);
    h->sum -= entry->amount;
    h->sqsum -=
        ((unsigned long) entry->amount) * ((unsigned long) entry->amount);
    h->cnt--;
  }
  GNUNET_assert (h->cnt < h->max_cnt);
  if (NULL == entry)
    entry = GNUNET_new (struct SDEntry);
  entry->amount = amount;
  GNUNET_CONTAINER_DLL_insert_tail (h->head, h->tail, entry);
  h->sum += amount;
  h->cnt++;
  h->avg = ((float) h->sum) / ((float) h->cnt);
  h->sqsum += ((unsigned long) amount) * ((unsigned long) amount);
  sqsum_avg = ((double) h->sqsum) / ((double) h->cnt);
  sqavg = ((double) h->avg) * ((double) h->avg);
  h->vr = sqsum_avg - sqavg;
}


/**
 * Calculates the factor by which the given amount differs
 *
 * @param h the SDhandle
 * @param amount the value for which the deviation is returned
 * @param factor the factor by which the given amont differs
 * @return GNUNET_SYSERR if the deviation cannot
 *   be calculated; GNUNET_OK if the deviation is returned through factor
 */
int
GNUNET_TESTBED_SD_deviation_factor_ (struct SDHandle *h, unsigned int amount,
                                     int *factor)
{
  double diff;
  int f;
  int n;

  if (h->cnt < 2)
    return GNUNET_SYSERR;
  if (((float) amount) > h->avg)
  {
    diff = ((float) amount) - h->avg;
    f = 1;
  }
  else
  {
    diff = h->avg - ((float) amount);
    f = -1;
  }
  diff *= diff;
  for (n = 1; n < 4; n++)
    if (diff < (((double) (n * n)) * h->vr))
      break;
  *factor = f * n;
  return GNUNET_OK;
}

/* end of testbed_api_sd.c */
