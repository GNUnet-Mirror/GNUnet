/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util_lib.h"

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


struct SDHandle *
SD_init (unsigned int max_cnt)
{
  struct SDHandle *h;
  
  GNUNET_assert (1 < max_cnt);
  h = GNUNET_malloc (sizeof (struct SDHandle));
  h->max_cnt = max_cnt;
  return h;
}

void
SD_destroy (struct SDHandle *h)
{
  struct SDEntry *entry;
  
  while (NULL != (entry = h->head))
  {
    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, entry);
    GNUNET_free (entry);
  }
  GNUNET_free (h);
}

void
SD_add_data (struct SDHandle *h, unsigned int amount)
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
    h->sqsum -= ((unsigned long) entry->amount) * 
        ((unsigned long) entry->amount);
    h->cnt--;
  }
  GNUNET_assert (h->cnt < h->max_cnt);
  if (NULL == entry)
    entry = GNUNET_malloc (sizeof (struct SDEntry));
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
 * Returns the factor by which the given amount differs from the standard deviation
 *
 * @param h the SDhandle
 * @param amount the value for which the deviation is returned
 * @return the deviation from the average; GNUNET_SYSERR if the deviation cannot
 *           be calculated; a maximum of 4 is returned for deviations equal to
 *           or larger than 4
 */
int
SD_deviation_factor (struct SDHandle *h, unsigned int amount)
{
  double diff;
  unsigned int n;

  if (h->cnt < 2)
    return GNUNET_SYSERR;
  if (((float) amount) > h->avg)
    diff = ((float) amount) - h->avg;
  else
    diff = h->avg - ((float) amount);
  diff *= diff;
  for (n = 1; n < 4; n++)
    if (diff < (((double) (n * n)) * h->vr))
      break;
  return n;
}


int
main ()
{
  struct SDHandle * h = SD_init (20);
  
  SD_add_data (h, 40);
  SD_add_data (h, 30);
  SD_add_data (h, 40);
  SD_add_data (h, 10);
  SD_add_data (h, 30);
  printf ("Average: %f\n", h->avg);
  printf ("Variance: %f\n", h->vr);
  printf ("Standard Deviation: %f\n", sqrt (h->vr));
  printf ("Deviation factor: %d\n", SD_deviation_factor (h, 60));
  SD_destroy (h);
  return 0;
}
