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

#include <gnunet/platform.h>
#include <gnunet/gnunet_common.h>

struct SDHandle
{
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
  unsigned int avg;

  /**
   * The variance
   */
  unsigned int vr;

  /**
   * Number of data values
   */
  unsigned int cnt;
};


struct SDHandle *
GNUNET_TESTBED_SD_init ()
{
  return GNUNET_malloc (sizeof (struct SDHandle));
}

void
GNUNET_TESTBED_SD_destroy (struct SDHandle *h)
{
  GNUNET_free (h);
}

void
GNUNET_TESTBED_SD_add_data (struct SDHandle *h, unsigned int amount)
{
  unsigned long sqavg;

  h->sum += amount;
  h->cnt++;
  h->sqsum += ((unsigned long) amount) * ((unsigned long) amount);
  h->avg = h->sum / h->cnt;
  sqavg = h->avg * h->avg;
  h->vr = (h->sqsum / h->cnt) - sqavg;
}


/**
 * Returns the factor by which the given amount differs from the standard deviation
 *
 * @param h the SDhandle
 * @param amount the value for which the deviation is returned
 * @return the deviation from the average; GNUNET_SYSERR if the deviation cannot
 *           be calculated
 */
int
GNUNET_TESTBED_SD_deviation_factor (struct SDHandle *h, unsigned int amount)
{
  unsigned long diff;
  unsigned int n;

  if (h->cnt < 2)
    return GNUNET_SYSERR;
  if (amount > h->avg)
    diff = amount - h->avg;
  else
    diff = h->avg - amount;
  diff *= diff;
  for (n = 1; n < 4; n++)
    if (diff < (n * n * h->vr))
      break;
  return n;
}


int
main ()
{
  struct SDHandle * h = GNUNET_TESTBED_SD_init ();
  
  GNUNET_TESTBED_SD_add_data (h, 40);
  GNUNET_TESTBED_SD_add_data (h, 30);
  GNUNET_TESTBED_SD_add_data (h, 40);
  GNUNET_TESTBED_SD_add_data (h, 10);
  GNUNET_TESTBED_SD_add_data (h, 30);
  printf ("Average: %d\n", h->avg);
  printf ("Variance: %d\n", h->vr);
  printf ("Standard Deviation: %d\n", (int) sqrt (h->vr));
  printf ("Deviation factor: %d\n", GNUNET_TESTBED_SD_deviation (h, 40));
  GNUNET_TESTBED_SD_destroy (h);
  return 0;
}
