/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/load.c
 * @brief functions related to load calculations
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_load_lib.h"

#define DEBUG_LOAD GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Values we track for load calculations.
 */
struct GNUNET_LOAD_Value
{

  /**
   * How fast should the load decline if no values are added?
   */
  struct GNUNET_TIME_Relative autodecline;

  /**
   * Last time this load value was updated by an event.
   */
  struct GNUNET_TIME_Absolute last_update;

  /**
   * Sum of all datastore delays ever observed (in ms).  Note that
   * delays above 64k ms are excluded (to avoid overflow within
   * first 4 billion requests).
   */
  uint64_t cummulative_delay;

  /**
   * Sum of squares of all datastore delays ever observed (in ms).   Note that
   * delays above 64k ms are excluded (to avoid overflow within
   * first 4 billion requests).
   */
  uint64_t cummulative_squared_delay;

  /**
   * Total number of requests included in the cummulative datastore delay values.
   */
  uint64_t cummulative_request_count;

  /**
   * Current running average datastore delay.  Its relation to the
   * average datastore delay and it std. dev. (as calcualted from the
   * cummulative values) tells us our current load.
   */
  double runavg_delay;

  /**
   * How high is the load?  0 for below average, otherwise
   * the number of std. devs we are above average, or 100 if the
   * load is so high that we currently cannot calculate it.
   */
  double load;

};


static void
internal_update (struct GNUNET_LOAD_Value *load)
{
  struct GNUNET_TIME_Relative delta;
  unsigned int n;

  if (load->autodecline.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
    return;
  delta = GNUNET_TIME_absolute_get_duration (load->last_update);
  if (delta.rel_value < load->autodecline.rel_value)
    return;
  if (load->autodecline.rel_value == 0)
  {
    load->runavg_delay = 0.0;
    load->load = 0;
    return;
  }
  n = delta.rel_value / load->autodecline.rel_value;
  if (n > 16)
  {
    load->runavg_delay = 0.0;
    load->load = 0;
    return;
  }
  while (n > 0)
  {
    n--;
    load->runavg_delay = (load->runavg_delay * 7.0) / 8.0;
  }
}


/**
 * Create a new load value.
 *
 * @param autodecline speed at which this value should automatically
 *        decline in the absence of external events; at the given
 *        frequency, 0-load values will be added to the load
 * @return the new load value
 */
struct GNUNET_LOAD_Value *
GNUNET_LOAD_value_init (struct GNUNET_TIME_Relative autodecline)
{
  struct GNUNET_LOAD_Value *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_LOAD_Value));
  ret->autodecline = autodecline;
  ret->last_update = GNUNET_TIME_absolute_get ();
  return ret;
}


/**
 * Change the value by which the load automatically declines.
 *
 * @param load load to update
 * @param autodecline frequency of load decline
 */
void
GNUNET_LOAD_value_set_decline (struct GNUNET_LOAD_Value *load,
                               struct GNUNET_TIME_Relative autodecline)
{
  internal_update (load);
  load->autodecline = autodecline;
}


/**
 * Recalculate our load value.
 *
 * @param load load to update
 */
static void
calculate_load (struct GNUNET_LOAD_Value *load)
{
  double stddev;
  double avgdel;
  double sum_val_i;
  double n;
  double nm1;

  if (load->cummulative_request_count <= 1)
    return;
  /* calcuate std dev of latency; we have for n values of "i" that:
   *
   * avg = (sum val_i) / n
   * stddev = (sum (val_i - avg)^2) / (n-1)
   * = (sum (val_i^2 - 2 avg val_i + avg^2) / (n-1)
   * = (sum (val_i^2) - 2 avg sum (val_i) + n * avg^2) / (n-1)
   */
  sum_val_i = (double) load->cummulative_delay;
  n = ((double) load->cummulative_request_count);
  nm1 = n - 1.0;
  avgdel = sum_val_i / n;
  stddev =
      (((double) load->cummulative_squared_delay) - 2.0 * avgdel * sum_val_i +
       n * avgdel * avgdel) / nm1;
  if (stddev <= 0)
    stddev = 0.01;              /* must have been rounding error or zero; prevent division by zero */
  /* now calculate load based on how far out we are from
   * std dev; or if we are below average, simply assume load zero */
  if (load->runavg_delay < avgdel)
    load->load = 0.0;
  else
    load->load = (load->runavg_delay - avgdel) / stddev;
}


/**
 * Get the current load.
 *
 * @param load load handle
 * @return zero for below-average load, otherwise
 *         number of std. devs we are above average;
 *         100 if the latest updates were so large
 *         that we could not do proper calculations
 */
double
GNUNET_LOAD_get_load (struct GNUNET_LOAD_Value *load)
{
  internal_update (load);
  calculate_load (load);
  return load->load;
}


/**
 * Get the average value given to update so far.
 *
 * @param load load handle
 * @return zero if update was never called
 */
double
GNUNET_LOAD_get_average (struct GNUNET_LOAD_Value *load)
{
  double n;
  double sum_val_i;

  internal_update (load);
  if (load->cummulative_request_count == 0)
    return 0.0;
  n = ((double) load->cummulative_request_count);
  sum_val_i = (double) load->cummulative_delay;
  return sum_val_i / n;
}


/**
 * Update the current load.
 *
 * @param load to update
 * @param data latest measurement value (for example, delay)
 */
void
GNUNET_LOAD_update (struct GNUNET_LOAD_Value *load, uint64_t data)
{
  uint32_t dv;

  internal_update (load);
  load->last_update = GNUNET_TIME_absolute_get ();
  if (data > 64 * 1024)
  {
    /* very large */
    load->load = 100.0;
    return;
  }
  dv = (uint32_t) data;
  load->cummulative_delay += dv;
  load->cummulative_squared_delay += dv * dv;
  load->cummulative_request_count++;
  load->runavg_delay = ((load->runavg_delay * 7.0) + dv) / 8.0;
}



/* end of load.c */
