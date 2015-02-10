/*
 This file is part of GNUnet.
 Copyright (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_normalization.c
 * @brief ats service address: management of ATS properties and preferences normalization
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include <float.h>
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_plugins.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-normalization",__VA_ARGS__)


/**
 * Range information for normalization of quality properties.
 */
struct PropertyRange
{
  /**
   * Minimum value we see for this property across all addresses.
   */
  struct GNUNET_ATS_Properties min;

  /**
   * Maximum value we see for this property across all addresses.
   */
  struct GNUNET_ATS_Properties max;
};


/**
 * Range information for all quality properties we see.
 */
static struct PropertyRange property_range;


/**
 * Add the value from @a atsi to the running average of the
 * given @a ni quality property.
 *
 * @param current_val the updated value
 * @param ni normalization information to update
 */
static void
update_avg (uint64_t current_val,
            struct GAS_NormalizationInfo *ni)
{
  double sum;
  uint32_t count;
  unsigned int c1;

  ni->atsi_abs[ni->avg_queue_index++] = current_val;
  if (GAS_normalization_queue_length == ni->avg_queue_index)
    ni->avg_queue_index = 0;
  count = 0;
  sum = 0.0;
  for (c1 = 0; c1 < GAS_normalization_queue_length; c1++)
  {
    if (UINT64_MAX != ni->atsi_abs[c1])
    {
      count++;
      sum += (double) ni->atsi_abs[c1];
    }
  }
  GNUNET_assert (0 != count);
  ni->avg = sum / count;
}


/**
 * Function called for all addresses and peers to find the minimum and
 * maximum (averaged) values for a given quality property.  Given
 * those, we can then calculate the normalized score.
 *
 * @param cls the `struct PropertyRange`
 * @param h which peer are we looking at (ignored)
 * @param k the address for that peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
find_min_max_it (void *cls,
                 const struct GNUNET_PeerIdentity *h,
                 void *k)
{
  struct PropertyRange *pr = cls;
  const struct ATS_Address *a = k;

  pr->max.utilization_out = GNUNET_MAX (pr->max.utilization_out,
                                        a->properties.utilization_out);
  pr->max.utilization_in = GNUNET_MAX (pr->max.utilization_in,
                                       a->properties.utilization_in);
  pr->max.distance = GNUNET_MAX (pr->max.distance,
                                 a->properties.distance);
  pr->max.delay = GNUNET_TIME_relative_max (pr->max.delay,
                                            a->properties.delay);
  pr->min.utilization_out = GNUNET_MIN (pr->min.utilization_out,
                                        a->properties.utilization_out);
  pr->min.utilization_in = GNUNET_MIN (pr->min.utilization_in,
                                       a->properties.utilization_in);
  pr->min.distance = GNUNET_MIN (pr->min.distance,
                                 a->properties.distance);
  pr->min.delay = GNUNET_TIME_relative_min (pr->min.delay,
                                            a->properties.delay);
  return GNUNET_OK;
}


/**
 * Compute the normalized value from the given @a ni range
 * data and the average value.
 *
 * @param min minimum value
 * @param max maximum value
 * @param ni normalization information to update
 */
static void
update_norm (uint64_t min,
             uint64_t max,
             struct GAS_NormalizationInfo *ni)
{
  /* max - 2 * min + avg_value / (max - min) */
  if (min < max)
    ni->norm = DEFAULT_REL_QUALITY + (ni->avg - min) / (double) (max - min);
  else
    ni->norm = DEFAULT_REL_QUALITY;
}


/**
 * Normalize the property value for a given address based
 * on the range we know that property values have globally.
 *
 * @param cls NULL
 * @param key which peer are we looking at (ignored)
 * @param value the address for that peer, from where we get
 *            the original value and where we write the
 *            normalized value
 * @return #GNUNET_OK (continue to iterate)
 */
static int
normalize_address (void *cls,
		   const struct GNUNET_PeerIdentity *key,
		   void *value)
{
  struct ATS_Address *address = value;

  update_norm (property_range.min.delay.rel_value_us,
               property_range.max.delay.rel_value_us,
               &address->norm_delay);
  update_norm (property_range.min.distance,
               property_range.max.distance,
               &address->norm_distance);
  update_norm (property_range.min.utilization_in,
               property_range.max.utilization_in,
               &address->norm_utilization_in);
  update_norm (property_range.min.utilization_out,
               property_range.max.utilization_out,
               &address->norm_utilization_out);
  return GNUNET_OK;
}


/**
 * Notify about change in normalized property.
 *
 * @param cls NULL
 * @param key which peer are we looking at (ignored)
 * @param value the address for that peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_change (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct ATS_Address *address = value;

  GAS_plugin_notify_property_changed (address);
  return GNUNET_OK;
}


/**
 * Initialize property range to the values corresponding
 * to an empty set.
 *
 * @param pr range to initialize
 */
static void
init_range (struct PropertyRange *pr)
{
  memset (pr, 0, sizeof (struct PropertyRange));
  pr->min.utilization_out = UINT32_MAX;
  pr->min.utilization_in = UINT32_MAX;
  pr->min.distance = UINT32_MAX;
  pr->min.delay = GNUNET_TIME_UNIT_FOREVER_REL;
}


/**
 * Update and normalize atsi performance information
 *
 * @param address the address to update
 */
void
GAS_normalization_update_property (struct ATS_Address *address)
{
  const struct GNUNET_ATS_Properties *prop = &address->properties;
  struct PropertyRange range;
  int range_changed;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating properties for peer `%s'\n",
       GNUNET_i2s (&address->peer));
  GAS_plugin_solver_lock ();
  update_avg (prop->delay.rel_value_us,
              &address->norm_delay);
  update_avg (prop->distance,
              &address->norm_distance);
  update_avg (prop->utilization_in,
              &address->norm_utilization_in);
  update_avg (prop->utilization_in,
              &address->norm_utilization_out);

  init_range (&range);
  GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                         &find_min_max_it,
                                         &range);
  if (0 != memcmp (&range,
                   &property_range,
                   sizeof (struct PropertyRange)))
  {
    /* limits changed, (re)normalize all addresses */
    property_range = range;
    range_changed = GNUNET_YES;
  }
  if (GNUNET_YES == range_changed)
    GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                           &normalize_address,
                                           NULL);
  else
    normalize_address (NULL,
                       &address->peer,
                       address);
  /* after all peers have been updated, notify about changes */
  if (GNUNET_YES == range_changed)
    GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                           &notify_change,
                                           NULL);
  else
    notify_change (NULL,
                   &address->peer,
                   address);
  GAS_plugin_solver_unlock ();
}


/**
 * Start the normalization component
 */
void
GAS_normalization_start ()
{
  init_range (&property_range);
}


/**
 * Stop the normalization component and free all items
 */
void
GAS_normalization_stop ()
{
  /* nothing to do */
}


/* end of gnunet-service-ats_normalization.c */
