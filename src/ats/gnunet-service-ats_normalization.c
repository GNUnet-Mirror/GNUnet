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
 *
 * FIXME: rename to 'properties'!? merge with addresses!?
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
struct Property
{
  /**
   * Index into the properties array.
   */
  uint32_t prop_type;

  /**
   * Corresponding enum value of the respective quality property.
   */
  enum GNUNET_ATS_Property atsi_type;

  /**
   * Minimum value we see for this property across all addresses.
   */
  uint32_t min;

  /**
   * Maximum value we see for this property across all addresses.
   */
  uint32_t max;
};


/**
 * Range information for all quality properties we see.
 */
static struct Property properties[GNUNET_ATS_QualityPropertiesCount];



/**
 * Add the value from @a atsi to the running average of the
 * given @a ni quality property.
 *
 * @param ni normalization information to update
 * @param atsi the ats information
 */
static void
property_average (struct GAS_NormalizationInfo *ni,
                  const struct GNUNET_ATS_Information *atsi)
{
  uint32_t current_val;
  uint32_t res;
  uint64_t sum;
  uint32_t count;
  unsigned int c1;

  current_val = ntohl (atsi->value);
  GNUNET_assert (GNUNET_ATS_VALUE_UNDEFINED != current_val);
  ni->atsi_abs[ni->avg_queue_index++] = current_val;
  if (GAS_normalization_queue_length == ni->avg_queue_index)
    ni->avg_queue_index = 0;
  count = 0;
  sum = 0;
  for (c1 = 0; c1 < GAS_normalization_queue_length; c1++)
  {
    if (GNUNET_ATS_VALUE_UNDEFINED != ni->atsi_abs[c1])
    {
      count++;
      sum += ni->atsi_abs[c1];
    }
  }
  GNUNET_assert (0 != count);
  res = sum / count;
  ni->avg = res;
}


/**
 * Closure for #find_min_max_it().
 */
struct FindMinMaxCtx
{
  /**
   * Property we are looking for.
   */
  struct Property *p;

  /**
   * Set to mimimum value observed.
   */
  uint32_t min;

  /**
   * Set to maximum value observed.
   */
  uint32_t max;
};


/**
 * Function called for all addresses and peers to find the minimum and
 * maximum (averaged) values for a given quality property.  Given
 * those, we can then calculate the normalized score.
 *
 * @param cls the `struct FindMinMaxCtx`
 * @param h which peer are we looking at (ignored)
 * @param k the address for that peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
find_min_max_it (void *cls,
                 const struct GNUNET_PeerIdentity *h,
                 void *k)
{
  struct FindMinMaxCtx *find_res = cls;
  const struct ATS_Address *a = k;

  find_res->max = GNUNET_MAX (find_res->max,
                              a->atsin[find_res->p->prop_type].avg);
  find_res->min = GNUNET_MIN (find_res->min,
                              a->atsin[find_res->p->prop_type].avg);
  return GNUNET_OK;
}


/**
 * Normalize the property value for a given address based
 * on the range we know that property value has globally.
 *
 * @param cls the `struct Property` with details on the
 *            property and its global range
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
  struct Property *p = cls;
  struct ATS_Address *address = value;
  double delta;
  double update;
  uint32_t avg_value;

  avg_value = address->atsin[p->prop_type].avg;
  delta = p->max - p->min;
  /* max - 2 * min + avg_value / (max - min) */
  if (delta > DBL_EPSILON)
    update = DEFAULT_REL_QUALITY + (avg_value - p->min) / delta;
  else
    update = DEFAULT_REL_QUALITY;

  if (update == address->atsin[p->prop_type].norm)
    return GNUNET_OK;
  address->atsin[p->prop_type].norm = update;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Normalize `%s' address %p's '%s' with value %u to range [%u..%u] = %.3f\n",
       GNUNET_i2s (&address->peer),
       address,
       GNUNET_ATS_print_property_type (p->atsi_type),
       address->atsin[p->prop_type].avg,
       p->min,
       p->max,
       address->atsin[p->prop_type].norm);
  return GNUNET_OK;
}


/**
 * Notify about change in normalized property.
 *
 * @param cls the `struct Property` with details on the
 *            property and its global range
 * @param key which peer are we looking at (ignored)
 * @param value the address for that peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_change (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct Property *p = cls;
  struct ATS_Address *address = value;

  GAS_normalized_property_changed (address,
				   p->atsi_type,
				   address->atsin[p->prop_type].norm);
  return GNUNET_OK;
}


/**
 * Update and normalize atsi performance information
 *
 * @param address the address to update
 * @param atsi the array of performance information
 * @param atsi_count the number of atsi information in the array
 */
void
GAS_normalization_normalize_property (struct ATS_Address *address,
                                      const struct GNUNET_ATS_Information *atsi,
                                      uint32_t atsi_count)
{
  unsigned int c1;
  unsigned int c2;
  uint32_t current_type;
  uint32_t old;
  struct FindMinMaxCtx find_ctx;
  int range_changed;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating %u elements for peer `%s'\n",
       atsi_count,
       GNUNET_i2s (&address->peer));
  GAS_plugin_solver_lock ();
  for (c1 = 0; c1 < atsi_count; c1++)
  {
    current_type = ntohl (atsi[c1].type);

    for (c2 = 0; c2 < GNUNET_ATS_QualityPropertiesCount; c2++)
      if (current_type == properties[c2].atsi_type)
        break;
    if (GNUNET_ATS_QualityPropertiesCount == c2)
    {
      /* Not a quality property, continue with next element */
      continue;
    }
    /* Calculate running average */
    old = address->atsin[c2].avg;
    property_average (&address->atsin[c2],
                      &atsi[c1]);
    if (old == address->atsin[c2].avg)
      continue; /* no change */
    range_changed = GNUNET_NO;
    if ( (old == properties[c2].min) ||
         (old == properties[c2].max) ||
         (address->atsin[c2].avg < properties[c2].min) ||
         (address->atsin[c2].avg > properties[c2].max) )
    {
      /* need to re-calculate min/max range, as it may have changed */
      find_ctx.p = &properties[c2];
      find_ctx.max = 0;
      find_ctx.min = UINT32_MAX;
      if (0 ==
          GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                                 &find_min_max_it,
                                                 &find_ctx))
      {
        GNUNET_break(0);
        continue;
      }
      if ( (find_ctx.min != properties[c2].min) ||
           (find_ctx.max != properties[c2].max) )
      {
        properties[c2].min = find_ctx.min;
        properties[c2].max = find_ctx.max;
        /* limits changed, (re)normalize all addresses */
        range_changed = GNUNET_YES;
      }
    }
    if (GNUNET_YES == range_changed)
      GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                             &normalize_address,
                                             &properties[c2]);
    else
      normalize_address (&properties[c2],
                         &address->peer,
                         address);
    /* after all peers have been updated, notify about changes */
    if (GNUNET_YES == range_changed)
      GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
                                             &notify_change,
                                             &properties[c2]);
    else
      notify_change (&properties[c2],
                     &address->peer,
                     address);

  }
  GAS_plugin_solver_unlock ();
}


/**
 * Start the normalization component
 */
void
GAS_normalization_start ()
{
  unsigned int c1;
  const unsigned int existing_properties[] = GNUNET_ATS_QualityProperties;

  for (c1 = 0; c1 < GNUNET_ATS_QualityPropertiesCount; c1++)
  {
    properties[c1].prop_type = c1;
    properties[c1].atsi_type = existing_properties[c1];
    properties[c1].min = UINT32_MAX;
    properties[c1].max = 0;
  }
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
