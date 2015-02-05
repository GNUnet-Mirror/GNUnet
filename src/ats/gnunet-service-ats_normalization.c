/*
 This file is part of GNUnet.
 (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * FIXME: rename to 'properties'!?
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet-service-ats_plugins.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-normalization",__VA_ARGS__)


/**
 * Quality Normalization
 */
struct Property
{
  /**
   * Index into the properties array.
   */
  uint32_t prop_type;

  /**
   * Corresponding enum value.  FIXME: type?
   */
  uint32_t atsi_type;

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
 * Range information for all properties we see.
 */
static struct Property properties[GNUNET_ATS_QualityPropertiesCount];


/**
 * Get the normalized properties values for a specific peer or
 * the default values if no normalized values are available.
 *
 * @param cls ignored
 * @param address the address
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind,
 * default preferences if peer does not exist
 */
const double *
GAS_normalization_get_properties (void *cls,
				  const struct ATS_Address *address)
{
  static double norm_values[GNUNET_ATS_QualityPropertiesCount];
  unsigned int i;

  for (i = 0; i < GNUNET_ATS_QualityPropertiesCount; i++)
  {
    if ((address->atsin[i].norm >= 1.0) && (address->atsin[i].norm <= 2.0))
      norm_values[i] = address->atsin[i].norm;
    else
      norm_values[i] = DEFAULT_REL_QUALITY;
  }
  return norm_values;
}


/**
 * Normalize a specific ATS type with the values in queue.
 *
 * @param address the address
 * @param atsi the ats information
 * @return the new average or GNUNET_ATS_VALUE_UNDEFINED
 */
static uint32_t
property_average (struct ATS_Address *address,
                  const struct GNUNET_ATS_Information *atsi)
{
  struct GAS_NormalizationInfo *ni;
  uint32_t current_type;
  uint32_t current_val;
  uint32_t res;
  uint64_t sum;
  uint32_t count;
  unsigned int c1;
  unsigned int index;
  unsigned int props[] = GNUNET_ATS_QualityProperties;

  /* Average the values of this property */
  current_type = ntohl (atsi->type);
  current_val = ntohl (atsi->value);

  for (c1 = 0; c1 < GNUNET_ATS_QualityPropertiesCount; c1++)
  {
    if (current_type == props[c1])
      break;
  }
  if (c1 == GNUNET_ATS_QualityPropertiesCount)
  {
    GNUNET_break(0);
    return GNUNET_ATS_VALUE_UNDEFINED;
  }
  index = c1;

  ni = &address->atsin[index];
  ni->atsi_abs[ni->avg_queue_index] = current_val;
  ni->avg_queue_index++;
  if (GAS_normalization_queue_length == ni->avg_queue_index)
    ni->avg_queue_index = 0;

  count = 0;
  sum = 0;
  for (c1 = 0; c1 < GAS_normalization_queue_length; c1++)
  {
    if (GNUNET_ATS_VALUE_UNDEFINED != ni->atsi_abs[c1])
    {
      count++;
      if (GNUNET_ATS_VALUE_UNDEFINED > (sum + ni->atsi_abs[c1]))
        sum += ni->atsi_abs[c1];
      else
      {
        sum = GNUNET_ATS_VALUE_UNDEFINED - 1;
        GNUNET_break(0);
      }
    }
  }
  GNUNET_assert(0 != count);
  res = sum / count;
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "New average of `%s' created by adding %u from %u elements: %u\n",
      GNUNET_ATS_print_property_type (current_type),
      current_val,
      count,
      res,
      sum);
  ni->avg = res;
  return res;
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
 * Function called on X to find the minimum and maximum
 * values for a given property.
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
 * @param h which peer are we looking at (ignored)
 * @param k the address for that peer, from where we get
 *            the original value and where we write the
 *            normalized value
 * @return #GNUNET_OK (continue to iterate)
 */
static int
normalize_address (void *cls,
		   const struct GNUNET_PeerIdentity *h,
		   void *k)
{
  struct Property *p = cls;
  struct ATS_Address *address = k;
  double delta;
  double backup;
  uint32_t avg_value;

  backup = address->atsin[p->prop_type].norm;
  avg_value = address->atsin[p->prop_type].avg;
  delta = p->max - p->min;
  /* max - 2 * min + avg_value / max - min */
  if (0 != delta)
    address->atsin[p->prop_type].norm = (delta + (avg_value - p->min)) / (delta);
  else
    address->atsin[p->prop_type].norm = DEFAULT_REL_QUALITY;

  if (backup == address->atsin[p->prop_type].norm)
    return GNUNET_OK;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Normalize `%s' address %p's '%s' with value %u to range [%u..%u] = %.3f\n",
       GNUNET_i2s (&address->peer), address,
       GNUNET_ATS_print_property_type (p->atsi_type),
       address->atsin[p->prop_type].avg, p->min, p->max,
       address->atsin[p->prop_type].norm);
  GAS_normalized_property_changed (address,
				   p->atsi_type,
				   address->atsin[p->prop_type].norm);
  return GNUNET_OK;
}


/**
 * Normalize @a avg_value to a range of values between [1.0, 2.0]
 * based on min/max values currently known.
 *
 * @param p the property
 * @param address the address
 * @param avg_value the value to normalize
 */
static void
property_normalize (struct Property *p,
		    struct ATS_Address *address,
		    uint32_t avg_value)
{
  struct FindMinMaxCtx find_ctx;
  int addr_count;
  int limits_changed;

  find_ctx.p = p;
  find_ctx.max = 0;
  find_ctx.min = UINT32_MAX;
  addr_count = GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
						      &find_min_max_it,
						      &find_ctx);
  if (0 == addr_count)
  {
    GNUNET_break(0);
    return;
  }

  limits_changed = GNUNET_NO;
  if (find_ctx.max != p->max)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Normalizing %s: new maximum %u -> recalculate all values\n",
	 GNUNET_ATS_print_property_type (p->atsi_type),
	 find_ctx.max);
    p->max = find_ctx.max;
    limits_changed = GNUNET_YES;
  }

  if ((find_ctx.min != p->min) && (find_ctx.min < p->max))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Normalizing %s: new minimum %u -> recalculate all values\n",
	 GNUNET_ATS_print_property_type (p->atsi_type),
	 find_ctx.min,
	 find_ctx.max);
    p->min = find_ctx.min;
    limits_changed = GNUNET_YES;
  }
  else if (find_ctx.min == p->max)
  {
    /* Only one value, so minimum has to be 0 */
    p->min = 0;
  }

  /* Normalize the values of this property */
  if (GNUNET_NO == limits_changed)
  {
    /* normalize just this  address */
    normalize_address (p,
                       &address->peer,
                       address);
  }
  else
  {
    /* limits changed, normalize all addresses */
    GNUNET_CONTAINER_multipeermap_iterate (GSA_addresses,
					   &normalize_address,
					   p);
  }
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
  struct Property *cur_prop;
  int c1;
  int c2;
  uint32_t current_type;
  uint32_t current_val;
  unsigned int existing_properties[] = GNUNET_ATS_QualityProperties;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating %u elements for peer `%s'\n",
       atsi_count,
       GNUNET_i2s (&address->peer));

  for (c1 = 0; c1 < atsi_count; c1++)
  {
    current_type = ntohl (atsi[c1].type);

    for (c2 = 0; c2 < GNUNET_ATS_QualityPropertiesCount; c2++)
    {
      /* Check if type is valid */
      if (current_type == existing_properties[c2])
        break;
    }
    if (GNUNET_ATS_QualityPropertiesCount == c2)
    {
      /* Invalid property, continue with next element */
      continue;
    }
    /* Averaging */
    current_val = property_average (address, &atsi[c1]);
    if (GNUNET_ATS_VALUE_UNDEFINED == current_val)
    {
      GNUNET_break(0);
      continue;
    }

    /* Normalizing */
    /* Check min, max */
    cur_prop = &properties[c2];
    property_normalize (cur_prop,
                        address,
                        current_val);
  }
}


/**
 * Start the normalization component
 */
void
GAS_normalization_start ()
{
  unsigned int c1;
  unsigned int existing_properties[] = GNUNET_ATS_QualityProperties;

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
