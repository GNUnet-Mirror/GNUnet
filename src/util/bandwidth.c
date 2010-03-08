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
 * @file util/bandwidth.c
 * @brief functions related to bandwidth (unit) 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_bandwidth_lib.h"
#include "gnunet_server_lib.h"

/**
 * Create a new bandwidth value.
 *
 * @param bytes_per_second value to create
 * @return the new bandwidth value
 */
struct GNUNET_BANDWIDTH_Value32NBO
GNUNET_BANDWIDTH_value_init (uint32_t bytes_per_second)
{
  struct GNUNET_BANDWIDTH_Value32NBO ret;

  ret.value__ = htonl (bytes_per_second);
  return ret;
}


/**
 * Compute the MIN of two bandwidth values.
 *
 * @param b1 first value
 * @param b2 second value
 * @return the min of b1 and b2
 */
struct GNUNET_BANDWIDTH_Value32NBO
GNUNET_BANDWIDTH_value_min (struct GNUNET_BANDWIDTH_Value32NBO b1,
			    struct GNUNET_BANDWIDTH_Value32NBO b2)
{
  return GNUNET_BANDWIDTH_value_init (GNUNET_MIN (ntohl (b1.value__),
						  ntohl (b2.value__)));
}


/**
 * At the given bandwidth, calculate how much traffic will be
 * available until the given deadline.
 *
 * @param bps bandwidth
 * @param deadline when is the deadline
 * @return number of bytes available at bps until deadline
 */
uint64_t 
GNUNET_BANDWIDTH_value_get_available_until (struct GNUNET_BANDWIDTH_Value32NBO bps,
					    struct GNUNET_TIME_Relative deadline)
{
  uint64_t b;

  b = ntohl (bps.value__);
  return b * deadline.value / 1000LL;
}


/**
 * At the given bandwidth, calculate how long it would take for
 * 'size' bytes to be transmitted.
 *
 * @param bps bandwidth
 * @param size number of bytes we want to have available
 * @return how long it would take
 */
struct GNUNET_TIME_Relative
GNUNET_BANDWIDTH_value_get_delay_for (struct GNUNET_BANDWIDTH_Value32NBO bps,
				      uint64_t size)
{
  uint64_t b;
  struct GNUNET_TIME_Relative ret;

  b = ntohl (bps.value__);
  if (b == 0)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.value = size * 1000LL / b;
  return ret;
}


/**
 * Initialize bandwidth tracker.  Note that in addition to the
 * 'max_carry_s' limit, we also always allow at least
 * GNUNET_SERVER_MAX_MESSAGE_SIZE to accumulate.  So if the
 * bytes-per-second limit is so small that within 'max_carry_s' not
 * even GNUNET_SERVER_MAX_MESSAGE_SIZE is allowed to accumulate, it is
 * ignored and replaced by GNUNET_SERVER_MAX_MESSAGE_SIZE (which is in
 * bytes).
 *
 * @param av tracker to initialize
 * @param bytes_per_second_limit initial limit to assume
 * @param max_carry_s maximum number of seconds unused bandwidth
 *        may accumulate before it expires
 */
void
GNUNET_BANDWIDTH_tracker_init (struct GNUNET_BANDWIDTH_Tracker *av,
			       struct GNUNET_BANDWIDTH_Value32NBO bytes_per_second_limit,
			       uint32_t max_carry_s)
{
  av->consumption_since_last_update__ = 0;
  av->last_update__ = GNUNET_TIME_absolute_get ();
  av->available_bytes_per_s__ = ntohl (bytes_per_second_limit.value__);
  av->max_carry_s__ = max_carry_s;
}


/**
 * Update the tracker, looking at the current time and
 * bandwidth consumption data.
 *
 * @param av tracker to update
 */
static void
update_tracker (struct GNUNET_BANDWIDTH_Tracker *av)
{
  struct GNUNET_TIME_Absolute now;
  uint64_t avail_per_ms;
  uint64_t delta_time;
  uint64_t delta_avail;
  uint64_t left_bytes;
  uint64_t left_time_ms;

  now = GNUNET_TIME_absolute_get ();
  delta_time = now.value - av->last_update__.value;
  delta_avail = (delta_time * ((unsigned long long) av->available_bytes_per_s__)) / 1000LL;
  if (av->consumption_since_last_update__ >= delta_avail)
    {
      av->consumption_since_last_update__ -= delta_avail;
      av->last_update__ = now;
    }
  else
    {
      left_bytes = delta_avail - av->consumption_since_last_update__;
      avail_per_ms = ((unsigned long long) av->available_bytes_per_s__) / 1000LL;
      if (avail_per_ms > 0)
	{
	  left_time_ms = left_bytes / avail_per_ms;	  
	  if (left_time_ms > ((unsigned long long) av->max_carry_s__) * 1000LL)
	    {
	      /* need to limit accumulation of unused bandwidth */
	      left_time_ms = ((unsigned long long) av->max_carry_s__) * 1000LL;
	      if (left_time_ms * avail_per_ms < GNUNET_SERVER_MAX_MESSAGE_SIZE)
		{
		  /* need to still allow GNUNET_SERVER_MAX_MESSAGE_SIZE accumulation */
		  if (left_bytes > GNUNET_SERVER_MAX_MESSAGE_SIZE)
		    left_bytes = GNUNET_SERVER_MAX_MESSAGE_SIZE;
		  left_time_ms = left_bytes / avail_per_ms;
		}
	    }
	}
      else
        {
           left_time_ms = 0;
	}
      av->consumption_since_last_update__ = 0;
      av->last_update__.value = now.value - left_time_ms;
    }
}


/**
 * Notify the tracker that a certain number of bytes of bandwidth have
 * been consumed.  Note that it is legal to consume bytes even if not
 * enough bandwidth is available (in that case,
 * GNUNET_BANDWIDTH_tracker_get_delay may return non-zero delay values
 * even for a size of zero for a while).
 *
 * @param av tracker to update
 * @param size number of bytes consumed
 * @return GNUNET_YES if this consumption is above the limit
 */
int
GNUNET_BANDWIDTH_tracker_consume (struct GNUNET_BANDWIDTH_Tracker *av,
				  ssize_t size)
{
  uint64_t nc;

  if (size > 0)
    {
      nc = av->consumption_since_last_update__ + size;
      if (nc < av->consumption_since_last_update__) 
	{
	  GNUNET_break (0);
	  return GNUNET_SYSERR;
	}
      av->consumption_since_last_update__ = nc;
      update_tracker (av);
      if (av->consumption_since_last_update__ > 0)
	return GNUNET_YES;
    }
  else
    {
      av->last_update__.value -= (size * av->available_bytes_per_s__) / 1000LL;
      update_tracker (av);
    }
  return GNUNET_NO;
}


/**
 * Compute how long we should wait until consuming 'size'
 * bytes of bandwidth in order to stay within the given
 * quota.
 *
 * @param av tracker to query
 * @param size number of bytes we would like to consume
 * @return time to wait for consumption to be OK
 */
struct GNUNET_TIME_Relative
GNUNET_BANDWIDTH_tracker_get_delay (struct GNUNET_BANDWIDTH_Tracker *av,
				    size_t size)
{
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_TIME_Absolute now;
  uint64_t delta_avail;
  uint64_t delta_time;
  uint64_t bytes_needed;

  if (av->available_bytes_per_s__ == 0)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  update_tracker (av);
  now = GNUNET_TIME_absolute_get ();
  delta_time = now.value - av->last_update__.value;
  delta_avail = (delta_time * ((unsigned long long) av->available_bytes_per_s__)) / 1000LL;
  if (delta_avail >= size)
    return GNUNET_TIME_UNIT_ZERO;
  bytes_needed = size - delta_avail;
  ret.value = 1000LL * bytes_needed / (unsigned long long) av->available_bytes_per_s__;
  return ret;
}


/**
 * Compute how many bytes are available for consumption right now.
 * quota.
 *
 * @param av tracker to query
 * @return number of bytes available for consumption right now
 */
int64_t 
GNUNET_BANDWIDTH_tracker_get_available (struct GNUNET_BANDWIDTH_Tracker *av)
{
  struct GNUNET_BANDWIDTH_Value32NBO bps;
  uint64_t avail;
  uint64_t used;

  update_tracker (av);
  bps = GNUNET_BANDWIDTH_value_init (av->available_bytes_per_s__);
  avail = GNUNET_BANDWIDTH_value_get_available_until (bps,
						      GNUNET_TIME_absolute_get_duration (av->last_update__));
  used = av->consumption_since_last_update__;
  return (int64_t) (avail - used);
}


/**
 * Update quota of bandwidth tracker.
 *
 * @param av tracker to initialize
 * @param bytes_per_second_limit new limit to assume
 */
void
GNUNET_BANDWIDTH_tracker_update_quota (struct GNUNET_BANDWIDTH_Tracker *av,
				       struct GNUNET_BANDWIDTH_Value32NBO bytes_per_second_limit)
{
  uint32_t old_limit;
  uint32_t new_limit;

  new_limit = ntohl (bytes_per_second_limit.value__);
  update_tracker (av);
  old_limit = av->available_bytes_per_s__;
  av->available_bytes_per_s__ = new_limit;
  if (old_limit > new_limit)
    update_tracker (av); /* maximum excess might be less now */
}


/* end of bandwidth.c */
