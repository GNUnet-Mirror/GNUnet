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

#define DEBUG_BANDWIDTH GNUNET_YES

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

#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Initializing bandwidth of %u bps\n",
	      (unsigned int) bytes_per_second);
#endif
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
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Bandwidth has %llu bytes available until deadline in %llums\n",
	      (unsigned long long) ((b * deadline.value + 500LL) / 1000LL),
	      deadline.value);
#endif
  return (b * deadline.value + 500LL) / 1000LL;
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
    {
#if DEBUG_BANDWIDTH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Bandwidth suggests delay of infinity (zero bandwidth)\n");
#endif
      return GNUNET_TIME_UNIT_FOREVER_REL;
    }
  ret.value = size * 1000LL / b;
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Bandwidth suggests delay of %llu ms for %llu bytes of traffic\n",
	      (unsigned long long) ret.value,
	      (unsigned long long) size);
#endif
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
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p initialized with %u bps and max carry %u\n",
	      av,
	      (unsigned int) av->available_bytes_per_s__,
	      (unsigned int) max_carry_s);
#endif
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
  uint64_t delta_time;
  uint64_t delta_avail;
  uint64_t left_bytes;
  uint64_t max_carry;

  now = GNUNET_TIME_absolute_get ();
  delta_time = now.value - av->last_update__.value;
  delta_avail = (delta_time * ((unsigned long long) av->available_bytes_per_s__) + 500LL) / 1000LL;
  av->consumption_since_last_update__ -= delta_avail;
  av->last_update__ = now;
  if (av->consumption_since_last_update__ < 0)
    {
      left_bytes = - av->consumption_since_last_update__;
      max_carry = av->available_bytes_per_s__ * av->max_carry_s__;
      if (max_carry > left_bytes)
	av->consumption_since_last_update__ = -max_carry;
    }
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p  updated, have %u bps last update was %llu ms ago\n",
	      av,
	      (unsigned int) av->available_bytes_per_s__,
	      (unsigned long long) (now.value - av->last_update__.value));
#endif
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

#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p consumes %d bytes\n",
	      av,
	      (int) size);
#endif
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
	{
#if DEBUG_BANDWIDTH
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Tracker %p consumption %llu bytes above limit\n",
		      av,
		      (unsigned long long) av->consumption_since_last_update__);
#endif
	  return GNUNET_YES;
	}
    }
  else
    {
      av->consumption_since_last_update__ += size;
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
    {
#if DEBUG_BANDWIDTH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Tracker %p delay is infinity\n",
		  av);
#endif
      return GNUNET_TIME_UNIT_FOREVER_REL;
    }
  update_tracker (av);
  now = GNUNET_TIME_absolute_get ();
  delta_time = now.value - av->last_update__.value;
  delta_avail = (delta_time * ((unsigned long long) av->available_bytes_per_s__) + 500LL) / 1000LL;
  if (delta_avail >= size)
    {
#if DEBUG_BANDWIDTH
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Tracker %p delay for %u bytes is zero\n",
		  av,
		  (unsigned int) size);
#endif
      return GNUNET_TIME_UNIT_ZERO;
    }
  bytes_needed = size - delta_avail;
  ret.value = 1000LL * bytes_needed / (unsigned long long) av->available_bytes_per_s__;
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p delay for %u bytes is %llu ms\n",
	      av,
	      (unsigned int) size,
	      (unsigned long long) ret.value);
#endif
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
  int64_t used;

  update_tracker (av);
  bps = GNUNET_BANDWIDTH_value_init (av->available_bytes_per_s__);
  avail = GNUNET_BANDWIDTH_value_get_available_until (bps,
						      GNUNET_TIME_absolute_get_duration (av->last_update__));
  used = av->consumption_since_last_update__;
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p  available bandwith is %lld ms\n",
	      av,	      
	      (long long) (int64_t) (avail - used));
#endif
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
#if DEBUG_BANDWIDTH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Tracker %p bandwith changed to %u bps\n",
	      av,	      
	      (unsigned int) new_limit);
#endif
  update_tracker (av);
  old_limit = av->available_bytes_per_s__;
  av->available_bytes_per_s__ = new_limit;
  if (old_limit > new_limit)
    update_tracker (av); /* maximum excess might be less now */
}


/* end of bandwidth.c */
