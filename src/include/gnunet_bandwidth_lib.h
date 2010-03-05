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
 * @file include/gnunet_bandwidth_lib.h
 * @brief functions related to bandwidth (unit)
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_BANDWIDTH_LIB_H
#define GNUNET_BANDWIDTH_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_time_lib.h"

/**
 * 32-bit bandwidth used for network exchange by GNUnet, in bytes per second.
 */
struct GNUNET_BANDWIDTH_Value32NBO
{
  /**
   * The actual value (bytes per second).
   */
  uint32_t value__ GNUNET_PACKED;
};


/**
 * Struct to track available bandwidth.  Combines a time stamp with a
 * number of bytes transmitted, a quota and a maximum amount that
 * carries over.  Not opaque so that it can be inlined into data
 * structures (reducing malloc-ing); however, values should not be
 * accessed directly by clients (hence the '__').
 */
struct GNUNET_BANDWIDTH_Tracker
{
  /**
   * Number of bytes consumed since we last updated the tracker.
   */
  uint64_t consumption_since_last_update__;

  /**
   * Time when we last updated the tracker.
   */
  struct GNUNET_TIME_Absolute last_update__;

  /**
   * Bandwidth limit to enforce in bytes per s.
   */
  uint32_t available_bytes_per_s__;

  /**
   * Maximum number of seconds over which bandwidth may "accumulate".
   * Note that additionally, we also always allow at least
   * GNUNET_SERVER_MAX_MESSAGE_SIZE to accumulate.
   */
  uint32_t max_carry_s__;
};


/**
 * Create a new bandwidth value.
 *
 * @param bytes_per_second value to create
 * @return the new bandwidth value
 */
struct GNUNET_BANDWIDTH_Value32NBO
GNUNET_BANDWIDTH_value_init (uint32_t bytes_per_second);


/**
 * Compute the MIN of two bandwidth values.
 *
 * @param b1 first value
 * @param b2 second value
 * @return the min of b1 and b2
 */
struct GNUNET_BANDWIDTH_Value32NBO
GNUNET_BANDWIDTH_value_min (struct GNUNET_BANDWIDTH_Value32NBO b1,
			    struct GNUNET_BANDWIDTH_Value32NBO b2);


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
			       uint32_t max_carry_s);


/**
 * Notify the tracker that a certain number of bytes of bandwidth have
 * been consumed.  Note that it is legal to consume bytes even if not
 * enough bandwidth is available (in that case,
 * GNUNET_BANDWIDTH_tracker_get_delay may return non-zero delay values
 * even for a size of zero for a while).
 *
 * @param av tracker to update
 * @param size number of bytes consumed
 */
void
GNUNET_BANDWIDTH_tracker_consume (struct GNUNET_BANDWIDTH_Tracker *av,
				  size_t size);


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
				    size_t size);


/**
 * Update quota of bandwidth tracker.
 *
 * @param av tracker to initialize
 * @param bytes_per_second_limit new limit to assume
 */
void
GNUNET_BANDWIDTH_tracker_update_quota (struct GNUNET_BANDWIDTH_Tracker *av,
				       struct GNUNET_BANDWIDTH_Value32NBO bytes_per_second_limit);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_BANDWIDTH_LIB_H */
#endif
/* end of gnunet_bandwidth_lib.h */
