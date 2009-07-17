/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_time_lib.h
 * @brief functions related to time
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_TIME_LIB_H
#define GNUNET_TIME_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"

/**
 * Time for absolute times used by GNUnet, in milliseconds.
 */
struct GNUNET_TIME_Absolute
{
  uint64_t value;
};

/**
 * Time for relative time used by GNUnet, in milliseconds.
 * Always positive, so we can only refer to future time.
 */
struct GNUNET_TIME_Relative
{
  uint64_t value;
};


/**
 * Time for relative time used by GNUnet, in milliseconds and in network byte order.
 */
struct GNUNET_TIME_RelativeNBO
{
  uint64_t value GNUNET_PACKED;
};


/**
 * Time for absolute time used by GNUnet, in milliseconds and in network byte order.
 */
struct GNUNET_TIME_AbsoluteNBO
{
  uint64_t value GNUNET_PACKED;
};

/**
 * @brief constants to specify time
 */
#define GNUNET_TIME_UNIT_ZERO     GNUNET_TIME_relative_get_zero()
#define GNUNET_TIME_UNIT_MILLISECONDS GNUNET_TIME_relative_get_unit()
#define GNUNET_TIME_UNIT_SECONDS GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 1000)
#define GNUNET_TIME_UNIT_MINUTES GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 60)
#define GNUNET_TIME_UNIT_HOURS   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 60)
#define GNUNET_TIME_UNIT_DAYS    GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_HOURS,   24)
#define GNUNET_TIME_UNIT_WEEKS   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_DAYS,     7)
#define GNUNET_TIME_UNIT_MONTHS  GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_DAYS,    30)
#define GNUNET_TIME_UNIT_YEARS   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_DAYS,   365)

/**
 * Constant used to specify "forever".  This constant
 * will be treated specially in all time operations.
 */
#define GNUNET_TIME_UNIT_FOREVER_REL GNUNET_TIME_relative_get_forever ()

/**
 * Constant used to specify "forever".  This constant
 * will be treated specially in all time operations.
 */
#define GNUNET_TIME_UNIT_FOREVER_ABS GNUNET_TIME_absolute_get_forever ()

/**
 * Return relative time of 0ms.
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_get_zero (void);

/**
 * Return relative time of 1ms.
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_get_unit (void);

/**
 * Return "forever".
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_get_forever (void);

/**
 * Return "forever".
 */
struct GNUNET_TIME_Absolute GNUNET_TIME_absolute_get_forever (void);

/**
 * Get the current time.
 *
 * @return the current time
 */
struct GNUNET_TIME_Absolute GNUNET_TIME_absolute_get (void);

/**
 * Convert relative time to an absolute time in the
 * future.
 *
 * @return timestamp that is "rel" in the future, or FOREVER if rel==FOREVER (or if we would overflow)
 */
struct GNUNET_TIME_Absolute GNUNET_TIME_relative_to_absolute (struct
                                                              GNUNET_TIME_Relative
                                                              rel);

/**
 * Return the minimum of two relative time values.
 *
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_min (struct
						      GNUNET_TIME_Relative
						      t1,
						      struct
						      GNUNET_TIME_Relative t2);

/**
 * Given a timestamp in the future, how much time
 * remains until then?
 *
 * @return future - now, or 0 if now >= future, or FOREVER if future==FOREVER.
 */
struct GNUNET_TIME_Relative GNUNET_TIME_absolute_get_remaining (struct
                                                                GNUNET_TIME_Absolute
                                                                future);

/**
 * Compute the time difference between the given start and end times.
 * Use this function instead of actual subtraction to ensure that
 * "FOREVER" and overflows are handeled correctly.
 *
 * @return 0 if start >= end; FOREVER if end==FOREVER; otherwise end - start
 */
struct GNUNET_TIME_Relative GNUNET_TIME_absolute_get_difference (struct
                                                                 GNUNET_TIME_Absolute
                                                                 start,
                                                                 struct
                                                                 GNUNET_TIME_Absolute
                                                                 end);

/**
 * Get the duration of an operation as the
 * difference of the current time and the given start time "hence".
 *
 * @return aborts if hence==FOREVER, 0 if hence > now, otherwise now-hence.
 */
struct GNUNET_TIME_Relative GNUNET_TIME_absolute_get_duration (struct
                                                               GNUNET_TIME_Absolute
                                                               hence);


/**
 * Add a given relative duration to the
 * given start time.
 *
 * @return FOREVER if either argument is FOREVER or on overflow; start+duration otherwise
 */
struct GNUNET_TIME_Absolute GNUNET_TIME_absolute_add (struct
                                                      GNUNET_TIME_Absolute
                                                      start,
                                                      struct
                                                      GNUNET_TIME_Relative
                                                      duration);

/**
 * Multiply relative time by a given factor.
 *
 * @return FOREVER if rel=FOREVER or on overflow; otherwise rel*factor
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_multiply (struct
                                                           GNUNET_TIME_Relative
                                                           rel,
                                                           unsigned int
                                                           factor);

/**
 * Add relative times together.
 *
 * @return FOREVER if either argument is FOREVER or on overflow; a1+a2 otherwise
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_add (struct
                                                      GNUNET_TIME_Relative a1,
                                                      struct
                                                      GNUNET_TIME_Relative
                                                      a2);


/**
 * Convert relative time to network byte order.
 */
struct GNUNET_TIME_RelativeNBO GNUNET_TIME_relative_hton (struct
                                                          GNUNET_TIME_Relative
                                                          a);

/**
 * Convert relative time from network byte order.
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_ntoh (struct
                                                       GNUNET_TIME_RelativeNBO
                                                       a);

/**
 * Convert relative time to network byte order.
 */
struct GNUNET_TIME_AbsoluteNBO GNUNET_TIME_absolute_hton (struct
                                                          GNUNET_TIME_Absolute
                                                          a);

/**
 * Convert relative time from network byte order.
 */
struct GNUNET_TIME_Absolute GNUNET_TIME_absolute_ntoh (struct
                                                       GNUNET_TIME_AbsoluteNBO
                                                       a);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TIME_LIB_H */
#endif
/* end of gnunet_time_lib.h */
