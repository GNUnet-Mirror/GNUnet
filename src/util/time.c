/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/time.c
 * @author Christian Grothoff
 * @brief functions for handling time and time arithmetic
 */
#include "platform.h"
#include "gnunet_time_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Variable used to simulate clock skew.  Used for testing, never in production.
 */
static long long timestamp_offset;

/**
 * Set the timestamp offset for this instance.
 *
 * @param offset the offset to skew the locale time by
 */
void
GNUNET_TIME_set_offset (long long offset)
{
  timestamp_offset = offset;
}

/**
 * Get the current time (works just as "time", just that we use the
 * unit of time that the cron-jobs use (and is 64 bit)).
 *
 * @return the current time
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get ()
{
  struct GNUNET_TIME_Absolute ret;
  struct timeval tv;

  GETTIMEOFDAY (&tv, NULL);
  ret.abs_value =
      (uint64_t) (((uint64_t) tv.tv_sec * 1000LL) +
                  ((uint64_t) tv.tv_usec / 1000LL)) + timestamp_offset;
  return ret;
}


/**
 * Return relative time of 0ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_zero_ ()
{
  static struct GNUNET_TIME_Relative zero;

  return zero;
}


/**
 * Return absolute time of 0ms.
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_zero_ ()
{
  static struct GNUNET_TIME_Absolute zero;

  return zero;
}


/**
 * Return relative time of 1ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_unit_ ()
{
  static struct GNUNET_TIME_Relative one = { 1 };
  return one;
}


/**
 * Return relative time of 1s.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_second_ ()
{
  static struct GNUNET_TIME_Relative one = { 1000 };
  return one;
}


/**
 * Return relative time of 1 minute.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_minute_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 1000 };
  return one;
}


/**
 * Return relative time of 1 hour.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_hour_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 60 * 1000 };
  return one;
}


/**
 * Return "forever".
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_forever_ ()
{
  static struct GNUNET_TIME_Relative forever = { UINT64_MAX };
  return forever;
}

/**
 * Return "forever".
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_forever_ ()
{
  static struct GNUNET_TIME_Absolute forever = { UINT64_MAX };
  return forever;
}

/**
 * Convert relative time to an absolute time in the
 * future.
 *
 * @return timestamp that is "rel" in the future, or FOREVER if rel==FOREVER (or if we would overflow)
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_relative_to_absolute (struct GNUNET_TIME_Relative rel)
{
  struct GNUNET_TIME_Absolute ret;

  if (rel.rel_value == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  if (rel.rel_value + now.abs_value < rel.rel_value)
  {
    GNUNET_break (0);           /* overflow... */
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value = rel.rel_value + now.abs_value;
  return ret;
}


/**
 * Return the minimum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_min (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2)
{
  return (t1.rel_value < t2.rel_value) ? t1 : t2;
}


/**
 * Return the maximum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is larger
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_max (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2)
{
  return (t1.rel_value > t2.rel_value) ? t1 : t2;
}



/**
 * Return the minimum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_min (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2)
{
  return (t1.abs_value < t2.abs_value) ? t1 : t2;
}


/**
 * Return the maximum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is bigger
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_max (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2)
{
  return (t1.abs_value > t2.abs_value) ? t1 : t2;
}


/**
 * Given a timestamp in the future, how much time
 * remains until then?
 *
 * @return future - now, or 0 if now >= future, or FOREVER if future==FOREVER.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_remaining (struct GNUNET_TIME_Absolute future)
{
  struct GNUNET_TIME_Relative ret;

  if (future.abs_value == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  if (now.abs_value > future.abs_value)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value = future.abs_value - now.abs_value;
  return ret;
}

/**
 * Compute the time difference between the given start and end times.
 * Use this function instead of actual subtraction to ensure that
 * "FOREVER" and overflows are handled correctly.
 *
 * @return 0 if start >= end; FOREVER if end==FOREVER; otherwise end - start
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_difference (struct GNUNET_TIME_Absolute start,
                                     struct GNUNET_TIME_Absolute end)
{
  struct GNUNET_TIME_Relative ret;

  if (end.abs_value == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (end.abs_value < start.abs_value)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value = end.abs_value - start.abs_value;
  return ret;
}

/**
 * Get the duration of an operation as the
 * difference of the current time and the given start time "whence".
 *
 * @return aborts if whence==FOREVER, 0 if whence > now, otherwise now-whence.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_duration (struct GNUNET_TIME_Absolute whence)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative ret;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_assert (whence.abs_value != UINT64_MAX);
  if (whence.abs_value > now.abs_value)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value = now.abs_value - whence.abs_value;
  return ret;
}


/**
 * Add a given relative duration to the
 * given start time.
 *
 * @return FOREVER if either argument is FOREVER or on overflow; start+duration otherwise
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_add (struct GNUNET_TIME_Absolute start,
                          struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute ret;

  if ((start.abs_value == UINT64_MAX) || (duration.rel_value == UINT64_MAX))
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  if (start.abs_value + duration.rel_value < start.abs_value)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value = start.abs_value + duration.rel_value;
  return ret;
}


/**
 * Subtract a given relative duration from the
 * given start time.
 *
 * @param start some absolute time
 * @param duration some relative time to subtract
 * @return ZERO if start <= duration, or FOREVER if start time is FOREVER; start-duration otherwise
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_subtract (struct GNUNET_TIME_Absolute start,
                               struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute ret;

  if (start.abs_value <= duration.rel_value)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  if (start.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  ret.abs_value = start.abs_value - duration.rel_value;
  return ret;
}


/**
 * Multiply relative time by a given factor.
 *
 * @return FOREVER if rel=FOREVER or on overflow; otherwise rel*factor
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_multiply (struct GNUNET_TIME_Relative rel,
                               unsigned int factor)
{
  struct GNUNET_TIME_Relative ret;

  if (factor == 0)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value = rel.rel_value * (unsigned long long) factor;
  if (ret.rel_value / factor != rel.rel_value)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  return ret;
}


/**
 * Divide relative time by a given factor.
 *
 * @param rel some duration
 * @param factor integer to divide by
 * @return FOREVER if rel=FOREVER or factor==0; otherwise rel/factor
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_divide (struct GNUNET_TIME_Relative rel,
                             unsigned int factor)
{
  struct GNUNET_TIME_Relative ret;

  if ((factor == 0) ||
      (rel.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value = rel.rel_value / (unsigned long long) factor;
  return ret;
}


/**
 * Calculate the estimate time of arrival/completion
 * for an operation.
 *
 * @param start when did the operation start?
 * @param finished how much has been done?
 * @param total how much must be done overall (same unit as for "finished")
 * @return remaining duration for the operation,
 *        assuming it continues at the same speed
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_calculate_eta (struct GNUNET_TIME_Absolute start, uint64_t finished,
                           uint64_t total)
{
  struct GNUNET_TIME_Relative dur;
  double exp;
  struct GNUNET_TIME_Relative ret;

  GNUNET_break (finished <= total);
  if (finished >= total)
    return GNUNET_TIME_UNIT_ZERO;
  if (finished == 0)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  dur = GNUNET_TIME_absolute_get_duration (start);
  exp = ((double) dur.rel_value) * ((double) total) / ((double) finished);
  ret.rel_value = ((uint64_t) exp) - dur.rel_value;
  return ret;
}


/**
 * Add relative times together.
 *
 * @param a1 first timestamp
 * @param a2 second timestamp
 * @return FOREVER if either argument is FOREVER or on overflow; a1+a2 otherwise
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_add (struct GNUNET_TIME_Relative a1,
                          struct GNUNET_TIME_Relative a2)
{
  struct GNUNET_TIME_Relative ret;

  if ((a1.rel_value == UINT64_MAX) || (a2.rel_value == UINT64_MAX))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (a1.rel_value + a2.rel_value < a1.rel_value)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  ret.rel_value = a1.rel_value + a2.rel_value;
  return ret;
}


/**
 * Subtract relative timestamp from the other.
 *
 * @param a1 first timestamp
 * @param a2 second timestamp
 * @return ZERO if a2>=a1 (including both FOREVER), FOREVER if a1 is FOREVER, a1-a2 otherwise
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_subtract (struct GNUNET_TIME_Relative a1,
                               struct GNUNET_TIME_Relative a2)
{
  struct GNUNET_TIME_Relative ret;

  if (a2.rel_value >= a1.rel_value)
    return GNUNET_TIME_UNIT_ZERO;
  if (a1.rel_value == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value = a1.rel_value - a2.rel_value;
  return ret;
}


/**
 * Convert relative time to network byte order.
 *
 * @param a time to convert
 * @return time in network byte order
 */
struct GNUNET_TIME_RelativeNBO
GNUNET_TIME_relative_hton (struct GNUNET_TIME_Relative a)
{
  struct GNUNET_TIME_RelativeNBO ret;

  ret.rel_value__ = GNUNET_htonll (a.rel_value);
  return ret;
}

/**
 * Convert relative time from network byte order.
 *
 * @param a time to convert
 * @return time in host byte order
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_ntoh (struct GNUNET_TIME_RelativeNBO a)
{
  struct GNUNET_TIME_Relative ret;

  ret.rel_value = GNUNET_ntohll (a.rel_value__);
  return ret;

}

/**
 * Convert absolute time to network byte order.
 *
 * @param a time to convert
 * @return time in network byte order
 */
struct GNUNET_TIME_AbsoluteNBO
GNUNET_TIME_absolute_hton (struct GNUNET_TIME_Absolute a)
{
  struct GNUNET_TIME_AbsoluteNBO ret;

  ret.abs_value__ = GNUNET_htonll (a.abs_value);
  return ret;
}

/**
 * Convert absolute time from network byte order.
 *
 * @param a time to convert
 * @return time in host byte order
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_ntoh (struct GNUNET_TIME_AbsoluteNBO a)
{
  struct GNUNET_TIME_Absolute ret;

  ret.abs_value = GNUNET_ntohll (a.abs_value__);
  return ret;

}

/**
 * Convert a relative time to a string.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param time the time to print
 *
 * @return string form of the time (as milliseconds)
 */
const char *
GNUNET_TIME_relative_to_string (struct GNUNET_TIME_Relative time)
{
  static char time_string[21];

  memset (time_string, 0, sizeof (time_string));

  sprintf (time_string, "%llu", (unsigned long long) time.rel_value);
  return (const char *) time_string;
}



/* end of time.c */
