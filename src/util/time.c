/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file util/time.c
 * @author Christian Grothoff
 * @brief functions for handling time and time arithmetic
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
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
 * Get the timestamp offset for this instance.
 *
 * @return the offset we currently skew the locale time by
 */
long long
GNUNET_TIME_get_offset ()
{
  return timestamp_offset;
}


/**
 * Round a time value so that it is suitable for transmission
 * via JSON encodings.
 *
 * @param at time to round
 * @return #GNUNET_OK if time was already rounded, #GNUNET_NO if
 *         it was just now rounded
 */
int
GNUNET_TIME_round_abs (struct GNUNET_TIME_Absolute *at)
{
  if (at->abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
    return GNUNET_OK;
  if (0 == at->abs_value_us % 1000000)
    return GNUNET_OK;
  at->abs_value_us -= at->abs_value_us % 1000000;
  return GNUNET_NO;
}


/**
 * Round a time value so that it is suitable for transmission
 * via JSON encodings.
 *
 * @param rt time to round
 * @return #GNUNET_OK if time was already rounded, #GNUNET_NO if
 *         it was just now rounded
 */
int
GNUNET_TIME_round_rel (struct GNUNET_TIME_Relative *rt)
{
  if (rt->rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    return GNUNET_OK;
  if (0 == rt->rel_value_us % 1000000)
    return GNUNET_OK;
  rt->rel_value_us -= rt->rel_value_us % 1000000;
  return GNUNET_NO;
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
  ret.abs_value_us =
      (uint64_t) (((uint64_t) tv.tv_sec * 1000LL * 1000LL) +
                  ((uint64_t) tv.tv_usec)) + timestamp_offset;
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
 * Return relative time of 1us.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_unit_ ()
{
  static struct GNUNET_TIME_Relative one = { 1 };

  return one;
}


/**
 * Return relative time of 1ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_millisecond_ ()
{
  static struct GNUNET_TIME_Relative one = { 1000 };

  return one;
}


/**
 * Return relative time of 1s.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_second_ ()
{
  static struct GNUNET_TIME_Relative one = { 1000 * 1000LL };

  return one;
}


/**
 * Return relative time of 1 minute.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_minute_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 1000 * 1000LL };

  return one;
}


/**
 * Return relative time of 1 hour.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_hour_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 60 * 1000 * 1000LL };

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

  if (rel.rel_value_us == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  if (rel.rel_value_us + now.abs_value_us < rel.rel_value_us)
  {
    GNUNET_break (0);           /* overflow... */
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value_us = rel.rel_value_us + now.abs_value_us;
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
  return (t1.rel_value_us < t2.rel_value_us) ? t1 : t2;
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
  return (t1.rel_value_us > t2.rel_value_us) ? t1 : t2;
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
  return (t1.abs_value_us < t2.abs_value_us) ? t1 : t2;
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
  return (t1.abs_value_us > t2.abs_value_us) ? t1 : t2;
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

  if (future.abs_value_us == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  if (now.abs_value_us > future.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = future.abs_value_us - now.abs_value_us;
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

  if (end.abs_value_us == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (end.abs_value_us < start.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = end.abs_value_us - start.abs_value_us;
  return ret;
}

/**
 * Get the duration of an operation as the
 * difference of the current time and the given start time "whence".
 *
 * @return 0 if whence > now, otherwise now-whence.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_duration (struct GNUNET_TIME_Absolute whence)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative ret;

  now = GNUNET_TIME_absolute_get ();
  if (whence.abs_value_us > now.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = now.abs_value_us - whence.abs_value_us;
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

  if ((start.abs_value_us == UINT64_MAX) || (duration.rel_value_us == UINT64_MAX))
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  if (start.abs_value_us + duration.rel_value_us < start.abs_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value_us = start.abs_value_us + duration.rel_value_us;
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

  if (start.abs_value_us <= duration.rel_value_us)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  if (start.abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  ret.abs_value_us = start.abs_value_us - duration.rel_value_us;
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

  if (0 == factor)
    return GNUNET_TIME_UNIT_ZERO;
  if (rel.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = rel.rel_value_us * (unsigned long long) factor;
  if (ret.rel_value_us / factor != rel.rel_value_us)
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

  if ((0 == factor) ||
      (rel.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = rel.rel_value_us / (unsigned long long) factor;
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
  if (0 == finished)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  dur = GNUNET_TIME_absolute_get_duration (start);
  exp = ((double) dur.rel_value_us) * ((double) total) / ((double) finished);
  ret.rel_value_us = ((uint64_t) exp) - dur.rel_value_us;
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

  if ((a1.rel_value_us == UINT64_MAX) || (a2.rel_value_us == UINT64_MAX))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (a1.rel_value_us + a2.rel_value_us < a1.rel_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  ret.rel_value_us = a1.rel_value_us + a2.rel_value_us;
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

  if (a2.rel_value_us >= a1.rel_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  if (a1.rel_value_us == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = a1.rel_value_us - a2.rel_value_us;
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

  ret.rel_value_us__ = GNUNET_htonll (a.rel_value_us);
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

  ret.rel_value_us = GNUNET_ntohll (a.rel_value_us__);
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

  ret.abs_value_us__ = GNUNET_htonll (a.abs_value_us);
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

  ret.abs_value_us = GNUNET_ntohll (a.abs_value_us__);
  return ret;

}


/**
 * Return the current year (i.e. '2011').
 */
unsigned int
GNUNET_TIME_get_current_year ()
{
  time_t tp;
  struct tm *t;

  tp = time (NULL);
  t = gmtime (&tp);
  if (t == NULL)
    return 0;
  return t->tm_year + 1900;
}


/**
 * Convert an expiration time to the respective year (rounds)
 *
 * @param at absolute time
 * @return year a year (after 1970), 0 on error
 */
unsigned int
GNUNET_TIME_time_to_year (struct GNUNET_TIME_Absolute at)
{
  struct tm *t;
  time_t tp;

  tp = at.abs_value_us / 1000LL / 1000LL;    /* microseconds to seconds */
  t = gmtime (&tp);
  if (t == NULL)
    return 0;
  return t->tm_year + 1900;

}


/**
 * Convert a year to an expiration time of January 1st of that year.
 *
 * @param year a year (after 1970, please ;-)).
 * @return absolute time for January 1st of that year.
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_year_to_time (unsigned int year)
{
  struct GNUNET_TIME_Absolute ret;
  time_t tp;
  struct tm t;

  memset (&t, 0, sizeof (t));
  if (year < 1900)
  {
    GNUNET_break (0);
    return GNUNET_TIME_absolute_get (); /* now */
  }
  t.tm_year = year - 1900;
  t.tm_mday = 1;
  t.tm_mon = 1;
  t.tm_wday = 1;
  t.tm_yday = 1;
  tp = mktime (&t);
  GNUNET_break (tp != (time_t) - 1);
  ret.abs_value_us = tp * 1000LL * 1000LL;  /* seconds to microseconds */
  return ret;
}



/* end of time.c */
