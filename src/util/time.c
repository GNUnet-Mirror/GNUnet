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
  ret.value = tv.tv_sec * 1000 + tv.tv_usec / 1000;
  return ret;
}


/**
 * Return relative time of 0ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_zero ()
{
  static struct GNUNET_TIME_Relative zero;
  return zero;
}

/**
 * Return relative time of 1ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_unit ()
{
  static struct GNUNET_TIME_Relative one = { 1 };
  return one;
}

/**
 * Return "forever".
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_forever ()
{
  static struct GNUNET_TIME_Relative forever = { (uint64_t) - 1LL };
  return forever;
}

/**
 * Return "forever".
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_forever ()
{
  static struct GNUNET_TIME_Absolute forever = { (uint64_t) - 1LL };
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
  if (rel.value == (uint64_t) - 1LL)
    return GNUNET_TIME_absolute_get_forever ();
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  if (rel.value + now.value < rel.value)
    {
      GNUNET_break (0);         /* overflow... */
      return GNUNET_TIME_absolute_get_forever ();
    }
  ret.value = rel.value + now.value;
  return ret;
}


/**
 * Return the minimum of two relative time values.
 *
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Relative GNUNET_TIME_relative_min (struct
						      GNUNET_TIME_Relative
						      t1,
						      struct
						      GNUNET_TIME_Relative t2)
{
  return (t1.value < t2.value) ? t1 : t2;
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
  if (future.value == (uint64_t) - 1LL)
    return GNUNET_TIME_relative_get_forever ();
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  if (now.value > future.value)
    return GNUNET_TIME_relative_get_zero ();
  ret.value = future.value - now.value;
  return ret;
}

/**
 * Compute the time difference between the given start and end times.
 * Use this function instead of actual subtraction to ensure that
 * "FOREVER" and overflows are handeled correctly.
 *
 * @return 0 if start >= end; FOREVER if end==FOREVER; otherwise end - start
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_difference (struct GNUNET_TIME_Absolute start,
                                     struct GNUNET_TIME_Absolute end)
{
  struct GNUNET_TIME_Relative ret;
  if (end.value == (uint64_t) - 1LL)
    return GNUNET_TIME_relative_get_forever ();
  if (end.value < start.value)
    return GNUNET_TIME_relative_get_zero ();
  ret.value = end.value - start.value;
  return ret;
}

/**
 * Get the duration of an operation as the
 * difference of the current time and the given start time "hence".
 *
 * @return aborts if hence==FOREVER, 0 if hence > now, otherwise now-hence.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_duration (struct GNUNET_TIME_Absolute hence)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative ret;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_assert (hence.value != (uint64_t) - 1LL);
  if (hence.value > now.value)
    return GNUNET_TIME_relative_get_zero ();
  ret.value = now.value - hence.value;
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

  if ((start.value == (uint64_t) - 1LL) ||
      (duration.value == (uint64_t) - 1LL))
    return GNUNET_TIME_absolute_get_forever ();
  if (start.value + duration.value < start.value)
    {
      GNUNET_break (0);
      return GNUNET_TIME_absolute_get_forever ();
    }
  ret.value = start.value + duration.value;
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
    return GNUNET_TIME_relative_get_zero ();
  ret.value = rel.value * factor;
  if (ret.value / factor != rel.value)
    {
      GNUNET_break (0);
      return GNUNET_TIME_relative_get_forever ();
    }
  return ret;
}

/**
 * Add relative times together.
 *
 * @return FOREVER if either argument is FOREVER or on overflow; a1+a2 otherwise
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_add (struct GNUNET_TIME_Relative a1,
                          struct GNUNET_TIME_Relative a2)
{
  struct GNUNET_TIME_Relative ret;

  if ((a1.value == (uint64_t) - 1LL) || (a2.value == (uint64_t) - 1LL))
    return GNUNET_TIME_relative_get_forever ();
  if (a1.value + a2.value < a1.value)
    {
      GNUNET_break (0);
      return GNUNET_TIME_relative_get_forever ();
    }
  ret.value = a1.value + a2.value;
  return ret;
}


/**
 * Convert relative time to network byte order.
 */
struct GNUNET_TIME_RelativeNBO
GNUNET_TIME_relative_hton (struct GNUNET_TIME_Relative a)
{
  struct GNUNET_TIME_RelativeNBO ret;
  ret.value = GNUNET_htonll (a.value);
  return ret;
}

/**
 * Convert relative time from network byte order.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_ntoh (struct GNUNET_TIME_RelativeNBO a)
{
  struct GNUNET_TIME_Relative ret;
  ret.value = GNUNET_ntohll (a.value);
  return ret;

}

/**
 * Convert absolute time to network byte order.
 */
struct GNUNET_TIME_AbsoluteNBO
GNUNET_TIME_absolute_hton (struct GNUNET_TIME_Absolute a)
{
  struct GNUNET_TIME_AbsoluteNBO ret;
  ret.value = GNUNET_htonll (a.value);
  return ret;
}

/**
 * Convert absolute time from network byte order.
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_ntoh (struct GNUNET_TIME_AbsoluteNBO a)
{
  struct GNUNET_TIME_Absolute ret;
  ret.value = GNUNET_ntohll (a.value);
  return ret;

}



/* end of time.c */
