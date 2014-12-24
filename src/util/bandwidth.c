/*
     This file is part of GNUnet.
     (C) 2010, 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/bandwidth.c
 * @brief functions related to bandwidth (unit)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util-bandwidth", __VA_ARGS__)

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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initializing bandwidth of %u Bps\n",
       (unsigned int) bytes_per_second);
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
  return
      GNUNET_BANDWIDTH_value_init (GNUNET_MIN
                                   (ntohl (b1.value__), ntohl (b2.value__)));
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Bandwidth has %llu bytes available until deadline in %s\n",
       (unsigned long long) ((b * deadline.rel_value_us + 500000LL) / 1000000LL),
       GNUNET_STRINGS_relative_time_to_string (deadline, GNUNET_YES));
  return (b * deadline.rel_value_us + 500000LL) / 1000000LL;
}


/**
 * At the given bandwidth, calculate how long it would take for
 * @a size bytes to be transmitted.
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
  if (0 == b)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Bandwidth suggests delay of infinity (zero bandwidth)\n");
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  ret.rel_value_us = size * 1000LL * 1000LL / b;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Bandwidth suggests delay of %s for %llu bytes of traffic\n",
       GNUNET_STRINGS_relative_time_to_string (ret, GNUNET_YES),
       (unsigned long long) size);
  return ret;
}


/**
 * Task run whenever we hit the bandwidth limit for a tracker.
 *
 * @param cls the `struct GNUNET_BANDWIDTH_Tracker`
 * @param tc scheduler context
 */
static void
excess_trigger (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_BANDWIDTH_Tracker *av = cls;

  av->excess_task = NULL;

  if (NULL != av->excess_cb)
    av->excess_cb (av->excess_cb_cls);
}


/**
 * Recalculate when we might need to call the excess callback.
 */
static void
update_excess (struct GNUNET_BANDWIDTH_Tracker *av)
{
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_TIME_Absolute now;
  uint64_t delta_time;
  uint64_t delta_avail;
  int64_t left_bytes;
  uint64_t max_carry;
  int64_t current_consumption;

  if (NULL == av->excess_cb)
    return; /* nothing to do */
  now = GNUNET_TIME_absolute_get ();
  delta_time = now.abs_value_us - av->last_update__.abs_value_us;
  delta_avail =
      (delta_time * ((unsigned long long) av->available_bytes_per_s__) +
       500000LL) / 1000000LL;
  current_consumption = av->consumption_since_last_update__ - delta_avail;
  /* negative current_consumption means that we have savings */
  max_carry = av->available_bytes_per_s__ * av->max_carry_s__;
  if (max_carry < GNUNET_SERVER_MAX_MESSAGE_SIZE)
    max_carry = GNUNET_SERVER_MAX_MESSAGE_SIZE;
  left_bytes = max_carry + current_consumption;
  /* left_bytes now contains the number of bytes needed until
     we have more savings than allowed */
  if (left_bytes < 0)
  {
    /* having excess already */
    delay = GNUNET_TIME_UNIT_ZERO;
  }
  else
  {
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                           left_bytes);
    delay = GNUNET_TIME_relative_divide (delay,
                                         av->available_bytes_per_s__);
  }
  if (NULL != av->excess_task)
    GNUNET_SCHEDULER_cancel (av->excess_task);
  av->excess_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                  &excess_trigger,
                                                  av);
}


/**
 * Initialize bandwidth tracker.  Note that in addition to the
 * 'max_carry_s' limit, we also always allow at least
 * #GNUNET_SERVER_MAX_MESSAGE_SIZE to accumulate.  So if the
 * bytes-per-second limit is so small that within 'max_carry_s' not
 * even #GNUNET_SERVER_MAX_MESSAGE_SIZE is allowed to accumulate, it is
 * ignored and replaced by #GNUNET_SERVER_MAX_MESSAGE_SIZE (which is in
 * bytes).
 *
 * To stop notifications about updates and excess callbacks use
 * #GNUNET_BANDWIDTH_tracker_notification_stop
 *
 * @param av tracker to initialize
 * @param update_cb callback to notify a client about the tracker being updated
 * @param update_cb_cls cls for the callback
 * @param bytes_per_second_limit initial limit to assume
 * @param max_carry_s maximum number of seconds unused bandwidth
 *        may accumulate before it expires
 * @param excess_cb callback to notify if we have excess bandwidth
 * @param excess_cb_cls closure for @a excess_cb
 */
void
GNUNET_BANDWIDTH_tracker_init2 (struct GNUNET_BANDWIDTH_Tracker *av,
                                GNUNET_BANDWIDTH_TrackerUpdateCallback update_cb,
                                void *update_cb_cls,
                                struct GNUNET_BANDWIDTH_Value32NBO bytes_per_second_limit,
                                uint32_t max_carry_s,
                                GNUNET_BANDWIDTH_ExcessNotificationCallback excess_cb,
                                void *excess_cb_cls)
{
  av->update_cb = update_cb;
  av->update_cb_cls = update_cb_cls;
  av->consumption_since_last_update__ = 0;
  av->last_update__ = GNUNET_TIME_absolute_get ();
  av->available_bytes_per_s__ = ntohl (bytes_per_second_limit.value__);
  av->max_carry_s__ = max_carry_s;
  av->excess_cb = excess_cb;
  av->excess_cb_cls = excess_cb_cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p initialized with %u Bps and max carry %u\n",
       av,
       (unsigned int) av->available_bytes_per_s__,
       (unsigned int) max_carry_s);
  update_excess (av);
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
 * @param update_cb callback to notify a client about the tracker being updated
 * @param update_cb_cls cls for the callback
 * @param bytes_per_second_limit initial limit to assume
 * @param max_carry_s maximum number of seconds unused bandwidth
 *        may accumulate before it expires
 */
void
GNUNET_BANDWIDTH_tracker_init (struct GNUNET_BANDWIDTH_Tracker *av,
                               GNUNET_BANDWIDTH_TrackerUpdateCallback update_cb,
                               void *update_cb_cls,
                               struct GNUNET_BANDWIDTH_Value32NBO bytes_per_second_limit,
                               uint32_t max_carry_s)
{
  GNUNET_BANDWIDTH_tracker_init2 (av, update_cb,
                                  update_cb_cls,
                                  bytes_per_second_limit,
                                  max_carry_s,
                                  NULL, NULL);
}


/**
 * Stop notifying about tracker updates and excess notifications
 *
 * @param av the respective trackers
 */
void
GNUNET_BANDWIDTH_tracker_notification_stop (struct GNUNET_BANDWIDTH_Tracker *av)
{
  if (NULL != av->excess_task)
    GNUNET_SCHEDULER_cancel (av->excess_task);
  av->excess_task = NULL;
  av->excess_cb = NULL;
  av->excess_cb_cls = NULL;
  av->update_cb = NULL;
  av->update_cb_cls = NULL;
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
  struct GNUNET_TIME_Relative delta;
  uint64_t delta_time;
  uint64_t delta_avail;
  uint64_t left_bytes;
  uint64_t max_carry;

  now = GNUNET_TIME_absolute_get ();
  delta_time = now.abs_value_us - av->last_update__.abs_value_us;
  delta_avail =
      (delta_time * ((unsigned long long) av->available_bytes_per_s__) +
       500000LL) / 1000000LL;
  av->consumption_since_last_update__ -= delta_avail;
  av->last_update__ = now;
  if (av->consumption_since_last_update__ < 0)
  {
    left_bytes = -av->consumption_since_last_update__;
    max_carry = av->available_bytes_per_s__ * av->max_carry_s__;
    if (max_carry < GNUNET_SERVER_MAX_MESSAGE_SIZE)
      max_carry = GNUNET_SERVER_MAX_MESSAGE_SIZE;
    if (max_carry > left_bytes)
      av->consumption_since_last_update__ = -left_bytes;
    else
      av->consumption_since_last_update__ = -max_carry;
  }
  delta.rel_value_us = delta_time;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p updated, have %u Bps, last update was %s ago\n", av,
       (unsigned int) av->available_bytes_per_s__,
       GNUNET_STRINGS_relative_time_to_string (delta, GNUNET_YES));
}


/**
 * Notify the tracker that a certain number of bytes of bandwidth have
 * been consumed.  Note that it is legal to consume bytes even if not
 * enough bandwidth is available (in that case,
 * #GNUNET_BANDWIDTH_tracker_get_delay may return non-zero delay values
 * even for a size of zero for a while).
 *
 * @param av tracker to update
 * @param size number of bytes consumed
 * @return #GNUNET_YES if this consumption is above the limit
 */
int
GNUNET_BANDWIDTH_tracker_consume (struct GNUNET_BANDWIDTH_Tracker *av,
                                  ssize_t size)
{
  int64_t nc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p consumes %d bytes\n",
       av,
       (int) size);
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
    update_excess (av);
    if (av->consumption_since_last_update__ > 0)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Tracker %p consumption %llu bytes above limit\n", av,
           (unsigned long long) av->consumption_since_last_update__);
      return GNUNET_YES;
    }
  }
  else
  {
    av->consumption_since_last_update__ += size;
    update_excess (av);
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
 * @return time in ms to wait for consumption to be OK
 */
struct GNUNET_TIME_Relative
GNUNET_BANDWIDTH_tracker_get_delay (struct GNUNET_BANDWIDTH_Tracker *av,
                                    size_t size)
{
  struct GNUNET_TIME_Relative ret;
  int64_t bytes_needed;

  if (0 == av->available_bytes_per_s__)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Tracker %p delay is infinity\n", av);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  update_tracker (av);
  bytes_needed = size + av->consumption_since_last_update__;
  if (bytes_needed <= 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Tracker %p delay for %u bytes is zero\n", av,
         (unsigned int) size);
    return GNUNET_TIME_UNIT_ZERO;
  }
  ret.rel_value_us =
      (1000LL * 1000LL * bytes_needed) /
      (unsigned long long) av->available_bytes_per_s__;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p delay for %u bytes is %s\n",
       av, (unsigned int) size,
       GNUNET_STRINGS_relative_time_to_string (ret, GNUNET_YES));
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
  avail =
      GNUNET_BANDWIDTH_value_get_available_until (bps,
                                                  GNUNET_TIME_absolute_get_duration
                                                  (av->last_update__));
  used = av->consumption_since_last_update__;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p available bandwidth is %lld bytes\n", av,
       (long long) (int64_t) (avail - used));
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tracker %p bandwidth changed to %u Bps\n", av,
       (unsigned int) new_limit);
  update_tracker (av);
  old_limit = av->available_bytes_per_s__;
  av->available_bytes_per_s__ = new_limit;
  if (NULL != av->update_cb)
    av->update_cb (av->update_cb_cls);
  if (old_limit > new_limit)
    update_tracker (av);        /* maximum excess might be less now */
  update_excess (av);
}


/* end of bandwidth.c */
