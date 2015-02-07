/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-tests/ats-testing-traffic.c
 * @brief ats benchmark: traffic generator
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "ats-testing.h"

static struct TrafficGenerator *tg_head;
static struct TrafficGenerator *tg_tail;

extern struct GNUNET_ATS_TEST_Topology *top;

static struct GNUNET_TIME_Relative
get_delay (struct TrafficGenerator *tg)
{
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_TIME_Relative time_delta;
  long long int cur_rate;
  long long int delta_rate;

  delay.rel_value_us = 0;

  /* Calculate the current transmission rate based on the type of traffic */
  switch (tg->type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      if (UINT32_MAX == tg->base_rate)
        return GNUNET_TIME_UNIT_ZERO;
      cur_rate = tg->base_rate;
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      time_delta = GNUNET_TIME_absolute_get_duration(tg->time_start);
      /* Calculate point of time in the current period */
      time_delta.rel_value_us = time_delta.rel_value_us % tg->duration_period.rel_value_us;
      delta_rate = ((double) time_delta.rel_value_us  / tg->duration_period.rel_value_us) *
          (tg->max_rate - tg->base_rate);
      if ((tg->max_rate < tg->base_rate) && ((tg->max_rate - tg->base_rate) > tg->base_rate))
      {
        /* This will cause an underflow */
        GNUNET_break (0);
      }
      cur_rate = tg->base_rate + delta_rate;
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      cur_rate = tg->base_rate + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
          tg->max_rate - tg->base_rate);
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      time_delta = GNUNET_TIME_absolute_get_duration(tg->time_start);
      /* Calculate point of time in the current period */
      time_delta.rel_value_us = time_delta.rel_value_us % tg->duration_period.rel_value_us;
      if ((tg->max_rate - tg->base_rate) > tg->base_rate)
      {
        /* This will cause an underflow for second half of sinus period,
         * will be detected in general when experiments are loaded */
        GNUNET_break (0);
      }
      delta_rate = (tg->max_rate - tg->base_rate) *
          sin ( (2 * M_PI) / ((double) tg->duration_period.rel_value_us) * time_delta.rel_value_us);
      cur_rate = tg->base_rate + delta_rate;
      break;
    default:
      return delay;
      break;
  }

  if (cur_rate < 0)
  {
    cur_rate = 1;
  }
  /* Calculate the delay for the next message based on the current delay  */
  delay.rel_value_us =  GNUNET_TIME_UNIT_SECONDS.rel_value_us * TEST_MESSAGE_SIZE / cur_rate;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Current rate is %u, calculated delay is %u \n",
      cur_rate, delay.rel_value_us);
  return delay;
}


static size_t
send_ping_ready_cb (void *cls, size_t size, void *buf)
{
  struct BenchmarkPartner *p = cls;
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_TIME_Relative delay;

  if (NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  if (size < TEST_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return 0;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Master [%u]: Sending PING to [%u]\n",
             p->me->no, p->dest->no);
  if (top->test_core)
  {
    if (NULL == p->cth)
    {
      GNUNET_break (0);
    }
    p->cth = NULL;
  }
  else
  {
    if (NULL == p->tth)
    {
      GNUNET_break (0);
    }
    p->tth = NULL;
  }

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PING);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  if (NULL == p->tg)
  {
    GNUNET_break (0);
    return TEST_MESSAGE_SIZE;
  }
  delay = get_delay (p->tg);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Delay for next transmission %llu ms\n",
      (long long unsigned int) delay.rel_value_us / 1000);
  p->tg->next_ping_transmission = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(),
      delay);

  return TEST_MESSAGE_SIZE;
}


static void
comm_schedule_send (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BenchmarkPartner *p = cls;

  p->tg->send_task = NULL;
  p->last_message_sent = GNUNET_TIME_absolute_get();
  if (GNUNET_YES == top->test_core)
  {
    p->cth = GNUNET_CORE_notify_transmit_ready (p->me->ch, GNUNET_NO,
                                                GNUNET_CORE_PRIO_BEST_EFFORT,
                                                GNUNET_TIME_UNIT_MINUTES,
                                                &p->dest->id,
                                                TEST_MESSAGE_SIZE,
                                                &send_ping_ready_cb, p);
  }
  else
  {
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (p->me->th,
                                                     &p->dest->id,
                                                     TEST_MESSAGE_SIZE,
                                                     GNUNET_TIME_UNIT_MINUTES,
                                                     &send_ping_ready_cb, p);
  }
}


static size_t
comm_send_pong_ready (void *cls, size_t size, void *buf)
{
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct BenchmarkPartner *p = cls;
  struct GNUNET_MessageHeader *msg;

  if (GNUNET_YES == top->test_core)
    p->cth = NULL;
  else
    p->tth = NULL;

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PONG);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);

  return TEST_MESSAGE_SIZE;
}


void
GNUNET_ATS_TEST_traffic_handle_ping (struct BenchmarkPartner *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Slave [%u]: Received PING from [%u], sending PONG\n", p->me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  if (GNUNET_YES == top->test_core)
  {
    GNUNET_assert (NULL == p->cth);

    p->cth
      = GNUNET_CORE_notify_transmit_ready (p->me->ch, GNUNET_NO,
                                           GNUNET_CORE_PRIO_BEST_EFFORT,
                                           GNUNET_TIME_UNIT_MINUTES,
                                           &p->dest->id, TEST_MESSAGE_SIZE,
                                           &comm_send_pong_ready, p);
  }
  else
  {
    GNUNET_assert (NULL == p->tth);
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (p->me->th, &p->dest->id,
        TEST_MESSAGE_SIZE, GNUNET_TIME_UNIT_MINUTES, &comm_send_pong_ready,
        p);
  }
}


void
GNUNET_ATS_TEST_traffic_handle_pong (struct BenchmarkPartner *p)
{
  struct GNUNET_TIME_Relative left;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Master [%u]: Received PONG from [%u], next message\n", p->me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;
  p->total_app_rtt += GNUNET_TIME_absolute_get_difference(p->last_message_sent,
      GNUNET_TIME_absolute_get()).rel_value_us;

  /* Schedule next send event */
  if (NULL == p->tg)
    return;

  left = GNUNET_TIME_absolute_get_remaining(p->tg->next_ping_transmission);
  if (UINT32_MAX == p->tg->base_rate)
  {
    p->tg->send_task = GNUNET_SCHEDULER_add_now (&comm_schedule_send, p);
  }
  else if (0 == left.rel_value_us)
  {
    p->tg->send_task = GNUNET_SCHEDULER_add_now (&comm_schedule_send, p);
  }
  else
  {
    /* Enforce minimum transmission rate 1 msg / sec */
    if (GNUNET_TIME_UNIT_SECONDS.rel_value_us == (left = GNUNET_TIME_relative_min (left, GNUNET_TIME_UNIT_SECONDS)).rel_value_us)
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          "Enforcing minimum send rate between master [%u] and slave [%u]\n",
          p->me->no, p->dest->no);
    p->tg->send_task = GNUNET_SCHEDULER_add_delayed (left,
        &comm_schedule_send, p);
  }
}


/**
 * Generate between the source master and the partner and send traffic with a
 * maximum rate.
 *
 * @param src traffic source
 * @param dest traffic partner
 * @param type type of traffic to generate
 * @param base_rate traffic base rate to send data with
 * @param max_rate  traffic maximum rate to send data with
 * @param period duration of a period of traffic generation (~ 1/frequency)
 * @param duration how long to generate traffic
 * @return the traffic generator
 */
struct TrafficGenerator *
GNUNET_ATS_TEST_generate_traffic_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    enum GeneratorType type,
    long int base_rate,
    long int max_rate,
    struct GNUNET_TIME_Relative period,
    struct GNUNET_TIME_Relative duration)
{
  struct TrafficGenerator *tg;

  if (NULL != dest->tg)
  {
    GNUNET_break (0);
    return NULL;
  }

  tg = GNUNET_new (struct TrafficGenerator);
  GNUNET_CONTAINER_DLL_insert (tg_head, tg_tail, tg);
  tg->type = type;
  tg->src = src;
  tg->dest = dest;
  tg->base_rate = base_rate;
  tg->max_rate = max_rate;
  tg->duration_period = period;
  tg->time_start = GNUNET_TIME_absolute_get();
  tg->next_ping_transmission = GNUNET_TIME_UNIT_FOREVER_ABS;

  switch (type) {
    case GNUNET_ATS_TEST_TG_CONSTANT:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up constant traffic generator master[%u] `%s' and slave [%u] `%s' max %u Bips\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_rate);
      break;
    case GNUNET_ATS_TEST_TG_LINEAR:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up linear traffic generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bips\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_rate, max_rate);
      break;
    case GNUNET_ATS_TEST_TG_SINUS:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up sinus traffic generator master[%u] `%s' and slave [%u] `%s' baserate %u Bips, amplitude %u Bps\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_rate, max_rate);
      break;
    case GNUNET_ATS_TEST_TG_RANDOM:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Setting up random traffic generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bps\n",
          dest->me->no, GNUNET_i2s (&dest->me->id),
          dest->dest->no, GNUNET_i2s (&dest->dest->id),
          base_rate, max_rate);
      break;
    default:
      break;
  }

  if ( ((GNUNET_YES == top->test_core) && (NULL != dest->cth)) ||
       ((GNUNET_NO == top->test_core) && (NULL != dest->tth)) )
  {
        GNUNET_break (0);
        GNUNET_CONTAINER_DLL_remove (tg_head, tg_tail, tg);
        GNUNET_free (tg);
        return NULL;
  }

  dest->tg = tg;
  tg->send_task = GNUNET_SCHEDULER_add_now (&comm_schedule_send, dest);
  return tg;
}


void
GNUNET_ATS_TEST_generate_traffic_stop (struct TrafficGenerator *tg)
{
  GNUNET_CONTAINER_DLL_remove (tg_head, tg_tail, tg);
  tg->dest->tg = NULL;

  if (NULL != tg->send_task)
  {
    GNUNET_SCHEDULER_cancel (tg->send_task);
    tg->send_task = NULL;
  }
  if (top->test_core)
  {
    if (NULL != tg->dest->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (tg->dest->cth);
      tg->dest->cth = NULL;
    }
  }
  else
  {
    if (NULL != tg->dest->tth)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (tg->dest->tth);
      tg->dest->tth = NULL;
    }
  }
  GNUNET_free (tg);
}


/**
 * Stop all traffic generators
 */
void
GNUNET_ATS_TEST_generate_traffic_stop_all ()
{
  struct TrafficGenerator *cur;
  struct TrafficGenerator *next;
  next = tg_head;
  for (cur = next; NULL != cur; cur = next)
  {
      next = cur->next;
      GNUNET_ATS_TEST_generate_traffic_stop(cur);
  }
}

/* end of file ats-testing-traffic.c */

