/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013, 2016 GNUnet e.V.

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
              "Current rate is %lld, calculated delay is %llu\n",
              cur_rate,
              (unsigned long long) delay.rel_value_us);
  return delay;
}


static void
update_ping_data (void *cls)
{
  struct BenchmarkPartner *p = cls;
  struct GNUNET_TIME_Relative delay;

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  if (NULL == p->tg)
  {
    GNUNET_break (0);
    return;
  }
  delay = get_delay (p->tg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Delay for next transmission %s\n",
	      GNUNET_STRINGS_relative_time_to_string (delay,
						      GNUNET_YES));
  p->tg->next_ping_transmission
    = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
				delay);
}


static void
comm_schedule_send (void *cls)
{
  struct BenchmarkPartner *p = cls;
  struct TestMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  p->tg->send_task = NULL;
  p->last_message_sent = GNUNET_TIME_absolute_get();
  env = GNUNET_MQ_msg (msg,
		       TEST_MESSAGE_TYPE_PING);
  memset (msg->padding,
	  'a',
	  sizeof (msg->padding));
  GNUNET_MQ_notify_sent (env,
			 &update_ping_data,
			 p);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Master [%u]: Sending PING to [%u]\n",
	      p->me->no,
	      p->dest->no);
  GNUNET_MQ_send (p->mq,
		  env);
}


static void
update_pong_data (void *cls)
{
  struct BenchmarkPartner *p = cls;

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;
}


void
GNUNET_ATS_TEST_traffic_handle_ping (struct BenchmarkPartner *p)
{
  struct TestMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Slave [%u]: Received PING from [%u], sending PONG\n",
	      p->me->no,
	      p->dest->no);
  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  
  env = GNUNET_MQ_msg (msg,
		       TEST_MESSAGE_TYPE_PING);
  memset (msg->padding,
	  'a',
	  sizeof (msg->padding));
  GNUNET_MQ_notify_sent (env,
			 &update_pong_data,
			 p);
  GNUNET_MQ_send (p->mq,
		  env);
}


void
GNUNET_ATS_TEST_traffic_handle_pong (struct BenchmarkPartner *p)
{
  struct GNUNET_TIME_Relative left;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Master [%u]: Received PONG from [%u], next message\n",
	      p->me->no,
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
                                        unsigned int base_rate,
                                        unsigned int max_rate,
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
  GNUNET_CONTAINER_DLL_insert (tg_head,
			       tg_tail,
			       tg);
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
		dest->me->no,
		GNUNET_i2s (&dest->me->id),
		dest->dest->no,
		GNUNET_i2s (&dest->dest->id),
		base_rate);
    break;
  case GNUNET_ATS_TEST_TG_LINEAR:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Setting up linear traffic generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bips\n",
		dest->me->no,
		GNUNET_i2s (&dest->me->id),
		dest->dest->no,
		GNUNET_i2s (&dest->dest->id),
		base_rate,
		max_rate);
    break;
  case GNUNET_ATS_TEST_TG_SINUS:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Setting up sinus traffic generator master[%u] `%s' and slave [%u] `%s' baserate %u Bips, amplitude %u Bps\n",
		dest->me->no,
		GNUNET_i2s (&dest->me->id),
		dest->dest->no,
		GNUNET_i2s (&dest->dest->id),
		base_rate,
		max_rate);
    break;
  case GNUNET_ATS_TEST_TG_RANDOM:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Setting up random traffic generator master[%u] `%s' and slave [%u] `%s' min %u Bips max %u Bps\n",
		dest->me->no,
		GNUNET_i2s (&dest->me->id),
		dest->dest->no,
		GNUNET_i2s (&dest->dest->id),
		base_rate,
		max_rate);
      break;
    default:
      break;
  }

  dest->tg = tg;
  tg->send_task
    = GNUNET_SCHEDULER_add_now (&comm_schedule_send,
				dest);
  return tg;
}


void
GNUNET_ATS_TEST_generate_traffic_stop (struct TrafficGenerator *tg)
{
  GNUNET_CONTAINER_DLL_remove (tg_head,
			       tg_tail,
			       tg);
  tg->dest->tg = NULL;
  if (NULL != tg->send_task)
  {
    GNUNET_SCHEDULER_cancel (tg->send_task);
    tg->send_task = NULL;
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
