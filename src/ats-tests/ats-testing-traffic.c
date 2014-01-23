/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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

static size_t
send_ping_ready_cb (void *cls, size_t size, void *buf)
{
  struct BenchmarkPartner *p = cls;
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct GNUNET_MessageHeader *msg;

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

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Master [%u]: Sending PING to [%u]\n",
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
  p->tg->next_ping_transmission = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(), p->tg->delta);

  return TEST_MESSAGE_SIZE;
}


static void
comm_schedule_send (void *cls,
    const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct BenchmarkPartner *p = cls;

  p->tg->send_task = GNUNET_SCHEDULER_NO_TASK;

  p->last_message_sent = GNUNET_TIME_absolute_get();
  if (GNUNET_YES == top->test_core)
  {
    p->cth = GNUNET_CORE_notify_transmit_ready (
      p->me->ch, GNUNET_NO, 0, GNUNET_TIME_UNIT_MINUTES, &p->dest->id,
      TEST_MESSAGE_SIZE, &send_ping_ready_cb, p);
  }
  else
  {
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (
      p->me->th, &p->dest->id, TEST_MESSAGE_SIZE, 0,GNUNET_TIME_UNIT_MINUTES,
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
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Slave [%u]: Received PING from [%u], sending PONG\n", p->me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  if (GNUNET_YES == top->test_core)
  {
    GNUNET_assert (NULL == p->cth);

    p->cth = GNUNET_CORE_notify_transmit_ready (p->me->ch, GNUNET_NO, 0,
        GNUNET_TIME_UNIT_MINUTES, &p->dest->id, TEST_MESSAGE_SIZE,
        &comm_send_pong_ready, p);
  }
  else
  {
    GNUNET_assert (NULL == p->tth);
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (p->me->th, &p->dest->id,
        TEST_MESSAGE_SIZE, 0, GNUNET_TIME_UNIT_MINUTES, &comm_send_pong_ready,
        p);
  }
}

void
GNUNET_ATS_TEST_traffic_handle_pong (struct BenchmarkPartner *p)
{
  struct GNUNET_TIME_Relative left;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Master [%u]: Received PONG from [%u], next message\n", p->me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;
  p->total_app_rtt += GNUNET_TIME_absolute_get_difference(p->last_message_sent,
      GNUNET_TIME_absolute_get()).rel_value_us;

  /* Schedule next send event */
  left = GNUNET_TIME_absolute_get_remaining(p->tg->next_ping_transmission);
  if (UINT32_MAX == p->tg->rate)
  {
    p->tg->send_task = GNUNET_SCHEDULER_add_now (&comm_schedule_send, p);
  }
  else if (0 == left.rel_value_us)
  {
    p->tg->send_task = GNUNET_SCHEDULER_add_now (&comm_schedule_send, p);
  }
  else
  {
    p->tg->send_task = GNUNET_SCHEDULER_add_delayed (left,
        &comm_schedule_send, p);
  }
}

/**
 * Generate between the source master and the partner and send traffic with a
 * maximum rate.
 *
 */

struct TrafficGenerator *
GNUNET_ATS_TEST_generate_traffic_start (struct BenchmarkPeer *src,
    struct BenchmarkPartner *dest,
    unsigned int rate,
    struct GNUNET_TIME_Relative duration)
{
  struct TrafficGenerator * tg;
  tg = NULL;

  if (NULL != dest->tg)
  {
    GNUNET_break (0);
    return NULL;
  }

  tg = GNUNET_new (struct TrafficGenerator);
  GNUNET_CONTAINER_DLL_insert (tg_head, tg_tail, tg);
  tg->src = src;
  tg->dest = dest;
  tg->rate = rate;
  if (UINT32_MAX == rate)
    tg->delta.rel_value_us = 0;
  else if (rate <= TEST_MESSAGE_SIZE)
    tg->delta.rel_value_us = (GNUNET_TIME_UNIT_SECONDS.rel_value_us);
  else
    tg->delta.rel_value_us = (GNUNET_TIME_UNIT_SECONDS.rel_value_us / (rate / TEST_MESSAGE_SIZE));
  tg->next_ping_transmission = GNUNET_TIME_UNIT_FOREVER_ABS;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
      "Setting up traffic generator master[%u] `%s' and slave [%u] `%s' max %u Bips\n",
      dest->me->no, GNUNET_i2s (&dest->me->id),
      dest->dest->no, GNUNET_i2s (&dest->dest->id),
      rate);

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

  if (GNUNET_SCHEDULER_NO_TASK != tg->send_task)
  {
    GNUNET_SCHEDULER_cancel (tg->send_task);
    tg->send_task = GNUNET_SCHEDULER_NO_TASK;
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

