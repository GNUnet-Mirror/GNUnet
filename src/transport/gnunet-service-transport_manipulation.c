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
 * @file transport/gnunet-service-transport_manipulation.c
 * @brief transport component manipulation traffic for simulation
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "transport.h"

enum TRAFFIC_METRIC_DIRECTION
{
  TM_SEND = 0, TM_RECEIVE = 1, TM_BOTH = 2
};

/**
 * Struct containing information about manipulations to a specific peer
 */
struct TM_Peer;

/**
 * Manipulation entry
 */
struct PropManipulationEntry
{
  /**
   * Next in DLL
   */
  struct PropManipulationEntry *next;

  /**
   * Previous in DLL
   */
  struct PropManipulationEntry *prev;

  /**
   * ATS type in HBO
   */
  uint32_t type;

  /**
   * Value in HBO
   */
  uint32_t metrics[TM_BOTH];

};

/**
 * Struct containing information about manipulations to a specific peer
 */
struct TM_Peer
{
  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity peer;

  struct PropManipulationEntry *head;
  struct PropManipulationEntry *tail;

  /**
   * Peer specific manipulation metrics
   */
  uint32_t metrics[TM_BOTH][GNUNET_ATS_QualityPropertiesCount];

  /**
   * Task to schedule delayed sendding
   */
  struct GNUNET_SCHEDULER_Task * send_delay_task;

  /**
   * Send queue DLL head
   */
  struct DelayQueueEntry *send_head;

  /**
   * Send queue DLL tail
   */
  struct DelayQueueEntry *send_tail;
};

struct GST_ManipulationHandle
{
  /**
   * Hashmap contain all peers currently manipulated
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peers;

  /**
   * Peer containing information for general manipulation
   */
  struct TM_Peer general;
};

/**
 * Entry in the delay queue for an outbound delayed message
 */
struct DelayQueueEntry
{
  /**
   * Next in DLL
   */
  struct DelayQueueEntry *prev;

  /**
   * Previous in DLL
   */
  struct DelayQueueEntry *next;

  /**
   * Peer this entry is belonging to
   * if (NULL == tmp): enqueued in generic DLL and scheduled by generic_send_delay_task
   * else: enqueued in tmp->send_head and tmp->send_tail and scheduled by tmp->send_delay_task
   */
  struct TM_Peer *tmp;

  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Absolute time when to send
   */
  struct GNUNET_TIME_Absolute sent_at;

  /**
   * The message
   */
  void *msg;

  /**
   * The message size
   */
  size_t msg_size;

  /**
   * Message timeout
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Transports send continuation
   */
  GST_NeighbourSendContinuation cont;

  /**
   * Transports send continuation cls
   */
  void *cont_cls;
};

struct GST_ManipulationHandle man_handle;

/**
 * DLL head for delayed messages based on general delay
 */
struct DelayQueueEntry *generic_dqe_head;

/**
 * DLL tail for delayed messages based on general delay
 */
struct DelayQueueEntry *generic_dqe_tail;

/**
 * Task to schedule delayed sending based on general delay
 */
struct GNUNET_SCHEDULER_Task * generic_send_delay_task;

static void
set_metric(struct TM_Peer *dest, int direction, uint32_t type, uint32_t value)
{
  struct PropManipulationEntry *cur;
  for (cur = dest->head; NULL != cur; cur = cur->next)
    {
      if (cur->type == type)
        break;
    }
  if (NULL == cur)
    {
      cur = GNUNET_new (struct PropManipulationEntry);
      GNUNET_CONTAINER_DLL_insert(dest->head, dest->tail, cur);
      cur->type = type;
      cur->metrics[TM_SEND] = UINT32_MAX;
      cur->metrics[TM_RECEIVE] = UINT32_MAX;
    }

  switch (direction)
    {
  case TM_BOTH:
    cur->metrics[TM_SEND] = value;
    cur->metrics[TM_RECEIVE] = value;
    break;
  case TM_SEND:
    cur->metrics[TM_SEND] = value;
    break;
  case TM_RECEIVE:
    cur->metrics[TM_RECEIVE] = value;
    break;
  default:
    break;
    }

}

static uint32_t
find_metric(struct TM_Peer *dest, uint32_t type, int direction)
{
  struct PropManipulationEntry *cur;

  for (cur = dest->head; NULL != cur; cur = cur->next)
    {
      if (cur->type == type)
        return cur->metrics[direction];

    }
  return UINT32_MAX;
}

/**
 * Clean up metrics for a peer
 */

static void
free_metric(struct TM_Peer *dest)
{
  struct PropManipulationEntry *cur;
  struct PropManipulationEntry *next;

  for (cur = dest->head; NULL != cur; cur = next)
    {
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove(dest->head, dest->tail, cur);
      GNUNET_free(cur);
    }
}

/**
 * Set traffic metric to manipulate
 *
 * @param cls closure
 * @param client client sending message
 * @param message containing information
 */
void
GST_manipulation_set_metric(void *cls, struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
  struct TrafficMetricMessage *tm = (struct TrafficMetricMessage *) message;
  struct GNUNET_PeerIdentity dummy;
  struct GNUNET_ATS_Information *ats;
  struct TM_Peer *tmp;
  uint32_t type;
  uint32_t value;
  uint16_t direction;
  int c;
  int c2;

  if (0 == ntohs(tm->ats_count))
    GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);

  direction = TM_BOTH;
  switch (ntohs(tm->direction))
    {
  case 1:
    direction = TM_SEND;
    break;
  case 2:
    direction = TM_RECEIVE;
    break;
  case 3:
    direction = TM_BOTH;
    break;
  default:
    break;
    }

  memset(&dummy, '\0', sizeof(struct GNUNET_PeerIdentity));
  if (0 == memcmp(&tm->peer, &dummy, sizeof(struct GNUNET_PeerIdentity)))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Received traffic metrics for all peers \n");

      ats = (struct GNUNET_ATS_Information *) &tm[1];
      for (c = 0; c < ntohs(tm->ats_count); c++)
        {
          type = htonl(ats[c].type);
          value = htonl(ats[c].value);
          set_metric(&man_handle.general, direction, type, value);
        }
      return;
    }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Received traffic metrics for peer `%s'\n", GNUNET_i2s(&tm->peer));

  if (NULL
      == (tmp = GNUNET_CONTAINER_multipeermap_get(man_handle.peers, &tm->peer)))
    {
      tmp = GNUNET_new (struct TM_Peer);
      tmp->peer = (tm->peer);
      for (c = 0; c < TM_BOTH; c++)
        {
          for (c2 = 0; c2 < GNUNET_ATS_QualityPropertiesCount; c2++)
            {
              tmp->metrics[c][c2] = UINT32_MAX;
            }
        }
      GNUNET_CONTAINER_multipeermap_put(man_handle.peers, &tm->peer, tmp,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }

  ats = (struct GNUNET_ATS_Information *) &tm[1];
  for (c = 0; c < ntohs(tm->ats_count); c++)
    {
      type = htonl(ats[c].type);
      value = htonl(ats[c].value);
      set_metric(tmp, direction, type, value);
    }

  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

static void
send_delayed(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DelayQueueEntry *dqe = cls;
  struct DelayQueueEntry *next;
  struct TM_Peer *tmp = dqe->tmp;
  struct GNUNET_TIME_Relative delay;

  if (NULL != tmp)
    {
      GNUNET_break(GNUNET_YES == GST_neighbours_test_connected (&dqe->id));
      tmp->send_delay_task = NULL;
      GNUNET_CONTAINER_DLL_remove(tmp->send_head, tmp->send_tail, dqe);
      GST_neighbours_send(&dqe->id, dqe->msg, dqe->msg_size, dqe->timeout,
          dqe->cont, dqe->cont_cls);

      next = tmp->send_head;
      if (NULL != next)
        {
          /* More delayed messages */
          delay = GNUNET_TIME_absolute_get_remaining(next->sent_at);
          tmp->send_delay_task = GNUNET_SCHEDULER_add_delayed(delay,
              &send_delayed, next);
        }
    }
  else
    {
      /* Remove from generic queue */
      GNUNET_break(GNUNET_YES == GST_neighbours_test_connected (&dqe->id));
      generic_send_delay_task = NULL;
      GNUNET_CONTAINER_DLL_remove(generic_dqe_head, generic_dqe_tail, dqe);
      GST_neighbours_send(&dqe->id, dqe->msg, dqe->msg_size, dqe->timeout,
          dqe->cont, dqe->cont_cls);
      next = generic_dqe_head;
      if (NULL != next)
        {
          /* More delayed messages */
          delay = GNUNET_TIME_absolute_get_remaining(next->sent_at);
          generic_send_delay_task = GNUNET_SCHEDULER_add_delayed(delay,
              &send_delayed, next);
        }
    }
  GNUNET_free(dqe);
}

/**
 * Adapter function between transport's send function and transport plugins
 *
 * @param target the peer the message to send to
 * @param msg the message received
 * @param msg_size message size
 * @param timeout timeout
 * @param cont the continuation to call after sending
 * @param cont_cls cls for continuation
 */
void
GST_manipulation_send(const struct GNUNET_PeerIdentity *target, const void *msg,
    size_t msg_size, struct GNUNET_TIME_Relative timeout,
    GST_NeighbourSendContinuation cont, void *cont_cls)
{
  struct TM_Peer *tmp;
  struct DelayQueueEntry *dqe;
  struct GNUNET_TIME_Relative delay;

  if (NULL
      != (tmp = GNUNET_CONTAINER_multipeermap_get(man_handle.peers, target)))
    {
      GNUNET_break(GNUNET_YES == GST_neighbours_test_connected(target));
      /* Manipulate here */
      /* Delay */
      if (UINT32_MAX != find_metric(tmp, GNUNET_ATS_QUALITY_NET_DELAY, TM_SEND))
        {
          /* We have a delay */
          delay.rel_value_us = find_metric(tmp, GNUNET_ATS_QUALITY_NET_DELAY,
              TM_SEND);
          dqe = GNUNET_malloc (sizeof (struct DelayQueueEntry) + msg_size);
          dqe->id = *target;
          dqe->tmp = tmp;
          dqe->sent_at = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(),
              delay);
          dqe->cont = cont;
          dqe->cont_cls = cont_cls;
          dqe->msg = &dqe[1];
          dqe->msg_size = msg_size;
          dqe->timeout = timeout;
          memcpy(dqe->msg, msg, msg_size);
          GNUNET_CONTAINER_DLL_insert_tail(tmp->send_head, tmp->send_tail, dqe);
          if (NULL == tmp->send_delay_task)
            tmp->send_delay_task = GNUNET_SCHEDULER_add_delayed(delay,
                &send_delayed, dqe);
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
              "Delaying %u byte message to peer `%s' with generic delay for %ms\n", msg_size, GNUNET_i2s (target), GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
          return;
        }
    }
  else if (UINT32_MAX
      != find_metric(&man_handle.general, GNUNET_ATS_QUALITY_NET_DELAY,
          TM_SEND))
    {
      GNUNET_break(GNUNET_YES == GST_neighbours_test_connected(target));
      /* We have a delay */
      delay.rel_value_us = find_metric(&man_handle.general,
          GNUNET_ATS_QUALITY_NET_DELAY, TM_SEND);
      dqe = GNUNET_malloc (sizeof (struct DelayQueueEntry) + msg_size);
      dqe->id = *target;
      dqe->tmp = NULL;
      dqe->sent_at = GNUNET_TIME_absolute_add(GNUNET_TIME_absolute_get(),
          delay);
      dqe->cont = cont;
      dqe->cont_cls = cont_cls;
      dqe->msg = &dqe[1];
      dqe->msg_size = msg_size;
      dqe->timeout = timeout;
      memcpy(dqe->msg, msg, msg_size);
      GNUNET_CONTAINER_DLL_insert_tail(generic_dqe_head, generic_dqe_tail, dqe);
      if (NULL == generic_send_delay_task)
        {
          generic_send_delay_task = GNUNET_SCHEDULER_add_delayed(delay,
              &send_delayed, dqe);
        }
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Delaying %u byte message to peer `%s' with peer specific delay for %s\n", msg_size, GNUNET_i2s (target), GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
      return;
    }

  /* Normal sending */
  GST_neighbours_send(target, msg, msg_size, timeout, cont, cont_cls);
}

/**
 * Function that will be called to manipulate ATS information according to
 * current manipulation settings
 *
 * @param peer the peer
 * @param address binary address
 * @param session the session
 * @param ats the ats information
 * @param ats_count the number of ats information
 */
struct GNUNET_ATS_Information *
GST_manipulation_manipulate_metrics(const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address, struct Session *session,
    const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct GNUNET_ATS_Information *ats_new =
      GNUNET_malloc (sizeof (struct GNUNET_ATS_Information) *ats_count);
  struct TM_Peer *tmp;
  uint32_t m_tmp;
  uint32_t g_tmp;
  int d;
  tmp = GNUNET_CONTAINER_multipeermap_get(man_handle.peers, peer);

  for (d = 0; d < ats_count; d++)
    {
      ats_new[d] = ats[d];
      m_tmp = UINT32_MAX;
      if (NULL != tmp)
        m_tmp = find_metric(tmp, ntohl(ats[d].type), TM_RECEIVE);
      g_tmp = find_metric(&man_handle.general, ntohl(ats[d].type), TM_RECEIVE);

      if (UINT32_MAX != g_tmp)
        ats_new[d].value = htonl(g_tmp);
      if (UINT32_MAX != m_tmp)
        ats_new[d].value = htonl(m_tmp);
    }

  return ats_new;
}

/**
 * Adapter function between transport plugins and transport receive function
 * manipulation delays for next send.
 *
 * @param cls the closure for transport
 * @param address the address and the peer the message was received from
 * @param message the message received
 * @param session the session the message was received on
 * @return manipulated delay for next receive
 */
struct GNUNET_TIME_Relative
GST_manipulation_recv (void *cls,
    const struct GNUNET_HELLO_Address *address,
    struct Session *session,
    const struct GNUNET_MessageHeader *message)
{
  struct TM_Peer *tmp;
  uint32_t p_recv_delay;
  uint32_t g_recv_delay;
  struct GNUNET_TIME_Relative quota_delay;
  struct GNUNET_TIME_Relative m_delay;

  g_recv_delay = find_metric(&man_handle.general, GNUNET_ATS_QUALITY_NET_DELAY,
      TM_RECEIVE);
  if ((g_recv_delay >= GNUNET_TIME_UNIT_ZERO.rel_value_us)
      && (UINT32_MAX != g_recv_delay))
    m_delay.rel_value_us = g_recv_delay; /* Global delay */
  else
    m_delay = GNUNET_TIME_UNIT_ZERO;

  if (NULL != (tmp = GNUNET_CONTAINER_multipeermap_get(man_handle.peers, &address->peer)))
    {
      /* Manipulate receive delay */
      p_recv_delay = find_metric(tmp, GNUNET_ATS_QUALITY_NET_DELAY, TM_RECEIVE);
      if (UINT32_MAX != p_recv_delay)
        m_delay.rel_value_us = p_recv_delay; /* Peer specific delay */
    }

  quota_delay = GST_receive_callback(cls, address, session, message);

  if (quota_delay.rel_value_us > m_delay.rel_value_us)
    m_delay = quota_delay;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Delaying next receive for peer `%s' for %s\n",
      GNUNET_i2s (&address->peer),
      GNUNET_STRINGS_relative_time_to_string (m_delay, GNUNET_YES));
  return m_delay;

}

/**
 * Initialize traffic manipulation
 *
 * @param GST_cfg configuration handle
 */
void
GST_manipulation_init(const struct GNUNET_CONFIGURATION_Handle *GST_cfg)
{
  unsigned long long tmp;
  struct GNUNET_TIME_Relative delay;

  if ((GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_number(GST_cfg, "transport",
          "MANIPULATE_DISTANCE_IN", &tmp)) && (tmp > 0))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Setting inbound distance_in to %llu\n", (unsigned long long) tmp);
      set_metric(&man_handle.general, TM_RECEIVE,
          GNUNET_ATS_QUALITY_NET_DISTANCE, tmp);
    }

  if ((GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_number(GST_cfg, "transport",
          "MANIPULATE_DISTANCE_OUT", &tmp)) && (tmp > 0))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Setting outbound distance_in to %llu\n", (unsigned long long) tmp);
      set_metric(&man_handle.general, TM_SEND, GNUNET_ATS_QUALITY_NET_DISTANCE,
          tmp);
    }

  if ((GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_time(GST_cfg, "transport",
          "MANIPULATE_DELAY_IN", &delay)) && (delay.rel_value_us > 0))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Delaying inbound traffic for %s\n", GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
      set_metric(&man_handle.general, TM_RECEIVE, GNUNET_ATS_QUALITY_NET_DELAY,
          delay.rel_value_us);
    }
  if ((GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_time(GST_cfg, "transport",
          "MANIPULATE_DELAY_OUT", &delay)) && (delay.rel_value_us > 0))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Delaying outbound traffic for %s\n", GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
      set_metric(&man_handle.general, TM_SEND, GNUNET_ATS_QUALITY_NET_DELAY,
          delay.rel_value_us);
    }
  man_handle.peers = GNUNET_CONTAINER_multipeermap_create(10, GNUNET_NO);
}

static int
free_tmps(void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct DelayQueueEntry *dqe;
  struct DelayQueueEntry *next;

  if (NULL != value)
    {
      struct TM_Peer *tmp = (struct TM_Peer *) value;

      if (GNUNET_YES
          != GNUNET_CONTAINER_multipeermap_remove(man_handle.peers, key, value))
        GNUNET_break(0);
      free_metric(tmp);
      next = tmp->send_head;
      while (NULL != (dqe = next))
        {
          next = dqe->next;
          GNUNET_CONTAINER_DLL_remove(tmp->send_head, tmp->send_tail, dqe);
          if (NULL != dqe->cont)
            dqe->cont(dqe->cont_cls, GNUNET_SYSERR, dqe->msg_size, 0);
          GNUNET_free(dqe);
        }
      if (NULL != tmp->send_delay_task)
        {
          GNUNET_SCHEDULER_cancel(tmp->send_delay_task);
          tmp->send_delay_task = NULL;
        }
      GNUNET_free(tmp);
    }
  return GNUNET_OK;
}

/**
 * Notify manipulation about disconnect so it can discard queued messages
 *
 * @param peer the disconnecting peer
 */
void
GST_manipulation_peer_disconnect(const struct GNUNET_PeerIdentity *peer)
{
  struct TM_Peer *tmp;
  struct DelayQueueEntry *dqe;
  struct DelayQueueEntry *next;

  if (NULL != (tmp = GNUNET_CONTAINER_multipeermap_get(man_handle.peers, peer)))
    {
      next = tmp->send_head;
      while (NULL != (dqe = next))
        {
          next = dqe->next;
          GNUNET_CONTAINER_DLL_remove(tmp->send_head, tmp->send_tail, dqe);
          if (NULL != dqe->cont)
            dqe->cont(dqe->cont_cls, GNUNET_SYSERR, dqe->msg_size, 0);
          GNUNET_free(dqe);
        }
    }
  else if (UINT32_MAX
      != find_metric(&man_handle.general, GNUNET_ATS_QUALITY_NET_DELAY,
          TM_SEND))
    {
      next = generic_dqe_head;
      while (NULL != (dqe = next))
        {
          next = dqe->next;
          if (0 == memcmp(peer, &dqe->id, sizeof(dqe->id)))
            {
              GNUNET_CONTAINER_DLL_remove(generic_dqe_head, generic_dqe_tail,
                  dqe);
              if (NULL != dqe->cont)
                dqe->cont(dqe->cont_cls, GNUNET_SYSERR, dqe->msg_size, 0);
              GNUNET_free(dqe);
            }
        }
      if (NULL != generic_send_delay_task)
        {
          GNUNET_SCHEDULER_cancel(generic_send_delay_task);
          generic_send_delay_task = NULL;
          if (NULL != generic_dqe_head)
            generic_send_delay_task = GNUNET_SCHEDULER_add_delayed(
                GNUNET_TIME_absolute_get_remaining(generic_dqe_head->sent_at),
                &send_delayed, generic_dqe_head);
        }
    }
}

/**
 * Stop traffic manipulation
 */
void
GST_manipulation_stop()
{
  struct DelayQueueEntry *cur;
  struct DelayQueueEntry *next;
  GNUNET_CONTAINER_multipeermap_iterate(man_handle.peers, &free_tmps, NULL);
  GNUNET_CONTAINER_multipeermap_destroy(man_handle.peers);

  next = generic_dqe_head;
  while (NULL != (cur = next))
    {
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove(generic_dqe_head, generic_dqe_tail, cur);
      if (NULL != cur->cont)
        cur->cont(cur->cont_cls, GNUNET_SYSERR, cur->msg_size, 0);
      GNUNET_free(cur);
    }
  if (NULL != generic_send_delay_task)
    {
      GNUNET_SCHEDULER_cancel(generic_send_delay_task);
      generic_send_delay_task = NULL;
    }

  free_metric(&man_handle.general);
  man_handle.peers = NULL;
}

/* end of file gnunet-service-transport_manipulation.c */
