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
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
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


/**
 * Struct containing information about manipulations to a specific peer
 */
struct TM_Peer
{
  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How long to delay incoming messages for this peer.
   */
  struct GNUNET_TIME_Relative delay_in;

  /**
   * How long to delay outgoing messages for this peer.
   */
  struct GNUNET_TIME_Relative delay_out;

  /**
   * Manipulated properties to use for this peer.
   */
  struct GNUNET_ATS_Properties properties;

  /**
   * Task to schedule delayed sendding
   */
  struct GNUNET_SCHEDULER_Task *send_delay_task;

  /**
   * Send queue DLL head
   */
  struct DelayQueueEntry *send_head;

  /**
   * Send queue DLL tail
   */
  struct DelayQueueEntry *send_tail;
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
   * Peer this entry is belonging to if (NULL == tmp): enqueued in
   * generic DLL and scheduled by generic_send_delay_task else:
   * enqueued in tmp->send_head and tmp->send_tail and scheduled by
   * tmp->send_delay_task
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

/**
 * Hashmap contain all peers currently manipulated
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * Inbound delay to apply to all peers.
 */
static struct GNUNET_TIME_Relative delay_in;

/**
 * Outbound delay to apply to all peers.
 */
static struct GNUNET_TIME_Relative delay_out;

/**
 * DLL head for delayed messages based on general delay
 */
static struct DelayQueueEntry *generic_dqe_head;

/**
 * DLL tail for delayed messages based on general delay
 */
static struct DelayQueueEntry *generic_dqe_tail;

/**
 * Task to schedule delayed sending based on general delay
 */
static struct GNUNET_SCHEDULER_Task *generic_send_delay_task;


/**
 * Set traffic metric to manipulate
 *
 * @param cls closure
 * @param client client sending message
 * @param message containing information
 */
void
GST_manipulation_set_metric (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  const struct TrafficMetricMessage *tm;
  static struct GNUNET_PeerIdentity zero;
  struct TM_Peer *tmp;

  tm = (const struct TrafficMetricMessage *) message;
  if (0 == memcmp (&tm->peer,
                   &zero,
                   sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received traffic metrics for all peers\n");
    delay_in = GNUNET_TIME_relative_ntoh (tm->delay_in);
    delay_out = GNUNET_TIME_relative_ntoh (tm->delay_out);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_OK);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received traffic metrics for peer `%s'\n",
              GNUNET_i2s(&tm->peer));
  if (NULL ==
      (tmp = GNUNET_CONTAINER_multipeermap_get (peers,
                                                &tm->peer)))
  {
    tmp = GNUNET_new (struct TM_Peer);
    tmp->peer = tm->peer;
    GNUNET_CONTAINER_multipeermap_put (peers,
                                       &tm->peer,
                                       tmp,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  GNUNET_ATS_properties_ntoh (&tmp->properties,
                              &tm->properties);
  tmp->delay_in = GNUNET_TIME_relative_ntoh (tm->delay_in);
  tmp->delay_out = GNUNET_TIME_relative_ntoh (tm->delay_out);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * We have delayed transmission, now it is time to send the
 * message.
 *
 * @param cls the `struct DelayQueueEntry` to transmit
 * @param tc unused
 */
static void
send_delayed (void *cls,
              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DelayQueueEntry *dqe = cls;
  struct DelayQueueEntry *next;
  struct TM_Peer *tmp = dqe->tmp;
  struct GNUNET_TIME_Relative delay;

  GNUNET_break (GNUNET_YES ==
                GST_neighbours_test_connected (&dqe->id));
  if (NULL != tmp)
  {
    tmp->send_delay_task = NULL;
    GNUNET_CONTAINER_DLL_remove (tmp->send_head,
                                 tmp->send_tail,
                                 dqe);
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
    generic_send_delay_task = NULL;
    GNUNET_CONTAINER_DLL_remove (generic_dqe_head,
                                 generic_dqe_tail,
                                 dqe);
    next = generic_dqe_head;
    if (NULL != next)
    {
      /* More delayed messages */
      delay = GNUNET_TIME_absolute_get_remaining(next->sent_at);
      generic_send_delay_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                              &send_delayed,
                                                              next);
    }
  }
  GST_neighbours_send (&dqe->id,
                       dqe->msg,
                       dqe->msg_size,
                       dqe->timeout,
                       dqe->cont,
                       dqe->cont_cls);
  GNUNET_free(dqe);
}


/**
 * Adapter function between transport's send function and transport plugins.
 * Delays message transmission if an artificial delay is configured.
 *
 * @param target the peer the message to send to
 * @param msg the message received
 * @param msg_size message size
 * @param timeout timeout
 * @param cont the continuation to call after sending
 * @param cont_cls cls for @a cont
 */
void
GST_manipulation_send (const struct GNUNET_PeerIdentity *target,
                       const void *msg,
                       size_t msg_size,
                       struct GNUNET_TIME_Relative timeout,
                       GST_NeighbourSendContinuation cont,
                       void *cont_cls)
{
  struct TM_Peer *tmp;
  struct DelayQueueEntry *dqe;
  struct GNUNET_TIME_Relative delay;

  if (NULL != (tmp =
               GNUNET_CONTAINER_multipeermap_get (peers,
                                                  target)))
    delay = tmp->delay_out;
  else
    delay = delay_out;
  if (0 == delay.rel_value_us)
  {
    /* Normal sending */
    GST_neighbours_send (target,
                         msg,
                         msg_size,
                         timeout,
                         cont, cont_cls);
    return;
  }
  dqe = GNUNET_malloc (sizeof (struct DelayQueueEntry) + msg_size);
  dqe->id = *target;
  dqe->tmp = tmp;
  dqe->sent_at = GNUNET_TIME_relative_to_absolute (delay);
  dqe->cont = cont;
  dqe->cont_cls = cont_cls;
  dqe->msg = &dqe[1];
  dqe->msg_size = msg_size;
  dqe->timeout = timeout;
  memcpy (dqe->msg,
          msg,
          msg_size);
  if (NULL == tmp)
  {
    GNUNET_CONTAINER_DLL_insert_tail (generic_dqe_head,
                                      generic_dqe_tail,
                                      dqe);
    if (NULL == generic_send_delay_task)
      generic_send_delay_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                              &send_delayed,
                                                              dqe);
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (tmp->send_head,
                                      tmp->send_tail,
                                      dqe);
    if (NULL == tmp->send_delay_task)
      tmp->send_delay_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                           &send_delayed,
                                                           dqe);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delaying %u byte message to peer `%s' with peer specific delay for %s\n",
              msg_size,
              GNUNET_i2s (target),
              GNUNET_STRINGS_relative_time_to_string (delay,
                                                      GNUNET_YES));
}


/**
 * Function that will be called to manipulate ATS information according to
 * current manipulation settings
 *
 * @param address binary address
 * @param session the session
 * @param prop[IN|OUT] metrics to modify
 */
void
GST_manipulation_manipulate_metrics (const struct GNUNET_HELLO_Address *address,
                                     struct Session *session,
                                     struct GNUNET_ATS_Properties *prop)
{
  const struct GNUNET_PeerIdentity *peer = &address->peer;
  struct TM_Peer *tmp;

  tmp = GNUNET_CONTAINER_multipeermap_get (peers,
                                           peer);
  if (NULL != tmp)
    *prop = tmp->properties;
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
  struct GNUNET_TIME_Relative quota_delay;
  struct GNUNET_TIME_Relative m_delay;

  if (NULL !=
      (tmp = GNUNET_CONTAINER_multipeermap_get (peers,
                                                &address->peer)))
    m_delay = tmp->delay_in;
  else
    m_delay = delay_in;

  quota_delay = GST_receive_callback (cls,
                                      address,
                                      session,
                                      message);
  m_delay = GNUNET_TIME_relative_max (m_delay,
                                      quota_delay);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delaying next receive for peer `%s' for %s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_STRINGS_relative_time_to_string (m_delay,
                                                      GNUNET_YES));
  return m_delay;
}


/**
 * Initialize traffic manipulation
 */
void
GST_manipulation_init ()
{
  struct GNUNET_TIME_Relative delay;

  if ( (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_time (GST_cfg,
                                             "transport",
                                             "MANIPULATE_DELAY_IN",
                                             &delay)) &&
       (delay.rel_value_us > 0) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Delaying inbound traffic for %s\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES));
    delay_in = delay;
  }
  if ( (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_time (GST_cfg,
                                             "transport",
                                             "MANIPULATE_DELAY_OUT",
                                             &delay)) &&
       (delay.rel_value_us > 0) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Delaying outbound traffic for %s\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES));
    delay_out = delay;
  }
  peers = GNUNET_CONTAINER_multipeermap_create (4,
                                                GNUNET_NO);
}


/**
 * Notify manipulation about disconnect so it can discard queued messages
 *
 * @param peer the disconnecting peer
 */
void
GST_manipulation_peer_disconnect (const struct GNUNET_PeerIdentity *peer)
{
  struct TM_Peer *tmp;
  struct DelayQueueEntry *dqe;
  struct DelayQueueEntry *next;

  tmp = GNUNET_CONTAINER_multipeermap_get (peers,
                                           peer);
  if (NULL != tmp)
  {
    while (NULL != (dqe = tmp->send_head))
    {
      GNUNET_CONTAINER_DLL_remove (tmp->send_head,
                                   tmp->send_tail,
                                   dqe);
      if (NULL != dqe->cont)
        dqe->cont (dqe->cont_cls,
                   GNUNET_SYSERR,
                   dqe->msg_size,
                   0);
      GNUNET_free(dqe);
    }
  }
  next = generic_dqe_head;
  while (NULL != (dqe = next))
  {
    next = dqe->next;
    if (0 == memcmp(peer, &dqe->id, sizeof(dqe->id)))
    {
      GNUNET_CONTAINER_DLL_remove (generic_dqe_head,
                                   generic_dqe_tail,
                                   dqe);
      if (NULL != dqe->cont)
        dqe->cont (dqe->cont_cls,
                   GNUNET_SYSERR,
                   dqe->msg_size,
                   0);
      GNUNET_free(dqe);
    }
  }
  if (NULL != generic_send_delay_task)
  {
    GNUNET_SCHEDULER_cancel (generic_send_delay_task);
    generic_send_delay_task = NULL;
    if (NULL != generic_dqe_head)
      generic_send_delay_task
        = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining(generic_dqe_head->sent_at),
                                        &send_delayed,
                                        generic_dqe_head);
  }
}


/**
 * Free manipulation information about a peer.
 *
 * @param cls NULL
 * @param key peer the info is about
 * @param value a `struct TM_Peer` to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_tmps (void *cls,
           const struct GNUNET_PeerIdentity *key,
           void *value)
{
  struct TM_Peer *tmp = value;
  struct DelayQueueEntry *dqe;

  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multipeermap_remove (peers,
                                                      key,
                                                      value));
  while (NULL != (dqe = tmp->send_head))
  {
    GNUNET_CONTAINER_DLL_remove (tmp->send_head,
                                 tmp->send_tail,
                                 dqe);
    if (NULL != dqe->cont)
      dqe->cont (dqe->cont_cls,
                 GNUNET_SYSERR,
                 dqe->msg_size,
                 0);
    GNUNET_free (dqe);
  }
  if (NULL != tmp->send_delay_task)
  {
    GNUNET_SCHEDULER_cancel (tmp->send_delay_task);
    tmp->send_delay_task = NULL;
  }
  GNUNET_free (tmp);
  return GNUNET_OK;
}


/**
 * Stop traffic manipulation
 */
void
GST_manipulation_stop ()
{
  struct DelayQueueEntry *cur;

  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &free_tmps,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (peers);
  peers = NULL;
  while (NULL != (cur = generic_dqe_head))
  {
    GNUNET_CONTAINER_DLL_remove (generic_dqe_head,
                                 generic_dqe_tail,
                                 cur);
    if (NULL != cur->cont)
      cur->cont (cur->cont_cls,
                 GNUNET_SYSERR,
                 cur->msg_size,
                 0);
    GNUNET_free (cur);
  }
  if (NULL != generic_send_delay_task)
  {
    GNUNET_SCHEDULER_cancel (generic_send_delay_task);
    generic_send_delay_task = NULL;
  }
}

/* end of file gnunet-service-transport_manipulation.c */
