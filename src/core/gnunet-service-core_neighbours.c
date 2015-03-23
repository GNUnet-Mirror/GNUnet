/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_neighbours.c
 * @brief code for managing low-level 'plaintext' connections with transport (key exchange may or may not be done yet)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_neighbours.h"
#include "gnunet-service-core_kx.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet_constants.h"


/**
 * Message ready for transmission via transport service.  This struct
 * is followed by the actual content of the message.
 */
struct NeighbourMessageEntry
{

  /**
   * We keep messages in a doubly linked list.
   */
  struct NeighbourMessageEntry *next;

  /**
   * We keep messages in a doubly linked list.
   */
  struct NeighbourMessageEntry *prev;

  /**
   * By when are we supposed to transmit this message?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How long is the message? (number of bytes following the "struct
   * MessageEntry", but not including the size of "struct
   * MessageEntry" itself!)
   */
  size_t size;

};


/**
 * Data kept per transport-connected peer.
 */
struct Neighbour
{

  /**
   * Head of the batched message queue (already ordered, transmit
   * starting with the head).
   */
  struct NeighbourMessageEntry *message_head;

  /**
   * Tail of the batched message queue (already ordered, append new
   * messages to tail).
   */
  struct NeighbourMessageEntry *message_tail;

  /**
   * Handle for pending requests for transmission to this peer
   * with the transport service.  NULL if no request is pending.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *th;

  /**
   * Information about the key exchange with the other peer.
   */
  struct GSC_KeyExchangeInfo *kxinfo;

  /**
   * Identity of the other peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * ID of task used for re-trying plaintext scheduling.
   */
  struct GNUNET_SCHEDULER_Task *retry_plaintext_task;

  /**
   * How many messages are in the queue for this neighbour?
   */
  unsigned int queue_size;

  /**
   * #GNUNET_YES if this peer currently has excess bandwidth.
   */
  int has_excess_bandwidth;

};


/**
 * Map of peer identities to 'struct Neighbour'.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *neighbours;

/**
 * Transport service.
 */
static struct GNUNET_TRANSPORT_Handle *transport;


/**
 * Find the entry for the given neighbour.
 *
 * @param peer identity of the neighbour
 * @return NULL if we are not connected, otherwise the
 *         neighbour's entry.
 */
static struct Neighbour *
find_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  if (NULL == neighbours)
    return NULL;
  return GNUNET_CONTAINER_multipeermap_get (neighbours, peer);
}


/**
 * Free the given entry for the neighbour.
 *
 * @param n neighbour to free
 */
static void
free_neighbour (struct Neighbour *n)
{
  struct NeighbourMessageEntry *m;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying neighbour entry for peer `%4s'\n",
              GNUNET_i2s (&n->peer));
  while (NULL != (m = n->message_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->message_head,
                                 n->message_tail,
                                 m);
    n->queue_size--;
    GNUNET_free (m);
  }
  GNUNET_assert (0 == n->queue_size);
  if (NULL != n->th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (n->th);
    n->th = NULL;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop
                            ("# sessions terminated by transport disconnect"),
                            1, GNUNET_NO);
  if (NULL != n->kxinfo)
  {
    GSC_KX_stop (n->kxinfo);
    n->kxinfo = NULL;
  }
  if (NULL != n->retry_plaintext_task)
  {
    GNUNET_SCHEDULER_cancel (n->retry_plaintext_task);
    n->retry_plaintext_task = NULL;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (neighbours,
                                                       &n->peer, n));
  GNUNET_STATISTICS_set (GSC_stats,
                         gettext_noop ("# neighbour entries allocated"),
                         GNUNET_CONTAINER_multipeermap_size (neighbours),
                         GNUNET_NO);
  GNUNET_free (n);
}


/**
 * Check if we have encrypted messages for the specified neighbour
 * pending, and if so, check with the transport about sending them
 * out.
 *
 * @param n neighbour to check.
 */
static void
process_queue (struct Neighbour *n);


/**
 * Function called when the transport service is ready to receive a
 * message for the respective peer
 *
 * @param cls neighbour to use message from
 * @param size number of bytes we can transmit
 * @param buf where to copy the message
 * @return number of bytes transmitted
 */
static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct Neighbour *n = cls;
  struct NeighbourMessageEntry *m;
  size_t ret;
  char *cbuf;

  n->th = NULL;
  m = n->message_head;
  if (NULL == m)
  {
    GNUNET_break (0);
    return 0;
  }
  GNUNET_CONTAINER_DLL_remove (n->message_head,
                               n->message_tail,
                               m);
  n->queue_size--;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmission of message of type %u and size %u failed\n",
                (unsigned int)
                ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                (unsigned int) m->size);
    GNUNET_free (m);
    process_queue (n);
    return 0;
  }
  cbuf = buf;
  GNUNET_assert (size >= m->size);
  memcpy (cbuf, &m[1], m->size);
  ret = m->size;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Copied message of type %u and size %u into transport buffer for `%4s'\n",
              (unsigned int)
              ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
              (unsigned int) ret, GNUNET_i2s (&n->peer));
  GNUNET_free (m);
  n->has_excess_bandwidth = GNUNET_NO;
  process_queue (n);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop
                            ("# encrypted bytes given to transport"), ret,
                            GNUNET_NO);
  return ret;
}


/**
 * Check if we have messages for the specified neighbour pending, and
 * if so, check with the transport about sending them out.
 *
 * @param n neighbour to check.
 */
static void
process_queue (struct Neighbour *n)
{
  struct NeighbourMessageEntry *m;

  if (NULL != n->th)
    return;                     /* request already pending */
  m = n->message_head;
  if (NULL == m)
  {
    /* notify sessions that the queue is empty and more messages
     * could thus be queued now */
    GSC_SESSIONS_solicit (&n->peer);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport for transmission of %u bytes to `%4s' in next %s\n",
              (unsigned int) m->size,
              GNUNET_i2s (&n->peer),
              GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (m->deadline),
                                                      GNUNET_NO));
  n->th
    = GNUNET_TRANSPORT_notify_transmit_ready (transport,
                                              &n->peer,
                                              m->size,
                                              GNUNET_TIME_absolute_get_remaining (m->deadline),
                                              &transmit_ready,
                                              n);
  if (NULL != n->th)
    return;
  /* message request too large or duplicate request */
  GNUNET_break (0);
  /* discard encrypted message */
  GNUNET_CONTAINER_DLL_remove (n->message_head,
                               n->message_tail,
                               m);
  n->queue_size--;
  GNUNET_free (m);
  process_queue (n);
}


/**
 * Function called by transport to notify us that
 * a peer connected to us (on the network level).
 *
 * @param cls closure
 * @param peer the peer that connected
 */
static void
handle_transport_notify_connect (void *cls,
                                 const struct GNUNET_PeerIdentity *peer)
{
  struct Neighbour *n;

  if (0 == memcmp (peer,
                   &GSC_my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return;
  }
  n = find_neighbour (peer);
  if (n != NULL)
  {
    /* duplicate connect notification!? */
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received connection from `%4s'.\n",
              GNUNET_i2s (peer));
  n = GNUNET_new (struct Neighbour);
  n->peer = *peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (neighbours,
                                                    &n->peer, n,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (GSC_stats,
                         gettext_noop ("# neighbour entries allocated"),
                         GNUNET_CONTAINER_multipeermap_size (neighbours),
                         GNUNET_NO);
  n->kxinfo = GSC_KX_start (peer);
}


/**
 * Function called by transport telling us that a peer
 * disconnected.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
handle_transport_notify_disconnect (void *cls,
                                    const struct GNUNET_PeerIdentity *peer)
{
  struct Neighbour *n;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected from us; received notification from transport.\n",
              GNUNET_i2s (peer));
  n = find_neighbour (peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  free_neighbour (n);
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 */
static void
handle_transport_receive (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message)
{
  struct Neighbour *n;
  uint16_t type;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %u from `%4s', demultiplexing.\n",
              (unsigned int) ntohs (message->type), GNUNET_i2s (peer));
  if (0 == memcmp (peer, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return;
  }
  n = find_neighbour (peer);
  if (n == NULL)
  {
    /* received message from peer that is not connected!? */
    GNUNET_break (0);
    return;
  }
  type = ntohs (message->type);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_CORE_EPHEMERAL_KEY:
    GSC_KX_handle_ephemeral_key (n->kxinfo, message);
    break;
  case GNUNET_MESSAGE_TYPE_CORE_PING:
    GSC_KX_handle_ping (n->kxinfo, message);
    break;
  case GNUNET_MESSAGE_TYPE_CORE_PONG:
    GSC_KX_handle_pong (n->kxinfo, message);
    break;
  case GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE:
    GSC_KX_handle_encrypted_message (n->kxinfo, message);
    break;
  case GNUNET_MESSAGE_TYPE_DUMMY:
    /*  Dummy messages for testing / benchmarking, just discard */
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Unsupported message of type %u (%u bytes) received from peer `%s'\n"),
                (unsigned int) type,
                (unsigned int) ntohs (message->size),
                GNUNET_i2s (peer));
    return;
  }
}


/**
 * Transmit the given message to the given target.
 *
 * @param target peer that should receive the message (must be connected)
 * @param msg message to transmit
 * @param timeout by when should the transmission be done?
 */
void
GSC_NEIGHBOURS_transmit (const struct GNUNET_PeerIdentity *target,
                         const struct GNUNET_MessageHeader *msg,
                         struct GNUNET_TIME_Relative timeout)
{
  struct NeighbourMessageEntry *me;
  struct Neighbour *n;
  size_t msize;

  n = find_neighbour (target);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  msize = ntohs (msg->size);
  me = GNUNET_malloc (sizeof (struct NeighbourMessageEntry) + msize);
  me->deadline = GNUNET_TIME_relative_to_absolute (timeout);
  me->size = msize;
  memcpy (&me[1],
          msg,
          msize);
  GNUNET_CONTAINER_DLL_insert_tail (n->message_head,
                                    n->message_tail,
                                    me);
  n->queue_size++;
  process_queue (n);
}


/**
 * One of our neighbours has excess bandwidth,
 * remember this.
 *
 * @param cls NULL
 * @param pid identity of the peer with excess bandwidth
 */
static void
handle_transport_notify_excess_bw (void *cls,
                                   const struct GNUNET_PeerIdentity *pid)
{
  struct Neighbour *n;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %s has excess bandwidth available\n",
              GNUNET_i2s (pid));
  n = find_neighbour (pid);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  n->has_excess_bandwidth = GNUNET_YES;
  GSC_SESSIONS_solicit (pid);
}


/**
 * Check how many messages are queued for the given neighbour.
 *
 * @param target neighbour to check
 * @return number of items in the message queue
 */
unsigned int
GSC_NEIGHBOURS_get_queue_size (const struct GNUNET_PeerIdentity *target)
{
  struct Neighbour *n;

  n = find_neighbour (target);
  if (NULL == n)
  {
    GNUNET_break (0);
    return UINT_MAX;
  }
  return n->queue_size;
}


/**
 * Check if the given neighbour has excess bandwidth available.
 *
 * @param target neighbour to check
 * @return #GNUNET_YES if excess bandwidth is available, #GNUNET_NO if not
 */
int
GSC_NEIGHBOURS_check_excess_bandwidth (const struct GNUNET_PeerIdentity *target)
{
  struct Neighbour *n;

  n = find_neighbour (target);
  if (NULL == n)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return n->has_excess_bandwidth;
}


/**
 * Initialize neighbours subsystem.
 */
int
GSC_NEIGHBOURS_init ()
{
  neighbours = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  transport =
      GNUNET_TRANSPORT_connect2 (GSC_cfg, &GSC_my_identity, NULL,
                                 &handle_transport_receive,
                                 &handle_transport_notify_connect,
                                 &handle_transport_notify_disconnect,
                                 &handle_transport_notify_excess_bw);
  if (NULL == transport)
  {
    GNUNET_CONTAINER_multipeermap_destroy (neighbours);
    neighbours = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Wrapper around 'free_neighbour'.
 *
 * @param cls unused
 * @param key peer identity
 * @param value the `struct Neighbour` to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_neighbour_helper (void *cls,
		       const struct GNUNET_PeerIdentity * key,
		       void *value)
{
  struct Neighbour *n = value;

  /* transport should have 'disconnected' all neighbours... */
  GNUNET_break (0);
  free_neighbour (n);
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GSC_NEIGHBOURS_done ()
{
  if (NULL != transport)
  {
    GNUNET_TRANSPORT_disconnect (transport);
    transport = NULL;
  }
  if (NULL != neighbours)
  {
    GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                           &free_neighbour_helper,
					   NULL);
    GNUNET_CONTAINER_multipeermap_destroy (neighbours);
    neighbours = NULL;
  }
}

/* end of gnunet-service-core_neighbours.c */
