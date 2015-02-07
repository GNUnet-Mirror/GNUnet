/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * @file core/core_api_mq.c
 * @brief MQ support for core service
 * @author Christian Grothoff
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "core.h"

#define LOG(kind,...) GNUNET_log_from (kind, "core-api",__VA_ARGS__)


/**
 * Internal state of a GNUNET-MQ queue for CORE.
 */
struct CoreMQState
{
  /**
   * Which peer does this queue target?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Handle to the CORE service used by this MQ.
   */
  struct GNUNET_CORE_Handle *core;

  /**
   * Transmission handle (if in use).
   */
  struct GNUNET_CORE_TransmitHandle *th;
};


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  @a buf will be
 * NULL and @a size zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
core_mq_ntr (void *cls, size_t size,
             void *buf)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct CoreMQState *mqs = GNUNET_MQ_impl_state (mq);
  const struct GNUNET_MessageHeader *mh = GNUNET_MQ_impl_current (mq);
  size_t msg_size = ntohs (mh->size);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "ntr called (size %u, type %u)\n",
       msg_size,
       ntohs (mh->type));
  mqs->th = NULL;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "send error\n");
    GNUNET_MQ_inject_error (mq, GNUNET_MQ_ERROR_WRITE);
    return 0;
  }
  memcpy (buf, mh, msg_size);
  GNUNET_MQ_impl_send_continue (mq);
  return msg_size;
}


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
core_mq_send (struct GNUNET_MQ_Handle *mq,
              const struct GNUNET_MessageHeader *msg,
              void *impl_state)
{
  struct CoreMQState *mqs = impl_state;

  GNUNET_assert (NULL == mqs->th);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending queued message (size %u)\n",
       ntohs (msg->size));
  mqs->th = GNUNET_CORE_notify_transmit_ready (mqs->core, GNUNET_YES, 0,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &mqs->target,
                                               ntohs (msg->size),
                                               &core_mq_ntr, mq);
}


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free @a mq, but should
 * take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
core_mq_destroy (struct GNUNET_MQ_Handle *mq,
                 void *impl_state)
{
  struct CoreMQState *mqs = impl_state;

  if (NULL != mqs->th)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (mqs->th);
    mqs->th = NULL;
  }
  GNUNET_free (mqs);
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
core_mq_cancel (struct GNUNET_MQ_Handle *mq,
                void *impl_state)
{
  struct CoreMQState *mqs = impl_state;

  GNUNET_assert (NULL != mqs->th);
  GNUNET_CORE_notify_transmit_ready_cancel (mqs->th);
}


/**
 * Create a message queue for sending messages to a peer with CORE.
 * Messages may only be queued with #GNUNET_MQ_send once the init callback has
 * been called for the given handle.
 * There must only be one queue per peer for each core handle.
 * The message queue can only be used to transmit messages,
 * not to receive them.
 *
 * @param h the core handle
 * @param target the target peer for this queue, may not be NULL
 * @return a message queue for sending messages over the core handle
 *         to the target peer
 */
struct GNUNET_MQ_Handle *
GNUNET_CORE_mq_create (struct GNUNET_CORE_Handle *h,
                       const struct GNUNET_PeerIdentity *target)
{
  struct CoreMQState *mqs = GNUNET_new (struct CoreMQState);

  mqs->core = h;
  mqs->target = *target;
  return GNUNET_MQ_queue_for_callbacks (&core_mq_send,
                                        &core_mq_destroy,
                                        &core_mq_cancel,
                                        mqs,
                                        NULL, NULL, NULL);
}

/* end of core_api_mq.c */
