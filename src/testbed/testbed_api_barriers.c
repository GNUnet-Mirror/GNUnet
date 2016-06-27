/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 GNUnet e.V.

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
 * @file testbed/testbed_api_barriers.c
 * @brief API implementation for testbed barriers
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_testbed_service.h"
#include "testbed_api.h"
#include "testbed_api_barriers.h"

/**
 * Logging shorthand
 */
#define LOG(type, ...)                          \
  GNUNET_log_from (type, "testbed-api-barriers", __VA_ARGS__);

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__);


/**
 * Barrier wait handle
 */
struct GNUNET_TESTBED_BarrierWaitHandle
{
  /**
   * The name of the barrier
   */
  char *name;

  /**
   * Then configuration used for the client connection
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The client connection
   */
  struct GNUNET_CLIENT_Connection *conn;

  /**
   * Transmit handle
   */
  struct GNUNET_CLIENT_TransmitHandle *tx;

  /**
   * The message to transmit with tx
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * The barrier wait callback
   */
  GNUNET_TESTBED_barrier_wait_cb cb;

  /**
   * The closure for the above callback
   */
  void *cls;
};


/**
 * Function to destroy barrier wait handle
 *
 * @param h the handle to destroy
 */
static void
destroy_handle (struct GNUNET_TESTBED_BarrierWaitHandle *h)
{
  GNUNET_free (h->name);
  if (NULL != h->tx)
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->tx);
  if (NULL != h->conn)
    GNUNET_CLIENT_disconnect (h->conn);
  if (NULL != h->msg)
    GNUNET_free (h->msg);
  GNUNET_CONFIGURATION_destroy (h->cfg);
  GNUNET_free (h);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param message received message; NULL on timeout or fatal error
 */
static void
receive_handler (void *cls,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_BarrierWaitHandle *h = cls;
  const struct GNUNET_TESTBED_BarrierStatusMsg *msg;
  uint16_t msize;

  if (NULL == message)
  {
    GNUNET_break_op (0);
    goto fail;
  }
  if (GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS != ntohs (message->type))
  {
    GNUNET_break_op (0);
    goto fail;
  }
  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_BarrierStatusMsg))
  {
    GNUNET_break_op (0);
    goto fail;
  }
  msg = (const struct GNUNET_TESTBED_BarrierStatusMsg *) message;
  switch (ntohs (msg->status))
  {
  case GNUNET_TESTBED_BARRIERSTATUS_ERROR:
    goto fail;
  case GNUNET_TESTBED_BARRIERSTATUS_INITIALISED:
    GNUNET_break (0);           /* FIXME */
    goto destroy;
  case GNUNET_TESTBED_BARRIERSTATUS_CROSSED:
    h->cb (h->cls, h->name, GNUNET_OK);
    goto destroy;
  default:
    GNUNET_break_op (0);
  }

 fail:
  h->cb (h->cls, h->name, GNUNET_SYSERR);

 destroy:
  destroy_handle (h);
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_TESTBED_BarrierWaitHandle *h = cls;
  uint16_t msize;

  h->tx = NULL;
  if ((0 == size) || (NULL == buf))
  {
    destroy_handle (h);
    return 0;
  }
  msize = htons (h->msg->size);
  GNUNET_assert (msize <= size);
  (void) memcpy (buf, h->msg, msize);
  GNUNET_free (h->msg);
  h->msg = NULL;
  GNUNET_CLIENT_receive (h->conn, &receive_handler, h, GNUNET_TIME_UNIT_FOREVER_REL);
  return msize;
}


/**
 * Wait for a barrier to be crossed.  This function should be called by the
 * peers which have been started by the testbed.  If the peer is not started by
 * testbed this function may return error
 *
 * @param name the name of the barrier
 * @param cb the barrier wait callback
 * @param cls the closure for the above callback
 * @return barrier wait handle which can be used to cancel the waiting at
 *   anytime before the callback is called.  NULL upon error.
 */
struct GNUNET_TESTBED_BarrierWaitHandle *
GNUNET_TESTBED_barrier_wait (const char *name,
                             GNUNET_TESTBED_barrier_wait_cb cb,
                             void *cls)
{
  struct GNUNET_TESTBED_BarrierWait *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TESTBED_BarrierWaitHandle *h;
  char *cfg_filename;
  size_t name_len;
  uint16_t msize;

  GNUNET_assert (NULL != cb);
  GNUNET_assert (NULL != name);
  cfg_filename = getenv (ENV_TESTBED_CONFIG);
  if (NULL == cfg_filename)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Are you running under testbed?\n");
    return NULL;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, cfg_filename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Unable to load configuration from file `%s'\n",
         cfg_filename);
    GNUNET_CONFIGURATION_destroy (cfg);
    return NULL;
  }
  h = GNUNET_new (struct GNUNET_TESTBED_BarrierWaitHandle);
  h->name = GNUNET_strdup (name);
  h->cfg = cfg;
  h->conn = GNUNET_CLIENT_connect ("testbed-barrier", h->cfg);
  h->cb = cb;
  h->cls = cls;
  if (NULL == h->conn)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Unable to connect to local testbed-barrier service\n");
    destroy_handle (h);
    return NULL;
  }
  name_len = strlen (name);
  msize = sizeof (struct GNUNET_TESTBED_BarrierWait) + name_len;
  msg = GNUNET_malloc (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT);
  msg->header.size = htons (msize);
  (void) memcpy (msg->name, name, name_len);
  h->msg = &msg->header;
  h->tx =
      GNUNET_CLIENT_notify_transmit_ready (h->conn, msize,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO,
                                           &transmit_notify,
                                           h);
  return h;
}


/**
 * Cancel a barrier wait handle
 *
 * @param h the barrier wait handle
 */
void
GNUNET_TESTBED_barrier_wait_cancel (struct GNUNET_TESTBED_BarrierWaitHandle *h)
{
  destroy_handle (h);
}

/* end of testbed_api_barriers.c */
