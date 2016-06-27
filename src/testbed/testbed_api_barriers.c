/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013, 2016 GNUnet e.V.

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
   * The testbed-barrier service message queue.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * The barrier wait callback
   */
  GNUNET_TESTBED_barrier_wait_cb cb;

  /**
   * The closure for @e cb.
   */
  void *cb_cls;
};



/**
 * Check if barrier status message is well-formed.
 *
 * @param cls closure
 * @param msg received message
 * @return #GNUNET_OK if the message is well-formed.
 */
static int
check_status (void *cls,
              const struct GNUNET_TESTBED_BarrierStatusMsg *msg)
{
  /* FIXME: this fails to actually check that the message
     follows the protocol spec (0-terminations!).  However,
     not critical as #handle_status() doesn't interpret the
     variable-size part anyway right now. */
  return GNUNET_OK;
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg received message
 */
static void
handle_status (void *cls,
               const struct GNUNET_TESTBED_BarrierStatusMsg *msg)
{
  struct GNUNET_TESTBED_BarrierWaitHandle *h = cls;

  switch (ntohs (msg->status))
  {
  case GNUNET_TESTBED_BARRIERSTATUS_ERROR:
    h->cb (h->cb_cls,
           h->name,
           GNUNET_SYSERR);
    break;
  case GNUNET_TESTBED_BARRIERSTATUS_INITIALISED:
    h->cb (h->cb_cls,
           h->name,
           GNUNET_SYSERR);
    GNUNET_break (0);
    break;
  case GNUNET_TESTBED_BARRIERSTATUS_CROSSED:
    h->cb (h->cb_cls,
           h->name,
           GNUNET_OK);
    break;
  default:
    GNUNET_break_op (0);
    h->cb (h->cb_cls,
           h->name,
           GNUNET_SYSERR);
    break;
  }
  GNUNET_TESTBED_barrier_wait_cancel (h);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TESTBED_BarrierWaitHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TESTBED_BarrierWaitHandle *h = cls;

  h->cb (h->cb_cls,
         h->name,
         GNUNET_SYSERR);
  GNUNET_TESTBED_barrier_wait_cancel (h);
}


/**
 * Wait for a barrier to be crossed.  This function should be called by the
 * peers which have been started by the testbed.  If the peer is not started by
 * testbed this function may return error
 *
 * @param name the name of the barrier
 * @param cb the barrier wait callback
 * @param cb_cls the closure for @a cb
 * @return barrier wait handle which can be used to cancel the waiting at
 *   anytime before the callback is called.  NULL upon error.
 */
struct GNUNET_TESTBED_BarrierWaitHandle *
GNUNET_TESTBED_barrier_wait (const char *name,
                             GNUNET_TESTBED_barrier_wait_cb cb,
                             void *cb_cls)
{
  GNUNET_MQ_hd_var_size (status,
                         GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS,
                         struct GNUNET_TESTBED_BarrierStatusMsg);
  struct GNUNET_TESTBED_BarrierWaitHandle *h
    = GNUNET_new (struct GNUNET_TESTBED_BarrierWaitHandle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_status_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTBED_BarrierWait *msg;
  const char *cfg_filename;
  size_t name_len;

  GNUNET_assert (NULL != cb);
  cfg_filename = getenv (ENV_TESTBED_CONFIG);
  if (NULL == cfg_filename)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Are you running under testbed?\n");
    GNUNET_free (h);
    return NULL;
  }
  h->cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (h->cfg,
                                 cfg_filename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Unable to load configuration from file `%s'\n",
         cfg_filename);
    GNUNET_CONFIGURATION_destroy (h->cfg);
    GNUNET_free (h);
    return NULL;
  }
  h->name = GNUNET_strdup (name);
  h->cb = cb;
  h->cb_cls = cb_cls;
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "testbed-barrier",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Unable to connect to local testbed-barrier service\n");
    GNUNET_TESTBED_barrier_wait_cancel (h);
    return NULL;
  }
  name_len = strlen (name); /* NOTE: unusual to not have 0-termination, change? */
  env = GNUNET_MQ_msg_extra (msg,
                             name_len,
                             GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT);
  memcpy (msg->name,
          name,
          name_len);
  GNUNET_MQ_send (h->mq,
                  env);
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
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h->name);
  GNUNET_CONFIGURATION_destroy (h->cfg);
  GNUNET_free (h);
}

/* end of testbed_api_barriers.c */
