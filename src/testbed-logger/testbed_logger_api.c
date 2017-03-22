/*
      This file is part of GNUnet
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
 * @file testbed-logger/testbed_logger_api.c
 * @brief Client-side routines for communicating with the tesbted logger service
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_logger_service.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-logger-api", __VA_ARGS__)


/**
 * The size of the buffer we fill before sending out the message
 */
#define BUFFER_SIZE (GNUNET_MAX_MESSAGE_SIZE - sizeof (struct GNUNET_MessageHeader))

/**
 * Connection handle for the logger service
 */
struct GNUNET_TESTBED_LOGGER_Handle
{
  /**
   * Client connection
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Flush completion callback
   */
  GNUNET_TESTBED_LOGGER_FlushCompletion cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;

  /**
   * Local buffer for data to be transmitted
   */
  char buf[BUFFER_SIZE];

  /**
   * How many bytes in @a buf are in use?
   */
  size_t buse;

  /**
   * Number of bytes wrote since last flush
   */
  size_t bwrote;

  /**
   * How long after should we retry sending a message to the service?
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Task to call the flush completion callback
   */
  struct GNUNET_SCHEDULER_Task *flush_completion_task;

  /**
   * Number of entries in the MQ.
   */
  unsigned int mq_len;
};


/**
 * Task to call the flush completion notification
 *
 * @param cls the logger handle
 */
static void
call_flush_completion (void *cls)
{
  struct GNUNET_TESTBED_LOGGER_Handle *h = cls;
  GNUNET_TESTBED_LOGGER_FlushCompletion cb;
  void *cb_cls;
  size_t bw;

  h->flush_completion_task = NULL;
  bw = h->bwrote;
  h->bwrote = 0;
  cb = h->cb;
  h->cb = NULL;
  cb_cls = h->cb_cls;
  h->cb_cls = NULL;
  if (NULL != cb)
    cb (cb_cls, bw);
}


/**
 * Schedule the flush completion notification task
 *
 * @param h logger handle
 */
static void
trigger_flush_notification (struct GNUNET_TESTBED_LOGGER_Handle *h)
{
  if (NULL != h->flush_completion_task)
    GNUNET_SCHEDULER_cancel (h->flush_completion_task);
  h->flush_completion_task
    = GNUNET_SCHEDULER_add_now (&call_flush_completion,
                                h);
}


/**
 * Send the buffered data to the service
 *
 * @param h the logger handle
 */
static void
dispatch_buffer (struct GNUNET_TESTBED_LOGGER_Handle *h);


/**
 * MQ successfully sent a message.
 *
 * @param cls our handle
 */
static void
notify_sent (void *cls)
{
  struct GNUNET_TESTBED_LOGGER_Handle *h = cls;

  h->mq_len--;
  if ( (0 == h->mq_len) &&
       (NULL != h->cb) )
  {
    if (0 == h->buse)
      trigger_flush_notification (h);
    else
      dispatch_buffer (h);
  }
}


/**
 * Send the buffered data to the service
 *
 * @param h the logger handle
 */
static void
dispatch_buffer (struct GNUNET_TESTBED_LOGGER_Handle *h)
{
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra (msg,
                             h->buse,
                             GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG);
  GNUNET_memcpy (&msg[1],
          h->buf,
          h->buse);
  h->bwrote += h->buse;
  h->buse = 0;
  h->mq_len++;
  GNUNET_MQ_notify_sent (env,
                         &notify_sent,
                         h);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * We got disconnected from the logger.  Stop logging.
 *
 * @param cls the `struct GNUNET_TESTBED_LOGGER_Handle`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TESTBED_LOGGER_Handle *h = cls;

  GNUNET_break (0);
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
}


/**
 * Connect to the testbed logger service
 *
 * @param cfg configuration to use
 * @return the handle which can be used for sending data to the service; NULL
 *           upon any error
 */
struct GNUNET_TESTBED_LOGGER_Handle *
GNUNET_TESTBED_LOGGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTBED_LOGGER_Handle *h;

  h = GNUNET_new (struct GNUNET_TESTBED_LOGGER_Handle);
  h->mq = GNUNET_CLIENT_connect (cfg,
                                 "testbed-logger",
                                 NULL,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the logger service.
 *
 * @param h the logger handle
 */
void
GNUNET_TESTBED_LOGGER_disconnect (struct GNUNET_TESTBED_LOGGER_Handle *h)
{
  if (NULL != h->flush_completion_task)
  {
    GNUNET_SCHEDULER_cancel (h->flush_completion_task);
    h->flush_completion_task = NULL;
  }
  if (0 != h->mq_len)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Disconnect lost %u logger message[s]\n",
         h->mq_len);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


/**
 * Send data to be logged to the logger service.  The data will be buffered and
 * will be sent upon an explicit call to GNUNET_TESTBED_LOGGER_flush() or upon
 * exceeding a threshold size.
 *
 * @param h the logger handle
 * @param data the data to send;
 * @param size how many bytes of @a data to send
 */
void
GNUNET_TESTBED_LOGGER_write (struct GNUNET_TESTBED_LOGGER_Handle *h,
                             const void *data,
                             size_t size)
{
  if (NULL == h->mq)
    return;
  while (0 != size)
  {
    size_t fit_size = GNUNET_MIN (size,
                                  BUFFER_SIZE - h->buse);
    GNUNET_memcpy (&h->buf[h->buse],
            data,
            fit_size);
    h->buse += fit_size;
    data += fit_size;
    size -= fit_size;
    if (0 != size)
      dispatch_buffer (h);
  }
}


/**
 * Flush the buffered data to the logger service
 *
 * @param h the logger handle
 * @param cb the callback to call after the data is flushed
 * @param cb_cls the closure for the above callback
 */
void
GNUNET_TESTBED_LOGGER_flush (struct GNUNET_TESTBED_LOGGER_Handle *h,
                             GNUNET_TESTBED_LOGGER_FlushCompletion cb,
                             void *cb_cls)
{
  GNUNET_assert (NULL == h->cb);
  h->cb = cb;
  h->cb_cls = cb_cls;
  if ( (NULL == h->mq) ||
       (0 == h->buse) )
  {
    trigger_flush_notification (h);
    return;
  }
  dispatch_buffer (h);
}


/**
 * Cancel notification upon flush.  Should only be used when the flush
 * completion callback given to GNUNET_TESTBED_LOGGER_flush() is not already
 * called.
 *
 * @param h the logger handle
 */
void
GNUNET_TESTBED_LOGGER_flush_cancel (struct GNUNET_TESTBED_LOGGER_Handle *h)
{
  if (NULL != h->flush_completion_task)
  {
    GNUNET_SCHEDULER_cancel (h->flush_completion_task);
    h->flush_completion_task = NULL;
  }
  h->cb = NULL;
  h->cb_cls = NULL;
}

/* End of testbed_logger_api.c */
