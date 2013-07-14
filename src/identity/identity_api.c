/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file identity/identity_api.c
 * @brief api to get information from the network size estimation service
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_identity_service.h"
#include "identity.h"

#define LOG(kind,...) GNUNET_log_from (kind, "identity-api",__VA_ARGS__)

/**
 * Handle for the service.
 */
struct GNUNET_IDENTITY_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

};


/**
 * Try again to connect to network size estimation service.
 *
 * @param cls the handle to the transport service
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  const struct GNUNET_IDENTITY_ClientMessage *client_msg;

  if (msg == NULL)
  {
    /* Error, timeout, death */
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
    h->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
    return;
  }
  // FIXME: process...
  GNUNET_CLIENT_receive (h->client, &message_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}



/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_IDENTITY_Handle *h)
{
  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);

  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to identity service in %llu ms.\n",
       h->reconnect_delay.rel_value);
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Transmit START message to service.
 *
 * @param cls unused
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_start (void *cls, size_t size, void *buf)
{
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Try again to connect to network size estimation service.
 *
 * @param cls the handle to the transport service
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_IDENTITY_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    /* shutdown, just give up */
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to network size estimation service.\n");
  GNUNET_assert (h->client == NULL);
  h->client = GNUNET_CLIENT_connect ("identity", h->cfg);
  GNUNET_assert (h->client != NULL);

  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &send_start, h);
  GNUNET_assert (h->th != NULL);
}


/**
 * Connect to the identity service.
 *
 * @param cfg the configuration to use
 * @param cb function to call on all identity events, can be NULL
 * @param cb_cls closure for 'cb'
 * @return handle to use
 */
struct GNUNET_IDENTITY_Handle *
GNUNET_IDENTITY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 GNUNET_IDENTITY_Callback cb,
			 void *cb_cls)
{
  struct GNUNET_IDENTITY_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_Handle));
  ret->cfg = cfg;
  ret->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ret->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, ret);
  return ret;
}


/**
 * Disconnect from identity service
 *
 * @param h handle to destroy
 */
void
GNUNET_IDENTITY_disconnect (struct GNUNET_IDENTITY_Handle *h)
{
  GNUNET_assert (NULL != h);
  if (h->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (h->th != NULL)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (h->client != NULL)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}

/* end of identity_api.c */
