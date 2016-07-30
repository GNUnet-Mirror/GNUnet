/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file transport/transport_api_hello_get.c
 * @brief library to obtain our HELLO from our transport service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_hello_service.h"
#include "transport.h"


/**
 * Functions to call with this peer's HELLO.
 */
struct GNUNET_TRANSPORT_HelloGetHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Transport handle.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Callback to call once we got our HELLO.
   */
  GNUNET_TRANSPORT_HelloUpdateCallback rec;

  /**
   * Closure for @e rec.
   */
  void *rec_cls;

  /**
   * Task for calling the HelloUpdateCallback when we already have a HELLO
   */
  struct GNUNET_SCHEDULER_Task *notify_task;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Type of HELLOs client cares about.
   */
  enum GNUNET_TRANSPORT_AddressClass ac;
};


/**
 * Function we use for checking incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param msg message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_hello (void *cls,
             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PeerIdentity me;

  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) msg,
                           &me))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving (my own) HELLO message (%u bytes), I am `%s'.\n",
              (unsigned int) ntohs (msg->size),
              GNUNET_i2s (&me));
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming HELLO messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_HelloGetHandle *`
 * @param msg message received
 */
static void
handle_hello (void *cls,
              const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh = cls;

  ghh->rec (ghh->rec_cls,
            msg);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param ghh transport service to reconnect
 */
static void
schedule_reconnect (struct GNUNET_TRANSPORT_HelloGetHandle *ghh);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Error receiving from transport service, disconnecting temporarily.\n");
  GNUNET_MQ_destroy (ghh->mq);
  ghh->mq = NULL;
  schedule_reconnect (ghh);
}


/**
 * Try again to connect to transport service.
 *
 * @param cls the handle to the transport service
 */
static void
reconnect (void *cls)
{
  GNUNET_MQ_hd_var_size (hello,
                         GNUNET_MESSAGE_TYPE_HELLO,
                         struct GNUNET_MessageHeader);
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_hello_handler (ghh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct StartMessage *s;

  ghh->reconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to transport service.\n");
  GNUNET_assert (NULL == ghh->mq);
  ghh->mq = GNUNET_CLIENT_connecT (ghh->cfg,
                                   "transport",
                                   handlers,
                                   &mq_error_handler,
                                   ghh);
  if (NULL == ghh->mq)
    return;
  env = GNUNET_MQ_msg (s,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  s->options = htonl (0);
  GNUNET_MQ_send (ghh->mq,
                  env);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param ghh transport service to reconnect
 */
static void
schedule_reconnect (struct GNUNET_TRANSPORT_HelloGetHandle *ghh)
{
  ghh->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (ghh->reconnect_delay,
                                    &reconnect,
                                    ghh);
  ghh->reconnect_delay = GNUNET_TIME_STD_BACKOFF (ghh->reconnect_delay);
}


/**
 * Obtain the HELLO message for this peer.  The callback given in this function
 * is never called synchronously.
 *
 * @param cfg configuration
 * @param ac which network type should the addresses from the HELLO belong to?
 * @param rec function to call with the HELLO, sender will be our peer
 *            identity; message and sender will be NULL on timeout
 *            (handshake with transport service pending/failed).
 *             cost estimate will be 0.
 * @param rec_cls closure for @a rec
 * @return handle to cancel the operation
 */
struct GNUNET_TRANSPORT_HelloGetHandle *
GNUNET_TRANSPORT_hello_get (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            enum GNUNET_TRANSPORT_AddressClass ac,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls)
{
  struct GNUNET_TRANSPORT_HelloGetHandle *ghh;

  ghh = GNUNET_new (struct GNUNET_TRANSPORT_HelloGetHandle);
  ghh->rec = rec;
  ghh->rec_cls = rec_cls;
  ghh->cfg = cfg;
  ghh->ac = ac;
  reconnect (ghh);
  if (NULL == ghh->mq)
  {
    GNUNET_free (ghh);
    return NULL;
  }
  return ghh;
}


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param ghh handle to cancel
 */
void
GNUNET_TRANSPORT_hello_get_cancel (struct GNUNET_TRANSPORT_HelloGetHandle *ghh)
{
  if (NULL != ghh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (ghh->reconnect_task);
    ghh->reconnect_task = NULL;
  }
  if (NULL != ghh->mq)
  {
    GNUNET_MQ_destroy (ghh->mq);
    ghh->mq = NULL;
  }
  GNUNET_free (ghh);
}


/* end of transport_api_hello_get.c */
