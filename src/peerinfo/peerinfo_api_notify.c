/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010 GNUnet e.V.

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
 * @file peerinfo/peerinfo_api_notify.c
 * @brief notify API to access peerinfo service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "peerinfo.h"

#define LOG(kind,...) GNUNET_log_from (kind, "peerinfo-api",__VA_ARGS__)

/**
 * Context for the info handler.
 */
struct GNUNET_PEERINFO_NotifyContext
{

  /**
   * Our connection to the PEERINFO service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call with information.
   */
  GNUNET_PEERINFO_Processor callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * Configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Tasked used for delayed re-connection attempt.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Include friend only HELLOs in callbacks
   */
  int include_friend_only;
};


/**
 * Task to re-try connecting to peerinfo.
 *
 * @param cls the `struct GNUNET_PEERINFO_NotifyContext *`
 */
static void
reconnect (void *cls);


/**
 * We encountered an error, reconnect to the service.
 *
 * @param nc context to reconnect
 */
static void
do_reconnect (struct GNUNET_PEERINFO_NotifyContext *nc)
{
  GNUNET_MQ_destroy (nc->mq);
  nc->mq = NULL;
  nc->task = GNUNET_SCHEDULER_add_now (&reconnect,
                                       nc);
}


/**
 * We got a disconnect after asking regex to do the announcement.
 * Retry.
 *
 * @param cls the `struct GNUNET_PEERINFO_NotifyContext` to retry
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERINFO_NotifyContext *nc = cls;

  do_reconnect (nc);
}


/**
 * Check that a peerinfo information message is well-formed.
 *
 * @param cls closure
 * @param im message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_notification (void *cls,
                    const struct InfoMessage *im)
{
  uint16_t ms = ntohs (im->header.size) - sizeof (*im);

  if (ms >= sizeof (struct GNUNET_MessageHeader))
  {
    const struct GNUNET_HELLO_Message *hello;

    hello = (const struct GNUNET_HELLO_Message *) &im[1];
    if (ms != GNUNET_HELLO_size (hello))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  if (0 != ms)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;  /* odd... */
}


/**
 * Receive a peerinfo information message, process it.
 *
 * @param cls closure
 * @param im message received
 */
static void
handle_notification (void *cls,
                     const struct InfoMessage *im)
{
  struct GNUNET_PEERINFO_NotifyContext *nc = cls;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms = ntohs (im->header.size) - sizeof (struct InfoMessage);

  if (0 == ms)
    return;
  hello = (const struct GNUNET_HELLO_Message *) &im[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received information about peer `%s' from peerinfo database\n",
       GNUNET_i2s (&im->peer));
  nc->callback (nc->callback_cls,
                &im->peer,
                hello,
                NULL);
}


/**
 * Type of a function to call when we receive a message from the
 * service.  Call the iterator with the result and (if applicable)
 * continue to receive more messages or trigger processing the next
 * event (if applicable).
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_end_iteration (void *cls,
                      const struct GNUNET_MessageHeader *msg)
{
  /* these are ignored by the notify API */
}


/**
 * Task to re-try connecting to peerinfo.
 *
 * @param cls the `struct GNUNET_PEERINFO_NotifyContext *`
 */
static void
reconnect (void *cls)
{
  struct GNUNET_PEERINFO_NotifyContext *nc = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (notification,
                           GNUNET_MESSAGE_TYPE_PEERINFO_INFO,
                           struct InfoMessage,
                           nc),
    GNUNET_MQ_hd_fixed_size (end_iteration,
                             GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END,
                             struct GNUNET_MessageHeader,
                             nc),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct NotifyMessage *nm;

  nc->task = NULL;
  nc->mq = GNUNET_CLIENT_connecT (nc->cfg,
                                  "peerinfo",
                                  handlers,
                                  &mq_error_handler,
                                  nc);
  if (NULL == nc->mq)
    return;
  env = GNUNET_MQ_msg (nm,
                       GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY);
  nm->include_friend_only = htonl (nc->include_friend_only);
  GNUNET_MQ_send (nc->mq,
                  env);
}


/**
 * Call a method whenever our known information about peers
 * changes.  Initially calls the given function for all known
 * peers and then only signals changes.
 *
 * If @a include_friend_only is set to #GNUNET_YES peerinfo will include HELLO
 * messages which are intended for friend to friend mode and which do not
 * have to be gossiped. Otherwise these messages are skipped.
 *
 * @param cfg configuration to use
 * @param include_friend_only include HELLO messages for friends only
 * @param callback the method to call for each peer
 * @param callback_cls closure for @a callback
 * @return NULL on error
 */
struct GNUNET_PEERINFO_NotifyContext *
GNUNET_PEERINFO_notify (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        int include_friend_only,
                        GNUNET_PEERINFO_Processor callback,
                        void *callback_cls)
{
  struct GNUNET_PEERINFO_NotifyContext *nc;

  nc = GNUNET_new (struct GNUNET_PEERINFO_NotifyContext);
  nc->cfg = cfg;
  nc->callback = callback;
  nc->callback_cls = callback_cls;
  nc->include_friend_only = include_friend_only;
  reconnect (nc);
  if (NULL == nc->mq)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Could not connect to PEERINFO service.\n");
    GNUNET_free (nc);
    return NULL;
  }
  return nc;
}


/**
 * Stop notifying about changes.
 *
 * @param nc context to stop notifying
 */
void
GNUNET_PEERINFO_notify_cancel (struct GNUNET_PEERINFO_NotifyContext *nc)
{
  if (NULL != nc->mq)
  {
    GNUNET_MQ_destroy (nc->mq);
    nc->mq = NULL;
  }
  if (NULL != nc->task)
  {
    GNUNET_SCHEDULER_cancel (nc->task);
    nc->task = NULL;
  }
  GNUNET_free (nc);
}

/* end of peerinfo_api_notify.c */
