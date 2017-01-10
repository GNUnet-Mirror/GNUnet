/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014, 2016 GNUnet e.V.

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
 * @file core/core_api_monitor_peers.c
 * @brief implementation of the peer_iterate function
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


/**
 * Handle to a CORE monitoring operation.
 */
struct GNUNET_CORE_MonitorHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Our connection to the service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function called with the peer.
   */
  GNUNET_CORE_MonitorCallback peer_cb;

  /**
   * Closure for @e peer_cb.
   */
  void *peer_cb_cls;

};


/**
 * Protocol error, reconnect to CORE service and notify
 * client.
 *
 * @param mh monitoring session to reconnect to CORE
 */
static void
reconnect (struct GNUNET_CORE_MonitorHandle *mh);


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure, a `struct GNUNET_CORE_MonitorHandle *`
 * @param error error code
 */
static void
handle_mq_error (void *cls,
                 enum GNUNET_MQ_Error error)
{
  struct GNUNET_CORE_MonitorHandle *mh = cls;

  reconnect (mh);
}


/**
 * Receive reply from CORE service with information about a peer.
 *
 * @param cls our `struct  GNUNET_CORE_MonitorHandle *`
 * @param mon_message monitor message
 */
static void
handle_receive_info (void *cls,
                     const struct MonitorNotifyMessage *mon_message)
{
  struct GNUNET_CORE_MonitorHandle *mh = cls;

  mh->peer_cb (mh->peer_cb_cls,
               &mon_message->peer,
               (enum GNUNET_CORE_KxState) ntohl (mon_message->state),
               GNUNET_TIME_absolute_ntoh (mon_message->timeout));
}


/**
 * Protocol error, reconnect to CORE service and notify
 * client.
 *
 * @param mh monitoring session to reconnect to CORE
 */
static void
reconnect (struct GNUNET_CORE_MonitorHandle *mh)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (receive_info,
                             GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY,
                             struct MonitorNotifyMessage,
                             mh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  if (NULL != mh->mq)
    GNUNET_MQ_destroy (mh->mq);
  /* FIXME: use backoff? */
  mh->mq = GNUNET_CLIENT_connect (mh->cfg,
                                  "core",
                                  handlers,
                                  &handle_mq_error,
                                  mh);
  if (NULL == mh->mq)
    return;
  /* notify callback about reconnect */
  mh->peer_cb (mh->peer_cb_cls,
               NULL,
               GNUNET_CORE_KX_CORE_DISCONNECT,
               GNUNET_TIME_UNIT_FOREVER_ABS);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS);
  GNUNET_MQ_send (mh->mq,
                  env);
}


/**
 * Monitor connectivity and KX status of all peers known to CORE.
 * Calls @a peer_cb with the current status for each connected peer,
 * and then once with NULL to indicate that all peers that are
 * currently active have been handled.  After that, the iteration
 * continues until it is cancelled.  Normal users of the CORE API are
 * not expected to use this function.  It is different in that it
 * truly lists all connections (including those where the KX is in
 * progress), not just those relevant to the application.  This
 * function is used by special applications for diagnostics.
 *
 * @param cfg configuration handle
 * @param peer_cb function to call with the peer information
 * @param peer_cb_cls closure for @a peer_cb
 * @return NULL on error
 */
struct GNUNET_CORE_MonitorHandle *
GNUNET_CORE_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CORE_MonitorCallback peer_cb,
                           void *peer_cb_cls)
{
  struct GNUNET_CORE_MonitorHandle *mh;

  GNUNET_assert (NULL != peer_cb);
  mh = GNUNET_new (struct GNUNET_CORE_MonitorHandle);
  mh->cfg = cfg;
  mh->peer_cb = peer_cb;
  mh->peer_cb_cls = peer_cb_cls;
  reconnect (mh);
  if (NULL == mh->mq)
  {
    GNUNET_free (mh);
    return NULL;
  }
  return mh;
}


/**
 * Stop monitoring CORE activity.
 *
 * @param mh monitor to stop
 */
void
GNUNET_CORE_monitor_stop (struct GNUNET_CORE_MonitorHandle *mh)
{
  if (NULL != mh->mq)
  {
    GNUNET_MQ_destroy (mh->mq);
    mh->mq = NULL;
  }
  GNUNET_free (mh);
}


/* end of core_api_monitor_peers.c */
