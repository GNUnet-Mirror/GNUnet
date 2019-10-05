/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017, 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file cadet/cadet_api_list_tunnels.c
 * @brief cadet api: client implementation of cadet service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_cadet_service.h"
#include "cadet.h"
#include "cadet_protocol.h"


/**
 * Operation handle.
 */
struct GNUNET_CADET_ListTunnels
{
  /**
   * Monitor callback
   */
  GNUNET_CADET_TunnelsCB tunnels_cb;

  /**
   * Info callback closure for @c tunnels_cb.
   */
  void *tunnels_cb_cls;

  /**
   * Message queue to talk to CADET service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Task to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Backoff for reconnect attempts.
   */
  struct GNUNET_TIME_Relative backoff;
};


/**
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param cls a `struct GNUNET_CADET_ListTunnels *`
 * @param info Message itself.
 */
static void
handle_get_tunnels (void *cls,
                    const struct GNUNET_CADET_LocalInfoTunnel *info)
{
  struct GNUNET_CADET_ListTunnels *lt = cls;
  struct GNUNET_CADET_TunnelDetails td;

  td.peer = info->destination;
  td.channels = ntohl (info->channels);
  td.connections = ntohl (info->connections);
  td.estate = ntohs (info->estate);
  td.cstate = ntohs (info->cstate);
  lt->tunnels_cb (lt->tunnels_cb_cls,
                  &td);
}


/**
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param cls a `struct GNUNET_CADET_ListTunnels *`
 * @param message Message itself.
 */
static void
handle_get_tunnels_end (void *cls,
                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CADET_ListTunnels *lt = cls;

  (void) msg;

  lt->tunnels_cb (lt->tunnels_cb_cls,
                  NULL);
  GNUNET_CADET_list_tunnels_cancel (lt);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_ListTunnels` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_ListTunnels`
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_ListTunnels *lt = cls;

  GNUNET_MQ_destroy (lt->mq);
  lt->mq = NULL;
  lt->backoff = GNUNET_TIME_randomized_backoff (lt->backoff,
                                                GNUNET_TIME_UNIT_MINUTES);
  lt->reconnect_task = GNUNET_SCHEDULER_add_delayed (lt->backoff,
                                                     &reconnect,
                                                     lt);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_ListTunnels` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_ListTunnels *lt = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (get_tunnels,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS,
                             struct GNUNET_CADET_LocalInfoTunnel,
                             lt),
    GNUNET_MQ_hd_fixed_size (get_tunnels_end,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS_END,
                             struct GNUNET_MessageHeader,
                             lt),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  lt->reconnect_task = NULL;
  lt->mq = GNUNET_CLIENT_connect (lt->cfg,
                                  "cadet",
                                  handlers,
                                  &error_handler,
                                  lt);
  if (NULL == lt->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_TUNNELS);
  GNUNET_MQ_send (lt->mq,
                  env);
}


/**
 * Request information about tunnels of the running cadet peer.
 * The callback will be called for every tunnel of the service.
 * Only one info request (of any kind) can be active at once.
 *
 * @param cfg configuration to use
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_ListTunnels *
GNUNET_CADET_list_tunnels (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_CADET_TunnelsCB callback,
                           void *callback_cls)
{
  struct GNUNET_CADET_ListTunnels *lt;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  lt = GNUNET_new (struct GNUNET_CADET_ListTunnels);
  lt->tunnels_cb = callback;
  lt->tunnels_cb_cls = callback_cls;
  lt->cfg = cfg;
  reconnect (lt);
  if (NULL == lt->mq)
  {
    GNUNET_free (lt);
    return NULL;
  }
  return lt;
}


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param lt operation handle
 * @return Closure given to GNUNET_CADET_list_tunnels().
 */
void *
GNUNET_CADET_list_tunnels_cancel (struct GNUNET_CADET_ListTunnels *lt)
{
  void *ret = lt->tunnels_cb_cls;

  if (NULL != lt->mq)
    GNUNET_MQ_destroy (lt->mq);
  if (NULL != lt->reconnect_task)
    GNUNET_SCHEDULER_cancel (lt->reconnect_task);
  GNUNET_free (lt);
  return ret;
}


/* end of cadet_api_list_tunnels.c */
