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
 * @file cadet/cadet_api_get_channel.c
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
struct GNUNET_CADET_ChannelMonitor
{
  /**
   * Channel callback.
   */
  GNUNET_CADET_ChannelCB channel_cb;

  /**
   * Info callback closure for @c channel_cb.
   */
  void *channel_cb_cls;

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Message queue to talk to CADET service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Task to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Backoff for reconnect attempts.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Peer we want information about.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Check that message received from CADET service is well-formed.
 *
 * @param cls unused
 * @param message the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_channel_info (void *cls,
                    const struct GNUNET_CADET_ChannelInfoMessage *message)
{
  (void) cls;

  return GNUNET_OK;
}


/**
 * Process a local peer info reply, pass info to the user.
 *
 * @param cls Closure
 * @param message Message itself.
 */
static void
handle_channel_info (void *cls,
                     const struct GNUNET_CADET_ChannelInfoMessage *message)
{
  struct GNUNET_CADET_ChannelMonitor *cm = cls;
  struct GNUNET_CADET_ChannelInternals ci;

  ci.root = message->root;
  ci.dest = message->dest;
  cm->channel_cb (cm->channel_cb_cls,
                  &ci);
  GNUNET_CADET_get_channel_cancel (cm);
}


/**
 * Process a local peer info reply, pass info to the user.
 *
 * @param cls Closure
 * @param message Message itself.
 */
static void
handle_channel_info_end (void *cls,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ChannelMonitor *cm = cls;

  cm->channel_cb (cm->channel_cb_cls,
                  NULL);
  GNUNET_CADET_get_channel_cancel (cm);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_ChannelMonitor` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_ChannelMonitor``
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_ChannelMonitor *cm = cls;

  GNUNET_MQ_destroy (cm->mq);
  cm->mq = NULL;
  cm->backoff = GNUNET_TIME_randomized_backoff (cm->backoff,
                                                GNUNET_TIME_UNIT_MINUTES);
  cm->reconnect_task = GNUNET_SCHEDULER_add_delayed (cm->backoff,
                                                     &reconnect,
                                                     cm);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_ChannelMonitor` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_ChannelMonitor *cm = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (channel_info_end,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL_END,
                             struct GNUNET_MessageHeader,
                             cm),
    GNUNET_MQ_hd_var_size (channel_info,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL,
                           struct GNUNET_CADET_ChannelInfoMessage,
                           cm),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CADET_RequestChannelInfoMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  cm->reconnect_task = NULL;
  cm->mq = GNUNET_CLIENT_connect (cm->cfg,
                                  "cadet",
                                  handlers,
                                  &error_handler,
                                  cm);
  if (NULL == cm->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_CHANNEL);
  msg->target = cm->peer;
  GNUNET_MQ_send (cm->mq,
                  env);
}


/**
 * Request information about a specific channel of the running cadet peer.
 *
 * @param cfg configuration to use
 * @param peer ID of the other end of the channel.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_ChannelMonitor *
GNUNET_CADET_get_channel (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_PeerIdentity *peer,
                          GNUNET_CADET_ChannelCB callback,
                          void *callback_cls)
{
  struct GNUNET_CADET_ChannelMonitor *cm;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  cm = GNUNET_new (struct GNUNET_CADET_ChannelMonitor);
  cm->channel_cb = callback;
  cm->channel_cb_cls = callback_cls;
  cm->cfg = cfg;
  cm->peer = *peer;
  reconnect (cm);
  if (NULL == cm->mq)
  {
    GNUNET_free (cm);
    return NULL;
  }
  return cm;
}


/**
 * Cancel a channel monitor request. The callback will not be called (anymore).
 *
 * @param h Cadet handle.
 * @return Closure that was given to #GNUNET_CADET_get_channel().
 */
void *
GNUNET_CADET_get_channel_cancel (struct GNUNET_CADET_ChannelMonitor *cm)
{
  void *ret = cm->channel_cb_cls;

  if (NULL != cm->mq)
    GNUNET_MQ_destroy (cm->mq);
  if (NULL != cm->reconnect_task)
    GNUNET_SCHEDULER_cancel (cm->reconnect_task);
  GNUNET_free (cm);
  return ret;
}


/* end of cadet_api_get_channel.c */
