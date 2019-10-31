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
 * @file cadet/cadet_api_list_peers.c
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
struct GNUNET_CADET_PeersLister
{
  /**
   * Monitor callback
   */
  GNUNET_CADET_PeersCB peers_cb;

  /**
   * Info callback closure for @c info_cb.
   */
  void *peers_cb_cls;

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
 * @param cls a `struct GNUNET_CADET_PeersLister`
 * @param info Message itself.
 */
static void
handle_get_peers (void *cls,
                  const struct GNUNET_CADET_LocalInfoPeers *info)
{
  struct GNUNET_CADET_PeersLister *pl = cls;
  struct GNUNET_CADET_PeerListEntry ple;

  ple.peer = info->destination;
  ple.have_tunnel = (int) ntohs (info->tunnel);
  ple.n_paths = (unsigned int) ntohs (info->paths);
  ple.best_path_length = (unsigned int) ntohl (info->best_path_length);
  pl->peers_cb (pl->peers_cb_cls,
                &ple);
}


/**
 * Process a end of list reply about info on all peers.
 *
 * @param cls a `struct GNUNET_CADET_PeersLister`
 * @param msg Message itself.
 */
static void
handle_get_peers_end (void *cls,
                      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CADET_PeersLister *pl = cls;

  (void) msg;

  pl->peers_cb (pl->peers_cb_cls,
                NULL);
  GNUNET_CADET_list_peers_cancel (pl);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_PeersLister` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_PeersLister`
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_PeersLister *pl = cls;

  GNUNET_MQ_destroy (pl->mq);
  pl->mq = NULL;
  pl->backoff = GNUNET_TIME_randomized_backoff (pl->backoff,
                                                GNUNET_TIME_UNIT_MINUTES);
  pl->reconnect_task = GNUNET_SCHEDULER_add_delayed (pl->backoff,
                                                     &reconnect,
                                                     pl);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_PeersLister` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_PeersLister *pl = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (get_peers,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS,
                             struct GNUNET_CADET_LocalInfoPeers,
                             pl),
    GNUNET_MQ_hd_fixed_size (get_peers_end,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS_END,
                             struct GNUNET_MessageHeader,
                             pl),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  pl->reconnect_task = NULL;
  pl->mq = GNUNET_CLIENT_connect (pl->cfg,
                                  "cadet",
                                  handlers,
                                  &error_handler,
                                  pl);
  if (NULL == pl->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PEERS);
  GNUNET_MQ_send (pl->mq,
                  env);
}


/**
 * Request information about peers known to the running cadet service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 * @param cfg configuration to use
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_PeersLister *
GNUNET_CADET_list_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         GNUNET_CADET_PeersCB callback,
                         void *callback_cls)
{
  struct GNUNET_CADET_PeersLister *pl;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  pl = GNUNET_new (struct GNUNET_CADET_PeersLister);
  pl->peers_cb = callback;
  pl->peers_cb_cls = callback_cls;
  pl->cfg = cfg;
  reconnect (pl);
  if (NULL == pl->mq)
  {
    GNUNET_free (pl);
    return NULL;
  }
  return pl;
}


/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * @param pl operation handle
 * @return Closure given to GNUNET_CADET_get_peers().
 */
void *
GNUNET_CADET_list_peers_cancel (struct GNUNET_CADET_PeersLister *pl)
{
  void *ret = pl->peers_cb_cls;

  if (NULL != pl->mq)
    GNUNET_MQ_destroy (pl->mq);
  if (NULL != pl->reconnect_task)
    GNUNET_SCHEDULER_cancel (pl->reconnect_task);
  GNUNET_free (pl);
  return ret;
}


/* end of cadet_api_list_peers.c */
