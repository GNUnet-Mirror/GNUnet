/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

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
 * @file cadet/cadet_api_get_path.c
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
struct GNUNET_CADET_GetPath
{
  /**
   * Monitor callback
   */
  GNUNET_CADET_PathCB path_cb;

  /**
   * Closure for @c path_cb.
   */
  void *path_cb_cls;

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

  /**
   * Peer we want information about.
   */
  struct GNUNET_PeerIdentity id;
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
check_get_path (void *cls,
                const struct GNUNET_CADET_LocalInfoPath *message)
{
  size_t msize = sizeof(struct GNUNET_CADET_LocalInfoPath);
  size_t esize;

  (void) cls;
  esize = ntohs (message->header.size);
  if (esize < msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != ((esize - msize) % sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a local peer info reply, pass info to the user.
 *
 * @param cls Closure
 * @param message Message itself.
 */
static void
handle_get_path (void *cls,
                 const struct GNUNET_CADET_LocalInfoPath *message)
{
  struct GNUNET_CADET_GetPath *gp = cls;
  struct GNUNET_CADET_PeerPathDetail ppd;

  ppd.peer = gp->id;
  ppd.path = (const struct GNUNET_PeerIdentity *) &message[1];
  ppd.target_offset = ntohl (message->off);
  ppd.path_length = (ntohs (message->header.size) - sizeof(*message))
                    / sizeof(struct GNUNET_PeerIdentity);
  gp->path_cb (gp->path_cb_cls,
               &ppd);
}


/**
 * Process a local peer info reply, pass info to the user.
 *
 * @param cls Closure
 * @param message Message itself.
 */
static void
handle_get_path_end (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_GetPath *gp = cls;

  (void) message;
  gp->path_cb (gp->path_cb_cls,
               NULL);
  GNUNET_CADET_get_path_cancel (gp);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_GetPath` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_GetPath`
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_GetPath *gp = cls;

  GNUNET_MQ_destroy (gp->mq);
  gp->mq = NULL;
  gp->backoff = GNUNET_TIME_randomized_backoff (gp->backoff,
                                                GNUNET_TIME_UNIT_MINUTES);
  gp->reconnect_task = GNUNET_SCHEDULER_add_delayed (gp->backoff,
                                                     &reconnect,
                                                     gp);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_GetPath` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_GetPath *gp = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (get_path,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH,
                           struct GNUNET_CADET_LocalInfoPath,
                           gp),
    GNUNET_MQ_hd_fixed_size (get_path_end,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH_END,
                             struct GNUNET_MessageHeader,
                             gp),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CADET_RequestPathInfoMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  gp->reconnect_task = NULL;
  gp->mq = GNUNET_CLIENT_connect (gp->cfg,
                                  "cadet",
                                  handlers,
                                  &error_handler,
                                  gp);
  if (NULL == gp->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PATH);
  msg->peer = gp->id;
  GNUNET_MQ_send (gp->mq,
                  env);
}


/**
 * Request information about paths known to the running cadet peer.
 *
 * @param cfg configuration to use
 * @param id Peer whose paths to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_GetPath *
GNUNET_CADET_get_path (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const struct GNUNET_PeerIdentity *id,
                       GNUNET_CADET_PathCB callback,
                       void *callback_cls)
{
  struct GNUNET_CADET_GetPath *gp;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  gp = GNUNET_new (struct GNUNET_CADET_GetPath);
  gp->path_cb = callback;
  gp->path_cb_cls = callback_cls;
  gp->cfg = cfg;
  gp->id = *id;
  reconnect (gp);
  if (NULL == gp->mq)
  {
    GNUNET_free (gp);
    return NULL;
  }
  return gp;
}


/**
 * Cancel @a gp operation.
 *
 * @param gp operation to cancel
 * @return closure from #GNUNET_CADET_get_path().
 */
void *
GNUNET_CADET_get_path_cancel (struct GNUNET_CADET_GetPath *gp)
{
  void *ret = gp->path_cb_cls;

  if (NULL != gp->mq)
    GNUNET_MQ_destroy (gp->mq);
  if (NULL != gp->reconnect_task)
    GNUNET_SCHEDULER_cancel (gp->reconnect_task);
  GNUNET_free (gp);
  return ret;
}


/* end of cadet_api_get_path.c */
