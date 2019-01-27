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
 * @file cadet/cadet_api_get_peer.c
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
struct GNUNET_CADET_GetPeer
{

  /**
   * Monitor callback
   */
  GNUNET_CADET_PeerCB peer_cb;

  /**
   * Closure for @c peer_cb.
   */
  void *peer_cb_cls;

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
check_get_peer (void *cls,
                const struct GNUNET_CADET_LocalInfoPeer *message)
{
  size_t msize = sizeof (struct GNUNET_CADET_LocalInfoPeer);
  size_t esize;

  (void) cls;
  esize = ntohs (message->header.size);
  if (esize < msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != ((esize - msize) % sizeof (struct GNUNET_PeerIdentity)))
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
handle_get_peer (void *cls,
                 const struct GNUNET_CADET_LocalInfoPeer *message)
{
  struct GNUNET_CADET_GetPeer *gp = cls;
  const struct GNUNET_PeerIdentity *paths_array;
  unsigned int paths;
  unsigned int path_length;
  int neighbor;
  unsigned int peers;

  paths = ntohs (message->paths);
  paths_array = (const struct GNUNET_PeerIdentity *) &message[1];
  peers = (ntohs (message->header.size) - sizeof (*message))
          / sizeof (struct GNUNET_PeerIdentity);
  path_length = 0;
  neighbor = GNUNET_NO;

  for (unsigned int i = 0; i < peers; i++)
  {
    path_length++;
    if (0 == memcmp (&paths_array[i],
		     &message->destination,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
      if (1 == path_length)
        neighbor = GNUNET_YES;
      path_length = 0;
    }
  }

  /* Call Callback with tunnel info */
  paths_array = (const struct GNUNET_PeerIdentity *) &message[1];
  gp->peer_cb (gp->peer_cb_cls,
		 &message->destination,
		 (int) ntohs (message->tunnel),
		 neighbor,
		 paths,
		 paths_array,
		 (int) ntohs (message->offset),
		 (int) ntohs (message->finished_with_paths));
  GNUNET_CADET_get_peer_cancel (gp);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_GetPeer` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_GetPeer`
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
	       enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_GetPeer *gp = cls;

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
 * @param cls a `struct GNUNET_CADET_GetPeer` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_GetPeer *gp = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (get_peer,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER,
                           struct GNUNET_CADET_LocalInfoPeer,
                           gp),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CADET_LocalInfo *msg;
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
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
  msg->peer = gp->id;
  GNUNET_MQ_send (gp->mq,
                  env);
}


/**
 * Request information about a peer known to the running cadet peer.
 * The callback will be called for the tunnel once.
 *
 * @param cfg configuration to use
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
struct GNUNET_CADET_GetPeer *
GNUNET_CADET_get_peer (const struct GNUNET_CONFIGURATION_Handle *cfg,
		       const struct GNUNET_PeerIdentity *id,
                       GNUNET_CADET_PeerCB callback,
                       void *callback_cls)
{
  struct GNUNET_CADET_GetPeer *gp;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  gp = GNUNET_new (struct GNUNET_CADET_GetPeer);
  gp->peer_cb = callback;
  gp->peer_cb_cls = callback_cls;
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
 * @return closure from #GNUNET_CADET_get_peer().
 */
void *
GNUNET_CADET_get_peer_cancel (struct GNUNET_CADET_GetPeer *gp)
{
  void *ret = gp->peer_cb_cls;

  if (NULL != gp->mq)
    GNUNET_MQ_destroy (gp->mq);
  if (NULL != gp->reconnect_task)
    GNUNET_SCHEDULER_cancel (gp->reconnect_task);
  GNUNET_free (gp);
  return ret;
}


/* end of cadet_api_get_peer.c */
