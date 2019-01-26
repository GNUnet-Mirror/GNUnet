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
 * @file cadet/cadet_api.c
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
 * Ugly legacy hack.
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
};


/**
 * Send message of @a type to CADET service of @a h
 *
 * @param h handle to CADET service
 * @param type message type of trivial information request to send
 */
static void
send_info_request (struct GNUNET_CADET_Handle *h,
                   uint16_t type)
{
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       type);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Request information about peers known to the running cadet service.
 * The callback will be called for every peer known to the service.
 * Only one info request (of any kind) can be active at once.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return #GNUNET_OK / #GNUNET_SYSERR
 */
int
GNUNET_CADET_list_peers (struct GNUNET_CADET_Handle *h,
			 GNUNET_CADET_PeersCB callback,
			 void *callback_cls)
{
  if (NULL != h->info_cb.peers_cb)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  send_info_request (h,
                     GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  h->info_cb.peers_cb = callback;
  h->info_cls = callback_cls;
  return GNUNET_OK;
}


/**
 * Cancel a peer info request. The callback will not be called (anymore).
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Cadet handle.
 * @return Closure given to GNUNET_CADET_get_peers().
 */
void *
GNUNET_CADET_list_peers_cancel (struct GNUNET_CADET_Handle *h)
{
  void *cls = h->info_cls;

  h->info_cb.peers_cb = NULL;
  h->info_cls = NULL;
  return cls;
}


/**
 * Check that message received from CADET service is well-formed.
 *
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param message the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_get_peers (void *cls,
                 const struct GNUNET_MessageHeader *message)
{
  size_t esize;

  (void) cls;
  esize = ntohs (message->size);
  if (sizeof (struct GNUNET_CADET_LocalInfoPeer) == esize)
    return GNUNET_OK;
  if (sizeof (struct GNUNET_MessageHeader) == esize)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Process a local reply about info on all tunnels, pass info to the user.
 *
 * @param cls Closure (Cadet handle).
 * @param msg Message itself.
 */
static void
handle_get_peers (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CADET_Handle *h = cls;
  const struct GNUNET_CADET_LocalInfoPeer *info =
    (const struct GNUNET_CADET_LocalInfoPeer *) msg;

  if (NULL == h->info_cb.peers_cb)
    return;
  if (sizeof (struct GNUNET_CADET_LocalInfoPeer) == ntohs (msg->size))
    h->info_cb.peers_cb (h->info_cls,
                         &info->destination,
                         (int) ntohs (info->tunnel),
                         (unsigned int) ntohs (info->paths),
                         0);
  else
    h->info_cb.peers_cb (h->info_cls,
                         NULL,
                         0,
                         0,
                         0);
}





