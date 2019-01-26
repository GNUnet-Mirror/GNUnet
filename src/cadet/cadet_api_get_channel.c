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
 * Ugly legacy hack.
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
 * Request information about a specific channel of the running cadet peer.
 *
 * WARNING: unstable API, likely to change in the future!
 *
 * @param h Handle to the cadet peer.
 * @param peer ID of the other end of the channel.
 * @param channel_number Channel number.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 */
struct GNUNET_CADET_ChannelMonitor *
GNUNET_CADET_get_channel (struct GNUNET_CADET_Handle *h,
                          struct GNUNET_PeerIdentity *peer,
                          uint32_t /* UGH */ channel_number,
                          GNUNET_CADET_ChannelCB callback,
                          void *callback_cls)
{
}


void *
GNUNET_CADET_get_channel_cancel (struct GNUNET_CADET_ChannelMonitor *cm);

