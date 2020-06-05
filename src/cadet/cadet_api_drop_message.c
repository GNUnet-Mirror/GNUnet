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
 * @file cadet/cadet_api_drop_message.c
 * @brief cadet api: client implementation of cadet service
 * @author t3sserakt
 */
#include "platform.h"
#include "cadet.h"


/**
 * Drop the next cadet message of a given type..
 *
 * @param mq message queue
 * @param ccn client channel number.
 * @param type of cadet message to be dropped.
 */
void
GNUNET_CADET_drop_message (struct GNUNET_MQ_Handle *mq,
			   struct GNUNET_CADET_ClientChannelNumber ccn,
			   uint16_t type)
{
  struct GNUNET_CADET_RequestDropCadetMessage *message;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (message, GNUNET_MESSAGE_TYPE_CADET_DROP_CADET_MESSAGE);

  message->ccn = ccn;
  message->type = type;
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Dropping message for channel of type %s (%d)\n", type == GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY ? "GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY" : "UNKNOWN", type);

  GNUNET_MQ_send (mq, env);
  
}




/* end of cadet_api_drop_message.c */
