/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file core/core_api_peer_get_info.c
 * @brief implementation of the peer_change_preference functions 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


struct GNUNET_CORE_InformationRequestContext 
{
  
  /**
   * Our connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Function to call with the information.
   */
  GNUNET_CORE_PeerConfigurationInfoCallback info;

  /**
   * Closure for info.
   */
  void *info_cls;

};


/**
 * Receive reply from core service with information about a peer.
 *
 * @param cls our 'struct  GNUNET_CORE_InformationRequestContext *'
 * @param msg NULL on error (i.e. timeout)
 */
static void
receive_info (void *cls,
	      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CORE_InformationRequestContext *irc = cls;
  const struct ConfigurationInfoMessage *cim;
  static struct GNUNET_BANDWIDTH_Value32NBO zbw; /* zero bandwidth */

  if (msg == NULL)
    {
      if (irc->info != NULL)
	irc->info (irc->info_cls, 
		   NULL, zbw, zbw, 0, 0);     
      GNUNET_CLIENT_disconnect (irc->client, GNUNET_NO);
      GNUNET_free (irc);
      return;
    }
  if ( (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO) ||
       (ntohs (msg->size) != sizeof (struct ConfigurationInfoMessage)) )
    {
      GNUNET_break (0);
      if (irc->info != NULL)
	irc->info (irc->info_cls, 
		   NULL, zbw, zbw, 0, 0);     
      GNUNET_CLIENT_disconnect (irc->client, GNUNET_NO);
      GNUNET_free (irc);
      return;
    }
  cim = (const struct ConfigurationInfoMessage*) msg;
  if (irc->info != NULL)
    irc->info (irc->info_cls,
	       &cim->peer,
	       cim->bw_in,
	       cim->bw_out,
	       ntohl (cim->reserved_amount),
	       GNUNET_ntohll (cim->preference));  
  GNUNET_CLIENT_disconnect (irc->client, GNUNET_NO);
  GNUNET_free (irc);
}


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param cfg configuration to use
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bw_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bw_out" to "-1" to avoid changing
 *                the current value; otherwise "bw_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bw_out" might not increase
 *                as specified since the upper bound is generally
 *                determined by the other peer!
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 * @return NULL on error
 */
struct GNUNET_CORE_InformationRequestContext *
GNUNET_CORE_peer_change_preference (const struct GNUNET_CONFIGURATION_Handle *cfg,
				    const struct GNUNET_PeerIdentity *peer,
				    struct GNUNET_TIME_Relative timeout,
				    struct GNUNET_BANDWIDTH_Value32NBO bw_out,
				    int32_t amount,
				    uint64_t preference,
				    GNUNET_CORE_PeerConfigurationInfoCallback info,
				    void *info_cls)
{
  struct GNUNET_CORE_InformationRequestContext *irc;
  struct RequestInfoMessage rim;
  struct GNUNET_CLIENT_Connection *client;
  int retry;

  client = GNUNET_CLIENT_connect ("core", cfg);
  if (client == NULL)
    return NULL;
  irc = GNUNET_malloc (sizeof (struct GNUNET_CORE_InformationRequestContext));
  irc->client = client;
  irc->info = info;
  irc->info_cls = info_cls;
  rim.header.size = htons (sizeof (struct RequestInfoMessage));
  rim.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO);
  rim.reserved = htonl (0);
  rim.limit_outbound = bw_out;
  rim.reserve_inbound = htonl (amount);
  rim.preference_change = GNUNET_htonll(preference);
  rim.peer = *peer;
  retry = ( (amount == 0) && (preference == 0) ) ? GNUNET_YES : GNUNET_NO;
  GNUNET_assert (GNUNET_OK == GNUNET_CLIENT_transmit_and_get_response (client,
								       &rim.header,
								       timeout,
								       retry,
								       &receive_info,
								       irc));  
  return irc;
}


/**
 * Cancel request for getting information about a peer.
 *
 * @param irc context returned by the original GNUNET_CORE_peer_get_info call
 */
void
GNUNET_CORE_peer_change_preference_cancel (struct GNUNET_CORE_InformationRequestContext *irc)
{
  GNUNET_CLIENT_disconnect (irc->client, GNUNET_NO);
  GNUNET_free (irc);
}

/* end of core_api_peer_get_info.c */
