/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file core/core_api_peer_request.c
 * @brief implementation of the peer_request functions 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "core.h"


/**
 * Handle for a request to the core to connect to
 * a particular peer.  Can be used to cancel the request
 * (before the 'cont'inuation is called).
 */
struct GNUNET_CORE_PeerRequestHandle
{

  /**
   * Our connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Function to call once done.
   */
  GNUNET_SCHEDULER_Task cont;
  
  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Identity of the peer to connect to.
   */
  struct GNUNET_PeerIdentity peer;
	
  /**
   * Message type to use.
   */
  uint16_t type;
};


/**
 * Transmit the request to the core service.
 *
 * @param cls our 'struct GNUNET_CORE_PeerRequestHandle'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */ 
static size_t
send_request (void *cls,
	      size_t size,
	      void *buf)
{
  struct GNUNET_CORE_PeerRequestHandle * prh = cls;
  struct ConnectMessage msg;

  if (buf == NULL)
    {
      GNUNET_SCHEDULER_add_continuation (prh->sched,
					 prh->cont,
					 prh->cont_cls,
					 GNUNET_SCHEDULER_REASON_TIMEOUT);
      GNUNET_CLIENT_disconnect (prh->client);
      GNUNET_free (prh);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct ConnectMessage));
  msg.header.type = htons (prh->type);
  msg.header.size = htons (sizeof (struct ConnectMessage));
  msg.reserved = htonl (0);
  msg.peer = prh->peer;
  memcpy (buf, &msg, sizeof (msg));
  GNUNET_SCHEDULER_add_continuation (prh->sched,
				     prh->cont,
				     prh->cont_cls,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_CLIENT_disconnect (prh->client);
  GNUNET_free (prh);
  return sizeof (msg);
}


/**
 * Request that the core should try to connect to a particular peer.
 * Once the request has been transmitted to the core, the continuation
 * function will be called.  Note that this does NOT mean that a
 * connection was successfully established -- it only means that the
 * core will now try.  Successful establishment of the connection
 * will be signalled to the 'connects' callback argument of
 * 'GNUNET_CORE_connect' only.  If the core service does not respond
 * to our connection attempt within the given time frame, 'cont' will
 * be called with the TIMEOUT reason code.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout how long to try to talk to core
 * @param cont function to call once the request has been completed (or timed out)
 * @param cont_cls closure for cont
 * @return NULL on error (cont will not be called), otherwise handle for cancellation
 */
struct GNUNET_CORE_PeerRequestHandle *
GNUNET_CORE_peer_request_connect (struct GNUNET_SCHEDULER_Handle *sched,
				  const struct GNUNET_CONFIGURATION_Handle *cfg,
				  struct GNUNET_TIME_Relative timeout,
				  const struct GNUNET_PeerIdentity * peer,
				  GNUNET_SCHEDULER_Task cont,
				  void *cont_cls)
{
  struct GNUNET_CORE_PeerRequestHandle *ret;
  struct GNUNET_CLIENT_Connection *client;
  
  client = GNUNET_CLIENT_connect (sched, "core", cfg);
  if (client == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_CORE_PeerRequestHandle));
  ret->client = client;
  ret->sched = sched;
  ret->cont = cont;
  ret->cont_cls = cont_cls;
  ret->peer = *peer;
  ret->type = GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT;
  GNUNET_CLIENT_notify_transmit_ready (client,
				       sizeof (struct ConnectMessage),
				       timeout,
				       GNUNET_YES,
				       &send_request,
				       ret);
  return ret;
}


/**
 * Cancel a pending request to connect to a particular peer.  Must not
 * be called after the 'cont' function was invoked.
 *
 * @param req request handle that was returned for the original request
 */
void
GNUNET_CORE_peer_request_connect_cancel (struct GNUNET_CORE_PeerRequestHandle *req)
{
  GNUNET_CLIENT_disconnect (req->client);
  GNUNET_free (req);
}


/* end of core_api_peer_request.c */
