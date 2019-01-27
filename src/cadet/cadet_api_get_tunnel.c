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
 * @file cadet/cadet_api_get_tunnel.c
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
struct GNUNET_CADET_GetTunnel
{

  /**
   * Monitor callback
   */
  GNUNET_CADET_TunnelCB callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;
  
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
 * @param cls the `struct GNUNET_CADET_Handle`
 * @param msg the message we got
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR otherwise
 */
static int
check_get_tunnel (void *cls,
                  const struct GNUNET_CADET_LocalInfoTunnel *msg)
{
  unsigned int ch_n;
  unsigned int c_n;
  size_t esize;
  size_t msize;

  (void) cls;
  /* Verify message sanity */
  msize = ntohs (msg->header.size);
  esize = sizeof (struct GNUNET_CADET_LocalInfoTunnel);
  if (esize > msize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ch_n = ntohl (msg->channels);
  c_n = ntohl (msg->connections);
  esize += ch_n * sizeof (struct GNUNET_CADET_ChannelTunnelNumber);
  esize += c_n * sizeof (struct GNUNET_CADET_ConnectionTunnelIdentifier);
  if (msize != esize)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "m:%u, e: %u (%u ch, %u conn)\n",
                (unsigned int) msize,
                (unsigned int) esize,
                ch_n,
                c_n);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a local tunnel info reply, pass info to the user.
 *
 * @param cls a `struct GNUNET_CADET_GetTunnel *`
 * @param msg Message itself.
 */
static void
handle_get_tunnel (void *cls,
                   const struct GNUNET_CADET_LocalInfoTunnel *msg)
{
  struct GNUNET_CADET_GetTunnel *gt = cls;
  unsigned int ch_n;
  unsigned int c_n;
  const struct GNUNET_CADET_ConnectionTunnelIdentifier *conns;
  const struct GNUNET_CADET_ChannelTunnelNumber *chns;

  ch_n = ntohl (msg->channels);
  c_n = ntohl (msg->connections);

  /* Call Callback with tunnel info. */
  conns = (const struct GNUNET_CADET_ConnectionTunnelIdentifier *) &msg[1];
  chns = (const struct GNUNET_CADET_ChannelTunnelNumber *) &conns[c_n];
  gt->callback (gt->callback_cls,
		&msg->destination,
		ch_n,
		c_n,
		chns,
		conns,
		ntohs (msg->estate),
		ntohs (msg->cstate));
  GNUNET_CADET_get_tunnel_cancel (gt);
}


/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_GetTunnel` operation
 */
static void
reconnect (void *cls);


/**
 * Function called on connection trouble.  Reconnects.
 *
 * @param cls a `struct GNUNET_CADET_GetTunnel`
 * @param error error code from MQ
 */
static void
error_handler (void *cls,
	       enum GNUNET_MQ_Error error)
{
  struct GNUNET_CADET_GetTunnel *gt = cls;

  GNUNET_MQ_destroy (gt->mq);
  gt->mq = NULL;
  gt->backoff = GNUNET_TIME_randomized_backoff (gt->backoff,
						GNUNET_TIME_UNIT_MINUTES);
  gt->reconnect_task = GNUNET_SCHEDULER_add_delayed (gt->backoff,
						     &reconnect,
						     gt);
}

  
/**
 * Reconnect to the service and try again.
 *
 * @param cls a `struct GNUNET_CADET_GetTunnel` operation
 */
static void
reconnect (void *cls)
{
  struct GNUNET_CADET_GetTunnel *gt = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (get_tunnel,
                           GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL,
                           struct GNUNET_CADET_LocalInfoTunnel,
                           gt),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalInfo *msg;
  
  gt->reconnect_task = NULL;
  gt->mq = GNUNET_CLIENT_connect (gt->cfg,
				  "cadet",
				  handlers,
				  &error_handler,
				  gt);
  if (NULL == gt->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
  msg->peer = gt->id;
  GNUNET_MQ_send (gt->mq,
                  env);
}

/**
 * Request information about a tunnel of the running cadet peer.
 * The callback will be called for the tunnel once.
 *
 * @param cfg configuration to use
 * @param id Peer whose tunnel to examine.
 * @param callback Function to call with the requested data.
 * @param callback_cls Closure for @c callback.
 * @return NULL on error
 */
struct GNUNET_CADET_GetTunnel *
GNUNET_CADET_get_tunnel (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 const struct GNUNET_PeerIdentity *id,
			 GNUNET_CADET_TunnelCB callback,
			 void *callback_cls)
{
  struct GNUNET_CADET_GetTunnel *gt;

  if (NULL == callback)
  {
    GNUNET_break (0);
    return NULL;
  }
  gt = GNUNET_new (struct GNUNET_CADET_GetTunnel);
  gt->callback = callback;
  gt->callback_cls = callback_cls;
  gt->cfg = cfg;
  gt->id = *id;
  reconnect (gt);
  if (NULL == gt->mq)
  {
    GNUNET_free (gt);
    return NULL;
  }
  return gt;
}


/**
 * Cancel a monitor request. The monitor callback will not be called.
 *
 * @param lt operation handle
 * @return Closure given to #GNUNET_CADET_get_tunnel(), if any.
 */
void *
GNUNET_CADET_get_tunnel_cancel (struct GNUNET_CADET_GetTunnel *gt)
{
  void *ret = gt->callback_cls;

  if (NULL != gt->mq)
    GNUNET_MQ_destroy (gt->mq);
  if (NULL != gt->reconnect_task)
    GNUNET_SCHEDULER_cancel (gt->reconnect_task);
  GNUNET_free (gt);
  return ret;
}

/* end of cadet_api_get_tunnel.c */
