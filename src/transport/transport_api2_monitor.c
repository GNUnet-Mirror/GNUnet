/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

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
 * @file transport/transport_api2_monitor.c
 * @brief implementation of the gnunet_transport_monitor_service.h API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_monitor_service.h"
#include "transport.h"


/**
 * Opaque handle to the transport service for monitors.
 */
struct GNUNET_TRANSPORT_MonitorContext
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Queue to talk to the transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Peer we monitor, all zeros for "all"
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * #GNUNET_YES to return the current state and then end.
   */
  int one_shot;

  /**
   * Function to call with monitor data.
   */
  GNUNET_TRANSPORT_MonitorCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


/**
 * (re)connect our monitor to the transport service
 *
 * @param mc handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_MonitorContext *mc);


/**
 * Send message to the transport service about our montoring
 * desire.
 *
 * @param ai address to delete
 */
static void
send_start_monitor (struct GNUNET_TRANSPORT_MonitorContext *mc)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_MonitorStart *smm;

  if (NULL == mc->mq)
    return;
  env = GNUNET_MQ_msg (smm, GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_START);
  smm->one_shot = htonl ((uint32_t) mc->one_shot);
  smm->peer = mc->peer;
  GNUNET_MQ_send (mc->mq, env);
}


/**
 * Disconnect from the transport service.
 *
 * @param mc service to disconnect from
 */
static void
disconnect (struct GNUNET_TRANSPORT_MonitorContext *mc)
{
  if (NULL == mc->mq)
    return;
  GNUNET_MQ_destroy (mc->mq);
  mc->mq = NULL;
}


/**
 * Function called on MQ errors. Reconnects to the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_MonitorContext *`
 * @param error what error happened?
 */
static void
error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_MonitorContext *mc = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "MQ failure %d, reconnecting to transport service.\n",
              error);
  disconnect (mc);
  /* TODO: maybe do this with exponential backoff/delay */
  reconnect (mc);
}


/**
 * Transport service sends us information about what is going on.
 * Check if @a md is well-formed.
 *
 * @param cls our `struct GNUNET_TRANSPORT_MonitorContext *`
 * @param md the monitor data we got
 * @return #GNUNET_OK if @a smt is well-formed
 */
static int
check_monitor_data (void *cls, const struct GNUNET_TRANSPORT_MonitorData *md)
{
  (void) cls;
  GNUNET_MQ_check_zero_termination (md);
  return GNUNET_OK;
}


/**
 * Transport service sends us information about what is going on.
 *
 * @param cls our `struct GNUNET_TRANSPORT_MonitorContext *`
 * @param md monitor data
 */
static void
handle_monitor_data (void *cls, const struct GNUNET_TRANSPORT_MonitorData *md)
{
  struct GNUNET_TRANSPORT_MonitorContext *mc = cls;
  struct GNUNET_TRANSPORT_MonitorInformation mi;

  mi.address = (const char *) &md[1];
  mi.nt = (enum GNUNET_NetworkType) ntohl (md->nt);
  mi.cs = (enum GNUNET_TRANSPORT_ConnectionStatus) ntohl (md->cs);
  mi.num_msg_pending = ntohl (md->num_msg_pending);
  mi.num_bytes_pending = ntohl (md->num_bytes_pending);
  mi.last_validation = GNUNET_TIME_absolute_ntoh (md->last_validation);
  mi.valid_until = GNUNET_TIME_absolute_ntoh (md->valid_until);
  mi.next_validation = GNUNET_TIME_absolute_ntoh (md->next_validation);
  mi.rtt = GNUNET_TIME_relative_ntoh (md->rtt);
  mc->cb (mc->cb_cls, &md->peer, &mi);
}


/**
 * One shot was requested, and transport service is done.
 *
 * @param cls our `struct GNUNET_TRANSPORT_MonitorContext *`
 * @param me end message
 */
static void
handle_monitor_end (void *cls, const struct GNUNET_MessageHeader *me)
{
  struct GNUNET_TRANSPORT_MonitorContext *mc = cls;

  if (GNUNET_YES != mc->one_shot)
  {
    GNUNET_break (0);
    disconnect (mc);
    reconnect (mc);
    return;
  }
  mc->cb (mc->cb_cls, NULL, NULL);
  GNUNET_TRANSPORT_monitor_cancel (mc);
}


/**
 * (re)connect our monitor to the transport service
 *
 * @param mc handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_MonitorContext *mc)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_var_size (monitor_data,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_DATA,
                           struct GNUNET_TRANSPORT_MonitorData,
                           mc),
    GNUNET_MQ_hd_fixed_size (monitor_end,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_END,
                             struct GNUNET_MessageHeader,
                             mc),
    GNUNET_MQ_handler_end () };

  mc->mq =
    GNUNET_CLIENT_connect (mc->cfg, "transport", handlers, &error_handler, mc);
  if (NULL == mc->mq)
    return;
  send_start_monitor (mc);
}


/**
 * Return information about a specific peer or all peers currently known to
 * transport service once or in monitoring mode. To obtain information about
 * a specific peer, a peer identity can be passed. To obtain information about
 * all peers currently known to transport service, NULL can be passed as peer
 * identity.
 *
 * For each peer, the callback is called with information about the address used
 * to communicate with this peer, the state this peer is currently in and the
 * the current timeout for this state.
 *
 * Upon completion, the #GNUNET_TRANSPORT_PeerIterateCallback is called one
 * more time with `NULL`. After this, the operation must no longer be
 * explicitly canceled.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel call MUST not be called in the
 * the peer_callback!
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain information for,
 *      NULL for all peers
 * @param one_shot #GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 #GNUNET_NO to monitor peers continuously
 * @param cb function to call with the results
 * @param cb_cls closure for @a mc
 */
struct GNUNET_TRANSPORT_MonitorContext *
GNUNET_TRANSPORT_monitor (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_PeerIdentity *peer,
                          int one_shot,
                          GNUNET_TRANSPORT_MonitorCallback cb,
                          void *cb_cls)
{
  struct GNUNET_TRANSPORT_MonitorContext *mc;

  mc = GNUNET_new (struct GNUNET_TRANSPORT_MonitorContext);
  mc->cfg = cfg;
  if (NULL != peer)
    mc->peer = *peer;
  mc->one_shot = one_shot;
  mc->cb = cb;
  mc->cb_cls = cb_cls;
  reconnect (mc);
  if (NULL == mc->mq)
  {
    GNUNET_free (mc);
    return NULL;
  }
  return mc;
}


/**
 * Cancel request to monitor peers
 *
 * @param pmc handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_cancel (struct GNUNET_TRANSPORT_MonitorContext *mc)
{
  disconnect (mc);
  GNUNET_free (mc);
}


/* end of transport_api2_monitor.c */
