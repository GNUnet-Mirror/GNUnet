/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Monitoring / diagnostics API for the transport service
 *
 * @defgroup transport TRANSPORT service
 * Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */
#ifndef GNUNET_TRANSPORT_MONITOR_SERVICE_H
#define GNUNET_TRANSPORT_MONITOR_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_transport_communication_service.h"


/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_MONITOR_VERSION 0x00000000


/**
 * Information about another peer's address.
 */
struct GNUNET_TRANSPORT_MonitorInformation
{
  /**
   * Address we have for the peer, human-readable, 0-terminated, in UTF-8.
   */
  const char *address;

  /**
   * Network type of the address.
   */
  enum GNUNET_NetworkType nt;

  /**
   * Connection status.
   */
  enum GNUNET_TRANSPORT_ConnectionStatus cs;

  /**
   * Number of messages pending transmission for this @e address.
   */
  uint32_t num_msg_pending;

  /**
   * Number of bytes pending transmission for this @e address.
   */
  uint32_t num_bytes_pending;

  /**
   * When was this address last validated.
   */
  struct GNUNET_TIME_Absolute last_validation;

  /**
   * When does this address expire.
   */
  struct GNUNET_TIME_Absolute valid_until;

  /**
   * Time of the next validation operation.
   */
  struct GNUNET_TIME_Absolute next_validation;

  /**
   * Current estimate of the RTT.
   */
  struct GNUNET_TIME_Relative rtt;
};


/**
 * Function to call with information about a peer.
 *
 * If one_shot was set to #GNUNET_YES to iterate over all peers once,
 * a final call with NULL for peer and address will follow when done.
 * In this case state and timeout do not contain valid values.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel() call MUST not be called from
 * within this function!
 *
 *
 * @param cls closure
 * @param peer peer this update is about,
 *        NULL if this is the final last callback for a iteration operation
 * @param mi monitoring data on the peer
 */
typedef void
(*GNUNET_TRANSPORT_MonitorCallback) (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct
                                     GNUNET_TRANSPORT_MonitorInformation *mi);


/**
 * Handle for a #GNUNET_TRANSPORT_monitor() operation.
 */
struct GNUNET_TRANSPORT_MonitorContext;


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
                          void *cb_cls);


/**
 * Cancel request to monitor peers
 *
 * @param mc handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_cancel (struct GNUNET_TRANSPORT_MonitorContext *mc);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_MONITOR_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_monitor_service.h */
