/*
      This file is part of GNUnet
      (C) 

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
 * @file include/gnunet_rps_service.h
 * @brief API to the rps service
 * @author Julius Bünger
 */
#ifndef GNUNET_RPS_SERVICE_H
#define GNUNET_RPS_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version of the rps API.
 */
#define GNUNET_RPS_VERSION 0x00000000

/**
 * Handle for the random peer sampling service
 */
struct GNUNET_RPS_Handle;

/**
 * Handle for one request to the rps service
 */
struct GNUNET_RPS_Request_Handle;

/**
 * Callback called when requested random peers are available.
 *
 * @param cls the closure given with the request
 * @param num_peers the number of peers returned
 * @param peers array with num_peers PeerIDs
 */
typedef void (* GNUNET_RPS_NotifyReadyCB) (void *cls, uint64_t num_peers, const struct GNUNET_PeerIdentity *peers);

/**
 * Request n random peers.
 *
 * This is a wrapper function that makes it unnecessary to have to
 * (dis)connect from/to the service.
 * 
 * @param cfg the configuration to use
 * @param n number of peers to be returned
 * @param ready_cb the callback to be called when the PeerIDs are available
 * @param cls closure given to the callback
 * @return handle to this request
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers_single_call (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls);

/**
 * Connect to the rps service
 *
 * @param cfg configuration to use
 * @return handle to the rps service
 */
  struct GNUNET_RPS_Handle *
GNUNET_RPS_connect( const struct GNUNET_CONFIGURATION_Handle *cfg );

/**
 * Request n random peers.
 *
 * This does exacly the same as GNUNET_RPS_request_peers_single_call
 * but needs a GNUNET_RPS_Handle.
 * This exists only for other parts of GNUnet that expect having to
 * (dis)connect from/to a service.
 *
 * @param h handle to the rps service
 * @param n number of random peers to return
 * @param ready_cb the callback to be called when the peers are available
 * @param cls a closure that will be given to the callback
 * @return handle to this request
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *h, uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls);

/**
 * Seed rps service with peerIDs.
 */
  void
GNUNET_RPS_seed_ids (struct GNUNET_RPS_Handle *h, uint64_t n,
                     struct GNUNET_PeerIdentity * ids);

/**
 * Cancle an issued request.
 *
 * @param rh handle of the pending request to be canceled
 */
  void
GNUNET_RPS_request_cancel ( struct GNUNET_RPS_Request_Handle *rh );

/**
 * Disconnect from the rps service
 *
 * @param h the handle to the rps service
 */
  void
GNUNET_RPS_disconnect ( struct GNUNET_RPS_Handle *h );

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
