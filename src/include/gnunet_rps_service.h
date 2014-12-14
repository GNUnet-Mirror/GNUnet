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

typedef void (* GNUNET_RPS_NotifyReadyCB) (void *cls, uint64_t num_peers, struct GNUNET_PeerIdentity *peers);

/**
 * Request n random peers.
 *
 * This is a wrapper function that makes it useless to have to
 * (dis)connect from/to the service.
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers_single_call (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls);

/**
 * Connect to the rps service
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
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *h, uint64_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls);

/**
 * Cancle an issued request.
 */
  void
GNUNET_RPS_request_cancel ( struct GNUNET_RPS_Request_Handle *rh );

/**
 * Disconnect from the rps service
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
