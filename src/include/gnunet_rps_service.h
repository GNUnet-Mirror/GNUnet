/*
      This file is part of GNUnet
      Copyright (C)

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
 * @author Julius Bünger
 *
 * @file
 * API to the rps service
 *
 * @defgroup rps  RPS service
 * Random Peer Sampling
 * @{
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
typedef void (* GNUNET_RPS_NotifyReadyCB) (void *cls,
    uint64_t num_peers,
    const struct GNUNET_PeerIdentity *peers);


/**
 * Callback called when requested random peer with additional information is
 * available.
 *
 * @param cls the closure given with the request
 * @param peer The Peer ID
 * @param probability The probability with which all elements have been observed
 * @param num_observed Number of IDs this sampler has observed
 */
typedef void (* GNUNET_RPS_NotifyReadySingleInfoCB) (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    double probability,
    uint32_t num_observed);


/**
 * Connect to the rps service
 *
 * @param cfg configuration to use
 * @return handle to the rps service
 */
struct GNUNET_RPS_Handle *
GNUNET_RPS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * @brief Start a sub with the given shared value
 *
 * @param h Handle to rps
 * @param shared_value The shared value that defines the members of the sub (-group)
 */
void
GNUNET_RPS_sub_start (struct GNUNET_RPS_Handle *h,
                      const char *shared_value);


/**
 * @brief Stop a sub with the given shared value
 *
 * @param h Handle to rps
 * @param shared_value The shared value that defines the members of the sub (-group)
 */
void
GNUNET_RPS_sub_stop (struct GNUNET_RPS_Handle *h,
                     const char *shared_value);


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
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *h, uint32_t n,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls);


/**
 * Request one random peer, getting additional information.
 *
 * @param rps_handle handle to the rps service
 * @param ready_cb the callback called when the peers are available
 * @param cls closure given to the callback
 * @return a handle to cancel this request
 */
struct GNUNET_RPS_Request_Handle_Single_Info *
GNUNET_RPS_request_peer_info (struct GNUNET_RPS_Handle *rps_handle,
                              GNUNET_RPS_NotifyReadySingleInfoCB ready_cb,
                              void *cls);


/**
 * Seed rps service with peerIDs.
 *
 * @param h handle to the rps service
 * @param n number of peers to seed
 * @param ids the ids of the peers seeded
 */
void
GNUNET_RPS_seed_ids (struct GNUNET_RPS_Handle *h, uint32_t n,
                     const struct GNUNET_PeerIdentity * ids);

/**
 * Cancle an issued request.
 *
 * @param rh handle of the pending request to be canceled
 */
void
GNUNET_RPS_request_cancel (struct GNUNET_RPS_Request_Handle *rh);


/**
 * Cancle an issued single info request.
 *
 * @param rhs request handle of request to cancle
 */
void
GNUNET_RPS_request_single_info_cancel (
    struct GNUNET_RPS_Request_Handle_Single_Info *rhs);


#if ENABLE_MALICIOUS
/**
 * Turn RPS service to act malicious.
 *
 * @param h handle to the rps service
 * @param type which type of malicious peer to turn to.
 *             0 Don't act malicious at all
 *             1 Try to maximise representation
 *             2 Try to partition the network
 *               (isolate one peer from the rest)
 * @param n number of @a ids
 * @param ids the ids of the malicious peers
 *            if @type is 2 the last id is the id of the
 *            peer to be isolated from the rest
 */
  void
GNUNET_RPS_act_malicious (struct GNUNET_RPS_Handle *h,
                          uint32_t type,
                          uint32_t num_peers,
                          const struct GNUNET_PeerIdentity *ids,
                          const struct GNUNET_PeerIdentity *target_peer);
#endif /* ENABLE_MALICIOUS */

/* Get internals for debugging/profiling purposes */

/**
 * Request updates of view
 *
 * @param rps_handle handle to the rps service
 * @param num_req_peers number of peers we want to receive
 *        (0 for infinite updates)
 * @param cls a closure that will be given to the callback
 * @param ready_cb the callback called when the peers are available
 */
void
GNUNET_RPS_view_request (struct GNUNET_RPS_Handle *rps_handle,
                         uint32_t num_updates,
                         GNUNET_RPS_NotifyReadyCB view_update_cb,
                         void *cls);


/**
 * Request biased stream of peers that are being put into the sampler
 *
 * @param rps_handle handle to the rps service
 * @param cls a closure that will be given to the callback
 * @param ready_cb the callback called when the peers are available
 */
struct GNUNET_RPS_StreamRequestHandle *
GNUNET_RPS_stream_request (struct GNUNET_RPS_Handle *rps_handle,
                           GNUNET_RPS_NotifyReadyCB stream_input_cb,
                           void *cls);


/**
 * @brief Cancel a specific request for updates from the biased peer stream
 *
 * @param srh The request handle to cancel
 */
void
GNUNET_RPS_stream_cancel (struct GNUNET_RPS_StreamRequestHandle *srh);


/**
 * Disconnect from the rps service
 *
 * @param h the handle to the rps service
 */
  void
GNUNET_RPS_disconnect (struct GNUNET_RPS_Handle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
